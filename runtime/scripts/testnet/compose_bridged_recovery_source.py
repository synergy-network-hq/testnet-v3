#!/usr/bin/env python3
"""Compose a verifier-friendly recovery source from canonical source state.

This is only for offline recovery staging. It never mutates target validator
state. The target committed-QC prefix is admitted only for heights before the
canonical source QC span and only when each admitted QC hash matches the
canonical source lock at that height.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ALLOWED_STATE_FILES = {
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
    "synid_registry.json",
}

HEIGHT_PATTERN = re.compile(r'"(?:block_index|block_height|height)"\s*:\s*(\d+)')


def load_json(path: Path):
    return json.loads(path.read_text())


def qc_height_hash(entry: dict) -> tuple[int, str]:
    qc = entry.get("qc") or entry
    votes = qc.get("votes") or []
    heights = {
        int(vote.get("block_index") or vote.get("height") or 0)
        for vote in votes
        if isinstance(vote, dict)
    }
    height = (
        max(heights)
        if heights
        else int(
            qc.get("height")
            or qc.get("block_height")
            or entry.get("height")
            or entry.get("block_height")
            or 0
        )
    )
    block_hash = (
        qc.get("block_hash")
        or qc.get("hash")
        or entry.get("block_hash")
        or entry.get("hash")
    )
    if height <= 0 or not block_hash:
        raise ValueError("committed QC entry is missing height or hash")
    return height, block_hash


def quick_qc_height(line: str) -> int | None:
    heights = [int(match.group(1)) for match in HEIGHT_PATTERN.finditer(line)]
    return max(heights) if heights else None


def iter_qcs(path: Path, *, min_height: int | None = None, stop_before_height: int | None = None):
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            quick_height = quick_qc_height(line)
            if min_height is not None and quick_height is not None and quick_height < min_height:
                continue
            if stop_before_height is not None and quick_height is not None and quick_height >= stop_before_height:
                break
            entry = json.loads(line)
            height, block_hash = qc_height_hash(entry)
            if min_height is not None and height < min_height:
                continue
            if stop_before_height is not None and height >= stop_before_height:
                break
            yield height, block_hash, line


def first_qc(path: Path) -> tuple[int, str, dict]:
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line:
                entry = json.loads(line)
                height, block_hash = qc_height_hash(entry)
                return height, block_hash, entry
    raise ValueError(f"{path} has no committed QC entries")


def last_qc(path: Path) -> tuple[int, str, dict]:
    raw = subprocess.check_output(["tail", "-n", "1", str(path)], text=True).strip()
    if not raw:
        raise ValueError(f"{path} has no committed QC tail")
    entry = json.loads(raw)
    height, block_hash = qc_height_hash(entry)
    return height, block_hash, entry


def line_count(path: Path) -> int:
    raw = subprocess.check_output(["wc", "-l", str(path)], text=True)
    return int(raw.strip().split()[0])


def hardlink_or_copy(src: Path, dst: Path) -> None:
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--target-data-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--bridge-from-height", required=True, type=int)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()

    source_dir = args.source_dir.resolve()
    target_dir = args.target_data_dir.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise SystemExit(f"output dir already exists: {output_dir}")
    output_dir.mkdir(parents=True)

    source_files = {path.name for path in source_dir.iterdir() if path.is_file()}
    unexpected = sorted(source_files - ALLOWED_STATE_FILES)
    if unexpected:
        raise SystemExit(f"source contains unexpected files: {unexpected}")
    for required in [
        "chain.json",
        "canonical_locks.json",
        "committed_qcs.jsonl",
        "dag_state.json",
        "validator_registry.json",
        "token_state.json",
    ]:
        if not (source_dir / required).is_file():
            raise SystemExit(f"source missing required file: {required}")

    for path in source_dir.iterdir():
        if path.is_file() and path.name != "committed_qcs.jsonl":
            hardlink_or_copy(path, output_dir / path.name)

    chain = load_json(source_dir / "chain.json")
    if not chain:
        raise SystemExit("source chain is empty")
    source_tip = chain[-1]
    source_tip_height = int(source_tip.get("block_index") or source_tip.get("height"))
    source_tip_hash = source_tip.get("hash") or source_tip.get("block_hash")

    locks = load_json(source_dir / "canonical_locks.json")
    pruned_locks = {k: v for k, v in locks.items() if int(k) <= source_tip_height}
    (output_dir / "canonical_locks.json").write_text(
        json.dumps(pruned_locks, indent=2, sort_keys=True) + "\n"
    )

    source_qc_path = source_dir / "committed_qcs.jsonl"
    source_first_height, _source_first_hash, _source_first_entry = first_qc(source_qc_path)
    source_last_height, source_last_hash, source_last_entry = last_qc(source_qc_path)
    if source_last_height > source_tip_height:
        raise SystemExit(
            "source committed_qcs.jsonl tail is above source chain tip; "
            "provide a source already pruned to its retained chain body"
        )
    source_last_vote_count = len((source_last_entry.get("qc") or source_last_entry).get("votes") or [])
    source_qc_count = line_count(source_qc_path)

    output_qc_path = output_dir / "committed_qcs.jsonl"
    admitted_prefix_first = None
    admitted_prefix_last = None
    admitted_prefix_count = 0
    rejected_prefix = 0
    with output_qc_path.open("w", encoding="utf-8") as out:
        for height, block_hash, line in iter_qcs(
            target_dir / "committed_qcs.jsonl",
            min_height=args.bridge_from_height,
            stop_before_height=source_first_height,
        ):
            lock = pruned_locks.get(str(height))
            lock_hash = (lock or {}).get("block_hash") or (lock or {}).get("hash")
            if lock_hash == block_hash:
                if admitted_prefix_first is None:
                    admitted_prefix_first = height
                admitted_prefix_last = height
                admitted_prefix_count += 1
                out.write(line + "\n")
            else:
                rejected_prefix += 1

        if admitted_prefix_count == 0:
            raise SystemExit("target QC prefix had no entries matching source locks")
        if admitted_prefix_first is None or admitted_prefix_last is None:
            raise SystemExit("target QC prefix summary was not populated")
        if admitted_prefix_first > args.bridge_from_height + 1:
            raise SystemExit(
                "target QC prefix still cannot bridge target height "
                f"{args.bridge_from_height}: first admitted h{admitted_prefix_first}"
            )
        if admitted_prefix_last < source_first_height - 1:
            raise SystemExit(
                "target QC prefix does not reach source QC span: "
                f"last admitted h{admitted_prefix_last}, source starts h{source_first_height}"
            )

        with source_qc_path.open(encoding="utf-8") as source_qcs:
            shutil.copyfileobj(source_qcs, out)

    if admitted_prefix_count == 0:
        raise SystemExit("target QC prefix had no entries matching source locks")

    lock = pruned_locks.get(str(source_last_height), {})
    lock_hash = lock.get("block_hash") or lock.get("hash")
    if lock_hash != source_last_hash:
        raise SystemExit("source latest QC hash does not match source canonical lock")

    summary = {
        "admitted_target_prefix_first_height": admitted_prefix_first,
        "admitted_target_prefix_last_height": admitted_prefix_last,
        "admitted_target_prefix_count": admitted_prefix_count,
        "bridge_from_height": args.bridge_from_height,
        "derived_qc_height": source_last_height,
        "derived_qc_hash": source_last_hash,
        "derived_qc_vote_count": source_last_vote_count,
        "output_dir": str(output_dir),
        "rejected_target_prefix_count": rejected_prefix,
        "source_first_qc_height": source_first_height,
        "source_qc_count": source_qc_count,
        "source_tip_height": source_tip_height,
        "source_tip_hash": source_tip_hash,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
