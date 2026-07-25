#!/usr/bin/env python3
"""Create a compact derived source workspace for support-node snapshots.

This does not sign or publish a snapshot. It copies only launch-approved public
state from a local source workspace into a compact workspace so the supported
`synergy-node create-snapshot` command can sign a role-specific support
snapshot without first staging multi-GB state files.
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Callable, Iterator

SENTINEL_HEIGHT = 175_518
DEFAULT_RETAIN_BLOCKS = 5_000
COPY_FILES = (
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
    "account_state.json",
    "synid_registry.json",
    "state_checkpoint.json",
)


def block_height(value: dict) -> int:
    for key in ("height", "block_height", "block_index", "number", "block_number"):
        raw = value.get(key)
        if raw is not None:
            return int(raw)
    block = value.get("block")
    if isinstance(block, dict):
        return block_height(block)
    raise ValueError("block is missing height")


def block_hash(value: dict) -> str:
    for key in ("hash", "block_hash"):
        raw = value.get(key)
        if raw:
            return str(raw)
    block = value.get("block")
    if isinstance(block, dict):
        return block_hash(block)
    raise ValueError("block is missing hash")


def qc_height(value: dict) -> int:
    for key in ("height", "block_height", "block_index"):
        raw = value.get(key)
        if raw is not None:
            return int(raw)
    qc = value.get("qc", value)
    if isinstance(qc, dict):
        for key in ("height", "block_height", "block_index"):
            raw = qc.get(key)
            if raw is not None:
                return int(raw)
        votes = qc.get("votes")
        if isinstance(votes, list):
            heights = [
                int(vote[key])
                for vote in votes
                if isinstance(vote, dict)
                for key in ("block_index", "height")
                if vote.get(key) is not None
            ]
            if heights:
                return max(heights)
    raise ValueError("committed QC is missing height")


def iter_json_array_objects(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8") as handle:
        depth = 0
        in_string = False
        escaped = False
        collecting = False
        buffer: list[str] = []
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            for char in chunk:
                if not collecting:
                    if char == "{":
                        collecting = True
                        depth = 1
                        in_string = False
                        escaped = False
                        buffer = ["{"]
                    continue

                buffer.append(char)
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        in_string = False
                    continue

                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        collecting = False
                        yield "".join(buffer)
                        buffer = []
        if collecting:
            raise SystemExit(f"{path} ended while reading a JSON object")


def keep_height(height: int, start_height: int, snapshot_height: int) -> bool:
    if height > snapshot_height:
        return False
    return height >= start_height or height == SENTINEL_HEIGHT


def latest_qc_height(path: Path) -> int:
    latest: int | None = None
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                height = qc_height(json.loads(line))
            except Exception as exc:  # pragma: no cover - remote operator evidence
                raise SystemExit(f"parse {path} line {line_number}: {exc}") from exc
            latest = height if latest is None else max(latest, height)
    if latest is None:
        raise SystemExit(f"{path} contains no committed QC entries")
    return latest


def write_compact_chain(
    source: Path,
    committed_blocks_path: Path,
    target: Path,
    start_height: int,
    snapshot_height: int,
) -> tuple[int, str]:
    blocks: dict[int, dict] = {}
    for raw in iter_json_array_objects(source):
        value = json.loads(raw)
        height = block_height(value)
        if keep_height(height, start_height, snapshot_height):
            blocks[height] = value

    filled_from_committed_blocks = False
    skipped_malformed_committed_blocks = 0
    if committed_blocks_path.is_file():
        with committed_blocks_path.open("r", encoding="utf-8") as input_file:
            for line_number, line in enumerate(input_file, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    height = block_height(record)
                except Exception as exc:
                    skipped_malformed_committed_blocks += 1
                    continue
                if not keep_height(height, start_height, snapshot_height):
                    continue
                block = record.get("block") if isinstance(record, dict) else None
                if not isinstance(block, dict):
                    block = record
                if isinstance(record, dict) and record.get("hash") and not block.get("hash"):
                    block["hash"] = record["hash"]
                if height not in blocks:
                    blocks[height] = block
                    filled_from_committed_blocks = True

    if not blocks or snapshot_height not in blocks:
        raise SystemExit(f"chain.json has no retained block at height {snapshot_height}")
    target_tmp = target.with_suffix(".json.tmp")
    with target_tmp.open("w", encoding="utf-8") as output:
        output.write("[")
        for index, height in enumerate(sorted(blocks)):
            if index:
                output.write(",")
            json.dump(blocks[height], output, separators=(",", ":"))
        output.write("]")
    kept = len(blocks)
    last_hash = block_hash(blocks[snapshot_height])
    target_tmp.replace(target)
    if filled_from_committed_blocks:
        print("compact_chain_filled_from_committed_blocks=true")
    if skipped_malformed_committed_blocks:
        print(f"skipped_malformed_committed_blocks={skipped_malformed_committed_blocks}")
    return kept, last_hash


def write_compact_jsonl(
    source: Path,
    target: Path,
    start_height: int,
    snapshot_height: int,
    height_fn: Callable[[dict], int],
    label: str,
    require_snapshot: bool,
) -> tuple[int, bool]:
    kept = 0
    found_snapshot = False
    skipped_malformed = 0
    target_tmp = target.with_suffix(target.suffix + ".tmp")
    with source.open("r", encoding="utf-8") as input_file, target_tmp.open(
        "w", encoding="utf-8"
    ) as output:
        for line_number, line in enumerate(input_file, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                height = height_fn(value)
            except Exception as exc:
                if label == "committed_blocks.jsonl" and not require_snapshot:
                    skipped_malformed += 1
                    continue
                raise SystemExit(f"parse {label} line {line_number}: {exc}") from exc
            if not keep_height(height, start_height, snapshot_height):
                continue
            output.write(line if line.endswith("\n") else line + "\n")
            kept += 1
            if height == snapshot_height:
                found_snapshot = True
    if require_snapshot and (kept == 0 or not found_snapshot):
        raise SystemExit(f"{label} has no retained entry at height {snapshot_height}")
    target_tmp.replace(target)
    if skipped_malformed:
        print(f"skipped_malformed_{label.replace('.', '_')}={skipped_malformed}")
    return kept, found_snapshot


def write_compact_locks(
    source: Path,
    target: Path,
    start_height: int,
    snapshot_height: int,
) -> int:
    locks = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(locks, dict):
        raise SystemExit("canonical_locks.json must be a JSON object")
    compact = {
        key: value
        for key, value in locks.items()
        if keep_height(int(key), start_height, snapshot_height)
    }
    if str(snapshot_height) not in compact:
        raise SystemExit(f"canonical_locks.json has no retained lock at {snapshot_height}")
    target.write_text(json.dumps(compact, separators=(",", ":"), sort_keys=True) + "\n")
    return len(compact)


def copy_config(source_workspace: Path, output_workspace: Path, config_path: Path | None) -> None:
    source_config_dir = source_workspace / "config"
    target_config_dir = output_workspace / "config"
    if source_config_dir.is_dir():
        shutil.copytree(source_config_dir, target_config_dir, dirs_exist_ok=True)
    else:
        target_config_dir.mkdir(parents=True, exist_ok=True)
    if config_path and config_path.is_file():
        shutil.copy2(config_path, target_config_dir / config_path.name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-workspace", type=Path, required=True)
    parser.add_argument("--source-config", type=Path)
    parser.add_argument("--output-workspace", type=Path, required=True)
    parser.add_argument("--retain-blocks", type=int, default=DEFAULT_RETAIN_BLOCKS)
    args = parser.parse_args()

    source_workspace = args.source_workspace
    source_data = source_workspace / "data"
    output_workspace = args.output_workspace
    output_data = output_workspace / "data"
    retain_blocks = args.retain_blocks
    if retain_blocks < 32:
        raise SystemExit("--retain-blocks must be at least 32")
    if not source_data.is_dir():
        raise SystemExit(f"missing source data dir: {source_data}")

    snapshot_height = latest_qc_height(source_data / "committed_qcs.jsonl")
    start_height = max(0, snapshot_height - retain_blocks + 1)
    if output_workspace.exists():
        shutil.rmtree(output_workspace)
    output_data.mkdir(parents=True)
    (output_workspace / "state" / "store").mkdir(parents=True)
    copy_config(source_workspace, output_workspace, args.source_config)

    chain_count, snapshot_hash = write_compact_chain(
        source_data / "chain.json",
        source_data / "committed_blocks.jsonl",
        output_data / "chain.json",
        start_height,
        snapshot_height,
    )
    lock_count = write_compact_locks(
        source_data / "canonical_locks.json",
        output_data / "canonical_locks.json",
        start_height,
        snapshot_height,
    )
    qcs_count, _ = write_compact_jsonl(
        source_data / "committed_qcs.jsonl",
        output_data / "committed_qcs.jsonl",
        start_height,
        snapshot_height,
        qc_height,
        "committed_qcs.jsonl",
        True,
    )
    committed_blocks = source_data / "committed_blocks.jsonl"
    committed_blocks_count = 0
    if committed_blocks.is_file():
        committed_blocks_count, _ = write_compact_jsonl(
            committed_blocks,
            output_data / "committed_blocks.jsonl",
            start_height,
            snapshot_height,
            block_height,
            "committed_blocks.jsonl",
            False,
        )

    for name in COPY_FILES:
        source = source_data / name
        if source.is_file():
            shutil.copy2(source, output_data / name)

    manifest = {
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_workspace": str(source_workspace),
        "output_workspace": str(output_workspace),
        "snapshot_height": snapshot_height,
        "snapshot_hash": snapshot_hash,
        "start_height": start_height,
        "retain_blocks": retain_blocks,
        "chain_blocks": chain_count,
        "canonical_locks": lock_count,
        "committed_qcs": qcs_count,
        "committed_blocks": committed_blocks_count,
        "runtime_workspace_gate_ready": True,
        "keys_or_configs_copied_into_snapshot_data": False,
    }
    (output_workspace / "compact-source-workspace-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
