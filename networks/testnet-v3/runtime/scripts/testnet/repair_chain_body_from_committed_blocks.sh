#!/usr/bin/env bash
set -euo pipefail

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
repair_log="${SYNERGY_COMMITTED_BLOCK_REPAIR_LOG:-$workspace/data/committed_blocks.jsonl}"

if [[ ! -d "$workspace" ]]; then
  echo "workspace not found: $workspace" >&2
  exit 2
fi
if [[ ! -f "$repair_log" ]]; then
  echo "committed block repair log not found: $repair_log" >&2
  exit 2
fi

cd "$workspace"

python3 - "$repair_log" <<'PY'
import json
import hashlib
import os
import re
import shutil
import sys
import time
from pathlib import Path

repair_log = Path(sys.argv[1])
dry_run = os.environ.get("SYNERGY_CHAIN_BODY_REPAIR_DRY_RUN", "").lower() in {
    "1",
    "true",
    "yes",
}
max_backups = int(os.environ.get("SYNERGY_CHAIN_BODY_REPAIR_MAX_BACKUPS", "16"))
data_dir = Path("data")
chain_path = data_dir / "chain.json"
canonical_locks_path = data_dir / "canonical_locks.json"
state_checkpoint_path = data_dir / "state_checkpoint.json"
if not chain_path.exists():
    raise SystemExit(f"missing chain body: {chain_path}")


def block_height(block):
    return int(block["block_index"])


def block_hash(block):
    value = block.get("hash")
    if not isinstance(value, str) or not value:
        raise ValueError("block hash is missing")
    return value


def read_chain(path):
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, list):
        raise ValueError("chain body is not a JSON array")
    for index, block in enumerate(value):
        if not isinstance(block, dict):
            raise ValueError(f"chain entry {index} is not an object")
        block_height(block)
        block_hash(block)
    return value


def summarize_chain(path):
    try:
        blocks = read_chain(path)
        if not blocks:
            return {"path": str(path), "valid": True, "empty": True}
        return {
            "path": str(path),
            "valid": True,
            "empty": False,
            "first_height": block_height(blocks[0]),
            "first_hash": block_hash(blocks[0]),
            "tip_height": block_height(blocks[-1]),
            "tip_hash": block_hash(blocks[-1]),
            "block_count": len(blocks),
        }
    except Exception as exc:
        return {"path": str(path), "valid": False, "error": str(exc)}


def validate_chain_shape(blocks):
    if not blocks:
        return
    previous = blocks[0]
    block_height(previous)
    block_hash(previous)
    compact_boundary_gap_used = False
    for index, block in enumerate(blocks[1:], start=1):
        expected_height = block_height(previous) + 1
        if block_height(block) != expected_height:
            if (
                index == 1
                and block_height(previous) > 0
                and not compact_boundary_gap_used
            ):
                compact_boundary_gap_used = True
                previous = block
                continue
            raise ValueError(
                f"chain body is not contiguous: h{block_height(previous)} followed by h{block_height(block)}"
            )
        if block.get("previous_hash") != block_hash(previous):
            raise ValueError(
                f"chain body parent mismatch at h{block_height(block)}: {block.get('previous_hash')} != {block_hash(previous)}"
            )
        previous = block


def validate_strict_chain_shape(blocks):
    if not blocks:
        raise ValueError("candidate chain body is empty")
    previous = blocks[0]
    block_height(previous)
    block_hash(previous)
    for block in blocks[1:]:
        expected_height = block_height(previous) + 1
        if block_height(block) != expected_height:
            raise ValueError(
                f"candidate chain body is not contiguous: h{block_height(previous)} followed by h{block_height(block)}"
            )
        if block.get("previous_hash") != block_hash(previous):
            raise ValueError(
                f"candidate chain body parent mismatch at h{block_height(block)}: {block.get('previous_hash')} != {block_hash(previous)}"
            )
        previous = block


def read_canonical_locks(path):
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("canonical_locks.json is not an object")
    locks = {}
    for raw_height, record in value.items():
        try:
            height = int(raw_height)
        except Exception:
            continue
        lock_hash = None
        if isinstance(record, str):
            lock_hash = record
        elif isinstance(record, dict):
            for key in ("block_hash", "hash", "qc_block_hash"):
                if isinstance(record.get(key), str) and record[key]:
                    lock_hash = record[key]
                    break
        if lock_hash:
            locks[height] = lock_hash
    return locks


def choose_target(locks):
    if not locks:
        return None
    height = max(locks)
    return {"height": height, "hash": locks[height]}


height_pattern = re.compile(r'"height"\s*:\s*(\d+)')


def iter_log_heights(path):
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            match = height_pattern.search(line)
            if match:
                yield line_number, int(match.group(1)), line


def log_height_bounds(path):
    min_height = None
    max_height = None
    for _, height, _ in iter_log_heights(path):
        min_height = height if min_height is None else min(min_height, height)
        max_height = height if max_height is None else max(max_height, height)
    return min_height, max_height


def read_log_entries(path, min_height, max_height):
    entries = {}
    malformed_lines = []
    if min_height is None:
        return entries, malformed_lines
    for line_number, height, line in iter_log_heights(path):
        if height < min_height:
            continue
        if max_height is not None and height > max_height:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed_lines.append(
                {
                    "line": line_number,
                    "height_hint": height,
                    "error": str(exc),
                }
            )
            continue
        entry_height = int(entry["height"])
        if entry_height != height:
            raise SystemExit(
                f"repair log line {line_number} regex height {height} does not match entry height {entry_height}"
            )
        block = entry["block"]
        if int(block.get("block_index", -1)) != height:
            raise SystemExit(
                f"repair log line {line_number} height {height} does not match block_index"
            )
        if entry.get("hash") != block.get("hash"):
            raise SystemExit(f"repair log line {line_number} hash mismatch")
        entries.setdefault(height, block)
    return entries, malformed_lines


def append_blocks_to_chain_file(path, blocks):
    if not blocks:
        return
    with path.open("r+b") as handle:
        handle.seek(0, 2)
        pos = handle.tell() - 1
        while pos >= 0:
            handle.seek(pos)
            byte = handle.read(1)
            if byte in b" \t\r\n":
                pos -= 1
                continue
            if byte != b"]":
                raise SystemExit(f"{path} does not end with a JSON array close bracket")
            break
        if pos < 0:
            raise SystemExit(f"{path} is empty")
        handle.truncate(pos)
        handle.seek(pos)
        handle.write(b",")
        for index, block in enumerate(blocks):
            if index:
                handle.write(b",")
            handle.write(json.dumps(block, separators=(",", ":")).encode("utf-8"))
        handle.write(b"]\n")
        handle.flush()
        os.fsync(handle.fileno())


def write_chain_file(path, blocks):
    tmp_path = path.with_name(f"{path.name}.repair-write-{int(time.time())}-{os.getpid()}")
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(blocks, handle, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, path)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_repair_checkpoint(first_block):
    checkpoint = {
        "format": "synergy_consensus_state_checkpoint_v1",
        "height": block_height(first_block),
        "block_hash": block_hash(first_block),
        "state_root": f"validator-pruned-chain-body-repair-h{block_height(first_block)}",
        "created_at_unix": int(time.time()),
        "created_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "created_by_tool": "scripts/testnet/repair_chain_body_from_committed_blocks.sh",
        "repair_scope": "validator-pruned-committed-block-log-retained-window",
        "chain_sha256": sha256_file(chain_path),
        "canonical_locks_sha256": sha256_file(canonical_locks_path),
        "committed_qcs_sha256": sha256_file(data_dir / "committed_qcs.jsonl"),
    }
    tmp_path = state_checkpoint_path.with_name(
        f"{state_checkpoint_path.name}.repair-write-{int(time.time())}-{os.getpid()}"
    )
    with tmp_path.open("w", encoding="utf-8") as handle:
        json.dump(checkpoint, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, state_checkpoint_path)


def candidate_from_committed_block_log(entries, locks, target):
    if not entries:
        raise ValueError("committed block log has no usable block entries")
    target_height = target["height"] if target else max(entries)
    target_block = entries.get(target_height)
    if target_block is None:
        raise ValueError(f"committed block log cannot cover target h{target_height}")
    if target and block_hash(target_block) != target["hash"]:
        raise ValueError(
            f"committed block log target h{target_height} hash {block_hash(target_block)} does not match canonical lock {target['hash']}"
        )
    candidate_starts = [
        height
        for height in sorted(entries)
        if height <= target_height
        and height in locks
        and locks[height] == block_hash(entries[height])
    ]
    rejection_samples = []
    for start_height in candidate_starts:
        blocks = []
        try:
            for height in range(start_height, target_height + 1):
                block = entries.get(height)
                if block is None:
                    raise ValueError(f"missing committed block h{height}")
                blocks.append(block)
            validate_strict_chain_shape(blocks)
        except Exception as exc:
            if len(rejection_samples) < 8:
                rejection_samples.append({"start_height": start_height, "error": str(exc)})
            continue
        return {
            "source_path": str(repair_log),
            "source_tip_height": block_height(blocks[-1]),
            "source_tip_hash": block_hash(blocks[-1]),
            "old_tip_height": current_summary.get("tip_height"),
            "new_tip_height": block_height(blocks[-1]),
            "new_tip_hash": block_hash(blocks[-1]),
            "appended_blocks": 0,
            "append_blocks": [],
            "full_blocks": blocks,
            "source_is_current": False,
            "source_kind": "committed_block_log_retained_window",
            "checkpoint_height": block_height(blocks[0]),
            "checkpoint_hash": block_hash(blocks[0]),
            "candidate_start_rejections": rejection_samples,
        }
    raise ValueError(
        "committed block log has no contiguous canonical-lock-backed retained window"
    )


locks = read_canonical_locks(canonical_locks_path)
target = choose_target(locks)
backups = [path for path in data_dir.glob("chain.json.pre-body-repair-*") if path != chain_path]
backups.sort(key=lambda path: path.stat().st_mtime if path.exists() else 0, reverse=True)
candidate_paths = [chain_path] + backups[:max_backups]
candidate_summaries = [summarize_chain(path) for path in candidate_paths]
current_summary = candidate_summaries[0]
log_min_height, log_max_height = log_height_bounds(repair_log)

candidate_blocks = []
pre_entry_rejections = []
for candidate_path, summary in zip(candidate_paths, candidate_summaries):
    if not summary.get("valid") or summary.get("empty"):
        pre_entry_rejections.append(
            {"path": str(candidate_path), "error": summary.get("error", "empty chain body")}
        )
        continue
    try:
        blocks = read_chain(candidate_path)
        validate_chain_shape(blocks)
        tip_height = block_height(blocks[-1])
        if target and target["height"] > tip_height:
            needed = tip_height + 1
            if (
                log_min_height is None
                or log_max_height is None
                or needed < log_min_height
                or needed > log_max_height
            ):
                raise ValueError(
                    f"committed block log cannot extend h{tip_height}: needs h{needed}, log range is h{log_min_height}..h{log_max_height}"
                )
        candidate_blocks.append(
            {"path": candidate_path, "blocks": blocks, "tip_height": tip_height}
        )
    except Exception as exc:
        pre_entry_rejections.append({"path": str(candidate_path), "error": str(exc)})

if target:
    min_entry_height = min(
        (
            candidate["tip_height"] + 1
            for candidate in candidate_blocks
            if target["height"] > candidate["tip_height"]
        ),
        default=None,
    )
    max_entry_height = target["height"] if min_entry_height is not None else None
else:
    min_entry_height = min(
        (candidate["tip_height"] + 1 for candidate in candidate_blocks),
        default=None,
    )
    max_entry_height = None

entries, malformed_log_lines = read_log_entries(repair_log, min_entry_height, max_entry_height)
all_entries, all_malformed_log_lines = read_log_entries(repair_log, log_min_height, log_max_height)


def materialize_from_candidate(candidate):
    path = candidate["path"]
    blocks = candidate["blocks"]
    if not blocks:
        return None

    first_height = block_height(blocks[0])
    if first_height > 0 and locks.get(first_height) != block_hash(blocks[0]):
        raise ValueError(
            f"compact boundary h{first_height} lacks matching canonical lock"
        )

    existing_by_height = {block_height(block): block for block in blocks}
    target_height = target["height"] if target else None
    tip = blocks[-1]
    expected = block_height(tip) + 1
    append_blocks = []
    appended = 0
    while expected in entries:
        next_block = entries[expected]
        if next_block.get("previous_hash") != block_hash(tip):
            raise ValueError(
                f"committed block log parent mismatch at h{expected}: {next_block.get('previous_hash')} != {block_hash(tip)}"
            )
        append_blocks.append(next_block)
        existing_by_height[expected] = next_block
        tip = next_block
        appended += 1
        expected += 1

    if target:
        target_block = existing_by_height.get(target_height)
        if target_block is None:
            raise ValueError(
                f"candidate cannot cover canonical lock h{target_height}; tip is h{block_height(tip)}"
            )
        if block_hash(target_block) != target["hash"]:
            raise ValueError(
                f"candidate target h{target_height} hash {block_hash(target_block)} does not match canonical lock {target['hash']}"
            )

    return {
        "source_path": str(path),
        "source_tip_height": block_height(blocks[-1]),
        "source_tip_hash": block_hash(blocks[-1]),
        "old_tip_height": current_summary.get("tip_height"),
        "new_tip_height": block_height(tip),
        "new_tip_hash": block_hash(tip),
        "appended_blocks": appended,
        "append_blocks": append_blocks,
        "source_is_current": path == chain_path,
    }


rejections = list(pre_entry_rejections)
selected = None
for candidate in candidate_blocks:
    try:
        materialized_candidate = materialize_from_candidate(candidate)
        if materialized_candidate is None:
            rejections.append({"path": str(candidate["path"]), "error": "empty chain body"})
            continue
        if selected is None or materialized_candidate["new_tip_height"] > selected["new_tip_height"]:
            selected = materialized_candidate
    except Exception as exc:
        rejections.append({"path": str(candidate["path"]), "error": str(exc)})

try:
    log_candidate = candidate_from_committed_block_log(all_entries, locks, target)
    if selected is None or log_candidate["new_tip_height"] > selected["new_tip_height"]:
        selected = log_candidate
except Exception as exc:
    rejections.append({"path": str(repair_log), "error": str(exc)})

metadata = {
    "canonical_target": target,
    "candidate_summaries": candidate_summaries,
    "candidate_rejections": rejections,
    "committed_block_log_min_height": log_min_height,
    "committed_block_log_max_height": log_max_height,
    "loaded_committed_block_min_height": min(entries) if entries else None,
    "loaded_committed_block_max_height": max(entries) if entries else None,
    "skipped_malformed_committed_block_log_lines": len(malformed_log_lines),
    "skipped_malformed_committed_block_log_line_samples": malformed_log_lines[:8],
    "skipped_malformed_all_committed_block_log_lines": len(all_malformed_log_lines),
    "skipped_malformed_all_committed_block_log_line_samples": all_malformed_log_lines[:8],
    "repair_log": str(repair_log),
}

if selected is None:
    print(
        json.dumps(
            {
                "chain_body_repaired": False,
                "dry_run": dry_run,
                "reason": "no current or backup chain body can cover canonical lock",
                "current_chain": current_summary,
                **metadata,
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)

would_replace_from_committed_block_log = (
    selected.get("source_kind") == "committed_block_log_retained_window"
)
would_replace_from_backup = (
    not selected["source_is_current"] and not would_replace_from_committed_block_log
)
would_append = selected["appended_blocks"] > 0
would_repair = (
    would_replace_from_backup or would_append or would_replace_from_committed_block_log
)
if dry_run:
    print(
        json.dumps(
            {
                "chain_body_repaired": False,
                "dry_run": True,
                "would_repair": would_repair,
                "would_replace_from_backup": would_replace_from_backup,
                "would_replace_from_committed_block_log": would_replace_from_committed_block_log,
                "would_write_checkpoint": would_replace_from_committed_block_log,
                "checkpoint_height": selected.get("checkpoint_height"),
                "checkpoint_hash": selected.get("checkpoint_hash"),
                "source_chain_path": selected["source_path"],
                "source_kind": selected.get("source_kind", "chain_body"),
                "old_tip_height": selected["old_tip_height"],
                "new_tip_height": selected["new_tip_height"],
                "new_tip_hash": selected["new_tip_hash"],
                "would_append_blocks": selected["appended_blocks"],
                **metadata,
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)

if not would_repair:
    print(
        json.dumps(
            {
                "chain_body_repaired": False,
                "dry_run": False,
                "reason": "current chain body already covers canonical lock",
                "source_chain_path": selected["source_path"],
                "old_tip_height": selected["old_tip_height"],
                "new_tip_height": selected["new_tip_height"],
                "new_tip_hash": selected["new_tip_hash"],
                **metadata,
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)

timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
backup_path = chain_path.with_name(
    f"chain.json.pre-body-repair-{timestamp}-{os.getpid()}"
)
shutil.copy2(chain_path, backup_path)
tmp_path = chain_path.with_name(f"chain.json.repair-tmp-{timestamp}-{os.getpid()}")
checkpoint_backup_path = None
if state_checkpoint_path.exists():
    checkpoint_backup_path = state_checkpoint_path.with_name(
        f"state_checkpoint.json.pre-body-repair-{timestamp}-{os.getpid()}"
    )
    shutil.copy2(state_checkpoint_path, checkpoint_backup_path)
if selected.get("source_kind") == "committed_block_log_retained_window":
    write_chain_file(chain_path, selected["full_blocks"])
    write_repair_checkpoint(selected["full_blocks"][0])
else:
    shutil.copy2(selected["source_path"], tmp_path)
    append_blocks_to_chain_file(tmp_path, selected["append_blocks"])
    os.replace(tmp_path, chain_path)
print(
    json.dumps(
        {
            "chain_body_repaired": True,
            "backup_path": str(backup_path),
            "checkpoint_backup_path": str(checkpoint_backup_path) if checkpoint_backup_path else None,
            "source_chain_path": selected["source_path"],
            "source_kind": selected.get("source_kind", "chain_body"),
            "replaced_from_backup": would_replace_from_backup,
            "replaced_from_committed_block_log": would_replace_from_committed_block_log,
            "checkpoint_path": str(state_checkpoint_path)
            if would_replace_from_committed_block_log
            else None,
            "checkpoint_height": selected.get("checkpoint_height"),
            "checkpoint_hash": selected.get("checkpoint_hash"),
            "old_tip_height": selected["old_tip_height"],
            "new_tip_height": selected["new_tip_height"],
            "new_tip_hash": selected["new_tip_hash"],
            "appended_blocks": selected["appended_blocks"],
            **metadata,
        },
        sort_keys=True,
    )
)
PY
