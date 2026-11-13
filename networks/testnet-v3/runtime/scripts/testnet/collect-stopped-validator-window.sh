#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/var/lib/synergy/validator}"
CONFIG_PATH="${CONFIG_PATH:-/etc/synergy/validator/config.toml}"
SERVICE="${SERVICE:-synergy-validator.service}"
QRPC_PORT="${SYNERGY_QRPC_PORT:-5640}"
TAIL_BYTES="${TAIL_BYTES:-67108864}"
TAIL_LINES="${TAIL_LINES:-2048}"
SAMPLE_LIMIT="${SAMPLE_LIMIT:-256}"
CANDIDATE_HEIGHTS="${CANDIDATE_HEIGHTS:-672063,672062,671910,671784,671641,650469,637015}"

run_python() {
  local script_path
  script_path="$(mktemp /tmp/synergy-stopped-state-window.XXXXXX.py)"
  cat > "$script_path"
  chmod 0600 "$script_path"
  trap 'rm -f "$script_path"' RETURN
  if sudo -n true >/dev/null 2>&1; then
    sudo -n env \
      ROOT="$ROOT" \
      CONFIG_PATH="$CONFIG_PATH" \
      SERVICE="$SERVICE" \
      QRPC_PORT="$QRPC_PORT" \
      TAIL_BYTES="$TAIL_BYTES" \
      TAIL_LINES="$TAIL_LINES" \
      SAMPLE_LIMIT="$SAMPLE_LIMIT" \
      CANDIDATE_HEIGHTS="$CANDIDATE_HEIGHTS" \
      SYNERGY_NODE="${SYNERGY_NODE:-}" \
      SYNERGY_SPREADSHEET_ROW="${SYNERGY_SPREADSHEET_ROW:-}" \
      python3 "$script_path"
    return
  fi
  if [[ -z "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]]; then
    echo "sudo unavailable and SYNERGY_REMOTE_SUDO_PASSWORD is not set" >&2
    return 1
  fi
  printf "%s\n" "$SYNERGY_REMOTE_SUDO_PASSWORD" | sudo -S -p "" env \
    ROOT="$ROOT" \
    CONFIG_PATH="$CONFIG_PATH" \
    SERVICE="$SERVICE" \
    QRPC_PORT="$QRPC_PORT" \
    TAIL_BYTES="$TAIL_BYTES" \
    TAIL_LINES="$TAIL_LINES" \
    SAMPLE_LIMIT="$SAMPLE_LIMIT" \
    CANDIDATE_HEIGHTS="$CANDIDATE_HEIGHTS" \
    SYNERGY_NODE="${SYNERGY_NODE:-}" \
    SYNERGY_SPREADSHEET_ROW="${SYNERGY_SPREADSHEET_ROW:-}" \
    python3 "$script_path"
}

run_python <<'PY'
from __future__ import annotations

import json
import os
import pwd
import grp
import re
import socket
import subprocess
import sys
from collections import deque
from pathlib import Path
from typing import Any


ROOT = Path(os.environ.get("ROOT", "/var/lib/synergy/validator"))
DATA = ROOT / "data"
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/etc/synergy/validator/config.toml"))
SERVICE = os.environ.get("SERVICE", "synergy-validator.service")
QRPC_PORT = int(os.environ.get("QRPC_PORT", "5640") or "5640")
TAIL_BYTES = int(os.environ.get("TAIL_BYTES", "67108864") or "67108864")
TAIL_LINES = int(os.environ.get("TAIL_LINES", "2048") or "2048")
SAMPLE_LIMIT = int(os.environ.get("SAMPLE_LIMIT", "256") or "256")
CANDIDATE_HEIGHTS = [
    int(raw)
    for raw in os.environ.get("CANDIDATE_HEIGHTS", "").replace(" ", "").split(",")
    if raw
]


def command_output(args: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return completed.returncode, completed.stdout.strip(), completed.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {' '.join(args)}"


def systemctl_value(args: list[str]) -> str:
    return command_output(["systemctl", *args])[1]


def qrpc_closed(port: int) -> dict[str, Any]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        result = sock.connect_ex(("127.0.0.1", port))
        return {"port": port, "closed": result != 0, "connect_ex": result}
    finally:
        sock.close()


def stat_path(path: Path) -> dict[str, Any]:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {"path": str(path), "exists": False}
    owner = str(st.st_uid)
    group = str(st.st_gid)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except KeyError:
        pass
    try:
        group = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        pass
    target = None
    if path.is_symlink():
        try:
            target = os.readlink(path)
        except OSError:
            target = None
    return {
        "path": str(path),
        "exists": True,
        "is_symlink": path.is_symlink(),
        "symlink_target": target,
        "is_dir": path.is_dir(),
        "is_file": path.is_file(),
        "mode": oct(st.st_mode & 0o777),
        "owner": owner,
        "group": group,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }


def value_height(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    for key in ("height", "block_height", "block_index", "number", "block_number"):
        raw = value.get(key)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    for nested_key in ("block", "header", "qc", "quorum_certificate", "certificate"):
        height = value_height(value.get(nested_key))
        if height is not None:
            return height
    votes = value.get("votes")
    if isinstance(votes, list):
        heights = [value_height(vote) for vote in votes if isinstance(vote, dict)]
        heights = [height for height in heights if height is not None]
        if heights:
            return max(heights)
    return None


def value_hash(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in (
        "hash",
        "block_hash",
        "qc_block_hash",
        "certified_block_hash",
        "committed_block_hash",
        "proposed_block_hash",
    ):
        raw = value.get(key)
        if isinstance(raw, str) and raw:
            return raw
    for nested_key in ("block", "header", "qc", "quorum_certificate", "certificate"):
        candidate = value_hash(value.get(nested_key))
        if candidate:
            return candidate
    votes = value.get("votes")
    if isinstance(votes, list):
        hashes = [value_hash(vote) for vote in votes if isinstance(vote, dict)]
        hashes = [candidate for candidate in hashes if candidate]
        if hashes and len(set(hashes)) == 1:
            return hashes[0]
    return None


def read_tail_text(path: Path, byte_limit: int) -> tuple[str, int | None]:
    if not path.is_file():
        return "", None
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - byte_limit))
        return handle.read().decode("utf-8", errors="ignore"), size


def parse_lock_fragment(fragment: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    pattern = re.compile(r'"(?P<height>\d+)"\s*:\s*(?P<value>\{[^{}]*\}|"[^"]+")')
    for match in pattern.finditer(fragment):
        raw_value = match.group("value")
        block_hash = None
        if raw_value.startswith('"'):
            block_hash = raw_value.strip('"')
        else:
            hash_match = re.search(
                r'"(?:block_hash|hash|qc_block_hash|committed_block_hash)"\s*:\s*"([^"]+)"',
                raw_value,
            )
            if hash_match:
                block_hash = hash_match.group(1)
        records.append({"height": int(match.group("height")), "hash": block_hash})
    records.sort(key=lambda item: item["height"])
    return records


def summarize_locks_window(path: Path) -> dict[str, Any]:
    text, size = read_tail_text(path, TAIL_BYTES)
    records = parse_lock_fragment(text)
    return {
        "path": str(path),
        "exists": path.is_file(),
        "size": size,
        "tail_bytes": min(size or 0, TAIL_BYTES) if size is not None else 0,
        "latest": records[-1] if records else None,
        "samples": records[-SAMPLE_LIMIT:],
        "candidate_matches": candidate_matches_locks(path),
    }


def parse_jsonl_lines(lines: list[str]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if ":" in stripped and stripped.split(":", 1)[0].isdigit():
            line_number_raw, stripped = stripped.split(":", 1)
            line_number = int(line_number_raw)
        else:
            line_number = None
        try:
            value = json.loads(stripped)
        except Exception:
            continue
        records.append({"line": line_number, "height": value_height(value), "hash": value_hash(value)})
    return records


def summarize_jsonl_window(path: Path) -> dict[str, Any]:
    text, size = read_tail_text(path, TAIL_BYTES)
    lines = text.splitlines()
    if len(lines) > TAIL_LINES:
        lines = lines[-TAIL_LINES:]
    records = parse_jsonl_lines(lines)
    return {
        "path": str(path),
        "exists": path.is_file(),
        "size": size,
        "tail_bytes": min(size or 0, TAIL_BYTES) if size is not None else 0,
        "latest": records[-1] if records else None,
        "max_height": max(
            (record for record in records if record.get("height") is not None),
            key=lambda item: item["height"],
            default=None,
        ),
        "samples": records[-SAMPLE_LIMIT:],
        "candidate_matches": candidate_matches_jsonl(path),
    }


def candidate_matches_locks(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or not CANDIDATE_HEIGHTS:
        return []
    height_group = "|".join(str(height) for height in sorted(set(CANDIDATE_HEIGHTS)))
    pattern = rf'"({height_group})"[[:space:]]*:[[:space:]]*(\{{[^}}]*\}}|"[^"]+")'
    rc, stdout, stderr = command_output(["grep", "-aEo", pattern, str(path)], timeout=25)
    records = parse_lock_fragment(stdout)
    return records if rc in (0, 1) else [{"error": stderr or f"grep exit {rc}"}]


def candidate_matches_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or not CANDIDATE_HEIGHTS:
        return []
    height_group = "|".join(str(height) for height in sorted(set(CANDIDATE_HEIGHTS)))
    pattern = rf'"(height|block_height|block_index)"[[:space:]]*:[[:space:]]*({height_group})([^0-9]|$)'
    rc, stdout, stderr = command_output(["grep", "-aEn", pattern, str(path)], timeout=25)
    if rc == 1:
        return []
    if rc not in (0, 1):
        return [{"error": stderr or f"grep exit {rc}"}]
    records = parse_jsonl_lines(stdout.splitlines())
    dedup: dict[tuple[int | None, str | None], dict[str, Any]] = {}
    for record in records:
        dedup[(record.get("height"), record.get("hash"))] = record
    return sorted(dedup.values(), key=lambda item: (item.get("height") or -1, item.get("hash") or ""))


def summarize_chain_window(path: Path) -> dict[str, Any]:
    text, size = read_tail_text(path, TAIL_BYTES)
    records: list[dict[str, Any]] = []
    for match in re.finditer(r'"block_index"\s*:\s*(\d+).*?"hash"\s*:\s*"([^"]+)"', text):
        records.append({"height": int(match.group(1)), "hash": match.group(2)})
    dedup: dict[int, dict[str, Any]] = {}
    for record in records:
        dedup[record["height"]] = record
    ordered = [dedup[height] for height in sorted(dedup)]
    return {
        "path": str(path),
        "exists": path.is_file(),
        "size": size,
        "tail_bytes": min(size or 0, TAIL_BYTES) if size is not None else 0,
        "latest": ordered[-1] if ordered else None,
        "samples": ordered[-SAMPLE_LIMIT:],
    }


service_state = systemctl_value(["is-active", SERVICE])
active_state = systemctl_value(["show", SERVICE, "-p", "ActiveState", "--value"])
sub_state = systemctl_value(["show", SERVICE, "-p", "SubState", "--value"])
main_pid = systemctl_value(["show", SERVICE, "-p", "MainPID", "--value"])
qrpc = qrpc_closed(QRPC_PORT)

report = {
    "node": os.environ.get("SYNERGY_NODE"),
    "spreadsheet_row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
    "generated_utc": command_output(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"])[1],
    "hostname": command_output(["hostname", "-f"])[1] or command_output(["hostname"])[1],
    "candidate_heights": CANDIDATE_HEIGHTS,
    "service": {
        "name": SERVICE,
        "is_active": service_state,
        "active_state": active_state,
        "sub_state": sub_state,
        "main_pid": main_pid,
    },
    "qrpc": qrpc,
    "paths": {
        "root": stat_path(ROOT),
        "data": stat_path(DATA),
        "config": stat_path(CONFIG_PATH),
        "old_validator_workspace": stat_path(Path.home() / "validator-workspace"),
    },
    "files": {
        name: stat_path(DATA / name)
        for name in (
            "chain.json",
            "canonical_locks.json",
            "committed_qcs.jsonl",
            "committed_blocks.jsonl",
            "consensus_vote_locks.json",
            "validator_registry.json",
            "state_checkpoint.json",
        )
    },
    "state": {
        "canonical_locks_window": summarize_locks_window(DATA / "canonical_locks.json"),
        "committed_qcs_window": summarize_jsonl_window(DATA / "committed_qcs.jsonl"),
        "committed_blocks_window": summarize_jsonl_window(DATA / "committed_blocks.jsonl"),
        "chain_window": summarize_chain_window(DATA / "chain.json"),
    },
}

gate_errors: list[str] = []
if service_state == "active" or active_state == "active" or (main_pid and main_pid != "0"):
    gate_errors.append("validator service is not stopped")
if not qrpc["closed"]:
    gate_errors.append("qRPC port is still accepting connections")
report["gate_errors"] = gate_errors

print(json.dumps(report, sort_keys=True))
if gate_errors:
    sys.exit(3)
PY
