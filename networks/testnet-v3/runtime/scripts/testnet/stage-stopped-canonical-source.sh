#!/usr/bin/env bash
set -euo pipefail

ROOT="${ROOT:-/var/lib/synergy/validator}"
SERVICE="${SERVICE:-synergy-validator.service}"
QRPC_PORT="${SYNERGY_QRPC_PORT:-5640}"
SOURCE_DIR="${SOURCE_DIR:-}"
EXPECTED_HEIGHT="${EXPECTED_HEIGHT:-}"
EXPECTED_HASH="${EXPECTED_HASH:-}"
ALLOWLIST="${ALLOWLIST:-chain.json committed_blocks.jsonl canonical_locks.json committed_qcs.json committed_qcs.jsonl dag_state.json token_state.json account_state.json validator_registry.json synid_registry.json state_checkpoint.json state_checkpoint.recovery_manifest.json}"

if [[ -z "$SOURCE_DIR" ]]; then
  echo "SOURCE_DIR is required" >&2
  exit 2
fi

rsudo() {
  if sudo -n "$@" >/tmp/synergy-stage-source-sudo.out 2>/tmp/synergy-stage-source-sudo.err; then
    cat /tmp/synergy-stage-source-sudo.out
    return 0
  fi
  local rc out err
  rc=$?
  out="$(cat /tmp/synergy-stage-source-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-stage-source-sudo.err 2>/dev/null || true)"
  if [[ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]] && printf "%s" "$err" | grep -Eiq "password|a password is required"; then
    if printf "%s\n" "$SYNERGY_REMOTE_SUDO_PASSWORD" | sudo -S -p "" "$@" >/tmp/synergy-stage-source-sudo.out 2>/tmp/synergy-stage-source-sudo.err; then
      cat /tmp/synergy-stage-source-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-stage-source-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-stage-source-sudo.err 2>/dev/null || true)"
  fi
  [[ -n "$out" ]] && printf "%s\n" "$out"
  [[ -n "$err" ]] && printf "%s\n" "$err" >&2
  return "$rc"
}

rpc_closed() {
  python3 - "$QRPC_PORT" <<'PY'
import socket, sys
port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    rc = sock.connect_ex(("127.0.0.1", port))
finally:
    sock.close()
print("closed=true" if rc != 0 else "closed=false")
raise SystemExit(0 if rc != 0 else 1)
PY
}

SOURCE_DATA="$ROOT/data"
TMP_SOURCE="${SOURCE_DIR}.tmp-$(date -u +%Y%m%dT%H%M%SZ)-$$"

echo "## Stopped Canonical Source Gate"
echo
echo '~~~text'
echo "node=${SYNERGY_NODE:-}"
echo "source_data=$SOURCE_DATA"
echo "source_dir=$SOURCE_DIR"
echo "tmp_source=$TMP_SOURCE"
echo "expected_height=$EXPECTED_HEIGHT"
echo "expected_hash=$EXPECTED_HASH"
echo "service_state=$(rsudo systemctl is-active "$SERVICE" 2>/dev/null || true)"
echo "qrpc_$(rpc_closed || true)"
echo '~~~'
echo

service_state="$(rsudo systemctl is-active "$SERVICE" 2>/dev/null || true)"
if [[ "$service_state" == "active" ]]; then
  echo "blocked=service_active"
  exit 3
fi
if ! rpc_closed >/dev/null; then
  echo "blocked=qrpc_open"
  exit 3
fi
if [[ -e "$SOURCE_DIR" ]]; then
  echo "blocked=source_dir_exists"
  exit 1
fi

echo "## Source File Inventory"
echo
echo '~~~text'
for name in $ALLOWLIST; do
  rsudo sh -c 'if [ -f "$1/$2" ]; then stat -c "%n %s %U:%G %a" "$1/$2"; else echo "missing $2"; fi' sh "$SOURCE_DATA" "$name" 2>/dev/null || true
done
echo '~~~'
echo

echo "## Source Tip Probe"
echo
echo '~~~json'
rsudo python3 - "$SOURCE_DATA" "$EXPECTED_HEIGHT" "$EXPECTED_HASH" <<'PY'
import json
import sys
from pathlib import Path

data = Path(sys.argv[1])
expected_height = int(sys.argv[2]) if sys.argv[2] else None
expected_hash = sys.argv[3].lower() if sys.argv[3] else None

def height_hash(value):
    if not isinstance(value, dict):
        return None, None
    block = value.get("block") if isinstance(value.get("block"), dict) else {}
    height = value.get("height") or value.get("block_height") or value.get("block_index")
    if height is None:
        height = block.get("height") or block.get("block_height") or block.get("block_index")
    block_hash = value.get("hash") or value.get("block_hash") or block.get("hash") or block.get("block_hash")
    return (int(height) if height is not None else None), (str(block_hash).lower() if block_hash else None)

def last_jsonl(path):
    with path.open("rb") as handle:
        handle.seek(0, 2)
        pos = handle.tell()
        buffer = b""
        while pos > 0:
            step = min(1024 * 1024, pos)
            pos -= step
            handle.seek(pos)
            buffer = handle.read(step) + buffer
            lines = [line for line in buffer.splitlines() if line.strip()]
            if len(lines) >= 2 or pos == 0:
                return json.loads(lines[-1].decode("utf-8", "ignore"))
    raise RuntimeError(f"{path} is empty")

def lock_hash(path, height):
    if height is None:
        return None
    key = f'"{height}"'
    text = path.read_text(encoding="utf-8", errors="ignore")
    index = text.find(key)
    if index < 0:
        return None
    window = text[index:index + 512]
    for marker in ('"block_hash"', '"hash"', '"qc_block_hash"'):
        marker_index = window.find(marker)
        if marker_index >= 0:
            quote = window.find('"', marker_index + len(marker))
            quote = window.find('"', quote + 1)
            end = window.find('"', quote + 1)
            if quote >= 0 and end >= 0:
                return window[quote + 1:end].lower()
    return None

committed_block = last_jsonl(data / "committed_blocks.jsonl")
height, block_hash = height_hash(committed_block)
lock = lock_hash(data / "canonical_locks.json", height)
result = {
    "committed_blocks_tip": {"height": height, "hash": block_hash},
    "canonical_lock_at_tip": lock,
    "expected_height": expected_height,
    "expected_hash": expected_hash,
    "ok": True,
    "errors": [],
}
if expected_height is not None and height != expected_height:
    result["errors"].append(f"height {height} != expected {expected_height}")
if expected_hash and block_hash != expected_hash:
    result["errors"].append(f"hash {block_hash} != expected {expected_hash}")
if lock and block_hash and lock != block_hash:
    result["errors"].append(f"lock {lock} != block {block_hash}")
result["ok"] = not result["errors"]
print(json.dumps(result, sort_keys=True))
raise SystemExit(0 if result["ok"] else 1)
PY
echo '~~~'
echo

echo "## Source Directory Creation"
echo
echo '~~~text'
rsudo rm -rf "$TMP_SOURCE"
rsudo mkdir -p "$TMP_SOURCE"
copied=0
for name in $ALLOWLIST; do
  if rsudo sh -c 'test -f "$1/$2"' sh "$SOURCE_DATA" "$name"; then
    if ! rsudo cp -a --reflink=auto --sparse=always "$SOURCE_DATA/$name" "$TMP_SOURCE/$name" 2>/tmp/synergy-stage-source-copy.err; then
      cat /tmp/synergy-stage-source-copy.err 2>/dev/null || true
      rsudo cp -a "$SOURCE_DATA/$name" "$TMP_SOURCE/$name"
    fi
    copied=$((copied + 1))
  fi
done
rsudo find "$TMP_SOURCE" -maxdepth 1 -type f -printf '%f\t%s bytes\n' 2>/dev/null | sort || true
rsudo mv "$TMP_SOURCE" "$SOURCE_DIR"
rsudo chmod -R a+rX "$SOURCE_DIR"
echo "copied_files=$copied"
echo "source_dir_du=$(rsudo du -sh "$SOURCE_DIR" 2>/dev/null || true)"
echo "service_after=$(rsudo systemctl is-active "$SERVICE" 2>/dev/null || true)"
echo '~~~'
