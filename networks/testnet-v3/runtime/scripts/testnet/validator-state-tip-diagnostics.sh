#!/usr/bin/env bash
set -uo pipefail

VALIDATOR_NAME="${VALIDATOR_NAME:-unknown-validator}"
SERVICE_NAME="${SERVICE_NAME:-synergy-validator.service}"
APPLIANCE_ROOT="${APPLIANCE_ROOT:-/var/lib/synergy/validator}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/synergy/validator}"
OLD_WORKSPACE="${OLD_WORKSPACE:-/home/node/.synergy/testnet/nodes/validator-workspace}"
QRPC_PORT="${SYNERGY_QRPC_PORT:-5640}"
QRPC_TIMEOUT_SECONDS="${QRPC_TIMEOUT_SECONDS:-8}"

rsudo() {
  if command sudo -n "$@" >/tmp/synergy-tip-diag-sudo.out 2>/tmp/synergy-tip-diag-sudo.err; then
    cat /tmp/synergy-tip-diag-sudo.out
    return 0
  fi
  local rc out err
  rc=$?
  out="$(cat /tmp/synergy-tip-diag-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-tip-diag-sudo.err 2>/dev/null || true)"
  if [[ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]] && [[ "$err" =~ (password|a\ password\ is\ required) ]]; then
    if printf '%s\n' "$SYNERGY_REMOTE_SUDO_PASSWORD" | command sudo -S -p '' "$@" >/tmp/synergy-tip-diag-sudo.out 2>/tmp/synergy-tip-diag-sudo.err; then
      cat /tmp/synergy-tip-diag-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-tip-diag-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-tip-diag-sudo.err 2>/dev/null || true)"
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  [[ -n "$err" ]] && printf '%s\n' "$err" >&2
  return "$rc"
}

old_refs() {
  rsudo sh -c '
old="$1"
shift
for root in "$@"; do
  [ -e "$root" ] || [ -L "$root" ] || continue
  grep -RInF "$old" "$root" 2>/dev/null || true
done
' sh "$OLD_WORKSPACE" \
    /etc/systemd/system/synergy-validator.service \
    /etc/systemd/system/synergy-validator.service.d \
    "$CONFIG_ROOT/config.toml" \
    "$CONFIG_ROOT/node.env" \
    "$CONFIG_ROOT/service.env" \
    "$CONFIG_ROOT/validator.env" \
    /etc/default/synergy-validator \
    /etc/sysconfig/synergy-validator
}

rpc_snapshot() {
  python3 - "$QRPC_PORT" "$QRPC_TIMEOUT_SECONDS" <<'PY' 2>/dev/null || true
import json, sys, urllib.request
port = sys.argv[1]
timeout = float(sys.argv[2])
methods = ["synergy_getBlockNumber", "synergy_getLatestBlock", "synergy_getCanonicalLock", "synergy_getNodeStatus"]
out = {}
for method in methods:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", data=payload, headers={"content-type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out[method] = json.loads(resp.read().decode())
    except Exception as exc:
        out[method] = {"error": str(exc)}
print(json.dumps(out, sort_keys=True))
PY
}

state_tip_json() {
  rsudo python3 - "$APPLIANCE_ROOT" <<'PY'
import json, os, re, sys
from pathlib import Path

root = Path(sys.argv[1])
data = root / "data"

def file_state(path):
    try:
        st = path.stat()
        return {"exists": True, "size_bytes": st.st_size, "mode": oct(st.st_mode & 0o777)}
    except FileNotFoundError:
        return {"exists": False}

def tail_text(path, size=64 * 1024 * 1024):
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        length = handle.tell()
        handle.seek(max(0, length - size))
        return handle.read().decode("utf-8", "ignore")

def chain_tip(path):
    info = file_state(path)
    if not info.get("exists"):
        return info
    text = tail_text(path)
    matches = re.findall(r'"block_index"\s*:\s*(\d+).*?"hash"\s*:\s*"([0-9a-fA-F]{64})"', text, re.S)
    info["tip_height"] = int(matches[-1][0]) if matches else None
    info["tip_hash"] = matches[-1][1].lower() if matches else None
    return info

def committed_blocks_tail(path):
    info = file_state(path)
    if not info.get("exists"):
        return info
    text = tail_text(path)
    first = None
    last = None
    count = 0
    contiguous_from_first = True
    previous = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        height = item.get("height")
        block = item.get("block") or {}
        block_hash = item.get("hash") or block.get("hash")
        if height is None:
            height = block.get("block_index")
        if height is None or block_hash is None:
            continue
        height = int(height)
        if first is None:
            first = {"height": height, "hash": str(block_hash).lower()}
        if previous is not None and height != previous + 1:
            contiguous_from_first = False
        previous = height
        last = {"height": height, "hash": str(block_hash).lower()}
        count += 1
    info.update({"tail_entries_parsed": count, "tail_first": first, "tail_last": last, "tail_contiguous_from_first": contiguous_from_first})
    return info

def canonical_locks(path):
    info = file_state(path)
    if not info.get("exists"):
        return info
    text = tail_text(path)
    pairs = re.findall(r'"(\d+)"\s*:\s*\{.*?"(?:block_hash|hash)"\s*:\s*"([0-9a-fA-F]{64})"', text, re.S)
    if pairs:
        height, block_hash = max(((int(h), b.lower()) for h, b in pairs), key=lambda item: item[0])
        info.update({"max_height": height, "max_hash": block_hash, "tail_locks_parsed": len(pairs)})
    else:
        info.update({"max_height": None, "max_hash": None, "tail_locks_parsed": 0})
    return info

def qc_tail(path):
    info = file_state(path)
    if not info.get("exists"):
        return info
    text = tail_text(path)
    last = None
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue
        qc = item.get("qc") or item
        votes = qc.get("votes") or []
        heights = []
        for vote in votes:
            if isinstance(vote, dict):
                value = vote.get("block_index") or vote.get("height") or vote.get("block_height")
                if value is not None:
                    heights.append(int(value))
        height = max(heights) if heights else qc.get("height") or qc.get("block_height") or item.get("height")
        block_hash = qc.get("block_hash") or qc.get("hash") or item.get("hash")
        if height and block_hash:
            last = {"height": int(height), "hash": str(block_hash).lower()}
            count += 1
    info.update({"tail_entries_parsed": count, "tail_last": last})
    return info

payload = {
    "appliance_root": str(root),
    "data_chain": chain_tip(data / "chain.json"),
    "root_chain": chain_tip(root / "chain.json"),
    "data_committed_blocks": committed_blocks_tail(data / "committed_blocks.jsonl"),
    "root_committed_blocks": committed_blocks_tail(root / "committed_blocks.jsonl"),
    "data_canonical_locks": canonical_locks(data / "canonical_locks.json"),
    "root_canonical_locks": canonical_locks(root / "canonical_locks.json"),
    "data_committed_qcs": qc_tail(data / "committed_qcs.jsonl"),
    "root_committed_qcs": qc_tail(root / "committed_qcs.jsonl"),
    "state_checkpoint": file_state(data / "state_checkpoint.json"),
    "consensus_vote_locks": file_state(data / "consensus_vote_locks.json"),
}
print(json.dumps(payload, indent=2, sort_keys=True))
PY
}

refs_text="$(old_refs || true)"
refs_count=0
if [[ -n "$refs_text" ]]; then
  refs_count="$(printf '%s\n' "$refs_text" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
fi

cat <<REPORT
# Validator State Tip Diagnostics

validator: ${VALIDATOR_NAME}
generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname: $(hostname -f 2>/dev/null || hostname)

## Service

service_state: $(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)
service_show: $(rsudo systemctl show "$SERVICE_NAME" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr '\n' '|' || true)

## Listeners

\`\`\`
$(rsudo ss -ltnp 2>/dev/null | grep -E ':(5622|5640|5660|6030)\b' || true)
\`\`\`

## Old Workspace References

active_old_workspace_reference_count: ${refs_count}

\`\`\`
${refs_text:-none}
\`\`\`

## qRPC Short Snapshot

\`\`\`json
$(rpc_snapshot)
\`\`\`

## Disk State Tips

\`\`\`json
$(state_tip_json)
\`\`\`

## Recent Journal Tail

\`\`\`
$(rsudo journalctl -u "$SERVICE_NAME" --since '20 min ago' --no-pager 2>/dev/null \
  | grep -Ei 'proposal height|does not extend|received block|blocks applied|sync|consensus|panic|fatal|permission denied|validator-workspace|state is busy' \
  | tail -180 || true)
\`\`\`
REPORT
