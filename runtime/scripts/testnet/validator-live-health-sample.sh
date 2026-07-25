#!/usr/bin/env bash
set -uo pipefail

VALIDATOR_NAME="${VALIDATOR_NAME:-unknown-validator}"
SERVICE_NAME="${SERVICE_NAME:-synergy-validator.service}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/synergy/validator}"
OLD_WORKSPACE="${OLD_WORKSPACE:-/home/node/.synergy/testnet/nodes/validator-workspace}"
QRPC_PORT="${SYNERGY_QRPC_PORT:-5640}"
QRPC_TIMEOUT_SECONDS="${QRPC_TIMEOUT_SECONDS:-45}"

rsudo() {
  if command sudo -n "$@" >/tmp/synergy-live-health-sudo.out 2>/tmp/synergy-live-health-sudo.err; then
    cat /tmp/synergy-live-health-sudo.out
    return 0
  fi
  local rc out err
  rc=$?
  out="$(cat /tmp/synergy-live-health-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-live-health-sudo.err 2>/dev/null || true)"
  if [[ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]] && [[ "$err" =~ (password|a\ password\ is\ required) ]]; then
    if printf '%s\n' "$SYNERGY_REMOTE_SUDO_PASSWORD" | command sudo -S -p '' "$@" >/tmp/synergy-live-health-sudo.out 2>/tmp/synergy-live-health-sudo.err; then
      cat /tmp/synergy-live-health-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-live-health-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-live-health-sudo.err 2>/dev/null || true)"
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
    "$CONFIG_ROOT/node.toml" \
    "$CONFIG_ROOT/node.env" \
    "$CONFIG_ROOT/service.env" \
    "$CONFIG_ROOT/validator.env" \
    /etc/default/synergy-validator \
    /etc/sysconfig/synergy-validator
}

rpc_probe() {
  python3 - "$QRPC_PORT" "$QRPC_TIMEOUT_SECONDS" <<'PY' 2>/dev/null || true
import json, sys, time, urllib.request

port = sys.argv[1]
timeout = float(sys.argv[2])
methods = [
    "synergy_getLatestBlock",
    "synergy_getBlockNumber",
    "synergy_getCanonicalLock",
    "synergy_getPeerInfo",
    "synergy_getNodeStatus",
    "synergy_getConsensusForkStatus",
]
out = {}
for method in methods:
    started = time.time()
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            out[method] = {
                "elapsed_sec": round(time.time() - started, 3),
                "response": json.loads(resp.read().decode()),
            }
    except Exception as exc:
        out[method] = {
            "elapsed_sec": round(time.time() - started, 3),
            "error": str(exc),
        }
print(json.dumps(out, sort_keys=True))
PY
}

refs_text="$(old_refs || true)"
refs_count=0
if [[ -n "$refs_text" ]]; then
  refs_count="$(printf '%s\n' "$refs_text" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
fi

cat <<REPORT
# Validator Live Health Sample

validator: ${VALIDATOR_NAME}
generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname: $(hostname -f 2>/dev/null || hostname)

## Service

service_state: $(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)
service_show: $(rsudo systemctl show "$SERVICE_NAME" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr '\n' '|' || true)

## Processes

\`\`\`
$(ps -eo pid=,ppid=,comm=,args= | grep -E 'synergy-(validator|node)' | grep -v grep || true)
\`\`\`

## Listeners

\`\`\`
$(rsudo ss -ltnp 2>/dev/null | grep -E ':(5622|5640|5660|6030)\b' || true)
\`\`\`

## Old Workspace References

active_old_workspace_reference_count: ${refs_count}

\`\`\`
${refs_text:-none}
\`\`\`

## qRPC

\`\`\`json
$(rpc_probe)
\`\`\`

## Recent Journal Signals

\`\`\`
$(rsudo journalctl -u "$SERVICE_NAME" --since '15 min ago' --no-pager 2>/dev/null \
  | grep -Ei 'validator-workspace|permission denied|identity|key mismatch|mismatch|compact|canonical|panic|fatal|failed|error|quarantine|divergen|stall|consensus|propos|block' \
  | tail -160 || true)
\`\`\`
REPORT
