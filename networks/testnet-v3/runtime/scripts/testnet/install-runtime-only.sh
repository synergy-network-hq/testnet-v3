#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
workspace="${SYNERGY_WORKSPACE:-}"
runtime="${SYNERGY_RUNTIME:-/tmp/synergy-testnet-linux-amd64.v13.0.1}"
runtime_sha="${SYNERGY_RUNTIME_SHA:-f5a1cf5b96bd647ba8bf32a6372858c2e7a0e7bc66d8d129ab65c7461314d9d1}"
start_after="${SYNERGY_START_AFTER:-true}"
binary_name="${SYNERGY_BINARY_NAME:-synergy-testnet-linux-amd64}"
listener_wait_secs="${SYNERGY_LISTENER_WAIT_SECS:-240}"
listener_poll_secs="${SYNERGY_LISTENER_POLL_SECS:-2}"
rollback_on_health_fail="${SYNERGY_ROLLBACK_ON_HEALTH_FAIL:-false}"
rollback_wait_secs="${SYNERGY_ROLLBACK_WAIT_SECS:-$listener_wait_secs}"
health_max_block_age_secs="${SYNERGY_HEALTH_MAX_BLOCK_AGE_SECS:-45}"
fresh_vote_max_age_secs="${SYNERGY_FRESH_VOTE_MAX_AGE_SECS:-90}"
expected_active_validators="${SYNERGY_EXPECTED_ACTIVE_VALIDATORS:-}"
public_rpc_url="${SYNERGY_PUBLIC_RPC_URL:-}"
systemd_service="${SYNERGY_SYSTEMD_SERVICE:-}"

node_env_value() {
  local key="$1"
  local env_file="$workspace/node.env"
  [[ -f "$env_file" ]] || return 0
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$env_file"
}

listener_present() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  ss -ltn 2>/dev/null | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit found ? 0 : 1}'
}

workspace_processes() {
  local proc pid exe cwd cmd
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    pid="${proc##*/}"
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    [[ -n "$cmd" ]] || continue
    if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" || "$cmd" == *"$workspace"* ]]; then
      if [[ "$cmd" == *" start --config "* || "$exe" == "$binary" ]]; then
        printf '%s\t%s\t%s\t%s\n' "$pid" "$exe" "$cwd" "$cmd"
      fi
    fi
  done
}

query_latest_block() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  curl -fsS --max-time 5 \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}' \
    "http://127.0.0.1:${port}" >/dev/null
}

rpc_health_probe() {
  local port="$1"
  local out="$2"
  python3 - "$port" "$health_max_block_age_secs" "$expected_active_validators" "$validator_address" "$fresh_vote_max_age_secs" "$public_rpc_url" > "$out" <<'PY'
import json
import sys
import time
import urllib.request

port = sys.argv[1]
max_block_age = int(sys.argv[2] or "45")
expected_active = int(sys.argv[3]) if sys.argv[3].strip() else None
validator_address = sys.argv[4].strip()
fresh_vote_max_age = int(sys.argv[5] or "90")
public_rpc_url = sys.argv[6].strip()
local_url = f"http://127.0.0.1:{port}"
errors = []

def rpc(url, method, params=None, timeout=5):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }).encode()
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read().decode())
    if "error" in body:
        raise RuntimeError(f"{method} returned error: {body['error']}")
    return body.get("result")

try:
    latest = rpc(local_url, "synergy_getLatestBlock")
except Exception as exc:
    latest = None
    errors.append(f"local_latest_block_unavailable: {exc}")

try:
    health = rpc(local_url, "synergy_getHealth")
except Exception as exc:
    health = None
    errors.append(f"local_health_unavailable: {exc}")

try:
    validator_stats = rpc(local_url, "synergy_getValidatorStats")
except Exception as exc:
    validator_stats = None
    errors.append(f"local_validator_stats_unavailable: {exc}")

latest_height = latest.get("block_index") if isinstance(latest, dict) else None
latest_hash = latest.get("hash") if isinstance(latest, dict) else None
latest_timestamp = latest.get("timestamp") if isinstance(latest, dict) else None
timestamp_delta = None
if isinstance(latest_timestamp, (int, float)):
    timestamp_delta = int(time.time()) - int(latest_timestamp)
    if timestamp_delta > max_block_age:
        errors.append(f"local_latest_block_stale: age={timestamp_delta}s max={max_block_age}s")

if isinstance(health, dict):
    if health.get("status") not in {"healthy", "ok"}:
        errors.append(f"local_health_status={health.get('status')}")
    sync = health.get("sync") if isinstance(health.get("sync"), dict) else {}
    if sync.get("syncing") is True:
        errors.append("local_health_syncing=true")
else:
    sync = {}

active_items = []
active_count = None
total_count = None
if isinstance(validator_stats, dict):
    raw_active = validator_stats.get("active_validators")
    if isinstance(raw_active, list):
        active_items = raw_active
        active_count = len(raw_active)
    elif isinstance(raw_active, int):
        active_count = raw_active
    raw_total = validator_stats.get("total_validators")
    if isinstance(raw_total, int):
        total_count = raw_total

if expected_active is not None:
    if active_count != expected_active:
        errors.append(f"active_validator_count={active_count} expected={expected_active}")
    if total_count is not None and total_count != expected_active:
        errors.append(f"total_validator_count={total_count} expected={expected_active}")

target_vote = None
if validator_address and active_items:
    for item in active_items:
        if isinstance(item, dict) and item.get("address") == validator_address:
            target_vote = item
            break
    if target_vote is None:
        errors.append(f"validator_not_active_in_local_stats: {validator_address}")
    else:
        last_vote = target_vote.get("last_vote_timestamp") or target_vote.get("last_active")
        if isinstance(last_vote, (int, float)):
            vote_age = int(time.time()) - int(last_vote)
            if vote_age > fresh_vote_max_age:
                errors.append(
                    f"validator_vote_stale: address={validator_address} age={vote_age}s max={fresh_vote_max_age}s"
                )
        else:
            errors.append(f"validator_vote_timestamp_missing: {validator_address}")

public = None
if public_rpc_url and latest_height is not None and latest_hash:
    try:
        public_latest = rpc(public_rpc_url, "synergy_getLatestBlock", timeout=8)
        public_height = public_latest.get("block_index") if isinstance(public_latest, dict) else None
        public_hash = public_latest.get("hash") if isinstance(public_latest, dict) else None
        public = {
            "latest_height": public_height,
            "latest_hash": public_hash,
        }
        if isinstance(public_height, int) and public_height >= int(latest_height):
            public_at_local = rpc(public_rpc_url, "synergy_getBlockByNumber", [int(latest_height)], timeout=8)
            public_at_local_hash = public_at_local.get("hash") if isinstance(public_at_local, dict) else None
            public["hash_at_local_height"] = public_at_local_hash
            if public_at_local_hash != latest_hash:
                errors.append(
                    f"public_hash_mismatch_at_local_height: h{latest_height} local={latest_hash} public={public_at_local_hash}"
                )
        elif isinstance(public_height, int):
            errors.append(f"public_rpc_behind_local: public={public_height} local={latest_height}")
    except Exception as exc:
        errors.append(f"public_rpc_alignment_unavailable: {exc}")

report = {
    "ok": not errors,
    "errors": errors,
    "local_latest_height": latest_height,
    "local_latest_hash": latest_hash,
    "local_latest_age_seconds": timestamp_delta,
    "local_health_status": health.get("status") if isinstance(health, dict) else None,
    "local_sync_state": sync.get("state") if isinstance(sync, dict) else None,
    "active_validators": active_count,
    "total_validators": total_count,
    "expected_active_validators": expected_active,
    "validator_address": validator_address or None,
    "target_validator_vote": target_vote,
    "public_rpc": public,
}
print(json.dumps(report, sort_keys=True))
raise SystemExit(0 if not errors else 1)
PY
}

wait_for_runtime_health() {
  local wait_secs="$1"
  local probe_file="$2"
  local deadline
  deadline=$(( $(date +%s) + wait_secs ))
  while [[ $(date +%s) -le $deadline ]]; do
    process_count="$(workspace_processes | wc -l | tr -d ' ')"
    if [[ "$process_count" != "0" ]] \
      && listener_present "$p2p_port" \
      && listener_present "$qrpc_port" \
      && listener_present "$ws_port" \
      && query_latest_block "$qrpc_port" \
      && rpc_health_probe "$qrpc_port" "$probe_file"; then
      return 0
    fi
    sleep "$listener_poll_secs"
  done
  return 1
}

if [[ -z "$workspace" || ! -d "$workspace" ]]; then
  echo "unable to resolve workspace for $node" >&2
  exit 2
fi

binary="$workspace/bin/$binary_name"
qrpc_port="${SYNERGY_QRPC_PORT:-${SYNERGY_RPC_PORT:-${RPC_PORT:-$(node_env_value RPC_PORT)}}}"
ws_port="${SYNERGY_WS_PORT:-${WS_PORT:-$(node_env_value WS_PORT)}}"
p2p_port="${SYNERGY_P2P_PORT:-${P2P_PORT:-$(node_env_value P2P_PORT)}}"
metrics_port="${SYNERGY_METRICS_PORT:-${METRICS_PORT:-$(node_env_value METRICS_PORT)}}"
validator_address="${SYNERGY_VALIDATOR_ADDRESS:-${NODE_ADDRESS:-$(node_env_value VALIDATOR_ADDRESS)}}"
test -f "$runtime"
actual_runtime_sha="$(sha256sum "$runtime" | awk '{print $1}')"
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime checksum mismatch: $actual_runtime_sha" >&2
  exit 3
fi
chmod 755 "$runtime" 2>/dev/null || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="$HOME/synergy-testnet-state-backups"
backup="$backup_root/${ts}-${node// /_}-runtime"
mkdir -p "$backup/bin" "$backup/process" "$backup/logs" "$backup/listeners" "$backup/health"

workspace_processes > "$backup/process/before.tsv" || true
ss -ltnp > "$backup/listeners/before.txt" 2>/dev/null || true
if [[ -f "$binary" ]]; then
  cp -p "$binary" "$backup/bin/synergy-testnet-linux-amd64"
  sha256sum "$binary" > "$backup/bin/synergy-testnet-linux-amd64.sha256"
fi
for log_file in "$workspace/data/logs/node.out" "$workspace/data/logs/node.err"; do
  if [[ -f "$log_file" ]]; then
    cp -p "$log_file" "$backup/logs/$(basename "$log_file").before"
  fi
done

if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$systemd_service" || true
elif [[ -x "$workspace/nodectl.sh" ]]; then
  (cd "$workspace" && ./nodectl.sh stop) || true
fi
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  [[ -n "${pid:-}" ]] || continue
  kill "$pid" 2>/dev/null || true
done < <(workspace_processes)
sleep 2
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  [[ -n "${pid:-}" ]] || continue
  kill -9 "$pid" 2>/dev/null || true
done < <(workspace_processes)

cp "$runtime" "$binary"
chmod 755 "$binary"
installed_sha="$(sha256sum "$binary" | awk '{print $1}')"
if [[ "$installed_sha" != "$runtime_sha" ]]; then
  echo "installed runtime checksum mismatch: $installed_sha" >&2
  exit 4
fi

if [[ "$start_after" == "true" ]]; then
  if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl start "$systemd_service"
  elif [[ -x "$workspace/nodectl.sh" ]]; then
    (cd "$workspace" && ./nodectl.sh start)
  else
    mkdir -p "$workspace/logs"
    (cd "$workspace" && nohup "./bin/$binary_name" start --config config/node.toml >> logs/manual-v13-start.log 2>&1 &)
  fi
fi

health_ok=false
if [[ "$start_after" == "true" ]]; then
  if wait_for_runtime_health "$listener_wait_secs" "$backup/health/install.json"; then
    health_ok=true
  fi
fi

workspace_processes > "$backup/process/after.tsv" || true
ss -ltnp > "$backup/listeners/after.txt" 2>/dev/null || true
for log_file in "$workspace/data/logs/node.out" "$workspace/data/logs/node.err"; do
  if [[ -f "$log_file" ]]; then
    cp -p "$log_file" "$backup/logs/$(basename "$log_file").after"
  fi
done

if [[ "$start_after" == "true" && "$health_ok" != "true" ]]; then
  if [[ "$rollback_on_health_fail" == "true" && -f "$backup/bin/synergy-testnet-linux-amd64" ]]; then
    if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop "$systemd_service" || true
    elif [[ -x "$workspace/nodectl.sh" ]]; then
      (cd "$workspace" && ./nodectl.sh stop) || true
    fi
    cp "$backup/bin/synergy-testnet-linux-amd64" "$binary"
    chmod 755 "$binary"
    if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl start "$systemd_service" || true
    elif [[ -x "$workspace/nodectl.sh" ]]; then
      (cd "$workspace" && ./nodectl.sh start) || true
    fi
    if wait_for_runtime_health "$rollback_wait_secs" "$backup/health/rollback.json"; then
      echo "runtime health check failed; rollback restored backup runtime and passed post-rollback health gates backup=$backup" >&2
    else
      echo "runtime health check failed; rollback incomplete because post-rollback health gates failed backup=$backup" >&2
      exit 6
    fi
  else
    echo "runtime health check failed: p2p_port=$p2p_port qrpc_port=$qrpc_port ws_port=$ws_port wait_secs=$listener_wait_secs backup=$backup" >&2
  fi
  exit 5
fi

echo "spreadsheet_row_used=true row=$row node=$node workspace=$workspace binary=$binary_name backup=$backup installed_runtime_sha=$installed_sha start_after=$start_after health_ok=$health_ok health_probe=$backup/health/install.json p2p_port=$p2p_port qrpc_port=$qrpc_port ws_port=$ws_port metrics_port=$metrics_port expected_active_validators=${expected_active_validators:-dynamic} validator_address=${validator_address:-unknown} public_rpc_url=${public_rpc_url:-not_checked} systemd_service=$systemd_service"
