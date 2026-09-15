#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
support-node-snapshot-reseed-remote.sh

Generic remote-side support-node reseed helper. Run on the target support node
after a snapshot distribution bundle has been extracted locally on that host.

Required environment:
  SUPPORT_SERVICE              systemd service to stop/start
  SUPPORT_WORKDIR              node workspace root
  SUPPORT_SNAPSHOT_CLASS       support-relayer|support-rpc|support-observer|indexer-replay|indexer-full
  SUPPORT_TARGET_ROLE          relayer|rpc|observer|indexer

Optional environment:
  SUPPORT_DISTRIBUTION_DIR     directory containing distribution-manifest.json
  SUPPORT_TARGET_DATA_DIR      default: $SUPPORT_WORKDIR/data
  SUPPORT_RUNTIME_REL          default: bin/synergy-testnet-linux-amd64
  SUPPORT_RUNTIME_PATH         absolute runtime path override
  SUPPORT_CONFIG_REL           default: config/node.toml
  SUPPORT_CONFIG_PATH          absolute config path override
  SUPPORT_VERIFY_SOURCE_WORKSPACE default: $SUPPORT_WORKDIR
  SUPPORT_POST_RESTART_WAIT_SECS default: 45
  SUPPORT_METRICS_URL          default: http://127.0.0.1:6030/metrics
  PUBLIC_RPC_URL               default: https://testnet-core-rpc.synergy-network.io
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

service="${SUPPORT_SERVICE:?SUPPORT_SERVICE is required}"
workdir="${SUPPORT_WORKDIR:?SUPPORT_WORKDIR is required}"
snapshot_class="${SUPPORT_SNAPSHOT_CLASS:?SUPPORT_SNAPSHOT_CLASS is required}"
target_role="${SUPPORT_TARGET_ROLE:?SUPPORT_TARGET_ROLE is required}"
target_data_dir="${SUPPORT_TARGET_DATA_DIR:-${workdir%/}/data}"
runtime_rel="${SUPPORT_RUNTIME_REL:-bin/synergy-testnet-linux-amd64}"
config_rel="${SUPPORT_CONFIG_REL:-config/node.toml}"
runtime_path="${SUPPORT_RUNTIME_PATH:-${workdir%/}/${runtime_rel}}"
config_path="${SUPPORT_CONFIG_PATH:-${workdir%/}/${config_rel}}"
verify_source_workspace="${SUPPORT_VERIFY_SOURCE_WORKSPACE:-$workdir}"
post_wait_secs="${SUPPORT_POST_RESTART_WAIT_SECS:-45}"
metrics_url="${SUPPORT_METRICS_URL:-http://127.0.0.1:6030/metrics}"
public_rpc_url="${PUBLIC_RPC_URL:-https://testnet-core-rpc.synergy-network.io}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
receiver="${SUPPORT_SNAPSHOT_RECEIVER:-${script_dir}/manual-snapshot-receiver.sh}"
applier="${SUPPORT_SNAPSHOT_APPLIER:-${script_dir}/apply-verified-support-snapshot.sh}"
distribution_dir="${SUPPORT_DISTRIBUTION_DIR:-}"

safe_sudo() {
  if command -v sudo >/dev/null 2>&1; then
    sudo -n "$@" 2>/dev/null || sudo "$@" 2>/dev/null || "$@"
  else
    "$@"
  fi
}

json_rpc_block_number() {
  python3 - "$public_rpc_url" <<'PY' 2>/dev/null || true
import json
import sys
import urllib.request

url = sys.argv[1]
payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "synergy_getBlockNumber", "params": []}).encode()
request = urllib.request.Request(url, data=payload, headers={"content-type": "application/json"}, method="POST")
try:
    with urllib.request.urlopen(request, timeout=8) as response:
        body = json.loads(response.read().decode())
    print(body.get("result", ""))
except Exception:
    print("")
PY
}

metrics_summary() {
  python3 - "$metrics_url" "$public_rpc_url" <<'PY' 2>/dev/null || true
import json
import re
import sys
import time
import urllib.request

metrics_url, rpc_url = sys.argv[1], sys.argv[2]

def get_text(url):
    start = time.time()
    try:
        with urllib.request.urlopen(url, timeout=8) as response:
            return response.read().decode(errors="replace"), round(time.time() - start, 3), None
    except Exception as exc:
        return "", round(time.time() - start, 3), str(exc)

def rpc_block_number():
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "synergy_getBlockNumber", "params": []}).encode()
    request = urllib.request.Request(rpc_url, data=payload, headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read().decode())
        return body.get("result")
    except Exception as exc:
        return {"error": str(exc)}

text, elapsed, error = get_text(metrics_url)
result = {"metrics_url": metrics_url, "elapsed_sec": elapsed, "error": error}
if text:
    gauges = {}
    for name in [
        "synergy_chain_height",
        "synergy_chain_blocks_total",
        "synergy_chain_last_block_timestamp_seconds",
        "synergy_chain_last_block_age_seconds",
        "synergy_sync_in_progress",
        "synergy_sync_gap_blocks",
        "synergy_sync_progress_percent",
        "synergy_p2p_peers_connected",
        "synergy_p2p_best_validator_peer_height",
    ]:
        match = re.search(rf"^{re.escape(name)}\s+([-+0-9.eE]+)$", text, re.MULTILINE)
        if match:
            raw = match.group(1)
            try:
                value = float(raw)
                gauges[name] = int(value) if value.is_integer() else value
            except Exception:
                gauges[name] = raw
    result["gauges"] = gauges
rpc_height = rpc_block_number()
result["public_rpc_block_number"] = rpc_height
try:
    if isinstance(rpc_height, int) and "synergy_chain_height" in result.get("gauges", {}):
        result["height_lag"] = rpc_height - int(result["gauges"]["synergy_chain_height"])
except Exception:
    pass
print(json.dumps(result, sort_keys=True))
PY
}

if [[ -z "$distribution_dir" ]]; then
  distribution_dir="$(find "$script_dir" -maxdepth 2 -type f -name distribution-manifest.json -print -quit | xargs -r dirname)"
fi
if [[ -z "$distribution_dir" || ! -f "$distribution_dir/distribution-manifest.json" ]]; then
  echo "missing support snapshot distribution-manifest.json" >&2
  exit 2
fi
if [[ ! -x "$runtime_path" || ! -d "$workdir" || ! -d "$target_data_dir" ]]; then
  echo "runtime, workdir, or target data dir is not accessible" >&2
  exit 3
fi
if [[ ! -x "$receiver" || ! -x "$applier" ]]; then
  echo "receiver or applier script is not executable" >&2
  exit 4
fi

case "$snapshot_class:$target_role" in
  support-relayer:relayer|support-rpc:rpc|support-observer:observer|indexer-replay:indexer|indexer-full:indexer) ;;
  *) echo "snapshot class $snapshot_class is not compatible with target role $target_role" >&2; exit 5 ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="/opt/synergy/backups/support-node-snapshot-reseed-${target_role}-${timestamp}"
extract_root="${backup_root}/extracted"
evidence_path="${backup_root}/evidence"
rollback_path="${backup_root}/rollback"

echo "# Support Node Snapshot Reseed"
echo
echo "service: ${service}"
echo "workdir: ${workdir}"
echo "verify_source_workspace: ${verify_source_workspace}"
echo "target_data_dir: ${target_data_dir}"
echo "snapshot_class: ${snapshot_class}"
echo "target_role: ${target_role}"
echo "distribution_dir: ${distribution_dir}"
echo "generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "hostname: $(hostname -f 2>/dev/null || hostname)"
echo "backup_root: ${backup_root}"
echo

safe_sudo mkdir -p "$backup_root" "$extract_root" "$evidence_path" "$rollback_path"

echo "## Before"
echo '~~~text'
systemctl is-active "$service" 2>/dev/null | sed 's/^/active=/' || true
systemctl show "$service" -p ActiveState -p SubState -p MainPID -p WorkingDirectory -p ExecStart -p FragmentPath -p DropInPaths --no-pager 2>/dev/null || true
sha256sum "$runtime_path" 2>/dev/null || true
"$runtime_path" --version 2>/dev/null || true
find "$target_data_dir" -maxdepth 1 -type f \( -name 'chain.json' -o -name 'canonical_locks.json' -o -name 'committed_blocks.jsonl' -o -name 'committed_qcs.jsonl' -o -name 'validator_registry.json' -o -name 'token_state.json' \) -printf '%p %s bytes\n' 2>/dev/null | sort || true
metrics_summary
echo '~~~'
echo

echo "## Backup"
echo '~~~text'
fragment="$(systemctl show "$service" -p FragmentPath --value 2>/dev/null || true)"
dropins="$(systemctl show "$service" -p DropInPaths --value 2>/dev/null || true)"
if [[ -n "$fragment" && -e "$fragment" ]]; then
  safe_sudo mkdir -p "${backup_root}/systemd"
  safe_sudo cp -a "$fragment" "${backup_root}/systemd/$(basename "$fragment")"
fi
for path in $dropins "$config_path" "${workdir%/}/node.env"; do
  [[ -n "$path" && -e "$path" ]] || continue
  safe_sudo mkdir -p "${backup_root}/preflight/$(dirname "${path#/}")"
  safe_sudo cp -a "$path" "${backup_root}/preflight/${path#/}"
done
find "$backup_root" -maxdepth 5 -type f -printf '%p\n' 2>/dev/null | sort || true
echo '~~~'
echo

echo "## Stop Service"
echo '~~~text'
safe_sudo systemctl stop "$service"
sleep 3
systemctl is-active "$service" 2>/dev/null | sed 's/^/active=/' || true
if systemctl is-active --quiet "$service"; then
  echo "target service still active after stop" >&2
  exit 6
fi
echo '~~~'
echo

echo "## Receive And Verify Snapshot"
echo '~~~text'
receiver_args=(
  --input "$distribution_dir"
  --snapshot-class "$snapshot_class"
  --target-role "$target_role"
  --extract-root "$extract_root"
  --runtime "$runtime_path"
  --source-workspace "$verify_source_workspace"
)
if [[ -f "$config_path" ]]; then
  receiver_args+=(--source-config "$config_path")
fi
bash "$receiver" "${receiver_args[@]}" | tee "${evidence_path}/receiver.log"
echo '~~~'
echo

snapshot_root="$(find "$extract_root" -maxdepth 2 -type f -name '*manifest.json' -print -quit | xargs -r dirname)"
if [[ -z "$snapshot_root" || ! -d "$snapshot_root" ]]; then
  echo "receiver did not extract a snapshot root" >&2
  exit 7
fi

echo "## Apply Snapshot"
echo '~~~text'
bash "$applier" \
  --distribution-manifest "$distribution_dir/distribution-manifest.json" \
  --snapshot-root "$snapshot_root" \
  --snapshot-class "$snapshot_class" \
  --target-role "$target_role" \
  --target-data-dir "$target_data_dir" \
  --evidence-path "$evidence_path" \
  --rollback-path "$rollback_path" \
  --confirm-target-stopped | tee "${evidence_path}/apply.log"
owner_group="$(stat -c '%U:%G' "$target_data_dir" 2>/dev/null || true)"
if [[ -n "$owner_group" ]]; then
  for file in chain.json canonical_locks.json canonical_locks.jsonl committed_blocks.jsonl committed_qcs.json committed_qcs.jsonl dag_state.json validator_registry.json token_state.json synid_registry.json account_state.json state_checkpoint.json; do
    [[ -e "$target_data_dir/$file" ]] || continue
    safe_sudo chown "$owner_group" "$target_data_dir/$file" 2>/dev/null || true
  done
fi
find "$target_data_dir" -maxdepth 1 -type f \( -name 'chain.json' -o -name 'canonical_locks.json' -o -name 'committed_blocks.jsonl' -o -name 'committed_qcs.jsonl' -o -name 'validator_registry.json' -o -name 'token_state.json' \) -printf '%p %s bytes\n' 2>/dev/null | sort || true
echo '~~~'
echo

echo "## Restart"
echo '~~~text'
safe_sudo systemctl daemon-reload
safe_sudo systemctl start "$service"
sleep "$post_wait_secs"
systemctl is-active "$service" 2>/dev/null | sed 's/^/active=/' || true
systemctl show "$service" -p ActiveState -p SubState -p MainPID -p WorkingDirectory -p ExecStart --no-pager 2>/dev/null || true
echo '~~~'
echo

echo "## After"
echo '~~~text'
sha256sum "$runtime_path" 2>/dev/null || true
"$runtime_path" --version 2>/dev/null || true
(ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true) | grep -Ei 'synergy|observer|relayer|rpc|indexer|:562|:564|:566|:6030|:6031|:80|:443|:9090|:9100' || true
echo '--- validator-workspace refs ---'
grep -RIn --exclude='*.log' --exclude='*.jsonl' 'validator-workspace' "$fragment" ${dropins:-} "${workdir%/}/config" /etc/default /etc/sysconfig 2>/dev/null || true
echo '--- metrics summary ---'
metrics_summary
echo '--- recent logs ---'
journalctl -u "$service" --since "5 minutes ago" -n 160 --no-pager 2>/dev/null \
  | grep -Ei 'error|warn|panic|fatal|failed|started|listening|connected|sync|block|height|peer|observer|relay|rpc|indexer' \
  | tail -160 || true
echo '~~~'
echo
echo "support_node_snapshot_reseed_complete=true backup_root=$backup_root"
