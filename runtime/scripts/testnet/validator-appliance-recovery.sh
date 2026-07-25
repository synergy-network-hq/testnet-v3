#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  validator-appliance-recovery.sh quorum-proof --nodes <validator-a>,<validator-b>,<validator-c> --heights <height-a>,<height-b> [--output <report.md>]
  validator-appliance-recovery.sh status --target <validator> [--output <report.md>]
  validator-appliance-recovery.sh stop --target <validator> [--execute] [--output <report.md>]
  validator-appliance-recovery.sh start --target <validator> [--execute] [--output <report.md>]
  validator-appliance-recovery.sh quarantine --target <validator> --quorum-height <height> --quorum-hash <hash> [--reason <text>] [--stop-target] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh transient-lock-recovery --target <validator> --finalized-height <height> [--min-age-secs <seconds>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh rejoin-eligibility --target <validator> [--output <report.md>]
  validator-appliance-recovery.sh request-rejoin --target <validator> --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation --operator-approved-rejoin [--operator-approved-emergency-leader-stall-recovery] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh promote-vote-only-to-active --target <validator> [--execute] [--output <report.md>]
  validator-appliance-recovery.sh emergency-promote-leader-stall-to-active --target <validator> --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation --operator-approved-emergency-leader-stall-recovery [--execute] [--output <report.md>]
  validator-appliance-recovery.sh wait-promote-vote-only-to-active --target <validator> --rejoin-height <height> [--probation-blocks <blocks>] [--public-rpc <url>] [--poll-secs <seconds>] [--max-wait-secs <seconds>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh mesh-reconnect --target <validator> [--validator-address <address>] [--sample-blocks <blocks>] [--restart-wait-secs <seconds>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh state-diagnostics --target <validator> [--output <report.md>]
  validator-appliance-recovery.sh chain-body-repair --target <validator> [--restart-target] [--restart-wait-secs <seconds>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh install-runtime --target <validator> --runtime <local-binary> --runtime-sha <sha256> [--remote-runtime /opt/synergy/bin/synergy-validator] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh install-node-tool --target <validator> --tool <local-binary> [--tool-sha <sha256>] [--remote-tool /opt/synergy/bin/synergy-node] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh rollback-runtime --target <validator> [--backup-dir <remote-backup-dir>] [--remote-runtime /opt/synergy/bin/synergy-validator] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh repair-permissions --target <validator> [--restart-target] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh create-cold-restore-source --target <validator> [--remote-bundle <remote-tar>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh create-cold-restore-source-dir --target <validator> [--remote-source-dir <remote-dir>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh transfer-cold-restore-source --source <validator> --target <validator> --remote-bundle <source-remote-tar> [--target-remote-bundle <target-remote-tar>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh cold-canonical-restore --target <validator> (--remote-bundle <remote-tar> | --remote-source-dir <remote-dir>) [--expected-source-tip-height <height>] [--expected-source-tip-hash <hash>] [--skip-helper-verify] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh create-snapshot --target <validator> [--conflict-height-hash <hash>] [--execute] [--output <report.md>]
  validator-appliance-recovery.sh snapshot-repair --target <validator> --manifest <remote-manifest> [--snapshot-root <remote-root>] [--execute] [--output <report.md>]

Generic validator appliance recovery helper.

This helper is intentionally node-agnostic. It uses workbook-backed access
through scripts/testnet/spreadsheet_host_access.py and supported runtime
commands. It does not hand-edit consensus JSON/JSONL files. Cold restore copies
only an explicit verified state allowlist and preserves target identity/config.

Global option:
  --workbook <xlsx>   Default: /Users/devpup/Desktop/node-machine-credentials.xlsx

Mutation phases require --execute. Without --execute they print the intended
runtime command and current gates only.
USAGE
}

phase="${1:-}"
if [[ -z "$phase" || "$phase" == "--help" || "$phase" == "-h" ]]; then
  usage
  exit 0
fi
shift || true

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
access_py="$repo_root/scripts/testnet/spreadsheet_host_access.py"
workbook_path="${SYNERGY_NODE_MACHINE_CREDENTIALS:-/Users/devpup/Desktop/node-machine-credentials.xlsx}"
output=""
target=""
source=""
nodes=""
heights=""
quorum_height=""
quorum_hash=""
common_height=""
common_hash=""
local_conflicting_height=""
local_conflicting_hash=""
conflict_height_hash=""
finalized_height=""
rejoin_height=""
min_age_secs="0"
probation_blocks="1000"
public_rpc_url="${SYNERGY_PUBLIC_RPC_URL:-https://testnet-core-rpc.synergy-network.io}"
poll_secs="30"
max_wait_secs="1800"
reason="operator_approved_stopped_validator_quarantine"
stop_target=false
restart_target=false
execute=false
exact_common_height_match=false
latest_finalized_qc_aegis_pqc_verified=false
state_root_matches=false
rejoin_at_finalized_safe_boundary=false
cluster_marks_pending_reactivation=false
operator_approved_rejoin=false
operator_approved_reactivation=false
operator_approved_emergency_leader_stall_recovery=false
skip_helper_verify=false
manifest=""
snapshot_root=""
remote_bundle=""
target_remote_bundle=""
remote_source_dir=""
expected_source_tip_height=""
expected_source_tip_hash=""
runtime_path=""
runtime_sha=""
tool_path=""
tool_sha=""
remote_tool="/opt/synergy/bin/synergy-node"
remote_runtime="/opt/synergy/bin/synergy-validator"
backup_dir=""
validator_address=""
sample_blocks="80"
restart_wait_secs="20"
timeout=240

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --source) source="${2:-}"; shift 2 ;;
    --nodes) nodes="${2:-}"; shift 2 ;;
    --heights) heights="${2:-}"; shift 2 ;;
    --quorum-height) quorum_height="${2:-}"; shift 2 ;;
    --quorum-hash) quorum_hash="${2:-}"; shift 2 ;;
    --common-height) common_height="${2:-}"; shift 2 ;;
    --common-hash) common_hash="${2:-}"; shift 2 ;;
    --local-conflicting-height) local_conflicting_height="${2:-}"; shift 2 ;;
    --local-conflicting-hash) local_conflicting_hash="${2:-}"; shift 2 ;;
    --conflict-height-hash) conflict_height_hash="${2:-}"; shift 2 ;;
    --finalized-height) finalized_height="${2:-}"; shift 2 ;;
    --rejoin-height) rejoin_height="${2:-}"; shift 2 ;;
    --min-age-secs) min_age_secs="${2:-}"; shift 2 ;;
    --probation-blocks) probation_blocks="${2:-}"; shift 2 ;;
    --public-rpc) public_rpc_url="${2:-}"; shift 2 ;;
    --poll-secs) poll_secs="${2:-}"; shift 2 ;;
    --max-wait-secs) max_wait_secs="${2:-}"; shift 2 ;;
    --reason) reason="${2:-}"; shift 2 ;;
    --manifest) manifest="${2:-}"; shift 2 ;;
    --snapshot-root) snapshot_root="${2:-}"; shift 2 ;;
    --remote-bundle) remote_bundle="${2:-}"; shift 2 ;;
    --target-remote-bundle) target_remote_bundle="${2:-}"; shift 2 ;;
    --remote-source-dir) remote_source_dir="${2:-}"; shift 2 ;;
    --expected-source-tip-height) expected_source_tip_height="${2:-}"; shift 2 ;;
    --expected-source-tip-hash) expected_source_tip_hash="${2:-}"; shift 2 ;;
    --runtime) runtime_path="${2:-}"; shift 2 ;;
    --runtime-sha) runtime_sha="${2:-}"; shift 2 ;;
    --tool) tool_path="${2:-}"; shift 2 ;;
    --tool-sha) tool_sha="${2:-}"; shift 2 ;;
    --remote-tool) remote_tool="${2:-}"; shift 2 ;;
    --remote-runtime) remote_runtime="${2:-}"; shift 2 ;;
    --backup-dir) backup_dir="${2:-}"; shift 2 ;;
    --validator-address) validator_address="${2:-}"; shift 2 ;;
    --sample-blocks) sample_blocks="${2:-}"; shift 2 ;;
    --restart-wait-secs) restart_wait_secs="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    --workbook) workbook_path="${2:-}"; shift 2 ;;
    --timeout) timeout="${2:-}"; shift 2 ;;
    --stop-target) stop_target=true; shift ;;
    --restart-target) restart_target=true; shift ;;
    --execute) execute=true; shift ;;
    --exact-common-height-match) exact_common_height_match=true; shift ;;
    --latest-finalized-qc-aegis-pqc-verified) latest_finalized_qc_aegis_pqc_verified=true; shift ;;
    --state-root-matches) state_root_matches=true; shift ;;
    --rejoin-at-finalized-safe-boundary) rejoin_at_finalized_safe_boundary=true; shift ;;
    --cluster-marks-pending-reactivation) cluster_marks_pending_reactivation=true; shift ;;
    --operator-approved-rejoin) operator_approved_rejoin=true; shift ;;
    --operator-approved-reactivation) operator_approved_reactivation=true; shift ;;
    --operator-approved-emergency-leader-stall-recovery) operator_approved_emergency_leader_stall_recovery=true; shift ;;
    --skip-helper-verify) skip_helper_verify=true; shift ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$output" ]]; then
  safe_phase="${phase//[^A-Za-z0-9_.-]/-}"
  safe_target="${target:-fleet}"
  safe_target="${safe_target//[^A-Za-z0-9_.-]/-}"
  output="$repo_root/outputs/${safe_target}-validator-appliance-recovery-${safe_phase}-${stamp}.md"
fi
mkdir -p "$(dirname "$output")"

run_workbook() {
  local node="$1"
  local command="$2"
  local run_timeout="${3:-$timeout}"
  python3 "$access_py" --workbook "$workbook_path" run "$node" "$command" \
    --remote-sudo-from-workbook \
    --timeout "$run_timeout"
}

stream_workbook() {
  local node="$1"
  local local_path="$2"
  local command="$3"
  local run_timeout="${4:-$timeout}"
  python3 "$access_py" --workbook "$workbook_path" stream-run "$node" "$local_path" "$command" \
    --remote-sudo-from-workbook \
    --timeout "$run_timeout"
}

pipe_workbook() {
  local source_node="$1"
  local source_command="$2"
  local target_node="$3"
  local target_command="$4"
  local run_timeout="${5:-$timeout}"
  python3 "$access_py" --workbook "$workbook_path" pipe-run \
    "$source_node" "$source_command" "$target_node" "$target_command" \
    --timeout "$run_timeout"
}

remote_common='
SERVICE="${SERVICE:-synergy-validator.service}"
ROOT="${ROOT:-/var/lib/synergy/validator}"
CONFIG_PATH="${CONFIG_PATH:-/etc/synergy/validator/config.toml}"
BIN="${BIN:-/opt/synergy/bin/synergy-node}"
RUNTIME_BIN="${RUNTIME_BIN:-/opt/synergy/bin/synergy-validator}"
PORT="${SYNERGY_QRPC_PORT:-5640}"
rsudo() {
  if command sudo -n "$@" >/tmp/synergy-validator-recovery-sudo.out 2>/tmp/synergy-validator-recovery-sudo.err; then
    cat /tmp/synergy-validator-recovery-sudo.out
    return 0
  fi
  local rc=$?
  local out err
  out="$(cat /tmp/synergy-validator-recovery-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-validator-recovery-sudo.err 2>/dev/null || true)"
  if [ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ] && printf "%s" "$err" | grep -Eiq "password|a password is required"; then
    if printf "%s\n" "$SYNERGY_REMOTE_SUDO_PASSWORD" | command sudo -S -p "" "$@" >/tmp/synergy-validator-recovery-sudo.out 2>/tmp/synergy-validator-recovery-sudo.err; then
      cat /tmp/synergy-validator-recovery-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-validator-recovery-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-validator-recovery-sudo.err 2>/dev/null || true)"
  fi
  [ -n "$out" ] && printf "%s\n" "$out"
  [ -n "$err" ] && printf "%s\n" "$err" >&2
  return "$rc"
}
run_node() {
  rsudo env SYNERGY_PROJECT_ROOT="$ROOT" SYNERGY_CONFIG_PATH="$CONFIG_PATH" "$BIN" "$@"
}
run_node_timeout() {
  local limit="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    rsudo env SYNERGY_PROJECT_ROOT="$ROOT" SYNERGY_CONFIG_PATH="$CONFIG_PATH" timeout "$limit" "$BIN" "$@"
  else
    run_node "$@"
  fi
}
rpc() {
  local url="${SYNERGY_QRPC_URL:-}"
  if [ -z "$url" ]; then
    local bind="${SYNERGY_QRPC_BIND_ADDRESS:-}"
    if [ -z "$bind" ] && rsudo test -f "$CONFIG_PATH"; then
      bind="$(rsudo grep -m1 "bind_address[[:space:]]*=" "$CONFIG_PATH" 2>/dev/null | sed -E "s/.*bind_address[[:space:]]*=[[:space:]]*\\\"([^\\\"]*)\\\".*/\\1/" || true)"
    fi
    if [ -z "$bind" ]; then
      bind="127.0.0.1:${PORT}"
    fi
    case "$bind" in
      http://*|https://*) url="$bind" ;;
      *) url="http://$bind" ;;
    esac
  fi
  python3 - "$url" "$1" "${2:-[]}" "${3:-6}" <<'"'"'PY'"'"' 2>/dev/null || true
import json, sys, time, urllib.request
url, method, params_json, timeout = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
try:
    params = json.loads(params_json)
except Exception:
    params = []
payload=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
req=urllib.request.Request(url, data=payload, headers={"content-type":"application/json"}, method="POST")
started=time.time()
try:
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        print(json.dumps({"elapsed_sec":round(time.time()-started,3),"response":json.loads(resp.read().decode())}, sort_keys=True))
except Exception as exc:
    print(json.dumps({"elapsed_sec":round(time.time()-started,3),"error":str(exc)}, sort_keys=True))
PY
}
'

remote_status='
'"${remote_common}"'
cat <<REPORT
## Remote Validator Status

generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
hostname: $(hostname -f 2>/dev/null || hostname)
runtime_root: $ROOT
config_path: $CONFIG_PATH
cli_binary: $BIN
runtime_binary: $RUNTIME_BIN
service_execstart: $(rsudo systemctl show "$SERVICE" -p ExecStart --value 2>/dev/null | sed "s/[[:space:]]\\+/ /g" || true)

### Service

~~~text
state=$(rsudo systemctl is-active "$SERVICE" 2>/dev/null || true)
show=$(rsudo systemctl show "$SERVICE" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr "\n" "|" || true)
~~~

### qRPC

~~~json
{
  "health": $(rpc synergy_getHealth),
  "latest": $(rpc synergy_getLatestBlock),
  "block_number": $(rpc synergy_getBlockNumber),
  "canonical_lock": $(rpc synergy_getCanonicalLock),
  "node_status": $(rpc synergy_getNodeStatus),
  "peer_info": $(rpc synergy_getPeerInfo)
}
~~~

### Listeners

~~~text
$(rsudo ss -ltnp 2>/dev/null | grep -E "(:${PORT}\\b|:5622\\b|:5660\\b|:6030\\b)" || true)
~~~

### Process

~~~text
$(
MAIN_PID=$(rsudo systemctl show "$SERVICE" -p MainPID --value 2>/dev/null | head -n 1 || true)
echo "main_pid=${MAIN_PID}"
if [ -n "$MAIN_PID" ] && [ "$MAIN_PID" != "0" ]; then
  ps -o pid,ppid,stat,etime,pcpu,pmem,rss,vsz,comm,args -p "$MAIN_PID" 2>/dev/null || true
  echo "--- threads ---"
  ps -L -o pid,tid,stat,pcpu,comm -p "$MAIN_PID" 2>/dev/null | head -80 || true
  echo "--- fd-count ---"
  ls "/proc/$MAIN_PID/fd" 2>/dev/null | wc -l || true
  echo "--- service-show ---"
  rsudo systemctl show "$SERVICE" -p ExecMainStartTimestamp -p ExecMainPID -p MainPID -p User -p Group -p MemoryCurrent -p CPUUsageNSec -p Restart -p RestartUSec --no-pager 2>/dev/null || true
fi
)
~~~

### Recent Service Logs

~~~text
$(rsudo journalctl -u "$SERVICE" -n 220 --no-pager 2>/dev/null || true)
~~~

### Runtime Recovery Status

#### quarantine-status

~~~json
$(run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true)
~~~

#### self-heal-status

~~~json
$(run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true)
~~~

#### snapshots

~~~json
$(run_node list-snapshots --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true)
~~~

### Snapshot Manifests

~~~text
$(rsudo find "$ROOT/data" -maxdepth 6 -type f \( -name "*manifest*.json" -o -name "*.manifest" -o -name "signed-*.json" \) -printf "%p\t%s bytes\t%TY-%Tm-%TdT%TH:%TM:%TSZ\n" 2>/dev/null | sort || true)
~~~
REPORT
'

write_header() {
  local title="$1"
  {
    echo "# $title"
    echo
    echo "generated_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "phase: $phase"
    echo "execute: $execute"
    echo
  } > "$output"
}

write_public_mesh_sample() {
  local title="$1"
  local address="$2"
  local blocks="${3:-80}"
  [[ -n "$public_rpc_url" ]] || return 0
  {
    echo "## ${title}"
    echo
    echo '~~~json'
    python3 - "$public_rpc_url" "$address" "$blocks" <<'PY'
import json
import sys
import time
import urllib.request

url, address, sample_blocks = sys.argv[1], sys.argv[2], int(sys.argv[3])

def rpc(method, params=None, timeout=10):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {
                "elapsed_sec": round(time.time() - started, 3),
                "response": json.loads(resp.read().decode()),
            }
    except Exception as exc:
        return {"elapsed_sec": round(time.time() - started, 3), "error": str(exc)}

latest = rpc("synergy_getLatestBlock")
latest_block = ((latest.get("response") or {}).get("result") or {})
height = latest_block.get("block_index")
start = None
block_range = None
proposer_count = 0
observed_proposers = []
if isinstance(height, int):
    start = max(0, height - max(0, sample_blocks - 1))
    block_range = rpc("synergy_getBlockRange", [start, height], timeout=15)
    blocks = ((block_range.get("response") or {}).get("result") or [])
    if isinstance(blocks, list):
        for block in blocks:
            if not isinstance(block, dict):
                continue
            proposer = block.get("validator_id") or block.get("validator")
            observed_proposers.append({
                "height": block.get("block_index"),
                "validator": proposer,
            })
            if address and proposer == address:
                proposer_count += 1

peer_info = rpc("synergy_getPeerInfo")
peers = ((peer_info.get("response") or {}).get("result") or {}).get("peers") or []
peer_present = any(
    isinstance(peer, dict) and peer.get("validator_address") == address
    for peer in peers
) if address else None
activity = rpc("synergy_getValidatorActivity")
activity_validators = ((activity.get("response") or {}).get("result") or {}).get("validators") or []
activity_record = None
for validator in activity_validators:
    if isinstance(validator, dict) and validator.get("address") == address:
        activity_record = validator
        break

print(json.dumps({
    "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "public_rpc": url,
    "target_validator_address": address or None,
    "sample_blocks_requested": sample_blocks,
    "sample_start_height": start,
    "sample_end_height": height,
    "latest": latest,
    "peer_present_in_public_peer_info": peer_present,
    "target_recent_proposer_count": proposer_count if address else None,
    "target_activity_record": activity_record,
    "peer_info": peer_info,
    "validator_activity": activity,
    "block_validation_status": rpc("synergy_getBlockValidationStatus"),
    "observed_proposers": observed_proposers,
}, indent=2, sort_keys=True))
PY
    echo '~~~'
    echo
  } >> "$output"
}

case "$phase" in
  quorum-proof)
    [[ -n "$nodes" ]] || { echo "--nodes is required" >&2; exit 2; }
    [[ -n "$heights" ]] || heights="651000,650900,650470"
    write_header "Validator Quorum Proof"
    IFS=',' read -r -a node_array <<< "$nodes"
    IFS=',' read -r -a height_array <<< "$heights"
    for node in "${node_array[@]}"; do
      node="${node//[[:space:]]/}"
      [[ -n "$node" ]] || continue
      heights_json="$(printf '%s\n' "${height_array[@]}" | python3 -c 'import json,sys; print(json.dumps([int(x.strip()) for x in sys.stdin if x.strip()]))')"
      {
        echo "## $node"
        echo
        echo '~~~json'
        run_workbook "$node" "${remote_common}
python3 - \"\$PORT\" <<'PY'
import json, socket, sys, time, urllib.request
port=sys.argv[1]
heights=${heights_json}
def rpc(method, params=None, timeout=6):
    payload=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or []}).encode()
    req=urllib.request.Request(f'http://127.0.0.1:{port}', data=payload, headers={'content-type':'application/json'}, method='POST')
    started=time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {'elapsed_sec':round(time.time()-started,3),'response':json.loads(resp.read().decode())}
    except Exception as exc:
        return {'elapsed_sec':round(time.time()-started,3),'error':str(exc)}
print(json.dumps({
  'generated_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
  'hostname': socket.getfqdn(),
  'latest': rpc('synergy_getLatestBlock'),
  'canonical_lock': rpc('synergy_getCanonicalLock'),
  'node_status': rpc('synergy_getNodeStatus'),
  'blocks': {str(h): rpc('synergy_getBlockByNumber', [h]) for h in heights},
}, indent=2, sort_keys=True))
PY" 120
        echo '~~~'
        echo
      } >> "$output" 2>&1
    done
    ;;
  status)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Recovery Status"
    run_workbook "$target" "$remote_status" "$timeout" >> "$output" 2>&1
    ;;
  stop)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Stop"
    run_workbook "$target" "${remote_common}
echo '## Stop Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo service=\"\$SERVICE\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo data_dir=\"\$ROOT/data\"
echo config_path=\"\$CONFIG_PATH\"
echo runtime_binary=\"\$RUNTIME_BIN\"
echo runtime_sha=\$(rsudo sha256sum \"\$RUNTIME_BIN\" 2>/dev/null | awk '{print \$1}' || true)
echo runtime_version=\$(rsudo \"\$RUNTIME_BIN\" --version 2>/dev/null | head -1 || true)
echo service_execstart=\$(rsudo systemctl show \"\$SERVICE\" -p ExecStart --value 2>/dev/null || true)
echo '~~~'
echo
echo '## Pre-stop qRPC'
echo
echo '~~~json'
printf '{\"latest\": %s, \"block_number\": %s, \"health\": %s, \"canonical_lock\": %s, \"node_status\": %s, \"validator_set\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock '[]' 10)\" \\
  \"\$(rpc synergy_getBlockNumber '[]' 10)\" \\
  \"\$(rpc synergy_getHealth '[]' 10)\" \\
  \"\$(rpc synergy_getCanonicalLock '[]' 10)\" \\
  \"\$(rpc synergy_getNodeStatus '[]' 10)\" \\
  \"\$(rpc synergy_getValidatorSet '[]' 10)\"
echo '~~~'
echo
echo '## Pre-stop File State'
echo
echo '~~~json'
rsudo python3 - \"\$ROOT/data\" <<'PY' 2>&1 || true
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        return {\"error\": str(exc), \"path\": str(path)}

def block_summary(block):
    if not isinstance(block, dict):
        return {\"raw_type\": type(block).__name__}
    return {
        \"height\": block.get(\"block_index\") or block.get(\"height\") or block.get(\"nonce\"),
        \"hash\": block.get(\"hash\") or block.get(\"block_hash\"),
        \"parent_hash\": block.get(\"parent_hash\") or block.get(\"previous_hash\"),
        \"validator\": block.get(\"validator\") or block.get(\"validator_id\"),
    }

chain = read_json(root / \"chain.json\")
blocks = chain.get(\"blocks\") if isinstance(chain, dict) else None
if isinstance(blocks, list) and blocks:
    chain_tip = block_summary(blocks[-1])
elif isinstance(blocks, dict) and blocks:
    key = max((int(k) for k in blocks if str(k).isdigit()), default=None)
    chain_tip = block_summary(blocks.get(str(key))) if key is not None else {\"error\": \"no numeric block keys\"}
else:
    chain_tip = {\"error\": \"no chain blocks\", \"shape\": type(blocks).__name__}

locks = read_json(root / \"canonical_locks.json\")
lock_tip = {\"error\": \"unreadable canonical_locks\"}
if isinstance(locks, dict):
    candidates = []
    for key, value in locks.items():
        try:
            height = int(key)
        except Exception:
            height = value.get(\"height\") if isinstance(value, dict) else None
        if height is not None:
            candidates.append((int(height), value))
    if candidates:
        height, value = max(candidates, key=lambda item: item[0])
        if isinstance(value, dict):
            lock_tip = {
                \"height\": value.get(\"height\", height),
                \"hash\": value.get(\"block_hash\") or value.get(\"hash\") or value.get(\"qc_block_hash\"),
                \"qc_hash\": value.get(\"qc_hash\"),
            }
        else:
            lock_tip = {\"height\": height, \"raw\": value}

def tail_jsonl(path, max_lines=4000):
    try:
        with path.open(\"rb\") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - 8_000_000))
            data = handle.read().decode(errors=\"replace\")
    except Exception as exc:
        return {\"error\": str(exc), \"path\": str(path)}
    malformed = 0
    last = None
    for line in data.splitlines()[-max_lines:]:
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
            last = item
        except Exception:
            malformed += 1
    if isinstance(last, dict):
        block = last.get(\"block\") if isinstance(last.get(\"block\"), dict) else last
        return {
            \"height\": block.get(\"height\") or block.get(\"block_index\") or last.get(\"height\"),
            \"hash\": block.get(\"hash\") or block.get(\"block_hash\") or last.get(\"block_hash\") or last.get(\"hash\"),
            \"qc_hash\": last.get(\"qc_hash\") or last.get(\"hash\"),
            \"malformed_tail_lines\": malformed,
        }
    return {\"error\": \"no parseable tail record\", \"malformed_tail_lines\": malformed}

registry = read_json(root / \"validator_registry.json\")
if isinstance(registry, dict):
    validators = registry.get(\"validators\") or registry.get(\"active_validators\") or registry
    if isinstance(validators, dict):
        registry_summary = {\"validator_count\": len(validators), \"keys\": list(validators)[:12]}
    elif isinstance(validators, list):
        registry_summary = {\"validator_count\": len(validators), \"addresses\": [v.get(\"address\") for v in validators if isinstance(v, dict)][:12]}
    else:
        registry_summary = {\"shape\": type(validators).__name__}
else:
    registry_summary = {\"shape\": type(registry).__name__}

print(json.dumps({
    \"chain_tip\": chain_tip,
    \"canonical_lock_tip\": lock_tip,
    \"committed_qc_tip\": tail_jsonl(root / \"committed_qcs.jsonl\"),
    \"committed_block_tip\": tail_jsonl(root / \"committed_blocks.jsonl\"),
    \"validator_registry\": registry_summary,
}, sort_keys=True))
PY
echo '~~~'
echo
echo '## Pre-stop Disk Usage'
echo
echo '~~~text'
df -h / /var /var/lib/synergy 2>/dev/null || true
rsudo du -xhd1 /var/lib/synergy 2>/dev/null | sort -h || true
echo '~~~'
echo
echo '## Pre-stop Consensus File Permissions'
echo
echo '~~~text'
for name in chain.json canonical_locks.json committed_qcs.jsonl committed_blocks.jsonl consensus_vote_locks.json validator_registry.json; do
  rsudo sh -c 'if [ -e \"\$1/\$2\" ]; then stat -c \"%n %s %U:%G %a\" \"\$1/\$2\"; else echo \"missing \$2\"; fi' sh \"\$ROOT/data\" \"\$name\" 2>/dev/null || true
done
echo '~~~'
echo
echo '## Pre-stop Recent Consensus Logs'
echo
echo '~~~text'
rsudo journalctl -u \"\$SERVICE\" -n 260 --no-pager 2>/dev/null \\
  | grep -Ei 'panic|compact|canonical|lock|commit|committed|selected leader|block_height|height|error|warn|stall|timeout|quorum|proposal|CHAIN_BODY' \\
  | tail -160 || true
echo '~~~'
echo
echo '## Stop Action'
echo
echo '~~~text'
if ! ${execute}; then
  echo dry_run=true
  echo would_stop=\"\$SERVICE\"
else
  rsudo systemctl stop \"\$SERVICE\" 2>&1 || true
  for i in \$(seq 1 40); do
    state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
    echo stop_wait_attempt=\"\$i\" state=\"\$state\"
    [ \"\$state\" != active ] && break
    sleep 2
  done
fi
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show_after=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
echo '~~~'
echo
echo '## Post-stop qRPC Closed Gate'
echo
echo '~~~json'
printf '{\"latest\": %s, \"health\": %s, \"block_number\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock '[]' 3)\" \\
  \"\$(rpc synergy_getHealth '[]' 3)\" \\
  \"\$(rpc synergy_getBlockNumber '[]' 3)\"
echo '~~~'
echo
echo '## Post-stop Listeners'
echo
echo '~~~text'
ss -ltnp 2>/dev/null | awk '\$4 ~ /:5640$/ || \$4 ~ /:5660$/ || \$4 ~ /:6030$/ || \$4 ~ /:5622$/ {print}' || true
echo '~~~'
echo
" "$timeout" >> "$output" 2>&1
    ;;
  start)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Start"
    run_workbook "$target" "${remote_common}
echo '## Start Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Start Service'
echo
echo '~~~text'
if ! ${execute}; then
  echo 'dry-run: would start validator service'
else
  rsudo systemctl start \"\$SERVICE\" 2>&1 || true
  sleep 8
fi
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  quarantine)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$quorum_height" ]] || { echo "--quorum-height is required" >&2; exit 2; }
    [[ -n "$quorum_hash" ]] || { echo "--quorum-hash is required" >&2; exit 2; }
    quarantine_extra_args=""
    if [[ -n "$local_conflicting_height" ]]; then
      quarantine_extra_args+=" --local-conflicting-height $(printf '%q' "$local_conflicting_height")"
    fi
    if [[ -n "$local_conflicting_hash" ]]; then
      quarantine_extra_args+=" --local-conflicting-hash $(printf '%q' "$local_conflicting_hash")"
    fi
    write_header "Validator Appliance Quarantine"
    run_workbook "$target" "${remote_common}
echo '## Quarantine Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo stop_target=\"${stop_target}\"
echo execute=\"${execute}\"
echo quorum_height=\"${quorum_height}\"
echo quorum_hash=\"${quorum_hash}\"
echo local_conflicting_height=\"${local_conflicting_height}\"
echo local_conflicting_hash=\"${local_conflicting_hash}\"
echo '~~~'
if ${stop_target}; then
  echo
  echo '## Stop Target'
  echo
  echo '~~~text'
  if ${execute}; then
    rsudo systemctl stop \"\$SERVICE\" 2>&1 || true
    sleep 5
  else
    echo 'dry-run: would stop target service'
  fi
  echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  echo '~~~'
fi
service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo
echo '## Runtime Quarantine'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node quarantine-stopped-validator\",\"requires_execute\":true}\\n'
elif [ \"\$service_state\" = active ]; then
  printf '{\"ok\":false,\"blocked\":\"target_service_still_active\"}\\n'
else
  run_node quarantine-stopped-validator \\
    --chain-id 1264 \\
    --network-id synergy-testnet-v3 \\
    --target-stopped \\
    --operator-approved-containment \\
    --quorum-majority-height \"${quorum_height}\" \\
    --quorum-majority-hash \"${quorum_hash}\" \\
    --reason \"${reason}\" ${quarantine_extra_args} 2>&1 || true
fi
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  transient-lock-recovery)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    if [[ -z "$finalized_height" && -n "$quorum_height" ]]; then
      finalized_height="$quorum_height"
    fi
    [[ -n "$finalized_height" ]] || { echo "--finalized-height is required" >&2; exit 2; }
    write_header "Validator Appliance Transient Vote Lock Recovery"
    run_workbook "$target" "${remote_common}
echo '## Transient Vote Lock Recovery Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo finalized_height=\"${finalized_height}\"
echo min_age_secs=\"${min_age_secs}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo '~~~'
echo
echo '## Before Diagnosis'
echo
echo '### diagnose-consensus-stall'
echo
echo '~~~json'
run_node_timeout 45s diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### diagnose-vote-locks'
echo
echo '~~~json'
run_node diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 --finalized-height \"${finalized_height}\" 2>&1 || true
echo '~~~'
echo
echo '### latest-before'
echo
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
echo '## Supported Runtime Recovery'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node recover-transient-vote-locks or synergy_recoverTransientVoteLocks\",\"requires_execute\":true,\"finalized_height\":%s,\"min_age_secs\":%s}\\n' \"${finalized_height}\" \"${min_age_secs}\"
else
  service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  if [ \"\$service_state\" = active ]; then
    rpc synergy_recoverTransientVoteLocks '{\"finalized_height\":${finalized_height},\"min_age_secs\":${min_age_secs},\"reason\":\"${reason}\"}' 30
  else
    run_node recover-transient-vote-locks \\
      --chain-id 1264 \\
      --network-id synergy-testnet-v3 \\
      --finalized-height \"${finalized_height}\" \\
      --min-age-secs \"${min_age_secs}\" \\
      --reason \"${reason}\" 2>&1 || true
  fi
fi
echo '~~~'
echo
echo '## After Diagnosis'
echo
echo '### diagnose-vote-locks-after'
echo
echo '~~~json'
run_node diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 --finalized-height \"${finalized_height}\" 2>&1 || true
echo '~~~'
echo
echo '### latest-after'
echo
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  rejoin-eligibility)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Rejoin Eligibility"
    run_workbook "$target" "${remote_common}
echo '## Rejoin Eligibility Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo '~~~'
echo
echo '## Runtime Rejoin Evidence'
echo
echo '### quarantine-status'
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### shadow-status'
echo '~~~json'
run_node shadow-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### rejoin-eligibility'
echo '~~~json'
run_node rejoin-eligibility --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### canonical-lock'
echo '~~~json'
rpc synergy_getCanonicalLock
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  request-rejoin)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$common_height" ]] || { echo "--common-height is required" >&2; exit 2; }
    [[ -n "$common_hash" ]] || { echo "--common-hash is required" >&2; exit 2; }
    if ${execute} && ! ${operator_approved_rejoin}; then
      echo "--operator-approved-rejoin is required with --execute" >&2
      exit 2
    fi
    rejoin_args=(--chain-id 1264 --network-id synergy-testnet-v3 --common-height "$common_height" --common-hash "$common_hash")
    ${exact_common_height_match} && rejoin_args+=(--exact-common-height-match)
    ${latest_finalized_qc_aegis_pqc_verified} && rejoin_args+=(--latest-finalized-qc-aegis-pqc-verified)
    ${state_root_matches} && rejoin_args+=(--state-root-matches)
    ${rejoin_at_finalized_safe_boundary} && rejoin_args+=(--rejoin-at-finalized-safe-boundary)
    ${cluster_marks_pending_reactivation} && rejoin_args+=(--cluster-marks-pending-reactivation)
    ${operator_approved_reactivation} && rejoin_args+=(--operator-approved-reactivation)
    ${operator_approved_emergency_leader_stall_recovery} && rejoin_args+=(--operator-approved-emergency-leader-stall-recovery)
    rejoin_arg_text="$(printf ' %q' "${rejoin_args[@]}")"
    write_header "Validator Appliance Request Rejoin"
    run_workbook "$target" "${remote_common}
echo '## Request Rejoin Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo operator_approved_rejoin=\"${operator_approved_rejoin}\"
echo common_height=\"${common_height}\"
echo common_hash=\"${common_hash}\"
echo exact_common_height_match=\"${exact_common_height_match}\"
echo latest_finalized_qc_aegis_pqc_verified=\"${latest_finalized_qc_aegis_pqc_verified}\"
echo state_root_matches=\"${state_root_matches}\"
echo rejoin_at_finalized_safe_boundary=\"${rejoin_at_finalized_safe_boundary}\"
echo cluster_marks_pending_reactivation=\"${cluster_marks_pending_reactivation}\"
echo operator_approved_emergency_leader_stall_recovery=\"${operator_approved_emergency_leader_stall_recovery}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Before Rejoin'
echo
echo '### quarantine-status-before'
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### rejoin-eligibility-before'
echo '~~~json'
run_node rejoin-eligibility --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### canonical-lock-before'
echo '~~~json'
rpc synergy_getCanonicalLock
echo '~~~'
echo
echo '## Supported Runtime Rejoin'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node request-rejoin\",\"requires_execute\":true,\"common_height\":%s,\"common_hash\":\"%s\"}\\n' \"${common_height}\" \"${common_hash}\"
else
  run_node request-rejoin ${rejoin_arg_text} 2>&1 || true
fi
echo '~~~'
echo
echo '## After Rejoin'
echo
echo '### quarantine-status-after'
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### self-heal-status-after'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  promote-vote-only-to-active)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Promote Vote Only To Active"
    run_workbook "$target" "${remote_common}
echo '## Promote Vote-only Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Before Promotion'
echo
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## Supported Runtime Promotion'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node promote-vote-only-to-active\",\"requires_execute\":true}\\n'
else
  run_node promote-vote-only-to-active --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
fi
echo '~~~'
echo
echo '## After Promotion'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  emergency-promote-leader-stall-to-active)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$common_height" ]] || { echo "--common-height is required" >&2; exit 2; }
    [[ -n "$common_hash" ]] || { echo "--common-hash is required" >&2; exit 2; }
    if ${execute} && ! ${operator_approved_emergency_leader_stall_recovery}; then
      echo "--operator-approved-emergency-leader-stall-recovery is required with --execute" >&2
      exit 2
    fi
    emergency_args=(--chain-id 1264 --network-id synergy-testnet-v3 --common-height "$common_height" --common-hash "$common_hash")
    ${exact_common_height_match} && emergency_args+=(--exact-common-height-match)
    ${latest_finalized_qc_aegis_pqc_verified} && emergency_args+=(--latest-finalized-qc-aegis-pqc-verified)
    ${state_root_matches} && emergency_args+=(--state-root-matches)
    ${rejoin_at_finalized_safe_boundary} && emergency_args+=(--rejoin-at-finalized-safe-boundary)
    ${cluster_marks_pending_reactivation} && emergency_args+=(--cluster-marks-pending-reactivation)
    ${operator_approved_emergency_leader_stall_recovery} && emergency_args+=(--operator-approved-emergency-leader-stall-recovery)
    emergency_arg_text="$(printf ' %q' "${emergency_args[@]}")"
    write_header "Validator Appliance Emergency Promote Leader Stall To Active"
    run_workbook "$target" "${remote_common}
echo '## Emergency Leader-Stall Promotion Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo operator_approved_emergency_leader_stall_recovery=\"${operator_approved_emergency_leader_stall_recovery}\"
echo common_height=\"${common_height}\"
echo common_hash=\"${common_hash}\"
echo exact_common_height_match=\"${exact_common_height_match}\"
echo latest_finalized_qc_aegis_pqc_verified=\"${latest_finalized_qc_aegis_pqc_verified}\"
echo state_root_matches=\"${state_root_matches}\"
echo rejoin_at_finalized_safe_boundary=\"${rejoin_at_finalized_safe_boundary}\"
echo cluster_marks_pending_reactivation=\"${cluster_marks_pending_reactivation}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Before Emergency Promotion'
echo
echo '### self-heal-status-before'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### quarantine-status-before'
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### latest-before'
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
echo '## Supported Runtime Emergency Promotion'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node emergency-promote-leader-stall-to-active\",\"requires_execute\":true,\"common_height\":%s,\"common_hash\":\"%s\"}\\n' \"${common_height}\" \"${common_hash}\"
else
  run_node emergency-promote-leader-stall-to-active ${emergency_arg_text} 2>&1 || true
fi
echo '~~~'
echo
echo '## After Emergency Promotion'
echo
echo '### self-heal-status-after'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  wait-promote-vote-only-to-active)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$rejoin_height" ]] || { echo "--rejoin-height is required" >&2; exit 2; }
    write_header "Validator Appliance Wait And Promote Vote Only To Active"
    {
      echo "## Public Probation Gate"
      echo
      echo '~~~json'
    } >> "$output"
    wait_rc=0
    python3 - "$public_rpc_url" "$rejoin_height" "$probation_blocks" "$poll_secs" "$max_wait_secs" "$execute" <<'PY' >> "$output" || wait_rc=$?
import json
import sys
import time
import urllib.request

rpc_url = sys.argv[1].rstrip("/")
rejoin_height = int(sys.argv[2])
probation_blocks = int(sys.argv[3])
poll_secs = max(1, int(sys.argv[4]))
max_wait_secs = max(0, int(sys.argv[5]))
execute = sys.argv[6].lower() == "true"
target_height = rejoin_height + probation_blocks

def rpc(method, params=None, timeout=10):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }).encode()
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    started = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = json.loads(resp.read().decode())
    if "error" in body:
        raise RuntimeError(json.dumps(body["error"], sort_keys=True))
    return round(time.time() - started, 3), body.get("result")

def height_from(value):
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        for key in ("height", "block_index", "number", "last_block", "highest_block"):
            item = value.get(key)
            if isinstance(item, int):
                return item
            if isinstance(item, str) and item.isdigit():
                return int(item)
    return None

def sample():
    errors = []
    for method in ("synergy_getCanonicalLock", "synergy_getLatestBlock", "synergy_getBlockNumber"):
        try:
            elapsed, result = rpc(method)
            height = height_from(result)
            if height is not None:
                return {
                    "ok": True,
                    "method": method,
                    "elapsed_sec": elapsed,
                    "height": height,
                    "result": result,
                }
            errors.append({"method": method, "error": "height_missing", "result": result})
        except Exception as exc:
            errors.append({"method": method, "error": str(exc)})
    return {"ok": False, "errors": errors}

started = time.time()
samples = []
ready = False
deadline = started + max_wait_secs

while True:
    current = sample()
    current["sampled_at_unix"] = int(time.time())
    samples.append(current)
    if len(samples) > 20:
        samples = samples[-20:]
    ready = bool(current.get("ok")) and int(current.get("height", -1)) >= target_height
    if ready or not execute:
        break
    if max_wait_secs == 0 or time.time() >= deadline:
        break
    time.sleep(min(poll_secs, max(0.0, deadline - time.time())))

report = {
    "public_rpc_url": rpc_url,
    "rejoin_height": rejoin_height,
    "probation_blocks": probation_blocks,
    "target_height": target_height,
    "execute": execute,
    "ready": ready,
    "elapsed_wait_sec": round(time.time() - started, 3),
    "poll_secs": poll_secs,
    "max_wait_secs": max_wait_secs,
    "latest_sample": samples[-1] if samples else None,
    "samples": samples,
}
if not ready:
    latest_height = (samples[-1] or {}).get("height") if samples else None
    if isinstance(latest_height, int):
        report["remaining_blocks"] = max(target_height - latest_height, 0)
    report["next_required_action"] = "wait_for_vote_only_probation_height"
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if ready or not execute else 124)
PY
    {
      echo '~~~'
      echo
    } >> "$output"
    if [[ "$wait_rc" -ne 0 ]]; then
      {
        echo "## Promotion Skipped"
        echo
        echo '~~~json'
        printf '{"skipped":true,"reason":"public_probation_gate_not_ready","exit_code":%s}\n' "$wait_rc"
        echo '~~~'
        echo
      } >> "$output"
    elif ! ${execute}; then
      {
        echo "## Promotion Skipped"
        echo
        echo '~~~json'
        printf '{"skipped":true,"reason":"dry_run","would_run":"synergy-node promote-vote-only-to-active"}\n'
        echo '~~~'
        echo
      } >> "$output"
    else
      run_workbook "$target" "${remote_common}
echo '## Supported Runtime Promotion After Public Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo public_rpc_url=\"${public_rpc_url}\"
echo rejoin_height=\"${rejoin_height}\"
echo probation_blocks=\"${probation_blocks}\"
echo required_public_height=\$(( ${rejoin_height} + ${probation_blocks} ))
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '~~~json'
run_node promote-vote-only-to-active --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## After Promotion'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    fi
    ;;
  mesh-reconnect)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Mesh Reconnect"
    write_public_mesh_sample "Public Mesh Before" "$validator_address" "$sample_blocks"
    run_workbook "$target" "${remote_common}
detect_validator_address() {
  python3 - \"\$CONFIG_PATH\" <<'PY' 2>/dev/null || true
import pathlib
import re
import sys
path = pathlib.Path(sys.argv[1])
text = path.read_text(errors=\"ignore\") if path.exists() else \"\"
for key in (\"validator_address\", \"address\"):
    match = re.search(rf\"^\\s*{key}\\s*=\\s*[\\\"']?([^\\\"'\\s#]+)\", text, re.M)
    if match and match.group(1).startswith(\"synv1\"):
        print(match.group(1))
        raise SystemExit(0)
PY
}
LOCAL_VALIDATOR_ADDRESS=\"${validator_address}\"
if [ -z \"\$LOCAL_VALIDATOR_ADDRESS\" ]; then
  LOCAL_VALIDATOR_ADDRESS=\$(detect_validator_address | head -n 1 || true)
fi
echo '## Mesh Reconnect Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo restart_wait_secs=\"${restart_wait_secs}\"
echo service=\"\$SERVICE\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo local_validator_address=\"\$LOCAL_VALIDATOR_ADDRESS\"
echo '~~~'
echo
echo '## Target Mesh Before'
echo
echo '### qRPC-before'
echo '~~~json'
printf '{\"latest\": %s, \"node_status\": %s, \"peer_info\": %s, \"canonical_lock\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getNodeStatus)\" \\
  \"\$(rpc synergy_getPeerInfo)\" \\
  \"\$(rpc synergy_getCanonicalLock)\"
echo '~~~'
echo
echo '### lifecycle-before'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### recent-mesh-logs-before'
echo '~~~text'
rsudo journalctl -u \"\$SERVICE\" -n 160 --no-pager 2>/dev/null | grep -Ei 'peer|mesh|leader|proposal|proposer|vote-only|quarantine|status sync|live validator' | tail -80 || true
echo '~~~'
echo
echo '## Mesh Reconnect Action'
echo
echo '~~~text'
if ! ${execute}; then
  echo dry_run=true
  echo would_restart=\"\$SERVICE\"
else
  rsudo systemctl restart \"\$SERVICE\"
  echo restarted=true
  sleep ${restart_wait_secs}
fi
echo service_after_action=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show_after_action=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
echo '~~~'
echo
echo '## Target Mesh After'
echo
echo '### qRPC-after'
echo '~~~json'
printf '{\"latest\": %s, \"node_status\": %s, \"peer_info\": %s, \"canonical_lock\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getNodeStatus)\" \\
  \"\$(rpc synergy_getPeerInfo)\" \\
  \"\$(rpc synergy_getCanonicalLock)\"
echo '~~~'
echo
echo '### lifecycle-after'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### recent-mesh-logs-after'
echo '~~~text'
rsudo journalctl -u \"\$SERVICE\" -n 220 --no-pager 2>/dev/null | grep -Ei 'peer|mesh|leader|proposal|proposer|vote-only|quarantine|status sync|live validator' | tail -120 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    write_public_mesh_sample "Public Mesh After" "$validator_address" "$sample_blocks"
    ;;
  state-diagnostics)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance State Diagnostics"
    run_workbook "$target" "${remote_common}
echo '## State Diagnostics Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo data_dir=\"\$ROOT/data\"
echo config_path=\"\$CONFIG_PATH\"
echo binary=\"\$BIN\"
echo '~~~'
echo
echo '## qRPC Snapshot'
echo
echo '~~~json'
printf '{\"latest\": %s, \"block_number\": %s, \"canonical_lock\": %s, \"node_status\": %s, \"peer_info\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getBlockNumber)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getNodeStatus)\" \\
  \"\$(rpc synergy_getPeerInfo)\"
echo '~~~'
echo
echo '## Consensus Diagnostics'
echo
echo '### diagnose-consensus-stall'
echo '~~~json'
run_node_timeout 45s diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### diagnose-vote-locks'
echo '~~~json'
run_node_timeout 45s diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## Validator State Store'
echo
echo '### inspect-state'
echo '~~~json'
run_node_timeout 60s validator inspect-state --state-root \"\$ROOT\" --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### verify-state'
echo '~~~json'
run_node_timeout 60s validator verify-state --state-root \"\$ROOT\" --allow-testnet-recovery-checkpoint --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### rebuild-derived-indexes-dry-run'
echo '~~~json'
run_node_timeout 60s validator rebuild-derived-indexes --state-root \"\$ROOT\" --dry-run --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## State File Inventory'
echo
echo '~~~text'
rsudo find \"\$ROOT/data\" -maxdepth 2 -type f \\( -name 'chain.json' -o -name 'canonical_locks.json' -o -name 'committed_qcs.jsonl' -o -name 'committed_blocks.jsonl' -o -name 'state_checkpoint.json' -o -name '*index*.json' -o -name '*receipt*.json' \\) -printf '%p\t%s bytes\t%TY-%Tm-%TdT%TH:%TM:%TSZ\n' 2>/dev/null | sort || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  chain-body-repair)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    repair_script="$repo_root/scripts/testnet/repair_chain_body_from_committed_blocks.sh"
    [[ -f "$repair_script" ]] || { echo "repair helper missing: $repair_script" >&2; exit 2; }
    repair_script_sha="$(sha256sum "$repair_script" | awk '{print $1}')"
    write_header "Validator Appliance Chain Body Repair"
    stream_workbook "$target" "$repair_script" "${remote_common}
set -euo pipefail
STAMP=\$(date -u +%Y%m%dT%H%M%SZ)
REPAIR_SCRIPT=\"/tmp/synergy-chain-body-repair-\${STAMP}-\$\$.sh\"
cat > \"\$REPAIR_SCRIPT\"
chmod 0700 \"\$REPAIR_SCRIPT\"
SERVICE_BEFORE=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '## Chain Body Repair Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo restart_target=\"${restart_target}\"
echo restart_wait_secs=\"${restart_wait_secs}\"
echo service_before=\"\$SERVICE_BEFORE\"
echo runtime_root=\"\$ROOT\"
echo data_dir=\"\$ROOT/data\"
echo committed_block_repair_log=\"\$ROOT/data/committed_blocks.jsonl\"
echo repair_helper_sha256=\"${repair_script_sha}\"
echo staged_repair_script_sha256=\$(sha256sum \"\$REPAIR_SCRIPT\" | awk '{print \$1}')
echo '~~~'
echo
echo '## Before Repair'
echo
echo '### qRPC-before'
echo '~~~json'
printf '{\"latest\": %s, \"block_number\": %s, \"canonical_lock\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getBlockNumber)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
echo '### diagnose-consensus-stall-before'
echo '~~~json'
run_node_timeout 45s diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### diagnose-vote-locks-before'
echo '~~~json'
run_node_timeout 45s diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## Repair Action'
echo
echo '~~~text'
REPAIR_RC=0
REPAIR_OUTPUT=\"\"
if ! ${execute}; then
  echo dry_run=true
  set +e
  REPAIR_OUTPUT=\$(rsudo env \\
    SYNERGY_WORKSPACE=\"\$ROOT\" \\
    SYNERGY_COMMITTED_BLOCK_REPAIR_LOG=\"\$ROOT/data/committed_blocks.jsonl\" \\
    SYNERGY_CHAIN_BODY_REPAIR_DRY_RUN=1 \\
    bash \"\$REPAIR_SCRIPT\" 2>&1)
  REPAIR_RC=\$?
  set -e
else
  echo dry_run=false
  echo stop_service_for_repair=true
  rsudo systemctl stop \"\$SERVICE\" 2>&1 || true
  sleep 5
  echo service_after_stop=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  set +e
  REPAIR_OUTPUT=\$(rsudo env \\
    SYNERGY_WORKSPACE=\"\$ROOT\" \\
    SYNERGY_COMMITTED_BLOCK_REPAIR_LOG=\"\$ROOT/data/committed_blocks.jsonl\" \\
    bash \"\$REPAIR_SCRIPT\" 2>&1)
  REPAIR_RC=\$?
  set -e
fi
echo repair_exit_code=\"\$REPAIR_RC\"
printf '%s\\n' \"\$REPAIR_OUTPUT\"
if ${execute}; then
  if [ \"\$SERVICE_BEFORE\" = active ] || ${restart_target}; then
    echo start_service_after_repair=true
    rsudo systemctl start \"\$SERVICE\" 2>&1 || true
    sleep ${restart_wait_secs}
  else
    echo start_service_after_repair=false
  fi
fi
echo service_after_action=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show_after_action=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
rm -f \"\$REPAIR_SCRIPT\"
echo '~~~'
echo
echo '## After Repair'
echo
echo '### qRPC-after'
echo '~~~json'
printf '{\"latest\": %s, \"block_number\": %s, \"canonical_lock\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getBlockNumber)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
echo '### verify-state-after'
echo '~~~json'
run_node_timeout 60s validator verify-state --state-root \"\$ROOT\" --allow-testnet-recovery-checkpoint --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### rebuild-derived-indexes-dry-run-after'
echo '~~~json'
run_node_timeout 60s validator rebuild-derived-indexes --state-root \"\$ROOT\" --dry-run --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### diagnose-consensus-stall-after'
echo '~~~json'
run_node_timeout 45s diagnose-consensus-stall --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### diagnose-vote-locks-after'
echo '~~~json'
run_node_timeout 45s diagnose-vote-locks --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  install-runtime)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$runtime_path" ]] || { echo "--runtime is required" >&2; exit 2; }
    [[ -f "$runtime_path" ]] || { echo "runtime does not exist: $runtime_path" >&2; exit 2; }
    runtime_file_info="$(file -b "$runtime_path" 2>/dev/null || true)"
    if [[ "$runtime_file_info" != *ELF* ]]; then
      echo "refusing to install non-ELF runtime: $runtime_path" >&2
      echo "file output: $runtime_file_info" >&2
      exit 2
    fi
    if [[ -z "$runtime_sha" ]]; then
      runtime_sha="$(sha256sum "$runtime_path" | awk '{print $1}')"
    fi
    write_header "Validator Appliance Runtime Install"
    if ! ${execute}; then
      run_workbook "$target" "${remote_common}
RUNTIME_BIN=\"${remote_runtime}\"
echo '## Runtime Install Dry Run'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo local_runtime=\"${runtime_path}\"
echo expected_runtime_sha=\"${runtime_sha}\"
echo local_runtime_file_info=\"${runtime_file_info}\"
echo remote_runtime=\"\$RUNTIME_BIN\"
echo cli_binary=\"\$BIN\"
echo service_execstart=\$(rsudo systemctl show \"\$SERVICE\" -p ExecStart --value 2>/dev/null | sed 's/[[:space:]]\\+/ /g' || true)
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo remote_current_sha=\$(rsudo sha256sum \"\$RUNTIME_BIN\" 2>/dev/null | awk '{print \$1}' || true)
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    else
      stream_workbook "$target" "$runtime_path" "${remote_common}
RUNTIME_BIN=\"${remote_runtime}\"
set -euo pipefail
STAMP=\$(date -u +%Y%m%dT%H%M%SZ)
TMP=\"/tmp/synergy-runtime-\${STAMP}-\$\$\"
BACKUP_DIR=\"/opt/synergy/backups/codex-runtime-rollout-${runtime_sha:0:12}-\${STAMP}-${target}\"
echo '## Runtime Install'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo expected_runtime_sha=\"${runtime_sha}\"
echo remote_runtime=\"\$RUNTIME_BIN\"
echo cli_binary=\"\$BIN\"
echo service_execstart=\$(rsudo systemctl show \"\$SERVICE\" -p ExecStart --value 2>/dev/null | sed 's/[[:space:]]\\+/ /g' || true)
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo backup_dir=\"\$BACKUP_DIR\"
cat > \"\$TMP\"
actual_sha=\$(sha256sum \"\$TMP\" | awk '{print \$1}')
uploaded_file_info=\$(file -b \"\$TMP\" 2>/dev/null || true)
echo uploaded_runtime_sha=\"\$actual_sha\"
echo uploaded_file_info=\"\$uploaded_file_info\"
if [ \"\$actual_sha\" != \"${runtime_sha}\" ]; then
  echo runtime_checksum_mismatch expected=\"${runtime_sha}\" actual=\"\$actual_sha\"
  rm -f \"\$TMP\"
  exit 3
fi
case \"\$uploaded_file_info\" in
  *ELF*) ;;
  *)
    echo runtime_platform_rejected=\"\$uploaded_file_info\"
    rm -f \"\$TMP\"
    exit 6
    ;;
esac
chmod 0755 \"\$TMP\"
set +e
uploaded_runtime_version_output=\$(\"\$TMP\" --version 2>&1)
uploaded_runtime_version_rc=\$?
set -e
echo uploaded_runtime_version=\"\$(printf \"%s\" \"\$uploaded_runtime_version_output\" | head -1)\"
if [ \"\$uploaded_runtime_version_rc\" -ne 0 ]; then
  echo uploaded_runtime_version_failed_rc=\"\$uploaded_runtime_version_rc\"
  rm -f \"\$TMP\"
  exit 7
fi
rsudo install -d -m 0755 \"\$(dirname \"\$RUNTIME_BIN\")\"
rsudo install -d -m 0755 \"\$BACKUP_DIR\"
if rsudo test -f \"\$RUNTIME_BIN\"; then
  RUNTIME_BASENAME=\$(basename \"\$RUNTIME_BIN\")
  rsudo cp -p \"\$RUNTIME_BIN\" \"\$BACKUP_DIR/\${RUNTIME_BASENAME}.pre-rollout\"
  echo previous_runtime_sha=\$(rsudo sha256sum \"\$BACKUP_DIR/\${RUNTIME_BASENAME}.pre-rollout\" | awk '{print \$1}' || true)
  echo previous_runtime_version=\$(rsudo \"\$BACKUP_DIR/\${RUNTIME_BASENAME}.pre-rollout\" --version 2>/dev/null | head -1 || true)
  RUNTIME_OWNER_UID=\$(rsudo stat -c '%u' \"\$RUNTIME_BIN\" 2>/dev/null || echo 0)
  RUNTIME_OWNER_GID=\$(rsudo stat -c '%g' \"\$RUNTIME_BIN\" 2>/dev/null || echo 0)
  RUNTIME_MODE=\$(rsudo stat -c '%a' \"\$RUNTIME_BIN\" 2>/dev/null || echo 755)
else
  RUNTIME_OWNER_UID=0
  RUNTIME_OWNER_GID=0
  RUNTIME_MODE=755
fi
rsudo sh -c 'systemctl cat "\$1" > "\$2"' sh \"\$SERVICE\" \"\$BACKUP_DIR/service-unit.txt\" 2>/dev/null || true
if rsudo test -f \"\$CONFIG_PATH\"; then
  rsudo cp -p \"\$CONFIG_PATH\" \"\$BACKUP_DIR/config.toml\"
  echo config_sha=\$(rsudo sha256sum \"\$CONFIG_PATH\" | awk '{print \$1}' || true)
fi
for cfg in /etc/synergy/validator/node.env /etc/synergy/validator/service.env /etc/synergy/validator/validator.env /etc/default/synergy-validator /etc/sysconfig/synergy-validator; do
  if rsudo test -f \"\$cfg\"; then
    rsudo cp -p \"\$cfg\" \"\$BACKUP_DIR/\$(basename \"\$cfg\")\"
    echo backup_config=\"\$cfg\"
  fi
done
rsudo install -m \"\$RUNTIME_MODE\" -o \"\$RUNTIME_OWNER_UID\" -g \"\$RUNTIME_OWNER_GID\" \"\$TMP\" \"\$RUNTIME_BIN.new\"
rsudo mv -f \"\$RUNTIME_BIN.new\" \"\$RUNTIME_BIN\"
rm -f \"\$TMP\"
echo installed_runtime_sha=\$(rsudo sha256sum \"\$RUNTIME_BIN\" | awk '{print \$1}')
echo installed_runtime_version=\$(rsudo \"\$RUNTIME_BIN\" --version 2>/dev/null | head -1 || true)
rsudo systemctl restart \"\$SERVICE\"
sleep 8
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
echo '~~~'
echo
echo '## Post-restart qRPC Wait'
echo
echo '~~~text'
for qrpc_attempt in \$(seq 1 36); do
  health_probe=\$(rpc synergy_getHealth '[]' 10)
  latest_probe=\$(rpc synergy_getLatestBlock '[]' 10)
  echo qrpc_wait_attempt=\"\$qrpc_attempt\"
  echo qrpc_health_probe=\"\$health_probe\"
  echo qrpc_latest_probe=\"\$latest_probe\"
  if printf \"%s\\n\" \"\$health_probe\" | grep -q '\"status\": \"healthy\"' \
    && printf \"%s\\n\" \"\$latest_probe\" | grep -q '\"block_index\"'; then
    echo qrpc_wait_result=ready
    break
  fi
  sleep 5
done
echo '~~~'
echo
echo '## Post-install qRPC'
echo
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    fi
    ;;
  install-node-tool)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$tool_path" ]] || { echo "--tool is required" >&2; exit 2; }
    [[ -f "$tool_path" ]] || { echo "tool does not exist: $tool_path" >&2; exit 2; }
    tool_file_info="$(file -b "$tool_path" 2>/dev/null || true)"
    if [[ "$tool_file_info" != *ELF* ]]; then
      echo "refusing to install non-ELF tool: $tool_path" >&2
      echo "file output: $tool_file_info" >&2
      exit 2
    fi
    if [[ -z "$tool_sha" ]]; then
      tool_sha="$(sha256sum "$tool_path" | awk '{print $1}')"
    fi
    write_header "Validator Appliance Node Tool Install"
    if ! ${execute}; then
      run_workbook "$target" "${remote_common}
echo '## Node Tool Install Dry Run'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo local_tool=\"${tool_path}\"
echo expected_tool_sha=\"${tool_sha}\"
echo local_tool_file_info=\"${tool_file_info}\"
echo remote_tool=\"${remote_tool}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo remote_current_sha=\$(rsudo sha256sum \"${remote_tool}\" 2>/dev/null | awk '{print \$1}' || true)
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    else
      stream_workbook "$target" "$tool_path" "${remote_common}
set -euo pipefail
STAMP=\$(date -u +%Y%m%dT%H%M%SZ)
REMOTE_TOOL=\"${remote_tool}\"
TMP=\"/tmp/synergy-node-tool-\${STAMP}-\$\$\"
BACKUP_DIR=\"\$ROOT/runtime/backups/\${STAMP}-node-tool-hotfix\"
echo '## Node Tool Install'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo expected_tool_sha=\"${tool_sha}\"
echo remote_tool=\"\$REMOTE_TOOL\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo backup_dir=\"\$BACKUP_DIR\"
cat > \"\$TMP\"
actual_sha=\$(sha256sum \"\$TMP\" | awk '{print \$1}')
uploaded_file_info=\$(file -b \"\$TMP\" 2>/dev/null || true)
echo uploaded_tool_sha=\"\$actual_sha\"
echo uploaded_file_info=\"\$uploaded_file_info\"
if [ \"\$actual_sha\" != \"${tool_sha}\" ]; then
  echo tool_checksum_mismatch expected=\"${tool_sha}\" actual=\"\$actual_sha\"
  rm -f \"\$TMP\"
  exit 3
fi
case \"\$uploaded_file_info\" in
  *ELF*) ;;
  *)
    echo tool_platform_rejected=\"\$uploaded_file_info\"
    rm -f \"\$TMP\"
    exit 6
    ;;
esac
rsudo install -d -m 0755 \"\$(dirname \"\$REMOTE_TOOL\")\"
rsudo install -d -m 0755 \"\$BACKUP_DIR\"
if rsudo test -f \"\$REMOTE_TOOL\"; then
  rsudo cp -p \"\$REMOTE_TOOL\" \"\$BACKUP_DIR/\$(basename \"\$REMOTE_TOOL\").pre-hotfix\"
  echo previous_tool_sha=\$(rsudo sha256sum \"\$BACKUP_DIR/\$(basename \"\$REMOTE_TOOL\").pre-hotfix\" | awk '{print \$1}' || true)
fi
rsudo install -m 0755 \"\$TMP\" \"\$REMOTE_TOOL\"
rm -f \"\$TMP\"
echo installed_tool_sha=\$(rsudo sha256sum \"\$REMOTE_TOOL\" | awk '{print \$1}')
echo service_after_no_restart=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Tool Smoke Test'
echo
echo '~~~text'
rsudo env SYNERGY_PROJECT_ROOT=\"\$ROOT\" SYNERGY_CONFIG_PATH=\"\$CONFIG_PATH\" \"\$REMOTE_TOOL\" --help 2>&1 | head -40 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    fi
    ;;
  rollback-runtime)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Runtime Rollback"
    run_workbook "$target" "${remote_common}
RUNTIME_BIN=\"${remote_runtime}\"
set -euo pipefail
echo '## Runtime Rollback'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo remote_runtime=\"\$RUNTIME_BIN\"
echo cli_binary=\"\$BIN\"
echo service_execstart=\$(rsudo systemctl show \"\$SERVICE\" -p ExecStart --value 2>/dev/null | sed 's/[[:space:]]\\+/ /g' || true)
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
if [ -n \"${backup_dir}\" ]; then
  BACKUP_DIR=\"${backup_dir}\"
else
  BACKUP_DIR=\$(rsudo find /opt/synergy/backups \"\$ROOT/runtime/backups\" -maxdepth 1 -type d \\( -name 'codex-runtime-rollout-*' -o -name '*-runtime-hotfix' \\) -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR==1 {print \$2}')
fi
echo backup_dir=\"\$BACKUP_DIR\"
if [ -z \"\$BACKUP_DIR\" ]; then
  echo rollback_backup_missing=true
  exit 4
fi
RUNTIME_BASENAME=\$(basename \"\$RUNTIME_BIN\")
BACKUP_BIN=\"\$BACKUP_DIR/\${RUNTIME_BASENAME}.pre-rollout\"
if ! rsudo test -f \"\$BACKUP_BIN\" && rsudo test -f \"\$BACKUP_DIR/synergy-node.pre-hotfix\"; then
  BACKUP_BIN=\"\$BACKUP_DIR/synergy-node.pre-hotfix\"
fi
if ! rsudo test -f \"\$BACKUP_BIN\"; then
  echo rollback_backup_binary_missing=\"\$BACKUP_BIN\"
  exit 5
fi
backup_file_info=\$(rsudo file -b \"\$BACKUP_BIN\" 2>/dev/null || true)
echo backup_runtime_sha=\$(rsudo sha256sum \"\$BACKUP_BIN\" | awk '{print \$1}' || true)
echo backup_file_info=\"\$backup_file_info\"
case \"\$backup_file_info\" in
  *ELF*) ;;
  *)
    echo rollback_backup_platform_rejected=\"\$backup_file_info\"
    exit 6
    ;;
esac
if ${execute}; then
  if rsudo test -f \"\$RUNTIME_BIN\"; then
    RUNTIME_OWNER_UID=\$(rsudo stat -c '%u' \"\$RUNTIME_BIN\" 2>/dev/null || echo 0)
    RUNTIME_OWNER_GID=\$(rsudo stat -c '%g' \"\$RUNTIME_BIN\" 2>/dev/null || echo 0)
    RUNTIME_MODE=\$(rsudo stat -c '%a' \"\$RUNTIME_BIN\" 2>/dev/null || echo 755)
  else
    RUNTIME_OWNER_UID=0
    RUNTIME_OWNER_GID=0
    RUNTIME_MODE=755
  fi
  rsudo install -m \"\$RUNTIME_MODE\" -o \"\$RUNTIME_OWNER_UID\" -g \"\$RUNTIME_OWNER_GID\" \"\$BACKUP_BIN\" \"\$RUNTIME_BIN.new\"
  rsudo mv -f \"\$RUNTIME_BIN.new\" \"\$RUNTIME_BIN\"
  echo restored_runtime_sha=\$(rsudo sha256sum \"\$RUNTIME_BIN\" | awk '{print \$1}' || true)
  echo restored_runtime_version=\$(rsudo \"\$RUNTIME_BIN\" --version 2>/dev/null | head -1 || true)
  rsudo systemctl restart \"\$SERVICE\"
  sleep 8
else
  echo dry_run=true
fi
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo show=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
echo '~~~'
echo
echo '## Post-rollback qRPC'
echo
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  repair-permissions)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Runtime Permission Repair"
    run_workbook "$target" "${remote_common}
set -euo pipefail
SERVICE_USER=\$(rsudo systemctl show \"\$SERVICE\" -p User --value 2>/dev/null | head -n 1 || true)
SERVICE_GROUP=\$(rsudo systemctl show \"\$SERVICE\" -p Group --value 2>/dev/null | head -n 1 || true)
MAIN_PID=\$(rsudo systemctl show \"\$SERVICE\" -p MainPID --value 2>/dev/null | head -n 1 || true)
if [ -z \"\$SERVICE_USER\" ] && [ -n \"\$MAIN_PID\" ] && [ \"\$MAIN_PID\" != 0 ]; then
  SERVICE_USER=\$(ps -o user= -p \"\$MAIN_PID\" 2>/dev/null | awk 'NR==1 {print \$1}' || true)
fi
if [ -z \"\$SERVICE_GROUP\" ] && [ -n \"\$SERVICE_USER\" ]; then
  SERVICE_GROUP=\$(id -gn \"\$SERVICE_USER\" 2>/dev/null || true)
fi
if [ -z \"\$SERVICE_USER\" ]; then
  echo \"unable to determine service user for \$SERVICE\" >&2
  exit 7
fi
if [ -z \"\$SERVICE_GROUP\" ]; then
  SERVICE_GROUP=\"\$SERVICE_USER\"
fi
echo '## Permission Repair Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo restart_target=\"${restart_target}\"
echo service=\"\$SERVICE\"
echo service_user=\"\$SERVICE_USER\"
echo service_group=\"\$SERVICE_GROUP\"
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo main_pid=\"\$MAIN_PID\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Ownership Before'
echo
echo '~~~text'
rsudo sh -c 'for path in \"\$@\"; do [ -e \"\$path\" ] || [ -L \"\$path\" ] || continue; stat -c \"%U:%G %a %n\" \"\$path\"; done' sh \\
  \"\$ROOT\" \\
  \"\$ROOT/data\" \\
  \"\$ROOT/data/consensus_vote_locks.json\" \\
  \"\$ROOT/data/consensus_vote_locks.json.tmp\" \\
  \"\$ROOT/data/consensus_recovery_evidence\" \\
  \"\$ROOT/data/self-heal-evidence\" \\
  \"\$ROOT/data/snapshots\" \\
  \"\$ROOT/runtime\" \\
  \"\$ROOT/logs\" 2>/dev/null || true
echo '--- non-service-owned hot-path sample ---'
rsudo find \"\$ROOT/data\" -maxdepth 2 \\( ! -user \"\$SERVICE_USER\" -o ! -group \"\$SERVICE_GROUP\" \\) -printf '%u:%g %m %p\n' 2>/dev/null | head -80 || true
echo '~~~'
echo
echo '## Repair'
echo
echo '~~~text'
if ! ${execute}; then
  echo dry_run=true
  echo would_chown=\"\$SERVICE_USER:\$SERVICE_GROUP \$ROOT/data \$ROOT/runtime \$ROOT/logs\"
  echo would_create_dirs=\"\$ROOT/data/consensus_recovery_evidence \$ROOT/data/self-heal-evidence \$ROOT/data/snapshots \$ROOT/runtime \$ROOT/logs\"
else
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0750 \"\$ROOT/data\"
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0750 \"\$ROOT/data/consensus_recovery_evidence\"
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0750 \"\$ROOT/data/self-heal-evidence\"
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0750 \"\$ROOT/data/snapshots\"
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0755 \"\$ROOT/runtime\"
  rsudo install -d -o \"\$SERVICE_USER\" -g \"\$SERVICE_GROUP\" -m 0755 \"\$ROOT/logs\"
  rsudo chown -R \"\$SERVICE_USER:\$SERVICE_GROUP\" \"\$ROOT/data\" \"\$ROOT/runtime\" \"\$ROOT/logs\" 2>&1 || true
  rsudo chmod 0750 \"\$ROOT/data\" \"\$ROOT/data/consensus_recovery_evidence\" \"\$ROOT/data/self-heal-evidence\" \"\$ROOT/data/snapshots\" 2>&1 || true
  rsudo chmod 0755 \"\$ROOT/runtime\" \"\$ROOT/logs\" 2>&1 || true
  echo repaired=true
fi
echo '~~~'
if ${execute} && ${restart_target}; then
  echo
  echo '## Restart'
  echo
  echo '~~~text'
  rsudo systemctl restart \"\$SERVICE\"
  sleep 8
  echo service_after_restart=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  echo show=\$(rsudo systemctl show \"\$SERVICE\" -p ActiveState -p SubState -p MainPID --value 2>/dev/null | tr \"\\n\" \"|\" || true)
  echo '~~~'
fi
echo
echo '## Ownership After'
echo
echo '~~~text'
rsudo sh -c 'for path in \"\$@\"; do [ -e \"\$path\" ] || [ -L \"\$path\" ] || continue; stat -c \"%U:%G %a %n\" \"\$path\"; done' sh \\
  \"\$ROOT\" \\
  \"\$ROOT/data\" \\
  \"\$ROOT/data/consensus_vote_locks.json\" \\
  \"\$ROOT/data/consensus_vote_locks.json.tmp\" \\
  \"\$ROOT/data/consensus_recovery_evidence\" \\
  \"\$ROOT/data/self-heal-evidence\" \\
  \"\$ROOT/data/snapshots\" \\
  \"\$ROOT/runtime\" \\
  \"\$ROOT/logs\" 2>/dev/null || true
echo '--- non-service-owned hot-path sample ---'
rsudo find \"\$ROOT/data\" -maxdepth 2 \\( ! -user \"\$SERVICE_USER\" -o ! -group \"\$SERVICE_GROUP\" \\) -printf '%u:%g %m %p\n' 2>/dev/null | head -80 || true
echo '~~~'
echo
echo '## Post-repair qRPC'
echo
echo '~~~json'
rpc synergy_getLatestBlock
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  create-cold-restore-source)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    if [[ -z "$remote_bundle" ]]; then
      safe_target="${target//[^A-Za-z0-9_.-]/-}"
      remote_bundle="/tmp/synergy-${safe_target}-cold-restore-source-${stamp}.tar.gz"
    fi
    write_header "Validator Appliance Cold Restore Source Bundle"
    run_workbook "$target" "${remote_common}
SOURCE_DATA=\"\$ROOT/data\"
BUNDLE=\"${remote_bundle}\"
TMP_SOURCE=\"/tmp/synergy-cold-restore-source-${stamp}\"
ALLOWLIST='chain.json committed_blocks.jsonl canonical_locks.json committed_qcs.json committed_qcs.jsonl dag_state.json token_state.json account_state.json validator_registry.json synid_registry.json state_checkpoint.json state_checkpoint.recovery_manifest.json'
echo '## Source Bundle Gate'
echo
echo '~~~text'
echo source_node=\"${target}\"
echo execute=\"${execute}\"
echo source_data=\"\$SOURCE_DATA\"
echo remote_bundle=\"\$BUNDLE\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo '~~~'
echo
echo '## Source qRPC Before Stop'
echo
echo '~~~json'
printf '{\"latest\": %s, \"canonical_lock\": %s, \"health\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getHealth)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
echo '## Source File Inventory Before'
echo
echo '~~~text'
for name in \$ALLOWLIST; do
  rsudo sh -c 'if [ -f \"\$1/\$2\" ]; then stat -c \"%n %s %U:%G %a\" \"\$1/\$2\"; else echo \"missing \$2\"; fi' sh \"\$SOURCE_DATA\" \"\$name\" 2>/dev/null || true
done
echo '~~~'
echo
echo '## Source Bundle Creation'
echo
echo '~~~text'
if ! ${execute}; then
  echo dry_run=true
  echo would_stop_service=\"\$SERVICE\"
  echo would_copy_allowlist=\"\$ALLOWLIST\"
  echo would_write_bundle=\"\$BUNDLE\"
else
  rsudo systemctl stop \"\$SERVICE\" 2>&1 || true
  for i in \$(seq 1 30); do
    state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
    echo stop_wait_attempt=\"\$i\" state=\"\$state\"
    [ \"\$state\" != active ] && break
    sleep 2
  done
  state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  if [ \"\$state\" = active ]; then
    echo source_stop_failed=true
  else
    rsudo rm -rf \"\$TMP_SOURCE\" 2>&1 || true
    rsudo mkdir -p \"\$TMP_SOURCE\" 2>&1 || true
    copied=0
    for name in \$ALLOWLIST; do
      if rsudo test -f \"\$SOURCE_DATA/\$name\"; then
        rsudo cp -a \"\$SOURCE_DATA/\$name\" \"\$TMP_SOURCE/\$name\" 2>&1 || true
        copied=\$((copied+1))
      fi
    done
    echo copied_files=\"\$copied\"
    rsudo find \"\$TMP_SOURCE\" -maxdepth 1 -type f -printf '%f\t%s bytes\n' 2>/dev/null | sort || true
    rsudo rm -f \"\$BUNDLE\" 2>&1 || true
    rsudo tar -C \"\$TMP_SOURCE\" -czf \"\$BUNDLE\" . 2>&1 || true
    rsudo chmod 0644 \"\$BUNDLE\" 2>&1 || true
    echo bundle_sha256=\$(rsudo sha256sum \"\$BUNDLE\" 2>/dev/null || true)
    echo bundle_info=\$(rsudo ls -lh \"\$BUNDLE\" 2>/dev/null || true)
    rsudo rm -rf \"\$TMP_SOURCE\" 2>&1 || true
  fi
  rsudo systemctl start \"\$SERVICE\" 2>&1 || true
  for i in \$(seq 1 36); do
    latest_probe=\$(rpc synergy_getLatestBlock '[]' 10)
    health_probe=\$(rpc synergy_getHealth '[]' 10)
    echo restart_wait_attempt=\"\$i\"
    echo qrpc_latest_probe=\"\$latest_probe\"
    echo qrpc_health_probe=\"\$health_probe\"
    if printf '%s' \"\$latest_probe\" | grep -q '\"block_index\"' && printf '%s' \"\$health_probe\" | grep -Eq '\"status\"[[:space:]]*:[[:space:]]*\"healthy\"'; then
      echo restart_wait_result=ready
      break
    fi
    sleep 5
  done
fi
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Source qRPC After Restart'
echo
echo '~~~json'
printf '{\"latest\": %s, \"canonical_lock\": %s, \"health\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getHealth)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  create-cold-restore-source-dir)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    if [[ -z "$remote_source_dir" ]]; then
      safe_target="${target//[^A-Za-z0-9_.-]/-}"
      remote_source_dir="/tmp/synergy-${safe_target}-cold-restore-source-dir-${stamp}"
    fi
    write_header "Validator Appliance Cold Restore Source Directory"
    run_workbook "$target" "${remote_common}
SOURCE_DATA=\"\$ROOT/data\"
SOURCE_DIR=\"${remote_source_dir}\"
TMP_SOURCE=\"\${SOURCE_DIR}.tmp-${stamp}\"
ALLOWLIST='chain.json committed_blocks.jsonl canonical_locks.json committed_qcs.json committed_qcs.jsonl dag_state.json token_state.json account_state.json validator_registry.json synid_registry.json state_checkpoint.json state_checkpoint.recovery_manifest.json'
echo '## Source Directory Gate'
echo
echo '~~~text'
echo source_node=\"${target}\"
echo execute=\"${execute}\"
echo source_data=\"\$SOURCE_DATA\"
echo remote_source_dir=\"\$SOURCE_DIR\"
echo temp_source_dir=\"\$TMP_SOURCE\"
echo service_before=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo '~~~'
echo
echo '## Source qRPC Before Stop'
echo
echo '~~~json'
printf '{\"latest\": %s, \"canonical_lock\": %s, \"health\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getHealth)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
echo '## Source File Inventory Before'
echo
echo '~~~text'
for name in \$ALLOWLIST; do
  rsudo sh -c 'if [ -f \"\$1/\$2\" ]; then stat -c \"%n %s %U:%G %a\" \"\$1/\$2\"; else echo \"missing \$2\"; fi' sh \"\$SOURCE_DATA\" \"\$name\" 2>/dev/null || true
done
echo '~~~'
echo
echo '## Source Directory Creation'
echo
echo '~~~text'
if ! ${execute}; then
  echo dry_run=true
  echo would_stop_service=\"\$SERVICE\"
  echo would_copy_allowlist=\"\$ALLOWLIST\"
  echo would_write_source_dir=\"\$SOURCE_DIR\"
else
  source_dir_exists=\$(rsudo sh -c 'test -e \"\$1\" && echo yes || echo no' sh \"\$SOURCE_DIR\" 2>/dev/null || true)
  if [ \"\$source_dir_exists\" = yes ]; then
    echo blocked=source_dir_already_exists
    exit 1
  fi
  rsudo rm -rf \"\$TMP_SOURCE\" 2>&1 || true
  rsudo systemctl stop \"\$SERVICE\" 2>&1 || true
  for i in \$(seq 1 30); do
    state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
    echo stop_wait_attempt=\"\$i\" state=\"\$state\"
    [ \"\$state\" != active ] && break
    sleep 2
  done
  state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
  if [ \"\$state\" = active ]; then
    echo source_stop_failed=true
    exit 1
  fi
  rsudo mkdir -p \"\$TMP_SOURCE\" 2>&1 || true
  copied=0
  for name in \$ALLOWLIST; do
    source_file_exists=\$(rsudo sh -c 'test -f \"\$1\" && echo yes || echo no' sh \"\$SOURCE_DATA/\$name\" 2>/dev/null || true)
    if [ \"\$source_file_exists\" = yes ]; then
      if ! rsudo cp -a --reflink=auto --sparse=always \"\$SOURCE_DATA/\$name\" \"\$TMP_SOURCE/\$name\" 2>/tmp/synergy-source-copy.err; then
        cat /tmp/synergy-source-copy.err 2>/dev/null || true
        rsudo cp -a \"\$SOURCE_DATA/\$name\" \"\$TMP_SOURCE/\$name\" 2>&1 || exit 1
      fi
      copied=\$((copied+1))
    fi
  done
  echo copied_files=\"\$copied\"
  rsudo find \"\$TMP_SOURCE\" -maxdepth 1 -type f -printf '%f\t%s bytes\n' 2>/dev/null | sort || true
  rsudo mv \"\$TMP_SOURCE\" \"\$SOURCE_DIR\" 2>&1
  rsudo chmod -R a+rX \"\$SOURCE_DIR\" 2>&1 || true
  echo source_dir_du=\$(rsudo du -sh \"\$SOURCE_DIR\" 2>/dev/null || true)
  rsudo systemctl start \"\$SERVICE\" 2>&1 || true
  for i in \$(seq 1 36); do
    latest_probe=\$(rpc synergy_getLatestBlock '[]' 10)
    health_probe=\$(rpc synergy_getHealth '[]' 10)
    echo restart_wait_attempt=\"\$i\"
    echo qrpc_latest_probe=\"\$latest_probe\"
    echo qrpc_health_probe=\"\$health_probe\"
    if printf '%s' \"\$latest_probe\" | grep -q '\"block_index\"' && printf '%s' \"\$health_probe\" | grep -Eq '\"status\"[[:space:]]*:[[:space:]]*\"healthy\"'; then
      echo restart_wait_result=ready
      break
    fi
    sleep 5
  done
fi
echo service_after=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo '~~~'
echo
echo '## Source qRPC After Restart'
echo
echo '~~~json'
printf '{\"latest\": %s, \"canonical_lock\": %s, \"health\": %s, \"node_status\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getHealth)\" \\
  \"\$(rpc synergy_getNodeStatus)\"
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  transfer-cold-restore-source)
    [[ -n "$source" ]] || { echo "--source is required" >&2; exit 2; }
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$remote_bundle" ]] || { echo "--remote-bundle is required" >&2; exit 2; }
    if [[ -z "$target_remote_bundle" ]]; then
      target_remote_bundle="$remote_bundle"
    fi
    source_bundle_q="$(printf '%q' "$remote_bundle")"
    target_bundle_q="$(printf '%q' "$target_remote_bundle")"
    write_header "Validator Appliance Cold Restore Source Transfer"
    {
      echo "## Transfer Gate"
      echo
      echo '~~~text'
      echo "source_node=${source}"
      echo "target_node=${target}"
      echo "execute=${execute}"
      echo "source_remote_bundle=${remote_bundle}"
      echo "target_remote_bundle=${target_remote_bundle}"
      echo "transport=spreadsheet_host_access.py pipe-run"
      echo '~~~'
      echo
      echo "## Transfer"
      echo
      echo '~~~text'
      if ! $execute; then
        echo "dry_run=true"
        echo "would_open_source_connection=${source}"
        echo "would_open_target_connection=${target}"
        echo "would_stream_source_bundle=${remote_bundle}"
        echo "would_write_target_bundle=${target_remote_bundle}"
      else
        pipe_workbook "$source" "
set -euo pipefail
SRC=${source_bundle_q}
if [ ! -f \"\$SRC\" ]; then
  echo source_bundle_missing=\"\$SRC\" >&2
  exit 3
fi
echo source_bundle_sha256=\$(sha256sum \"\$SRC\" 2>/dev/null || true) >&2
echo source_bundle_info=\$(ls -lh \"\$SRC\" 2>/dev/null || true) >&2
cat \"\$SRC\"
" "$target" "
set -euo pipefail
DEST=${target_bundle_q}
if [ -e \"\$DEST\" ]; then
  echo blocked=target_bundle_already_exists \"\$DEST\" >&2
  exit 4
fi
TMP=\"\${DEST}.tmp-${stamp}-\$\$\"
rm -f \"\$TMP\"
umask 077
cat > \"\$TMP\"
chmod 0644 \"\$TMP\"
mv \"\$TMP\" \"\$DEST\"
echo target_bundle_sha256=\$(sha256sum \"\$DEST\" 2>/dev/null || true) >&2
echo target_bundle_info=\$(ls -lh \"\$DEST\" 2>/dev/null || true) >&2
" "$timeout"
      fi
      echo '~~~'
    } >> "$output" 2>&1
    ;;
  cold-canonical-restore)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    if [[ -z "$remote_bundle" && -z "$remote_source_dir" ]]; then
      echo "--remote-bundle or --remote-source-dir is required" >&2
      exit 2
    fi
    if [[ -n "$remote_bundle" && -n "$remote_source_dir" ]]; then
      echo "--remote-bundle and --remote-source-dir are mutually exclusive" >&2
      exit 2
    fi
    write_header "Validator Appliance Cold Canonical Restore"
    source_state_dir="${remote_source_dir:-/var/lib/synergy/cold-restore-source-${stamp}}"
    restore_args=(--validator-name "$target" --source-state-dir "$source_state_dir" --target-root "/var/lib/synergy/validator/data" --config-root "/etc/synergy/validator" --archive-root "/var/backups/synergy" --staging-root "/var/lib/synergy/validator/.cold-restore-staging" --helper "/opt/synergy/bin/synergy-node" --allow-testnet-recovery-checkpoint)
    if [[ -n "$expected_source_tip_height" ]]; then
      restore_args+=(--expected-source-tip-height "$expected_source_tip_height")
    fi
    if [[ -n "$expected_source_tip_hash" ]]; then
      restore_args+=(--expected-source-tip-hash "$expected_source_tip_hash")
    fi
    if $skip_helper_verify; then
      restore_args+=(--skip-helper-verify)
    fi
    restore_arg_text="$(printf ' %q' "${restore_args[@]}")"
    stream_workbook "$target" "$repo_root/scripts/testnet/val2_cold_canonical_snapshot_restore.py" "${remote_common}
RESTORE_SCRIPT=\"/tmp/synergy-cold-canonical-restore-${stamp}.py\"
SOURCE_DIR=\"${source_state_dir}\"
BUNDLE=\"${remote_bundle}\"
cat > \"\$RESTORE_SCRIPT\"
chmod 0700 \"\$RESTORE_SCRIPT\"
echo '## Cold Restore Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo remote_bundle=\"\$BUNDLE\"
echo remote_source_dir=\"${remote_source_dir}\"
echo source_dir=\"\$SOURCE_DIR\"
echo expected_source_tip_height=\"${expected_source_tip_height}\"
echo expected_source_tip_hash=\"${expected_source_tip_hash}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo target_root=\"\$ROOT/data\"
echo config_path=\"\$CONFIG_PATH\"
if [ -n \"\$BUNDLE\" ]; then
  echo bundle_sha256=\$(rsudo sha256sum \"\$BUNDLE\" 2>/dev/null || true)
  echo bundle_info=\$(rsudo ls -lh \"\$BUNDLE\" 2>/dev/null || true)
else
  echo bundle_sha256=not_applicable_existing_source_dir
  echo bundle_info=not_applicable_existing_source_dir
fi
echo '~~~'
echo
echo '## Bundle Extraction'
echo
echo '~~~text'
service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
if [ \"\$service_state\" = active ]; then
  echo blocked=target_service_active
elif ! ${execute}; then
  echo dry_run=true
  if [ -n \"\$BUNDLE\" ]; then
    echo would_extract_bundle=\"\$BUNDLE\"
  else
    echo would_reuse_source_dir=\"\$SOURCE_DIR\"
  fi
  echo would_run=\"python3 \$RESTORE_SCRIPT --dry-run ${restore_arg_text}\"
  echo would_run_apply=\"python3 \$RESTORE_SCRIPT --apply ${restore_arg_text}\"
else
  if [ -n \"\$BUNDLE\" ]; then
    rsudo rm -rf \"\$SOURCE_DIR\" 2>&1 || true
    rsudo mkdir -p \"\$SOURCE_DIR\" 2>&1 || true
    if ! rsudo tar -C \"\$SOURCE_DIR\" -xzf \"\$BUNDLE\" 2>&1; then
      echo blocked=bundle_extract_failed
      exit 1
    fi
    rsudo rm -f \"\$BUNDLE\" 2>&1 || true
    echo bundle_removed_after_extract=true
  else
    echo reusing_existing_source_dir=\"\$SOURCE_DIR\"
  fi
  rsudo find \"\$SOURCE_DIR\" -maxdepth 1 -type f -printf '%f\t%s bytes\n' 2>/dev/null | sort || true
  echo source_dir_du=\$(rsudo du -sh \"\$SOURCE_DIR\" 2>/dev/null || true)
fi
echo '~~~'
if [ \"\$service_state\" != active ] && ${execute}; then
  echo
  echo '## Cold Restore Dry Run'
  echo
  echo '~~~json'
  set +e
  dry_output=\$(rsudo python3 \"\$RESTORE_SCRIPT\" --dry-run ${restore_arg_text} 2>&1)
  dry_rc=\$?
  dry_gate=false
  if printf '%s\n' \"\$dry_output\" | grep -q '\"ok\": true' && printf '%s\n' \"\$dry_output\" | grep -q '\"decision\": \"DRY_RUN_GO\"'; then
    dry_gate=true
  fi
  set -e
  printf '%s\n' \"\$dry_output\"
  echo '~~~'
  echo
  echo dry_run_exit_code=\"\$dry_rc\"
  echo dry_run_decision_gate=\"\$dry_gate\"
  if [ \"\$dry_rc\" -eq 0 ] && [ \"\$dry_gate\" = true ]; then
    echo
    echo '## Cold Restore Apply'
    echo
    echo '~~~json'
    set +e
    apply_output=\$(rsudo python3 \"\$RESTORE_SCRIPT\" --apply ${restore_arg_text} 2>&1)
    apply_rc=\$?
    apply_gate=false
    if printf '%s\n' \"\$apply_output\" | grep -q '\"ok\": true' && printf '%s\n' \"\$apply_output\" | grep -q '\"decision\": \"GO\"'; then
      apply_gate=true
    fi
    set -e
    printf '%s\n' \"\$apply_output\"
    echo '~~~'
    echo
    echo apply_exit_code=\"\$apply_rc\"
    echo apply_decision_gate=\"\$apply_gate\"
    if [ \"\$apply_rc\" -eq 0 ] && [ \"\$apply_gate\" = true ]; then
      echo
      echo '## Cold Restore Workspace Cleanup'
      echo
      echo '~~~text'
      rsudo rm -rf \"\$SOURCE_DIR\" 2>&1 || true
      echo source_dir_exists_after_cleanup=\$(rsudo sh -c 'test -e \"\$1\" && echo yes || echo no' sh \"\$SOURCE_DIR\" 2>/dev/null || true)
      echo '~~~'
    else
      echo
      echo '## Cold Restore Workspace Preserved'
      echo
      echo '~~~text'
      echo source_dir_preserved_after_failed_apply=\"\$SOURCE_DIR\"
      echo '~~~'
    fi
  else
    echo
    echo '## Cold Restore Apply Skipped'
    echo
    echo '~~~text'
    echo skipped_apply_due_to_dry_run_exit_code=\"\$dry_rc\"
    echo skipped_apply_due_to_dry_run_decision_gate=\"\$dry_gate\"
    echo source_dir_preserved_after_failed_dry_run=\"\$SOURCE_DIR\"
    echo '~~~'
  fi
fi
echo
echo '## Runtime Recovery Status After Restore'
echo
echo '### quarantine-status'
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '### self-heal-status'
echo '~~~json'
run_node self-heal-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  create-snapshot)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    write_header "Validator Appliance Snapshot Creation"
    snapshot_extra_args=""
    if [[ -n "$conflict_height_hash" ]]; then
      snapshot_extra_args+=" --conflict-height-hash $(printf '%q' "$conflict_height_hash")"
    fi
    run_workbook "$target" "${remote_common}
echo '## Snapshot Creation Gate'
echo
echo '~~~text'
echo target_node=\"${target}\"
echo execute=\"${execute}\"
echo conflict_height_hash=\"${conflict_height_hash}\"
echo service_state=\$(rsudo systemctl is-active \"\$SERVICE\" 2>/dev/null || true)
echo runtime_root=\"\$ROOT\"
echo config_path=\"\$CONFIG_PATH\"
echo '~~~'
echo
echo '## Source qRPC Before'
echo
echo '~~~json'
printf '{\"latest\": %s, \"canonical_lock\": %s, \"node_status\": %s, \"health\": %s, \"peer_info\": %s}\\n' \\
  \"\$(rpc synergy_getLatestBlock)\" \\
  \"\$(rpc synergy_getCanonicalLock)\" \\
  \"\$(rpc synergy_getNodeStatus)\" \\
  \"\$(rpc synergy_getHealth)\" \\
  \"\$(rpc synergy_getPeerInfo)\"
echo '~~~'
echo
echo '## Source Quarantine Status'
echo
echo '~~~json'
run_node quarantine-status --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## Supported Snapshot Creation'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node create-snapshot\",\"requires_execute\":true}\\n'
else
  run_node create-snapshot \\
    --chain-id 1264 \\
    --network-id synergy-testnet-v3 \\
    --source-node-majority-branch-proven \\
    --source-role VALIDATOR \\
    --snapshot-class validator-pruned \\
    --allowed-role validator ${snapshot_extra_args} 2>&1 || true
fi
echo '~~~'
echo
echo '## Snapshot Catalog After'
echo
echo '~~~json'
run_node list-snapshots --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  snapshot-repair)
    [[ -n "$target" ]] || { echo "--target is required" >&2; exit 2; }
    [[ -n "$manifest" ]] || { echo "--manifest is required" >&2; exit 2; }
    write_header "Validator Appliance Snapshot Repair"
    snapshot_arg=""
    if [[ -n "$snapshot_root" ]]; then
      snapshot_arg="--snapshot-root $(printf '%q' "$snapshot_root")"
    fi
    run_workbook "$target" "${remote_common}
echo '## Snapshot Verification'
echo
echo '~~~json'
run_node verify-snapshot --manifest \"${manifest}\" ${snapshot_arg} --snapshot-class validator-pruned --target-role validator --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
echo '~~~'
echo
echo '## Snapshot Repair'
echo
echo '~~~json'
if ! ${execute}; then
  printf '{\"ok\":false,\"dry_run\":true,\"would_run\":\"synergy-node self-heal-from-snapshot\",\"requires_execute\":true}\\n'
else
  run_node self-heal-from-snapshot --manifest \"${manifest}\" ${snapshot_arg} --chain-id 1264 --network-id synergy-testnet-v3 2>&1 || true
fi
echo '~~~'
echo
${remote_status}" "$timeout" >> "$output" 2>&1
    ;;
  *)
    echo "unsupported phase: $phase" >&2
    usage >&2
    exit 2
    ;;
esac

printf 'report=%s\n' "$output"
