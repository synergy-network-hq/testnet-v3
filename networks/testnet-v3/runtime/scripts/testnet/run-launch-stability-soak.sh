#!/usr/bin/env bash
set -euo pipefail

duration_seconds="${SOAK_DURATION_SECONDS:-7200}"
interval_seconds="${SOAK_INTERVAL_SECONDS:-300}"
soak_scope="${SOAK_SCOPE:-full}"
out_root="${SOAK_OUT_ROOT:-/Volumes/xcode/synergy-testnet-soaks}"
python_bin="${PYTHON_BIN:-/Users/devpup/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3}"
public_rpc_url="${PUBLIC_RPC_URL:-https://testnet-core-rpc.synergy-network.io}"
atlas_api_url="${ATLAS_API_URL:-https://testnet-atlas.synergy-network.io/api/v1}"
max_rpc_lag_blocks="${MAX_RPC_LAG_BLOCKS:-5}"
max_atlas_lag_blocks="${MAX_ATLAS_LAG_BLOCKS:-25}"
expected_validator_sha="${EXPECTED_VALIDATOR_SHA:-50f95442de06b15193e8d77bff6c8ed3676986cfc4e234ee7b5845f936df0d90}"
expected_val5_sha="${EXPECTED_VAL5_SHA:-$expected_validator_sha}"
expected_rpc_sha="${EXPECTED_RPC_SHA:-115233b08a3d25f340c3c6bd2edef4b17ba972e6d4ba440b65c9d6ff964471ed}"
max_support_lag_blocks="${MAX_SUPPORT_LAG_BLOCKS:-5}"
validator_rows_raw="${SOAK_VALIDATOR_ROWS:-Val1 Val2 Val3 Val4 Val5 Val6}"
relayer_rows_raw="${SOAK_RELAYER_ROWS:-Relayer-1 Relayer-2}"
spreadsheet_workbook="${SPREADSHEET_WORKBOOK:-/Users/devpup/Desktop/node machine credentials.xlsx}"
if [[ ! -f "$spreadsheet_workbook" && -f "/Users/devpup/Desktop/node-machine-credentials.xlsx" ]]; then
  spreadsheet_workbook="/Users/devpup/Desktop/node-machine-credentials.xlsx"
fi

case "$soak_scope" in
  consensus|full) ;;
  *)
    echo "unsupported SOAK_SCOPE=$soak_scope; expected consensus or full" >&2
    exit 2
    ;;
esac

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
out_dir="$out_root/$timestamp"
mkdir -p "$out_dir/raw"

host_access=("$python_bin" scripts/testnet/spreadsheet_host_access.py --workbook "$spreadsheet_workbook")

# Format: node|primary auth args|fallback auth args|extra remote env
# Auth args and fallback auth must stay empty: the host helper invokes only the
# exact workbook SSH command and supplies workbook credentials via ephemeral
# askpass if the command prompts.
read -r -a validators <<< "${validator_rows_raw//,/ }"
read -r -a relayers <<< "${relayer_rows_raw//,/ }"
if [[ "${#validators[@]}" -eq 0 ]]; then
  echo "SOAK_VALIDATOR_ROWS resolved to an empty validator list" >&2
  exit 2
fi
nodes=()
for validator in "${validators[@]}"; do
  nodes+=("$validator|||")
done
for relayer in "${relayers[@]}"; do
  nodes+=("$relayer|||SYNERGY_WORKSPACE=/opt/synergy/testnet/relayer")
done
nodes+=("RPC Gateway|||SYNERGY_WORKSPACE=/opt/synergy/Node-RPC")
validator_rows_csv="$(IFS=,; echo "${validators[*]}")"
relayer_rows_csv="$(IFS=,; echo "${relayers[*]}")"

echo "soak_dir=$out_dir"
{
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "soak_scope=$soak_scope"
  echo "duration_seconds=$duration_seconds"
  echo "interval_seconds=$interval_seconds"
  echo "spreadsheet=$spreadsheet_workbook"
  echo "public_rpc_url=$public_rpc_url"
  echo "atlas_api_url=$atlas_api_url"
  echo "max_rpc_lag_blocks=$max_rpc_lag_blocks"
  echo "max_support_lag_blocks=$max_support_lag_blocks"
  echo "max_atlas_lag_blocks=$max_atlas_lag_blocks"
  echo "expected_validator_sha=$expected_validator_sha"
  echo "expected_val5_sha=$expected_val5_sha"
  echo "expected_rpc_sha=$expected_rpc_sha"
  echo "validator_rows=$validator_rows_csv"
  echo "relayer_rows=$relayer_rows_csv"
  echo "expected_validator_count=${#validators[@]}"
} > "$out_dir/manifest.txt"

run_host_file() {
  local node="$1"
  local script_path="$2"
  local log="$3"
  local auth="$4"
  local fallback_auth="$5"
  local env_spec="$6"
  shift 6
  local remote_env_args=("$@")

  local cmd=("${host_access[@]}" run-file "$node" "$script_path" --timeout 90)
  if [[ -n "$auth" ]]; then
    # shellcheck disable=SC2206
    local auth_parts=($auth)
    cmd+=("${auth_parts[@]}")
  fi
  if [[ -n "$env_spec" ]]; then
    cmd+=(--remote-env "$env_spec")
  fi
  for remote_env in "${remote_env_args[@]}"; do
    cmd+=(--remote-env "$remote_env")
  done
  for attempt in 1 2; do
    if "${cmd[@]}" > "$log" 2>&1; then
      return 0
    fi
    echo "primary_attempt_${attempt}_failed=true" >> "$log"
    sleep 2
  done
  if [[ -n "$fallback_auth" ]]; then
    echo "fallback_auth_refused=true reason=workbook_ssh_command_only" >> "$log"
  fi
  return 1
}

extract_json_payload() {
  local sample="$1"
  local node="$2"
  local log="$3"
  "$python_bin" - "$sample" "$node" "$log" <<'PY'
import json
import sys

sample = int(sys.argv[1])
node = sys.argv[2]
path = sys.argv[3]
payload = None
try:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    payload = json.loads(line)
                except Exception:
                    pass
except Exception as exc:
    payload = {"error": f"read_failed: {exc}"}
if payload is None:
    tail = ""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            tail = "".join(handle.readlines()[-8:])
    except Exception as exc:
        tail = str(exc)
    payload = {
        "error": "sample_command_failed",
        "raw_log": path,
        "tail": tail[-800:],
    }
payload["sample"] = sample
payload["node_requested"] = node
print(json.dumps(payload, sort_keys=True))
PY
}

sample_public_rpc() {
  local sample="$1"
  "$python_bin" - "$sample" "$public_rpc_url" <<'PY'
import json
import sys
import time
import urllib.request

sample = int(sys.argv[1])
url = sys.argv[2]

def rpc(method, params=None, timeout=10):
    data = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).encode()
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc)}

def result(payload):
    return payload.get("result") if isinstance(payload, dict) else None

def block_summary(block):
    if isinstance(block, dict) and isinstance(block.get("block"), dict):
        block = block["block"]
    if not isinstance(block, dict):
        return None
    return {
        "height": block.get("block_index") or block.get("height") or block.get("number") or block.get("block_number"),
        "hash": block.get("hash") or block.get("block_hash"),
        "parent_hash": block.get("parent_hash") or block.get("previous_hash") or block.get("parentHash"),
        "timestamp": block.get("timestamp"),
    }

latest = block_summary(result(rpc("synergy_getLatestBlock")))
height = latest.get("height") if latest else None
cadence = {}
if isinstance(height, int):
    for window in (50, 120, 300):
        prior_height = height - window
        if prior_height >= 0:
            prior = block_summary(result(rpc("synergy_getBlockByNumber", [prior_height])))
            if prior and isinstance(prior.get("timestamp"), (int, float)) and isinstance(latest.get("timestamp"), (int, float)):
                delta = latest["timestamp"] - prior["timestamp"]
                cadence[str(window)] = {
                    "prior_height": prior_height,
                    "prior_hash": prior.get("hash"),
                    "seconds": delta,
                    "seconds_per_block": delta / window if window else None,
                }
            else:
                cadence[str(window)] = {"prior_height": prior_height, "error": "prior_block_unavailable"}
timestamp_delta = None
if latest and isinstance(latest.get("timestamp"), (int, float)):
    timestamp_delta = int(time.time()) - int(latest["timestamp"])
print(json.dumps({
    "sample": sample,
    "node_requested": "public_rpc",
    "spreadsheet_row_used": "not_applicable_public_https",
    "url": url,
    "latest_block": latest,
    "cadence": cadence,
    "timestamp_delta_seconds": timestamp_delta,
}, sort_keys=True))
PY
}

sample_atlas() {
  local sample="$1"
  local sample_dir="$2"
  local host_log="$sample_dir/Atlas_Indexer_DB.log"
  local dag_log="$sample_dir/Atlas_DAG_public.log"

  curl -sS --max-time 15 "$atlas_api_url/dag/status" > "$dag_log" 2>&1 || true
  "${host_access[@]}" run 'Explorer Indexer' \
    'set -euo pipefail
echo "spreadsheet_row_used=true"
sudo -u postgres psql -d synergy_explorer -P pager=off -F $'"'"'\t'"'"' -Atc "select '"'"'blocks'"'"', coalesce(max(number)::text,'"'"'null'"'"'), coalesce(max(hash),'"'"'null'"'"'), coalesce(max(timestamp)::text,'"'"'null'"'"'), count(*)::text from blocks; select '"'"'dag_vertices'"'"', coalesce(max(block_number)::text,'"'"'null'"'"'), coalesce(max(block_hash),'"'"'null'"'"'), coalesce(max(created_at)::text,'"'"'null'"'"'), count(*)::text from dag_vertices; select '"'"'network_snapshots'"'"', coalesce(max(latest_block)::text,'"'"'null'"'"'), coalesce(max(indexed_at)::text,'"'"'null'"'"'), count(*)::text from network_snapshots;" 2>&1' \
    --timeout 60 > "$host_log" 2>&1 || true

  "$python_bin" - "$sample" "$atlas_api_url" "$host_log" "$dag_log" <<'PY'
import json
import sys

sample = int(sys.argv[1])
atlas_api_url = sys.argv[2]
host_log = sys.argv[3]
dag_log = sys.argv[4]
db = {}
spreadsheet_row_used = False
try:
    with open(host_log, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if "spreadsheet_row_used=true" in line:
                spreadsheet_row_used = True
            parts = line.split("\t")
            if not parts:
                continue
            if parts[0] == "blocks" and len(parts) >= 5:
                db["blocks"] = {"latest_height": int(parts[1]) if parts[1].isdigit() else None, "latest_hash": parts[2], "latest_timestamp": parts[3], "count": int(parts[4]) if parts[4].isdigit() else None}
            elif parts[0] == "dag_vertices" and len(parts) >= 5:
                db["dag_vertices"] = {"latest_height": int(parts[1]) if parts[1].isdigit() else None, "latest_hash": parts[2], "latest_timestamp": parts[3], "count": int(parts[4]) if parts[4].isdigit() else None}
            elif parts[0] == "network_snapshots" and len(parts) >= 4:
                db["network_snapshots"] = {"latest_height": int(parts[1]) if parts[1].isdigit() else None, "indexed_at": parts[2], "count": int(parts[3]) if parts[3].isdigit() else None}
except Exception as exc:
    db["error"] = str(exc)

dag = None
try:
    with open(dag_log, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    dag = json.loads(text)
except Exception as exc:
    dag = {"error": str(exc)}

print(json.dumps({
    "sample": sample,
    "node_requested": "atlas",
    "spreadsheet_row_used": spreadsheet_row_used,
    "atlas_api_url": atlas_api_url,
    "db": db,
    "public_dag_status": dag,
    "raw_logs": {"db": host_log, "dag": dag_log},
}, sort_keys=True))
PY
}

summarize_sample() {
  local sample="$1"
  "$python_bin" - "$out_dir" "$sample" "$soak_scope" "$max_rpc_lag_blocks" "$max_support_lag_blocks" "$max_atlas_lag_blocks" "$expected_validator_sha" "$expected_rpc_sha" "$expected_val5_sha" "$validator_rows_csv" "$relayer_rows_csv" <<'PY'
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
sample = int(sys.argv[2])
soak_scope = sys.argv[3]
max_rpc_lag = int(sys.argv[4])
max_support_lag = int(sys.argv[5])
max_atlas_lag = int(sys.argv[6])
expected_validator_sha = sys.argv[7]
expected_rpc_sha = sys.argv[8]
expected_val5_sha = sys.argv[9]
validators = {item for item in sys.argv[10].split(",") if item}
relayers = {item for item in sys.argv[11].split(",") if item}
expected_validator_shas = {node: expected_validator_sha for node in validators}
expected_validator_shas["Val5"] = expected_val5_sha
failures = []
warnings = []
entries = []
previous_validator_height = None

def load_jsonl(path):
    values = []
    if not path.exists():
        return values
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                values.append(json.loads(line))
            except Exception:
                pass
    return values

all_samples = load_jsonl(out_dir / "samples.jsonl")
for value in all_samples:
    if value.get("sample") == sample and value.get("node_requested"):
        entries.append(value)
    if value.get("sample") == sample - 1 and value.get("node_requested") in validators:
        lock = value.get("canonical_lock")
        if isinstance(lock, dict) and isinstance(lock.get("height"), int):
            previous_validator_height = max(previous_validator_height or 0, lock["height"])

by_node = {value.get("node_requested"): value for value in entries}
validator_heights = {}
validator_hashes = {}
for node in validators:
    value = by_node.get(node)
    if not value:
        failures.append(f"{node}: missing sample")
        continue
    if value.get("error"):
        failures.append(f"{node}: sample error {value.get('error')}")
        continue
    lock = value.get("canonical_lock")
    if isinstance(lock, dict) and isinstance(lock.get("height"), int):
        validator_heights[node] = lock["height"]
        validator_hashes[node] = lock.get("hash")
    else:
        failures.append(f"{node}: missing canonical lock")
    if value.get("quarantine_marker"):
        failures.append(f"{node}: quarantine marker present")
    if value.get("deleted_inode_process"):
        failures.append(f"{node}: deleted-inode runtime process")
    if value.get("process_count") != 1:
        failures.append(f"{node}: process count {value.get('process_count')} != 1")
    expected_sha = expected_validator_shas.get(node, expected_validator_sha)
    if value.get("runtime_sha256") != expected_sha:
        failures.append(f"{node}: runtime checksum drift {value.get('runtime_sha256')} expected {expected_sha}")
    locks_above = value.get("vote_locks_above_canonical")
    if isinstance(locks_above, int) and locks_above > 0:
        failures.append(f"{node}: vote locks above canonical={locks_above}")

if len(validator_heights) == len(validators):
    max_height = max(validator_heights.values())
    min_height = min(validator_heights.values())
    if previous_validator_height is not None and max_height <= previous_validator_height:
        failures.append(f"stall: validator head did not advance past previous sample {previous_validator_height}")
    if max_height - min_height > 5:
        failures.append(f"validator lag too high: min={min_height} max={max_height}")
validator_head = max(validator_heights.values()) if validator_heights else None

common_values = [value for value in load_jsonl(out_dir / "common-height.jsonl") if value.get("sample") == sample and value.get("node_requested")]
common_hashes = {}
common_height = None
for value in common_values:
    node = value.get("node_requested")
    if node in validators | relayers | {"RPC Gateway"}:
        if value.get("found") and value.get("hash"):
            common_hashes[node] = value["hash"]
            common_height = value.get("common_height")
        else:
            failures.append(f"{node}: common-height block missing at {value.get('common_height')}")
if common_hashes and len(set(common_hashes.values())) != 1:
    failures.append(f"same-height split at common height {common_height}: {common_hashes}")

rpc_gateway = by_node.get("RPC Gateway")
if rpc_gateway:
    if rpc_gateway.get("runtime_sha256") != expected_rpc_sha:
        failures.append(f"RPC Gateway: runtime checksum drift {rpc_gateway.get('runtime_sha256')}")
    if rpc_gateway.get("deleted_inode_process"):
        failures.append("RPC Gateway: deleted-inode runtime process")
    listener_process_count = rpc_gateway.get("listener_process_count")
    process_count = rpc_gateway.get("process_count")
    if isinstance(listener_process_count, int):
        if listener_process_count != 1:
            failures.append(f"RPC Gateway: listener process count {listener_process_count} != 1")
        elif process_count != 1:
            warnings.append(
                f"RPC Gateway: process count {process_count}, listener process count 1; non-listener runtime process ignored"
            )
    elif process_count != 1:
        failures.append(
            f"RPC Gateway: process count {process_count} != 1 and listener ownership unavailable"
        )
    latest = rpc_gateway.get("latest_block")
    rpc_gateway_height = latest.get("height") if isinstance(latest, dict) else None
    if validator_head is not None and isinstance(rpc_gateway_height, int):
        lag = validator_head - rpc_gateway_height
        if lag > max_support_lag:
            failures.append(f"RPC Gateway lag {lag} blocks > {max_support_lag}")
    else:
        failures.append("RPC Gateway latest height unavailable")

for node in relayers:
    value = by_node.get(node)
    if not value:
        failures.append(f"{node}: missing sample")
        continue
    if value.get("runtime_sha256") != expected_validator_sha:
        failures.append(f"{node}: runtime checksum drift {value.get('runtime_sha256')}")
    if value.get("deleted_inode_process"):
        failures.append(f"{node}: deleted-inode runtime process")
    if value.get("process_count") != 1:
        failures.append(f"{node}: process count {value.get('process_count')} != 1")
    latest = value.get("latest_block")
    relayer_height = latest.get("height") if isinstance(latest, dict) else None
    if validator_head is not None and isinstance(relayer_height, int):
        lag = validator_head - relayer_height
        if lag > max_support_lag:
            failures.append(f"{node} lag {lag} blocks > {max_support_lag}")
    else:
        failures.append(f"{node}: latest height unavailable")

public_rpc = by_node.get("public_rpc")
public_height = None
if public_rpc:
    latest = public_rpc.get("latest_block")
    if isinstance(latest, dict):
        public_height = latest.get("height")
    if validator_head is not None and isinstance(public_height, int):
        lag = validator_head - public_height
        if lag > max_rpc_lag:
            failures.append(f"public RPC lag {lag} blocks > {max_rpc_lag}")
    else:
        failures.append("public RPC latest height unavailable")
    cadence_warnings = []
    for window, cadence in (public_rpc.get("cadence") or {}).items():
        spb = cadence.get("seconds_per_block") if isinstance(cadence, dict) else None
        if isinstance(spb, (int, float)) and spb > 4.0:
            cadence_warnings.append(f"cadence {window} blocks outside expected range: {spb:.3f}s")
    warnings.extend(cadence_warnings)
    if cadence_warnings and sample > 1:
        previous_summaries = [
            value for value in load_jsonl(out_dir / "sample-summaries.jsonl")
            if value.get("sample") == sample - 1
        ]
        previous_warnings = previous_summaries[-1].get("warnings") if previous_summaries else []
        if any(str(item).startswith("cadence ") for item in previous_warnings or []):
            failures.append("cadence warnings persisted across consecutive samples")
else:
    failures.append("public RPC sample missing")

atlas = by_node.get("atlas")
atlas_block_height = None
atlas_dag_height = None
if atlas:
    db = atlas.get("db") or {}
    atlas_block_height = ((db.get("network_snapshots") or {}).get("latest_height")
        or (db.get("blocks") or {}).get("latest_height"))
    atlas_dag_height = (db.get("dag_vertices") or {}).get("latest_height")
    if validator_head is not None and isinstance(atlas_block_height, int):
        lag = validator_head - atlas_block_height
        if lag > max_atlas_lag:
            message = f"Atlas block lag {lag} blocks > {max_atlas_lag}"
            if soak_scope == "full":
                failures.append(message)
            else:
                warnings.append(message)
    else:
        message = "Atlas block height unavailable"
        if soak_scope == "full":
            failures.append(message)
        else:
            warnings.append(message)
    if validator_head is not None and isinstance(atlas_dag_height, int):
        dag_lag = validator_head - atlas_dag_height
        if dag_lag > max_atlas_lag:
            message = f"Atlas DAG lag {dag_lag} blocks > {max_atlas_lag}"
            if soak_scope == "full":
                failures.append(message)
            else:
                warnings.append(message)
else:
    message = "Atlas sample missing"
    if soak_scope == "full":
        failures.append(message)
    else:
        warnings.append(message)

summary = {
    "sample": sample,
    "soak_scope": soak_scope,
    "validator_heights": validator_heights,
    "validator_hashes": validator_hashes,
    "common_height": common_height,
    "common_hash": next(iter(set(common_hashes.values()))) if common_hashes and len(set(common_hashes.values())) == 1 else None,
    "public_rpc_height": public_height,
    "atlas_block_height": atlas_block_height,
    "atlas_dag_height": atlas_dag_height,
    "rpc_gateway_process_count": rpc_gateway.get("process_count") if rpc_gateway else None,
    "rpc_gateway_listener_process_count": rpc_gateway.get("listener_process_count") if rpc_gateway else None,
    "rpc_gateway_listener_owner_pids": rpc_gateway.get("listener_owner_pids") if rpc_gateway else None,
    "failures": failures,
    "warnings": warnings,
}
print(json.dumps(summary, sort_keys=True))
PY
}

preserve_failure_evidence() {
  local sample="$1"
  local failure_dir="$out_dir/failure-evidence-sample-$sample"
  mkdir -p "$failure_dir"
  cp "$out_dir"/samples.jsonl "$out_dir"/common-height.jsonl "$out_dir"/sample-summaries.jsonl "$failure_dir"/ 2>/dev/null || true
  for entry in "${nodes[@]}"; do
    IFS='|' read -r node auth fallback_auth env_spec <<< "$entry"
    local safe_node="${node// /_}"
    local log="$failure_dir/${safe_node}_preserve.log"
    run_host_file "$node" scripts/testnet/preserve-live-consensus-evidence.sh "$log" "$auth" "$fallback_auth" "$env_spec" || true
  done
  "${host_access[@]}" run-file 'Explorer Indexer' scripts/testnet/preserve-live-consensus-evidence.sh \
    --timeout 120 --remote-env SYNERGY_WORKSPACE=/opt/synergy/Node-EXP > "$failure_dir/Explorer_Indexer_preserve.log" 2>&1 || true
  echo "failure_evidence_dir=$failure_dir" >> "$out_dir/manifest.txt"
}

end_epoch=$(( $(date +%s) + duration_seconds ))
sample=0
while true; do
  sample_started_epoch="$(date +%s)"
  sample_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  sample_dir="$out_dir/raw/sample-$sample"
  mkdir -p "$sample_dir"
  echo "{\"sample\":$sample,\"sample_started_utc\":\"$sample_started\"}" >> "$out_dir/samples.jsonl"

  for entry in "${nodes[@]}"; do
    IFS='|' read -r node auth fallback_auth env_spec <<< "$entry"
    safe_node="${node// /_}"
    log="$sample_dir/$safe_node.log"
    run_host_file "$node" scripts/testnet/remote-consensus-sample.sh "$log" "$auth" "$fallback_auth" "$env_spec" || true
    extract_json_payload "$sample" "$node" "$log" >> "$out_dir/samples.jsonl"
  done

  sample_public_rpc "$sample" >> "$out_dir/samples.jsonl"
  sample_atlas "$sample" "$sample_dir" >> "$out_dir/samples.jsonl"

  common_height="$(
    "$python_bin" - "$out_dir/samples.jsonl" "$sample" <<'PY'
import json
import sys

path = sys.argv[1]
sample = int(sys.argv[2])
heights = []
with open(path, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        try:
            value = json.loads(line)
        except Exception:
            continue
        if value.get("sample") != sample or "node_requested" not in value:
            continue
        lock = value.get("canonical_lock")
        if isinstance(lock, dict) and isinstance(lock.get("height"), int):
            heights.append(lock["height"])
if heights:
    print(min(heights))
PY
  )"

  if [[ -n "$common_height" ]]; then
    echo "{\"sample\":$sample,\"common_height\":$common_height,\"common_check_started_utc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" >> "$out_dir/common-height.jsonl"
    for entry in "${nodes[@]}"; do
      IFS='|' read -r node auth fallback_auth env_spec <<< "$entry"
      safe_node="${node// /_}"
      log="$sample_dir/common-$safe_node.log"
      run_host_file "$node" scripts/testnet/remote-block-at-height.sh "$log" "$auth" "$fallback_auth" "$env_spec" "SYNERGY_BLOCK_HEIGHT=$common_height" || true
      "$python_bin" - "$sample" "$node" "$common_height" "$log" >> "$out_dir/common-height.jsonl" <<'PY'
import json
import sys

sample = int(sys.argv[1])
node = sys.argv[2]
height = int(sys.argv[3])
path = sys.argv[4]
payload = None
with open(path, "r", encoding="utf-8", errors="replace") as handle:
    for line in handle:
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
            except Exception:
                pass
if payload is None:
    payload = {"found": False, "error": "no_json_payload", "raw_log": path}
payload["sample"] = sample
payload["node_requested"] = node
payload["common_height"] = height
print(json.dumps(payload, sort_keys=True))
PY
    done
  fi

  summary="$(summarize_sample "$sample")"
  echo "$summary" >> "$out_dir/sample-summaries.jsonl"
  echo "$summary"
  failure_count="$("$python_bin" -c 'import json,sys; print(len(json.loads(sys.argv[1]).get("failures") or []))' "$summary")"
  if [[ "$failure_count" != "0" ]]; then
    echo "failed_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out_dir/manifest.txt"
    echo "failed_sample=$sample" >> "$out_dir/manifest.txt"
    echo "$summary" > "$out_dir/failure-summary.json"
    preserve_failure_evidence "$sample"
    echo "soak_failed=true"
    echo "soak_dir=$out_dir"
    exit 20
  fi

  now="$(date +%s)"
  if (( now >= end_epoch )); then
    break
  fi
  next_epoch=$(( sample_started_epoch + interval_seconds ))
  sleep_for=$(( next_epoch - now ))
  if (( sleep_for < 1 )); then
    sleep_for=1
  fi
  if (( now + sleep_for > end_epoch )); then
    sleep_for=$(( end_epoch - now ))
  fi
  sleep "$sleep_for"
  sample=$((sample + 1))
done

echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$out_dir/manifest.txt"
echo "soak_passed=true"
echo "soak_dir=$out_dir"
