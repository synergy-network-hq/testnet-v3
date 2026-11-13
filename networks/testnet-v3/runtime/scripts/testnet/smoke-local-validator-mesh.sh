#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CALLER_PWD="$(pwd -P)"
BINARY="${ROOT_DIR}/target/release/synergy-testnet"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-2}"
MIN_HEIGHT="${MIN_HEIGHT:-2}"
KEEP_WORKDIR="false"
LEAVE_RUNNING="false"
SKIP_PEER_MESH_CHECK="${SKIP_PEER_MESH_CHECK:-false}"
WORKDIR=""
CREATED_WORKDIR="false"

VALIDATOR_ADDRESSES=(
  "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
  "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"
  "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
  "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5"
  "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f"
)
P2P_PORTS=(5722 5723 5724 5725 5726)
RPC_PORTS=(5740 5741 5742 5743 5744)
WS_PORTS=(5760 5761 5762 5763 5764)
START_VALIDATOR_COUNT="${START_VALIDATOR_COUNT:-5}"
PIDS=()
WORKSPACES=()
CONSENSUS_PRIVATE_KEY_FILES=()
LOCAL_CONFIG_DIR=""
LOCAL_GENESIS_FILE=""
LOCAL_INITIAL_VALIDATORS_DIR=""
RUNTIME_SHA256=""

usage() {
  cat <<USAGE
Usage: $0 [--binary PATH] [--timeout SECONDS] [--workdir PATH] [--keep-workdir] [--leave-running]

Starts the first five local validators against the canonical five-validator
genesis and fails unless all active validators form the full validator peer
mesh and advance chain height from genesis within the timeout.

Environment:
  MIN_HEIGHT  Minimum height every validator must reach before success (default: 2).
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      BINARY="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    --workdir)
      WORKDIR="$2"
      shift 2
      ;;
    --keep-workdir)
      KEEP_WORKDIR="true"
      shift
      ;;
    --leave-running)
      KEEP_WORKDIR="true"
      LEAVE_RUNNING="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$BINARY" != /* ]]; then
  BINARY="${CALLER_PWD}/${BINARY}"
fi

if [[ ! -x "$BINARY" ]]; then
  echo "Binary not found at $BINARY; building release node binary..." >&2
  cargo build --manifest-path "$ROOT_DIR/src/Cargo.toml" --release --bin synergy-testnet
fi

sha256_for_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    sha256sum "$file" | awk '{print $1}'
  fi
}

RUNTIME_SHA256="$(sha256_for_file "$BINARY")"

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-testnet-mesh-smoke.XXXXXX")"
  CREATED_WORKDIR="true"
else
  mkdir -p "$WORKDIR"
fi

cleanup() {
  if [[ "$LEAVE_RUNNING" == "true" ]]; then
    echo "Smoke-test mesh left running at: $WORKDIR"
    printf 'Stop with: for f in %q/validator-*/node.pid; do kill "$(cat "$f")" 2>/dev/null || true; done\n' "$WORKDIR"
    return 0
  fi

  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done

  for _ in {1..10}; do
    local running="false"
    for pid in "${PIDS[@]:-}"; do
      if kill -0 "$pid" 2>/dev/null; then
        running="true"
        break
      fi
    done
    [[ "$running" == "false" ]] && break
    sleep 1
  done

  for pid in "${PIDS[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -9 "$pid" 2>/dev/null || true
    fi
  done

  if [[ "$KEEP_WORKDIR" == "true" || "$CREATED_WORKDIR" != "true" ]]; then
    echo "Smoke-test workspace preserved at: $WORKDIR"
  else
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

assert_port_available() {
  local port="$1"
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Smoke-test port already in use: $port" >&2
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >&2 || true
    exit 1
  fi
}

assert_ports_available() {
  local count="$1"
  local i
  for ((i = 0; i < count; i++)); do
    assert_port_available "${P2P_PORTS[$i]}"
    assert_port_available "${RPC_PORTS[$i]}"
    assert_port_available "${WS_PORTS[$i]}"
  done
}

assert_ports_available "$START_VALIDATOR_COUNT"

json_array() {
  python3 - "$@" <<'PY'
import json
import sys
print(json.dumps(sys.argv[1:]))
PY
}

prepare_test_consensus_material() {
  local key_root="${WORKDIR}/test-only-consensus-keys"
  local public_keys_tsv="${key_root}/public-keys.tsv"
  local index

  LOCAL_CONFIG_DIR="${WORKDIR}/local-test-config"
  LOCAL_GENESIS_FILE="${LOCAL_CONFIG_DIR}/genesis.json"
  LOCAL_INITIAL_VALIDATORS_DIR="${LOCAL_CONFIG_DIR}/genesis-validators"

  mkdir -p "$key_root" "$LOCAL_CONFIG_DIR"
  cp "$ROOT_DIR/config/genesis.json" "$LOCAL_GENESIS_FILE"
  cp -R "$ROOT_DIR/config/genesis-validators" "$LOCAL_INITIAL_VALIDATORS_DIR"
  : > "$public_keys_tsv"

  for index in $(seq 1 "$START_VALIDATOR_COUNT"); do
    local key_dir="${key_root}/validator-${index}"
    local private_key_file="${key_dir}/private.key"
    local public_key_file="${key_dir}/public.key"
    local validator_address="${VALIDATOR_ADDRESSES[$((index - 1))]}"

    mkdir -p "$key_dir"
    "$BINARY" generate-keypair --output "$key_dir" --class 1 >/dev/null
    chmod 700 "$key_dir"
    chmod 600 "$private_key_file"
    printf '%s\tfn-dsa:%s\n' "$validator_address" "$(tr -d '\n\r ' < "$public_key_file")" >> "$public_keys_tsv"
    CONSENSUS_PRIVATE_KEY_FILES[$((index - 1))]="$private_key_file"
  done

  python3 - "$LOCAL_GENESIS_FILE" "$LOCAL_INITIAL_VALIDATORS_DIR" "$public_keys_tsv" <<'PY'
import json
import pathlib
import sys

import blake3

genesis_path = pathlib.Path(sys.argv[1])
identity_dir = pathlib.Path(sys.argv[2])
public_keys_path = pathlib.Path(sys.argv[3])

public_keys = {}
for line in public_keys_path.read_text(encoding="utf-8").splitlines():
    address, public_key = line.split("\t", 1)
    public_keys[address] = public_key

def canonical_json(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(
            json.dumps(key, separators=(",", ":")) + ":" + canonical_json(value[key])
            for key in sorted(value)
        ) + "}"
    raise TypeError(type(value).__name__)

def hash_json(value):
    return blake3.blake3(canonical_json(value).encode("utf-8")).hexdigest()

def remove_dotted(value, dotted):
    current = value
    parts = dotted.split(".")
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict):
        current.pop(parts[-1], None)

def genesis_hash_payload(genesis):
    payload = {
        key: genesis[key]
        for key in genesis["canonicalization"]["genesis_hash_inputs"]
        if key in genesis
    }
    payload = json.loads(json.dumps(payload))
    exclusions = set(genesis["canonicalization"].get("excluded_from_genesis_hash", []))
    exclusions.update({
        "integrity.genesis_hash",
        "integrity.signed_by",
        "integrity.draft_artifact_sha256",
        "integrity.recompute_required",
        "integrity.recompute_reason",
        "p2p_identity.network_magic_bytes",
        "p2p_identity.provisional_derivation_note",
    })
    for dotted in sorted(exclusions):
        remove_dotted(payload, dotted)
    return payload

def network_magic_bytes_for(caip2, genesis_hash):
    data = b"synergy-network-magic-v1" + caip2.encode("utf-8") + genesis_hash.encode("utf-8")
    return blake3.blake3(data).digest()[:4].hex()

def patch_consensus_keys(value):
    if isinstance(value, dict):
        address = (
            value.get("operator_address")
            or value.get("validator_address")
            or value.get("address")
        )
        if address in public_keys:
            if "consensus_public_key" in value:
                value["consensus_public_key"] = public_keys[address]
            if "consensus_key_type" in value:
                value["consensus_key_type"] = "FN-DSA-1024"
            consensus_key = value.get("consensus_key")
            if isinstance(consensus_key, dict):
                consensus_key["algorithm"] = "FN-DSA-1024"
                consensus_key["public_key"] = public_keys[address]
        for child in value.values():
            patch_consensus_keys(child)
    elif isinstance(value, list):
        for child in value:
            patch_consensus_keys(child)

genesis = json.loads(genesis_path.read_text(encoding="utf-8"))
patch_consensus_keys(genesis)

empty_hash = blake3.blake3(b"").hexdigest()
validator_set = genesis["contracts"]["validator_registry"]["init_params"]["validators"]
genesis["integrity"]["validator_hash"] = hash_json(genesis["validators"])
validator_set_hash = hash_json(validator_set)
genesis["contracts"]["validator_registry"]["init_params"]["validator_set_hash"] = validator_set_hash
genesis["integrity"]["validator_set_hash"] = validator_set_hash
genesis["integrity"]["allocation_hash"] = hash_json(genesis["allocations"])
genesis["header"]["parent_hash"] = "0" * 64
genesis["header"]["transactions_root"] = empty_hash
genesis["header"]["receipts_root"] = empty_hash
genesis["integrity"]["contract_hash"] = hash_json(genesis["contracts"])
state_root = hash_json({
    "accounts": genesis["accounts"],
    "balances": genesis["balances"],
    "allocations": genesis["allocations"],
    "contracts": genesis["contracts"],
    "consensus": genesis["consensus"],
    "genesis_message": genesis["genesis_message"],
    "governance": genesis["governance"],
    "modules": genesis["modules"],
    "network": genesis["network"],
    "network_identity": genesis["network_identity"],
    "reserved_addresses": genesis["system_reserved_addresses"],
    "security": genesis["security"],
    "synergy_state": genesis["synergy_state"],
    "token": genesis["token"],
    "validators": genesis["validators"],
})
data_root = hash_json({
    "contracts": genesis["contracts"],
    "modules": genesis["modules"],
    "precompiles": genesis["precompiles"],
})
genesis["header"]["state_root"] = state_root
genesis["header"]["data_root"] = data_root
genesis["integrity"]["state_root"] = state_root
genesis["integrity"]["contract_hash"] = hash_json(genesis["contracts"])
genesis["integrity"]["recompute_required"] = False
genesis_hash = hash_json(genesis_hash_payload(genesis))
genesis["integrity"]["genesis_hash"] = genesis_hash
caip2 = genesis["network_identity"]["canonical_caip2"]["value"]
genesis["p2p_identity"]["network_magic_bytes"] = network_magic_bytes_for(caip2, genesis_hash)
genesis_path.write_text(json.dumps(genesis, indent=2, sort_keys=False) + "\n", encoding="utf-8")

for identity_path in sorted(identity_dir.glob("*.identity.json")):
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    patch_consensus_keys(identity)
    identity_path.write_text(json.dumps(identity, indent=2, sort_keys=False) + "\n", encoding="utf-8")
PY
}

rpc_height() {
  local port="$1"
  python3 - "$port" <<'PY'
import json
import sys
import urllib.error
import urllib.request

port = int(sys.argv[1])
payload = json.dumps({
    "jsonrpc": "2.0",
    "method": "synergy_blockNumber",
    "params": [],
    "id": 1,
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=2) as response:
        body = json.loads(response.read().decode())
except Exception:
    print(-1)
    raise SystemExit(0)

result = body.get("result", -1)
try:
    if isinstance(result, str):
        print(int(result, 0))
    else:
        print(int(result))
except Exception:
    print(-1)
PY
}

rpc_peer_mesh_status() {
  local port="$1"
  local self_address="$2"
  shift 2
  python3 - "$port" "$self_address" "$@" <<'PY'
import json
import sys
import urllib.request

port = int(sys.argv[1])
self_address = sys.argv[2]
expected = set(sys.argv[3:])
payload = json.dumps({
    "jsonrpc": "2.0",
    "method": "synergy_getPeerInfo",
    "params": [],
    "id": 1,
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=2) as response:
        body = json.loads(response.read().decode())
except Exception:
    print("rpc-unavailable")
    raise SystemExit(1)

peers = body.get("result", {}).get("peers", [])
seen = {
    str(peer.get("validator_address", "")).strip()
    for peer in peers
    if str(peer.get("validator_address", "")).strip()
}
seen.discard(self_address)
missing = sorted(expected - seen)
extra = sorted(seen - expected)
status = "ok" if not missing and not extra else "incomplete"
summary = ",".join(sorted(seen)) if seen else "(none)"
if status == "ok":
    print(f"ok:{summary}")
    raise SystemExit(0)
print(
    "incomplete:"
    + summary
    + "|missing="
    + (",".join(missing) if missing else "(none)")
    + "|extra="
    + (",".join(extra) if extra else "(none)")
)
raise SystemExit(1)
PY
}

log_snippet() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  python3 - "$file" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="replace")
pattern = re.compile(
    r"(?ms)^.*?(Handshake received|Received status|Waiting for validator mesh status sync before block production|Vote request broadcast|Validator missed vote deadline|Peer disconnected|Failed to dial peer|Incoming peer connection|Sync complete).*$"
)
matches = pattern.findall(text)
lines = []
for line in text.splitlines():
    if any(token in line for token in [
        "Handshake received",
        "Received status",
        "Waiting for validator mesh status sync before block production",
        "Vote request broadcast",
        "Validator missed vote deadline",
        "Peer disconnected",
        "Failed to dial peer",
        "Incoming peer connection",
        "Sync complete",
    ]):
        lines.append(line)
    elif lines and line.startswith("  Metadata:"):
        lines.append(line)
trimmed = lines[-40:]
print("\n".join(trimmed))
PY
}

create_workspace() {
  local index="$1"
  local workspace="${WORKDIR}/validator-${index}"
  local validator_address="${VALIDATOR_ADDRESSES[$((index - 1))]}"
  local consensus_private_key="${CONSENSUS_PRIVATE_KEY_FILES[$((index - 1))]}"
  local p2p_port="${P2P_PORTS[$((index - 1))]}"
  local rpc_port="${RPC_PORTS[$((index - 1))]}"
  local ws_port="${WS_PORTS[$((index - 1))]}"
  local node_name="smoke-validator-${index}"
  local additional_targets=()
  local i

  mkdir -p "$workspace/config/validator" "$workspace/data" "$workspace/logs"
  cp "$LOCAL_GENESIS_FILE" "$workspace/config/genesis.json"
  cp -R "$LOCAL_INITIAL_VALIDATORS_DIR" "$workspace/config/"
  cp "$consensus_private_key" "$workspace/config/validator/consensus.private.key"
  chmod 600 "$workspace/config/validator/consensus.private.key"

  for i in "${!P2P_PORTS[@]}"; do
    if [[ "$i" -ne $((index - 1)) ]]; then
      additional_targets+=("127.0.0.1:${P2P_PORTS[$i]}")
    fi
  done

  local allowed_json
  local targets_json
  allowed_json="$(json_array "${VALIDATOR_ADDRESSES[@]}")"
  targets_json="$(json_array "${additional_targets[@]}")"

  cat > "${workspace}/config/node.toml" <<CONFIG
[identity]
node_id = "${validator_address}"
role = "validator"
role_display = "Validator Node"
environment = "testnet"
display_environment = "Testnet"
address = "${validator_address}"
label = "Smoke Validator ${index}"

[network]
id = 1264
name = "synergy-testnet"
chain_name = "synergy-testnet"
chain_id = 1264
p2p_port = ${p2p_port}
rpc_port = ${rpc_port}
ws_port = ${ws_port}
p2p_listen = "127.0.0.1:${p2p_port}"
bootnodes = []
seed_servers = []
bootstrap_dns_records = []
additional_dial_targets = ${targets_json}
max_peers = 32
public_host = "127.0.0.1"

[blockchain]
block_time = 2
max_gas_limit = "0x2fefd8"
chain_id = 1264

[consensus]
algorithm = "Proof of Synergy"
block_time_secs = 2
epoch_length = 1000
emergency_stable_committee_mode = true
freeze_validator_set = true
freeze_score_weighted_proposer_order = true
vote_only_rejoin_enabled = true
vote_only_probation_blocks = 1000
min_validators = 4
validator_cluster_size = 5
validator_vote_threshold = 0
max_validators = ${START_VALIDATOR_COUNT}
status_ready_gate_enabled = true
status_ready_min_validators = 4
status_ready_genesis_grace_secs = 60
allow_genesis_status_bypass = false
mesh_settle_secs = 3
leader_timeout_secs = ${LEADER_TIMEOUT_SECS:-120}
vote_timeout_secs = ${VOTE_TIMEOUT_SECS:-12}
block_timeout_secs = 30
penalization_enabled = false
synergy_score_decay_rate = 0.05
vrf_enabled = true
vrf_seed_epoch_interval = 1000
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "info"
log_file = "${workspace}/logs/synergy-testnet.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "127.0.0.1:${rpc_port}"
enable_http = true
http_port = ${rpc_port}
enable_ws = true
ws_port = ${ws_port}
enable_grpc = true
grpc_port = ${rpc_port}
cors_enabled = false
cors_origins = []

[p2p]
listen_address = "127.0.0.1:${p2p_port}"
public_address = "127.0.0.1:${p2p_port}"
node_name = "${node_name}"
enable_discovery = false
discovery_port = $((5800 + index))
heartbeat_interval = 5
bootstrap_refresh_secs = 60

[storage]
database = "rocksdb"
engine = "rocksdb"
path = "${workspace}/data"
mode = "role-bounded"
enable_pruning = false
pruning_interval = 86400

[node]
bootstrap_only = false
auto_register_validator = false
validator_address = "${validator_address}"
strict_validator_allowlist = false
allowed_validator_addresses = ${allowed_json}

[telemetry]
metrics_bind = "127.0.0.1:$((6000 + index))"
structured_logs = true
log_level = "info"

[policy]
allow_remote_admin = false
require_signed_updates = true
quarantine_on_policy_failure = true
quarantine_on_key_role_mismatch = true
connectivity_fail_mode = "warn-and-continue"

[wallet]
reward_address = "${validator_address}"
sponsored_stake_snrg = "5000.000000000"
sponsored_stake_nwei = "5000000000000"
treasury_wallet = "synw1rmj046xra4059csdc94pltfjsr5tkduhuc74ep"
stake_vault_wallet = "synl1ta7vczypesta385h64fw3n5sfsqg9sqv3upp5t"

[bootstrap]
status = "configured"
note = "Local smoke validator mesh"

[role]
compiled_profile = "validator_node"
services = ["p2p", "consensus", "mempool", "state", "aegis-verifier", "telemetry"]

[validator]
participation = "active"
verify_quorum_certificates = true
state_sync_before_join = true
CONFIG

  WORKSPACES+=("$workspace")
}

start_node() {
  local workspace="$1"
  local config_path="${workspace}/config/node.toml"
  local stdout_path="${workspace}/logs/control-start.stdout.log"
  local stderr_path="${workspace}/logs/control-start.stderr.log"
  local node_name
  local validator_index
  local validator_address
  node_name="$(basename "$workspace")"
  validator_index="${node_name##*-}"
  validator_address="${VALIDATOR_ADDRESSES[$((validator_index - 1))]}"

  (
    cd "$workspace"
    SYNERGY_PROJECT_ROOT="$workspace" \
    SYNERGY_CONFIG_PATH="$config_path" \
    SYNERGY_GENESIS_FILE="$workspace/config/genesis.json" \
    SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_FILE="$workspace/config/validator/consensus.private.key" \
    SYNERGY_RUNTIME_SHA256="$RUNTIME_SHA256" \
    SYNERGY_TIMING_TRACE_NODE_ROLE="validator" \
    SYNERGY_TIMING_TRACE_NODE_NAME="$node_name" \
    SYNERGY_TIMING_TRACE_VALIDATOR="$validator_address" \
    SYNERGY_CONSENSUS_TIMING_TRACE_PATH="$workspace/data/consensus_timing_trace.jsonl" \
    exec "$BINARY" start --config "$config_path" >"$stdout_path" 2>"$stderr_path"
  ) &
  local pid="$!"
  PIDS+=("$pid")
  echo "$pid" > "${workspace}/node.pid"
}

print_diagnostics() {
  local i
  echo
  echo "Smoke test diagnostics:"
  for i in "${!WORKSPACES[@]}"; do
    local workspace="${WORKSPACES[$i]}"
    local rpc_port="${RPC_PORTS[$i]}"
    local height
    local self_address="${VALIDATOR_ADDRESSES[$i]}"
    local expected_peers=()
    height="$(rpc_height "$rpc_port")"
    for j in "${!WORKSPACES[@]}"; do
      if [[ "$j" -ne "$i" ]]; then
        expected_peers+=("${VALIDATOR_ADDRESSES[$j]}")
      fi
    done
    echo
    echo "validator-$((i + 1)) rpc_port=${rpc_port} height=${height} workspace=${workspace}"
    echo "peer-mesh=$(rpc_peer_mesh_status "$rpc_port" "$self_address" "${expected_peers[@]}" 2>/dev/null || true)"
    echo "--- ${workspace}/logs/synergy-testnet.log ---"
    log_snippet "${workspace}/logs/synergy-testnet.log"
    echo "--- ${workspace}/logs/control-start.stderr.log ---"
    tail -n 20 "${workspace}/logs/control-start.stderr.log" 2>/dev/null || true
  done
}

prepare_test_consensus_material

for index in $(seq 1 "$START_VALIDATOR_COUNT"); do
  create_workspace "$index"
done

for workspace in "${WORKSPACES[@]}"; do
  start_node "$workspace"
done

echo "Started local ${START_VALIDATOR_COUNT}-validator smoke mesh against canonical 5-validator genesis in: $WORKDIR"
deadline=$(( $(date +%s) + TIMEOUT_SECS ))
while [[ "$(date +%s)" -lt "$deadline" ]]; do
  ready="true"
  mesh_ready="true"
  min_height=999999999
  max_height=-1
  for i in "${!WORKSPACES[@]}"; do
    height="$(rpc_height "${RPC_PORTS[$i]}")"
    if [[ "$height" -lt 1 ]]; then
      ready="false"
    fi
    if [[ "$height" -ge 0 && "$height" -lt "$min_height" ]]; then
      min_height="$height"
    fi
    if [[ "$height" -gt "$max_height" ]]; then
      max_height="$height"
    fi
  done

  if [[ "$SKIP_PEER_MESH_CHECK" != "true" ]]; then
    for i in "${!WORKSPACES[@]}"; do
      expected_peers=()
      for j in "${!WORKSPACES[@]}"; do
        if [[ "$j" -ne "$i" ]]; then
          expected_peers+=("${VALIDATOR_ADDRESSES[$j]}")
        fi
      done
      if ! rpc_peer_mesh_status "${RPC_PORTS[$i]}" "${VALIDATOR_ADDRESSES[$i]}" "${expected_peers[@]}" >/dev/null; then
        mesh_ready="false"
      fi
    done
  fi

  if [[ "$ready" == "true" && "$mesh_ready" == "true" && "$min_height" -ge "$MIN_HEIGHT" ]]; then
    echo "Smoke test passed: all validators formed the full peer mesh and reached min_height=${min_height}, max_height=${max_height}, required_min_height=${MIN_HEIGHT}."
    exit 0
  fi

  sleep "$POLL_INTERVAL_SECS"
done

echo "Smoke test failed: validators did not all form the full peer mesh and reach height ${MIN_HEIGHT} within ${TIMEOUT_SECS}s." >&2
print_diagnostics >&2
exit 1
