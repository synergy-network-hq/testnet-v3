#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
HOSTS_FILE="${1:-${HOSTS_FILE:-}}"
OUT_DIR="$ROOT_DIR/testnet/runtime/configs"
NODE_ADDRESSES_FILE="${SYNERGY_TESTNET_NODE_ADDRESSES_FILE:-$ROOT_DIR/testnet/runtime/node-addresses.csv}"
MANIFEST_FILE="${SYNERGY_TESTNET_CANONICAL_MANIFEST_FILE:-$ROOT_DIR/../config/operational-manifest.json}"
TESTNET_ENV_DIR_DEFAULT="${TESTNET_ENV_DIR_DEFAULT:-$ROOT_DIR/testnet/runtime/env-files}"
ENV_OVERRIDE_HELPER="${ENV_OVERRIDE_HELPER:-$ROOT_DIR/../scripts/testnet/testnet-env-overrides.sh}"
USE_HOST_OVERRIDES="false"
TESTNET_CHAIN_ID="${TESTNET_CHAIN_ID:-1266}"
TESTNET_NETWORK_NAME="${TESTNET_NETWORK_NAME:-synergy-testnet}"
TESTNET_BLOCK_TIME_SECS="${TESTNET_BLOCK_TIME_SECS:-2}"
TESTNET_EPOCH_LENGTH="${TESTNET_EPOCH_LENGTH:-1000}"
TESTNET_MIN_VALIDATORS="${TESTNET_MIN_VALIDATORS:-4}"
TESTNET_MIN_VALIDATOR_CLUSTER_SIZE="${TESTNET_MIN_VALIDATOR_CLUSTER_SIZE:-5}"
TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE="${TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE:-7}"
TESTNET_STATUS_READY_GATE_ENABLED="${TESTNET_STATUS_READY_GATE_ENABLED:-true}"
TESTNET_STATUS_READY_MIN_VALIDATORS="${TESTNET_STATUS_READY_MIN_VALIDATORS:-4}"
TESTNET_STATUS_READY_GENESIS_GRACE_SECS="${TESTNET_STATUS_READY_GENESIS_GRACE_SECS:-0}"
TESTNET_ALLOW_GENESIS_STATUS_BYPASS="${TESTNET_ALLOW_GENESIS_STATUS_BYPASS:-false}"
TESTNET_MESH_SETTLE_SECS="${TESTNET_MESH_SETTLE_SECS:-1}"
TESTNET_LEADER_TIMEOUT_SECS="${TESTNET_LEADER_TIMEOUT_SECS:-4}"
TESTNET_VOTE_TIMEOUT_SECS="${TESTNET_VOTE_TIMEOUT_SECS:-2}"
TESTNET_BLOCK_TIMEOUT_SECS="${TESTNET_BLOCK_TIMEOUT_SECS:-6}"
TESTNET_CONSENSUS_PENALIZATION_ENABLED="${TESTNET_CONSENSUS_PENALIZATION_ENABLED:-false}"
TESTNET_P2P_BOOTSTRAP_REFRESH_SECS="${TESTNET_P2P_BOOTSTRAP_REFRESH_SECS:-3600}"
TESTNET_P2P_HEARTBEAT_INTERVAL_SECS="${TESTNET_P2P_HEARTBEAT_INTERVAL_SECS:-1}"
ALLOW_WILDCARD_LISTEN="${ALLOW_WILDCARD_LISTEN:-false}"

if [[ -f "$ENV_OVERRIDE_HELPER" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_OVERRIDE_HELPER"
fi

normalize_bool() {
  local raw="${1:-}"
  raw="$(echo "$raw" | tr '[:upper:]' '[:lower:]' | xargs)"
  case "$raw" in
    1|true|yes|on)
      echo "true"
      ;;
    0|false|no|off|"")
      echo "false"
      ;;
    *)
      echo "false"
      ;;
  esac
}

detect_validator_count() {
  python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
validators = manifest.get("validators")
if not isinstance(validators, list):
    raise SystemExit("operational manifest validators must be a list")
print(len(validators))
PY
}

require_positive_integer() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
    echo "$name must be a positive integer, got: $value" >&2
    exit 1
  fi
}

require_nonnegative_integer() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be a non-negative integer, got: $value" >&2
    exit 1
  fi
}

derive_validator_cluster_count() {
  local validator_count="$1"
  local split_threshold=$((TESTNET_MIN_VALIDATOR_CLUSTER_SIZE * 2))
  local cluster_count
  if (( validator_count == 0 )); then
    echo "0"
    return
  fi
  if (( validator_count < split_threshold )); then
    echo "1"
    return
  fi
  if (( validator_count < TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE * 3 )); then
    cluster_count=2
  else
    cluster_count=$((validator_count / TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE))
  fi
  if (( cluster_count < 2 )); then
    cluster_count=2
  fi
  while (( cluster_count > 1 && validator_count / cluster_count < TESTNET_MIN_VALIDATOR_CLUSTER_SIZE )); do
    cluster_count=$((cluster_count - 1))
  done
  echo "$cluster_count"
}

derive_validator_cluster_size() {
  local validator_count="$1"
  local cluster_count
  cluster_count="$(derive_validator_cluster_count "$validator_count")"
  echo $(((validator_count + cluster_count - 1) / cluster_count))
}

derive_validator_quorum() {
  local validator_count="$1"
  if (( validator_count == 0 )); then
    echo "0"
  elif (( validator_count == 5 )); then
    echo "3"
  else
    echo $(((validator_count * 2 + 2) / 3))
  fi
}

if [[ "${SYNERGY_RENDER_CONFIGS_CLUSTER_POLICY_TEST:-false}" == "true" ]]; then
  for fixture in "0:0" "1:1" "9:1" "10:2" "20:2" "21:3" "22:3" "27:3" "28:4" "29:4" "35:5"; do
    validators="${fixture%%:*}"
    expected="${fixture##*:}"
    actual="$(derive_validator_cluster_count "$validators")"
    [[ "$actual" == "$expected" ]] || {
      echo "cluster count mismatch for $validators validators: expected $expected, got $actual" >&2
      exit 1
    }
  done
  [[ "$(derive_validator_quorum 5)" == "3" ]]
  [[ "$(derive_validator_quorum 6)" == "4" ]]
  [[ "$(derive_validator_quorum 7)" == "5" ]]
  echo "Dynamic validator cluster policy QA passed."
  exit 0
fi

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Missing inventory file: $INVENTORY_FILE" >&2
  exit 1
fi

if [[ ! -f "$NODE_ADDRESSES_FILE" ]]; then
  echo "Missing node address file: $NODE_ADDRESSES_FILE" >&2
  exit 1
fi

if [[ ! -f "$MANIFEST_FILE" ]]; then
  echo "Missing operational manifest: $MANIFEST_FILE" >&2
  exit 1
fi

TESTNET_VALIDATOR_COUNT="${TESTNET_VALIDATOR_COUNT:-$(detect_validator_count)}"
require_positive_integer "TESTNET_VALIDATOR_COUNT" "$TESTNET_VALIDATOR_COUNT"
EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE="$(derive_validator_cluster_size "$TESTNET_VALIDATOR_COUNT")"
TESTNET_DYNAMIC_VALIDATOR_QUORUM="$(derive_validator_quorum "$EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE")"
EXPECTED_TESTNET_VALIDATOR_VOTE_THRESHOLD=0
TESTNET_VALIDATOR_CLUSTER_SIZE="${TESTNET_VALIDATOR_CLUSTER_SIZE:-$EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE}"
TESTNET_MAX_VALIDATORS="${TESTNET_MAX_VALIDATORS:-$TESTNET_VALIDATOR_COUNT}"
TESTNET_VALIDATOR_VOTE_THRESHOLD="${TESTNET_VALIDATOR_VOTE_THRESHOLD:-$EXPECTED_TESTNET_VALIDATOR_VOTE_THRESHOLD}"
require_positive_integer "TESTNET_MIN_VALIDATOR_CLUSTER_SIZE" "$TESTNET_MIN_VALIDATOR_CLUSTER_SIZE"
require_positive_integer "TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE" "$TESTNET_VALIDATOR_CLUSTER_TARGET_SIZE"
require_positive_integer "TESTNET_VALIDATOR_CLUSTER_SIZE" "$TESTNET_VALIDATOR_CLUSTER_SIZE"
require_positive_integer "TESTNET_MAX_VALIDATORS" "$TESTNET_MAX_VALIDATORS"
require_nonnegative_integer "TESTNET_VALIDATOR_VOTE_THRESHOLD" "$TESTNET_VALIDATOR_VOTE_THRESHOLD"

if (( TESTNET_VALIDATOR_CLUSTER_SIZE != EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE )); then
  echo "TESTNET_VALIDATOR_CLUSTER_SIZE must match the dynamic cluster policy ($EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE for $TESTNET_VALIDATOR_COUNT validators)." >&2
  exit 1
fi

if (( TESTNET_VALIDATOR_VOTE_THRESHOLD != EXPECTED_TESTNET_VALIDATOR_VOTE_THRESHOLD )); then
  echo "TESTNET_VALIDATOR_VOTE_THRESHOLD must be 0 so runtime derives the canonical cluster quorum (${TESTNET_DYNAMIC_VALIDATOR_QUORUM} for cluster size $EXPECTED_TESTNET_VALIDATOR_CLUSTER_SIZE)." >&2
  exit 1
fi

if (( TESTNET_MAX_VALIDATORS != TESTNET_VALIDATOR_COUNT )); then
  echo "TESTNET_MAX_VALIDATORS must match manifest validator count ($TESTNET_VALIDATOR_COUNT) for dynamic quorum safety." >&2
  exit 1
fi

if [[ -n "${HOSTS_FILE:-}" && -s "$HOSTS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$HOSTS_FILE"
  USE_HOST_OVERRIDES="true"
else
  if [[ -n "${HOSTS_FILE:-}" ]]; then
    echo "Hosts override file not found or empty at $HOSTS_FILE; using values from inventory." >&2
  else
    echo "No hosts override file provided; using values from inventory." >&2
  fi
fi

mkdir -p "$OUT_DIR"
find "$OUT_DIR" -maxdepth 1 -type f -name '*.toml' -delete 2>/dev/null || true

resolve_public_host() {
  local node_slot_id="$1"
  local default_host="$2"
  local node_slot_key
  if [[ "$USE_HOST_OVERRIDES" != "true" ]]; then
    echo "$default_host"
    return
  fi

  node_slot_key="$(echo "$node_slot_id" | tr '[:lower:]-' '[:upper:]_')"
  local var_name="${node_slot_key}_HOST"
  local value="${!var_name:-}"
  if [[ -n "$value" ]]; then
    echo "$value"
  else
    echo "$default_host"
  fi
}

resolve_public_p2p_port() {
  local validator_address="$1"
  local default_port="$2"
  local env_port=""
  if declare -F testnet_validator_env_value >/dev/null 2>&1; then
    env_port="$(testnet_first_nonempty \
      "$(testnet_validator_env_value "$validator_address" "P2P_PORT_EXTERNAL" || true)" \
      "$(testnet_validator_env_value "$validator_address" "P2P_PORT" || true)" \
    )"
  fi

  if [[ -n "$env_port" ]]; then
    echo "$env_port"
    return
  fi

  case "$validator_address" in
    synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t) echo "5622" ;;
    synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk) echo "5622" ;;
    synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj) echo "5622" ;;
    synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg) echo "5622" ;;
    synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu) echo "5622" ;;
    *) echo "$default_port" ;;
  esac
}

role_uses_sentry_upstreams() {
  case "${1:-}" in
    rpc_gateway|indexer_explorer|observer_light)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

collect_bootnode_targets() {
  python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

targets = []
for entry in manifest.get("bootstrap", {}).get("bootnodes", []):
    host = str(entry.get("host") or "").strip()
    port = int(entry.get("port") or 5620)
    if host:
        targets.append(f"\"snr://bootstrap@{host}:{port}\"")

print("[" + ",".join(targets) + "]")
PY
}

collect_sentry_public_peers_for_role() {
  local role_id="$1"
  python3 - "$MANIFEST_FILE" "$role_id" <<'PY'
import json
import sys

manifest_path, role_id = sys.argv[1], sys.argv[2]

with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

routing_role = {
    "indexer_explorer": "indexer",
    "observer_light": "observer",
}.get(role_id, role_id)

bootstrap = manifest.get("bootstrap", {})
sentries = {
    str(entry.get("label") or "").strip(): entry
    for entry in bootstrap.get("sentries", [])
    if str(entry.get("label") or "").strip()
}
targets = []
for label in bootstrap.get("routing", {}).get(routing_role, []):
    entry = sentries.get(str(label).strip())
    if not entry:
        continue
    host = str(entry.get("public_ip") or entry.get("public_host") or "").strip()
    port = int(entry.get("port") or 5622)
    if host:
        targets.append(f"\"snr://{label}@{host}:{port}\"")

print("[" + ",".join(targets) + "]")
PY
}

inventory_validator_mesh_host() {
  local slot="${1:-}"
  local canonical_node_id legacy_node_id
  canonical_node_id="$(printf 'Validator-%02d' "$slot")"
  legacy_node_id="$(printf 'GenVal-%02d' "$slot")"
  awk -F, -v canonical_id="$canonical_node_id" -v legacy_id="$legacy_node_id" '
    NR > 1 && ($1 == canonical_id || $1 == legacy_id) {
      if ($22 != "") {
        print $22
      } else if ($13 != "") {
        print $13
      } else if ($12 != "") {
        print $12
      }
      exit
    }
  ' "$INVENTORY_FILE"
}

normalize_role_id() {
  local raw="${1:-}"
  raw="$(echo "$raw" | tr '[:upper:]-' '[:lower:]_' | xargs)"
  case "$raw" in
    validator) echo "validator" ;;
    committee) echo "committee" ;;
    archive_validator) echo "archive_validator" ;;
    audit_validator) echo "audit_validator" ;;
    relayer) echo "relayer" ;;
    witness) echo "witness" ;;
    oracle) echo "oracle" ;;
    uma_coordinator) echo "uma_coordinator" ;;
    cross_chain_verifier) echo "cross_chain_verifier" ;;
    compute|synq_execution) echo "synq_execution" ;;
    ai_inference|analytics_simulation) echo "analytics_simulation" ;;
    pqc_crypto|aegis_cryptography) echo "aegis_cryptography" ;;
    data_availability) echo "data_availability" ;;
    governance_auditor) echo "governance_auditor" ;;
    treasury_controller) echo "treasury_controller" ;;
    security_council) echo "security_council" ;;
    rpc_gateway) echo "rpc_gateway" ;;
    indexer|indexer_explorer) echo "indexer_explorer" ;;
    observer|observer_light) echo "observer_light" ;;
    *)
      echo "$raw"
      ;;
  esac
}

compiled_profile_for_role() {
  local role_id="$1"
  case "$role_id" in
    validator) echo "validator_node" ;;
    committee) echo "committee_node" ;;
    archive_validator) echo "archive_validator_node" ;;
    audit_validator) echo "audit_validator_node" ;;
    relayer) echo "relayer_node" ;;
    witness) echo "witness_node" ;;
    oracle) echo "oracle_node" ;;
    uma_coordinator) echo "uma_coordinator_node" ;;
    cross_chain_verifier) echo "cross_chain_verifier_node" ;;
    synq_execution) echo "synq_execution_node" ;;
    analytics_simulation) echo "analytics_and_simulation_node" ;;
    aegis_cryptography) echo "aegis_cryptography_node" ;;
    data_availability) echo "data_availability_node" ;;
    governance_auditor) echo "governance_auditor_node" ;;
    treasury_controller) echo "treasury_controller_node" ;;
    security_council) echo "security_council_node" ;;
    rpc_gateway) echo "rpc_gateway_node" ;;
    indexer_explorer) echo "indexer_and_explorer_node" ;;
    observer_light) echo "observer_light_node" ;;
    *)
      echo "${role_id}_node"
      ;;
  esac
}

resolve_p2p_host() {
  local node_slot_id="$1"
  local default_management_host="$2"
  local fallback_public_host="$3"
  local node_slot_key
  if [[ "$USE_HOST_OVERRIDES" != "true" ]]; then
    if [[ -n "${default_management_host}" ]]; then
      echo "${default_management_host}"
    else
      echo "${fallback_public_host}"
    fi
    return
  fi

  node_slot_key="$(echo "$node_slot_id" | tr '[:lower:]-' '[:upper:]_')"

  local management_host_var="${node_slot_key}_MANAGEMENT_HOST"
  local p2p_var="${node_slot_key}_P2P_HOST"
  local internal_var="${node_slot_key}_INTERNAL_HOST"

  if [[ -n "${!management_host_var:-}" ]]; then
    echo "${!management_host_var}"
    return
  fi

  if [[ -n "${!p2p_var:-}" ]]; then
    echo "${!p2p_var}"
    return
  fi

  if [[ -n "${!internal_var:-}" ]]; then
    echo "${!internal_var}"
    return
  fi

  if [[ -n "${default_management_host}" ]]; then
    echo "${default_management_host}"
    return
  fi

  echo "${fallback_public_host}"
}

compute_listen_address() {
  local p2p_host="$1"
  local p2p_port="$2"

  if [[ "$p2p_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    if [[ "$p2p_host" =~ ^10\. ]] || [[ "$p2p_host" =~ ^192\.168\. ]] || [[ "$p2p_host" =~ ^172\.([1][6-9]|2[0-9]|3[0-1])\. ]] || [[ "$p2p_host" =~ ^127\. ]]; then
      echo "${p2p_host}:${p2p_port}"
      return
    fi
    echo "0.0.0.0:${p2p_port}"
    return
  fi

  if [[ "$p2p_host" == "localhost" ]]; then
    echo "127.0.0.1:${p2p_port}"
    return
  fi

  echo "0.0.0.0:${p2p_port}"
}

compute_public_address() {
  local p2p_host="$1"
  local p2p_port="$2"

  if [[ "$p2p_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "${p2p_host}:${p2p_port}"
    return
  fi

  if [[ "$p2p_host" == "localhost" ]]; then
    echo "127.0.0.1:${p2p_port}"
    return
  fi

  echo "${p2p_host}:${p2p_port}"
}

compute_p2p_listen_address() {
  local role_group="$1"
  local node_type="$2"
  local p2p_host="$3"
  local p2p_port="$4"

  compute_listen_address "$p2p_host" "$p2p_port"
}

compute_discovery_listen_address() {
  local role_group="$1"
  local node_type="$2"
  local p2p_host="$3"
  local discovery_port="$4"

  compute_listen_address "$p2p_host" "$discovery_port"
}

resolve_bind_host() {
  local bind_ip="${1:-}"
  local local_ip="${2:-}"
  local management_host="${3:-}"
  local public_host="${4:-}"
  testnet_first_nonempty "$bind_ip" "$local_ip" "$management_host" "$public_host"
}

lookup_node_address() {
  local node_slot_id="$1"
  python3 - "$NODE_ADDRESSES_FILE" "$node_slot_id" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    for row in csv.DictReader(handle):
        slot = row.get("node_slot_id") or row.get("machine_id")
        if slot == sys.argv[2]:
            print((row.get("address") or "").strip(), end="")
            break
PY
}

lookup_canonical_validator_address() {
  local node_slot_id="$1"
  python3 - "$MANIFEST_FILE" "$node_slot_id" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

for validator in manifest.get("validators", []):
    if validator.get("label") == sys.argv[2]:
        print(validator.get("address", ""), end="")
        break
PY
}

read_canonical_validators() {
  python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

for entry in manifest.get("validators", []):
    slot = entry.get("slot")
    address = str(entry.get("address") or "").strip()
    if slot is None or not address:
        continue
    print(f"{slot},{address}")
PY
}

collect_allowed_validator_addresses() {
  local addresses=()
  while IFS=, read -r _ validator_address || [[ -n "${validator_address:-}" ]]; do
    [[ -n "${validator_address:-}" ]] || continue
    addresses+=("\"$validator_address\"")
  done < <(read_canonical_validators)

  if [[ "${#addresses[@]}" -eq 0 ]]; then
    echo "[]"
    return
  fi

  local joined
  joined="$(IFS=,; echo "${addresses[*]}")"
  echo "[$joined]"
}

collect_static_validator_mesh_peers() {
  local current_node_slot_id="${1:-}"
  local current_validator_address="${2:-}"
  local target_mode="${3:-socket}"
  local peers=()
  while IFS=, read -r slot peer_id || [[ -n "${peer_id:-}" ]]; do
    [[ -n "${peer_id:-}" ]] || continue
    if [[ -n "$current_validator_address" && "$peer_id" == "$current_validator_address" ]]; then
      continue
    fi

    if [[ "$target_mode" == "identity" ]]; then
      peers+=("\"${peer_id}\"")
      continue
    fi

    local validator_env_file resolved_host public_p2p_port
    validator_env_file=""
    if declare -F testnet_env_file_for_validator_address >/dev/null 2>&1; then
      validator_env_file="$(testnet_env_file_for_validator_address "$peer_id" || true)"
    fi
    resolved_host="$(testnet_first_nonempty \
      "$(inventory_validator_mesh_host "$slot")" \
      "$(testnet_env_value "$validator_env_file" "LOCAL_IP" || true)" \
      "$(testnet_env_value "$validator_env_file" "MANAGEMENT_HOST" || true)" \
      "$(testnet_env_value "$validator_env_file" "HOSTNAME" || true)" \
    )"
    [[ -n "$resolved_host" ]] || continue
    if [[ "$resolved_host" =~ ^10\.69\.10\. ]]; then
      resolved_host="validator-${slot}.vpn.synergynode.xyz"
    fi
    public_p2p_port="$(testnet_first_nonempty \
      "$(testnet_env_value "$validator_env_file" "P2P_PORT_EXTERNAL" || true)" \
      "$(testnet_env_value "$validator_env_file" "P2P_PORT" || true)" \
      "$(resolve_public_p2p_port "$peer_id" "5622")" \
    )"
    peers+=("\"snr://${peer_id}@${resolved_host}:${public_p2p_port}\"")
  done < <(read_canonical_validators)

  if [[ "${#peers[@]}" -eq 0 ]]; then
    echo "Inventory does not define any assigned consensus validators for static mesh dialing." >&2
    exit 1
  fi

  local joined
  joined="$(IFS=,; echo "${peers[*]}")"
  echo "[$joined]"
}

collect_static_validator_vpn_transports() {
  local current_validator_address="${1:-}"
  local blocks=()
  while IFS=, read -r slot peer_id || [[ -n "${peer_id:-}" ]]; do
    [[ -n "${peer_id:-}" ]] || continue
    if [[ -n "$current_validator_address" && "$peer_id" == "$current_validator_address" ]]; then
      continue
    fi

    local resolved_host
    resolved_host="$(testnet_first_nonempty \
      "$(inventory_validator_mesh_host "$slot")" \
      "10.70.10.${slot}" \
    )"
    [[ -n "$resolved_host" ]] || continue
    blocks+=("[[network.validator_vpn_transports]]
validator_address = \"${peer_id}\"
dial_address = \"${resolved_host}:5622\"
")
  done < <(read_canonical_validators)

  if [[ "${#blocks[@]}" -eq 0 ]]; then
    echo "Inventory does not define any assigned consensus validators for VPN transport routing." >&2
    exit 1
  fi

  printf '%s' "${blocks[@]}"
}

collect_validator_relayer_mesh_peers() {
  python3 - "$MANIFEST_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle)

targets = []
for entry in manifest.get("bootstrap", {}).get("sentries", []):
    label = str(entry.get("label") or "").strip()
    host = str(entry.get("private_ip") or entry.get("private_host") or "").strip()
    port = int(entry.get("port") or 5622)
    if label and host:
        targets.append(f"\"snr://{label}@{host}:{port}\"")

print("[" + ",".join(targets) + "]")
PY
}

merge_json_arrays() {
  python3 - "$@" <<'PY'
import json
import sys

merged = []
seen = set()
for raw in sys.argv[1:]:
    for value in json.loads(raw):
        if value not in seen:
            seen.add(value)
            merged.append(value)
print(json.dumps(merged, separators=(",", ":")))
PY
}

render_bootnode_list() {
  local joined
  joined="$(IFS=,; echo "$*")"
  echo "[${joined}]"
}
ALLOWED_VALIDATOR_ADDRESSES="$(collect_allowed_validator_addresses)"
BOOTNODE_TARGETS="$(collect_bootnode_targets)"
RPC_GATEWAY_P2P_ADDRESS="rpc.synergynode.xyz:5623"
RPC_GATEWAY_DISCOVERY_ADDRESS="rpc.synergynode.xyz:5681"
RPC_GATEWAY_BOOTNODE_TARGETS='["snr://bootstrap@bootnode1.synergynode.xyz:5620","snr://bootstrap@bootnode2.synergynode.xyz:5620","snr://bootstrap@bootnode3.synergynode.xyz:5620"]'
RPC_GATEWAY_SEED_SERVERS='["http://seed1.synergynode.xyz:5621","http://seed2.synergynode.xyz:5621","http://seed3.synergynode.xyz:5621"]'
RPC_GATEWAY_BOOTSTRAP_DNS_RECORDS='["_dnsaddr.bootstrap.synergynode.xyz"]'
RPC_GATEWAY_P2P_PEERS='["relay1.synergynode.xyz:5622","relay2.synergynode.xyz:5622","62.146.182.207:5622","62.146.182.208:5622","62.146.182.209:5622","73.79.66.255:5622","194.163.183.166:5622","157.173.192.45:5622","archive.synergynode.xyz:5615","209.145.50.9:5622"]'

generated_count=0

while IFS=, read -r node_slot_id node_alias role_group role node_type _ p2p_port rpc_port ws_port grpc_port discovery_port host management_host physical_machine_id auto_register enable_pruning vrf_enabled operator device operating_system public_ip local_ip || [[ -n "${node_slot_id:-}" ]]; do
  [[ "$node_slot_id" == "node_slot_id" ]] && continue
  if [[ "$(printf '%s' "$node_type" | tr '[:upper:]' '[:lower:]')" == "bootnode" ]]; then
    continue
  fi

  source_env_file="$(testnet_env_file_for_inventory_node "$node_slot_id" "$node_type" "" "$host" || true)"
  inventory_host="$host"
  inventory_management_host="$management_host"
  inventory_public_ip="$public_ip"
  inventory_local_ip="$local_ip"
  lookup_role_id="$(normalize_role_id "$role")"
  node_identity_address="$(testnet_first_nonempty \
    "$(lookup_node_address "$node_slot_id")" \
    "$(testnet_env_value "$source_env_file" "NODE_WALLET" || true)" \
  )" || true
  if [[ -z "$node_identity_address" ]]; then
    echo "Missing node identity address mapping for ${node_slot_id} in ${NODE_ADDRESSES_FILE}" >&2
    exit 1
  fi
  validator_address=""
  if [[ "$lookup_role_id" == "validator" ]]; then
    validator_address="$(testnet_first_nonempty \
      "$(lookup_canonical_validator_address "$node_slot_id" || true)" \
      "$node_identity_address" \
    )" || true
    if [[ -z "$validator_address" || "$validator_address" != "$node_identity_address" ]]; then
      echo "Validator identity mismatch for ${node_slot_id}: node identity=${node_identity_address}, canonical validator=${validator_address}" >&2
      exit 1
    fi
  fi

  host="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "HOSTNAME" "$host")"
  public_ip="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "PUBLIC_IP" "$public_ip")"
  local_ip="$(testnet_inventory_env_value_allow_empty "$node_slot_id" "$node_type" "$node_identity_address" "$host" "LOCAL_IP" "$local_ip")"
  bind_ip="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "BIND_IP" "")"
  p2p_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "P2P_PORT" "$p2p_port")"
  rpc_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "RPC_PORT" "$rpc_port")"
  ws_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "WS_PORT" "$ws_port")"
  grpc_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "GRPC_PORT" "$grpc_port")"
  discovery_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "DISCOVERY_PORT" "$discovery_port")"

  management_host="$(testnet_first_nonempty \
    "$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "MANAGEMENT_HOST" "")" \
    "$local_ip" \
    "$management_host" \
    "$public_ip" \
    "$host" \
  )"
  resolved_public_host="$(resolve_public_host "$node_slot_id" "$host")"
  resolved_p2p_host="$(resolve_p2p_host "$node_slot_id" "$management_host" "$resolved_public_host")"
  bind_host="$(resolve_bind_host "$bind_ip" "$local_ip" "$resolved_p2p_host" "$resolved_public_host")"
  listen_address="$(compute_p2p_listen_address "$role_group" "$node_type" "$bind_host" "$p2p_port")"
  public_p2p_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "P2P_PORT_EXTERNAL" "$(resolve_public_p2p_port "$validator_address" "$p2p_port")")"
  public_address="$(compute_public_address "$resolved_public_host" "$public_p2p_port")"
  public_discovery_port="$(testnet_inventory_env_value "$node_slot_id" "$node_type" "$node_identity_address" "$host" "DISCOVERY_PORT_EXTERNAL" "$discovery_port")"
  discovery_listen_address="$(compute_discovery_listen_address "$role_group" "$node_type" "$bind_host" "$discovery_port")"
  discovery_public_address="$(compute_public_address "$resolved_public_host" "$public_discovery_port")"
  rpc_bind_address="${bind_host}:${rpc_port}"
  role_id="$(normalize_role_id "$role")"
  compiled_profile="$(compiled_profile_for_role "$role_id")"
  seed_servers="[]"
  bootstrap_dns_records="[]"

  if [[ "$role_group" == "consensus" && "$node_type" == "validator" ]]; then
    validator_slot=""
    if [[ "$node_slot_id" =~ ^(Validator|GenVal)-([0-9]+)$ ]]; then
      validator_slot="$((10#${BASH_REMATCH[2]}))"
    fi
    validator_mesh_host="$(testnet_first_nonempty \
      "$(inventory_validator_mesh_host "$validator_slot")" \
      "$inventory_local_ip" \
      "$inventory_management_host" \
      "$local_ip" \
      "$management_host" \
      "$inventory_host" \
    )"
    if [[ -n "$validator_mesh_host" ]]; then
      local_ip="$validator_mesh_host"
      management_host="$validator_mesh_host"
      resolved_p2p_host="$validator_mesh_host"
      bind_host="$validator_mesh_host"
      listen_address="$(compute_listen_address "$bind_host" "$p2p_port")"
      discovery_listen_address="$(compute_listen_address "$bind_host" "$discovery_port")"
    fi
    resolved_public_host=""
    public_address="$validator_address"
    discovery_public_address="$validator_address"
    rpc_bind_address="0.0.0.0:${rpc_port}"
    bootnodes="[]"
    seed_servers="[]"
    bootstrap_dns_records="[]"
    validator_mesh_targets="$(collect_static_validator_mesh_peers "$node_slot_id" "$validator_address" "identity")"
    case "${SYNERGY_INNERNET_MIGRATION_READY:-false}" in
      1|true|TRUE|yes|YES)
        # The Innernet coordinator owns all transport addresses after cutover.
        # Keep node.toml identity-only until its signed receipt is recorded.
        validator_vpn_transport_blocks=""
        ;;
      *)
        validator_vpn_transport_blocks="$(collect_static_validator_vpn_transports "$validator_address")"
        ;;
    esac
    relayer_mesh_targets="$(collect_validator_relayer_mesh_peers)"
    additional_dial_targets="$(merge_json_arrays "$validator_mesh_targets" "$relayer_mesh_targets")"
    auto_register="false"
  else
    validator_vpn_transport_blocks=""
    if [[ "$role_id" == "rpc_gateway" ]]; then
      bootnodes="$RPC_GATEWAY_BOOTNODE_TARGETS"
      seed_servers="$RPC_GATEWAY_SEED_SERVERS"
      bootstrap_dns_records="$RPC_GATEWAY_BOOTSTRAP_DNS_RECORDS"
      additional_dial_targets="$RPC_GATEWAY_P2P_PEERS"
      public_address="$RPC_GATEWAY_P2P_ADDRESS"
      discovery_public_address="$RPC_GATEWAY_DISCOVERY_ADDRESS"
      rpc_bind_address="127.0.0.1:${rpc_port}"
    elif [[ "$role_id" == "relayer" ]]; then
      bootnodes="[]"
      additional_dial_targets="$(collect_static_validator_mesh_peers "$node_slot_id" "")"
    elif role_uses_sentry_upstreams "$role_id"; then
      bootnodes="[]"
      additional_dial_targets="$(collect_sentry_public_peers_for_role "$role_id")"
    else
      bootnodes="$BOOTNODE_TARGETS"
      additional_dial_targets="[]"
    fi
    if [[ "$role_group" == "services" && "$role_id" != "rpc_gateway" ]]; then
      rpc_bind_address="0.0.0.0:${rpc_port}"
    fi
    auto_register="$(normalize_bool "$auto_register")"
  fi

  enable_pruning="$(normalize_bool "$enable_pruning")"
  vrf_enabled="$(normalize_bool "$vrf_enabled")"
  snapshots_enabled="false"
  snapshot_interval_blocks="5000"
  if [[ "$role_id" == "archive_validator" ]]; then
    snapshots_enabled="true"
    snapshot_interval_blocks="15000"
  fi

  cat > "$OUT_DIR/${node_slot_id}.toml" <<CONFIG
# Auto-generated by scripts/testnet/render-configs.sh
# Node Slot: ${node_slot_id}
# Role Group: ${role_group}
# Role: ${role}
# Node Type: ${node_type}

[identity]
node_id = "${node_slot_id}"
role = "${role_id}"
role_display = "${role}"
address = "${node_identity_address}"
label = "${node_alias}"

[role]
compiled_profile = "${compiled_profile}"
services = []

[network]
id = ${TESTNET_CHAIN_ID}
name = "${TESTNET_NETWORK_NAME}"
p2p_port = ${p2p_port}
rpc_port = ${rpc_port}
ws_port = ${ws_port}
max_peers = 100
bootnodes = ${bootnodes}
seed_servers = ${seed_servers}
bootstrap_dns_records = ${bootstrap_dns_records}
additional_dial_targets = ${additional_dial_targets}
persistent_peers = ${additional_dial_targets}
${validator_vpn_transport_blocks}

[blockchain]
block_time = ${TESTNET_BLOCK_TIME_SECS}
max_gas_limit = "0x2fefd8"
chain_id = ${TESTNET_CHAIN_ID}

[consensus]
algorithm = "Proof of Synergy"
block_time_secs = ${TESTNET_BLOCK_TIME_SECS}
epoch_length = ${TESTNET_EPOCH_LENGTH}
min_validators = ${TESTNET_MIN_VALIDATORS}
validator_cluster_size = ${TESTNET_VALIDATOR_CLUSTER_SIZE}
validator_vote_threshold = ${TESTNET_VALIDATOR_VOTE_THRESHOLD}
max_validators = ${TESTNET_MAX_VALIDATORS}
status_ready_gate_enabled = ${TESTNET_STATUS_READY_GATE_ENABLED}
status_ready_min_validators = ${TESTNET_STATUS_READY_MIN_VALIDATORS}
status_ready_genesis_grace_secs = ${TESTNET_STATUS_READY_GENESIS_GRACE_SECS}
allow_genesis_status_bypass = ${TESTNET_ALLOW_GENESIS_STATUS_BYPASS}
mesh_settle_secs = ${TESTNET_MESH_SETTLE_SECS}
leader_timeout_secs = ${TESTNET_LEADER_TIMEOUT_SECS}
vote_timeout_secs = ${TESTNET_VOTE_TIMEOUT_SECS}
block_timeout_secs = ${TESTNET_BLOCK_TIMEOUT_SECS}
penalization_enabled = ${TESTNET_CONSENSUS_PENALIZATION_ENABLED}
synergy_score_decay_rate = 0.05
vrf_enabled = ${vrf_enabled}
vrf_seed_epoch_interval = 1000
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "debug"
log_file = "data/logs/${node_alias}.log"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "${rpc_bind_address}"
enable_http = true
http_port = ${rpc_port}
enable_ws = true
ws_port = ${ws_port}
enable_grpc = true
grpc_port = ${grpc_port}
cors_enabled = false
cors_origins = []

[p2p]
listen_address = "${listen_address}"
public_address = "${public_address}"
node_name = "${node_alias}"
enable_discovery = false
discovery_port = ${discovery_port}
discovery_listen_address = "${discovery_listen_address}"
discovery_public_address = "${discovery_public_address}"
heartbeat_interval = ${TESTNET_P2P_HEARTBEAT_INTERVAL_SECS}
bootstrap_refresh_secs = ${TESTNET_P2P_BOOTSTRAP_REFRESH_SECS}

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = ${enable_pruning}
pruning_interval = 86400

[snapshots]
enabled = ${snapshots_enabled}
interval_blocks = ${snapshot_interval_blocks}

[node]
auto_register_validator = ${auto_register}
validator_address = "${validator_address}"
strict_validator_allowlist = false
allowed_validator_addresses = ${ALLOWED_VALIDATOR_ADDRESSES}

[validator]
participation = "active"
verify_quorum_certificates = true
state_sync_before_join = true
CONFIG

  echo "Generated ${OUT_DIR}/${node_slot_id}.toml"
  generated_count=$((generated_count + 1))
done < "$INVENTORY_FILE"

echo "Rendered ${generated_count} node configs into: $OUT_DIR"
