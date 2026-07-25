#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
KEYS_DIR="$ROOT_DIR/testnet/runtime/keys"
ROLE_GROUP_FILTER="${SXCP_BOOTSTRAP_ROLE_GROUPS:-interop}"
ROLE_FILTER="${SXCP_BOOTSTRAP_ROLES:-}"

default_rpc_port="$(awk -F, 'NR > 1 && tolower($5)=="rpc-gateway" {print $8; exit}' "$INVENTORY_FILE" 2>/dev/null || true)"
default_rpc_port="${default_rpc_port:-5646}"
RPC_URL="${1:-http://127.0.0.1:${default_rpc_port}}"

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Missing inventory file: $INVENTORY_FILE" >&2
  exit 1
fi

rpc_call() {
  local method="$1"
  local params_json="$2"
  local id="$3"

  curl -sS -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":${id}}"
}

echo "Bootstrapping SXCP relayer set against RPC: $RPC_URL"
echo "Role-group filter: $ROLE_GROUP_FILTER"
if [[ -n "$ROLE_FILTER" ]]; then
  echo "Role filter: $ROLE_FILTER"
fi

id_counter=1
while IFS=, read -r node_slot_id node_alias role_group role node_type address_class p2p_port rpc_port ws_port grpc_port discovery_port host management_host physical_machine_id auto_register enable_pruning vrf_enabled operator device operating_system public_ip local_ip || [[ -n "${node_slot_id:-}" ]]; do
  [[ "$node_slot_id" == "node_slot_id" ]] && continue

  if [[ ",$ROLE_GROUP_FILTER," != *",$role_group,"* ]]; then
    continue
  fi

  if [[ -n "$ROLE_FILTER" && ",$ROLE_FILTER," != *",$role,"* ]]; then
    continue
  fi

  address_file="$KEYS_DIR/$node_slot_id/address.txt"
  pubkey_file="$KEYS_DIR/$node_slot_id/public.key"

  if [[ ! -f "$address_file" || ! -f "$pubkey_file" ]]; then
    echo "Missing key material for $node_slot_id" >&2
    exit 1
  fi

  address="$(cat "$address_file")"
  public_key="$(cat "$pubkey_file")"

  echo "Registering relayer: $node_slot_id ($node_type) $address"
  register_response="$(rpc_call "synergy_registerRelayer" "[\"$address\",\"$public_key\"]" "$id_counter")"
  echo "$register_response"
  id_counter=$((id_counter + 1))

  heartbeat_response="$(rpc_call "synergy_relayerHeartbeat" "[\"$address\"]" "$id_counter")"
  echo "$heartbeat_response"
  id_counter=$((id_counter + 1))
done < "$INVENTORY_FILE"

echo "Fetching final relayer set..."
set_response="$(rpc_call "synergy_getRelayerSet" "[]" "$id_counter")"
id_counter=$((id_counter + 1))
status_response="$(rpc_call "synergy_getSxcpStatus" "[]" "$id_counter")"

if command -v jq >/dev/null 2>&1; then
  echo "$set_response" | jq
  echo "$status_response" | jq
else
  echo "$set_response"
  echo "$status_response"
fi

echo "SXCP bootstrap complete."
