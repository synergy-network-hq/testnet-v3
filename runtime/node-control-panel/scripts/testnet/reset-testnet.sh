#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
HOSTS_FILE="${HOSTS_FILE:-$ROOT_DIR/testnet/runtime/hosts.env}"
RUN_NODE_SCRIPT="$ROOT_DIR/scripts/testnet/run-node.sh"
RENDER_CONFIGS_SCRIPT="$ROOT_DIR/scripts/testnet/render-configs.sh"
GENESIS_SCRIPT="$ROOT_DIR/scripts/testnet/generate-testnet-genesis.sh"
VALIDATE_CLOSED_SCRIPT="$ROOT_DIR/scripts/testnet/validate-testnet.sh"
TESTNET_AGENT_PORT="${SYNERGY_TESTNET_AGENT_PORT:-47990}"

REBUILD_INSTALLERS="false"
SKIP_RESTART="false"

usage() {
  cat <<USAGE
Usage: $0 [--hosts-file <path>] [--rebuild-installers (GitHub Actions only)] [--skip-restart]

Performs a full closed-testnet reset workflow:
1) stop nodes
2) clear chain/token/validator state
3) re-render configs
4) regenerate genesis
5) restart cluster in deterministic order

Optional remote control:
- If hosts.env defines NODE_XX_STOP_CMD / START_CMD / RESET_CMD, those are used.
- Otherwise the script falls back to local scripts/testnet/run-node.sh commands.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts-file)
      if [[ $# -lt 2 ]]; then
        echo "--hosts-file requires a path" >&2
        exit 1
      fi
      HOSTS_FILE="$2"
      shift 2
      ;;
    --rebuild-installers)
      REBUILD_INSTALLERS="true"
      shift
      ;;
    --skip-restart)
      SKIP_RESTART="true"
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

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Missing inventory file: $INVENTORY_FILE" >&2
  exit 1
fi

if [[ ! -x "$RUN_NODE_SCRIPT" ]]; then
  echo "Missing run-node script: $RUN_NODE_SCRIPT" >&2
  exit 1
fi

if [[ -s "$HOSTS_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$HOSTS_FILE"
fi

machine_var_prefix() {
  local node_slot_id="$1"
  echo "$node_slot_id" | tr '[:lower:]-' '[:upper:]_'
}

machine_hook_cmd() {
  local node_slot_id="$1"
  local hook="$2"
  local prefix
  prefix="$(machine_var_prefix "$node_slot_id")"
  local var_name="${prefix}_${hook}"
  echo "${!var_name:-}"
}

inventory_management_host() {
  local node_slot_id="$1"
  awk -F, -v id="$node_slot_id" 'NR > 1 && tolower($1) == tolower(id) { print $13; exit }' "$INVENTORY_FILE"
}

agent_endpoint() {
  local node_slot_id="$1"
  local prefix
  prefix="$(machine_var_prefix "$node_slot_id")"
  local management_host_var="${prefix}_MANAGEMENT_HOST"
  local management_host="${!management_host_var:-}"
  if [[ -z "$management_host" ]]; then
    management_host="$(inventory_management_host "$node_slot_id")"
  fi
  [[ -n "$management_host" ]] || return 1
  echo "http://${management_host}:${TESTNET_AGENT_PORT}/v1/control"
}

run_agent_action() {
  local node_slot_id="$1"
  local action="$2"
  local endpoint
  endpoint="$(agent_endpoint "$node_slot_id")" || return 1

  if ! command -v curl >/dev/null 2>&1; then
    return 1
  fi

  echo "[$node_slot_id] attempting testnet agent action: $action"
  curl -fsS -X POST "$endpoint" \
    -H "Content-Type: application/json" \
    -d "{\"node_slot_id\":\"${node_slot_id}\",\"action\":\"${action}\"}" >/dev/null
}

run_hook_or_local() {
  local node_slot_id="$1"
  local hook="$2"
  local local_action="$3"
  local cmd
  cmd="$(machine_hook_cmd "$node_slot_id" "$hook")"

  if run_agent_action "$node_slot_id" "$local_action"; then
    return
  fi

  if [[ -n "$cmd" ]]; then
    echo "[$node_slot_id] running remote hook: ${hook}"
    eval "$cmd"
    return
  fi

  echo "[$node_slot_id] running local action: $local_action"
  "$RUN_NODE_SCRIPT" "$local_action" "$node_slot_id" || true
}

inventory_node_slot_ids() {
  awk -F, 'NR > 1 {print $1}' "$INVENTORY_FILE"
}

is_bootnode_slot() {
  local node_slot_id="$1"
  awk -F, -v id="$node_slot_id" '
    NR > 1 && tolower($1) == tolower(id) {
      node_type = tolower($5)
      role = tolower($4)
      exit(!(node_type == "bootnode" || role == "bootnode"))
    }
    END {
      exit(1)
    }
  ' "$INVENTORY_FILE"
}

bootstrap_validator_slots() {
  awk -F, '
    NR > 1 {
      role_group = tolower($3)
      role = tolower($4)
      node_type = tolower($5)
      if (role_group == "consensus" && (role == "validator" || node_type == "validator")) {
        print $1
      }
    }
  ' "$INVENTORY_FILE"
}

derived_start_order() {
  local -a bootnodes=()
  local -a bootstrap_validators=()
  local -a remaining=()
  local -A seen=()

  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    if is_bootnode_slot "$node_slot_id"; then
      bootnodes+=("$node_slot_id")
      seen["$node_slot_id"]=1
    fi
  done < <(bootstrap_validator_slots)

  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    if [[ -z "${seen[$node_slot_id]:-}" ]]; then
      bootstrap_validators+=("$node_slot_id")
      seen["$node_slot_id"]=1
    fi
  done < <(bootstrap_validator_slots)

  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    if [[ -z "${seen[$node_slot_id]:-}" ]]; then
      remaining+=("$node_slot_id")
      seen["$node_slot_id"]=1
    fi
  done < <(inventory_node_slot_ids)

  printf '%s\n' "${bootnodes[@]}" "${bootstrap_validators[@]}" "${remaining[@]}"
}

stop_cluster() {
  echo "Stopping testnet nodes..."
  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    run_hook_or_local "$node_slot_id" "STOP_CMD" "stop"
  done < <(inventory_node_slot_ids)
}

reset_local_state() {
  echo "Clearing local chain data..."
  rm -f "$ROOT_DIR/data/chain.json"
  rm -f "$ROOT_DIR/data/token_state.json"
  rm -f "$ROOT_DIR/data/validator_registry.json"
  rm -f "$ROOT_DIR/data/committed_qcs.json"
  rm -f "$ROOT_DIR/data/committed_qcs.json.tmp"
  rm -f "$ROOT_DIR/data/canonical_locks.json"
  rm -f "$ROOT_DIR/data/canonical_locks.json.tmp"
  rm -f "$ROOT_DIR/data/consensus_vote_locks.json"
  rm -f "$ROOT_DIR/data/consensus_vote_locks.json.tmp"
  rm -f "$ROOT_DIR/data/dag_state.json"
  rm -f "$ROOT_DIR/data/synergy-testnet.pid"
  rm -f "$ROOT_DIR/data/.reset_flag"

  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    local_data_dir="$ROOT_DIR/data/testnet15/$node_slot_id"
    rm -rf "$local_data_dir/chain" "$local_data_dir/logs"
    rm -f "$local_data_dir/committed_qcs.json" "$local_data_dir/committed_qcs.json.tmp"
    rm -f "$local_data_dir/canonical_locks.json" "$local_data_dir/canonical_locks.json.tmp"
    rm -f "$local_data_dir/consensus_vote_locks.json" "$local_data_dir/consensus_vote_locks.json.tmp"
    rm -f "$local_data_dir/dag_state.json"
    mkdir -p "$local_data_dir/chain" "$local_data_dir/logs"
  done < <(inventory_node_slot_ids)
}

reset_remote_nodes() {
  while IFS= read -r node_slot_id; do
    [[ -z "$node_slot_id" ]] && continue
    if run_agent_action "$node_slot_id" "reset_chain"; then
      continue
    fi
    reset_cmd="$(machine_hook_cmd "$node_slot_id" "RESET_CMD")"
    if [[ -n "$reset_cmd" ]]; then
      echo "[$node_slot_id] running remote hook: RESET_CMD"
      eval "$reset_cmd"
    fi
  done < <(inventory_node_slot_ids)
}

render_and_regenerate() {
  echo "Re-rendering configs..."
  "$RENDER_CONFIGS_SCRIPT" "$HOSTS_FILE"

  echo "Validating closed-testnet constraints..."
  "$VALIDATE_CLOSED_SCRIPT"

  echo "Regenerating deterministic genesis..."
  "$GENESIS_SCRIPT"
}

rebuild_installers_if_requested() {
  if [[ "$REBUILD_INSTALLERS" != "true" ]]; then
    return
  fi
  echo "Local installer rebuilds have been removed from the repo." >&2
  echo "Trigger the GitHub Actions release workflow to produce updated installers." >&2
  exit 1
}

start_machine() {
  local node_slot_id="$1"
  run_hook_or_local "$node_slot_id" "START_CMD" "start"
}

wait_for_bootnode_rpc() {
  # Polls a bootnode's RPC endpoint until it returns a valid response.
  local node_slot_id="$1"
  local max_attempts="${2:-60}"
  local prefix
  prefix="$(machine_var_prefix "$node_slot_id")"
  local management_host_var="${prefix}_MANAGEMENT_HOST"
  local management_host="${!management_host_var:-}"
  if [[ -z "$management_host" ]]; then
    management_host="$(inventory_management_host "$node_slot_id")"
  fi
  if [[ -z "$management_host" ]]; then
    echo "WARNING: No Management Host for $node_slot_id, skipping readiness check." >&2
    return 0
  fi
  # Use the node's RPC port from inventory (column 8, 0-indexed col 7)
  local rpc_port
  rpc_port=$(awk -F, -v id="$node_slot_id" 'NR > 1 && tolower($1) == tolower(id) { print $8; exit }' "$INVENTORY_FILE")
  rpc_port="${rpc_port:-5640}"
  local rpc_url="http://${management_host}:${rpc_port}"

  echo "Waiting for bootnode $node_slot_id RPC at $rpc_url to become ready..."
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    attempt=$((attempt + 1))
    local response
    response=$(curl -sS --max-time 3 -X POST "$rpc_url" \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' 2>/dev/null) || true
    if [[ -n "$response" ]] && echo "$response" | grep -q '"result"'; then
      echo "Bootnode $node_slot_id is ready (attempt $attempt/$max_attempts)."
      return 0
    fi
    sleep 3
  done
  echo "WARNING: Bootnode $node_slot_id did not become ready after $max_attempts attempts." >&2
  return 1
}

restart_cluster() {
  if [[ "$SKIP_RESTART" == "true" ]]; then
    echo "Skipping restart (--skip-restart)."
    return
  fi

  mapfile -t start_order < <(derived_start_order)
  local -a bootnodes=()
  local -a remaining=()

  for node_slot_id in "${start_order[@]}"; do
    [[ -z "$node_slot_id" ]] && continue
    if is_bootnode_slot "$node_slot_id"; then
      bootnodes+=("$node_slot_id")
    else
      remaining+=("$node_slot_id")
    fi
  done

  if [[ "${#bootnodes[@]}" -eq 0 ]]; then
    echo "WARNING: No bootstrap bootnodes found in inventory; starting all nodes in inventory order."
    remaining=("${start_order[@]}")
  fi

  if [[ "${#bootnodes[@]}" -gt 0 ]]; then
    echo "Starting bootnode(s) first: ${bootnodes[*]}"
  fi
  for node_slot_id in "${bootnodes[@]}"; do
    start_machine "$node_slot_id"
    sleep 1
  done

  # Wait for bootnodes to be ready before starting remaining nodes.
  echo "Waiting for bootnode(s) to become ready before starting remaining nodes..."
  for node_slot_id in "${bootnodes[@]}"; do
    wait_for_bootnode_rpc "$node_slot_id" 60 || echo "WARNING: Proceeding despite bootnode $node_slot_id not ready."
  done

  echo "Starting remaining testnet nodes in deterministic order..."
  for node_slot_id in "${remaining[@]}"; do
    start_machine "$node_slot_id"
    sleep 1
  done
}

post_check() {
  echo ""
  echo "=== Post-Reset Status ==="
  echo "All nodes have been stopped and chain data has been erased."
  echo "Nodes are ready for manual start via the control panel dashboard."
  echo ""
  echo "To start the testnet, use 'Start All' from the Network Monitor dashboard,"
  echo "or run the start commands manually in the deterministic boot order."
  echo ""

  # Verify no node processes are still running.
  local still_running=0
  while IFS=',' read -r node_slot_id _ _ _ _ _ _ _ _ _ _ host management_host _ _ _ _ _ _ _ _ _; do
    [[ "$node_slot_id" == "node_slot_id" || -z "$node_slot_id" ]] && continue
    local target_ip="${management_host:-$host}"
    [[ -z "$target_ip" ]] && continue
    if run_agent_action "$node_slot_id" "status" 2>/dev/null | grep -qi "running"; then
      echo "WARNING: $node_slot_id still appears to be running on $target_ip"
      still_running=$((still_running + 1))
    fi
  done < "$INVENTORY_FILE"

  if [[ "$still_running" -gt 0 ]]; then
    echo "WARNING: $still_running node(s) may still be running. Check manually."
  else
    echo "All nodes confirmed stopped."
  fi
}

echo "=== Synergy Closed Testnet Reset ==="
echo "inventory: $INVENTORY_FILE"
echo "hosts:     $HOSTS_FILE"

stop_cluster
reset_local_state
reset_remote_nodes
render_and_regenerate
rebuild_installers_if_requested
# Nodes are intentionally NOT restarted after reset.
# Use "Start All" from the control panel dashboard when ready.
post_check

echo "Reset workflow complete."
