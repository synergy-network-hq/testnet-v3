#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
HOSTS_FILE="${HOSTS_FILE:-$ROOT_DIR/testnet/runtime/hosts.env}"
RUN_NODE_SCRIPT="$ROOT_DIR/scripts/testnet/run-node.sh"
RENDER_CONFIGS_SCRIPT="$ROOT_DIR/scripts/testnet/render-configs.sh"
GENESIS_SCRIPT="$ROOT_DIR/scripts/testnet/generate-testnet-genesis.sh"
VALIDATE_CLOSED_SCRIPT="$ROOT_DIR/scripts/testnet/validate-testnet.sh"

REBUILD_INSTALLERS="false"
SKIP_RESTART="false"

START_ORDER=(
  machine-01
  machine-02
  machine-03
  machine-04
  machine-05
  machine-10
  machine-11
  machine-06
  machine-07
  machine-08
  machine-09
  machine-12
  machine-13
  machine-14
  machine-15
)

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
- If hosts.env defines MACHINE_XX_STOP_CMD / START_CMD / RESET_CMD, those are used.
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
  local machine_id="$1"
  echo "$machine_id" | tr '[:lower:]-' '[:upper:]_'
}

machine_hook_cmd() {
  local machine_id="$1"
  local hook="$2"
  local prefix
  prefix="$(machine_var_prefix "$machine_id")"
  local var_name="${prefix}_${hook}"
  echo "${!var_name:-}"
}

run_hook_or_local() {
  local machine_id="$1"
  local hook="$2"
  local local_action="$3"
  local cmd
  cmd="$(machine_hook_cmd "$machine_id" "$hook")"

  if [[ -n "$cmd" ]]; then
    echo "[$machine_id] running remote hook: ${hook}"
    eval "$cmd"
    return
  fi

  echo "[$machine_id] running local action: $local_action"
  "$RUN_NODE_SCRIPT" "$local_action" "$machine_id" || true
}

inventory_machine_ids() {
  awk -F, 'NR > 1 {print $1}' "$INVENTORY_FILE"
}

stop_cluster() {
  echo "Stopping testnet nodes..."
  while IFS= read -r machine_id; do
    [[ -z "$machine_id" ]] && continue
    run_hook_or_local "$machine_id" "STOP_CMD" "stop"
  done < <(inventory_machine_ids)
}

reset_local_state() {
  echo "Clearing local chain data..."
  rm -f "$ROOT_DIR/data/chain.json"
  rm -f "$ROOT_DIR/data/token_state.json"
  rm -f "$ROOT_DIR/data/validator_registry.json"
  rm -f "$ROOT_DIR/data/committed_qcs.json"
  rm -f "$ROOT_DIR/data/committed_qcs.json.tmp"
  rm -f "$ROOT_DIR/data/committed_qcs.jsonl"
  rm -f "$ROOT_DIR/data/canonical_locks.json"
  rm -f "$ROOT_DIR/data/canonical_locks.json.tmp"
  rm -f "$ROOT_DIR/data/consensus_vote_locks.json"
  rm -f "$ROOT_DIR/data/consensus_vote_locks.json.tmp"
  rm -f "$ROOT_DIR/data/dag_state.json"
  rm -f "$ROOT_DIR/data/synergy-testnet.pid"
  rm -f "$ROOT_DIR/data/.reset_flag"

  while IFS= read -r machine_id; do
    [[ -z "$machine_id" ]] && continue
    local_data_dir="$ROOT_DIR/data/testnet15/$machine_id"
    rm -rf "$local_data_dir/chain" "$local_data_dir/logs"
    rm -f "$local_data_dir/committed_qcs.json" "$local_data_dir/committed_qcs.json.tmp" "$local_data_dir/committed_qcs.jsonl"
    rm -f "$local_data_dir/canonical_locks.json" "$local_data_dir/canonical_locks.json.tmp"
    rm -f "$local_data_dir/consensus_vote_locks.json" "$local_data_dir/consensus_vote_locks.json.tmp"
    rm -f "$local_data_dir/dag_state.json"
    mkdir -p "$local_data_dir/chain" "$local_data_dir/logs"
  done < <(inventory_machine_ids)
}

reset_remote_nodes() {
  while IFS= read -r machine_id; do
    [[ -z "$machine_id" ]] && continue
    reset_cmd="$(machine_hook_cmd "$machine_id" "RESET_CMD")"
    if [[ -n "$reset_cmd" ]]; then
      echo "[$machine_id] running remote hook: RESET_CMD"
      eval "$reset_cmd"
    fi
  done < <(inventory_machine_ids)
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
  echo "Local installer rebuilds have been removed from this repository." >&2
  echo "Trigger the GitHub Actions packaging workflow for installers instead." >&2
  exit 1
}

start_machine() {
  local machine_id="$1"
  run_hook_or_local "$machine_id" "START_CMD" "start"
}

restart_cluster() {
  if [[ "$SKIP_RESTART" == "true" ]]; then
    echo "Skipping restart (--skip-restart)."
    return
  fi

  echo "Starting testnet nodes in deterministic order..."
  for machine_id in "${START_ORDER[@]}"; do
    start_machine "$machine_id"
    sleep 1
  done
}

post_check() {
  local rpc_url="${TESTNET_RPC_URL:-http://127.0.0.1:5640}"
  echo "Post-reset check via $rpc_url ..."
  curl -sS -X POST "$rpc_url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' || true
  echo
}

echo "=== Synergy Closed Testnet Reset ==="
echo "inventory: $INVENTORY_FILE"
echo "hosts:     $HOSTS_FILE"

stop_cluster
reset_local_state
reset_remote_nodes
render_and_regenerate
rebuild_installers_if_requested
restart_cluster
post_check

echo "Reset workflow complete."
