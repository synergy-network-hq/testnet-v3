#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ORCHESTRATOR="${ORCHESTRATOR:-$ROOT_DIR/node-control-panel/scripts/testnet/remote-node-orchestrator.sh}"
TX_HELPER="${TX_HELPER:-$ROOT_DIR/scripts/testnet/send-launch-block1-transaction.sh}"

BOOTNODES=(Node-0A Node-0B Node-0C)
QUORUM_VALIDATORS=(GenVal-01 GenVal-02 GenVal-04)
EXPANSION_VALIDATORS=(GenVal-03 GenVal-05)
SUPPORT_NODES=(Node-RPC Node-EXP)

usage() {
  cat <<'USAGE'
Usage:
  clean-launch-testnet.sh prepare
  clean-launch-testnet.sh launch-quorum
  clean-launch-testnet.sh expand validator3|validator5|all
  clean-launch-testnet.sh start-support
  clean-launch-testnet.sh launch-transaction
  clean-launch-testnet.sh status

Phases:
  prepare            Stop support nodes and all validators, then wipe/redeploy validator1, validator2, and validator4.
  launch-quorum      Start only validator1, validator2, and validator4 after bootnodes are confirmed reachable.
  expand             Wipe/redeploy validator3 and/or validator5 after the core quorum is stable.
  start-support      Start RPC and indexer only after validator liveness is stable.
  launch-transaction Generate and bundle the deterministic block-1 launch transaction envelope.
  status             Print orchestrator status for bootnodes, validators, RPC, and indexer.
USAGE
}

require_orchestrator() {
  if [[ ! -x "$ORCHESTRATOR" ]]; then
    echo "Remote orchestrator not found or not executable: $ORCHESTRATOR" >&2
    exit 1
  fi
}

run_remote() {
  local node_id="$1"
  local op="$2"
  echo "[$node_id] $op"
  "$ORCHESTRATOR" "$node_id" "$op"
}

stop_nodes() {
  local node_id
  for node_id in "$@"; do
    run_remote "$node_id" stop || true
  done
}

reset_nodes() {
  local node_id
  for node_id in "$@"; do
    run_remote "$node_id" reset_chain
  done
}

prepare_launch_transaction() {
  if [[ ! -x "$TX_HELPER" ]]; then
    echo "Launch transaction helper not found or not executable: $TX_HELPER" >&2
    exit 1
  fi
  "$TX_HELPER"
}

deploy_nodes() {
  local node_id
  for node_id in "$@"; do
    run_remote "$node_id" install_node
  done
}

bootstrap_nodes() {
  local node_id
  for node_id in "$@"; do
    run_remote "$node_id" bootstrap_node
  done
}

show_status() {
  local node_id
  for node_id in "${BOOTNODES[@]}" "${QUORUM_VALIDATORS[@]}" "${EXPANSION_VALIDATORS[@]}" "${SUPPORT_NODES[@]}"; do
    run_remote "$node_id" status || true
  done
}

require_orchestrator

case "${1:-}" in
  prepare)
    stop_nodes "${SUPPORT_NODES[@]}" "${EXPANSION_VALIDATORS[@]}" "${QUORUM_VALIDATORS[@]}"
    prepare_launch_transaction
    reset_nodes "${QUORUM_VALIDATORS[@]}"
    echo "Core quorum validators have been wiped and redeployed, and the deterministic block-1 transaction envelope has been bundled. Leave the three Linux bootnodes online."
    ;;
  launch-quorum)
    prepare_launch_transaction
    deploy_nodes "${QUORUM_VALIDATORS[@]}"
    show_status
    bootstrap_nodes "${QUORUM_VALIDATORS[@]}"
    echo "Launched validator1, validator2, and validator4 only. Wait for 20 consecutive blocks before expanding."
    ;;
  expand)
    case "${2:-}" in
      validator3)
        reset_nodes GenVal-03
        bootstrap_nodes GenVal-03
        ;;
      validator5)
        reset_nodes GenVal-05
        bootstrap_nodes GenVal-05
        ;;
      all)
        reset_nodes "${EXPANSION_VALIDATORS[@]}"
        bootstrap_nodes "${EXPANSION_VALIDATORS[@]}"
        ;;
      *)
        echo "Specify which validator to expand: validator3, validator5, or all." >&2
        usage
        exit 1
        ;;
    esac
    ;;
  start-support)
    bootstrap_nodes "${SUPPORT_NODES[@]}"
    ;;
  launch-transaction)
    prepare_launch_transaction
    ;;
  status)
    show_status
    ;;
  -h|--help|"")
    usage
    ;;
  *)
    echo "Unknown command: $1" >&2
    usage
    exit 1
    ;;
esac
