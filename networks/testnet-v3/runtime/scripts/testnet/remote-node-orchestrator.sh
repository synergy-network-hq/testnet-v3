#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
HOSTS_ENV_FILE="${SYNERGY_MONITOR_HOSTS_ENV:-$ROOT_DIR/testnet/runtime/hosts.env}"
INSTALLERS_DIR="$ROOT_DIR/testnet/runtime/installers"
REMOTE_ROOT_DEFAULT="${SYNERGY_REMOTE_ROOT:-/opt/synergy}"
REMOTE_EXPORTS_DIR="$ROOT_DIR/testnet/runtime/reports/remote-exports"

usage() {
  cat <<USAGE
Usage: $0 <machine-id> <operation>

Operations:
  install_node          Copy installer bundle to remote machine
  setup_node            Deploy installer bundle and run install_and_start.sh
  bootstrap_node        Deploy installer bundle and run install_and_start.sh
  reset_chain           Stop node, delete local chain state, restart from genesis
  start                 nodectl start
  stop                  nodectl stop
  restart               nodectl restart
  status                nodectl status
  logs                  tail nodectl logs (last 120 lines)
  export_logs           Download logs archive from remote machine to local reports dir
  view_chain_data       Show chain data size and top files on remote machine
  export_chain_data     Download chain data archive from remote machine to local reports dir
  info                  Print resolved host/ssh/paths for this machine

Required local files:
  - testnet/runtime/node-inventory.csv
  - testnet/runtime/hosts.env
  - testnet/runtime/installers/<machine-id>/

USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 2 ]]; then
  usage
  exit $(( $# < 2 ? 1 : 0 ))
fi

MACHINE_ID="$1"
OPERATION="$2"
MACHINE_KEY_UPPER="$(printf '%s' "$MACHINE_ID" | tr '[:lower:]-' '[:upper:]_')"

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Inventory file missing: $INVENTORY_FILE" >&2
  exit 1
fi

if [[ -f "$HOSTS_ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$HOSTS_ENV_FILE"
else
  echo "Warning: hosts.env not found at $HOSTS_ENV_FILE. Falling back to inventory/default SSH settings." >&2
fi

inventory_host() {
  awk -F, -v machine="$MACHINE_ID" 'NR>1 && tolower($1)==tolower(machine){print $12; exit}' "$INVENTORY_FILE"
}

inventory_management_host() {
  awk -F, -v machine="$MACHINE_ID" 'NR>1 && tolower($1)==tolower(machine){print $13; exit}' "$INVENTORY_FILE"
}

inventory_public_ip() {
  awk -F, -v machine="$MACHINE_ID" 'NR>1 && tolower($1)==tolower(machine){print $21; exit}' "$INVENTORY_FILE"
}

resolve_var() {
  local name="$1"
  printf '%s' "${!name:-}"
}

HOST_VAR="${MACHINE_KEY_UPPER}_HOST"
MANAGEMENT_HOST_VAR="${MACHINE_KEY_UPPER}_MANAGEMENT_HOST"
SSH_USER_VAR="${MACHINE_KEY_UPPER}_SSH_USER"
SSH_PORT_VAR="${MACHINE_KEY_UPPER}_SSH_PORT"
SSH_KEY_VAR="${MACHINE_KEY_UPPER}_SSH_KEY"
REMOTE_DIR_VAR="${MACHINE_KEY_UPPER}_REMOTE_DIR"
HOST="$(resolve_var "$HOST_VAR")"
if [[ -z "$HOST" ]]; then
  HOST="$(inventory_host)"
fi
MANAGEMENT_HOST="$(resolve_var "$MANAGEMENT_HOST_VAR")"
if [[ -z "$MANAGEMENT_HOST" ]]; then
  MANAGEMENT_HOST="$(inventory_management_host)"
fi
PUBLIC_IP="$(inventory_public_ip)"

SSH_USER="$(resolve_var "$SSH_USER_VAR")"
if [[ -z "$SSH_USER" ]]; then
  SSH_USER="${SYNERGY_TESTNET_SSH_USER:-ops}"
fi

SSH_PORT="$(resolve_var "$SSH_PORT_VAR")"
if [[ -z "$SSH_PORT" ]]; then
  SSH_PORT="${SYNERGY_TESTNET_SSH_PORT:-22}"
fi

SSH_KEY="$(resolve_var "$SSH_KEY_VAR")"
if [[ -z "$SSH_KEY" ]]; then
  SSH_KEY="${SYNERGY_TESTNET_SSH_KEY:-}"
fi
REMOTE_NODE_DIR="$(resolve_var "$REMOTE_DIR_VAR")"
if [[ -z "$REMOTE_NODE_DIR" ]]; then
  REMOTE_NODE_DIR="$REMOTE_ROOT_DEFAULT/$MACHINE_ID"
fi

if [[ -z "$HOST" ]]; then
  echo "Unable to resolve host for $MACHINE_ID from hosts.env or inventory." >&2
  exit 1
fi

append_unique_host_candidate() {
  local candidate="${1:-}"
  [[ -n "$candidate" ]] || return 0
  local existing
  for existing in "${HOST_CANDIDATES[@]:-}"; do
    if [[ "$existing" == "$candidate" ]]; then
      return 0
    fi
  done
  HOST_CANDIDATES+=( "$candidate" )
}

local_ipv4_list() {
  if command -v ip >/dev/null 2>&1; then
    ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true
  fi
  if command -v ifconfig >/dev/null 2>&1; then
    ifconfig 2>/dev/null | awk '/inet /{print $2}' || true
  fi
  if command -v hostname >/dev/null 2>&1; then
    hostname -I 2>/dev/null | tr ' ' '\n' || true
  fi
}

is_local_ip() {
  local candidate="$1"
  [[ -z "$candidate" ]] && return 1
  [[ "$candidate" == "127.0.0.1" || "$candidate" == "::1" ]] && return 0
  local_ipv4_list | grep -Fxq "$candidate"
}

is_local_host_token() {
  local candidate
  candidate="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ -z "$candidate" ]] && return 1
  [[ "$candidate" == "localhost" || "$candidate" == "127.0.0.1" || "$candidate" == "::1" ]] && return 0
  if is_local_ip "$candidate"; then
    return 0
  fi
  local host_short host_full
  host_short="$(hostname -s 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  host_full="$(hostname -f 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  [[ -n "$host_short" && "$candidate" == "$host_short" ]] && return 0
  [[ -n "$host_full" && "$candidate" == "$host_full" ]] && return 0
  return 1
}

IS_LOCAL_TARGET=0
if is_local_host_token "$HOST" || { [[ -n "$MANAGEMENT_HOST" ]] && is_local_host_token "$MANAGEMENT_HOST"; }; then
  IS_LOCAL_TARGET=1
fi

HOST_CANDIDATES=()
append_unique_host_candidate "$HOST"
append_unique_host_candidate "$MANAGEMENT_HOST"
append_unique_host_candidate "$PUBLIC_IP"

if [[ "$IS_LOCAL_TARGET" -eq 1 ]]; then
  LOCAL_INSTALLER_DIR="$INSTALLERS_DIR/$MACHINE_ID"
  if [[ ! -d "$REMOTE_NODE_DIR" && -d "$LOCAL_INSTALLER_DIR" ]]; then
    REMOTE_NODE_DIR="$LOCAL_INSTALLER_DIR"
  fi
fi

SSH_ARGS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=8
  -o ConnectionAttempts=1
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=2
  -p "$SSH_PORT"
)
SCP_ARGS=(
  -o BatchMode=yes
  -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=8
  -o ConnectionAttempts=1
  -P "$SSH_PORT"
)

if [[ -n "$SSH_KEY" ]]; then
  SSH_ARGS+=( -i "$SSH_KEY" )
  SCP_ARGS+=( -i "$SSH_KEY" )
fi

REMOTE_TARGET="${SSH_USER}@${HOST}"
ACTIVE_REMOTE_HOST="$HOST"
INSTALLER_DIR="$INSTALLERS_DIR/$MACHINE_ID"

ssh_run() {
  local remote_cmd="$1"
  local stdin_payload="${2-__NO_STDIN__}"
  local candidate target

  for candidate in "${HOST_CANDIDATES[@]}"; do
    target="${SSH_USER}@${candidate}"
    if [[ "$stdin_payload" == "__NO_STDIN__" ]]; then
      if ssh "${SSH_ARGS[@]}" "$target" "$remote_cmd"; then
        ACTIVE_REMOTE_HOST="$candidate"
        REMOTE_TARGET="$target"
        return 0
      fi
    else
      if ssh "${SSH_ARGS[@]}" "$target" "$remote_cmd" <<<"$stdin_payload"; then
        ACTIVE_REMOTE_HOST="$candidate"
        REMOTE_TARGET="$target"
        return 0
      fi
    fi
  done

  return 1
}

scp_to_remote() {
  local local_path="$1"
  local remote_path="$2"
  local candidate target

  for candidate in "${HOST_CANDIDATES[@]}"; do
    target="${SSH_USER}@${candidate}"
    if scp "${SCP_ARGS[@]}" "$local_path" "${target}:$remote_path"; then
      ACTIVE_REMOTE_HOST="$candidate"
      REMOTE_TARGET="$target"
      return 0
    fi
  done

  return 1
}

scp_from_remote() {
  local remote_path="$1"
  local local_path="$2"
  local candidate target

  for candidate in "${HOST_CANDIDATES[@]}"; do
    target="${SSH_USER}@${candidate}"
    if scp "${SCP_ARGS[@]}" "${target}:$remote_path" "$local_path"; then
      ACTIVE_REMOTE_HOST="$candidate"
      REMOTE_TARGET="$target"
      return 0
    fi
  done

  return 1
}

remote_run_script() {
  local script="$1"
  if [[ "$IS_LOCAL_TARGET" -eq 1 ]]; then
    bash -s <<<"$script"
  else
    ssh_run "bash -s" "$script"
  fi
}

copy_to_remote() {
  local local_path="$1"
  local remote_path="$2"
  if [[ "$IS_LOCAL_TARGET" -eq 1 ]]; then
    mkdir -p "$(dirname "$remote_path")"
    cp "$local_path" "$remote_path"
  else
    scp_to_remote "$local_path" "$remote_path"
  fi
}

copy_from_remote() {
  local remote_path="$1"
  local local_path="$2"
  if [[ "$IS_LOCAL_TARGET" -eq 1 ]]; then
    mkdir -p "$(dirname "$local_path")"
    cp "$remote_path" "$local_path"
  else
    scp_from_remote "$remote_path" "$local_path"
  fi
}

deploy_installer_bundle() {
  if [[ ! -d "$INSTALLER_DIR" ]]; then
    echo "Installer directory missing: $INSTALLER_DIR" >&2
    exit 1
  fi

  local archive
  archive="$(mktemp "/tmp/${MACHINE_ID}-installer.XXXXXX.tgz")"
  tar -C "$INSTALLER_DIR" -czf "$archive" .

  local remote_archive
  remote_archive="/tmp/${MACHINE_ID}-installer.tgz"
  copy_to_remote "$archive" "$remote_archive"
  rm -f "$archive"

  remote_run_script "
set -euo pipefail
mkdir -p '$REMOTE_NODE_DIR'
tar -xzf '$remote_archive' -C '$REMOTE_NODE_DIR'
rm -f '$remote_archive'
chmod +x '$REMOTE_NODE_DIR/install_and_start.sh' '$REMOTE_NODE_DIR/nodectl.sh' || true
echo 'Installer deployed to $REMOTE_NODE_DIR'
"
}

run_nodectl() {
  local command="$1"
  remote_run_script "
set -euo pipefail
if [[ ! -x '$REMOTE_NODE_DIR/nodectl.sh' ]]; then
  echo 'nodectl.sh not found in $REMOTE_NODE_DIR. Run install_node or setup_node first.' >&2
  exit 1
fi
cd '$REMOTE_NODE_DIR'
./nodectl.sh $command
"
}

reset_chain() {
  # Stop first, but do not fail if the process is already down.
  run_nodectl "stop" || true

  remote_run_script "
set -euo pipefail
cd '$REMOTE_NODE_DIR'
rm -rf data/chain data/testnet15/'$MACHINE_ID'/chain
rm -f data/chain.json data/token_state.json data/validator_registry.json
rm -f data/committed_qcs.json data/committed_qcs.json.tmp data/committed_qcs.jsonl
rm -f data/canonical_locks.json data/canonical_locks.json.tmp
rm -f data/consensus_vote_locks.json data/consensus_vote_locks.json.tmp
rm -f data/dag_state.json
rm -f data/testnet15/'$MACHINE_ID'/committed_qcs.json data/testnet15/'$MACHINE_ID'/committed_qcs.json.tmp data/testnet15/'$MACHINE_ID'/committed_qcs.jsonl
rm -f data/testnet15/'$MACHINE_ID'/canonical_locks.json data/testnet15/'$MACHINE_ID'/canonical_locks.json.tmp
rm -f data/testnet15/'$MACHINE_ID'/consensus_vote_locks.json data/testnet15/'$MACHINE_ID'/consensus_vote_locks.json.tmp
rm -f data/testnet15/'$MACHINE_ID'/dag_state.json
mkdir -p data/chain data/testnet15/'$MACHINE_ID'/chain data/logs
echo 'Cleared chain data for $MACHINE_ID in $REMOTE_NODE_DIR'
"

  run_nodectl "start"
  run_nodectl "status" || true
}

export_logs() {
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local remote_archive
  remote_archive="/tmp/${MACHINE_ID}-logs-${ts}.tgz"

  remote_run_script "
set -euo pipefail
if [[ ! -d '$REMOTE_NODE_DIR/data/logs' ]]; then
  echo 'Remote logs directory not found: $REMOTE_NODE_DIR/data/logs' >&2
  exit 1
fi
tar -C '$REMOTE_NODE_DIR' -czf '$remote_archive' data/logs
echo '$remote_archive'
"

  local local_dir
  local_dir="$REMOTE_EXPORTS_DIR/$MACHINE_ID"
  mkdir -p "$local_dir"
  local local_archive
  local_archive="$local_dir/${MACHINE_ID}-logs-${ts}.tgz"

  copy_from_remote "$remote_archive" "$local_archive"
  remote_run_script "rm -f '$remote_archive'"

  echo "Exported logs to $local_archive"
}

view_chain_data() {
  remote_run_script "
set -euo pipefail
if [[ ! -d '$REMOTE_NODE_DIR/data/chain' ]]; then
  echo 'Remote chain directory not found: $REMOTE_NODE_DIR/data/chain' >&2
  exit 1
fi
du -sh '$REMOTE_NODE_DIR/data/chain'
ls -lah '$REMOTE_NODE_DIR/data/chain' | head -40
"
}

export_chain_data() {
  local ts
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  local remote_archive
  remote_archive="/tmp/${MACHINE_ID}-chain-${ts}.tgz"

  remote_run_script "
set -euo pipefail
if [[ ! -d '$REMOTE_NODE_DIR/data/chain' ]]; then
  echo 'Remote chain directory not found: $REMOTE_NODE_DIR/data/chain' >&2
  exit 1
fi
tar -C '$REMOTE_NODE_DIR' -czf '$remote_archive' data/chain
echo '$remote_archive'
"

  local local_dir
  local_dir="$REMOTE_EXPORTS_DIR/$MACHINE_ID"
  mkdir -p "$local_dir"
  local local_archive
  local_archive="$local_dir/${MACHINE_ID}-chain-${ts}.tgz"

  copy_from_remote "$remote_archive" "$local_archive"
  remote_run_script "rm -f '$remote_archive'"

  echo "Exported chain data to $local_archive"
}

show_info() {
  cat <<INFO
Machine:            $MACHINE_ID
Host:               $HOST
Management Host:             ${MANAGEMENT_HOST:-unknown}
SSH candidates:     ${HOST_CANDIDATES[*]}
Execution mode:     $([[ "$IS_LOCAL_TARGET" -eq 1 ]] && echo "local" || echo "ssh")
SSH user:           $SSH_USER
SSH port:           $SSH_PORT
SSH key:            ${SSH_KEY:-default-agent}
Active remote host: ${ACTIVE_REMOTE_HOST:-n/a}
Remote node dir:    $REMOTE_NODE_DIR
Installer source:   $INSTALLER_DIR
INFO
}

case "$OPERATION" in
  install_node)
    deploy_installer_bundle
    ;;
  setup_node)
    deploy_installer_bundle
    remote_run_script "set -euo pipefail; cd '$REMOTE_NODE_DIR'; ./install_and_start.sh"
    ;;
  bootstrap_node)
    deploy_installer_bundle
    remote_run_script "set -euo pipefail; cd '$REMOTE_NODE_DIR'; ./install_and_start.sh"
    ;;
  reset_chain)
    reset_chain
    ;;
  start)
    run_nodectl "start"
    ;;
  stop)
    run_nodectl "stop"
    ;;
  restart)
    run_nodectl "restart"
    ;;
  status)
    run_nodectl "status"
    ;;
  logs)
    run_nodectl "logs"
    ;;
  export_logs)
    export_logs
    ;;
  view_chain_data)
    view_chain_data
    ;;
  export_chain_data)
    export_chain_data
    ;;
  info)
    show_info
    ;;
  *)
    echo "Unsupported operation: $OPERATION" >&2
    usage
    exit 1
    ;;
esac
