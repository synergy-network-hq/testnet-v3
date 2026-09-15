#!/usr/bin/env bash
set -uo pipefail

VALIDATOR_NAME="${VALIDATOR_NAME:-unknown-validator}"
SERVICE_NAME="${SERVICE_NAME:-synergy-validator.service}"
OLD_WORKSPACE="${OLD_WORKSPACE:-/home/node/.synergy/testnet/nodes/validator-workspace}"
APPLIANCE_ROOT="${APPLIANCE_ROOT:-/var/lib/synergy/validator}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/synergy/validator}"
LOG_ROOT="${LOG_ROOT:-/var/log/synergy/validator}"

findings=()
actions=()

rsudo() {
  if command sudo -n "$@" >/tmp/synergy-offline-layout-sudo.out 2>/tmp/synergy-offline-layout-sudo.err; then
    cat /tmp/synergy-offline-layout-sudo.out
    return 0
  fi
  local rc=$?
  local err
  local out
  out="$(cat /tmp/synergy-offline-layout-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-offline-layout-sudo.err 2>/dev/null || true)"
  if [[ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]] && [[ "$err" =~ (password|a\ password\ is\ required) ]]; then
    if printf '%s\n' "$SYNERGY_REMOTE_SUDO_PASSWORD" | command sudo -S -p '' "$@" >/tmp/synergy-offline-layout-sudo.out 2>/tmp/synergy-offline-layout-sudo.err; then
      cat /tmp/synergy-offline-layout-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-offline-layout-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-offline-layout-sudo.err 2>/dev/null || true)"
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  [[ -n "$err" ]] && printf '%s\n' "$err" >&2
  return "$rc"
}

record_finding() {
  findings+=("$1")
}

record_action() {
  actions+=("$1")
}

path_state() {
  local label="$1"
  local path="$2"
  local exists="false"
  local kind="missing"
  local target=""
  local mode=""
  local owner=""
  local stat_line=""

  stat_line="$(rsudo stat -c '%F|%N|%U:%G|%a' "$path" 2>/dev/null || true)"
  if [[ -n "$stat_line" ]]; then
    exists="true"
    mode="$(printf '%s' "$stat_line" | awk -F'|' '{print $4}')"
    owner="$(printf '%s' "$stat_line" | awk -F'|' '{print $3}')"
    case "$stat_line" in
      symbolic\ link*)
        kind="symlink"
        target="$(rsudo readlink "$path" 2>/dev/null || true)"
        ;;
      directory*) kind="directory" ;;
      regular\ file*) kind="file" ;;
      *) kind="$(printf '%s' "$stat_line" | awk -F'|' '{print $1}')" ;;
    esac
  fi

  printf '%s|path=%s|exists=%s|kind=%s|target=%s|mode=%s|owner=%s\n' \
    "$label" "$path" "$exists" "$kind" "$target" "$mode" "$owner"
}

grep_old_workspace_refs() {
  rsudo sh -c '
old="$1"
shift
for root in "$@"; do
  [ -e "$root" ] || [ -L "$root" ] || continue
  grep -RInF "$old" "$root" 2>/dev/null || true
done
' sh "$OLD_WORKSPACE" \
    /etc/systemd/system/synergy-validator.service \
    /etc/systemd/system/synergy-validator.service.d \
    "$CONFIG_ROOT/config.toml" \
    "$CONFIG_ROOT/node.toml" \
    "$CONFIG_ROOT/node.env" \
    "$CONFIG_ROOT/service.env" \
    "$CONFIG_ROOT/validator.env" \
    /etc/default/synergy-validator \
    /etc/sysconfig/synergy-validator
}

now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hostname="$(hostname -f 2>/dev/null || hostname)"

service_before="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
if [[ "$service_before" == "active" ]]; then
  rsudo systemctl stop "$SERVICE_NAME" >/dev/null
  record_action "stopped active $SERVICE_NAME and left it stopped"
  sleep 2
fi
service_after="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
if [[ "$service_after" == "active" ]]; then
  record_finding "validator_service_active_after_stop"
fi

process_lines="$(ps -eo pid=,comm=,args= | awk '$2 ~ /^synergy-(validator|node)$/ || $3 ~ /^\/opt\/synergy\/bin\/synergy-(validator|node)$/ {print}' || true)"
if [[ -n "$process_lines" ]]; then
  record_finding "validator_process_present"
fi

service_show="$(rsudo systemctl show "$SERVICE_NAME" \
  -p FragmentPath \
  -p WorkingDirectory \
  -p ExecStart \
  -p EnvironmentFiles \
  -p ReadWritePaths \
  -p User \
  -p Group 2>/dev/null || true)"

working_directory="$(printf '%s\n' "$service_show" | awk -F= '$1=="WorkingDirectory"{print $2}')"
if [[ "$working_directory" != "$APPLIANCE_ROOT" ]]; then
  record_finding "service_working_directory_not_appliance_root:${working_directory}"
fi

if ! printf '%s\n' "$service_show" | grep -Fq "$APPLIANCE_ROOT"; then
  record_finding "service_show_missing_appliance_root"
fi

if printf '%s\n' "$service_show" | grep -Fq "$OLD_WORKSPACE"; then
  record_finding "service_references_old_workspace"
fi

if ! rsudo test -d "$APPLIANCE_ROOT"; then
  record_finding "appliance_root_missing"
fi
if ! rsudo test -d "$CONFIG_ROOT"; then
  record_finding "config_root_missing"
fi
old_workspace_state="$(path_state "old_workspace" "$OLD_WORKSPACE")"
old_workspace_kind="$(printf '%s\n' "$old_workspace_state" | awk -F'|' '{for (i=1; i<=NF; i++) if ($i ~ /^kind=/) {sub(/^kind=/, "", $i); print $i}}')"
if [[ "$old_workspace_kind" == "symlink" ]]; then
  record_finding "old_workspace_is_symlink"
elif [[ "$old_workspace_kind" == "directory" ]]; then
  old_children="$(rsudo sh -c 'find "$1" -mindepth 1 -maxdepth 1 -printf "%f\n" | sort' sh "$OLD_WORKSPACE" 2>/dev/null || true)"
  if [[ "$old_children" != "README.validator-appliance-migrated.txt" ]]; then
    record_finding "old_workspace_directory_not_inert"
  fi
fi

required_dirs=(
  "$APPLIANCE_ROOT/identity"
  "$APPLIANCE_ROOT/config"
  "$APPLIANCE_ROOT/state"
  "$APPLIANCE_ROOT/state/store"
  "$APPLIANCE_ROOT/state/derived"
  "$APPLIANCE_ROOT/state/checkpoints"
  "$APPLIANCE_ROOT/state/snapshots"
  "$APPLIANCE_ROOT/state/quarantine"
  "$APPLIANCE_ROOT/evidence"
  "$APPLIANCE_ROOT/logs"
  "$APPLIANCE_ROOT/runtime"
)
for dir in "${required_dirs[@]}"; do
  if ! rsudo test -d "$dir"; then
    record_finding "required_appliance_dir_missing:$dir"
  fi
done

old_refs="$(grep_old_workspace_refs || true)"
old_refs_count=0
if [[ -n "$old_refs" ]]; then
  old_refs_count="$(printf '%s\n' "$old_refs" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
fi
if [[ "$old_refs_count" != "0" ]]; then
  record_finding "active_config_old_workspace_refs:${old_refs_count}"
fi

status="MIGRATED_OFFLINE_READY"
if ((${#findings[@]} > 0)); then
  status="BLOCKED_OFFLINE_LAYOUT"
fi

cat <<REPORT
# Validator Offline Appliance Layout Verification

validator: ${VALIDATOR_NAME}
generated_utc: ${now_utc}
hostname: ${hostname}
final_status: ${status}

## Runtime Boundary

- Validator startup was not performed.
- qRPC, chain-health, sync, finality, block-production, consensus, and live chain checks were not run.
- Consensus JSON/JSONL files were not edited.

## Service State

- service: ${SERVICE_NAME}
- service_before: ${service_before:-unknown}
- service_after: ${service_after:-unknown}
- stop_actions: ${#actions[@]}
- validator_process_lines:
\`\`\`
${process_lines:-none}
\`\`\`

## Service Paths

\`\`\`
${service_show}
\`\`\`

## Filesystem Paths

\`\`\`
$(path_state "old_workspace" "$OLD_WORKSPACE")
$(path_state "appliance_root" "$APPLIANCE_ROOT")
$(path_state "config_root" "$CONFIG_ROOT")
$(path_state "log_root" "$LOG_ROOT")
\`\`\`

## Required Appliance Directories

\`\`\`
$(for dir in "${required_dirs[@]}"; do path_state "required" "$dir"; done)
\`\`\`

## Old Workspace References

- active_old_workspace_reference_count: ${old_refs_count}

\`\`\`
${old_refs:-none}
\`\`\`

## Actions

\`\`\`
$(printf '%s\n' "${actions[@]:-none}")
\`\`\`

## Findings

\`\`\`
$(printf '%s\n' "${findings[@]:-none}")
\`\`\`
REPORT

if [[ "$status" == "MIGRATED_OFFLINE_READY" ]]; then
  exit 0
fi
exit 1
