#!/usr/bin/env bash
set -uo pipefail

VALIDATOR_NAME="${VALIDATOR_NAME:-unknown-validator}"
SERVICE_NAME="${SERVICE_NAME:-synergy-validator.service}"
APPLIANCE_ROOT="${APPLIANCE_ROOT:-/var/lib/synergy/validator}"
CONFIG_ROOT="${CONFIG_ROOT:-/etc/synergy/validator}"
LOG_ROOT="${LOG_ROOT:-/var/log/synergy/validator}"
OLD_WORKSPACE="${OLD_WORKSPACE:-/home/node/.synergy/testnet/nodes/validator-workspace}"
CHAIN_ID="${CHAIN_ID:-1264}"
NETWORK_ID="${NETWORK_ID:-synergy-testnet-v3}"
VERIFY_TIMEOUT_SECONDS="${VERIFY_TIMEOUT_SECONDS:-90}"
START_VALIDATOR="${START_VALIDATOR:-true}"
SERVICE_WAIT_SECONDS="${SERVICE_WAIT_SECONDS:-18}"
FORCE_REPAIR_RESTART="${FORCE_REPAIR_RESTART:-false}"
QRPC_PORT="${SYNERGY_QRPC_PORT:-5640}"
WS_PORT="${SYNERGY_WS_PORT:-5660}"
METRICS_PORT="${SYNERGY_METRICS_PORT:-6030}"
P2P_PORT="${SYNERGY_P2P_PORT:-5622}"
QRPC_PROBE_TIMEOUT_SECONDS="${QRPC_PROBE_TIMEOUT_SECONDS:-45}"

findings=()
warnings=()
actions=()

rsudo() {
  if command sudo -n "$@" >/tmp/synergy-startup-sudo.out 2>/tmp/synergy-startup-sudo.err; then
    cat /tmp/synergy-startup-sudo.out
    return 0
  fi
  local rc=$?
  local out err
  out="$(cat /tmp/synergy-startup-sudo.out 2>/dev/null || true)"
  err="$(cat /tmp/synergy-startup-sudo.err 2>/dev/null || true)"
  if [[ -n "${SYNERGY_REMOTE_SUDO_PASSWORD:-}" ]] && [[ "$err" =~ (password|a\ password\ is\ required) ]]; then
    if printf '%s\n' "$SYNERGY_REMOTE_SUDO_PASSWORD" | command sudo -S -p '' "$@" >/tmp/synergy-startup-sudo.out 2>/tmp/synergy-startup-sudo.err; then
      cat /tmp/synergy-startup-sudo.out
      return 0
    fi
    rc=$?
    out="$(cat /tmp/synergy-startup-sudo.out 2>/dev/null || true)"
    err="$(cat /tmp/synergy-startup-sudo.err 2>/dev/null || true)"
  fi
  [[ -n "$out" ]] && printf '%s\n' "$out"
  [[ -n "$err" ]] && printf '%s\n' "$err" >&2
  return "$rc"
}

add_finding() {
  findings+=("$1")
}

add_warning() {
  warnings+=("$1")
}

add_action() {
  actions+=("$1")
}

path_state() {
  local label="$1"
  local path="$2"
  local stat_line exists="false" kind="missing" target="" owner="" mode=""
  stat_line="$(rsudo stat -c '%F|%N|%U:%G|%a' "$path" 2>/dev/null || true)"
  if [[ -n "$stat_line" ]]; then
    exists="true"
    owner="$(printf '%s' "$stat_line" | awk -F'|' '{print $3}')"
    mode="$(printf '%s' "$stat_line" | awk -F'|' '{print $4}')"
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
  printf '%s|path=%s|exists=%s|kind=%s|target=%s|owner=%s|mode=%s\n' "$label" "$path" "$exists" "$kind" "$target" "$owner" "$mode"
}

old_refs() {
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
    "$CONFIG_ROOT/node.env" \
    "$CONFIG_ROOT/service.env" \
    "$CONFIG_ROOT/config.toml" \
    "$CONFIG_ROOT/active-profile.toml" \
    "$CONFIG_ROOT/cluster-assignment.toml" \
    /etc/default/synergy-validator \
    /etc/sysconfig/synergy-validator
}

exact_processes() {
  ps -eo pid=,comm=,args= | awk '$2 ~ /^synergy-(validator|node)$/ || $3 ~ /^\/opt\/synergy\/bin\/synergy-(validator|node)$/ {print}' || true
}

offline_tip() {
  python3 - "$APPLIANCE_ROOT/chain.json" <<'PY' 2>/dev/null || true
import json, os, re, sys
path = sys.argv[1]
if not os.path.exists(path):
    print("unavailable")
    raise SystemExit(0)
size = os.path.getsize(path)
with open(path, "rb") as handle:
    handle.seek(max(0, size - 16 * 1024 * 1024))
    text = handle.read().decode("utf-8", "ignore")
pairs = re.findall(r'"height"\s*:\s*(\d+).*?"hash"\s*:\s*"([0-9a-fA-F]+)"', text, re.S)
if pairs:
    height, block_hash = pairs[-1]
    print(f"height={height} hash={block_hash}")
else:
    heights = re.findall(r'"height"\s*:\s*(\d+)', text)
    hashes = re.findall(r'"hash"\s*:\s*"([0-9a-fA-F]+)"', text)
    print(f"height={heights[-1] if heights else 'unknown'} hash={hashes[-1] if hashes else 'unknown'}")
PY
}

identity_evidence() {
  rsudo sh -c '
set +e
for p in "$1"/keys/address.txt "$1"/keys/public.key "$1"/identity/key_manifest.json "$1"/node.env; do
  [ -f "$p" ] || continue
  case "$p" in
    */private.key) continue ;;
  esac
  bytes=$(wc -c < "$p" 2>/dev/null || echo 0)
  sha=$(sha256sum "$p" 2>/dev/null | awk "{print \$1}")
  echo "$p bytes=$bytes sha256=$sha"
done
' sh "$CONFIG_ROOT"
}

detect_verify_binary() {
  local service_bin="$1"
  for candidate in /opt/synergy/bin/synergy-node "$service_bin" /usr/local/bin/synergy-node /usr/bin/synergy-node; do
    [[ -n "$candidate" ]] || continue
    if rsudo test -x "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

run_verify_state() {
  local bin="$1"
  local out="/tmp/${VALIDATOR_NAME}-verify-state-startup.json"
  local err="/tmp/${VALIDATOR_NAME}-verify-state-startup.err"
  rsudo timeout "$VERIFY_TIMEOUT_SECONDS" "$bin" validator verify-state \
    --state-root "$APPLIANCE_ROOT" \
    --allow-testnet-recovery-checkpoint \
    --chain-id "$CHAIN_ID" \
    --network-id "$NETWORK_ID" >"$out" 2>"$err"
  local rc=$?
  printf 'verify_binary=%s\nverify_rc=%s\nverify_stdout_tail=\n' "$bin" "$rc"
  tail -c 4000 "$out" 2>/dev/null || true
  printf '\nverify_stderr_tail=\n'
  tail -c 4000 "$err" 2>/dev/null || true
  return "$rc"
}

listener_snapshot() {
  rsudo ss -ltnp 2>/dev/null | grep -E ":(${P2P_PORT}|${QRPC_PORT}|${WS_PORT}|${METRICS_PORT})\\b" || true
}

rpc_probe() {
  python3 - "$QRPC_PORT" "$QRPC_PROBE_TIMEOUT_SECONDS" <<'PY' 2>/dev/null || true
import json, sys, urllib.error, urllib.request
port = sys.argv[1]
timeout = float(sys.argv[2])
def rpc(method, params=None):
    payload = json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}", data=payload, headers={"content-type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        return {"error": str(exc)}
out = {
    "latest_block": rpc("synergy_getLatestBlock"),
    "canonical_lock": rpc("synergy_getCanonicalLock"),
    "peer_info": rpc("synergy_getPeerInfo"),
    "node_status": rpc("synergy_getNodeStatus"),
}
print(json.dumps(out, sort_keys=True))
PY
}

journal_signals() {
  local since="$1"
  rsudo journalctl -u "$SERVICE_NAME" --since "$since" -n 220 --no-pager 2>/dev/null \
    | grep -Ei 'validator-workspace|permission denied|identity|key mismatch|mismatch|compact|canonical|panic|fatal|failed|error|quarantine|divergen|stall' \
    | tail -80 || true
}

ensure_runtime_genesis() {
  local src="$CONFIG_ROOT/genesis.json"
  local dst="$APPLIANCE_ROOT/config/genesis.json"
  local src_sha dst_sha backup replacement_stamp
  if ! rsudo test -f "$src"; then
    add_finding "canonical_genesis_missing:$src"
    return 1
  fi
  src_sha="$(rsudo sha256sum "$src" 2>/dev/null | awk '{print $1}' || true)"
  dst_sha=""
  if rsudo test -f "$dst"; then
    dst_sha="$(rsudo sha256sum "$dst" 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -n "$src_sha" && "$src_sha" == "$dst_sha" ]]; then
    rsudo chown node:node "$dst" >/dev/null 2>&1 || true
    rsudo chmod 0640 "$dst" >/dev/null 2>&1 || true
    return 0
  fi
  replacement_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if rsudo test -e "$dst"; then
    backup="${dst}.pre-startup-replaced-${replacement_stamp}"
    rsudo mv "$dst" "$backup" >/dev/null 2>&1 || {
      add_finding "runtime_genesis_backup_failed:$dst"
      return 1
    }
    add_action "backed up replaced runtime genesis $dst to $backup"
  fi
  if rsudo install -o node -g node -m 0640 "$src" "$dst" >/dev/null 2>&1; then
    add_action "installed runtime genesis $dst from $src"
    return 0
  fi
  add_finding "runtime_genesis_install_failed:$dst"
  return 1
}

ensure_runtime_consensus_fork() {
  local dst="$APPLIANCE_ROOT/config/consensus-fork-migration.json"
  local src="" candidate src_sha dst_sha backup replacement_stamp validation
  for candidate in \
    "$CONFIG_ROOT/consensus-fork-migration.json" \
    "$CONFIG_ROOT/config/consensus-fork-migration.json" \
    "$APPLIANCE_ROOT/config/consensus-fork-migration.json"
  do
    if rsudo test -s "$candidate"; then
      src="$candidate"
      break
    fi
  done
  if [[ -z "$src" ]]; then
    add_finding "consensus_fork_migration_missing"
    return 1
  fi
  validation="$(rsudo python3 - "$src" <<'PY' 2>&1
import json, sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
required = [
    "fork_height",
    "parent_height",
    "parent_hash",
    "state_root",
    "old_consensus_algorithm",
    "new_consensus_algorithm",
    "new_validator_registry",
    "parser_mode",
]
missing = [key for key in required if key not in data]
if missing:
    raise SystemExit(f"missing required consensus fork fields: {','.join(missing)}")
if data.get("parser_mode") != "fail_closed":
    raise SystemExit("consensus fork parser_mode is not fail_closed")
validators = data.get("new_validator_registry") or []
if not validators:
    raise SystemExit("consensus fork validator registry is empty")
print(
    f"fork_height={data.get('fork_height')} validators={len(validators)} "
    f"parser_mode={data.get('parser_mode')}"
)
PY
)" || {
    add_finding "consensus_fork_migration_invalid:${validation}"
    return 1
  }
  src_sha="$(rsudo sha256sum "$src" 2>/dev/null | awk '{print $1}' || true)"
  dst_sha=""
  if rsudo test -f "$dst"; then
    dst_sha="$(rsudo sha256sum "$dst" 2>/dev/null | awk '{print $1}' || true)"
  fi
  if [[ -n "$src_sha" && "$src_sha" == "$dst_sha" ]]; then
    rsudo chown node:node "$dst" >/dev/null 2>&1 || true
    rsudo chmod 0640 "$dst" >/dev/null 2>&1 || true
    return 0
  fi
  replacement_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  if rsudo test -e "$dst"; then
    backup="${dst}.pre-startup-replaced-${replacement_stamp}"
    rsudo mv "$dst" "$backup" >/dev/null 2>&1 || {
      add_finding "runtime_consensus_fork_backup_failed:$dst"
      return 1
    }
    add_action "backed up replaced runtime consensus fork $dst to $backup"
  fi
  if rsudo install -o node -g node -m 0640 "$src" "$dst" >/dev/null 2>&1; then
    add_action "installed runtime consensus fork $dst from $src (${validation})"
    return 0
  fi
  add_finding "runtime_consensus_fork_install_failed:$dst"
  return 1
}

ensure_runtime_data_files() {
  rsudo mkdir -p "$APPLIANCE_ROOT/data" >/dev/null 2>&1 || {
    add_finding "runtime_data_dir_create_failed:$APPLIANCE_ROOT/data"
    return 1
  }
  rsudo chown node:node "$APPLIANCE_ROOT/data" >/dev/null 2>&1 || true
  rsudo chmod 0750 "$APPLIANCE_ROOT/data" >/dev/null 2>&1 || true

  local name src dst candidate src_sha dst_sha replacement_stamp backup
  replacement_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  for name in \
    chain.json \
    canonical_locks.json \
    committed_blocks.jsonl \
    committed_qcs.json \
    committed_qcs.jsonl \
    dag_state.json \
    token_state.json \
    validator_registry.json \
    state_checkpoint.json \
    consensus_vote_locks.json
  do
    dst="$APPLIANCE_ROOT/data/$name"
    src=""
    for candidate in \
      "$APPLIANCE_ROOT/$name" \
      "$APPLIANCE_ROOT/state/$name" \
      "$APPLIANCE_ROOT/state/derived/$name"
    do
      if rsudo test -s "$candidate"; then
        src="$candidate"
        break
      fi
    done
    if [[ -z "$src" ]]; then
      case "$name" in
        chain.json)
          rsudo test -s "$APPLIANCE_ROOT/state/derived/chain_export.json" && src="$APPLIANCE_ROOT/state/derived/chain_export.json"
          ;;
        committed_qcs.json)
          rsudo test -s "$APPLIANCE_ROOT/state/derived/committed_qcs_export.json" && src="$APPLIANCE_ROOT/state/derived/committed_qcs_export.json"
          ;;
        committed_qcs.jsonl)
          rsudo test -s "$APPLIANCE_ROOT/state/derived/committed_qcs_export.jsonl" && src="$APPLIANCE_ROOT/state/derived/committed_qcs_export.jsonl"
          ;;
      esac
    fi
    if [[ -z "$src" ]]; then
      case "$name" in
        chain.json|canonical_locks.json|committed_qcs.jsonl|validator_registry.json)
          add_finding "runtime_state_source_missing:$name"
          ;;
        *)
          add_warning "optional_runtime_state_source_missing:$name"
          ;;
      esac
      continue
    fi
    src_sha="$(rsudo sha256sum "$src" 2>/dev/null | awk '{print $1}' || true)"
    dst_sha=""
    if rsudo test -s "$dst"; then
      dst_sha="$(rsudo sha256sum "$dst" 2>/dev/null | awk '{print $1}' || true)"
    fi
    if [[ -n "$src_sha" && "$src_sha" == "$dst_sha" ]]; then
      rsudo chown node:node "$dst" >/dev/null 2>&1 || true
      continue
    fi
    if rsudo test -e "$dst"; then
      backup="${dst}.pre-startup-replaced-${replacement_stamp}"
      rsudo mv "$dst" "$backup" >/dev/null 2>&1 || {
        add_finding "runtime_data_backup_failed:$dst"
        continue
      }
      add_action "backed up replaced runtime data $dst to $backup"
    fi
    if rsudo ln "$src" "$dst" >/dev/null 2>&1 || rsudo cp -p "$src" "$dst" >/dev/null 2>&1; then
      rsudo chown node:node "$dst" >/dev/null 2>&1 || true
      add_action "installed runtime data $dst from $src"
    else
      add_finding "runtime_data_install_failed:$dst"
    fi
  done
}

runtime_data_summary() {
  rsudo sh -c '
for name in chain.json canonical_locks.json committed_blocks.jsonl committed_qcs.json committed_qcs.jsonl dag_state.json token_state.json validator_registry.json state_checkpoint.json consensus_vote_locks.json; do
  p="$1/data/$name"
  if [ -e "$p" ]; then
    size=$(stat -c "%s" "$p")
    stat -c "$name|%F|%U:%G|%a|%s" "$p"
    if [ "$size" -le 104857600 ]; then
      sha256sum "$p" 2>/dev/null | awk -v n="$name" "{print n\"|sha256|\"\$1}"
    else
      echo "$name|sha256|skipped_large_file_size=$size"
    fi
  else
    echo "$name|missing"
  fi
done
' sh "$APPLIANCE_ROOT"
}

runtime_genesis_summary() {
  rsudo sh -c '
for p in "$1/genesis.json" "$2/config/genesis.json"; do
  if [ -e "$p" ]; then
    stat -c "$p|%F|%U:%G|%a|%s" "$p"
    sha256sum "$p" 2>/dev/null | awk -v p="$p" "{print p\"|sha256|\"\$1}"
    sudo -n -u node test -r "$p" 2>/dev/null && echo "$p|node_readable|yes" || echo "$p|node_readable|no"
  else
    echo "$p|missing"
  fi
done
' sh "$CONFIG_ROOT" "$APPLIANCE_ROOT"
}

runtime_consensus_fork_summary() {
  rsudo sh -c '
for p in "$1/consensus-fork-migration.json" "$2/config/consensus-fork-migration.json"; do
  if [ -e "$p" ]; then
    stat -c "$p|%F|%U:%G|%a|%s" "$p"
    sha256sum "$p" 2>/dev/null | awk -v p="$p" "{print p\"|sha256|\"\$1}"
    sudo -n -u node test -r "$p" 2>/dev/null && echo "$p|node_readable|yes" || echo "$p|node_readable|no"
  else
    echo "$p|missing"
  fi
done
' sh "$CONFIG_ROOT" "$APPLIANCE_ROOT"
}

now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hostname_value="$(hostname -f 2>/dev/null || hostname)"
service_before="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
service_show="$(rsudo systemctl show "$SERVICE_NAME" -p FragmentPath -p WorkingDirectory -p ExecStart -p EnvironmentFiles -p ReadWritePaths -p User -p Group 2>/dev/null || true)"
service_bin="$(printf '%s\n' "$service_show" | sed -n 's/^ExecStart={ path=\\([^ ]*\\) .*/\\1/p' | head -1)"
if [[ "$START_VALIDATOR" == "true" && "$FORCE_REPAIR_RESTART" == "true" && "$service_before" == "active" ]]; then
  rsudo systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  rsudo systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
  add_action "force stopped active service for runtime data repair"
  service_before="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
fi
if [[ "$START_VALIDATOR" == "true" && "$service_before" != "inactive" && "$service_before" != "active" ]]; then
  rsudo systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  rsudo systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
  add_action "stopped/reset prior non-inactive service state:${service_before:-unknown}"
  service_before="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
fi
processes_before="$(exact_processes)"
old_refs_text="$(old_refs)"
old_refs_count=0
if [[ -n "$old_refs_text" ]]; then
  old_refs_count="$(printf '%s\n' "$old_refs_text" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
fi
old_state="$(path_state "old_workspace" "$OLD_WORKSPACE")"
old_kind="$(printf '%s\n' "$old_state" | awk -F'|' '{for (i=1; i<=NF; i++) if ($i ~ /^kind=/) {sub(/^kind=/, "", $i); print $i}}')"
old_children=""
if [[ "$old_kind" == "directory" ]]; then
  old_children="$(rsudo sh -c 'find "$1" -mindepth 1 -maxdepth 1 -printf "%f\n" | sort' sh "$OLD_WORKSPACE" 2>/dev/null || true)"
fi

[[ "$service_before" == "active" || "$service_before" == "inactive" ]] || add_warning "service_state_before_unexpected:${service_before:-unknown}"
[[ -z "$processes_before" || "$service_before" == "active" ]] || add_finding "validator_process_present_while_service_not_active"
printf '%s\n' "$service_show" | grep -Fq "WorkingDirectory=$APPLIANCE_ROOT" || add_finding "service_working_directory_not_appliance_root"
printf '%s\n' "$service_show" | grep -Fq "$APPLIANCE_ROOT" || add_finding "service_missing_appliance_root"
printf '%s\n' "$service_show" | grep -Fq "$CONFIG_ROOT" || add_finding "service_missing_config_root"
[[ "$old_refs_count" == "0" ]] || add_finding "active_old_workspace_references:${old_refs_count}"
[[ "$old_kind" != "symlink" ]] || add_finding "old_workspace_is_symlink"
if [[ "$old_kind" == "directory" && "$old_children" != "README.validator-appliance-migrated.txt" ]]; then
  add_finding "old_workspace_directory_not_inert"
fi
rsudo test -d "$APPLIANCE_ROOT" || add_finding "appliance_root_missing"
rsudo test -d "$CONFIG_ROOT" || add_finding "config_root_missing"

required_dirs=(
  "$APPLIANCE_ROOT/identity" "$APPLIANCE_ROOT/config" "$APPLIANCE_ROOT/state" "$APPLIANCE_ROOT/state/store"
  "$APPLIANCE_ROOT/state/derived" "$APPLIANCE_ROOT/state/checkpoints" "$APPLIANCE_ROOT/state/snapshots"
  "$APPLIANCE_ROOT/state/quarantine" "$APPLIANCE_ROOT/evidence" "$APPLIANCE_ROOT/logs" "$APPLIANCE_ROOT/runtime"
)
for dir in "${required_dirs[@]}"; do
  rsudo test -d "$dir" || add_finding "required_dir_missing:$dir"
done
ensure_runtime_genesis >/dev/null || true
ensure_runtime_consensus_fork >/dev/null || true
ensure_runtime_data_files >/dev/null || true

verify_output=""
verify_rc="not_run"
verify_bin="$(detect_verify_binary "$service_bin" || true)"
if [[ -z "$verify_bin" ]]; then
  add_warning "verify_state_binary_not_found"
else
  verify_output="$(run_verify_state "$verify_bin")"
  verify_rc="$(printf '%s\n' "$verify_output" | awk -F= '$1=="verify_rc"{print $2}' | head -1)"
  if [[ "$verify_rc" == "124" ]]; then
    add_warning "verify_state_timeout_${VERIFY_TIMEOUT_SECONDS}s"
  elif [[ "$verify_rc" != "0" ]]; then
    add_finding "verify_state_failed_rc:${verify_rc}"
  fi
fi

startup_status="NOT_STARTED"
start_since="$(date -u '+%Y-%m-%d %H:%M:%S')"
attempted_start="false"
if ((${#findings[@]} == 0)) && [[ "$START_VALIDATOR" == "true" ]]; then
  if [[ "$service_before" == "active" ]]; then
    add_action "service already active; did not restart"
    attempted_start="true"
  else
    rsudo systemctl daemon-reload >/dev/null 2>&1
    add_action "systemctl daemon-reload"
    attempted_start="true"
    if rsudo systemctl start "$SERVICE_NAME" >/dev/null 2>&1; then
      add_action "systemctl start $SERVICE_NAME"
    else
      add_finding "systemctl_start_failed"
    fi
  fi
  sleep "$SERVICE_WAIT_SECONDS"
elif ((${#findings[@]} > 0)); then
  startup_status="PRESTART_BLOCKED"
fi

service_after="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
processes_after="$(exact_processes)"
listeners_after="$(listener_snapshot)"
rpc_after="$(rpc_probe)"
journal_after="$(journal_signals "$start_since")"
service_final="$(rsudo systemctl is-active "$SERVICE_NAME" 2>/dev/null || true)"
processes_final="$(exact_processes)"

if [[ "$START_VALIDATOR" == "true" && "$attempted_start" == "true" ]]; then
  if [[ "$service_final" == "active" ]]; then
    startup_status="STARTED_ACTIVE"
  else
    startup_status="START_FAILED"
    add_finding "service_final_not_active:${service_final:-unknown}"
  fi
  if ! printf '%s\n' "$listeners_after" | grep -Eq ":${QRPC_PORT}\\b"; then
    add_finding "qrpc_listener_missing:${QRPC_PORT}"
  fi
  if ! printf '%s\n' "$rpc_after" | grep -q '"latest_block".*"result"'; then
    add_finding "qrpc_latest_block_unavailable"
  fi
fi

if printf '%s\n' "$journal_after" | grep -Eiq 'validator-workspace|permission denied|key mismatch|identity mismatch|compact.*(fail|panic|error)|canonical.*(fail|panic|error)|panic|fatal'; then
  add_finding "fatal_or_path_error_in_recent_journal"
fi

final_status="VALIDATOR_STARTUP_OK"
if ((${#findings[@]} > 0)); then
  final_status="VALIDATOR_STARTUP_BLOCKED"
fi

cat <<REPORT
# Validator Startup Run

validator: ${VALIDATOR_NAME}
generated_utc: ${now_utc}
hostname: ${hostname_value}
service: ${SERVICE_NAME}
final_status: ${final_status}
startup_status: ${startup_status}

## Pre-Start State

- service_before: ${service_before:-unknown}
- exact_processes_before:
\`\`\`
${processes_before:-none}
\`\`\`

## Service Paths

\`\`\`
${service_show}
\`\`\`

## Filesystem Paths

\`\`\`
${old_state}
$(path_state "appliance_root" "$APPLIANCE_ROOT")
$(path_state "config_root" "$CONFIG_ROOT")
$(path_state "log_root" "$LOG_ROOT")
$(for dir in "${required_dirs[@]}"; do path_state "required" "$dir"; done)
\`\`\`

## Old Workspace References

- active_old_workspace_reference_count: ${old_refs_count}

\`\`\`
${old_refs_text:-none}
\`\`\`

## Offline State Evidence

- best_effort_tip: $(offline_tip)
- runtime_genesis_summary:
\`\`\`
$(runtime_genesis_summary)
\`\`\`
- runtime_consensus_fork_summary:
\`\`\`
$(runtime_consensus_fork_summary)
\`\`\`
- runtime_data_summary:
\`\`\`
$(runtime_data_summary)
\`\`\`
- identity_public_artifacts:
\`\`\`
$(identity_evidence)
\`\`\`
- verify_state_result:
\`\`\`
${verify_output:-not_run}
\`\`\`

## Startup Actions

\`\`\`
$(printf '%s\n' "${actions[@]:-none}")
\`\`\`

## Post-Start State

- service_after: ${service_after:-unknown}
- service_final: ${service_final:-unknown}
- exact_processes_after:
\`\`\`
${processes_after:-none}
\`\`\`
- exact_processes_final:
\`\`\`
${processes_final:-none}
\`\`\`

## Listener Snapshot

\`\`\`
${listeners_after:-none}
\`\`\`

## Local qRPC Snapshot

\`\`\`json
${rpc_after:-{}}
\`\`\`

## Recent Journal Signals

\`\`\`
${journal_after:-none}
\`\`\`

## Warnings

\`\`\`
$(printf '%s\n' "${warnings[@]:-none}")
\`\`\`

## Findings

\`\`\`
$(printf '%s\n' "${findings[@]:-none}")
\`\`\`
REPORT

if [[ "$final_status" == "VALIDATOR_STARTUP_OK" ]]; then
  exit 0
fi
exit 1
