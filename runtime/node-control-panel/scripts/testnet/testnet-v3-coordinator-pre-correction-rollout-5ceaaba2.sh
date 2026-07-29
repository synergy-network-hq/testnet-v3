#!/usr/bin/env bash
#
# Reversible Testnet-v3 coordinator release switch.  This script intentionally
# does not invoke a coordinator admin endpoint.  It installs only the exact
# checksum-bound v19.0.55 binary, proves the generation-21 public bytes did not
# change, and leaves a root-only checkpoint for the separate one-shot repair.

set -Eeuo pipefail
umask 077

SERVICE="synergy-validator-vpn-coordinator.service"
RELEASE_ROOT="/opt/synergy/synergy-node-control-panel-coordinator/releases"
CURRENT_RELEASE="${RELEASE_ROOT}/v19.0.54-tv3-transport-release-21-84bbd5cc"
CURRENT_BINARY="${CURRENT_RELEASE}/control-service"
CURRENT_BINARY_SHA256="84bbd5cc10b1d6c9eb7cf3786a2872d76b4419e3323da3bce2312a6449e682b0"
TARGET_RELEASE="${RELEASE_ROOT}/v19.0.55-tv3-canonical-binding-correction-5ceaaba2"
TARGET_BINARY="${TARGET_RELEASE}/control-service"
TARGET_BINARY_SHA256="5ceaaba2a24bace5064b4c26d792840a218034c7ad2236cd4c3b8774a2e74374"
ARTIFACT="/tmp/testnet-v3-control-service-v19.0.55-5ceaaba2"
DROPIN_DIR="/etc/systemd/system/${SERVICE}.d"
DROPIN="${DROPIN_DIR}/60-release.conf"
TOKEN_REFERENCE='${SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN}'
EXPECTED_CURRENT_EXEC="ExecStart=${CURRENT_BINARY} --port 47895 --token ${TOKEN_REFERENCE}"
EXPECTED_TARGET_EXEC="ExecStart=${TARGET_BINARY} --port 47895 --token ${TOKEN_REFERENCE}"
PUBLIC_SNAPSHOT_URL="http://127.0.0.1:47895/v1/mesh/transports/current"
HEALTH_URL="http://127.0.0.1:47895/health"
GENERATION_21_RAW_SHA256="9779596497e1925415ff85658c0b128bdb6be37c83367da2fe73fb24a9a67926"
BACKUP_ROOT="/var/backups/synergy-testnet"
CHECKPOINT_DIR="/var/lib/synergy-validator-vpn-coordinator"
CHECKPOINT="${CHECKPOINT_DIR}/testnet-v3-pre-correction-v19.0.55-5ceaaba2.complete"

BACKUP_DIR=""
ROLLBACK_REQUIRED=0

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run through sudo as root"
}

require_commands() {
  local command_name
  for command_name in curl sha256sum systemctl install cp mv python3 stat date find mktemp chmod chown grep awk sleep; do
    command -v "${command_name}" >/dev/null 2>&1 || die "required command is missing: ${command_name}"
  done
}

sha256_of() {
  sha256sum "$1" | awk '{print $1}'
}

require_sha256() {
  local path="$1"
  local expected="$2"
  [[ -f "${path}" ]] || die "required file is missing: ${path}"
  [[ "$(sha256_of "${path}")" == "${expected}" ]] || die "checksum mismatch: ${path}"
}

find_enrollment_state() {
  local -a candidates=()
  mapfile -d '' -t candidates < <(
    find /root /home /var/lib /opt/synergy -xdev -type f \
      -path '*/testnet/runtime/innernet/enrollment-state.json' -print0 2>/dev/null
  )
  [[ "${#candidates[@]}" -eq 1 ]] || die "expected exactly one coordinator enrollment state file; found ${#candidates[@]}"
  printf '%s\n' "${candidates[0]}"
}

verify_generation_21_state() {
  local state_path="$1"
  python3 - "${state_path}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    state = json.load(handle)
if state.get("latest_generation") != 21:
    raise SystemExit("coordinator enrollment state is not at generation 21")
if not isinstance(state.get("enrollments"), list) or len(state["enrollments"]) != 9:
    raise SystemExit("coordinator enrollment state does not contain the fresh nine-peer mesh")
if state.get("canonical_validator_address_binding_correction_audit"):
    raise SystemExit("canonical binding correction audit already exists")
PY
}

wait_for_health() {
  local deadline=$((SECONDS + 90))
  until curl --silent --show-error --fail --connect-timeout 2 --max-time 5 "${HEALTH_URL}" >/dev/null; do
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

rollback() {
  local rollback_status=0
  (( ROLLBACK_REQUIRED == 1 )) || return 0
  ROLLBACK_REQUIRED=0
  printf 'Post-switch verification failed; restoring the prior coordinator release.\n' >&2
  [[ -n "${BACKUP_DIR}" && -f "${BACKUP_DIR}/60-release.conf" ]] || {
    printf 'Rollback cannot proceed because the backed-up drop-in is unavailable.\n' >&2
    return 1
  }
  cp -f "${BACKUP_DIR}/60-release.conf" "${DROPIN}" || rollback_status=1
  systemctl daemon-reload || rollback_status=1
  systemctl restart "${SERVICE}" || rollback_status=1
  if ! wait_for_health; then
    rollback_status=1
  fi
  if (( rollback_status == 0 )); then
    printf 'Rollback restored the prior coordinator service.\n' >&2
  else
    printf 'Rollback could not prove prior coordinator health; stop and inspect %s.\n' "${BACKUP_DIR}" >&2
  fi
  return "${rollback_status}"
}

on_exit() {
  local exit_status=$?
  trap - EXIT
  if (( exit_status != 0 && ROLLBACK_REQUIRED == 1 )); then
    rollback || true
  fi
  exit "${exit_status}"
}

main() {
  require_root
  require_commands
  trap on_exit EXIT

  if [[ -e "${CHECKPOINT}" ]]; then
    grep -Fxq "target_binary_sha256=${TARGET_BINARY_SHA256}" "${CHECKPOINT}" \
      || die "an incompatible pre-correction checkpoint already exists"
    printf 'PRE-CORRECTION CHECKPOINT ALREADY COMPLETE\n'
    printf 'Checkpoint: %s\n' "${CHECKPOINT}"
    return 0
  fi

  [[ -d "${CURRENT_RELEASE}" ]] || die "current release directory is missing"
  require_sha256 "${CURRENT_BINARY}" "${CURRENT_BINARY_SHA256}"
  [[ -f "${DROPIN}" ]] || die "current systemd release drop-in is missing"
  grep -Fxq "${EXPECTED_CURRENT_EXEC}" "${DROPIN}" \
    || die "current drop-in does not point at the expected v19.0.54 release"
  require_sha256 "${ARTIFACT}" "${TARGET_BINARY_SHA256}"

  local state_path
  state_path="$(find_enrollment_state)"
  verify_generation_21_state "${state_path}"
  systemctl is-active --quiet "${SERVICE}" || die "coordinator service is not active"
  wait_for_health || die "coordinator health endpoint did not return HTTP 200"

  BACKUP_DIR="${BACKUP_ROOT}/coordinator-pre-correction-$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g root -m 0700 "${BACKUP_DIR}"
  cp -a "${CURRENT_RELEASE}" "${BACKUP_DIR}/current-release"
  cp -a "${DROPIN}" "${BACKUP_DIR}/60-release.conf"
  cp -a "${state_path}" "${BACKUP_DIR}/enrollment-state.before.json"
  curl --silent --show-error --fail --connect-timeout 3 --max-time 10 \
    "${PUBLIC_SNAPSHOT_URL}" -o "${BACKUP_DIR}/public-transport-snapshot.generation-21.before.json"
  [[ "$(sha256_of "${BACKUP_DIR}/public-transport-snapshot.generation-21.before.json")" == "${GENERATION_21_RAW_SHA256}" ]] \
    || die "current public transport snapshot does not match the expected generation-21 raw bytes"
  sha256sum "${CURRENT_BINARY}" "${DROPIN}" "${state_path}" "${ARTIFACT}" \
    "${BACKUP_DIR}/public-transport-snapshot.generation-21.before.json" >"${BACKUP_DIR}/CHECKSUMS.sha256"
  chmod -R go-rwx "${BACKUP_DIR}"

  if [[ -e "${TARGET_RELEASE}" ]]; then
    [[ -d "${TARGET_RELEASE}" ]] || die "target release path exists but is not a directory"
    require_sha256 "${TARGET_BINARY}" "${TARGET_BINARY_SHA256}"
  else
    install -d -o root -g root -m 0755 "${TARGET_RELEASE}"
    install -o root -g root -m 0755 "${ARTIFACT}" "${TARGET_BINARY}"
    require_sha256 "${TARGET_BINARY}" "${TARGET_BINARY_SHA256}"
    {
      printf 'release=v19.0.55-tv3-canonical-binding-correction-5ceaaba2\n'
      printf 'control_service_sha256=%s\n' "${TARGET_BINARY_SHA256}"
    } >"${TARGET_RELEASE}/RELEASE-SHA256"
    chown root:root "${TARGET_RELEASE}/RELEASE-SHA256"
    chmod 0444 "${TARGET_RELEASE}/RELEASE-SHA256"
  fi

  local staged_dropin
  staged_dropin="$(mktemp "${DROPIN_DIR}/.60-release.conf.v19.0.55.XXXXXX")"
  {
    printf '[Service]\n'
    printf 'ExecStart=\n'
    printf '%s\n' "${EXPECTED_TARGET_EXEC}"
  } >"${staged_dropin}"
  chown root:root "${staged_dropin}"
  chmod 0644 "${staged_dropin}"
  mv -f "${staged_dropin}" "${DROPIN}"
  ROLLBACK_REQUIRED=1
  systemctl daemon-reload
  systemctl restart "${SERVICE}"
  wait_for_health

  curl --silent --show-error --fail --connect-timeout 3 --max-time 10 \
    "${PUBLIC_SNAPSHOT_URL}" -o "${BACKUP_DIR}/public-transport-snapshot.generation-21.after-release-switch.json"
  [[ "$(sha256_of "${BACKUP_DIR}/public-transport-snapshot.generation-21.after-release-switch.json")" == "${GENERATION_21_RAW_SHA256}" ]] \
    || die "release switch changed the public generation-21 transport bytes"
  sha256sum "${BACKUP_DIR}/public-transport-snapshot.generation-21.after-release-switch.json" \
    >>"${BACKUP_DIR}/CHECKSUMS.sha256"
  chmod -R go-rwx "${BACKUP_DIR}"

  install -d -o root -g root -m 0700 "${CHECKPOINT_DIR}"
  local staged_checkpoint
  staged_checkpoint="$(mktemp "${CHECKPOINT_DIR}/.testnet-v3-pre-correction.XXXXXX")"
  {
    printf 'release=v19.0.55-tv3-canonical-binding-correction-5ceaaba2\n'
    printf 'target_binary_sha256=%s\n' "${TARGET_BINARY_SHA256}"
    printf 'prior_generation=21\n'
    printf 'prior_public_snapshot_sha256=%s\n' "${GENERATION_21_RAW_SHA256}"
    printf 'backup=%s\n' "${BACKUP_DIR}"
  } >"${staged_checkpoint}"
  chown root:root "${staged_checkpoint}"
  chmod 0600 "${staged_checkpoint}"
  mv -f "${staged_checkpoint}" "${CHECKPOINT}"

  ROLLBACK_REQUIRED=0
  printf 'PRE-CORRECTION CHECKPOINT COMPLETE\n'
  printf 'Backup: %s\n' "${BACKUP_DIR}"
  printf 'Release: %s\n' "${TARGET_RELEASE}"
  printf 'No admin correction endpoint was invoked.\n'
}

main "$@"
