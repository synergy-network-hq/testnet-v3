#!/usr/bin/env bash
#
# One-shot Testnet-v3 coordinator repair.  It can run only after the separate
# v19.0.55 pre-correction checkpoint.  This script makes exactly one authenticated
# POST to the narrowly scoped correction endpoint; no peer, route, key, release,
# or service setting is an input to or a side effect of this script.

set -Eeuo pipefail
umask 077

SERVICE="synergy-validator-vpn-coordinator.service"
RELEASE_ROOT="/opt/synergy/synergy-node-control-panel-coordinator/releases"
TARGET_RELEASE="${RELEASE_ROOT}/v19.0.55-tv3-canonical-binding-correction-5ceaaba2"
TARGET_BINARY="${TARGET_RELEASE}/control-service"
TARGET_BINARY_SHA256="5ceaaba2a24bace5064b4c26d792840a218034c7ad2236cd4c3b8774a2e74374"
DROPIN="/etc/systemd/system/${SERVICE}.d/60-release.conf"
TOKEN_REFERENCE='${SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN}'
EXPECTED_TARGET_EXEC="ExecStart=${TARGET_BINARY} --port 47895 --token ${TOKEN_REFERENCE}"
TOKEN_ENV_FILE="/etc/synergy/validator-vpn-coordinator.env"
HEALTH_URL="http://127.0.0.1:47895/health"
PUBLIC_SNAPSHOT_URL="http://127.0.0.1:47895/v1/mesh/transports/current"
CORRECTION_URL="http://127.0.0.1:47895/v1/migration/bootstrap/correct-canonical-validator-address-bindings"
GENERATION_21_RAW_SHA256="9779596497e1925415ff85658c0b128bdb6be37c83367da2fe73fb24a9a67926"
APPLIED_GENESIS_SHA256="ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf"
APPLIED_GENESIS_HASH="c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d"
CANONICAL_BINDINGS_SHA256="602abed04b0e17cfbe3d9720737b851d9cf9d5235393285a7271b2f7e8ecc80e"
ACTOR="testnet-v3-release-operator"
REASON="Correct the signed generation-21 public transport registry to the immutable Testnet-v3 canonical validator-address bindings."
BACKUP_ROOT="/var/backups/synergy-testnet"
CHECKPOINT="/var/lib/synergy-validator-vpn-coordinator/testnet-v3-pre-correction-v19.0.55-5ceaaba2.complete"
PUBLIC_OUTPUT="/tmp/testnet-v3-validator-transport-snapshot-generation-22.json"

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run through sudo as root"
}

require_commands() {
  local command_name
  for command_name in curl sha256sum systemctl install cp mv python3 stat date find chmod chown grep awk sleep cat; do
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
  local deadline=$((SECONDS + 30))
  until curl --silent --show-error --fail --connect-timeout 2 --max-time 5 "${HEALTH_URL}" >/dev/null; do
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
}

read_token_to_stdout() {
  python3 - "${TOKEN_ENV_FILE}" <<'PY'
import sys

token_name = "SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN"
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    for raw_line in handle:
        if raw_line.startswith(token_name + "="):
            token = raw_line.split("=", 1)[1].rstrip("\r\n")
            if not token:
                raise SystemExit("coordinator token is empty")
            sys.stdout.write(token + "\n")
            break
    else:
        raise SystemExit("coordinator token is missing")
PY
}

post_correction_once() {
  local request_path="$1"
  local response_path="$2"
  # The token reaches Python only over stdin: it is never printed, exported,
  # written to disk, or supplied in a process argument.
  read_token_to_stdout | python3 -c '
import json
import pathlib
import sys
import urllib.error
import urllib.request

request_path = pathlib.Path(sys.argv[1])
response_path = pathlib.Path(sys.argv[2])
token = sys.stdin.buffer.readline().rstrip(b"\r\n").decode("utf-8")
if not token:
    raise SystemExit("coordinator token stream was empty")
body = request_path.read_bytes()
request = urllib.request.Request(
    "http://127.0.0.1:47895/v1/migration/bootstrap/correct-canonical-validator-address-bindings",
    data=body,
    method="POST",
    headers={"Content-Type": "application/json", "X-Admin-Key": token},
)
try:
    with urllib.request.urlopen(request, timeout=30) as handle:
        status = handle.status
        payload = handle.read()
except urllib.error.HTTPError as error:
    status = error.code
    payload = error.read()
except Exception as error:
    response_path.write_text(json.dumps({"transport_error": str(error)}) + "\n", encoding="utf-8")
    raise SystemExit(2)
response_path.write_bytes(payload)
if status != 200:
    raise SystemExit(1)
' "${request_path}" "${response_path}"
}

verify_correction_evidence() {
  local before_state="$1"
  local after_state="$2"
  local response_path="$3"
  local after_snapshot="$4"
  python3 - "${before_state}" "${after_state}" "${response_path}" "${after_snapshot}" \
    "${APPLIED_GENESIS_SHA256}" "${APPLIED_GENESIS_HASH}" "${CANONICAL_BINDINGS_SHA256}" \
    "${GENERATION_21_RAW_SHA256}" <<'PY'
import json
import sys

before_path, after_path, response_path, snapshot_path, genesis_sha, genesis_hash, bindings_sha, prior_sha = sys.argv[1:]
with open(before_path, "r", encoding="utf-8") as handle:
    before = json.load(handle)
with open(after_path, "r", encoding="utf-8") as handle:
    after = json.load(handle)
with open(response_path, "r", encoding="utf-8") as handle:
    response = json.load(handle)
with open(snapshot_path, "r", encoding="utf-8") as handle:
    snapshot = json.load(handle)

if before.get("latest_generation") != 21 or after.get("latest_generation") != 22:
    raise SystemExit("state does not prove the required 21 to 22 transition")
for key, expected in {
    "applied_genesis_sha256": genesis_sha,
    "applied_genesis_hash": genesis_hash,
    "canonical_validator_bindings_sha256": bindings_sha,
    "prior_snapshot_sha256": prior_sha,
}.items():
    if response.get(key) != expected:
        raise SystemExit(f"correction response anchor mismatch: {key}")
if response.get("previous_generation") != 21 or response.get("effective_generation") != 22:
    raise SystemExit("correction response does not prove generation 21 to 22")
changes = response.get("corrected_bindings")
if not isinstance(changes, list) or {entry.get("peer_name") for entry in changes} != {
    "validator-1", "validator-2", "validator-3", "validator-4", "validator-5", "validator-6"
}:
    raise SystemExit("correction response does not prove exactly the six fixed validator bindings")
audits = after.get("canonical_validator_address_binding_correction_audit")
if not isinstance(audits, list) or len(audits) != 1:
    raise SystemExit("state does not contain exactly one correction audit record")
audit = audits[0]
for key, expected in {
    "applied_genesis_sha256": genesis_sha,
    "applied_genesis_hash": genesis_hash,
    "canonical_validator_bindings_sha256": bindings_sha,
    "prior_snapshot_sha256": prior_sha,
    "previous_generation": 21,
    "effective_generation": 22,
}.items():
    if audit.get(key) != expected:
        raise SystemExit(f"correction audit mismatch: {key}")
if snapshot.get("configuration_version") != 22:
    raise SystemExit("public signed transport snapshot is not generation 22")
if not isinstance(snapshot.get("transports"), list) or len(snapshot["transports"]) != 6:
    raise SystemExit("public signed transport snapshot does not contain exactly six validators")
PY
}

main() {
  require_root
  require_commands
  [[ -f "${CHECKPOINT}" ]] || die "pre-correction checkpoint is missing; run the reversible v19.0.55 pre-correction script first"
  [[ "$(stat -c '%U:%G:%a' "${CHECKPOINT}")" == "root:root:600" ]] \
    || die "pre-correction checkpoint does not have the required root-only ownership and mode"
  grep -Fxq 'release=v19.0.55-tv3-canonical-binding-correction-5ceaaba2' "${CHECKPOINT}" \
    || die "pre-correction checkpoint does not bind the expected release name"
  grep -Fxq "target_binary_sha256=${TARGET_BINARY_SHA256}" "${CHECKPOINT}" \
    || die "pre-correction checkpoint does not bind the expected v19.0.55 binary"
  grep -Fxq 'prior_generation=21' "${CHECKPOINT}" \
    || die "pre-correction checkpoint does not prove the generation-21 gate"
  grep -Fxq "prior_public_snapshot_sha256=${GENERATION_21_RAW_SHA256}" "${CHECKPOINT}" \
    || die "pre-correction checkpoint does not bind the expected generation-21 snapshot"
  require_sha256 "${TARGET_BINARY}" "${TARGET_BINARY_SHA256}"
  [[ -f "${DROPIN}" ]] || die "systemd release drop-in is missing"
  grep -Fxq "${EXPECTED_TARGET_EXEC}" "${DROPIN}" \
    || die "coordinator is not pinned to the successful v19.0.55 pre-correction release"
  [[ -f "${TOKEN_ENV_FILE}" ]] || die "coordinator token environment file is missing"
  [[ ! -e "${PUBLIC_OUTPUT}" ]] || die "refusing to overwrite an existing generation-22 public snapshot: ${PUBLIC_OUTPUT}"
  systemctl is-active --quiet "${SERVICE}" || die "coordinator service is not active"
  wait_for_health || die "coordinator health endpoint did not return HTTP 200"

  local state_path
  state_path="$(find_enrollment_state)"
  verify_generation_21_state "${state_path}"

  local backup_dir
  backup_dir="${BACKUP_ROOT}/coordinator-canonical-binding-correction-21-to-22-$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g root -m 0700 "${backup_dir}"
  cp -a "${state_path}" "${backup_dir}/enrollment-state.before.json"
  curl --silent --show-error --fail --connect-timeout 3 --max-time 10 \
    "${PUBLIC_SNAPSHOT_URL}" -o "${backup_dir}/public-transport-snapshot.generation-21.before.json"
  [[ "$(sha256_of "${backup_dir}/public-transport-snapshot.generation-21.before.json")" == "${GENERATION_21_RAW_SHA256}" ]] \
    || die "current public transport snapshot does not match the expected generation-21 raw bytes"

  cat >"${backup_dir}/correction-request.json" <<JSON
{
  "applied_genesis_sha256": "${APPLIED_GENESIS_SHA256}",
  "applied_genesis_hash": "${APPLIED_GENESIS_HASH}",
  "canonical_validator_bindings_sha256": "${CANONICAL_BINDINGS_SHA256}",
  "prior_snapshot_sha256": "${GENERATION_21_RAW_SHA256}",
  "actor": "${ACTOR}",
  "reason": "${REASON}"
}
JSON
  chmod 0600 "${backup_dir}/correction-request.json"

  local post_rc=0
  if ! post_correction_once "${backup_dir}/correction-request.json" "${backup_dir}/release-action-response.json"; then
    post_rc=1
  fi
  chmod 0600 "${backup_dir}/release-action-response.json" 2>/dev/null || true

  cp -a "${state_path}" "${backup_dir}/enrollment-state.after.json"
  local snapshot_rc=0
  if ! curl --silent --show-error --fail --connect-timeout 3 --max-time 10 \
    "${PUBLIC_SNAPSHOT_URL}" -o "${backup_dir}/public-transport-snapshot.after.json"; then
    snapshot_rc=1
    printf 'public transport snapshot fetch failed after the one-shot request\n' >"${backup_dir}/public-transport-snapshot.after.error.txt"
  fi
  sha256sum "${backup_dir}"/* >"${backup_dir}/CHECKSUMS.sha256"
  chmod -R go-rwx "${backup_dir}"

  (( post_rc == 0 )) || die "the one-shot correction endpoint returned an error; no retry was attempted; inspect ${backup_dir}"
  (( snapshot_rc == 0 )) || die "the one-shot correction endpoint returned success but the public snapshot could not be fetched; inspect ${backup_dir}"
  verify_correction_evidence \
    "${backup_dir}/enrollment-state.before.json" \
    "${backup_dir}/enrollment-state.after.json" \
    "${backup_dir}/release-action-response.json" \
    "${backup_dir}/public-transport-snapshot.after.json"
  [[ "$(sha256_of "${backup_dir}/public-transport-snapshot.after.json")" != "${GENERATION_21_RAW_SHA256}" ]] \
    || die "generation-22 public snapshot unexpectedly has the prior generation-21 raw bytes"
  install -o devpup -g devpup -m 0644 \
    "${backup_dir}/public-transport-snapshot.after.json" "${PUBLIC_OUTPUT}"

  printf 'CANONICAL VALIDATOR ADDRESS CORRECTION COMPLETE\n'
  printf 'Evidence: %s\n' "${backup_dir}"
  printf 'Public snapshot: %s\n' "${PUBLIC_OUTPUT}"
  sha256sum "${backup_dir}/release-action-response.json" \
    "${backup_dir}/enrollment-state.before.json" \
    "${backup_dir}/enrollment-state.after.json" \
    "${backup_dir}/public-transport-snapshot.generation-21.before.json" \
    "${backup_dir}/public-transport-snapshot.after.json" \
    "${PUBLIC_OUTPUT}"
}

main "$@"
