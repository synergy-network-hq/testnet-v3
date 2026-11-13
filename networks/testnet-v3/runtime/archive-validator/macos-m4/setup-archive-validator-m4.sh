#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${PACKAGE_ROOT}/archive-paths.sh"
TEST_ROOT=""
PUBLIC_HOST=""
SNAPSHOT_API_BIND="0.0.0.0:48640"
SKIP_LAUNCHD_LOAD="false"
YES="false"
SERVICE_TIMEOUT_SECS="${ARCHIVE_VALIDATOR_SERVICE_TIMEOUT_SECS:-120}"
archive_paths_load_defaults

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --app-root) ARCHIVE_APP_ROOT="$2"; shift 2 ;;
    --publish-root) ARCHIVE_PUBLISH_ROOT="$2"; shift 2 ;;
    --storage-volume) ARCHIVE_STORAGE_VOLUME="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    --snapshot-api-bind) SNAPSHOT_API_BIND="$2"; shift 2 ;;
    --skip-launchd-load) SKIP_LAUNCHD_LOAD="true"; shift ;;
    --service-timeout) SERVICE_TIMEOUT_SECS="$2"; shift 2 ;;
    --yes) YES="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

archive_paths_validate

[[ "$(uname -s)" == "Darwin" ]] || { echo "The M4 archive installer requires macOS." >&2; exit 1; }
[[ "$(uname -m)" == "arm64" ]] || { echo "The M4 archive installer requires Apple Silicon arm64." >&2; exit 1; }
if [[ -n "${TEST_ROOT}" ]]; then
  mkdir -p "${TEST_ROOT}"
  TEST_ROOT="$(cd "${TEST_ROOT}" && pwd)"
fi
[[ -n "${PUBLIC_HOST}" ]] || { echo "--public-host is required." >&2; exit 1; }

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
}

is_production_install() {
  [[ -z "${TEST_ROOT}" ]]
}

install_dir() {
  local mode="$1"
  shift
  local path
  for path in "$@"; do
    if is_production_install; then
      install -d -o root -g wheel -m "${mode}" "${path}"
    else
      install -d -m "${mode}" "${path}"
    fi
  done
}

install_file() {
  local mode="$1"
  local source="$2"
  local destination="$3"
  if is_production_install; then
    install -o root -g wheel -m "${mode}" "${source}" "${destination}"
  else
    install -m "${mode}" "${source}" "${destination}"
  fi
}

clear_quarantine() {
  command -v xattr >/dev/null 2>&1 || return 0
  for path in "$@"; do
    [[ -e "${path}" ]] || continue
    xattr -dr com.apple.quarantine "${path}" >/dev/null 2>&1 || true
  done
}

adhoc_sign_and_verify() {
  local binary="$1"
  command -v codesign >/dev/null 2>&1 || {
    echo "codesign is required to prepare launchd-safe Archive Validator payloads." >&2
    exit 1
  }
  codesign --force --sign - "${binary}" >/dev/null 2>&1 || {
    echo "failed to ad-hoc sign ${binary}" >&2
    exit 1
  }
  codesign --verify --verbose=2 "${binary}" >/dev/null 2>&1 || {
    echo "failed to verify ad-hoc signature for ${binary}" >&2
    exit 1
  }
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local name="$3"
  local timeout="$4"
  local attempt
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if python3 - "${host}" "${port}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=1.0):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      echo "listener_ok=${name}:${host}:${port}"
      return 0
    fi
    sleep 1
  done
  echo "required listener did not appear: ${name} ${host}:${port}" >&2
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-api.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-worker.err.log" >&2 2>/dev/null || true
  return 1
}

wait_for_qrpc_latest_block() {
  local port="$1"
  local timeout="$2"
  local output="${APP_ROOT}/evidence/archive-validator-qrpc-latest-block.json"
  local attempt
  install_dir 0750 "${APP_ROOT}/evidence"
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if python3 - "${port}" "${output}" <<'PY'
import json
import sys
import urllib.request

port, output = sys.argv[1:3]
payload = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "synergy_getLatestBlock",
    "params": [],
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=2.0) as response:
        value = json.loads(response.read().decode())
except Exception:
    raise SystemExit(1)
if "result" not in value:
    raise SystemExit(1)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    then
      echo "archive_qrpc_latest_block_ok=true"
      echo "archive_qrpc_latest_block_evidence=${output}"
      return 0
    fi
    sleep 1
  done
  echo "archive qRPC did not return synergy_getLatestBlock on 127.0.0.1:${port}" >&2
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  return 1
}

wait_for_launchd_label() {
  local label="$1"
  local timeout="$2"
  local status_file="${APP_ROOT}/evidence/${label}.launchctl.txt"
  local attempt
  install_dir 0750 "${APP_ROOT}/evidence"
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if launchctl print "system/${label}" > "${status_file}" 2>&1 &&
      grep -Eq 'state = running|pid = [0-9]+' "${status_file}"
    then
      echo "launchd_running=${label}"
      return 0
    fi
    sleep 1
  done
  echo "launchd service failed to stay running: ${label}" >&2
  cat "${status_file}" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-api.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-worker.err.log" >&2 2>/dev/null || true
  return 1
}

bootstrap_enable_kickstart_services() {
  local label
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
  local plist
  for plist in \
    io.synergynetwork.archive-validator.plist \
    io.synergynetwork.archive-snapshot-api.plist \
    io.synergynetwork.archive-snapshot-worker.plist
  do
    launchctl bootstrap system "${LAUNCHD_ROOT}/${plist}"
    launchctl enable "system/${plist%.plist}"
    launchctl kickstart -k "system/${plist%.plist}"
  done
  wait_for_launchd_label io.synergynetwork.archive-validator "${SERVICE_TIMEOUT_SECS}"
  wait_for_launchd_label io.synergynetwork.archive-snapshot-api "${SERVICE_TIMEOUT_SECS}"
  wait_for_launchd_label io.synergynetwork.archive-snapshot-worker "${SERVICE_TIMEOUT_SECS}"
}

snapshot_api_port() {
  printf '%s\n' "${SNAPSHOT_API_BIND##*:}"
}

verify_runtime_listeners() {
  local timeout="$1"
  wait_for_tcp 127.0.0.1 5622 archive_p2p "${timeout}"
  wait_for_tcp 127.0.0.1 "$(snapshot_api_port)" snapshot_api "${timeout}"
  wait_for_tcp 127.0.0.1 5640 archive_qrpc "${timeout}"
  wait_for_tcp 127.0.0.1 5660 archive_ws "${timeout}"
  wait_for_tcp 127.0.0.1 6030 archive_metrics "${timeout}"
  wait_for_qrpc_latest_block 5640 "${timeout}"
}

STORAGE_VOLUME="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_STORAGE_VOLUME}")"
if [[ -n "${TEST_ROOT}" ]]; then
  [[ -d "${STORAGE_VOLUME}" ]] || {
    echo "archive storage volume missing in test root: ${STORAGE_VOLUME}" >&2
    exit 1
  }
else
  [[ -d "${STORAGE_VOLUME}" ]] || {
    echo "required archive storage volume is not mounted: ${STORAGE_VOLUME}" >&2
    exit 1
  }
  /sbin/mount | grep -F " on ${STORAGE_VOLUME} " >/dev/null || {
    echo "required archive storage volume is not mounted as a filesystem: ${STORAGE_VOLUME}" >&2
    exit 1
  }
  [[ "$(id -u)" == "0" ]] || { echo "Run the production install with sudo." >&2; exit 1; }
fi

BIN_ROOT="$(prefix_path /usr/local/synergy/bin)"
SHARE_ROOT="$(prefix_path /usr/local/synergy/share/archive-validator)"
APP_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_APP_ROOT}")"
WORKSPACE="${APP_ROOT}/workspace"
LOG_ROOT="${APP_ROOT}/logs"
SMB_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_STORAGE_VOLUME}/archive-validator")"
PUBLISH_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_PUBLISH_ROOT}")"
INCOMING_BOOTSTRAP="${SMB_ROOT}/incoming/bootstrap"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
PROOF_MARKER="${APP_ROOT}/evidence/source-majority-branch-proven.json"
PYTHON3_PATH="$(command -v python3 || true)"

if [[ -z "${TEST_ROOT}" ]]; then
  case "${APP_ROOT}" in
    /Volumes/*)
      echo "runtime root must be local storage, not an SMB/network volume: ${APP_ROOT}" >&2
      exit 1
      ;;
  esac
fi

for dependency in python3 tar shasum plutil codesign; do
  command -v "${dependency}" >/dev/null 2>&1 || {
    echo "Missing required macOS dependency: ${dependency}" >&2
    exit 1
  }
done
[[ -n "${PYTHON3_PATH}" && -x "${PYTHON3_PATH}" ]] || {
  echo "python3 must resolve to an executable absolute path for launchd." >&2
  exit 1
}
if ! command -v zstd >/dev/null 2>&1; then
  if [[ -n "${TEST_ROOT}" ]]; then
    echo "zstd is required for isolated acceptance testing." >&2
    exit 1
  fi
  command -v brew >/dev/null 2>&1 || {
    echo "Homebrew is required to install zstd. Install Homebrew, then rerun this script." >&2
    exit 1
  }
  brew install zstd
fi

if [[ "${YES}" != "true" ]]; then
  read -r -p "Install the Synergy Testnet 1264 Archive Validator on this Apple Silicon Mac? [y/N] " answer
  [[ "${answer}" == "y" || "${answer}" == "Y" ]] || exit 1
fi

clear_quarantine "${PACKAGE_ROOT}"
(cd "${PACKAGE_ROOT}" && shasum -a 256 -c BINARY_SHA256SUMS)
for binary in aegis-pqvm synergy-archive-validator-node; do
  file "${PACKAGE_ROOT}/bin/${binary}" | grep -q 'arm64' || {
    echo "${binary} is not an Apple Silicon arm64 executable." >&2
    exit 1
  }
done

install_dir 0755 "${BIN_ROOT}"
install_dir 0755 "${SHARE_ROOT}"
install_dir 0755 "${LAUNCHD_ROOT}"
install_dir 0750 \
  "${APP_ROOT}/config" \
  "${APP_ROOT}/keys" \
  "${APP_ROOT}/logs" \
  "${APP_ROOT}/evidence" \
  "${APP_ROOT}/tmp" \
  "${APP_ROOT}/backups" \
  "${WORKSPACE}/config" \
  "${WORKSPACE}/data"
install_dir 0750 \
  "${SMB_ROOT}" \
  "${INCOMING_BOOTSTRAP}" \
  "${PUBLISH_ROOT}" \
  "${PUBLISH_ROOT}/staging" \
  "${PUBLISH_ROOT}/failed" \
  "${PUBLISH_ROOT}/retired" \
  "${PUBLISH_ROOT}/testnet-1264"
install_file 0755 "${PACKAGE_ROOT}/bin/aegis-pqvm" "${BIN_ROOT}/aegis-pqvm"
install_file 0755 "${PACKAGE_ROOT}/bin/synergy-archive-validator-node" "${BIN_ROOT}/synergy-archive-validator-node"
install_file 0755 "${PACKAGE_ROOT}/bin/synergy-archive" "${BIN_ROOT}/synergy-archive"
clear_quarantine "${BIN_ROOT}/aegis-pqvm" "${BIN_ROOT}/synergy-archive-validator-node" "${BIN_ROOT}/synergy-archive"
adhoc_sign_and_verify "${BIN_ROOT}/aegis-pqvm"
adhoc_sign_and_verify "${BIN_ROOT}/synergy-archive-validator-node"
adhoc_sign_and_verify "${BIN_ROOT}/synergy-archive"
install_file 0644 "${PACKAGE_ROOT}/BINARY_SHA256SUMS" "${SHARE_ROOT}/BINARY_SHA256SUMS"
(cd "${BIN_ROOT}" && shasum -a 256 aegis-pqvm synergy-archive-validator-node synergy-archive > "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS")
if is_production_install; then
  chown root:wheel "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS"
  chmod 0644 "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS"
fi
install_file 0644 "${PACKAGE_ROOT}/SOURCE-PROVENANCE.json" "${SHARE_ROOT}/SOURCE-PROVENANCE.json"
install_file 0644 "${PACKAGE_ROOT}/config/genesis.json" "${WORKSPACE}/config/genesis.json"
install_file 0644 "${PACKAGE_ROOT}/config/consensus-fork-migration.json" "${WORKSPACE}/config/consensus-fork-migration.json"
install_file 0644 "${PACKAGE_ROOT}/config/consensus-fork-migration.json" "${APP_ROOT}/config/consensus-fork-migration.json"
install_file 0644 "${PACKAGE_ROOT}/config/snapshot-policy.toml" "${APP_ROOT}/config/snapshot-policy.toml"
sed "s/replace-with-public-host/${PUBLIC_HOST}/g" \
  "${PACKAGE_ROOT}/config/node.toml.template" > "${WORKSPACE}/config/node.toml"
chmod 0644 "${WORKSPACE}/config/node.toml"
if is_production_install; then
  chown root:wheel "${WORKSPACE}/config/node.toml"
fi

GENESIS_HASH="$(python3 - "${WORKSPACE}/config/genesis.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["integrity"]["genesis_hash"])
PY
)"
[[ "${GENESIS_HASH}" == "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789" ]] || {
  echo "Packaged genesis hash mismatch." >&2
  exit 1
}

PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/aegis-pqvm" smoke-test >/dev/null
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive-validator-node" version >/dev/null
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive" init \
    --root "${APP_ROOT}" \
    --publish-root "${PUBLISH_ROOT}" \
    --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
    --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null

render_plist() {
  local template="$1"
  local output="$2"
  sed \
    -e "s|__BIN_ROOT__|${BIN_ROOT}|g" \
    -e "s|__APP_ROOT__|${APP_ROOT}|g" \
    -e "s|__WORKSPACE__|${WORKSPACE}|g" \
    -e "s|__LOG_ROOT__|${LOG_ROOT}|g" \
    -e "s|__PUBLISH_ROOT__|${PUBLISH_ROOT}|g" \
    -e "s|__PROOF_MARKER__|${PROOF_MARKER}|g" \
    -e "s|__PYTHON3__|${PYTHON3_PATH}|g" \
    -e "s|__SNAPSHOT_API_BIND__|${SNAPSHOT_API_BIND}|g" \
    -e "s|__STORAGE_VOLUME__|${STORAGE_VOLUME}|g" \
    "${template}" > "${output}"
  chmod 0644 "${output}"
  if is_production_install; then
    chown root:wheel "${output}"
  fi
  clear_quarantine "${output}"
  plutil -lint "${output}" >/dev/null
}

for plist in "${PACKAGE_ROOT}/launchd/"*.plist.in; do
  name="$(basename "${plist%.in}")"
  render_plist "${plist}" "${LAUNCHD_ROOT}/${name}"
done

PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive" status \
    --root "${APP_ROOT}" \
    --publish-root "${PUBLISH_ROOT}" \
    --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
    --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null

if [[ "${SKIP_LAUNCHD_LOAD}" != "true" ]]; then
  bootstrap_enable_kickstart_services
  verify_runtime_listeners "${SERVICE_TIMEOUT_SECS}"
fi

echo "archive_validator_install_ok=true"
echo "runtime_root=${APP_ROOT}"
echo "workspace=${WORKSPACE}"
echo "publish_root=${PUBLISH_ROOT}"
echo "incoming_bootstrap=${INCOMING_BOOTSTRAP}"
echo "majority_proof_marker=${PROOF_MARKER}"
echo "next_action=sync archive node, preserve parity evidence, then run synergy-archive record-majority-proof before worker publication"
