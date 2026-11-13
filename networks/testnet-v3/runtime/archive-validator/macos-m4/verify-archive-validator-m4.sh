#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${PACKAGE_ROOT}/archive-paths.sh"

TEST_ROOT=""
SKIP_LAUNCHD_CHECK="false"
SKIP_LISTENER_CHECK="false"
SERVICE_TIMEOUT_SECS="${ARCHIVE_VALIDATOR_SERVICE_TIMEOUT_SECS:-60}"
P2P_PORT="5622"
QRPC_PORT="5640"
WS_PORT="5660"
METRICS_PORT="6030"
SNAPSHOT_API_BIND="0.0.0.0:48640"
archive_paths_load_defaults
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --app-root) ARCHIVE_APP_ROOT="$2"; shift 2 ;;
    --publish-root) ARCHIVE_PUBLISH_ROOT="$2"; shift 2 ;;
    --storage-volume) ARCHIVE_STORAGE_VOLUME="$2"; shift 2 ;;
    --skip-launchd-check) SKIP_LAUNCHD_CHECK="true"; shift ;;
    --skip-listener-check) SKIP_LISTENER_CHECK="true"; shift ;;
    --service-timeout) SERVICE_TIMEOUT_SECS="$2"; shift 2 ;;
    --p2p-port) P2P_PORT="$2"; shift 2 ;;
    --qrpc-port) QRPC_PORT="$2"; shift 2 ;;
    --ws-port) WS_PORT="$2"; shift 2 ;;
    --metrics-port) METRICS_PORT="$2"; shift 2 ;;
    --snapshot-api-bind) SNAPSHOT_API_BIND="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

archive_paths_validate

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
}

is_production_verify() {
  [[ -z "${TEST_ROOT}" ]]
}

snapshot_api_port() {
  printf '%s\n' "${SNAPSHOT_API_BIND##*:}"
}

install_evidence_dir() {
  install -d -m 0750 "${APP_ROOT}/evidence"
}

assert_stat() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(stat -f '%Su:%Sg %Lp' "${path}")"
  [[ "${actual}" == "${expected}" ]] || {
    echo "incorrect ownership/permissions for ${path}: actual=${actual} expected=${expected}" >&2
    exit 1
  }
}

assert_no_quarantine() {
  command -v xattr >/dev/null 2>&1 || return 0
  local path="$1"
  if xattr -p com.apple.quarantine "${path}" >/dev/null 2>&1; then
    echo "quarantine attribute still present on ${path}" >&2
    exit 1
  fi
}

assert_codesign_valid() {
  command -v codesign >/dev/null 2>&1 || {
    echo "codesign is required for Archive Validator launchd payload verification." >&2
    exit 1
  }
  local path="$1"
  codesign --verify --verbose=2 "${path}" >/dev/null 2>&1 || {
    echo "codesign verification failed for ${path}" >&2
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
  echo "required listener unavailable: ${name} ${host}:${port}" >&2
  return 1
}

wait_for_qrpc_latest_block() {
  local port="$1"
  local timeout="$2"
  local output="${APP_ROOT}/evidence/archive-validator-verify-qrpc-latest-block.json"
  local attempt
  install_evidence_dir
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
  return 1
}

assert_launchd_running() {
  local label="$1"
  local status_file="${APP_ROOT}/evidence/${label}.verify.launchctl.txt"
  install_evidence_dir
  launchctl print "system/${label}" > "${status_file}" 2>&1 || {
    echo "launchd service is not loaded: ${label}" >&2
    cat "${status_file}" >&2 2>/dev/null || true
    exit 1
  }
  if ! grep -Eq 'state = running|pid = [0-9]+' "${status_file}"; then
    echo "launchd service is not running: ${label}" >&2
    cat "${status_file}" >&2 2>/dev/null || true
    exit 1
  fi
  echo "launchd_running=${label}"
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
fi

BIN_ROOT="$(prefix_path /usr/local/synergy/bin)"
SHARE_ROOT="$(prefix_path /usr/local/synergy/share/archive-validator)"
APP_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_APP_ROOT}")"
SMB_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_STORAGE_VOLUME}/archive-validator")"
PUBLISH_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_PUBLISH_ROOT}")"
INCOMING_BOOTSTRAP="${SMB_ROOT}/incoming/bootstrap"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
FORBIDDEN_APP_ROOT="$(prefix_path "/Library/Application Support/Synergy/archive""-validator")"
FORBIDDEN_PUBLISH_ROOT="$(prefix_path "/srv/synergy""-snapshots")"

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]
if [[ -z "${TEST_ROOT}" ]]; then
  case "${APP_ROOT}" in
    /Volumes/*)
      echo "runtime root must be local storage, not an SMB/network volume: ${APP_ROOT}" >&2
      exit 1
      ;;
  esac
fi
[[ -d "${APP_ROOT}" ]] || { echo "archive runtime root missing: ${APP_ROOT}" >&2; exit 1; }
[[ -d "${APP_ROOT}/workspace/data" ]] || { echo "archive workspace data root missing: ${APP_ROOT}/workspace/data" >&2; exit 1; }
[[ -d "${APP_ROOT}/logs" ]] || { echo "archive log root missing: ${APP_ROOT}/logs" >&2; exit 1; }
[[ -d "${APP_ROOT}/tmp" ]] || { echo "archive tmp root missing: ${APP_ROOT}/tmp" >&2; exit 1; }
[[ -d "${APP_ROOT}/evidence" ]] || { echo "archive evidence root missing: ${APP_ROOT}/evidence" >&2; exit 1; }
[[ -f "${APP_ROOT}/config/consensus-fork-migration.json" ]] || { echo "archive fork metadata missing: ${APP_ROOT}/config/consensus-fork-migration.json" >&2; exit 1; }
[[ -f "${APP_ROOT}/workspace/config/consensus-fork-migration.json" ]] || { echo "runtime fork metadata missing: ${APP_ROOT}/workspace/config/consensus-fork-migration.json" >&2; exit 1; }
python3 - "${APP_ROOT}/config/consensus-fork-migration.json" "${APP_ROOT}/workspace/config/consensus-fork-migration.json" <<'PY'
import base64
import json
import sys

expected_parent = "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816"
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    checks = {
        "fork_height": value.get("fork_height") == 204216,
        "parent_height": value.get("parent_height") == 204215,
        "parent_hash": value.get("parent_hash") == expected_parent,
        "new_consensus_algorithm": value.get("new_consensus_algorithm") == "FN-DSA",
        "parser_mode": value.get("parser_mode") == "fail_closed",
    }
    registry = value.get("new_validator_registry") or []
    declared_validator_count = value.get("validator_count")
    validator_addresses = [item.get("validator_address") for item in registry]
    checks["validator_count"] = (
        len(registry) >= 1
        and (declared_validator_count in (None, len(registry)))
        and len(set(validator_addresses)) == len(registry)
        and all(validator_addresses)
    )
    checks["all_validator_keys_fndsa"] = all(
        item.get("consensus_key_type") == "FN-DSA"
        and len(base64.b64decode(item.get("consensus_public_key", ""), validate=True)) == 1793
        for item in registry
    )
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise SystemExit(f"invalid archive consensus fork metadata {path}: {failed}")
print("archive_consensus_fork_metadata_ok=true")
PY
[[ -d "${SMB_ROOT}" ]] || { echo "archive SMB root missing: ${SMB_ROOT}" >&2; exit 1; }
[[ -d "${PUBLISH_ROOT}" ]] || { echo "archive snapshot root missing: ${PUBLISH_ROOT}" >&2; exit 1; }
[[ -d "${INCOMING_BOOTSTRAP}" ]] || { echo "archive bootstrap staging root missing: ${INCOMING_BOOTSTRAP}" >&2; exit 1; }
[[ ! -e "${FORBIDDEN_APP_ROOT}" ]] || {
  echo "forbidden archive storage path exists: ${FORBIDDEN_APP_ROOT}" >&2
  exit 1
}
[[ ! -e "${FORBIDDEN_PUBLISH_ROOT}" ]] || {
  echo "forbidden archive snapshot path exists: ${FORBIDDEN_PUBLISH_ROOT}" >&2
  exit 1
}
for binary in aegis-pqvm synergy-archive-validator-node synergy-archive; do
  [[ -x "${BIN_ROOT}/${binary}" ]]
  assert_no_quarantine "${BIN_ROOT}/${binary}"
  assert_codesign_valid "${BIN_ROOT}/${binary}"
  if is_production_verify; then
    assert_stat "${BIN_ROOT}/${binary}" "root:wheel 755"
  fi
done
(cd "${BIN_ROOT}" && shasum -a 256 -c "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS")
"${BIN_ROOT}/aegis-pqvm" smoke-test >/dev/null
"${BIN_ROOT}/synergy-archive-validator-node" version | grep -q 'Archive Validator Node'
"${BIN_ROOT}/synergy-archive" status \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null
for plist in "${LAUNCHD_ROOT}"/io.synergynetwork.archive-*.plist; do
  plutil -lint "${plist}" >/dev/null
  assert_no_quarantine "${plist}"
  if is_production_verify; then
    assert_stat "${plist}" "root:wheel 644"
  fi
done
python3 - "${LAUNCHD_ROOT}/io.synergynetwork.archive-snapshot-worker.plist" <<'PY'
import plistlib
import sys

path = sys.argv[1]
with open(path, "rb") as fh:
    plist = plistlib.load(fh)
args = plist.get("ProgramArguments") or []
if "worker" not in args:
    raise SystemExit(f"{path} must run the class-aware synergy-archive worker command")
if "--snapshot-class" in args:
    raise SystemExit(
        f"{path} must omit --snapshot-class so unattended worker mode publishes the current scheduled snapshot classes"
    )
required = {"--workspace", "--majority-proof-marker", "--publish-root", "--runtime", "--aegis"}
missing = sorted(required.difference(args))
if missing:
    raise SystemExit(f"{path} is missing required worker arguments: {missing}")
print("archive_snapshot_worker_current_classes_default_ok=true")
PY
if [[ "${SKIP_LAUNCHD_CHECK}" != "true" ]]; then
  for label in \
    io.synergynetwork.archive-validator \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-snapshot-worker
  do
    assert_launchd_running "${label}"
  done
fi
if [[ "${SKIP_LISTENER_CHECK}" != "true" ]]; then
  wait_for_tcp 127.0.0.1 "${P2P_PORT}" archive_p2p "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "$(snapshot_api_port)" snapshot_api "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${QRPC_PORT}" archive_qrpc "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${WS_PORT}" archive_ws "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${METRICS_PORT}" archive_metrics "${SERVICE_TIMEOUT_SECS}"
  wait_for_qrpc_latest_block "${QRPC_PORT}" "${SERVICE_TIMEOUT_SECS}"
fi
echo "archive_validator_verify_ok=true"
