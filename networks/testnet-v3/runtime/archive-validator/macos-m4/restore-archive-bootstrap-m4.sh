#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${PACKAGE_ROOT}/archive-paths.sh"

SNAPSHOT=""
EXPECTED_SHA256=""
BOOTSTRAP_MANIFEST=""
TEST_ROOT=""
YES="false"
ALLOW_VALIDATOR_PRUNED_BOOTSTRAP="false"
SERVICE_TIMEOUT_SECS="${ARCHIVE_VALIDATOR_RESTORE_TIMEOUT_SECS:-180}"
archive_paths_load_defaults

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --sha256) EXPECTED_SHA256="$2"; shift 2 ;;
    --manifest) BOOTSTRAP_MANIFEST="$2"; shift 2 ;;
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --app-root) ARCHIVE_APP_ROOT="$2"; shift 2 ;;
    --publish-root) ARCHIVE_PUBLISH_ROOT="$2"; shift 2 ;;
    --storage-volume) ARCHIVE_STORAGE_VOLUME="$2"; shift 2 ;;
    --service-timeout) SERVICE_TIMEOUT_SECS="$2"; shift 2 ;;
    --allow-validator-pruned-bootstrap) ALLOW_VALIDATOR_PRUNED_BOOTSTRAP="true"; shift ;;
    --yes) YES="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

archive_paths_validate

[[ "$(uname -s)" == "Darwin" ]] || { echo "Archive bootstrap restore requires macOS." >&2; exit 1; }
[[ -n "${SNAPSHOT}" && -f "${SNAPSHOT}" ]] || { echo "--snapshot must point to a bootstrap .tar.zst or .tar file." >&2; exit 1; }
[[ -n "${EXPECTED_SHA256}" ]] || { echo "--sha256 is required." >&2; exit 1; }
if [[ -n "${TEST_ROOT}" ]]; then
  mkdir -p "${TEST_ROOT}"
  TEST_ROOT="$(cd "${TEST_ROOT}" && pwd)"
fi

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
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
  [[ "$(id -u)" == "0" ]] || { echo "Run production restore with sudo." >&2; exit 1; }
fi

APP_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_APP_ROOT}")"
WORKSPACE="${APP_ROOT}/workspace"
DATA_DIR="${WORKSPACE}/data"
BACKUP_ROOT="${APP_ROOT}/backups"
LOG_ROOT="${APP_ROOT}/logs"
SMB_ROOT="$(archive_paths_prefix "${TEST_ROOT}" "${ARCHIVE_STORAGE_VOLUME}/archive-validator")"
INCOMING_BOOTSTRAP="${SMB_ROOT}/incoming/bootstrap"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
MANAGE_LAUNCHD="true"
if [[ -n "${TEST_ROOT}" || "${SKIP_LAUNCHD_STOP:-false}" == "true" ]]; then
  MANAGE_LAUNCHD="false"
fi

install_dir() {
  local mode="$1"
  shift
  local path
  for path in "$@"; do
    if [[ -z "${TEST_ROOT}" ]]; then
      install -d -o root -g wheel -m "${mode}" "${path}"
    else
      install -d -m "${mode}" "${path}"
    fi
  done
}

wait_for_launchd_label() {
  local label="$1"
  local timeout="$2"
  local status_file="${APP_ROOT}/evidence/${label}.restore.launchctl.txt"
  install_dir 0750 "${APP_ROOT}/evidence"
  local attempt
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if launchctl print "system/${label}" > "${status_file}" 2>&1 &&
      grep -Eq 'state = running|pid = [0-9]+' "${status_file}"
    then
      echo "launchd_running=${label}"
      return 0
    fi
    sleep 1
  done
  echo "launchd service failed to stay running after restore: ${label}" >&2
  cat "${status_file}" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-api.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-worker.err.log" >&2 2>/dev/null || true
  return 1
}

restart_launchd_services() {
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

wait_for_qrpc_latest_block() {
  local output="${APP_ROOT}/evidence/archive-bootstrap-restore-qrpc-latest-block.json"
  install_dir 0750 "${APP_ROOT}/evidence"
  local attempt
  for ((attempt = 1; attempt <= SERVICE_TIMEOUT_SECS; attempt++)); do
    if python3 - "${output}" <<'PY'
import json
import sys
import urllib.request

output = sys.argv[1]
payload = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "synergy_getLatestBlock",
    "params": [],
}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:5640/",
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
  echo "archive qRPC did not return synergy_getLatestBlock after bootstrap restore" >&2
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  return 1
}

validate_bootstrap_payload() {
  local extract_root="$1"
  local restore_source="$2"
  local report="$3"
  install_dir 0750 "${APP_ROOT}/evidence"
  python3 - \
    "${extract_root}" \
    "${restore_source}" \
    "${BOOTSTRAP_MANIFEST}" \
    "${ALLOW_VALIDATOR_PRUNED_BOOTSTRAP}" \
    "${report}" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

extract_root = Path(sys.argv[1])
restore_source = Path(sys.argv[2])
explicit_manifest = sys.argv[3].strip()
allow_validator_pruned = sys.argv[4] == "true"
report_path = Path(sys.argv[5])

EXPECTED = {
    "chain_id": 1264,
    "network_id": "synergy-testnet-v3",
    "fork_height": 204216,
    "fork_parent_height": 204215,
    "fork_parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
    "consensus_algorithm": "FN-DSA",
    "parser_mode": "fail_closed",
}
REQUIRED_DATA = {
    "chain.json",
    "canonical_locks.json",
    "committed_qcs.json",
    "committed_qcs.jsonl",
    "dag_state.json",
    "validator_registry.json",
    "token_state.json",
}
OPTIONAL_DATA = {
    "account_state.json",
    "state_checkpoint.json",
    "committed_blocks.jsonl",
    "canonical_locks.jsonl",
}


def fail(message, **extra):
    payload = {"ok": False, "error": message, **extra}
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(message)


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_class(value):
    value = (value or "").strip().lower().replace("_", "-")
    if value == "archive-validator-bootstrap":
        return "archive-bootstrap"
    return value


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"unable to parse bootstrap manifest {path}: {exc}")


manifest_candidates = []
if explicit_manifest:
    manifest_candidates.append(Path(explicit_manifest))
manifest_candidates.extend([
    extract_root / "metadata" / "archive-bootstrap-manifest.json",
    extract_root / "archive-bootstrap-manifest.json",
])
manifest_candidates.extend(sorted(extract_root.glob("**/snapshot-*-manifest.json")))
manifest_path = next((path for path in manifest_candidates if path.is_file()), None)
if manifest_path is None:
    fail("bootstrap artifact has no archive bootstrap or signed snapshot manifest")

raw = load_json(manifest_path)
signed_manifest = raw.get("manifest") if isinstance(raw, dict) else None
manifest = signed_manifest if isinstance(signed_manifest, dict) else raw
artifact_class = normalize_class(
    manifest.get("artifact_class") or manifest.get("snapshot_class") or raw.get("artifact_class")
)

if artifact_class == "validator-pruned" and not allow_validator_pruned:
    fail("validator-pruned bootstrap is rejected for Archive Validator restore")
if artifact_class not in {"archive-full", "archive-bootstrap"}:
    fail(f"unsupported Archive Validator bootstrap class: {artifact_class}")

chain_id = manifest.get("chain_id")
network_id = manifest.get("network_id")
if chain_id != EXPECTED["chain_id"]:
    fail(f"bootstrap chain_id mismatch: {chain_id}")
if network_id != EXPECTED["network_id"]:
    fail(f"bootstrap network_id mismatch: {network_id}")

fork = manifest.get("consensus_fork") if isinstance(manifest.get("consensus_fork"), dict) else manifest
fork_height = fork.get("fork_height")
parent_height = fork.get("parent_height") or fork.get("fork_parent_height")
parent_hash = fork.get("parent_hash") or fork.get("fork_parent_hash")
new_algorithm = fork.get("new_consensus_algorithm") or manifest.get("consensus_algorithm")
parser_mode = fork.get("parser_mode") or manifest.get("parser_mode")
if fork_height != EXPECTED["fork_height"]:
    fail(f"bootstrap fork_height mismatch: {fork_height}")
if parent_height != EXPECTED["fork_parent_height"]:
    fail(f"bootstrap fork parent height mismatch: {parent_height}")
if parent_hash != EXPECTED["fork_parent_hash"]:
    fail(f"bootstrap fork parent hash mismatch: {parent_hash}")
if new_algorithm != EXPECTED["consensus_algorithm"]:
    fail(f"bootstrap consensus algorithm mismatch: {new_algorithm}")
if parser_mode != EXPECTED["parser_mode"]:
    fail(f"bootstrap parser mode mismatch: {parser_mode}")

if artifact_class == "archive-bootstrap":
    if manifest.get("historical_archive_complete_from_genesis") is not False:
        fail("archive-bootstrap must declare historical_archive_complete_from_genesis=false")

for name in REQUIRED_DATA:
    if not (restore_source / name).is_file():
        fail(f"bootstrap missing required state file: {name}")

file_entries = manifest.get("files") if isinstance(manifest.get("files"), list) else []
verified_files = []
for entry in file_entries:
    rel = entry.get("relative_path") or entry.get("path")
    expected = entry.get("sha256")
    if not rel or not expected:
        continue
    rel_path = Path(rel)
    if rel_path.is_absolute() or ".." in rel_path.parts:
        fail(f"bootstrap manifest has unsafe file path: {rel}")
    candidates = [extract_root / rel_path, restore_source / rel_path.name]
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        fail(f"bootstrap manifest file is missing: {rel}")
    actual = sha256(path)
    if actual != expected:
        fail(f"bootstrap manifest checksum mismatch for {rel}", actual=actual, expected=expected)
    verified_files.append(rel)

payload = {
    "ok": True,
    "artifact_class": artifact_class,
    "target_role": "archive_validator",
    "manifest_path": str(manifest_path),
    "chain_id": chain_id,
    "network_id": network_id,
    "height": manifest.get("height") or manifest.get("snapshot_height"),
    "hash": manifest.get("hash") or manifest.get("snapshot_block_hash"),
    "fork_height": fork_height,
    "fork_parent_height": parent_height,
    "fork_parent_hash": parent_hash,
    "consensus_algorithm": new_algorithm,
    "parser_mode": parser_mode,
    "historical_archive_complete_from_genesis": bool(
        manifest.get("historical_archive_complete_from_genesis")
    ),
    "required_data_files": sorted(REQUIRED_DATA),
    "optional_data_files_present": sorted(name for name in OPTIONAL_DATA if (restore_source / name).is_file()),
    "verified_manifest_files": verified_files,
}
report_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

if [[ -z "${TEST_ROOT}" ]]; then
  case "${APP_ROOT}" in
    /Volumes/*)
      echo "runtime root must be local storage, not an SMB/network volume: ${APP_ROOT}" >&2
      exit 1
      ;;
  esac
fi

install_dir 0750 "${APP_ROOT}" "${APP_ROOT}/tmp" "${SMB_ROOT}" "${INCOMING_BOOTSTRAP}"
app_root_real="$(cd "${APP_ROOT}" && pwd -P)"
bootstrap_root_real="$(cd "${INCOMING_BOOTSTRAP}" && pwd -P)"
snapshot_dir="$(cd "$(dirname "${SNAPSHOT}")" && pwd -P)"
snapshot_real="${snapshot_dir}/$(basename "${SNAPSHOT}")"
case "${snapshot_real}" in
  "${bootstrap_root_real}"/*) ;;
  *)
    echo "--snapshot must be staged under ${INCOMING_BOOTSTRAP}" >&2
    exit 1
    ;;
esac

actual_sha="$(shasum -a 256 "${SNAPSHOT}" | awk '{print $1}')"
[[ "${actual_sha}" == "${EXPECTED_SHA256}" ]] || {
  echo "bootstrap snapshot checksum mismatch: actual=${actual_sha} expected=${EXPECTED_SHA256}" >&2
  exit 1
}

if [[ "${YES}" != "true" ]]; then
  read -r -p "Stop Archive Validator, replace workspace data from ${SNAPSHOT}, and restart? [y/N] " answer
  [[ "${answer}" == "y" || "${answer}" == "Y" ]] || exit 1
fi

extract_root="$(mktemp -d "${APP_ROOT}/tmp/synergy-archive-bootstrap.XXXXXX")"
cleanup() {
  rm -rf "${extract_root}"
}
trap cleanup EXIT

case "${SNAPSHOT}" in
  *.tar.zst|*.tzst)
    command -v zstd >/dev/null 2>&1 || { echo "zstd is required to restore ${SNAPSHOT}." >&2; exit 1; }
    zstd -dc "${SNAPSHOT}" | tar -xf - -C "${extract_root}"
    ;;
  *.tar)
    tar -xf "${SNAPSHOT}" -C "${extract_root}"
    ;;
  *)
    echo "unsupported bootstrap archive extension: ${SNAPSHOT}" >&2
    exit 1
    ;;
esac

if [[ -d "${extract_root}/data" ]]; then
  RESTORE_SOURCE="${extract_root}/data"
elif [[ -d "${extract_root}/workspace/data" ]]; then
  RESTORE_SOURCE="${extract_root}/workspace/data"
else
  RESTORE_SOURCE="${extract_root}"
fi

bootstrap_validation_report="${APP_ROOT}/evidence/archive-bootstrap-restore-validation.json"
validate_bootstrap_payload "${extract_root}" "${RESTORE_SOURCE}" "${bootstrap_validation_report}"

for forbidden in keys key.pem private.pem node.env .env genesis.json config.toml node.toml; do
  if find "${RESTORE_SOURCE}" -iname "${forbidden}" -type f | grep -q .; then
    echo "bootstrap snapshot contains forbidden key/config material: ${forbidden}" >&2
    exit 1
  fi
done

if [[ "${MANAGE_LAUNCHD}" == "true" ]]; then
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install_dir 0750 "${BACKUP_ROOT}" "${WORKSPACE}"
if [[ -d "${DATA_DIR}" ]]; then
  mv "${DATA_DIR}" "${BACKUP_ROOT}/data-pre-bootstrap-${timestamp}"
fi
install_dir 0750 "${DATA_DIR}"
ditto "${RESTORE_SOURCE}/" "${DATA_DIR}/"
if [[ -z "${TEST_ROOT}" ]]; then
  chown -R root:wheel "${DATA_DIR}"
  chmod -R u+rwX,go-rwx "${DATA_DIR}"
fi

if grep -q '"artifact_class": "archive-bootstrap"' "${bootstrap_validation_report}"; then
  cp "${bootstrap_validation_report}" "${APP_ROOT}/evidence/archive-bootstrap-limitation.json"
fi

if [[ "${MANAGE_LAUNCHD}" == "true" ]]; then
  restart_launchd_services
  wait_for_qrpc_latest_block
fi

echo "archive_bootstrap_restore_ok=true"
echo "snapshot_sha256=${actual_sha}"
echo "bootstrap_validation_report=${bootstrap_validation_report}"
echo "runtime_root=${APP_ROOT}"
echo "incoming_bootstrap=${INCOMING_BOOTSTRAP}"
echo "data_dir=${DATA_DIR}"
echo "backup_root=${BACKUP_ROOT}"
echo "next_action=wait for archive qRPC to catch up, then preserve height/hash parity evidence before majority proof or snapshot publication"
