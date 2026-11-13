#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${PACKAGE_ROOT}/archive-paths.sh"
archive_paths_load_defaults
archive_paths_validate
TEST_ROOT="${1:-/Volumes/xcode/synergy-archive-mac-acceptance-$(date -u +%Y%m%dT%H%M%SZ)}"
BIN_ROOT="${TEST_ROOT}/usr/local/synergy/bin"
STORAGE_VOLUME="${TEST_ROOT}${ARCHIVE_STORAGE_VOLUME}"
SMB_ROOT="${STORAGE_VOLUME}/archive-validator"
APP_ROOT="${TEST_ROOT}${ARCHIVE_APP_ROOT}"
PUBLISH_ROOT="${TEST_ROOT}${ARCHIVE_PUBLISH_ROOT}"
INCOMING_BOOTSTRAP="${SMB_ROOT}/incoming/bootstrap"
WORKSPACE="${APP_ROOT}/workspace"
EVIDENCE="${APP_ROOT}/evidence/isolated-acceptance"
FORBIDDEN_APP_REL="/Library/Application Support/Synergy/archive""-validator"
FORBIDDEN_PUBLISH_REL="/srv/synergy""-snapshots"
mkdir -p "${EVIDENCE}"
BACKGROUND_PIDS=()

cleanup() {
  stop_background_pids >/dev/null 2>&1 || true
}
trap cleanup EXIT

stop_background_pids() {
  for pid in "${BACKGROUND_PIDS[@]}"; do
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
  done
  BACKGROUND_PIDS=()
}

start_plist_service() {
  local plist="$1"
  local label="$2"
  local pid_file="${EVIDENCE}/${label}.pid"
  python3 - "${plist}" "${pid_file}" <<'PY'
import os
import plistlib
import subprocess
import sys
from pathlib import Path

plist_path = Path(sys.argv[1])
pid_file = Path(sys.argv[2])
with plist_path.open("rb") as handle:
    config = plistlib.load(handle)
args = config["ProgramArguments"]
env = os.environ.copy()
env.update(config.get("EnvironmentVariables") or {})
cwd = config.get("WorkingDirectory")
stdout_path = Path(config.get("StandardOutPath", os.devnull))
stderr_path = Path(config.get("StandardErrorPath", os.devnull))
stdout_path.parent.mkdir(parents=True, exist_ok=True)
stderr_path.parent.mkdir(parents=True, exist_ok=True)
stdout = stdout_path.open("ab")
stderr = stderr_path.open("ab")
process = subprocess.Popen(args, cwd=cwd or None, env=env, stdout=stdout, stderr=stderr)
pid_file.write_text(str(process.pid) + "\n", encoding="utf-8")
PY
  local pid
  pid="$(cat "${pid_file}")"
  BACKGROUND_PIDS+=("${pid}")
  echo "launchd_equivalent_started=${label} pid=${pid} plist=${plist}"
}

assert_pid_alive() {
  local pid="$1"
  local label="$2"
  kill -0 "${pid}" >/dev/null 2>&1 || {
    echo "launchd-equivalent service is not running: ${label} pid=${pid}" >&2
    exit 1
  }
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local label="$3"
  for _ in {1..60}; do
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
      echo "listener_ok=${label}:${host}:${port}"
      return 0
    fi
    sleep 1
  done
  echo "listener did not appear in isolated launchd-equivalent acceptance: ${label} ${host}:${port}" >&2
  return 1
}

wait_for_qrpc_latest_block() {
  local port="$1"
  local output="$2"
  for _ in {1..60}; do
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
      return 0
    fi
    sleep 1
  done
  echo "qRPC latest block did not return in isolated launchd-equivalent acceptance" >&2
  return 1
}

mkdir -p "${STORAGE_VOLUME}"
"${PACKAGE_ROOT}/setup-archive-validator-m4.sh" \
  --test-root "${TEST_ROOT}" \
  --public-host 127.0.0.1 \
  --snapshot-api-bind 127.0.0.1:48641 \
  --skip-launchd-load \
  --yes | tee "${EVIDENCE}/install.txt"
"${PACKAGE_ROOT}/verify-archive-validator-m4.sh" \
  --test-root "${TEST_ROOT}" \
  --skip-launchd-check \
  --skip-listener-check | tee "${EVIDENCE}/verify.txt"

[[ -d "${APP_ROOT}" ]]
[[ -d "${APP_ROOT}/tmp" ]]
[[ -d "${APP_ROOT}/workspace/data" ]]
[[ -d "${APP_ROOT}/logs" ]]
[[ -d "${APP_ROOT}/evidence" ]]
[[ -f "${APP_ROOT}/config/consensus-fork-migration.json" ]]
[[ -f "${WORKSPACE}/config/consensus-fork-migration.json" ]]
[[ -d "${SMB_ROOT}" ]]
[[ -d "${INCOMING_BOOTSTRAP}" ]]
[[ -d "${PUBLISH_ROOT}/staging" ]]
[[ -d "${PUBLISH_ROOT}/failed" ]]
[[ -d "${PUBLISH_ROOT}/retired" ]]
[[ ! -e "${TEST_ROOT}${FORBIDDEN_APP_REL}" ]]
[[ ! -e "${TEST_ROOT}${FORBIDDEN_PUBLISH_REL}" ]]
if grep -R -F \
  -e "${FORBIDDEN_APP_REL}" \
  -e "${FORBIDDEN_PUBLISH_REL}" \
  "${TEST_ROOT}/Library/LaunchDaemons" "${APP_ROOT}" >/dev/null 2>&1
then
  echo "isolated acceptance found forbidden archive storage path" >&2
  exit 1
fi
if grep -R -F \
  -e "${STORAGE_VOLUME}/archive-validator/workspace" \
  -e "${STORAGE_VOLUME}/archive-validator/logs" \
  -e "${STORAGE_VOLUME}/archive-validator/evidence" \
  -e "${STORAGE_VOLUME}/archive-validator/tmp" \
  "${TEST_ROOT}/Library/LaunchDaemons" "${APP_ROOT}" >/dev/null 2>&1
then
  echo "isolated acceptance found SMB-backed runtime storage path" >&2
  exit 1
fi

python3 - "${WORKSPACE}/config/node.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
for before, after in {
    "p2p_port = 5622": "p2p_port = 45622",
    "rpc_port = 5640": "rpc_port = 45640",
    "ws_port = 5660": "ws_port = 45660",
    'bind_address = "127.0.0.1:5640"': 'bind_address = "127.0.0.1:45640"',
    "http_port = 5640": "http_port = 45640",
    "ws_port = 5660": "ws_port = 45660",
    'listen_address = "0.0.0.0:5622"': 'listen_address = "127.0.0.1:45622"',
    'public_address = "127.0.0.1:5622"': 'public_address = "127.0.0.1:45622"',
    "discovery_port = 5680": "discovery_port = 45680",
    'discovery_listen_address = "0.0.0.0:5680"': 'discovery_listen_address = "127.0.0.1:45680"',
    'discovery_public_address = "127.0.0.1:5680"': 'discovery_public_address = "127.0.0.1:45680"',
    'metrics_bind = "127.0.0.1:6030"': 'metrics_bind = "127.0.0.1:46030"',
}.items():
    text = text.replace(before, after)
path.write_text(text, encoding="utf-8")
PY

start_plist_service \
  "${TEST_ROOT}/Library/LaunchDaemons/io.synergynetwork.archive-validator.plist" \
  io.synergynetwork.archive-validator
start_plist_service \
  "${TEST_ROOT}/Library/LaunchDaemons/io.synergynetwork.archive-snapshot-api.plist" \
  io.synergynetwork.archive-snapshot-api
start_plist_service \
  "${TEST_ROOT}/Library/LaunchDaemons/io.synergynetwork.archive-snapshot-worker.plist" \
  io.synergynetwork.archive-snapshot-worker
wait_for_tcp 127.0.0.1 45622 archive_p2p
wait_for_tcp 127.0.0.1 48641 snapshot_api
wait_for_tcp 127.0.0.1 45640 archive_qrpc
wait_for_tcp 127.0.0.1 45660 archive_ws
wait_for_tcp 127.0.0.1 46030 archive_metrics
wait_for_qrpc_latest_block 45640 "${EVIDENCE}/archive-node-qrpc-latest-block.json"
for pid in "${BACKGROUND_PIDS[@]}"; do
  assert_pid_alive "${pid}" launchd-equivalent-service
done
sleep 2
grep -q 'worker failed closed' "${APP_ROOT}/logs/snapshot-worker.err.log"
echo "snapshot_worker_pending_majority_proof_ok=true"
"${PACKAGE_ROOT}/verify-archive-validator-m4.sh" \
  --test-root "${TEST_ROOT}" \
  --skip-launchd-check \
  --p2p-port 45622 \
  --qrpc-port 45640 \
  --ws-port 45660 \
  --metrics-port 46030 \
  --snapshot-api-bind 127.0.0.1:48641 | tee "${EVIDENCE}/verify-launchd-equivalent.txt"
stop_background_pids

printf '{"acceptance":true}\n' > "${EVIDENCE}/payload.json"
"${BIN_ROOT}/aegis-pqvm" sign-json \
  --identity "${APP_ROOT}/keys/archive-authority-identity.json" \
  --domain SYNERGY_ARCHIVE_MAC_ACCEPTANCE_V1 \
  --input "${EVIDENCE}/payload.json" \
  --output "${EVIDENCE}/payload.json.sig" | tee "${EVIDENCE}/aegis-sign.json"
"${BIN_ROOT}/aegis-pqvm" verify-json \
  --domain SYNERGY_ARCHIVE_MAC_ACCEPTANCE_V1 \
  --input "${EVIDENCE}/payload.json" \
  --signature "${EVIDENCE}/payload.json.sig" | tee "${EVIDENCE}/aegis-verify.json"

FIXTURE_ROOT="${EVIDENCE}/fixture-validator-pruned"
SYNERGY_ARCHIVE_FIXTURE_MODE=1 "${BIN_ROOT}/aegis-pqvm" \
  test-only-create-snapshot-fixture \
  --output "${FIXTURE_ROOT}" \
  --snapshot-class validator-pruned | tee "${EVIDENCE}/fixture-create.json"
"${BIN_ROOT}/synergy-archive" publish-snapshot \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --snapshot-class validator-pruned \
  --snapshot-root "${FIXTURE_ROOT}" \
  --manifest "${FIXTURE_ROOT}/snapshot-100-manifest.json" \
  --fixture-mode | tee "${EVIDENCE}/publish-snapshot.json"

SNAPSHOT_DIR="${PUBLISH_ROOT}/testnet-1264/validator-pruned/snapshot-000000100"
python3 - "${SNAPSHOT_DIR}/distribution-manifest.json" "${PUBLISH_ROOT}/catalog.json" <<'PY'
import json
import sys

distribution_path, catalog_path = sys.argv[1:3]
with open(distribution_path, encoding="utf-8") as handle:
    distribution = json.load(handle)
with open(catalog_path, encoding="utf-8") as handle:
    catalog = json.load(handle)
for label, value in {
    "distribution": distribution.get("consensus_fork"),
    "catalog": catalog.get("consensus_fork"),
    "catalog_entry": (catalog.get("snapshots") or [{}])[0].get("consensus_fork"),
}.items():
    if not isinstance(value, dict):
        raise SystemExit(f"{label} consensus_fork missing")
    if value.get("fork_height") != 204216:
        raise SystemExit(f"{label} fork_height mismatch: {value.get('fork_height')}")
    if value.get("new_consensus_algorithm") != "FN-DSA":
        raise SystemExit(f"{label} new_consensus_algorithm mismatch: {value.get('new_consensus_algorithm')}")
    if value.get("parser_mode") != "fail_closed":
        raise SystemExit(f"{label} parser_mode mismatch: {value.get('parser_mode')}")
print("snapshot_consensus_fork_metadata_published_ok=true")
PY
"${BIN_ROOT}/synergy-archive" verify-distribution \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --input "${SNAPSHOT_DIR}" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --target-role validator \
  --extract-root "${EVIDENCE}/receiver-valid" | tee "${EVIDENCE}/receiver-verify.json"
MISSING_FORK_DIR="${EVIDENCE}/post-fork-missing-fork-distribution"
mkdir -p "${MISSING_FORK_DIR}"
python3 - "${SNAPSHOT_DIR}/distribution-manifest.json" "${MISSING_FORK_DIR}/distribution-manifest.json" <<'PY'
import json
import sys

source, output = sys.argv[1:3]
with open(source, encoding="utf-8") as handle:
    value = json.load(handle)
value["height"] = 204216
value.pop("consensus_fork", None)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
if "${BIN_ROOT}/synergy-archive" verify-distribution \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --input "${MISSING_FORK_DIR}" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --target-role validator \
  --extract-root "${EVIDENCE}/receiver-missing-fork" \
  > "${EVIDENCE}/receiver-missing-fork.out" 2> "${EVIDENCE}/receiver-missing-fork.err"
then
  echo "post-fork distribution missing consensus_fork was not rejected" >&2
  exit 1
fi
[[ ! -e "${EVIDENCE}/receiver-missing-fork" ]]
if "${BIN_ROOT}/synergy-archive" verify-distribution \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --input "${SNAPSHOT_DIR}" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --target-role rpc_gateway \
  --extract-root "${EVIDENCE}/receiver-wrong-class" \
  > "${EVIDENCE}/receiver-wrong-class.out" 2> "${EVIDENCE}/receiver-wrong-class.err"
then
  echo "wrong-class receiver was not rejected" >&2
  exit 1
fi
[[ ! -e "${EVIDENCE}/receiver-wrong-class" ]]

"${BIN_ROOT}/synergy-archive" pin \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --snapshot-id snapshot-000000100 \
  --snapshot-class validator-pruned \
  --reason isolated-mac-acceptance | tee "${EVIDENCE}/pin.json"
"${BIN_ROOT}/synergy-archive" unpin \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --snapshot-id snapshot-000000100 \
  --snapshot-class validator-pruned \
  --reason isolated-mac-acceptance | tee "${EVIDENCE}/unpin.json"
"${BIN_ROOT}/synergy-archive" prune \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" | tee "${EVIDENCE}/prune-dry-run.json"

"${BIN_ROOT}/synergy-archive" serve \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --bind 127.0.0.1:48642 > "${EVIDENCE}/snapshot-api.out" 2> "${EVIDENCE}/snapshot-api.err" &
API_PID=$!
BACKGROUND_PIDS+=("${API_PID}")
sleep 2
[[ "$(curl -fsS -H 'Range: bytes=0-4' \
  http://127.0.0.1:48642/testnet-1264/validator-pruned/snapshot-000000100/distribution-manifest.json \
  | wc -c | tr -d ' ')" == "5" ]]
curl -fsS http://127.0.0.1:48642/staging/not-public >/dev/null 2>&1 && {
  echo "snapshot API exposed staging path" >&2
  exit 1
}
kill "${API_PID}" >/dev/null 2>&1 || true
wait "${API_PID}" 2>/dev/null || true
BACKGROUND_PIDS=()

for plist in "${TEST_ROOT}/Library/LaunchDaemons/"*.plist; do
  plutil -lint "${plist}" >/dev/null
done
"${BIN_ROOT}/synergy-archive" status \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" | tee "${EVIDENCE}/final-status.json"
echo "isolated_mac_acceptance_ok=true"
echo "test_root=${TEST_ROOT}"
echo "evidence=${EVIDENCE}"
