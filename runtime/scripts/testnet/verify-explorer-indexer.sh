#!/usr/bin/env bash
set -u

OUTPUT_PATH=""
USE_SSH=0
SSH_ALIAS="synergy-vps"
SERVICE_NAME="synergy-explorer-indexer.service"
NODE_CONFIG="/etc/synergy/explorer-indexer/node.toml"
PEERS_CONFIG="/etc/synergy/explorer-indexer/peers.toml"
INDEX_HEALTH_URL=""
ATLAS_URL=""
P2P_PORT=""
TIMEOUT_SECONDS=4

usage() {
  cat <<'EOF'
Usage: verify-explorer-indexer.sh [options]

Verifies explorer-indexer service/config/health without writing a report unless
--output is explicitly provided. SSH is opt-in and must use a workbook-backed
alias, defaulting to synergy-vps.

Options:
  --output PATH             Write report to PATH. Defaults to stdout.
  --ssh                     Use SSH to inspect remote service and config.
  --ssh-alias ALIAS         SSH alias to use with --ssh. Default: synergy-vps.
  --service NAME            Systemd service name. Default: synergy-explorer-indexer.service.
  --node-config PATH        Remote node config path.
  --peers-config PATH       Remote peers config path.
  --index-health-url URL    HTTP endpoint exposing indexer height/status.
  --atlas-url URL           Atlas/explorer URL to check for HTTP 200.
  --p2p-port PORT           TCP-check 74.208.227.23:PORT when a public port exists.
  --timeout SECONDS         Network timeout. Default: 4.
  -h, --help                Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_PATH="${2:-}"
      shift 2
      ;;
    --ssh)
      USE_SSH=1
      shift
      ;;
    --ssh-alias)
      SSH_ALIAS="${2:-}"
      shift 2
      ;;
    --service)
      SERVICE_NAME="${2:-}"
      shift 2
      ;;
    --node-config)
      NODE_CONFIG="${2:-}"
      shift 2
      ;;
    --peers-config)
      PEERS_CONFIG="${2:-}"
      shift 2
      ;;
    --index-health-url)
      INDEX_HEALTH_URL="${2:-}"
      shift 2
      ;;
    --atlas-url)
      ATLAS_URL="${2:-}"
      shift 2
      ;;
    --p2p-port)
      P2P_PORT="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -n "${OUTPUT_PATH}" ]]; then
  if ! exec >"${OUTPUT_PATH}"; then
    echo "failed to open output path: ${OUTPUT_PATH}" >&2
    exit 2
  fi
fi

STATUS=0
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS %s\n' "$*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  STATUS=1
  printf 'FAIL %s\n' "$*"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  printf 'WARN %s\n' "$*"
}

skip() {
  SKIP_COUNT=$((SKIP_COUNT + 1))
  printf 'SKIP %s\n' "$*"
}

tcp_probe() {
  local host="$1"
  local port="$2"
  python3 - "$host" "$port" "$TIMEOUT_SECONDS" <<'PY'
import socket
import sys

host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    with socket.create_connection((host, port), timeout=timeout):
        pass
except OSError as exc:
    print(str(exc))
    sys.exit(1)
sys.exit(0)
PY
}

http_probe() {
  local url="$1"
  python3 - "$url" "$TIMEOUT_SECONDS" <<'PY'
import sys
import urllib.request

url, timeout = sys.argv[1], float(sys.argv[2])
with urllib.request.urlopen(url, timeout=timeout) as response:
    body = response.read(2048).decode("utf-8", errors="replace")
    print(f"HTTP {response.status}")
    if body:
        print(body[:500])
PY
}

contains_required_peer() {
  local content="$1"
  local peer="$2"
  [[ "${content}" == *"${peer}"* ]]
}

EXPECTED_PEERS=(
  "relay1.synergynode.xyz:5622"
  "relay2.synergynode.xyz:5622"
  "relay3.synergynode.xyz:5622"
)

cat <<EOF
Synergy explorer-indexer verification
output=${OUTPUT_PATH:-stdout}
ssh_enabled=${USE_SSH}
ssh_alias=${SSH_ALIAS}
service=${SERVICE_NAME}
node_config=${NODE_CONFIG}
peers_config=${PEERS_CONFIG}
EOF

if [[ "${USE_SSH}" -eq 0 && -z "${INDEX_HEALTH_URL}" && -z "${ATLAS_URL}" && -z "${P2P_PORT}" ]]; then
  fail "no verification source supplied; rerun with --ssh using workbook alias ${SSH_ALIAS}, --index-health-url, --atlas-url, or --p2p-port"
fi

if [[ -n "${P2P_PORT}" ]]; then
  if err="$(tcp_probe "74.208.227.23" "${P2P_PORT}" 2>&1)"; then
    pass "explorer-indexer TCP 74.208.227.23:${P2P_PORT} reachable"
  else
    fail "explorer-indexer TCP 74.208.227.23:${P2P_PORT} unreachable: ${err}"
  fi
else
  skip "explorer-indexer TCP reachability skipped; no public P2P port was provided in the topology prompt"
fi

if [[ -n "${INDEX_HEALTH_URL}" ]]; then
  if response="$(http_probe "${INDEX_HEALTH_URL}" 2>&1)"; then
    pass "index health endpoint reachable: ${INDEX_HEALTH_URL}"
    if [[ "${response}" =~ [Hh]eight|[Bb]lock|[Ii]ndex ]]; then
      pass "index health response includes height/block/index status"
    else
      warn "index health response did not include obvious height/block/index status"
    fi
  else
    fail "index health endpoint failed: ${INDEX_HEALTH_URL}: ${response}"
  fi
else
  skip "index height check skipped; pass --index-health-url when available"
fi

if [[ -n "${ATLAS_URL}" ]]; then
  if response="$(http_probe "${ATLAS_URL}" 2>&1)"; then
    pass "Atlas/explorer URL reachable: ${ATLAS_URL}"
  else
    fail "Atlas/explorer URL failed: ${ATLAS_URL}: ${response}"
  fi
else
  skip "Atlas/explorer pipeline HTTP check skipped; pass --atlas-url when available"
fi

if [[ "${USE_SSH}" -eq 1 ]]; then
  if [[ "${SSH_ALIAS}" == *"."* || "${SSH_ALIAS}" == *@* || "${SSH_ALIAS}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "ssh alias must be a workbook-backed alias, not a raw host: ${SSH_ALIAS}"
  else
    REMOTE_OUTPUT="$(ssh "${SSH_ALIAS}" 'bash -s' -- "${SERVICE_NAME}" "${NODE_CONFIG}" "${PEERS_CONFIG}" <<'REMOTE' 2>&1
set -u
service_name="$1"
node_config="$2"
peers_config="$3"

printf 'SERVICE_ACTIVE='
systemctl is-active "${service_name}" 2>/dev/null || true
printf 'SERVICE_STATUS='
systemctl status "${service_name}" --no-pager -n 20 2>/dev/null | sed -n '1,20p' || true
printf '\nNODE_CONFIG_BEGIN\n'
if [ -r "${node_config}" ]; then
  sed -n '1,260p' "${node_config}"
else
  printf 'MISSING %s\n' "${node_config}"
fi
printf '\nNODE_CONFIG_END\n'
printf '\nPEERS_CONFIG_BEGIN\n'
if [ -r "${peers_config}" ]; then
  sed -n '1,260p' "${peers_config}"
else
  printf 'MISSING %s\n' "${peers_config}"
fi
printf '\nPEERS_CONFIG_END\n'
REMOTE
)"
    ssh_status=$?
    if [[ "${ssh_status}" -ne 0 ]]; then
      fail "ssh ${SSH_ALIAS} failed: ${REMOTE_OUTPUT}"
    else
      pass "ssh ${SSH_ALIAS} completed"
      if [[ "${REMOTE_OUTPUT}" == *"SERVICE_ACTIVE=active"* ]]; then
        pass "explorer indexer service active"
      else
        fail "explorer indexer service is not active"
      fi
      if [[ "${REMOTE_OUTPUT}" == *"MISSING ${NODE_CONFIG}"* ]]; then
        fail "remote node config missing: ${NODE_CONFIG}"
      else
        pass "remote node config readable: ${NODE_CONFIG}"
      fi
      if [[ "${REMOTE_OUTPUT}" == *"MISSING ${PEERS_CONFIG}"* ]]; then
        fail "remote peers config missing: ${PEERS_CONFIG}"
      else
        pass "remote peers config readable: ${PEERS_CONFIG}"
      fi
      if grep -Eq '10\.69\.|10\.[0-9]+\.[0-9]+\.[0-9]+:5622|127\.0\.0\.1:5622|localhost:5622|192\.168\.[0-9]+\.[0-9]+:5622|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+:5622' <<<"${REMOTE_OUTPUT}"; then
        fail "explorer indexer config contains VPN/private/localhost public P2P endpoint"
      else
        pass "explorer indexer config has no VPN/private public P2P endpoints"
      fi
      for peer in "${EXPECTED_PEERS[@]}"; do
        if contains_required_peer "${REMOTE_OUTPUT}" "${peer}"; then
          pass "explorer indexer peer present: ${peer}"
        else
          fail "explorer indexer peer missing: ${peer}"
        fi
      done
    fi
  fi
else
  skip "remote service/config checks skipped; pass --ssh to inspect ${SSH_ALIAS}"
fi

echo
printf 'Summary: pass=%s fail=%s warn=%s skip=%s\n' "${PASS_COUNT}" "${FAIL_COUNT}" "${WARN_COUNT}" "${SKIP_COUNT}"
exit "${STATUS}"
