#!/usr/bin/env bash
set -euo pipefail

CHAIN_ID="1264"
NETWORK_ID="synergy-testnet-v3"
GENESIS_FILE=""
EXPECTED_GENESIS_HASH=""
ARCHIVE_DATA_DIR="/Volumes/Synergy_Archive/archive-validator"
SNAPSHOT_API_BIND="0.0.0.0:48640"
SNAPSHOT_PUBLIC_URL=""
P2P_BIND="0.0.0.0:38639"
METRICS_BIND="127.0.0.1:9091"
ENABLE_NGINX="false"
YES="false"
INSTALL_USER="synergy"
INSTALL_GROUP="synergy"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --chain-id) CHAIN_ID="$2"; shift 2 ;;
    --network-id) NETWORK_ID="$2"; shift 2 ;;
    --genesis-file) GENESIS_FILE="$2"; shift 2 ;;
    --expected-genesis-hash) EXPECTED_GENESIS_HASH="$2"; shift 2 ;;
    --archive-data-dir) ARCHIVE_DATA_DIR="$2"; shift 2 ;;
    --snapshot-api-bind) SNAPSHOT_API_BIND="$2"; shift 2 ;;
    --snapshot-public-url) SNAPSHOT_PUBLIC_URL="$2"; shift 2 ;;
    --p2p-bind) P2P_BIND="$2"; shift 2 ;;
    --metrics-bind) METRICS_BIND="$2"; shift 2 ;;
    --enable-nginx) ENABLE_NGINX="$2"; shift 2 ;;
    --bootnodes|--snapshot-interval-blocks) shift 2 ;;
    --yes) YES="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ "$(uname -s)" == "Linux" ]] || { echo "setup-archive-validator.sh supports Linux only; use the signed macOS pkg on Darwin." >&2; exit 1; }
[[ "$(id -u)" == "0" ]] || { echo "setup must run as root so systemd services and protected paths can be installed" >&2; exit 1; }
[[ "${CHAIN_ID}" == "1264" ]] || { echo "chain_id must be 1264" >&2; exit 1; }
[[ "${NETWORK_ID}" == "synergy-testnet-v3" ]] || { echo "network_id must be synergy-testnet-v3" >&2; exit 1; }
[[ -n "${GENESIS_FILE}" && -f "${GENESIS_FILE}" ]] || { echo "genesis file is missing" >&2; exit 1; }
[[ -n "${EXPECTED_GENESIS_HASH}" ]] || { echo "expected genesis hash is required" >&2; exit 1; }
command -v aegis-pqvm >/dev/null 2>&1 || { echo "aegis-pqvm is required and unavailable" >&2; exit 1; }
if [[ -x ./bin/synergy-archive ]]; then
  install -m 0755 ./bin/synergy-archive /usr/local/bin/synergy-archive
elif ! command -v synergy-archive >/dev/null 2>&1; then
  echo "synergy-archive binary is missing. Install from the trusted release artifact or include ./bin/synergy-archive in this package." >&2
  exit 1
fi

if [[ "${YES}" != "true" ]]; then
  read -r -p "Install Synergy Archive Validator Node for Testnet chain 1264? [y/N] " answer
  [[ "${answer}" == "y" || "${answer}" == "Y" ]] || exit 1
fi

GENESIS_HASH="$(python3 - "$GENESIS_FILE" <<'PY'
import json, sys
with open(sys.argv[1], 'r', encoding='utf-8') as fh:
    data = json.load(fh)
value = data.get("integrity", {}).get("genesis_hash")
if not value:
    raise SystemExit("integrity.genesis_hash missing from genesis file")
print(value)
PY
)"
[[ "${GENESIS_HASH}" == "${EXPECTED_GENESIS_HASH}" ]] || { echo "computed genesis hash ${GENESIS_HASH} does not match expected ${EXPECTED_GENESIS_HASH}" >&2; exit 1; }

if ! getent group "${INSTALL_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${INSTALL_GROUP}"
fi
if ! id -u "${INSTALL_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir "${ARCHIVE_DATA_DIR}" --shell /usr/sbin/nologin --gid "${INSTALL_GROUP}" "${INSTALL_USER}"
fi

install -d -m 0750 "${ARCHIVE_DATA_DIR}/"{config,keys,data,logs,tmp,backups,run,snapshots,evidence}
install -d -m 0750 "${ARCHIVE_DATA_DIR}/data/"{blocks,qcs,state,epochs,validators,evidence,indexes}
install -d -m 0750 "${ARCHIVE_DATA_DIR}/workspace/config"
install -m 0640 "${GENESIS_FILE}" "${ARCHIVE_DATA_DIR}/config/genesis.json"
install -m 0640 ./config/archive-validator.testnet.toml "${ARCHIVE_DATA_DIR}/config/archive-validator.toml"
install -m 0640 ./config/snapshot-policy.testnet.toml "${ARCHIVE_DATA_DIR}/config/snapshot-policy.toml"
install -m 0640 ./config/archive-api.testnet.toml "${ARCHIVE_DATA_DIR}/config/archive-api.toml"
install -m 0640 ./config/archive-validator.testnet.toml "${ARCHIVE_DATA_DIR}/workspace/config/node.toml"
rm -rf "${ARCHIVE_DATA_DIR}/workspace/data"
ln -s ../data "${ARCHIVE_DATA_DIR}/workspace/data"
chown -R "${INSTALL_USER}:${INSTALL_GROUP}" "${ARCHIVE_DATA_DIR}"

./scripts/verify-aegis-pqvm.sh
export ARCHIVE_DATA_DIR
./scripts/init-aegis-archive-identity.sh

if command -v systemctl >/dev/null 2>&1; then
  install -m 0644 ./systemd/*.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service
  systemctl start synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service
fi

if [[ "${ENABLE_NGINX}" == "true" ]]; then
  install -m 0644 ./nginx/synergy-archive-snapshot-api.conf /etc/nginx/conf.d/synergy-archive-snapshot-api.conf
fi

if ! SNAPSHOT_PUBLIC_URL="${SNAPSHOT_PUBLIC_URL}" SNAPSHOT_API_BIND="${SNAPSHOT_API_BIND}" P2P_BIND="${P2P_BIND}" METRICS_BIND="${METRICS_BIND}" ./scripts/healthcheck.sh; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service || true
  fi
  echo "post-install health check failed; archive services were stopped and must not run partially configured" >&2
  exit 1
fi
echo "Archive validator ready. snapshot_api_bind=${SNAPSHOT_API_BIND} p2p_bind=${P2P_BIND} metrics_bind=${METRICS_BIND}"
