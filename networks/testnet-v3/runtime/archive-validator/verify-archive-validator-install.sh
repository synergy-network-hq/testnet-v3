#!/usr/bin/env bash
set -euo pipefail
command -v aegis-pqvm >/dev/null 2>&1
ARCHIVE_DATA_DIR="${ARCHIVE_DATA_DIR:-/Volumes/Synergy_Archive/archive-validator}"
test -f "${ARCHIVE_DATA_DIR}/config/archive-validator.toml"
test -f "${ARCHIVE_DATA_DIR}/config/genesis.json"
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-enabled synergy-archive-validator.service >/dev/null
  systemctl is-enabled synergy-archive-snapshot-api.service >/dev/null
  systemctl is-enabled synergy-archive-snapshot-worker.service >/dev/null
fi
echo "Archive validator install readiness checks passed."
