#!/usr/bin/env bash
set -euo pipefail
./scripts/verify-aegis-pqvm.sh
ARCHIVE_DATA_DIR="${ARCHIVE_DATA_DIR:-/Volumes/Synergy_Archive/archive-validator}"
install -d -m 0750 "${ARCHIVE_DATA_DIR}/keys"
printf '%s\n' 'aegis-pqvm:ARCHIVE_PEER' > "${ARCHIVE_DATA_DIR}/keys/aegis-archive-peer-key.ref"
printf '%s\n' 'aegis-pqvm:ARCHIVE_SNAPSHOT_SIGNER' > "${ARCHIVE_DATA_DIR}/keys/aegis-snapshot-signing-key.ref"
echo "Aegis archive key references initialized; raw private keys are not stored in this package."
