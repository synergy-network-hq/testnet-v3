#!/usr/bin/env bash
set -euo pipefail

ROOT="${SYNERGY_ARCHIVE_APP_ROOT:-${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}}"
STORAGE_VOLUME="${SYNERGY_ARCHIVE_STORAGE_VOLUME:-/Volumes/Synergy_Archive}"
PUBLISH_ROOT="${SYNERGY_SNAPSHOT_PUBLISH_ROOT:-${STORAGE_VOLUME}/archive-validator/snapshots}"
RUNTIME="${SYNERGY_ARCHIVE_RUNTIME:-/usr/local/synergy/bin/synergy-archive-validator-node}"
AEGIS="${SYNERGY_AEGIS_CLI:-/usr/local/synergy/bin/aegis-pqvm}"
WORKSPACE="${SYNERGY_ARCHIVE_WORKSPACE:-${ROOT}/workspace}"
MAJORITY_PROOF_MARKER="${SYNERGY_ARCHIVE_MAJORITY_PROOF_MARKER:-${ROOT}/evidence/source-majority-branch-proven.json}"

if [[ $# -eq 0 ]]; then
  synergy-archive worker \
    --root "${ROOT}" \
    --publish-root "${PUBLISH_ROOT}" \
    --storage-volume "${STORAGE_VOLUME}" \
    --runtime "${RUNTIME}" \
    --aegis "${AEGIS}" \
    --workspace "${WORKSPACE}" \
    --majority-proof-marker "${MAJORITY_PROOF_MARKER}" \
    --once
  exit 0
fi

snapshot_class="$1"
synergy-archive create-snapshot \
  --root "${ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --storage-volume "${STORAGE_VOLUME}" \
  --runtime "${RUNTIME}" \
  --aegis "${AEGIS}" \
  --workspace "${WORKSPACE}" \
  --snapshot-class "${snapshot_class}" \
  --majority-proof-marker "${MAJORITY_PROOF_MARKER}"
