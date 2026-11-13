#!/usr/bin/env bash
set -euo pipefail
ARCHIVE_DATA_DIR="${ARCHIVE_DATA_DIR:-/Volumes/Synergy_Archive/archive-validator}"
out="${ARCHIVE_DATA_DIR}/logs/diagnostics-$(date +%Y%m%d%H%M%S).txt"
{
  date -u
  synergy-archive status || true
  systemctl status synergy-archive-validator.service --no-pager || true
  systemctl status synergy-archive-snapshot-api.service --no-pager || true
  systemctl status synergy-archive-snapshot-worker.service --no-pager || true
} > "${out}"
echo "${out}"
