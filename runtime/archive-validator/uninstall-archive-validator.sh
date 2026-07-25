#!/usr/bin/env bash
set -euo pipefail
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service || true
  systemctl disable synergy-archive-validator.service synergy-archive-snapshot-api.service synergy-archive-snapshot-worker.service || true
  rm -f /etc/systemd/system/synergy-archive-validator.service /etc/systemd/system/synergy-archive-snapshot-api.service /etc/systemd/system/synergy-archive-snapshot-worker.service
  systemctl daemon-reload
fi
echo "Archive validator services removed. Data under /Volumes/Synergy_Archive/archive-validator was preserved."
