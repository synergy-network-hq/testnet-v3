#!/usr/bin/env bash
set -euo pipefail

PURGE_DATA="false"
if [[ "${1:-}" == "--purge-data" ]]; then
  PURGE_DATA="true"
fi

for label in \
  io.synergynetwork.archive-snapshot-worker \
  io.synergynetwork.archive-snapshot-api \
  io.synergynetwork.archive-validator
do
  launchctl bootout "system/${label}" >/dev/null 2>&1 || true
done

rm -f /Library/LaunchDaemons/io.synergynetwork.archive-validator.plist
rm -f /Library/LaunchDaemons/io.synergynetwork.archive-snapshot-api.plist
rm -f /Library/LaunchDaemons/io.synergynetwork.archive-snapshot-worker.plist
rm -f /usr/local/synergy/bin/synergy-archive

if [[ "${PURGE_DATA}" == "true" ]]; then
  rm -rf "/Volumes/Synergy_Archive/archive-validator"
else
  echo "Archive validator services removed. Data and logs were preserved."
fi
