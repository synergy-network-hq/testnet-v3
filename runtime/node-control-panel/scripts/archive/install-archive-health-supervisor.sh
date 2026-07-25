#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_ROOT="${SYNERGY_ARCHIVE_INSTALL_ROOT:-/Users/Shared/Synergy/archive-validator}"
BIN_DIR="${INSTALL_ROOT}/bin"
HEALTH_DIR="${INSTALL_ROOT}/health"
LAUNCHD_DIR="${SYNERGY_ARCHIVE_LAUNCHD_DIR:-/Library/LaunchDaemons}"
LABEL="network.synergy.archive-health-supervisor"
PLIST_PATH="${LAUNCHD_DIR}/${LABEL}.plist"
SKIP_LAUNCHCTL="${SYNERGY_ARCHIVE_INSTALL_SKIP_LAUNCHCTL:-0}"
HEALTH_READER_USER="${SYNERGY_ARCHIVE_HEALTH_READER_USER:-synergynode}"

case "$SKIP_LAUNCHCTL" in
  0|1) ;;
  *) echo "SYNERGY_ARCHIVE_INSTALL_SKIP_LAUNCHCTL must be 0 or 1" >&2; exit 64 ;;
esac
if [[ "$SKIP_LAUNCHCTL" != "1" && "$EUID" -ne 0 ]]; then
  echo "archive health supervisor installation requires root for launchd persistence" >&2
  exit 77
fi

mkdir -p "$BIN_DIR" "${INSTALL_ROOT}/logs" "$LAUNCHD_DIR"
if [[ "$EUID" -eq 0 ]]; then
  HEALTH_READER_GROUP="$(id -gn "$HEALTH_READER_USER")"
  install -d -o "$HEALTH_READER_USER" -g "$HEALTH_READER_GROUP" -m 0750 "$HEALTH_DIR"
else
  install -d -m 0750 "$HEALTH_DIR"
fi
install -m 0750 "$SOURCE_DIR/archive-health-supervisor.sh" "$BIN_DIR/archive-health-supervisor.sh"
install -m 0750 "$SOURCE_DIR/require-archive-health-green.sh" "$BIN_DIR/require-archive-health-green.sh"

python3 - "$SOURCE_DIR/network.synergy.archive-health-supervisor.plist" "$PLIST_PATH" "$INSTALL_ROOT" <<'PY'
import pathlib
import sys

source, destination, root = map(pathlib.Path, sys.argv[1:])
value = source.read_text(encoding="utf-8").replace("/Users/Shared/Synergy/archive-validator", str(root))
destination.write_text(value, encoding="utf-8")
PY
chmod 0644 "$PLIST_PATH"

if [[ "$SKIP_LAUNCHCTL" == "1" ]]; then
  echo "archive health supervisor installed without launchd bootstrap: ${PLIST_PATH}"
  exit 0
fi
chown root:wheel "$PLIST_PATH" "$BIN_DIR/archive-health-supervisor.sh"
chown root:"$HEALTH_READER_GROUP" "$BIN_DIR/require-archive-health-green.sh"
/bin/launchctl bootout "system/${LABEL}" >/dev/null 2>&1 || true
/bin/launchctl enable "system/${LABEL}"
/bin/launchctl bootstrap system "$PLIST_PATH"
echo "archive health supervisor installed and bootstrapped: ${PLIST_PATH}"
