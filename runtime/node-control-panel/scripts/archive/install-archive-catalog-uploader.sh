#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="${SOURCE_DIR}/upload-public-catalog-local.sh"
SOURCE_PLIST="${SOURCE_DIR}/network.synergy.archive-catalog-uploader.plist"
LABEL="network.synergy.archive-catalog-uploader"
HOME_DIR="${HOME:?HOME must be set}"
INSTALL_DIR="${SYNERGY_ARCHIVE_CATALOG_INSTALL_DIR:-${HOME_DIR}/Library/Application Support/Synergy Network/archive-catalog-freshness}"
LAUNCHD_DIR="${SYNERGY_ARCHIVE_CATALOG_LAUNCHD_DIR:-${HOME_DIR}/Library/LaunchAgents}"
SCRIPT_PATH="${SYNERGY_ARCHIVE_CATALOG_SCRIPT_PATH:-${INSTALL_DIR}/upload-public-catalog.sh}"
PLIST_PATH="${SYNERGY_ARCHIVE_CATALOG_PLIST_PATH:-${LAUNCHD_DIR}/${LABEL}.plist}"
LAUNCHCTL="${SYNERGY_LAUNCHCTL:-/bin/launchctl}"
GUI_UID="${SYNERGY_ARCHIVE_CATALOG_LAUNCHD_UID:-$(id -u)}"
SKIP_LAUNCHCTL="${SYNERGY_ARCHIVE_CATALOG_INSTALL_SKIP_LAUNCHCTL:-0}"

case "$SKIP_LAUNCHCTL" in
  0|1) ;;
  *) echo "SYNERGY_ARCHIVE_CATALOG_INSTALL_SKIP_LAUNCHCTL must be 0 or 1" >&2; exit 64 ;;
esac
[[ -f "$SOURCE_SCRIPT" ]] || { echo "missing archive catalog uploader: $SOURCE_SCRIPT" >&2; exit 66; }
[[ -f "$SOURCE_PLIST" ]] || { echo "missing launchd plist template: $SOURCE_PLIST" >&2; exit 66; }
[[ "$GUI_UID" =~ ^[0-9]+$ ]] || { echo "archive catalog launchd UID must be numeric: $GUI_UID" >&2; exit 64; }

install -d -m 0700 "$INSTALL_DIR" "$LAUNCHD_DIR" "$(dirname "$SCRIPT_PATH")" "$(dirname "$PLIST_PATH")"

install_atomic() {
  local source="$1"
  local destination="$2"
  local mode="$3"
  local parent temporary
  parent="$(dirname "$destination")"
  temporary="$(mktemp "${parent}/.${LABEL}.XXXXXX")"
  trap 'rm -f "$temporary"' RETURN
  install -m "$mode" "$source" "$temporary"
  mv -f "$temporary" "$destination"
  trap - RETURN
}

install_atomic "$SOURCE_SCRIPT" "$SCRIPT_PATH" 0700
install_atomic "$SOURCE_PLIST" "$PLIST_PATH" 0600
plutil -lint "$PLIST_PATH" >/dev/null

if [[ "$SKIP_LAUNCHCTL" == "1" ]]; then
  echo "archive catalog uploader installed without launchd bootstrap: ${PLIST_PATH}"
  exit 0
fi

"$LAUNCHCTL" bootout "gui/${GUI_UID}/${LABEL}" >/dev/null 2>&1 || true
"$LAUNCHCTL" bootstrap "gui/${GUI_UID}" "$PLIST_PATH"
"$LAUNCHCTL" enable "gui/${GUI_UID}/${LABEL}"
"$LAUNCHCTL" kickstart -k "gui/${GUI_UID}/${LABEL}"
echo "archive catalog uploader installed and started: ${PLIST_PATH}"
