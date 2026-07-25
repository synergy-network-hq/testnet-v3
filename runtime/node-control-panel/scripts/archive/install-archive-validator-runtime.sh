#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_PLIST="${SOURCE_DIR}/network.synergy.archive-validator.plist"
LABEL="network.synergy.archive-validator"
LEGACY_LABELS=("io.synergynetwork.archive-validator")
DEFAULT_INSTALL_ROOT="/Users/Shared/Synergy/archive-validator"
DEFAULT_BINARY="/usr/local/synergy/bin/synergy-archive-validator-node"
DEFAULT_LAUNCHD_DIR="/Library/LaunchDaemons"
DEFAULT_RUNTIME_USER="synergynode"
SKIP_LAUNCHCTL="${SYNERGY_ARCHIVE_RUNTIME_INSTALL_SKIP_LAUNCHCTL:-0}"
LAUNCHCTL="${SYNERGY_LAUNCHCTL:-/bin/launchctl}"

case "$SKIP_LAUNCHCTL" in
  0|1) ;;
  *) echo "SYNERGY_ARCHIVE_RUNTIME_INSTALL_SKIP_LAUNCHCTL must be 0 or 1" >&2; exit 64 ;;
esac

if [[ "$SKIP_LAUNCHCTL" != "1" && "$EUID" -ne 0 ]]; then
  echo "archive validator runtime installation requires root" >&2
  exit 77
fi

if [[ "$SKIP_LAUNCHCTL" == "1" ]]; then
  INSTALL_ROOT="${SYNERGY_ARCHIVE_RUNTIME_INSTALL_ROOT:-$DEFAULT_INSTALL_ROOT}"
  BINARY_PATH="${SYNERGY_ARCHIVE_RUNTIME_BINARY:-$DEFAULT_BINARY}"
  LAUNCHD_DIR="${SYNERGY_ARCHIVE_RUNTIME_LAUNCHD_DIR:-$DEFAULT_LAUNCHD_DIR}"
  RUNTIME_USER="${SYNERGY_ARCHIVE_RUNTIME_USER:-$DEFAULT_RUNTIME_USER}"
  FILE_OWNER="$(id -un)"
  FILE_GROUP="$(id -gn)"
else
  INSTALL_ROOT="$DEFAULT_INSTALL_ROOT"
  BINARY_PATH="$DEFAULT_BINARY"
  LAUNCHD_DIR="$DEFAULT_LAUNCHD_DIR"
  RUNTIME_USER="$DEFAULT_RUNTIME_USER"
  if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
    echo "required archive validator runtime user does not exist: ${RUNTIME_USER}" >&2
    exit 67
  fi
  FILE_OWNER="root"
  FILE_GROUP="wheel"
fi

WORKSPACE_DIR="${INSTALL_ROOT}/workspace"
CONFIG_DIR="${WORKSPACE_DIR}/config"
CONFIG_PATH="${CONFIG_DIR}/node.toml"
LOG_DIR="${INSTALL_ROOT}/logs"
PLIST_PATH="${LAUNCHD_DIR}/${LABEL}.plist"

[[ -f "$SOURCE_PLIST" ]] || { echo "missing launchd plist template: ${SOURCE_PLIST}" >&2; exit 66; }
[[ -x "$BINARY_PATH" ]] || { echo "archive validator runtime binary is not executable: ${BINARY_PATH}" >&2; exit 66; }
[[ -f "$CONFIG_PATH" ]] || { echo "archive validator config is missing: ${CONFIG_PATH}" >&2; exit 66; }
[[ ! -L "$LAUNCHD_DIR" ]] || { echo "launchd directory must not be a symbolic link: ${LAUNCHD_DIR}" >&2; exit 73; }

if [[ "$SKIP_LAUNCHCTL" == "1" ]]; then
  install -d -m 0750 "$INSTALL_ROOT" "$WORKSPACE_DIR" "$CONFIG_DIR" "$LOG_DIR"
  install -d -m 0755 "$LAUNCHD_DIR"
  RUNTIME_GROUP="$(id -gn)"
else
  RUNTIME_GROUP="$(id -gn "$RUNTIME_USER")"
  install -d -o "$RUNTIME_USER" -g "$RUNTIME_GROUP" -m 0750 \
    "$INSTALL_ROOT" "$WORKSPACE_DIR" "$CONFIG_DIR" "$LOG_DIR"
fi

STAGED_PLIST="$(mktemp "${LAUNCHD_DIR}/.${LABEL}.plist.XXXXXX")"
cleanup() {
  [[ -z "${STAGED_PLIST:-}" ]] || rm -f "$STAGED_PLIST"
}
trap cleanup EXIT

python3 - "$SOURCE_PLIST" "$STAGED_PLIST" "$BINARY_PATH" "$CONFIG_PATH" "$RUNTIME_USER" "$WORKSPACE_DIR" "$LOG_DIR" <<'PY'
import plistlib
import sys

source, destination, binary, config, runtime_user, workspace, log_dir = sys.argv[1:]
with open(source, "rb") as handle:
    value = plistlib.load(handle)

value["ProgramArguments"] = [binary, "start", "--config", config]
value["UserName"] = runtime_user
value["WorkingDirectory"] = workspace
value["StandardOutPath"] = f"{log_dir}/archive-validator.out.log"
value["StandardErrorPath"] = f"{log_dir}/archive-validator.err.log"

with open(destination, "wb") as handle:
    plistlib.dump(value, handle, fmt=plistlib.FMT_XML, sort_keys=False)
PY

plutil -lint "$STAGED_PLIST" >/dev/null
chmod 0644 "$STAGED_PLIST"
chown "${FILE_OWNER}:${FILE_GROUP}" "$STAGED_PLIST"
mv -f "$STAGED_PLIST" "$PLIST_PATH"
STAGED_PLIST=""
plutil -lint "$PLIST_PATH" >/dev/null

if [[ "$SKIP_LAUNCHCTL" == "1" ]]; then
  echo "archive validator runtime installed without launchd bootstrap: ${PLIST_PATH}"
  exit 0
fi

for legacy_label in "${LEGACY_LABELS[@]}"; do
  legacy_plist="${LAUNCHD_DIR}/${legacy_label}.plist"
  "$LAUNCHCTL" bootout "system/${legacy_label}" >/dev/null 2>&1 || true
  "$LAUNCHCTL" disable "system/${legacy_label}" >/dev/null 2>&1 || true
  if [[ -f "$legacy_plist" ]]; then
    mv "$legacy_plist" "${legacy_plist}.disabled-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
done

"$LAUNCHCTL" bootout "system/${LABEL}" >/dev/null 2>&1 || true
"$LAUNCHCTL" enable "system/${LABEL}"
"$LAUNCHCTL" bootstrap system "$PLIST_PATH"
echo "archive validator runtime installed and bootstrapped: ${PLIST_PATH}"
