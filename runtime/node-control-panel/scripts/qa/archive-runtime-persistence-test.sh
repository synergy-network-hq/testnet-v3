#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLIST_SOURCE="$ROOT_DIR/scripts/archive/network.synergy.archive-validator.plist"
INSTALLER="$ROOT_DIR/scripts/archive/install-archive-validator-runtime.sh"
SUPERVISOR="$ROOT_DIR/scripts/archive/archive-health-supervisor.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-archive-runtime-qa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

plutil -lint "$PLIST_SOURCE" >/dev/null
python3 - "$PLIST_SOURCE" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as handle:
    value = plistlib.load(handle)

assert value["Label"] == "network.synergy.archive-validator"
assert value["ProgramArguments"] == [
    "/usr/local/synergy/bin/synergy-archive-validator-node",
    "start",
    "--config",
    "/Users/Shared/Synergy/archive-validator/workspace/config/node.toml",
]
assert value["UserName"] == "synergynode"
assert value["WorkingDirectory"] == "/Users/Shared/Synergy/archive-validator/workspace"
assert value["StandardOutPath"] == "/Users/Shared/Synergy/archive-validator/logs/archive-validator.out.log"
assert value["StandardErrorPath"] == "/Users/Shared/Synergy/archive-validator/logs/archive-validator.err.log"
assert value["RunAtLoad"] is True
assert value["KeepAlive"] == {"SuccessfulExit": False}
assert value["ThrottleInterval"] >= 10
assert value["ProcessType"] == "Standard"
assert value["Umask"] == 0o27
assert value["SoftResourceLimits"]["NumberOfFiles"] == 65536
assert value["HardResourceLimits"]["NumberOfFiles"] == 65536
PY

rg -Fq 'RUNTIME_LABEL="${SYNERGY_ARCHIVE_RUNTIME_LAUNCHD_LABEL:-network.synergy.archive-validator}"' "$SUPERVISOR"
rg -Fq '"$LAUNCHCTL" bootout "system/${LABEL}"' "$INSTALLER"
rg -Fq 'LEGACY_LABELS=("io.synergynetwork.archive-validator")' "$INSTALLER"
rg -Fq '"$LAUNCHCTL" bootout "system/${legacy_label}"' "$INSTALLER"
rg -Fq '"$LAUNCHCTL" disable "system/${legacy_label}"' "$INSTALLER"
rg -Fq 'mv "$legacy_plist" "${legacy_plist}.disabled-$(date -u +%Y%m%dT%H%M%SZ)"' "$INSTALLER"
rg -Fq '"$LAUNCHCTL" bootstrap system "$PLIST_PATH"' "$INSTALLER"
rg -Fq '"$LAUNCHCTL" enable "system/${LABEL}"' "$INSTALLER"
if rg -Fq '"$LAUNCHCTL" kickstart -k "system/${LABEL}"' "$INSTALLER"; then
  echo "RunAtLoad archive runtime must not be kickstarted immediately after bootstrap" >&2
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  set +e
  "$INSTALLER" >"$TMP_DIR/non-root.out" 2>"$TMP_DIR/non-root.err"
  NON_ROOT_STATUS=$?
  set -e
  [[ "$NON_ROOT_STATUS" == "77" ]]
  rg -Fq 'archive validator runtime installation requires root' "$TMP_DIR/non-root.err"
fi

INSTALL_ROOT="$TMP_DIR/archive-validator"
LAUNCHD_DIR="$TMP_DIR/launchd"
FAKE_BINARY="$TMP_DIR/bin/synergy-archive-validator-node"
FAKE_LAUNCHCTL="$TMP_DIR/bin/launchctl"
mkdir -p "$INSTALL_ROOT/workspace/config" "$(dirname "$FAKE_BINARY")"
printf '%s\n' 'archive workspace state must survive installer updates' > "$INSTALL_ROOT/workspace/state-marker"
printf '%s\n' '[node]' 'role = "archive"' > "$INSTALL_ROOT/workspace/config/node.toml"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > "$FAKE_BINARY"
printf '%s\n' '#!/usr/bin/env bash' 'exit 99' > "$FAKE_LAUNCHCTL"
chmod 0755 "$FAKE_BINARY" "$FAKE_LAUNCHCTL"

MARKER_SHA_BEFORE="$(shasum -a 256 "$INSTALL_ROOT/workspace/state-marker" | awk '{print $1}')"
CONFIG_SHA_BEFORE="$(shasum -a 256 "$INSTALL_ROOT/workspace/config/node.toml" | awk '{print $1}')"

SYNERGY_ARCHIVE_RUNTIME_INSTALL_SKIP_LAUNCHCTL=1 \
SYNERGY_ARCHIVE_RUNTIME_INSTALL_ROOT="$INSTALL_ROOT" \
SYNERGY_ARCHIVE_RUNTIME_BINARY="$FAKE_BINARY" \
SYNERGY_ARCHIVE_RUNTIME_LAUNCHD_DIR="$LAUNCHD_DIR" \
SYNERGY_ARCHIVE_RUNTIME_USER="$(id -un)" \
SYNERGY_LAUNCHCTL="$FAKE_LAUNCHCTL" \
  "$INSTALLER" >/dev/null

INSTALLED_PLIST="$LAUNCHD_DIR/network.synergy.archive-validator.plist"
plutil -lint "$INSTALLED_PLIST" >/dev/null
python3 - "$INSTALLED_PLIST" "$FAKE_BINARY" "$INSTALL_ROOT" "$(id -un)" <<'PY'
import os
import plistlib
import stat
import sys

plist_path, binary, install_root, runtime_user = sys.argv[1:]
with open(plist_path, "rb") as handle:
    value = plistlib.load(handle)

workspace = f"{install_root}/workspace"
assert value["ProgramArguments"] == [binary, "start", "--config", f"{workspace}/config/node.toml"]
assert value["UserName"] == runtime_user
assert value["WorkingDirectory"] == workspace
assert value["StandardOutPath"] == f"{install_root}/logs/archive-validator.out.log"
assert value["StandardErrorPath"] == f"{install_root}/logs/archive-validator.err.log"
assert stat.S_IMODE(os.stat(plist_path).st_mode) == 0o644
assert stat.S_IMODE(os.stat(workspace).st_mode) == 0o750
assert stat.S_IMODE(os.stat(f"{install_root}/logs").st_mode) == 0o750
PY

[[ "$MARKER_SHA_BEFORE" == "$(shasum -a 256 "$INSTALL_ROOT/workspace/state-marker" | awk '{print $1}')" ]]
[[ "$CONFIG_SHA_BEFORE" == "$(shasum -a 256 "$INSTALL_ROOT/workspace/config/node.toml" | awk '{print $1}')" ]]

if compgen -G "$LAUNCHD_DIR/.network.synergy.archive-validator.plist.*" >/dev/null; then
  echo "installer left a staged plist behind" >&2
  exit 1
fi

echo "Archive runtime persistence QA passed: launch contract, crash-only keepalive, atomic install, secure modes, and workspace preservation."
