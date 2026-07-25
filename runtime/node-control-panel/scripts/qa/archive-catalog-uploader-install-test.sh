#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLIST_SOURCE="$ROOT_DIR/scripts/archive/network.synergy.archive-catalog-uploader.plist"
UPLOADER="$ROOT_DIR/scripts/archive/upload-public-catalog-local.sh"
INSTALLER="$ROOT_DIR/scripts/archive/install-archive-catalog-uploader.sh"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-archive-catalog-qa.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

plutil -lint "$PLIST_SOURCE" >/dev/null
python3 - "$PLIST_SOURCE" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as handle:
    value = plistlib.load(handle)
assert value["Label"] == "network.synergy.archive-catalog-uploader"
assert value["RunAtLoad"] is True
assert value["StartInterval"] == 300
assert value["ProgramArguments"][:2] == ["/bin/bash", "-lc"]
assert "upload-public-catalog.sh" in value["ProgramArguments"][2]
assert "mkdir -p" in value["ProgramArguments"][2]
assert value["ProcessType"] == "Background"
PY

rg -Fq 'require-archive-health-green.sh' "$UPLOADER"
rg -Fq 'ssh -o BatchMode=yes "$REMOTE_ALIAS" "$REMOTE_HEALTH_GATE"' "$UPLOADER"
if rg -n 'AWS_ACCESS_KEY|AWS_SECRET|CLOUDFLARE_API_TOKEN|R2_ACCESS|credential|password|secret' "$INSTALLER" "$PLIST_SOURCE"; then
  echo "archive catalog installer or plist exposes credential material" >&2
  exit 1
fi

HOME_DIR="$TMP_DIR/home"
LAUNCHCTL_LOG="$TMP_DIR/launchctl.log"
FAKE_LAUNCHCTL="$TMP_DIR/launchctl"
cat > "$FAKE_LAUNCHCTL" <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail
printf '%s\n' "$*" >> "$LAUNCHCTL_LOG"
SH
chmod 0700 "$FAKE_LAUNCHCTL"

run_install() {
  HOME="$HOME_DIR" \
  SYNERGY_ARCHIVE_CATALOG_INSTALL_SKIP_LAUNCHCTL=1 \
  SYNERGY_ARCHIVE_CATALOG_LAUNCHD_UID=4242 \
  "$INSTALLER" >/dev/null
}

run_install
run_install
INSTALLED_SCRIPT="$HOME_DIR/Library/Application Support/Synergy Network/archive-catalog-freshness/upload-public-catalog.sh"
INSTALLED_PLIST="$HOME_DIR/Library/LaunchAgents/network.synergy.archive-catalog-uploader.plist"
cmp "$UPLOADER" "$INSTALLED_SCRIPT"
cmp "$PLIST_SOURCE" "$INSTALLED_PLIST"
[[ "$(stat -f '%Lp' "$INSTALLED_SCRIPT")" == 700 ]]
[[ "$(stat -f '%Lp' "$INSTALLED_PLIST")" == 600 ]]
plutil -lint "$INSTALLED_PLIST" >/dev/null
[[ "$(find "$HOME_DIR" -name '.network.synergy.archive-catalog-uploader.*' -print | wc -l | tr -d ' ')" == 0 ]]

HOME="$HOME_DIR" \
SYNERGY_ARCHIVE_CATALOG_INSTALL_SKIP_LAUNCHCTL=0 \
SYNERGY_ARCHIVE_CATALOG_LAUNCHD_UID=4242 \
SYNERGY_LAUNCHCTL="$FAKE_LAUNCHCTL" \
LAUNCHCTL_LOG="$LAUNCHCTL_LOG" \
  "$INSTALLER" >/dev/null
[[ "$(sed -n '1p' "$LAUNCHCTL_LOG")" == "bootout gui/4242/network.synergy.archive-catalog-uploader" ]]
[[ "$(sed -n '2p' "$LAUNCHCTL_LOG")" == "bootstrap gui/4242 $INSTALLED_PLIST" ]]
[[ "$(sed -n '3p' "$LAUNCHCTL_LOG")" == "enable gui/4242/network.synergy.archive-catalog-uploader" ]]
[[ "$(sed -n '4p' "$LAUNCHCTL_LOG")" == "kickstart -k gui/4242/network.synergy.archive-catalog-uploader" ]]

echo "Archive catalog uploader QA passed: plist interval, idempotent install, validation, secure modes, and GUI launchd lifecycle."
