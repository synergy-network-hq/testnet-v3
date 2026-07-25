#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MACOS_DIR="${ROOT_DIR}/macos"
DIST_DIR="${MACOS_DIR}/dist"
WORK_DIR="${MACOS_DIR}/build"
PAYLOAD_DIR="${WORK_DIR}/payload"
SCRIPTS_DIR="${WORK_DIR}/scripts"
COMPONENT_PKG="${DIST_DIR}/SynergyArchiveValidator.component.pkg"
SIGNED_PKG="${DIST_DIR}/SynergyArchiveValidator.pkg"

: "${SYNERGY_ARCHIVE_BINARY:?Set SYNERGY_ARCHIVE_BINARY to the trusted universal synergy-archive executable.}"
: "${DEVELOPER_ID_APPLICATION:?Set DEVELOPER_ID_APPLICATION to the Synergy Developer ID Application signing identity.}"
: "${DEVELOPER_ID_INSTALLER:?Set DEVELOPER_ID_INSTALLER to the Synergy Developer ID Installer signing identity.}"
: "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID to the Synergy Apple Developer Team ID.}"
: "${NOTARYTOOL_KEY_ID:?Set NOTARYTOOL_KEY_ID for Apple notarization.}"
: "${NOTARYTOOL_ISSUER_ID:?Set NOTARYTOOL_ISSUER_ID for Apple notarization.}"
: "${NOTARYTOOL_KEY_PATH:?Set NOTARYTOOL_KEY_PATH to the App Store Connect API private key path.}"

[[ "$(uname -s)" == "Darwin" ]] || { echo "macOS package build must run on macOS." >&2; exit 1; }
[[ -x "${SYNERGY_ARCHIVE_BINARY}" ]] || { echo "SYNERGY_ARCHIVE_BINARY is not executable." >&2; exit 1; }
command -v codesign >/dev/null 2>&1 || { echo "codesign is required." >&2; exit 1; }
command -v pkgbuild >/dev/null 2>&1 || { echo "pkgbuild is required." >&2; exit 1; }
command -v productbuild >/dev/null 2>&1 || { echo "productbuild is required." >&2; exit 1; }
command -v xcrun >/dev/null 2>&1 || { echo "xcrun/notarytool is required." >&2; exit 1; }

rm -rf "${WORK_DIR}" "${DIST_DIR}"
mkdir -p "${PAYLOAD_DIR}/usr/local/synergy/bin"
mkdir -p "${PAYLOAD_DIR}/usr/local/synergy/share/archive-validator"
mkdir -p "${PAYLOAD_DIR}/Volumes/Synergy_Archive/archive-validator/config"
mkdir -p "${PAYLOAD_DIR}/Library/LaunchDaemons"
mkdir -p "${SCRIPTS_DIR}" "${DIST_DIR}"

install -m 0755 "${SYNERGY_ARCHIVE_BINARY}" "${PAYLOAD_DIR}/usr/local/synergy/bin/synergy-archive"
install -m 0755 "${MACOS_DIR}/uninstall-macos.sh" "${PAYLOAD_DIR}/usr/local/synergy/share/archive-validator/uninstall-macos.sh"
install -m 0644 "${ROOT_DIR}/config/archive-validator.testnet.toml" "${PAYLOAD_DIR}/Volumes/Synergy_Archive/archive-validator/config/archive-validator.toml"
install -m 0644 "${ROOT_DIR}/config/snapshot-policy.testnet.toml" "${PAYLOAD_DIR}/Volumes/Synergy_Archive/archive-validator/config/snapshot-policy.toml"
install -m 0644 "${ROOT_DIR}/config/archive-api.testnet.toml" "${PAYLOAD_DIR}/Volumes/Synergy_Archive/archive-validator/config/archive-api.toml"
install -m 0644 "${ROOT_DIR}/launchd/"*.plist "${PAYLOAD_DIR}/Library/LaunchDaemons/"
install -m 0755 "${MACOS_DIR}/preinstall" "${SCRIPTS_DIR}/preinstall"
install -m 0755 "${MACOS_DIR}/postinstall" "${SCRIPTS_DIR}/postinstall"

codesign --force --options runtime --timestamp \
  --entitlements "${MACOS_DIR}/entitlements.plist" \
  --sign "${DEVELOPER_ID_APPLICATION}" \
  "${PAYLOAD_DIR}/usr/local/synergy/bin/synergy-archive"
codesign --verify --strict --verbose=2 "${PAYLOAD_DIR}/usr/local/synergy/bin/synergy-archive"

pkgbuild \
  --root "${PAYLOAD_DIR}" \
  --scripts "${SCRIPTS_DIR}" \
  --identifier "io.synergynetwork.archive-validator" \
  --version "12.2.19" \
  --install-location "/" \
  "${COMPONENT_PKG}"

productbuild \
  --sign "${DEVELOPER_ID_INSTALLER}" \
  --timestamp \
  --package "${COMPONENT_PKG}" \
  "${SIGNED_PKG}"

pkgutil --check-signature "${SIGNED_PKG}"
spctl --assess --type install --verbose=4 "${SIGNED_PKG}"

xcrun notarytool submit "${SIGNED_PKG}" \
  --key "${NOTARYTOOL_KEY_PATH}" \
  --key-id "${NOTARYTOOL_KEY_ID}" \
  --issuer "${NOTARYTOOL_ISSUER_ID}" \
  --team-id "${APPLE_TEAM_ID}" \
  --wait

xcrun stapler staple "${SIGNED_PKG}"
spctl --assess --type install --verbose=4 "${SIGNED_PKG}"
pkgutil --check-signature "${SIGNED_PKG}"

(cd "${DIST_DIR}" && shasum -a 256 SynergyArchiveValidator.pkg > SHA256SUMS)
echo "Created signed and notarized ${SIGNED_PKG}"
