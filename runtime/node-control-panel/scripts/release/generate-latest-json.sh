#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: $0 <assets-dir> <version-tag> [releases-repo]" >&2
  echo "Example: $0 release-assets v19.0.9 synergy-network-hq/synergy-node-control-panel-releases" >&2
  exit 1
fi

ASSETS_DIR="$1"
VERSION_TAG="$2"
RELEASES_REPO="${3:-synergy-network-hq/synergy-node-control-panel-releases}"

if [[ ! -d "$ASSETS_DIR" ]]; then
  echo "Assets directory not found: $ASSETS_DIR" >&2
  exit 1
fi

VERSION_NUM="${VERSION_TAG#v}"
RELEASE_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BASE_URL="https://github.com/${RELEASES_REPO}/releases/download/${VERSION_TAG}"

find_first_match() {
  local pattern
  for pattern in "$@"; do
    local match
    match="$(find "$ASSETS_DIR" -type f -name "$pattern" | sort | head -n 1)"
    if [[ -n "$match" ]]; then
      printf '%s\n' "$match"
      return 0
    fi
  done
  return 1
}

require_match() {
  local label="$1"
  shift
  local match
  match="$(find_first_match "$@")" || {
    echo "Missing ${label} in ${ASSETS_DIR}. Expected one of: $*" >&2
    exit 1
  }
  printf '%s\n' "$match"
}

require_signature_for_bundle() {
  local bundle_path="$1"
  local signature_name
  local signature_path

  signature_name="$(basename "$bundle_path").sig"
  signature_path="$(find "$ASSETS_DIR" -type f -name "$signature_name" | sort | head -n 1)"
  if [[ -z "$signature_path" ]]; then
    echo "Missing updater signature for bundle $(basename "$bundle_path") in ${ASSETS_DIR}" >&2
    exit 1
  fi
  printf '%s\n' "$signature_path"
}

read_signature() {
  tr -d '\r\n' < "$1"
}

urlencode() {
  jq -rn --arg value "$1" '$value | @uri'
}

MAC_BUNDLE_PATH="$(require_match "macOS updater bundle" "*.app.tar.gz")"
LINUX_BUNDLE_PATH="$(require_match "Linux updater bundle" "*.AppImage" "*.AppImage.tar.gz")"
# Windows updater bundle generation is paused while Windows installer support is paused.
# WIN_BUNDLE_PATH="$(require_match "Windows updater bundle" "*.exe" "*.msi" "*.exe.zip" "*.msi.zip" "*.nsis.zip")"
MAC_SIG_PATH="$(require_signature_for_bundle "$MAC_BUNDLE_PATH")"
LINUX_SIG_PATH="$(require_signature_for_bundle "$LINUX_BUNDLE_PATH")"
# WIN_SIG_PATH="$(require_signature_for_bundle "$WIN_BUNDLE_PATH")"

MAC_BUNDLE="$(basename "$MAC_BUNDLE_PATH")"
LINUX_BUNDLE="$(basename "$LINUX_BUNDLE_PATH")"
# WIN_BUNDLE="$(basename "$WIN_BUNDLE_PATH")"
MAC_BUNDLE_URL="$(urlencode "$MAC_BUNDLE")"
LINUX_BUNDLE_URL="$(urlencode "$LINUX_BUNDLE")"
# WIN_BUNDLE_URL="$(urlencode "$WIN_BUNDLE")"

MAC_SIG="$(read_signature "$MAC_SIG_PATH")"
LINUX_SIG="$(read_signature "$LINUX_SIG_PATH")"
# WIN_SIG="$(read_signature "$WIN_SIG_PATH")"

jq -n \
  --arg version "$VERSION_NUM" \
  --arg notes "Synergy Node Control Panel ${VERSION_TAG}" \
  --arg pub_date "$RELEASE_DATE" \
  --arg mac_url "${BASE_URL}/${MAC_BUNDLE_URL}" \
  --arg mac_sig "$MAC_SIG" \
  --arg linux_url "${BASE_URL}/${LINUX_BUNDLE_URL}" \
  --arg linux_sig "$LINUX_SIG" \
  '{
    version: $version,
    notes: $notes,
    pub_date: $pub_date,
    platforms: {
      "darwin-aarch64": {
        url: $mac_url,
        signature: $mac_sig
      },
      "linux-x86_64": {
        url: $linux_url,
        signature: $linux_sig
      }
    }
  }' > "${ASSETS_DIR}/latest.json"

# Windows updater platform is paused while Windows installer support is paused.
# Re-enable by restoring WIN_BUNDLE_PATH / WIN_SIG_PATH above, adding:
#   --arg win_url "${BASE_URL}/${WIN_BUNDLE_URL}"
#   --arg win_sig "$WIN_SIG"
# and adding platforms."windows-x86_64" to the jq payload.

echo "Generated ${ASSETS_DIR}/latest.json"
