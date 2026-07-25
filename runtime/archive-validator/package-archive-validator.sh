#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
GENERIC_ARTIFACT="${ROOT_DIR}/synergy-archive-validator-testnet-v3.zip"
LINUX_ARTIFACT="${ROOT_DIR}/synergy-archive-validator-testnet-v3-linux-x64.zip"
MACOS_ARTIFACT="${ROOT_DIR}/synergy-archive-validator-testnet-v3-macos-universal.zip"
WINDOWS_ARTIFACT="${ROOT_DIR}/synergy-archive-validator-testnet-v3-windows-receiver.zip"
TARGET="linux"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --linux) TARGET="linux"; shift ;;
    --macos) TARGET="macos"; shift ;;
    --windows) TARGET="windows"; shift ;;
    --all) TARGET="all"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

forbidden_files="$(
  find "${ROOT_DIR}" \
    \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '.env' -o -name 'id_*' \) \
    -type f ! -name '.env.example' -print
)"
forbidden_dirs="$(
  find "${ROOT_DIR}" \
    \( -path '*/data/*' -o -path '*/snapshots/*' -o -path '*/logs/*' -o -path '*/evidence/*' -o -path '*/chain-data/*' \) \
    -type f -print
)"
if [[ -n "${forbidden_files}${forbidden_dirs}" ]]; then
  echo "Refusing to package private keys, identity files, secrets, chain data, snapshots, logs, or evidence." >&2
  printf '%s\n%s\n' "${forbidden_files}" "${forbidden_dirs}" >&2
  exit 1
fi

mkdir -p "${DIST_DIR}"

package_linux() {
  rm -f "${LINUX_ARTIFACT}" "${GENERIC_ARTIFACT}"
  cd "${ROOT_DIR}/.."
  zip -r "${LINUX_ARTIFACT}" archive-validator \
    -x 'archive-validator/synergy-archive-validator-testnet-v3-*.zip' \
    -x 'archive-validator/dist/*' \
    -x 'archive-validator/**/.DS_Store' \
    -x 'archive-validator/**/*.key' \
    -x 'archive-validator/**/*.pem' \
    -x 'archive-validator/**/*.p12' \
    -x 'archive-validator/.env' \
    -x 'archive-validator/**/data/**' \
    -x 'archive-validator/**/snapshots/**' \
    -x 'archive-validator/**/logs/**' \
    -x 'archive-validator/**/evidence/**'
  cp "${LINUX_ARTIFACT}" "${GENERIC_ARTIFACT}"
  (cd "${ROOT_DIR}" && shasum -a 256 "$(basename "${LINUX_ARTIFACT}")" > "${DIST_DIR}/SHA256SUMS.linux")
  (cd "${ROOT_DIR}" && shasum -a 256 "$(basename "${GENERIC_ARTIFACT}")" > "${DIST_DIR}/SHA256SUMS")
  echo "Created ${LINUX_ARTIFACT}"
  echo "Created ${GENERIC_ARTIFACT}"
}

package_macos() {
  "${ROOT_DIR}/macos/build-macos-pkg.sh"
  local pkg="${ROOT_DIR}/macos/dist/SynergyArchiveValidator.pkg"
  [[ -f "${pkg}" ]] || { echo "macOS package was not produced" >&2; exit 1; }
  rm -f "${MACOS_ARTIFACT}"
  rm -rf "${DIST_DIR}/macos-universal"
  mkdir -p "${DIST_DIR}/macos-universal"
  install -m 0644 "${pkg}" "${DIST_DIR}/macos-universal/SynergyArchiveValidator.pkg"
  install -m 0644 "${ROOT_DIR}/macos/README-GATEKEEPER.md" "${DIST_DIR}/macos-universal/README-GATEKEEPER.md"
  install -m 0644 "${ROOT_DIR}/docs/MACOS_INSTALL.md" "${DIST_DIR}/macos-universal/MACOS_INSTALL.md"
  (cd "${DIST_DIR}/macos-universal" && shasum -a 256 SynergyArchiveValidator.pkg > SHA256SUMS)
  (cd "${DIST_DIR}/macos-universal" && zip -r "${MACOS_ARTIFACT}" SynergyArchiveValidator.pkg SHA256SUMS README-GATEKEEPER.md MACOS_INSTALL.md)
  echo "Created ${MACOS_ARTIFACT}"
}

package_windows() {
  rm -f "${WINDOWS_ARTIFACT}"
  rm -rf "${DIST_DIR}/windows-receiver"
  mkdir -p "${DIST_DIR}/windows-receiver/windows" "${DIST_DIR}/windows-receiver/docs" "${DIST_DIR}/windows-receiver/config"
  install -m 0644 "${ROOT_DIR}/README.md" "${DIST_DIR}/windows-receiver/README.md"
  install -m 0644 "${ROOT_DIR}/windows/"*.ps1 "${DIST_DIR}/windows-receiver/windows/"
  install -m 0644 "${ROOT_DIR}/docs/WINDOWS_VALIDATOR_SNAPSHOT_RESTORE.md" "${DIST_DIR}/windows-receiver/docs/"
  install -m 0644 "${ROOT_DIR}/docs/NEW_VALIDATOR_FAST_SYNC.md" "${DIST_DIR}/windows-receiver/docs/"
  install -m 0644 "${ROOT_DIR}/docs/SNAPSHOT_FORMAT.md" "${DIST_DIR}/windows-receiver/docs/"
  install -m 0644 "${ROOT_DIR}/docs/SNAPSHOT_VERIFICATION.md" "${DIST_DIR}/windows-receiver/docs/"
  install -m 0644 "${ROOT_DIR}/config/snapshot-policy.testnet.toml" "${DIST_DIR}/windows-receiver/config/"
  (cd "${DIST_DIR}/windows-receiver" && zip -r "${WINDOWS_ARTIFACT}" README.md windows docs config)
  (cd "${ROOT_DIR}" && shasum -a 256 "$(basename "${WINDOWS_ARTIFACT}")" > "${DIST_DIR}/SHA256SUMS.windows")
  echo "Created ${WINDOWS_ARTIFACT}"
}

case "${TARGET}" in
  linux) package_linux ;;
  macos) package_macos ;;
  windows) package_windows ;;
  all) package_linux; package_macos; package_windows ;;
esac
