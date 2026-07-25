#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
BUILD_ROOT="${ROOT_DIR}/dist/macos-m4"
PAYLOAD="${BUILD_ROOT}/synergy-archive-validator-testnet-v3-macos-m4"
ARTIFACT="${ROOT_DIR}/dist/synergy-archive-validator-testnet-v3-macos-m4-storage-volume.zip"
if [[ -d /Volumes/xcode && -w /Volumes/xcode ]]; then
  DEFAULT_CARGO_TARGET_DIR="/Volumes/xcode/synergy-archive-macos-m4-target"
else
  DEFAULT_CARGO_TARGET_DIR="${TMPDIR:-/tmp}/synergy-archive-macos-m4-target"
fi
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${DEFAULT_CARGO_TARGET_DIR}}"
export CARGO_TARGET_DIR

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]] || {
  echo "Build the M4 handoff artifact on an Apple Silicon Mac." >&2
  exit 1
}
command -v cargo >/dev/null
command -v zip >/dev/null
command -v codesign >/dev/null

clear_quarantine() {
  command -v xattr >/dev/null 2>&1 || return 0
  for path in "$@"; do
    [[ -e "${path}" ]] || continue
    xattr -dr com.apple.quarantine "${path}" >/dev/null 2>&1 || true
  done
}

adhoc_sign_and_verify() {
  local binary="$1"
  codesign --force --sign - "${binary}" >/dev/null 2>&1 || {
    echo "failed to ad-hoc sign payload binary: ${binary}" >&2
    exit 1
  }
  codesign --verify --verbose=2 "${binary}" >/dev/null 2>&1 || {
    echo "failed to verify payload signature: ${binary}" >&2
    exit 1
  }
}

cd "${REPO_ROOT}"
mkdir -p "${CARGO_TARGET_DIR}"
cargo build --release -p synergy-testnet --bin aegis-pqvm --bin synergy-archive-validator-node

rm -rf "${BUILD_ROOT}"
mkdir -p "${PAYLOAD}/"{bin,config,launchd,docs}
install -m 0755 "${CARGO_TARGET_DIR}/release/aegis-pqvm" "${PAYLOAD}/bin/aegis-pqvm"
install -m 0755 "${CARGO_TARGET_DIR}/release/synergy-archive-validator-node" "${PAYLOAD}/bin/synergy-archive-validator-node"
install -m 0755 "${ROOT_DIR}/macos/archive-authority.py" "${PAYLOAD}/bin/synergy-archive"
install -m 0755 "${ROOT_DIR}/macos-m4/setup-archive-validator-m4.sh" "${PAYLOAD}/setup-archive-validator-m4.sh"
install -m 0755 "${ROOT_DIR}/macos-m4/archive-paths.sh" "${PAYLOAD}/archive-paths.sh"
install -m 0755 "${ROOT_DIR}/macos-m4/restore-archive-bootstrap-m4.sh" "${PAYLOAD}/restore-archive-bootstrap-m4.sh"
install -m 0755 "${ROOT_DIR}/macos-m4/verify-archive-validator-m4.sh" "${PAYLOAD}/verify-archive-validator-m4.sh"
install -m 0755 "${ROOT_DIR}/macos-m4/run-isolated-mac-acceptance.sh" "${PAYLOAD}/run-isolated-mac-acceptance.sh"
install -m 0644 "${ROOT_DIR}/macos-m4/launchd/"*.plist.in "${PAYLOAD}/launchd/"
install -m 0644 "${REPO_ROOT}/templates/archive-validator.toml" "${PAYLOAD}/config/node.toml.template"
install -m 0644 "${REPO_ROOT}/config/genesis.json" "${PAYLOAD}/config/genesis.json"
install -m 0644 "${REPO_ROOT}/config/consensus-fork-migration.json" "${PAYLOAD}/config/consensus-fork-migration.json"
install -m 0644 "${ROOT_DIR}/config/snapshot-policy.testnet.toml" "${PAYLOAD}/config/snapshot-policy.toml"
install -m 0644 "${ROOT_DIR}/docs/MACOS_M4_HANDOFF.md" "${PAYLOAD}/docs/MACOS_M4_HANDOFF.md"

clear_quarantine "${PAYLOAD}"
for binary in \
  "${PAYLOAD}/bin/aegis-pqvm" \
  "${PAYLOAD}/bin/synergy-archive-validator-node" \
  "${PAYLOAD}/bin/synergy-archive"
do
  adhoc_sign_and_verify "${binary}"
done
clear_quarantine "${PAYLOAD}"

(
  cd "${PAYLOAD}"
  shasum -a 256 bin/aegis-pqvm bin/synergy-archive-validator-node bin/synergy-archive > BINARY_SHA256SUMS
)

python3 - "${REPO_ROOT}" "${PAYLOAD}/SOURCE-PROVENANCE.json" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone

repo, output = sys.argv[1:3]
def git(*args):
    return subprocess.check_output(["git", "-C", repo, *args], text=True).strip()
dirty = git("status", "--short", "--", ".", ":(exclude)archive-validator/dist", ":(exclude)dist").splitlines()
payload = {
    "schema": "synergy-archive-macos-m4-source-provenance-v1",
    "built_at_utc": datetime.now(timezone.utc).isoformat(),
    "source_commit": git("rev-parse", "HEAD"),
    "source_dirty": bool(dirty),
    "source_dirty_paths": dirty,
    "target": "apple-silicon-arm64",
    "chain_id": 1264,
    "network_id": "synergy-testnet-v3",
}
open(output, "w", encoding="utf-8").write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY

forbidden="$(find "${PAYLOAD}" \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '.env' -o -name 'node.env' \) -type f -print)"
[[ -z "${forbidden}" ]] || {
  echo "Refusing to package private key or secret material:" >&2
  printf '%s\n' "${forbidden}" >&2
  exit 1
}

forbidden_storage_paths="$(grep -R -F \
  -e '/Library/Application Support/Synergy/archive-validator' \
  -e '/srv/synergy-snapshots' \
  -e '/Volumes/Synergy_Archive/archive-validator/workspace' \
  -e '/Volumes/Synergy_Archive/archive-validator/logs' \
  -e '/Volumes/Synergy_Archive/archive-validator/evidence' \
  -e '/Volumes/Synergy_Archive/archive-validator/tmp' \
  "${PAYLOAD}" || true)"
[[ -z "${forbidden_storage_paths}" ]] || {
  echo "Refusing to package forbidden archive storage paths:" >&2
  printf '%s\n' "${forbidden_storage_paths}" >&2
  exit 1
}

rm -f "${ARTIFACT}"
clear_quarantine "${PAYLOAD}"
(cd "${BUILD_ROOT}" && zip -qr "${ARTIFACT}" "$(basename "${PAYLOAD}")")
clear_quarantine "${ARTIFACT}"
(cd "${ROOT_DIR}/dist" && shasum -a 256 "$(basename "${ARTIFACT}")" > "$(basename "${ARTIFACT}").sha256")
echo "artifact=${ARTIFACT}"
echo "checksum=${ARTIFACT}.sha256"
echo "runtime_root=/Users/Shared/Synergy/archive-validator"
echo "publish_root=/Volumes/Synergy_Archive/archive-validator/snapshots"
echo "incoming_bootstrap=/Volumes/Synergy_Archive/archive-validator/incoming/bootstrap"
