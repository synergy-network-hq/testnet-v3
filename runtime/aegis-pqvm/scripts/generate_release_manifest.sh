#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/artifacts/checksums"
mkdir -p "$OUT_DIR"

ARTIFACTS=(
  "$ROOT_DIR/Cargo.toml"
  "$ROOT_DIR/Cargo.lock"
  "$ROOT_DIR/build.rs"
  "$ROOT_DIR/README.md"
  "$ROOT_DIR/SECURITY.md"
  "$ROOT_DIR/docs/manual/USER_MANUAL.md"
  "$ROOT_DIR/docs/security/THREAT_MODEL.md"
  "$ROOT_DIR/scripts/run_quality_gates.sh"
)

manifest="$OUT_DIR/release-manifest.txt"
: > "$manifest"
for f in "${ARTIFACTS[@]}"; do
  if [[ -f "$f" ]]; then
    rel="${f#$ROOT_DIR/}"
    sha=$(shasum -a 256 "$f" | awk '{print $1}')
    echo "$sha  $rel" | tee -a "$manifest"
  fi
done

cp "$manifest" "$OUT_DIR/release-manifest.sha256"

echo "Release manifest created at $manifest"
