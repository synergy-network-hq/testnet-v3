#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/artifacts/sbom"
mkdir -p "$OUT_DIR"

find "$ROOT_DIR" -maxdepth 3 -type f -name '*.cdx.json' ! -path "$OUT_DIR/*" -delete

(
  cd "$ROOT_DIR"
  cargo install cargo-cyclonedx --locked >/dev/null 2>&1 || true
  cargo cyclonedx --all-features --format json
)

generated="$(find "$ROOT_DIR" -maxdepth 3 -type f -name '*.cdx.json' ! -path "$OUT_DIR/*" | head -n1 || true)"
if [[ -z "$generated" ]]; then
  echo "SBOM generation failed"
  exit 1
fi

cp "$generated" "$OUT_DIR/aegis-pqvm.cdx.json"
rm -f "$generated"

# Normalize host-specific absolute paths to a stable release path.
perl -pi -e "s|\\Q$ROOT_DIR\\E|/workspace/aegis-pqvm|g" "$OUT_DIR/aegis-pqvm.cdx.json"

ABS_PATH_PATTERN='/(Users|home)/|C:\\Users\\'
if rg -n "$ABS_PATH_PATTERN" "$OUT_DIR/aegis-pqvm.cdx.json" >/dev/null 2>&1; then
  echo "SBOM contains user-specific absolute paths"
  rg -n "$ABS_PATH_PATTERN" "$OUT_DIR/aegis-pqvm.cdx.json" || true
  exit 1
fi

echo "SBOM generated at $OUT_DIR/aegis-pqvm.cdx.json"
