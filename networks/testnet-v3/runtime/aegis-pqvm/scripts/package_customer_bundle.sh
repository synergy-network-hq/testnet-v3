#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/artifacts/package"
mkdir -p "$OUT_DIR"

STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-pqvm-bundle.XXXXXX")"
cleanup() {
  rm -rf "$STAGE_DIR"
}
trap cleanup EXIT

# Build a curated release tree that is sufficient to compile/audit PQVM without
# bundling unrelated reference/test assets.
INCLUDE_PATHS=(
  "Cargo.toml"
  "Cargo.lock"
  "LICENSE"
  "README.md"
  "SECURITY.md"
  "PQVM_USAGE_MANUAL.md"
  "build.rs"
  "src"
  "examples"
  "docs"
  "scripts"
  ".github/workflows"
  "pqcore"
  "vendor/pqcrypto-internals"
  "vendor/pqcrypto-traits"
  "vendor/nist_wrappers"
  "vendor/pqnist/NIST-ml-kem/Reference_Implementation/crypto_kem/kyber512"
  "vendor/pqnist/NIST-ml-kem/Reference_Implementation/crypto_kem/kyber768"
  "vendor/pqnist/NIST-ml-kem/Reference_Implementation/crypto_kem/kyber1024"
)

for rel in "${INCLUDE_PATHS[@]}"; do
  src="$ROOT_DIR/$rel"
  if [[ -e "$src" ]]; then
    mkdir -p "$STAGE_DIR/$(dirname "$rel")"
    cp -R "$src" "$STAGE_DIR/$rel"
  fi
done

# Prune non-production files from vendored NIST ML-KEM reference trees.
find "$STAGE_DIR/vendor/pqnist/NIST-ml-kem/Reference_Implementation/crypto_kem" \
  -type f \
  \( -name 'rng.c' -o -name 'rng.c.backup' -o -name 'PQCgenKAT_kem.c' -o -name 'test_speed.c' -o -name 'speed_print.c' -o -name 'speed_print.h' -o -name 'Makefile' \) \
  -delete

# Prune PQCore auxiliary test/dev assets that are not part of production build scope.
find "$STAGE_DIR/pqcore" -type d \( -name '.github' -o -name 'test' -o -name 'tests' \) -prune -exec rm -rf {} +
find "$STAGE_DIR/pqcore" -type f \( -name 'PQCgenKAT*' -o -name 'test_*' -o -name '*_test.*' -o -name 'benchmark*' -o -name '*bench*' -o -name '*.py' -o -name '*.sh' -o -name 'Makefile' \) -delete

# Enforce release-scope policy: no known non-production marker strings.
NON_PROD_PATTERN='NOT cryptographically secure but serves as a place[h]older|place[h]older implementation|st[u]b implementation|pseu[d]o[- ]?code'
if rg -n -i "$NON_PROD_PATTERN" "$STAGE_DIR" --glob '!**/package_customer_bundle.sh' >/dev/null 2>&1; then
  echo "Release-scope non-production marker detected in curated bundle." >&2
  rg -n -i "$NON_PROD_PATTERN" "$STAGE_DIR" --glob '!**/package_customer_bundle.sh' || true
  exit 1
fi

# Enforce no user-specific absolute paths in release payload.
ABS_PATH_PATTERN='/(Users|home)/|C:\\Users\\'
if rg -n "$ABS_PATH_PATTERN" "$STAGE_DIR" \
  --glob '!**/check_no_absolute_paths.sh' \
  --glob '!**/generate_sbom.sh' \
  --glob '!**/package_customer_bundle.sh' >/dev/null 2>&1; then
  echo "Release-scope absolute path detected in curated bundle." >&2
  rg -n "$ABS_PATH_PATTERN" "$STAGE_DIR" \
    --glob '!**/check_no_absolute_paths.sh' \
    --glob '!**/generate_sbom.sh' \
    --glob '!**/package_customer_bundle.sh' || true
  exit 1
fi

BUNDLE_NAME="aegis-pqvm-customer-bundle-$(date -u +%Y%m%dT%H%M%SZ)"
BUNDLE_PATH="$OUT_DIR/$BUNDLE_NAME.tgz"
tar -czf "$BUNDLE_PATH" -C "$STAGE_DIR" .

(
  cd "$OUT_DIR"
  shasum -a 256 "$BUNDLE_NAME.tgz" > "$BUNDLE_NAME.tgz.sha256"
)

echo "Customer bundle created: $BUNDLE_PATH"
