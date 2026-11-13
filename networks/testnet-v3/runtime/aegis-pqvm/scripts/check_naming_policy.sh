#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DISALLOWED='\b(kyber|dilithium|falcon|sphincs\+?)\b'
TARGETS=(
  "README.md"
  "SECURITY.md"
  "PQVM_USAGE_MANUAL.md"
  "Cargo.toml"
  "docs"
  "src/lib.rs"
  "src/key_lifecycle.rs"
  "src/security/mod.rs"
  "src/integrations"
)

violations=$(rg -n -i "$DISALLOWED" "${TARGETS[@]}" 2>/dev/null || true)
if [[ -n "$violations" ]]; then
  echo "Naming-policy violations detected (use ML-KEM / ML-DSA / FN-DSA / SLH-DSA canonical names):"
  echo "$violations"
  exit 1
fi

echo "Naming policy check passed."
