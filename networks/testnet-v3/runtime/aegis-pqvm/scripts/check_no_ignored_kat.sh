#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

violations=$(rg -n '#\[(ignore|cfg\(.*ignore.*\))' tests/kat*.rs tests/*validation*.rs tests/*security*.rs 2>/dev/null || true)
if [[ -n "$violations" ]]; then
  echo "Ignored KAT/validation/security tests are not permitted:"
  echo "$violations"
  exit 1
fi

echo "KAT ignore-policy check passed."
