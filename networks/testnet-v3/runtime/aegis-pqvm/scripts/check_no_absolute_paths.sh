#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

violations=$(rg -n '/Users/|/home/|C:\\Users\\' \
  --glob '!target/**' \
  --glob '!vendor/**' \
  --glob '!pqcore/**' \
  --glob '!artifacts/**' \
  --glob '!scripts/check_no_absolute_paths.sh' \
  . 2>/dev/null || true)

if [[ -n "$violations" ]]; then
  echo "Absolute-path references detected:"
  echo "$violations"
  exit 1
fi

echo "Absolute-path policy check passed."
