#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_SOURCE_ROOT="$ROOT_DIR/pqcore"
SOURCE_ROOT="${AEGIS_PQ_SOURCE_ROOT:-$DEFAULT_SOURCE_ROOT}"

if [[ ! -d "$SOURCE_ROOT" ]]; then
  echo "Effective PQC source root not found: $SOURCE_ROOT" >&2
  exit 1
fi

echo "Effective PQC source root: $SOURCE_ROOT"

SEARCH_PATHS=()
for rel in crypto_kem crypto_sign common; do
  if [[ -d "$SOURCE_ROOT/$rel" ]]; then
    SEARCH_PATHS+=("$SOURCE_ROOT/$rel")
  fi
done

if [[ ${#SEARCH_PATHS[@]} -eq 0 ]]; then
  echo "No expected PQC source subdirectories found under $SOURCE_ROOT" >&2
  exit 1
fi

if rg -n -i '(TODO|FIXME|WIP|placeholder|stub)' "${SEARCH_PATHS[@]}"; then
  echo "Non-production markers found in effective PQC source root." >&2
  exit 1
fi

echo "Effective PQC source marker check passed."
