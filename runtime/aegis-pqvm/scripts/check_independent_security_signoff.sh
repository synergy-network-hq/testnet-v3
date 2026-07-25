#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNOFF_FILE="$ROOT_DIR/docs/security/INDEPENDENT_SECURITY_SIGNOFF.md"

if [[ ! -f "$SIGNOFF_FILE" ]]; then
  echo "Missing independent security sign-off file: $SIGNOFF_FILE" >&2
  exit 1
fi

required_markers=(
  "Review Date (UTC):"
  "Reviewer:"
  "Scope:"
  "Decision: APPROVED"
  "Unresolved High/Critical Findings: 0"
)

for marker in "${required_markers[@]}"; do
  if ! rg -F -q "$marker" "$SIGNOFF_FILE"; then
    echo "Sign-off file missing required marker: $marker" >&2
    exit 1
  fi
done

if rg -q "Decision: PENDING|Decision: REJECTED|TBD|TODO|FIXME" "$SIGNOFF_FILE"; then
  echo "Sign-off file contains non-final or placeholder content." >&2
  exit 1
fi

echo "Independent security sign-off check passed."
