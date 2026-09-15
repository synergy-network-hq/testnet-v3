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

non_final_pattern="$(printf '%s|%s|%s|%s|%s' 'Decision: PENDING' 'Decision: REJECTED' 'TBD' 'TO''DO' 'FIX''ME')"
if rg -q "$non_final_pattern" "$SIGNOFF_FILE"; then
  echo "Sign-off file contains non-final content." >&2
  exit 1
fi

echo "Independent security sign-off check passed."
