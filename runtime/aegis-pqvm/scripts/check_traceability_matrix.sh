#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX_FILE="$ROOT_DIR/docs/security/TRACEABILITY_MATRIX.md"

if [[ ! -f "$MATRIX_FILE" ]]; then
  echo "Traceability matrix missing: $MATRIX_FILE" >&2
  exit 1
fi

required_ids=(
  "RQ-VM-001"
  "RQ-VM-002"
  "RQ-VM-003"
  "RQ-VM-004"
  "RQ-VM-005"
  "RQ-VM-006"
  "RQ-VM-007"
  "RQ-VM-008"
  "RQ-VM-009"
  "RQ-VM-010"
)

for requirement_id in "${required_ids[@]}"; do
  if ! rg -q "$requirement_id" "$MATRIX_FILE"; then
    echo "Traceability matrix missing requirement row: $requirement_id" >&2
    exit 1
  fi
done

required_paths=(
  "docs/security/INDEPENDENT_SECURITY_SIGNOFF.md"
  "docs/security/SIDE_CHANNEL_REVIEW.md"
  "docs/security/SECURITY_CASE_BUNDLE.md"
  "scripts/run_quality_gates.sh"
  "scripts/run_side_channel_review.sh"
  "scripts/run_fuzz_fault_campaign.sh"
  "scripts/check_independent_security_signoff.sh"
  "tests/integrations_dispatch.rs"
  "tests/quantum_randomness_beacon.rs"
  "tests/side_channel_review.rs"
  "tests/fault_injection_campaign.rs"
)

for required_path in "${required_paths[@]}"; do
  if [[ ! -e "$ROOT_DIR/$required_path" ]]; then
    echo "Traceability matrix references missing path: $required_path" >&2
    exit 1
  fi
done

echo "Traceability matrix check passed."
