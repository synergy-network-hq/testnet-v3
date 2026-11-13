#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

tests=(
  "consensus_state"
  "sync::state_sync"
  "validator_lifecycle"
  "fleet_status"
  "archive_validator"
  "community_onboarding"
  "chaos_harness"
)

for test_filter in "${tests[@]}"; do
  echo "prompt2_offline_gate=test filter=${test_filter}"
  cargo test --locked -p synergy-testnet "${test_filter}" -- --nocapture
done

cargo check --locked -p synergy-testnet --bin synergy-node

echo "prompt2_offline_gate=PASS"
