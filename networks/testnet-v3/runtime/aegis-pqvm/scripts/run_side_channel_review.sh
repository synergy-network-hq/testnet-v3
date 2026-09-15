#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/security"
mkdir -p "$LOG_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$LOG_DIR/side_channel_review_${stamp}.log"
report_file="$LOG_DIR/side_channel_review_${stamp}.md"

set +e
(
  cd "$ROOT_DIR"
  echo "[side-channel] running boundary tests"
  cargo test --all-features --locked --test side_channel_review -- --nocapture

  echo "[side-channel] verifying deterministic adapters do not call off-chain dispatcher"
  if rg -n "dispatch_offchain" src/integrations/{evm,substrate,solana,bitcoin}/mod.rs; then
    echo "[side-channel] unexpected off-chain dispatcher usage in deterministic adapters"
    exit 1
  fi

  echo "[side-channel] verifying secret-key ops are blocked for deterministic encoding/dispatch"
  rg -n "mlkem decapsulation payload encoding is off-chain only" src/integrations/abi.rs
  rg -n "mlkem decapsulation is disabled for deterministic dispatcher" src/integrations/abi.rs

  echo "[side-channel] verifying route-binding controls for Move/CosmWasm adapters"
  rg -n "expected_route|op/alg does not match Move module/function route" src/integrations/move/mod.rs
  rg -n "decode_bound_message|contract mismatch" src/integrations/cosmwasm/mod.rs
) 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

result="PASS"
if [[ $status -ne 0 ]]; then
  result="FAIL"
fi

cat > "$report_file" <<EOF
# Side-Channel and Constant-Time Boundary Review

- Timestamp (UTC): ${stamp}
- Module: aegis-pqvm
- Result: ${result}
- Log: artifacts/security/$(basename "$log_file")

## Scope
- Deterministic interfaces are validated to reject secret-key-bearing operations.
- Adapter routing checks ensure payloads cannot bypass intended deterministic controls.
- Wrapper-layer constant-time comparator behavior is validated via targeted tests.

## Residual Risk
- Constant-time and microarchitectural side-channel properties inside vendored C cryptographic implementations still require platform-specific laboratory assessment.
EOF

if [[ $status -ne 0 ]]; then
  echo "Side-channel review failed."
  exit $status
fi

echo "Side-channel review complete: $report_file"
