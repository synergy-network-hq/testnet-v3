#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/security"
mkdir -p "$LOG_DIR"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
fault_log="$LOG_DIR/fault_injection_${stamp}.log"
fuzz_log="$LOG_DIR/fuzz_campaign_${stamp}.log"
result_file="$LOG_DIR/fuzz_fault_campaign_${stamp}.json"

fault_iterations="${AEGIS_FAULT_ITERATIONS:-10000}"
fault_seed="${AEGIS_FAULT_SEED:-aegis-pqvm-fault-seed-v1}"
fuzz_max_total_time="${AEGIS_FUZZ_MAX_TOTAL_TIME:-120}"

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "[fuzz-fault] cargo-fuzz not found; installing"
  cargo install cargo-fuzz --locked
fi

if ! rustup toolchain list | rg -q '^nightly'; then
  echo "[fuzz-fault] nightly toolchain not found; installing"
  rustup toolchain install nightly --profile minimal
fi

set +e
(
  cd "$ROOT_DIR"
  echo "[fault] AEGIS_FAULT_SEED=${fault_seed}"
  echo "[fault] AEGIS_FAULT_ITERATIONS=${fault_iterations}"
  AEGIS_FAULT_SEED="$fault_seed" AEGIS_FAULT_ITERATIONS="$fault_iterations" \
    cargo test --all-features --locked --test fault_injection_campaign -- --nocapture
) 2>&1 | tee "$fault_log"
fault_status=${PIPESTATUS[0]}
set -e

set +e
(
  cd "$ROOT_DIR/fuzz"
  echo "[fuzz] AEGIS_FUZZ_MAX_TOTAL_TIME=${fuzz_max_total_time}"
  cargo +nightly fuzz run abi_decode -- -max_total_time="$fuzz_max_total_time"
  cargo +nightly fuzz run dispatch_deterministic -- -max_total_time="$fuzz_max_total_time"
) 2>&1 | tee "$fuzz_log"
fuzz_status=${PIPESTATUS[0]}
set -e

campaign_status="PASS"
if [[ $fault_status -ne 0 || $fuzz_status -ne 0 ]]; then
  campaign_status="FAIL"
fi

cat > "$result_file" <<JSON
{
  "timestamp_utc": "${stamp}",
  "module": "aegis-pqvm",
  "status": "${campaign_status}",
  "fault_seed": "${fault_seed}",
  "fault_iterations": ${fault_iterations},
  "fuzz_max_total_time_seconds_per_target": ${fuzz_max_total_time},
  "fault_log": "artifacts/security/$(basename "$fault_log")",
  "fuzz_log": "artifacts/security/$(basename "$fuzz_log")"
}
JSON

if [[ $fault_status -ne 0 ]]; then
  echo "Fault injection campaign failed."
  exit $fault_status
fi

if [[ $fuzz_status -ne 0 ]]; then
  echo "Fuzz campaign failed."
  exit $fuzz_status
fi

echo "Fuzz and fault-injection campaign complete: $result_file"
