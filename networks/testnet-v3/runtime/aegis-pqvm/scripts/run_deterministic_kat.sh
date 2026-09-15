#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/acvp/replay_logs"
CORPUS_DIR="$ROOT_DIR/artifacts/acvp/result_corpus"
mkdir -p "$LOG_DIR" "$CORPUS_DIR"

seed="${AEGIS_KAT_SEED:-aegis-pqvm-kat-seed-v1}"
export AEGIS_KAT_SEED="$seed"
export AEGIS_KAT_MAX_CASES="${AEGIS_KAT_MAX_CASES:-25}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$LOG_DIR/kat_replay_${stamp}.log"
result_file="$CORPUS_DIR/kat_result_${stamp}.json"

set +e
(
  cd "$ROOT_DIR"
  echo "AEGIS_KAT_SEED=$AEGIS_KAT_SEED"
  echo "AEGIS_KAT_MAX_CASES=$AEGIS_KAT_MAX_CASES"
  cargo test --all-features --test kat_mlkem -- --nocapture
  cargo test --all-features --test kat_mldsa_aegis -- --nocapture
  cargo test --all-features --test kat_fndsa -- --nocapture
) 2>&1 | tee "$log_file"
status=${PIPESTATUS[0]}
set -e

state="PASS"
if [[ $status -ne 0 ]]; then
  state="FAIL"
fi

cat > "$result_file" <<JSON
{
  "timestamp_utc": "${stamp}",
  "module": "aegis-pqvm",
  "seed": "${seed}",
  "max_cases": ${AEGIS_KAT_MAX_CASES},
  "status": "${state}",
  "log": "artifacts/acvp/replay_logs/$(basename "$log_file")"
}
JSON

if [[ $status -ne 0 ]]; then
  echo "Deterministic KAT replay failed."
  exit $status
fi

echo "Deterministic KAT replay complete: $log_file"
