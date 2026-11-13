#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "Aegis PQVM Quality Gates"
echo "======================="

PASS=0
FAIL=0

run_gate() {
  local name="$1"
  shift
  echo ""
  echo "==> $name"
  if "$@"; then
    echo "PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name"
    FAIL=$((FAIL + 1))
  fi
}

# 1) Functional/unit tests (Rust)
run_gate "Rust tests (functional + security smoke + KATs)" cargo test --quiet

# 2) Benchmarks (optional; can be slow on CI)
if [[ "${AEGIS_SKIP_BENCH:-0}" == "1" ]]; then
  echo ""
  echo "==> Benchmarks"
  echo "SKIP: Benchmarks (AEGIS_SKIP_BENCH=1)"
else
  run_gate "Benchmarks (pqvm)" bash tests/benchmarks/pqvm/run_benchmarks.sh
fi

TOTAL=$((PASS + FAIL))
if [[ "$TOTAL" -eq 0 ]]; then
  echo "No gates executed."
  exit 2
fi

SCORE_PCT=$(( (PASS * 100) / TOTAL ))
echo ""
echo "Summary"
echo "-------"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "SCORE: ${SCORE_PCT}%"

if [[ "$SCORE_PCT" -lt 90 ]]; then
  echo "ERROR: score is below 90% threshold"
  exit 1
fi

echo "OK: score meets 90%+ threshold"


