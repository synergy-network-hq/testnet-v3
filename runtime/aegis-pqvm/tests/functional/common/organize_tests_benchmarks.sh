#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_TESTS="$ROOT/tests/functional/pqtests"
OUT_BENCH="$ROOT/tests/functional/pqbench"

mkdir -p "$OUT_TESTS/common" "$OUT_BENCH/common"

echo "Organizing module-local test and benchmark files from: $ROOT"

copy_if_exists() {
  local src="$1"
  local dst_dir="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$dst_dir"
    cp "$src" "$dst_dir/"
    echo "  copied $(basename "$src") -> $dst_dir"
  fi
}

# Core Rust KAT and validation tests.
for test_file in "$ROOT"/tests/kat_*.rs "$ROOT"/tests/*validation*.rs "$ROOT"/tests/*security*.rs; do
  if [[ -f "$test_file" ]]; then
    copy_if_exists "$test_file" "$OUT_TESTS/pqvm"
  fi
done

# Benchmark runners used by this module.
copy_if_exists "$ROOT/tests/benchmarks/pqvm/run_benchmarks.sh" "$OUT_BENCH/pqvm"
copy_if_exists "$ROOT/tests/benchmarks/pqnodejs/benchmark_all.js" "$OUT_BENCH/pqnodejs"
copy_if_exists "$ROOT/tests/benchmarks/pqpython/benchmark.py" "$OUT_BENCH/pqpython"
copy_if_exists "$ROOT/tests/benchmarks/pqmobile/benchmark.sh" "$OUT_BENCH/pqmobile"
copy_if_exists "$ROOT/tests/benchmarks/pqwear/benchmark.sh" "$OUT_BENCH/pqwear"

# Shared functional helper scripts.
for helper in "$ROOT/tests/functional/common"/test*.py "$ROOT/tests/functional/common"/test*.js "$ROOT/tests/functional/common"/test*.sh; do
  if [[ -f "$helper" ]]; then
    copy_if_exists "$helper" "$OUT_TESTS/common"
  fi
done

echo "Organization complete."
echo "  Tests:      $OUT_TESTS"
echo "  Benchmarks: $OUT_BENCH"
