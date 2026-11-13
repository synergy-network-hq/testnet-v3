#!/usr/bin/env bash
set -euo pipefail

TS=$(date +%Y%m%d-%H%M%S)
# Script lives at tests/benchmarks/pqvm/run_benchmarks.sh
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
LOGDIR="$ROOT/archive/logs"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/$TS-benchmarks.log"

echo "PQC Benchmarks starting at $(date)" | tee -a "$LOG"
echo "=================================" | tee -a "$LOG"

# Build all targets first
echo "Building all targets..." | tee -a "$LOG"
cargo build --release 2>&1 | tee -a "$LOG"

echo "Running PQVM microbenchmarks..." | tee -a "$LOG"
echo "-------------------------------" | tee -a "$LOG"
time cargo run --release --bin pqvm_bench -- --iterations 100 2>&1 | tee -a "$LOG"

echo "Benchmark results summary:" | tee -a "$LOG"
echo "- All targets built successfully" | tee -a "$LOG"
echo "- PQVM microbenchmarks completed" | tee -a "$LOG"

echo "Benchmarks completed at $(date)" | tee -a "$LOG"

