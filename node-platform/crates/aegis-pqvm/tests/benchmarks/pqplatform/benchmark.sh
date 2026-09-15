#!/bin/bash

# PQPlatform Benchmark Script
# Runs the real Aegis-PQVM cryptographic microbenchmarks.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PQVM_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

ITERATIONS="${ITERATIONS:-100}"
PLATFORM="${PLATFORM:-host}"

echo "PQPlatform Performance Benchmarks"
echo "================================="
echo "Iterations: ${ITERATIONS}"
echo "Platform: ${PLATFORM}"

cd "${PQVM_ROOT}"
cargo run --release --bin pqvm_bench -- --iterations "${ITERATIONS}"
