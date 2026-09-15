#!/bin/bash

# Script to organize test and benchmark files into platform-specific directories

set -e

echo "Organizing test and benchmark files..."

# Create platform-specific directories
mkdir -p pqtests/common
mkdir -p pqbench/common

# Move platform-specific test files
echo "Moving platform-specific test files..."

# pqcrypto Rust tests
if [ -f "/Users/devpup/Desktop/aegis/pqc/pqcrypto/pqcrypto/examples/kat_test.rs" ]; then
    mkdir -p pqtests/pqcrypto
    cp "/Users/devpup/Desktop/aegis/pqc/pqcrypto/pqcrypto/examples/kat_test.rs" pqtests/pqcrypto/
    echo "  Copied pqcrypto KAT test"
fi

if [ -f "/Users/devpup/Desktop/aegis/pqc/pqcrypto/pqcrypto/examples/benchmark.rs" ]; then
    mkdir -p pqbench/pqcrypto
    cp "/Users/devpup/Desktop/aegis/pqc/pqcrypto/pqcrypto/examples/benchmark.rs" pqbench/pqcrypto/
    echo "  Copied pqcrypto benchmark"
fi

# pqnodejs tests and benchmarks
if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqnodejs/benchmark/benchmark_all.js" ]; then
    mkdir -p pqtests/pqnodejs pqbench/pqnodejs
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqnodejs/benchmark/benchmark_all.js" pqbench/pqnodejs/
    echo "  Copied pqnodejs benchmark"
fi

# pqpython tests and benchmarks
if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqpython/benchmarks/benchmark.py" ]; then
    mkdir -p pqbench/pqpython
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqpython/benchmarks/benchmark.py" pqbench/pqpython/
    echo "  Copied pqpython benchmark"
fi

# pqvm tests and benchmarks
if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqvm/tools/run_benchmarks.sh" ]; then
    mkdir -p pqbench/pqvm
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqvm/tools/run_benchmarks.sh" pqbench/pqvm/
    echo "  Copied pqvm benchmark script"
fi

if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqvm/benchmark_results.log" ]; then
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqvm/benchmark_results.log" pqbench/pqvm/
    echo "  Copied pqvm benchmark results"
fi

# pqmobile/pqsmart benchmarks
if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqmobile/benchmark.sh" ]; then
    mkdir -p pqbench/pqmobile
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqmobile/benchmark.sh" pqbench/pqmobile/
    echo "  Copied pqmobile benchmark script"
fi

if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqsmart/pqmobile/benchmark.sh" ]; then
    mkdir -p pqbench/pqsmart
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqsmart/pqmobile/benchmark.sh" pqbench/pqsmart/
    echo "  Copied pqsmart benchmark script"
fi

if [ -f "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqwear/pqmobile/benchmark.sh" ]; then
    mkdir -p pqbench/pqwear
    cp "/Users/devpup/Desktop/aegis/pqc/pqplatforms/pqwear/pqmobile/benchmark.sh" pqbench/pqwear/
    echo "  Copied pqwear benchmark script"
fi

# Copy any other test files to common
echo "Copying remaining test files to common..."

# Find any other test files that might exist
find /Users/devpup/Desktop/aegis/pqc -name "*test*.py" -o -name "*test*.js" -o -name "*test*.sh" | while read -r file; do
    # Skip files we've already moved
    case "$file" in
        */pqtests/*|*/pqbench/*|*/target/*|*/build/*|*/__pycache__/*)
            continue
            ;;
    esac

    # Copy to common tests
    cp "$file" pqtests/common/
    echo "  Copied $(basename "$file") to common tests"
done

echo "Test and benchmark organization complete!"
echo ""
echo "Structure created:"
echo "  pqtests/common/     - Shared test files"
echo "  pqtests/pqcrypto/   - Rust pqcrypto tests"
echo "  pqtests/pqnodejs/   - Node.js tests"
echo ""
echo "  pqbench/common/     - Shared benchmark files"
echo "  pqbench/pqcrypto/   - Rust pqcrypto benchmarks"
echo "  pqbench/pqnodejs/   - Node.js benchmarks"
echo "  pqbench/pqpython/   - Python benchmarks"
echo "  pqbench/pqvm/       - VM benchmarks"
echo "  pqbench/pqmobile/   - Mobile benchmarks"
echo "  pqbench/pqsmart/    - Smart platform benchmarks"
echo "  pqbench/pqwear/     - Wearable benchmarks"
