#!/bin/sh
echo "Checking WASM build for FIPS 203/204/206 PQC wrappers..."

# Install wasm-pack if not already installed
if ! command -v wasm-pack &> /dev/null; then
    echo "Installing wasm-pack..."
    cargo install wasm-pack
fi

wasm-pack build --target nodejs --no-default-features --features "mlkem mldsa fndsa wasm"
