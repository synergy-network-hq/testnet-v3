#!/bin/sh
echo "Running native FIPS 203/204/206 PQC tests..."
export RUST_MIN_STACK=8388608
cargo test \
  --no-default-features \
  --features mlkem,mldsa,fndsa,std \
  --test fips_roundtrip_tests \
  "$@"
