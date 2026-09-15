# Aegis Crypto Core Tests

This directory intentionally keeps the active Rust integration suite focused on
the implemented FIPS algorithms used by PQSynQ:

- FIPS 203 ML-KEM: 512, 768, 1024
- FIPS 204 ML-DSA: 44, 65, 87
- FIPS 206 FN-DSA: 512, 1024

Run the native FIPS suite with:

```sh
cargo test --no-default-features --features mlkem,mldsa,fndsa,std --test fips_roundtrip_tests
```

The tests perform real key generation, encapsulation, decapsulation, signing,
verification, and negative verification checks through the pqrust-backed
wrappers. Legacy algorithm-name tests were removed with the old sketch-only KAT files.
