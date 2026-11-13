# No-Stub PQC Audit Checklist

Scope: canonical Aegis-PQC PQSynQ module, including `pqsynq` and sibling `aegis_crypto_core`.

## Fixed

- Replaced old `Kyber` API surfaces in `aegis_crypto_core` with FIPS 203 `ML-KEM` wrappers for 512, 768, and 1024.
- Replaced old `Dilithium` API surfaces in `aegis_crypto_core` with FIPS 204 `ML-DSA` wrappers for 44, 65, and 87.
- Replaced legacy Falcon-named stub functions with FIPS 206 `FN-DSA` wrappers for 512 and 1024 backed by `pqrust-fndsa`.
- Removed the zero-return `src/nist/mod.rs` pseudo implementation.
- Removed placeholder KAT sketches and legacy algorithm-name tests from `aegis_crypto_core/tests`.
- Removed dead backup/demo files that contained simulated or placeholder crypto flows.
- Fixed feature gates so `mlkem`, `mldsa`, and `fndsa` compile behind their actual Cargo feature names.
- Repointed canonical PQSynQ dependencies at the canonical Aegis-PQC `aegis-pqrust` crates instead of missing workspace dependencies.
- Rewrote PQSynQ KEM/sign adapters to match the actual pqrust APIs.
- Implemented real FN-DSA context signing by signing a length-framed, domain-separated context payload.
- Removed the `PqcError::NotImplemented` variant from PQSynQ.
- Removed literal old ML-DSA fixture names from source while preserving NIST replay compatibility.
- Added real FIPS 203/204/206 round-trip tests in `aegis_crypto_core`.

## Verified

- `aegis_crypto_core`: `cargo check --no-default-features --features mlkem,mldsa,fndsa,std`
- `aegis_crypto_core`: `cargo test --no-default-features --features mlkem,mldsa,fndsa,std --test fips_roundtrip_tests`
- `pqsynq`: `cargo check --all-features`
- `pqsynq`: `cargo test --features full --test comprehensive_tests`
- `pqsynq`: `cargo test --test canonical_payload_tests --test synq_deploy_vector_tests --test synq_verifier_tests`
- Active-source scans for `kyber`, `dilithium`, and common stub markers returned no hits in `aegis_crypto_core` source/tests/benches/fuzz and in `pqsynq` source/tests/examples.
