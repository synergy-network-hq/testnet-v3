# Aegis PQSynQ (`aegis-pqsynq`)

`aegis-pqsynq` is the SynQ-facing PQC facade crate used by the SynQ VM and compiler.
It provides a consistent Rust API over the currently integrated `pqrust` algorithms.

## Current Support Matrix

### KEM
- `ML-KEM-512`
- `ML-KEM-768`
- `ML-KEM-1024`
- `HQC-KEM-128` (feature: `hqckem`)
- `HQC-KEM-192` (feature: `hqckem`)
- `HQC-KEM-256` (feature: `hqckem`)

### Signatures
- `ML-DSA-44`
- `ML-DSA-65`
- `ML-DSA-87`
- `FN-DSA-512`
- `FN-DSA-1024`

### Contextual Signatures
- Supported for `ML-DSA-*` via `sign_ctx` / `verify_ctx`
- Not implemented for `FN-DSA-*` (returns `PqcError::NotImplemented`)

## Package Name and Import Name

The package name is `aegis-pqsynq`, while the library crate name remains `pqsynq`.

```toml
[dependencies]
pqsynq = { package = "aegis-pqsynq", path = "../aegis-pqsynq/pqsynq" }
```

## Basic Usage

```rust
use pqsynq::{DigitalSignature, Kem, KeyEncapsulation, Sign};

fn main() -> Result<(), pqsynq::PqcError> {
    let kem = Kem::mlkem768();
    let (pk, sk) = kem.keygen()?;
    let (ct, ss1) = kem.encapsulate(&pk)?;
    let ss2 = kem.decapsulate(&ct, &sk)?;
    assert_eq!(ss1, ss2);

    let signer = Sign::mldsa65();
    let (pk, sk) = signer.keygen()?;
    let msg = b"hello-synq";
    let sig = signer.detached_sign(msg, &sk)?;
    assert!(signer.verify_detached(msg, &sig, &pk)?);

    let ctx_sig = signer.sign_ctx(msg, &sk, b"synq-contract-v1")?;
    assert!(signer.verify_ctx(msg, &ctx_sig, &pk, b"synq-contract-v1")?);

    Ok(())
}
```

## Features

- `std` (default)
- `mlkem` (default)
- `mldsa` (default)
- `fndsa` (default)
- `hqckem` (optional)
- `full` (enables `std`, `mlkem`, `mldsa`, `fndsa`, `hqckem`)

## Validation Commands

```bash
# From SynQ workspace root
cargo fmt --all --check
cargo clippy -p aegis-pqsynq --all-targets --all-features --no-deps --locked -- -D warnings
cargo test -p aegis-pqsynq --all-features --all-targets --locked
cargo check -p aegis-pqsynq --no-default-features --locked
cargo check -p aegis-pqsynq --target wasm32-unknown-unknown --no-default-features --locked

# For wasm32-wasip1 full-feature compilation, provide a WASI SDK clang toolchain.
WASI_SDK_DIR=/path/to/wasi-sdk/share/wasi-sysroot \
CC_wasm32_wasi=/path/to/wasi-sdk/bin/clang \
cargo check -p aegis-pqsynq --target wasm32-wasip1 \
  --no-default-features --features "mlkem,mldsa,fndsa,hqckem" --locked

# Full package validation script
bash aegis-pqsynq/pqsynq/scripts/run_tests.sh

# Install pinned WASI SDK locally (deterministic bootstrap)
bash aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh

# Replay official NIST vectors (default: first 10 vectors per algorithm)
cargo test -p aegis-pqsynq --all-features --test nist_vector_replay_tests --locked

# Generate compliance artifact + logs
bash aegis-pqsynq/pqsynq/scripts/generate_compliance_report.sh
```

## Deterministic Replay Fixtures

`aegis-pqsynq` ships pinned replay fixtures for all currently supported SynQ profile algorithms:
- `aegis-pqsynq/pqsynq/tests/vectors/pinned_vectors.json`
- `aegis-pqsynq/pqsynq/tests/vectors/manifest.json` (hash integrity gate)

Refresh fixtures:

```bash
bash aegis-pqsynq/pqsynq/scripts/refresh_pinned_vectors.sh
```

The replay tests validate KEM decapsulation and signature verification semantics against pinned artifacts and fail if fixture hash integrity drifts.

## Official NIST Replay Harness

`aegis-pqsynq` also validates against official NIST vector files from:
- `5-nist-kat-vectors/NIST-ml-kem/reference/*`
- `5-nist-kat-vectors/NIST-ml-dsa/reference/*`
- `5-nist-kat-vectors/NIST-fn-dsa/reference/*`
- `5-nist-kat-vectors/NIST-hqc-kem/reference/*`

Harness entry point:
- `aegis-pqsynq/pqsynq/tests/nist_vector_replay_tests.rs`

Default replay uses the first 10 vectors per algorithm for CI/runtime balance.
Override with `PQSYNQ_NIST_MAX_VECTORS=<N>`.

## Key Lifecycle Policy

Key-material handling policy is documented in:
- `aegis-pqsynq/pqsynq/docs/KEY_MATERIAL_LIFECYCLE_POLICY.md`

Utility hooks:
- `pqsynq::utils::zeroize_bytes`
- `pqsynq::SecretBytes`

Additional hardening docs:
- `aegis-pqsynq/pqsynq/docs/WASI_TOOLCHAIN_BOOTSTRAP.md`
- `aegis-pqsynq/pqsynq/docs/TARGET_SUPPORT_MATRIX.md`
- `aegis-pqsynq/pqsynq/docs/SIDE_CHANNEL_POSTURE.md`
- `aegis-pqsynq/pqsynq/docs/DEPENDENCY_PINNING_POLICY.md`

## Status Policy

This README is intentionally scoped to currently implemented behavior.
Algorithm families not listed above are not considered shipped in this crate.
CMCE and SLH-DSA are currently de-scoped for SynQ smart-contract usage due key-size and footprint tradeoffs.
