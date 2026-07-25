# Aegis PQVM — Usage Manual

## What “production-ready” means here

`aegis-pqvm` is **green on the repository’s current quality gates** (functional + KAT + security smoke + benchmarks) on this machine.

However, **commercial production readiness** also depends on platform packaging + licensing enforcement + integration hardening. Those pieces are still being rebuilt across the repo, so treat PQVM as:

- ✅ **Cryptography core ready for integration/testing**
- ✅ **Quality-gated in-repo**
- ⚠️ **Licensing/subscription enforcement: not yet wired into PQVM APIs**
- ⚠️ **Blockchain integrations are present but some are scaffolds/simulations**

## Quick install (Rust)

PQVM is a Rust crate intended to be used as a **path dependency** in your blockchain/VM toolchain.

Add to your `Cargo.toml`:

```toml
[dependencies]
aegis-pqvm = { path = "/absolute/path/to/Aegis-PQC-Full-Program/aegis-pqvm" }
```

Optional: enable/disable algorithms with features:

```toml
[dependencies]
aegis-pqvm = { path = "/absolute/path/to/Aegis-PQC-Full-Program/aegis-pqvm", default-features = false, features = ["mlkem","mldsa","fndsa"] }
```

## Build requirements

- **Rust**: stable toolchain (edition 2021)
- **C toolchain**: a working C compiler (on macOS: Xcode command line tools / clang)
- No network access is required to build (vendored dependencies live under `aegis-pqvm/vendor/`).

## API usage

PQVM re-exports algorithm modules at the crate root:

- `aegis_pqvm::mlkem` (ML-KEM)
- `aegis_pqvm::mldsa` (ML-DSA)
- `aegis_pqvm::fndsa` (FN-DSA)

### ML-KEM (key exchange / encapsulation)

```rust
use aegis_pqvm::mlkem::mlkem512;
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _};

fn main() {
    let (pk, sk) = mlkem512::keypair();
    let (ss1, ct) = mlkem512::encapsulate(&pk);
    let ss2 = mlkem512::decapsulate(&ct, &sk);

    assert_eq!(ss1.as_bytes(), ss2.as_bytes());
}
```

### ML-DSA (sign / verify)

```rust
use aegis_pqvm::mldsa::mldsa44;

fn main() {
    let msg = b"hello from pqvm";
    let (pk, sk) = mldsa44::keypair();
    let sig = mldsa44::detached_sign(msg, &sk);
    mldsa44::verify_detached_signature(&sig, msg, &pk).unwrap();
}
```

### FN-DSA (Falcon sign / verify)

```rust
use aegis_pqvm::fndsa::fndsa512;

fn main() {
    let msg = b"hello from pqvm";
    let (pk, sk) = fndsa512::keypair();
    let sig = fndsa512::detached_sign(msg, &sk);
    fndsa512::verify_detached_signature(&sig, msg, &pk).unwrap();
}
```

## Blockchain integration modules

PQVM includes integration modules under `aegis_pqvm::integrations`:

- `integrations::evm`
- `integrations::substrate`
- `integrations::cosmwasm`
- `integrations::move_vm`
- `integrations::solana`

These are **host-side integration shims**: a deterministic dispatch layer + a small byte ABI (`AEG1`) that chain-specific code can call into.
This repo intentionally avoids pulling full chain SDK dependencies into the core crate, so PQVM does **not** ship full pallets/contracts/programs here.

For example, the EVM module exposes a deterministic “precompile entrypoint” that dispatches an `AEG1`-encoded payload:

```rust
use aegis_pqvm::integrations::evm;
use aegis_pqvm::integrations::abi;

fn main() {
    let call = abi::Call {
        op: abi::Op::MldsaVerifyDetached,
        alg: abi::Alg::Mldsa44,
        args: vec![vec![0u8; 1], vec![0u8; 1], vec![0u8; 1]],
    };
    let payload = abi::encode_call(&call);
    let response = evm::evm_precompile_call(&payload).unwrap();
    let _ = response;
}
```

## Running tests

From the `aegis-pqvm/` folder:

```bash
cargo test
```

## Running the PQVM quality gates (90%+ threshold)

PQVM includes a non-interactive runner that executes:

- Rust tests (functional + security smoke + KATs)
- Benchmarks (unless skipped)

```bash
bash scripts/run_quality_gates.sh
```

To skip benchmarks (useful in CI):

```bash
AEGIS_SKIP_BENCH=1 bash scripts/run_quality_gates.sh
```

## Benchmarks

Run the PQVM microbench binary directly:

```bash
cargo run --release --bin pqvm_bench -- --iterations 100
```

Or run the benchmark wrapper (writes logs under `aegis-pqvm/archive/logs/`):

```bash
bash tests/benchmarks/pqvm/run_benchmarks.sh
```

## KATs (Known Answer Tests)

PQVM currently enforces:

- **ML‑KEM decapsulation KAT checks** against `aegis-pqvm/tests/kats/mlkem/...`
- **Aegis baseline ML‑DSA regression KATs** under `aegis-pqvm/tests/kats/aegis/`

To regenerate the baseline ML‑DSA vectors:

```bash
cargo run --bin gen_aegis_kats
```

## Licensing / distribution note

`aegis-pqvm` is marked **Proprietary** in its `Cargo.toml`. In the new model:

- customer builds should be distributed via a secure portal or private registry, and
- runtime license enforcement will be added as part of the broader “licensed/subscription” rebuild.

See `0-documentation/IMPLEMENTATION_BUILD_AND_LICENSING_PLAN.md` for the repo-wide build and monetization plan.
