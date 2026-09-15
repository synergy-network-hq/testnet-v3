# Aegis-PQSynQ Target Support Matrix

This document defines the officially supported build/validation matrix for `aegis-pqsynq` in the SynQ workspace.

Last validated: 2026-02-09.

## Scope

- Crate: `aegis-pqsynq` (`aegis-pqsynq/pqsynq`)
- Validation runner: `aegis-pqsynq/pqsynq/scripts/run_tests.sh`
- Toolchain bootstrap reference: `aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh`

## Supported Targets

| Target | Profile | Features | Validation Command | Status |
| --- | --- | --- | --- | --- |
| Host native (macOS/Linux) | default | `default` (`mlkem,mldsa,fndsa,std`) | `cargo test -p aegis-pqsynq --all-targets --all-features --locked` | Supported |
| Host native (macOS/Linux) | minimal | `--no-default-features` | `cargo check -p aegis-pqsynq --no-default-features --locked` | Supported |
| `wasm32-unknown-unknown` | baseline compile | `--no-default-features` | `cargo check -p aegis-pqsynq --target wasm32-unknown-unknown --no-default-features --locked` | Supported |
| `wasm32-wasip1` | full compile | `mlkem,mldsa,fndsa,hqckem` | `WASI_SDK_DIR=... CC_wasm32_wasi=... cargo check -p aegis-pqsynq --target wasm32-wasip1 --no-default-features --features "mlkem,mldsa,fndsa,hqckem" --locked` | Supported |

## Integration Gate (SynQ Runtime Consumption)

The PQ foundation is only accepted as release-candidate quality when these SynQ-side checks are also green:

- `cargo test -p cli --test integration_test --locked`
  - includes deterministic bytecode verification (`cli verify`)
  - includes tamper rejection for mismatched bytecode
- `cargo test --workspace --all-targets --locked`
  - verifies compiler/VM/CLI contract-level and opcode-level integration

## Tooling Requirements

- Rust target installs:
  - `wasm32-unknown-unknown`
  - `wasm32-wasip1`
- WASI SDK 20.0 for `wasm32-wasip1` C toolchain-backed checks.
  - install via: `bash aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh`
  - export:
    - `WASI_SDK_DIR=<...>/share/wasi-sysroot`
    - `CC_wasm32_wasi=<...>/bin/clang`

## Non-Goals (Current Cycle)

- Runtime execution smoke tests for `wasm32-wasip1` are not yet mandatory in CI.
- CMCE and SLH-DSA targets are intentionally out of scope for SynQ smart-contract profile in this cycle.

