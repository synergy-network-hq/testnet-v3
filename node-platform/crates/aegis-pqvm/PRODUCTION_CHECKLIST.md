# Aegis pqvm Production Checklist

This checklist defines the minimum release gate for `aegis-pqvm` in blockchain
VM integration environments (EVM, Substrate, CosmWasm, Solana, Move).

## 1. Build Integrity

- [ ] `cargo build --release` completes successfully.
- [ ] `cargo check --all-features` passes without errors or warnings.
- [ ] `cargo build --bin generate_license --release` produces a working binary.
- [ ] All vendored C/assembly sources compile cleanly (`build.rs` / `cc` crate, no `stderr` output).

## 2. Cryptographic Correctness

- [ ] ML-KEM (512/768/1024) keygen, encapsulate, decapsulate round-trips pass.
- [ ] ML-DSA (44/65/87) keygen, sign, verify round-trips pass.
- [ ] FN-DSA (512/1024) keygen, sign, verify round-trips pass.
- [ ] SLH-DSA keygen, sign, verify round-trips pass (all parameter sets in scope).
- [ ] HQC keygen, encapsulate, decapsulate round-trips pass.
- [ ] Known-answer tests (KATs) pass against NIST ACVP vectors where available.

## 3. AEG1 ABI Validation

- [ ] `abi::encode_call` / `abi::decode_call` round-trips for every `(Op, Alg)` pair.
- [ ] `dispatch_deterministic` returns correct output for a valid ML-KEM verify call.
- [ ] `dispatch_offchain` returns correct output for a valid ML-DSA detached verify.
- [ ] Malformed AEG1 payload (truncated, wrong magic, bad length) returns `InvalidPayload`.
- [ ] Unknown `Op`/`Alg` byte returns `UnsupportedOperation`.

## 4. VM Integration Smoke Tests

- [ ] **EVM**: `evm_precompile_call` dispatches a valid ML-KEM encapsulate payload.
- [ ] **EVM**: `evm_gas_cost` returns a non-zero estimate for every supported algorithm.
- [ ] **Substrate**: `dispatch_call` routes a valid AEG1 payload to the correct handler.
- [ ] **CosmWasm**: `encode_bound_message` / `call_contract` round-trip succeeds.
- [ ] **CosmWasm**: Contract mismatch in envelope returns `InvalidPayload`.
- [ ] **Solana**: `invoke_instruction` dispatches a valid AEG1 instruction.
- [ ] **Move**: `invoke_entry_function` dispatches `aegis::mldsa44_verify_detached` correctly.
- [ ] **Move**: Module/function mismatch vs AEG1 payload op/alg returns `InvalidPayload`.

## 5. Security and Operational Hardening

- [ ] Input validation for all public integration entry points (empty/oversized payload guards).
- [ ] No private key material or license secrets appear in logs or error messages.
- [ ] Error messages are actionable but do not leak internal state.
- [ ] `cargo audit` passes (no known vulnerable dependencies).
- [ ] Fuzz campaign smoke pass: `cargo fuzz run aeg1_roundtrip -- -max_total_time=60`.

## 6. Compliance and Evidence Artifacts

- [ ] Threat model reviewed and updated for VM platform surface area.
- [ ] FIPS algorithm boundary document updated for all in-scope algorithms.
- [ ] ACVP-like KAT corpus archived in `artifacts/validation/`.
- [ ] Security case bundle updated in `docs/security/`.

## 7. Release Documentation and Delivery

- [ ] `README.md` reflects current API surface and supported VM platforms.
- [ ] `PQVM_USAGE_MANUAL.md` updated for current release.
- [ ] `LICENSING.md` reviewed and accurate for all four tiers.
- [ ] Distribution policy documented (`docs/release/LICENSE_DISTRIBUTION_POLICY.md`).
- [ ] Customer delivery workflow present (`docs/release/CUSTOMER_DELIVERY_BUNDLE.md`).
- [ ] Release bundle generation script present (`scripts/build_release_bundle.sh`).
- [ ] Release artifact hash captured in release notes.
- [ ] `Cargo.toml`: confirm `publish = false` (already set).

## 8. Licensing System

- [x] `src/licensing.rs` — BLAKE3-authenticated 4-tier license token system.
- [x] `VmPlatform` enum — EVM, Substrate, CosmWasm, Solana, Move.
- [x] `licensing::init(key)` — validates key and installs process-level license.
- [x] `licensing::check_platform(platform)` — tier-gates VM platform access.
- [x] `licensing::check_algorithm(alg)` — tier-gates algorithm access + decrements op counter.
- [x] `licensing::license_summary()` — diagnostic string for ops/tier/expiry.
- [x] `abi::dispatch_deterministic` wired with `check_algorithm` at central choke-point.
- [x] `abi::dispatch_offchain` wired with `check_algorithm`.
- [x] `integrations::evm` — `check_platform(Evm)` in `evm_precompile_call` and `evm_gas_cost`.
- [x] `integrations::substrate` — `check_platform(Substrate)` in `dispatch_call`.
- [x] `integrations::cosmwasm` — `check_platform(CosmWasm)` in `call_contract`.
- [x] `integrations::solana` — `check_platform(Solana)` in `invoke_instruction`.
- [x] `integrations::move` — `check_platform(Move)` in `invoke_entry_function`.
- [x] `src/bin/generate_license.rs` — CLI to generate and validate `AEGIS-V-` keys.
- [x] `LICENSING.md` — full tier/platform/algorithm matrix and integration guide.
- [x] 8 unit tests in `src/licensing.rs` (valid key, expired, tampered, tier access, op limit, platform access).
- [ ] Pre-ship: replace `LICENSE_SECRET` in `src/licensing.rs` **and** `src/bin/generate_license.rs` with a production secret not committed to source control.
- [ ] Pre-ship: run `cargo test licensing` and confirm all 8 tests pass.
- [ ] Pre-ship: generate sample keys for each tier, validate with `generate_license --validate`, and smoke-test against a live VM integration call.
- [ ] Pre-ship: confirm `generate_license` binary is excluded from customer delivery bundles.

## Suggested Release Commands

```bash
cd aegis-pqvm
cargo test --release
cargo build --release
cargo build --bin generate_license --release
cargo audit
cargo fuzz run aeg1_roundtrip -- -max_total_time=60
```

## Evidence

_Fill in after pre-release validation run._

- `cargo build --release` → 
- `cargo test --release` → 
- `cargo audit` → 
- KAT corpus run → 
- VM integration smoke tests → 
