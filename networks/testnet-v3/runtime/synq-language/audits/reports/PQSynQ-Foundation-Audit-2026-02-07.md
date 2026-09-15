# PQSynQ Foundation Audit Report

Audit ID: `PQSYNQ-FOUNDATION-2026-02-07`
Project Name: `pqsynq` (SynQ foundational PQC module)
Audit Date: 2026-02-07
Auditing Entity: SynQ Internal Engineering Review
Target Certification Level: Foundational Readiness (internal gate before SynQ production claims)

---

## 1. Executive Summary

This audit was conducted to validate whether `pqsynq` is a trustworthy foundation for SynQ smart-contract cryptography and whether current progress/claims are technically verifiable.

### Bottom-line decision

- Overall Assessment: **Fail** for production-readiness claims.
- Current state: **Functional for the default subset** (ML-KEM, ML-DSA, FN-DSA), but **not trustworthy as currently represented** due to major claim-vs-implementation drift and non-functional "full" validation path.

### What is true

- Default feature set can compile and execute core operations.
- Basic tests pass for subset functionality.

### What is not true (as currently claimed)

- "Production-ready", "100% KAT compliance", "all NIST algorithms", and "100% test pass" are not supported by current evidence.
- The `full` feature path fails hard and includes APIs/tests that do not exist.

### Post-Audit Remediation Update (2026-02-07)

- Package/module naming standardized to `aegis-pqsynq` (package) with `pqsynq` crate-name compatibility.
- `full` feature remapped to implemented algorithms (`mlkem`, `mldsa`, `fndsa`, `std`) and is now executable.
- Missing helper APIs (`detached_sign`, `verify_detached`, `sign_ctx`, `verify_ctx`) are now implemented on `Sign`.
- Legacy failing `full` test suites were replaced with implementation-aligned tests for supported algorithms.
- CI and `scripts/run_tests.sh` were rewritten to remove non-existent targets and misleading zero-test passes.
- Revalidation:
  - `cargo test -p aegis-pqsynq --all-features --all-targets` -> PASS
  - `cargo clippy -p aegis-pqsynq --all-targets --all-features --no-deps -- -D warnings` -> PASS

Open strategic gap remains: CMCE/SLH algorithm families are still not implemented in this crate and are currently de-scoped from SynQ smart-contract profile.

---

## 2. Scope and Methodology

## 2.1 In-Scope

- `aegis-pqsynq/pqsynq/src/*`
- `aegis-pqsynq/pqsynq/tests/*`
- `aegis-pqsynq/pqsynq/benches/*`
- `aegis-pqsynq/pqsynq/.github/workflows/ci.yml`
- `aegis-pqsynq/pqsynq/scripts/run_tests.sh`
- `aegis-pqsynq/pqsynq/README.md`
- `aegis-pqsynq/pqsynq/Cargo.toml`

## 2.2 Out-of-Scope

- External cryptographic proofs for underlying `pqrust-*` primitives
- Third-party audit records outside this repository
- Network/runtime integration behavior outside `pqsynq`

## 2.3 Validation commands executed

- `cargo test -p pqsynq`
- `cargo test -p pqsynq --all-targets`
- `cargo test -p pqsynq --features full --all-targets`
- `cargo check -p pqsynq --no-default-features`
- `cargo check -p pqsynq --no-default-features --features mlkem,mldsa,fndsa`
- `cargo check -p pqsynq --target wasm32-unknown-unknown --no-default-features`
- `cargo clippy -p pqsynq --all-targets --all-features --no-deps -- -D warnings`
- `bash aegis-pqsynq/pqsynq/scripts/run_tests.sh`
- `cargo test --test integration_tests` (from `aegis-pqsynq/pqsynq`)

---

## 3. Findings Summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 4 |
| Medium | 4 |
| Low | 2 |
| Informational | 3 |

---

## 4. Detailed Findings

### F-001: Full-feature validation path is broken and non-shippable

- Severity: **High**
- Status: Open
- Evidence:
  - `aegis-pqsynq/pqsynq/Cargo.toml:34` defines `full = []` (empty feature)
  - `aegis-pqsynq/pqsynq/tests/comprehensive_tests.rs:1`
  - `aegis-pqsynq/pqsynq/tests/individual_results.rs:1`
  - `aegis-pqsynq/pqsynq/tests/kat_tests.rs:1`
  - Tests call missing APIs such as:
    - `Kem::hqckem128()` (`aegis-pqsynq/pqsynq/tests/comprehensive_tests.rs:18`)
    - `Sign::slhdsa_shake128f()` (`aegis-pqsynq/pqsynq/tests/comprehensive_tests.rs:61`)
    - `detached_sign`/`verify_detached` (`aegis-pqsynq/pqsynq/tests/comprehensive_tests.rs:99`)
    - `sign_ctx`/`verify_ctx` (`aegis-pqsynq/pqsynq/tests/comprehensive_tests.rs:164`)
- Impact:
  - Any claim of full algorithm coverage or full compliance is currently non-verifiable.
  - Downstream teams cannot rely on feature flags for release confidence.
- Recommendation:
  - Either implement missing APIs and algorithm families, or remove `full` and all related claims/tests immediately.

### F-002: Test and CI pipeline contain non-existent targets and misleading success paths

- Severity: **High**
- Status: Open
- Evidence:
  - CI references non-existent target `integration_tests`:
    - `aegis-pqsynq/pqsynq/.github/workflows/ci.yml:59`
  - Local validation confirms failure: `cargo test --test integration_tests` -> no such test target.
  - Script also references `integration_tests`:
    - `aegis-pqsynq/pqsynq/scripts/run_tests.sh:59`
  - Script invokes many ignored tests that do not exist (e.g., `test_algorithm_*`, `test_cross_platform`, `test_memory_leaks`):
    - `aegis-pqsynq/pqsynq/scripts/run_tests.sh:130-147`
  - These commands return pass with `running 0 tests`, creating false confidence.
- Impact:
  - Quality gates are not trustworthy.
  - Progress can appear green while substantive coverage is absent.
- Recommendation:
  - Replace with deterministic, existing test targets only.
  - Fail hard on zero-test runs for expected suites.

### F-003: README claims exceed implemented API and supported algorithms

- Severity: **High**
- Status: Open
- Evidence:
  - Claims production-ready and full compliance:
    - `aegis-pqsynq/pqsynq/README.md:8-19`
  - Claims support for HQC/CMCE/SLH:
    - `aegis-pqsynq/pqsynq/README.md:38-47`
  - Usage examples call non-existent methods (`detached_sign`, `verify_detached`, `sign_ctx`, `verify_ctx`):
    - `aegis-pqsynq/pqsynq/README.md:99-121`
  - Source does not implement those methods for `Sign`:
    - `aegis-pqsynq/pqsynq/src/sign.rs:36-231`
  - README references non-existent file `integration_tests.rs`:
    - `aegis-pqsynq/pqsynq/README.md:199`
- Impact:
  - Engineering and governance decisions may be based on incorrect capability assumptions.
  - External trust and auditability are compromised.
- Recommendation:
  - Immediately publish an implementation-truth matrix and trim unsupported claims.

### F-004: Documentation/code mismatch in crate-level algorithm claims

- Severity: **High**
- Status: Open
- Evidence:
  - Crate docs advertise HQC/CMCE/SLH as supported:
    - `aegis-pqsynq/pqsynq/src/lib.rs:9-16`
  - `KemAlgorithm` only includes ML-KEM variants:
    - `aegis-pqsynq/pqsynq/src/kem.rs:16-23`
  - `SignAlgorithm` only includes ML-DSA/FN-DSA variants:
    - `aegis-pqsynq/pqsynq/src/sign.rs:18-29`
- Impact:
  - API consumers are misled at compile-time documentation level.
- Recommendation:
  - Align docs with actual enums and constructors now; move planned algorithms to roadmap section.

### F-005: no_std posture is not portable in current dependency/config model

- Severity: **Medium**
- Status: Open
- Evidence:
  - Crate declares `#![no_std]`: `aegis-pqsynq/pqsynq/src/lib.rs:39`
  - Depends on `serde_json` and `getrandom` with std-oriented config:
    - `aegis-pqsynq/pqsynq/Cargo.toml:18,22`
  - WASM `no-default-features` check fails due getrandom backend requirements.
  - `random_bytes` in non-std path panics:
    - `aegis-pqsynq/pqsynq/src/utils.rs:45-49`
- Impact:
  - Portability claims are fragile and can fail for real no_std/wasm consumers.
- Recommendation:
  - Split std-only helpers behind explicit `std` feature and remove unconditional std dependencies.

### F-006: Trait surface advertises capabilities not wired into concrete implementation

- Severity: **Medium**
- Status: Open
- Evidence:
  - Traits define detached/context APIs:
    - `aegis-pqsynq/pqsynq/src/traits.rs:51-67`
  - No `impl DetachedSignature for Sign` or `impl Contextual for Sign` present.
  - Tests and docs rely on those methods.
- Impact:
  - Contract for users is inconsistent, increasing integration risk.
- Recommendation:
  - Either implement traits for supported algorithms or remove traits until shipped.

### F-007: Error taxonomy is underutilized and semantically collapsed

- Severity: **Medium**
- Status: Open
- Evidence:
  - `check_buffer_size` always returns `InvalidKeySize`:
    - `aegis-pqsynq/pqsynq/src/utils.rs:19-22`
  - `PqcError` has distinct variants (`InvalidCiphertextSize`, `InvalidSignatureSize`, etc.) not leveraged consistently:
    - `aegis-pqsynq/pqsynq/src/error.rs:10-35`
- Impact:
  - Diagnostics are weaker than they need to be for security triage and debugging.
- Recommendation:
  - Introduce context-specific validation helpers and preserve precise error typing.

### F-008: Sensitive material handling does not include explicit zeroization strategy

- Severity: **Medium**
- Status: Open
- Evidence:
  - Secret keys are moved through standard `Vec<u8>` without explicit zeroization on drop.
  - No `zeroize` usage present in module.
- Impact:
  - In-memory key lifecycle hardening is weaker than expected for production crypto libraries.
- Recommendation:
  - Introduce key wrappers with zeroization and document memory-handling guarantees.

### F-009: Type aliases imply unsupported algorithm families

- Severity: **Low**
- Status: Open
- Evidence:
  - KEM aliases for HQC/CMCE exist despite no constructors/algorithm enum support:
    - `aegis-pqsynq/pqsynq/src/kem.rs:180-187`
- Impact:
  - API surface suggests capabilities that are not usable in practice.
- Recommendation:
  - Remove aliases for unsupported families or implement full path.

### F-010: Lint/format discipline is currently inconsistent

- Severity: **Low**
- Status: Open
- Evidence:
  - `cargo fmt --check` fails due formatting drift in `benches/pqc_benchmarks.rs`.
  - `cargo clippy ... -D warnings` fails (workspace/local dependency and pqsynq target-level warnings).
- Impact:
  - Weakens quality signal and increases regression risk.
- Recommendation:
  - Enforce package-scoped lint/fmt gates in CI on each PR.

---

## 5. Validation Matrix (Observed Reality)

| Check | Result | Notes |
|---|---|---|
| `cargo test -p pqsynq` | PASS | Only subset tests exercised; `full`-gated suites excluded |
| `cargo test -p pqsynq --all-targets` | PASS | Benchmarks run; `full`-gated suites still excluded |
| `cargo test -p pqsynq --features full --all-targets` | FAIL | Missing APIs, missing constructors, compile errors in test corpus |
| `cargo check -p pqsynq --no-default-features` | PASS (with warnings) | Does not validate no_std target portability |
| `cargo check -p pqsynq --target wasm32-unknown-unknown --no-default-features` | FAIL | getrandom backend/config incompatibility |
| `cargo test --test integration_tests` | FAIL | Test target does not exist |
| `bash scripts/run_tests.sh` | FAIL | Reports pass on many zero-test invocations; 3 failures overall |

---

## 6. Remediation Backlog (Detailed To-Do)

## Phase 0: Integrity Reset (Immediate, P0)

1. Replace all unsupported production/compliance claims in `README.md` and crate docs.
   - Acceptance: all claims map to currently passing test evidence.
2. Publish an algorithm support matrix with explicit status labels: `implemented`, `experimental`, `not implemented`.
   - Acceptance: matrix checked into repo and referenced by README.
3. Remove or correct references to nonexistent test targets (`integration_tests`).
   - Acceptance: CI and local script run without target-not-found errors.
4. Stop counting zero-test runs as success.
   - Acceptance: script fails if expected suite executes 0 tests.

## Phase 1: Feature/API Consistency (P0)

5. Decide `full` feature policy:
   - Option A: implement missing families and methods.
   - Option B: remove `full` flag and all dependent tests/docs.
   - Acceptance: `cargo test -p pqsynq --features full --all-targets` either passes or feature is removed.
6. Align traits and implementations:
   - implement `DetachedSignature` / `Contextual` for `Sign`, or deprecate these traits.
   - Acceptance: no docs/tests call methods absent from concrete API.
7. Remove misleading alias types for unsupported algorithms or implement full constructors + enum variants.
   - Acceptance: aliases and constructors are 1:1 consistent.

## Phase 2: QA Hardening (P0/P1)

8. Create deterministic test suite taxonomy:
   - `unit`, `integration`, `kat`, `property`, `bench-compile`.
9. Add CI guardrail for test-count minima (e.g., KAT suite must execute >= N tests).
10. Add CI job for feature permutations:
   - default
   - no-default + each supported algorithm feature
   - full (if retained)
11. Split script from hype to factual reporting (remove 100% language until proven).
12. Enforce package-scoped `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`.

## Phase 3: no_std and portability correctness (P1)

13. Move std-only dependencies behind `std` feature gates.
14. Rework randomness abstraction for no_std/wasm-friendly configuration.
15. Add target matrix checks for `wasm32-unknown-unknown` and one embedded no_std target.
16. Replace panic-based non-std random path with explicit error return.

## Phase 4: Cryptographic hygiene and diagnostics (P1)

17. Add key-material wrappers that zeroize on drop.
18. Refactor validation helpers to return correct typed errors (`InvalidCiphertextSize`, `InvalidSignatureSize`, etc.).
19. Define stable error codes/messages for downstream consumers.
20. Add misuse tests (wrong key type, malformed lengths, corrupted signatures/ciphertexts).

## Phase 5: Evidence-quality claims (P1/P2)

21. Rebuild KAT suite so all claims are reproducible with checked-in or fetched vectors.
22. Add generated report artifact for KAT pass/fail per algorithm/variant.
23. Add benchmark reproducibility notes (hardware, target, profile).
24. Add security section documenting what is and is not audited externally.
25. Gate release tags on passing audited checklist.

---

## 7. Certification Decision

- Certified: **No**
- Not Certified: **Yes**

Rationale:
- Foundational subset works, but verification integrity and feature-claim integrity are currently insufficient for certification-level trust.

---

## 8. Auditor Attestation

This report reflects direct repository and command-level evidence gathered on 2026-02-07 in the audited workspace.
