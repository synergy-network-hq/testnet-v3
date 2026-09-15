# Technical Specification: Aegis PQVM

**Document Status:** Approved for Internal Release Engineering
**Version:** 1.0
**Module:** `aegis-pqvm`
**Last Updated (UTC):** 2026-02-19
**Primary Audience:** Runtime integrators, cryptography engineers, security reviewers

---

## 1. Executive Summary

`aegis-pqvm` is a deterministic post-quantum cryptography integration module for blockchain virtual-machine environments. It provides a compact, bounded byte ABI (`AEG1`) that supports deterministic detached-signature verification (ML-DSA and FN-DSA) and an explicitly segregated off-chain path for ML-KEM decapsulation.

The module includes:

- Algorithm wrappers and FFI bindings for ML-KEM, ML-DSA, FN-DSA.
- Deterministic adapter shims for EVM, Substrate, CosmWasm, Solana, Move, and Bitcoin-style verification contexts.
- Key lifecycle metadata management and auditable state transitions.
- A policy-driven randomness beacon with proof commitment and signature verification.
- Reproducible quality gates, evidence generation, and release packaging scripts.

---

## 2. Context and Problem Statement

Blockchain runtime integrations require deterministic behavior across validator nodes. Traditional cryptographic APIs often expose key-generation or signing/decapsulation interfaces that depend on secret keys or runtime entropy, which can violate deterministic execution and confidentiality constraints in public execution contexts.

This module addresses that by:

- Narrowing deterministic VM-facing operations to verification-only paths.
- Enforcing strict payload parsing and size limits.
- Rejecting deterministic payloads that require secret-key-bearing arguments.
- Preserving a separate off-chain channel for trusted secret-key operations.

---

## 3. Goals and Non-Goals

### 3.1 Goals

1. Provide deterministic VM-compatible interfaces for post-quantum verification.
2. Ensure fail-closed parsing and dispatch semantics.
3. Prevent secret-key payload usage in deterministic/on-chain interfaces.
4. Maintain reproducible test, security, and release evidence workflows.
5. Support integration patterns across multiple blockchain runtime families.

### 3.2 Non-Goals

1. Running full chain-specific deployment pipelines from this crate.
2. Exposing deterministic signing or key-generation in VM adapter interfaces.
3. Replacing platform-laboratory side-channel certification of third-party C implementations.
4. Publishing public package-manager distributions outside licensed channels.

---

## 4. Normative Language

The keywords MUST, MUST NOT, REQUIRED, SHOULD, and MAY are used as defined by RFC 2119.

---

## 5. System Overview

### 5.1 Logical Components

1. `src/pqc/*`: algorithm wrappers and FFI boundaries.
2. `src/integrations/abi.rs`: deterministic ABI parser/encoder/dispatcher.
3. `src/integrations/*`: chain-specific adapter shims.
4. `src/key_lifecycle.rs`: key metadata lifecycle manager.
5. `src/quantum_randomness_beacon.rs`: beacon generation and verification.
6. `src/security/mod.rs`, `src/utils.rs`: hardened utility primitives.

### 5.2 Trust Boundaries

1. Host runtime input boundary -> AEG1 payload parser.
2. Rust wrapper boundary -> vendored C cryptographic functions.
3. Build environment -> generated release artifacts.
4. Release artifacts -> customer verification environment.

---

## 6. Functional Requirements

### FR-001 Deterministic Interface Safety

The deterministic interface MUST reject operations requiring secret-key-bearing payloads.

- Implementation: `src/integrations/abi.rs` deterministic encode/dispatch checks.
- Verification: `tests/integrations_dispatch.rs`, `tests/side_channel_review.rs`.

### FR-002 Bounded ABI Parsing

The ABI MUST enforce payload and argument bounds and reject malformed/truncated payloads.

- Limits:
  - `MAX_PAYLOAD_BYTES = 1_048_576`
  - `MAX_ARGS = 8`
  - `MAX_ARG_BYTES = 131_072`
  - `MAX_RESPONSE_BYTES = 131_072`

### FR-003 Deterministic Verification Operations

The deterministic dispatcher MUST support:

- ML-DSA detached verification for 44/65/87 parameter sets.
- FN-DSA detached verification for 512/1024 parameter sets.

### FR-004 Off-chain Decapsulation Path

The module MUST expose ML-KEM decapsulation via off-chain dispatch only.

### FR-005 Adapter Routing/Binding Integrity

Adapters with route or binding semantics MUST enforce those semantics before dispatch.

- Move: module/function to op/alg match.
- CosmWasm: bound contract identifier envelope match.

### FR-006 Key Lifecycle State Integrity

Key state transitions MUST be validated and auditable.

### FR-007 Beacon Commitment and Policy Enforcement

Beacon verification MUST validate commitment correctness and enforce policy fields.

### FR-008 Panic-Resilient Error Handling

Expected failure modes in runtime-facing interfaces SHOULD return errors and SHOULD NOT crash host processes.

### FR-009 Reproducible Security Gates

The module MUST provide scripts to execute quality, security, and release evidence gates deterministically.

---

## 7. Non-Functional Requirements

### NFR-001 Determinism

Deterministic adapters MUST avoid entropy-requiring operations in dispatch paths.

### NFR-002 Robustness

Malformed payloads MUST fail closed with explicit errors.

### NFR-003 Auditability

Release outputs SHOULD include checksums, SBOM, and reproducible logs.

### NFR-004 Portability

The module SHOULD build on supported Rust toolchains with C compiler availability and optional architecture-specific optimizations.

### NFR-005 Security Posture

The module MUST enforce strict lint/test/security gate checks before release packaging.

---

## 8. Public Rust Interface Specification

### 8.1 Crate Exports

From `src/lib.rs`:

- `pub mod integrations`
- `pub mod key_lifecycle`
- `pub mod pqc`
- `pub mod quantum_randomness_beacon`
- `pub mod security`
- `pub mod traits`
- `pub mod utils`
- `pub use pqc::kem::mlkem`
- `pub use pqc::signatures::{fndsa, mldsa}`

### 8.2 Common Traits

From `src/traits.rs`:

- `KeyEncapsulation`
- `SignatureScheme`
- `SelfTest`

These traits define conceptual interfaces used across module primitives.

---

## 9. AEG1 ABI Specification

### 9.1 Request Encoding

`request := magic(4) || op(1) || alg(1) || argc(1) || args`

`arg := arg_len_be_u32(4) || arg_bytes`

`magic` MUST equal ASCII `AEG1`.

### 9.2 Response Encoding

`response := magic(4) || status(1) || body`

- `status=0`: `body := result_len_be_u32 || result_bytes`
- `status=1`: `body := error_code(1) || msg_len_be_u32 || msg_bytes`

### 9.3 Operations and Arguments

| Op | Name | Deterministic | Arguments | Output |
|---|---|---|---|---|
| 1 | `MlkemDecapsulate` | No | `ciphertext`, `secret_key` | `shared_secret` |
| 2 | `MldsaVerifyDetached` | Yes | `public_key`, `message`, `signature` | `[1]` or `[0]` |
| 3 | `FndsaVerifyDetached` | Yes | `public_key`, `message`, `signature` | `[1]` or `[0]` |

### 9.4 Algorithm Identifiers

| Alg ID | Algorithm |
|---|---|
| 1 | ML-KEM-512 |
| 2 | ML-KEM-768 |
| 3 | ML-KEM-1024 |
| 10 | ML-DSA-44 |
| 11 | ML-DSA-65 |
| 12 | ML-DSA-87 |
| 20 | FN-DSA-512 |
| 21 | FN-DSA-1024 |

### 9.5 Deterministic Dispatch Contract

`dispatch_deterministic(payload)` MUST:

- decode payload with bounded parsing;
- reject unsupported operations;
- reject ML-KEM decapsulation;
- return encoded `AEG1` success body for successful verification;
- return `IntegrationError` for malformed/unsupported requests.

### 9.6 Off-chain Dispatch Contract

`dispatch_offchain(payload)` MAY execute ML-KEM decapsulation in trusted environments where secret-key payload handling is acceptable by deployment policy.

---

## 10. Deterministic Gas Cost Specification

`gas = fixed(op,alg) + 21000 + 500*argc + 16*total_arg_bytes`

Fixed cost mapping:

- ML-DSA-44 verify: `120000`
- ML-DSA-65 verify: `150000`
- ML-DSA-87 verify: `200000`
- FN-DSA-512 verify: `90000`
- FN-DSA-1024 verify: `140000`

If op/alg is unsupported for deterministic metering, an error is returned.

---

## 11. Adapter Specifications

### 11.1 EVM Adapter

- Function: `evm_precompile_call(payload)`
- Function: `evm_gas_cost(payload)`
- Empty payload MUST be rejected.
- Dispatch target MUST be deterministic dispatcher.

### 11.2 Substrate Adapter

- Function: `SubstrateIntegration::dispatch_call(call_data)`
- Empty payload MUST be rejected.
- Dispatch target MUST be deterministic dispatcher.

### 11.3 CosmWasm Adapter

Envelope format:

`CWB1 || contract_len_u32_be || contract || aeg1_payload`

Rules:

- contract bytes MUST be non-empty;
- encoded message MUST include valid envelope;
- bound contract in envelope MUST equal runtime contract parameter;
- payload MUST be non-empty;
- dispatch target MUST be deterministic dispatcher.

### 11.4 Solana Adapter

- Function: `SolanaIntegration::invoke_instruction(ix)`
- Instruction bytes are interpreted as AEG1 payload.
- Empty instruction payload MUST be rejected.

### 11.5 Move Adapter

- Function: `MoveIntegration::invoke_entry_function(module, function, args)`
- `module` and `function` MUST be non-empty.
- `args.len()` MUST equal `1`.
- Decoded payload op/alg MUST match route mapping.

Route mapping:

- `aegis::mldsa44_verify_detached -> (MldsaVerifyDetached, Mldsa44)`
- `aegis::mldsa65_verify_detached -> (MldsaVerifyDetached, Mldsa65)`
- `aegis::mldsa87_verify_detached -> (MldsaVerifyDetached, Mldsa87)`
- `aegis::fndsa512_verify_detached -> (FndsaVerifyDetached, Fndsa512)`
- `aegis::fndsa1024_verify_detached -> (FndsaVerifyDetached, Fndsa1024)`

### 11.6 Bitcoin Adapter

- Function: `BitcoinIntegration::verify_script_payload(payload)`
- Empty payload MUST be rejected.
- Dispatch target MUST be deterministic dispatcher.

---

## 12. Key Lifecycle Specification

### 12.1 Data Model

- Key ID: `u64`
- Algorithm family enum: ML-KEM/ML-DSA/FN-DSA variants
- Metadata fields: `created_at`, `last_used`, `state`
- Audit event fields: timestamp, key ID, event type, details

### 12.2 State Machine

| Current State | Operation | Next State | Allowed |
|---|---|---|---|
| N/A | `register_key` | `Active` | Yes |
| `Active` | `touch_key` | `Active` | Yes |
| `RotationScheduled` | `touch_key` | `RotationScheduled` | Yes |
| `Active` | `schedule_rotation` | `RotationScheduled` | Yes |
| `Active` | `retire_key` | `Retired` | Yes |
| `RotationScheduled` | `retire_key` | `Retired` | Yes |
| Any except `Destroyed` | `destroy_key` | `Destroyed` | Yes |
| `Destroyed` | `destroy_key` | N/A | No |

Invalid transitions MUST return `KeyLifecycleError`.

### 12.3 Capacity and ID Allocation

- Default manager capacity: `100000` keys.
- ID allocation is monotonic and checked for overflow.

### 12.4 Audit Export

`write_audit_log_jsonl(path)` writes JSONL records with escaped details and flushes output to stable storage.

---

## 13. Randomness Beacon Specification

### 13.1 Core Types

- `QuantumBeacon`
- `BeaconOutput`
- `BeaconProof`
- `BeaconPolicy`
- `VerificationResult`

### 13.2 Entropy Source Interface

`EntropySource` trait:

- `sample(bytes) -> Result<Vec<u8>, String>`
- `source_name() -> &str`

### 13.3 Policy Parameters

- `min_entropy_sources`
- `epoch_duration_seconds`
- `require_hardware_entropy`

### 13.4 Beacon Generation Algorithm (Normative)

Given policy `P` and current state:

1. Validate policy exists.
2. Validate registered entropy source count >= `P.min_entropy_sources`.
3. If `P.require_hardware_entropy`, ensure at least one registered hardware-attested source.
4. Enforce cadence: current timestamp >= previous timestamp + `P.epoch_duration_seconds`.
5. Sample all entropy sources.
6. Build randomness input over prior hash, timestamp, policy id, epoch, and source samples.
7. Extract 32-byte output via SHAKE256.
8. Construct commitment hash over proof-critical fields.
9. Sign signature message with ML-DSA-87 keypair.
10. Append output to chain, update previous output and epoch.

### 13.5 Beacon Verification Algorithm (Normative)

`verify_beacon(output)` MUST validate:

1. epoch coherence (`proof.epoch == output.epoch` and sequence constraints),
2. policy existence and conformance,
3. source metadata consistency,
4. derived randomness recomputation,
5. commitment recomputation equality,
6. signature validity,
7. chaining and epoch cadence constraints against previous entry.

### 13.6 Standalone Verification

`verify_beacon_standalone(output, verification_key, previous_randomness)` MUST verify signature and commitment without requiring full beacon state, with optional previous-hash chaining check.

---

## 14. Security Utility Specification

### 14.1 Constant-Time Comparison

`constant_time_eq(a, b)` compares equal-length slices in a branch-stable XOR accumulation pattern.

### 14.2 Zeroization

`zeroize(buf)` performs volatile byte writes and a compiler fence (`SeqCst`) to reduce optimization-elision risk.

### 14.3 Secure Random

`secure_random_bytes(len)` delegates to `getrandom` and returns an error on backend failure.

### 14.4 C-ABI Random Compatibility

`randombytes` and `randombytes_init` provide compatibility entry points for linked C implementations expecting NIST-style RNG symbols.

---

## 15. Build and Supply-Chain Specification

### 15.1 Source Resolution

`build.rs` MUST resolve cryptographic source roots via explicit override or pinned local tree.

### 15.2 Source Collection Rules

The build process excludes:

- test directories/files,
- KAT generators,
- benchmark/speed helper files,
- non-production wrappers not required by linked targets.

### 15.3 Quality Gates

Release candidates MUST pass `scripts/run_quality_gates.sh` end-to-end.

### 15.4 Release Evidence

Release evidence MUST include:

- checksum manifest files,
- CycloneDX SBOM,
- customer package archive and checksum,
- security gate outputs and sign-off docs.

---

## 16. Verification and Acceptance Criteria

A build is considered release-candidate-ready when all of the following are true:

1. formatting, compile, tests, lint, and dependency audit pass;
2. deterministic KAT replay passes;
3. side-channel boundary review passes;
4. fuzz and fault campaign pass;
5. traceability matrix check passes;
6. independent sign-off check passes;
7. release manifest, SBOM, and customer bundle artifacts are generated.

---

## 17. Limitations and Residual Risks

1. Deterministic adapters intentionally do not provide signing or deterministic decapsulation.
2. Off-chain decapsulation requires trusted secret handling outside on-chain calldata domains.
3. Third-party vendored C implementation microarchitectural properties require platform-specific lab assessment.
4. Supply-chain and dependency risk is reduced but not eliminated between release windows.

---

## 18. Documented Test Evidence Mapping

The module maintains a formal requirement-to-evidence mapping in:

- `docs/security/TRACEABILITY_MATRIX.md`

This mapping links requirement IDs `RQ-VM-001` through `RQ-VM-010` to source controls and verification artifacts.

---

## 19. Revision Control

This specification MUST be updated when any of the following change:

- AEG1 payload schema,
- supported operations or algorithm IDs,
- deterministic/off-chain boundary rules,
- adapter route-binding semantics,
- policy gate requirements or release evidence requirements.
