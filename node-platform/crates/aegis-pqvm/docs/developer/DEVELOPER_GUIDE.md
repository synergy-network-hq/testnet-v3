# Aegis PQVM Developer Guide

## 1. Purpose and Scope

`aegis-pqvm` is the post-quantum virtual machine integration module in the Aegis suite. It provides:

- Production Rust wrappers for ML-KEM, ML-DSA, and FN-DSA implementations.
- A deterministic byte-level ABI (`AEG1`) for VM-facing verification workloads.
- Integration adapters for EVM, Substrate, CosmWasm, Solana, Move, and Bitcoin-style host runtimes.
- Key lifecycle tracking and audit log generation.
- A verifiable randomness beacon with policy controls.
- Security and release evidence workflows for reproducible shipment.

This guide is for engineers extending, integrating, or operating `aegis-pqvm` as part of a production runtime pipeline.

## 2. Module Boundaries

In scope:

- Deterministic verification flows for on-chain style dispatch.
- Off-chain ML-KEM decapsulation flows in trusted environments.
- Build-time C source selection and reproducibility controls.
- Security gate scripts and release evidence artifacts.

Out of scope:

- Full blockchain node integration logic (gas metering policy, chain storage, account models).
- Runtime deployment/publishing orchestration for specific chains.
- Platform-lab side-channel certification of third-party vendored C code.

## 3. High-Level Architecture

```text
+------------------------------- Host Runtime --------------------------------+
| EVM | Substrate | CosmWasm | Solana | Move | Bitcoin-style verifier         |
+-------------------------------+--------------------------------------------+
                                |
                                v
                     +--------------------------+
                     | integrations::<adapter>  |
                     +------------+-------------+
                                  |
                                  v
                     +--------------------------+
                     | integrations::abi (AEG1) |
                     | decode/validate/dispatch |
                     +------------+-------------+
                                  |
                 +----------------+----------------+
                 |                                 |
                 v                                 v
      +-----------------------+          +----------------------------+
      | Deterministic ops     |          | Off-chain-only ops         |
      | ML-DSA verify         |          | ML-KEM decapsulate         |
      | FN-DSA verify         |          | (secret key in payload)    |
      +-----------------------+          +----------------------------+
                                  |
                                  v
                     +--------------------------+
                     | src/pqc/* Rust wrappers  |
                     | -> vendored C impls      |
                     +--------------------------+
```

## 4. Source Layout

Top-level module structure:

- `src/lib.rs`: module exports.
- `src/pqc/`: cryptographic wrappers and FFI bindings.
- `src/integrations/`: `AEG1` ABI and chain adapter shims.
- `src/key_lifecycle.rs`: key metadata state machine and audit events.
- `src/quantum_randomness_beacon.rs`: beacon generation/verification.
- `src/security/mod.rs`: hardened primitives facade and self-test hook.
- `src/utils.rs`: constant-time compare, zeroization, random bytes, C-ABI RNG shims.
- `src/bin/gen_aegis_kats.rs`: baseline vector generator for ML-DSA.
- `src/bin/pqvm_bench.rs`: benchmark runner.

Operational and compliance assets:

- `scripts/`: policy checks, quality gates, KAT replay, fuzz/fault, packaging.
- `docs/security/`: threat model, side-channel review, traceability, sign-off.
- `docs/compliance/`: ACVP and CMVP/FIPS boundary narratives.
- `docs/release/`: release policy, provenance and signing references.
- `artifacts/`: generated evidence output roots.

## 5. Build and Feature Configuration

### 5.1 Cargo Features

Default features:

- `mlkem`
- `mldsa`
- `fndsa`
- `security`

Optional features:

- `serialization` (enables `serde`, `serde-big-array`)
- `benchmarks` (enables `criterion`)
- chain markers: `evm`, `substrate`, `cosmwasm`, `move`, `solana`
- architecture markers: `avx2`, `neon`
- additional flags: `hardware-entropy`, `aes`

### 5.2 Build Source Root Pinning

`build.rs` resolves cryptographic C sources in this order:

1. `AEGIS_PQ_SOURCE_ROOT` environment variable (if set)
2. local pinned root: `./pqcore`
3. fail build if neither exists

This behavior ensures source provenance is explicit and reproducible.

### 5.3 Architecture-Specific Compilation

- `avx2` is activated only on `x86_64` targets when the `avx2` feature is enabled.
- `neon` is activated only on `aarch64` targets when the `neon` feature is enabled.

`build.rs` compiles clean implementations by default and optional optimized variants when available.

## 6. Cryptographic API Surface

### 6.1 ML-KEM

Module path: `aegis_pqvm::mlkem`

Implemented parameter sets:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

Common API per parameter set (`mlkem512`, `mlkem768`, `mlkem1024`):

- `keypair() -> (PublicKey, SecretKey)`
- `encapsulate(&PublicKey) -> (SharedSecret, Ciphertext)`
- `decapsulate(&Ciphertext, &SecretKey) -> SharedSecret`
- `public_key_bytes()`, `secret_key_bytes()`, `ciphertext_bytes()`, `shared_secret_bytes()`

### 6.2 ML-DSA

Module path: `aegis_pqvm::mldsa`

Implemented parameter sets:

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87

Common API per parameter set:

- `keypair()`
- `sign()`, `open()`
- `detached_sign()`, `verify_detached_signature()`
- context variants: `sign_ctx()`, `open_ctx()`, `detached_sign_ctx()`, `verify_detached_signature_ctx()`
- size helpers: `public_key_bytes()`, `secret_key_bytes()`, `signature_bytes()`

### 6.3 FN-DSA

Module path: `aegis_pqvm::fndsa`

Implemented variants:

- FN-DSA-512
- FN-DSA-1024
- FN-DSA-padded-512
- FN-DSA-padded-1024

Common API per variant:

- `keypair()`
- `sign()`, `open()`
- `detached_sign()`, `verify_detached_signature()`
- size helpers: `public_key_bytes()`, `secret_key_bytes()`, `signature_bytes()`

### 6.4 Canonical Byte Sizes

| Family | Variant | Public Key | Secret Key | Ciphertext | Signature | Shared Secret |
|---|---|---:|---:|---:|---:|---:|
| ML-KEM | ML-KEM-512 | 800 | 1632 | 768 | - | 32 |
| ML-KEM | ML-KEM-768 | 1184 | 2400 | 1088 | - | 32 |
| ML-KEM | ML-KEM-1024 | 1568 | 3168 | 1568 | - | 32 |
| ML-DSA | ML-DSA-44 | 1312 | 2560 | - | 2420 | - |
| ML-DSA | ML-DSA-65 | 1952 | 4032 | - | 3309 | - |
| ML-DSA | ML-DSA-87 | 2592 | 4896 | - | 4627 | - |
| FN-DSA | FN-DSA-512 | 897 | 1281 | - | 752 | - |
| FN-DSA | FN-DSA-1024 | 1793 | 2305 | - | 1462 | - |
| FN-DSA | FN-DSA-padded-512 | 897 | 1281 | - | 666 | - |
| FN-DSA | FN-DSA-padded-1024 | 1793 | 2305 | - | 1280 | - |

## 7. Deterministic Integration ABI (`AEG1`)

Primary file: `src/integrations/abi.rs`

### 7.1 Payload Format

`AEG1` request payload:

- `magic`: 4 bytes (`AEG1`)
- `op`: 1 byte
- `alg`: 1 byte
- `argc`: 1 byte
- repeated args:
  - `arg_len`: 4-byte big-endian unsigned integer
  - `arg_bytes`

Hard limits:

- `MAX_PAYLOAD_BYTES = 1_048_576`
- `MAX_ARGS = 8`
- `MAX_ARG_BYTES = 131_072`
- `MAX_RESPONSE_BYTES = 131_072`

### 7.2 Supported Operations

- `MlkemDecapsulate` (`op=1`): `(ciphertext, secret_key) -> shared_secret`
- `MldsaVerifyDetached` (`op=2`): `(public_key, message, signature) -> [0|1]`
- `FndsaVerifyDetached` (`op=3`): `(public_key, message, signature) -> [0|1]`

### 7.3 Deterministic vs Off-chain Dispatch

Deterministic APIs:

- `encode_call()`
- `dispatch_deterministic()`

Off-chain APIs:

- `encode_call_offchain()`
- `dispatch_offchain()`

Security boundary rule:

- deterministic encoding and deterministic dispatch reject ML-KEM decapsulation because it requires secret-key payload material.

### 7.4 Response Format

`AEG1` response payload:

- `magic`: 4 bytes (`AEG1`)
- `status`: 1 byte
  - `0 = OK`: followed by length-prefixed result bytes
  - `1 = ERR`: followed by `error_code` byte and length-prefixed UTF-8 message

### 7.5 Deterministic Gas Model

`gas_cost_deterministic(payload)` applies:

- fixed op/alg cost
- base tx cost `21_000`
- `500 * arg_count`
- `16 * total_arg_bytes`

Fixed costs:

- ML-DSA-44 verify: `120_000`
- ML-DSA-65 verify: `150_000`
- ML-DSA-87 verify: `200_000`
- FN-DSA-512 verify: `90_000`
- FN-DSA-1024 verify: `140_000`

No deterministic gas estimate is provided for ML-KEM decapsulation.

## 8. Adapter Behavior by Runtime

### 8.1 EVM Adapter

File: `src/integrations/evm/mod.rs`

- Entry: `evm_precompile_call(payload)`
- Deterministic only.
- Empty payloads are rejected.
- Gas helper: `evm_gas_cost(payload)`.

### 8.2 Substrate Adapter

File: `src/integrations/substrate/mod.rs`

- Entry: `SubstrateIntegration::dispatch_call(call_data)`
- Deterministic only.
- Empty payloads are rejected.

### 8.3 CosmWasm Adapter

File: `src/integrations/cosmwasm/mod.rs`

Envelope format:

- `CWB1 || contract_len_u32_be || contract || aeg1_payload`

Behavior:

- Contract-bound envelope must match the runtime contract identifier.
- Missing envelope fields, bad magic, mismatch, or empty payload fail closed.

### 8.4 Solana Adapter

File: `src/integrations/solana/mod.rs`

- Entry: `SolanaIntegration::invoke_instruction(ix)`
- Convention: instruction data bytes are the AEG1 payload.
- Empty payloads are rejected.

### 8.5 Move Adapter

File: `src/integrations/move/mod.rs`

- Entry: `MoveIntegration::invoke_entry_function(module, function, args)`
- Requires exactly one payload argument (`args.len() == 1`).
- Route binding enforcement: decoded `(op, alg)` must match `(module, function)`.

Supported routes:

- `aegis::mldsa44_verify_detached`
- `aegis::mldsa65_verify_detached`
- `aegis::mldsa87_verify_detached`
- `aegis::fndsa512_verify_detached`
- `aegis::fndsa1024_verify_detached`

### 8.6 Bitcoin Adapter

File: `src/integrations/bitcoin/mod.rs`

- Entry: `BitcoinIntegration::verify_script_payload(payload)`
- Deterministic only.
- Empty payloads are rejected.

## 9. Key Lifecycle Manager

Primary file: `src/key_lifecycle.rs`

### 9.1 Core Types

- `AlgorithmFamily`
- `KeyState`
  - `Active`
  - `RotationScheduled { at_timestamp }`
  - `Retired { reason }`
  - `Destroyed`
- `KeyMetadata`
- `KeyLifecycleEvent`
- `KeyLifecycleManager`

### 9.2 Default Capacity

- `KeyLifecycleManager::new()` defaults to `100_000` keys.
- `with_capacity(max_keys)` allows explicit caps.

### 9.3 State Transitions

Allowed:

- register -> active
- active -> rotation scheduled
- active/rotation scheduled -> retired
- any non-destroyed -> destroyed

Rejected with explicit errors:

- missing key id
- invalid state transitions
- non-future rotation timestamps
- empty retire reason
- capacity overflow

### 9.4 Audit Events

Each mutation records append-only events:

- `registered`
- `accessed`
- `rotation_scheduled`
- `retired`
- `destroyed`

JSONL export is provided by `write_audit_log_jsonl(path)`.

## 10. Quantum Randomness Beacon

Primary file: `src/quantum_randomness_beacon.rs`

### 10.1 Beacon Outputs

`BeaconOutput` includes:

- `epoch`
- `randomness` (`[u8; 32]`)
- `proof`

`BeaconProof` binds:

- epoch and timestamp
- policy id
- previous hash
- entropy inputs
- entropy source metadata
- hardware source metadata
- ML-KEM ciphertext provenance field
- ML-DSA signature
- commitment hash

### 10.2 Policy Controls

`BeaconPolicy` fields:

- `min_entropy_sources`
- `epoch_duration_seconds`
- `require_hardware_entropy`

Default policy:

- `id = default`
- `min_entropy_sources = 2`
- `epoch_duration_seconds = 300`
- `require_hardware_entropy = true`

### 10.3 Generation Workflow

`generate_beacon(policy_id)`:

1. load and validate policy
2. enforce minimum entropy source count
3. enforce hardware entropy requirement
4. enforce epoch cadence against previous timestamp
5. sample all entropy sources
6. derive randomness via SHAKE256 extractor
7. construct commitment over proof-critical fields
8. sign output with ML-DSA-87 signing key
9. append to chain and advance epoch

All failures return `Err(String)` and avoid panic-based termination in expected runtime paths.

### 10.4 Verification Workflow

`verify_beacon(output)` validates:

- epoch consistency
- policy existence and policy conformance
- source metadata consistency
- derived ML-KEM ciphertext field consistency
- derived randomness recomputation
- commitment recomputation
- signature validity
- previous-hash chaining
- epoch-duration enforcement

Standalone verifier:

- `verify_beacon_standalone(output, verification_key, previous_randomness)`

## 11. Security Primitives and Utility Layer

### 11.1 SecurityPrimitives

File: `src/security/mod.rs`

Exposes:

- constant-time compare
- zeroization
- secure random bytes
- key material length validation
- `SelfTest` implementation

### 11.2 Utility Functions

File: `src/utils.rs`

- `constant_time_eq(a, b)`
- `zeroize(buf)` using volatile writes and compiler fence
- `secure_random_bytes(len)`
- `ensure_key_length(buf, expected)`
- `sha3_digest(data)`

Also exports C-ABI compatibility RNG shims:

- `randombytes`
- `randombytes_init`

## 12. Test and Verification Strategy

Key suites:

- `tests/integrations_dispatch.rs`: deterministic boundary enforcement and adapter behavior.
- `tests/vm_validation.rs`: malformed input and adapter semantics.
- `tests/quantum_randomness_beacon.rs`: commitment, policy, and entropy-failure handling.
- `tests/side_channel_review.rs`: wrapper-boundary checks.
- `tests/fault_injection_campaign.rs`: deterministic mutation campaign.
- `tests/kat_mlkem.rs`, `tests/kat_mldsa_aegis.rs`, `tests/kat_fndsa.rs`: deterministic vector replay.
- `tests/security_smoke.rs`: tamper/negative-path cryptographic smoke tests.

## 13. Quality Gates and Evidence Pipeline

Primary orchestrator: `scripts/run_quality_gates.sh`

Ordered gates (17 total):

1. `cargo fmt --all -- --check`
2. `cargo check --all-targets --all-features --locked`
3. `cargo test --all-targets --all-features --locked`
4. `cargo clippy --all-targets --all-features --locked -- -D warnings`
5. `cargo audit`
6. naming policy
7. ignored-test policy
8. absolute-path policy
9. effective source marker policy
10. deterministic KAT replay
11. side-channel boundary review
12. fuzz + fault-injection campaign
13. traceability matrix check
14. independent security sign-off check
15. benchmark reproducibility report
16. release manifest + SBOM generation
17. customer bundle packaging

Key artifact outputs:

- `artifacts/acvp/`
- `artifacts/security/`
- `artifacts/checksums/`
- `artifacts/sbom/`
- `artifacts/package/`

## 14. Developer Workflows

### 14.1 Core Build and Test

```bash
cd aegis-pqvm
cargo build --all-features
cargo test --all-features
cargo clippy --all-targets --all-features --locked -- -D warnings
```

### 14.2 Full Production Gate Run

```bash
cd aegis-pqvm
./scripts/run_quality_gates.sh
```

### 14.3 Deterministic KAT Replay

```bash
cd aegis-pqvm
AEGIS_KAT_SEED=aegis-pqvm-kat-seed-v1 \
AEGIS_KAT_MAX_CASES=25 \
./scripts/run_deterministic_kat.sh
```

### 14.4 Fuzz and Fault Campaign

```bash
cd aegis-pqvm
AEGIS_FAULT_SEED=aegis-pqvm-fault-seed-v1 \
AEGIS_FAULT_ITERATIONS=10000 \
AEGIS_FUZZ_MAX_TOTAL_TIME=120 \
./scripts/run_fuzz_fault_campaign.sh
```

## 15. Extending the Module

### 15.1 Add a New Deterministic ABI Operation

1. Add enum value in `Op` and any new `Alg` identifiers in `src/integrations/abi.rs`.
2. Update encode/decode switch statements for op and alg parsing.
3. Implement dispatch branch in `dispatch_decoded_call`.
4. Decide deterministic eligibility:
   - if secret-key payload is required, keep off-chain only.
5. Add gas-cost mapping in `gas_cost_deterministic` if deterministic.
6. Add integration tests and VM validation tests.
7. Update user and technical documentation.

### 15.2 Add a New Adapter

1. Create `src/integrations/<adapter>/mod.rs`.
2. Add module export in `src/integrations/mod.rs`.
3. Enforce deterministic boundary on public entrypoints.
4. Add adapter-specific negative-path tests.
5. Add policy checks if adapter introduces routing/binding semantics.

### 15.3 Add New Algorithm Variant

1. Add or update FFI constants and bindings in `src/pqc/*/ffi.rs`.
2. Implement wrapper module (`keypair`, sign/verify or encapsulate/decapsulate).
3. Expose reexports in the parent `mod.rs`.
4. Extend `Alg` mapping and dispatch paths.
5. Add KAT and integration tests.
6. Confirm release scripts and docs reference the new variant.

## 16. Troubleshooting for Developers

### Build cannot find source root

- Ensure `./pqcore` exists, or set:

```bash
AEGIS_PQ_SOURCE_ROOT=/path/to/trusted/source/tree cargo build --all-features
```

### Deterministic adapter rejects payload unexpectedly

- Decode payload and verify `op` and `alg`.
- Confirm operation is deterministic-safe.
- Confirm argument count and exact byte lengths.

### Move adapter rejects payload-route mismatch

- Ensure `module`/`function` map exactly to payload `op`/`alg`.
- Ensure exactly one AEG1 payload is passed in `args`.

### CosmWasm adapter rejects contract mismatch

- Regenerate envelope with matching runtime contract bytes using `encode_bound_message`.

### Fuzz script fails on missing tooling

- Install `cargo-fuzz` and nightly toolchain.
- Re-run `./scripts/run_fuzz_fault_campaign.sh`.

## 17. Related Documentation

- User manual: `docs/manual/USER_MANUAL.md`
- Technical specification: `docs/specification/TECHNICAL_SPECIFICATION.md`
- Threat model: `docs/security/THREAT_MODEL.md`
- Traceability matrix: `docs/security/TRACEABILITY_MATRIX.md`
- Release policy: `docs/release/RELEASE_POLICY.md`
