# SynQ / aegis-pqsynq / AIVM Integration Contract

Status date: 2026-05-26

This document defines the contract between the language/compiler surface, the
SynQ-specific PQ policy adapter, and the deterministic AIVM runtime.

## SynQ Compiler Emits

The compiler/CLI/SDK must emit a deterministic artifact bundle:

- `.synq` source hash
- SynQ bytecode
- ABI
- manifest
- compiler version
- target AIVM version
- required chain ID and network ID
- security requirements
- bytecode hash
- ABI hash
- manifest hash

The compiler may validate security declarations against `aegis-pqsynq`, but it
must not duplicate deploy/call verification policy.

## aegis-pqsynq Verifies

`aegis-pqsynq` owns all SynQ-specific PQ authorization rules:

- algorithm allowlists
- key/public-key format validation
- SynQ address derivation
- domain separation
- chain and network binding
- nonce and expiration requirements
- canonical signing payload bytes
- signature verification
- deploy authorization
- call authorization
- structured SynQ crypto/security error codes

Required launch policy:

- chain ID: `1264`
- network: `synergy-testnet`
- default transaction/deploy/call algorithm: `ML-DSA-65`
- deployment domain: `SYNQ_CONTRACT_DEPLOY_V1`
- call domain: `SYNQ_CONTRACT_CALL_V1`

Current Testnet-Beta node source uses network ID `synergy-testnet-v3`. The
Model B node adapter treats `synergy-testnet` and `synergy-testnet-v3` as aliases
only for chain `1264`, normalizing to pqsynq's `synergy-testnet` before calling
`AegisSynQVerifier::testnet_1264()`. Wrong chains and unrelated network IDs are
rejected at the SynQ admission boundary.

## Testnet-Beta SynQ Carrier

The current source-backed carrier is
`/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/synq_admission.rs`.
It uses prefix `synq-admission-v1:` and a JSON-encoded
`SynQAdmissionEnvelope` with:

- `version`
- `kind = deploy | call`
- `chain_id`
- `network_id`
- `signer`
- `payload_hash`
- optional `bytecode_hash`, `manifest_hash`, and `abi_hash`
- `encoded_pqsynq_envelope`

The carrier is transported inside the existing outer Synergy
`synergy_types::Transaction.payload`. It does not replace the outer
`AegisTxSubmissionEnvelope` or `aegis-pqvm` admission layer.

The node adapter returns `SynQVerificationSummary` on success and
`SynQAdmissionError` on failure. The error wrapper preserves
`AegisSynQError::code()` values, including `AEGIS-CHAIN`, `AEGIS-DOMAIN`,
`AEGIS-SIG`, and `AEGIS-CANON`.

## AIVM Requires Before Execution

For deployment:

- valid bytecode format and version
- supported target AIVM version
- explicit AIVM execution context with chain ID, network ID, block
  height/timestamp, transaction hash, caller, contract address, gas limit,
  PQ-Gas limit, and security policy reference
- bytecode, ABI, and manifest hashes match the artifact envelope
- manifest security requirements are supported
- `aegis-pqsynq` verifies the deploy envelope
- chain ID, network ID, domain, nonce, expiration, and deployer are valid
- gas and PQ-Gas budgets are available

For contract calls:

- target contract exists
- ABI method exists and is visible
- arguments decode canonically
- `aegis-pqsynq` verifies the call envelope
- chain ID, network ID, domain, nonce, expiration, caller, and method selector
  are valid
- gas and PQ-Gas budgets are available

## AIVM Returns After Execution

AIVM must return a deterministic receipt:

- receipt version
- chain ID and network ID
- block height/timestamp from consensus context
- transaction hash
- contract address
- caller/deployer
- status
- gas used
- PQ-Gas used
- state root before and after
- event logs
- return data
- trap code and structured error family if failed
- execution trace hash
- `aegis-pqsynq` verification summary
- canonical receipt hash

Receipts must not include host-local, wall-clock, filesystem, random, or
non-canonical debug data.

Current source-backed status: `synergy-aivm/runtime/aivm-core` defines
`ExecutionContext`, rejects WASM host imports before instantiation, preserves
structured `AivmErrorCode` receipt errors, and exposes
`ExecutionReceipt::canonical_hash()` for deterministic local receipts. It also
defines a namespaced ordered key-value `StateOverlay` with commit/rollback,
deterministic state-root hashing, and an `AivmGasMeter` with separate ordinary
and PQ-Gas lanes. `ExecutionContext.admission_pq_gas_used` carries the inner
authorization cost into the local execution receipt. `ContractArtifact` now
carries `manifest_json`, and `validate_synq_artifact` verifies manifest
presence, `synq-bytecode-v1`, bytecode version/hash, ABI hash when present,
chain `1264`, `synergy-testnet`/`synergy-testnet-v3` aliasing, and ML-DSA-65
policy before SynQ bytecode execution.

## TESTNET Node Validates

The chain-1264 node/runtime must:

- reject wrong chain/network/domain payloads before execution
- verify `synq-admission-v1:` deploy/call carriers through `aegis-pqsynq`
  before outer `aegis-pqvm` transaction admission
- enforce nonce and replay rules
- precheck fees, gas, and PQ-Gas
- call AIVM for deploy/call execution
- commit state only on successful execution
- index contract address, bytecode hash, ABI hash, manifest hash, events, gas,
  PQ-Gas, status, trap code, and receipt hash
- replay the same block deterministically across validators

## Project Rosetta Boundary

Rosetta is a settlement/verification consumer of the network, not a privileged
compiler or AIVM owner. Its first Synergy profile binds to chain `1264` and
network `synergy-testnet`. Rosetta may consume or index AIVM/node receipts after
the receipt format is frozen, and it may use `aegis-pqsynq` for Synergy/SynQ
signatures. It must preserve per-intent escrow, no pooled custody, and no
wrapped-asset default.

Current local Rosetta code includes a mock `SynergyTestnetReceiptVerifier` that
accepts deterministic chain-1264 receipt artifacts and returns a Rosetta
`VerificationResult`. It intentionally has no live transaction submission API;
the current public RPC/indexer exposure of the new internal SynQ verification
summary fields remains pending.
