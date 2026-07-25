# SynQ / aegis-pqsynq / Synergy-AIVM / Rosetta Dependency Map

Status date: 2026-05-26

## Canonical Direction

```text
.synq source
  -> SynQ compiler / CLI / SDK
  -> SynQ bytecode + ABI + manifest + security requirements
  -> aegis-pqsynq policy and verification
  -> Synergy-AIVM deterministic execution
  -> Synergy TESTNET chain 1264
  -> receipts, indexed events, replay evidence
```

Project Rosetta integrates beside the SynQ contract path as a network
settlement/verification consumer:

```text
Rosetta intent + scope digest + replay domain
  -> Rosetta verification/settlement artifacts
  -> aegis-pqsynq for Synergy/SynQ signatures where applicable
  -> Synergy TESTNET chain 1264 adapter / receipt verification
  -> optional Synergy-AIVM indexing or execution hooks after ownership decision
```

## Repositories And Roles

| Surface | Local path | Role | Must not own |
|---|---|---|---|
| SynQ Language | `/Volumes/xcode/synergy-network-projects/synq-language` | Source language, parser, AST, semantic analysis, type checking, bytecode, ABI, manifest, CLI, SDK, local simulation hooks | SynQ-specific PQ policy, AIVM runtime rules, live node consensus |
| aegis-pqsynq | `/Volumes/xcode/synergy-network-projects/aegis-pqsynq` and embedded `/Volumes/xcode/synergy-network-projects/synq-language/aegis-pqsynq` | SynQ-specific algorithm policy, domain separation, chain binding, signing payload canonicalization, key/address derivation, deploy/call verification | Bytecode execution, chain state transition, wallet UX policy |
| Synergy-AIVM | `/Volumes/xcode/synergy-network-projects/synergy-aivm` | Deterministic execution, bytecode loading, host ABI, gas/PQ-Gas metering, receipt generation, transcript/verifier flow | Language syntax, cryptographic policy definitions |
| Project Rosetta | `/Volumes/xcode/Synergy-Network-Projects/project-rosetta` | Prototype per-intent settlement/verification artifacts, scope digest/replay domain, mock adapters, future Synergy TESTNET receipt integration | Pooled bridge custody, wrapped-asset default, unreviewed production cryptography |
| Synergy TESTNET / chain 1264 | live node/runtime repos and hosts, not audited in this pass | Transaction admission, mempool policy, block execution, state commitment, RPC, validator replay, receipt indexing | Compiler semantics, generic Rosetta bridge custody |

## Allowed Dependencies

- `synq-language` may depend on `aegis-pqsynq` for policy validation, keygen,
  signing payload creation, deploy verification, call verification, and address
  derivation.
- `synergy-aivm` may depend on `aegis-pqsynq` for deploy/call verification
  gates and structured verification errors.
- `synergy-aivm` may depend on a SynQ bytecode/ABI/artifact crate if it is
  split out; until then it uses a relative dependency on `synq-language/vm`.
- TESTNET node/runtime may depend on `synergy-aivm` and either directly or
  indirectly on `aegis-pqsynq` for transaction precheck.
- Project Rosetta may depend on Synergy chain constants, `aegis-pqsynq`
  signature verification where Synergy/SynQ signatures appear, and Synergy
  TESTNET receipt/RPC types after those are frozen.

## Forbidden Dependencies

- `aegis-pqsynq` must not depend on `synergy-aivm`.
- `aegis-pqsynq` must not depend on Project Rosetta.
- SynQ compiler/CLI/SDK must not duplicate cryptographic policy that belongs in
  `aegis-pqsynq`.
- Synergy-AIVM must not invent independent SynQ address/signing/domain rules.
- Project Rosetta must not introduce a pooled custody bridge, wrapped-asset
  default, or live submit path before read-only chain-1264 verification passes.

## Current Verified Local Wiring

- SynQ workspace includes embedded `aegis-pqsynq/pqsynq` as a member.
- The active `aegis-pqsynq` crate is a SynQ-specific adapter over bundled
  `pqrust` crates. It does not wrap `aegis-pqvm`, and it should not own
  blockchain transaction admission.
- Testnet-Beta node source at
  `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/Cargo.toml`
  depends on `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/aegis-pqvm`
  for the active blockchain/PQVM admission path.
- Testnet-Beta node source now also depends on the active SynQ workspace
  `aegis-pqsynq` crate as `pqsynq` for inner SynQ deploy/call admission.
- `/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/src/synq_admission.rs`
  defines the Model B node boundary: `SynQAdmissionEnvelope`,
  `SynQAdmissionKind`, `SynQVerificationSummary`,
  `verify_synq_deploy_for_chain_admission`, and
  `verify_synq_call_for_chain_admission`.
- The Testnet-Beta Aegis carrier path calls pqsynq admission before existing
  `aegis-pqvm` outer transaction verification and DAG admission. Non-SynQ
  payloads continue through the existing pqvm path unchanged.
- Chain-1264 SynQ admission normalizes `synergy-testnet-v3` to pqsynq's
  `synergy-testnet` only at the SynQ gate; it rejects wrong chains and
  unrelated networks.
- Testnet-Beta internal execution receipts now carry optional
  `synq_verification`, `synq_error_code`, and `synq_error_message` fields.
- AIVM `runtime/aivm-core` depends on `../../../synq-language/vm` behind its
  default `synq` feature.
- AIVM currently accepts `synq-bytecode-v1` artifacts and executes them through
  the current SynQ VM bridge.
- Project Rosetta now has Rust and TypeScript helpers for Synergy TESTNET chain
  `1264` and namespace `synergy-testnet`, plus a Rust receipt-verifier
  interface that consumes deterministic chain-1264 receipt artifacts without a
  live transaction submission API.

## Open Dependency Decisions

- How to promote the active embedded `aegis-pqsynq` crate and standalone mirror
  into one build-proven authoritative source without breaking workspace-inherited
  `pqrust` dependencies.
- Whether AIVM embeds `quantumvm` or owns native SynQ opcode execution.
- Whether shared types become a new `synq-core-types` crate/package.
- Whether Project Rosetta verification logic runs inside AIVM, is only indexed
  by AIVM/node receipts, or stays external and read-only for the first TESTNET
  integration phase.
