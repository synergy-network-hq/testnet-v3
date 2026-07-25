# Synergy AIVM Current Status

Audit date: 2026-07-15

Audited authoritative AIVM revision: `d2d8e67df88145d2262f5997800d6bb2171577ea`

Verdict: **not production-ready, not operational for general SynQ smart contracts, and not operational for decentralized AI inference**

## Architectural rule used by this audit

The Synergy AIVM is the one and only virtual machine for SynQ. SynQ may own its language definition, parser, compiler, artifact format, and shared bytecode definitions, but it must not own or ship another executable VM, interpreter, state machine, or simulator. Smart-contract execution and AI execution must terminate in the AIVM.

The current source violates that rule. `runtime/aivm-core/Cargo.toml:8,17` imports `quantumvm` from `synq-language/vm`, and `runtime/aivm-core/src/execution.rs:305-323` constructs that separate VM. Testnet also contains an unrelated legacy WASM VM under `TESTNET:src/aivm/wasm_vm.rs:1-293` and a fake SynQ interpreter under `TESTNET:src/synq/interpreter.rs:45-173`.

## Scope and source authority

This report was produced from source, manifests, repository topology, fresh builds/tests, and the live public testnet RPC. Existing status documents, roadmaps, proof logs, and completion checklists were not treated as evidence.

Evidence prefixes used in all readiness documents:

- `AIVM:` means this authoritative submodule at `network-components/01-Testnet/synergy-testnet/synergy-aivm`.
- `TESTNET:` means the parent repository at `network-components/01-Testnet/synergy-testnet`.
- `TOP-COPY:` means the unversioned collection copy at `network-components/synergy-aivm`.
- `CLONE:` means `network-components/synergy-aivm-git-checkout`.

Three AIVM copies exist and are not equivalent:

| Copy | Observed state | Consequence |
|---|---|---|
| `AIVM:` integrated submodule | Git revision `d2d8e67`; matches fetched `origin/main`; pinned by testnet | This is the authoritative code audited for network integration |
| `CLONE:` standalone checkout | Git revision `0b80a2c`; behind `origin/main` at `d2d8e67` | A developer building this checkout does not build the integrated source |
| `TOP-COPY:` collection folder | Not a Git worktree; source hash differs from the integrated submodule | It is an uncontrolled divergent copy and includes a fake attestation verifier absent from the authoritative revision |

Until there is one canonical checkout/release input, fixes can land in the wrong copy and never reach the network.

## Executive status

| Capability | Status | Source-derived finding |
|---|---|---|
| Single AIVM architecture | **Failed** | AIVM imports and constructs the separate `synq-language/vm` runtime |
| General SynQ execution | **Failed** | Deployment records metadata; calls either use hard-coded Counter/STS behavior or a stateless VM that receives no calldata/storage host |
| Deterministic artifact admission | **Partial** | Format, bytecode hash, optional ABI hash, chain/network, and policy strings are checked; multiple security/compatibility manifest fields are ignored |
| Contract state | **Prototype only** | Deterministic in-memory map and overlay exist; no persistent canonical database, snapshot/replay/reorg lifecycle, or live state owner exists |
| Gas/PQ-gas | **Partial** | Meters and receipt fields exist; WASM reports zero gas, generic stateful semantics do not execute bytecode, and no complete fee settlement path is live |
| Consensus execution | **Not wired to live node** | `execute_block` owns AIVM state in memory, but its production-looking PoSy callers are only reached by tests; live persistence/commit wiring was not found |
| Deployment/call RPC | **Disabled/not exposed** | AIVM/AI handlers are commented out; generic call/code/storage routes explicitly return empty values while AIVM is disabled |
| AIVM node service | **Absent** | All three Rust source files in `runtime/aivm-node/src` are zero bytes; the crate fails with `E0601` |
| AIVM verifier | **Absent in authoritative tree** | Verifier source files are zero bytes and its Cargo manifest has no usable target |
| AI model registry | **Absent** | Registry API/controllers/tools/storage adapters are empty; the checked-in JSON is a schema, not a deployed registry record |
| Provider network | **Absent** | Worker is a local one-shot ONNX demo with missing inputs; operator, configuration, attestation, scheduling, transport, and settlement are absent |
| Decentralized inference | **Absent** | No live task protocol, execution service, result verification, quorum binding, payment, RPC service, or contract host API exists |
| Operational deployment | **Failed** | Public testnet reports AIVM methods as `Method not found`; contract read routes return empty code/zero storage |

## What actually works

The following source is real, but its scope is narrow:

- `AIVM:runtime/aivm-core/src/execution.rs:236-263` computes a canonical receipt hash.
- `AIVM:runtime/aivm-core/src/state.rs:20-80` provides a deterministic in-memory state map and transactional overlay semantics.
- `AIVM:runtime/aivm-core/src/metering.rs` implements base and PQ-gas counters with limit checks.
- `AIVM:runtime/aivm-core/src/execution.rs:337-434` rejects malformed SynQ artifact formats, incorrect bytecode hashes, chain/network mismatches, and policy-string mismatches.
- `AIVM:runtime/aivm-core/src/synq_runtime.rs:701-725` deploys a hard-coded Counter state machine or generic metadata profile.
- `AIVM:runtime/aivm-core/src/synq_runtime.rs:914-925` routes a limited deterministic STS read surface and token emulation before falling back to the stateless VM.
- An isolated build outside the broken parent workspace passed all 38 `aivm-core` unit tests. Those tests cover receipt hashing, meters, state overlay behavior, artifact validation, Counter behavior, limited generic behavior, STS reads, and STS-9 token emulation. They do not prove arbitrary SynQ contract execution or network deployment.

## Why general SynQ contracts do not work

There are two divergent execution paths, neither of which implements the required contract lifecycle.

### Stateless bytecode path

`AIVM:runtime/aivm-core/src/execution.rs:295-335`:

1. Creates `quantumvm::QuantumVM` from the separate SynQ repository.
2. Loads only artifact bytes.
3. Calls `execute()` without calldata, caller, block context, persistent storage, contract address, value, logs, or host-function access.
4. Returns a debug-formatted VM stack as contract return data.

This is not an AIVM-owned contract ABI and cannot implement stateful arbitrary smart contracts.

### Stateful profile path

`AIVM:runtime/aivm-core/src/synq_runtime.rs:108-190,469-504,701-789,884-949`:

1. Validates the artifact and chooses either a `Counter` profile or a generic profile by contract name/metadata.
2. Deploys by writing `__deployed`, names, hashes, and optional token fields; it never executes deployment bytecode or a constructor.
3. Implements Counter, STS host reads, and STS-9 token calls directly in Rust using hard-coded selectors.
4. Sends every other call to the stateless bytecode path, which cannot see or modify the state map. The generic state root therefore remains unchanged by bytecode execution.

The current successful demonstrations prove hard-coded runtime behavior, not execution of compiled SynQ semantics.

## Network integration status

The parent testnet does contain a substantial admission/envelope/receipt prototype:

- `TESTNET:src/synq_execution.rs:306-362` constructs deploy requests and records artifacts/deployments in maps.
- `TESTNET:src/synq_execution.rs:446-489` constructs call requests and invokes `call_synq_contract`.
- `TESTNET:src/execution.rs:12-39` owns balances, STS data, SynQ artifacts, deployments, and AIVM state in one in-memory `ExecutionState`.
- `TESTNET:src/execution.rs:223-257` includes the AIVM state root in a derived execution state root.

It is not a live production execution lifecycle:

- `ExecutionState` has no persistent database owner or serialization/restore path at `TESTNET:src/execution.rs:12-39`.
- The only non-test source callers of `execute_block` are PoSy/anti-divergence helper methods. Repository-wide call tracing found those proposal/validation methods invoked only in their tests.
- RPC receipt lookup replays committed carrier transactions into a separate receipt index. That is derived RPC replay, not proof that consensus committed AIVM state.
- `TESTNET:src/synq_execution.rs:543-566` ignores the verification argument and writes `block_height: 0` even while carrying a runtime block height separately.
- `TESTNET:src/rpc/rpc_server.rs:3005-3194` comments out the direct AIVM and AI handlers.
- `TESTNET:src/rpc/rpc_server.rs:3671-3692,3845-3879` explicitly returns empty call/code/storage values because AIVM is disabled.

## Fresh verification results

| Check | Result |
|---|---|
| AIVM integrated revision vs fetched remote | `HEAD == origin/main == d2d8e67` |
| Direct `cargo test` in the integrated parent workspace | **Failed before compiling AIVM tests**: two workspace packages are named `pqrust-internals` (`aegis-pqvm/vendor/...` and `synq-language/pqrust/...`) |
| Isolated `cargo test` for `aivm-core` with copied AIVM + SynQ trees | **Passed: 38 passed, 0 failed, 0 ignored** |
| Isolated `cargo check` for `aivm-node` | **Failed**: `E0601`, `main` function not found |
| Isolated `cargo check` for `verifier-core` | **Failed**: manifest has no targets |
| Parent testnet Counter integration test | Not runnable in place because of duplicate workspace package names |
| Test fixture validity | Broken paths cause Counter execution/RPC tests to print a skip message and return success without testing |
| `.DS_Store` search in workspace | **0 remaining** |

The skipped test paths are exact: `TESTNET:src/execution.rs:1007-1018,1347-1350` and `TESTNET:src/rpc/rpc_server.rs:8932-8938,9586-9590,9646-9650` look for `/Volumes/xcode/Synergy-Network-Projects/synq-language/contracts`, while the integrated artifacts are under `network-components/01-Testnet/synergy-testnet/synq-language/contracts`.

## Live public testnet result

Fresh JSON-RPC requests to `https://testnet-rpc.synergy-network.io` produced:

- `synergy_getAIVMStats`: `-32601 Method not found`
- `synergy_deployAIVMContract`: `-32601 Method not found`
- `synergy_initiateDistributedAI`: `-32601 Method not found`
- `synergy_getCode` for a contract-shaped address: `0x`
- `synergy_getStorageAt` for a contract-shaped address: 32 zero bytes
- `synergy_call`: rejected on the public validator exposure profile; the checked-in handler would return an explicit AIVM-disabled empty result

This means a developer cannot currently use the public network surface to deploy and then execute a general SynQ contract, and no public decentralized-AI job surface exists.

## Readiness conclusion

The smart-contract side is an **engineering prototype** with useful artifact validation, deterministic hashing/metering primitives, and hard-coded Counter/STS demonstrations. It is not a general AIVM, it is not connected to durable consensus state, and it is not exposed as a working deployed contract platform.

The AI side is a **repository scaffold** plus a one-shot local ONNX example. It has no operational decentralized inference system.

Completion work is defined only in:

- `SMART_CONTRACT_PRODUCTION_READINESS.md`
- `AI_FEATURES_OPERATIONAL_READINESS.md`

Every source instance found that is empty, fake, hard-coded, disabled, dead, misleading, or materially incomplete is recorded separately in `INCOMPLETE_IMPLEMENTATIONS.md`.
