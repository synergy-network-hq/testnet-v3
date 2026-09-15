# Smart-Contract Production-Readiness Checklist

Audit baseline: 2026-07-15 at AIVM revision `d2d8e67`

Current status: **0 production sign-off gates satisfied**

This checklist covers the work required before SynQ smart contracts can be deployed and used on the Synergy network. Items are intentionally unchecked. Existing demonstrations and isolated unit tests do not satisfy a gate unless the acceptance evidence below exists on the actual integrated and deployed path.

## P0 — establish the single AIVM architecture

- [ ] Make `synergy-aivm` the sole owner of the executable SynQ instruction engine, runtime state machine, host ABI, and execution semantics.
- [ ] Remove the `quantumvm` dependency on `synq-language/vm` from `runtime/aivm-core/Cargo.toml`.
- [ ] Remove `synq-language/vm` as an executable workspace VM; retain only shared versioned bytecode/ABI definitions needed by compiler and AIVM.
- [ ] Delete or quarantine the dead `TESTNET:src/aivm` duplicate runtime and separate WASM VM so it cannot be re-enabled as a competing AIVM.
- [ ] Delete or replace the fake `TESTNET:src/synq/compiler.rs` and `TESTNET:src/synq/interpreter.rs` surfaces; testnet must call the real SynQ compiler/artifact libraries and the one AIVM.
- [ ] Select one canonical AIVM Git checkout and remove the stale standalone/unversioned copies from release and developer workflows.
- [ ] Define a version compatibility matrix for SynQ compiler, bytecode, ABI, manifest, AIVM runtime, chain protocol, and activation height.

Acceptance: dependency inspection and repository-wide call tracing show exactly one executable VM; CI rejects reintroduction of a second interpreter/runtime.

## P0 — define and implement real SynQ execution

- [ ] Freeze a canonical, versioned SynQ bytecode specification with opcode encodings, operands, stack/memory rules, traps, control flow, and upgrade rules.
- [ ] Implement the complete bytecode decoder/verifier inside AIVM with bounds, type/stack, jump-target, resource, and forbidden-operation validation.
- [ ] Implement AIVM-owned deterministic execution for every supported SynQ opcode.
- [ ] Pass calldata, caller, contract address, transaction hash, block height/time, chain/network IDs, value, gas limits, and policy context into execution.
- [ ] Implement canonical ABI decoding/encoding; remove ad hoc JSON argument decoding from consensus execution.
- [ ] Implement method dispatch from the compiled ABI rather than hard-coded contract names/selectors.
- [ ] Execute deployment bytecode and constructors; reject deployment if initialization traps or exceeds gas.
- [ ] Return canonical ABI bytes, structured logs/events, and stable error/revert data instead of a debug-formatted stack.
- [ ] Implement deterministic memory allocation, maximum memory, call stack, operand stack, recursion/call-depth, and instruction limits.
- [ ] Implement contract-to-contract calls, static/read-only calls, nested rollback, return/revert propagation, and reentrancy policy.
- [ ] Implement value transfer semantics and atomic balance/state rollback.
- [ ] Decide whether WASM is a supported contract artifact. If yes, implement actual export invocation, ABI, deterministic host functions, metering, memory limits, and traps; if no, remove `WasmModuleV1` and the loader-only success path.
- [ ] Replace Counter and STS-9 Rust emulation with normal compiled SynQ contracts or formally declare/version narrowly scoped native precompiles that are not presented as general bytecode execution.

Acceptance: a conformance suite compiles and executes representative contracts using the same bytecode and AIVM path deployed on validators; changing contract source changes runtime behavior without adding Rust contract-specific code.

## P0 — canonical contract state and host functions

- [ ] Define canonical account, contract, code, storage, nonce, balance, and metadata schemas.
- [ ] Persist contract bytecode, ABI, manifest, deployment record, and storage in the chain’s canonical database.
- [ ] Bind all state reads/writes to the current block execution transaction and commit them atomically with the block.
- [ ] Implement snapshot, restart restore, replay, compaction, pruning, reorg/fork, and crash-consistency behavior.
- [ ] Include full AIVM state in the canonical consensus state root, not only an in-memory helper root.
- [ ] Implement deterministic host functions for storage, caller/value, block context, hashing, signature verification, events, and cross-contract calls.
- [ ] Specify every host function’s ABI, gas/PQ-gas schedule, mutability, authorization, and deterministic error behavior.
- [ ] Replace address-shape checks with canonical Synergy address decoding, checksum/network validation, and typed address handling.
- [ ] Eliminate wall-clock time, filesystem, network, random, process, and host-order nondeterminism from consensus execution.
- [ ] Prove state equivalence across supported validator platforms and clean restarts.

Acceptance: validators replay the same block from the prior canonical state and produce identical receipts/state roots after process restarts and across platforms.

## P0 — consensus, transaction, and fee integration

- [ ] Wire AIVM execution into the actual live block proposal, validation, commit, replay, and synchronization paths.
- [ ] Make failed contract transactions consensus-visible with canonical status, gas consumption, fees, and state rollback.
- [ ] Persist and restore SynQ verification summaries, artifacts, deployments, AIVM state, and receipts.
- [ ] Remove the separate RPC-only receipt replay as an authority; RPC must read consensus-committed execution records.
- [ ] Bind actual block height and consensus-bounded timestamp into the AIVM context; remove `block_height: 0`.
- [ ] Bind the verified signer/authorization result into execution instead of discarding `_verification`.
- [ ] Define nonce, replay protection, maximum artifact/calldata sizes, expiration, and transaction ordering rules.
- [ ] Integrate base gas and PQ-gas with fee reservation, charging, refunds, burn/reward accounting, and insufficient-funds behavior.
- [ ] Version gas schedules under consensus and provide activation/migration logic.
- [ ] Validate proposal-vs-execution state/receipt roots before a validator votes or commits.
- [ ] Add state migration and rollback procedures for AIVM protocol upgrades.

Acceptance: a multi-validator test produces the same committed AIVM roots/receipts on every node and retains them after restart, resync, and compaction.

## P0 — artifact admission and security policy

- [ ] Require ABI artifacts rather than validating `abi_hash` only when an optional ABI is present.
- [ ] Validate `manifest_version`, `compiler_version`, `required_aivm_version`, `source_hash`, and `storage_schema_hash`.
- [ ] Validate requested `permissions` and `host_functions` against an allowed, versioned capability policy.
- [ ] Cryptographically bind bytecode, ABI, manifest, compiler/source metadata, chain/network, deployer, nonce, and expiration in the signed deployment payload.
- [ ] Verify ML-DSA signatures with approved keys/algorithms on the actual admission path and account for PQ-gas.
- [ ] Enforce maximum bytecode, manifest, ABI, metadata, calldata, return-data, log, and storage-write sizes.
- [ ] Reject unknown fields/versions where consensus safety requires closed-world decoding.
- [ ] Define artifact/code availability, retention, retrieval, and content-addressing rules.
- [ ] Produce reproducible compiler builds and artifact provenance/SBOM evidence.

Acceptance: negative/adversarial tests demonstrate fail-closed behavior for every altered field, unsupported capability, oversize payload, bad signature, and version mismatch.

## P0 — deployed RPC and developer transaction path

- [ ] Provide a supported deploy transaction builder that signs the canonical SynQ envelope with the user’s wallet key.
- [ ] Provide a supported call transaction builder and read-only call endpoint using identical ABI/runtime semantics.
- [ ] Expose committed deployment status, receipt, code, ABI/manifest, storage, logs/events, and execution errors.
- [ ] Replace the disabled/empty `synergy_call`, `synergy_getCode`, and `synergy_getStorageAt` handlers with canonical state-backed implementations.
- [ ] Decide and document the supported AIVM RPC method set; remove commented handlers and fabricated stats.
- [ ] Route public RPC methods through the correct service-access role and prove availability through the production gateway.
- [ ] Add gas/PQ-gas estimation that executes against a snapshot with the same limits and rules as consensus.
- [ ] Integrate SynQ deployment/call flows into the supported wallet, CLI, JS SDK, and any explorer/Atlas surfaces.
- [ ] Publish stable JSON-RPC schemas, errors, examples, and versioning rules.

Acceptance: from a clean external machine, a user can compile, wallet-sign, deploy, query, call, observe events, and verify changed state on the public network.

## P0 — build and test gates

- [ ] Fix duplicate `pqrust-internals` workspace identities so the official integrated workspace builds without copying source elsewhere.
- [ ] Add a real root Cargo workspace for AIVM or explicit reproducible build orchestration for every component.
- [ ] Implement `aivm-node` or remove it if validators embed AIVM; an empty binary may not remain a release component.
- [ ] Implement a real verifier crate target or remove the unusable manifest.
- [ ] Fix all contract fixture paths and replace skip-and-return tests with hard failures when required artifacts are absent.
- [ ] Add compiler-to-artifact-to-signed-transaction-to-mempool-to-consensus-to-RPC end-to-end tests.
- [ ] Test deploy/call/revert/events/storage/value/cross-call/recursion/out-of-gas/PQ-out-of-gas/invalid-artifact/replay/restart/reorg behavior.
- [ ] Add bytecode verifier fuzzing, interpreter differential tests, state-machine property tests, ABI fuzzing, and malformed-input corpora.
- [ ] Add deterministic cross-platform vectors for state roots, receipt roots, gas, PQ-gas, return data, and errors.
- [ ] Add performance limits and benchmarks for block execution, large state, cold/warm access, worst-case bytecode, and denial-of-service inputs.
- [ ] Run all tests in CI with no ignored/skipped required gates and archive machine-readable evidence.

Acceptance: the official release commit passes a clean, reproducible, fail-closed CI pipeline in the integrated topology.

## P0 — security and operations sign-off

- [ ] Complete a repository-grounded threat model covering consensus determinism, untrusted bytecode, state, gas, PQC, RPC, artifact supply chain, and upgrades.
- [ ] Remove every P0/P1 item in `INCOMPLETE_IMPLEMENTATIONS.md`; CI must reject empty or marker implementations in production packages.
- [ ] Add sandbox/resource isolation appropriate to the chosen execution design.
- [ ] Prove access control for deployment policy, upgrades, privileged host functions, registry/governance actions, pause/recovery, and state migration.
- [ ] Add reentrancy, checks-effects-interactions, nested-call rollback, unchecked-result, integer-boundary, precision/rounding, and authorization invariants.
- [ ] Define oracle freshness/authenticity/manipulation rules before exposing any oracle host/precompile surface.
- [ ] Perform internal security review, external smart-contract VM audit, dependency audit, and reproducible remediation verification.
- [ ] Define metrics, logs, traces, alerts, and health checks for AIVM execution without leaking sensitive payloads.
- [ ] Define validator rollout, activation height, mixed-version prevention, canary, rollback, and chain-recovery runbooks.
- [ ] Package exact AIVM version/hash/config into every validator release and expose it through diagnostics.
- [ ] Run a public testnet soak with adversarial contracts, load, validator restarts, state sync, and upgrade rehearsal.
- [ ] Obtain explicit consensus, security, operations, SDK/wallet, and network release sign-offs.

Acceptance: audited release artifacts are deployed to all required nodes, public end-to-end proof passes, and monitoring confirms sustained correct operation.

## Final production acceptance scenario

This checklist is complete only when all of the following occur on the real public network:

1. A clean SynQ toolchain compiles a non-hard-coded stateful contract.
2. A supported wallet signs and submits its deployment.
3. Validators execute the same AIVM bytecode and commit identical state/receipt roots.
4. Public RPC returns the committed code, manifest, receipt, logs, and storage.
5. A second wallet submits calls that exercise authorization, state mutation, read-only queries, events, revert, and gas limits.
6. Results survive validator restarts, replay, state sync, and a compacted history window.
7. No separate VM/interpreter participates anywhere in that path.
