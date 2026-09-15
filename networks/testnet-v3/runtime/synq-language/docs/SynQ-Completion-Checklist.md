# SynQ Actual-Project Status and Completion Checklist

Audit date: 2026-07-15
Audit scope: `network-components/synq-language` and the SynQ execution surfaces in `network-components/synergy-aivm`
Status authority: this is the only current SynQ language project-status and completion-checklist document in `network-components/synq-language`.

## Architectural rule

SynQ does not own or ship a separate virtual machine. The Synergy Network AIVM in `network-components/synergy-aivm` is the one and only execution environment for SynQ contracts. A bytecode-format library shared by the compiler and AIVM is acceptable; a second executable VM, interpreter, state machine, or simulator in `synq-language` is not.

## Current verdict

SynQ is **not complete and not production-ready**. It is an engineering prototype with a useful parser/compiler skeleton, deterministic artifact generation, offline ML-DSA-65 deploy/call signing, substantial PQC backend coverage, and a tested Counter demonstration. It does not yet have a correct general-purpose compiler-to-AIVM execution path.

The most important blockers are architectural and semantic:

1. `synq-language/vm` is a separate `quantumvm` runtime and is still a workspace member and a compiler/CLI dependency.
2. `synergy-aivm/runtime/aivm-core` embeds that separate runtime through a path dependency instead of owning SynQ execution.
3. AIVM has two divergent SynQ paths: a stateless `quantumvm` path and a stateful path hard-coded to the Counter contract. The hard-coded path validates the Counter artifacts but does not execute their bytecode.
4. The compiler accepts syntax that its AST, semantic analyzer, or code generator cannot correctly represent or execute.
5. The AIVM node and chain adapters needed to expose execution to the network are empty.
6. The official NIST/PQC KAT replay suite fails because the required vector packages are absent.

No completion percentage is assigned because the missing pieces include the execution architecture itself; a numeric percentage would imply precision the project does not have.

## How this status was determined

This audit did not use previous roadmaps, completion plans, status documents, proof logs, or unchecked task registers as evidence. It examined the current manifests, owned source, tests, examples, generated artifacts, and fresh command behavior.

The separate `docs/SynQ-Incomplete-Code-Register.md` records 122 inspected instances of stubs, placeholders, mocks, hard-coded demonstrations, silent fallbacks, empty subsystems, and incomplete implementations with exact file and line references. It is defect evidence, not a second status checklist.

Primary source evidence:

| Surface | Current evidence | Assessment |
|---|---|---|
| Workspace architecture | `Cargo.toml` includes `vm`; `compiler/Cargo.toml` and `cli/Cargo.toml` depend on `quantumvm` | Incorrect for the required AIVM-only architecture |
| AIVM ownership | `synergy-aivm/runtime/aivm-core/Cargo.toml:8,17` enables SynQ by importing `../../../synq-language/vm` | AIVM does not own the current SynQ interpreter |
| Generic AIVM execution | `synergy-aivm/runtime/aivm-core/src/execution.rs:192-231` constructs `quantumvm::QuantumVM` and returns a debug-formatted stack | Prototype-only, stateless, and not a canonical contract ABI result |
| Stateful AIVM execution | `synergy-aivm/runtime/aivm-core/src/synq_runtime.rs:12-13,88-319,354-441` contains fixed Counter selectors and rejects every other contract | Demonstration, not a language runtime |
| AIVM node/chain connection | `runtime/aivm-node/src/*.rs` and the Cosmos handler/keeper files are zero bytes | No runnable AIVM network service or chain execution adapter |
| Parser | `compiler/src/synq.pest` exposes global functions, enums, generics, postfix access, rich literals, and modifiers | Grammar surface is broader than the implementation |
| AST lowering | `compiler/src/parser.rs:134-136` discards contract-local types; `405-433` discards lvalue access paths; `639-642` collapses unparsed expressions into identifiers | Lossy and unsafe for code generation |
| Version pragma | `compiler/src/parser.rs:49-79` keeps only the first constraint; `cli/src/main.rs:1083` discards the parsed requirement | Accepted but not enforced |
| Semantic analysis | `compiler/src/semantic.rs:655-658` tolerates unknown call targets; several accessor/initializer paths deliberately return unknown | Partial type and name safety |
| Control flow | Code generation treats `JumpIf` as a jump-on-false instruction while `vm/src/vm.rs:312-327` jumps on true | `if`, ternary, `require`, and `require_pqc` semantics are not trustworthy |
| Function calls | `compiler/src/codegen.rs:436-440` emits `Call` without the four-byte address required by `vm/src/vm.rs:328-340` | Ordinary calls produce malformed execution streams |
| Values | `compiler/src/ast.rs:171-177` stores numeric literals as `u64`; codegen truncates them to `u32`; the VM executes arithmetic as `i32` | Declared `UInt256`/`Int256` semantics are absent |
| State/events | Compiler state addresses are function-local hashes; event generation only leaves values on the stack | No general persistent storage or event ABI behavior |
| Artifacts | ABI/manifest generation and hashing are deterministic for exactly one contract | Useful foundation, but manifest fields are mostly empty and AIVM validation is incomplete |
| Admission security | CLI can sign and verify envelopes, but `ExecutionRequest` has no signed envelope/nonce and AIVM only compares signature-policy strings | No runtime signature admission or replay protection |
| PQC backends | ML-KEM, ML-DSA, FN-DSA, and HQC-KEM backend roundtrips pass; official replay files are missing | Substantial foundation with an evidence gap |
| CLI | Build/check/artifact/sign/verify commands exist; run/simulate use the forbidden local VM; no AIVM deploy/call submit command exists | Development tooling is partial |
| TypeScript SDK | Six fresh tests pass, including real local PQC operations, but the package is private, non-strict, has no entry point/build, and mocks RPC methods that no AIVM node implements | Prototype library, not a releasable SDK |
| Examples | All seven checked-in `.synq` source examples failed fresh local simulation | Examples demonstrate parsing/compilation only, not executable language coverage |
| Repository quality | Root SynQ formatting passes; strict clippy fails in three unsafe PQC functions; 669 `sdk/node_modules` files are tracked | Release hygiene is incomplete |

## Fresh verification results

The following results were produced from the current checkout during this audit:

- `cargo test --workspace --all-features --all-targets` — **failed**: four `nist_vector_replay_tests` could not find required ML-KEM, ML-DSA, FN-DSA, and HQC-KEM KAT files under `5-nist-kat-vectors/`.
- `cargo test --workspace --all-features --lib --bins --tests --examples -- --skip test_nist` — **passed**: 172 tests passed; the four official-vector tests were filtered out.
- `cargo test --manifest-path runtime/aivm-core/Cargo.toml --all-features --all-targets` in `synergy-aivm` — **passed**: 31 tests.
- Fresh isolated SDK install, typecheck, and integration tests — **passed**: 6 tests.
- `cargo fmt --all -- --check` in SynQ and `cargo fmt --manifest-path runtime/aivm-core/Cargo.toml -- --check` in AIVM — **passed**.
- `cargo clippy --workspace --all-features --all-targets -- -D warnings` — **failed** on three missing `# Safety` sections in `pqrust-internals`.
- AIVM core strict clippy — **passed**.
- `cargo check --manifest-path runtime/aivm-node/Cargo.toml` — **failed** because `src/main.rs` has no `main` function.
- Grammar-valid global-function probe — **panicked** at `compiler/src/parser.rs:38`.
- Canonical Counter simulation — **failed** with an uninitialized-memory address error.
- Ordinary function-call probe — **failed** because the VM could not read the missing four-byte call address.
- Modulo probe — **failed** with `Unsupported binary operation` after parsing succeeded.
- Six documented application contracts plus the HQC-KEM contract flow — **0 of 7 executed successfully**.

## Completion rules

- Every item below starts open. Existing code is foundation evidence, not proof that a completion task is done.
- An item may be checked only when its implementation and acceptance tests are committed together.
- Mock-only, compile-only, hash-only, or Counter-only tests cannot close a general language/runtime item.
- Production execution proof must use AIVM. Tests that directly instantiate `synq-language/vm` cannot close any AIVM item.
- Consensus-critical behavior must be deterministic across supported architectures and must fail closed.
- SynQ is fully complete only when every P0, P1, and release-gate item is checked and the final commands all pass without filters or missing external assets.

# Completion checklist

## P0 — Make AIVM the only SynQ execution environment

- [ ] **AIVM-001** Move or reimplement the SynQ bytecode interpreter under `synergy-aivm/runtime/aivm-core`; AIVM must own execution code, runtime values, gas metering, storage access, host functions, traps, and receipts.
- [ ] **AIVM-002** Remove `vm` from the `synq-language` workspace and delete the `quantumvm` crate after all AIVM-owned replacements and tests are active.
- [ ] **AIVM-003** Remove `quantumvm` dependencies and `pqc-aegis` forwarding from the SynQ compiler and CLI. The compiler may depend only on a non-executable, versioned bytecode-format/API crate.
- [ ] **AIVM-004** Remove the `quantumvm = ../../../synq-language/vm` path dependency and feature wiring from `aivm-core`.
- [ ] **AIVM-005** Create one canonical AIVM SynQ entry point for deploy and call. Remove the divergent stateless `execution.rs` interpreter path and hard-coded `synq_runtime.rs` Counter path.
- [ ] **AIVM-006** Make the canonical path execute the submitted SynQ bytecode for every accepted contract. Artifact validation without bytecode execution is not sufficient.
- [ ] **AIVM-007** Replace `CounterStateMachine`, fixed Counter selectors, fixed Counter ABI checks, and fixed Counter log strings with general ABI dispatch and storage operations.
- [ ] **AIVM-008** Implement the AIVM node binary, server, and provider-agent entry points; `cargo check --manifest-path runtime/aivm-node/Cargo.toml` must pass.
- [ ] **AIVM-009** Implement the chain handler/keeper/message boundary that submits verified deploy/call requests, commits state atomically, and returns canonical receipts to chain consensus.
- [ ] **AIVM-010** Define the deterministic boundary between consensus-critical SynQ execution and AIVM AI/model inference. Model calls must use explicit host functions, declared permissions, bounded metering, and verifiable deterministic receipt inputs.
- [ ] **AIVM-011** Implement real block, transaction, caller, contract-address, network, and timestamp context injection from the chain. Test constructors and functions that consume every context value.
- [ ] **AIVM-012** Eliminate direct debug-stack return data. Encode return values and errors according to the SynQ ABI/receipt formats.
- [ ] **AIVM-013** Distinguish success, revert, trap, gas exhaustion, PQ-gas exhaustion, admission rejection, and internal invariant failure in canonical receipts.
- [ ] **AIVM-014** Ensure deploy/call state overlays commit only on success and roll back on every other outcome, including PQC and AI host-function failures.
- [ ] **AIVM-015** Prove deterministic replay of identical request plus pre-state into identical post-state root, logs, gas, return data, and receipt hash on every supported validator architecture.

Acceptance gate:

- No source or manifest outside `synergy-aivm` defines or instantiates a SynQ executable VM.
- `rg -n "quantumvm|QuantumVM" network-components/synq-language network-components/synergy-aivm` returns no production execution dependency or user-facing command.
- At least three materially different contracts deploy and execute stateful calls through the same AIVM path without contract-name conditionals.

## P0 — Make the language front end lossless and fail-safe

- [ ] **LANG-001** Decide the complete SynQ 1.0 surface in the grammar. Every accepted construct must be represented in the AST and supported through AIVM, or be rejected with a diagnostic.
- [ ] **LANG-002** Replace the duplicate simplified parser `VersionRequirement` with the version module's complete model; preserve every comparator and range.
- [ ] **LANG-003** Enforce `pragma synq` during check/build and reject incompatible, malformed, duplicated, or missing pragmas according to an explicit policy.
- [ ] **LANG-004** Remove all parser `unwrap`/`unreachable` paths reachable from user source. Arbitrary input must produce diagnostics, never a panic.
- [ ] **LANG-005** Implement global functions end to end or remove them from the grammar. Add a regression test for the current panic.
- [ ] **LANG-006** Add AST nodes and semantic/codegen support for global and contract-local structs, enums, and generic parameters, or reject each construct explicitly.
- [ ] **LANG-007** Preserve state-variable initializers and execute them exactly once during deployment.
- [ ] **LANG-008** Preserve complete lvalues (`mapping[key]`, arrays, and nested members) instead of reducing assignments to the root identifier.
- [ ] **LANG-009** Replace raw-text expression reparsing and identifier fallback with structured precedence parsing for calls, member access, indexing, tuples, arrays, objects, postfix operations, and ternaries.
- [ ] **LANG-010** Define the literal grammar precisely. Implement full-width signed/unsigned integers and escape-aware strings/bytes, or reject decimal, scientific, negative, null, and other unsupported literals at parse time.
- [ ] **LANG-011** Preserve tuple and generic types without encoding them as ad hoc `Generic("Tuple", ...)` or silently falling back to `Struct("Unknown")`.
- [ ] **LANG-012** Add source spans to every AST node and semantic error, including filename, line, column, and a usable code frame.
- [ ] **LANG-013** Implement lexical scopes, shadowing rules, duplicate detection, mutability, visibility, constructor scope, loop scope, and nested block scope without name-only heuristics.
- [ ] **LANG-014** Reject unknown functions, builtins, annotations, modifiers, members, enum variants, and types unless they resolve to an explicit extension/host-function declaration.
- [ ] **LANG-015** Replace numeric “all types compatible” behavior with width/sign-aware checking and defined explicit conversions.
- [ ] **LANG-016** Enforce assignment-target typing for mappings, arrays, structs, generics, and member/index access instead of skipping imprecise targets.
- [ ] **LANG-017** Implement definite assignment, uninitialized read detection, complete return-path analysis, unreachable code, and loop-control validation.
- [ ] **LANG-018** Define annotation/modifier semantics and validate their named arguments; currently annotation argument names are discarded.

Acceptance gate:

- A grammar-to-AST coverage test proves that every public grammar production is either losslessly lowered or intentionally rejected.
- Parser fuzz/property tests produce no panic, hang, or unbounded allocation.
- Negative tests assert exact diagnostic codes and source spans.

## P0 — Replace prototype code generation with correct AIVM bytecode

- [ ] **CODEGEN-001** Publish a versioned SynQ bytecode format/API shared by the compiler and AIVM without sharing an executable runtime.
- [ ] **CODEGEN-002** Add a bytecode verifier in AIVM that validates headers, section lengths, opcode operands, jump/call targets, stack effects, type effects, feature/version declarations, and resource limits before execution.
- [ ] **CODEGEN-003** Implement a real function table and selector dispatcher. Function labels must use actual emitted positions, and every `Call` must include a valid target operand.
- [ ] **CODEGEN-004** Decode ABI calldata into function parameters and constructor parameters; implement a defined call frame and return convention.
- [ ] **CODEGEN-005** Fix conditional lowering so `if`, `else if`, ternary, loops, `require`, and `require_pqc` match their source semantics and the AIVM branch opcode definition.
- [ ] **CODEGEN-006** Implement real revert semantics with rollback, ABI error data, and `ExecutionStatus::Reverted`; `Halt` cannot represent both success and failure.
- [ ] **CODEGEN-007** Implement short-circuit `&&`/`||`, modulo, shifts if retained, prefix/postfix increment/decrement, unary negation, and logical not with complete tests.
- [ ] **CODEGEN-008** Implement `UInt8/32/64/128/256` and `Int8/32/64/128/256` exactly. Remove `u64 -> u32 -> i32` truncation and define checked/wrapping arithmetic policy.
- [ ] **CODEGEN-009** Implement `Bool`, address, bytes, string, arrays, mappings, structs, enums, tuples, PQC types, and generic values with canonical in-memory and ABI representations.
- [ ] **CODEGEN-010** Replace `DefaultHasher` variable/event addresses with a stable, specified, collision-resistant layout independent of Rust version.
- [ ] **CODEGEN-011** Separate local variables, call frames, transient memory, persistent contract storage, calldata, and return data.
- [ ] **CODEGEN-012** Implement state-schema-driven load/store for public and private fields, nested structures, mappings, and arrays.
- [ ] **CODEGEN-013** Implement event opcodes/host calls that write ABI-encoded indexed and non-indexed log data into the receipt. Do not leave event arguments on the value stack.
- [ ] **CODEGEN-014** Implement member/index access and assignment with bounds checking, key encoding, and deterministic storage layout.
- [ ] **CODEGEN-015** Implement `msg.sender`, `msg.value`, block number, timestamp, contract address, chain ID, and approved AIVM host functions from `ExecutionContext`.
- [ ] **CODEGEN-016** Generate and enforce declared stack, memory, storage, recursion/call-depth, code-size, and data-size limits.
- [ ] **CODEGEN-017** Make compiler output reproducible across machines and build profiles; add golden fixtures for every bytecode/ABI/manifest version.
- [ ] **CODEGEN-018** Remove Solidity compatibility generation from the production build path or define it as a separately versioned, tested translator that cannot be mistaken for SynQ/AIVM execution proof.

Acceptance gate:

- Every accepted AST node has codegen and AIVM execution tests.
- Multi-function calls, recursion policy, nested branches, revert paths, state mutation, and event emission pass end to end through AIVM.
- Full-width arithmetic test vectors cover boundaries, overflow, division/modulo by zero, signed behavior, and ABI roundtrips.

## P0 — Generalize AIVM state, ABI, artifacts, and receipts

- [ ] **ABI-001** Finalize one canonical ABI schema for deploy, call, constructor arguments, function arguments, return values, errors, events, and state fields.
- [ ] **ABI-002** Validate selector uniqueness and collisions at compile time; bind AIVM dispatch to the validated ABI and manifest hashes.
- [ ] **ABI-003** Represent multiple return values directly rather than flattening tuple returns into one generic type string.
- [ ] **ABI-004** Infer function mutability from resolved state effects and host calls, not every syntactic assignment or event indiscriminately.
- [ ] **ABI-005** Generate non-empty manifest `host_functions` and `permissions` from resolved program behavior; reject undeclared calls in AIVM.
- [ ] **ABI-006** Validate `manifest_version`, `compiler_version`, `required_aivm_version`, `security_policy`, source hash, storage-schema hash, host functions, permissions, contract name, and ABI presence in AIVM.
- [ ] **ABI-007** Require ABI bytes whenever a manifest carries an ABI hash; do not silently skip ABI-hash validation.
- [ ] **ABI-008** Version storage schemas and implement an explicit compatibility/migration policy for contract upgrades.
- [ ] **ABI-009** Define canonical contract-address derivation from deployer, nonce, chain/network, bytecode/manifest hashes, and any salt.
- [ ] **ABI-010** Use binary canonical receipt/log/return encodings; prohibit debug text and unordered maps in consensus outputs.
- [ ] **ABI-011** Add schema generators and compatibility tests so SynQ compiler, AIVM, Rust tooling, TypeScript SDK, and chain code consume the same definitions.

## P0 — Connect signing and runtime admission security

- [ ] **SEC-001** Extend the AIVM deploy/call request with the canonical signed envelope, public key, algorithm identifier, domain, chain/network binding, nonce, expiry, bytecode/manifest/ABI hashes, selector, and argument hash.
- [ ] **SEC-002** Verify ML-DSA-65 admission signatures inside the chain/AIVM admission path through `aegis-pqsynq`; CLI-only verification is insufficient.
- [ ] **SEC-003** Derive `caller` from the verified signer and reject caller fields supplied independently by an untrusted request.
- [ ] **SEC-004** Implement account/contract nonce state and atomic replay protection for deploy and call.
- [ ] **SEC-005** Enforce domain separation so deploy, call, wallet authentication, AI host calls, and other transaction types cannot be replayed across domains.
- [ ] **SEC-006** Enforce expiry/height windows and deterministic clock/height use at admission.
- [ ] **SEC-007** Bind admission verification, compiler artifacts, ABI dispatch, runtime permissions, and receipt hashes to the same chain/network identity.
- [ ] **SEC-008** Define key-material handling rules: secret keys must never enter contract bytecode, logs, receipts, persisted public state, or CLI output.
- [ ] **SEC-009** Threat-model KEM decapsulation inside contracts. Replace raw private-key stack inputs with an approved secure AIVM capability or explicitly prohibit the operation in deployed contracts.
- [ ] **SEC-010** Add malformed, oversized, replayed, cross-domain, wrong-chain, wrong-selector, wrong-artifact, and corrupted-key negative tests at the actual AIVM admission boundary.

## P0 — Complete and prove PQC behavior

- [ ] **PQC-001** Add the required official ML-KEM, ML-DSA, FN-DSA, and HQC-KEM KAT assets with provenance, hashes, licensing, and reproducible acquisition instructions.
- [ ] **PQC-002** Make official-vector replay part of the normal required test/CI gate; no environment variable, missing fixture, or skip may turn it into an optional pass.
- [ ] **PQC-003** Align the language surface, semantic builtins, bytecode opcodes, AIVM backends, CLI, and SDK on the exact supported variants. Remove accepted-but-disabled algorithm/type surfaces.
- [ ] **PQC-004** Decide SLH-DSA's SynQ 1.0 status. Either implement it fully in AIVM and tests or remove its types/opcode/builtins from the 1.0 grammar and ABI.
- [ ] **PQC-005** Rename legacy Falcon-facing SDK/API surfaces to FN-DSA while retaining only explicitly versioned compatibility aliases if required.
- [ ] **PQC-006** Define consensus-fixed ordinary-gas and PQ-gas schedules per operation, variant, input size, and failure path; benchmark data may inform constants but must not change consensus dynamically.
- [ ] **PQC-007** Add wrong-size, malformed, non-canonical, tampered, cross-variant, context/domain, and resource-exhaustion tests at both backend and AIVM opcode/host-function layers.
- [ ] **PQC-008** Complete side-channel, zeroization, randomness, FFI-safety, WASM/no-std, and supported-platform evidence for every enabled backend.

## P1 — Replace local-VM CLI behavior with real AIVM workflows

- [ ] **CLI-001** Remove or replace `run`, `simulate`, and `verify --run` paths that instantiate the local `QuantumVM`.
- [ ] **CLI-002** Add an AIVM-owned local harness for deterministic developer tests and a network RPC path for real deploy/call submission.
- [ ] **CLI-003** Implement `deploy` and `call` commands that build/sign/submit canonical envelopes and verify the returned AIVM receipt against submitted hashes.
- [ ] **CLI-004** Implement `test`, gas/PQ-gas estimate, trace, and receipt inspection against the AIVM execution API.
- [ ] **CLI-005** Add argument encoding from ABI types, multiple return decoding, error decoding, event decoding, and state query support.
- [ ] **CLI-006** Make project/package/compiler versions coherent and enforce `synq.toml` without hard-coded testnet-only assumptions in reusable compiler code.
- [ ] **CLI-007** Add stable machine-readable JSON output, exit codes, diagnostic codes, and a no-secret-output guarantee for automation.
- [ ] **CLI-008** Replace generic crate/binary names (`compiler`, `cli`) with versioned SynQ package names and complete license/repository/package metadata.

## P1 — Make the TypeScript SDK real and releasable

- [ ] **SDK-001** Create a public package entry point and explicit exports; add build, declaration, lint, format, test, and package-dry-run scripts.
- [ ] **SDK-002** Enable strict TypeScript and replace public `any`/`unknown` return surfaces with generated canonical request, ABI, manifest, envelope, and receipt types.
- [ ] **SDK-003** Replace `QuantumVMClient`/`QuantumVMSDK` naming with AIVM/SynQ naming and remove the implication of a separate SynQ VM.
- [ ] **SDK-004** Replace mocked `contract_deploy`, `contract_call`, and `tx_sendRaw` assumptions with the actual implemented AIVM node/chain API.
- [ ] **SDK-005** Implement the same canonical deploy/call signing and serialization as the Rust CLI; add byte-for-byte cross-language vectors.
- [ ] **SDK-006** Replace JSON transaction serialization with the network's canonical binary encoding and bind chain, network, nonce, domain, expiry, selector, and argument hash.
- [ ] **SDK-007** Rename the current `ECDSAKeypair`: it uses TweetNaCl signing and is not ECDSA. Remove classical signing from SynQ admission surfaces unless an explicit non-SynQ use is documented.
- [ ] **SDK-008** Protect secret-key material from accidental mutation/logging and define import/export, encrypted storage, zeroization limits, and browser/Node compatibility.
- [ ] **SDK-009** Add ABI contract wrappers, argument validation, return/event/error decoding, nonce retrieval, receipt polling, and structured RPC errors.
- [ ] **SDK-010** Add live AIVM integration tests in addition to fetch mocks; include deploy, stateful call, revert, bad signature, replay, gas, PQ-gas, and event cases.
- [ ] **SDK-011** Remove tracked `sdk/node_modules` content, keep it ignored, and prove a clean `npm ci` build/test/package flow.

## P1 — Tests, CI, examples, and quality gates

- [ ] **TEST-001** Add root CI that covers the SynQ compiler, AIVM-owned runtime, CLI, SDK, PQC crates, official vectors, formatting, strict clippy, audits, and artifact determinism.
- [ ] **TEST-002** Fix the three unsafe FFI functions' safety contracts so strict workspace clippy passes without blanket warning suppression.
- [ ] **TEST-003** Add regression tests for the global-function panic, missing call operand, reversed branches, unconditional/ambiguous halt behavior, state-address mismatch, full-width truncation, and all seven failing examples.
- [ ] **TEST-004** Convert compile-only example tests into deploy-and-call AIVM tests that validate outputs, state transitions, events, gas, receipts, and failure paths.
- [ ] **TEST-005** Make every documented example executable through AIVM; compilation alone is not a passing example.
- [ ] **TEST-006** Add parser/semantic/codegen fuzzing and property tests with bounded resource assertions.
- [ ] **TEST-007** Add bytecode-verifier and AIVM-runtime fuzzing for malformed headers, sections, opcodes, operands, jumps, calls, stacks, memory, state, and host calls.
- [ ] **TEST-008** Add differential tests from AST/ABI intent to AIVM result, including an independent reference encoder/decoder for canonical artifacts and receipts.
- [ ] **TEST-009** Add deterministic replay tests across macOS/Linux and every validator CPU architecture, including PQC backend selection.
- [ ] **TEST-010** Add concurrency, reentrancy, nested call, state-conflict, rollback, and resource-exhaustion tests.
- [ ] **TEST-011** Add end-to-end chain tests that submit signed deploy/call transactions through the actual node API and prove committed state plus queryable receipt/log data.
- [ ] **TEST-012** Add release fixture regeneration checks so checked-in bytecode/ABI/manifest/vector files cannot drift silently.
- [ ] **TEST-013** Run an independent security audit of the final compiler/AIVM boundary, bytecode verifier, storage model, admission signatures, host functions, and PQC FFI before release.

## P1 — Documentation and release engineering

- [ ] **REL-001** Rewrite language, bytecode, ABI, signing, gas, receipt, security, and AIVM execution specifications to match the final implemented behavior exactly.
- [ ] **REL-002** Remove all remaining references that describe `synq-language/vm`, `QuantumVM`, or a separate SynQ VM as the production execution environment.
- [ ] **REL-003** Generate grammar/type/builtin/opcode/ABI references from code where possible and test every documentation example.
- [ ] **REL-004** Document supported platforms, toolchain/MSRV/Node versions, reproducible builds, dependency pinning, vector acquisition, and release signing.
- [ ] **REL-005** Add coherent versions and changelogs for the language, bytecode, compiler, CLI, SDK, AIVM compatibility, ABI, manifest, and receipt formats.
- [ ] **REL-006** Complete license/repository metadata for every shipped crate/package and produce an SBOM plus dependency/license/security scan.
- [ ] **REL-007** Define upgrade and deprecation rules for language pragmas, bytecode, artifacts, storage schemas, SDKs, and AIVM consensus behavior.
- [ ] **REL-008** Produce installable CLI/SDK artifacts with checksums and signatures; validate installation from a clean machine without the monorepo.
- [ ] **REL-009** Publish a developer workflow that initializes, builds, tests through AIVM, signs, deploys, calls, inspects receipts/events, and debugs a nontrivial contract.
- [ ] **REL-010** Keep this file as the sole current checklist. Historical audit reports may remain evidence, but must not be presented as current completion status.
- [ ] **REL-011** Resolve, remove from the supported surface, or explicitly isolate every production finding in `docs/SynQ-Incomplete-Code-Register.md`; replace every test/demo-only fake that is currently used as release evidence with real AIVM coverage.

## Final release gate

SynQ may be declared fully complete only after all checklist items are checked and all of the following pass from clean checkouts with pinned toolchains and dependencies:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
npm ci --prefix sdk --ignore-scripts --no-audit --no-fund
npm run --prefix sdk typecheck
npm run --prefix sdk test
npm run --prefix sdk build
npm pack --prefix sdk --dry-run
```

The AIVM repository must also provide one root command that builds and tests its core, node, chain adapter, SynQ execution engine, and end-to-end network path. Release proof must include:

1. All official PQC vectors present and passing.
2. All documented SynQ examples deployed and called through AIVM.
3. No separate SynQ VM implementation or runtime dependency.
4. No skipped, ignored, filtered, mock-only, compile-only, or missing-fixture release gate.
5. Deterministic cross-platform bytecode, artifacts, execution results, state roots, gas, logs, and receipts.
6. A clean repository with no tracked dependency directories, generated build trees, `.DS_Store` files, secrets, or unexplained changes.
