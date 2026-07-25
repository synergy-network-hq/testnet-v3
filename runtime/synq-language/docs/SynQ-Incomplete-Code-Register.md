# SynQ Stub, Placeholder, Fake, and Incomplete Code Register

Audit date: 2026-07-15
Scope: first-party source, tests, manifests, scripts, and scaffolding in `network-components/synq-language` and the complete sibling `network-components/synergy-aivm` tree
Companion completion plan: `docs/SynQ-Completion-Checklist.md`

## What this register is

This is a separate, source-derived inventory of code that is empty, deliberately mocked, hard-coded to a demonstration, silently lossy, falsely reports success, accepts behavior it cannot implement, or otherwise substitutes for a complete implementation.

It is not a search-results dump. Each item below was inspected in context. Normal test data, legitimate error branches, generated build output, vendored upstream implementations, and intentionally empty ownership-based operations were not labeled as stubs merely because they contain words such as `test`, `default`, or `empty`.

Line references are for the audited checkout on the date above. For a zero-byte file, `:1` means the file has no physical source line; line 1 is the only usable location anchor.

Excluded third-party/generated material:

- `target/`, SDK `node_modules/`, Python virtual environments, and generated binaries;
- vendored PQClean sources under `pqrust/*/pqclean/`;
- the bundled WASI SDK under `aegis-pqsynq/aegis_crypto_core/tools/`;
- historical documentation and external binary model data.

## 1. Forbidden separate SynQ VM architecture

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| VM-001 | `Cargo.toml:1-16` | The SynQ workspace still owns `vm` as an executable runtime crate. This directly violates the AIVM-only execution architecture. |
| VM-002 | `compiler/Cargo.toml:6-17` | The compiler depends on `quantumvm` and even forwards a runtime PQC feature. A compiler should emit a shared bytecode format, not own or select the execution engine. |
| VM-003 | `cli/Cargo.toml:6-17` | The CLI directly depends on the separate `quantumvm` runtime. |
| VM-004 | `compiler/src/codegen.rs:1-5` | Production code generation imports opcodes and the assembler from the forbidden local VM instead of a non-executable bytecode-format package owned by the AIVM interface. |
| VM-005 | `cli/src/main.rs:181-208`, `930-944`, `994-1029`, `1564-1570` | `simulate`, `run`, and `verify --run` instantiate the separate local VM and can report local execution success; none uses AIVM. |
| VM-006 | `../synergy-aivm/runtime/aivm-core/Cargo.toml:6-17` | AIVM imports `../../../synq-language/vm` as `quantumvm`; execution ownership is backwards. |
| VM-007 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:192-232`, `341-350` | The nominal AIVM SynQ execution path constructs `quantumvm::QuantumVM`, exposing a stateless foreign interpreter instead of AIVM-owned execution. |
| VM-008 | `vm/src/vm.rs:134-168` | The separate runtime is a process-local stack and `HashMap` memory machine with no AIVM storage, context, ABI, admission, receipt, or consensus boundary. |
| VM-009 | `vm/src/vm.rs:63-89`, `182-205` | The bytecode loader parses but does not enforce header version, canonical header length, exact total length, reset all execution state, or verify instructions before reporting the code loaded. |

## 2. Parser and AST stubs, silent fallbacks, and discarded syntax

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| PARSE-001 | `compiler/src/parser.rs:9-14`, `49-80` | A second, explicitly “simple” `VersionRequirement` substitutes for the real version module, retains only the first comparator/version pair, and fabricates `^1.0.0` on fallback. |
| PARSE-002 | `compiler/src/synq.pest:8`, `compiler/src/parser.rs:49-80` | The grammar accepts multiple version constraints, but lowering discards every constraint after the first. |
| PARSE-003 | `compiler/src/synq.pest:12`, `compiler/src/parser.rs:29-39` | The grammar accepts global functions, but the parser has no lowering arm and reaches `unreachable!()`. A valid grammar input panics. |
| PARSE-004 | `compiler/src/synq.pest:20-21`, `28-29`, `compiler/src/parser.rs:115-156` | Contract generics and contract-local structs/enums are accepted, then their generic parameters are ignored and local type declarations are deliberately discarded. |
| PARSE-005 | `compiler/src/ast.rs:6-31`, `58-69` | The AST has no enum source unit, enum definition, generic-parameter ownership, or contract-local type representation despite the public grammar accepting them. |
| PARSE-006 | `compiler/src/parser.rs:158-167` | An unknown contract part is silently reinterpreted as a function instead of producing an internal/parser diagnostic. |
| PARSE-007 | `compiler/src/synq.pest:31-33`, `compiler/src/parser.rs:217-257`, `compiler/src/ast.rs:33-39` | Solidity-style state initializers are accepted by the grammar, but the initializer is discarded and the AST has no field for it. |
| PARSE-008 | `compiler/src/parser.rs:320-329`, `353-433`, `500-528` | Block parsing uses `filter_map`; failed statement lowering becomes a silently missing statement rather than a compile error. Several branches return `None` when recovery fails. |
| PARSE-009 | `compiler/src/synq.pest:67-68`, `compiler/src/parser.rs:405-433`, `compiler/src/ast.rs:83-95` | Full mapping/array/member lvalues are reduced to the first identifier. The AST stores assignment targets as a bare `String`, losing every accessor. |
| PARSE-010 | `compiler/src/parser.rs:639-748` | Expressions are reparsed from raw text by an ad hoc parser. Unsupported calls/accessors/literals can be collapsed into a fabricated identifier containing the original text. |
| PARSE-011 | `compiler/src/synq.pest:80-94`, `compiler/src/parser.rs:639-720` | The grammar accepts postfix calls, member/index chains, tuple/array/object literals, and increment/decrement, but the raw-text lowering implements only a subset and returns no structured representation for the rest. |
| PARSE-012 | `compiler/src/synq.pest:97-102`, `compiler/src/parser.rs:695-705`, `756-799` | Decimal, scientific, negative, null, and escape-containing literals are accepted in grammar or strings, but lowering rejects/collapses them or strips quotes without decoding escapes. |
| PARSE-013 | `compiler/src/parser.rs:1095-1215` | Malformed or unsupported types become `Struct("Unknown")`, arbitrary struct names, or the ad hoc generic name `Tuple`; this is silent fallback, not type parsing. |
| PARSE-014 | `compiler/src/parser.rs:532-557`, `compiler/src/ast.rs:12-16` | Annotation argument names are discarded. Only expression values survive, so named annotation semantics cannot be enforced. |
| PARSE-015 | `compiler/src/parser.rs:574-622` | C-style `for` lowering discards the update expression and approximates the condition as a range end. Unsupported forms can silently disappear. |
| PARSE-016 | `compiler/src/parser.rs:217-304` | State/function visibility is inferred with raw string `contains` checks, and absent names/types begin as empty strings/`UInt256`; this is heuristic recovery presented as a real AST. |
| PARSE-017 | `compiler/src/ast.rs:83-107`, `170-177` | The AST has no break/continue, compound assignment, call receiver, structured object/tuple literal, multiple return list, source span, or integer width in literals; all numbers are `u64`. |

## 3. Semantic-analysis holes that allow invalid code through

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| SEM-001 | `compiler/src/semantic.rs:70-75` | Semantic analysis ignores every non-contract source unit, including top-level structs and any future global unit. |
| SEM-002 | `compiler/src/semantic.rs:109-117` | Duplicate function names are silently collapsed by `or_insert`; no overload rules or duplicate diagnostic exists. |
| SEM-003 | `compiler/src/semantic.rs:239-259` | Because lvalues are lossy, strict type checks are deliberately skipped for mappings, arrays, structs, and generics. |
| SEM-004 | `compiler/src/semantic.rs:354-359` | `emit` only type-walks arguments; the event name, existence, arity, indexed fields, and parameter types are never validated. |
| SEM-005 | `compiler/src/semantic.rs:394-414`, `807-839` | Most member and index access resolves to `Unknown`; mapping key types, bounds, struct members, and nested access are not enforced. |
| SEM-006 | `compiler/src/semantic.rs:552-603` | Collapsed complex literals and uppercase dotted identifiers such as enum variants are accepted as `Unknown` instead of being resolved or rejected. |
| SEM-007 | `compiler/src/semantic.rs:630-659` | Unknown call targets are explicitly tolerated and return `Unknown`, allowing misspelled/nonexistent functions to pass semantic analysis. |
| SEM-008 | `compiler/src/semantic.rs:726-772` | PQC-like names not in the small recognized subset are deliberately treated as non-builtins rather than rejected, compounding the unknown-call hole. |
| SEM-009 | `compiler/src/semantic.rs:713-718`, `compiler/src/ast.rs:196-201` | Every semantic error is emitted with `line: None` and `column: None`; AST nodes carry no spans. |
| SEM-010 | `compiler/src/semantic.rs:865-893` | Every numeric width and signedness is declared mutually compatible, so truncating and sign-changing assignments pass. |
| SEM-011 | `compiler/src/semantic.rs:895-924` | Container assignments and untyped declarations use explicit skip/heuristic paths instead of sound type inference. |
| SEM-012 | `compiler/src/semantic.rs:729-733`, `compiler/src/parser.rs:1167-1169` | SLH-DSA types are accepted, but the semantic profile rejects SLH-DSA calls; the public language surface contradicts the runtime profile. |
| SEM-013 | `compiler/src/semantic.rs:78-154`, `156-185` | Contract/function/state annotations and modifiers are not interpreted or validated by the analyzer at all. |

## 4. Bytecode generation placeholders and incorrect implementations

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| CODE-001 | `compiler/src/codegen.rs:55-68` | The “first pass” records every function at the assembler's initial position before any code is emitted, so labels are not real function addresses. |
| CODE-002 | `compiler/src/codegen.rs:84-128` | There is no contract/function dispatcher, call frame, constructor separation, or parameter decoding. The function prologue is an empty “simplified” comment. |
| CODE-003 | `compiler/src/codegen.rs:140-149` | A missing initializer is replaced with integer zero regardless of declared type, masking parser loss as executable code. |
| CODE-004 | `compiler/src/codegen.rs:160-181` | `require` and `revert` use `Halt`; the error label is placed immediately after the branch, and no revert status, message, or rollback data is emitted. |
| CODE-005 | `compiler/src/codegen.rs:182-233`, `464-506`, `vm/src/vm.rs:312-327` | `if` and ternary lowering assumes `JumpIf` jumps on false, while the runtime jumps on true. Source branch semantics are inverted/unreliable. |
| CODE-006 | `compiler/src/codegen.rs:234-250` | Event generation hashes the name, pushes the ID/arguments, and stops. No log opcode or receipt event is produced. |
| CODE-007 | `compiler/src/codegen.rs:251-325` | `require_pqc` assumes only the last stack value represents all checks, uses the same inverted branch assumption, and maps failure to `Halt`. |
| CODE-008 | `compiler/src/codegen.rs:402-440`, `vm/src/vm.rs:328-341` | Ordinary calls emit the `Call` opcode without its required four-byte address operand, producing malformed execution streams. |
| CODE-009 | `compiler/src/codegen.rs:442-463` | Member and index access evaluate operands but emit no member lookup, offset calculation, bounds check, or load. The result left on the stack is not the requested value. |
| CODE-010 | `compiler/src/codegen.rs:511-520`, `compiler/src/ast.rs:170-177`, `vm/src/vm.rs:12-19`, `241-298` | Numeric source values are `u64`, truncated to `u32`, then executed as signed `i32`; advertised 8- through 256-bit semantics do not exist. |
| CODE-011 | `compiler/src/codegen.rs:554-595` | Modulo, logical operators, shifts, increment, and decrement exist in AST/grammar but terminate code generation as unsupported. |
| CODE-012 | `compiler/src/codegen.rs:597-622` | Variables use truncated Rust `DefaultHasher` addresses scoped by current function. This is neither a specified deterministic storage layout nor shared persistent contract state. |
| CODE-013 | `compiler/src/codegen.rs:408-435`, `vm/src/vm.rs:375-443` | Algorithm variants collapse into single opcodes: ML-DSA always executes 65, FN-DSA always 512, ML-KEM always 768, while multiple variants are accepted by names/types. |
| CODE-014 | `vm/src/vm.rs:412-416` | The bytecode declares and accepts `SLHDSAVerify`, but executing it always returns “not enabled.” |
| CODE-015 | `vm/src/vm.rs:380-443`, `456-477` | Consensus gas weights are unexplained hard-coded estimates, and KEM decapsulation requires a raw private key on the value stack. |
| CODE-016 | `vm/src/vm.rs:574-600` | Backend verification errors are collapsed to `false` with `unwrap_or(false)`, hiding backend faults as ordinary invalid signatures. |
| CODE-017 | `vm/src/opcode.rs:81-83`, `vm/src/vm.rs:444-450` | Production bytecode contains a direct `Print` side effect, and `Halt` has no success/revert distinction. |

## 5. Artifact, compatibility-output, CLI, and SDK substitutes

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| ART-001 | `compiler/src/artifacts.rs:133-145`, `203-217` | Artifact generation supports exactly one contract and has no package/multi-contract linkage model. |
| ART-002 | `compiler/src/artifacts.rs:156-173` | Manifest `host_functions` and `permissions` are always empty, regardless of actual source behavior. |
| ART-003 | `compiler/src/artifacts.rs:219-249` | ABI errors are always empty, constructors are omitted, and security requirements are fixed strings rather than derived policy. |
| ART-004 | `compiler/src/artifacts.rs:259-289` | Method selector collisions are never detected; tuple/multiple returns are flattened into a single string entry. |
| ART-005 | `compiler/src/artifacts.rs:300-315` | Mutability is a syntax heuristic: every assignment or event marks a function `write`, without symbol resolution or host effects. |
| ART-006 | `compiler/src/version.rs:140-146` | The compiler version function is explicitly a fake “real implementation” placeholder and returns hard-coded `1.0.0`, inconsistent with crate version `0.1.0`. |
| SOL-001 | `compiler/src/solidity_gen.rs:6-38` | The generator identifies its output as a non-production preview and emits commented “to be implemented” PQC imports. It is still generated by normal build/compile paths. |
| SOL-002 | `compiler/src/solidity_gen.rs:156-180`, `183-191`, `267-276` | Generated Solidity can be syntactically invalid: returning functions receive both `external` and another visibility, while events/emits contain doubled parentheses. |
| SOL-003 | `compiler/src/solidity_gen.rs:298-315` | `require_pqc` is replaced by `bool __synq_pqc_ok = true`, so the compatibility output always treats PQC policy as satisfied. |
| SOL-004 | `compiler/src/solidity_gen.rs:386-413`, `459-470` | PQC key material is reduced to generic `bytes memory` in all contexts, generic types lose parameters, and gas annotation arguments are discarded. |
| CLI-001 | `cli/src/main.rs:57-179`, `549-910` | Key generation/sign/verify are offline-only. There is no deploy/call submission, nonce lookup/commit, AIVM receipt verification, or node RPC implementation. |
| CLI-002 | `cli/src/main.rs:130-156`, `1460-1499` | Call signing deliberately supports only zero-argument methods and hashes an empty argument payload. |
| CLI-003 | `cli/src/main.rs:947-992` | `init` creates a Counter-only project and a “deploy” script that explicitly does not deploy; it only builds locally. |
| CLI-004 | `cli/src/main.rs:1079-1110` | The parsed language pragma is discarded, and a missing project config silently receives the hard-coded testnet-1264 artifact profile. |
| SDK-001 | `sdk/src/sdk.ts:30-66`, `68-127` | The SDK exposes `QuantumVMClient`/`QuantumVMSDK` and sends invented JSON-RPC methods (`contract_deploy`, `contract_call`, `tx_sendRaw`, etc.) for which no AIVM node implementation exists. |
| SDK-002 | `sdk/src/sdk.ts:39-40`, `68-84` | Public RPC, ABI, argument, and result surfaces use `any`; ABI encoding/decoding is not implemented. |
| SDK-003 | `sdk/src/keys.ts:138-159` | `ECDSAKeypair` is not ECDSA. It calls TweetNaCl Ed25519 signing while presenting a false algorithm name. |
| SDK-004 | `sdk/src/tx.ts:15-60` | Transactions are ad hoc JSON, begin with an empty signature, have no chain/network/domain/expiry binding, and are not the network's canonical signed envelope. |
| SDK-005 | `sdk/package.json:1-18`, `sdk/tsconfig.json:1-15` | The package is private, has no entry point, export map, build, declarations, lint, package test, or publish surface; strict type checking is disabled. |

## 6. PQC evidence gaps and misleading replay coverage

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| PQC-001 | `aegis-pqsynq/pqsynq/tests/nist_vector_replay_tests.rs:121-150`, `383-463` | The normal all-feature suite requires official vector paths under `5-nist-kat-vectors/`, but those assets are absent. Four integration tests fail before replay. |
| PQC-002 | `aegis-pqsynq/pqsynq/tests/nist_vector_replay_tests.rs:179-188`, `222-253`, `405-425` | The HQC tests labeled NIST replay modify official key/ciphertext framing and then use generated roundtrips instead of comparing decapsulation with the official expected shared secret. This is compatibility testing, not KAT replay. |
| PQC-003 | `smart-contracts/examples/hqckem-contract-flow.synq:3-26` | The checked-in example explicitly contains non-runnable `REPLACE_WITH_RUNTIME_*` placeholder values for all three algorithms. |
| PQC-004 | `smart-contracts/tests/hqckem128-decap-fixture.synq:3-9`, `smart-contracts/tests/hqckem192-decap-fixture.synq:3-9`, `smart-contracts/tests/hqckem256-decap-fixture.synq:3-9` | These are template files with `{{CIPHERTEXT_HEX}}` and `{{PRIVATE_KEY_HEX}}`, not independently runnable contracts. They are valid test templates but must not be presented as finished examples. |

## 7. AIVM core and verifier implementations that are demonstrations, not platform behavior

| ID | Exact location | Incomplete or false implementation |
|---|---|---|
| AIVM-001 | `../synergy-aivm/runtime/aivm-core/src/api.rs:1`, `../synergy-aivm/runtime/aivm-core/src/orchestration.rs:1`, `../synergy-aivm/runtime/aivm-core/src/vm/host.rs:1`, `../synergy-aivm/runtime/aivm-core/src/vm/sandbox.rs:1` | Four named core subsystems contain only a newline. There is no API, orchestration, host-function layer, or sandbox implementation. |
| AIVM-002 | `../synergy-aivm/runtime/aivm-core/src/main.rs:1-17` | The “core” binary only loads a WASM path or prints initialized; it exposes no node/service, SynQ deployment/call, state backend, scheduling, or provider orchestration. |
| AIVM-003 | `../synergy-aivm/runtime/aivm-core/src/vm/wasm_runner.rs:13-45` | `run_wasm` does not invoke an exported function. It instantiates a no-import module and reports export names/counts as a successful run. |
| AIVM-004 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:53-74` | `ExecutionRequest` has no signed envelope, signer key/signature, nonce, expiry, deploy/call operation, state handle/root, or receipt/transaction identity binding. |
| AIVM-005 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:96-133` | The convenience request fabricates height/timestamp/tx hash/caller as zero/empty and derives contract address from an arbitrary ID string. It is test scaffolding exposed in production code. |
| AIVM-006 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:234-322` | Artifact validation treats ABI as optional and never validates manifest/compiler/AIVM versions, source/storage hashes, contract name, host functions, permissions, security policy ID, or an actual signature. |
| AIVM-007 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:364-377` | WASM metadata inspection returns `Succeeded` with zero gas, no output/logs, and silently turns JSON serialization failure into empty return data. |
| AIVM-008 | `../synergy-aivm/runtime/aivm-core/src/state.rs:82-127` | The only contract state abstraction is a hard-coded `CounterStateMachine` with fixed `counter` and `__deployed` keys and `u64` saturating increment. |
| AIVM-009 | `../synergy-aivm/runtime/aivm-core/src/synq_runtime.rs:12-19`, `88-319` | The stateful SynQ path uses fixed Counter selectors/gas constants and manually performs deploy/increment/get. It never executes submitted SynQ bytecode. |
| AIVM-010 | `../synergy-aivm/runtime/aivm-core/src/synq_runtime.rs:335-441` | Artifact/ABI dispatch rejects every contract except `Counter`, requires two exact names/mutabilities/selectors, and accepts only four bytes of calldata. |
| AIVM-011 | `../synergy-aivm/runtime/aivm-core/src/synq_runtime.rs:175-187`, `277-316` | Receipts contain manually assembled diagnostic strings such as `synq.counter.value=...`, not ABI event/log records produced by execution. |
| AIVM-012 | `../synergy-aivm/runtime/aivm-core/src/transcript.rs:1-18` | A transcript is only three mutable strings and has no input/output commitments, model hash, provider identity, attestation, signature, resource usage, or canonical hash. |
| AIVM-013 | `../synergy-aivm/verifier/verifier-core/src/attestation.rs:3-18`, `../synergy-aivm/verifier/verifier-core/src/verifier.rs:19-30` | Any report with four non-empty fields is returned as `Trusted`; quote, measurement, and signature are never parsed or cryptographically verified. |
| AIVM-014 | `../synergy-aivm/providers/gpu-worker/worker_service.py:7-41` | The worker is a top-level one-image demo with a literal `path/to/your/image.jpg`; the referenced labels file is absent, and there is no job API, manifest validation, sandboxing, attestation, scheduling, or signed result. |
| AIVM-015 | `../synergy-aivm/sdk/proto/aivm.proto:1-48` | The proto contains data messages only—no service/RPC definitions, SynQ request/receipt messages, signing/admission fields, streaming, or error contract. |

## 8. Zero-byte and near-empty AIVM scaffolding

Every file in this section is first-party and empty unless stated otherwise. These are concrete empty subsystems, not inferred future ideas.

| ID | Exact location | Missing implementation |
|---|---|---|
| EMPTY-001 | `../synergy-aivm/runtime/aivm-node/src/main.rs:1`, `../synergy-aivm/runtime/aivm-node/src/server.rs:1`, `../synergy-aivm/runtime/aivm-node/src/provider_agent.rs:1` | The AIVM node binary, server, and provider agent are zero bytes; the node crate has no `main` and cannot build. |
| EMPTY-002 | `../synergy-aivm/synergy_chain/cosmos_module/app.go:1`, `../synergy-aivm/synergy_chain/cosmos_module/x/aivm/genesis.go:1`, `../synergy-aivm/synergy_chain/cosmos_module/x/aivm/handler.go:1`, `../synergy-aivm/synergy_chain/cosmos_module/x/aivm/keeper.go:1`, `../synergy-aivm/synergy_chain/cosmos_module/x/aivm/msgs.proto:1` | The complete chain/Cosmos integration is zero bytes. |
| EMPTY-003 | `../synergy-aivm/synergy_chain/contracts/EscrowManager.sol:1`, `../synergy-aivm/synergy_chain/contracts/Governance.sol:1`, `../synergy-aivm/synergy_chain/contracts/ModelRegistry.sol:1`, `../synergy-aivm/synergy_chain/contracts/Staking.sol:1` | All four named chain contracts are zero bytes. |
| EMPTY-004 | `../synergy-aivm/model-registry/model_tools/pack_model.py:1`, `../synergy-aivm/model-registry/model_tools/validate_manifest.py:1` | Both model packaging/validation tools are zero bytes. |
| EMPTY-005 | `../synergy-aivm/model-registry/registry-api/src/controllers/manifestController.ts:1`, `../synergy-aivm/model-registry/registry-api/src/{server.ts}:1` | The registry controller and literally brace-named server file are zero bytes. `../synergy-aivm/model-registry/registry-api/package.json:4` points to nonexistent `src/server.ts`. |
| EMPTY-006 | `../synergy-aivm/model-registry/storage/arweave_adapter.go:1`, `../synergy-aivm/model-registry/storage/ipfs_adapter.go:1` | Both registry storage adapters are zero bytes. |
| EMPTY-007 | `../synergy-aivm/providers/gpu-worker/attestation/sgx_client.py:1`, `../synergy-aivm/providers/gpu-worker/{worker_config.yaml}:1` | Worker attestation and the literally brace-named configuration file are zero bytes. |
| EMPTY-008 | `../synergy-aivm/providers/provider-operator/Dockerfile:1`, `../synergy-aivm/providers/provider-operator/README.md:1`, `../synergy-aivm/providers/provider-operator/deploy/k8s-deployment.yaml:1`, `../synergy-aivm/providers/provider-operator/deploy/node-setup.sh:1` | The provider operator image, documentation, Kubernetes deployment, and setup script are all zero bytes. |
| EMPTY-009 | `../synergy-aivm/scripts/deploy-testnet.sh:1`, `../synergy-aivm/scripts/dev-setup.sh:1`, `../synergy-aivm/scripts/run-local-sim.sh:1` | Every top-level operational script is zero bytes. |
| EMPTY-010 | `../synergy-aivm/sdk/js/src/index.js:1`, `../synergy-aivm/sdk/js/package.json:1-6` | The JavaScript SDK entry point is zero bytes; its package points directly at that empty file. |
| EMPTY-011 | `../synergy-aivm/sdk/python/setup.py:1-6` | The Python package declaration exists, but there is no first-party `synergy_aivm` package/module outside the checked-in virtual environment. |
| EMPTY-012 | `../synergy-aivm/synergy_portal_integration/web-ui/src/pages/AIVMDashboard.tsx:1`, `../synergy-aivm/synergy_portal_integration/web-ui/src/pages/ModelRegistry.tsx:1`, `../synergy-aivm/synergy_portal_integration/web-ui/src/pages/ProviderConsole.tsx:1`, `../synergy-aivm/synergy_portal_integration/web-ui/package.json:1-5` | All named UI pages are zero bytes; the package has no scripts or dependencies. |
| EMPTY-013 | `../synergy-aivm/verifier/zk-circuits/small_property_circuits/circuit.circom:1` | The only named ZK circuit is zero bytes. |
| EMPTY-014 | `../synergy-aivm/security/{threat_model.md}:1` | A literally brace-named security file is zero bytes; it is not a threat model. |
| EMPTY-015 | `../synergy-aivm/ci/github/workflows/.gitkeep:1`, `../synergy-aivm/tests/e2e/.gitkeep:1`, `../synergy-aivm/tests/integration/.gitkeep:1`, `../synergy-aivm/tests/perf/.gitkeep:1`, `../synergy-aivm/security/audits/.gitkeep:1`, `../synergy-aivm/security/sops/.gitkeep:1` | CI workflows, all top-level test classes, audits, and security operations contain directory placeholders only. |
| EMPTY-016 | `../synergy-aivm/marketplace/auction-service/.gitkeep:1`, `../synergy-aivm/marketplace/billing/.gitkeep:1`, `../synergy-aivm/marketplace/pricing-engine/.gitkeep:1` | All marketplace services are directory placeholders only. |
| EMPTY-017 | `../synergy-aivm/monitoring/grafana/.gitkeep:1`, `../synergy-aivm/monitoring/prometheus/.gitkeep:1` | Both monitoring integrations are directory placeholders only. |
| EMPTY-018 | `../synergy-aivm/samples/agent-example/.gitkeep:1`, `../synergy-aivm/samples/federated-training-example/.gitkeep:1`, `../synergy-aivm/samples/simple-inference/.gitkeep:1` | All sample directories have placeholder files; simple inference contains a model binary but no runnable sample inputs, labels, or sample code. |
| EMPTY-019 | `../synergy-aivm/legal/model_license_templates/.gitkeep:1`, `../synergy-aivm/legal/privacy_policies/.gitkeep:1` | Model-license and privacy-policy directories contain placeholders only. |
| EMPTY-020 | `../synergy-aivm/synergy_portal_integration/utility-tool-plugin/plugin/.gitkeep:1`, `../synergy-aivm/verifier/attestation/.gitkeep:1` | The utility plugin and verifier-attestation integration contain placeholders only. |
| EMPTY-021 | `CODE_OF_CONDUCT.md:1`, `governance/SECURITY_POLICY.md:1`, `tooling/registry-scripts/README.md:1` | These three named SynQ governance/tooling documents are zero bytes. They are documentation gaps rather than runtime code, but they are retained here so no first-party empty file is hidden. |

## 9. Test/demo fakes that cannot prove production behavior

These are not production implementations, but they are listed because their current names or assertions can be mistaken for end-to-end proof.

| ID | Exact location | Fake or incomplete proof |
|---|---|---|
| TEST-001 | `sdk/tests/integration.test.ts:18-63`, `65-160` | Every SDK RPC “integration” test replaces global `fetch` with an in-process mock and returns invented deploy/call/transaction/balance/block responses. No node is contacted. |
| TEST-002 | `cli/tests/integration_test.rs:257-294` | The six application examples are asserted only to compile and create files. No bytecode execution, AIVM deployment, call, state, event, or receipt is tested. |
| TEST-003 | `cli/tests/integration_test.rs:328-377` | The positive simulation test uses an empty `noop` function, so it avoids state initialization, calls, ABI, branches, and all meaningful runtime behavior. |
| TEST-004 | `cli/tests/integration_test.rs:410-420` | The canonical Counter simulation test explicitly expects failure, documenting rather than closing the runtime limitation. |
| TEST-005 | `aegis-pqsynq/pqsynq/examples/synq_deploy_call_verifier.rs:54-57` | The example uses hashes of literal labels such as `example-counter-bytecode`, not compiler artifacts. Appropriate as example data, but not deploy/call integration proof. |
| TEST-006 | `../synergy-aivm/runtime/aivm-core/src/synq_runtime.rs:548-727`, `../synergy-aivm/runtime/aivm-core/examples/counter_state_demo.rs:1-106` | All stateful AIVM proof is Counter-only and calls the hand-written Counter path; it does not prove general SynQ bytecode execution. |
| TEST-007 | `../synergy-aivm/runtime/aivm-core/src/execution.rs:417-805` | Core execution tests construct local artifacts/contexts and the forbidden `quantumvm`; there is no node, signed admission, chain state, or multi-contract test. |

## Closure rule

No production item in this register may be dismissed by renaming it, deleting its comment, adding a mock, or documenting it as unsupported while the public surface still accepts or advertises it. It must be implemented through AIVM, explicitly removed from the supported SynQ/AIVM surface, or moved to a clearly isolated test/example-only location with names that cannot be mistaken for production proof.

SynQ cannot be called complete while any `VM-*`, `PARSE-*`, `SEM-*`, `CODE-*`, `ART-*`, `CLI-*`, `SDK-*`, `PQC-*`, `AIVM-*`, or SynQ/AIVM-critical `EMPTY-*` finding remains unresolved. Test/demo findings require real replacement coverage before they can serve as release evidence.
