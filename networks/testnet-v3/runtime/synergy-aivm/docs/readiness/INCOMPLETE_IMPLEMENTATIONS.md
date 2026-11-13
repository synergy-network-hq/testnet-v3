# Incomplete, Fake, Stub, Placeholder, Disabled, and Dead Implementation Register

Audit date: 2026-07-15

Audited authoritative AIVM revision: `d2d8e67df88145d2262f5997800d6bb2171577ea`

This is deliberately separate from the readiness checklists. It records every instance found in authored AIVM code and its actual testnet integration that is zero-byte, empty, stubbed, fake, dummy, hard-coded as a demonstration, misleadingly successful, disabled, dead/unwired, silently skipped, or materially incomplete.

## Scope and notation

- `AIVM:` = `network-components/01-Testnet/synergy-testnet/synergy-aivm`
- `TESTNET:` = `network-components/01-Testnet/synergy-testnet`
- `TOP-COPY:` = `network-components/synergy-aivm`
- Line `1` on a zero-byte file means the implementation file itself is empty; it has no source lines.
- Dependency/vendor sources, generated build output, the ONNX binary, and locally ignored development environments were not classified line-by-line as authored fake code.
- `.gitkeep` is not executable code, but a subsystem directory containing only `.gitkeep` is listed because it is direct evidence that the advertised subsystem is empty.

Severity:

- **P0**: prevents the claimed AIVM capability from working or creates consensus/security risk.
- **P1**: deceptive coverage, dead competing implementation, broken deployment/tooling, or major production gap.
- **P2**: repository/operational hygiene that materially obscures readiness.

## A. Architecture violations and competing VMs

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| ARCH-001 | P0 | `AIVM:runtime/aivm-core/Cargo.toml:8,17` | The AIVM `synq` feature imports `quantumvm` from `../../../synq-language/vm`; SynQ therefore owns a second executable VM instead of AIVM owning execution. |
| ARCH-002 | P0 | `AIVM:runtime/aivm-core/src/execution.rs:294-335` | AIVM constructs the separate `quantumvm::QuantumVM`, loads bytes, and executes it without AIVM contract state/host context. |
| ARCH-003 | P1 | `TESTNET:src/aivm/mod.rs:1-17` | A complete competing `src/aivm` module tree exists but `TESTNET:src/lib.rs:1-45` never declares `mod aivm`; the entire tree is dead, uncompiled code. |
| ARCH-004 | P1 | `TESTNET:src/aivm/chat_interface.rs:1-255` | Dead member of the competing AIVM implementation. It cannot provide a production feature because the module is not compiled or wired. |
| ARCH-005 | P1 | `TESTNET:src/aivm/distributed_ai.rs:1-548` | Dead member of the competing AIVM implementation. |
| ARCH-006 | P1 | `TESTNET:src/aivm/interoperability.rs:1-928` | Dead member of the competing AIVM implementation. |
| ARCH-007 | P1 | `TESTNET:src/aivm/model_registry.rs:1-327` | Dead member of the competing AIVM implementation. |
| ARCH-008 | P1 | `TESTNET:src/aivm/provider.rs:1-413` | Dead member of the competing AIVM implementation. |
| ARCH-009 | P1 | `TESTNET:src/aivm/runtime.rs:1-472` | Dead member of the competing AIVM implementation. |
| ARCH-010 | P1 | `TESTNET:src/aivm/verifier.rs:1-406` | Dead member of the competing AIVM implementation. |
| ARCH-011 | P1 | `TESTNET:src/aivm/wasm_vm.rs:1-293` | Dead separate VM implementation; it conflicts with the required single-AIVM architecture. |
| ARCH-012 | P1 | `TESTNET:src/synq/mod.rs:1-5` | Testnet compiles a second SynQ compiler/interpreter module, but repository-wide reference tracing found no production caller outside the module itself. |

## B. Authoritative smart-contract runtime: misleading or incomplete behavior

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| VM-001 | P0 | `AIVM:runtime/aivm-core/src/api.rs:1` | Empty one-line module. No AIVM API implementation. |
| VM-002 | P0 | `AIVM:runtime/aivm-core/src/orchestration.rs:1` | Empty one-line module. No orchestration implementation. |
| VM-003 | P0 | `AIVM:runtime/aivm-core/src/vm/host.rs:1` | Empty one-line module. No contract host implementation. |
| VM-004 | P0 | `AIVM:runtime/aivm-core/src/vm/sandbox.rs:1` | Empty one-line module. No sandbox implementation. |
| VM-005 | P0 | `AIVM:runtime/aivm-core/src/execution.rs:305-323` | The SynQ executor ignores `request.calldata`, storage, caller, block host access, logs, and value; successful output is `format!("{:?}", vm.stack)`, a debug string rather than canonical ABI bytes. |
| VM-006 | P0 | `AIVM:runtime/aivm-core/src/execution.rs:30-46,337-434` | Manifest fields `compiler_version`, `host_functions`, `manifest_version`, `permissions`, `required_aivm_version`, `source_hash`, and `storage_schema_hash` are decoded but never enforced. |
| VM-007 | P0 | `AIVM:runtime/aivm-core/src/execution.rs:379-390` | ABI validation is conditional on an optional ABI; omitting the ABI bypasses the ABI-hash check. |
| VM-008 | P0 | `AIVM:runtime/aivm-core/src/execution.rs:482-496` | WASM “execution” reports success after loading/inspecting a module, charges zero gas/PQ-gas, and returns module metadata; it invokes no contract export. |
| VM-009 | P0 | `AIVM:runtime/aivm-core/src/vm/wasm_runner.rs:18-46` | The WASM runner only compiles, rejects imports, instantiates, and enumerates exports. There is no calldata, ABI, function call, metering, memory policy, or state host. |
| VM-010 | P1 | `AIVM:runtime/aivm-core/src/main.rs:3-18` | Binary only prints startup and optionally loads a WASM file; it is not an execution service/node. |
| VM-011 | P1 | `AIVM:runtime/aivm-core/src/transcript.rs:1-19` | “Transcript” contains only job ID, model ID, and mutable status. It does not bind artifact/input/output/runtime/provider/proof/gas/state and is not signed. |
| VM-012 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:13-30` | Runtime behavior is selected through hard-coded Counter/STS selectors and a hard-coded activation height rather than a versioned general ABI/bytecode mechanism. |
| VM-013 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:108-190` | Deploy validates and initializes a Rust profile but never executes deployment bytecode or constructor calldata; deploy calldata is forcibly required to be empty. |
| VM-014 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:355-400,469-504` | Runtime classifies only `Counter` versus `Generic` by manifest contract name and rejects every non-Counter contract before a hard-coded height. This is contract-specific emulation. |
| VM-015 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:701-725` | Contract deployment chooses a Rust Counter state machine or generic metadata writer; compiled bytecode does not define initialization semantics. |
| VM-016 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:728-789` | Generic deployment only records deployed/name/runtime/artifact-hash fields and optional token metadata; it does not execute the contract. |
| VM-017 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:884-949` | Generic call handles hard-coded STS/token routes, otherwise runs the stateless VM. The VM cannot access `ContractState`, so arbitrary bytecode cannot mutate persistent contract state and the post-state root remains unchanged. |
| VM-018 | P1 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:914-919,951-1301` | STS host behavior is implemented as fixed Rust selector routing rather than SynQ contract execution; writes are rejected and the surface is read-only. |
| VM-019 | P1 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:1303-1518` | STS-9 token execution is a hard-coded Rust state machine, not execution of the deployed SynQ artifact. |
| VM-020 | P0 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:1574-1613` | Consensus calldata arguments are decoded from ad hoc JSON arrays/objects, and object fields are gathered in a fixed key list rather than a canonical typed ABI. |
| VM-021 | P1 | `AIVM:runtime/aivm-core/src/synq_runtime.rs:1754-1761` | “Address validation” checks only length, `syn` prefix, and lowercase/digits; it performs no canonical decode, checksum, address type, or network validation. |
| VM-022 | P0 | `AIVM:runtime/aivm-core/src/state.rs:20-80` | State is only an in-memory `BTreeMap`; there is no canonical database, durable commit, restart restore, reorg, pruning, or synchronization implementation. |

## C. Zero-byte implementation and deployment files

Every item below is an actual zero-byte file. `:1` is used as its exact implementation location because no source line exists.

| ID | Severity | Exact location | Missing implementation |
|---|---:|---|---|
| EMPTY-001 | P0 | `AIVM:model-registry/model_tools/pack_model.py:1` | Model packer |
| EMPTY-002 | P0 | `AIVM:model-registry/model_tools/validate_manifest.py:1` | Manifest validator |
| EMPTY-003 | P0 | `AIVM:model-registry/registry-api/src/controllers/manifestController.ts:1` | Registry controller |
| EMPTY-004 | P0 | `AIVM:model-registry/registry-api/src/{server.ts}:1` | Registry server; braces are literally part of the filename, indicating a malformed scaffold |
| EMPTY-005 | P0 | `AIVM:model-registry/storage/arweave_adapter.go:1` | Arweave storage adapter |
| EMPTY-006 | P0 | `AIVM:model-registry/storage/ipfs_adapter.go:1` | IPFS storage adapter |
| EMPTY-007 | P0 | `AIVM:providers/gpu-worker/attestation/sgx_client.py:1` | SGX attestation client |
| EMPTY-008 | P0 | `AIVM:providers/gpu-worker/{worker_config.yaml}:1` | Worker configuration; braces are literally part of the filename |
| EMPTY-009 | P0 | `AIVM:providers/provider-operator/Dockerfile:1` | Provider image |
| EMPTY-010 | P1 | `AIVM:providers/provider-operator/README.md:1` | Provider operator instructions |
| EMPTY-011 | P0 | `AIVM:providers/provider-operator/deploy/k8s-deployment.yaml:1` | Provider Kubernetes deployment |
| EMPTY-012 | P0 | `AIVM:providers/provider-operator/deploy/node-setup.sh:1` | Provider node setup |
| EMPTY-013 | P0 | `AIVM:runtime/aivm-node/src/main.rs:1` | Node binary entrypoint |
| EMPTY-014 | P0 | `AIVM:runtime/aivm-node/src/provider_agent.rs:1` | Provider agent |
| EMPTY-015 | P0 | `AIVM:runtime/aivm-node/src/server.rs:1` | Node server |
| EMPTY-016 | P1 | `AIVM:scripts/deploy-testnet.sh:1` | Testnet deployment |
| EMPTY-017 | P1 | `AIVM:scripts/dev-setup.sh:1` | Developer setup |
| EMPTY-018 | P1 | `AIVM:scripts/run-local-sim.sh:1` | Local simulation |
| EMPTY-019 | P0 | `AIVM:sdk/js/src/index.js:1` | JavaScript SDK |
| EMPTY-020 | P1 | `AIVM:security/{threat_model.md}:1` | Malformed literal-brace threat-model placeholder |
| EMPTY-021 | P0 | `AIVM:synergy_chain/contracts/EscrowManager.sol:1` | Escrow contract |
| EMPTY-022 | P0 | `AIVM:synergy_chain/contracts/Governance.sol:1` | Governance contract |
| EMPTY-023 | P0 | `AIVM:synergy_chain/contracts/ModelRegistry.sol:1` | Model registry contract |
| EMPTY-024 | P0 | `AIVM:synergy_chain/contracts/Staking.sol:1` | Provider staking contract |
| EMPTY-025 | P0 | `AIVM:synergy_chain/cosmos_module/app.go:1` | Chain module app wiring |
| EMPTY-026 | P0 | `AIVM:synergy_chain/cosmos_module/x/aivm/genesis.go:1` | Module genesis state |
| EMPTY-027 | P0 | `AIVM:synergy_chain/cosmos_module/x/aivm/handler.go:1` | Module transaction handler |
| EMPTY-028 | P0 | `AIVM:synergy_chain/cosmos_module/x/aivm/keeper.go:1` | Module keeper/state |
| EMPTY-029 | P0 | `AIVM:synergy_chain/cosmos_module/x/aivm/msgs.proto:1` | Module messages |
| EMPTY-030 | P1 | `AIVM:synergy_portal_integration/web-ui/src/pages/AIVMDashboard.tsx:1` | AIVM dashboard |
| EMPTY-031 | P1 | `AIVM:synergy_portal_integration/web-ui/src/pages/ModelRegistry.tsx:1` | Model-registry UI |
| EMPTY-032 | P1 | `AIVM:synergy_portal_integration/web-ui/src/pages/ProviderConsole.tsx:1` | Provider console |
| EMPTY-033 | P0 | `AIVM:verifier/verifier-core/src/attestation.rs:1` | Authoritative attestation implementation |
| EMPTY-034 | P0 | `AIVM:verifier/verifier-core/src/verifier.rs:1` | Authoritative verifier implementation |
| EMPTY-035 | P0 | `AIVM:verifier/zk-circuits/small_property_circuits/circuit.circom:1` | ZK circuit |

## D. Empty subsystem markers

These directories contain a zero-byte `.gitkeep` instead of an implementation or test asset.

| ID | Severity | Exact location | Empty subsystem |
|---|---:|---|---|
| MARKER-001 | P1 | `AIVM:ci/github/workflows/.gitkeep:1` | CI workflows |
| MARKER-002 | P1 | `AIVM:legal/model_license_templates/.gitkeep:1` | Model license templates |
| MARKER-003 | P1 | `AIVM:legal/privacy_policies/.gitkeep:1` | AI privacy policies |
| MARKER-004 | P0 | `AIVM:marketplace/auction-service/.gitkeep:1` | Provider auction service |
| MARKER-005 | P0 | `AIVM:marketplace/billing/.gitkeep:1` | Billing/settlement |
| MARKER-006 | P0 | `AIVM:marketplace/pricing-engine/.gitkeep:1` | Pricing engine |
| MARKER-007 | P1 | `AIVM:monitoring/grafana/.gitkeep:1` | Grafana dashboards |
| MARKER-008 | P1 | `AIVM:monitoring/prometheus/.gitkeep:1` | Prometheus rules/config |
| MARKER-009 | P1 | `AIVM:samples/agent-example/.gitkeep:1` | Agent example |
| MARKER-010 | P1 | `AIVM:samples/federated-training-example/.gitkeep:1` | Federated training example |
| MARKER-011 | P1 | `AIVM:samples/simple-inference/.gitkeep:1` | Sample supporting files; an ONNX binary exists but required labels/input do not |
| MARKER-012 | P1 | `AIVM:security/audits/.gitkeep:1` | Security audit evidence |
| MARKER-013 | P1 | `AIVM:security/sops/.gitkeep:1` | Security operations |
| MARKER-014 | P1 | `AIVM:synergy_portal_integration/utility-tool-plugin/plugin/.gitkeep:1` | Portal plugin |
| MARKER-015 | P0 | `AIVM:tests/e2e/.gitkeep:1` | End-to-end tests |
| MARKER-016 | P0 | `AIVM:tests/integration/.gitkeep:1` | Integration tests |
| MARKER-017 | P0 | `AIVM:tests/perf/.gitkeep:1` | Performance tests |
| MARKER-018 | P0 | `AIVM:verifier/attestation/.gitkeep:1` | Attestation subsystem |

## E. AI and SDK code that is present but not operational

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| AI-001 | P0 | `AIVM:providers/gpu-worker/worker_service.py:8-10` | Hard-coded relative model/labels paths and literal `path/to/your/image.jpg`; the label file and image are not present. |
| AI-002 | P0 | `AIVM:providers/gpu-worker/worker_service.py:12-41` | One-shot local ImageNet inference script. It has no service, task transport, authentication, provider identity, registered model verification, isolation, attestation, metering, result signature, quorum, or settlement. |
| AI-003 | P0 | `AIVM:model-registry/manifests/modelmanifest.json:1-100` | File is a JSON Schema, not an actual registered model manifest or registry implementation. |
| AI-004 | P0 | `AIVM:model-registry/registry-api/package.json:1-6` | Declares a TypeScript server entrypoint but has an empty dependency set and the literal-brace entrypoint file is zero bytes. |
| AI-005 | P0 | `AIVM:sdk/proto/aivm.proto:1-48` | Defines only data messages; there is no `service` or RPC method definition. |
| AI-006 | P1 | `AIVM:sdk/python/setup.py:1-6` | Packaging shell only; there are no Python SDK modules outside the checked-in virtual environment. |
| AI-007 | P1 | `AIVM:README.md:217-224` | Instructs users to run root `cargo build` and `cargo run --example basic_vm`, but the repository has no root Cargo manifest and no `basic_vm` example. |

## F. Testnet fake SynQ compiler/interpreter

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| SYNQ-FAKE-001 | P0 | `TESTNET:src/synq/compiler.rs:111-130` | “Parser” stores the entire source string with fixed metadata and wall-clock creation time; it does not parse SynQ. |
| SYNQ-FAKE-002 | P0 | `TESTNET:src/synq/compiler.rs:133-156` | “Bytecode” is only magic bytes, algorithm ID, contract name, wall-clock timestamp, and 256 zero bytes. No contract semantics are compiled. |
| SYNQ-FAKE-003 | P1 | `TESTNET:src/synq/compiler.rs:159-220` | Emits a static Solidity template unrelated to source semantics; generated PQC verification always reverts and key update has no authorization. |
| SYNQ-FAKE-004 | P0 | `TESTNET:src/synq/compiler.rs:222-233` | ABI generator ignores `_code` and always emits one static metadata object. |
| SYNQ-FAKE-005 | P0 | `TESTNET:src/synq/interpreter.rs:45-89` | Ignores `_contract_code`, always returns success/21,000 gas, and fabricates “verification passed” strings without verification. |
| SYNQ-FAKE-006 | P1 | `TESTNET:src/synq/interpreter.rs:91-107` | Syntax validation is only substring checks for `contract`, `function`, and `pqc`. |
| SYNQ-FAKE-007 | P1 | `TESTNET:src/synq/interpreter.rs:110-130` | Gas estimation is a fixed string heuristic (`transfer`, `pqc`) rather than executed instruction cost. |
| SYNQ-FAKE-008 | P1 | `TESTNET:src/synq/interpreter.rs:133-173` | Ignores `_synq_code` and returns a static Solidity contract with wall-clock timestamp. |

## G. Dead legacy AIVM code contains additional fake behavior

These items remain serious even though `TESTNET:src/aivm` is uncompiled: the commented RPC surface was written against them, and re-enabling the module would expose fake/nondeterministic behavior and compile failures.

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| LEGACY-001 | P0 | `TESTNET:src/aivm/runtime.rs:55-122` | Creates only in-memory maps and a separate WASM VM; deployment inserts an object and uses wall-clock time. No chain state/consensus commit. |
| LEGACY-002 | P0 | `TESTNET:src/aivm/runtime.rs:165-202` | “Standard contract” executes the competing WASM VM, uses broken instance-selection logic, and returns a fixed `wasm_success` marker. |
| LEGACY-003 | P0 | `TESTNET:src/aivm/runtime.rs:204-284` | AI-enhanced call extracts `model:` from arbitrary output, defaults to a hard-coded model, blocks/polls locally, and adds a fixed gas amount. |
| LEGACY-004 | P0 | `TESTNET:src/aivm/runtime.rs:286-332` | Cross-chain operation is explicitly simulated and fabricates `cross_chain_result:<chain>:<input>` while reporting success. |
| LEGACY-005 | P0 | `TESTNET:src/aivm/runtime.rs:334-385` | Oracle uses hard-coded mock price/weather/news JSON and a fixed fake timestamp. |
| LEGACY-006 | P0 | `TESTNET:src/aivm/runtime.rs:403-414` | Contract address includes wall-clock seconds, making execution nondeterministic/collision-prone. |
| LEGACY-007 | P1 | `TESTNET:src/aivm/runtime.rs:416-470` | Parses colon-delimited transaction strings, substitutes empty bytes on decode failure, sets block height zero, and uses wall-clock time. |
| LEGACY-008 | P0 | `TESTNET:src/aivm/wasm_vm.rs:90-125` | Host functions return block `12345`, wall-clock time, print instead of reading memory, and report successful store/load without storing/loading data. |
| LEGACY-009 | P0 | `TESTNET:src/aivm/wasm_vm.rs:153-203` | Passes placeholder pointer zero without writing input, fabricates zero-byte output, meters gas from host execution time, and ignores the supplied `gas_limit`. |
| LEGACY-010 | P0 | `TESTNET:src/aivm/distributed_ai.rs:123-132` | Computation IDs use wall-clock seconds and can collide; they are not bound to request/provider/chain commitments. |
| LEGACY-011 | P0 | `TESTNET:src/aivm/distributed_ai.rs:209-256` | Result submission has no result signature, proof, attestation, model/input commitment, or replay protection; line 244 references `task` outside its scope and would not compile. |
| LEGACY-012 | P0 | `TESTNET:src/aivm/distributed_ai.rs:259-281` | “Dispatch” only prints notification messages; no network task is sent. |
| LEGACY-013 | P0 | `TESTNET:src/aivm/distributed_ai.rs:316-348` | Aggregation is raw byte majority with no signature/attestation/proof/tolerance/collusion controls. |
| LEGACY-014 | P0 | `TESTNET:src/aivm/distributed_ai.rs:401-430` | Rewards are hard-coded to 1,000 per validator and only stored/printed; no token transfer, escrow, or settlement occurs. |
| LEGACY-015 | P1 | `TESTNET:src/aivm/distributed_ai.rs:518-543` | Expired jobs are deleted/printed; cleanup/refunds are explicitly not implemented. |
| LEGACY-016 | P0 | `TESTNET:src/aivm/provider.rs:99-126` | Moves `provider` into a map at line 105 and then reuses it at lines 109/119/122; code would not compile if the dead module were enabled. |
| LEGACY-017 | P0 | `TESTNET:src/aivm/provider.rs:180-187` | Task submission merely pushes to an in-memory vector and returns a success string. |
| LEGACY-018 | P0 | `TESTNET:src/aivm/provider.rs:197-214` | Records every result with `output_data: vec![]` instead of an actual provider result. |
| LEGACY-019 | P0 | `TESTNET:src/aivm/provider.rs:308-340` | “Process queue” sorts and drains up to ten tasks, discards them, performs no work/dispatch, and returns the drained count as processed. |
| LEGACY-020 | P0 | `TESTNET:src/aivm/verifier.rs:254-302` | Attestation “signature verification” trusts any nonempty signature and data. |
| LEGACY-021 | P1 | `TESTNET:src/aivm/verifier.rs:122-155` | Provider verification begins with trust score zero while later logic subtracts penalties, making the scoring path internally invalid. |
| LEGACY-022 | P0 | `TESTNET:src/aivm/verifier.rs:392-402` | Built-in “trusted roots” are plain marker strings (`intel_sgx_root`, etc.), not certificate chains or pinned identities. |
| LEGACY-023 | P0 | `TESTNET:src/aivm/interoperability.rs:342-347` | “Zero-knowledge proof” is the plaintext string `zk_proof_of_validity_<hex message>`. |
| LEGACY-024 | P0 | `TESTNET:src/aivm/interoperability.rs:852-865` | Encryption verification is only nonempty/length comparison; ZK verification is only a nonempty-message check. |
| LEGACY-025 | P0 | `TESTNET:src/aivm/interoperability.rs:878-884` | Cross-chain message ID is wall-clock seconds, unsuitable for deterministic uniqueness/replay protection. |
| LEGACY-025A | P0 | `TESTNET:src/aivm/interoperability.rs:257-261` | Generates a fake ZK proof into `zk_proof` and then discards it; no proof is attached to or verified with the message. |
| LEGACY-025B | P1 | `TESTNET:src/aivm/interoperability.rs:733-739` | Cross-chain fee calculation ignores chain conditions and always returns a hard-coded one-ETH-equivalent base fee. |
| LEGACY-026 | P0 | `TESTNET:src/aivm/model_registry.rs:74-105` | Registry is an in-memory map with hard-coded address `aivm_registry`, not a chain registry. |
| LEGACY-027 | P1 | `TESTNET:src/aivm/model_registry.rs:266-282` | Uses `ModelType` as a `HashMap` key without deriving `Hash`; code would fail if compiled. |
| LEGACY-028 | P0 | `TESTNET:src/aivm/model_registry.rs:285-325` | “Built-in GPT-OSS-20B” registers metadata only; no model artifact, weight hash, tokenizer, runtime, or endpoint is bound. |
| LEGACY-029 | P0 | `TESTNET:src/aivm/chat_interface.rs:29-44` | Defaults to an unauthenticated localhost model endpoint. |
| LEGACY-030 | P0 | `TESTNET:src/aivm/chat_interface.rs:51-115` | Method takes `&self` but mutates `self.sessions` at line 113; it would not compile if enabled. It also uses wall-clock session data in an AIVM context. |
| LEGACY-031 | P1 | `TESTNET:src/aivm/chat_interface.rs:145-178` | Hard-codes model, sampling parameters, token limit, and system prompt rather than using registered job/model policy. |

## H. Disabled RPC and false network surface

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| RPC-001 | P0 | `TESTNET:src/rpc/rpc_server.rs:43-44,566-568,1647-1648` | AIVM import, global runtime, and handler argument are explicitly commented out “for quick compile.” |
| RPC-002 | P0 | `TESTNET:src/rpc/rpc_server.rs:3005-3058` | Direct deploy/execute AIVM methods are fully commented out. |
| RPC-003 | P0 | `TESTNET:src/rpc/rpc_server.rs:3060-3164` | Distributed AI submit/status/result/partial-result/tasks/rewards/stats/chat methods are fully commented out. |
| RPC-004 | P1 | `TESTNET:src/rpc/rpc_server.rs:3159-3160` | Disabled chat handler would return success while explicitly saying async chat is not implemented. |
| RPC-005 | P0 | `TESTNET:src/rpc/rpc_server.rs:3166-3193` | AIVM contract/stats methods are commented out; stats would advertise fabricated model/chain/feature arrays. |
| RPC-006 | P0 | `TESTNET:src/rpc/rpc_server.rs:3671-3692` | `synergy_call` returns empty data plus an AIVM-disabled note instead of executing a read-only call. |
| RPC-007 | P0 | `TESTNET:src/rpc/rpc_server.rs:3845-3860` | `synergy_getCode` returns `0x` for every contract because AIVM is disabled. |
| RPC-008 | P0 | `TESTNET:src/rpc/rpc_server.rs:3863-3882` | `synergy_getStorageAt` returns 32 zero bytes for every contract because AIVM is disabled. |

## I. Consensus/state integration gaps masquerading as a complete path

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| WIRE-001 | P0 | `TESTNET:src/execution.rs:12-39` | AIVM artifacts/deployments/state exist only in an in-memory `ExecutionState`; there is no persisted canonical state implementation in this type. |
| WIRE-002 | P0 | `TESTNET:src/execution.rs:127-158` | AIVM execution is present in a helper block executor, but call tracing found its PoSy proposal/validation callers invoked only by tests; live node commit ownership was not found. |
| WIRE-003 | P0 | `TESTNET:src/synq_execution.rs:543-566` | Discards `_verification`, hard-codes `block_height: 0`, and hard-codes security policy/PQ-gas values. |
| WIRE-004 | P1 | `TESTNET:src/rpc/rpc_server.rs:7400-7480` | Receipt lookup reconstructs SynQ/AIVM receipts by replaying committed carrier transactions into a separate RPC index; this is not canonical consensus execution state. |

## J. Tests that silently do not test

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| TEST-001 | P0 | `TESTNET:src/execution.rs:1007-1018` | Counter fixture builds an invalid path and falls back to a missing absolute path; it returns `None` when artifacts are absent. |
| TEST-002 | P0 | `TESTNET:src/execution.rs:1347-1350` | Core deploy/increment/get integration test prints “skipping” and returns success when the broken fixture returns `None`. |
| TEST-003 | P0 | `TESTNET:src/rpc/rpc_server.rs:8932-8938` | RPC fixture hard-codes the same missing absolute artifact root and returns `None`. |
| TEST-004 | P0 | `TESTNET:src/rpc/rpc_server.rs:9586-9590` | RPC receipt replay test silently passes by printing a skip message and returning. |
| TEST-005 | P0 | `TESTNET:src/rpc/rpc_server.rs:9646-9650` | Compacted-window receipt test silently passes by printing a skip message and returning. |
| TEST-006 | P1 | `AIVM:runtime/aivm-core/src/vm/wasm_runner.rs:63-82` | WASM tests prove only that an empty module loads and a host import is rejected; they do not execute a function, meter gas, or exercise state. |

## K. Build-break and repository-divergence instances

| ID | Severity | Exact location | Finding |
|---|---:|---|---|
| BUILD-001 | P0 | `AIVM:runtime/aivm-node/src/main.rs:1` | Isolated `cargo check` fails `E0601: main function not found`. |
| BUILD-002 | P0 | `AIVM:verifier/verifier-core/Cargo.toml:1-7` | Isolated `cargo check` fails because the manifest has no target; authoritative source files are empty and there is no `src/lib.rs`. |
| BUILD-003 | P0 | `TESTNET:aegis-pqvm/vendor/pqcrypto-internals/Cargo.toml:1` and `TESTNET:synq-language/pqrust/pqrust-internals/Cargo.toml:1` | Integrated Cargo commands fail before AIVM tests because the parent workspace contains two packages named `pqrust-internals`. |
| BUILD-004 | P1 | `AIVM:` repository root | No root `Cargo.toml` or build orchestrator exists, despite root build instructions. |
| BUILD-005 | P1 | `CLONE:` repository root | Standalone checkout is at `0b80a2c` while fetched `origin/main` and integrated AIVM are `d2d8e67`. |
| BUILD-006 | P1 | `TOP-COPY:runtime/aivm-core/src/execution.rs:1-805` | Unversioned top-level source differs byte-for-byte from authoritative revision; it lacks the latest integrated execution context and cannot identify provenance. |
| BUILD-007 | P0 | `TOP-COPY:verifier/verifier-core/src/attestation.rs:11-17` | Stale copy calls a report “complete” solely when four fields are nonempty. |
| BUILD-008 | P0 | `TOP-COPY:verifier/verifier-core/src/verifier.rs:19-30` | Stale copy marks every “complete” attestation `Trusted` without cryptographic signature, quote, measurement, freshness, TCB, or identity verification. |

## Required disposition

For every row above, choose exactly one outcome before production sign-off:

1. Implement it completely with fail-closed tests and integration proof.
2. Remove it and remove every claim/reference/RPC/schema that advertises it.
3. For intentionally native/precompile behavior, formally specify, version, meter, secure, test, and name it as such; do not present it as execution of arbitrary SynQ bytecode.

No empty implementation file, skip-and-return production test, fake-success response, uncompiled duplicate VM, or non-cryptographic verifier may remain in a production release.
