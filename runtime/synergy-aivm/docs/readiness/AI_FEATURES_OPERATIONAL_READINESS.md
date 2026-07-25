# AI Features Operational-Readiness Checklist

Audit baseline: 2026-07-15 at AIVM revision `d2d8e67`

Current status: **AI features are not operational**

The checked-in AI surface is a directory scaffold and a one-shot local ONNX example. This checklist separates deterministic on-chain AIVM behavior from nondeterministic/off-chain provider computation so decentralized inference cannot accidentally become consensus nondeterminism.

## P0 — define the AIVM AI execution model

- [ ] Specify which AI operations, if any, execute deterministically inside consensus and which create asynchronous off-chain jobs.
- [ ] Define a versioned AIVM AI host ABI callable by SynQ contracts: job creation, input commitment, model/version, budget, provider policy, deadline, status, result commitment, dispute, and cancellation.
- [ ] Define deterministic transaction/state transitions for every asynchronous job lifecycle state.
- [ ] Define how contracts consume results in later blocks without blocking validator consensus on model inference.
- [ ] Define content-addressed encodings and maximum sizes for inputs, outputs, model artifacts, transcripts, proofs, and metadata.
- [ ] Define AI-specific gas/PQ-gas, escrow, storage rent, provider fees, refunds, penalties, and timeout settlement.
- [ ] Define protocol/version activation and model/runtime compatibility rules.
- [ ] Ensure the AI ABI is implemented by the same AIVM; do not create another AI VM or provider-side consensus interpreter.

Acceptance: a reviewed protocol specification and conformance vectors cover the full lifecycle and make consensus behavior deterministic even when providers fail or disagree.

## P0 — model registry and artifact supply chain

- [ ] Implement a real model manifest format and distinguish it from the current JSON Schema file.
- [ ] Implement registry create/update/deprecate/revoke/query operations backed by canonical network state.
- [ ] Bind model ID, version, weights hash, runtime/ops set, tokenizer/pre/post-processing, license, author, resource limits, and security policy.
- [ ] Implement content-addressed model storage adapters with availability, integrity, pinning, replication, and retention rules.
- [ ] Implement `pack_model.py` and `validate_manifest.py` with reproducible artifact hashing and strict validation.
- [ ] Implement registry authorization/governance, publisher identity, signature verification, revocation, and emergency disable.
- [ ] Implement model-license and privacy-policy enforcement hooks.
- [ ] Generate SBOM/provenance for models, runtimes, operators, and native dependencies.
- [ ] Add malicious-model scanning, unsafe operator rejection, archive/path traversal protection, decompression limits, and sandbox compatibility checks.

Acceptance: a signed model can be registered, independently fetched/verified by providers, revoked, and rejected after any artifact or manifest alteration.

## P0 — provider/operator network

- [ ] Implement the GPU worker as a long-running authenticated service, not a local script with hard-coded files.
- [ ] Define and implement provider registration, capabilities, endpoint discovery, liveness, capacity, region, pricing, reputation, and version negotiation.
- [ ] Implement provider-operator configuration, container image, node setup, Kubernetes deployment, secrets, upgrades, and health checks.
- [ ] Implement task assignment/claim/lease/heartbeat/cancel/retry/result protocols over authenticated transport.
- [ ] Bind every task and result to job ID, model hash/version, input commitment, provider identity, runtime hash, nonce, deadline, and chain state.
- [ ] Implement concurrency, queue backpressure, timeouts, GPU memory limits, disk quotas, process isolation, and cleanup.
- [ ] Implement model caching with verified hashes, eviction, poisoning prevention, and confidential temporary storage.
- [ ] Implement provider admission and slashing/reputation rules without trusting self-reported hardware or results.
- [ ] Prevent validators from being implicitly required to own GPUs unless the protocol and network economics explicitly require that role.

Acceptance: multiple independently operated providers receive authenticated jobs, execute the exact registered artifact, report health/capacity, and recover safely from disconnect/restart.

## P0 — inference runtime and deterministic packaging

- [ ] Select supported inference runtimes/operators/hardware and freeze compatible versions.
- [ ] Implement model loading, input validation, preprocessing, inference, postprocessing, and output serialization from the registered manifest.
- [ ] Replace hard-coded EfficientNet paths and provide complete runnable sample inputs/labels.
- [ ] Define reproducibility/tolerance rules for floating-point, hardware, quantization, batching, seeds, sampling, and nondeterministic GPU kernels.
- [ ] Implement deterministic/random-seed commitments for generative workloads where exact byte equality is not possible.
- [ ] Meter CPU, GPU, memory, disk, bandwidth, model load, tokens, and wall-time for billing while keeping consensus accounting deterministic.
- [ ] Implement isolation against malicious models and inputs, including runtime sandboxing and network/filesystem denial by default.
- [ ] Produce signed execution transcripts that bind the complete request/runtime/result context rather than three mutable strings.
- [ ] Implement streaming/chunked results only with authenticated ordering, limits, cancellation, and final commitments.

Acceptance: registered sample models run through the production worker protocol on all supported hardware profiles with reproducible/tolerance-qualified results and signed transcripts.

## P0 — result verification and attestation

- [ ] Define the assurance modes supported by each model/job: replicated quorum, TEE attestation, zkML/proof, deterministic replay, optimistic challenge, or combinations.
- [ ] Implement cryptographic provider result signatures and verify them against registered provider keys.
- [ ] Implement real SGX/SEV/GPU attestation quote verification, certificate chains, measurements, TCB status, freshness, nonce binding, and revocation.
- [ ] Replace completeness/nonempty checks with actual verification; a filled report must never become `Trusted` without cryptographic proof.
- [ ] Implement result aggregation that validates participant authorization and signatures and resists Sybil/collusion/equivocation.
- [ ] Define numeric/tolerance aggregation for nondeterministic models; raw byte majority is insufficient.
- [ ] Implement dispute/challenge evidence, time windows, re-execution, adjudication, and finality.
- [ ] Implement zk circuits/provers/verifiers only for explicitly supported model/operator sets; remove placeholder ZK strings/basic nonempty checks.
- [ ] Commit accepted result/transcript/proof hashes to canonical chain state and expose verification evidence.

Acceptance: forged signatures, replayed quotes, altered inputs/models/results, stale TCBs, equivocation, and insufficient quorum all fail closed in integration and adversarial tests.

## P0 — economics and settlement

- [ ] Implement user budget escrow before dispatch.
- [ ] Define deterministic price selection/auction rules and maximum-charge authorization.
- [ ] Settle provider payment only after accepted verification/finality.
- [ ] Implement timeouts, cancellations, partial execution, retries, refunds, protocol fees, and rounding.
- [ ] Implement stake, slashing, challenge bonds, reputation updates, and appeals with canonical accounting.
- [ ] Prevent double claims, fabricated completion, reward-without-work, and overflow/underflow.
- [ ] Expose auditable job cost and settlement receipts.

Acceptance: end-to-end accounting invariants hold under success, failure, timeout, dispute, provider loss, and chain replay/reorg scenarios.

## P0 — privacy, safety, and policy

- [ ] Define whether job inputs/outputs are public, encrypted, committed, or available only inside attested environments.
- [ ] Implement end-to-end payload encryption, key release, rotation, erasure, and failure handling for private jobs.
- [ ] Prevent secrets, API keys, prompts, model inputs, and outputs from leaking through chain data, logs, metrics, crash dumps, or provider caches.
- [ ] Implement data-retention, deletion, consent, jurisdiction, and model-license policies where applicable.
- [ ] Define network-level prohibited workload/content policy and enforcement/governance boundaries.
- [ ] Threat-model model extraction, prompt injection, data poisoning, malicious weights, side channels, denial of service, and provider collusion.

Acceptance: the approved privacy/security design is implemented, tested, audited, and reflected in user-visible job policy before accepting sensitive workloads.

## P0 — APIs, SDKs, contracts, and user surfaces

- [ ] Add an actual RPC/gRPC service definition; the current protobuf defines messages but no service.
- [ ] Implement job submit/status/cancel/result/proof/provider/model methods on production service roles.
- [ ] Add SynQ AI host functions and example contracts that use the asynchronous lifecycle correctly.
- [ ] Implement JS, Python, and Rust SDKs with signing, commitments, encryption, retries, and typed errors.
- [ ] Implement model publisher/provider/user CLI workflows.
- [ ] Implement working dashboard, model registry, provider console, job explorer, and proof/transcript views.
- [ ] Publish schemas, limits, error codes, lifecycle diagrams, and version compatibility documentation.

Acceptance: an external user can register/fetch a permitted model, fund and submit a contract-originated job, observe assignment, verify the accepted result, and settle payment using supported public tools.

## P0 — testing, security, deployment, and operations

- [ ] Add unit, integration, end-to-end, performance, chaos, and adversarial AI test suites; the current test directories contain only `.gitkeep`.
- [ ] Test multiple real providers/models/hardware profiles and all failure/dispute/economic paths.
- [ ] Add protocol fuzzing, malicious model/input corpora, attestation-negative vectors, and result-forgery tests.
- [ ] Establish latency, throughput, availability, cost, model-load, and result-finality SLOs.
- [ ] Implement Prometheus metrics, Grafana dashboards, alerting, tracing, log redaction, and capacity planning.
- [ ] Implement reproducible worker/verifier images, signed releases, SBOMs, dependency scanning, and staged rollout/rollback.
- [ ] Conduct external reviews for protocol economics, worker sandboxing, attestation, cryptography, privacy, and smart-contract integration.
- [ ] Run a multi-operator public testnet soak with provider churn, GPU faults, network partitions, invalid results, disputes, and upgrades.
- [ ] Obtain explicit security, protocol, economics, operations, provider, SDK, and network release sign-offs.

Acceptance: the production release passes all fail-closed gates and the public testnet demonstrates sustained decentralized inference with independently operated providers.

## Final operational acceptance scenario

The AI side is operational only when a SynQ contract on the public network can create a funded job for a registered content-addressed model, independent providers execute it, the required assurance mechanism verifies it, canonical chain state records the accepted result and settlement, the contract consumes the result in a later transaction, and the entire flow survives provider and validator restarts without using any VM other than AIVM.
