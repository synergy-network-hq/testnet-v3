# Synergy Node Architecture — Expanded Production Completion Checklist (Canonical 20-Role Taxonomy)

> **Canonical repository ledger:**
> `docs/refactor/NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md` is the one canonical
> version. Every canonical clone contains this same tracked file. Update it in
> place and never create alternate, renamed, or divergent copies. An absolute
> checkout path never defines canonical file identity.

> This replaces the narrower working checklist. It preserves Codex's verified progress while adding the architecture, role, security, operator, packaging, simulation, fuzzing, versioning, and production-validation work that was missing.

**Implementation rule:** `[x]` means the assigned production responsibility is
implemented. `[~]` means real implementation exists but required behavior is
incomplete. `[ ]` means absent or mostly scaffold. Testing is tracked separately
in Phase 2 and is not required to mark implementation progress.


> **Historical-name note:** References to removed/renamed roles below are migration instructions only. The only valid target node roles are the 20 roles in the canonical taxonomy section.

**Overall completion rule:** the software migration cannot be called complete
while a required implementation item is unchecked/partial, callers still depend
on legacy ownership, or `synergy-node` does not own the new runtime. Production
readiness is a later claim requiring Phase 2 build, test, integration, new-network
artifact generation, and launch evidence.

**Current reconciliation (2026-09-15):** 125 of 314 checklist items are complete,
30 are partial, and 159 are open. Using `complete = 1`, `partial = 0.5`, and
`open = 0`, overall weighted completion is **44.6%**. The production-source queue
is separately 100% implemented; the remaining percentage is dominated by caller
migration, legacy retirement, canonical-role completion, packaging/operations,
and deferred Phase 2 verification. Newly reconciled source includes concrete
SynQ/PQSynQ/AIVM, SXCP/UMA, governance/system dispatch, cross-epoch Sync,
authenticated ETDAG shard serving, and deterministic finalized-world-state
execution callers for node ownership, naming, and owner-authorized reward
withdrawal. The shared Admin API and CLI inspect finalized state or prepare the
same native transaction actions without mutating local caches. No live evidence
is implied. The
2026-09-15 architecture expansion below adds newly approved Core Protocol root,
Node Address/NodeID, ownership, rewards, exact interface parity, updater,
simplification, onboarding, and production-acceptance requirements; the weighted
percentage includes these expanded requirements.

## Canonical Core Protocol reorganization and approved architecture expansion

- [x] Move the sole canonical implementation from `01-Core-Protocol/testnet-v3/node-platform/` to `01-Core-Protocol/node-platform/` on Val4.
- [x] Lift the existing Git repository metadata to `01-Core-Protocol/` without creating a second repository or implementation.
- [x] Prove that no second `node-platform/` tree remains under `networks/testnet-v3/`.
- [x] Create the sibling `networks/`, `protocol/`, and `tooling/` ownership roots and all four required network directories.
- [~] Redistribute the former Testnet-v3 root so `networks/testnet-v3/` retains only network-specific governed artifacts and explicitly frozen migration reference material.
- [ ] Reconcile existing Devnet governed artifacts under `networks/devnet/` without fabricating values.
- [ ] Reconcile existing Testnet-v3 governed manifest, Genesis, bootseed, version, role, and ETDAG artifacts under `networks/testnet-v3/`.
- [ ] Keep unauthorized Mainnet Beta and Mainnet artifacts absent or explicitly blocked; never fabricate parameters.
- [ ] Move normative PoSy, ETDAG, SXCP, UMA, Aegis, transaction, block/state, address, naming, ownership, reward, manifest, lifecycle, and wire/schema ownership under `protocol/` without duplicating Rust engines.
- [ ] Reconcile executable operator/developer/release/Genesis/DB/key tooling under `tooling/` while keeping reusable Rust libraries in `node-platform`.
- [~] Repair every Cargo, CI, script, package, service, configuration, documentation, and operator path to the canonical Core Protocol root.
- [ ] Remove generated `target/`, AppleDouble, backup, temporary, and duplicate-vendored residue only after exact source/use checks permit removal.
- [~] Replace protocol-critical uses of `NodeId`/validator ID as the canonical `synv...` identity with `NodeAddress`. The validator Admin/CLI/RPC public boundary is actively moving to typed `NodeAddress`/`--node-address`; remaining networking, PoSy, persistence, telemetry, GUI, and legacy fields still require classification and cutover.
- [x] Reserve `NodeID` exclusively for normalized human-readable `<name>.node` Synergy Naming System aliases.
- [x] Implement first-class NodeID normalization, availability checking, registration, forward resolution, reverse resolution, rename/update, duplicate refusal, and owner authorization. Deterministic actions update the execution overlay stored in canonical `WorldState.protocol`; only the existing PoSy-finalized state commit makes them authoritative. Local persistence is a rebuildable finalized cache and ownership comes from `synergy-node-ownership`.
- [~] Prove NodeID changes cannot alter Node Address, consensus keys/authority, rewards, ownership, transport identity, stake, or sync state. Source boundaries and focused tests prove NodeAddress/ownership/reward independence; end-to-end caller and acceptance evidence remains.
- [x] Implement durable cryptographic Node Address to owner-wallet binding without storing the wallet private key. Claims require the wallet-signed transaction plus a detached Aegis node-possession proof, transfers require replacement-owner acceptance, and only the PoSy-finalized world-state path establishes authoritative state.
- [x] Implement governed/owner-authorized ownership transfer rather than editable local configuration. Current-owner proof and replacement-owner acceptance are required before a transfer can enter finalized state.
- [x] Implement reward attribution to Node Address without inventing an unapproved reward formula. `synergy-rewards` applies externally supplied canonical credits and never calculates economics.
- [x] Require linked owner-wallet authorization for every reward withdrawal transition. The execution caller binds the transaction sender to its public key, queries the independent ownership state, and applies the withdrawal transition only within the finality-gated world-state path.
- [~] Establish one typed management dispatcher and machine-readable capability registry shared by CLI and Node Control Panel.
- [ ] Achieve EXACT CAPABILITY PARITY between backend, CLI, and Node Control Panel for every supported operation.
- [ ] Prove the GUI never shells out to or scrapes the CLI and neither interface owns separate protocol decisions.
- [ ] Implement signed automatic update discovery, channels, policy, staging, Aegis verification, compatibility, disk preflight, drain/restart, health validation, rollback, audit, and activation awareness.
- [ ] Prove software installation cannot activate future protocol behavior before its governed activation boundary.
- [x] Document the retained/removed PoSy mechanism classification, exact invariant, failure scenario, and rejected simpler alternative in `protocol/posy-v3/PO_SY_SIMPLIFICATION_AUDIT.md`.
- [ ] Build the retained-mechanism dependency map so a future proven simplification can remove an entire derived chain from its root invariant.
- [~] Complete caller, persisted-state, wire, and test evidence before removing any remaining PoSy mechanism or legacy coordinator.
- [~] Simplify the operator lifecycle to `Create -> Join -> Sync -> Ready -> Active` while retaining required internal safety states.
- [ ] Resolve the authoritative classification of the historical 1,000-block shadow requirement and implement the decision.
- [ ] Implement zero-touch node/validator onboarding through the same typed CLI and GUI operations without modifying existing validators.
- [ ] Prove restart/double-sign safety, rolling upgrades, governed activation, sixth-validator onboarding, removal/jailing continuity, bootseed independence, and VPN-control-plane outage tolerance in the production-equivalent acceptance scenario.

## Canonical Synergy Node Role Taxonomy — 20 Roles

This taxonomy is now authoritative for the node-platform architecture. A **node role** exists only when it has a materially different trust boundary, networking responsibility, persistence requirement, authority model, or operator/resource responsibility. Individual jobs within one trust/resource boundary are modeled as **capabilities**, not separate node roles.

| Class | Canonical Node Role | Exact Function | Key Boundary / Notes |
|---|---|---|---|
| **I — Consensus & Chain Integrity** | **Validator Node** | Runs Proof-of-Synergy consensus; validates state transitions; performs proposal/vote/certificate/finality duties; performs validator-side ETDAG duties; maintains current canonical state. | PoSy authority only after canonical authorization/activation. Stake is accountability/economic security, not PoS voting power. |
| **I — Consensus & Chain Integrity** | **Sentry Node** | Hardened dual-homed perimeter between the public Synergy P2P network and validators on the private validator VPN; forwards permitted authenticated protocol traffic, shields validator endpoints, rate-limits/filters abuse, and provides redundant validator ingress/egress. | **No PoSy signing/finality authority.** Sentry compromise must not expose validator signing keys. Validators independently verify everything received through sentries. |
| **I — Consensus & Chain Integrity** | **Archive Node** | Preserves full/long-term chain history; serves historical blocks/state/proofs; creates and serves verified snapshots; supports recovery and synchronization. | Renamed from **Archive Validator** because archival storage does not itself grant validator authority. |
| **I — Consensus & Chain Integrity** | **Consensus Audit Node** | Independently revalidates PoSy artifacts, finalized blocks, state transitions, divergence, equivocation, and validator behavior; emits audit findings/alerts. | Renamed from **Audit Validator**; non-signing audit role. |
| **II — Interoperability** | **Cross-Chain Node** | Provides SXCP relay and verification capabilities: observes/consumes external-chain proofs, relays packages, validates proof/finality/scope/receipts, and submits accepted interoperability work. | Replaces separate Relayer + Cross-Chain Verifier roles. `relay` and `verify` remain separate capabilities; a node's own relay artifact cannot independently satisfy the verification requirement for that same acceptance decision. |
| **II — Interoperability** | **Witness Node** | Independently observes external-chain events and produces signed observation/proof material. | Separate evidence source from Cross-Chain Node acceptance logic. |
| **II — Interoperability** | **Oracle Node** | Acquires approved off-chain/external data, authenticates sources, normalizes data, and publishes signed feed attestations. | Oracle/data-attestation scope only. |
| **II — Interoperability** | **UMA Coordinator Node** | Maintains and verifies UMA identity/address mappings, refreshes mappings, handles consistency/recovery, and emits auditable mapping records. | Mapping/identity coordination only. |
| **III — Execution, Data & Cryptography** | **SynQ Execution Node** | Provides deterministic SynQ execution, contract verification, trace generation, simulation/pre-execution, and execution-job capacity. | Service execution does not decide PoSy finality. |
| **III — Execution, Data & Cryptography** | **Network Analytics Node** | Performs network/chain simulations, anomaly detection, performance analysis, risk modeling, and approved analytical workloads. | Renamed from Analytics & Simulation; advisory output is not protocol truth. |
| **III — Execution, Data & Cryptography** | **Aegis Cryptography Node** | Provides Aegis/PQC verification, cryptographic attestations, key lifecycle, threshold/KMS/HSM support, and authorized cryptographic services. | High-security cryptographic role with isolated key custody. |
| **III — Execution, Data & Cryptography** | **Data Availability Node** | Stores/serves required availability data, maintains shards/objects, proves retrievability, performs repair/recovery, and provides availability proofs. | Distinct from Archive: DA is protocol/current retrievability; Archive is long-term history/recovery. |
| **IV — AI & Intelligence** | **AI Compute Node** | Performs inference, embeddings, multimodal inference, training, fine-tuning, and bounded AI-agent execution according to advertised capabilities/GPU class. | Replaces AI Inference + AI Training/Fine-Tuning + AI Agent Execution. |
| **IV — AI & Intelligence** | **AI Coordination Node** | Handles AI workload routing, GPU scheduling/placement, quotas, model-policy matching, capacity coordination, utilization metering, and federated-learning coordination. | Replaces AI Routing + GPU Scheduler + Federated Learning Coordinator. |
| **IV — AI & Intelligence** | **AI Data Node** | Provides model artifact storage/metadata/hash verification, dataset provenance/rights/redaction metadata, vector/embedding memory storage/retrieval, and deletion/retention receipts. | Replaces Model Repository + Dataset Provenance + Vector Memory. Data namespaces/policies remain isolated internally. |
| **IV — AI & Intelligence** | **AI Assurance Node** | Independently verifies AI receipts/results, replay/reproducibility where possible, model/runtime/dataset policy, benchmarks, safety/evaluation, provider reputation, latency/cost/quality evidence. | Replaces AI Verification + AI Reputation & Evaluation; assurance should be independent of the workload it validates where settlement/security requires independence. |
| **V — Service & Access** | **RPC Gateway Node** | Exposes public/internal RPC and WebSocket access with rate limiting, auth where required, caching, request isolation, and API availability. | Public RPC remains separate from privileged Admin API. |
| **V — Service & Access** | **Indexer Node** | Indexes finalized chain data for transactions, accounts, contracts, tokens, NFTs, events, analytics, search, and Explorer APIs. | Renamed from Indexer & Explorer. Explorer is an application consuming indexed data, not a separate node role. |
| **V — Service & Access** | **Observer / Light Node** | Synchronizes headers/finality proofs and minimal state/proofs; verifies light proofs; supplies wallet/light-client feeds. | Non-signing observer. |
| **V — Service & Access** | **Bootseed Node** | Provides initial authenticated P2P discovery, peer exchange, bootstrap availability, and peer advertisement. | Discovery only; no consensus authority and no permanent liveness dependency after peer mesh establishment. |

### Node-role totals

| Class | Count |
|---|---:|
| I — Consensus & Chain Integrity | 4 |
| II — Interoperability | 4 |
| III — Execution, Data & Cryptography | 4 |
| IV — AI & Intelligence | 4 |
| V — Service & Access | 4 |
| **Total** | **20** |

### Explicitly not canonical node roles

The following remain modules, capabilities, applications, or infrastructure services rather than canonical `NodeRole` values:

- **Committee** — removed entirely as a node role. Any legitimate quorum/rotation/coordination duty defined by PoSy is a dynamically assigned Validator duty/capability.
- **Governance Auditor / Treasury Controller / Security Council** — cross-cutting governance/security control-plane functions, not public node roles.
- **Explorer** — application consuming Indexer data.
- **VPN Enrollment Broker** — control-plane service supporting zero-touch validator/sentry overlay enrollment.
- **Validator Transport Registry** — signed transport/lease control-plane service.
- **Snapshot Publisher** — Archive capability/service, not a canonical node role.
- **Seed server** — legacy/auxiliary infrastructure; Bootseed Node is the canonical discovery role.


## Phase 0 — Migration governance and evidence

- [x] Declare `01-Core-Protocol/node-platform/` the canonical universal runtime and the network-nested legacy runtime a semantic reference only.
- [x] Remove old Genesis/wire/validator-set/storage/runtime interoperability from the implementation blocker list.
- [x] Separate implementation states from deferred build/test/integration/network-verification states.
- [x] Current architecture inventory and dependency map.
- [x] Target architecture and migration-map documents.
- [x] Consensus, ETDAG, P2P, VPN, Admin API, and genesis-change audits.
- [x] Durable implementation status ledger.
- [x] Refresh inventory/migration/status after every major extraction completed through the 2026-09-12 direct migration wave; continue this gate for future waves.
- [ ] Record every retired legacy module and prove all callers/state migrations are accounted for.
- [ ] Maintain a protocol-change ledger for consensus/ETDAG/wire/storage-format changes.

## Phase 1 — Workspace, shared types, and dependency direction

- [x] `synergy-node-core` foundation exists.
- [x] `synergy-admin-api` foundation exists.
- [~] Create all first-class crates in the complete target tree. Canonical node-platform crates are now present and registered in the workspace; remaining standalone infrastructure services and caller retirement are still open.
- [ ] Enforce one-way dependency direction; no P2P↔PoSy↔ETDAG↔execution circular ownership.
- [~] Split oversized `synergy_types.rs` into focused canonical types. The new authority-neutral protocol-types crate now owns chain, height, epoch, validator identity, cluster, hash, block/transaction, transaction/certificate references, and bounded frame descriptors; subsystem caller migration and retirement of the legacy aggregate remain.
- [ ] Remove obsolete cross-subsystem runtime ownership.
- [ ] Pin supported Rust toolchain and repository formatting/lint/security policies.
- [ ] Define reproducible release/test Cargo profiles with safe disk headroom.

## Phase 2 — Configuration, manifests, schemas, and version compatibility

- [x] Create typed `synergy-config` using the clean canonical schema v1 with no legacy adapters.
- [x] Validate node/network/P2P/PoSy/ETDAG/storage/RPC/telemetry/role/VPN config before startup using bounded loading, strict unknown-field rejection, and borrowed cross-field checks.
- [x] Create signed `synergy-manifest` library/tooling. Source ownership now includes the canonical manifest model, hash, verifier, and signed CLI boundaries; runtime caller migration remains.
- [x] Implement strict canonical network-manifest build, deterministic hashing, governed ML-DSA-65 signing/PQVM verification, safe inspection, and bounded structural diff tooling.
- [ ] Bind chain/network/genesis/PoSy/ETDAG/P2P/bootstrap/release/role schema in signed manifest.
- [x] Separate software, P2P, PoSy, ETDAG, sync, snapshot, Admin, DB, and config versions in `synergy-version`.
- [x] Implement explicit compatibility matrix and governed epoch/finalized-height activation metadata with a required governance commitment.
- [x] Implement offline canonical Chain 1266 Genesis validation, deterministic hashing, governed ML-DSA-65 authority signing, and PQVM verification without creating launch artifacts.
- [ ] Create machine-readable schemas for network manifest, node config, role profiles, leases, snapshots, genesis, ETDAG, validator membership.
- [ ] Add explicit canonical role-taxonomy schema/version and role-profile hash migration for the 20-role model.

## Phase 3 — Identity, key custody, cryptography, and Aegis

- [x] Create `synergy-identity` and enforce Node ID = Synergy node address identity rule in the source owner; runtime callers remain to migrate.
- [~] Implement Aegis-backed proof-of-possession and identity rotation/storage contracts. Node/P2P runtime binding exists; consensus/VPN caller migration remains.
- [x] Implement duplicate/conflicting-key identity protection and authorization-bound rotation contracts.
- [x] Define `synergy-crypto` as the protocol-neutral facade over the single Aegis Cryptography Engine; raw PQVM/KEM/digest/entropy implementations remain owned below `synergy-aegis`, and facade callers remain to migrate.
- [ ] Support encrypted filesystem, remote KMS, HSM, and TPM provider boundaries where applicable.
- [ ] Never expose raw validator/private signing keys via CLI/Admin API/GUI.
- [x] Create first-class node-facing `synergy-aegis` boundary with explicit PQ policy, key-ID-only custody, signer/verifier providers, attestation, lifecycle, and secret-free audit contracts.
- [x] Implement the offline synergy-keytool for non-overwriting ML-DSA-65 node/consensus keys, ML-KEM-768 ETDAG keys, public inspection, strict private-file custody, and governed rotation-plan generation.
- [ ] Add key/provider outage, rotation, backup/restore, and recovery tests.

## Phase 4 — Unified node core, lifecycle, supervisor, and roles

- [x] Runtime-owned management dispatcher serves status, health, readiness, diagnostics, canonical configuration validation, role inspection, and actual service-derived capability discovery.
- [x] Local Admin API lifecycle wiring exists.
- [x] Implement service supervisor, dependency graph, criticality, restart/fail-closed policy, cancellation, concrete runtime registrations, and reverse-order shutdown on signal, startup observation failure, or runtime tick failure.
- [x] Implement explicit node lifecycle states through ready/active/degraded/draining/failed and drive them from the retained supervised runtime.
- [x] Implement role-specific readiness gates for PoSy, ETDAG, network, storage, verified sync, and role-scoped VPN evidence; remote Sync head claims now carry bounded three-QC evidence that only PoSy verifies.
- [~] Create declarative `synergy-roles` capability/service/port/key/storage model. Source ownership exists; node caller migration remains.
- [x] Ensure role selection alone never grants validator authority; voting requires explicit authority binding, safe recovery, key custody, sync, and H+5 evidence.
- [x] Ensure non-validator roles cannot request consensus voting mode.
- [ ] Use one primary node distribution for all node roles.

## Phase 5 — CLI, Admin API, Control Panel, and event parity

- [x] Owner-only Unix Admin API with bounded typed requests.
- [x] macOS accepted-socket race fixed and stress-tested.
- [x] Initial headless CLI consumes shared management dispatcher.
- [x] Control Panel typed Admin API client and authenticated read-only bridge.
- [x] Control Panel canonical validator authorization semantics; stake/VPN do not grant authority.
- [~] Modularize CLI into complete init/start/stop/restart/join/leave/identity/keys/peers/sync/snapshot/config/manifest/role/validator/VPN/PoSy/ETDAG/storage/telemetry/upgrade/version commands. Ownership, naming, and rewards now have typed inspect/resolve/availability and transaction-preparation commands through the shared Admin contract; broader operation groups, protected transaction submission, audit, and subsystem runtime handlers remain.
- [~] Implement safe idempotent Admin API mutation operations with authorization/audit logging. Validator lifecycle mutations now use permission checks, idempotency, durable canonical management state, and frozen-authority binding; remaining subsystem operations and audit persistence remain.
- [ ] Implement typed Admin event streaming with bounded subscriber queues/backpressure.
- [ ] Route all practical Control Panel operations through the same shared operation/event model.
- [ ] Implement Node Control Panel node creation, lifecycle, config, peers, sync, validator, VPN, PoSy, ETDAG, storage/snapshots, telemetry/diagnostics, and upgrade UI.
- [ ] Add automated CLI/Admin/GUI capability-parity tests.

## Phase 6 — P2P transport, handshake, peer lifecycle, discovery, framing, and routing

- [x] Canonical dial/endpoint parsing extracted.
- [x] Handshake signing bytes/PQ algorithm policy extracted.
- [x] VPN route policy extracted.
- [x] Signed validator transport registry preserved.
- [x] Initial peer admission/duplicate/backoff lifecycle policy extracted.
- [x] Create first-class `synergy-network` and core `synergy-p2p-protocols`, with new-node authenticated runtime caller cutover for Sync, ETDAG, and PoSy.
- [x] Complete raw TCP transport/listener/dialer/connection/timeouts/resource limits with nonblocking accept, bounded-time dialing, and configured I/O.
- [x] Complete handshake identity/chain/network/role/version challenge verification and wire the governed PQVM/Aegis provider into inbound and outbound runtime admission.
- [~] Complete peer manager states, health, quarantine/ban, duplicate resolution, persistence, and bounded exponential retry. Governed signed-overlay inbound/outbound admission and bounded retry dialing are wired; jitter and remaining persistence callers remain.
- [x] Implement prioritized bootseeds, authenticated peer exchange input validation, signed transport-registry discovery boundary, and bounded expiring cache.
- [x] Implement protocol envelope/codec/framing/size limits/version registry and compatibility policy. Replay enforcement remains exact-session runtime work.
- [x] Implement bounded per-subsystem queues, watermarked backpressure, fair peer mailboxes, and attempt/capacity-bounded retransmission.
- [x] Extract transport-only PoSy, ETDAG, and sync network adapters; none can determine finality.
- [x] Implement the dual-homed **Sentry** perimeter source path with authenticated public/validator links, protocol/size filtering, bounded forwarding, and health-based failover.
- [x] Implement Sentry forwarding ACLs so only explicitly permitted opaque protocols/messages cross the public↔validator boundary; three focused policy/overload tests pass.
- [x] Implement redundant deterministic healthy multi-Sentry path selection per Validator; no mandatory 1:1 Sentry-to-Validator topology.
- [x] Ensure Sentry peer/network scoring and transport metadata cannot become PoSy authority or determine finality.
- [ ] Retire/reduce `networking.rs` god module.
- [ ] Add malicious/stale/slow/duplicate/protocol mismatch/churn/oversized-frame tests and fuzzing.

## Phase 7 — Validator VPN, NetBird, transport leases, and zero-touch enrollment

- [x] VPN route is transport only, not authority.
- [x] Current Control Panel onboarding uses canonical registration + authorization.
- [x] Dynamic routes reconcile without static validator peer mappings.
- [~] Create first-class `synergy-vpn` and `synergy-transport-registry`. Production source owns enrollment/leases/NetBird control/cache/reconciliation/revocation; the universal node verifies pinned snapshots, persists accepted generations, checks active-authority coverage, installs signed overlay admission, and schedules bounded dials. Enrollment/lease publication, deployment bindings, and live verification remain.
- [~] Implement VPN enrollment broker. Challenge, eligibility, proof, authorization, response, resume, and revocation owners exist; the Admin/runtime broker endpoint remains.
- [x] Implement synv/node challenge-response possession proof with caller-supplied finalized eligibility and injected signature verification.
- [~] Issue one-use/short-lived NetBird enrollment material with redacted diagnostics; guaranteed in-memory credential destruction remains.
- [~] Automatically establish overlay route and publish signed identity-bound transport lease. NetBird daemon observation and signed-registry route establishment are wired into authenticated network dialing/admission; lease publication remains.
- [x] Implement lease expiry/generation/stale rejection/revocation and deterministic route/key/IP reconciliation ownership.
- [x] Implement distinct **Validator** and **Sentry** overlay membership scopes/identity-route binding; neither grants PoSy authority.
- [~] Automate Sentry overlay enrollment/rotation/revocation using role-bound identity and approved policy. Source operations exist; runtime orchestration remains.
- [x] Ensure VPN management-plane status degradation does not automatically tear down an established transport.
- [ ] Test unauthorized/replayed enrollment, broker restart, management outage, IP/key changes, revocation, simultaneous joins, mass restart, split-brain lease state.
- [ ] Prove new validator joins require no manual edits/restarts on existing validators.

## Phase 8 — Verified head, block/state sync, snapshots, and recovery

- [x] Create first-class `synergy-sync` and wire authenticated head claims, PoSy evidence verification, source planning, local advertisement, and readiness into the node runtime.
- [x] Collect/verify authenticated head/finality views through the runtime PoSy owner with monotonic per-peer collection and conflict refusal.
- [x] Implement bounded block range scheduling/request/verification/import/failover. The runtime requests one parent-anchored finalized candidate at a time, transports complete transactions/receipts/account state, verifies QC/TC safety evidence through the single PoSy driver, deterministically re-executes it, commits only matching finality, and uses bounded source timeout/failover with durable request resume.
- [x] Implement finality-bound checkpoint/chunk state sync with durable resume. Candidate and snapshot state have verified sequential import, bounded integrity-checked chunks, conflict-safe durable acquisition, Aegis verification, execution restore handoff/commit/receipt, finalized publication, and fail-closed trust-root-signed cross-epoch authority transition.
- [x] Implement archive/snapshot/peer source scoring and automatic failover. Source adapters, deterministic scoring, bounded runtime failover, and authenticated transport/storage callers are wired.
- [x] Create first-class `synergy-snapshot` build/sign/publish/verify/restore/retention subsystem. Production source and callers own finality-bound build, Aegis signing/verification, peer chunk serving, resumable acquisition, restore handoff, durable execution commit/receipt, finalized publication, and successor-epoch handoff. External object-store deployment is Phase 2 integration, not missing Phase 1 ownership.
- [ ] Integrate configured archive/object-store publication without hard-coded secrets.
- [~] Test dishonest heads, corrupt blocks/snapshots, interrupted restore, source loss, restart, and partition healing. Dishonest advertised height, wrong response anchor/range, and ineligible/conflicting support-source cases are covered; recovery and partition scenarios remain.

## Phase 9 — Proof-of-Synergy isolation, membership, persistence, recovery, and liveness

- [x] Audit frozen validator weight semantics.
- [x] Remove unsupported equal-numeric-weight guard.
- [x] Preserve approved non-uniform frozen PoSy weights where current specification requires them.
- [ ] Classify every legacy weight/power field by actual source/meaning before commitment migration.
- [x] Create first-class `synergy-posy` and wire the single proposal/vote/QC/TC/finality driver into the universal node; no foreign consensus model is imported.
- [x] Preserve explicit rules: stake is not PoSy authority; stake is unrelated to Synergy Score; Synergy Score does not determine finality. Canonical validator-management, PoSy, Sync, VPN, transport-registry, governance, and execution callers preserve these authority separations.
- [x] Implement deterministic PoSy engine, proposal, voting, quorum/certificates, finality, timeout/progress recovery exactly per authoritative spec. The final owner pipelines QC heights, applies three-QC finality, preserves strict count+frozen-weight quorum, advances takeover only from a verified TC, replays verified QC/TC state, and carries the verified two-QC boundary tail across a trust-root-signed epoch transition.
- [x] Implement validator Registered/Authorized/Synchronizing/Shadowing/Ready/ActivationScheduled/Active/Jailed/Removed/Expelled lifecycle. Admin and CLI mutations, durable persistence/reload, frozen-authority reconciliation, and governed future-epoch activation use the canonical validator-management owner.
- [~] Verify and implement 1,000-block shadow requirement if still authoritative; governed required-progress enforcement, atomic persistence, and bypass refusal exist, but the authoritative numeric requirement and runtime evidence caller remain.
- [x] Apply validator-set changes only at valid governed epoch boundaries. Finalized epoch-closure evidence, future registry assembly, trust-root-signed successor bindings, exact boundary-QC anchoring, durable transition persistence, and builtin service-graph reconstruction are wired.
- [x] Separate slashing/economic stake logic from PoSy authority. Canonical management and PoSy lifecycle callers keep penalties outside frozen voting weight/finality; remaining work is legacy-owner retirement.
- [~] Implement durable signing authority, safety journal, vote/proposal/certificate/finality/prepared-state persistence and explicit fsync boundaries. Verify-before-persist proposal/vote stores, contiguous finality records, prepared checkpoints, sign-once records, per-height QCs, and exact-slot TCs have canonical owners. Runtime proposal/vote/timeout signing uses durable sign-once authority; cross-process writer ownership and multi-record crash atomicity remain.
- [x] Disable signing until startup recovery proves safe state. Prepared checkpoints, authenticated peer reports, strict count+non-uniform-weight recovery quorum, rollback/conflict-safe reconciliation, verified QC/TC replay, durable-finality matching, and the runtime signing gate are wired.
- [ ] Test crash before/after persist/send/partial broadcast/certificate/final commit and prove no double-sign.
- [ ] Test proposer failure, dropped/delayed/reordered/duplicate votes, timeout recovery, certificate conflict, join/leave/jail/activation/epoch transition.

## Phase 10 — ETDAG first-class protected transaction subsystem

- [ ] Finish authority-field classification before changing versioned ETDAG commitments.
- [ ] Preserve approved non-stake PoSy authority commitments; remove only traced legacy PoS leakage.
- [x] Create `synergy-etdag` and `synergy-etdag-client`; authenticated runtime DAG, availability, order, reveal-certificate, exact-H+5, and execution handoff callers are wired.
- [x] Extract profile/parameters/domains/digests, provider-bound KEM/AEAD, canonical padding/nonce/key registry, exact-H+5 target admission, and check-before-mutation protected ingress.
- [x] Extract DAG vertices/identifiers/parents/dependencies/cycle checks/bounded traversal/certified cuts/deterministic ordering.
- [x] Extract availability and all certificate types with frozen quorum, canonical roots, deduplicated signers, and injected membership/signature verification.
- [x] Extract reveal authorization/decrypt shares/transcript/decryption with finality-bound authorization, threshold verification, and no plaintext persistence. Concrete PQ reconstruction remains provider-owned.
- [x] Extract deterministic execution handoff with exact protected order, aggregate reveal-transcript binding, bounded plaintext validation, and an execution-only adapter that cannot determine finality.
- [x] Extract ETDAG governance manifests, frozen exact-H+5 parameters, fee schedules, activation succession, KEM key activation, and explicit governance-authority verification.
- [x] Implement atomic safety/admission/protected-input/DAG/certificate/reveal persistence and bounded startup reconciliation/replay. Multi-record transactions, runtime callers, and crash testing remain later verification/integration work.
- [x] Extract authenticated ETDAG P2P transport adapter, bounded deduplicated gossip, and bounded retransmission; transport grants no authority or finality.
- [ ] Retire monolithic `runtime/src/etdag.rs` only after state/caller/test migration.
- [~] Preserve the ordinary-user ETDAG path and explicitly authorize any system/governance/internal bypass. The wallet request is being rebound to chain/network context, target context/height, sender wallet, nonce, algorithm, presented public key, and the complete encrypted-envelope commitment; client construction, Aegis provider wiring, RPC/transport admission, and negative/end-to-end evidence remain.
- [~] Add encryption, malformed input, replay, DAG dependency/cycle, deterministic order, availability, reveal, restart, delayed-input, resource exhaustion, and full e2e tests. Ten focused admission/order/persistence tests pass; crypto, availability, reveal, restart, exhaustion, and e2e coverage remain.

## Phase 11 — Transaction ingress, execution, block/state, SynQ, and AIVM

- [~] Create canonical transaction and ingress crates. The new transaction action, class authorization, nonce, validation, and receipt model is implemented; transaction ingress remains.
- [x] Route runtime ordinary-user transaction plaintext into execution only through a quorum-certified ETDAG protected-batch handoff.
- [x] Define explicit authorized system/governance/internal ingress. Protected/user ingress remains separate; system-class governance and supported system actions require canonical proposal/constitution commitments, frozen-authority Aegis votes, threshold/delay/activation checks, and deterministic state mutation. Unknown system actions fail closed.
- [x] Create deterministic execution engine with admission context, PQVM transaction verification, scheduling, governed Testnet-v3 fees, receipts, speculative candidates, rollback isolation, and finality-gated state commit. New-node callers persist candidates before PoSy publication and re-execute only frozen-authority-QC-bound candidates on restart.
- [x] Route every canonical transaction action through the execution dispatcher. `ExecutionService` wires concrete native, Aegis/PQSynQ+AIVM, dual-quorum SXCP+UMA, governance, and narrow governance-delegating system providers; unsupported operations fail closed at their owning boundary.
- [~] Create canonical block and state crates with deterministic roots/commitments/proofs. Canonical blocks bind ordered transactions and receipts, validate parent/network/height/timestamp continuity and proposer signatures, and use a bounded versioned codec. Finalized account state now persists with its root-checked commitment and reloads for execution restart; state proof and speculative-candidate recovery remain.
- [x] Integrate SynQ through the narrow deterministic adapter. Aegis verifies the PQSynQ account-domain authorization and exact artifact/input commitments; AIVM executes supported QVM bytecode with bounded gas and deterministic host behavior; deployment/call state changes flow through the canonical scheduler.
- [x] Integrate AIVM through a narrow sandbox/resource/determinism adapter. The concrete SynQ runtime executes bounded deterministic QVM bytecode; unsupported cryptographic/KEM opcodes fail closed pending an injected Aegis provider.
- [x] Prove by ownership that execution accepts only certified ETDAG order and commits only an exact PoSy finality record; execution exposes no finality action. PoSy validator votes are now withheld until the signed proposal matches a locally executed ETDAG candidate; early valid proposals are deferred to candidate arrival.
- [~] Add cross-node deterministic execution/state-root and rollback/restart tests. Focused forged-input, transition-failure, invalid-root, state-history, and interrupted-pointer retry tests pass; cross-node and restart integration remain.

## Phase 12 — Storage durability, integrity, pruning, and disk safety

- [~] Create first-class `synergy-storage`. Atomic bounded-file and WAL primitives compile and have focused tests; runtime stores and full keyspaces remain.
- [ ] Define keyspaces for blocks/state/consensus/ETDAG/peers/metadata.
- [~] Implement atomic writes, WAL/intent journaling where required, fsync durability, migrations, integrity checks, corruption handling. Atomic replacement, bounded reads, directory fsync, sequenced checksummed WAL replay, and truncated-record failure are tested; multi-file transactions and runtime schema/caller migration remain.
- [ ] Implement safe pruning/retention.
- [ ] Implement disk free-space guards and bounded evidence/log/cache/snapshot growth.
- [~] Add disk-full, partial-write, fsync failure, migration crash, corruption, and pruning tests. Oversize/traversal/truncated-WAL cases are covered; injected disk-full/fsync/migration/pruning scenarios remain.

## Phase 13 — SXCP, UMA, DA, governance, and role-specific services

- [x] Create first-class `synergy-sxcp`, `synergy-uma`, `synergy-data-availability`, `synergy-governance`, and validator-management libraries. Production callers now cover validator lifecycle/Admin, ETDAG custody/retention/serving, canonical UMA resolution, finalized SXCP relay intents, and governed execution/state mutation.
- [ ] Define `CrossChainCapability::{Relay, Verify, ...}` and supported-chain capabilities under one **Cross-Chain Node** role.
- [ ] Enforce relay/verification independence in SXCP acceptance and receipts.
- [x] Create common `synergy-ai` service contracts for the four canonical AI roles. Capability, job, policy, provider, compute, coordination, data, assurance, receipt, and metrics owners are populated.
- [x] Model inference/training/agent, routing/scheduling/federated coordination, model/dataset/vector data, and assurance/evaluation as capabilities/work types rather than additional node roles. The canonical enum remains exactly four AI roles.
- [ ] Implement external-chain adapters/proof/finality boundaries required by SXCP.
- [x] Implement UMA registry/mapping/coordinator/verifier and required BTC/ETH/SOL destination adapters; the SXCP execution caller applies its dual-quorum-covered mapping and resolves the exact destination through the canonical registry.
- [x] Implement DA store/shard/proof/serve/audit/retention. Durable custody stores the proof with the shard; authenticated ETDAG admission and bounded recovery responses enforce exact vertex/object/shard/proof bindings, governed Aegis verification, conflict safety, and finalized-height retention.
- [x] Implement node-side governance proposal/vote/authorization/activation/constitution/emergency validation. The node dispatcher verifies canonical roots, frozen-authority Aegis votes, constitutional threshold and delay, exact activation height and payload binding, then applies only the authorized deterministic protocol-state mutation.
- [ ] Add role-specific service tests and prove none can acquire PoSy signing authority without canonical validator membership.

## Phase 14 — Public RPC/WS, telemetry, health/readiness, stall diagnosis, and doctor

- [x] Create public `synergy-rpc` and `synergy-ws`; keep privileged Admin API separate. Crate source owners and bounded auth/rate-limit/server/method/subscription boundaries exist; runtime endpoint qualification remains.
- [ ] Implement rate/body/concurrency/time limits and auth for restricted methods.
- [x] Create `synergy-telemetry` with node/P2P/sync/PoSy/ETDAG/VPN/storage/resource metrics. Source owners and metric families exist; exporter/provider caller qualification remains.
- [ ] Publish Sentry public/VPN path, forwarding, queue, drop/filter, validator-link, and failover metrics.
- [ ] Publish Cross-Chain relay/verify/adapter/receipt/independence metrics.
- [ ] Publish AI role/capability/workload/GPU/data/receipt/assurance metrics.
- [x] Create shared `synergy-health` diagnostic engine used by CLI and Control Panel. Typed status/check/liveness/readiness/stall/dependency owners exist; remaining client cutover remains.
- [ ] Implement precise chain-stall reason classification rather than generic failure.
- [ ] Implement only safe automatic remediation; never auto-wipe/reset/sign/bypass finality.
- [ ] Create alerts/runbooks for no-finalization, peer collapse, sync lag, VPN outage, disk pressure, DB integrity, ETDAG backlog, protocol mismatch.

## Phase 15 — Canonical 20-Role Taxonomy, Capability Boundaries, and Role Completion

### Taxonomy migration

- [x] Replace canonical production-source role references to the old 19-role runtime and NORS-03 28-role taxonomy with the new 20-role taxonomy. Historical migration text is not an active role definition.
- [x] Remove **Committee** as a canonical `NodeRole`, role profile, onboarding option, Admin/CLI node type, and standalone operator role. Control Panel parity remains tracked separately.
- [ ] Trace any legitimate committee/quorum/rotation behavior in current PoSy and migrate it to dynamically assigned **Validator duties/capabilities** without changing authoritative PoSy semantics.
- [x] Rename the validator-perimeter **Relayer** role to **Sentry Node** in the canonical production-source taxonomy.
- [x] Introduce **Cross-Chain Node** as the single canonical SXCP interoperability role replacing separate Cross-Chain Relayer and Cross-Chain Verifier node roles in the production-source taxonomy.
- [ ] Preserve `relay` and `verify` as separate Cross-Chain capabilities and enforce that one operator/node cannot independently satisfy the verification requirement for its own relayed package in the same acceptance decision.
- [x] Rename **Archive Validator** → **Archive Node** in the canonical production-source taxonomy.
- [x] Rename **Audit Validator** → **Consensus Audit Node** in the canonical production-source taxonomy.
- [x] Rename **Analytics & Simulation** → **Network Analytics Node** in the canonical production-source taxonomy.
- [x] Rename **Indexer & Explorer** → **Indexer Node** in the canonical production-source taxonomy; Explorer remains an application consuming the Indexer.
- [x] Rename **Bootstrap Node** → **Bootseed Node** in the canonical production-source taxonomy.
- [x] Remove Governance Auditor, Treasury Controller, and Security Council from canonical `NodeRole`; their source ownership remains cross-cutting governance/security control-plane behavior.
- [x] Consolidate the 11 prior AI node roles into exactly four canonical roles: **AI Compute**, **AI Coordination**, **AI Data**, **AI Assurance**.
- [x] Preserve the prior AI jobs as capabilities/work types rather than canonical node identities. Reward/accounting caller integration remains part of role completion.
- [ ] Add a versioned role-taxonomy/config migration so legacy role names fail safely or map only where the mapping is unambiguous and approved.
- [ ] Update signed role/profile manifests, schemas, Admin API enums, CLI values, Control Panel options, metrics labels, telemetry, dashboards, tests, docs, deployment configuration, and reward/service eligibility code to use the new canonical names.

### Class I — Consensus & Chain Integrity

- [ ] **Validator Node** production-complete.
- [ ] **Sentry Node** production-complete.
- [ ] **Archive Node** production-complete.
- [ ] **Consensus Audit Node** production-complete.

### Class II — Interoperability

- [ ] **Cross-Chain Node** production-complete.
- [ ] **Witness Node** production-complete.
- [ ] **Oracle Node** production-complete.
- [ ] **UMA Coordinator Node** production-complete.

### Class III — Execution, Data & Cryptography

- [ ] **SynQ Execution Node** production-complete.
- [ ] **Network Analytics Node** production-complete.
- [ ] **Aegis Cryptography Node** production-complete.
- [ ] **Data Availability Node** production-complete.

### Class IV — AI & Intelligence

- [ ] **AI Compute Node** production-complete with capability flags for inference, embeddings, multimodal, training, fine-tuning, and bounded agent execution.
- [ ] **AI Coordination Node** production-complete with capability flags for routing, GPU scheduling/placement, quota/policy matching, capacity metering, and federated-learning coordination.
- [ ] **AI Data Node** production-complete with capability flags for model repository, dataset provenance, vector memory, retention, and deletion receipts.
- [ ] **AI Assurance Node** production-complete with capability flags for verification/replay, evaluation, safety testing, benchmarking, provider reputation, and latency/cost/quality scoring.

### Class V — Service & Access

- [ ] **RPC Gateway Node** production-complete.
- [ ] **Indexer Node** production-complete.
- [ ] **Observer / Light Node** production-complete.
- [ ] **Bootseed Node** production-complete.

### Cross-cutting role gates

- [ ] Every canonical role has a role profile, capability graph, required/forbidden service graph, key requirements, networking policy, storage policy, hardware/resource profile, health contract, readiness contract, telemetry, CLI/Admin visibility, Control Panel support, operator documentation, and tests.
- [ ] Sentry Nodes can be members of the validator transport overlay with a **Sentry scope** that never grants PoSy signing/finality authority.
- [ ] Validators can use multiple Sentry paths with automatic failover; Sentry loss must not create a one-to-one validator single point of failure.
- [ ] Sentry Nodes validate framing/network/genesis/protocol/identity and apply filtering/rate limits before forwarding, but Validators still independently verify all consensus-critical artifacts.
- [ ] Cross-Chain Node relay and verification capabilities remain independently attributable in receipts/evidence/rewards even though they share one canonical node role.
- [ ] AI capability advertisement controls workload eligibility; operators do not need separate node identities for each AI workload.
- [ ] Capability-isolation tests prove roles cannot access forbidden services or signing authority.
- [ ] Remove obsolete role files/tests/config values after compatibility migration is verified.

## Phase 16 — Native community packaging and operator documentation

- [ ] Native Linux headless install is first-class; Docker is not required.
- [ ] Create systemd hardening, Debian package, RPM/supported equivalent, signed tarball, install/upgrade/uninstall/release-verification tooling.
- [ ] Provide safe examples for Validator, Sentry, Archive, Cross-Chain, AI Compute, RPC Gateway, Indexer, Observer/Light, and other roles where specialized configuration is useful.
- [ ] Document CLI, Control Panel, every role, validator VPN, backup/restore/snapshots, monitoring, troubleshooting, upgrades, incident response, key custody, architecture, PoSy, ETDAG.
- [ ] Verify a fresh community operator does not need internal source-tree knowledge.

## Phase 17 — Test/simulation/fuzz/benchmark infrastructure

- [x] Management core/Admin IPC tests pass.
- [x] Control Panel Admin bridge/lifecycle semantic tests pass.
- [x] Current runtime cargo-check/test-compilation evidence exists for exercised paths.
- [x] Current `node-platform` workspace formatting and focused unit suite pass on `synergy-val4` (101 passed, 0 failed; source-only, not live-chain evidence).
- [ ] Complete unit/integration suites for all subsystems.
- [ ] Build deterministic virtual-clock/virtual-network multi-node simulator.
- [ ] Test 3/5/7 and larger practical validator clusters.
- [ ] Inject proposer failure, drops/delay/reorder/duplicates, latency/jitter/loss/bandwidth, partitions, crashes, disk/fsync failures, corruption, bootseed/VPN outages, validator lifecycle changes, ETDAG failures.
- [ ] Add fuzz targets for P2P, handshake, block/tx, PoSy, ETDAG, snapshot, network manifest.
- [ ] Add performance regression benchmarks without weakening correctness.

## Phase 18 — Upgrade and release security

- [ ] Implement signed release/checksum verification and compatibility windows.
- [ ] Implement governed protocol activation and pre-activation compatibility.
- [ ] Test mixed compatible/incompatible versions, activation boundary, DB/config migration, interrupted upgrade, supported rollback.
- [ ] Run rustfmt, Clippy, dependency/security, reproducible-build, and signed-artifact gates.
- [ ] Generate SBOM/dependency inventory if adopted.

## Phase 19 — Community validator zero-touch end-to-end acceptance

- [ ] Clean host installs signed node package.
- [ ] Initialize validator/network/identity and pass host/config/manifest/genesis/protocol checks.
- [ ] Verify canonical validator registration/authorization.
- [ ] Automatically complete VPN challenge-response, one-use enrollment, overlay connection, and signed transport lease.
- [ ] Automatically discover/authenticate peers and verified network head.
- [ ] Complete state/block/snapshot sync.
- [ ] Recover PoSy and ETDAG persistent state.
- [ ] Complete shadow/readiness; persist progress across restart.
- [ ] Activate only at valid PoSy epoch boundary.
- [ ] Participate in PoSy and finalize subsequent blocks.
- [ ] Process ETDAG protected transactions.
- [ ] Require no manual existing-validator VPN/config edit or restart.
- [ ] Prove both headless CLI and Control Panel can perform/observe the same workflow.

## Phase 20 — Multi-node stall prevention, recovery, and soak

- [ ] Run production-equivalent multi-validator network with sustained finalization and ETDAG load.
- [ ] Verify consistent finalized heights/state roots.
- [ ] Exercise repeated single/multiple validator restarts, proposer failure, message faults, bootseed loss, sync-source loss, VPN management outage, endpoint change, live validator join/shadow/activation, jail/remove, partitions/heal, snapshots, DB recovery, rolling upgrades.
- [ ] Exercise Sentry failover, Sentry loss, Sentry overload/filtering, and validator migration between healthy Sentry paths without exposing Validator public endpoints.
- [ ] Prove no double-signing, early ETDAG reveal, unauthorized VPN/validator enrollment, or unbounded disk growth.
- [ ] Run long-duration randomized-fault soak.
- [ ] Fail soak if chain stops without legitimate PoSy safety reason; every legitimate halt must surface precise diagnostics.
- [ ] Record duration, workload, faults, recovery times, failures, and final consistency.

## Phase 21 — Legacy retirement and final production evidence

- [ ] Retire/reduce `networking.rs`, monolithic ETDAG, scattered consensus ownership, duplicated CLI/GUI management logic, legacy stake-based onboarding semantics, static validator VPN mappings, and duplicate role binaries.
- [ ] Verify no ordinary-user path bypasses ETDAG.
- [ ] Verify no foreign/non-PoSy consensus remains active.
- [ ] Verify no stake-derived PoS authority, Synergy Score→finality, or VPN→validator authority path remains.
- [ ] Verify final workspace matches target tree or documents an explicitly approved equivalent boundary.
- [ ] Verify exactly 20 canonical `NodeRole` values are exposed after migration, with former granular AI roles represented only as capabilities/work types.
- [ ] Verify every authoritative node type is represented.
- [ ] Verify all release-gate tests actually executed; compile-only is not pass evidence.
- [ ] Verify full builds/tests/rustfmt/Clippy/security/native install/CLI parity/GUI parity/community onboarding/repeated finalization/recovery/ETDAG/activation/soak.
- [ ] Produce final implementation report and do not call production-ready until all required gates have evidence.

## Non-negotiable production invariants

- [ ] Proof-of-Synergy is the sole Synergy consensus/finality authority.
- [ ] PoSy is not Proof-of-Stake.
- [ ] Stake remains economic/security participation logic, not PoSy consensus authority.
- [ ] Approved non-uniform PoSy weights come only from authoritative PoSy semantics, never inferred from stake.
- [ ] Stake has nothing to do with Synergy Score.
- [ ] Synergy Score does not determine finality.
- [ ] VPN membership never grants validator authority.
- [ ] Sentry Nodes are transport-security perimeter nodes, never PoSy consensus participants merely because they share the validator overlay.
- [ ] Cross-Chain relay and verification are capabilities of one Cross-Chain Node role, with independent acceptance evidence where required.
- [ ] AI has exactly four canonical node roles—Compute, Coordination, Data, Assurance—while individual AI services remain capabilities/work types.
- [ ] Committee is not a canonical node role; any legitimate committee-like PoSy work is a Validator duty.
- [ ] Node/P2P/VPN/consensus identities are cryptographically verified and safely separated.
- [ ] Validator-set changes activate only at valid governed PoSy boundaries.
- [ ] Consensus signing is crash-safe and cannot double-sign under the required crash suite.
- [ ] ETDAG ordinary-user transactions cannot bypass protected ingress.
- [ ] ETDAG cannot reveal plaintext before authorized reveal.
- [ ] Sync never decides finality and never blindly trusts one peer's height.
- [ ] P2P never implements consensus decisions.
- [ ] CLI and GUI use one shared management implementation.
- [ ] Community validator onboarding requires no manual changes on existing validators.
- [ ] VPN management-plane and bootseed outages are not liveness dependencies for an established healthy validator mesh.
- [ ] Disk/log/evidence/cache/snapshot growth is bounded.
- [ ] Process-alive, VPN-connected, and P2P-connected are not equivalent to validator readiness/activation.
- [ ] Safety is never weakened simply to make a stalled chain appear live.


> **Canonical-root migration note (2026-09-11):** node-platform is the replacement implementation root. Target-path scaffolding is not completion: use SCAFFOLDED, MIGRATING, IMPLEMENTED, and VERIFIED in the implementation ledger. A checkbox remains unchecked until actual ownership, callers, and required evidence meet this checklist's existing rule.
