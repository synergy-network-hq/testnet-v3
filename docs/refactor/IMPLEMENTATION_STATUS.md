# Production node implementation status

> **Canonical repository ledger:** `docs/refactor/IMPLEMENTATION_STATUS.md` is
> the one canonical version. Every canonical clone contains this same tracked
> file. Update it in place and never create alternate, renamed, or divergent
> copies. An absolute checkout path never defines canonical file identity.

Updated: 2026-09-15. `COMPLETE` means the production responsibility is
implemented. It does not mean tested, integrated, network-verified, or release
qualified. Those states are intentionally tracked separately after migration.
The implementation phase remains incomplete while required production files,
callers, or legacy ownership remain open.

## Migration-phase governing state

Core Protocol root migration (2026-09-15): the canonical workspace was moved
in place on Val4 from `01-Core-Protocol/testnet-v3/node-platform/` to
`01-Core-Protocol/node-platform/`. The former Testnet-v3 repository is now
`01-Core-Protocol/networks/testnet-v3/`, Git ownership is rooted at
`01-Core-Protocol/`, and sibling `networks/`, `protocol/`, and `tooling/`
directories exist. There is one node-platform tree. Path-consumer repair,
network/protocol/tooling redistribution, generated-artifact cleanup, and Git
tracking reconciliation remain in progress.

Runtime completion sprint (2026-09-12): the universal service graph now connects governed Aegis Network -> verified Sync -> ETDAG H+5 certification -> deterministic Execution -> the single PoSy proposal/vote/QC/TC/finality owner. Source was formatted; build, tests, and live qualification remain Phase 2 and were not run in this sprint.

Current reconciliation (2026-09-15): the persistent production-source queue is
100% implemented. The latest direct Val4 source also wires the concrete
SynQ/PQSynQ/AIVM, SXCP/UMA, governance, and supported system-action execution
providers; trust-root-signed cross-epoch Sync handoff; and authenticated ETDAG
shard request/response serving with durable custody. This is source evidence,
not build, test, deployment, or production-readiness evidence. The canonical
completion checklist currently contains 125 complete, 30 partial, and 159 open
items, for **44.6% weighted overall completion** (`complete = 1`, `partial =
0.5`). The target file-tree ledger is **68.4% weighted complete** (984 complete,
66 partial, 436 open); it measures file-level ownership and must not be used as
a substitute for caller migration or legacy retirement.

Active correction wave (2026-09-15): the canonical PoSy simplification audit
now exists at `protocol/posy-v3/PO_SY_SIMPLIFICATION_AUDIT.md`. The public
validator Admin/CLI boundary is being migrated from the ambiguous
`validator_id`/`--validator-id` name to a validated canonical `NodeAddress` and
`--node-address`; internal PoSy `ValidatorId` values remain canonical
NodeAddress aliases, not a second identity. The ordinary-wallet ETDAG admission
wire contract is also being corrected to carry and sign chain/network context,
wallet address, nonce, algorithm, presented public key, and the complete
encrypted-envelope commitment. These newest edits are in progress and have not
yet passed a focused build/test gate, so they are not recorded as complete.


| Gate | Status | Current implementation boundary |
| --- | --- | --- |
| Canonical Core Protocol root | MOVED; RECONCILING | The only runtime tree is `/home/node/Synergy-Network/01-Core-Protocol/node-platform`; the Git root is `/home/node/Synergy-Network/01-Core-Protocol`. Network/protocol/tooling redistribution and path-consumer repair remain. |
| Canonical runtime | IMPLEMENTED (source), CALLERS MIGRATING | `node-platform/bin/synergy-node` loads canonical configuration and authority, registers the complete configured identity/storage/network/sync/Admin/ETDAG/execution/PoSy/RPC/WS/VPN/Sentry/telemetry/health graph, supervises it, and shuts it down in reverse order. Legacy runtime retirement remains separate. |
| Node Address terminology | PARTIAL; ACTIVE CUTOVER | The typed validator Admin operation and CLI are being changed to validated `NodeAddress`/`--node-address`; `--validator-id` is no longer the intended public node-identity option. Remaining production `NodeId`, ambiguous validator/peer fields, persistence, networking, telemetry, GUI, and legacy callers still require classification and migration. `NodeID` remains reserved for a human-readable `.node` alias. |
| Synergy Naming System NodeID | IMPLEMENTED, CALLERS MIGRATING | `synergy-naming` owns normalized `.node` aliases and no ownership state. The production native dispatcher applies register/rename to canonical `WorldState.protocol`, which becomes authoritative only through PoSy finality; Admin/CLI read finalized state or prepare the same wallet-signed action. GUI/RPC/WS/protected-submission and legacy callers remain. |
| Node owner wallet | IMPLEMENTED, CALLERS MIGRATING | `synergy-node-ownership` owns NodeAddress→wallet state. Production execution enforces transaction sender/public-key binding, detached Aegis node possession, and replacement-owner acceptance; Admin/CLI cannot establish ownership locally. Onboarding/GUI/protected-submission and legacy callers remain. |
| Reward withdrawal authorization | IMPLEMENTED, CALLERS MIGRATING | `synergy-rewards` owns NodeAddress-keyed accounting. Production execution authorizes withdrawal against canonical current ownership and commits only through PoSy finality; Admin/CLI inspect or prepare but do not mutate. Reward producers, GUI/protected-submission, audit, and legacy callers remain. |
| Exact CLI/GUI capability parity | PARTIAL | A shared typed Admin foundation exists, but the machine-readable registry and full CLI/Control Panel operation equality are incomplete. |
| Automatic signed updater | OPEN | Signed discovery/staging/verification/drain/restart/health/rollback/activation-aware ownership is not implemented. |
| PoSy simplification | PARTIAL | One new driver exists and the canonical audit now classifies retained mechanisms by safety/liveness/membership/recovery invariant and prohibits derived legacy complexity. The retained-mechanism dependency map, caller/state/wire proof, and evidence-backed removals remain. |
| Legacy artifact compatibility | NOT REQUIRED | Old Genesis, wire bytes, validator-set schema, persistence layout, configuration layout, and release layout are not migration blockers. Preserve semantics and security invariants only. |
| Existing validator deployment | DEFERRED | The failed old-network deployment is not the migration target and must remain untouched during software migration. |
| Build/test/debug/hardening | REQUIRED AFTER SOURCE MIGRATION | Run only after source/path/caller/legacy reconciliation, then record exact static, unit, integration, restart, upgrade, and acceptance evidence. |
| Network artifacts | RECONCILING | Move only existing governed network-specific artifacts under `networks/<network>`; do not fabricate mainnet/mainnet-beta values or alter live deployment state. |

| Launch class | Area | Status | Evidence / remaining boundary |
| --- | --- | --- | --- |
| POST-LAUNCH | Architecture inventory | COMPLETE | Current/target/migration/audit documents in `docs/refactor/`. |
| P0-LAUNCH | Common protocol/config types | IN PROGRESS | Shared node-core/Admin types and complete canonical config schema/validation exist; manifest, identity, and broader protocol callers remain. |
| P0-LAUNCH | Aegis cryptography engine and shared facade | IMPLEMENTED (source), CALLERS MIGRATING | `synergy-aegis` is the single engine/provider owner over required Aegis modules. `synergy-crypto` is protocol-neutral facade only and has no raw PQVM dependency. Network, ETDAG/DA, PoSy, SynQ/PQSynQ, SXCP, UMA, snapshot, and governance production paths now use the Aegis engine/provider boundary; remaining legacy hash and utility callers still require targeted retirement. |
| P0-LAUNCH | Canonical Synergy address engine | IMPLEMENTED, CALLERS_MIGRATED | `synergy-address` owns SNTS-01/Address Engine v1 derivation and Bech32m validation, and `synergy-transaction` delegates sender/receiver admission to that owner. Validator identity and transport route identifiers are governed identifiers, not Synergy payment addresses, and therefore are not address-engine caller gaps. Legacy address ownership still requires retirement. |
| P1-LAUNCH | Naming, node ownership, and rewards | IMPLEMENTED, CALLERS MIGRATING | The three owners run through the canonical native execution overlay and PoSy-finalized world-state commit. Shared Admin/CLI callers inspect finalized state or prepare exact wallet-signed actions without local mutation. Ten focused crate tests and a focused `synergy-node` check pass; protected submission, reward producers, GUI/RPC/WS, legacy retirement, and Phase 2 acceptance remain. |
| P0-LAUNCH | Genesis utility | IMPLEMENTED (source) | Canonical Chain 1266 network/validator/ETDAG/state/authority bindings, deterministic hashing, governed ML-DSA-65 signing, and PQVM verification are implemented; schemas, ceremony artifacts, and Phase 2 qualification remain. |
| P0-LAUNCH | Offline key lifecycle | IMPLEMENTED (source) | synergy-keytool generates non-overwriting ML-DSA-65 node/consensus and ML-KEM-768 ETDAG bundles with 0600 secret custody, validates public metadata, and emits rotation plans without changing membership authority; provider/recovery tests remain Phase 2. |
| P0-LAUNCH | Network manifest CLI | IMPLEMENTED (source) | Strict canonical Chain 1266 bindings, deterministic hashing, governed ML-DSA-65 signing/PQVM verification, safe inspection, and bounded diff tooling are implemented; full library/schema/runtime caller migration and Phase 2 artifacts remain. |
| P0-LAUNCH | Unified node core | IMPLEMENTED (runtime batch), CALLERS MIGRATING | `synergy-node-core` owns lifecycle/management types, dependency-ordered supervision, bounded restart, health/fail-closed inspection, cancellation, and reverse shutdown; `synergy-node` is a real caller. Legacy runtime retirement remains. |
| P0-LAUNCH | Supervisor/lifecycle | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Canonical dependency supervision, lifecycle/evidence transitions, complete configured service registration, retained run loop, and reverse shutdown are wired into `synergy-node`; remaining work is legacy caller retirement and Phase 2 qualification. |
| POST-LAUNCH | Governance library | IMPLEMENTED, CALLERS_MIGRATED | Constitutional rules, proposals, independently verified frozen-authority Aegis approvals, threshold authorization, delayed activation, exact payload/action binding, bounded emergency authority, and audit contracts are populated. The execution dispatcher now has a concrete governance provider and a narrow governance-delegating system provider; legacy retirement remains. |
| POST-LAUNCH | Data availability library | IMPLEMENTED, CALLERS_MIGRATED | Bounded Aegis-facade shard commitments, governed proof verification, serving, audit, and retention ownership are populated. The node ETDAG service now owns authenticated custody admission, finalized-height retention, authenticated bounded shard requests, durable lookup, signed response serving, receiver re-verification, and conflict-safe re-admission. Legacy ownership retirement remains. |
| POST-LAUNCH | AIVM sandbox | IMPLEMENTED, CALLERS_MIGRATED FOR SYNQ | Deterministic sandbox policy, resource budgets, bounded module/input validation, output commitments, runtime engine boundary, and metrics are populated. `CanonicalSynqRuntime` executes the supported deterministic QVM instruction set with bounded gas; unsupported cryptographic/KEM opcodes fail closed pending an injected Aegis provider. Other standalone AIVM role callers and Phase 2 qualification remain. |
| POST-LAUNCH | AI workload contracts | IMPLEMENTED (source) | Authority-neutral capability, job/policy/provider admission, bounded compute, deterministic coordination, data provenance, receipts, metrics, and independent assurance owners are populated; runtime providers and qualification remain. |
| POST-LAUNCH | Role/capability architecture | IMPLEMENTED (source), CALLERS MIGRATING | Typed role/capability/service-graph ownership exists and `synergy-node` validates its configured service declaration through `synergy-roles`; role-specific runtime providers and legacy caller retirement remain. |
| P1-LAUNCH | Admin API | IMPLEMENTED (read, validator lifecycle, node-state query/preparation), CALLERS MIGRATING | The owner-local dispatcher reads canonical finalized ownership/naming/reward state and prepares the exact native actions accepted by execution. It explicitly reports that it did not mutate state and requires wallet-signed protected ETDAG submission. Audit persistence, submission, remaining operation groups, and remaining clients are separate. |
| P0-LAUNCH | CLI | IN PROGRESS | First-class `synergy-node` exposes ownership inspect/claim/transfer preparation, naming resolve/reverse/availability/register/rename preparation, and reward account/withdrawal inspection/preparation through the shared Admin operation enum. Protected submission, broader mutation/audit, and remaining subsystem handlers remain. |
| POST-LAUNCH | Node Control Panel | IN PROGRESS | Uses the shared local Admin API for read operations; operation parity incomplete. |
| P0-LAUNCH | P2P transport | IMPLEMENTED (runtime batch) | Governed PQVM mutual handshake, exact sessions, authenticated frames, replay refusal, listener/dialer shutdown, bounded fair routing, and protocol egress are owned by the universal node. |
| P0-LAUNCH | Handshake | IMPLEMENTED (runtime batch) | Inbound/outbound challenge transcripts, chain identity, governed key bindings, PQVM signing/verification, peer admission, and exact session establishment are wired. |
| P0-LAUNCH | Peer lifecycle | SOURCE IMPLEMENTED | Exact-session manager, legal states, health, score, limits, quarantine/ban, duplicate resolution, persistence boundary, and bounded retry are implemented; runtime socket callers and jitter remain. |
| P0-LAUNCH | Discovery | SOURCE IMPLEMENTED | Prioritized bootseeds, DNS candidates, validated peer exchange, signed-registry boundary, and bounded expiring cache are implemented; resolver/runtime callers remain. |
| P0-LAUNCH | Message routing | SOURCE IMPLEMENTED | Bounded fair per-peer routing, watermarked backpressure, protocol handlers, and attempt/capacity-bounded retransmission are implemented; runtime dispatch callers remain. |
| P0-LAUNCH | VPN routing | IMPLEMENTED, CALLERS MIGRATING | Validator/Sentry route scopes, signed leases, exact peer binding, NetBird control/readiness, and metrics are implemented. The universal node verifies pinned signed registry state, observes NetBird, and schedules bounded authenticated dials; enrollment/lease publication and deployment bindings remain. |
| P0-LAUNCH | VPN enrollment | SOURCE IMPLEMENTED | Challenge/proof/eligibility/authorization/response/resume/revocation owners exist with redacted credential diagnostics; broker endpoint, zeroization, and runtime orchestration remain. |
| P0-LAUNCH | Transport registry | IMPLEMENTED, CALLERS MIGRATING | Signed verification, atomic cache, generation/equivocation/rollback control, leases, revocation, reconciliation, custody boundary, and registry state are implemented. Universal-node callers now pin trust, verify local snapshots, require active-authority coverage, persist accepted generations, and enforce signed routes during authentication; remote fetch, deployment bindings, and legacy retirement remain. |
| P0-LAUNCH | Block/head/state sync | IMPLEMENTED, CALLERS_MIGRATED | Authenticated verified heads select sources; sequential parent-anchored responses carry complete candidate transactions, receipts, and account state with bounded verified-source failover. PoSy verifies/replays the three-QC and required timeout evidence through its one driver, Execution recomputes the transition before finality-gated persistence, and a trust-root-signed successor authority binding is admitted only after the exact epoch-end three-QC witness and anchor are verified and durably committed. Legacy ownership retirement remains. |
| P0-LAUNCH | Snapshot sync | IMPLEMENTED, CALLERS_MIGRATED | Finality-bound manifest/chunk build and Aegis verification are wired through Sync; chunk requests/responses persist conflict-safely with resumable acquisition, verified restore handoff, execution snapshot commit/receipt, finalized publication, and successor-epoch graph reconstruction. Configured external object-store publication is still open; deployment qualification is Phase 2. |
| P0-LAUNCH | PoSy isolation | IMPLEMENTED (runtime batch), CALLERS_MIGRATED, LEGACY REMAINS | The new-platform `PosyService` owns governed authority binding, proposal/vote/QC/TC/three-QC-finality progression, authenticated ingress/egress, verified QC/TC persistence before broadcast, three-QC Sync witness verification, and execution-candidate handoff through one driver. A validator cannot vote until the signed proposal matches locally executed ETDAG material; early valid proposals wait for the candidate. Verified restart replay and successor-epoch two-QC-tail continuity are wired; legacy retirement remains. |
| P0-LAUNCH | PoSy persistence | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Proposal/vote/prepared/QC/TC/finality and durable sign-once ownership are wired into `PosyService`; exact-slot TCs and per-height QCs are independently reverified during startup. Cross-process writer ownership and multi-record crash atomicity remain. |
| P0-LAUNCH | PoSy recovery | IMPLEMENTED, CALLERS_MIGRATED | Checkpoint validation, authenticated peer reports, strict count+non-uniform-weight recovery quorum, fail-closed reconciliation, runtime signing-gate ownership, verified QC/TC replay, exact committed three-QC finality, and successor-epoch transition recovery are wired. Cross-process writer ownership, multi-record crash atomicity, legacy retirement, and Phase 2 qualification remain. |
| P0-LAUNCH | Validator membership/epochs | IMPLEMENTED, CALLERS_MIGRATED, LEGACY REMAINS | Admin and CLI lifecycle mutations, durable reload, activation/deactivation, jailing, expulsion, removal, slashing, frozen-authority reconciliation, future-epoch registry construction, and trust-root-signed epoch activation route through `synergy-validator-management`/PoSy authority ownership. The authoritative numeric shadow-duration requirement and legacy retirement remain separately open. |
| P0-LAUNCH | ETDAG extraction | IMPLEMENTED (runtime batch) | Authenticated validator messages, DAG/availability/order certificates, reveal/batch validation, current-finality H+5 context, and execution handoff are wired through the PQ authority owner. |
| P0-LAUNCH | ETDAG persistence | SOURCE IMPLEMENTED | Atomic admission, encrypted-input, DAG, certificate, sign-once safety, and no-plaintext reveal stores plus bounded reconciliation/replay are implemented; multi-record transactions, live callers, and crash verification remain. |
| P0-LAUNCH | Transaction/block/execution | IMPLEMENTED, CALLERS_MIGRATED | Certified ETDAG batches decode bounded signed transactions, verify them through the Aegis/PQVM boundary, route every supported action through concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, or supported system providers, produce receipts/state/block candidates, feed PoSy, and commit only matching finality. Candidates persist before PoSy publication and QC-bound candidates are re-executed on restart. Native external-chain proof adapters, ordinary-user transaction ingress, state proofs, cross-process safety, and legacy retirement remain. |
| P0-LAUNCH | Storage hardening | IN PROGRESS | Atomic bounded-file and integrity-bound WAL paths plus the configured critical `StorageService` caller exist; multi-file transactions, remaining safety-store cutover, injected fsync/disk failures, and pruning/migrations remain. |
| P1-LAUNCH | Telemetry | IMPLEMENTED (runtime batch), CALLERS MIGRATING | A configured supervised telemetry service and canonical subsystem metric owners exist; exporter/provider completeness and legacy caller retirement remain. |
| P0-LAUNCH | Readiness/health | IMPLEMENTED (runtime batch), CALLERS MIGRATING | Typed readiness evidence, supervised health observations, runtime snapshot publication, and role/service gates are wired; Phase 2 release criteria and legacy caller retirement remain. |
| P0-LAUNCH | Doctor diagnostics | IN PROGRESS | Typed diagnostic report exists; live network/storage diagnostics remain. |
| POST-LAUNCH | All supported node roles | NOT STARTED | Per-role completion remains. |
| POST-LAUNCH | Community validator onboarding | NOT STARTED | Required zero-touch acceptance scenario remains. |
| P0-LAUNCH | Crash/recovery tests | UNVERIFIED | Test-only stripped/non-incremental Cargo profile now permits focused runtime tests; crash/recovery suite has not yet executed. |
| P0-LAUNCH | Partition tests | NOT STARTED | Deterministic network simulation remains. |
| P1-LAUNCH | Upgrade tests | NOT STARTED | Mixed-version/upgrade coverage remains. |
| POST-LAUNCH | Soak tests | NOT STARTED | Multi-node stability validation remains. |

## EXPEDITED CRITICAL PATH

| # | Dependency | Status | Blocker | Next action | Tests | Dependent phases |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Common types/config/manifest/identity | CALLERS MIGRATING | Canonical config, manifest, identity, and protocol-type source owners exist; `synergy-node start` loads config and public identity. Broader subsystem callers and legacy aggregate retirement remain. | Migrate the remaining subsystem callers without reintroducing runtime-local types. | Phase 2. | 2–15 |
| 2 | Node supervisor/lifecycle | IMPLEMENTED (runtime batch) | The canonical supervisor and retained process loop register every configured production service and fail closed on incomplete coverage. | Retire legacy startup ownership only after caller migration is proven. | Phase 2 verification deferred. | 3–15 |
| 3 | P2P decomposition | IMPLEMENTED (runtime batch) | TCP listener/dialer, governed PQVM handshake/framing, exact sessions/replay refusal, peer admission, bounded routing, protocol adapters, and new-node `NetworkService` wiring exist. | Continue discovery/registry/VPN caller completion and retire legacy networking ownership only after proof. | Phase 2 verification deferred. | 4–15 |
| 4 | Sentry/VPN/transport registry | CALLERS MIGRATING | Source owners and conditional runtime registration exist. Pinned signed-registry verification/install, rollback-resistant cache, authority coverage, authenticated route admission, and bounded dial scheduling are wired; remote fetch, lease publication, enrollment broker, deployment bindings, and legacy retirement remain. | Connect enrollment/lease publication and deployment inputs without generating Phase 2 artifacts. | New caller verification deferred to Phase 2. | 5, 6, 14, 15 |
| 5 | Verified sync | IMPLEMENTED, CALLERS_MIGRATED | Authenticated heads, source selection, finality advertisement, bounded verified-source failover, sequential finalized candidate/state transport, snapshot chunk/resume, durable request recovery, and trust-root-signed epoch crossing are wired. PoSy verifies and replays QC/TC evidence; Execution validates commitments, re-executes transactions, persists candidates, and commits matching state. | Retire legacy Sync ownership; configured external archive/object-store integration is separate. | New caller verification deferred to Phase 2. | 6, 7, 14, 15 |
| 6 | PoSy isolation | IMPLEMENTED (runtime batch), CALLERS_MIGRATED, LEGACY REMAINS | Governed authority, authenticated transport, durable signing, proposal/vote/QC/TC/three-QC-finality, execution handoff, and verified successor-epoch reconstruction are wired through one `PosyService` driver. | Retire legacy ownership and close the remaining cross-process persistence boundaries. | Historical focused coverage exists; no current migration gate. | 7–15 |
| 7 | PoSy persistence/recovery | CALLERS MIGRATING | Canonical stores, sign-once authority, checkpoints, quorum reconciliation, verified QC/TC replay, exact durable-finality matching, and runtime signing gate are wired; cross-process writer ownership, speculative execution recovery, and multi-record crash atomicity remain. | Complete the remaining durable recovery callers before legacy retirement. | Phase 2 verification deferred. | 8, 14, 15 |
| 8 | Validator membership/epochs | IMPLEMENTED, CALLERS_MIGRATED, LEGACY REMAINS | Durable Admin/CLI lifecycle transitions, frozen-authority reconciliation, future-epoch registry assembly, and governed successor-epoch activation are wired. | Resolve the authoritative shadow-duration constant and retire legacy lifecycle ownership. | Phase 2 verification deferred. | 14, 15 |
| 9 | ETDAG extraction | IMPLEMENTED (runtime batch), CALLERS_MIGRATING | The production tree and supervised `EtdagService` own authenticated H+5 ingress, certification/order/reveal, execution handoff, governance, durable-store boundaries, recovery, metrics, durable shard custody, retention, and authenticated outbound shard serving. Ordinary-user client submission and legacy retirement remain. | Complete ordinary-user protected submission transport and retire the monolithic legacy owner. | Verification intentionally deferred for this bulk migration pass. | 10, 14, 15 |
| 10 | Transaction/execution/block/state | IMPLEMENTED, CALLERS_MIGRATED | Certified ETDAG batches decode and Aegis/PQVM-verify canonical transactions; every supported action routes through concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, or supported system providers. Candidates persist before PoSy publication, restart recovery re-executes only QC-bound candidates, and finalized account bytes precede their matching commitment. | Finish ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement. | New recovery/account-state/provider paths not tested. | 11, 14, 15 |
| 11 | Storage durability | IN PROGRESS | No runtime caller cutover or multi-record crash transaction. | Add injected failure coverage and migrate one safety journal at a time. | 5 focused storage tests pass. | 14, 15 |
| 12 | Admin API/CLI/Control Panel parity | IN PROGRESS | Mutating typed operations remain gated. | Expand shared safe operation model. | Read-path tests only. | 13–15 |
| 13 | Canonical role implementation | IN PROGRESS | Most profiles lack independent runtime completion. | Continue capability-based role migration after foundations. | Partial profile checks. | 14, 15 |
| 14 | Full integration/adversarial testing | PHASE 2 | Intentionally deferred until implementation coverage and caller migration are complete. | Do not execute during the migration phase. | Deferred. | 15 |
| 15 | New-network initialization and launch | PHASE 2 | New Genesis, validator set, manifests, transport state, release artifacts, and deployment configuration are intentionally not generated yet. | Build them from the completed architecture, then qualify and launch. | Deferred. | — |

## Phase 2 live deployment gate — intentionally deferred

The table below is retained as historical old-network operational context only.
It is not a blocker for the canonical `node-platform/` software migration and
must not drive compatibility work or mutation of the approved installation.

| Gate | Status | Deterministic material / action |
| --- | --- | --- |
| Transport snapshot | REQUIRED — BLOCKED | The external release-bound transport-attestation signer must publish a signed `synergy-testnet-v3-validator-transport-snapshot-v1` covering the authoritative active identities `validator-02` through `validator-06`, their canonical `synv` addresses, and provider-authorized `10.69.10.N:5622` routes. It must bind the provider-plan SHA-256 and configured release-bound public verification key. No static route fallback is permitted. |
| Snapshot inputs | READY | `scripts/generate-fresh-posy-v3-validator-vpn-provider.py` deterministically produces the public provider plan and offline proof from the canonical validator inputs and authority freeze; it deliberately does not sign or handle provider credentials. |
| Snapshot verification | READY at runtime; standalone current-schema CLI is NOT STARTED | `P2PNetwork::start` fetches, signature-verifies, binds, and coverage-checks the configured snapshot before opening production networking. On each validator, after the signer publishes the snapshot, run `set -a; . /etc/synergy/chain1266/validator-NN.env; set +a; "$CHAIN1266_ROLE_BINARY" preflight-release --config "$CHAIN1266_ROLE_CONFIG"`; then the approved service restart executes the transport verification fail-closed. The existing Python offline checker is legacy-schema and must not be substituted for this current runtime gate. |
| New binary | NOT REQUIRED for snapshot-only recovery | The deployed approved r11 binary already fetched a signed snapshot, bound its listener, and failed only at peer readiness because the live mapping was incomplete. A correct signed snapshot may therefore be consumed without replacing the binary. Current source router/registry changes require a new immutable binary only if they are to be deployed. |
| Release approval | NOT REQUIRED for snapshot-only recovery; REQUIRED for a replacement binary | A replacement package must be bound by the V4 Governance Authority approval over its exact Genesis, desired-state, binary, and configuration hashes. Do not self-approve or substitute a prior approval. |
| Post-approval deployment | BLOCKED on external signer/approval | After a valid snapshot is available and release preflight succeeds, the next approved existing-binary command is `sudo systemctl restart synergy-chain1266-role@validator-NN.service` on each governed host. Observe identity-complete authenticated peers and advancing finalized height before any further rollout. |


## Canonical node-platform transition - 2026-09-11

The legacy runtime tree is frozen as a behavioral reference only. New
production ownership is being implemented under `node-platform/`; scaffolded
files are not evidence of implemented behavior, and legacy artifact compatibility
is not required.

| Boundary | Launch class | New-platform status | Evidence | Legacy status |
| --- | --- | --- | --- | --- |
| Workspace root and target tree | POST-LAUNCH | SCAFFOLDED | 216 directories / 1,138 target files created without overwriting existing content | Runtime remains reference only |
| Shared protocol types | P0-LAUNCH | VERIFIED (foundation) | 4 unit tests pass; canonical 20-role taxonomy is authority-neutral | MIGRATING |
| Node core and Admin API | P0-LAUNCH | VERIFIED (foundation) | 5 unit tests pass; shared typed contract only | MIGRATING |
| Transport parser | P0-LAUNCH | VERIFIED (foundation) | 2 direct behavior-port tests pass | MIGRATING |
| Peer manager | P0-LAUNCH | VERIFIED (foundation) | 4 tests: exact-session cleanup, duplicate dials, quarantine/ban, stale detection | MIGRATING |
| Bounded router | P0-LAUNCH | VERIFIED (foundation) | 4 tests: total/per-peer bounds, fairness, exact cleanup, opaque protocol categories | MIGRATING |
| PoSy / ETDAG / Sync adapters | P0-LAUNCH | VERIFIED (boundary only) | 2 tests; adapters reject wrong route and cannot determine finality | MIGRATING |
| Handshake compatibility and dnsaddr candidate parsing | P0-LAUNCH | VERIFIED (foundation) | 3 tests: accepted algorithms, chain compatibility, TCP-only candidates | MIGRATING |
| VPN route policy and initial registry coverage | P0-LAUNCH | VERIFIED (foundation) | 4 tests: Validator/Sentry scopes, route validation, duplicate and active-set coverage | MIGRATING |
| Sentry perimeter policy and bounded forwarding | P0-LAUNCH | VERIFIED (foundation) | 3 tests: no-authority capability, allowed opaque forwarding, overload containment | MIGRATING |
| Signed provider snapshot verifier and overlay admission | P0-LAUNCH | VERIFIED (foundation) | 7 tests: Ed25519 signature, tampering, plan binding, rollback/equivocation, exact-route fail-closed handoff | MIGRATING |
| Verified sync | P0-LAUNCH | VERIFIED (foundation) | 4 tests: evidence-gated head selection, bounded failover, and no signing while behind | MIGRATING |

Historical verification before the strategy correction: 101 workspace tests
passed on synergy-val4. No further compile/test/validation gate is being run
during implementation migration. Testing, integration, and live validation are
separate Phase 2 states.

| Verified source selection and signing readiness | runtime sync and P2P source selection | node-platform/crates/synergy-sync | MIGRATING | 4 unit tests pass | Runtime synchronization callers | Only authenticated, compatible, evidence-backed sources may contribute; advertised height is never authoritative. |
| PoSy proposal/vote/QC/TC/finality and sign-once safety journal | runtime consensus safety state and simplified driver | node-platform/crates/synergy-posy | BEHAVIOR_MIGRATING | 8 focused tests pass; legacy runtime callers remain. | Runtime PoSy callers | One driver pipelines certified heights, applies three-QC finality, verifies strict independent validator-count and frozen-weight QC/TC quorum, retains lease takeover, and keeps stake/score/VPN/role outside authority. |
| ETDAG protected admission and deterministic ordering | runtime ETDAG pipeline | node-platform/crates/synergy-etdag | BEHAVIOR_MIGRATING | Final ownership is now split across admission, ingress, and persistence; legacy pipeline callers remain. | Runtime ETDAG callers | H+5 context-bound ciphertext ingress; names preserve frozen v3 commitments without interpreting them as stake. |
| Authorized deterministic execution input | runtime protected execution path | node-platform/crates/synergy-execution | MIGRATING | 3 unit tests pass | Runtime execution callers | Accepts only already-authorized, strictly ETDAG-ordered reveals; permits explicit empty input and cannot determine finality. |
| Atomic bounded-file persistence | Dispersed runtime file writes | node-platform/crates/synergy-storage | BEHAVIOR_MIGRATING | Final ownership is now database plus fsync; no runtime safety-journal cutover yet. | Runtime persistence callers | Atomic temp write, file fsync, rename, parent-directory fsync, bounded reads, and traversal rejection are executable. |
| Finalized state commit | Runtime state persistence | node-platform/crates/synergy-state | BEHAVIOR_MIGRATING | Final ownership is now state model plus transition store; runtime callers remain. | Runtime state callers | Persists only caller-supplied PoSy-verified finalization records, enforces contiguous history and idempotent replay, and cannot determine finality. |
| PoSy prepared/proposal/vote/certificate/finality recovery journal | Runtime PoSy persistence | node-platform/crates/synergy-posy | MIGRATING | 4 unit tests pass | Runtime PoSy callers | Shared atomic storage persists opaque validated safety records, survives restart, rejects conflicts and duplicate recovery slots; it does not calculate quorum or finality. |
| Failed durable PoSy write regression | Runtime safety journal semantics | node-platform/crates/synergy-posy | MIGRATING | Focused regression included in current 101-test workspace pass | Runtime PoSy callers | A failed atomic write leaves in-memory sign-once authorization unchanged, preventing false durable-state acknowledgement. |
| ETDAG durable admission recovery | Runtime ETDAG persistence | node-platform/crates/synergy-etdag | BEHAVIOR_MIGRATING | Final persistence owner is persistence/admission_store.rs; runtime callers remain. | Runtime ETDAG callers | Atomic storage restores only matching H+5 admission context, ciphertext envelopes, deterministic order, and closed state; mismatched context fails closed. |
| Deterministic execution transition sequencing | Runtime execution path | node-platform/crates/synergy-execution | MIGRATING | Focused transitions included in current 101-test workspace pass | Runtime execution callers | Applies only ETDAG-established authorized order through a state/VM adapter, returns state-root receipt, permits empty input, and cannot determine finality. |

## Implementation-first migration wave - 2026-09-11

| Component | Classification | Final owner now populated | Remaining migration |
| --- | --- | --- | --- |
| Role, snapshot, SXCP, UMA, and validator-management source owners | IMPLEMENTED; CALLERS_MIGRATING | synergy-roles, synergy-snapshot, synergy-sxcp, synergy-uma, synergy-validator-management | Snapshot, SXCP/UMA execution, and validator lifecycle callers are wired. Role-specific service providers, native external-chain proof adapters, and legacy retirement remain. |
| Storage columns/transactions and Sync/SynQ support owners | IMPLEMENTED; CALLERS_MIGRATING | synergy-storage, synergy-sync, synergy-synq | Verified Sync/snapshot/epoch and concrete SynQ execution callers are wired. Full storage keyspace/runtime schema migration, pruning, disk guards, and legacy retirement remain. |
| PoSy protocol support ownership batch | IMPLEMENTED (source), CALLERS MIGRATING | synergy-posy clustering verification, lifecycle scheduling, domains, metrics, durability/signing boundaries, proposal recovery, replay, and versioning | Source ownership exists without a second consensus driver; frozen-epoch authority remains immutable and legacy caller retirement remains. |
| PoSy proposal/vote/QC/TC/finality driver | BEHAVIOR_MIGRATING | synergy-posy/src/{engine,proposal,voting,quorum,finality,timeout} plus new-node single driver | Epoch-transition recovery, remaining live callers, and legacy retirement remain. |
| PoSy persistence and recovery | IMPLEMENTED, CALLERS_MIGRATED | synergy-posy/src/persistence and recovery canonical stores/checkpoints/reports/reconciliation plus new-node QC/TC and epoch-transition replay | Cross-process writer ownership, multi-record crash atomicity, and legacy retirement remain. |
| ETDAG production subsystem | IMPLEMENTED; CALLERS_MIGRATING | synergy-etdag crypto/admission/ingress/DAG/availability/ordering/certificates/reveal/execution/governance/persistence/network/recovery/metrics plus supervised EtdagService | Governed PQ providers, validator runtime, durable DA custody/retention, and authenticated artifact serving are wired. Ordinary-user protected submission transport, multi-record persistence consolidation, legacy retirement, and Phase 2 verification remain. |
| ETDAG protected client ingress | PARTIAL; SECURITY CORRECTION IN PROGRESS | synergy-etdag admission/ingress plus synergy-etdag-client/src/{target_context,ingress_keys,encrypt,padding,envelope,submit,receipt} | The server request is being changed from governed-validator sender IDs to a wallet-presented signed request bound to chain, network, target context/height, nonce, algorithm, public key, and encrypted envelope. Client construction, RPC/transport submission, final Aegis provider wiring, negative tests, and end-to-end finality evidence remain. |
| ETDAG protected look-ahead | FOUNDATION_VERIFIED | New-platform admission parameter/context now require governed H+5. | Legacy H+3 reference must be reconciled during its governed driver migration; no runtime behavior changed by this source-only boundary. |
| Atomic storage | BEHAVIOR_MIGRATING | synergy-storage/src/database.rs, fsync.rs | WAL, integrity, recovery, pruning, disk guard, and runtime callers remain. |
| Finalized state | BEHAVIOR_MIGRATING | synergy-state/src/state.rs, transition.rs plus new-node ExecutionService | Root-checked account bytes and QC-bound speculative candidates now reload for runtime execution; Sync state import, proofs, pruning, cross-process safety, and legacy caller cutover remain. |
| Deterministic execution | IMPLEMENTED; CALLERS_MIGRATED | synergy-execution/src/{context,executor,receipts,transition,dispatcher}.rs plus synergy-node ExecutionService | Runtime protected execution and concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, and supported system action providers are wired; ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement remain. |
| Canonical transaction and block | IMPLEMENTED; CALLERS_MIGRATED | synergy-transaction and synergy-block canonical action/nonce/receipt/block/codec/validation files plus Execution/PoSy/Sync callers | Canonical execution dispatch, state, SynQ/AIVM, PoSy proposal/import, Aegis verification, and universal-node callers are wired. Ordinary-user ingress, state proofs, and legacy retirement remain. |
| Canonical shared protocol types | IMPLEMENTED | synergy-protocol-types complete focused type set | Subsystem caller migration and legacy synergy_types retirement remain. |
| Independent version domains | IMPLEMENTED | synergy-version release/protocol/database/config compatibility and activation modules | Manifest/runtime callers remain. |
| Universal node start boundary | IMPLEMENTED (runtime batch), LEGACY REMAINS | synergy-node absolute-path config/authority load, complete required-service coverage gate, retained poll/shutdown loop, runtime snapshot, and all configured production services | Legacy startup ownership remains until caller migration and retirement are proven. |
| ETDAG verified reveal and persistence | SOURCE IMPLEMENTED | finality-bound reveal verification/decrypt plus atomic admission/encrypted-input/DAG/certificate/safety/reveal stores and bounded recovery | Concrete PQC reconstruction, runtime callers, multi-record transactions, and verification remain. |
| Canonical block execution | IMPLEMENTED, CALLERS_MIGRATED | execution validation/scheduler/fees/receipts/dispatcher plus `ExecutionService` ETDAG conversion, concrete native/SynQ/PQSynQ/AIVM/SXCP/UMA/governance/system action routing, block/state candidate, PoSy handoff, and finality-gated commit | Ordinary-user ingress, native external-chain proof adapters, state proofs, cross-process safety, and legacy retirement remain. |
| Node-facing Aegis policy/provider boundary | IMPLEMENTED, CALLERS_MIGRATED | synergy-aegis signer/verifier/custody/policy/attestation/lifecycle/audit plus PQVM/PQSynQ provider modules | Remaining established legacy hash/utility callers and legacy retirement remain; synergy-crypto remains a facade, not a second engine. |
| Canonical base runtime services | IMPLEMENTED (runtime batch), LEGACY REMAINS | synergy-node real identity/storage/network/sync/Admin/ETDAG/execution/PoSy/RPC/WS/VPN/Sentry/telemetry/health ManagedService adapters and retained supervised process | Legacy runtime remains the frozen semantic reference until explicit caller-retirement proof. |

Narrow cargo check completed after each moved crate group on synergy-val4.
Comprehensive test, simulation, and fleet verification are intentionally deferred
until behavior and callers are substantially migrated.

| Node core lifecycle/readiness/supervision | IMPLEMENTED (runtime batch) | synergy-node-core lifecycle, readiness, and supervisor modules plus complete `synergy-node` service registration/transition ownership | Legacy startup caller retirement remains. |
| Canonical configuration | IMPLEMENTED, CALLERS MIGRATING | synergy-config complete schema-v1 model, bounded loader, cross-field validation, and `synergy-node start` caller | Broader manifest/subsystem callers remain. |
| Canonical network handshake/framing | IMPLEMENTED (runtime batch) | synergy-network plus `NetworkService` governed Aegis/PQVM handshake, authenticated framing, exact sessions, replay refusal, listener/dialer, PeerManager, routing, and protocol adapters | Discovery/registry/VPN extensions and legacy retirement remain. |
| Canonical verified sync | IMPLEMENTED, CALLERS_MIGRATED | synergy-sync plus `SyncService` authenticated heads and sequential full-candidate transport; PoSy QC/TC replay; Execution commitment validation, deterministic re-execution, candidate persistence, finality-gated state commit, bounded failover, durable active-request resume, finality-bound snapshot transport/restore, and trust-root-signed cross-epoch authority transition with full builtin service-graph reconstruction | Legacy retirement and configured external archive/object-store integration remain. |
| Typed config / public identity / manifest composition | IMPLEMENTED, CALLERS MIGRATING | synergy-config/src/{node,role,validation}, synergy-identity/src/{public_identity,key_binding,synv}, synergy-manifest/src/{network_manifest,hash,verifier} | Canonical source owners and bounded validation are populated; full configuration domains, cryptographic proof verification, signatures, and runtime caller migration remain. |
| Verified sync head selection / readiness | IMPLEMENTED, CALLERS_MIGRATED | synergy-sync/src/head/{candidate,quorum_view,selection}.rs, wire.rs, and runtime Sync/PoSy/Execution callers | Finalized candidate/state transfer, bounded failover, durable request resume, manifest/state-root anchored snapshot transport/storage, verified restore handoff, durable execution commit/receipt, and exact trust-root-signed epoch transition are wired; Phase 2 verification and legacy retirement remain. |

## Historical scheduled migration work session - 2026-09-12 01:15 UTC

The counts and "does not start a node" statements in this dated section are
historical observations, not current migration state. The current state is the
governing table above: `synergy-node` now starts and supervises the configured
service graph, while caller migration and legacy retirement remain incomplete.

This run corrected the first broken boundary in the new PoSy owner: the state
machine previously waited for finality before advancing height, so QC(H1)
could never be followed by QC(H2). It now advances after every accepted QC,
retains lease takeover state across heights, and finalizes H only after the
consecutive QC(H), QC(H+1), QC(H+2) witness. Timeout votes and timeout
certificates now flow through the same driver instead of being ignored.

Production files (audited `node-platform/crates/synergy-posy` scope, 85 files):

- IMPLEMENTED: 37
- PARTIAL: 25
- PLACEHOLDER: 23
- DECLARATION_ONLY: 0

The broader `node-platform` filesystem inventory (excluding build `target/`)
currently contains 1,146 files: 298 are non-empty and 848 remain zero-byte.
This inventory includes planned tests/tools/configuration paths; its per-file
semantic audit is not complete, so non-empty files are not automatically
labeled implemented.

Responsibilities (canonical migration-map rows):

- BEHAVIOR_MIGRATING: 9
- BEHAVIOR_VERIFIED: 0
- CALLERS_MIGRATED: 0
- LEGACY_REMOVED: 0

Can `node-platform/bin/synergy-node` operate entirely without legacy production
runtime? **NO.** It is now a functional read-only local Admin API client, but
does not start a node or own runtime services. Remaining legacy dependencies
include runtime startup/lifecycle and mutating/subsystem CLI wiring, P2P socket
and protocol adapters, PoSy durable-state/live-driver callers, ETDAG, verified
sync transfer, execution/state integration, configuration/identity/manifest
consumers, RPC/WS, storage migration, and role implementations.

CURRENT SUBSYSTEM: PoSy engine / proposal / voting / quorum / finality / timeout

CURRENT FILES: `node-platform/crates/synergy-posy/src/{engine,proposal,voting,quorum,finality,timeout}`

LAST COMPLETED RESPONSIBILITY: One driver now accepts proposals, block votes,
QCs, timeout votes, and TCs; QC identity is proof-round/signer-subset
independent; strict count+frozen-weight quorum produces QCs/TCs; each QC
advances the certified height; a consecutive three-QC chain finalizes its
grandparent; timeout takeover persists within the governed leader lease.

CURRENT INCOMPLETE RESPONSIBILITY: Define the clean canonical PoSy protocol and
membership representations; persist typed proposal, vote, QC, TC, finality, and
prepared-state records; reconstruct the highest-parent, lock, takeover, and
three-QC tail before enabling signing after restart.

NEXT FILE / CALLER: Populate
`node-platform/crates/synergy-posy/src/persistence/{proposal_store,vote_store,certificate_store,finality_store,prepared_state}.rs`
and `recovery/{replay,prepared_state,reconciliation}.rs`, then connect the new
runtime driver adapter. Legacy bytes are not a prerequisite.

BLOCKER, IF ANY: No external blocker for source migration. Live validator/fleet
validation remains separately blocked by the missing identity-complete signed
transport snapshot and is not part of this source-only work session.

## Historical direct six-agent migration wave - 2026-09-12 04:26 UTC

This dated verification and caller state is historical; current source and
caller state is recorded in the governing tables above.

The recurring `Migrate Files` automation was deleted before this direct run so
it could not overlap edits. Six subagents were launched in two concurrency
waves with non-overlapping ownership; the configuration/identity foundation
agent exhausted the account usage window before making changes. The other five
agents and the coordinator completed these source-only boundaries:

- PoSy: frozen BLAKE3 domain framing/raw leader-seed handling, pre-mutation
  three-QC witness validation, and verified per-height QC persistence.
- ETDAG: frozen content-blind dependency ordering, order-seed derivation,
  duplicate/cycle refusal, and gas/byte prefix selection.
- Execution/state: decoded-input revalidation, rollback-safe cloned execution,
  immutable finalized per-height history, and conflict-safe pointer retry.
- Network/VPN/registry: exact canonical Validator/Sentry route shapes, signed
  snapshot/coverage/generation handling, and verified route admission.
- Sync: request-anchor/range enforcement, no partial importer advance, and
  bounded failover over a frozen verified support-source set.
- Storage: bounded reads remain bounded after open, WAL sequence/integrity
  replay fails closed on truncation, and first-file directory durability is
  explicit.

Verification on `synergy-val4`:

- `cargo fmt --check`: pass for the full `node-platform` workspace.
- `cargo test --workspace -- --test-threads=1`: 101 passed, 0 failed.
- Focused totals: PoSy 11, ETDAG 10, execution 6, state 4, storage 5,
  sync 8, network 17, transport registry 7, VPN 2.

No deployment or live-validator change was made. The universal node now owns
canonical execution and local management callers for ownership, naming, and
reward withdrawal, but protected ordinary-user transaction submission and
remaining legacy caller retirement are still open.

CURRENT SUBSYSTEM: Canonical NodeAddress terminology and ordinary-wallet protected ETDAG ingress

CURRENT FILES: `node-platform/crates/{synergy-admin-api,synergy-rpc,synergy-etdag,synergy-etdag-client}` and `node-platform/bin/synergy-node`

LAST COMPLETED RESPONSIBILITY: Canonical ownership, NodeID, and reward-withdrawal actions execute against the PoSy-finalized world-state path; the canonical PoSy simplification classification audit was added without changing consensus behavior.

CURRENT INCOMPLETE RESPONSIBILITY: Finish and validate the NodeAddress public-boundary rename, complete signed wallet admission construction and Aegis verification, and wire the request through the public RPC/transport path into ETDAG without bypassing protection.

NEXT FILE / CALLER: `node-platform/crates/synergy-etdag-client/src/{request,submit}.rs`, then the `synergy-rpc` submission method and universal-node ETDAG ingress owner.

BLOCKER, IF ANY: No source-edit blocker. The newest NodeAddress and ETDAG request edits are incomplete and unverified; live Chain 1266 state remains untouched.
