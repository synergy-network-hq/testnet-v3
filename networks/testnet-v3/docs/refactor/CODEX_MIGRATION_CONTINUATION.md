AEGIS_ENGINE_OWNERSHIP: synergy-aegis is the single cryptographic engine; synergy-crypto is facade only; consumer callers remain migrating
AEGIS_HASH_CALLERS_MIGRATED: PARTIAL - data-availability and snapshot source now use the Aegis engine through synergy-crypto while preserving protocol framing; established legacy hashes remain queued
DATA_AVAILABILITY_CALLERS_MIGRATED: PARTIAL - authenticated ETDAG shard-custody frames now verify governed Aegis proof, exact sender/key, chain/network and vertex/shard bindings, then commit to a conflict-safe durable filesystem store; finalized-height retention scheduling is wired, while outbound serving and legacy retirement remain
CURRENT_PHASE: Phase 1 runtime service graph batch complete; caller migration continuing
PRODUCTION_SOURCE_QUEUE_COMPLETE: YES - every queued source owner is IMPLEMENTED; caller migration and legacy retirement remain distinct
ROLE_CALLERS_MIGRATED: PARTIAL - synergy-node startup now validates its concrete service declaration through synergy-roles; legacy runtime role ownership remains
SYNC_SUPPORT_CALLERS_MIGRATED: PARTIAL - authenticated Sync heads now carry bounded three-QC witnesses verified only by PoSy against frozen authority; non-validator verified sources are eligible and stale sessions are pruned; block/state/snapshot transfer and restart replay remain
SYNQ_CALLERS_MIGRATED: PARTIAL - synergy-execution now provides a narrow injected SynQ VM/host/trace adapter; concrete VM and node dispatcher wiring remain
UMA_CALLERS_MIGRATED: PARTIAL - SXCP now resolves and chain-validates UMA destinations through the canonical UMA registry; runtime relay callers remain
VALIDATOR_LIFECYCLE_CALLERS_MIGRATED: YES - Admin, CLI validator mutations, durable persistence/reload, activation/deactivation, jailing, expulsion, removal, slashing, and frozen-authority reconciliation route through synergy-validator-management; legacy ownership retirement remains
POSY_SIGNING_CALLERS_MIGRATED: YES - runtime proposal/block-vote/timeout-vote signing passes through durable sign-once authority; verified QCs and exact-slot TCs persist before broadcast; verified QC/TC restart replay restores the one driver and requires exact durable-finality matching; speculative execution recovery, epoch transition, and legacy retirement remain
CURRENT_AEGIS_STATE: Governed key binding, PQVM handshake and frame verification/signing, exact authenticated sessions, replay refusal, and protocol routing are wired into NetworkService.
REQUIRED_AEGIS_MODULES_COPIED: aegis-pqvm (complete source, vendored primitives, archives, docs, artifacts), aegis-pqsynq (complete source); relevant build/VCS metadata excluded only
ADDRESS_ENGINE_MIGRATED: PARTIAL - synergy-transaction structural validation now delegates sender/receiver address validity to canonical synergy-address; identity/transport registries still use governed validator identifiers and remain queued
PQVM_INTEGRATED: YES
PQSYNQ_INTEGRATED: PARTIAL - full module is present; deterministic SynQ VM provider remains a later queue item
HANDSHAKE_VERIFIER_IMPLEMENTED: YES
HANDSHAKE_VERIFIER_WIRED: YES
FRAME_AUTH_IMPLEMENTED: YES
GOVERNED_KEY_BINDING_IMPLEMENTED: YES
NETWORK_SERVICE_COMPLETE: YES
SYNC_SERVICE_COMPLETE: YES
ETDAG_SERVICE_COMPLETE: YES
EXECUTION_SERVICE_COMPLETE: YES
POSY_SERVICE_COMPLETE: YES
CURRENT_SUBSYSTEM: Persistent Phase 1 production migration queue
CURRENT_FILE / CALLER: node-platform/bin/synergy-node/src/services/sync.rs and start.rs RPC/WS query-store wiring
LAST_COMPLETED RESPONSIBILITY: finality-bound snapshot publication, resumable chunk acquisition, verified restore handoff, durable snapshot commit/receipt, and canonical RPC/WS finalized query/event callers
CURRENT INCOMPLETE RESPONSIBILITY: concrete SynQ/SXCP/governance/system execution providers, Sync cross-epoch authority transition, ETDAG outbound artifact serving, and legacy ownership retirement
NEXT FILE / CALLER: node-platform/bin/synergy-node/src/services/execution.rs provider construction, then epoch transition in services/sync.rs
LEGACY_CALLERS_REMAINING: no direct runtime/ imports from node-platform production crates or synergy-node entrypoints; legacy runtime source remains frozen reference, while queue-owned utilities, secondary subsystem callers, and provider ownership retirement remain
SYNERGY_NODE_STANDALONE: SOURCE COMPLETE FOR NETWORK/SYNC/ETDAG/EXECUTION/POSY GRAPH; Phase 2 build/test/live qualification intentionally not run
SINGLE_SOURCE_RECONCILIATION: COMPLETE - canonical Val4 checkout retained; duplicate local staging/docs and noncanonical Val4-root migration documents reconciled and removed
UNIQUE_RECONCILIATION_RECOVERY: synergy-execution canonical transaction action router recovered from staged work; caller wiring remains distinct
TRANSPORT_REGISTRY_CALLERS_MIGRATED: PARTIAL - VpnService verifies pinned signed snapshots, checks active authority coverage, persists accepted generation, and schedules bounded authenticated outbound dials; authenticated inbound route admission is wired; deployment bindings and live qualification remain.
WORKSPACE_MEMBERSHIP_MIGRATED: YES - every canonical node-platform crate, including synergy-etdag-client, snapshot, SXCP, UMA, validator-management, version, RPC, WS, roles, is now registered in the production workspace.
ETDAG_CLIENT_SOURCE_MIGRATED: YES - client modules were relocated from the crate root into the canonical src/ tree; duplicate root copies were removed, and Cargo now resolves the complete protected-ingress API.
GOVERNANCE_ACTIVATION_CALLERS_MIGRATED: PARTIAL - GovernanceIngress now validates proposal/authorization identity and nonzero activation points through synergy-governance::GovernedActivation; full operation dispatch, persistence, and legacy caller retirement remain.
EXECUTION_DISPATCH_CALLERS_MIGRATED: PARTIAL - ExecutionService routes every TransactionAction through CanonicalTransactionDispatcher; native provider is concrete while SynQ, SXCP, governance, and system providers remain fail-closed pending canonical engine contracts.
SYNC_BLOCK_STATE_CALLERS_MIGRATED: PARTIAL - authenticated peers exchange one parent-anchored complete execution candidate at a time with three-QC/timeout evidence, deterministic replay, durable request resume, and finality-gated commit; snapshot chunk transport, verified restore handoff, and durable snapshot commit are wired, while cross-epoch authority transition and legacy retirement remain.

SNAPSHOT_CHUNK_CALLERS_MIGRATED: PARTIAL - Sync carries finality-bound manifest/state-root chunk requests/responses with conflict-safe persistence, resumable active acquisition, Aegis manifest/chunk verification, execution restore handoff, durable snapshot commit/receipt, and finalized publication; cross-epoch authority transition and external source serving remain.
SNAPSHOT_CALLERS_MIGRATED: PARTIAL - finality-bound snapshot transport, durable resume, Aegis verification, restore handoff, and execution commit/receipt are wired; cross-epoch authority transition and external source serving remain

RPC_CALLERS_MIGRATED: PARTIAL - canonical finalized block/transaction/account query provider is wired into the RPC dispatcher and shared listener; remaining legacy callers and Phase 2 qualification remain
WS_CALLERS_MIGRATED: PARTIAL - shared WebSocket listener, bounded subscriptions, runtime/finalized block/transaction/finality event publication are wired; remaining legacy callers and Phase 2 qualification remain
ADMIN_CALLERS_MIGRATED: PARTIAL - typed read operations and validator lifecycle mutations use canonical Admin/provider ownership; broader operation groups and legacy retirement remain
SYNERGY_NODE_STANDALONE_SOURCE_COMPLETE: YES - canonical service graph, query provider, snapshot restore, and lifecycle callers have production source; build/test/live qualification intentionally deferred
BLOCKER, IF ANY: Canonical concrete SynQ VM/AIVM, SXCP relay, governance operation, and system-action contracts are not present in the repository; providers remain fail-closed rather than fabricated

CORE_PROTOCOL_ROOT_MIGRATION: IN_PROGRESS
PRE_MOVE_REPOSITORY_ROOT: /home/node/Synergy-Network/01-Core-Protocol/testnet-v3
PRE_MOVE_BRANCH: codex/node-reorganization-remote
PRE_MOVE_HEAD: 4aa6ae8
PRE_MOVE_NODE_PLATFORM_STATE: untracked canonical workspace; 605 MiB; 27,175 files; 1,255 directories
PRE_MOVE_DESTINATION: /home/node/Synergy-Network/01-Core-Protocol/node-platform (verified absent)
PRE_MOVE_GENERATED_RESIDUE: node-platform/target plus AppleDouble and one Cargo.toml.workspace.bak retained for later evidence-gated cleanup
PRE_MOVE_PATH_REFERENCE_RESULT: no active source/script hard-coded testnet-v3/node-platform path outside generated inventory/history material
NEXT_FILE / CALLER: perform the authorized single-source Core Protocol root move, then repair repository/path ownership
