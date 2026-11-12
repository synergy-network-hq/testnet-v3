# Canonical migration continuation

Updated: 2026-09-19
Canonical repository: `/home/node/Synergy-Network/01-Core-Protocol`
Canonical implementation: `/home/node/Synergy-Network/01-Core-Protocol/node-platform`
Branch: `reconcile/core-protocol-root-2026-09-15`

CURRENT_PHASE: Phase 1 caller integration and non-runtime target completion; production source queue remains complete.
CURRENT_SUBSYSTEM: Signed updater caller boundary, Admin/control-plane parity, protected ETDAG public ingress, and remaining role/infrastructure callers.
CURRENT_FILE / CALLER: node-platform/bin/synergy-node/src/services/{admin,etdag,ingress}.rs; typed ETDAG ingress pause/resume controls are complete; exact-source artifact recovery remains fail closed.
LAST_COMPLETED RESPONSIBILITY: Wired typed CLI/Admin ETDAG ingress pause/resume through the canonical EtdagService with bounded synchronous receipts, retained finalized-height custody maintenance, explicit degraded/pending readiness, and no finality authority.
CURRENT_INCOMPLETE RESPONSIBILITY: Concrete updater apply/rollback lifecycle provider, automatic scheduler, and GUI; remaining Admin operation owners and Control Panel parity; protected RPC transaction submission; concrete public ETDAG wallet verifier/RPC transport and exact-source artifact recovery control; role-specific runtime completion, packaging, governed network artifacts, and Phase 2 acceptance evidence.
NEXT FILE / CALLER: Continue the highest-priority independently derivable PARTIAL caller, prioritizing durable peer-state reload/retry jitter or another safe canonical provider; do not fabricate VPN authorization, Sentry transport ownership, ETDAG wallet admission roots/source selection, or updater self-replacement.
BLOCKER, IF ANY: Public ETDAG wallet admission cannot be safely wired until governed target-context roots and the canonical wallet-address/public-key derivation contract are available. The historical 1,000-block shadow value also lacks authoritative specification. Do not fabricate either. Updater stage wiring is complete; apply/rollback still requires a supervised lifecycle provider that cannot safely be fabricated as an in-process self-replacement.

PRODUCTION_SOURCE_QUEUE_COMPLETE: YES
AEGIS_ENGINE_OWNERSHIP: `synergy-aegis` is the sole engine/provider owner; `synergy-crypto` is a protocol-neutral facade only.
REQUIRED_AEGIS_MODULES_PRESENT_ONCE: YES — canonical node-platform contains the required Aegis PQVM/PQSynQ sources with no second integration layer.
PQVM_INTEGRATED: YES
PQSYNQ_INTEGRATED: YES
SYNQ_CALLERS_MIGRATED: YES — ExecutionService constructs the canonical SynQ/PQSynQ/AIVM provider.
EXECUTION_DISPATCH_CALLERS_MIGRATED: YES — supported native, SynQ, SXCP/UMA, governance, and system actions route through concrete canonical providers.
SYNC_BLOCK_STATE_CALLERS_MIGRATED: YES — authenticated verified block/state transfer, deterministic replay, finality-gated persistence, and cross-epoch handoff are wired.
SNAPSHOT_CALLERS_MIGRATED: YES — manifest/chunk transport, resumable acquisition, Aegis verification, restore handoff, execution commit/receipt, and finalized publication are wired; external object-store publication remains a separate target item.
VALIDATOR_LIFECYCLE_CALLERS_MIGRATED: YES — Admin/CLI lifecycle mutations, persistence/reload, frozen-authority reconciliation, and epoch activation use `synergy-validator-management`.
UMA_CALLERS_MIGRATED: PARTIAL — execution/SXCP resolution uses canonical UMA; standalone relay/coordinator role callers and external adapters remain.
ADDRESS_ENGINE_MIGRATED: YES — canonical transaction address admission delegates to `synergy-address`; NodeAddress and transport IDs are separate governed identity domains.
TRANSPORT_REGISTRY_CALLERS_MIGRATED: PARTIAL — node VPN/session callers verify pinned signed snapshots and exact routes; remote fetch/enrollment/lease publication/deployment binding remain.
RPC_CALLERS_MIGRATED: PARTIAL — canonical finalized query provider is wired; protected transaction submission and restricted-method policy remain.
WS_CALLERS_MIGRATED: PARTIAL — canonical bounded subscriptions and finalized/runtime events are wired; parity/qualification remain.
ADMIN_CALLERS_MIGRATED: PARTIAL — reads, validator lifecycle, finalized ownership/naming/reward queries/preparation, config validation, storage verification, telemetry snapshot, governed signed-release staging, durable audit, supervised stop, exact-session peer lifecycle controls, canonical Sync controls, and ETDAG ingress pause/resume have handlers; start/restart/drain lifecycle plus VPN/Sentry/PoSy/ETDAG artifact recovery/update/cross-chain/AI handlers remain.
LEGACY_CALLERS_REMAINING: 0 direct production source/script references to the removed `networks/testnet-v3/runtime`, old runtime source paths, or old v20 binary. Historical documentation/evidence is non-authoritative.
SYNERGY_NODE_STANDALONE_SOURCE_COMPLETE: YES for the canonical Network/Sync/ETDAG/Execution/PoSy/RPC/WS/Admin service graph; broader target-role and interface parity remain incomplete.

VALIDATION_COMPLETED:
- `/home/node/.cargo/bin/cargo fmt --all -- --check`: PASS.
- `/home/node/.cargo/bin/cargo clippy --workspace --all-targets --locked -- -D warnings`: PASS on pinned Rust 1.97.
- Focused validation: 3 synergy-config tests and 4 synergy-node CLI parser tests passed.
- Focused peer-manager lifecycle test: PASS; focused synergy-network/synergy-node Clippy: PASS.
- Canonical Sync Admin control caller check and synergy-node Clippy: PASS; workspace formatting check: PASS.
- Canonical ETDAG Admin ingress control caller check and synergy-node Clippy: PASS; workspace formatting check: PASS.
- `git diff --check` for canonical ledgers and node-platform changes: PASS.
- Production source/script search for removed runtime/old binary references: zero matches.

CANONICAL_LEDGER_STATE:
- `NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md`: 129 complete, 35 partial, 153 open; 46.2% weighted.
- `NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md`: 1,256 complete, 182 partial, 62 open; 89.8% weighted.
- `NODE_PLATFORM_ACTUAL_FILE_TREE.md`: regenerated in place from canonical Val4 source, excluding reproducible `target/` output and Apple metadata.
- These counts track expanded target architecture, not only Phase 1 production source ownership.
