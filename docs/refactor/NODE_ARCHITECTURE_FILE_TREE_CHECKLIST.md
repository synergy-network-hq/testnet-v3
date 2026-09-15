# Synergy Node Architecture — Complete Target File Tree Checklist (Canonical 20-Role Taxonomy)

> **Canonical repository ledger:**
> `docs/refactor/NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md` is the one canonical
> version. Every canonical clone contains this same tracked file. Update it in
> place and never create alternate, renamed, or divergent copies. An absolute
> checkout path never defines canonical file identity.

> This is the **full target-state tree**, not merely a list of files Codex has already touched. It restores the first-class crates, services, role definitions, network artifacts, schemas, packaging, tests, simulation, fuzzing, benchmarks, operator documentation, and Node Control Panel integration required by the production architecture.

**Implementation status:** `[x]` assigned production responsibility implemented;
`[~]` real implementation exists but required behavior remains incomplete; `[ ]`
absent or mostly scaffold. Test status is tracked separately in Phase 2.


> **Historical-name note:** Old names such as `Committee`, `Archive Validator`, `Audit Validator`, generic `Relayer`, `Cross-Chain Verifier`, `Analytics & Simulation`, `Indexer & Explorer`, `Bootstrap`, and the 11 former AI roles may appear only in migration/history text explaining what must be removed or mapped. They are **not** valid target `NodeRole` values.

**Critical rule:** existence alone never earns `[x]`, but lack of Phase 2 testing
does not prevent `[x]` once the file's real responsibility is implemented. A
checked file does not by itself make the whole subsystem production-ready.

**Current reconciliation (2026-09-15):** 984 of 1,486 file-tree entries are
complete, 66 are partial, and 436 are open. Using `complete = 1`, `partial =
0.5`, and `open = 0`, file-level weighted completion is **68.4%**. The
persistent production-source queue is 100% implemented, but this broader target
tree also includes role-specific runtimes, Control Panel surfaces, tests,
simulation, fuzzing, benchmarks, packaging, deployment assets, and other later
target-state files. File completion is not caller migration, legacy retirement,
or production-readiness evidence. The 2026-09-15 target-root and new subsystem
entries below are included in this denominator.

## Target tree with descriptions

### [~] `01-Core-Protocol/`

**Folder purpose:** Canonical repository root. The universal node implementation
is a sibling of network artifacts, normative protocol definitions, and tooling.

```text
[x] AGENTS.md                                        # Root single-source, safety, and canonical-path governance.
[~] node-platform/                                   # Sole universal Synergy node implementation; physically moved, migration still incomplete.
[~] networks/                                        # Governed network-specific artifacts only; redistribution is in progress.
[~] networks/devnet/                                 # Devnet manifest/Genesis/bootseed/version/role/ETDAG artifacts; values still require reconciliation.
[~] networks/testnet-v3/                             # Testnet-v3 artifacts plus temporary frozen migration reference material; non-network ownership must move out.
[~] networks/mainnet-beta/                           # Mainnet Beta ownership root; unauthorized artifacts must remain absent.
[~] networks/mainnet/                                # Mainnet ownership root; unauthorized artifacts must remain absent.
[~] protocol/                                        # Normative specifications and schemas; directory exists but ownership migration remains.
[~] tooling/                                         # Operator/developer/release/Genesis/DB/key tooling; directory exists but ownership migration remains.
```

Required network artifact shape, instantiated only where governed values exist:

```text
[ ] networks/<network>/network-manifest.json         # Signed governed network identity and trust roots.
[ ] networks/<network>/genesis.json                  # Governed network Genesis; never fabricate Mainnet values.
[ ] networks/<network>/bootseeds.json                # Authenticated network-specific discovery seeds.
[ ] networks/<network>/protocol-versions.json        # Independently governed protocol component versions.
[ ] networks/<network>/roles.json                    # Network-specific enabled role/capability policy.
[ ] networks/<network>/etdag/parameters.json         # Governed ETDAG parameters, including exact H+5 semantics.
[ ] networks/<network>/etdag/fee-schedule.json       # Governed ETDAG fee schedule.
[ ] networks/<network>/etdag/ingress-key-registry.json # Governed ETDAG ingress KEM registry.
[ ] networks/<network>/etdag/activation.json         # Governed deterministic ETDAG activation boundary.
```


### [~] `docs/refactor/`

**Folder purpose:** Live migration audits, status ledgers, and current→target ownership records.

```text
[x] CURRENT_ARCHITECTURE.md                          # Documentation for CURRENT ARCHITECTURE.
[x] TARGET_ARCHITECTURE.md                           # Documentation for TARGET ARCHITECTURE.
[x] MIGRATION_MAP.md                                 # Documentation for MIGRATION MAP.
[x] CONSENSUS_AUDIT.md                               # Documentation for CONSENSUS AUDIT.
[x] ETDAG_AUDIT.md                                   # Encrypted Transaction DAG protected transaction behavior.
[x] P2P_AUDIT.md                                     # Documentation for P2P AUDIT.
[x] VPN_AUDIT.md                                     # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[x] NODE_CONTROL_API.md                              # Documentation for NODE CONTROL API.
[x] IMPLEMENTATION_STATUS.md                         # Documentation for IMPLEMENTATION STATUS.
[x] GENESIS_CHANGE_AUDIT.md                          # Documentation for GENESIS CHANGE AUDIT.
[x] NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md        # Documentation for NODE ARCHITECTURE COMPLETION CHECKLIST.
[x] NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md         # Documentation for NODE ARCHITECTURE FILE TREE CHECKLIST.
[x] NODE_PLATFORM_ACTUAL_FILE_TREE.md                # Actual annotated on-disk tree generated directly from the canonical Val4 node-platform directory.
```

### [x] `protocol/architecture/`

**Folder purpose:** Stable post-migration architecture and trust-boundary documentation.

```text
[x] OVERVIEW.md                                      # Documentation for OVERVIEW.
[x] NODE_LIFECYCLE.md                                # Documentation for NODE LIFECYCLE.
[x] SERVICE_SUPERVISION.md                           # Documentation for SERVICE SUPERVISION.
[x] SERVICE_BOUNDARIES.md                            # Documentation for SERVICE BOUNDARIES.
[x] ROLE_ARCHITECTURE.md                             # Declarative node role, capability, service, port, and readiness policy.
[x] NETWORKING.md                                    # Documentation for NETWORKING.
[x] P2P.md                                           # Documentation for P2P.
[x] SYNC.md                                          # Verified head/block/state/snapshot synchronization and recovery.
[x] STORAGE.md                                       # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] EXECUTION.md                                     # Deterministic transaction/state execution; no finality decisions.
[x] VPN.md                                           # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[x] NODE_CONTROL_PLANE.md                            # Documentation for NODE CONTROL PLANE.
[x] KEY_MANAGEMENT.md                                # Cryptographic key registry/custody/rotation behavior.
[x] SECURITY_BOUNDARIES.md                           # Documentation for SECURITY BOUNDARIES.
[x] SNAPSHOT_ARCHITECTURE.md                         # Finality-bound snapshot build/verify/restore/publication behavior.
[x] UPGRADE_MODEL.md                                 # Signed software/protocol upgrade and compatibility workflow.
```

### [x] `protocol/specifications/`

**Folder purpose:** Normative Synergy protocol documentation and invariants.

```text
[x] PROOF_OF_SYNERGY.md                              # Documentation for PROOF OF SYNERGY.
[x] POSY_INVARIANTS.md                               # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] POSY_MESSAGE_PROTOCOL.md                         # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] POSY_MEMBERSHIP.md                               # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] POSY_RECOVERY.md                                 # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] ETDAG.md                                         # Encrypted Transaction DAG protected transaction behavior.
[x] ETDAG_CRYPTOGRAPHY.md                            # Encrypted Transaction DAG protected transaction behavior.
[x] ETDAG_ADMISSION.md                               # Encrypted Transaction DAG protected transaction behavior.
[x] ETDAG_DAG_ORDERING.md                            # Encrypted Transaction DAG protected transaction behavior.
[x] ETDAG_REVEAL.md                                  # Encrypted Transaction DAG protected transaction behavior.
[x] ETDAG_EXECUTION.md                               # Encrypted Transaction DAG protected transaction behavior.
[x] SXCP.md                                          # SXCP cross-chain proof/relay/finality behavior.
[x] UMA.md                                           # Universal Meta-Address registry/mapping/coordinator behavior.
[x] AEGIS.md                                         # Aegis PQ cryptography integration and policy.
[x] NETWORK_MANIFEST.md                              # Signed/canonical manifest artifact handling and verification.
```

### [x] `protocol/posy-v3/`

**Folder purpose:** Canonical PoSy v3 architecture audits and governed simplification evidence outside the Rust implementation.

```text
[x] PO_SY_SIMPLIFICATION_AUDIT.md                    # Invariant/failure-based retained-mechanism classification and prohibited-derived-complexity freeze; dependency-map application remains a separate checklist item.
```

### [x] `tooling/docs/operators/`

**Folder purpose:** Headless and GUI operating procedures for every node role.

```text
[x] INSTALL.md                                       # Documentation for INSTALL.
[x] QUICKSTART.md                                    # Documentation for QUICKSTART.
[x] CLI_REFERENCE.md                                 # Documentation for CLI REFERENCE.
[x] CONTROL_PANEL.md                                 # Documentation for CONTROL PANEL.
[x] VALIDATOR.md                                     # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] COMMUNITY_VALIDATOR.md                           # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] VALIDATOR_VPN.md                                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] SENTRY_NODE.md                                   # Operating guide for the hardened public-P2P ↔ validator-VPN Sentry perimeter, forwarding ACLs, redundancy, failover, and diagnostics.
[x] ARCHIVE_NODE.md                                  # Operating guide for long-term chain history, proofs, snapshots, archival storage, retrieval, and recovery support.
[x] CONSENSUS_AUDIT_NODE.md                          # Operating guide for independent PoSy/finality/state audit, divergence detection, equivocation evidence, and non-signing assurance.
[x] CROSS_CHAIN_NODE.md                              # Operating guide for SXCP relay/verify capabilities, external-chain adapters, receipts, finality proofs, and independence rules.
[x] WITNESS.md                                       # Documentation for WITNESS.
[x] ORACLE.md                                        # Documentation for ORACLE.
[x] UMA_COORDINATOR.md                               # Universal Meta-Address registry/mapping/coordinator behavior.
[x] SYNQ_EXECUTION.md                                # Deterministic transaction/state execution; no finality decisions.
[x] NETWORK_ANALYTICS_NODE.md                        # Operating guide for network simulation, anomaly detection, performance/risk analysis, and advisory analytics.
[x] AEGIS_CRYPTOGRAPHY.md                            # Aegis PQ cryptography integration and policy.
[x] DATA_AVAILABILITY.md                             # Documentation for DATA AVAILABILITY.
[x] AI_COMPUTE_NODE.md                                # Operating guide for AI Compute capabilities, GPU classes, receipts, sandboxing, and workload isolation.
[x] AI_COORDINATION_NODE.md                           # Operating guide for AI routing, scheduling, quotas, capacity, and federated coordination.
[x] AI_DATA_NODE.md                                   # Operating guide for model artifacts, dataset provenance, vector memory, tenant isolation, and receipts.
[x] AI_ASSURANCE_NODE.md                              # Operating guide for independent AI verification, evaluation, reputation, reproducibility, and safety testing.
[x] RPC_GATEWAY.md                                   # Documentation for RPC GATEWAY.
[x] INDEXER_NODE.md                                  # Operating guide for finalized-data indexing, query/search APIs, token/NFT/event indexes, and Explorer backend support.
[x] OBSERVER_LIGHT.md                                # Documentation for OBSERVER LIGHT.
[x] BOOTSEED.md                                      # Operating guide for authenticated initial peer discovery, bootseed availability, peer exchange, and non-authoritative bootstrap service.
[x] UPGRADES.md                                      # Signed software/protocol upgrade and compatibility workflow.
[x] BACKUP_RESTORE.md                                # Documentation for BACKUP RESTORE.
[x] SNAPSHOTS.md                                     # Finality-bound snapshot build/verify/restore/publication behavior.
[x] MONITORING.md                                    # Documentation for MONITORING.
[x] TROUBLESHOOTING.md                               # Documentation for TROUBLESHOOTING.
[x] INCIDENT_RESPONSE.md                             # Documentation for INCIDENT RESPONSE.
```

### [x] `tooling/docs/development/`

**Folder purpose:** Developer build, test, simulation, fuzz, and release procedures.

```text
[x] BUILD.md                                         # Documentation for BUILD.
[x] TESTING.md                                       # Automated verification of the owning subsystem or failure mode.
[x] CONSENSUS_TESTING.md                             # Automated verification of the owning subsystem or failure mode.
[x] ETDAG_TESTING.md                                 # Encrypted Transaction DAG protected transaction behavior.
[x] NETWORK_SIMULATION.md                            # Documentation for NETWORK SIMULATION.
[x] FUZZING.md                                       # Malformed/untrusted input fuzz target.
[x] BENCHMARKING.md                                  # Performance measurement/regression target.
[x] RELEASES.md                                      # Release build/sign/verify/publication metadata or tooling.
[x] CONTRIBUTING_PROTOCOL_CHANGES.md                 # Documentation for CONTRIBUTING PROTOCOL CHANGES.
```

### [x] `node-platform/bin/synergy-node/`

**Folder purpose:** Primary universal node executable and complete headless CLI; all operations use the shared management contract.

**Current migration state:** The universal package now retains the supervised process and wires the canonical authenticated Network, verified Sync, ETDAG, deterministic Execution, and single-owner PoSy services through one bounded runtime pipeline. Phase 2 compile/test/live qualification remains separate.

```text
[x] Cargo.toml                                       # First-class runtime package with canonical Admin/core/config dependencies.
[x] src/main.rs                                      # Dispatches start and Admin commands and retains the supervised node process.
[x] src/cli.rs                                       # Strict start/config and management/socket option separation with fail-closed parsing.
[x] src/admin_client.rs                              # Narrow local Unix Admin API client; no duplicate management decisions.
[x] src/services/mod.rs                              # Concrete runtime service-adapter registry.
[x] src/services/storage.rs                          # Real canonical storage adapter with schema verification and live health.
[x] src/services/authority.rs                        # Pinned Aegis/PQVM verification of frozen PoSy/ETDAG authority plus trust-root-signed, three-QC-bound epoch transition custody.
[x] src/services/ingress.rs                          # Bounded authenticated queues, exact-session admission, signed-overlay installation, and verified Sync candidate handoffs.
[x] src/services/network_session.rs                  # Mutual PQVM handshake, signed identity/IP route admission, authenticated frames, session/replay binding, and shutdown.
[x] src/services/network.rs                          # Governed listener/dialer, peer admission, bounded routing, signed-overlay enforcement, and protocol egress.
[x] src/services/vpn.rs                              # Pinned signed-registry verification/cache, authority coverage, NetBird readiness, and bounded authenticated dial scheduling.
[x] src/services/sync.rs                             # Authenticated verified-head selection, durable sequential finalized candidate/state requests, bounded failover, finality-bound manifest/chunk transport with resumable restore handoff, and response routing.
[x] src/services/etdag.rs                            # Authenticated DAG/availability/order/reveal-certificate verification, durable shard custody with finalized-height retention, and H+5 handoff.
[x] src/services/execution.rs                        # ETDAG dispatch, concrete native ownership/naming/reward, SynQ/SXCP/governance/system providers, sender-key binding, durable candidates, QC-bound restart, and finality-gated state commit.
[x] src/services/posy.rs                             # Frozen authority, sign-once signer, QC/TC custody/replay, execution-gated votes, and single-driver Sync safety-witness replay.
[x] src/commands/mod.rs                              # Canonical start command registration.
[x] src/commands/init.rs                             # Rust implementation for init within this subsystem.
[x] src/commands/start.rs                            # Canonical config, verified authority, complete service graph, lifecycle, retained run loop, and fail-closed reverse shutdown.
[x] src/commands/stop.rs                             # Rust implementation for stop within this subsystem.
[x] src/commands/restart.rs                          # Rust implementation for restart within this subsystem.
[x] src/commands/status.rs                           # Rust implementation for status within this subsystem.
[x] src/commands/health.rs                           # Subsystem/node health state and diagnostics.
[x] src/commands/readiness.rs                        # Role-aware readiness evaluation; process-alive is not sufficient.
[x] src/commands/doctor.rs                           # Comprehensive structured diagnostic checks and safe remediation metadata.
[x] src/commands/join.rs                             # Rust implementation for join within this subsystem.
[x] src/commands/leave.rs                            # Rust implementation for leave within this subsystem.
[x] src/commands/identity.rs                         # Canonical node identity, possession proofs, and key bindings.
[x] src/commands/keys.rs                             # Cryptographic key registry/custody/rotation behavior.
[x] src/commands/peers.rs                            # Authenticated peer discovery/lifecycle/state/routing behavior.
[x] src/commands/sync.rs                             # Verified head/block/state/snapshot synchronization and recovery.
[x] src/commands/snapshot.rs                         # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/commands/config.rs                           # Typed configuration, validation, defaults, and migration.
[x] src/commands/manifest.rs                         # Signed/canonical manifest artifact handling and verification.
[x] src/commands/node_state.rs                       # Shared ownership, naming, and reward finalized-state queries plus wallet-transaction preparation; never mutates local caches.
[x] src/commands/role.rs                             # Declarative node role, capability, service, port, and readiness policy.
[x] src/commands/validator.rs                         # Validator onboarding/shadow/activation/jailing/status operations.
[x] src/commands/sentry.rs                            # Sentry public/VPN path, forwarding, peer, ACL, redundancy, and diagnostics operations.
[x] src/commands/cross_chain.rs                       # Cross-Chain relay/verify capability, adapter, receipt, and queue operations.
[x] src/commands/ai.rs                                # AI role capability/workload/resource/receipt/status operations.                        # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/commands/vpn.rs                              # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[x] src/commands/posy.rs                             # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/commands/etdag.rs                            # Encrypted Transaction DAG protected transaction behavior.
[x] src/commands/database.rs                         # Database inspection/open/repair/migration behavior.
[x] src/commands/telemetry.rs                        # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/commands/upgrade.rs                          # Signed software/protocol upgrade and compatibility workflow.
[x] src/commands/version.rs                          # Software/protocol/storage/config compatibility and activation.
[x] src/output/mod.rs                                # Module registration and exports.
[x] src/output/human.rs                              # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/output/json.rs                               # Rust implementation for json within this subsystem.
```

### [x] `node-platform/bin/synergy-keytool/`

**Folder purpose:** Offline/controlled node, consensus, Aegis, and ETDAG key lifecycle utility.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/main.rs                                      # Cryptographic key registry/custody/rotation behavior.
[x] src/node_identity.rs                             # Canonical node identity, possession proofs, and key bindings.
[x] src/consensus_keys.rs                            # Cryptographic key registry/custody/rotation behavior.
[x] src/aegis_keys.rs                                # Cryptographic key registry/custody/rotation behavior.
[x] src/etdag_keys.rs                                # Encrypted Transaction DAG protected transaction behavior.
[x] src/rotation.rs                                  # Cryptographic key registry/custody/rotation behavior.
[x] src/inspect.rs                                   # Cryptographic key registry/custody/rotation behavior.
```

### [x] `node-platform/bin/synergy-genesis/`

**Folder purpose:** Deterministic genesis build, ceremony, binding, signing, and verification utility.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/main.rs                                      # Rust implementation for main within this subsystem.
[x] src/builder.rs                                   # Rust implementation for builder within this subsystem.
[x] src/validator_set.rs                             # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/etdag.rs                                     # Encrypted Transaction DAG protected transaction behavior.
[x] src/network.rs                                   # Rust implementation for network within this subsystem.
[x] src/verify.rs                                    # Rust implementation for verify within this subsystem.
[x] src/signing.rs                                   # Rust implementation for signing within this subsystem.
```

### [x] `node-platform/bin/synergy-manifest/`

**Folder purpose:** Signed network/protocol/release manifest build, sign, verify, inspect, and diff utility.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/main.rs                                      # Signed/canonical manifest artifact handling and verification.
[x] src/build.rs                                     # Signed/canonical manifest artifact handling and verification.
[x] src/sign.rs                                      # Signed/canonical manifest artifact handling and verification.
[x] src/verify.rs                                    # Signed/canonical manifest artifact handling and verification.
[x] src/inspect.rs                                   # Signed/canonical manifest artifact handling and verification.
[x] src/diff.rs                                      # Signed/canonical manifest artifact handling and verification.
```

### [x] `node-platform/bin/synergy-db/`

**Folder purpose:** Offline database integrity, migration, repair, and export utility.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/main.rs                                      # Rust implementation for main within this subsystem.
[x] src/inspect.rs                                   # Rust implementation for inspect within this subsystem.
[x] src/verify.rs                                    # Rust implementation for verify within this subsystem.
[x] src/repair.rs                                    # Rust implementation for repair within this subsystem.
[x] src/migrate.rs                                   # Rust implementation for migrate within this subsystem.
[x] src/export.rs                                    # Rust implementation for export within this subsystem.
```

### [~] `node-platform/crates/synergy-node-core/`

**Folder purpose:** First-class `synergy-node-core` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/node.rs                                      # Read-only management operation taxonomy and schema ownership.
[x] src/context.rs                                   # Management schema version boundary.
[x] src/supervisor/mod.rs                            # Canonical service-supervisor API and exports.
[x] src/supervisor/supervisor.rs                     # Dependency-ordered startup, bounded restart, health/fail-closed inspection, and reverse shutdown.
[x] src/supervisor/service.rs                        # Typed heterogeneous service boundary, state, health, criticality, and specification.
[x] src/supervisor/dependency_graph.rs               # Unknown-dependency and cycle-refusing deterministic startup graph.
[x] src/supervisor/restart_policy.rs                 # Bounded never/on-failure/always restart policy.
[x] src/supervisor/cancellation.rs                   # Cloneable thread-safe one-way cancellation signal.
[x] src/supervisor/shutdown.rs                       # Exact stopped/failed reverse-order shutdown report.
[x] src/lifecycle/mod.rs                             # Canonical lifecycle evidence/state exports.
[x] src/lifecycle/state.rs                           # Transition controller refuses initialization, readiness, and drain bypasses.
[x] src/lifecycle/startup.rs                         # Validated immutable role/service startup plan.
[x] src/lifecycle/preflight.rs                       # Blocking diagnostic aggregation before service startup.
[x] src/lifecycle/bootstrap.rs                       # Config/identity/storage/network bootstrap readiness boundary.
[x] src/lifecycle/synchronized.rs                    # Finality-evidence-bound synchronization readiness; advertised height is insufficient.
[x] src/lifecycle/ready.rs                           # Required-service and preflight/bootstrap/sync readiness evidence.
[x] src/lifecycle/degraded.rs                        # Typed service/sync/storage/network/authority degradation conditions.
[x] src/lifecycle/draining.rs                        # Bounded graceful drain plan before reverse dependency shutdown.
[x] src/lifecycle/shutdown.rs                        # Final drain and service-shutdown outcome.
[x] src/readiness/mod.rs                             # Canonical role-aware readiness evidence exports.
[x] src/readiness/gate.rs                            # Lifecycle plus fail/unknown check aggregation; process-alive is insufficient.
[x] src/readiness/checks.rs                          # Typed pass/warn/fail/unknown diagnostics and remediation metadata.
[x] src/readiness/consensus.rs                       # Membership/recovery/key/H+5 signing gate; role alone grants no authority.
[x] src/readiness/networking.rs                      # Listener/router and authenticated-compatible-peer requirement.
[x] src/readiness/storage.rs                         # Open/integrity/writable/free-space durable storage gate.
[x] src/readiness/sync.rs                            # Verified-finality target gate; advertised height is insufficient.
[x] src/readiness/vpn.rs                             # Role-scoped identity-route/lease gate that grants no validator authority.
[x] src/readiness/etdag.rs                           # Governed parameters/keys/recovery/proposal-material gate without finality authority.
[x] src/error.rs                                     # Typed supervisor/service lifecycle error ownership.
```

### [x] `node-platform/crates/synergy-roles/`

**Folder purpose:** First-class `synergy-roles` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Declarative node role, capability, service, port, and readiness policy.
[x] src/role.rs                                      # Declarative node role, capability, service, port, and readiness policy.
[x] src/profile.rs                                   # Declarative node role, capability, service, port, and readiness policy.
[x] src/capability.rs                                # Declarative node role, capability, service, port, and readiness policy.
[x] src/authority_plane.rs                           # Declarative node role, capability, service, port, and readiness policy.
[x] src/service_graph.rs                             # Declarative node role, capability, service, port, and readiness policy.
[x] src/ports.rs                                     # Declarative node role, capability, service, port, and readiness policy.
[x] src/validation.rs                                # Declarative node role, capability, service, port, and readiness policy.
[x] src/registry.rs                                  # Declarative node role, capability, service, port, and readiness policy.
```

### [x] `node-platform/crates/synergy-config/`

**Folder purpose:** First-class `synergy-config` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Canonical new-config package and dependency boundary.
[x] src/lib.rs                                       # Strict schema-v1 configuration API; no legacy adapters.
[x] src/node.rs                                      # Complete typed universal node configuration.
[x] src/network.rs                                   # Typed listener/advertisement/timeout network configuration.
[x] src/p2p.rs                                       # Bounded authenticated-peer/frame/gossip configuration.
[x] src/consensus.rs                                 # Disabled/observe/vote mode, explicit authority binding, and provisioned consensus-key path.
[x] src/etdag.rs                                     # Governed H+5 protected-transaction configuration.
[x] src/storage.rs                                   # Durable storage/WAL/pruning configuration.
[x] src/rpc.rs                                       # Bounded optional RPC service configuration.
[x] src/telemetry.rs                                 # Structured logging and bounded trace configuration.
[x] src/role.rs                                      # Role-aware service selection without authority grant.
[x] src/vpn.rs                                       # Disabled/preferred/required role-scoped VPN configuration.
[x] src/validation.rs                                # Strict borrowed cross-field and authority-boundary validation.
[x] src/loader.rs                                    # Bounded 1 MiB strict JSON loader with typed errors.
```

### [x] `node-platform/crates/synergy-manifest/`

**Folder purpose:** First-class `synergy-manifest` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Signed/canonical manifest artifact handling and verification.
[x] src/network_manifest.rs                          # Signed/canonical manifest artifact handling and verification.
[x] src/chain_identity.rs                            # Canonical chain/network identity binding owner.
[x] src/genesis_binding.rs                           # Canonical Genesis binding owner.
[x] src/protocol_versions.rs                         # Independent governed protocol-version bindings.
[x] src/consensus_binding.rs                         # Canonical PoSy parameter/authority manifest binding.
[x] src/etdag_binding.rs                             # Canonical ETDAG parameter/root manifest binding.
[x] src/transport_binding.rs                         # Transport-only route/registry manifest binding; no consensus authority.
[x] src/role_binding.rs                              # Canonical role/capability manifest binding.
[x] src/release_binding.rs                           # Canonical release identity binding.
[x] src/signature.rs                                 # Governed manifest signature verification boundary.
[x] src/verifier.rs                                  # Signed/canonical manifest artifact handling and verification.
[x] src/hash.rs                                      # Signed/canonical manifest artifact handling and verification.
```

### [~] `node-platform/crates/synergy-identity/`

**Folder purpose:** First-class `synergy-identity` subsystem boundary in the production node workspace. Node/address validation, Aegis possession proof, duplicate protection, governed rotation, and storage contracts have source owners; remaining callers are not migrated.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Canonical node identity, possession proofs, and key bindings.
[~] src/node_id.rs                                   # Transitional canonical-address type; migrate to NodeAddress and reserve NodeID for `.node` aliases.
[x] src/synv.rs                                      # Canonical node identity, possession proofs, and key bindings.
[x] src/public_identity.rs                           # Canonical node identity, possession proofs, and key bindings.
[x] src/proof_of_possession.rs                       # Canonical node identity, possession proofs, and key bindings.
[x] src/key_binding.rs                               # Canonical node identity, possession proofs, and key bindings.
[x] src/rotation.rs                                  # Canonical node identity, possession proofs, and key bindings.
[x] src/duplicate_guard.rs                           # Canonical node identity, possession proofs, and key bindings.
[x] src/store.rs                                     # Canonical node identity, possession proofs, and key bindings.
```

### [x] `node-platform/crates/synergy-naming/`

**Folder purpose:** First-class Synergy Naming System owner for human-readable
`<name>.node` aliases. Finalized network state is authoritative, the local
snapshot is cache-only, and authorization queries the independent canonical
NodeAddress-to-wallet ownership registry.

```text
[x] Cargo.toml                                       # Rust package and independent ownership dependency boundary.
[x] src/lib.rs                                       # Public finalized naming API and identity/ownership separation invariants.
[x] src/nodeid.rs                                    # Normalized `<name>.node` value type.
[x] src/normalization.rs                             # Canonical case/character/length normalization.
[x] src/availability.rs                              # Duplicate-safe finalized-name availability checks.
[x] src/registration.rs                              # Owner-authorized transitions applied only from finalized batches.
[x] src/resolution.rs                                # Finalized NodeID to NodeAddress resolution.
[x] src/reverse_resolution.rs                        # Finalized NodeAddress to current NodeID lookup.
[x] src/authorization.rs                             # Current-owner wallet proof boundary; no ownership state in naming records.
[x] src/store.rs                                     # Monotonic rebuildable cache of finalized forward/reverse naming state.
```

### [x] `node-platform/crates/synergy-node-ownership/`

**Folder purpose:** Durable cryptographic binding from canonical Node Address to
owner Synergy Wallet without wallet-private-key custody.

```text
[x] Cargo.toml                                       # Rust package and dependency boundary.
[x] src/lib.rs                                       # Public finalized ownership API and naming-independent invariants.
[x] src/binding.rs                                   # Versioned NodeAddress-to-wallet ownership record and resolver.
[x] src/challenge.rs                                 # Domain-bound claim and transfer signing payloads.
[x] src/authorization.rs                             # Aegis-provider wallet and node-possession verification boundary.
[x] src/transfer.rs                                  # Current-owner-authorized, replacement-owner-accepted finalized transfer.
[x] src/store.rs                                     # Conflict-safe history plus rebuildable finalized ownership cache.
```

### [x] `node-platform/crates/synergy-rewards/`

**Folder purpose:** Reward attribution and owner-wallet-only withdrawal
authorization boundary without inventing economic formulas.

```text
[x] Cargo.toml                                       # Rust package and independent ownership dependency boundary.
[x] src/lib.rs                                       # Public finalized reward accounting API and invariants.
[x] src/account.rs                                   # Reward account keyed only by NodeAddress.
[x] src/ledger.rs                                    # Finalized earned/pending/available/settled/cancelled transitions.
[x] src/withdrawal.rs                                # Versioned owner-authorized withdrawal request/state machine.
[x] src/authorization.rs                             # Current canonical owner-wallet signature requirement.
[x] src/store.rs                                     # Conflict-safe reward history plus rebuildable finalized cache.
```

### [ ] `node-platform/crates/synergy-updater/`

**Folder purpose:** Signed automatic software update lifecycle kept independent
from governed protocol activation.

```text
[ ] Cargo.toml                                       # Rust package and dependency boundary.
[ ] src/lib.rs                                       # Public updater API and lifecycle invariants.
[ ] src/metadata.rs                                  # Signed bounded release metadata.
[ ] src/channel.rs                                   # Release-channel selection.
[ ] src/policy.rs                                    # Operator-configurable update policy.
[ ] src/discovery.rs                                 # Bounded release discovery.
[ ] src/staging.rs                                   # Atomic staged download ownership.
[ ] src/verification.rs                              # Aegis signature/integrity verification.
[ ] src/compatibility.rs                             # Software/protocol/schema compatibility gate.
[ ] src/preflight.rs                                 # Disk/custody/readiness preflight.
[ ] src/drain.rs                                     # Controlled service drain coordination.
[ ] src/install.rs                                   # Atomic install handoff without protocol activation.
[ ] src/health.rs                                    # Post-restart health/readiness evaluation.
[ ] src/rollback.rs                                  # Bounded rollback when the staged release cannot start safely.
[ ] src/activation.rs                                # Awareness of separately governed protocol activation.
[ ] src/audit.rs                                     # Secret-free update telemetry and durable audit events.
```

### [x] `node-platform/crates/synergy-crypto/`

**Folder purpose:** Shared protocol-neutral API/facade over the single Aegis Cryptography Engine; it owns no independent cryptographic engine.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/hash.rs                                      # Rust implementation for hash within this subsystem.
[x] src/domain.rs                                    # Rust implementation for domain within this subsystem.
[x] src/random.rs                                    # Rust implementation for random within this subsystem.
[x] src/constant_time.rs                             # Rust implementation for constant time within this subsystem.
[x] src/encoding.rs                                  # Rust implementation for encoding within this subsystem.
[x] src/signatures/mod.rs                            # Module registration and exports.
[x] src/signatures/ml_dsa.rs                         # Rust implementation for ml dsa within this subsystem.
[x] src/signatures/fn_dsa.rs                         # Rust implementation for fn dsa within this subsystem.
[x] src/signatures/sphincs.rs                        # Rust implementation for sphincs within this subsystem.
[x] src/signatures/verifier.rs                       # Rust implementation for verifier within this subsystem.
[x] src/kem/mod.rs                                   # Module registration and exports.
[x] src/kem/ml_kem.rs                                # Rust implementation for ml kem within this subsystem.
[x] src/symmetric/mod.rs                             # Module registration and exports.
[x] src/symmetric/aes_gcm.rs                         # Rust implementation for aes gcm within this subsystem.
[x] src/key_provider/mod.rs                          # Module registration and exports.
[x] src/key_provider/provider.rs                     # Cryptographic key registry/custody/rotation behavior.
[x] src/key_provider/filesystem.rs                   # Cryptographic key registry/custody/rotation behavior.
[x] src/key_provider/remote.rs                       # Cryptographic key registry/custody/rotation behavior.
[x] src/key_provider/hsm.rs                          # Cryptographic key registry/custody/rotation behavior.
[x] src/key_provider/tpm.rs                          # Cryptographic key registry/custody/rotation behavior.
```

### [~] `node-platform/crates/synergy-aegis/`

**Folder purpose:** First-class `synergy-aegis` subsystem boundary in the production node workspace.

**Current migration state:** The canonical Aegis Cryptography Engine owns PQVM/KEM/digest/entropy implementation boundaries. The synergy-crypto facade delegates to these providers; consumer caller migration remains separate.

```text
[x] Cargo.toml                                       # Canonical node-facing Aegis package and dependency boundary.
[x] src/lib.rs                                       # Private-material-free Aegis policy/provider API exports.
[x] src/verifier.rs                                  # Context/public-key/signature verification provider contract.
[x] src/signer.rs                                    # Key-ID/context/message signing contract with typed failures.
[x] src/key_lifecycle.rs                             # Bounded key IDs, purposes, public metadata, and legal state transitions.
[x] src/policy.rs                                    # Explicit PQ algorithm allowlist and bounded message/signature policy.
[x] src/attestation.rs                               # Bounded provider attestation shape and validity-window checks.
[x] src/kms_bridge.rs                                # Key-ID-only custody-provider bridge; no raw private-key export.
[x] src/audit.rs                                     # Secret-free structured Aegis audit events and sink contract.
[x] src/digest.rs                                    # Canonical Aegis digest provider and SHA3 implementation.
[x] src/entropy.rs                                   # Canonical Aegis entropy provider implementation.
[x] src/kem.rs                                       # Canonical Aegis PQVM ML-KEM provider implementation.
```

### [~] `node-platform/crates/synergy-network/`

**Folder purpose:** First-class `synergy-network` subsystem boundary in the production node workspace.

**Current migration state:** Production source now owns synchronous TCP listen/dial/connections, authenticated framing/compatibility, peer policy/state helpers, bounded discovery/routing/retransmission, Sentry filtering/failover, and network metrics. The new node runtime adapter is wired; Phase 2 full verification remains.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Tested first-class network API surface.
[x] src/transport/mod.rs                             # Module registration and exports.
[x] src/transport/transport.rs                       # Concrete TCP transport boundary with typed configuration/I/O errors.
[x] src/transport/address.rs                         # Canonical endpoint parsing/normalization; two focused tests pass.
[x] src/transport/tcp.rs                             # TCP no-delay/read/write timeout configuration.
[x] src/transport/listener.rs                        # Nonblocking TCP listener and configured inbound connection admission.
[x] src/transport/dialer.rs                          # Bounded-time multi-address TCP dialing.
[x] src/transport/connection.rs                      # Exact-peer read/write/flush/shutdown connection owner.
[x] src/transport/limits.rs                          # Validated total/directional/frame transport limits.
[x] src/transport/timeout.rs                         # Nonzero connect/handshake/read/write timeout policy.
[x] src/handshake/mod.rs                             # Module registration and exports.
[x] src/handshake/signing.rs                         # Static canonical handshake signer/verifier boundary.
[x] src/handshake/policy.rs                          # Aegis algorithm plus chain/genesis/protocol compatibility policy; two tests pass.
[x] src/handshake/protocol.rs                        # Transcript binds nonces/session/chain/role/algorithm/capabilities.
[x] src/handshake/challenge.rs                       # Short-lived nonzero challenge ownership.
[x] src/handshake/identity.rs                        # Canonical peer identity and sorted capability validation.
[x] src/handshake/chain.rs                           # Exact network/chain/genesis binding and remote verification.
[x] src/handshake/role.rs                            # Authority-neutral advertised role classification.
[x] src/handshake/compatibility.rs                   # Chain plus handshake-metadata compatibility gate.
[x] src/handshake/verifier.rs                        # Fail-closed proof verification into private authenticated peer state.
[x] src/handshake/rejection.rs                       # Typed fail-closed handshake rejection causes.
[x] src/peer/mod.rs                                  # Module registration and exports.
[x] src/peer/peer.rs                                 # Canonical peer descriptor and dial-address validation.
[x] src/peer/manager.rs                              # Exact-session cleanup, duplicate dials, quarantine/ban, and stale detection; four tests pass.
[x] src/peer/state.rs                                # Legal peer-state transition validation.
[x] src/peer/session.rs                              # Exact authenticated-session replay-sequence ownership.
[x] src/peer/admission.rs                            # Authenticated admission decision boundary used by the tested manager.
[x] src/peer/score.rs                                # Saturating bounded transport-quality score.
[x] src/peer/ban.rs                                  # Timed/permanent identity ban table.
[x] src/peer/quarantine.rs                           # Timed quarantine table with expiry cleanup.
[x] src/peer/connection_limits.rs                    # Total and directional connection-capacity enforcement.
[x] src/peer/duplicate.rs                            # Deterministic reciprocal-dial direction selection.
[x] src/peer/backoff.rs                              # Bounded exponential reconnect backoff.
[x] src/peer/persistence.rs                          # Authority-neutral persisted peer snapshot boundary.
[x] src/peer/health.rs                               # Healthy/degraded/stale peer liveness evaluation.
[x] src/discovery/mod.rs                             # Module registration and exports.
[x] src/discovery/bootseed.rs                        # Canonical prioritized bootseed candidates; no permanent liveness dependency.
[x] src/discovery/seed_set.rs                        # Deduplicated canonical seed address set.
[x] src/discovery/peer_exchange.rs                   # Bounded duplicate-free peer exchange validation.
[x] src/discovery/transport_registry.rs              # Transport-only discovery registry interface.
[x] src/discovery/dns.rs                             # TCP-only DNS/dnsaddr candidate parsing; focused test passes.
[x] src/discovery/cache.rs                           # Capacity-bounded expiring discovery cache.
[x] src/discovery/verifier.rs                        # Identity/lifetime/address discovery-record validation.
[x] src/protocol/mod.rs                              # Canonical new-network protocol/framing exports.
[x] src/protocol/id.rs                               # Stable canonical protocol identifiers.
[x] src/protocol/version.rs                          # Major/minor protocol compatibility model.
[x] src/protocol/registry.rs                         # Stable-ID protocol registration and payload bounds.
[x] src/protocol/envelope.rs                         # Session/sequence-bound authenticated envelope and exact-session routing handoff.
[x] src/protocol/codec.rs                            # Pre-allocation verification and canonical envelope codec.
[x] src/protocol/framing.rs                          # Bounded versioned canonical binary framing.
[x] src/protocol/size_limits.rs                      # Pre-allocation payload/authenticator limits.
[x] src/protocol/compatibility.rs                    # Kind/version/payload protocol compatibility check.
[x] src/router/mod.rs                                # Module registration and exports.
[x] src/router/router.rs                             # Typed next-frame dispatch to exact protocol handler.
[x] src/router/handler.rs                            # Transport-only protocol handler boundary; no finality authority.
[x] src/router/mailbox.rs                            # Bounded fair mailbox, overload rejection, and exact-session cleanup; four tests pass.
[x] src/router/backpressure.rs                       # Open/throttled/closed queue watermarks.
[x] src/router/queue.rs                              # Generic capacity-bounded FIFO.
[x] src/router/retransmit.rs                         # Capacity/attempt-bounded outbound retransmission buffer.
[~] runtime/src/p2p/router.rs                        # Legacy caller/adapter owner pending cutover to the first-class mailbox.
[x] src/sentry/mod.rs                               # Sentry perimeter exports; no consensus authority.
[x] src/sentry/policy.rs                            # Allowed public↔validator opaque-protocol forwarding policy and no-authority boundary.
[x] src/sentry/validator_link.rs                    # Exact authenticated VPN validator link with no authority grant.
[x] src/sentry/public_peers.rs                      # Capacity-bounded authenticated public peer set.
[x] src/sentry/forwarder.rs                         # Bounded validated bidirectional protocol forwarding; policy/overload tests pass.
[x] src/sentry/failover.rs                          # Deterministic healthy-link Sentry failover selection.
[x] src/sentry/filter.rs                            # Protocol and payload-size filtering before forwarding.
[x] src/sentry/metrics.rs                           # Saturating Sentry connection/forward/drop/failover counters.
[x] src/metrics.rs                                   # Saturating connection/frame/reconnect metrics by protocol.
```

### [~] `node-platform/crates/synergy-p2p-protocols/`

**Folder purpose:** First-class `synergy-p2p-protocols` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # First-class transport-only protocol adapter package.
[x] src/lib.rs                                       # Authority-neutral adapter envelope and protocol boundary.
[x] src/status.rs                                    # Status protocol adapter.
[x] src/peer_exchange.rs                             # Discovery protocol adapter; candidates remain untrusted.
[x] src/block_sync.rs                                # Opaque verified-sync delivery boundary.
[x] src/state_sync.rs                                # Authenticated state-sync delivery adapter; semantic verification remains Sync-owned.
[x] src/posy.rs                                      # Transport-only PoSy adapter with no consensus authority.
[x] src/etdag.rs                                     # Transport-only ETDAG adapter with no finality authority.
[x] src/transaction.rs                               # Transaction protocol adapter.
[x] src/snapshot.rs                                  # Snapshot protocol adapter; verification remains sync-owned.
[x] src/sxcp.rs                                      # SXCP cross-chain proof/relay/finality behavior.
[x] src/observer.rs                                  # Rust implementation for observer within this subsystem.
[x] src/errors.rs                                    # Typed adapter routing/empty-payload/consumer errors.
```

### [~] `node-platform/crates/synergy-vpn/`

**Folder purpose:** First-class `synergy-vpn` subsystem boundary in the production node workspace.

**Current migration state:** Production source owns signed transport leases, eligibility-bound enrollment/resume/revocation, validator/Sentry peer binding, NetBird daemon/profile/status/client control, role-aware readiness, and VPN metrics. The universal node now verifies pinned signed snapshots, persists the accepted generation, checks active-authority coverage, installs the verified overlay into network admission, and schedules bounded dials. Enrollment-broker, lease publication, deployment bindings, and Phase 2 verification remain.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Route-policy API surface; transport-only and authority-neutral.
[x] src/client.rs                                    # Stateful NetBird connection/refresh/disconnect orchestration.
[x] src/state.rs                                     # Explicit VPN lifecycle/readiness states.
[x] src/readiness.rs                                 # Role-aware readiness using management/signal/IP evidence.
[x] src/route_policy.rs                              # Exact synv/lowercase identity and 10.69 scope/canonical port validation; two tests pass.
[x] src/overlay_scope.rs                            # Validator/Sentry overlay assignment; never consensus authority.
[x] src/sentry_binding.rs                           # Exact Sentry identity/route binding to verified lease.
[x] src/peer_binding.rs                              # Exact validator identity/route binding to verified lease.
[x] src/transport_lease.rs                           # Signed, expiring, generation-bound transport lease.
[x] src/lease_verifier.rs                            # Explicit authority allowlist and signature verification boundary.
[x] src/enrollment/mod.rs                            # Enrollment module registration and exports.
[x] src/enrollment/request.rs                        # Challenge/key/scope-bound signed enrollment request.
[x] src/enrollment/challenge.rs                      # Nonzero expiring enrollment challenge.
[x] src/enrollment/proof.rs                          # Eligibility and injected-signature proof verification.
[x] src/enrollment/authorization.rs                  # Expiring enrollment authorization with no consensus authority.
[x] src/enrollment/response.rs                       # Redacted credential response bound to signed lease.
[x] src/enrollment/resume.rs                         # Prior authorization/lease/challenge-bound resume request.
[x] src/enrollment/revoke.rs                         # Typed bounded enrollment revocation.
[x] src/netbird/mod.rs                               # NetBird module registration and exports.
[x] src/netbird/daemon.rs                            # Absolute-path NetBird CLI status/up/down control.
[x] src/netbird/api.rs                               # Management API boundary for revocation/key rotation/authorization.
[x] src/netbird/status.rs                            # Bounded daemon-status parsing and connectivity evidence.
[x] src/netbird/profile.rs                           # HTTPS management/admin and interface profile validation.
[x] src/metrics.rs                                   # VPN connectivity/enrollment/lease/revocation metrics.
```

### [~] `node-platform/crates/synergy-transport-registry/`

**Folder purpose:** First-class `synergy-transport-registry` subsystem boundary in the production node workspace.

**Current migration state:** Signed snapshot verification is joined by atomic durable cache, generation gate, transport leases, revocation, reconciliation, custody signer boundary, and a fail-closed registry state owner. The universal-node VPN service now supplies pinned trust, verifies and installs the local governed snapshot, persists rollback-resistant accepted generation state, requires active-authority route coverage, and feeds exact signed route admission/dials. Remote fetch, lease publication, deployment bindings, and Phase 2 verification remain.

```text
[x] Cargo.toml                                       # First-class package and cryptographic dependencies build in the workspace.
[x] src/lib.rs                                       # Identity-complete verified registry plus generation install semantics.
[x] src/binding.rs                                   # Verified identity-to-route binding required before overlay peer authentication.
[x] src/lease.rs                                     # Expiring generation-bound transport lease; never authority.
[x] src/registry.rs                                  # Verified current registry plus revocation-aware route lookup.
[x] src/signer.rs                                    # Approved-custody snapshot signing provider boundary.
[x] src/verifier.rs                                  # Bounded Ed25519 snapshot verification, provider binding, coverage, rollback/equivocation refusal; focused tests pass.
[x] src/generation.rs                                # Nonzero rollback-refusing generation install gate.
[x] src/revocation.rs                                # Idempotent generation-effective identity revocations.
[x] src/cache.rs                                     # Bounded atomic signed-snapshot cache with fsync/rename/directory sync.
[x] src/reconciliation.rs                            # Deterministic added/changed/removed route delta.
```

### [~] `node-platform/crates/synergy-sync/`

**Folder purpose:** First-class `synergy-sync` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Tested sync API and regression coverage.
[x] src/manager.rs                                   # Plans from eligible verified-head candidates without determining finality.
[x] src/status.rs                                    # Read-only authority-neutral synchronization status.
[x] src/readiness.rs                                 # Signing remains closed while behind verified eligible evidence; two tests pass.
[x] src/head/mod.rs                                  # Module registration and exports.
[x] src/head/candidate.rs                            # Authority-neutral authenticated/protocol-compatible candidate model.
[x] src/head/collector.rs                            # Monotonic per-peer verified heads, conflict refusal, and disconnected-source pruning.
[x] src/head/verifier.rs                             # Opaque bounded three-QC witness carriage and caller-owned PoSy verification for untrusted head claims.
[~] src/head/quorum_view.rs                          # Verified-head record exists; finality-evidence verifier/quorum integration remains.
[x] src/head/selection.rs                            # Selects authenticated caller-verified evidence without treating validator duty as a source requirement.
[x] src/block/mod.rs                                 # Module registration and exports.
[x] src/block/scheduler.rs                           # Bounded anchored single-flight block scheduling.
[x] src/block/requester.rs                           # Validated bounded range request and parent anchor.
[x] src/block/responder.rs                           # Verified head/block/state/snapshot synchronization and recovery.
[x] src/block/verifier.rs                            # Anchored contiguous response import with exact through-height enforcement and no partial advance.
[x] src/block/importer.rs                            # Per-block finality verification and post-durable-write anchor advancement.
[x] src/block/retry.rs                               # Bounded retry ownership for block ranges.
[x] src/state/mod.rs                                 # Module registration and exports.
[x] src/state/checkpoint.rs                          # Chain/network/finalized-block/finality-bound state checkpoint.
[x] src/state/manifest.rs                            # Finality-bound manifest and complete chunk-root verification.
[x] src/state/chunk.rs                               # Deterministic bounded state-chunk digest model.
[x] src/state/downloader.rs                          # Bounded ordered deduplicated resumable state-chunk download.
[x] src/state/verifier.rs                            # Chunk and recomputed state-root verification.
[x] src/state/importer.rs                            # Atomic canonical-state commit after complete verification.
[x] src/state/resume.rs                              # Canonical new-format integrity-protected resume state; legacy formats fail closed.
[x] src/sources/mod.rs                               # Module registration and exports.
[x] src/sources/peer.rs                              # Verified head/block/state/snapshot synchronization and recovery.
[x] src/sources/archive.rs                           # Verified head/block/state/snapshot synchronization and recovery.
[x] src/sources/snapshot.rs                          # Verified head/block/state/snapshot synchronization and recovery.
[x] src/sources/scoring.rs                           # Verified head/block/state/snapshot synchronization and recovery.
[x] src/wire.rs                                      # Authenticated finalized-candidate, snapshot chunk, and successor-epoch authority-binding transport messages.
[x] src/sources/failover.rs                          # Frozen eligible support sources, target coverage, and one-attempt bounded failover; focused test passes.
[x] src/persistence.rs                               # Canonical integrity-protected sync metadata/resume persistence.
[x] src/metrics.rs                                   # Verified head/block/state/snapshot synchronization and recovery.
[x] src/wire.rs                                      # Tagged authenticated head/finalized-candidate request-response protocol with complete execution state.
```

### [~] `node-platform/crates/synergy-posy/`

**Folder purpose:** First-class `synergy-posy` subsystem boundary in the production node workspace.

**Current migration state:** The final owner contains executable proposal, vote,
strict dual-quorum QC, timeout-certificate takeover, pipelined height
advancement, signer-independent candidate identity, three-QC finality,
sign-once/recovery journal behavior, and a per-height QC store. Clean canonical
protocol/membership types, remaining typed stores, durable driver replay, live
adapters/callers, and legacy retirement remain. Old wire/Genesis/validator-set
serialization parity is not required.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Thin first-class PoSy module/API surface; no imported PoS semantics.
[~] src/protocol.rs                                  # Domains/signature boundary exists; complete the clean canonical new message protocol.
[x] src/version.rs                                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/domains.rs                                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/parameters.rs                                # Governed simplified-PoSy constants; no stake/score authority.
[x] src/errors.rs                                    # Typed invalid/conflict/not-ready/quorum failures.
[x] src/engine/mod.rs                                # Thin module registration and exports.
[~] src/engine/driver.rs                             # One event driver handles proposals, votes, QCs, timeout votes, and TCs; durable/live caller wiring remains.
[x] src/engine/state_machine.rs                      # Pipelined QC progression, three-QC finality, lock/highest-parent, TC takeover, durable restart, and verified successor-epoch integration.
[x] src/engine/height.rs                             # Checked height progression primitive.
[x] src/engine/round.rs                              # Checked round progression primitive.
[x] src/engine/transition.rs                         # Typed proposal/vote/QC/TC/finality/height/round transitions.
[~] src/engine/timers.rs                             # Bounded local timer exists; governed adaptive timing and recovery integration remain.
[x] src/engine/events.rs                             # Typed single-driver input events.
[x] src/membership/mod.rs                            # Canonical membership authority and registration exports.
[x] src/membership/validator.rs                      # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/membership/registry.rs                       # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/authority.rs                      # Finalized epoch-closure authority for next-epoch changes only.
[~] src/membership/epoch.rs                          # Epoch context exists; canonical transition/recovery ownership remains.
[x] src/membership/registration.rs                   # Validated shadow registration that grants no active authority.
[x] src/membership/shadow.rs                         # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/activation.rs                     # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/deactivation.rs                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/jailing.rs                        # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/slashing.rs                       # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/expulsion.rs                      # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/membership/transition.rs                     # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/clustering/mod.rs                            # Module registration and exports.
[x] src/clustering/cluster.rs                        # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/clustering/assignment.rs                     # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[~] src/clustering/schedule.rs                       # Governed leader ranking exists; canonical clustering integration remains.
[x] src/clustering/membership.rs                     # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/clustering/verification.rs                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/proposal/mod.rs                              # Thin module registration and exports.
[x] src/proposal/proposal.rs                         # Context-bound proposal, Genesis/QC ancestry, and stable certified-candidate subject.
[x] src/proposal/builder.rs                          # Binds proposal to verified height material and rejects template/source conflicts.
[x] src/proposal/validation.rs                       # Frozen proposer/key/context/signature validation.
[x] src/proposal/selection.rs                        # Frozen epoch leader-ring proposer lookup.
[x] src/proposal/recovery.rs                         # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/voting/mod.rs                                # Thin module registration and exports.
[x] src/voting/vote.rs                               # Context-bound block and timeout vote records.
[~] src/voting/phase.rs                              # Phase declarations exist; signing-authority integration remains.
[x] src/voting/validation.rs                         # Frozen key/context/signature and timeout-parent validation.
[x] src/voting/collection.rs                         # Candidate-scoped vote collection with certified-height cleanup.
[x] src/voting/duplicate_guard.rs                    # Signer/height/round conflict refusal with bounded cleanup.
[x] src/quorum/mod.rs                                # Thin module registration and exports.
[~] src/quorum/policy.rs                             # Frozen weight declaration exists; governed membership/authority binding remains.
[x] src/quorum/certificate.rs                        # Stable signer/round-independent candidate identity and verified participant proofs.
[x] src/quorum/builder.rs                            # Canonical QC construction from one vote transcript.
[x] src/quorum/verifier.rs                           # Strict independent validator-count and frozen-weight quorum.
[x] src/quorum/compatible_merge.rs                   # Safe proof-subset merge for one certified candidate.
[x] src/finality/mod.rs                              # Thin module registration and exports.
[x] src/finality/finality.rs                         # Consecutive three-QC grandparent finality.
[x] src/finality/certificate.rs                      # Typed finalized block record.
[~] src/finality/observer.rs                         # Observer interface exists; durable post-finalization hook integration remains.
[~] src/finality/commit.rs                           # Commit-sink interface exists; atomic protected state/chain commit remains.
[~] src/finality/verifier.rs                         # QC verifier interface exists; complete three-QC finality witness integration remains.
[x] src/timeout/mod.rs                               # Thin module registration and exports.
[x] src/timeout/timeout.rs                           # Canonical per-slot timeout collection, conflict refusal, and cleanup.
[x] src/timeout/certificate.rs                       # Strict dual-quorum TC, self-contained highest-QC proofs, and mandatory carry.
[x] src/timeout/round_change.rs                      # Checked sequential round derivation.
[x] src/timeout/recovery.rs                          # Verified highest-parent recovery boundary.
[x] src/persistence/mod.rs                           # Canonical bounded immutable PoSy object-store exports.
[x] src/persistence/signing_authority.rs             # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/persistence/safety_journal.rs                # Atomic sign-once conflict refusal; memory advances only after durable write.
[x] src/persistence/vote_store.rs                    # Verify-before-persist immutable canonical vote storage.
[x] src/persistence/proposal_store.rs                # Verify-before-persist immutable canonical proposal storage.
[x] src/persistence/certificate_store.rs             # Per-height QC store verifies signatures/quorum on write and reload and rejects conflicting replay; focused test passes.
[x] src/persistence/timeout_store.rs                 # Exact-slot verified timeout certificates persist and reverify for single-driver restart replay.
[x] src/persistence/finality_store.rs                # Exactly-once contiguous finalized-record persistence.
[x] src/persistence/prepared_state.rs                # Bounded integrity-hashed immutable canonical object storage.
[x] src/persistence/fsync.rs                         # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/recovery/mod.rs                              # Canonical prepared, peer-quorum, and reconciliation recovery exports.
[x] src/recovery/startup.rs                          # Atomic conflict-refusing recovery journal for all safety record kinds.
[x] src/recovery/replay.rs                           # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/recovery/peer_recovery.rs                    # Authenticated peer reports and strict independent count+weight quorum selection.
[x] src/sync_witness.rs                              # Complete three-QC plus required timeout-certificate evidence for single-driver Sync replay.
[x] src/recovery/prepared_state.rs                   # Restart checkpoint validation for epoch, ancestry, lock, takeover TC, and finality.
[x] src/recovery/reconciliation.rs                   # Fail-closed local/quorum reconciliation preventing rollback and ancestry conflict.
[x] src/network/mod.rs                               # Module registration and exports.
[x] src/network/adapter.rs                           # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/network/envelope.rs                          # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/network/inbound.rs                           # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/network/outbound.rs                          # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/network/retransmission.rs                    # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/metrics.rs                                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
```

### [~] `node-platform/crates/synergy-etdag/`

**Folder purpose:** First-class `synergy-etdag` subsystem boundary in the production node workspace.

**Current migration state:** Production source is populated across exact-H+5 admission, provider-bound crypto, protected ingress, DAG/cuts, availability, ordering/certificates, finality-authorized reveal, deterministic execution handoff, crash-safe stores, authenticated transport, bounded recovery, governance, and metrics. The ordinary-wallet admission request is actively being corrected to carry signed chain/network/context/nonce/algorithm/presented-key/envelope bindings; client construction, Aegis provider wiring, RPC/transport callers, negative tests, and finality evidence remain.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Tested first-class ETDAG API surface.
[x] src/profile.rs                                   # Canonical ETDAG profile identifier.
[x] src/parameters.rs                                # Governed H+5 and bounded admission parameters used by tested policy.
[x] src/domains.rs                                   # Frozen canonical protocol domain separators and allowlist validation.
[x] src/digest.rs                                    # Frozen SHA3-512 domain framing/canonical digest representation used by ordering.
[x] src/errors.rs                                    # Typed fail-closed ETDAG errors.
[x] src/crypto/mod.rs                                # Canonical ETDAG cryptographic verification boundary and exports.
[x] src/crypto/envelope.rs                           # Context/height-bound encrypted envelope and share-capsule shape validation.
[x] src/crypto/kem.rs                                # Provider-injected KEM boundary with typed fail-closed errors.
[x] src/crypto/aead.rs                               # Provider-injected AEAD boundary and authenticated ciphertext representation.
[x] src/crypto/padding.rs                            # Canonical size-class padding/unpadding with noncanonical padding refusal.
[x] src/crypto/nonce.rs                              # Nonzero fixed-width envelope nonce validation.
[x] src/crypto/key_registry.rs                       # Context-bound validator KEM registry with key/window uniqueness checks.
[x] src/crypto/key_rotation.rs                       # Nonoverlapping governed key schedule and active-key selection.
[x] src/crypto/verifier.rs                           # Domain-separated validator-key signature verification boundary; transport identity grants no authority.
[~] src/admission/mod.rs                             # Wallet admission verification exports are being corrected; focused validation remains.
[x] src/admission/context.rs                         # H+5 context binding and canonical admission commitment.
[~] src/admission/request.rs                         # In-progress signed wallet request binding chain/network/context/height/nonce/algorithm/public key and encrypted envelope.
[x] src/admission/policy.rs                          # Context-bound ciphertext admission, duplicate/closed refusal, and deterministic order; three tests pass.
[~] src/admission/validator.rs                       # In-progress chain/network/context/resource/wallet-signature admission validation pipeline.
[x] src/admission/target_height.rs                   # Checked exact finalized-height-plus-five target derivation.
[x] src/admission/nonce_window.rs                    # Bounded sender nonce replay window.
[x] src/admission/resource_limits.rs                 # Canonical ciphertext class and capsule resource limits.
[x] src/admission/certificate.rs                     # Context/height/envelope-bound deduplicated admission votes and certificate.
[~] src/admission/verifier.rs                        # In-progress narrow Aegis-owned wallet-key/address/signature verification boundary.
[~] src/ingress/mod.rs                               # Governed-validator sender-policy export is being retired from production ingress.
[~] src/ingress/service.rs                           # In-progress check-before-mutation wallet ingress service; never determines finality.
[x] src/ingress/protected_transaction.rs             # Canonical protected transaction representation.
[x] src/ingress/envelope_validation.rs               # Exact context/target/envelope identifier validation.
[~] src/ingress/sender_validation.rs                 # Orphaned governed-validator sender allowlist; remove after wallet ingress cutover is validated.
[~] src/ingress/replay_protection.rs                 # In-progress bounded wallet-address/nonce and envelope replay protection.
[x] src/ingress/rate_limit.rs                        # Bounded per-sender ingress rate accounting.
[x] src/ingress/admission_queue.rs                   # Capacity-bounded protected admission queue.
[x] src/ingress/receipt.rs                           # Context-bound admission receipt.
[x] src/dag/mod.rs                                   # DAG module registration and exports.
[x] src/dag/vertex.rs                                # Context/height/envelope/parent/author-bound vertex shape.
[x] src/dag/vertex_id.rs                             # Frozen-domain canonical unsigned vertex identifier.
[x] src/dag/parents.rs                               # Bounded canonical parent validation and deduplication.
[x] src/dag/graph.rs                                 # Context-bound graph with fail-closed insertion and durable serialization.
[x] src/dag/dependency.rs                            # Parent/context dependency validation without mutation.
[x] src/dag/insertion.rs                             # Validated graph insertion boundary.
[x] src/dag/validation.rs                            # Vertex identity, dependency, and cycle validation.
[x] src/dag/traversal.rs                             # Capacity-bounded ancestor and descendant traversal.
[x] src/dag/cut.rs                                   # Dependency-safe certified cut and canonical cut root.
[x] src/dag/deterministic_order.rs                   # Arrival-independent content-blind topological order.
[x] src/availability/mod.rs                          # Availability vote/certificate ownership and exports.
[x] src/availability/vote.rs                         # Context/vertex/validator/key-bound availability vote.
[x] src/availability/collector.rs                    # Context/vertex/member-bound collection with pre-mutation duplicate and authorization checks.
[x] src/availability/custody.rs                   # Aegis-verified generic shard custody bound to one ETDAG vertex; grants no ETDAG certificate authority.
[x] src/availability/certificate.rs                  # Frozen quorum and deduplicated availability certificate construction.
[x] src/availability/verifier.rs                     # Unique-member signature and frozen-quorum availability-certificate verification.
[x] src/availability/recovery.rs                     # Missing and orphan availability-certificate recovery planning.
[x] src/ordering/mod.rs                              # Module registration and exports.
[x] src/ordering/seed.rs                             # Frozen finalized-context/DCC/height order-seed derivation; focused binding test passes.
[x] src/ordering/content_blind.rs                    # Frozen dependency-aware deterministic order and gas/byte prefix selection; four focused tests pass.
[x] src/ordering/order_key.rs                        # Frozen content-blind seed/vertex order-key derivation.
[x] src/ordering/protected_cut.rs                    # Sorted duplicate-free certified cut proof and semantic-root validation.
[x] src/ordering/cut_marker.rs                       # Context/height/cut-bound durable cut marker.
[x] src/ordering/proof.rs                            # Canonical context/target/cut/seed/order/root binding proof.
[x] src/ordering/order_root.rs                       # Canonical protected order-root derivation.
[x] src/ordering/batch.rs                            # Duplicate-free context-bound deterministic protected batch.
[x] src/ordering/verifier.rs                         # Content-blind seed order, duplicate, and order-root verification.
[x] src/certificates/mod.rs                          # Certificate family registration and exports.
[x] src/certificates/target_admission.rs             # Canonical admission-certificate root.
[x] src/certificates/availability.rs                 # Canonical availability-certificate root.
[x] src/certificates/ordering.rs                     # Ordering proof certificate and duplicate-signer refusal.
[x] src/certificates/batch_validate.rs               # Execution-input-root validation certificate.
[x] src/certificates/batch_finality.rs               # PoSy-owned finality-reference consumer that cannot determine finality.
[x] src/certificates/batch_timeout.rs                # Bounded protected-batch timeout certificate.
[x] src/certificates/canonical.rs                    # Canonical certificate enum, signatures, and roots.
[x] src/certificates/verifier.rs                     # Membership/quorum/signature verification boundary.
[x] src/reveal/mod.rs                                # Finality-authorized reveal gate/transcript ownership and exports.
[x] src/reveal/gate.rs                               # Finality-bound, idempotent authorization gate with conflict refusal.
[x] src/reveal/authorization.rs                      # Context/height/batch/finality-bound reveal authorization.
[x] src/reveal/decrypt_share.rs                      # Signed context/member/key-bound opaque decrypt-share representation.
[x] src/reveal/share_collector.rs                    # Pre-mutation validation, dedupe, threshold collection, and canonical share ordering.
[x] src/reveal/transcript.rs                         # Canonically sorted, deduplicated threshold transcript and transcript root.
[x] src/reveal/decrypt.rs                            # Finality-authorized threshold decrypt boundary; plaintext only after verified shares.
[x] src/reveal/verifier.rs                           # Context/membership/key/signature verification before share promotion.
[x] src/execution/mod.rs                             # Deterministic handoff module registration and exports.
[x] src/execution/execution_input.rs                 # Context/batch/order/transcript-bound execution input.
[x] src/execution/batch_validation.rs                # Batch-to-handoff binding validation.
[x] src/execution/transaction_validation.rs          # Injected bounded plaintext transaction validation boundary.
[x] src/execution/deterministic_batch.rs             # Exact-order reveal-to-plaintext batch preparation after authorization.
[x] src/execution/execution_adapter.rs               # Execution-only adapter boundary that cannot determine finality.
[x] src/governance/mod.rs                            # ETDAG governance module registration and exports.
[x] src/governance/manifest.rs                       # Network/chain/profile/parameter/fee/key-bound governed manifest.
[x] src/governance/parameters.rs                     # Frozen exact-H+5 governed parameter validation.
[x] src/governance/fee_schedule.rs                   # Canonical duplicate-free governed fee classes and schedule root.
[x] src/governance/activation.rs                     # Future-only manifest succession and frozen-field enforcement.
[x] src/governance/key_registry.rs                   # Manifest-bound KEM key activation validation.
[x] src/governance/verifier.rs                       # Explicit governance-authority signature verification boundary.
[x] src/persistence/mod.rs                           # Module registration and exports.
[x] src/persistence/admission_store.rs               # Atomic context-bound admission recovery, mismatch refusal, and closed-state restore; two tests pass.
[x] src/persistence/safety_journal.rs                # Atomic sign-once safety slots with idempotency and conflict refusal.
[x] src/persistence/protected_input_store.rs         # Atomic encrypted-input store that never persists plaintext.
[x] src/persistence/graph_store.rs                   # Atomic context-bound validated DAG persistence and recovery.
[x] src/persistence/certificate_store.rs             # Canonical-root-keyed atomic certificate persistence.
[x] src/persistence/reveal_store.rs                  # Atomic authorization/share persistence with no plaintext and conflict refusal.
[x] src/persistence/recovery.rs                      # Durable shape/slot recovery requiring fresh cryptographic reverification.
[x] src/network/mod.rs                               # Authenticated ETDAG transport module registration and exports.
[x] src/network/adapter.rs                           # Transport-only adapter that cannot grant authority or finality.
[x] src/network/messages.rs                          # Canonical authenticated ETDAG envelope plus bounded missing-shard request and recovered-custody response.
[x] src/network/handler.rs                           # Authorized-member signature verification before handling.
[x] src/network/gossip.rs                            # Capacity-bounded deduplicated gossip queue.
[x] src/network/retransmission.rs                    # Bounded exponential-backoff artifact retransmission queue.
[x] src/recovery/mod.rs                              # ETDAG recovery module registration and exports.
[x] src/recovery/startup.rs                          # Dependency-ordered startup recovery and readiness plan.
[x] src/recovery/reconcile.rs                        # Protected-input/parent/certificate reconciliation.
[x] src/recovery/missing_artifacts.rs                # Typed missing-artifact inventory.
[x] src/recovery/replay.rs                           # Validate-first typed recovery replay boundary.
[x] src/metrics.rs                                   # Overflow-safe ETDAG production counters and snapshot.
```

### [~] `node-platform/crates/synergy-etdag-client/`

**Folder purpose:** First-class `synergy-etdag-client` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Encrypted Transaction DAG protected transaction behavior.
[x] src/target_context.rs                            # Canonical target-height context derivation and validation.
[x] src/ingress_keys.rs                              # Governed ETDAG ingress-key selection boundary.
[x] src/encrypt.rs                                   # Aegis-backed protected client encryption owner.
[x] src/padding.rs                                   # Deterministic bounded protected-envelope padding.
[x] src/envelope.rs                                  # Canonical protected submission envelope.
[ ] src/request.rs                                   # Wallet-signed outer admission request construction bound to the encrypted transaction envelope.
[~] src/submit.rs                                    # Existing envelope-only submitter must migrate to the signed AdmissionRequest transport contract.
[x] src/receipt.rs                                   # Typed protected submission receipt validation.
```

### [~] `node-platform/crates/synergy-transaction/`

**Folder purpose:** First-class `synergy-transaction` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Canonical transaction package and dependency boundary.
[x] src/lib.rs                                       # Canonical transaction API and versioned action exports.
[x] src/transaction.rs                               # Bounded canonical actions, class/action authorization, and canonical synergy-address sender/receiver validation.
[x] src/id.rs                                        # Rust implementation for id within this subsystem.
[x] src/nonce.rs                                     # Checked reservation, release, inspection, and overflow-safe advancement.
[x] src/signature.rs                                 # Rust implementation for signature within this subsystem.
[x] src/validation.rs                                # Address/payload/action/class validation before admission.
[x] src/fee.rs                                       # Rust implementation for fee within this subsystem.
[x] src/system_transaction.rs                        # Explicit authorized system/governance transaction representation.
[x] src/receipt.rs                                   # Domain-separated canonical transaction-receipt commitments.
```

### [x] `node-platform/crates/synergy-tx-ingress/`

**Folder purpose:** First-class `synergy-tx-ingress` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/router.rs                                    # Rust implementation for router within this subsystem.
[x] src/protected.rs                                 # Rust implementation for protected within this subsystem.
[x] src/system.rs                                    # Rust implementation for system within this subsystem.
[x] src/governance.rs                                # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/internal.rs                                  # Rust implementation for internal within this subsystem.
[x] src/admission.rs                                 # Rust implementation for admission within this subsystem.
[x] src/metrics.rs                                   # Prometheus/operational metric definitions for the owning subsystem.
```

### [~] `node-platform/crates/synergy-execution/`

**Folder purpose:** First-class `synergy-execution` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Tested deterministic execution API and regression suite.
[x] src/executor.rs                                  # Revalidates decoded input and commits cloned state only after full transition/root success.
[x] src/context.rs                                   # Strict H+5 authorized reveal/order input validation.
[x] src/transition.rs                                # Narrow deterministic state-transition adapter; no finality authority.
[x] src/validation.rs                                # Structural, Aegis signature, network, height, and index revalidation.
[x] src/scheduler.rs                                 # All-or-nothing block execution and header root verification.
[x] src/fees.rs                                      # Deterministic fee-cap/base-price settlement to configured collector.
[x] src/receipts.rs                                  # Per-transaction roots/receipts/totals and finalized-state metadata output.
[x] src/candidate.rs                                 # Canonical complete execution candidate with account-root and block-commitment validation.
[x] src/rollback.rs                                  # Speculative execution checkpoint and candidate discard boundary; no finality authority.
[x] src/dispatcher/mod.rs                            # Typed action-dispatch boundary; ExecutionService routes every action family through it.
[~] src/dispatcher/native.rs                         # Native transfer/nonce transition implemented; richer native actions remain.
[x] src/dispatcher/synq.rs                           # Deterministic SynQ dispatch boundary wired to the canonical Aegis PQSynQ verifier and AIVM QVM provider.
[x] src/dispatcher/sxcp.rs                           # Deterministic SXCP dispatch wired to frozen-dual-quorum proof authorization, UMA resolution, protocol state, and finalized relay outbox.
[x] src/dispatcher/governance.rs                     # Governance dispatch wired to canonical proposal/constitution roots, Aegis votes, thresholds, delay, activation, and protocol-state mutation.
[x] src/dispatcher/system.rs                         # Narrow system dispatch delegates supported mutations to the canonical governance provider; unknown actions fail closed.
```

### [~] `node-platform/crates/synergy-synq/`

**Folder purpose:** First-class `synergy-synq` subsystem boundary in the production node workspace.

**Current migration state:** The canonical node caller verifies PQSynQ through Aegis and executes supported deterministic QVM bytecode through AIVM; unsupported host/crypto opcodes remain explicitly fail closed.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # SynQ deterministic smart-contract execution integration.
[x] src/vm.rs                                        # SynQ deterministic smart-contract execution integration.
[x] src/bytecode.rs                                  # SynQ deterministic smart-contract execution integration.
[x] src/verifier.rs                                  # SynQ deterministic smart-contract execution integration.
[x] src/executor.rs                                  # SynQ deterministic smart-contract execution integration.
[x] src/gas.rs                                       # SynQ deterministic smart-contract execution integration.
[x] src/host.rs                                      # SynQ deterministic smart-contract execution integration.
[x] src/storage.rs                                   # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/determinism.rs                               # SynQ deterministic smart-contract execution integration.
[x] src/tracing.rs                                   # SynQ deterministic smart-contract execution integration.
```

### [x] `node-platform/crates/synergy-aivm/`

**Folder purpose:** First-class `synergy-aivm` subsystem boundary in the production node workspace.

**Current migration state:** Deterministic bounded AIVM source owns sandbox, resources, validation, engine, output commitment, metrics, and the concrete SynQ/QVM execution adapter.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # AIVM runtime/sandbox/resource integration.
[x] src/runtime.rs                                   # AIVM runtime/sandbox/resource integration.
[x] src/sandbox.rs                                   # AIVM runtime/sandbox/resource integration.
[x] src/resources.rs                                 # AIVM runtime/sandbox/resource integration.
[x] src/validation.rs                                # AIVM runtime/sandbox/resource integration.
[x] src/metrics.rs                                   # Prometheus/operational metric definitions for the owning subsystem.
[x] src/synq_vm.rs                                   # Concrete deterministic SynQ VM adapter over the canonical AIVM QVM.
[x] src/quantum/mod.rs                               # Canonical QVM module boundary.
[x] src/quantum/opcode.rs                            # Established bounded QVM opcode decoding and costs.
[x] src/quantum/vm.rs                                # Deterministic QVM execution; unsupported crypto opcodes require an injected Aegis provider and fail closed.
```

### [x] `node-platform/crates/synergy-ai/`

**Folder purpose:** Common AI service contracts used by the four canonical AI node roles. The role is coarse-grained; individual AI jobs are capabilities/work types.

```text
[x] Cargo.toml                                       # AI service crate manifest and dependency boundary.
[x] src/lib.rs                                       # Public AI service contracts and capability exports.
[x] src/capability.rs                                # Advertised AI capabilities and hardware/resource eligibility.
[x] src/job.rs                                       # Canonical AI workload/job request and lifecycle types.
[x] src/receipt.rs                                   # Signed workload/capacity/verification receipts used for acceptance and settlement.
[x] src/policy.rs                                    # Model/runtime/dataset/privacy/tenant/agent policy enforcement contracts.
[x] src/provider.rs                                  # Operator/provider identity and capability advertisement.
[x] src/compute/mod.rs                               # AI Compute role services.
[x] src/compute/inference.rs                         # Inference, embeddings, and multimodal execution.
[x] src/compute/training.rs                          # Training/fine-tuning/checkpoint/reproducibility execution.
[x] src/compute/agent.rs                             # Bounded sandboxed AI-agent execution with explicit external-action policy.
[x] src/coordination/mod.rs                          # AI Coordination role services.
[x] src/coordination/routing.rs                      # Model/provider routing, quota, and policy matching.
[x] src/coordination/scheduler.rs                    # GPU/capacity scheduling, placement, and utilization metering.
[x] src/coordination/federated.rs                    # Federated-learning round coordination and secure aggregation orchestration.
[x] src/data/mod.rs                                  # AI Data role services.
[x] src/data/model_repository.rs                     # Versioned model artifacts, metadata, digests, and publication workflow.
[x] src/data/dataset_provenance.rs                   # Dataset manifests, rights/consent/redaction/training eligibility metadata.
[x] src/data/vector_memory.rs                        # Tenant-isolated embeddings/vector memory, retrieval, retention, and deletion receipts.
[x] src/assurance/mod.rs                             # AI Assurance role services.
[x] src/assurance/verification.rs                    # Receipt/result replay, policy checks, and independent verification.
[x] src/assurance/evaluation.rs                      # Benchmarks, quality/safety tests, latency/cost evaluation.
[x] src/assurance/reputation.rs                      # Evidence-based provider/model reputation inputs.
[x] src/assurance/independence.rs                    # Prevents a workload provider from independently satisfying assurance for its own job where independence is required.
[x] src/metrics.rs                                   # AI workload/capacity/receipt/verification/storage/quality metrics.
```

### [~] `node-platform/crates/synergy-block/`

**Folder purpose:** First-class `synergy-block` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Canonical block package using canonical transaction types.
[x] src/lib.rs                                       # Canonical block, builder, commitment, codec, and validation API.
[x] src/header.rs                                    # Canonical block representation, validation, import, or construction.
[x] src/body.rs                                      # Canonical block representation, validation, import, or construction.
[x] src/block.rs                                     # Ordered transaction/receipt block representation and bound roots.
[x] src/builder.rs                                   # Canonical block construction with ordered receipt correspondence.
[x] src/validation.rs                                # Network/height/parent/timestamp/root and proposer-signature verification.
[x] src/commitment.rs                                # Domain-separated transaction and receipt commitment roots.
[x] src/encoding.rs                                  # Bounded versioned canonical block codec for the new network.
```

### [~] `node-platform/crates/synergy-state/`

**Folder purpose:** First-class `synergy-state` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Finalized-state store API; cannot determine finality.
[x] src/state.rs                                     # Validated durable finalized-height/block/state-root record and immutable history paths.
[x] src/account.rs                                   # Canonical blockchain state, overlays, roots, proofs, and transitions.
[x] src/root.rs                                      # Canonical blockchain state, overlays, roots, proofs, and transitions.
[x] src/overlay.rs                                   # Canonical blockchain state, overlays, roots, proofs, and transitions.
[x] src/transition.rs                                # History-first finality commit, immutable root-checked account-state custody, contiguous/idempotent replay, conflict-safe interrupted-pointer retry, and authenticated snapshot commits across unavailable height ranges; new world-state path is not yet tested.
[x] src/diff.rs                                      # Canonical blockchain state, overlays, roots, proofs, and transitions.
[x] src/proof.rs                                     # Canonical blockchain state, overlays, roots, proofs, and transitions.
[x] src/pruning.rs                                   # Canonical blockchain state, overlays, roots, proofs, and transitions.
```

### [~] `node-platform/crates/synergy-storage/`

**Folder purpose:** First-class `synergy-storage` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # First-class package builds in the node-platform workspace.
[x] src/lib.rs                                       # Bounded atomic-store/WAL/integrity/disk/pruning API surface.
[x] src/database.rs                                  # Atomic temp write, fsync, rename, parent sync, bounded read, and traversal refusal; three tests pass.
[x] src/transaction.rs                               # Durable database/WAL/integrity/pruning/disk safety behavior.
[~] src/migration.rs                                 # Schema-version primitive exists; migration planning/crash recovery remains.
[~] src/integrity.rs                                 # Domain-separated integrity digest exists; broader record integration/tests remain.
[~] src/recovery.rs                                  # WAL recovery report validates replay; domain-specific reconciliation remains.
[x] src/fsync.rs                                     # Platform directory fsync boundary used after atomic rename and first WAL creation.
[x] src/wal.rs                                       # Sequence/integrity-bound durable append, strict replay, and truncated-record refusal; two tests pass.
[~] src/disk_guard.rs                                # Free-space policy primitive exists; OS collector and injected disk-pressure tests remain.
[~] src/pruning.rs                                   # Finalized-height retention boundary exists; safe pruning execution/tests remain.
[x] src/column/mod.rs                                # Module registration and exports.
[x] src/column/blocks.rs                             # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/column/state.rs                              # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/column/consensus.rs                          # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/column/etdag.rs                              # Encrypted Transaction DAG protected transaction behavior.
[x] src/column/peers.rs                              # Authenticated peer discovery/lifecycle/state/routing behavior.
[x] src/column/metadata.rs                           # Durable database/WAL/integrity/pruning/disk safety behavior.
```

### [x] `node-platform/crates/synergy-snapshot/`

**Folder purpose:** First-class `synergy-snapshot` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/manifest.rs                                  # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/builder.rs                                   # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/chunk.rs                                     # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/signer.rs                                    # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/verifier.rs                                  # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/restore.rs                                   # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/uploader.rs                                  # Finality-bound snapshot build/verify/restore/publication behavior.
[x] src/retention.rs                                 # Finality-bound snapshot build/verify/restore/publication behavior.
```

### [x] `node-platform/crates/synergy-sxcp/`

**Folder purpose:** First-class `synergy-sxcp` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # SXCP cross-chain proof/relay/finality behavior.
[x] src/capability.rs                                # Cross-Chain Node capability advertisement: relay, verify, supported external chains, and service limits.
[x] src/independence.rs                              # Enforces relay/verification independence; a node cannot self-satisfy acceptance for its own relayed package.
[x] src/protocol.rs                                  # SXCP cross-chain proof/relay/finality behavior.
[x] src/proof.rs                                     # SXCP cross-chain proof/relay/finality behavior.
[x] src/relay.rs                                     # SXCP cross-chain proof/relay/finality behavior.
[x] src/verifier.rs                                  # SXCP cross-chain proof/relay/finality behavior.
[x] src/finality.rs                                  # SXCP cross-chain proof/relay/finality behavior.
[x] src/vault.rs                                     # SXCP cross-chain proof/relay/finality behavior.
[x] src/uma.rs                                     # Resolves chain-validated relay destinations through the canonical UMA registry.
[x] src/receipt.rs                                   # SXCP cross-chain proof/relay/finality behavior.
[x] src/execution.rs                                 # Dual-quorum-authorized external proof, canonical UMA resolution, and finalized relay-intent contract.
[x] src/adapters/mod.rs                              # Module registration and exports.
[x] src/adapters/bitcoin.rs                          # SXCP cross-chain proof/relay/finality behavior.
[x] src/adapters/ethereum.rs                         # SXCP cross-chain proof/relay/finality behavior.
[x] src/adapters/solana.rs                           # SXCP cross-chain proof/relay/finality behavior.
```

### [x] `node-platform/crates/synergy-uma/`

**Folder purpose:** First-class `synergy-uma` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/address.rs                                   # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/registry.rs                                  # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/mapping.rs                                   # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/coordinator.rs                               # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/verifier.rs                                  # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/adapters/mod.rs                              # Module registration and exports.
[x] src/adapters/bitcoin.rs                          # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/adapters/ethereum.rs                         # Universal Meta-Address registry/mapping/coordinator behavior.
[x] src/adapters/solana.rs                           # Universal Meta-Address registry/mapping/coordinator behavior.
```

### [x] `node-platform/crates/synergy-data-availability/`

**Folder purpose:** First-class `synergy-data-availability` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/store.rs                                     # Durable conflict-safe shard-plus-proof custody, bounded reads, exact binding checks, and retention pruning.
[x] src/shard.rs                                     # Rust implementation for shard within this subsystem.
[x] src/proof.rs                                     # Rust implementation for proof within this subsystem.
[x] src/serve.rs                                     # Bounded custody serving with exact object-root, shard-index, proof-root, and payload-root checks.
[x] src/audit.rs                                     # Rust implementation for audit within this subsystem.
[x] src/retention.rs                                 # Rust implementation for retention within this subsystem.
```

### [x] `node-platform/crates/synergy-governance/`

**Folder purpose:** First-class `synergy-governance` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/proposal.rs                                  # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/vote.rs                                      # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/authorization.rs                             # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/activation.rs                                # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/constitution.rs                              # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/audit.rs                                     # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/emergency.rs                                 # Governance authorization, proposal, vote, activation, or audit behavior.
[x] src/execution.rs                                 # Canonical-root, Aegis-vote, threshold, delay, activation, payload, and deterministic state-mutation validation.
```

### [x] `node-platform/crates/synergy-validator-management/`

**Folder purpose:** First-class `synergy-validator-management` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/registry.rs                                  # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/onboarding.rs                                # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/activation.rs                                # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/shadow.rs                                    # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/health.rs                                    # Subsystem/node health state and diagnostics.
[x] src/jailing.rs                                   # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/slashing.rs                                  # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/expulsion.rs                                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/removal.rs                                   # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/migration.rs                                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/lifecycle.rs                               # No-bypass operational lifecycle; Active requires frozen PoSy membership witness.
[x] src/persistence.rs                             # Atomic compare-and-swap lifecycle and shadow-progress persistence boundary.
```

### [x] `node-platform/crates/synergy-rpc/`

**Folder purpose:** First-class `synergy-rpc` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/server.rs                                    # Rust implementation for server within this subsystem.
[x] src/auth.rs                                      # Rust implementation for auth within this subsystem.
[x] src/rate_limit.rs                                # Rust implementation for rate limit within this subsystem.
[x] src/health.rs                                    # Subsystem/node health state and diagnostics.
[x] src/methods/mod.rs                               # Module registration and exports.
[x] src/methods/chain.rs                             # Rust implementation for chain within this subsystem.
[x] src/methods/block.rs                             # Canonical block representation, validation, import, or construction.
[x] src/methods/transaction.rs                       # Rust implementation for transaction within this subsystem.
[x] src/methods/account.rs                           # Rust implementation for account within this subsystem.
[x] src/methods/node.rs                              # Rust implementation for node within this subsystem.
[x] src/methods/peers.rs                             # Authenticated peer discovery/lifecycle/state/routing behavior.
[x] src/methods/sync.rs                              # Verified head/block/state/snapshot synchronization and recovery.
[x] src/methods/validator.rs                         # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[x] src/methods/etdag.rs                             # Encrypted Transaction DAG protected transaction behavior.
[x] src/methods/posy.rs                              # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/methods/system.rs                            # Rust implementation for system within this subsystem.
[x] src/middleware/mod.rs                            # Module registration and exports.
[x] src/middleware/request_id.rs                     # Rust implementation for request id within this subsystem.
[x] src/middleware/limits.rs                         # Rust implementation for limits within this subsystem.
[x] src/middleware/metrics.rs                        # Prometheus/operational metric definitions for the owning subsystem.
```

### [x] `node-platform/crates/synergy-ws/`

**Folder purpose:** First-class `synergy-ws` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/server.rs                                    # Rust implementation for server within this subsystem.
[x] src/subscriptions.rs                             # Rust implementation for subscriptions within this subsystem.
[x] src/blocks.rs                                    # Canonical block representation, validation, import, or construction.
[x] src/transactions.rs                              # Rust implementation for transactions within this subsystem.
[x] src/finality.rs                                  # Rust implementation for finality within this subsystem.
[x] src/node.rs                                      # Rust implementation for node within this subsystem.
```

### [x] `node-platform/crates/synergy-admin-api/`

**Folder purpose:** First-class `synergy-admin-api` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Privileged typed node-management API behavior.
[x] src/protocol.rs                                  # Privileged typed node-management API behavior.
[x] src/server.rs                                    # Privileged typed node-management API behavior.
[x] src/client.rs                                    # Privileged typed node-management API behavior.
[x] src/auth.rs                                      # Privileged typed node-management API behavior.
[x] src/authorization.rs                             # Privileged typed node-management API behavior.
[x] src/audit.rs                                     # Privileged typed node-management API behavior.
[x] src/operations/mod.rs                            # Module registration and exports.
[x] src/operations/lifecycle.rs                      # Privileged typed node-management API behavior.
[x] src/operations/config.rs                         # Typed configuration, validation, defaults, and migration.
[x] src/operations/identity.rs                       # Canonical node identity, possession proofs, and key bindings.
[x] src/operations/peers.rs                          # Authenticated peer discovery/lifecycle/state/routing behavior.
[x] src/operations/sync.rs                           # Verified head/block/state/snapshot synchronization and recovery.
[x] src/operations/validator.rs                      # Validator onboarding, shadowing, activation, jailing, status, and safe lifecycle operations.
[x] src/operations/ownership.rs                      # Typed finalized ownership inspection and claim/transfer transaction preparation.
[x] src/operations/naming.rs                         # Typed finalized NodeID resolution/availability and register/rename transaction preparation.
[x] src/operations/rewards.rs                        # Typed finalized reward inspection and owner-withdrawal transaction preparation.
[x] src/operations/sentry.rs                         # Sentry public/VPN path health, forwarding policy, redundancy, and safe remediation operations.
[x] src/operations/cross_chain.rs                    # Cross-Chain relay/verify capability, adapter, receipt, queue, and independence inspection/operations.
[x] src/operations/ai.rs                             # AI Compute/Coordination/Data/Assurance capability, workload, receipt, resource, and health operations.
[x] src/operations/vpn.rs                            # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[x] src/operations/posy.rs                           # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[x] src/operations/etdag.rs                          # Encrypted Transaction DAG protected transaction behavior.
[x] src/operations/storage.rs                        # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/operations/telemetry.rs                      # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/operations/upgrade.rs                        # Privileged typed node-management API behavior.
[x] src/events/mod.rs                                # Module registration and exports.
[x] src/events/event.rs                              # Privileged typed node-management API behavior.
[x] src/events/stream.rs                             # Privileged typed node-management API behavior.
[x] src/events/backpressure.rs                       # Privileged typed node-management API behavior.
[x] src/error.rs                                     # Privileged typed node-management API behavior.
```

### [x] `node-platform/crates/synergy-telemetry/`

**Folder purpose:** First-class `synergy-telemetry` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/metrics.rs                                   # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/registry.rs                                  # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/prometheus.rs                                # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/tracing.rs                                   # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/structured_log.rs                            # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/health.rs                                    # Subsystem/node health state and diagnostics.
[x] src/readiness.rs                                 # Role-aware readiness evaluation; process-alive is not sufficient.
[x] src/consensus.rs                                 # Metrics, traces, structured logs, alerts, and operational observability.
[x] src/etdag.rs                                     # Encrypted Transaction DAG protected transaction behavior.
[x] src/p2p.rs                                       # General P2P metrics.
[x] src/sentry.rs                                    # Sentry public/VPN forwarding, drop, queue, failover, and validator-path metrics.
[x] src/cross_chain.rs                               # Cross-Chain relay/verify/adapters/receipts/finality-proof metrics.
[x] src/ai.rs                                        # AI workload/capability/GPU/receipt/data/assurance metrics.
[x] src/sync.rs                                      # Verified head/block/state/snapshot synchronization and recovery.
[x] src/vpn.rs                                       # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[x] src/storage.rs                                   # Durable database/WAL/integrity/pruning/disk safety behavior.
[x] src/alerts.rs                                    # Metrics, traces, structured logs, alerts, and operational observability.
```

### [x] `node-platform/crates/synergy-health/`

**Folder purpose:** First-class `synergy-health` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] src/lib.rs                                       # Subsystem/node health state and diagnostics.
[x] src/status.rs                                    # Subsystem/node health state and diagnostics.
[x] src/checks.rs                                    # Subsystem/node health state and diagnostics.
[x] src/liveness.rs                                  # Subsystem/node health state and diagnostics.
[x] src/readiness.rs                                 # Role-aware readiness evaluation; process-alive is not sufficient.
[x] src/stall.rs                                     # Subsystem/node health state and diagnostics.
[x] src/dependency.rs                                # Subsystem/node health state and diagnostics.
```

### [x] `node-platform/crates/synergy-protocol-types/`

**Folder purpose:** First-class `synergy-protocol-types` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Authority-neutral shared-type package with serde only.
[x] src/lib.rs                                       # Focused canonical exports plus authority-neutral session/routing types.
[x] src/chain.rs                                     # Nonzero chain identity and Genesis-bound chain context.
[x] src/height.rs                                    # Canonical overflow-safe finalized-chain height.
[x] src/epoch.rs                                     # Canonical overflow-safe consensus epoch number.
[x] src/validator.rs                                 # Bounded validator identity only; active authority remains PoSy-owned.
[x] src/cluster.rs                                   # Bounded operational cluster identity that cannot determine authority.
[x] src/hash.rs                                      # Fixed-width opaque protocol commitment.
[x] src/block.rs                                     # Nonzero, non-self-parenting canonical block reference.
[x] src/transaction.rs                               # Nonzero canonical transaction reference with nonce.
[x] src/certificate.rs                               # Opaque typed certificate reference; verification/finality remains with owners.
[x] src/serialization.rs                             # Versioned, overflow-safe, caller-bounded frame descriptor.
```

### [x] `node-platform/crates/synergy-version/`

**Folder purpose:** First-class `synergy-version` subsystem boundary in the production node workspace.

```text
[x] Cargo.toml                                       # Canonical version-domain package with serde-only data dependency.
[x] src/lib.rs                                       # Independent release/protocol/database/config compatibility exports.
[x] src/release.rs                                   # Strict canonical major.minor.patch software release identity.
[x] src/protocol.rs                                  # Independently governed P2P/PoSy/ETDAG/sync/snapshot/Admin versions.
[x] src/database.rs                                  # Database schema version independent from software and protocol.
[x] src/config.rs                                    # Configuration schema version independent from software and protocol.
[x] src/compatibility.rs                             # Explicit supported ranges with unspecified-domain refusal.
[x] src/activation.rs                                # Governed epoch/height activation bound to a commitment.
```

### [ ] `runtime/services/vpn-enrollment-broker/`

**Folder purpose:** Production infrastructure service `vpn-enrollment-broker`; not a substitute for PoSy consensus authority.

```text
[ ] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[ ] src/main.rs                                      # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/server.rs                                    # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/challenge.rs                                 # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/authorization.rs                             # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/chain_verifier.rs                            # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/one_time_key.rs                              # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/peer_binding.rs                              # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/transport_lease.rs                           # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/revocation.rs                                # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/reconciliation.rs                            # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/audit.rs                                     # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/metrics.rs                                   # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] src/providers/mod.rs                             # Module registration and exports.
[ ] src/providers/netbird.rs                         # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
```

### [ ] `runtime/services/bootseed-registry/`

**Folder purpose:** Production infrastructure service `bootseed-registry`; not a substitute for PoSy consensus authority.

```text
[ ] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[ ] src/main.rs                                      # Rust implementation for main within this subsystem.
[ ] src/registry.rs                                  # Rust implementation for registry within this subsystem.
[ ] src/records.rs                                   # Rust implementation for records within this subsystem.
[ ] src/signing.rs                                   # Rust implementation for signing within this subsystem.
[ ] src/verification.rs                              # Rust implementation for verification within this subsystem.
[ ] src/expiry.rs                                    # Rust implementation for expiry within this subsystem.
[ ] src/metrics.rs                                   # Prometheus/operational metric definitions for the owning subsystem.
```

### [ ] `runtime/services/snapshot-publisher/`

**Folder purpose:** Production infrastructure service `snapshot-publisher`; not a substitute for PoSy consensus authority.

```text
[ ] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[ ] src/main.rs                                      # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/publisher.rs                                 # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/manifest.rs                                  # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/signer.rs                                    # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/storage.rs                                   # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/retention.rs                                 # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/metrics.rs                                   # Finality-bound snapshot build/verify/restore/publication behavior.
```

### [ ] `runtime/roles/`

**Folder purpose:** Declarative capability/service/port/storage/key/readiness profiles for every node and infrastructure role.

```text
[ ] validator.toml                                   # Validator PoSy/ETDAG/signing/VPN/sync capability, key, port, service, and readiness profile.
[ ] sentry.toml                                      # Sentry dual-homed public-P2P/VPN forwarding, ACL, peer, filtering, redundancy, and no-consensus-authority profile.
[ ] archive.toml                                     # Archive history, proof reconstruction, snapshot creation/serving, storage, and recovery-source profile.
[ ] consensus_audit.toml                             # Non-signing PoSy/finality/state audit, divergence/equivocation detection, and alerting profile.
[ ] cross_chain.toml                                 # Cross-Chain SXCP relay/verify capabilities, supported-chain adapters, receipt policy, and independence constraints.
[ ] witness.toml                                     # Independent external-chain observation and signed evidence/proof-material profile.
[ ] oracle.toml                                      # Authenticated external data-source, normalization, feed-attestation, and receipt profile.
[ ] uma_coordinator.toml                             # UMA mapping refresh, consistency, recovery, registry, and audit profile.
[ ] synq_execution.toml                              # Deterministic SynQ execution, verification, traces, simulation, and execution-job profile.
[ ] network_analytics.toml                           # Network/chain simulation, anomaly detection, performance/risk analysis, and advisory analytics profile.
[ ] aegis_cryptography.toml                          # Aegis PQC verification, key-lifecycle, KMS/HSM, attestation, and high-security service profile.
[ ] data_availability.toml                           # Protocol data storage, shard/repair/retrieval, proof-availability, and durability profile.
[ ] ai_compute.toml                                  # AI Compute role with inference/embeddings/multimodal/training/fine-tuning/agent-execution capability flags.
[ ] ai_coordination.toml                             # AI Coordination role with routing/GPU scheduling/quota/policy/capacity/federated-coordination capabilities.
[ ] ai_data.toml                                     # AI Data role with model repository/dataset provenance/vector memory/retention/deletion-receipt capabilities.
[ ] ai_assurance.toml                                # AI Assurance role with verification/replay/evaluation/safety/benchmark/reputation capabilities and independence policy.
[ ] rpc_gateway.toml                                 # Public RPC/WS gateway, auth/rate-limit/cache/edge-isolation, state-query, and readiness profile.
[ ] indexer.toml                                     # Finalized-data indexing/search/query/Explorer-backend capability and storage profile.
[ ] observer_light.toml                              # Header/finality-proof/light-state/wallet-feed non-signing observer profile.
[ ] bootseed.toml                                    # Authenticated initial peer discovery/peer-exchange bootstrap profile with no consensus authority.
[ ] infrastructure/snapshot_source.toml              # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] infrastructure/transport_registry.toml           # Raw network route/listen/dial/connection behavior; no consensus decisions.
```

### [ ] `networks/devnet/`

**Folder purpose:** Signed immutable/governed artifacts for Synergy devnet; never per-validator hand-edited configuration.

```text
[ ] network-manifest.json                            # Signed/canonical manifest artifact handling and verification.
[ ] genesis.json                                     # Machine-readable genesis artifact/configuration.
[ ] bootseeds.json                                   # Machine-readable bootseeds artifact/configuration.
[ ] protocol-versions.json                           # Software/protocol/storage/config compatibility and activation.
[ ] roles.json                                       # Declarative node role, capability, service, port, and readiness policy.
[ ] etdag/parameters.json                            # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/fee-schedule.json                          # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/ingress-key-registry.json                  # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/activation.json                            # Encrypted Transaction DAG protected transaction behavior.
```

### [ ] `networks/testnet-v3/`

**Folder purpose:** Signed immutable/governed artifacts for Synergy testnet; never per-validator hand-edited configuration.

```text
[ ] network-manifest.json                            # Signed/canonical manifest artifact handling and verification.
[ ] genesis.json                                     # Automated verification of the owning subsystem or failure mode.
[ ] bootseeds.json                                   # Automated verification of the owning subsystem or failure mode.
[ ] protocol-versions.json                           # Software/protocol/storage/config compatibility and activation.
[ ] roles.json                                       # Declarative node role, capability, service, port, and readiness policy.
[ ] etdag/parameters.json                            # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/fee-schedule.json                          # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/ingress-key-registry.json                  # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/activation.json                            # Encrypted Transaction DAG protected transaction behavior.
```

### [ ] `networks/mainnet/`

**Folder purpose:** Signed immutable/governed artifacts for Synergy mainnet; never per-validator hand-edited configuration.

```text
[ ] network-manifest.json                            # Signed/canonical manifest artifact handling and verification.
[ ] genesis.json                                     # Machine-readable genesis artifact/configuration.
[ ] bootseeds.json                                   # Machine-readable bootseeds artifact/configuration.
[ ] protocol-versions.json                           # Software/protocol/storage/config compatibility and activation.
[ ] roles.json                                       # Declarative node role, capability, service, port, and readiness policy.
[ ] etdag/parameters.json                            # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/fee-schedule.json                          # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/ingress-key-registry.json                  # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag/activation.json                            # Encrypted Transaction DAG protected transaction behavior.
```

### [ ] `runtime/schemas/`

**Folder purpose:** Machine-readable validation schemas for signed artifacts and configuration.

```text
[ ] network-manifest.schema.json                     # Signed/canonical manifest artifact handling and verification.
[ ] node-config.schema.json                          # Typed configuration, validation, defaults, and migration.
[ ] role-profile.schema.json                         # Declarative node role, capability, service, port, and readiness policy.
[ ] transport-lease.schema.json                      # Raw network route/listen/dial/connection behavior; no consensus decisions.
[ ] bootseed-record.schema.json                      # Machine-readable bootseed record.schema artifact/configuration.
[ ] snapshot-manifest.schema.json                    # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] genesis.schema.json                              # Machine-readable genesis.schema artifact/configuration.
[ ] etdag-parameters.schema.json                     # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag-fee-schedule.schema.json                   # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag-ingress-keys.schema.json                   # Encrypted Transaction DAG protected transaction behavior.
[ ] validator-membership.schema.json                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
```

### [ ] `runtime/proto/p2p/`

**Folder purpose:** Language-neutral `p2p` wire/control message definitions where Protobuf remains the chosen encoding.

```text
[ ] handshake.proto                                  # Authenticated chain/network/genesis/identity/protocol negotiation.
[ ] status.proto                                     # Language-neutral wire schema for status messages.
[ ] discovery.proto                                  # Language-neutral wire schema for discovery messages.
[ ] peer_exchange.proto                              # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] errors.proto                                     # Language-neutral wire schema for errors messages.
```

### [ ] `runtime/proto/sync/`

**Folder purpose:** Language-neutral `sync` wire/control message definitions where Protobuf remains the chosen encoding.

```text
[ ] blocks.proto                                     # Verified head/block/state/snapshot synchronization and recovery.
[ ] state.proto                                      # Verified head/block/state/snapshot synchronization and recovery.
[ ] checkpoint.proto                                 # Verified head/block/state/snapshot synchronization and recovery.
[ ] snapshot.proto                                   # Verified head/block/state/snapshot synchronization and recovery.
```

### [ ] `runtime/proto/posy/`

**Folder purpose:** Language-neutral `posy` wire/control message definitions where Protobuf remains the chosen encoding.

```text
[ ] proposal.proto                                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] vote.proto                                       # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] quorum_certificate.proto                         # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] timeout.proto                                    # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] finality.proto                                   # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
```

### [ ] `runtime/proto/etdag/`

**Folder purpose:** Language-neutral `etdag` wire/control message definitions where Protobuf remains the chosen encoding.

```text
[ ] ingress.proto                                    # Encrypted Transaction DAG protected transaction behavior.
[ ] vertex.proto                                     # Encrypted Transaction DAG protected transaction behavior.
[ ] availability.proto                               # Encrypted Transaction DAG protected transaction behavior.
[ ] ordering.proto                                   # Encrypted Transaction DAG protected transaction behavior.
[ ] certificates.proto                               # Encrypted Transaction DAG protected transaction behavior.
[ ] reveal.proto                                     # Encrypted Transaction DAG protected transaction behavior.
[ ] recovery.proto                                   # Encrypted Transaction DAG protected transaction behavior.
```

### [ ] `runtime/proto/admin/`

**Folder purpose:** Language-neutral `admin` wire/control message definitions where Protobuf remains the chosen encoding.

```text
[ ] management.proto                                 # Privileged typed node-management API behavior.
[ ] events.proto                                     # Privileged typed node-management API behavior.
[ ] health.proto                                     # Subsystem/node health state and diagnostics.
[ ] vpn.proto                                        # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
```

### [ ] `runtime/packaging/systemd/`

**Folder purpose:** Native `systemd` packaging/service support for community-operated headless nodes; Docker is not required.

```text
[ ] synergy-node.service                             # Target artifact for synergy node.
[ ] synergy-node.env                                 # Target artifact for synergy node.
[ ] synergy-vpn-enrollment.service                   # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] hardening.conf                                   # Target artifact for hardening.
```

### [ ] `runtime/packaging/deb/`

**Folder purpose:** Native `deb` packaging/service support for community-operated headless nodes; Docker is not required.

```text
[ ] control                                          # Target artifact for control.
[ ] postinst                                         # Target artifact for postinst.
[ ] prerm                                            # Target artifact for prerm.
[ ] postrm                                           # Target artifact for postrm.
```

### [ ] `runtime/packaging/rpm/`

**Folder purpose:** Native `rpm` packaging/service support for community-operated headless nodes; Docker is not required.

```text
[ ] synergy-node.spec                                # Target artifact for synergy node.
```

### [ ] `runtime/packaging/tarball/`

**Folder purpose:** Native `tarball` packaging/service support for community-operated headless nodes; Docker is not required.

```text
[ ] build-release.sh                                 # Release build/sign/verify/publication metadata or tooling.
```

### [ ] `runtime/packaging/install/`

**Folder purpose:** Native `install` packaging/service support for community-operated headless nodes; Docker is not required.

```text
[ ] install.sh                                       # Native operator/release helper for install.
[ ] uninstall.sh                                     # Native operator/release helper for uninstall.
[ ] upgrade.sh                                       # Signed software/protocol upgrade and compatibility workflow.
[ ] verify-release.sh                                # Release build/sign/verify/publication metadata or tooling.
```

### [ ] `runtime/config/`

**Folder purpose:** Shipped safe defaults/examples and common resource/telemetry policies.

```text
[ ] example/validator.toml                              # Production-oriented Validator example with private overlay, Sentry peers, PoSy/ETDAG, and local-only Admin API.
[ ] example/sentry.toml                                 # Dual-homed Sentry example with public P2P, validator overlay, forwarding ACLs, redundancy, and limits.                           # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] example/archive.toml                   # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] example/rpc-gateway.toml                         # Typed configuration, validation, defaults, and migration.
[ ] example/observer.toml                            # Typed configuration, validation, defaults, and migration.
[ ] example/cross_chain.toml                            # Cross-Chain Node example with relay/verify capabilities and supported-chain adapters.
[ ] example/ai-compute.toml                             # AI Compute example with advertised workload/GPU capabilities and receipt policy.                             # Typed configuration, validation, defaults, and migration.
[ ] example/indexer.toml                             # Typed configuration, validation, defaults, and migration.
[ ] logging.toml                                     # Typed configuration, validation, defaults, and migration.
[ ] telemetry.toml                                   # Typed configuration, validation, defaults, and migration.
[ ] limits.toml                                      # Typed configuration, validation, defaults, and migration.
```

### [ ] `runtime/tools/bootstrap/`

**Folder purpose:** Operator/developer `bootstrap` helpers that invoke supported interfaces rather than bypassing safety.

```text
[ ] clean-host.sh                                    # Native operator/release helper for clean host.
[ ] install-node.sh                                  # Native operator/release helper for install node.
[ ] verify-host.sh                                   # Native operator/release helper for verify host.
```

### [ ] `runtime/tools/validator/`

**Folder purpose:** Operator/developer `validator` helpers that invoke supported interfaces rather than bypassing safety.

```text
[ ] generate-identity.sh                             # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] verify-membership.sh                             # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] test-vpn.sh                                      # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] test-peers.sh                                    # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] readiness-report.sh                              # Role-aware readiness evaluation; process-alive is not sufficient.
```

### [ ] `runtime/tools/network/`

**Folder purpose:** Operator/developer `network` helpers that invoke supported interfaces rather than bypassing safety.

```text
[ ] peer-probe.rs                                    # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] latency-test.rs                                  # Automated verification of the owning subsystem or failure mode.
[ ] partition-test.rs                                # Automated verification of the owning subsystem or failure mode.
[ ] protocol-probe.rs                                # Rust implementation for protocol probe within this subsystem.
```

### [ ] `runtime/tools/storage/`

**Folder purpose:** Operator/developer `storage` helpers that invoke supported interfaces rather than bypassing safety.

```text
[ ] verify-db.rs                                     # Durable database/WAL/integrity/pruning/disk safety behavior.
[ ] inspect-wal.rs                                   # Durable database/WAL/integrity/pruning/disk safety behavior.
[ ] corrupt-test-db.rs                               # Durable database/WAL/integrity/pruning/disk safety behavior.
```

### [ ] `runtime/tools/release/`

**Folder purpose:** Operator/developer `release` helpers that invoke supported interfaces rather than bypassing safety.

```text
[ ] build.sh                                         # Release build/sign/verify/publication metadata or tooling.
[ ] sign.sh                                          # Release build/sign/verify/publication metadata or tooling.
[ ] checksum.sh                                      # Release build/sign/verify/publication metadata or tooling.
[ ] verify.sh                                        # Release build/sign/verify/publication metadata or tooling.
[ ] publish.sh                                       # Release build/sign/verify/publication metadata or tooling.
```

### [ ] `runtime/tests/unit/`

**Folder purpose:** Release-gate `unit` test area; tests must actually execute, not merely compile.

```text
[ ] posy/                                            # Subdirectory grouping  fixtures/tests/components.
[ ] etdag/                                           # Subdirectory grouping  fixtures/tests/components.
[ ] p2p/                                             # Subdirectory grouping  fixtures/tests/components.
[ ] sync/                                            # Subdirectory grouping  fixtures/tests/components.
[ ] vpn/                                             # Subdirectory grouping  fixtures/tests/components.
[ ] execution/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] storage/                                         # Subdirectory grouping  fixtures/tests/components.
[ ] management/                                      # Subdirectory grouping  fixtures/tests/components.
```

### [ ] `runtime/tests/integration/`

**Folder purpose:** Release-gate `integration` test area; tests must actually execute, not merely compile.

```text
[ ] startup.rs                                       # Automated verification of the owning subsystem or failure mode.
[ ] shutdown.rs                                      # Automated verification of the owning subsystem or failure mode.
[ ] peer_discovery.rs                                # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] peer_authentication.rs                           # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] block_sync.rs                                    # Verified head/block/state/snapshot synchronization and recovery.
[ ] state_sync.rs                                    # Verified head/block/state/snapshot synchronization and recovery.
[ ] snapshot_restore.rs                              # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] validator_join.rs                                # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] validator_remove.rs                              # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] validator_restart.rs                         # Active validator restart/recovery integration.
[ ] sentry_perimeter.rs                          # Public peer ↔ Sentry ↔ validator VPN message-path and filtering integration.
[ ] sentry_failover.rs                           # Validator multi-Sentry redundancy/failover integration.
[ ] cross_chain_independence.rs                  # Cross-Chain relay/verify same-role independence acceptance integration.
[ ] ai_capability_roles.rs                       # Four canonical AI roles expose all former workload capabilities correctly.                             # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] vpn_enrollment.rs                                # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] etdag_ingress.rs                                 # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag_reveal.rs                                  # Encrypted Transaction DAG protected transaction behavior.
[ ] admin_api.rs                                     # Privileged typed node-management API behavior.
[ ] cli_parity.rs                                    # Automated verification of the owning subsystem or failure mode.
[ ] control_panel_parity.rs                          # Automated verification of the owning subsystem or failure mode.
[ ] role_isolation.rs                                # Declarative node role, capability, service, port, and readiness policy.
```

### [ ] `runtime/tests/consensus/`

**Folder purpose:** Release-gate `consensus` test area; tests must actually execute, not merely compile.

```text
[ ] normal_progress.rs                               # Automated verification of the owning subsystem or failure mode.
[ ] proposer_failure.rs                              # Automated verification of the owning subsystem or failure mode.
[ ] dropped_vote.rs                                  # Automated verification of the owning subsystem or failure mode.
[ ] duplicate_vote.rs                                # Automated verification of the owning subsystem or failure mode.
[ ] delayed_vote.rs                                  # Automated verification of the owning subsystem or failure mode.
[ ] reordered_vote.rs                                # Automated verification of the owning subsystem or failure mode.
[ ] timeout_recovery.rs                              # Automated verification of the owning subsystem or failure mode.
[ ] compatible_certificates.rs                       # Automated verification of the owning subsystem or failure mode.
[ ] conflicting_certificates.rs                      # Automated verification of the owning subsystem or failure mode.
[ ] restart_before_persist.rs                        # Automated verification of the owning subsystem or failure mode.
[ ] restart_after_persist.rs                         # Automated verification of the owning subsystem or failure mode.
[ ] restart_after_send.rs                            # Automated verification of the owning subsystem or failure mode.
[ ] partial_broadcast_restart.rs                     # Automated verification of the owning subsystem or failure mode.
[ ] membership_epoch_transition.rs                   # Automated verification of the owning subsystem or failure mode.
[ ] shadow_activation.rs                             # Automated verification of the owning subsystem or failure mode.
[ ] finality_safety.rs                               # Automated verification of the owning subsystem or failure mode.
```

### [ ] `runtime/tests/etdag/`

**Folder purpose:** Release-gate `etdag` test area; tests must actually execute, not merely compile.

```text
[ ] encryption.rs                                    # Encrypted Transaction DAG protected transaction behavior.
[ ] malformed_ciphertext.rs                          # Encrypted Transaction DAG protected transaction behavior.
[ ] target_admission.rs                              # Encrypted Transaction DAG protected transaction behavior.
[ ] nonce_window.rs                                  # Encrypted Transaction DAG protected transaction behavior.
[ ] dag_dependencies.rs                              # Encrypted Transaction DAG protected transaction behavior.
[ ] deterministic_ordering.rs                        # Encrypted Transaction DAG protected transaction behavior.
[ ] availability_certificate.rs                      # Encrypted Transaction DAG protected transaction behavior.
[ ] protected_cut.rs                                 # Encrypted Transaction DAG protected transaction behavior.
[ ] reveal_gate.rs                                   # Encrypted Transaction DAG protected transaction behavior.
[ ] decrypt_shares.rs                                # Encrypted Transaction DAG protected transaction behavior.
[ ] invalid_reveal.rs                                # Encrypted Transaction DAG protected transaction behavior.
[ ] batch_execution.rs                               # Encrypted Transaction DAG protected transaction behavior.
[ ] restart_recovery.rs                              # Encrypted Transaction DAG protected transaction behavior.
[ ] resource_exhaustion.rs                           # Encrypted Transaction DAG protected transaction behavior.
```

### [ ] `runtime/tests/networking/`

**Folder purpose:** Release-gate `networking` test area; tests must actually execute, not merely compile.

```text
[ ] bootseed_failure.rs                              # Automated verification of the owning subsystem or failure mode.
[ ] stale_peer.rs                                    # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] malicious_peer.rs                                # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] duplicate_connection.rs                          # Automated verification of the owning subsystem or failure mode.
[ ] handshake_timeout.rs                             # Authenticated chain/network/genesis/identity/protocol negotiation.
[ ] protocol_mismatch.rs                             # Automated verification of the owning subsystem or failure mode.
[ ] frame_limits.rs                                  # Automated verification of the owning subsystem or failure mode.
[ ] backpressure.rs                              # Bounded queue/backpressure behavior under slow consumers.
[ ] sentry_acl.rs                                # Only permitted protocol/message classes cross the Sentry public↔validator boundary.
[ ] sentry_filtering.rs                          # Malformed/incompatible/abusive public traffic is rejected before validator forwarding.
[ ] sentry_redundancy.rs                         # Multiple Sentry paths avoid a single-perimeter-node liveness dependency.                                  # Automated verification of the owning subsystem or failure mode.
[ ] peer_churn.rs                                    # Authenticated peer discovery/lifecycle/state/routing behavior.
```

### [ ] `runtime/tests/sync/`

**Folder purpose:** Release-gate `sync` test area; tests must actually execute, not merely compile.

```text
[ ] dishonest_head.rs                                # Verified head/block/state/snapshot synchronization and recovery.
[ ] missing_blocks.rs                                # Verified head/block/state/snapshot synchronization and recovery.
[ ] corrupt_block.rs                                 # Verified head/block/state/snapshot synchronization and recovery.
[ ] source_failure.rs                                # Verified head/block/state/snapshot synchronization and recovery.
[ ] corrupt_snapshot.rs                              # Verified head/block/state/snapshot synchronization and recovery.
[ ] interrupted_snapshot.rs                          # Verified head/block/state/snapshot synchronization and recovery.
[ ] multi_source_failover.rs                         # Verified head/block/state/snapshot synchronization and recovery.
```

### [ ] `runtime/tests/vpn/`

**Folder purpose:** Release-gate `vpn` test area; tests must actually execute, not merely compile.

```text
[ ] zero_touch_join.rs                           # Fresh authorized Validator enrolls without administrator intervention.
[ ] sentry_scope.rs                              # Sentry overlay membership/ACL works without granting validator authority.
[ ] sentry_enrollment.rs                         # Authorized Sentry can enroll/rotate/recover its overlay identity under Sentry scope.                               # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] unauthorized_join.rs                             # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] reused_enrollment_key.rs                         # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] broker_restart.rs                                # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] management_outage.rs                             # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] ip_change.rs                                     # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] key_rotation.rs                                  # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] validator_revocation.rs                          # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] stale_transport_lease.rs                         # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] simultaneous_join.rs                             # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
[ ] mass_restart.rs                                  # Dedicated validator overlay transport, enrollment, lease, and recovery behavior.
```

### [ ] `runtime/tests/partitions/`

**Folder purpose:** Release-gate `partitions` test area; tests must actually execute, not merely compile.

```text
[ ] half_split.rs                                    # Automated verification of the owning subsystem or failure mode.
[ ] minority_partition.rs                            # Automated verification of the owning subsystem or failure mode.
[ ] asymmetric_partition.rs                          # Automated verification of the owning subsystem or failure mode.
[ ] isolated_validator.rs                            # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] heal_and_resume.rs                               # Automated verification of the owning subsystem or failure mode.
```

### [ ] `runtime/tests/adverse_network/`

**Folder purpose:** Release-gate `adverse_network` test area; tests must actually execute, not merely compile.

```text
[ ] latency.rs                                       # Automated verification of the owning subsystem or failure mode.
[ ] jitter.rs                                        # Automated verification of the owning subsystem or failure mode.
[ ] packet_loss.rs                                   # Automated verification of the owning subsystem or failure mode.
[ ] bandwidth.rs                                     # Automated verification of the owning subsystem or failure mode.
[ ] connection_churn.rs                              # Automated verification of the owning subsystem or failure mode.
```

### [ ] `runtime/tests/upgrade/`

**Folder purpose:** Release-gate `upgrade` test area; tests must actually execute, not merely compile.

```text
[ ] mixed_versions.rs                                # Software/protocol/storage/config compatibility and activation.
[ ] pre_activation.rs                                # Signed software/protocol upgrade and compatibility workflow.
[ ] activation_height.rs                             # Signed software/protocol upgrade and compatibility workflow.
[ ] incompatible_version.rs                          # Software/protocol/storage/config compatibility and activation.
[ ] rollback.rs                                      # Signed software/protocol upgrade and compatibility workflow.
[ ] database_migration.rs                            # Database inspection/open/repair/migration behavior.
```

### [ ] `runtime/tests/roles/`

**Folder purpose:** Release-gate `roles` test area; tests must actually execute, not merely compile.

```text
[ ] validator.rs                                     # Validator services, authorization, PoSy signing, ETDAG, VPN, sync, and readiness isolation tests.
[ ] sentry.rs                                        # Sentry public/VPN forwarding ACL, no-signing, redundancy, filtering, failover, and readiness tests.
[ ] archive.rs                                       # Archive storage/history/proof/snapshot/recovery-source capability and readiness tests.
[ ] consensus_audit.rs                               # Consensus Audit non-signing verification, divergence/equivocation detection, and isolation tests.
[ ] cross_chain.rs                                   # Cross-Chain relay/verify capability, supported-chain, receipt, and self-verification-independence tests.
[ ] witness.rs                                       # Witness observation/evidence integrity and role-isolation tests.
[ ] oracle.rs                                        # Oracle source-auth/feed-attestation/integrity and role-isolation tests.
[ ] uma_coordinator.rs                               # UMA mapping/refresh/recovery/audit role tests.
[ ] synq_execution.rs                                # SynQ deterministic execution/trace/job role tests.
[ ] network_analytics.rs                             # Network analytics simulation/anomaly/risk/report isolation tests.
[ ] aegis_cryptography.rs                            # Aegis key-custody/PQC/attestation/KMS role tests.
[ ] data_availability.rs                             # DA durability/retrieval/proof/repair role tests.
[ ] ai_compute.rs                                    # AI Compute capability, GPU/resource, sandbox, receipt, and role-isolation tests.
[ ] ai_coordination.rs                               # AI Coordination routing/scheduling/federated/quota/capacity role tests.
[ ] ai_data.rs                                       # AI Data model/dataset/vector-memory isolation, durability, provenance, and deletion tests.
[ ] ai_assurance.rs                                  # AI Assurance verification/evaluation/reputation/independence and receipt tests.
[ ] rpc_gateway.rs                                   # RPC/WS public-edge, rate-limit/auth/cache, no-privileged-control role tests.
[ ] indexer.rs                                       # Indexer finalized-data freshness/query/search/Explorer-backend role tests.
[ ] observer_light.rs                                # Observer/light header/finality-proof/wallet-feed non-signing role tests.
[ ] capability_isolation.rs                          # Cross-role forbidden-service/key/signing/capability isolation tests for all 20 canonical roles.
```

### [ ] `runtime/tests/fixtures/`

**Folder purpose:** Release-gate `fixtures` test area; tests must actually execute, not merely compile.

```text
[ ] manifests/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] genesis/                                         # Subdirectory grouping  fixtures/tests/components.
[ ] validator_sets/                                  # Subdirectory grouping  fixtures/tests/components.
[ ] certificates/                                    # Subdirectory grouping  fixtures/tests/components.
[ ] etdag/                                           # Subdirectory grouping  fixtures/tests/components.
[ ] snapshots/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] corrupted/                                       # Subdirectory grouping  fixtures/tests/components.
```

### [ ] `runtime/simulation/`

**Folder purpose:** Deterministic multi-node/fault simulator with virtual time/network for PoSy and ETDAG safety/liveness.

```text
[ ] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[ ] src/main.rs                                      # Rust implementation for main within this subsystem.
[ ] src/cluster.rs                                   # Rust implementation for cluster within this subsystem.
[ ] src/virtual_network.rs                           # Rust implementation for virtual network within this subsystem.
[ ] src/virtual_clock.rs                             # Rust implementation for virtual clock within this subsystem.
[ ] src/validator.rs                                  # Simulated Validator runtime/adapter.
[ ] src/sentry.rs                                    # Simulated dual-homed Sentry forwarding/failover node.                                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] src/fault.rs                                     # Rust implementation for fault within this subsystem.
[ ] src/partition.rs                                 # Rust implementation for partition within this subsystem.
[ ] src/latency.rs                                   # Rust implementation for latency within this subsystem.
[ ] src/packet_loss.rs                               # Rust implementation for packet loss within this subsystem.
[ ] src/disk_failure.rs                              # Rust implementation for disk failure within this subsystem.
[ ] src/crash.rs                                     # Rust implementation for crash within this subsystem.
[ ] src/byzantine.rs                                 # Rust implementation for byzantine within this subsystem.
[ ] src/invariant.rs                                 # Rust implementation for invariant within this subsystem.
[ ] src/report.rs                                    # Rust implementation for report within this subsystem.
```

### [ ] `runtime/fuzz/`

**Folder purpose:** Parser/protocol/artifact fuzz harness.

```text
[ ] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[ ] fuzz_targets/p2p_frame.rs                        # Malformed/untrusted input fuzz target.
[ ] fuzz_targets/handshake.rs                        # Authenticated chain/network/genesis/identity/protocol negotiation.
[ ] fuzz_targets/block.rs                            # Canonical block representation, validation, import, or construction.
[ ] fuzz_targets/transaction.rs                      # Malformed/untrusted input fuzz target.
[ ] fuzz_targets/posy_vote.rs                        # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] fuzz_targets/posy_certificate.rs                 # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] fuzz_targets/etdag_envelope.rs                   # Encrypted Transaction DAG protected transaction behavior.
[ ] fuzz_targets/etdag_vertex.rs                     # Encrypted Transaction DAG protected transaction behavior.
[ ] fuzz_targets/etdag_certificate.rs                # Encrypted Transaction DAG protected transaction behavior.
[ ] fuzz_targets/etdag_reveal.rs                     # Encrypted Transaction DAG protected transaction behavior.
[ ] fuzz_targets/snapshot_manifest.rs                # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] fuzz_targets/network_manifest.rs                 # Signed/canonical manifest artifact handling and verification.
```

### [ ] `runtime/benches/`

**Folder purpose:** Performance regression benchmarks that never replace correctness tests.

```text
[ ] p2p.rs                                           # Rust implementation for p2p within this subsystem.
[ ] signature_verification.rs                        # Rust implementation for signature verification within this subsystem.
[ ] block_validation.rs                              # Canonical block representation, validation, import, or construction.
[ ] state_transition.rs                              # Canonical blockchain state, overlays, roots, proofs, and transitions.
[ ] etdag_encryption.rs                              # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag_validation.rs                              # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag_ordering.rs                                # Encrypted Transaction DAG protected transaction behavior.
[ ] etdag_reveal.rs                                  # Encrypted Transaction DAG protected transaction behavior.
[ ] posy_vote_processing.rs                          # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] certificate_validation.rs                        # Rust implementation for certificate validation within this subsystem.
[ ] storage.rs                                       # Durable database/WAL/integrity/pruning/disk safety behavior.
```

### [~] `07-Node-Control-Panel/control-service/`

**Folder purpose:** Native authenticated Control Panel bridge to the same typed Admin API used by the CLI.

```text
[x] Cargo.toml                                       # Rust package/workspace manifest and dependency boundary.
[x] Cargo.lock                                       # Locked dependency graph for reproducible builds.
[x] src/lib.rs                                       # Rust implementation for lib within this subsystem.
[x] src/node_admin_client.rs                         # Privileged typed node-management API behavior.
[x] src/control_service.rs                           # Rust implementation for control service within this subsystem.
[x] src/ncp_node.rs                                  # Rust implementation for ncp node within this subsystem.
[ ] src/validator_vpn.rs
[ ] src/sentry.rs                                    # Typed Sentry path/ACL/peer/forwarding/failover/diagnostics client.
[ ] src/cross_chain.rs                               # Typed Cross-Chain relay/verify capability, adapter, receipt, and independence-status client.
[ ] src/ai.rs                                        # Typed AI Compute/Coordination/Data/Assurance capabilities, resources, jobs, receipts, data, and status client.
[ ] src/node_lifecycle.rs                            # Rust implementation for node lifecycle within this subsystem.
[ ] src/node_config.rs                               # Typed configuration, validation, defaults, and migration.
[ ] src/peers.rs                                     # Authenticated peer discovery/lifecycle/state/routing behavior.
[ ] src/sync.rs                                      # Verified head/block/state/snapshot synchronization and recovery.
[ ] src/validator.rs                                 # Validator identity, lifecycle, authority, onboarding, or role-specific behavior.
[ ] src/posy.rs                                      # Proof-of-Synergy consensus-specific behavior; no imported PoS semantics.
[ ] src/etdag.rs                                     # Encrypted Transaction DAG protected transaction behavior.
[ ] src/snapshots.rs                                 # Finality-bound snapshot build/verify/restore/publication behavior.
[ ] src/upgrades.rs                                  # Signed software/protocol upgrade and compatibility workflow.
[ ] src/diagnostics.rs                               # Rust implementation for diagnostics within this subsystem.
[ ] src/events.rs                                    # Typed real-time node management/status events.
[ ] src/monitor.rs                                   # Rust implementation for monitor within this subsystem.
[ ] src/testnet.rs                                   # Automated verification of the owning subsystem or failure mode.
```

### [ ] `07-Node-Control-Panel/renderer/`

**Folder purpose:** GUI presentation surfaces with practical parity for node creation, operation, monitoring, troubleshooting, and recovery.

```text
[ ] node-setup/                                      # Subdirectory grouping  fixtures/tests/components.
[ ] dashboard/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] operations/                                      # Subdirectory grouping  fixtures/tests/components.
[ ] validator/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] sentry/                                         # Sentry public↔VPN perimeter, validator-path health, forwarding, filtering, and failover UI.
[ ] cross-chain/                                    # Cross-Chain relay/verification capability, external-chain adapter, receipt, and independence status UI.
[ ] ai/                                             # AI role/capability, resource, workload, receipt, data, coordination, and assurance UI.
[ ] vpn/                                             # Subdirectory grouping  fixtures/tests/components.
[ ] peers/                                           # Subdirectory grouping  fixtures/tests/components.
[ ] sync/                                            # Subdirectory grouping  fixtures/tests/components.
[ ] posy/                                            # Subdirectory grouping  fixtures/tests/components.
[ ] etdag/                                           # Subdirectory grouping  fixtures/tests/components.
[ ] storage/                                         # Subdirectory grouping  fixtures/tests/components.
[ ] telemetry/                                       # Subdirectory grouping  fixtures/tests/components.
[ ] diagnostics/                                     # Subdirectory grouping  fixtures/tests/components.
[ ] upgrades/                                        # Subdirectory grouping  fixtures/tests/components.
[ ] settings/                                        # Subdirectory grouping  fixtures/tests/components.
```

## Current migration-source files that must be retired or reduced

These are **not the desired final ownership model**, but they currently contain implementation that must be moved without losing behavior or user changes:

```text
[x] runtime/src/node_management.rs                # Current runtime dispatcher; migrate stable operations into node-core/Admin handlers.
[x] runtime/src/role_runtime.rs                   # Current Admin API lifecycle wiring; migrate to node supervisor/lifecycle ownership.
[~] runtime/src/role_profiles.rs                  # Canonical 20-role profile boundary now exists; role capability graphs, manifests, Admin/CLI/GUI integration, and role-completion evidence remain.
[~] runtime/src/bin/synergy-node.rs              # Current CLI entrypoint; reduce to thin package/client after modular CLI migration.
[~] runtime/src/synergy_types.rs                 # Oversized shared type owner; split into focused protocol/identity/state types.
[~] runtime/src/consensus/                       # Current PoSy source; migrate into first-class synergy-posy without changing consensus semantics.
[~] runtime/src/etdag.rs                         # Current monolithic ETDAG; retire only after full protected-pipeline extraction/recovery tests.
[x] runtime/src/p2p/transport.rs                 # Extracted endpoint logic; eventual owner is synergy-network transport/address.
[x] runtime/src/p2p/handshake.rs                 # Extracted handshake signing/policy; eventual owner is synergy-network handshake.
[x] runtime/src/p2p/vpn.rs                       # Extracted VPN route policy; eventual owner is synergy-vpn route policy.
[x] runtime/src/p2p/peer_lifecycle.rs            # Initial peer lifecycle extraction; full peer manager/state/backpressure still incomplete.
[x] runtime/src/p2p/validator_transport_registry.rs # Existing signed route registry; migrate to synergy-transport-registry.
[~] runtime/src/p2p/networking.rs                # Remaining networking god module; must be retired or reduced to a tiny compatibility facade.
[~] runtime/src/sync/                            # Current synchronization source; migrate to first-class synergy-sync.
[~] runtime/synq-language/                       # Existing SynQ implementation dependency; retain behind synergy-synq adapter.
[~] runtime/aegis-pqvm/                          # Existing Aegis implementation dependency; retain behind synergy-aegis adapter.
[~] runtime/synergy-aivm/                        # Existing AIVM implementation; retain behind synergy-aivm adapter.
```

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


## Non-negotiable final architecture invariants

- Proof-of-Synergy owns consensus/finality. P2P transports; sync verifies/acquires; ETDAG protects/orders/reveals; execution computes deterministic state transitions.
- PoSy is not Proof-of-Stake. Stake remains economic/security participation logic and cannot silently become consensus authority.
- Approved non-uniform PoSy weights may remain only where the authoritative PoSy specification defines them; do not infer them from stake.
- Synergy Score does not determine finality.
- VPN membership is transport only and never grants validator authority. Validator and Sentry overlay scopes are distinct and enforced.
- Cross-Chain relay and verification are capabilities of one Cross-Chain Node role, with protocol-enforced independence for the same acceptance decision.
- AI is represented by four canonical roles—Compute, Coordination, Data, Assurance—with fine-grained workloads expressed as capabilities, not additional node types.
- Node identity follows the Synergy node-address identity rule and separate domain keys are cryptographically bound without unsafe key reuse.
- One shared management implementation serves the CLI and Node Control Panel. The GUI must not shell out to CLI commands or scrape text.
- One node distribution composes validated role capability graphs rather than maintaining unrelated node implementations.
- `networking.rs`, monolithic ETDAG ownership, and oversized shared-type ownership are migration artifacts, not acceptable final boundaries.
- Native headless installation is first-class; Docker is not required.
- Tests, simulation, fuzzing, packaging, schemas, docs, release tooling, and soak evidence are part of production readiness.


> **Canonical-root migration note (2026-09-15):** The only node-platform tree is now physically rooted at `synergy-val4:/home/node/Synergy-Network/01-Core-Protocol/node-platform`. `networks/`, `protocol/`, and `tooling/` are siblings. A directory's existence never earns `[x]`; ownership, callers, legacy retirement, and verification remain distinct.
