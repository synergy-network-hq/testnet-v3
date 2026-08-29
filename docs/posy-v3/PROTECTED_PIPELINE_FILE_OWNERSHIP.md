# ProtectedPipeline R11 file ownership

Baseline: `a732bc16ff4c5b23561758dad6f05752bd2576c6`

Integration branch: `feat/posy-protected-pipeline-r11`

The primary agent owns architecture, public interfaces, merge order, release
qualification, and every live action. Validators 02-06 remain untouched while
source work and harness qualification are in progress.

| Agent | Task | Files/directories owned | Interfaces consumed | Interfaces produced | Tests required |
|---|---|---|---|---|---|
| PRIMARY | Protocol contract, shared types, integration, release and activation | `docs/posy-v3/PROTECTED_PIPELINE_PROTOCOL.md`, this file, `runtime/src/lib.rs`, `runtime/src/etdag.rs`, `runtime/src/synergy_types.rs`, `runtime/src/role_runtime.rs`, shared module registries and release artifacts | All agent reports and commits | Canonical protected-pipeline interfaces, integrated production path, frozen release | All focused tests, determinism suite, H1-H4, five-node 20-block and restart gates |
| A | Durable per-target coordinator core | New `runtime/src/consensus/protected_pipeline_runtime.rs` and `runtime/src/consensus/protected_pipeline_runtime_tests.rs` only | Existing `ProtectedPipeline`, ETDAG types, and a narrow PRIMARY-registered module interface | Single-writer durable target registry, event ingestion/reconciliation, ready-input publisher and restart recovery | Duplicate/reorder/restart/monotonic-state/coordinator readiness tests |
| B | PoSy / VC / reveal bridge | `runtime/src/consensus/simplified_posy/material.rs`, `runtime/src/consensus/simplified_posy/protected_material.rs`, `runtime/src/consensus/simplified_posy/reliable_delivery.rs`, and integration tests under that directory | A's ready-input lookup trait and existing bootstrap types | H1/H2 bootstrap lookup and H3+ coordinator lookup; commitment, VC reveal, proposal binding | H1/H2 ready-to-propose and certified-pipeline-to-proposal tests |
| C | P2P evidence to coordinator ingest | `runtime/src/p2p/messages.rs`, `runtime/src/p2p/networking.rs`, and their focused tests | A's public coordinator ingress handle; existing authenticated semantic evidence | Authenticated direct coordinator delivery, bounded dedup/recovery, no legacy dependency | Early/late/duplicate/reordered/invalid evidence tests |
| D | Five-node harness | `runtime/src/bin/posy-simplified-five-node-harness.rs`, `runtime/src/bin/posy-simplified-five-driver-harness.rs`, `runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh`, `runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh`, and new harness fixtures only | Integrated runtime interfaces | H1-H4 diagnostics, 20-block/restart qualification at 0.1–1.1s block target | Real five-node state-machine and production-driver runs |
| E | Legacy active-path audit | Read-only; report only in `docs/posy-v3/CURRENT_PROTECTED_FLOW.md` | Current production call graph | ACTIVE/COMPATIBILITY_ONLY/TEST_ONLY/DEAD classification and exact active liveness dependencies | Production-path reference scan |
| F | Node Control Panel operations | `runtime/node-control-panel/` only | Stable abstract read-only consensus and ProtectedPipeline status schema supplied by PRIMARY | Validator discovery, preflight, health, snapshots and first-missing-transition | Expedited NCP acceptance tests |
| G | Release / preflight gate | New release-gate scripts and test fixtures only, named before implementation | Frozen source and governed artifacts supplied by PRIMARY | Clean-source, provenance, Genesis/config/binary/host-stage preflight gates | Release-gate dry-run tests |

## Conflict rules

- Agents may not edit PRIMARY-owned files.
- Any newly discovered central-file dependency is reported before editing.
- No two implementation agents edit the same file.
- Every agent works in its own branch and worktree, commits only owned changes,
  and returns a commit SHA for serial review.
- Subagents never deploy, access live validator state, sign releases, or use
  production keys.
- Merge order is A, PRIMARY module registration, C, B, D, E audit, F (independent
  and non-consensus-critical), G release gate, then full qualification.
