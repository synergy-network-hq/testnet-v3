# ProtectedPipeline R11 file ownership

Baseline: `a732bc16ff4c5b23561758dad6f05752bd2576c6`

Integration branch: `feat/posy-protected-pipeline-r11`

The primary agent owns architecture, public interfaces, merge order, release
qualification, and every live action. Validators 02-06 remain untouched while
source work and harness qualification are in progress.

| Agent | Task | Files/directories owned | Interfaces consumed | Interfaces produced | Tests required |
|---|---|---|---|---|---|
| PRIMARY | Protocol contract, shared types, integration, release and activation | `docs/posy-v3/PROTECTED_PIPELINE_PROTOCOL.md`, this file, `runtime/src/lib.rs`, `runtime/src/etdag.rs`, `runtime/src/synergy_types.rs`, `runtime/src/role_runtime.rs`, shared module registries and release artifacts | All agent reports and commits | Canonical protected-pipeline interfaces, integrated production path, frozen release | All focused tests, determinism suite, H1-H4, five-node 20-block and restart gates |
| A | Current protocol/code map; read-only | No source files. Report only at `docs/posy-v3/CURRENT_PROTECTED_FLOW.md` after reassignment to write | Current VAC, target admission, marker, DCC/BVC/BOC, proposal, VC/QC, reveal, stores, and wire paths | Component/security-purpose/collapse map and exact call sites | Report completeness checks only |
| B | ProtectedPipeline core | New `runtime/src/consensus/protected_pipeline/` directory only | PRIMARY-owned shared ETDAG/types interfaces | Monotonic durable state machine, reconciliation, CutProof and deterministic batch derivation | Unit/property tests for permutation, signer subsets, restart, duplicate and invalid evidence |
| C | PoSy block integration | `runtime/src/consensus/simplified_posy/material.rs`, `runtime/src/consensus/simplified_posy/protected_material.rs`, `runtime/src/consensus/simplified_posy/reliable_delivery.rs`, and a new integration-only test file under `runtime/src/consensus/simplified_posy/` | PRIMARY and B interfaces | Proposal commitment inclusion/validation and n-1 ECHO VC reveal-authorization adapter | Valid commitment, mismatch rejection, parent/target binding, VC/reveal-gate tests |
| D | Genesis/bootstrap | `runtime/src/consensus/testnet_v3_bootstrap.rs` and a new bootstrap-only test file | PRIMARY protected-batch interface | Genesis-bound empty batches and explicit H1/H2 to H3 transition | H1/H2/H3/H4 boundary tests |
| E | ETDAG evidence networking | `runtime/src/p2p/messages.rs`, `runtime/src/p2p/networking.rs`, and new networking-focused tests | PRIMARY evidence types and B semantic IDs | Evidence propagation, bounded deduplication and compatibility decoding | Duplicate/reorder/late evidence and invalid-message tests |
| F | Five-validator/adversarial harness | `runtime/src/bin/posy-simplified-five-node-harness.rs`, `runtime/src/bin/posy-simplified-five-driver-harness.rs`, `runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh`, `runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh`, and new harness fixtures only | Integrated runtime interfaces | H1-H4 diagnostics, 20/100-block and restart/fault qualification | Five-node state-machine and production-driver runs |
| G | Dead-path audit and later removal | Read-only initially. After reassignment, only files explicitly listed in its approved removal patch | Current production call graph | Exact DCC/BVC/BOC/BTC/batch-leader/timeout/target-admission dependency report | Reference scan and production-path absence checks |
| H | Validator Operations API and Node Control Panel | `runtime/node-control-panel/` only | Stable abstract read-only consensus and ProtectedPipeline status schema supplied by PRIMARY | Discovery, preflight, health, service control, snapshots, first-missing-transition and release-mismatch UI/API | Control-service tests and expedited NCP acceptance tests |

## Conflict rules

- Agents may not edit PRIMARY-owned files.
- Any newly discovered central-file dependency is reported before editing.
- No two implementation agents edit the same file.
- Every agent works in its own branch and worktree, commits only owned changes,
  and returns a commit SHA for serial review.
- Subagents never deploy, access live validator state, sign releases, or use
  production keys.
- Merge order is A, PRIMARY interfaces, B, D, C, E, F, G removal, H (independent
  and non-consensus-critical), then full integration and qualification.
