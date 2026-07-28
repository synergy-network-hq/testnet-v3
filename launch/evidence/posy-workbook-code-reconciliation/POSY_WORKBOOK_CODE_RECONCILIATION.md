# PoSy v2.2 workbook to current-code reconciliation

Status: **all 844 Parameter Register controls checked; Testnet-v3 launch remains blocked**

## Scope and method

- Source workbook SHA-256: `f84846ca688b40c77893c3b9ace18b5f8a14ddf52a96a1875bddc871f357736e`
- Current indexed working-tree SHA-256: `71644ce9807cbbaf462b0bed667ad5350929d0577051e3673c59a6db1b9e0b33`
- Indexed files: 3586
- Controls: 844 unique IDs
- Mechanical pass: exact symbols/config keys across active code, config, tests, templates, docs, and legacy paths.
- Semantic pass: token-cooccurrence candidates used only to locate code.
- Adjudication pass: every row classified separately for component implementation, production integration, verification evidence, and final launch gate.

## Decisive result

The current tree now contains tested typed PoSy and ETDAG components that make many workbook divergence statements stale. However, `runtime/src/role_runtime.rs:931-935` deliberately returns `POSY_V2_2_OPERATIONAL_COORDINATOR_NOT_READY`. The validator production path therefore cannot start the typed coordinator. No component-only PASS is treated as production readiness.

Focused suites run during this audit: **49 passed, 0 failed**.

## Component status counts

- IMPLEMENTED_TESTED_COMPONENT: 259
- NOT_APPLICABLE_DISABLED_PROFILE: 19
- NO_LIVE_CAPACITY_EVIDENCE: 16
- NO_RELEASE_GATE_EVIDENCE: 44
- PARTIAL_IMPLEMENTATION: 336
- PARTIAL_NOT_BOUND_TO_TYPED_RUNTIME: 131
- PARTIAL_OPTIONAL_COMPONENT: 19
- PARTIAL_TEST_COVERAGE: 1
- PARTIAL_TYPED_EVIDENCE_PATH: 5
- PARTIAL_TYPED_RECOVERY_IMPLEMENTATION: 13
- WALLET_PRODUCTION_PATH_MISSING: 1

## Workbook alignment

- RECORDED_DIVERGENCE_STILL_MATERIAL: 72
- REVIEWED_NO_RECORDED_DIVERGENCE: 666
- STALE_SUPERSEDED_BY_CURRENT_COMPONENT_CODE: 106

The 106 rows marked `STALE_SUPERSEDED_BY_CURRENT_COMPONENT_CODE` are not automatically launch-ready. They indicate only that the workbook's recorded description of missing code is no longer current.

## Approved parameter resolution

- `CRYPTO-001`: workbook proposes ML-DSA-87 for validator consensus; current approved code uses ML-DSA-65 for consensus and ML-DSA-87 for the account/SynQ domain.
- `EPOCH-001`: Decision `TV3-POSY-PARAMS-2026-07-28-01` finalizes 1,000 slots. The competing 7,200-slot fixture was replaced, and 3,600 slots is explicitly deferred.
- `TIME-001` / `TIME-002`: the finalized manifest and source Genesis now use 1,500 ms for proposal, prevote, and precommit. The old Genesis proposal/validation fields were removed.
- `TIME-030`: the finalized manifest and source Genesis now use a 10,000 ms maximum round timeout. The 30,000 ms value is explicitly deferred.
- Healthy-path targets (450 ms proposal, 1,850 ms QC, 2,250 ms commit, 2,500 ms p95 finality, and 3,000 ms p99 finality) remain performance gates and are not consensus timeouts.
- `PID-002`: workbook text still describes PoSy 2.1 while current typed code requires `posy/2.2`.

## Remaining launch-critical blockers derived from the row audit

1. Wire the typed PoSy/ETDAG coordinator into the production role runtime and prove it is the only reachable validator signing path.
2. Complete a fresh custody-prompted ceremony execution and bind the already-approved parameter root into the final deployed Genesis artifact.
3. Implement production wallet-local ETDAG sealing across supported send paths; registry flags and runtime test helpers are insufficient.
4. Complete distributed ETDAG/P2P reveal orchestration and hard resource isolation.
5. Complete security, formal/adversarial, live capacity, 10,000-block timing, recovery rehearsal, and rollout evidence.

The full row-level record is in `posy-code-reconciliation.adjudicated.json` and the reconciled workbook.
