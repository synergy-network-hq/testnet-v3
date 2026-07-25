# Dynamic Cluster Registry

The Control Panel must treat cluster membership as registry data, not hard-coded topology. The current six-validator testnet is a current registry state, not the final topology.

## Registry Shape

The v2 registry model carries:

| Field | Meaning |
| --- | --- |
| `network_id` | Network scope, currently `synergy-testnet-v3`. |
| `registry_epoch` | Registry version used for stable committee decisions. |
| `clusters[]` | Dynamic cluster list. |
| `cluster_id` | Stable cluster identifier. |
| `status` | `ACTIVE`, `DEGRADED`, `ASSIGNMENT_PENDING`, `VOTE_ONLY`, or `PROPOSER_PROBATION`. |
| `validator_count` | Total validators assigned to the cluster. |
| `active_count` | Validators eligible to vote. |
| `quorum_threshold` | Runtime quorum requirement derived from cluster size. |
| `fault_model` | Fault tolerance model, currently BFT. |
| `fault_tolerance_target` | Current target such as `f=1` or `f=2`. |
| `proposer_schedule_mode` | Dynamic proposer schedule mode. |
| `stable_committee_mode` | Committee pinning mode by registry epoch. |
| `validators[]` | Validator membership and lifecycle state. |
| `liveness_margin` | Active validators minus quorum threshold. |

## Required Fixtures

Control Panel v2 ships registry fixtures for one-cluster six-validator, seven-validator, two-cluster, three-cluster, pending assignment, quarantined, vote-only, and proposer-probation states. Tests must cover each fixture.

## Assignment Rules

Cluster assignment is a preview-then-confirm mutation. The preview must show quorum, active count, liveness margin, capacity, lifecycle mix, and the reason an assignment is blocked. Assignment is disabled when the target cluster would fall below safe quorum margin or when state proof is missing.

Operators must not edit `node-inventory.csv`, peer files, genesis, validator registries, consensus JSON, JSONL, or QC logs to force cluster membership. `node-inventory.csv` is import/export material only and is not protocol truth.
