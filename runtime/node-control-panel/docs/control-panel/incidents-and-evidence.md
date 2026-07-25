# Incidents And Evidence

Every mutating v2 command and every failed safety gate writes evidence. The UI surfaces evidence before asking the operator to continue.

## Evidence Fields

Evidence entries include:

| Field | Meaning |
| --- | --- |
| `incident_id` | Unique evidence id. |
| `category` | `mutation`, `safety-gate`, `archive`, `state-sync`, `cluster`, or `lifecycle`. |
| `severity` | `info`, `warn`, `fatal`. |
| `command` | Control-service command name. |
| `summary` | Operator-facing message. |
| `node_id` | Validator node id when available. |
| `cluster_id` | Cluster id when available. |
| `evidence_path` | Local JSON receipt path. |
| `created_at` | UTC evidence timestamp. |

## Envelope Contract

The UI consumes `ControlActionEnvelope` fields: `ok`, `command`, `phase`, `node_id`, `cluster_id`, `lifecycle_state`, `status`, `safe_to_continue`, `mutated`, `evidence_path`, `checks`, `blockers`, `warnings`, `next_actions`, `rollback_path`, `operator_message`, and `developer_details`.

Raw errors are translated into structured blockers. Examples include `SNAPSHOT_VERIFIER_CRASHED`, `SNAPSHOT_QUORUM_BELOW_THRESHOLD`, `P2P_PORT_CLOSED`, `WRONG_NETWORK_ID`, `ARCHIVE_NOT_CANONICAL`, `STATE_SYNC_QUORUM_PROOF_MISSING`, and `CONFIRMATION_REQUIRED`.
