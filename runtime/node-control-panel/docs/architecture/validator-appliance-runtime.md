# Validator Appliance Runtime

The validator appliance model is the runtime filesystem and safety contract used by Node Control Panel v2. It replaces ad hoc validator workspaces as the normal operator path.

## Filesystem Model

Every validator appliance resolves these typed roots:

| Root | Purpose |
| --- | --- |
| `identity/` | Public validator identity metadata and signing key references. |
| `config/` | Rendered `node.toml`, `peers.toml`, runtime env, and generated config receipts. |
| `state/store/` | Primary consensus state store. |
| `state/store/consensus.db` | Primary consensus truth. |
| `state/derived/` | Rebuildable JSON and JSONL state derived from consensus truth. |
| `state/checkpoints/` | Checkpoint lineage used by state verification and state-sync. |
| `state/snapshots/` | Local snapshot cache; not publishable without canonical archive proof. |
| `state/quarantine/` | Unsafe or rejected state artifacts. |
| `evidence/` | Receipts for safety gates, mutations, and failed checks. |
| `logs/` | Runtime and control-service logs. |
| `runtime/releases/` | Installed runtime packages and binary digests. |
| `rollback/` | Rollback manifests written before mutating commands. |

`state/store/consensus.db` or the current runtime equivalent is the only consensus truth. JSON, JSONL, cached snapshots, and rendered summaries are rebuildable.

## Migration Rules

The migration planner inventories a legacy workspace first, then copies identity/config, moves consensus truth into `state/store/`, rebuilds derived state, and records an evidence receipt. Operators must not hand-copy snapshots or edit state files.

## Package Rules

Validator Appliance Packages must declare package version, network id, chain id, supported roles, binary digests, config schema version, state schema version, archive canonical requirement, vote-only rejoin support, state-sync support, dynamic cluster support, minimum Control Panel version, and NO-GO denylist.

Package verification fails closed for unsigned manifests, missing hashes, wrong network, wrong chain, stale schemas, unsupported Control Panel version, NO-GO entries, missing capabilities, or archive dependency on a contained/noncanonical source.

No live deployment or validator restart is implied by this model.
