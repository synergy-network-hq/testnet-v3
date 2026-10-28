# Protocol State-Sync Repair Runbook

Status: **historical pre-P3 offline fixture procedure.** Its Chain `1264` /
`synergy-testnet-v3` examples are retained as compatibility evidence only and
must not be used for the fresh Chain `1266` / network `testnet` / `posy/3.0`
chain. P3 repair requires independently verified P3 material, QC/TC ancestry,
typed Genesis or v3 transition authority, and separate qualification.

This runbook is for offline planning and deterministic test fixtures. It does
not authorize live validator restarts, binary deployment, archive snapshot use,
or mutation of live validator chain data.

## Safety Boundary

- Do not manually edit `chain.json`, `canonical_locks.json`,
  `committed_qcs.jsonl`, checkpoint files, or derived indexes to force recovery.
  Protocol-native state-sync repair and supervisor state flow replace manual
  JSON/JSONL consensus surgery.
- Use protocol-native block body, committed-QC, and canonical-lock proofs from
  canonical peers.
- Do not use archive snapshots unless archive canonical reseed has been
  completed and separately authorized.
- Do not select a source by raw height alone.
- Do not fabricate compact-boundary finality when QC or checkpoint evidence is
  absent.
- Live validator paths must not be used by the apply command. The offline apply
  path requires a `STATE_SYNC_OFFLINE_WORKSPACE` marker in the workspace and is
  intended for deterministic fixtures and future rollout rehearsal only.

## Dry-Run Planner

```bash
synergy-node validator state-sync-plan \
  --request request.json \
  --source-proof source-proof.json \
  --transfer-proof transfer-proof.json \
  --state-root /path/to/validator-runtime \
  --output state-sync-plan.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The planner returns `DRY_RUN_GO` only when:

- request, source proof, and transfer proof use `synergy-state-sync-v1`;
- chain ID, network ID, and genesis hash match Testnet v3;
- the source common block exactly matches the local tip;
- the source target block exactly matches the requested repair target;
- the source is not quarantined, stale, unverified, or archive-backed;
- Aegis PQC QC, parent continuity, and state-root checks are recorded as true;
- block body, committed-QC, and canonical-lock spans all cover the full repair
  interval;
- the source proof declares a validator cluster id and majority-branch proof;
  and
- local state verification passes when `--state-root` is supplied.

## Offline Repair Apply

```bash
synergy-node validator state-sync repair \
  --plan state-sync-plan.json \
  --workspace /path/to/offline-fixture-workspace \
  --dry-run \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator state-sync repair \
  --plan state-sync-plan.json \
  --workspace /path/to/offline-fixture-workspace \
  --apply \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The workspace must contain:

- `STATE_SYNC_OFFLINE_WORKSPACE`;
- `data/chain.json`;
- `data/canonical_locks.json`;
- `data/committed_qcs.jsonl`;
- `data/state_checkpoint.json` when the retained state is compacted; and
- `state_sync_repair_bundle/` containing `chain.json`,
  `canonical_locks.json`, `committed_qcs.jsonl`, and `repair_manifest.json`.

The repair bundle manifest must match the plan transfer id, transfer content
digest, source node, source role, source cluster id, validator-set digest,
cluster-map digest, and protocol config digest. Config digest mismatch is
accepted only when the manifest explicitly lists the plan digest as compatible.

`--apply` is atomic for the offline workspace:

1. verify the plan and bundle evidence;
2. create a backup of `data/`;
3. stage repairs in a temporary workspace;
4. verify body, QC, lock, checkpoint, and local anchor invariants;
5. rebuild derived indexes in the staged workspace;
6. write `state_sync_repair_receipt.json`; and
7. swap the repaired `data/` directory into place only after all checks pass.

The receipt records the plan hash, transfer id, transfer digest, source node,
source cluster id, height range, backup path, repaired data path, derived-index
rebuild status, and `qc_fabricated=false`.

## Rejection Cases

The planner must return `NO_GO` for:

- body-only transfers;
- QC-only transfers;
- lock-only transfers;
- divergent common block or target hash;
- stale source peer;
- quarantined or unverified source peer;
- partial transfer;
- archive validator or snapshot-manifest source;
- public RPC-only or Atlas-only source proof;
- missing cluster id or missing majority-branch proof;
- mismatched validator-set, cluster-map, or unapproved config digest;
- missing block body, committed QC, or canonical lock in the repair bundle;
- local state verification failure; and
- local tip mismatch between request and inspected state.

## Live Rollout Limitation

The apply path is offline only in this branch. It does not authorize live
validator deployment, restart, service mutation, archive snapshot use, or direct
repair of a live validator data directory. A future live rollout must rehearse
the same command against copied fixture workspaces first, then follow the
one-validator-at-a-time runtime rollout runbook with quorum-margin proof.
