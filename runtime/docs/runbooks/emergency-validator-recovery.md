# Emergency Validator Recovery Runbook

This runbook is a Prompt 2 recovery handoff. It does not authorize live
deployment, validator restart, validator chain-state mutation, quorum lowering,
archive validator re-enable, archive snapshot API re-enable, or archive
snapshot worker re-enable.

## Shared Safety Invariants

- Do not manually edit `chain.json`, `canonical_locks.json`,
  `committed_qcs.jsonl`, checkpoint files, supervisor state JSON, or generated
  validator manifests to force recovery.
- Protocol-native state-sync repair and supervisor state transitions replace
  manual JSON/JSONL surgery.
- Archive data and archive snapshots are not valid recovery sources until the
  archive canonical reseed runbook passes and receives explicit authorization.
- The current six validators are live-fleet fixtures, not the final topology.
  Validator and cluster counts are dynamic, and quorum is derived from the
  active validator set.
- No live deploy, restart, rejoin, rollback, archive use, or service mutation is
  allowed without explicit operator authorization.
- Future live rollout proceeds one validator at a time and must never take a
  cluster below quorum margin.
- Rollback success requires health proof: local validator health, canonical
  height advancement, qRPC health, metrics scrape, public RPC parity, and Atlas
  exact-height hash parity where available.
- Archive services remain disabled until canonical reseed passes.

## Triage Order

1. Confirm whether public RPC still advances by reading latest height and latest
   block hash.
2. Confirm validator count, cluster count, and per-cluster quorum margin from
   dynamic fleet evidence. Do not assume six validators or `4-of-6`.
3. Check Atlas only as a public-surface read. Atlas disagreement is backend
   confidence evidence, not proof to rewrite consensus state.
4. Classify affected validators with supervisor evidence. Recovery-state
   validators move through quarantine, state-sync, vote-only, and proposer
   probation gates instead of jumping directly to `ACTIVE`.
5. Build a protocol state-sync plan only from canonical peer evidence with block
   body, committed-QC, canonical-lock, checkpoint, config, validator-set, and
   cluster digest proof.
6. Keep archive out of the repair source set unless canonical reseed has already
   passed and a separate authorization allows archive use.

## Vote-only Probation Promotion

When a validator has rejoined as vote-only, do not manually change supervisor
state to force proposer duties. Use the generic appliance helper to wait on a
public canonical-height gate and then run the supported runtime promotion once:

```bash
scripts/testnet/validator-appliance-recovery.sh wait-promote-vote-only-to-active \
  --target <validator-name-from-workbook> \
  --rejoin-height <height> \
  --probation-blocks <blocks> \
  --public-rpc https://testnet-core-rpc.synergy-network.io \
  --workbook /Users/devpup/Desktop/node-machine-credentials.xlsx \
  --execute
```

The helper polls the public RPC locally during the probation window and opens a
workbook-backed target connection only after the public height is eligible. The
runtime still fails closed if local committed-QC proof, block hash proof, or
vote-lock cleanliness is not sufficient.

## Allowed Offline Commands

```bash
synergy-node validator inspect-state --state-root <copy>
synergy-node validator verify-state --state-root <copy>
synergy-node validator state-sync-plan --request <json> --source-proof <json> --transfer-proof <json> --state-root <copy> --output <plan.json>
synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run
synergy-node validator supervisor-transition --evidence <json> --previous-state <json> --output <transition.json>
synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run
synergy-node fleet status --snapshot <json> --strict
```

The repair and supervisor writers require offline workspace markers. They must
not be pointed at live validator data directories in this branch.

## Future Live Recovery Window

When an operator explicitly opens a live recovery window, perform the same
sequence against copied workspaces first. Only after dry-run evidence passes:

1. Select one validator while keeping every cluster above quorum margin.
2. Record rollback binary, config, validator-set, cluster-map, and state digest.
3. Stop only the selected validator service if authorized.
4. Apply the reviewed repair or supervisor-state write through the approved
   rollout command path.
5. Restart only the selected validator if authorized.
6. Prove post-action health before touching any other validator.

## Rollback Success Evidence

A rollback is not complete until the target validator is healthy, the canonical
chain advances after rollback, public RPC remains synced, Atlas agrees on
sampled exact-height hashes when available, and validator duties match the
supervisor state. If any proof is missing, keep the validator in the appropriate
recovery state and stop the rollout.
