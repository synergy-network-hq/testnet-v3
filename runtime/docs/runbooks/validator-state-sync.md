# Validator State-Sync Runbook

This runbook describes the Prompt 2 protocol-native state-sync flow. It is not a
live repair authorization.

## Shared Safety Invariants

- Do not manually edit consensus JSON/JSONL files to repair a validator.
- State-sync requests, source proofs, transfer proofs, repair plans, and
  supervisor transition evidence replace manual consensus-state surgery.
- A source must prove block body, committed-QC, canonical-lock, checkpoint,
  config, validator-set, and cluster identity before it can repair state.
- Public RPC and Atlas evidence can reveal surface disagreement, but public
  RPC-only or Atlas-only proof is not a repair source.
- Archive snapshots are excluded until archive canonical reseed passes and a
  separate authorization allows archive use.
- Current six-validator references are fixtures only. State-sync must use
  dynamic validator and cluster counts.
- No live deployment, validator restart, state mutation, or quorum change is
  allowed without explicit authorization.

## Plan Generation

```bash
synergy-node validator state-sync-plan \
  --request request.json \
  --source-proof source-proof.json \
  --transfer-proof transfer-proof.json \
  --state-root /path/to/offline-copy \
  --output state-sync-plan.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The planner fails closed when the source is stale, minority, quarantined,
unverified, archive-contained, public-RPC-only, Atlas-only, missing QC, missing
body, missing lock, or mismatched on cluster/config/validator-set digests.

## Repair Execution

Use the dedicated repair runbook for apply details:
`docs/runbooks/protocol-state-sync-repair.md`.

```bash
synergy-node validator state-sync repair \
  --plan state-sync-plan.json \
  --workspace /path/to/offline-workspace \
  --dry-run
```

`--apply` is limited to marker-gated offline workspaces in this branch. It
creates a backup, writes into a temporary workspace, verifies invariants,
rebuilds derived indexes, writes a receipt, and swaps repaired state only after
all checks pass. It never fabricates QC and never chooses a branch by raw height
alone.

## Rollout Boundary

Future live use requires explicit authorization, one-validator-at-a-time
rollout, and quorum-margin proof. Rollback is successful only when validator
health, canonical height advancement, public RPC parity, and Atlas exact-height
hash parity where available are proven after rollback.
