# Validator State-Sync Runbook

Status: **historical pre-P3 operational tooling with a P3 design note.** The
Chain `1264` / `synergy-testnet-v3` command examples below are not valid P3
commands. Fresh Chain `1266` / network `testnet` state sync must use the typed
Genesis parent and P3 QC/TC/transition proof path and needs a dedicated
qualification runbook before live use.

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

## Proposed PoSy v3 certified reconstruction

For a future activated `posy/3.0` epoch, a peer bundle is acceptable only when
the node independently verifies the pinned epoch context and anchor, every
ML-DSA-65 QC and TC signature, strict dual quorum, consecutive QC ancestry,
sequential TC predecessors, and the three-chain-derived finalized head. Peer
claims for `highest_qc`, `locked_qc`, signer counts, weights, and finality are
never trusted as cached authority.

State sync preserves the receiving node's durable last-vote record and any
SafetyHalt. It rejects a lower highest QC, a lower finalized head, missing TC
evidence for takeover rounds, or evidence outside the anchored chain. A node
may resume signing only after the reconstructed state is atomically persisted
and the existing signer journal independently permits signing.

Do not recover by deleting signer state, clearing a lock, forcing a leader,
editing height, or sequencing restarts. A restarted validator learns successor
authority only from a verified TC chain; the next ten-block lease boundary
resets authority to the frozen epoch schedule automatically.

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
