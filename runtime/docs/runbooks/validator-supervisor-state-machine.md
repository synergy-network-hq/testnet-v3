# Validator Supervisor State Machine Runbook

This runbook describes the offline classifier in `src/validator_lifecycle.rs`.
It does not authorize live restarts, binary deployment, archive snapshot use, or
mutation of validator chain data.

The supervisor state flow replaces manual marker-file or JSON surgery. Operators
must not hand-edit consensus JSON/JSONL files or persisted supervisor state to
force a validator back into service.

## Inputs

The classifier consumes explicit evidence about:

- finalized-height stall against canonical peers;
- local hash, canonical-lock, body, committed-QC, checkpoint, and compact
  boundary disagreements;
- binary, config, and validator-set digest mismatches;
- peer count, disk, memory, qRPC, and metrics degradation;
- snapshot or state-sync verification failures;
- verified state-sync plan availability; and
- exact finalized-head, QC, fork, and vote-only probation proof.

## Command

```bash
synergy-node validator classify-supervisor-state \
  --evidence supervisor-evidence.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The command prints the classifier decision and exits nonzero when the decision
is fail-closed. It does not write marker files, restart a validator, or mutate
chain data.

To plan the next persisted supervisor state without writing it:

```bash
synergy-node validator supervisor-transition \
  --evidence supervisor-evidence.json \
  --previous-state supervisor-state.json \
  --output supervisor-transition-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

`--previous-state` is optional for first-run planning (`--previous` remains a
compatibility alias). The transition report includes
the next `synergy-validator-supervisor-state-v1` object, duty gate, monotonic
sequence, write recommendation, evidence hash, duty booleans, blocked reasons,
next recommended actions, and transition notes.

To write the planned state into an offline fixture workspace:

```bash
synergy-node validator supervisor-write \
  --transition supervisor-transition-report.json \
  --workspace /path/to/offline-supervisor-workspace \
  --dry-run \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator supervisor-write \
  --transition supervisor-transition-report.json \
  --workspace /path/to/offline-supervisor-workspace \
  --apply \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

`--apply` currently requires `VALIDATOR_SUPERVISOR_OFFLINE_WORKSPACE` in the
workspace and writes `supervisor/validator-supervisor-state.json`. It backs up
any existing state file, writes the new state to a temporary file, and then
atomically renames it into place.

## State Mapping

- `ACTIVE`: normal voting and proposer duties remain enabled.
- `SUSPECT`: stop proposer/vote duties and collect evidence.
- `QUARANTINED`: preserve evidence and keep validator out of quorum,
  proposer rotation, QC aggregation, and canonical-source duty.
- `SPEED_SYNCING`: run only a verified protocol-native state-sync plan.
- `VOTE_ONLY`: allow votes and quorum counting, but no proposer or QC
  aggregation duties.
- `PENDING_REACTIVATION`: proposer-probation state. Proposer duties remain
  disabled until a promotion proof passes.
- `FAILED_CLOSED`: require operator intervention before duties can resume.

qRPC or metrics degradation alone keeps consensus duties active and returns the
`isolate_qrpc_and_metrics` action. Consensus data must not be mutated to fix a
public-serving or observability-only failure.

## Fail-Closed Triggers

`FAILED_CLOSED` is required for binary/config/validator-set digest mismatch,
repeated panic loops, snapshot verification failure, state-sync verification
failure, or checkpoint hash mismatch.

`QUARANTINED` is required for local hash disagreement, body/lock/QC gaps,
compact-boundary evidence gaps, inconsistent vote-lock/high-QC evidence, locks
ahead of body tip, or any divergence during vote-only probation.

## Rejoin Boundary

Vote-only rejoin requires exact finalized-head match, latest QC verification,
and no unresolved fork evidence. A clean vote-only probation window writes
`PENDING_REACTIVATION`, not `ACTIVE`. `ACTIVE` is written only after proposer
probation promotion proof passes with zero missed votes.

A persisted `FAILED_CLOSED` state remains failed closed until a governed reset
exists. Recovery states such as `QUARANTINED`, `EVIDENCE_PRESERVED`,
`SPEED_SYNCING`, `SHADOW_OBSERVING`, or `READY_TO_REJOIN` cannot transition
directly back to `ACTIVE`; they must pass through verified vote-only rejoin
evidence first.

## Write Guards

The writer fails closed when:

- dry-run/apply mode is ambiguous;
- the offline workspace marker is missing;
- a previous state file is malformed or unreadable;
- the transition sequence does not increase monotonically;
- transition evidence is stale;
- validator id, cluster id, or evidence hash is missing;
- a recovery state or `FAILED_CLOSED` jumps directly to `ACTIVE`;
- `VOTE_ONLY` or `PENDING_REACTIVATION` enables proposer duties;
- duty booleans disagree with the persisted duty gate; or
- `ACTIVE` has blocked reasons, fail-closed status, or incomplete duty gates.

This writer is not a live rollout authorization. Future live adoption must write
one validator at a time and preserve cluster quorum margin.
