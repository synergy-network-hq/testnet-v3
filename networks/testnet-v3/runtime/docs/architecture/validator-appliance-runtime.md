# Validator Appliance Runtime Architecture

Prompt 2 treats a validator appliance as a dynamic participant in a validator
cluster, not as a permanent member of a fixed six-validator topology.

## Runtime Roles

- `OBSERVER`: syncs state and proves readiness without voting or proposing.
- `VOTE_ONLY`: may vote and count toward quorum only after verified rejoin
  proof; it cannot propose or aggregate QC.
- `PENDING_REACTIVATION`: proposer probation. The validator still cannot
  propose until promotion proof passes.
- `ACTIVE`: full validator duty after clean state, matching binary/config/
  validator-set digests, no unresolved recovery reason, and passing promotion
  proof.
- `QUARANTINED` or `FAILED_CLOSED`: excluded from proposer, vote, QC
  aggregation, canonical-source, and repair-source duties until verified
  evidence allows a safe transition.

## Topology Model

Validator count and cluster count are dynamic. The current six validators are
current-live fixtures and incident-test coverage only. Runtime code and rollout
docs must derive quorum from the active validator set and must never hard-code
`4-of-6` as a permanent rule.

Cluster assignment preview rejects unsafe placements that would leave an
existing or planned cluster below quorum margin. Future live rollout works one
validator at a time and stops before any action that could take a cluster below
that margin.

## State And Supervisor Model

The appliance does not recover through manual JSON/JSONL edits. Protocol-native
state-sync repair verifies source proofs, writes receipts, backs up the prior
state, rebuilds derived indexes, and swaps state atomically in marker-gated
offline workspaces. The supervisor flow records lifecycle state, duty gates,
evidence hash/path, sequence, blocked reasons, and next actions.

Recovery-state validators cannot jump directly back to `ACTIVE`. They pass
through state-sync, vote-only rejoin, and proposer probation gates.

## Onboarding Model

Offline onboarding gates verify enrollment token, package compatibility,
identity bundle, backup proof, cluster assignment preview, config render
manifest, observer sync proof, vote-only eligibility, proposer probation
eligibility, and activation eligibility. Tests use fixtures only and do not
create live validator identities or keys.

## Archive Boundary

Archive services, snapshot API, and snapshot worker remain disabled until
canonical reseed passes. Archive state is not trusted for repair or onboarding
activation until canonical identity, source proof, restore role, and current
height alignment are proven and separately authorized.

## Release Boundary

No live deploy, restart, state mutation, rollback, archive re-enable, or quorum
change is authorized by this architecture document. Rollback success requires
post-rollback health proof across validator health, canonical advancement,
public RPC parity, and Atlas exact-height hash parity where available.
