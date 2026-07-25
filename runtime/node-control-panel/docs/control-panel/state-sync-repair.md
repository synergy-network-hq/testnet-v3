# State-Sync Repair

State-sync repair replaces manual state transfer. It is the only normal operator path for repairing validator state.

## Required UI Data

The State Sync page shows peer source list, quorum agreement, repair range, repair reason, estimated download, mutation summary, backup path, dry-run result, and repair receipt.

## Gate Order

1. Inspect local state and identify primary consensus truth.
2. Compare peer sources.
3. Require validator quorum agreement.
4. Produce a dry-run receipt.
5. Write backup and rollback paths.
6. Run confirmed repair only after quorum proof passes.
7. Record evidence.

Repair is disabled until quorum proof is present. Operators must not SSH into another validator, copy snapshot files by hand, or start temporary HTTP servers to repair state.

Vote-only rejoin and proposer probation are separate lifecycle gates after state repair. A repaired validator does not become proposer-eligible immediately.
