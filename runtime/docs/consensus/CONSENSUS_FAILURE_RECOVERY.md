# Coordinated Consensus Failure and Recovery

Status: Phase One recovery design and implemented runtime behavior. Operational
qualification remains pending.

## Coordinator unavailable

Val1 is the only coordinator. If it is unavailable, the chain pauses; no
replacement, election, coordinator vote, certificate, or automatic fallback
is legal. When Val1 restarts it loads the last finalized coordinated package,
the coordinator state, and the signer journal. It replays the exact pending
assignment or resumes its timeout and must never invent a conflicting round.

## Producer unavailable

After the configured producer-turn timeout, Val1 records the missed turn
durably and signs one replacement assignment for the next member of the fixed
Val2--Val6 order at the same height. The missed producer does not receive a
second normal turn at that height. The new assignment is broadcast and
validated like the first one.

## Producer restart or stale assignment

A producer reloads its durable pending assignment. A valid assignment for an
already-finalized height is harmlessly ignored. A lower replacement round for
the same pending height is ignored after signature verification. A competing
same-round assignment, a different parent, a different finality reference, or
a duplicate producer proposal with different content is rejected.

## Validator restart and catch-up

At startup, a node verifies every durable coordinated package, reconciles a
lagging `CoordinatorState` using the exact carried assignments, and replays
execution only from a state root proven by the durable sequence. It can request
one package or a bounded contiguous range from any authenticated validator.
It does not need a QC, a timeout certificate, manual database copying, or
manual proof reconstruction.

## Safety failures

Stop signing and preserve evidence if any of the following occurs:

- different durable commit evidence for one height;
- a state file ahead of or contradictory to finality storage;
- an invalid/unknown consensus key or sender binding;
- invalid block, transaction ordering, transaction signature, parent, state,
  receipt, assignment, or commit binding;
- a finality sync gap or non-contiguous range;
- a coordinator signer-journal conflict.

Do not delete data to repair an ordinary crash, missed producer, or validator
lag. A fresh-genesis reset is a deliberate fleet operation, not a recovery
shortcut.
