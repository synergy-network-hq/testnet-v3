# Coordinated Consensus Persistence Invariants

Status: Phase One implementation reference.

Coordinated mode writes its state separately from typed-PoSy finality. It must
not reinterpret a QC, VC, TC, or typed signing record as a coordinated commit.

## Durable records

`CoordinatorState` persists the finalized height and block hash, prior
finality reference, pending height/round/producer, producer cursor, pending
assignment hash and envelope, committed block hash for the pending height, and
missed producer turns. The exact serialized form is owned by
`CoordinatorStateStore` in `coordinated_round_robin.rs`.

`DurableConsensusSigningAuthority` records the exact signed assignment or
commit envelope before it can be broadcast. The journal has separate slots for
assignment and commit. Assignment slots distinguish replacement rounds;
commit slots prevent Val1 from signing two different finalized block subjects
at the same height, even after a restart.

`CoordinatedFinalityStore` holds the complete verified committed package,
anchored to the pre-coordinated parent block and state root. Writes are atomic
and fsynced. A duplicate exact package is idempotent; different evidence at an
already-finalized height is a safety failure.

## Required write ordering

1. Persist assignment signer-journal evidence.
2. Persist the pending coordinator state.
3. For an accepted producer block, execute and verify it.
4. Persist the commit signer-journal evidence.
5. Persist the coordinated finality package.
6. Persist the advanced coordinator state and publish the new execution tip.
7. Only then permit network egress.

The ordering is intentionally conservative. A crash may leave a durable
package ahead of the coordinator-state file; recovery derives state from the
verified package. A crash must never permit a second assignment or commit
signature for the same durable signing slot.

## Invariants

- Finalized height and parent hash are contiguous from the configured migration
  anchor.
- The pending assignment can only target the next unfinalized height.
- Replacement assignments keep that height and advance only the producer
  round/cursor.
- Every final package has exactly one coordinator commit and exactly the
  producer assignment that authorized its block.
- The execution-state root is either the migration anchor or a root proven by
  the durable finality sequence; an arbitrary local snapshot is rejected.
- Finalized records are durable network knowledge. Any authenticated validator
  holding an exact record may serve it to another validator.

Persistent state is chain-derived data. It may be reset only by the controlled
fresh-genesis procedure described in the runbook; validator keys, peer
identities, credentials, and immutable genesis artifacts are outside that
deletion scope.
