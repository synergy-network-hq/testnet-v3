# Coordinated Consensus Message Schemas

Status: Phase One schema reference. These messages are not yet enabled by the
production role lifecycle.

Only the messages in `runtime/src/p2p/messages.rs` are legal for
`coordinated_round_robin_v1`. All are accepted only after the existing P2P
handshake binds the sender to an active finalized validator identity and
consensus key.

| Message | Sender | Required content | Receiver action |
| --- | --- | --- | --- |
| `ProducerAssignment` | Val1 | signed assignment | Verify and durably install the pending assignment. |
| `ProposedBlock` | assigned Val2--Val6 | assignment, proposal binding, existing signed block | Val1 verifies and may create one commit. |
| `CoordinatorCommit` | Val1 | complete committed package | Verify, execute, durably finalize. |
| `CommittedBlock` | any authenticated holder | complete committed package | Verify, execute, durably finalize; reply to a direct request. |
| `GetCommittedBlock` | authenticated validator | height | Return the exact durable package or reject. |
| `GetCommittedBlockRange` | authenticated validator | bounded inclusive height range | Return only contiguous durable packages. |
| `CommittedBlockRange` | authenticated holder | contiguous packages | Verify and apply in order. |

There are no validation votes, finality votes, QCs, VCs, TCs, timeout
certificates, aggregates, peer-count proofs, cluster proofs, or fallback
messages in this family.

## Signed objects

`ProducerAssignment` binds `chain_id`, `network_id`, consensus version, epoch,
height, producer round, parent block hash, prior finality reference, assigned
producer, coordinator, assignment sequence, intended bounded timestamp, and
the Val1 signature under `SYNERGY_COORDINATED_ASSIGNMENT_V1`.

`CoordinatedProposal` binds the same height/round/parent/finality reference to
the assignment hash, producer ID, existing block ID, transaction root, receipt
root, state root, and the existing producer block signature.

`CoordinatorCommit` binds the same canonical height/round/parent/finality
reference to the assignment hash, block hash, producer ID, commit sequence,
and the Val1 signature under `SYNERGY_COORDINATED_COMMIT_V1`.

The package contains the exact existing `Block`, signed assignment, proposal,
and signed commit. The block must identify the coordinated protocol version,
have an all-zero legacy QC hash, carry the prior finality reference as its
evidence root, and reproduce its transaction count and ordering root from its
body. No old certificate is synthesized for compatibility.

## Validation order

The verifier rejects a message before state mutation unless all of the
following are true: sender binding, mode/chain/network/epoch binding, strict
producer rotation, signature/key binding, assignment and proposal hashes,
parent/finality continuity, block header/body transaction order and count,
individual transaction signatures, deterministic execution, and resulting
state and receipt roots. A recipient must not trust the coordinator merely
because it signed the commit.

Range synchronization is bounded by
`MAX_COORDINATED_CONSENSUS_SYNC_RANGE_BLOCKS`; gaps, reordered packages,
unexpected sender identities, and different durable evidence at an already
finalized height are failures.
