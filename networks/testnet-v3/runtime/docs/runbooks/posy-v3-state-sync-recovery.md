# PoSy v3 state-sync and restart recovery

Status: source-aligned recovery design; not permission to access a node,
restart a service, replace data, or deploy an artifact.

## Authoritative evidence

Recovery applies only to Chain 1266, technical network ID `testnet`, release
`testnet-v3`, and protocol `posy/3.0`. A P3 node may reconstruct authority only
from the canonical fresh Genesis reference, verified P3 QCs and sequential TCs,
content-addressed protected proposal material, replay-verified finality records,
and independently verified P3-to-P3 transition proofs.

Retired-chain blocks, QCs, snapshots, state roots, transition records, data
directories, and peer claims are never recovery inputs. A transport peer,
snapshot manifest, or locally cached height is not consensus authority.

## Recovery sequence

1. Preserve the durable signer journal, rooted safety state, finality WAL,
   material store, SafetyHalt evidence, and current epoch context. Never clear
   them to make a node start.
2. Verify the local Genesis hash, signed V4 release record, consensus parameter
   root, governed ETDAG roots, and initial membership anchor before accepting
   any peer evidence.
3. Request bounded, request-correlated state and material chunks from an
   authenticated validator whose identity belongs to the expected frozen set.
4. Verify every proposal subject, participant, ML-DSA-65 signature, QC, TC,
   parent link, height/round/lease coordinate, root, and content-addressed
   material reference before staging it.
5. Reconstruct the contiguous QC/TC chain and three-QC finality witness. A TC
   may inherit only the remainder of its certified lease and can never provide
   a block parent, clear a lock, finalize a block, or change membership.
6. When crossing an epoch, verify the receiver-owned transition subject, exact
   previous-epoch finality tail, certified parent, finalized seed, and complete
   next epoch roots before installing the new context.
7. Atomically install only a state that is monotonic with local last-vote,
   locked/highest typed parents, finalized head, transition state, and signer
   journal. Reopen and replay the durable records before rejoining consensus.
8. Confirm the recovered node derives the same epoch context, leader ring,
   takeover owner, finalized head, and protected execution roots as the healthy
   quorum before permitting it to vote or propose.

## Fail-closed conditions

Enter or preserve SafetyHalt on conflicting valid QCs. Reject missing material,
gaps, rollback, stale or skipped TCs, wrong-session responses, unknown signers,
root divergence, a Genesis object decoded as a QC, a bare next-epoch bundle
without its transition proof, or any evidence from another chain incarnation.

Required qualification includes a lagging validator, disconnect/rejoin,
missing-material fetch, sequential TC reconstruction, cross-epoch state sync,
process restart, exact durable tree-root preservation, and subsequent three-QC
finality. Until those current-build exercises pass, this runbook is a review
artifact rather than launch evidence.
