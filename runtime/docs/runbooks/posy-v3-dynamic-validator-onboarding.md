# PoSy v3 dynamic validator onboarding

Status: governed operations design and preflight only. This document does not
authorize a membership change, identity creation, deployment, or live-node
mutation.

## Boundary

This procedure applies only to the fresh Chain 1266 `testnet-v3` network using
technical network ID `testnet` and protocol `posy/3.0`. The five Genesis
validators are the initial epoch set, not a protocol ceiling. Every later set
is a complete newly finalized epoch context; validators never join by editing
an in-memory ring, a local allowlist, or a quorum constant.

## Required public inputs

- the currently finalized epoch context and exact active-set, consensus-key,
  frozen-weight, leader-ring, consensus-parameter, and finality roots;
- the exact previous-epoch three-QC finality tail and certified parent required
  by the transition proof;
- a unique candidate validator ID and approved ML-DSA-65 consensus public key
  with the required Aegis proposer and vote roles;
- the complete proposed next-epoch validator set and frozen weights, including
  every continuing validator rather than only the added validator;
- an independently authorized transition subject that binds the current and
  next roots, activation epoch/height, and prior finality evidence; and
- public transport, service, monitoring, and storage preflight evidence that
  does not confer consensus authority by itself.

No private key, passphrase, credential, raw host secret, or mutable local
configuration is a membership input.

## Deterministic preflight

1. Verify the candidate identity and key are unique and not revoked, reused, or
   present under another validator ID.
2. Canonically sort and validate the complete next set. Derive its active-set,
   key, and frozen-weight roots from the public records.
3. Derive the next immutable leader ring from the finalized transition seed.
   Every existing validator must obtain the same ordered ring and ring root.
4. Recompute count quorum from the next set with `3*q > 2*n`; do not carry the
   initial four-signer value forward as a constant.
5. Check exact frozen-weight quorum and every leave-one-out set with checked
   arithmetic. Reject a topology in which any one validator holds one third or
   more, or one unavailable validator removes strict weight quorum.
6. Verify the transition proof against the current receiver-owned epoch context,
   exact previous three-QC tail, next roots, and activation coordinate.
7. Rehearse state sync, disconnect/rejoin, and durable restart across the
   boundary using the verified transition proof and production driver paths.
8. Stage public configuration only after the proof and all roots agree. Staging
   is not activation; the new validator has no vote or proposal authority
   before the finalized epoch boundary.

## Activation and evidence

At the governed boundary, each validator independently consumes the same
verified transition proof, installs the complete next epoch context atomically,
and derives authority from that context. Record the transition proof digest,
old and new roots, binary/configuration hashes, per-node acceptance, first new
epoch QC, first three-QC finality result, and restart/state-sync results.

Abort on any root, key, weight, ring, height, proof, or finality-tail mismatch.
Never recover by lowering quorum, forcing a leader, changing a local membership
file, deleting a signer journal, skipping transition evidence, or accepting a
transport/VPN record as consensus authority.
