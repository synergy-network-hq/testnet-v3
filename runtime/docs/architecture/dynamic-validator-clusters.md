# Dynamic Validator Clusters

> Profile precedence: this document describes the current v2.2/dynamic
> topology source. If and only if the proposed `posy/3.0` profile is finalized
> and activated at a declared epoch boundary,
> `docs/posy-v3/POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md` governs consensus
> for the initial activation epoch, whose hardware-backed proposal contains
> exactly five ACTIVE validators in one cluster. It uses strict `4-of-5` count
> quorum, frozen-weight quorum, and an unweighted ten-block leader ring. Five is
> not a protocol limit: later finalized v3 epoch contexts derive membership,
> cluster topology, quorum, and the leader ring from their complete frozen set.

Dynamic validator cluster handling must derive quorum and liveness from the
planned validator count in the evidence being evaluated. Current six-validator
Testnet fixtures are compatibility inputs, not permanent protocol topology.

## Canonical Epoch Boundaries

An epoch contains exactly 1,000 finalized block heights and uses one-based
block ranges:

- Height `0` is genesis/pre-block state and belongs to epoch `0` only for
  compatibility reporting.
- Blocks `1` through `1,000` are epoch `0`.
- Blocks `1,001` through `2,000` are epoch `1`.
- Blocks `2,001` through `3,000` are epoch `2`.
- For every positive height, `epoch = (height - 1) / 1,000` using integer
  division.

An epoch starts at `epoch * 1,000 + 1` and ends at
`(epoch + 1) * 1,000`. Activation, assignment, shadow-observation, and rotation
evidence must use those boundaries exactly.

Runtime `v19.0.15` finalized exact 1,000-block boundaries with the legacy
`height / 1,000` QC epoch label. Runtime `v19.0.22` normalizes that metadata only
for hash-bound, finalized dual-quorum QCs on canonical 1,000-block boundaries at
or before the frozen migration cutoff at block `1,052,000`. Canonical QC labels
remain unchanged. The same off-by-one label at block `1,053,000` or any later
boundary fails closed.

## Canonical Cluster Topology

- `1-9` active validators use one cluster.
- `10-20` active validators use exactly two balanced clusters. At 10
  validators this is two `4-of-5` clusters.
- `21-27` active validators use exactly three balanced clusters. At 21
  validators this is three `5-of-7` clusters.
- At 28 validators and above, cluster count is `floor(active_validators / 7)`.
  Therefore 28 validators use four clusters, 35 use five, and each additional
  seven validators adds one cluster.
- A validator added without a cluster-count expansion joins a least-populated
  cluster without moving existing members.
- Cluster-count expansion performs a deterministic, finalized-QC-seeded
  rebalance across the new cluster count.
- Cluster membership is balanced so cluster sizes differ by at most one.

Quorum is calculated independently for each cluster from its active member
count. The strict rule requires `4-of-5`, `5-of-6`, and `5-of-7`; it
must never reuse a network-wide static threshold for a cluster.

## Rotation Rules

- Automatic rotation is disabled while fewer than three clusters exist.
- With three or more clusters, every epoch moves the two validators with the
  lowest finalized Synergy scores in each cluster to another cluster.
- Every tenth epoch performs a full deterministic reshuffle instead of the
  low-score rotation.
- Finalized QC-derived randomness is the only accepted rotation seed. Local
  clocks, process order, and unfinalized scores must not affect assignment.
- Assignment epoch, effective height, seed, cluster id, cluster address, and
  member list are persisted and exposed as one hash-bound membership bundle.

## Offline Cluster Assignment Preview

```bash
synergy-node validator cluster-assignment preview \
  --input cluster-assignment.json \
  --output cluster-assignment-report.json \
  --chain-id 1266 \
  --network-id synergy-testnet-v3
```

The preview model evaluates:

- Testnet v3 chain and network identity.
- Candidate validator id.
- Existing and planned validator counts.
- Planned cluster id.
- Dynamic quorum threshold from the planned validator count.
- Active liveness margin.
- Anti-affinity and fault-domain diversity checks.
- Whether the assignment would reduce quorum or displace an active validator.
- Archive-contained dependency isolation.

The command is dry-run only. It fails closed on wrong chain/network, missing
cluster assignment, non-expanding validator count, anti-affinity failure,
fault-domain diversity failure, quorum reduction, active-validator displacement,
or archive-contained dependency.

## Safety Rules

- Cluster expansion must not hard-code six validators or `4-of-6`.
- New validators join through observer sync, vote-only, proposer probation, and
  activation proof gates.
- Archive-contained state cannot be used as cluster assignment evidence.
- Assignment preview does not create identities, keys, WireGuard peers,
  validator services, or live cluster changes.
