# PoSy simplified consensus requirements delta

Status: implemented in the current branch; current build, release, and launch qualification remain open.

This delta is the implementation contract for the fresh block-zero Testnet-v3 simplified consensus profile. The coordinated PoSy v2.2-rc1 column is comparison-only historical context and supplies no P3 Genesis or runtime authority. POSY-00C continues to control every safety rule not explicitly replaced here. POSY-00D continues to control ETDAG admission, ordering, reveal, and protected execution; an ETDAG certificate never becomes a block-finality certificate.

## Activation and compatibility boundary

- Retired manifests, decision records, bytes, hashes, parameter roots, and state are historical evidence only and are not P3 inputs.
- The simplified profile is `posy/3.0` and requires a canonical fresh-Genesis manifest, governance decision, epoch `0`/first height `1`, initial five-validator active-set and weight roots, leader-ring root, binary hash, governed ETDAG binding, and all-node preflight evidence. Five is the first epoch's hardware-backed set, not a permanent protocol limit; later additions become authoritative only through a finalized v3 epoch transition.
- Every P3 height uses only P3 objects. Historical `posy/2.2` objects may exist in explicitly versioned audit code, but cannot supply synchronization, recovery, or authority to the fresh chain.
- Implementation and test completion do not activate the profile or satisfy deployment, performance, operations, governance, or launch gates.

## Intentional replacements

| Area | Coordinated v2.2 rule | Simplified `posy/3.0` rule |
|---|---|---|
| Healthy path | `PROPOSAL -> VALIDATE -> VC -> FINALITY -> QC` | `PROPOSAL -> VOTE -> QC`; one ordinary block vote and one ordinary block certificate |
| Commit rule | A block is finalized by its own finality QC | A block is committed only by a valid consecutive three-certified-block chain `B0 <- B1 <- B2` |
| Lock | Prepared-candidate VC lock plus height-wide finality slot | Highest certified-chain lock; a vote is safe only when the proposal extends the lock or a strictly higher valid QC supplies the specified unlock proof |
| Leader schedule | Height/round-derived priority schedule, historically score/stake influenced | One immutable epoch ring: full SHA3-512 rank over `PoSy/LeaderSchedule/v3 || epoch_seed || validator_id`, canonical validator-ID tie-break, no weights or local observations |
| Leader tenure | Slot/height rotation | Governed fixed lease of 10 blocks; final partial lease ends at the epoch boundary |
| View change | TC advances a round and next round leader for one height | A valid TC increments the current lease takeover offset; the next ring member inherits the remainder of that lease |
| Lease boundary | Round state follows a height | Takeover state is lease-local. The predetermined epoch schedule resumes at the next lease boundary |
| QC schema | VC reference and cached/declared signer totals | Canonical context, block/parent-QC identity, canonical participant evidence, and individual ML-DSA-65 signatures only; all counts and weights are recomputed |
| TC schema | Highest QC and VC plus cached/declared totals | Abandoned epoch/lease/height/round, preceding TC root when round > 0, highest safe QC, canonical participant evidence, and individual ML-DSA-65 signatures; no replacement certificate |
| Active topology | Current approved manifest describes six active validators | New proposal starts with exactly five active validators in one cluster; each later epoch derives dynamic membership and quorum from its finalized frozen set |

No `LeaderReplacementCertificate`, `LeaseTransferCertificate`, `RecoveryCertificate`, or `FinalityCertificate` is introduced.

## Preserved invariants

- Aegis authorization and the Testnet-v3 native ML-DSA-65 consensus-signature policy.
- Durable journal-before-signature release, conflicting-signature prevention, and irreversible `SafetyHalt` for conflicting valid consensus evidence.
- Exact chain, network, protocol, schema, epoch, height, round, parameter-root, validator-set-root, key-root, weight-root, and consensus-context binding.
- Canonical deterministic serialization and distinct canonical signer ordering.
- Independent strict quorums over the frozen active set: `3 * signer_count > 2 * validator_count` and `3 * signed_weight > 2 * total_weight`, using checked integer arithmetic. Invalid, duplicate, revoked, or wrong-context signatures contribute zero.
- The already approved frozen finality-weight source. Synergy Score does not become a new authority source in this change.
- ETDAG isolation, BOC-bound protected execution, reveal gating, and plaintext-user-transaction restrictions.
- Fail-closed behavior when quorum, durable state, context, ancestry, or cryptographic verification cannot be established.
- The inherited legacy consensus engine remains disabled.

## Formal safety state and transitions

The durable v3 safety state is:

- `epoch_context`: activated epoch, height range, epoch/context root, active-set root, weight root, key root, parameter root, and immutable leader ring/root;
- `highest_qc`: highest verified QC by `(height, round, qc_id)` deterministic order;
- `locked_qc`: highest QC whose certified child caused lock advancement;
- `last_vote`: epoch, height, round, candidate ID, protected-execution root, and exact signing transcript; a different candidate at the same height is forbidden across all takeover rounds and independently protected by the signer journal;
- `takeover`: current lease index, verified sequential TC roots, and resulting takeover offset;
- `finalized`: last committed height, block ID, and QC ID;
- durable `SafetyHalt` evidence.

For a proposal `P` justified by `Q`, `safe(P)` holds only when all context, proposer, execution, ETDAG, parent, and signature checks pass and either:

1. `P` extends `locked_qc.block_id`; or
2. `Q.height > locked_qc.height`, `Q` is fully verified, and `P` extends `Q.block_id`.

A validator votes at most once for a candidate at an `(epoch,height,round)` and never votes for conflicting siblings at the same height. The signer journal is written before the signature is released. A QC advances `highest_qc`. Observing a valid certified parent-child pair advances `locked_qc` to the parent QC. Observing valid consecutive certified blocks `B0 <- B1 <- B2` commits `B0`. Finalization is monotonic and a conflicting valid QC or committed branch causes `SafetyHalt`; neither a timer nor a TC clears a vote, lock, finalization record, or halt.

## Deterministic lease authority

For height `h` in an epoch beginning at `epoch_start_height`:

```text
lease_index     = (h - epoch_start_height) / leader_lease_blocks
scheduled_index = lease_index mod validator_count
authorized      = ring[(scheduled_index + takeover_offset) mod validator_count]
```

`leader_lease_blocks` is 10. `takeover_offset` is the number of valid, sequential TCs accepted for that lease. Round zero has no TC. Round `r > 0` requires the TC chain through `r - 1`; a local clock can emit a timeout vote but cannot change authority. A TC must certify the current authorized owner and current round, satisfy both strict quorums, carry the highest safe QC, and link to the preceding TC for nonzero rounds. Takeover state resets at the next predetermined lease boundary and at an epoch boundary.

## Five-validator launch preconditions

- Exactly five distinct active validator identities, public ML-DSA-65 consensus keys, nonzero frozen weights, and identical canonical roots on all nodes.
- Four distinct valid signatures are necessary but not sufficient; strict frozen weight must also pass.
- For single-validator-failure liveness, every leave-one-out set must retain strict weight quorum. Equivalently, no individual validator may control one-third or more of total frozen weight.
- Seed, relay, archive, RPC, explorer, and boot roles have no consensus weight unless their identities are explicitly present in the frozen active set.
- No private keys, credentials, passwords, or identity assignments are generated or modified by this work.

## Required evidence before activation

Launch remains fail-closed until deterministic vectors, unit/property tests, five-independent-process fault tests, restart/state-sync tests, complete canonical-manifest/root verification, all-five-node preflight agreement, signer/key readiness, release/binary hashes, fresh-chain staging rehearsal, abort criteria, governed ETDAG artifacts, and the existing launch controls are reviewed. Performance evidence must include proposal, vote, QC, chained-finality, TC/takeover, PQC verification, certificate-size, and restart/rejoin measurements. The public launch state remains blocked until those separate gates pass.
