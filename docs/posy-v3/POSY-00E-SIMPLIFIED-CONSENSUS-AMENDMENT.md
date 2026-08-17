# PROOF OF SYNERGY

## POSY-00E — PoSy v3 simplified chained-QC consensus amendment

Status: proposed and implementation-aligned at component scope, but not activated or launch-qualified until every gate in §15 passes.  
Prepared: 12 August 2026.  
Protocol profile: `posy/3.0`.  
Precedence: this amendment supersedes conflicting POSY-00C block-finality, ordinary block-vote, and leader-scheduling language only after a finalized epoch-boundary activation. POSY-00D continues to control ETDAG, BOC, reveal, and protected execution.

### 1. Scope and non-regression boundary

PoSy v3 replaces the repeated normal-path `VALIDATE -> VC -> FINALITY -> QC` ceremony with `PROPOSAL -> VOTE -> QC`, commits through a chained three-QC rule, and assigns proposals through an immutable epoch leader ring with fixed ten-block leases. It does not alter transaction validity, the frozen finality-weight source, validator key policy, ETDAG isolation, protected execution, or emergency governance.

The finalized `posy/2.2` schema-2 manifest and its canonical root are historical consensus facts and MUST remain byte-for-byte unchanged. A v3 node MUST NOT activate from a proposed manifest, infer an activation height, or mix v2.2 and v3 objects at one height.

### 2. Non-negotiable invariants

1. Every signed object binds chain, network, protocol, schema, epoch, height, round, epoch-context root, parameter root, active-set root, key root, and frozen-weight root.
2. The native Testnet-v3 consensus signature is Aegis-authorized ML-DSA-65. Individual signatures remain independently verified.
3. A signer-journal compare-and-set is durable before signature material leaves the signer. No timer, restart, database cleanup, or operator action deletes an authorization.
4. Count and weight quorums are independent and exact: `3 * distinct_signers > 2 * active_validators` and `3 * signed_weight > 2 * total_frozen_weight`. Multiplication is overflow checked. Duplicate or invalid signers contribute zero.
5. A TC changes only proposal authority for the current lease. It never commits a block, lowers quorum, or changes membership. Its signed reports either mandate re-enveloping one already protected stable candidate or prove that no hidden QC existed for the abandoned round before a fresh candidate may be voted.
6. Two different stable candidates with valid QCs at one height cause durable `SafetyHalt`; there is no automatic weight, round, or arrival-time fork choice. Proof variants for the same stable candidate are merged as equivalent evidence.
7. ETDAG certificates remain transaction-layer objects. BOC/reveal/protected-execution validation remains required before a proposal may receive a block vote.
8. Local live-peer sets, health observations, wall clocks, floating point, stake, Synergy Score, stale-lock age, and fallback loops never determine proposer authority.

### 3. Frozen epoch context

The finalized epoch transition commits:

- epoch and exact inclusive height range;
- finalized schedule seed;
- canonical parameter root;
- the complete active validator identities for the epoch (exactly five for the initial Testnet-v3 v3 activation, with later additions admitted only by finalized epoch transition);
- active-set, consensus-key, frozen-weight, and leader-ring roots;
- the full ordered leader ring;
- exact certified-parent QC and separately proven finalized-seed QC, or the
  one-time finalized v2.2 boundary anchor;
- activation epoch and height.

Every validator MUST reconstruct identical canonical context bytes and roots before activation. Validator count is derived from the finalized set, not a protocol constant. Membership and the leader ring are immutable within an epoch; onboarding becomes authoritative only in a later finalized epoch context. A first v3 height references the finalized v2.2 transition/anchor. A v3-to-v3 transition retains the exact three-QC tail at heights `E-2`, `E-1`, and `E` of the preceding epoch: `QC(E)` is the certified parent extended by the first next-epoch block, while `QC(E-2)` is the latest finalized seed. The next context commits both identities plus the transition-subject root; it MUST NOT promote `QC(E)` to finality merely because the epoch changed.

The schema-v2 transition subject binds the adjacent epoch number and height range, the previous epoch-context root, the exact committing height, the next canonical parameter root, and the complete next active-validator, consensus-key, and frozen-weight roots. It deliberately excludes the finalized block and QC identifiers: those identifiers are derived from the protected-execution commitment that contains the subject, so including either would create an impossible cryptographic fixed point. A production transition verifier MUST separately bind the exact finalized QC and prove that the schema-v2 subject was authorized by the protected execution finalized at `E-2`. An unsigned validator list, local registry snapshot, operator flag, or single boundary QC is insufficient.

### 4. Immutable epoch leader ring

For each active validator `v`:

```text
rank(v) = SHA3-512("PoSy/LeaderSchedule/v3" || epoch_seed || canonical_validator_id(v))
```

Sort ascending on the complete 512-bit rank and use canonical validator ID as the tie-break. No rank truncation is allowed. The ring contains every and only active validator exactly once. The schedule is never rewritten when a validator is slow, unavailable, jailed mid-lease without a finalized status transition, or locally unreachable.

### 5. Fixed ten-block leases

`leader_lease_blocks = 10`. For height `h`:

```text
lease_index     = floor((h - epoch_start_height) / leader_lease_blocks)
scheduled_index = lease_index mod validator_count
scheduled_owner = leader_ring[scheduled_index]
authorized      = leader_ring[(scheduled_index + takeover_offset) mod validator_count]
```

The final epoch lease MAY contain fewer than ten blocks. It ends at the exact epoch boundary. Takeover state resets at every predetermined lease boundary; forfeiture never carries into an unrelated future lease.

### 6. Proposal delivery and ordinary vote

A `PROPOSAL` contains the canonical block/candidate, parent QC, proposer identity, current TC root when takeover is active, protected-execution commitment, and proposer ML-DSA-65 authorization. A proposal is valid only from the uniquely authorized ring member for `(epoch,height,round)`. Validators may retain a bounded set of independently valid values from a Byzantine proposer, but locally ECHO at most one value in that slot.

Before an ordinary block vote, the single-fault-liveness profile runs authenticated consistent proposal delivery for the exact `(epoch,height,round)` slot. Let `n` be the frozen epoch validator count:

- `ECHO(candidate)` is signed only after the proposal, complete block/body material, ETDAG/BOC/reveal evidence, parent, proposer, and protected-execution result pass local validation;
- `n-1` distinct valid ECHOs permit a validator to sign `READY(candidate)`;
- two distinct valid READYs cause READY relay by a validator that has not already sent READY for that slot;
- three distinct valid READYs deliver the stable candidate and permit the one ordinary block vote.

ECHO and READY are bounded, domain-separated dissemination statements, not ordinary block votes and not finality certificates. Their signer-journal slots are round-scoped; the ordinary block-vote conflict rule remains height-scoped. A node persists authenticated delivery evidence and retransmits its exact signed local statements after restart. Under the declared one-fault liveness model, proposal delivery prevents two honest validators from delivering different stable candidates for every supported `n>=5`. The protocol does not silently claim additional Byzantine liveness merely because later epochs contain more validators.

`VOTE` is the sole ordinary block-vote phase. It binds the proposal block ID, parent block/QC, context, takeover TC root, protected-execution root, validator, and key. A correct validator:

- fully verifies context, proposer authority, parent QC, protected execution, BOC/reveal inputs, and safe-proposal rules;
- writes its durable vote authorization before signing;
- signs no block vote after durably signing a timeout vote for the same `(epoch,height,round)`;
- rejects a vote that would move last-voted height/round backward, conflicts with its durable lock, or names a different candidate/protected-execution root at a height already voted in any takeover round.

A validator MAY vote again for the identical stable candidate in a later takeover round. It MAY change its height-wide protected candidate only when a fully verified later-round TC contains no mandatory carry candidate. The no-carry TC is durably committed in the vote authorization. Let `q=floor(2n/3)+1`. A hidden `q`-vote QC intersects every `q`-report TC in at least `2q-n` signers; for every supported `n>=5`, removing the one permitted faulty reporter leaves at least two honest reports. Because timeout-then-vote is forbidden, those honest reports must name the hidden candidate, which would make it mandatory rather than no-carry.

There is no ordinary block VC and no ordinary block FINALITY certificate in this profile.

### 7. Quorum Certificate

A QC proof contains canonical proof context, block ID, parent block/QC reference, optional current takeover TC ID, the exact protected-execution root certified by every vote, and a canonically validator-ID-sorted bundle of individual participant IDs, key IDs, and ML-DSA-65 signatures. The stable certified-candidate subject canonicalizes the proof round to zero and excludes takeover evidence and the participant bundle. Its ID binds height, block/body commitment, parent block/QC, frozen roots, and protected-execution root. Independently formed valid quorum subsets, randomized ML-DSA signatures, and same-candidate proof rounds therefore converge on one parent reference; all proofs remain independently verified. A QC contains no authoritative cached count, weight, threshold, or `quorum_met` boolean.

A verifier rejects noncanonical participant order, duplicates, inactive/revoked/wrong-key signers, context mismatch, bad ancestry, a stale or missing takeover proof, and every invalid signature. It recomputes both strict quorums from the frozen context.

### 8. Safety state and safe proposal rule

Each validator durably persists:

- activated epoch/context root;
- anchor, highest, and locked QC;
- last voted height, round, candidate, and transcript root;
- authenticated ECHO/READY evidence and any delivered candidate for the active slot;
- current lease index, effective height, sequential TC chain, and takeover offset;
- last finalized height, block, and QC;
- verified stable certified-chain records plus local QC/TC proof variants needed for ancestry and state sync;
- signer journal and any `SafetyHalt` incident.

For proposal `P` justified by fully verified QC `Q`, `safe(P)` holds only if all ordinary validation succeeds and either:

1. `P` extends the durable locked QC chain; or
2. `Q.height > locked_qc.height` and `P` directly extends `Q`.

The second clause is the higher-QC unlock rule. TC height/round, elapsed time, a new proposer, or more locally connected peers are not unlock evidence. Lock advancement is monotonic: accepting a certified child advances the lock to its certified parent when that parent is higher.

### 9. Chained-QC finality

Let three consecutive certified blocks be:

```text
B0 <- B1 <- B2
```

where `QC(B1)` directly references `QC(B0)`, `QC(B2)` directly references `QC(B1)`, heights are consecutive, and every QC is valid under the same applicable frozen contexts. Accepting `QC(B2)` commits `B0`. The finalized pointer is monotonic and application side effects become externally final only at the atomic commit boundary.

The three-chain MAY cross scheduled leader boundaries, a TC-authorized takeover, or an epoch transition with the separately specified cross-epoch proof. At a v3 boundary, the prior-epoch three-QC tail remains available to ancestry and finality evaluation: accepting the first valid next-epoch QC may finalize `E-1`, not reset the chain and not finalize `E` early. A TC alone never contributes a certified block to the chain.

### 10. Timeout and lease inheritance

A local timeout only permits a validator to emit a `TIMEOUT_VOTE`. That vote binds the abandoned epoch, lease, height, round, uniquely authorized proposer, the signer's highest safe QC, previous TC ID when round is nonzero, the signer's last delivered-or-voted stable candidate when present, signer identity/key, and full frozen context. Once persisted, that timeout authorization prohibits the signer from later block-voting in the abandoned slot.

A TC is a canonical bundle of individually signed reports for one exact timeout closure: context, lease, abandoned proposer, round, and predecessor. Reported highest QCs and last candidates MAY differ. Every non-anchor reported highest QC is accompanied by a complete deduplicated QC proof so a lagging receiver can independently verify the deterministic maximum. The TC satisfies the same strict count and weight quorums as a QC. Round zero has no predecessor; round `r > 0` MUST reference the verified closure ID for `r-1`. The closure ID excludes the report subset, signature bytes, reported HQCs, and carry result, so every valid strict-quorum report subset for the same abandonment (four-of-five in the initial epoch) converges on one takeover reference.

If at least two distinct reports name one stable candidate, it is the unique mandatory carry candidate under the declared one-fault model; multiple such candidates fail closed. The successor must re-envelope that exact candidate and body. If no candidate reaches two reports, the successor may propose a fresh candidate that directly extends the maximum fully verified reported QC, and the verified no-carry TC may unlock earlier non-quorate height-wide vote protection. A valid sequential TC increments `takeover_offset` by exactly one and transfers the remaining current lease to the next ring validator. No separate replacement, transfer, recovery, or finality certificate exists.

Stale, duplicated, wrong-height, wrong-lease, wrong-round, skipped-predecessor, wrong-proposer, missing-HQC-proof, contradictory-carry, or nonquorate TCs are rejected. At the next lease boundary, `takeover_offset` returns to zero and the original epoch schedule applies.

### 11. Dynamic epoch membership and initial five-validator profile

The initial activation target is exactly five active validators in one cluster because those are the approved hardware-backed operators available for the first epoch. Five is not a protocol-wide membership constant. For every epoch, count quorum is recomputed as the smallest integer `q` satisfying `3*q > 2*n`; a five-validator epoch therefore requires four signatures, while later larger epochs use their own derived threshold. Weight quorum is independently recomputed from that epoch's frozen weights.

New validators do not enter a live epoch from peer discovery, a mutable registry read, or local health state. Governance/onboarding prepares their public identities, ML-DSA-65 keys, weights, and transport evidence; the next finalized epoch transition freezes the complete new set and derives a new active-set root, key root, weight root, and leader ring. All nodes switch at the same certified boundary only after independently verifying the prior-epoch three-QC tail and the executed transition-subject proof. The preceding epoch remains immutable and verifiable. Proof-aware restart/state-sync and dynamic 5-to-7 reconstruction are implemented, but later-epoch onboarding MUST continue to fail closed until the production finalized-execution inclusion/receipt proof for the transition subject is installed.

To claim single-validator-failure liveness, every leave-one-out validator set MUST retain strict count and frozen-weight quorum. Therefore no validator may hold one-third or more of total frozen weight. Additional fault-tolerance claims require their own protocol analysis and qualification; they are not inferred from validator count alone.

Boot, seed, relay, archive, explorer, RPC, observer, and indexer roles have zero implicit consensus authority unless the exact identity appears in the frozen active set. Single-authority shortcuts are prohibited after v3 activation.

### 12. Restart and state sync

Before signing after restart, a validator verifies the persisted record root, reconciles the signer journal, restores the epoch context, highest/locked QCs, last vote, finalized head, TC chain, and SafetyHalt state, and validates all roots against the activated transition. Missing or inconsistent state fails closed.

State sync supplies a certified anchor plus the contiguous QC chain and any sequential TCs needed to explain current proposal authority. For a v3-to-v3 boundary, the receiver MUST already own and independently verify the immutable transition proof, executed transition-subject authority, and exact prior-epoch three-QC tail through the transition/bootstrap authority path; peer state sync cannot authorize membership. The peer transcript may carry matching tail finality claims, but substitution or a bare bundle is rejected. Evidence is transferred in bounded, ordered, hash-chained chunks bound to one authenticated peer, request, epoch context, anchor, and terminal bundle root. The receiver applies strict byte/evidence/session/TTL/replay bounds, stages without mutation, reconstructs the complete bundle, independently verifies every certificate and overlap with local evidence, and only then persists the new safety state. Conflicting valid local/peer stable candidates or TC closures enter durable `SafetyHalt`; proof variants for the same stable subject are not conflicts. Routine recovery never deletes journals, forces a leader, edits height, lowers quorum, or depends on restart order.

### 13. Canonical schemas and domains

Normative schema details are in `CONSENSUS_OBJECT_SCHEMAS.md`. Consensus domains begin with `PoSy/Consensus/v3/`; the leader rank domain is exactly `PoSy/LeaderSchedule/v3`. Unknown fields and noncanonical encodings are rejected. Historical v2.2 parsing is read/sync compatibility only and never changes active v3 semantics.

### 14. Required observability

Implementations expose bounded, non-consensus measurements for proposal latency, vote propagation, QC formation, chained finality, TC recovery, leader takeover, PQC verification, certificate size, and restart/rejoin. Measurements never authorize a proposer, change timeout evidence, or relax validation.

### 15. Activation gates

1. Specification and cross-repository publication are ratified.
2. The canonical v3 manifest is finalized with approval ID, activation epoch/height, and exact root.
3. Five approved public validator identities, ML-DSA-65 keys, active-set/key/weight/ring roots, and identical all-node preflight are evidenced.
4. Signer-journal, lock, chained-finality, TC, restart, state-sync, fork, and SafetyHalt tests pass, including property/model analysis.
5. Five independent OS processes, each owning the production driver, real timers, real ML-DSA-65 authority, and distinct durable safety/signing/material/finality stores, pass 4/5 progress, 3/5 fail-closed, partition-heal, restart, takeover, and chained-finality scenarios. The parent MAY substitute only bounded authenticated routing and fault injection; it MUST NOT construct consensus evidence. A state-machine worker harness alone does not satisfy this gate.
6. Five complete node processes using the production role-runtime and socket stack, protected execution, atomic application commit, and production identities pass disconnect/rejoin, backpressure, Byzantine, and node-database convergence qualification.
7. Full runtime suites pass; no inherited production engine is enabled.
8. At least 10,000 representative blocks establish proposal/vote/QC/finality/takeover/PQC/certificate/rejoin distributions.
9. Migration and abort/fail-closed procedures are rehearsed with every validator in the frozen activation set at one certified state.
10. ETDAG, security, operations, release, governance, and all existing Testnet-v3 launch controls pass.

Until then the profile remains a proposal and Testnet-v3 launch status remains blocked.
