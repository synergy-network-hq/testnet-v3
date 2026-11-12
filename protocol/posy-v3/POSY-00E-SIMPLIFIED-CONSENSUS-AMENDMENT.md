# PROOF OF SYNERGY

## POSY-00E — PoSy v3 simplified chained-QC consensus amendment

Status: implemented in the current branch, but not release-authorized or launch-qualified until every gate in §15 passes.
Prepared: 12 August 2026.  
Protocol profile: `posy/3.0`.  
Precedence: this amendment is the Genesis consensus profile for the separate fresh Testnet-v3 P3 chain. POSY-00D continues to control ETDAG, BOC, reveal, and protected execution.

### 1. Scope and non-regression boundary

PoSy v3 replaces the repeated normal-path `VALIDATE -> VC -> FINALITY -> QC` ceremony with `PROPOSAL -> VOTE -> QC`, commits through a chained three-QC rule, and assigns proposals through an immutable epoch leader ring with fixed ten-block leases. It does not alter transaction validity, the frozen finality-weight source, validator key policy, ETDAG isolation, protected execution, or emergency governance.

Retired-chain manifests and roots are historical evidence only and MUST NOT be imported into the fresh P3 Genesis or runtime state. A v3 node MUST NOT activate from an unsigned candidate, infer an activation boundary, or mix retired consensus objects with P3 authority at one height.

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
- the typed fresh-Genesis finality reference for epoch zero, or the exact
  certified-parent QC and separately proven finalized-seed QC for a later P3
  epoch;
- activation epoch and height.

Every validator MUST reconstruct identical canonical context bytes and roots before activation. Validator count is derived from the finalized set, not a protocol constant. Membership and the leader ring are immutable within an epoch; onboarding becomes authoritative only in a later finalized epoch context. The first P3 block extends the typed fresh-Genesis finality reference. A v3-to-v3 transition retains the exact three-QC tail at heights `E-2`, `E-1`, and `E` of the preceding epoch: `QC(E)` is the certified parent extended by the first next-epoch block, while `QC(E-2)` is the latest finalized seed. The next context commits both identities plus the transition-subject root; it MUST NOT promote `QC(E)` to finality merely because the epoch changed.

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

The initial activation target is exactly five active validators in one cluster because those are the approved hardware-backed operators available for the first epoch. Their canonical IDs are `validator-02` through `validator-06`. An enrollment inventory may pre-generate `validator-01` through `validator-21`, but that inventory is not consensus authority: `validator-01` and `validator-07` through `validator-21` are inactive at epoch zero. Five is not a protocol-wide membership constant. For every epoch, count quorum is recomputed as the smallest integer `q` satisfying `3*q > 2*n`; a five-validator epoch therefore requires four signatures, while later larger epochs use their own derived threshold. Weight quorum is independently recomputed from that epoch's frozen weights.

New validators do not enter a live epoch from peer discovery, a mutable registry read, or local health state. Governance/onboarding prepares their public identities, ML-DSA-65 keys, weights, and transport evidence; the next finalized epoch transition freezes the complete new set and derives a new active-set root, key root, weight root, and leader ring. All nodes switch at the same certified boundary only after independently verifying the prior-epoch three-QC tail and the executed transition-subject proof. The preceding epoch remains immutable and verifiable. Proof-aware restart/state-sync and dynamic 5-to-7 reconstruction are implemented, but later-epoch onboarding MUST continue to fail closed until the production finalized-execution inclusion/receipt proof for the transition subject is installed.

To claim single-validator-failure liveness, every leave-one-out validator set MUST retain strict count and frozen-weight quorum. Therefore no validator may hold one-third or more of total frozen weight. Additional fault-tolerance claims require their own protocol analysis and qualification; they are not inferred from validator count alone.

Boot, seed, relay, archive, explorer, RPC, observer, and indexer roles have zero implicit consensus authority unless the exact identity appears in the frozen active set. Single-authority shortcuts are prohibited after v3 activation.

### 12. Restart and state sync

Before signing after restart, a validator verifies the persisted record root, reconciles the signer journal, restores the epoch context, highest/locked QCs, last vote, finalized head, TC chain, and SafetyHalt state, and validates all roots against the activated transition. Missing or inconsistent state fails closed.

State sync supplies a certified anchor plus the contiguous QC chain and any sequential TCs needed to explain current proposal authority. For a v3-to-v3 boundary, the receiver MUST already own and independently verify the immutable transition proof, executed transition-subject authority, and exact prior-epoch three-QC tail through the transition/bootstrap authority path; peer state sync cannot authorize membership. The peer transcript may carry matching tail finality claims, but substitution or a bare bundle is rejected. Evidence is transferred in bounded, ordered, hash-chained chunks bound to one authenticated peer, request, epoch context, anchor, and terminal bundle root. The receiver applies strict byte/evidence/session/TTL/replay bounds, stages without mutation, reconstructs the complete bundle, independently verifies every certificate and overlap with local evidence, and only then persists the new safety state. Conflicting valid local/peer stable candidates or TC closures enter durable `SafetyHalt`; proof variants for the same stable subject are not conflicts. Routine recovery never deletes journals, forces a leader, edits height, lowers quorum, or depends on restart order.

### 13. Canonical schemas and domains

Normative schema details are in `CONSENSUS_OBJECT_SCHEMAS.md`. Consensus domains begin with `PoSy/Consensus/v3/`; the leader rank domain is exactly `PoSy/LeaderSchedule/v3`. Unknown fields and noncanonical encodings are rejected. Historical v2.2 parsing is confined to explicitly versioned audit/test paths and never supplies fresh-chain synchronization, recovery, or authority.

### 14. Required observability

Implementations expose bounded, non-consensus measurements for proposal latency, vote propagation, QC formation, chained finality, TC recovery, leader takeover, PQC verification, certificate size, and restart/rejoin. Measurements never authorize a proposer, change timeout evidence, or relax validation.

### 15. Activation gates

1. Specification and cross-repository publication are ratified.
2. The canonical v3 manifest is finalized for `fresh_genesis_block_zero` with approval ID, epoch `0`, first block height `1`, and exact root; the V4 release request is signed by the frozen governance authority.
3. Five approved public validator identities, ML-DSA-65 keys, active-set/key/weight/ring roots, and identical all-node preflight are evidenced.
4. Signer-journal, lock, chained-finality, TC, restart, state-sync, fork, and SafetyHalt tests pass, including property/model analysis.
5. Five independent OS processes, each owning the production driver, real timers, real ML-DSA-65 authority, and distinct durable safety/signing/material/finality stores, pass 4/5 progress, 3/5 fail-closed, partition-heal, restart, takeover, and chained-finality scenarios. The parent MAY substitute only bounded authenticated routing and fault injection; it MUST NOT construct consensus evidence. A state-machine worker harness alone does not satisfy this gate.
6. Five complete node processes using the production role-runtime and socket stack, protected execution, atomic application commit, and production identities pass disconnect/rejoin, backpressure, Byzantine, and node-database convergence qualification.
7. Full runtime suites pass; no inherited production engine is enabled.
8. At least 10,000 representative blocks establish proposal/vote/QC/finality/takeover/PQC/certificate/rejoin distributions.
9. Fresh-chain staging and abort/fail-closed procedures are rehearsed with every validator in the frozen Genesis set; retired-chain data is absent and rejected as input.
10. ETDAG, security, operations, release, governance, and all existing Testnet-v3 launch controls pass.

Until then the profile remains a proposal and Testnet-v3 launch status remains blocked.


### Recovery clarification R1 — operator approved 2026-10-09; activation gated on validation

Observed fresh-chain trigger: Val5 accepted the quorum-valid H196/round0 timeout with a mandatory carry for the same candidate later certified by QC196/round0. The other validators certified that candidate before accepting the timeout, then formed their first timeout at H197/round0. Because timeout IDs include height, these are different lease-control paths despite identical certified block ancestry. Replaying Val5's accepted timeout before its older-round QC preserves a takeover reference that cannot accept the other path. Four validators continue finalizing; Val5 retains finalized H194. The earlier approved protected cutoff clarification does not authorize this change.

Operator-approved narrow authorization:

1. During restart or authenticated state-sync recovery, a complete independently verified three-QC finality chain may select its referenced timeout closure as the canonical certified-history path. Each QC, every required TC, count and weight quorum, frozen authority, parent link, protected root and durable finalized record must verify before installing recovered state.
2. An accepted local timeout omitted from that certified path may be superseded only at a height already covered by this verified chain, only when its highest parent equals that certified candidate's parent and its unique mandatory carry equals the exact same stable candidate. Missing carry, different candidate/parent, missing timeout predecessor, conflicting finalized record, unsupported epoch transition or invalid proof remains a safety failure. A timeout alone can never supersede a QC or finalize a block.
3. Keep every original timeout, vote authorization, lock, QC, finalized record and signer journal intact. Recovery changes the active projection of fully certified history; it never erases evidence or permits a forbidden signature. Outstanding uncertified-tip timeouts remain active and must be restored. No local timer, peer claim or operator height edit grants recovery authority.
4. Ordinary live proposal/TC admission, deterministic proposer selection, strict quorum, PQC verification, mandatory carry, three-QC finality and epoch membership rules remain unchanged. There is no new certificate or second consensus coordinator.
5. Approval authorizes implementation and testing of this exact rule, followed by binding the ratified amendment commitment into a governance-signed release before activation on this fresh stability profile. Activation requires a regression reproducing timeout-before-older-QC plus the alternate next-height timeout path, conflict/missing-proof fail-closed tests, and preserved-journal Val5 catch-up. It does not approve moving public routing or converting Val1 before existing live acceptance gates pass.

Status: operator explicitly approved R1 in this chat on 2026-10-09. Implementation and validation are authorized; deployment remains gated on the listed proof tests and governance-signed release commitment. The preliminary ordering experiment was reverted because it lacked those checks. This approval does not claim live recovery or amend the protected cutoff rule.

### Live lease convergence clarification R2 — operator approved 2026-10-10

Observed trigger: all five validators finalized the same H5797. Val2/Val3 accepted TC5799/round0 before QC5799 and retained round1 into H5800; Val4/Val6 accepted that QC first, advanced to H5800/round0, and rejected the delayed original-height TC. Their next-height timeout reports therefore cannot form one quorum. Restart and reconnection do not reconcile the different lease projections. R1 clause4 leaves this live admission rule unchanged and requires subsequent certified history that the split prevents from forming.

Approved narrow authorization:

1. A validator may reconcile a delayed, independently quorum-verified timeout certificate from an earlier height in its current proposer lease, without requiring a subsequent three-QC finality witness, only after verifying its complete exact timeout-predecessor closure and the contiguous locally verified QC suffix from its original height to the current parent.
2. The delayed timeout's highest parent must equal the original-height QC's parent, and its unique mandatory carry must equal that QC's exact stable candidate. The suffix must use the same frozen authority and lease, preserve contiguous parent/block/protected-root bindings, and introduce no conflicting certified candidate or incompatible timeout closure. Missing carry/proof, a different lease, or contradictory certified evidence cannot authorize reconciliation.
3. Reconciliation installs the same successor lease round and takeover reference that accepting this timeout before that matching QC would have produced. It never moves finalized height, replaces a certified block, lowers an accepted round, clears a signing restriction, or treats a timeout as finality. Any already accepted later timeout closure must be verified as a compatible extension; incompatible valid evidence remains fail-closed. All original QCs, TCs, locks, votes, delivery and signer journals remain intact.
4. This reconciliation is automatic during live authenticated message delivery and restart restoration. Reliable delivery retains the exact signed timeout evidence needed by lagging peers until its lease no longer governs their possible current slot. The existing single PoSy driver owns the operation; no operator action, timer-only round change, new certificate, quorum reduction or identity reset supplies authority.
5. Activation requires genuine-signature tests covering both TC/QC arrival orders, dropped/reordered delivery and automatic convergence, retained-state restart, conflicting/missing/invalid proof rejection, and continued three-QC finality with unchanged quorum. Bind the ratified R2 commitment into a governance-signed release before fleet activation. A reset to H0 does not substitute for these gates.

Status: operator explicitly approved this exact R2 rule in this chat on 2026-10-10. Implementation and validation are authorized. Fleet activation remains gated on the genuine-signature convergence, restart, rejection and finality tests above and a governance-signed release binding the ratified R2 commitment. Approval does not claim implementation completion or live recovery.

### Recovery amendment R3 — operator approved for implementation and validation

Observed trigger on the funded five-validator chain: all validators remain at finalized H47 with block `6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27`. The genuine wallet envelope for target H51 has a verified availability certificate on every validator, with all five availability votes observed. At the same accepted cutoff context, Val2/Val4/Val6 durably signed an empty frontier, while Val3/Val5 signed the frontier containing the transaction. Neither semantic closure has four agreeing markers. A later-arriving valid availability certificate cannot alter an already signed marker. This is a shared cutoff/recovery defect, not misconduct by a validator. No TPS result has been established.

Proposed narrow authorization:

1. Only the existing PoSy driver may authorize a replacement close generation for an uncommitted protected target T when the proposer for H=T-1 is blocked on that target's cut. Authority must be a completely verified, strictly advancing timeout-predecessor closure for H, under the same frozen Genesis/epoch/lease authority. The timeout must have no mandatory carry. A wall-clock timer, RPC request, service restart, or operator cannot authorize a generation.
2. Before replacement, reject recovery if any accepted VC/QC/protected proposal carry or consumed/finalized execution binds the affected cut. An already certified or carry-bound proposal must recover its exact original evidence. Missing proof, conflicting certified evidence, wrong target/domain/lease/parent, and nonadvancing timeout paths remain fail-closed. The implementation must formally resolve the exact exclusion predicates against production proposal/VC/QC/carry stores and prove them before activation; this proposal does not declare those predicates implemented.
3. The replacement cutoff context deterministically binds the original cutoff context, target T, exact verified timeout identity/predecessor path and certified parent. Admission and new availability voting remain closed. Existing authenticated vertices and valid original availability certificates may converge through reliable delivery. A validator may sign one complete cutoff marker for this new context; it must never overwrite or re-sign a different marker in the original context. Existing capacity, wallet authorization, ancestor, signature, 4-of-5 marker/availability and semantic-closure equality checks remain unchanged.
4. Retain every original close marker, context, VAC, timeout, QC, lock, vote and signing record. Persist the new generation and its exact authorization before broadcasting. Restart/rejoin must reconstruct the greatest compatible verified generation and original history without an H0 reset. If availability delivery causes another split, only a later compatible quorum timeout may authorize another generation; no independent ETDAG timeout/round engine is introduced.
5. The existing PoSy proposal/vote/QC path binds the selected recovered cut and deterministic protected batch. Three-QC finality, parent binding, governed proposer selection and mandatory-carry preservation remain unchanged. Never merge incompatible marker closures, lower quorum, substitute an empty batch, or force a locally preferred transaction into a certified cut.
6. Activation requires the genuine-signature H47/H51 3-empty/2-transaction counterexample to recover automatically with retained markers and finalized successful transfer; both delayed-VAC arrival orders; 4/5 online progress and 3/5 fail-closed; repeated timeout generations; retained-state restart/rejoin; rejection of invalid/stale/missing/conflicting timeout, parent and carry evidence; rejection of VC/QC/consumed-cut replacement; and continued identical three-QC finality. Bind the approved R3 rule into a signed release/activation commitment only after these gates pass. The first successful live transfer must precede the measured TPS baseline.

Status: operator approved by the direct user message `approved` on 2026-10-10 following the R3 approval request. Approval authorizes implementation and validation of this narrow rule; it does not establish completion, safety qualification, deployment, TPS capacity, or a clean reliability soak. The six activation requirements above remain mandatory.

### Admission measurement amendment A1 — isolated experiment approved 2026-10-12; live activation not approved

**Scope of requested approval:** implement and run bounded isolated qualification
experiments with a governed target offset D in6..16, retaining the current F+5
profile as the control. This is an experimental range, not a selected production
parameter or a claim that16 is sufficient. It does not authorize live activation,
a live reset, a production release, a TPS claim or soak commencement. A final
measured timing/parameter report and production amendment remain separately
reviewable before activation. If no tested combination meets the contract,
stop and revise the design rather than expanding the range automatically.

Measured need: native isolated run9 had a224.383ms target window but274.791ms
HTTP intake. Run10 under100ms egress delay admitted a genuine transfer locally,
but remote receipt followed cutoff and no availability certificate formed.
Five validators finalized identical empty material with unchanged wallet effects.
There is no successful complete admission-to-VAC sample and therefore no honest
production p99, final cadence or final offset to approve yet. The experiment
allows that missing path to be measured without reopening a closed target.
Exact evidence and independently reviewed owner design are in `ARCHITECTURE.md`,
section “HTTP scheduling measurement and selected preparation direction”.

1. Each experimental incarnation has fresh synthetic custody and a distinct
   signed network/profile identity. The single signed ETDAG parameter commitment
   selects D. Configuration may only match that commitment; no unsigned local
   override, automatic tuning, or mixed-offset nodes are allowed. Current-profile
   parsing retains exact F+5 semantics. Experimental evidence cannot authorize
   the current profile or any live validator incarnation.
2. Non-Genesis source finality F opens target T=F+D. Genesis opens targets3..D;
   H1/H2 execution bootstrap is unchanged. For T≤D the source is the governed
   Genesis reference; otherwise it is the exact verified finalized record T−D.
   Signing, verification, source roots, storage, RPC, telemetry and recovery use
   that same mapping. Signed target/context/encryption bindings remain immutable;
   material is never retargeted after authoring.
3. VC(T−2) still closes T, VC(T−1) still authorizes reveal, and ordinary target
   execution with three-QC finality remains unchanged. Retain four-of-five count
   and weight quorum, native cryptography, original cutoff/reveal evidence,
   existing timeout recovery and every signing/safety journal. No new certificate,
   coordinator, admission reservation, uncertified empty fallback or delayed
   cutoff is introduced.
4. Genesis opening and bounded source/target reconstruction must cover D without
   deleting evidence needed by supported recovery. Keep existing byte/count
   ceilings; reject a candidate that cannot fit them. Cancel stale generations
   and forbid overlapping active signers. Experimental fresh incarnations retain
   their diagnostic history; no production state is copied or reset.
5. Change inventory: `synergy-etdag` parameters and both context versions' target
   validation; `synergy-config` default/profile validation; node ETDAG bootstrap,
   opening and source retention; execution's next-batch, cutoff, execution and
   batch source-authority derivation; native keytool/client context validation;
   baseline source verification and source-root reconstruction. Use one governed
   mapping, not independent rewritten constants at each caller.
6. Before running any candidate, validate overflow, wrong offset/profile/root,
   wrong incarnation, Genesis boundaries, source substitution, cutoff and reveal,
   restart reconstruction and old-evidence rejection. Then qualify the exact
   diagnostic Linux bytes with genuine nonempty transfers and all-five identical
   finalized wallet effects. Measure the complete path through durable quorum
   availability and finality; record rejection and missing boundaries explicitly.
7. Compare the current control and smallest candidate offsets under the same
   workload, supported delay and one-validator outage. Derive a proposed cadence
   from eligible healthy proposal-to-QC p99 plus25percent rounded up to100ms;
   require at least50percent admission headroom and actual fault/load qualification.
   Recovered/observed cohorts and failed operations cannot supply a healthy p99.
   This experiment does not waive integrated runtime, exact-artifact, five-host,
   TPS or soak entry gates.

Status: operator explicitly approved “Approve isolated A1 experiment” on
2026-10-12. This authorizes the bounded implementation and isolated experiments
above only. A production parameter selection and live activation remain unapproved.


### Timeout proof variant amendment T1 — proposal only; operator approval pending (2026-10-13)

**Status: NOT APPROVED.** This section requests review of timeout-proof reconciliation.
It authorizes no implementation, protocol activation, validator restart, identity change,
journal deletion or live release. Closure IDs, four-of-five quorum and three-QC finality
remain unchanged. A separate explicit approval is required before implementing these semantics.

**Observed boundary and limits.** Section 10, lines 135–139, permits differing reports
and excludes report subsets, reported highest QCs and carry results from the closure ID.
The current implementation at
`node-platform/crates/synergy-posy/src/engine/state_machine.rs`,
`accept_verified_timeout_certificate`, rejects a duplicate closure when its derived
parent or carry differs. The runtime at
`node-platform/bin/synergy-node/src/services/posy.rs`,
`peer_error_is_fatal`, treats this verified-certificate conflict as fatal.
On 2026-10-13 Val3 stopped with that error and durable delivery slot H10866/R2.
Stored H10866/R1 contains one candidate-bearing report among four; stored H10865/R0
contains two candidate-bearing reports among four. These are different closures:
they do not identify the incoming failing variant or prove that variant valid.
An isolated genuine-signature counterexample must independently establish the permitted
same-closure subset variation before this proposal can be qualified.

**Narrow existing-contract correction (separate from this unapproved proposal).**
A fully verified duplicate closure with the identical verified parent, noncontradictory
overlapping signed reports and no incoming carry is weaker than an already accepted
carry-bearing proof. Reject it as a stale/invalid duplicate without clearing carry,
changing projection, issuing signatures or stopping the owner. Parent conflicts,
same-validator contradictory signed reports and different carry candidates retain
their existing fail-closed classification. This is rejection
under Section 10, not the union/upgrade semantics proposed below. Candidate equality
continues to compare every native stable subject field; no signature-bearing
certificate is substituted for that semantic comparison.
A stronger duplicate at an already certified historical height is redundant only
when its carry exactly equals that independently verified QC's complete stable
candidate subject, both timeout parents equal the QC parent, and overlapping
signed reports agree. The stored timeout authority and all active signing state
remain unchanged. This historical exception does not implement carry union.

**Additional narrow rejection — operator approved 2026-10-23.** After complete
native verification, reject a duplicate at the active height as invalid rather
than stopping the owner when the accepted carry is absent, the incoming carry
is present, the verified parents are identical and overlapping signed reports
agree. Preserve the first accepted timeout and every carry, round, signing
permission, lock, finality record and durable original. This grants no carry
upgrade or report union. Historical mismatches, incompatible carry candidates,
parent conflicts and contradictory signed reports retain their existing
fail-closed handling. Qualify actual five-validator convergence and restart;
the rejection alone is not evidence of recovery or release readiness.

**Proposed rules.**

1. Independently authenticate every incoming report and its complete QC ancestry under
   the exact frozen chain, incarnation, epoch and timeout closure. Reject invalid,
   nonquorate or wrong-predecessor input without mutable consensus effects. Keep the
   existing closure ID; a duplicate proof never advances the takeover offset again.
2. Retain a bounded canonical union of reports indexed by validator for each closure.
   The union contains at most the frozen validator count (five initially), remains under
   existing byte limits, and is not a new certificate. Equivalent signature variants
   for identical signed report bytes are evidence variants. Different signed report
   bytes from one validator constitute contradictory timeout evidence: retain the
   incident and fail closed; never silently select one report.
3. Derive mandatory carry from the authenticated union using the existing two-report
   threshold and stable candidate identity. Carry may strengthen from absent to one
   candidate; it may never disappear. Two incompatible mandatory candidates fail
   closed. A subset lacking a previously verified carry is weaker evidence, not
   permission to clear that carry or unlock a conflicting vote.
4. Derive the maximum reported parent only from fully verified, compatible QC ancestry.
   Equivalent proofs of one certified block merge. A later parent must demonstrably
   extend the accepted ancestry; incompatible certified blocks or state commitments
   retain durable SafetyHalt. Neither lexical ordering nor arrival time resolves a
   fork. A duplicate timeout cannot regress a parent, lock or finalized pointer.
5. Record both the closure reference and exact authorizing report-set digest in durable
   vote/proposal authorization. Before issuing any new safety-sensitive signature,
   reconcile strengthened constraints against existing delivered proposals, durable
   votes, locks and QCs. Do not overwrite or retract an issued signature. If a pending
   unsigned proposal conflicts, reject it and proceed only through already supported
   sequential timeout authority. If reconciliation would require rewriting a durable
   vote, changing a certified block, erasing a lock or inventing authority, halt with
   the exact incompatible boundary; this amendment promises no automatic recovery
   for that unresolved safety condition.
6. For historical closures, retain evidence and compare it with the already certified
   candidate and ancestry; do not reinterpret or replace historical commits. A compatible
   stronger variant changes no committed material. An incompatible certified result
   remains SafetyHalt. Live projection is derived from the complete verified journal,
   not an empty restart or whichever proof arrived last.
7. Persist the merged evidence and verified projection transition atomically before
   publishing dependent signatures. Restart must reconstruct the same monotone parent,
   carry, predecessor chain and exact authorization digests from retained records.
   Cancel obsolete worker results; no overlapping signer or journal namespace reset.
8. Qualification must cover every four-of-five subset of one genuine five-report set,
   both arrival orders for no-carry/carry variants, five-report union, signature variants,
   same-validator contradictions, parent advancement and incompatible parents, late
   evidence before and after proposal/vote/QC boundaries, restart at each durable
   transition, retention and duplicate replay. Require unchanged closure references,
   no extra takeover increment, identical finalized execution and explicit unresolved
   safety cases. A passing subset reproducer is not full protocol qualification.

**Unresolved review requirement.** The design must prove that permitted late carry
strengthening cannot authorize two conflicting height-wide signing paths, including
a no-carry-authorized fresh vote issued before the stronger evidence arrives. If the
existing journals and sequential timeout rules cannot preserve both safety and supported
liveness in that case, revise this design before approval or implementation. Do not
convert the current fatal error into a blanket ignored exception.

### Retention clarification R4 — operator approved 2026-10-14; activation pending

This proposal narrows R3 clause 4's lifetime retention requirement. It does not
change admission, cutoff, reveal, quorum, finality, signing or timeout authority.
It is separate from the bounded in-memory recovery corrections, which preserve
all durable originals and may be qualified under the existing approved rules.

1. An obsolete protected-target journal may be retired only after its exact target
   is both canonically finalized and durably executed on this validator. Use
   independently verified local finalized and execution commitments, never peer
   height, a consumed flag alone, service health or an unsigned operator watermark.
2. Retain all targets above `min(F, E) - max(8, governed_lookahead + 2)`, including
   every future, unexecuted and still-recoverable target. Finalized targets cannot
   reopen. Missing or contradictory durable commitment evidence prevents retirement.
3. Preserve PoSy signing journals, votes, locks, QCs, TCs, finalized records,
   execution candidates, receipts and committed account state. Retire only the
   proven obsolete protected-pipeline journal, using bounded incremental cleanup
   through its existing owner; no full-history rewrite or copied runtime directory.
4. Retirement removes the old target's raw ETDAG markers, VACs, generation and
   reveal transcripts. Those raw audit proofs are not preserved in execution
   candidates; commitments, finalized transactions and receipts remain. This
   explicit audit-history tradeoff requires operator approval before deletion.
5. Qualification must prove restart and historical catch-up without retired
   journals; identical committed wallet effects and receipts; retention of delayed
   execution and every live target; rejection of insufficient/conflicting watermarks;
   symlink/path protection; and bounded cleanup work during sustained production.

Status: operator explicitly approved the R4 retirement rule on 2026-10-14,
including the raw historical ETDAG audit-proof tradeoff in clause 4. Implementation
and qualification are authorized. No existing protected journal has been deleted
under R4. Bind activation to the qualified binary and an explicitly R4-bound signed
release; candidate sequence 21 preserves the previous retention behavior.
