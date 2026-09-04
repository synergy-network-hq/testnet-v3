# Chain 1266 stall and node-incident log

Canonical network: **Synergy Testnet-v3**  
Canonical chain ID: **1266**  
Log created: **2026-07-30**

## Mandatory operating rule

Before diagnosing, changing, restarting, resetting, or deploying anything in
response to a Chain 1266 stall or node problem:

1. Read this file **from the first line through the last line**. A search,
   excerpt, dashboard summary, or handoff is not a substitute.
2. Add a new incident entry before taking a mutating recovery action, unless
   the chain is actively losing data and the entry must immediately follow the
   emergency action.
3. Record every attempted action separately. Never overwrite or omit an
   unsuccessful attempt.
4. Record the exact outcome of each action. “Fixed,” “healthy,” or “running”
   is insufficient without heights, block IDs, service states, restart counts,
   and relevant error counts.
5. If responsibility is a shared runtime defect rather than one faulty
   operator or host, say so. Do not falsely blame the validator that happened
   to expose valid evidence first.
6. An incident is resolved only after every validator agrees on an advancing
   finalized tip and the relayer, RPC, Explorer, and Atlas tiers are following
   within their declared lag bounds.

Every entry must contain:

- incident ID, detection time, status, and severity;
- first bad height and last agreed finalized block ID;
- affected and responsible nodes or runtime component;
- exact symptoms and evidence;
- root cause, distinguishing confirmed evidence from inference;
- every recovery action in chronological order and the result of each;
- final outcome, residual risks, and the next required observation.

This log is append-only. Corrections must be added as dated amendments.

---

## C1266-2026-07-30-001 — Height 90 / height 91 crash loop

**Status:** Resolved by later code changes and a Genesis reset  
**Severity:** P0  
**Detected:** 2026-07-30 11:56:58 UTC failure window; diagnosed later that day  
**First bad height:** consensus work for height 91  
**Last agreed finalized height:** 90  
**Last agreed finalized block ID:** `d0191e143cdb6525f6964a27ca62a80ebc2ab6358043c980e2b05f807928dfe0`

### Affected and responsible nodes

- Affected: `synergy-val1` through `synergy-val6`.
- The six validators were converged at height 90 before the failure.
- No individual validator operator caused the incident. The responsible
  component was the common typed PoSy runtime and its incomplete durable
  prepared-state recovery.
- The differing durable timeout records on validator 1 and validator 3 were
  evidence of the runtime defect, not validator misconduct.

### Symptoms and evidence

- All six validator services crash-looped roughly 220 times.
- Dominant failure:

  `CONSENSUS_SIGNING_CONFLICT: Timeout slot already authorizes candidate Some(BlockId("c305e182cb5d41eb4d2c9543b454a80c179a50d82ecc7e8d33642cf04c2e6fee"))`

- Validator 1 had durably authorized the timeout slot with candidate
  `c305e182…` and a prepared-VC root; validator 3 had the same slot without a
  prepared candidate.
- `safety_halts` remained zero. The signing guard prevented equivocation; this
  was a liveness failure, not a confirmed safety violation.

### Confirmed cause

The timeout slot was durable, but the highest prepared validation certificate
used to derive it was process-memory-only. After restart, a validator could
derive an empty or different timeout subject for a slot it had already
authorized. The signing guard correctly rejected that non-identical replay,
and the process repeated the same failure indefinitely.

### Recovery actions and outcomes

1. **Added durable authorization reuse for an already-used timeout slot.**
   `timeout_vote` was changed to re-emit the exact recorded authorization.
   **Outcome:** the specific timeout-slot crash loop stopped and restart counts
   stayed at zero in the next run. This was only a partial resolution: it
   exposed additional round-change source conflicts.
2. **Changed cross-round VC handling and made missing carry-forward material
   non-fatal.**  
   **Outcome:** the loud crash was removed, but the network could later halt
   silently when no proposer could reconstruct the carried candidate.
3. **Reset validator and relayer state to Genesis at 2026-07-30 14:10:43 UTC.**  
   **Outcome:** the abandoned height-90/91 state was removed and the new chain
   advanced immediately, but it stopped again at height 37. The reset proved
   the defect was in code rather than only in the height-91 data.

### Final outcome

This specific poisoned height-91 state was abandoned. Durable prepared-state
and peer-recovery work described in the next incident superseded the partial
fixes.

### Source evidence

- `launch/TYPED_FINALITY_OBSERVER_DEFECT_ANALYSIS_2026-07-30.md`
- `launch/VALIDATOR_ROUND_CHANGE_DEFECTS_2026-07-30.md`
- `launch/CLAUDE_TO_CODEX_TESTNET_V3_HANDOFF_2026-07-30.md`

---

## C1266-2026-07-30-002 — Silent carry-forward halt at height 37

**Status:** Resolved  
**Severity:** P0  
**Detected:** 2026-07-30 after the 14:10:43 UTC Genesis reset  
**First bad height:** 38  
**Last agreed finalized height:** 37  
**Last agreed finalized block ID:** recorded identically on all six validators
in the contemporaneous finality stores; the historical defect report did not
preserve the hexadecimal ID

### Affected and responsible nodes

- Affected: `synergy-val1` through `synergy-val6`; `synergy-relayer1` through
  `synergy-relayer3` followed correctly to height 37.
- Responsible component: common typed PoSy driver carry-forward and restart
  recovery.
- No individual validator was responsible. All six were active, converged,
  and running the same defective state machine.

### Symptoms and evidence

- The fresh chain advanced from 0 to 37 in approximately three minutes.
- Every validator remained `active/running`, with zero restarts and no fatal
  log line, but no further vote or block progress occurred.
- The trigger was the first round change where the eligible proposer could not
  reconstruct the prepared candidate required by the timeout certificate.

### Confirmed cause

The earlier change correctly stopped treating a missing local carried
candidate as a fatal source conflict, but it supplied no recovery path.
Prepared validation certificates were not durable, a restarted/missing
proposer could not obtain the exact certificate and proposal body from peers,
and all eligible proposers could return without proposing forever.

### Recovery actions and outcomes

1. **Persisted the prepared block, validation certificate, and applicable
   timeout certificate beside the typed finality store.**  
   **Outcome:** prepared authority survived process restart.
2. **Added authenticated, bounded peer recovery for an exact prepared
   certificate and proposal.**  
   **Outcome:** a proposer missing local carry material could request it rather
   than silently skip its duty.
3. **Added direct restart re-entry at the successor round authorized by a
   verified timeout certificate.**  
   **Outcome:** the coordinator no longer resumed at the durable tip and then
   remained idle.
4. **Added six-validator restart and carry-forward regression coverage.**  
   **Outcome:** the source-level recovery cases passed and later live chains
   advanced well beyond height 37.

### Final outcome

The height-37 failure mode was closed. A later chain reached height 266 before
a different same-round timeout-certificate merge defect stopped it.

### Source evidence

- `launch/VALIDATOR_ROUND_CHANGE_DEFECTS_2026-07-30.md`
- `launch/CLAUDE_TO_CODEX_TESTNET_V3_HANDOFF_2026-07-30.md`
- `runtime/src/consensus/typed_prepared_store.rs`
- `runtime/src/consensus/typed_coordinator.rs`

---

## C1266-2026-07-30-003 — Relayer observer rejection and stale public data

**Status:** Resolved  
**Severity:** P0 public-tier launch blocker  
**Detected:** 2026-07-30 12:30 UTC and again after later resets  
**Consensus height at first diagnosis:** validators 90; public RPC and Atlas 0  
**Abandoned public height after reset:** 90

### Affected and responsible nodes

- Affected: `synergy-relayer1`, `synergy-relayer2`, `synergy-relayer3`,
  `synergy-rpc`, `synergy-index`, Atlas API, and Atlas Indexer.
- Responsible components:
  - typed finality observer incorrectly required process-local live timeout
    authority for a durable round-greater-than-zero finalized record;
  - inbound DNS allowlist matching stripped the port before resolution;
  - RPC RocksDB and Atlas PostgreSQL retained abandoned-chain data after a
    validator reset.
- No validator caused this public-tier issue.

### Symptoms and evidence

- Relayers repeatedly rejected valid finalized records with
  `round 1 is not authorized`.
- The RPC gateway was rejected as
  `not from a configured public service role`.
- Validators reached 90 while the public RPC and Atlas remained at 0.
- After a later validator reset, the public tier could continue to display the
  abandoned height-90 chain until its own state was explicitly cleared.

### Recovery actions and outcomes

1. **Added finalized-record round authority distinct from the live signing
   path.**  
   **Outcome:** all three relayers imported round-greater-than-zero records
   without weakening validator signing checks.
2. **Resolved configured DNS host and port together on inbound authorization.**  
   **Outcome:** the RPC Gateway matched its configured public-service identity.
3. **Deployed relayers first, then RPC and Explorer.**  
   **Outcome:** observer stores followed the validators in lockstep.
4. **On the 2026-07-30 final Genesis reset, deleted the RPC and Explorer
   chain-derived state and truncated Atlas’s 24 chain-derived tables while
   preserving six validator profiles.**  
   **Outcome:** Atlas returned to height 0 with no abandoned blocks, then
   indexed only the new chain. At the later height-54 sample it contained
   blocks 0 through 54, six active validators, and no validator with zero
   produced blocks.

### Final outcome

Resolved for the current fresh chain. Public readiness must still be checked on
every incident because an active Atlas service can serve stale data.

### Source evidence

- `launch/TYPED_FINALITY_OBSERVER_DEFECT_ANALYSIS_2026-07-30.md`
- `launch/VALIDATOR_ROUND_CHANGE_DEFECTS_2026-07-30.md`
- `work/atlas-purge-chain-data.sh` in the operator workspace

---

## C1266-2026-07-30-004 — Same-round timeout evidence conflict at height 266

**Status:** Resolved by code fix plus explicitly authorized fresh-Genesis reset  
**Severity:** P0  
**Detected:** 2026-07-30 approximately 19:26–19:28 UTC  
**First bad height:** 267  
**Last agreed finalized height:** 266  
**Last agreed finalized block ID:** `6685744abc37eefab8a6a3aa2ee2bddf74dc7185bbb03048b66c04c2269b32c5`

### Affected and responsible nodes

- Affected: `synergy-val1` through `synergy-val6`.
- All six eventually agreed on height 266 and the block ID above, then each
  automatically restarted twice on the old runtime.
- Validator 1 held a valid round-2 timeout certificate carrying the prepared
  candidate. Validators 2, 4, 5, and 6 held a valid weaker no-carry
  certificate from another strict-quorum subset. Validator 3 later recovered
  the stronger carried evidence.
- No individual validator was at fault. With six validators, two different
  valid 5-of-6 timeout-certificate signer subsets can omit or include the sole
  timeout vote reporting a prepared candidate. The responsible component was
  the shared driver comparison logic.

### Symptoms and evidence

- Fatal error on every validator:

  `TYPED_DRIVER_SOURCE_CONFLICT: timeout certificates disagree on round or carry-forward source`

- The services exited and restarted while attempting height 267.
- The certificates closed the same consensus round and authorized the same
  transition, but differed in signer subset and strength of prepared evidence.

### Confirmed cause

The driver treated the raw timeout-certificate evidence—including signer
subset and carry/no-carry detail—as a unique consensus source. It should have
compared the verified transition context, retained or upgraded to stronger
prepared-candidate evidence, and rejected only a genuinely different prepared
candidate for the same transition.

### Recovery actions and outcomes

1. **Changed same-round timeout handling to compare transition context,
   retain stronger carry evidence, and upgrade a previously installed
   no-carry transition.** Source revision
   `d76dbf3ef315beca3a31974f7785d76b14e6e71c`.  
   **Outcome:** 28 typed-coordinator tests passed, including a regression with
   two valid 5-of-6 timeout-certificate subsets. The new runtime stopped the
   fatal restart loop.
2. **Stopped all six validators and staged the `d76dbf3…` runtime without
   erasing height-266 finality. Restarted all six together.**  
   **Outcome:** all six stayed active with zero new restarts, but finality did
   not advance. The durable round split remained: validators 1 and 3 recovered
   the stronger round-2-to-3 carry transition, while validators 2, 4, 5, and 6
   remained on weaker round-1-to-2 evidence.
3. **Synchronized the exact stronger prepared record already verified and
   persisted by validator 3 across all six stopped validators, then started
   them together.**  
   **Outcome:** the files were byte-identical and ownership/mode remained
   `node:node 0600`. The user then explicitly ordered the height-266 chain
   abandoned and reset before this attempt could be declared successful.
4. **Diagnosed the remaining startup liveness gap.** Signed validation,
   finality, and timeout votes were emitted once. Peers whose typed mailbox was
   not yet installed rejected or missed the message, and no retransmission
   repaired the loss.  
   **Outcome:** this explained why valid durable state could remain split after
   a coordinated restart without another fatal error.
5. **Added periodic retransmission of the exact already-authorized signed
   vote, without creating a new vote subject.** Source revision
   `606ec51f303b0cf19843f9da257d15ef38186681`. Added regression
   `driver_rebroadcasts_identical_vote_after_remote_mailbox_startup_loss`.
   **Outcome:** the regression passed; the complete typed-coordinator module
   passed 28/28 before the additional regression and the new focused regression
   passed separately.
6. **Built immutable v20.0.0 Linux artifacts in Control Panel workflow run
   `30580144756` and verified all five checksums and ELF architecture.**  
   **Outcome:** validator SHA-256
   `5c9c115c1288d110d77d9da25712367c67f1d6bd6c99ec88494c2790575572fb`;
   relayer SHA-256
   `59db301cd3ae3dd039795e502eea1e0661bda39baa468fa96303ba3ad462cd85`;
   generic SHA-256
   `87121f473c43e166a27ac31150e4f4186d771492b4057e44fb0531bdd42e7f39`.
7. **Performed the user-authorized fresh-Genesis reset.** Explicitly removed
   disposable Chain 1266 state on validators 1–6, relayers 1–3, RPC Gateway,
   Explorer Indexer, and bootnodes 1–3. Truncated Atlas chain-derived tables.
   Started boot/seeds, relayers, RPC, Explorer, and Atlas before validators.
   **Outcome:** every tier began at height 0 with no stale chain.
8. **Started all six validators together on the `606ec51f…` runtime.**  
   **Outcome at 2026-07-30 20:55:23 UTC:** all six had the same height 68 and
   block ID
   `c01c919be9d30507ef4fa8543db34211aa4b95f5c92ea5994976de0942a939ea`;
   five non-zero-round blocks had finalized, the maximum finalized round was
   4, every validator had zero restarts, and fatal consensus/signing conflict
   count was zero. RPC and Atlas were at 66 with Atlas lag 0 relative to RPC.
   Atlas reported six active validators and every validator had produced at
   least one block.

### Final outcome

The current fresh chain crossed the prior height-37 failure, exercised five
non-zero-round finalizations including round 4, and remained converged and
advancing. Continue monitoring; append a new incident rather than rewriting
this one if progress stops again.

### Source evidence

- `runtime/src/consensus/typed_coordinator.rs`
- `runtime/src/rpc/rpc_server.rs`
- `launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json`
- Git commits `d76dbf3`, `606ec51`
- GitHub Actions run `30580144756`

---

## C1266-2026-07-30-005 — Excessive finalized block time

**Status:** Open  
**Severity:** P0 launch-performance defect  
**Detected:** 2026-07-30 21:02:14 UTC  
**First bad height:** 1; the defect affects the healthy path from Genesis  
**Last agreed finalized height:** 117  
**Last agreed finalized block ID:** `67e9ee912ef75a8a0b85019733b1346cb36c6064f7d4adedcbd3c742a112cece`

### Affected and responsible nodes

- Affected: `synergy-val1` through `synergy-val6`, plus Atlas block-time
  reporting.
- All six validators agreed at height 117, were active, had zero restarts, and
  reported the same finalized block when this incident was recorded.
- No individual node is responsible. The confirmed performance defect is in
  the common typed PoSy coordinator scheduler. Atlas also presents
  batch-ingestion timestamps as if they were consensus production timestamps
  when the consensus-bounded header timestamp is unavailable.

### Symptoms and evidence

- Atlas displayed an average block time of approximately 7.32 seconds, above
  the canonical 2,000 ms target.
- Earlier approximately 0.02-second readings occurred when multiple already
  finalized blocks were imported and timestamped in one Atlas batch; they were
  not real consensus intervals.
- Validator 1's durable finality-signing journal contained 74 measurable
  consecutive intervals. All 74 exceeded three seconds:
  - overall average 6.346 seconds;
  - healthy round-0 average 4.182 seconds across 62 intervals;
  - five intervals exceeded ten seconds;
  - maximum 61.892 seconds at round 7.
- The latest 30 measurable intervals averaged 8.669 seconds.
- Across validators 1–6, the latest 31 finality-signing records averaged
  between 8.030 and 9.196 seconds.

### Confirmed cause

`TypedPosyDriver::tick_at` waits for the complete 1,500 ms proposal timeout
before emitting a validation vote, then waits until 3,000 ms from round start
before emitting a finality vote. Those governed values are failure deadlines,
but the implementation treats them as mandatory healthy-path sleeps.
Consequently an ideal round cannot form a finality certificate before roughly
three seconds, and live cryptography/networking pushes the observed round-0
average above four seconds. Incoming authenticated proposals and validation
certificates are recorded but do not immediately trigger the corresponding
vote.

Atlas has a separate reporting defect: finalized typed blocks currently carry
zero in `timestamp_ms_consensus_bounded`, so batched index time can produce
both implausibly small readings such as 0.02 seconds and exaggerated gaps.

### Recovery actions and outcomes

1. **Read the complete Chain 1266 incident log and measured validator signing
   intervals before changing runtime state.**  
   **Outcome:** the delay was proven in validator evidence rather than inferred
   only from Atlas. The chain remained converged and advancing at height 117,
   so no reset or emergency restart was justified.
2. **Changed the typed coordinator to emit validation and finality votes
   immediately after authenticated proposal and validation-certificate
   acceptance. Retained 1,500/1,500/1,500/10,000 ms as failure deadlines and
   retained independent retransmission of every locally authorized phase
   vote.** Source revision
   `a9fb7a07b839929d945baccb16be5ff1908db7eb`.  
   **Outcome:** all 30 typed-coordinator tests passed. A new six-validator
   regression finalized a healthy round before any stage deadline with one
   validation and one finality vote per replica and zero timeout votes.
   Startup-loss, two-timeout-round, carried-candidate, missed-QC, and
   successor-height recovery regressions also passed.
3. **Pushed the immutable source and authorized it in both guarded staging
   scripts and the Control Panel release variables. Started Control Panel
   workflow run `30583401875`.**  
   **Outcome:** the workflow accepted the exact source binding and began the
   corrected Linux runtime build. Deployment and live timing verification were
   still pending when this action was recorded.
4. **Deployed the verified `a9fb7a07…` artifacts to Relayers 1–3, the RPC
   Gateway, Explorer Indexer, and all six validators using a coordinated
   stop-stage-start cutover for the validator quorum.**  
   **Outcome:** the height-246 successor split cleared without deleting chain
   state. All six validators converged and advanced through height 311 with
   zero service restarts or fatal signing conflicts.
5. **Measured the post-cutover signing cadence and runtime load instead of
   relying on Atlas. Inspected the typed driver's proposal/vote retry paths and
   duplicate-message verification order.**  
   **Outcome:** round-0 finality intervals remained approximately 5.5–6.6
   seconds and each validator consumed approximately 104–114% of one CPU core.
   The remaining delay is a self-inflicted authenticated replay workload:
   proposals and every retained ML-DSA vote were rebroadcast every 250 ms, and
   exact duplicate votes underwent full post-quantum verification again.
6. **Implemented one bounded retry before the 1,500 ms stage deadline,
   stopped superseded phase-vote retries, stopped same-round proposal retries
   after preparation, and added an authenticated exact-vote replay fast path
   that rejects changed signatures through normal verification.**  
   **Outcome:** the full typed-coordinator module passed 31/31 tests, including
   healthy finality, startup loss, two timeout rounds, carried-candidate
   recovery, missed-QC recovery, bounded ingress, and the new exact-replay
   tamper regression. No live node has received this performance correction
   yet.
7. **Built the correction from immutable source revision
   `d373e778f683dbf96d638736adcef89e0d127951` in Control Panel workflow
   `30585860119`, downloaded its runtime artifact, verified all five published
   checksums, and reread this incident log from first line through last line
   before deployment.**  
   **Outcome:** the artifact is source-bound, all three role binaries are
   x86-64 Linux v20.0.0 executables, and the validator binary SHA-256 is
   `df5333ac6d688cfb8b9625821c039a6a316c2d480787d8d1302f2369851abedf`.
   Planned mutation: switch the five support roles first, stop and stage all
   six validators inactive, then start the six-validator quorum together.
8. **Attempted the guarded support-tier switch concurrently on Relayers 1–3,
   RPC Gateway, and Explorer Indexer.**  
   **Outcome:** every new process remained systemd-active but failed to expose
   its local Chain 1266 RPC within the helper's 180-second readiness window.
   Each helper exited nonzero and performed its automatic rollback. The prior
   support runtimes were restored; no validator service or chain state was
   changed. Startup journals and rollback evidence must be compared before
   another switch.
9. **Amendment to action 8 after inspecting every live process, backup, and
   startup journal:** the helper printed a readiness failure but its ERR trap
   was bypassed by `fail` calling `exit`; therefore it did not roll back.
   Relayer RPC became ready 187–222 seconds after node startup, just beyond the
   180-second gate. Replaced the ERR trap with an armed EXIT rollback handler
   and extended the support-role RPC gate to 360 seconds.  
   **Outcome:** Relayers 1–3 are active with zero restarts on runtime SHA-256
   `f0d27ae27a56ccdb81989aa309416c5095469f9f1dfe4a870df65cce5a03e132`;
   RPC Gateway and Explorer Indexer are active with zero restarts on SHA-256
   `012f9081da22ef4887e83f4db8717bcede79d40848fd6826fe05d24ab51772a5`.
   All five local RPC endpoints return Chain 1266 and canonical Genesis.
   Validator services and chain state remain unchanged.
10. **Stopped all six validators at their identical height-326 block
    `3ac974e616171f5cfdfd009ffe40a3d2c98f655e5de58e08694afaf1a94cc879`,
    staged runtime SHA-256 `df5333ac…` on every inactive host, and started all
    six together. Measured durable finality-signing times through height 330.**  
    **Outcome:** all validators remained converged with zero restarts and zero
    fatal signing/consensus conflicts, but performance was not resolved.
    Heights 328–330 finalized in rounds 5, 4, and 2 at approximately 18–30
    second intervals; validator CPU returned to approximately 91–107% of one
    core. No chain data was removed.
11. **Traced the complete certificate formation and verification path using
    the live phase timestamps and source, rather than applying another timer
    change.**  
    **Outcome:** every incoming vote is fully ML-DSA-65 verified once, but each
    replica then verifies the same five cached votes again while assembling a
    certificate and verifies those same five signatures a third time through
    the completed certificate. Every replica independently repeats this for
    validation, finality, and timeout certificates, and received certificates
    repeat the verification again. The local validation-certificate work alone
    took approximately two seconds in live evidence, exceeding the 1,500 ms
    failure deadline. Exact retry deduplication cannot solve this mandatory
    repeated-cryptography path.
12. **Added a 4,096-entry bounded positive verification cache keyed by the
    complete domain-signature transcript, including public-key bytes, while
    retaining lifecycle/role/algorithm checks before every lookup. Built
    immutable source `fd3b3e4d882b17e3393a13645984f044fdedc32b` in workflow
    `30587342645`, verified all artifact checksums, and reread this complete
    log before deployment.**
    **Outcome:** altered payloads and signatures remain rejected and never
    enter the cache. Aegis verifier tests passed 6/6, PoSy certificate/safety
    tests passed 10/10, and typed-coordinator recovery/liveness tests passed
    31/31. The validator artifact SHA-256 is
    `5ed84c7f608173ce6013b5879c881c44ce2227f428cfd38161f70880718c4550`.
    Live deployment and sustained timing evidence are pending.
13. **Stopped the cache-only live rollout when the operator supplied the
    complete architectural diagnosis and ordered the piecemeal rollout
    abandoned. Cancelled Control Panel workflow `30587342645` and performed
    read-only process checks on every support role and validator.**
    **Outcome:** the cancellation completed with workflow conclusion
    `cancelled`. Before the stop reached the already-running guarded helpers,
    all three relayers had completed on role binary SHA-256
    `8e329e835a7e6e30953005081ea003e901f01907ced346ed07f7554a4abd7966`;
    RPC Gateway and Explorer Indexer had completed on generic binary SHA-256
    `ee5834c94f469c45d88a359a8bbec2320d3aa51217a23bda400f12f57077491c`.
    All five support services were active with zero restarts. No validator
    deployment helper was invoked: validators 1–6 remained active with zero
    service restarts on the preceding replay-bound release (validator SHA-256
    `df5333ac6d688cfb8b9625821c039a6a316c2d480787d8d1302f2369851abedf`).
    The partially deployed cache release is explicitly **not** accepted as a
    release candidate or health result. The operator required one unified
    implementation of canonical consensus-subject identity, certificate
    equivalence/merge, durable atomic recovery, startup readiness gating,
    role-based protocol authorization, verified-transcript reuse, a bounded
    PQ worker pool/cache, the complete invariant/fault matrix, and then a full
    disposable Chain 1266 state wipe and clean-Genesis restart.

### Final outcome

Open. Safety and forward progress are restored, but the tested replay-pressure
correction must be built, deployed coherently, and measured against the
sub-two-second target. Atlas must separately stop labeling batch-ingestion
intervals as block-production time.

### Residual risks and next observation

After a fixed immutable runtime is deployed, verify actual signed consecutive
finality intervals on all six validators, including average and p95, and
separately verify Atlas's displayed metric against authoritative timing
evidence.

### Source evidence

- `/tmp/chain1266-finality-intervals.tsv` on the operator machine
- `/var/lib/synergy/validator/data/typed-posy-finality.json` on validators 1–6
- `/var/lib/synergy/validator/data/consensus_signing_authorizations.json` on
  validators 1–6
- `runtime/src/consensus/typed_coordinator.rs`

---

## C1266-2026-07-30-006 — Post-finality successor-height split at height 246

**Status:** Resolved  
**Severity:** P0  
**Detected:** 2026-07-30 approximately 21:29 UTC  
**First bad height:** 247  
**Last agreed finalized height:** 246  
**Last agreed finalized block ID:** `a8eaf5d303ad3ca5ba2ffc86f1df15d425dc1030bffd48dd4dc27b4481b9e6bc`

### Affected and responsible nodes

- Affected: `synergy-val1` through `synergy-val6`.
- All six validator services remained active with zero restarts and exposed
  the same finalized height and block ID.
- No individual node is responsible. The split occurred in the shared typed
  coordinator after a valid round-2 finality event.

### Symptoms and evidence

- The finalized tip remained unchanged at height 246 across repeated samples.
- Validators 1, 2, 4, and 5 retained a stale durable prepared record for
  height 246 after that height was finalized. Their latest signing
  authorization was a height-246 round-3 timeout carrying candidate
  `1ce93f5dba108d3bf090015dda9bb28f0a7c408c059a57841312f504b4c5087e`.
- Validators 3 and 6 had correctly cleared the height-246 prepared record and
  authorized a height-247 round-0 no-carry timeout.
- Every validator's typed finality store contained height 246 and the same
  block ID. Validator 6 held a different valid QC proof root from the other
  five, consistent with independently assembled strict-quorum signer subsets;
  the finalized block subject did not differ.
- No validator had restarted and no fatal consensus/signing conflict appeared.

### Confirmed cause

The durable evidence confirms a post-finality successor-state split, not a
block fork: four replicas retained prior-height prepared/round state while two
entered height 247. The exact triggering code path is inferred from the old
runtime: `emit_finality_vote` can itself complete the QC and reset the driver,
after which the caller unconditionally writes the previous height's
`Finality` stage. This can overwrite the successor reset and leave replicas
with different process-local stage and stale prepared-state cleanup outcomes.

The already-tested `a9fb7a07…` runtime guards that assignment with the original
height and round, so a locally completing finality vote cannot overwrite the
successor reset. Its restart path also clears a prepared record whose height
is already finalized.

### Recovery actions and outcomes

1. **Read this incident log from top to bottom and compared finality stores,
   finality heads, prepared stores, signing journals, service states, and
   restart counts on all six validators.**  
   **Outcome:** confirmed one finalized block with no safety divergence and a
   4/2 successor-state split. No chain data was deleted and no service was
   restarted during diagnosis.
2. **Downloaded and independently verified Control Panel workflow
   `30583401875` artifact `testnet-v3-linux-runtime-hotfix`.**  
   **Outcome:** every published checksum passed, the ELF binaries are x86-64
   Linux executables, and `TESTNET_SOURCE_REVISION` binds the artifact to
   `a9fb7a07b839929d945baccb16be5ff1908db7eb`. The validator binary SHA-256 is
   `20018822311a70c0fe7279a4853f5b951b4ea49b464dea1c94915b45b0ec266c`.
   No live service was changed at this checkpoint.
3. **Switched Relayers 1–3, the RPC Gateway, and the Explorer Indexer to the
   exact `a9fb7a07…` role-bound artifacts before touching validators.**  
   **Outcome:** all five guarded switches completed without rollback, each
   local RPC returned Chain 1266 and the canonical Genesis hash, and all five
   services were active on the new runtime. Backups were written under
   `/var/backups/synergy-testnet-v3/runtime-hotfix-*` on the assigned hosts.
4. **Stopped all six validators, staged the exact role-bound validator binary
   on every host while inactive, verified its version and checksum, then
   started all six together.**  
   **Outcome:** all validators cleared the stale height-246 state, converged
   on height 247, and continued together through height 311. All six services
   remained active with zero restarts and no fatal consensus or signing
   conflict. No finalized data was deleted.

### Final outcome

Resolved. The agreed height-246 finality was preserved and the six validators
resumed one canonical successor chain. The remaining excessive block interval
is tracked separately in incident C1266-2026-07-30-005.

### Residual risks and next observation

Continue monitoring identical finalized block IDs and zero restart/fatal-error
counts while the performance correction for incident 005 is deployed.

### Source evidence

- `/var/lib/synergy/validator/data/typed-posy-finality.json` on validators 1–6
- `/var/lib/synergy/validator/data/typed-posy-prepared.json` on validators 1–6
- `/var/lib/synergy/validator/data/consensus_signing_authorizations.json` on
  validators 1–6
- `runtime/src/consensus/typed_coordinator.rs`
- Control Panel workflow run `30583401875`

---

## New incident template

Copy this entire section to the end of the file before a mutating response:

```markdown
## C1266-YYYY-MM-DD-NNN — Short incident name

**Status:** Open | Monitoring | Resolved  
**Severity:** P0 | P1 | P2  
**Detected:** YYYY-MM-DD HH:MM:SS UTC  
**First bad height:**  
**Last agreed finalized height:**  
**Last agreed finalized block ID:**  

### Affected and responsible nodes

### Symptoms and evidence

### Confirmed cause

### Recovery actions and outcomes

1. **Action.**  
   **Outcome:**

### Final outcome

### Residual risks and next observation

### Source evidence
```

## Controlled operation — 2026-07-31T22:08:48Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## C1266-2026-08-01-013 — Ring 2 legacy-validator quarantine gate omitted the active public service

**Status:** Contained; a fresh private qualification is required
**Severity:** P1 qualification-integrity failure
**Detected:** 2026-08-01 10:36 UTC
**First bad height:** Not established; RC7 failed at its first running-state snapshot

### Confirmed facts

- RC7 completed private material generation, paused-readiness, WireGuard mesh, and signed-start
  barriers, then the common-time metrics request to private validator 3 was refused. The run
  failed closed and its cleanup removed the disposable roots, interface, and units from all six
  validator hosts.
- The Ring 2 control gate checked only `synergy-chain1266-role@validator-node-0N.service`, but
  the fleet inventory also declares `synergy-validator.service` as the legacy canonical validator
  service. All six of those legacy services were active and crash-looping at inspection time
  (restart counters 900 or greater).
- This proves the preflight was incomplete. It does not by itself prove that the concurrent legacy
  crash loops caused validator 3's private metrics listener to disappear.

### Containment and repair

1. Stopped only `synergy-validator.service` on validator hosts 1 through 6. Each now reports
   `ActiveState=inactive`, `SubState=dead`, with restart counters stable after the stop. No public
   data, keys, genesis, configuration, or non-validator public role was changed.
2. Committed `ac99f4c` to make both the Ring 2 control-plane gate and the runner reject active or
   activating legacy validator services, including an immediate recheck before signed release.
   The focused control-plane behavior test, Bash syntax check, and whitespace check passed.

### Required next step

Create a runner-only RC8 package from the already verified `ae413ce31cae27970ae6ccc16999e563878ed433`
executables, run fresh preflight, and repeat the full private six-host qualification from Genesis.
No public-chain promotion is authorized from RC7.

## C1266-2026-08-01-014 — Ring 2 per-second metrics collection destabilized observation before smoke gate

**Status:** Contained; runner-only correction ready for a fresh private run
**Severity:** P1 qualification observability and performance risk
**Detected:** 2026-08-01 10:49 UTC
**First bad height:** Approximately 55

### Confirmed facts

- RC8 cleared private material, paused-readiness, mesh, legacy-service recheck, signed start, and
  the first live snapshot. A separate read-only sample then showed all six private validators at
  heights 31--33, round 0, with mean finality about 1.8 seconds.
- Near height 55, validator 1 reported mean finality 2.668 seconds and 83.6% round-zero finality.
  The simultaneous snapshot cycle then encountered metrics connection resets/refusals and failed
  closed. Disposable cleanup was verified CLEAN on all six validator hosts.
- The runner requested six complete metrics payloads every second. Its direct redirection also
  truncated the prior evidence files before a replacement response completed, leaving no durable
  last-good snapshot after the collection failure.

### Assessment

The early degradation is not yet proof of a runtime safety or liveness defect. The qualification
collector itself was placing repeated concurrent full-metrics load on all validators and could
both perturb finality and erase the evidence required to distinguish infrastructure failure from a
chain fault. RC8 is therefore inconclusive and is not promotable.

### Repair and validation

Committed `3178264652c4cb4eb30d73a799b8c0193a16a6cb`:

1. Writes each common-time response to a unique temporary file and atomically renames it only
   after all six validated responses are present.
2. Retries a failed coherent snapshot three times and records an explicit
   `QUALIFICATION_INFRASTRUCTURE_FAILURE` if all attempts fail.
3. Captures run-specific service state, listener state, and journals before disposable cleanup.
4. Samples at a ten-second cadence (configurable only within 5--30 seconds), preserving the
   cumulative finality gates without observer-induced per-second load.

`bash -n`, the focused snapshot-resilience assertions, and `git diff --check` passed. The runtime
executables remain the Ring-1-verified `ae413ce31cae27970ae6ccc16999e563878ed433` set; no binary
rebuild is required.

## C1266-2026-08-01-009 — Ring 2 binaries missing compiled source revision

**Status:** Open; private qualification aborted before consensus and cleanup pending
**Severity:** P1 qualification gate failure
**Detected:** 2026-08-01 02:26:26 UTC
**First bad height:** None; every validator remained below the paused-readiness barrier
**Last agreed finalized height:** 0 (no signed start command was issued)
**Last agreed finalized block ID:** N/A

### Affected and responsible nodes

- Affected only the disposable Ring 2 roles for release `chain1266-incarnation-4-rc2`.
- The public Chain 1266 services, data, and Atlas were not changed.
- Responsible component: Linux release build provenance injection, not a validator or P2P runtime.

### Symptoms and evidence

- Each private validator unit exited before `PAUSED_READY` with:
  `Failed to validate Chain 1266 desired state: release binary omits compiled Testnet-v3 revision`.
- The runner remained at its paused-readiness barrier; no validator finalized a block and no
  start-consensus command was distributed.
- The immutable package checksum manifest verified, so the failure is an intentional
  desired-state provenance gate rather than a corrupted transfer.

### Confirmed cause

The `rc2` binaries were compiled from a source cache that does not provide the revision metadata
expected by the role-service desired-state verifier. The package manifest correctly declared
source revision `6b2a6a459632f744821b50b0a3bb31ccca289bd1`, but the executable was built without
the corresponding compiled Testnet-v3 revision binding.

### Recovery actions and outcomes

1. **Captured service status and the exact desired-state rejection from all six validators.**
   **Outcome:** failure occurred before P2P readiness or consensus; no production service was
   contacted or changed.
2. **Requested controlled termination of the local private qualification supervisor.**
   **Outcome:** pending verification that its cleanup trap removes only this run's disposable
   units, overlay, roots, and data paths.

### Final outcome

Open. The release artifact is not eligible for another Ring 2 attempt until the build embeds the
same source revision that the desired-state manifest declares.

### Residual risks and next observation

Verify the exact build-time provenance input and the binary's exposed revision before rebuilding.
Do not bypass the desired-state gate or edit source while a qualification run is active.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260801021742/
- launch/chain1266-systemd/chain1266-role-service
- /tmp/chain1266-compile-20260731/ring2-private-release-6b2a6a4/

### Amendment — 2026-08-01 02:39 UTC

3. **Rebuilt all nine Linux role and control binaries with Git-derived compiled source bindings.**
   **Outcome:** the build supplied `SYNERGY_TESTNET_V3_SOURCE_REVISION`,
   `SYNERGY_SYNQ_SOURCE_REVISION`, and `SYNERGY_AEGIS_SOURCE_REVISION` from the checked-out
   revisions. The rebuilt validator binary contains all three bindings; its SHA-256 is
   `422de401ea4b350f929f1d58f3c0f610d658e2f95b13085c36fc7a094abac5a4`.
4. **Created immutable private-only release `chain1266-incarnation-4-rc3`.**
   **Outcome:** every entry in
   `/tmp/chain1266-compile-20260731/ring2-private-release-6b2a6a4-provenance/SHA256SUMS`
   verified, and its desired-state manifest declares the same three source revisions that its
   binaries compile. A new preflight and qualification run are required; `rc2` remains rejected.

## Controlled operation — 2026-07-31T22:10:02Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## C1266-2026-07-31-007 — Ring 2 private-genesis legacy peer endpoints

**Status:** Corrected and smoke-verified; fresh qualification rerun pending  
**Severity:** P1 qualification gate failure  
**Detected:** 2026-07-31 23:31:49 UTC  
**First bad height:** None; all private validators remained paused at height 0  
**Last agreed finalized height:** 0 (no signed consensus release occurred)  
**Last agreed finalized block ID:** N/A

### Affected and responsible nodes

- Affected only the disposable Ring 2 qualification units on the six validator hosts.
- The public Chain 1266 fleet remained inactive; Atlas was not touched.
- Responsible component: the private qualification material generator, which
  replaced validator public keys but preserved legacy endpoint strings in the
  generated private genesis.

### Symptoms and evidence

- All twelve disposable units were created with distinct temporary identities,
  data paths, WireGuard interface, firewall chain, and systemd template.
- Validator startup failed closed at the paused-ready gate. The journal from
  validator 1 recorded peer dials to 10.70.10.*:5622 and then timed out
  waiting for finalized typed PoSy peer readiness.
- The configuration renderer correctly emitted 10.126.* addresses, proving
  a second endpoint source remained in the generated private genesis.
- No validator advanced, no start command was distributed, and no public
  service or public chain-derived state changed.

### Confirmed cause

build-chain1266-private-ring-material changed only the active validators'
ML-DSA-65 public keys. Its output retained the canonical 10.70.* endpoint
strings that the runtime obtains from private genesis metadata, so the
disposable hosts attempted to dial the production-overlay range instead of
the isolated 10.126.* overlay.

### Recovery actions and outcomes

1. **Captured the failed-unit evidence and stopped the local supervised
   qualification job.**  
   **Outcome:** the runner's cleanup trap removed the temporary roots, data
   roots, unit template, units, firewall rules, and WireGuard interfaces from
   all six hosts; each host verified CLEAN.
2. **Extended the private material generator with an explicit complete
   endpoint map and a fail-closed legacy-overlay guard.**  
   **Outcome:** source commit 78853ed was built on Linux; its installed helper
   hash is `04897fc5042db8695570a0d62b3e74225b022f9926c155795017ec461f7069aa`.
   Its disposable smoke generated a private genesis and all twelve configs
   free of 10.70.*; smoke private keys were removed.
3. **Added a real-host runner pre-service guard over both generated genesis
   and rendered configs.**  
   **Outcome:** source commit 53d1205 aborts before distribution or service
   creation if any 10.70.* reference survives.

### Final outcome

The failed Ring 2 run produced no consensus blocks and no production mutation.
Cleanup was verified across all six validator hosts. A fresh preflight and
qualification run are required; the corrected generator has passed its
targeted material smoke test.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260731232419/
- runtime/src/bin/build-chain1266-private-ring-material.rs
- scripts/chain1266/run-ring2-real-host-qualification.sh


## Controlled operation — 2026-07-31T22:28:18Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:30:01Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:32:39Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:33:37Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:36:07Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:36:51Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:46:05Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T22:56:21Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T23:07:21Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive


## Controlled operation — 2026-07-31T23:25:12Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## Controlled operation — 2026-08-01T00:59:33Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc1`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## C1266-2026-08-01-008 — Ring 2 runtime resolved private peers through the public transport registry

**Status:** Open; source correction awaiting focused verification and a fresh private qualification
**Severity:** P1 qualification gate failure
**Detected:** 2026-08-01 01:48:13 UTC
**First bad height:** None; every private validator remained paused at height 0
**Last agreed finalized height:** 0 (no signed start command was issued)
**Last agreed finalized block ID:** N/A

### Affected and responsible nodes

- Affected only the disposable Ring 2 validator and downstream-role units.
- The public Chain 1266 services, state, and Atlas were not changed.
- Responsible component: private-qualification transport resolution in the common P2P runtime.

### Symptoms and evidence

- The second private run rendered only `10.126.*` endpoints, but every validator failed its
  paused-ready gate while attempting `10.70.10.*:5622` peer dials.
- The validators therefore observed fewer than the five required remote validator peers; no
  consensus process passed the barrier or finalized a block.
- The private resolver also attempted the public transport-registry path before cleanup.

### Confirmed cause

The rendered private configuration retains canonical logical validator identifiers. Before this
incident, the runtime resolved those identifiers through the signed public transport registry and
classified only the production `10.70.*` validator and relayer ranges as valid. The configured
private `10.126.*` transport map was consequently not usable by the qualification process.

### Recovery actions and outcomes

1. **Stopped the local qualification supervisor and allowed its cleanup trap to run.**
   **Outcome:** no consensus start command or public mutation occurred; the prior live snapshot
   confirms no Chain 1266 process or private overlay remains on validator hosts 1 through 6.
2. **Added private-qualification transport resolution that skips the public registry and permits
   only the isolated `10.126.10.*` transport map.**
   **Outcome:** source is pending focused Rust verification; it is not yet an accepted release.
3. **Identified the remaining outgoing-relayer scope check that still recognized only
   `10.70.20.*`.**
   **Outcome:** it will be corrected before the focused test and Linux artifact build.

### Final outcome

Open. The failure was contained before consensus and a new immutable private-ring artifact is
required. The production fleet remains quarantined.

### Residual risks and next observation

The private resolver must prove that it accepts the isolated validator and relayer ranges only in
qualification mode while production continues to reject unsigned static fallback and retains its
canonical public transport requirements.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260801005525/
- runtime/src/p2p/networking.rs
- scripts/chain1266/run-ring2-real-host-qualification.sh

### Amendment — 2026-08-01 02:08 UTC

4. **Completed the isolated resolver repair and focused release-mode tests.**
   **Outcome:** source revision `6b2a6a459632f744821b50b0a3bb31ccca289bd1` passed
   `private_qualification_static_transport_requires_the_isolated_overlay` and
   `production_transport_resolution_rejects_unsigned_static_fallback`. The private path admits
   only `10.126.10.*` and `10.126.20.*` in qualification mode; the production path retains its
   public signed-transport requirement.
5. **Ran the three missing deterministic qualification proofs from the same release-mode test
   harness.**
   **Outcome:** the retirement-watermark journal compaction, authenticated stale-finalized
   pre-crypto rejection, and six-validator real ML-DSA-65 multi-height burn-in all passed. The
   first direct invocation of the journal test failed only before its assertion because the SSH
   working environment lacked `SYNERGY_GENESIS_FILE`; rerunning with the checked-in test fixture
   passed without source or node changes.
6. **Built all nine Ring 2 role and control binaries and created a new private-only immutable
   package.**
   **Outcome:** every entry in
   `/tmp/chain1266-compile-20260731/ring2-private-release-6b2a6a4/SHA256SUMS` verified. The
   package is release `chain1266-incarnation-4-rc2`, binds the source revision above, and includes
   the corrected runtime and configuration renderer. Fresh real-host preflight and qualification
   are still required.

## Controlled operation — 2026-08-01T02:18:47Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc2`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## Controlled operation — 2026-08-01T02:40:52Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc3`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## C1266-2026-08-01-010 — Ring 2 validator-health sweep used a non-coherent snapshot

**Status:** Contained; qualification-runner correction required before a fresh private run
**Severity:** P1 qualification gate failure
**Detected:** 2026-08-01 02:47 UTC
**First bad height:** 2 through 7 in one serial observation sweep
**Last agreed finalized height:** Not established by a coherent snapshot; all six validators were actively finalizing after the signed start release
**Last agreed finalized block ID:** Not established by a coherent snapshot

### Affected and responsible nodes

- Affected only the disposable Ring 2 run `c1266q20260801024006` and its health controller.
- The public Chain 1266 validator, relayer, RPC, Explorer, and Atlas services were not changed.
- Responsible component: the Ring 2 health sampler in
  `scripts/chain1266/run-ring2-real-host-qualification.sh`.

### Symptoms and evidence

- RC3 passed all six-host preflight, paused-readiness, disposable WireGuard, desired-state, and signed-start gates.
- The first six metrics files were written one second apart while the private chain was actively
  finalizing: validator finalized heights read `2 3 4 5 6 7`.
- The runner rejected that serially observed interval as a five-block tip spread before any
  consensus stall, same-height finality conflict, restart, or public mutation was observed.

### Confirmed cause

The qualification controller fetched each validator's metrics through SSH serially and compared
the moving results as if they were a single snapshot. It also compared finalized block IDs across
different heights, although adjacent finalized heights necessarily have different block IDs. Neither
comparison can establish a same-height safety conflict.

### Recovery actions and outcomes

1. **Allowed the private supervisor to exit through its cleanup trap.**
   **Outcome:** all six disposable roots, data paths, WireGuard interfaces, firewall chains, and
   transient units were removed; the public fleet remains quarantined.
2. **Preserved the evidence bundle and stopped before any public deployment operation.**
   **Outcome:** RC3 is not promotable and no 10,000-block result is claimed.
3. **Queued a narrow runner-only correction.**
   **Outcome:** the next run will collect all six metrics concurrently within a bounded observation
   window and will compare block IDs only among validators reporting the same finalized height.

### Final outcome

Contained. This is a qualification-instrumentation defect, not evidence of a consensus liveness or
safety defect. A new immutable private qualification package and a fresh 10,000-block Ring 2 run
are required before governance signing or any public-chain action.

### Residual risks and next observation

The repaired sampler must fail closed if its concurrent observation window cannot be obtained,
must retain the two-block lag threshold, and must reject different finalized block IDs at the same
height. The next private run must complete the entire 10,000-block gate without manual
intervention.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260801024006/
- scripts/chain1266/run-ring2-real-host-qualification.sh

## Controlled operation — 2026-08-01T08:36:08Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc4`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## C1266-2026-08-01-011 — Ring 2 concurrent sampler used controller completion time as a health gate

**Status:** Contained; scheduled common-time snapshot required before another private run
**Severity:** P1 qualification gate failure
**Detected:** 2026-08-01 08:43 UTC
**First bad height:** 0; the sampler ran during the ten-second signed-start activation interval
**Last agreed finalized height:** 0 in the captured pre-activation snapshot
**Last agreed finalized block ID:** N/A

### Affected and responsible nodes

- Affected only disposable Ring 2 run `c1266q20260801083608`.
- The public Chain 1266 fleet and Atlas were not changed.
- Responsible component: the first concurrent implementation of the Ring 2 health sampler.

### Symptoms and evidence

- RC4 again passed preflight, paused readiness, WireGuard, desired-state, and signed-start gates.
- Six parallel SSH metric requests completed in 2,348 ms. The controller treated that transport
  completion duration as a failed health condition before evaluating any chain criterion.
- Every captured metric was still at height 0 because the signed start command deliberately
  activates ten seconds after issuance. No consensus stall or safety conflict was observed.

### Confirmed cause

Concurrency removed the serial height skew but did not create a common observation instant. A
one-second controller-side completion limit was both unrelated to validator health and too short
for the authenticated SSH transport.

### Recovery actions and outcomes

1. **Allowed the supervisor cleanup trap to complete.**
   **Outcome:** roots, data, WireGuard, transient services, and firewall state verified CLEAN on
   validators 1 through 6.
2. **Preserved the height-zero metrics and start-command evidence.**
   **Outcome:** RC4 remains non-promotable; no soak result is claimed.
3. **Queued a scheduled common-time sampler.**
   **Outcome:** each already-multiplexed remote collector will be dispatched before a shared
   future Unix-second target, issue its local metrics request at that target, and fail closed if
   it begins more than one second late. The existing two-block and same-height-ID gates remain.

### Final outcome

Contained instrumentation defect. A fresh immutable private package and full Ring 2 gate remain
required. The public chain remains quarantined.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260801083608/
- scripts/chain1266/run-ring2-real-host-qualification.sh

## Controlled operation — 2026-08-01T08:59:15Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc5`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## C1266-2026-08-01-012 — Ring 2 direct finality SLO violation with recurrent timeout rounds

**Status:** Open; private qualification will be halted for source-level diagnosis
**Severity:** P0 qualification performance and liveness failure
**Detected:** 2026-08-01 09:12 UTC
**First bad height:** By the 70-block snapshot; the direct finality mean already exceeded 3.4 seconds
**Last agreed finalized height:** 76 on all six validators in the common-time snapshot
**Last agreed finalized block ID:** `77b8a1c901632fd9608b73c7cbcba6b759829822f6c81e2452941f42bc7bce87`

### Affected and responsible nodes

- Affected only private Ring 2 run `c1266q20260801085915` using RC5.
- All six validators remained converged, active, and at zero restart count; no individual host is
  responsible.
- The public Chain 1266 fleet, public state, and Atlas were not changed.
- Responsible component: common typed consensus liveness under the real six-host P2P transport.

### Symptoms and evidence

- The synchronized common-time sampler proved all validators were within one block, but at height
  70--76 every validator reported 3.47--3.64-second mean finality, 2.23--2.59-second median,
  8.45--10.92-second p95, and only 78.9--80.3% round-zero finality.
- Validator 1 had 75 interval samples, 414 timeout votes, 118 timeout certificates, current round
  4 at height 77, and a latest finality interval of 6.053 seconds.
- PQ queue depth and queue rejections remained zero, so the evidence does not support a saturated
  PQ worker queue as the immediate cause. The validator had 740 pre-crypto rejections and 156
  rebroadcasts; an observer message rejected at validator 6 was fail-closed and did not establish
  observer authority over consensus.

### Confirmed cause

The private release cannot satisfy the required direct-finality SLO in its current form. The exact
source-level mechanism behind the recurrent timeout rounds remains unconfirmed; it requires
forensic analysis after the disposable run is cleanly stopped. This is not a safe candidate for a
10,000-block soak or public promotion.

### Recovery actions and outcomes

1. **Captured synchronized direct-validator metrics and relevant service journals before
   intervention.**
   **Outcome:** all replicas agreed on the observed tip, zero restarts, empty PQ queue, and the
   recurrent timeout/round evidence above.
2. **Will stop the local qualification supervisor and allow its cleanup trap to remove only
   disposable Ring 2 state.**
   **Outcome:** pending verification across all six hosts; no public role may be changed.

### Residual risks and next observation

Do not normalize the existing 3.6-second mean or 10-second p95. Identify why validators enter
timeout rounds despite an empty PQ queue and valid authenticated mesh, add a deterministic
regression, then build a new immutable private candidate and restart Ring 2 from Genesis.

### Source evidence

- /Users/devpup/.chain1266-qualification-evidence/c1266q20260801085915/
- runtime/src/consensus/
- scripts/chain1266/run-ring2-real-host-qualification.sh

### Amendment — 2026-08-01 09:16 UTC

3. **Stopped the local Ring 2 supervisor after the direct SLO failure and allowed the cleanup trap
   to run.**
   **Outcome:** validator hosts 1 through 6 each verified `CLEAN`: no run-specific root or data
   directory, WireGuard interface, transient unit, or private process remained. Public Chain 1266
   services and public state were not modified.
4. **Paused the qualification monitor during diagnosis.**
   **Outcome:** one incident commander remains the sole writer until a new immutable private
   candidate is ready.
5. **Completed read-only source and journal analysis after cleanup.**
   **Outcome:** the six replicas were repeatedly generating equivalent validation-certificate
   evidence for the same authenticated quorum. The current driver permits every replica to
   broadcast that evidence, even though the scheduled proposer already receives the same quorum
   and can fan out one verified certificate. This is a candidate cause of the real-host CPU and
   delivery pressure; it is not yet claimed as the sole cause. The next source change will retain
   all-validator timeout-certificate formation for failover, but restrict healthy validation and
   finality certificate aggregation to the scheduled proposer and add a six-validator regression
   proving the one-certificate healthy path.
6. **Validated the proposer-only healthy certificate aggregation change locally.**
   **Outcome:** the single-height finality test, four-height six-validator ML-DSA-65 burn-in,
   two-timeout recovery test, and missed-finality-QC recovery test all passed. The strengthened
   burn-in asserts exactly one validation certificate and one finality certificate cluster-wide
   for each healthy height. This confirms the intended local safety and recovery boundaries; the
   new immutable private Ring 2 candidate remains the decisive performance qualification.
7. **Completed the mandatory Ring 1 deterministic fault matrix for the new source revision.**
   **Outcome:** all 23 of 23 cases passed from 2026-08-01T09:45:21Z through
   2026-08-01T09:53:56Z. The checksum-verified report binds Testnet-v3 revision
   `ae413ce31cae27970ae6ccc16999e563878ed433`, SynQ revision
   `3f7886701ffee4303a24fa6c6584b792a5e36254`, and Aegis revision
   `b51884a661e3aed4bb242ecbced47f3d8777b313`. No validator host was contacted.
8. **Built and verified private-only release `chain1266-incarnation-4-rc6`.**
   **Outcome:** all nine Linux binaries were rebuilt one Cargo process at a time with the Ring 1
   source revisions embedded. The validator SHA-256 is
   `23cdef886251621dd4a4465abf408bc543445a40c0e3200ff2734fcf7dcdd8a5` and contains all three
   exact revisions. Every file in
   `/tmp/chain1266-compile-20260731/ring2-private-release-ae413ce-provenance/SHA256SUMS`
   verified. This package is private qualification only and has not been deployed to a validator.
9. **Ran RC6 private qualification until the first synchronized running-state sample.**
   **Outcome:** all six private validators passed the paused-readiness and signed-start barriers;
   validators 1--5 were RUNNING and had finalized heights 6--10 at the shared 10:19:34 UTC
   sample. Validator 6 accepted the common-time request but did not finish its HTTP metrics
   response within the runner's three-second deadline. Its journal shows a running node through
   that sample and no runtime failure. The run failed closed and cleanup verified CLEAN on all six
   hosts. This is a qualification-collector false negative, not a consensus-stall finding.
10. **Built private-only release `chain1266-incarnation-4-rc7` for the collector correction.**
    **Outcome:** the compiled binaries and their Testnet-v3 source binding remain the RC6-verified
    `ae413ce31cae27970ae6ccc16999e563878ed433`; no executable source changed. The checksum-bound
    runner provenance records commit `09740336807b2ee0fec1aa75512c07896ae5630c`, which retains
    the synchronized request start and changes only the response deadline from three to ten
    seconds. RC7 must pass fresh preflight and the full six-host qualification.

## Controlled operation — 2026-08-01T10:09:22Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## Controlled operation — 2026-08-01T10:26:10Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc7`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service_state=inactive
- `validator-node-02`: `PASS` — canonical_service_state=inactive
- `validator-node-03`: `PASS` — canonical_service_state=inactive
- `validator-node-04`: `PASS` — canonical_service_state=inactive
- `validator-node-05`: `PASS` — canonical_service_state=inactive
- `validator-node-06`: `PASS` — canonical_service_state=inactive

## Controlled operation — 2026-08-01T10:42:22Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc8`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive

## C1266-2026-08-02-022 — Coordinated P1 production reset and launch

**Status:** Open
**Severity:** P0
**Detected:** 2026-08-02 10:03:00 UTC
**First bad height:** 0; the prior public chain-derived data remains indexed at height 348
**Last agreed finalized height:** 0 for the inactive production validator fleet
**Last agreed finalized block ID:** canonical immutable Genesis only

### Affected and responsible nodes

- Affected: the six production validators, relayers, RPC gateway, observer,
  explorer/indexer, and Atlas on the production fleet.
- Responsible component: the missing coordinated P1 release/control path and
  stale public chain-derived state; no individual validator is implicated.

### Symptoms and evidence

- Validators 1 through 6 are inactive, have no staged P1 release, and retain
  no active canonical Chain-1266 role unit.
- Atlas/API is serving the earlier height-348 chain while the explorer support
  role remains at genesis and still invokes a retired DAG RPC.
- All six deployed Genesis files and Val1's release manifest agree on the
  immutable Genesis file SHA-256 `ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`
  and semantic Genesis hash
  `c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d`.

### Confirmed cause

The prior live deployment contains only the retired PoSy release machinery.
It cannot authorize or start the signed immutable-Genesis coordinated P1
runtime required for the new h1 activation.

### Recovery actions and outcomes

1. **Read the complete incident ledger and performed a workbook-backed,
   alias-only, read-only production inventory.**
   **Outcome:** the controller/release candidate, validator fleet, Atlas
   deployment, canonical Genesis binding, and stale-state scope were
   identified without changing host state.
2. **Build an immutable-Genesis P1 release on the production release host,
   then stage a signed activation manifest and controller-generated reset
   manifest.**
   **Outcome:** in progress; no service, key, Genesis file, or chain-derived
   state has yet been changed.

### Final outcome

Pending. The fleet must remain stopped until the signed release, exact reset
manifest, and Atlas P1 adapter are verified.

### Residual risks and next observation

Verify the activation signature against the existing governance authority,
the exact canonical Genesis binding, and each staged role before any reset.

### Source evidence

- Node Credentials Workbook
- `/etc/synergy/testnet-v3/genesis.json` on validators 1 through 6
- Val1 production release manifest
- Atlas API/indexer and explorer-indexer service inventory on `synergy-index`
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive

## Controlled operation — 2026-08-01T10:56:46Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc9`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive

### Incident C015 — 2026-08-01: RC9 rejected a pre-smoke catch-up spread

- RC9 passed fresh six-host preflight, paused readiness, the signed-start barrier, and began
  finalizing on all six private validators.
- Its first retained atomic snapshot showed every validator at height 19, round zero, with a
  roughly 1.12--1.23 second mean finality interval.  A later snapshot observed heights
  `27 27 27 27 27 24` and the runner failed its two-block tip-spread gate.
- The pre-cleanup diagnostics showed the private validator units still active and listening with
  zero restarts.  The per-run root, data, WireGuard interface, units, and private processes then
  cleaned up on all six hosts.  This was a transient startup catch-up observation, not evidence
  of a finalized-block conflict, a validator crash, or a consensus stall.
- Correction: runner revision `2d4f4e2d71fcbc43200ac3694ba45e1589b9f378` keeps the finalized
  block-ID conflict check and the 30-second no-progress failure active at all heights, but starts
  enforcing the two-block spread only once every validator has crossed the 100-block smoke gate.
  The next attempt must use a new checksum-verified private-only release and fresh preflight.

### Incident C016 — 2026-08-01: RC10 exposed private co-host RPC collisions

- Runtime candidate `ae413ce31cae27970ae6ccc16999e563878ed433` reached coherent first
  finality: all six validators reported height 26 and the same finalized block ID, with zero
  restarts.  It advanced to height 27, then the atomic collector continued to succeed while no
  further finality appeared for the 30-second liveness interval.  The runner therefore failed
  closed for liveness, not for a tip-spread, snapshot, or controller error.
- Pre-cleanup diagnostics found all validator units active with zero restarts.  Read-only journal
  retrieval then showed that validators 4--6 had each spawned failing RPC and WebSocket listener
  threads because co-hosted private roles all inherited loopback ports 5640 and 5660.  The
  private cleanup completed `CLEAN` on all six hosts; no public Chain 1266 state was changed.
- Correction: qualification renderer and runner revision
  `5739598faf3b413bb0b1aaeaec465f0f94ea42d0` assigns each of the twelve disposable roles a
  unique loopback HTTP/WebSocket/gRPC port and refuses a run if any assigned listener is already
  occupied.  The render test passed for all twelve configs and all six real hosts reported the
  assigned ports free before packaging.
- Private package identity is now runtime candidate `chain1266-runtime-rc6` (the unchanged
  `ae413ce` binary) plus qualification runner `ring2-runner-r6`; it is checksum-verified and
  requires fresh six-host preflight before another attempt.

## Controlled operation — 2026-08-01T11:09:28Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc10`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive

### Incident C017 — 2026-08-01: RC10 invalidated by a comprehensive socket-map gap

- RC10's 30-second absence of finality after height 27 is retained as a real observation, but
  the run is `INVALID / INCONCLUSIVE`: co-hosted roles on validators 4--6 had deterministic
  loopback RPC/WebSocket collisions, so an active systemd main PID did not prove that every
  listener task initialized. No same-height finalized-block conflict, validator restart, or
  safety failure was observed.
- The private-only renderer correction is commit
  `663c6c4877c5089e151bedcaf2d19120fbc99705`. It freezes runtime candidate
  `chain1266-runtime-rc6` at `ae413ce31cae27970ae6ccc16999e563878ed433`; it changes no
  consensus source, binary, Ring 1 evidence, public configuration, or Genesis.
- New qualification configuration `ring2-config-r7` emits a checksum-bound
  `QUALIFICATION_SOCKET_MANIFEST.json`: 72 deterministic endpoint declarations across the six
  physical hosts, with 48 mandatory TCP listeners in private range 22000--29999. HTTP,
  WebSocket, metrics, and P2P are mandatory; gRPC and discovery are explicitly disabled because
  this runtime implements neither listener. Administrative, health, debug, IPC, embedded
  database, and P2P UDP/QUIC surfaces are recorded as not configured listeners.
- Render validation verifies role-to-host assignment, every configuration field against the
  manifest, range policy, missing/duplicate endpoint definitions, and IPv4/IPv6 wildcard
  overlap. The static test rendered all twelve configs and rejected an injected
  `0.0.0.0:PORT` collision with an interface-specific listener.
- The next attempt must use a newly checksummed private package, fresh read-only preflight, and
  validator-only startup through 100 finalized blocks. Before any role starts, each host checks
  the manifest against `ss -lntup` and required private interfaces. Post-start readiness requires
  active unit, expected main PID ownership of every mandatory listener, responsive metrics, and
  no bind/AddrInUse/listener-panic journal record. Downstream roles start only after that smoke
  gate; validator and observer restart exercises repeat the listener-ownership check.

## Controlled operation — 2026-08-01T11:53:46Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`; runtime candidate: `chain1266-runtime-rc6`
- Qualification configuration: `ring2-config-r7`; runner revision:
  `aa5f46e580cf6319f61d8df4aa598c9f22cd23a6`
- Package: `ring2-private-runtime-rc6-config-r7`; `SHA256SUMS` SHA-256:
  `78c9caed29f5f4fb0a00b604fa414e6cdeed4c78b7599542e9650f1b6581f636`
- Socket manifest SHA-256: `4f72893ffc5894bcfc802ea00b3acb445b977081406131e8e0edb48a2bb46c03`
- Run: `c1266q20260801115316`
- Fresh read-only preflight: `PASS` on validator hosts 1--6; legacy public validator services
  inactive and no private qualification unit present. The public Chain 1266 fleet remains
  quarantined and unchanged.

### Incident C018 — 2026-08-01: private overlay setup exited before any role start

- Run `c1266q20260801115316` generated its disposable private Genesis and signed desired state,
  distributed the package to all six hosts, and passed its legacy private RPC-port availability
  check. It then exited during private overlay setup, before the socket host-preflight marker,
  systemd unit installation, validator start, signed consensus release, or finalized block.
- Pre-cleanup diagnostics captured the temporary WireGuard UDP listeners, confirming that all six
  disposable interfaces had been created. The runner's cleanup then completed cleanly: read-only
  verification found no run interface, qualification root/data directory, qualification unit, or
  firewall chain on any host. The public fleet was not changed.
- The original runner did not identify the exact failing setup stage. Commit
  `4a02a8947fe688c9723502760ae8f34a8a7fcf59` adds only stage-labelled fail-closed reporting and
  progression markers to the qualification runner. The next package keeps `ring2-config-r7`, the
  existing runtime candidate, and all rendered configuration inputs unchanged.

## Controlled operation — 2026-08-01T12:05:12Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`; runtime candidate: `chain1266-runtime-rc6`
- Qualification configuration: `ring2-config-r7`; diagnostic runner revision:
  `4a02a8947fe688c9723502760ae8f34a8a7fcf59`
- Package: `ring2-private-runtime-rc6-config-r7-runner-r8`; `SHA256SUMS` SHA-256:
  `87efd0f55e9829ea6c04ca734c43bb15087c78b5ccaa49f0cf0eda8fba09053a`
- Socket manifest SHA-256: `4f72893ffc5894bcfc802ea00b3acb445b977081406131e8e0edb48a2bb46c03`
- Run: `c1266q20260801120512`
- Fresh read-only preflight: `PASS` on validator hosts 1--6. The preceding private run cleaned
  completely; legacy public validators remain inactive and the public fleet remains quarantined.

### Incident C019 — 2026-08-01: socket preflight treated disabled endpoints as mandatory

- Run `c1266q20260801120512` completed private material rendering, payload distribution, legacy
  port availability, interface creation, and mesh configuration. It exited at the first host
  socket preflight before a unit or validator started because the loop rejected disabled gRPC and
  discovery entries instead of skipping their ownership checks.
- Commit `575a159632db35312a1fc546375de944a1b709a6` preserves static validation of those entries
  and skips them only for live-listener ownership, leaving 48 mandatory sockets enforced. Cleanup
  completed before the replacement preflight.

## Controlled operation — 2026-08-01T12:13:37Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`; runtime candidate: `chain1266-runtime-rc6`
- Qualification configuration: `ring2-config-r7`; runner revision:
  `575a159632db35312a1fc546375de944a1b709a6`
- Package: `ring2-private-runtime-rc6-config-r7-runner-r9`; `SHA256SUMS` SHA-256:
  `fe72cd93cafe71cdeb1b4e5ccbc70c96406e5ec4e24fcd1b42439cee23284f6a`
- Run: `c1266q20260801121337`; fresh read-only preflight: `PASS` on validator hosts 1--6.
- Public Chain 1266 remains quarantined and unchanged.

## Controlled operation — 2026-08-01T12:15:53Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`; runtime candidate: `chain1266-runtime-rc6`
- Qualification configuration: `ring2-config-r7`; runner revision:
  `575a159632db35312a1fc546375de944a1b709a6`
- Package: `ring2-private-runtime-rc6-config-r7-runner-r10`; `SHA256SUMS` SHA-256:
  `e40d6a80af9c91d6e464b4f32c6f6d48a5701d9be979fa8e0d3d2485685b0d64`
- Socket-gate evidence: 72 declarations; 48 mandatory checked; 24 disabled skipped; missing or
  conflicting mandatory sockets fail; missing disabled sockets pass.
- Run: `c1266q20260801121553`; fresh read-only preflight: `PASS` on validator hosts 1--6.
- Public Chain 1266 remains quarantined and unchanged.

### Incident C020 — 2026-08-01: validator private-mesh P2P port contract mismatch

- Retained run `c1266q20260801121553` reached validator startup but emitted
  `PAUSED_READY` on 0/6 validators. Complete journals from validators 4 and 6 showed that the
  unchanged RC6 binary accepted its binary/configuration hashes, private Genesis, Chain 1266,
  incarnation 4, identity, and signed desired state; bound its mandatory listeners and metrics;
  then failed closed because it required five authenticated remote validators and observed one.
- RC6 permits validator VPN consensus routes only on the canonical validator P2P port 5622,
  while qualification configuration r7 had rendered validator P2P ports 22004--27004. Commit
  `4d7949cb8781d8cd6f1a5588bb056cc303ed43c7` corrects only that configuration contract:
  validator P2P/listen/dial endpoints use 5622; downstream isolated P2P and all RPC, WebSocket,
  metrics, disabled endpoints, runner r10, readiness thresholds, runtime binaries, Genesis,
  consensus source, and Ring 1 artifacts remain unchanged.

## Controlled operation — 2026-08-01T12:53:41Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc6`; runtime candidate: `chain1266-runtime-rc6`
- Qualification configuration identity: `ring2-config-r7`; configuration revision:
  `4d7949cb8781d8cd6f1a5588bb056cc303ed43c7`; frozen runner revision:
  `575a159632db35312a1fc546375de944a1b709a6`
- Package: `ring2-private-runtime-rc6-config-r7-p2p5622-runner-r10`; `SHA256SUMS` SHA-256:
  `1ae3a82fdda443549785555d5651ab6f4ef078d05b02b5aa487758747a0b9402`
- Run: `c1266q20260801125341`; fresh read-only preflight: `PASS` on validator hosts 1--6.
- Public Chain 1266 remains quarantined and unchanged.

## C1266-2026-08-01-021 — RC6 post-validation-certificate finality stall at height 98

**Status:** Corrected locally; provenance build and six-host 200-block smoke pending
**Severity:** P0 consensus-liveness failure
**Detected:** 2026-08-01 13:05 UTC
**First bad height:** 98
**Last agreed finalized height:** 97
**Last agreed finalized block ID:**
`ef5df947d2198468ba745db1565e23452dea51f25966ed214ed0348550036001`

### Affected and responsible nodes

- Affected: private validators `validator-node-01` through `validator-node-06` in retained run
  `c1266q20260801125341`.
- Responsible component: the common RC6 typed-consensus finality-certificate aggregation and
  recovery path. No individual validator or operator is responsible.
- Public Chain 1266 and Atlas were not changed.

### Symptoms and evidence

- All six validators passed `PAUSED_READY`, mandatory socket ownership, authenticated-mesh, and
  signed-start gates. All remained `active/running`, `ExecMainStatus=0`, with zero restarts.
- The final coherent metric vector was `97 97 97 97 97 97`; every validator reported the same
  finalized block ID above, so no safety conflict was observed.
- Every validator was at current height 98, round 5, with the same height-98 round-0 prepared
  candidate `28d3da8d53a198d1e13a7040cc77e1c2a103826ccf0f8655991a3ec209031772`.
  This proves a validation certificate was formed and installed across the full replica set.
- Every highest QC remained at height 97. No height-98 finality QC was installed.
- Every validator held the same round-5 timeout-certificate root
  `2330bdef8b83942edb8eeed5c762749c54578812ac0053bd0f01d317ab1c06d7`, proving timeout
  quorum formation and round advancement continued but did not restore finality.
- Every validator had five connected consensus peers and six live/eligible validators.
  Mailbox depths were `0 0 0 0 0 1`; all PQ queue depths and queue-rejection counts were zero.
- The retained evidence does not contain per-height proposer identities, vote signer sets,
  certificate creator identities, an outbound-send backlog metric, or a series of height-93--98
  snapshots. Those values will not be inferred or invented.

### Confirmed cause and bounded source classification

The exact stalled phase is confirmed as post-VC / pre-finality-QC at height 98. RC6 function
`TypedPosyDriver::maybe_form_finality_certificate` permits only the scheduled proposer to convert
a locally verified strict quorum of finality votes into a QC. Non-proposers retain verified votes
but return without forming the certificate, and the finality deadline transitions them directly
to timeout recovery. This makes one proposer's receipt/aggregation path a liveness choke point:
quorum evidence available elsewhere cannot close the height. The clean six-host evidence rules
out socket, process, mesh, mailbox, and PQ saturation as competing immediate causes.

### Recovery action and local outcome

1. **Added deterministic staggered backup QC aggregation for a replica already holding an exact,
   verified finality quorum.** The scheduled proposer remains the zero-delay primary. Backups
   become eligible in leader-schedule order at 250 ms intervals after local quorum observation,
   before the unchanged finality deadline. Quorum, governed timeouts, block time, epoch length,
   canonical QC subject validation, and the 30-second external no-progress gate remain unchanged.
   **Outcome:** committed as `242445e0283d9cd2cbd576852d587da68f8f4344` in
   `runtime/src/consensus/typed_coordinator.rs` only.
2. **Ran the focused regression and the four existing affected healthy/recovery cases once.**
   **Outcome:** all five passed: deterministic backup formation when the primary misses quorum;
   unchanged one-VC/one-QC healthy path; two-timeout recovery followed by finality; missed-QC
   recovery; and the real ML-DSA multi-height burn-in. The unrelated integration target
   `testnet_genesis_artifacts` has a pre-existing missing `crate::utils` compile error, so the
   scoped consensus cases were correctly invoked as library tests.

### Residual risks and next observation

The local proof is complete. The next evidence gate is one provenance-bound Linux runtime
candidate followed by a validator-only 200-block six-host smoke. A stall must preserve live
validator state; a pass permits the unchanged 10,000-block Ring 2 qualification to begin.

### Source evidence

- `/Users/devpup/.chain1266-qualification-evidence/c1266q20260801125341/`
- `runtime/src/consensus/typed_coordinator.rs`

## Controlled operation — 2026-08-01T15:06:25Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc7`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive


## Controlled operation — 2026-08-01T15:21:47Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc7`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive


## Controlled operation — 2026-08-01T16:11:30Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc8`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive


## Controlled operation — 2026-08-01T18:25:39Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc9`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive


## Controlled operation — 2026-08-01T19:16:47Z

- Operation: `RING2_REAL_HOST_QUALIFICATION_BEGIN`
- Release: `chain1266-incarnation-4-rc10`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-01.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-02`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-02.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-03`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-03.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-04`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-04.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-05`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-05.service state=inactive
canonical_service=synergy-validator.service state=inactive
- `validator-node-06`: `PASS` — canonical_service=synergy-chain1266-role@validator-node-06.service state=inactive
canonical_service=synergy-validator.service state=inactive

## Controlled operation — 2026-08-02T12:53:48Z

- Operation: `STAGE_IMMUTABLE_RELEASE_FAILED`
- Release: `chain1266-incarnation-4-rc11`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — sha256sum: /opt/synergy/chain1266/releases/.staging-chain1266-incarnation-4-rc11-validator-node-01/consensus-activation.json: Permission denied


## Controlled operation — 2026-08-02T12:58:34Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc11`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T12:59:12Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc11`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T12:59:23Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc11`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T13:15:04Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T13:19:10Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T13:20:09Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T13:21:44Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T13:22:04Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-02T13:22:38Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc12`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Incident chain1266-20260802T132326Z-0a13ab9d — 2026-08-02T13:23:26Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `OBSERVER_LAG:atlas-indexer`, `OBSERVER_LAG:explorer-indexer`, `OBSERVER_LAG:observer`, `OBSERVER_LAG:relay1`, `OBSERVER_LAG:relay2`, `OBSERVER_LAG:relay3`, `OBSERVER_LAG:rpc-gateway`, `VALIDATOR_RESTART:validator-node-01`, `VALIDATOR_RESTART:validator-node-02`, `VALIDATOR_RESTART:validator-node-03`, `VALIDATOR_RESTART:validator-node-04`, `VALIDATOR_RESTART:validator-node-05`, `VALIDATOR_RESTART:validator-node-06`
- Common/min/max finalized height: `38` / `38` / `38`
- Responsible/affected node(s): `atlas-api`, `atlas-indexer`, `explorer-indexer`, `observer`, `relay1`, `relay2`, `relay3`, `rpc-gateway`, `validator-node-01`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T132326Z-0a13ab9d`

## Controlled operation — 2026-08-02T14:08:14Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T14:09:04Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T14:10:16Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T14:12:46Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T14:17:16Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T14:21:42Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
Created symlink '/etc/systemd/system/multi-user.target.wants/synergy-chain1266-role@rpc-gateway.service' → '/etc/systemd/system/synergy-chain1266-role@.service'.
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc14 activation_height=1 activation_root=b2530184f39ff0983bdc93d4cc5b1404be9ad3f32e913dadb483f1b6f214c386d740679696304d043b086c1e82788aed6a21fc944805b3799a1ebda327fc976b
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc14 desired_state_sha256=7562c649483a2661ed177d13036f01b25b8ff31baa12c88419042b6e58c754e2
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc14 atlas_release_manifest_sha256=2cd9c0271db1fb6712b616a20caa5bded8d8ff7049cdc121a07feb1d957f05dd reset_manifest_sha256=ddf00f103a0001706dfa97fac684a4e2efe1695caa0672547521f79a3843213d
CHAIN1266_IMMUTABLE_ROLE_STAGED
Created symlink /etc/systemd/system/multi-user.target.wants/synergy-chain1266-role@explorer-indexer.service → /etc/systemd/system/synergy-chain1266-role@.service.
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
Created symlink /etc/systemd/system/multi-user.target.wants/synergy-chain1266-role@observer.service → /etc/systemd/system/synergy-chain1266-role@.service.
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-02T14:22:02Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T14:22:11Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260802T142351Z-b442fa5b — 2026-08-02T14:23:51Z

- Operational state: `STARTING`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `validator-node-01`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T142351Z-b442fa5b`

## Incident chain1266-20260802T142431Z-6fe24142 — 2026-08-02T14:24:31Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `atlas-api`, `atlas-indexer`, `validator-node-01`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T142431Z-6fe24142`

## Controlled operation — 2026-08-02T14:30:16Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T14:30:43Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T14:30:55Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T14:30:58Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260802T143344Z-34d13b96 — 2026-08-02T14:33:44Z

- Operational state: `STARTING`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `validator-node-01`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T143344Z-34d13b96`

## Controlled operation — 2026-08-02T14:35:30Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T14:36:20Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T14:38:50Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T14:39:03Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T14:39:11Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260802T144118Z-366f6f08 — 2026-08-02T14:41:18Z

- Operational state: `STARTING`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `validator-node-05`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T144118Z-366f6f08`

## Controlled operation — 2026-08-02T14:45:44Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-02T15:06:56Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc14`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Incident chain1266-20260802T150708Z-0c53a3a2 — 2026-08-02T15:07:08Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_RESTART:validator-node-05`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `atlas-api`, `atlas-indexer`, `validator-node-05`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T150708Z-0c53a3a2`

## Incident chain1266-20260802T150819Z-fe573052 — 2026-08-02T15:08:19Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_RESTART:validator-node-05`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `atlas-api`, `atlas-indexer`, `validator-node-05`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260802T150819Z-fe573052`

## Controlled operation — 2026-08-02T17:06:31Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T17:08:58Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T17:11:18Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T17:12:30Z

- Operation: `WIPE_ALL_CHAIN_STATE_FAILED`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — state root is not empty after reset


## Controlled operation — 2026-08-02T18:40:02Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T18:44:04Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc16 activation_height=1 activation_root=5824a8bd70bc5e1538c12625723a895949b6f939e9e3e2c1167b4e647bd93d83d79dbf8891e2e4eaa27433b2058e79bebcea2e940455902505185e9fa776d222
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc16 desired_state_sha256=8b9a2c6d9013015de23689e0f3d21a1034e705d7171245ed44653ab14e9f20db
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc16 atlas_release_manifest_sha256=9d7c745e84b8c2c3df4e5fba1f7cb638990e3ff9e61e85f8ccf56444a350ee0f reset_manifest_sha256=3eea8d85d3fdb8e8654313852f1c97f2cb0ee2692dc898d8116b106ac492cdd6
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc16 activation_height=1 activation_root=5824a8bd70bc5e1538c12625723a895949b6f939e9e3e2c1167b4e647bd93d83d79dbf8891e2e4eaa27433b2058e79bebcea2e940455902505185e9fa776d222
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc16 desired_state_sha256=8b9a2c6d9013015de23689e0f3d21a1034e705d7171245ed44653ab14e9f20db
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc16 atlas_release_manifest_sha256=9d7c745e84b8c2c3df4e5fba1f7cb638990e3ff9e61e85f8ccf56444a350ee0f reset_manifest_sha256=3eea8d85d3fdb8e8654313852f1c97f2cb0ee2692dc898d8116b106ac492cdd6
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-02T18:45:40Z

- Operation: `ATLAS_OFFLINE_CHAIN_DATA_RESET`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `atlas-indexer`: `FAIL` — curl: (7) Failed to connect to 127.0.0.1 port 3020 after 0 ms: Couldn't connect to server


## Controlled operation — 2026-08-02T18:46:52Z

- Operation: `ATLAS_OFFLINE_CHAIN_DATA_RESET`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `atlas-indexer`: `PASS` — ATLAS_CHAIN1266_P1_DERIVED_DATA_RESET_APPLIED phase=offline-reset evidence=/var/lib/synergy/chain1266-evidence/chain1266-incarnation-4-rc16/atlas-offline-reset
CHAIN1266_ATLAS_OFFLINE_RESET_COMPLETE


## Controlled operation — 2026-08-02T18:47:17Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T18:47:29Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc16`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T19:02:25Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T19:03:06Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T19:09:08Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc17 activation_height=1 activation_root=505ca5e0a02130f31aacdca8dd0c702bf6e3cb5c7f274fa1f22e54bb0b30c98b061261c78e20acc0b8a34ecc18600fd1398007061c503650905103aea1230c97
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc17 desired_state_sha256=5d06e2d619c07fd7dfd6ccdfa835aad61f841a777d0bfd0008a6b64086330ee3
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc17 atlas_release_manifest_sha256=ec73785a312817633d1efefef0da2800548ae046082ee01c7606403fbd075e37 reset_manifest_sha256=454404b40b7085f40961547302254840703f4a72db7f303ce7fe3afd5ab31c53
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc17 activation_height=1 activation_root=505ca5e0a02130f31aacdca8dd0c702bf6e3cb5c7f274fa1f22e54bb0b30c98b061261c78e20acc0b8a34ecc18600fd1398007061c503650905103aea1230c97
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc17 desired_state_sha256=5d06e2d619c07fd7dfd6ccdfa835aad61f841a777d0bfd0008a6b64086330ee3
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc17 atlas_release_manifest_sha256=ec73785a312817633d1efefef0da2800548ae046082ee01c7606403fbd075e37 reset_manifest_sha256=454404b40b7085f40961547302254840703f4a72db7f303ce7fe3afd5ab31c53
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-02T19:09:49Z

- Operation: `ATLAS_OFFLINE_CHAIN_DATA_RESET`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `atlas-indexer`: `PASS` — ATLAS_CHAIN1266_P1_DERIVED_DATA_RESET_APPLIED phase=offline-reset evidence=/var/lib/synergy/chain1266-evidence/chain1266-incarnation-4-rc17/atlas-offline-reset
CHAIN1266_ATLAS_OFFLINE_RESET_COMPLETE


## Controlled operation — 2026-08-02T19:10:11Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T19:10:26Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T19:13:19Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-02T19:20:56Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-02T19:31:22Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T19:31:49Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc17`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T20:06:44Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-02T20:07:35Z

- Operation: `WIPE_ALL_CHAIN_STATE`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-02`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-03`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-04`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-05`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `validator-node-06`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay1`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay2`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `relay3`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `rpc-gateway`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `explorer-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `observer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-api`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED
- `atlas-indexer`: `PASS` — CHAIN1266_ALL_CHAIN_DERIVED_STATE_WIPED


## Controlled operation — 2026-08-02T20:13:51Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc18 activation_height=1 activation_root=5672b0c18d87c4bc5237b00ead9187be7dfb03c2bbc2e30d9796489de8ba1ce2c8faaefb4a0cba34373b220f973b6588b781c34dd5e0f96e45bf7840a9804f1d
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc18 desired_state_sha256=6bdeec1dcb3c85ffb0b7e828588125dfbdc60121ebf6b046b58bdea22e9898ca
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc18 atlas_release_manifest_sha256=6f11b6d22cd8807f7b7c9815ab899bd4937614ab32a91b443727623a58fa7976 reset_manifest_sha256=183130aba86376802bc11886010921fa96fe721698491ce76284ef9ecee27c4a
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc18 activation_height=1 activation_root=5672b0c18d87c4bc5237b00ead9187be7dfb03c2bbc2e30d9796489de8ba1ce2c8faaefb4a0cba34373b220f973b6588b781c34dd5e0f96e45bf7840a9804f1d
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc18 desired_state_sha256=6bdeec1dcb3c85ffb0b7e828588125dfbdc60121ebf6b046b58bdea22e9898ca
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc18 atlas_release_manifest_sha256=6f11b6d22cd8807f7b7c9815ab899bd4937614ab32a91b443727623a58fa7976 reset_manifest_sha256=183130aba86376802bc11886010921fa96fe721698491ce76284ef9ecee27c4a
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-02T20:15:00Z

- Operation: `ATLAS_OFFLINE_CHAIN_DATA_RESET`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `atlas-indexer`: `PASS` — ATLAS_CHAIN1266_P1_DERIVED_DATA_RESET_APPLIED phase=offline-reset evidence=/var/lib/synergy/chain1266-evidence/chain1266-incarnation-4-rc18/atlas-offline-reset
CHAIN1266_ATLAS_OFFLINE_RESET_COMPLETE


## Controlled operation — 2026-08-02T20:15:15Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T20:15:30Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-02T20:15:51Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-02T20:17:27Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-02T20:21:37Z

- Operation: `ATLAS_OPERATIONAL_RPC_BOUND`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `atlas-indexer`: `PASS` — ATLAS_CHAIN1266_P1_DERIVED_DATA_RESET_APPLIED phase=operational-bind evidence=/var/lib/synergy/chain1266-evidence/chain1266-incarnation-4-rc18/atlas-operational-bind
CHAIN1266_ATLAS_OPERATIONAL_BIND_COMPLETE


## Controlled operation — 2026-08-02T20:21:37Z

- Operation: `ATLAS_ACTIVATED`
- Release: `chain1266-incarnation-4-rc18`
- Chain: `1266`, incarnation: `4`
- `atlas-api`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260803T001216Z-47cfdc55 — 2026-08-03T00:12:16Z

- Operational state: `CRITICAL`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `DESIRED_STATE_MISMATCH:validator-node-02`, `DESIRED_STATE_MISMATCH:validator-node-03`, `DESIRED_STATE_MISMATCH:validator-node-04`, `DESIRED_STATE_MISMATCH:validator-node-05`, `DESIRED_STATE_MISMATCH:validator-node-06`, `DOWNSTREAM_IDENTITY_MISMATCH:relay1`, `FEWER_THAN_FIVE_ACTIVE_VALIDATORS`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `relay1`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260803T001216Z-47cfdc55`

## Incident chain1266-20260803T002157Z-d19b0c1d — 2026-08-03T00:21:57Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `COORDINATED_PRODUCER_SEQUENCE_STALL`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260803T002157Z-d19b0c1d`

## Controlled operation — 2026-08-03T00:55:15Z

- Operation: `STOP_FOR_FULL_RESET_FAILED`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `FAIL` — Connection closed by 195.26.241.95 port 22


## Controlled operation — 2026-08-03T01:32:56Z

- Operation: `STAGE_IMMUTABLE_RELEASE_FAILED`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `FAIL` — immutable release directory already exists


## Controlled operation — 2026-08-03T01:34:09Z

- Operation: `STAGE_IMMUTABLE_RELEASE_FAILED`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `validator-node-02`: `FAIL` — immutable release directory already exists


## Controlled operation — 2026-08-03T01:37:47Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc19 activation_height=1 activation_root=6fb5020eb6c1630ee4eaf0cd8c995be523df6eb5277a51afbc3bd319280f4b04b1cd4934285244ab9e98138220c61e87794cf0a5bcea72d5fdf973c19a65fe57
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc19 desired_state_sha256=6d2fd7ecaa6aad0ddd7e12aea8f616e7efdb11565591e6d7201acea775850d67
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc19 atlas_release_manifest_sha256=7ec753e8e93c3ba1b17e3be5001f0463cc5c8969eb8f737637313ae95f170e96 reset_manifest_sha256=5d18f07e4c7f09eb3a23e29844b0e561a0fa6623ffeca976deb5d693f94cf115
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc19 activation_height=1 activation_root=6fb5020eb6c1630ee4eaf0cd8c995be523df6eb5277a51afbc3bd319280f4b04b1cd4934285244ab9e98138220c61e87794cf0a5bcea72d5fdf973c19a65fe57
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc19 desired_state_sha256=6d2fd7ecaa6aad0ddd7e12aea8f616e7efdb11565591e6d7201acea775850d67
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc19 atlas_release_manifest_sha256=7ec753e8e93c3ba1b17e3be5001f0463cc5c8969eb8f737637313ae95f170e96 reset_manifest_sha256=5d18f07e4c7f09eb3a23e29844b0e561a0fa6623ffeca976deb5d693f94cf115
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T01:52:45Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T01:53:24Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc19`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260803T015545Z-61c6187c — 2026-08-03T01:55:45Z

- Operational state: `STARTING`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `validator-node-01`, `validator-node-02`, `validator-node-03`, `validator-node-04`, `validator-node-05`, `validator-node-06`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260803T015545Z-61c6187c`

## Controlled operation — 2026-08-03T03:17:19Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc20`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc20 activation_height=1 activation_root=ae22c4c98909240f007fa9758987263bec1ce1e83e28e34b708ddb66e16024618e0680f485c806d7374edcbf6023cfeeb9383eaaaec277002826cb668a6f58f2
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc20 desired_state_sha256=2421a8822690171f1baffacddb7e16190f3cc5b29dc0393d87b4287940c2580a
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc20 atlas_release_manifest_sha256=a4dd7c89a61e07d750493ce135ed5f285d1ca2b95335c1a4e4103beecd844b80 reset_manifest_sha256=1fc761aa2a257fdc2041ce77342fa7144a41784b4f9d7192aedda85bedb428a9
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc20 activation_height=1 activation_root=ae22c4c98909240f007fa9758987263bec1ce1e83e28e34b708ddb66e16024618e0680f485c806d7374edcbf6023cfeeb9383eaaaec277002826cb668a6f58f2
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc20 desired_state_sha256=2421a8822690171f1baffacddb7e16190f3cc5b29dc0393d87b4287940c2580a
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc20 atlas_release_manifest_sha256=a4dd7c89a61e07d750493ce135ed5f285d1ca2b95335c1a4e4103beecd844b80 reset_manifest_sha256=1fc761aa2a257fdc2041ce77342fa7144a41784b4f9d7192aedda85bedb428a9
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T03:17:39Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc20`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T03:18:19Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc20`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T03:19:10Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc20`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-03T03:20:57Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc20`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Incident chain1266-20260803T032147Z-eabdd5fc — 2026-08-03T03:21:47Z

- Operational state: `DEGRADED`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `DOWNSTREAM_IDENTITY_MISMATCH:relay2`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `atlas-indexer`, `relay2`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260803T032147Z-eabdd5fc`

## Controlled operation — 2026-08-03T04:16:49Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc21 activation_height=1 activation_root=b2ab18b346e072cc98ff8fc00c0f476200d7a3dee2abe5619383bef608fdd4da3b81d56a94fd515ab7557f502d20288fc81be509c58dfe9ee32beea4f3c59fd8
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc21 desired_state_sha256=cfef0d3031ebc30a1079db4d67cc3ebd1dd1c1c91773a4c8e83d28bfe275b0ea
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc21 atlas_release_manifest_sha256=e89f729d3045644b49888755dac8c4fa9b4267f2b2093bd1b56e996a6072b2a1 reset_manifest_sha256=9b5c560a187e0077556ef9389b6bf4108a573ab908d0bb08c750aec6a5f2360a
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc21 activation_height=1 activation_root=b2ab18b346e072cc98ff8fc00c0f476200d7a3dee2abe5619383bef608fdd4da3b81d56a94fd515ab7557f502d20288fc81be509c58dfe9ee32beea4f3c59fd8
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc21 desired_state_sha256=cfef0d3031ebc30a1079db4d67cc3ebd1dd1c1c91773a4c8e83d28bfe275b0ea
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc21 atlas_release_manifest_sha256=e89f729d3045644b49888755dac8c4fa9b4267f2b2093bd1b56e996a6072b2a1 reset_manifest_sha256=9b5c560a187e0077556ef9389b6bf4108a573ab908d0bb08c750aec6a5f2360a
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T04:17:32Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T04:18:11Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T04:18:54Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T04:19:40Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-03T04:21:09Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc21`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T04:49:37Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc22 activation_height=1 activation_root=b3af7aef3387e1219bd72a3c2196d80d45f6196e44bbdba59d39776acc3c4dd0f34b4bd280e403d377a8833f6beb62d2d8b0d2f1c8d953ce39499bfcf149fdc7
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc22 desired_state_sha256=eb4a6fcea57e564950c57ca8cb8eee170cb7aef85875240bfc9b207c061f7afc
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc22 atlas_release_manifest_sha256=16bcaf3190f57f39176afadfbe31e4b2db616c4e3931cfad6b042385116515e8 reset_manifest_sha256=f92d07f09fbf976ba5ca965d70164b93be8687691b620848f18439d94a78c4f9
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc22 activation_height=1 activation_root=b3af7aef3387e1219bd72a3c2196d80d45f6196e44bbdba59d39776acc3c4dd0f34b4bd280e403d377a8833f6beb62d2d8b0d2f1c8d953ce39499bfcf149fdc7
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc22 desired_state_sha256=eb4a6fcea57e564950c57ca8cb8eee170cb7aef85875240bfc9b207c061f7afc
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc22 atlas_release_manifest_sha256=16bcaf3190f57f39176afadfbe31e4b2db616c4e3931cfad6b042385116515e8 reset_manifest_sha256=f92d07f09fbf976ba5ca965d70164b93be8687691b620848f18439d94a78c4f9
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T04:49:58Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T04:50:42Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Incident chain1266-20260803T045326Z-897d88a0 — 2026-08-03T04:53:26Z

- Operational state: `STARTING`
- Chain: `1266`, incarnation: `4`
- Trigger(s): `VALIDATOR_PAUSED_BARRIER_TIMEOUT`
- Common/min/max finalized height: `0` / `0` / `0`
- Responsible/affected node(s): `unresolved`
- Automatic action: compact read-only evidence capture; no validator mutation
- Outcome: `OPEN`
- Evidence bundle: `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3/launch/chain1266-incidents/chain1266-20260803T045326Z-897d88a0`

## Controlled operation — 2026-08-03T04:54:39Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T04:55:21Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T04:56:01Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T04:56:46Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-03T05:01:56Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T05:13:54Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc22`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T05:41:39Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc23`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc23 activation_height=1 activation_root=84f277541046354ec73eb7213fa0e04f4be36eefff3f45489508811fa07f6d3582992411d0de27284772200c762acc339a03decd103134a10186ad59a02d14cc
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc23 desired_state_sha256=9d6a4bccd298fb870071503c84c24543c9707ca9b412222cbdede3455a3c16e9
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc23 atlas_release_manifest_sha256=25304b3dffe0fb8f35e281349c6e7018ecd82bfbc3ea44ce246068a4f37c76f1 reset_manifest_sha256=7456be235f7f675b5d1be7e2c97370362764728e5148bcee4fb3ed62c0e4783a
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc23 activation_height=1 activation_root=84f277541046354ec73eb7213fa0e04f4be36eefff3f45489508811fa07f6d3582992411d0de27284772200c762acc339a03decd103134a10186ad59a02d14cc
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc23 desired_state_sha256=9d6a4bccd298fb870071503c84c24543c9707ca9b412222cbdede3455a3c16e9
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc23 atlas_release_manifest_sha256=25304b3dffe0fb8f35e281349c6e7018ecd82bfbc3ea44ce246068a4f37c76f1 reset_manifest_sha256=7456be235f7f675b5d1be7e2c97370362764728e5148bcee4fb3ed62c0e4783a
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T05:42:29Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc23`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T05:43:05Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc23`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T05:52:04Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc23`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T06:12:42Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc24`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc24 activation_height=1 activation_root=621136e7444e8b11dd6a31b1da2069029d86ce0140582ba2a3624d244b48bedd1c6137540b09174faa20a3421df0b06876a9410d10d8ddc5a62456cac1e9b70b
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc24 desired_state_sha256=8e0d50f6d6907fcced965b53086b8e4d96696b35daca7db193c441740fb5b102
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc24 atlas_release_manifest_sha256=63d27c69146964d19fb4f4256fff60d8e1c3bb0476265fc691f437d5e59c364f reset_manifest_sha256=704d7869eca49b3d2979d8ebf873747c6fe97501258c6f8d6907bdad466698e9
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc24 activation_height=1 activation_root=621136e7444e8b11dd6a31b1da2069029d86ce0140582ba2a3624d244b48bedd1c6137540b09174faa20a3421df0b06876a9410d10d8ddc5a62456cac1e9b70b
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc24 desired_state_sha256=8e0d50f6d6907fcced965b53086b8e4d96696b35daca7db193c441740fb5b102
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc24 atlas_release_manifest_sha256=63d27c69146964d19fb4f4256fff60d8e1c3bb0476265fc691f437d5e59c364f reset_manifest_sha256=704d7869eca49b3d2979d8ebf873747c6fe97501258c6f8d6907bdad466698e9
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T06:13:01Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc24`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T06:13:04Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc24`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T06:16:22Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc24`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T06:20:40Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc24`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T06:48:16Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc25`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc25 activation_height=1 activation_root=e04e58aaf47c6cc6810963656b7266c6343908753dd37b628edc19bc3cac3831376f723f2f176ff95488b46770086d5d71499f2eaf9d3954a313dd55e942f3cd
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc25 desired_state_sha256=3bc9734ee8126844aa899023a83ce7f6541f5f9776a072af8b5d3f161e23af62
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc25 atlas_release_manifest_sha256=28d7b5245efeef67813acc99cd117e96a8edf6865ebcd031790ad3be066cc5ec reset_manifest_sha256=96f2a8fbaf277404fe8d2b5cc7e64609a5ad3436652cfbfcab23a49b5245b7a7
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc25 activation_height=1 activation_root=e04e58aaf47c6cc6810963656b7266c6343908753dd37b628edc19bc3cac3831376f723f2f176ff95488b46770086d5d71499f2eaf9d3954a313dd55e942f3cd
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc25 desired_state_sha256=3bc9734ee8126844aa899023a83ce7f6541f5f9776a072af8b5d3f161e23af62
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc25 atlas_release_manifest_sha256=28d7b5245efeef67813acc99cd117e96a8edf6865ebcd031790ad3be066cc5ec reset_manifest_sha256=96f2a8fbaf277404fe8d2b5cc7e64609a5ad3436652cfbfcab23a49b5245b7a7
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T06:49:00Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc25`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T06:49:03Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc25`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T06:52:21Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc25`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T06:56:24Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc25`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T07:31:07Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc27`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc27 activation_height=1 activation_root=cb9fc90fa78ae7cc219b926f3fff8d085087fbae5b0d0b335edd03d9ecf638d0959e085462351e4f48c54e027af13563c7696ca47b1a3a478c91f70529c70ac0
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc27 desired_state_sha256=59c2aa5faa9fb4811c4392deb85ff57afec2c31484fa5197a64972a8b7e653f9
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc27 atlas_release_manifest_sha256=a27757c0542932a60d167f1e787820c5d5e4d1ed99f2f3e8c005cc4afd6e6e73 reset_manifest_sha256=35d524fdc1346fe29008f5763c43afd3dcb448c23745cf6546d564f25262fdc6
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc27 activation_height=1 activation_root=cb9fc90fa78ae7cc219b926f3fff8d085087fbae5b0d0b335edd03d9ecf638d0959e085462351e4f48c54e027af13563c7696ca47b1a3a478c91f70529c70ac0
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc27 desired_state_sha256=59c2aa5faa9fb4811c4392deb85ff57afec2c31484fa5197a64972a8b7e653f9
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc27 atlas_release_manifest_sha256=a27757c0542932a60d167f1e787820c5d5e4d1ed99f2f3e8c005cc4afd6e6e73 reset_manifest_sha256=35d524fdc1346fe29008f5763c43afd3dcb448c23745cf6546d564f25262fdc6
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T07:31:30Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc27`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T07:31:33Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc27`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T07:35:45Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc27`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T07:42:36Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc27`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T08:29:34Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc28`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc28 activation_height=1 activation_root=07ad72d979c7a081cfcb9108b8c1636cd0c6149d6408164bacaf5bb0dbf05fd723f1cd4ffe002c14fbc99eeae0af4d2ef774a332b2d40d42cd1b1f51c3ba8f18
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc28 desired_state_sha256=1a361fc49c8bc8ac70d7cc3550016d9dc0f68f5664a5975c7748227a2ba234bc
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc28 atlas_release_manifest_sha256=fe93a3ed64b1304569c3359d44faf6af3c77fd6157007647a965f6ad517ce3ad reset_manifest_sha256=b03c7f5e223afe9dbfb02bbae1fc100690976048f4be9a775f04633b57036fb7
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc28 activation_height=1 activation_root=07ad72d979c7a081cfcb9108b8c1636cd0c6149d6408164bacaf5bb0dbf05fd723f1cd4ffe002c14fbc99eeae0af4d2ef774a332b2d40d42cd1b1f51c3ba8f18
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc28 desired_state_sha256=1a361fc49c8bc8ac70d7cc3550016d9dc0f68f5664a5975c7748227a2ba234bc
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc28 atlas_release_manifest_sha256=fe93a3ed64b1304569c3359d44faf6af3c77fd6157007647a965f6ad517ce3ad reset_manifest_sha256=b03c7f5e223afe9dbfb02bbae1fc100690976048f4be9a775f04633b57036fb7
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T08:30:12Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc28`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T08:30:15Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc28`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T08:33:31Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc28`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T08:54:47Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc28`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T09:33:01Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc29 activation_height=1 activation_root=00fcc38531a0df22a05acd1720264212d36984e6f4b0be7e9c91b43ab58da59ffe2fc4984951720380ec41a07210a60dfe6e384813197f4f6fe600d6c1853b16
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc29 desired_state_sha256=b67d6bbfd0edcd20172e575fd16f3bdffa5e7b3d97dcc76554669267733ea049
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc29 atlas_release_manifest_sha256=38657547248c09a5d410118f0f8bfbd31e2cb5da82bfc3a7882cc8e3688ec449 reset_manifest_sha256=ac8e5e29870c86d35eee0201fbbfd9748cde615fd7bf9c353000175029b415b9
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc29 activation_height=1 activation_root=00fcc38531a0df22a05acd1720264212d36984e6f4b0be7e9c91b43ab58da59ffe2fc4984951720380ec41a07210a60dfe6e384813197f4f6fe600d6c1853b16
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc29 desired_state_sha256=b67d6bbfd0edcd20172e575fd16f3bdffa5e7b3d97dcc76554669267733ea049
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc29 atlas_release_manifest_sha256=38657547248c09a5d410118f0f8bfbd31e2cb5da82bfc3a7882cc8e3688ec449 reset_manifest_sha256=ac8e5e29870c86d35eee0201fbbfd9748cde615fd7bf9c353000175029b415b9
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T09:34:11Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T09:34:47Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T09:37:19Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-03T09:45:35Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T09:51:52Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc29`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


## Controlled operation — 2026-08-03T10:33:18Z

- Operation: `STAGE_IMMUTABLE_RELEASE`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-02`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-03`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-04`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-05`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `validator-node-06`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay1`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay2`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `relay3`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `rpc-gateway`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `explorer-indexer`: `PASS` — CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc30 activation_height=1 activation_root=2b72a298410ac7908a7b4c8daf4de44d5a468a5cea4ceb4d61be69a06b57a3d6a8ab3ba22f26384bd42c23e8c0bf0fae36cb0e0655f86ea3cf8acbee512812a5
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc30 desired_state_sha256=a1ee4a9d0639f742deb4c1a9c2d418638b37ea8ebb8e500b253fad8a755c5edf
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc30 atlas_release_manifest_sha256=890643ad065c7e8e25cce31dbb903596fb44c49be5098f841fc668d6a8e91772 reset_manifest_sha256=b6d62169ddf7599827e3cb19742e7622d3466a92b060cb0f16c92273ec9bb591
CHAIN1266_IMMUTABLE_ROLE_STAGED
CHAIN1266_CONSENSUS_ACTIVATION_VERIFIED release_id=chain1266-incarnation-4-rc30 activation_height=1 activation_root=2b72a298410ac7908a7b4c8daf4de44d5a468a5cea4ceb4d61be69a06b57a3d6a8ab3ba22f26384bd42c23e8c0bf0fae36cb0e0655f86ea3cf8acbee512812a5
CHAIN1266_DESIRED_STATE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc30 desired_state_sha256=a1ee4a9d0639f742deb4c1a9c2d418638b37ea8ebb8e500b253fad8a755c5edf
ATLAS_P1_RELEASE_AUTHORIZATION_VERIFIED release_id=chain1266-incarnation-4-rc30 atlas_release_manifest_sha256=890643ad065c7e8e25cce31dbb903596fb44c49be5098f841fc668d6a8e91772 reset_manifest_sha256=b6d62169ddf7599827e3cb19742e7622d3466a92b060cb0f16c92273ec9bb591
- `observer`: `PASS` — CHAIN1266_IMMUTABLE_ROLE_STAGED
- `atlas-api`: `SKIP` — non-runtime role
- `atlas-indexer`: `SKIP` — non-runtime role


## Controlled operation — 2026-08-03T10:33:32Z

- Operation: `PASSIVE_SUPPORT_ROLES_STARTED`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `relay1`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay2`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `relay3`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `observer`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T10:33:34Z

- Operation: `VALIDATORS_STARTED_PAUSED`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_ACTIVE
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_ACTIVE


## Controlled operation — 2026-08-03T10:34:14Z

- Operation: `VALIDATOR_PAUSED_BARRIER_READY`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PAUSED_READY`
- `validator-node-02`: `PAUSED_READY`
- `validator-node-03`: `PAUSED_READY`
- `validator-node-04`: `PAUSED_READY`
- `validator-node-05`: `PAUSED_READY`
- `validator-node-06`: `PAUSED_READY`


## Controlled operation — 2026-08-03T10:36:58Z

- Operation: `SIGNED_START_DISTRIBUTED`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-02`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-03`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-04`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-05`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED
- `validator-node-06`: `PASS` — CHAIN1266_SIGNED_START_INSTALLED


## Controlled operation — 2026-08-03T10:39:09Z

- Operation: `STOP_FOR_FULL_RESET`
- Release: `chain1266-incarnation-4-rc30`
- Chain: `1266`, incarnation: `4`
- `validator-node-01`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-02`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-03`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-04`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-05`: `PASS` — CHAIN1266_ROLE_STOPPED
- `validator-node-06`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay1`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay2`: `PASS` — CHAIN1266_ROLE_STOPPED
- `relay3`: `PASS` — CHAIN1266_ROLE_STOPPED
- `rpc-gateway`: `PASS` — CHAIN1266_ROLE_STOPPED
- `explorer-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `observer`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-api`: `PASS` — CHAIN1266_ROLE_STOPPED
- `atlas-indexer`: `PASS` — CHAIN1266_ROLE_STOPPED


---

## C1266-2026-09-04-001 — Testnet-v3 recovery and NetBird five-validator launch

**Status:** Open
**Severity:** P0
**Detected:** 2026-09-04 UTC
**First bad height:** No live Testnet-v3 height established
**Last agreed finalized height:** None
**Last agreed finalized block ID:** None

### Affected and responsible nodes

- Affected: validators 02 through 06 and BootSeed hosts 1 through 3.
- Responsible component under current investigation: recovered launch deployment state and seed/runtime availability. No validator identity, stake, ownership binding, or canonical SGEN is implicated or will be regenerated.

### Recovery actions and outcomes

1. **Relocated the canonical execution workspace to synergy-val4 after external-volume recovery.**
   **Outcome:** Testnet-v3 revision 4aa6ae8463b1deababfe6b222dbc9251b1938ba1 is a clean Val4 checkout; the recovered NCP source containing the headless dynamic-NetBird support is present on Val4. No validator or seed service changed in this action.
2. **Read the historical Chain 1266 incident record before mutation.**
   **Outcome:** historical qualification branches and static-peer/legacy transport paths will not be used; the next action is canonical seed-service recovery only.

### Residual risks and next observation

- Verify all three seed HTTP endpoints, then deploy only verified validator/NCP artifacts through NCP and diagnose the first missing live transition if H1 does not finalize.

### Source evidence

- /home/node/synergy-network/01-Core-Protocol/testnet-v3
3. **Installed the current seed1 script, guard, configuration, unit, and an assumed current source genesis file.**
   **Outcome:** seed1 guard failed closed with ; the unit requires the separately pinned seed-support genesis SHA-256 , while the top-level source genesis has a different hash. No validator changed and seeds2-3 were untouched.
4. **Selected the exact guard-approved seed-support genesis from healthy seed3 for seed services only.**
   **Outcome:** pending installation and health verification on seeds1-3; this does not modify or distribute validator genesis configuration.

5. **Built the headless NCP control CLI from the recovered Val4 source and validated both focused NetBird advertisement tests.**
   **Outcome:** release binary deployment to validators 02 through 06 is beginning; no validator runtime or identity is changed by this step.

6. **Completed frozen native validator build and verified the canonical SGEN hash.**
   **Outcome:** deploying validator binary SHA-256 eead22289f1b4e215418aa9a605e50862fab283121363a29e9d1e8034d7bb56b to validators 02 through 06 before NCP-controlled preflight; SGEN SHA-256 is 439e18b91d71be45fa2ec8ba87167689e06413790303fe3568375498d73b3a8b.


7. **Amendment to action 3.** The guard failure was a genesis SHA-256 mismatch. The expected seed-support genesis hash was ee554cfb93bbe760540721e91ba69404716180621e2fc0e6483c87576fa7f253.
   **Outcome:** the exact support file was verified from the healthy Seed3 service before installation; this seed-only support file is not a validator genesis input.

8. **Seed service recovery.**
   **Outcome:** Seed1, Seed2, and Seed3 are active with local health checks passing. Seed1 has the required inbound TCP/5621 firewall allowance. No legacy seed service was enabled.

9. **Headless NCP deployment.**
   **Outcome:** the canonical headless NCP CLI was installed on validator-02 through validator-06; all installed binaries match SHA-256 035779d614d5a7de4b9ecb3c56531b55ce1cd9373434360eb561d365bc2f9eeb.

10. **Canonical validator runtime deployment.**
   **Outcome:** the canonical validator binary was installed on validator-02 through validator-06; all installed binaries match SHA-256 eead22289f1b4e215418aa9a605e50862fab283121363a29e9d1e8034d7bb56b. Live NCP preflight is next.

11. **validator-02 live NCP start.**
   **Outcome:** NCP verified NetBird health and launched the canonical binary, but the process exited before H0 at the configuration-authority gate: canonical Testnet-v3 Genesis has no finalized consensus parameter manifest.

12. **Live missing transition isolation.**
   **Outcome:** the frozen signed SGEN verifies and carries the Genesis-bound simplified PoSy v3 activation. The runtime startup guard still requires the retired JSON consensus_parameters compatibility wrapper, even though the SGEN loader intentionally uses the activation binding. No Genesis, identity, transport, or remaining validator was modified. The next change is limited to making that guard accept the signed activation manifest.

13. **SGEN activation runtime compatibility correction.**
   **Outcome:** the startup configuration guard now validates the verified Genesis-bound simplified PoSy v3 activation when the frozen signed SGEN intentionally omits the retired consensus_parameters JSON wrapper. Focused frozen-SGEN regression test passed. Rebuilt validator SHA-256: f251bc8d7cca999db65dbd5c446b08225fd0313a60aa87ce21a0b99ffefeee91. Deploying to validator-02 for the live rerun.

14. **validator-02 SGEN configuration comparison.**
   **Outcome:** the repaired activation guard reached the next check and rejected the NCP-generated 500 ms override. The frozen SGEN commits a 2000 ms cadence. This is a configuration handoff defect: NCP must reconcile its managed config to the frozen SGEN cadence, and the runtime NCP parser must accept that exact signed cadence. No runtime, Genesis, identity, or transport change is being made.

15. **Cadence correction and SGEN reissue authorization.**
   **Outcome:** the operator set the required cadence to 500 ms, within the current 100-1500 ms launch envelope, and authorized a replacement signed SGEN using the existing authorities. The uncompleted 2000 ms NCP/runtime configuration path was reverted before deployment. The reissue must preserve the same membership, authority set, identities, and 36 deterministic H0 operations; only the governed cadence parameter may change. No validator has been started from the obsolete 2000 ms SGEN.

16. **Correction to action 15: governed derivative rebinding.**
   **Outcome:** changing the approved 500 ms cadence necessarily changes the simplified PoSy activation root, parameter root, release-decision digest, Genesis hash, and ETDAG membership-anchor commitment. The five-validator membership root, identities, authority roster, all 36 H0 operation bytes, and all H0 execution roots remain required to be identical.

17. **Unsigned 500 ms SGEN staging and verification.**
   **Outcome:** the no-overwrite reissue command produced build/testnet-v3/sgen-500ms/genesis.unsigned.sgen with file SHA-256 662fed4caf4915348304fc7618ef30c1a32a82562eb02fbb840c3d9511272217. It verifies Chain 1266, testnet, posy/3.0, validators 02-06, 36 H0 operations, target 500 ms, membership root 4a059c97a3bf88216a9fc94fa81304dc26303424bc04620dc47d47f64f11ce9b, execution root 55ca242d074ea2844520d7c6fd4c26af3b35904e6173357ac4c18516e88ffdc6, AIVM root 9c11bc3f6ef9379fdd875ecdc887301af3239197aa1fd0a8fc490785dd5c3854, and receipt root fbf68f46186d661fbdf19d30003ae541a5d056f440dac6bc20e93676f05e271a. The existing authority signer has not been invoked; no custody data was opened and no validator state changed.
