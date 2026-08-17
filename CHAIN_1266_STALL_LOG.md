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

---

## C1266-2026-08-08-007 — Single-authority journal growth OOM stall

**Status:** Monitoring; durable runtime fix in progress  
**Severity:** P0  
**Detected:** 2026-08-08 16:27:03 UTC  
**First bad height:** 52,734  
**Last agreed finalized height:** 52,733  
**Last agreed finalized block ID:** `58d430e4e457c71174808abef1b360942c476040d0697d37d128ca9f34995bab`

### Affected and responsible nodes

- Affected: the sole `authority-node-01` validator on `synergy-val`, and all
  Chain 1266 consumers while it was stopped.
- Responsible component: the shared `single_authority_v1` signing-journal
  persistence path. No host or operator action caused the runtime defect.

### Symptoms and evidence

- The chain progressed from roughly 1.5-second blocks to roughly 7-second
  blocks, then stopped at height 52,733.
- At 2026-08-08 06:21:32 UTC the kernel OOM killer terminated
  `synergy-validator-node`: 21,798,056 KiB anonymous RSS; systemd recorded a
  24,474,923,008-byte memory peak and `Result=oom-kill`.
- The original service had `Restart=no`, so no process restarted after the
  OOM kill.
- The single-authority durable directory then contained a 279,665,771-byte
  signing journal, a 290,675,620-byte finality log, and a
  1,021,332,407-byte committed-block archive. The journal implementation
  deserializes and atomically rewrites its complete JSON history for intent,
  signature, and finalization of every new block.

### Confirmed cause

The signing journal has unbounded O(n) read/deserialize/search/serialize work
and allocation per block. Its complete historical record is loaded repeatedly
in the critical single-authority path, so work, lock hold time, and memory
pressure rise with chain height until the host OOM-kills the validator. The
`chain_tip_lock_unavailable` RPC warnings are a resulting contention symptom,
not the initiating failure. The existing writable finality-store wrapper is
already steady-state O(1); this incident requires a bounded, crash-safe
signing-journal implementation and a release using it.

### Recovery actions and outcomes

1. **Captured systemd, kernel, service-log, and durable-finality evidence.**  
   **Outcome:** proved an OOM kill rather than disk exhaustion, peer loss, or
   a signing conflict; the validator had 368 GiB free disk and 22 GiB free
   RAM after termination.
2. **Attempted `systemctl set-property ... Restart=on-failure`.**  
   **Outcome:** systemd rejected the unsupported property update; the failed
   attempt changed no service state.
3. **Installed a reversible systemd drop-in with `Restart=on-failure` and
   `RestartSec=10s`, then reset the failed state and started the original
   service.**  
   **Outcome:** no chain data was changed. The durable head resumed through
   height 52,993 by 2026-08-08 17:01:46 UTC with zero service restarts and no
   new fatal journal entry. This restored availability but did not cure the
   growing per-block journal cost.
4. **Read this complete incident log and began the source-level bounded-
   journal correction.**  
   **Outcome:** pending targeted safety, migration, long-history, artifact,
   and live sustained-block verification.

### Final outcome

Availability is restored, but this incident remains open until a validated
runtime removes the unbounded signing-journal work and demonstrates sustained
advancing finality without the prior memory growth.

### Residual risks and next observation

- The restarted pre-fix binary can still experience increasing block latency
  and memory pressure until the fixed runtime is deployed.
- Before declaring resolution, require an advancing finalized tip, zero new
  fatal consensus/signing errors, bounded validator RSS, bounded per-block
  journal work, and live Atlas visibility. The checkout operating rule also
  requires equivalent advancing tips across all six validators before a full
  Chain 1266 health declaration; the present single-authority configuration
  therefore remains a controlled temporary exception rather than proof of a
  six-validator healthy network.

### Source evidence

- `/etc/systemd/system/synergy-chain1266-authority.service` and its recovery
  drop-in on `synergy-val`
- `/var/log/synergy/chain1266-authority.log` and the 2026-08-08 kernel journal
  on `synergy-val`
- `runtime/src/consensus/single_authority_signing_journal.rs`
- `runtime/src/consensus/single_authority_writable_store.rs`

### 2026-08-08 17:35 UTC amendment — bounded journal hotfix deployed

5. **Implemented and tested the bounded signing-journal migration.**
   **Outcome:** `single_authority_signing_journal.json` keeps the V1 JSON
   shape for rollback compatibility, archives the complete legacy V1 journal
   before compaction, and uses a separate fsynced hot-state marker. Completed
   entries are removed only after the finality head is durable; the
   append-only finality record remains the exact public-signature audit
   source. Startup fails closed on a finality/journal mismatch. Focused tests
   passed for 19 journal cases (including a 52,733-entry migration), two
   height-one/restart cases, two real-transaction/restart cases, and 13
   startup cases. `cargo check -p synergy-testnet` passed. The unfiltered
   integration-test command remains blocked by the pre-existing
   `testnet_genesis_artifacts` missing-`crate::utils` compile error.
6. **Built and verified the Linux validator artifact.**
   **Outcome:** a locally built x86_64 Linux ELF from source base commit
   `c3429743c3ff4e78b44e020672d23a10ac988172` plus source-diff digest
   `4d0a2fec7f71d8da02e08a4082cd00326029e388bd468183b15e136e08aea617`
   produced SHA-256
   `5a3eddcc8d646305c8c44ddc9b982ada06a77a4dedf1cdc5422fd27f27c9d135`.
   The legacy immutable-release workflow was not used because it still pins
   the prior chain incarnation; this is a controlled temporary-authority
   hotfix with the prior binary retained for rollback.
7. **Staged the artifact, verified its host SHA-256 and Linux identity, then
   performed a rollback-safe cutover on `synergy-val`.**
   **Outcome:** at 2026-08-08 17:35:31 UTC the prior binary was retained as
   `/usr/local/bin/synergy-validator-node.pre-journal-hotfix-20260808T173531Z`.
   The new binary started successfully as service PID 160734 with zero
   restarts. If it had failed the 20-second start gate, the procedure would
   have restored and started the retained binary automatically; that rollback
   was not invoked. No manual finality, journal, block-body, receipt, or
   execution-state repair occurred.
8. **Verified live migration and sustained durable finality.**
   **Outcome:** the legacy journal was preserved as a 282,571,936-byte archive;
   the active canonical journal compacted to 32 bytes when idle (one active
   signing record is approximately 5 KiB while a block is being produced),
   and its hot-state matched the durable finalized head. The head advanced
   from 53,297 to 53,366 in approximately 74 seconds and then to 53,412;
   no restart, fatal, panic, or OOM entry occurred. Post-cutover RSS remained
   approximately 1.6--1.9 GiB, versus 5.6 GiB immediately before cutover and
   the incident's 21.8 GiB OOM condition.

### Final outcome amendment

The single-authority chain-stall cause is resolved: the validator is running
the bounded journal runtime, its existing historical journal is safely
archived and compacted, and its durable finalized head is advancing at roughly
the configured one-second cadence. This is evidence for the controlled
temporary single-authority chain only, not a declaration that a six-validator
network is healthy.

### Residual risks and next observation amendment

- The local `synergy_getBlockNumber` RPC request on port 5640 did not return
  within the eight-second probe window both before and after cutover. Durable
  finality remained the authoritative proof for this incident; investigate the
  separate RPC responsiveness issue before using that endpoint as a health
  gate or declaring public Atlas/API parity.
- Continue observing finalized-head growth, RSS, and the compact journal. The
  reversible `Restart=on-failure` systemd drop-in remains installed until the
  temporary authority service definition is formally replaced.

**Final observation for this response (2026-08-08 17:40:18 UTC):** durable
head 53,534; hot-state 53,534; zero active canonical journal entries; 32-byte
idle canonical journal; service active with zero restarts and zero new
fatal/panic/OOM lines since cutover. Current RSS was 2,296,180,736 bytes and
the migration/startup peak was 3,752,505,344 bytes.

---

## C1266-2026-08-09-008 — Single-authority RPC fan-out OOM recurrence

**Status:** Open; immediate containment in progress
**Severity:** P0
**Detected:** 2026-08-08 21:19:44 UTC
**First bad height:** 65,895
**Last agreed finalized height:** 65,894
**Last agreed finalized block ID:**
`c7253fe96fbf5b041f861124923b0faf1df40ddc20be7093f3563d81b3d1017f`

### Affected and responsible nodes

- Affected: the temporary `authority-node-01` validator on `synergy-val`,
  its local RPC listener, and all public consumers waiting on that listener.
- Responsible components: the `single_authority_v1` RPC history reader and
  the unbounded thread-per-connection RPC server. A persistent forwarded
  client session amplified the defect but did not create it.
- The bounded signing-journal implementation introduced in incident 007 is
  not the source of this recurrence: its canonical journal remained 32 bytes
  while this process exhausted memory.

### Symptoms and evidence

- The bounded-journal runtime (SHA-256
  `5a3eddcc8d646305c8c44ddc9b982ada06a77a4dedf1cdc5422fd27f27c9d135`)
  was kernel-OOM-killed at 2026-08-08 21:19:44 UTC after finalizing height
  65,894. The automatic `Restart=on-failure` drop-in started it again at
  21:19:57 UTC.
- At diagnosis the restarted process had 811 tasks and 21.8 GiB anonymous
  RSS on a 23 GiB host, with only 2.8 GiB available. It held hundreds of
  `CLOSE-WAIT` connections on its local port 5640; the connecting forwarding
  process had corresponding `FIN-WAIT-2` sockets.
- The active signing journal was still a 32-byte zero-entry JSON document and
  its hot-state reported `finalized_through=78,243`. The historical V1 journal
  archive remained unchanged at 282,571,936 bytes.
- At the same sample, `single-authority-finality.log` was 431,224,862 bytes
  and `single-authority-committed-blocks.ndjson` was 1,516,136,727 bytes.
  The local `synergy_getBlockNumber` request again timed out after eight
  seconds, while durable finality itself continued through height 78,294.

### Confirmed cause

For every single-authority RPC request,
`single_authority_entries_for_rpc` calls `SingleAuthorityFinalityStore::recover`
to deserialize the entire finality log, then recovers and clones every
committed block body into a map before constructing the response. The generic
RPC listener spawns an unbounded operating-system thread for every accepted
TCP connection. As those whole-history requests accumulated behind a forwarded
local session, hundreds of concurrent 431 MB plus 1.5 GB recoveries retained
anonymous allocations and starved the producer/RPC threads until the kernel
OOM-killed the validator.

### Recovery actions and outcomes

1. **Captured durable-head, kernel, systemd, process, socket, file-size, and
   application-log evidence before changing live state.**
   **Outcome:** established that this is a second OOM mechanism after the
   journal hotfix, not a regression to the old unbounded signing journal or a
   disk, consensus, or safety conflict.

2. **Stopped only Atlas's `synergy-chain1266-rpc-tunnel.service` and restarted
   the authority service after its confirmed RPC backlog returned.**
   **Outcome:** Atlas's PostgreSQL data and API/indexer services remained
   running; the temporary tunnel stop prevented the 239 abandoned RPC clients
   from immediately recreating the authority's 5.7 GiB RSS pressure while the
   replacement was built.

3. **Prepared a bounded-RPC runtime for controlled deployment.**
   `synergy_getBlockNumber` reads the atomically committed finalized-head
   pointer instead of reconstructing history; the authority publishes a
   startup-reconciled, 8,192-block in-process tail for Atlas's 100-block range
   requests; and the HTTP listener permits at most four concurrent handlers,
   rejecting overload with HTTP 503. The target x86_64 Linux artifact has
   SHA-256 `60a1736d74a938f0f0686c3f5b418be1dcc572a39d90a9727392f83a544d3a23`.
   **Outcome:** `cargo check -p synergy-testnet --lib` and the focused
   `http_rpc_connection_permits_are_capped_and_released` test passed before
   this deployment step. The full source-diff digest for the runtime change is
   `fef8bd3b65348949161368c2b5a39b86ec717b4d1a2c6d514ce2b5bfc8aa3387`.

4. **Prepared a follow-up summary-RPC correction before reopening Atlas.**
   Atlas caught up from 75,138 through 79,472 in nine seconds using the
   bounded tail, but its parallel post-backfill `synergy_getNetworkStats`,
   `synergy_getValidatorStats`, and `synergy_getValidatorActivity` calls
   invoked the old full-history validator snapshot while holding the shared
   chain lock. Four handlers therefore remained occupied and correctly
   received HTTP 503 under the new cap. The follow-up makes those
   single-authority summaries use the finalized head and Genesis-bound
   authority instead. Its verified x86_64 Linux artifact SHA-256 is
   `5017f7bfa32d4788e0585fcf98a581495c75ee1ab6511d0758aa22f8fd85d6a4`.
   **Outcome:** Atlas tunnel paused and authority restarted to release the
   stale handlers; `cargo check -p synergy-testnet --lib` passed before this
   cutover.

### Final outcome

Pending containment, a restart with the connection backlog drained, and a
bounded RPC implementation. The automatic restart restored durable block
production temporarily but is not a resolution while unbounded public-history
requests can recreate the same pressure.

### Residual risks and next observation

- Containment must prevent the current forwarded connection backlog from
  recreating OOM before the source fix is ready.
- The fixed runtime must cap concurrent RPC work and avoid whole-history
  finality/body reconstruction for a height query. Verify exact durable-head
  advance, bounded task count/RSS, responsive local RPC, and no new OOM after
  deployment.

### Source evidence

- `/var/log/synergy/chain1266-authority.log`, kernel journal, and systemd
  status on `synergy-val`
- `runtime/src/rpc/single_authority_finality_rpc.rs`
- `runtime/src/rpc/rpc_server.rs`
- `runtime/src/consensus/single_authority_finality_store.rs`

### Recovery completion amendment (2026-08-09 01:31 UTC)

1. **Deployed the bounded RPC-tail runtime and then its summary-RPC follow-up
   atomically on `synergy-val`.**
   **Outcome:** the running binary SHA-256 is
   `5017f7bfa32d4788e0585fcf98a581495c75ee1ab6511d0758aa22f8fd85d6a4`.
   The preceding bounded-RPC binary remains at
   `/usr/local/bin/synergy-validator-node.pre-summary-rpc-20260809`, and the
   pre-incident binary remains at
   `/usr/local/bin/synergy-validator-node.pre-rpc-tail-20260809`, providing
   explicit rollback points without altering finality, committed bodies,
   receipts, execution state, or signing history.

2. **Validated the authority locally before re-enabling Atlas.**
   **Outcome:** an Atlas-sized 100-block range returned HTTP 200 in 0.096 s;
   the four simultaneous polling methods (`synergy_getBlockNumber`,
   `synergy_getNetworkStats`, `synergy_getValidatorStats`, and
   `synergy_getValidatorActivity`) returned HTTP 200 in 2--7 ms with no
   lingering handler sockets.

3. **Re-enabled `synergy-chain1266-rpc-tunnel.service` on `synergy-index`
   (Atlas) and observed recovery.**
   **Outcome:** Atlas caught up from its persisted block 75,138 to 79,472 in
   nine seconds, and after the follow-up from 79,616 to the live head. At
   2026-08-09 01:31 UTC the authority RPC, Atlas tunnel RPC, and Atlas public
   API all independently reported block 79,848. The indexer journal showed
   successful contiguous ranges through that height and ongoing one-to-two
   block ranges, with no post-recovery 503 or timeout entry.

4. **Observed post-recovery resource bounds.**
   **Outcome:** authority service active with zero restarts, 10 threads, and
   764,542,976 bytes cgroup memory (approximately 743 MiB RSS); only listener
   and normal TIME-WAIT sockets remained. This replaces the 21.8 GiB / 811
   task OOM condition.

### Final outcome amendment

Resolved. Atlas indexing and the temporary single-authority chain are both
advancing. The cause was RPC design rather than consensus safety: full-history
deserialization per request, unbounded handler creation, and summary methods
that repeated the same work under the chain lock. The deployed path uses the
durable finalized-head pointer for polling, a bounded 8,192-block reconciled
tail for Atlas range reads, bounded handler admission, and fast
single-authority summary calculations.

### Residual risks and next observation amendment

- Historical requests outside the 8,192-block hot window deliberately retain
  the fail-closed durable-recovery path and may receive HTTP 503 while bounded
  worker capacity is occupied. They cannot recreate the prior unbounded OOM
  fan-out, but should receive a separately indexed durable query path before
  relying on arbitrary deep-history public reads.
- Continue observing durable-head growth, Atlas/API parity, RSS, handler
  counts, and the bounded signing journal during the temporary authority
  period.

---

## C1266-2026-08-16-009 — Single-authority full-history recovery OOM loop

**Status:** Resolved for the temporary single-authority authority; monitoring
**Severity:** P0
**Detected:** 2026-08-16 12:10:17 UTC
**First bad height:** 633,460 (Atlas's persisted tip is 633,459)
**Last agreed finalized height:** 633,459 (Atlas evidence; authority durable
head and block ID must be recovered without relying on the failing RPC path)
**Last agreed finalized block ID:** Not yet recovered from durable storage

### Affected and responsible nodes

- Affected: the temporary sole authority on `synergy-val` and Atlas on
  `synergy-index`.
- Responsible component: the shared single-authority finality/body recovery
  path. No host or operator action is implicated.

### Symptoms and evidence

- Atlas's public summary reports block 633,459 with `indexedAt`
  `2026-08-15T22:24:06.409Z`; it is not merely presenting a cached current
  chain tip.
- At 2026-08-16 13:09 UTC the authority had restart count 566 and an active
  process consuming 22.8 GiB on a 23 GiB host. The kernel repeatedly recorded
  `oom-kill` after approximately 80--115 seconds of each startup.
- The currently deployed authority binary is the verified bounded-RPC
  follow-up, SHA-256
  `5017f7bfa32d4788e0585fcf98a581495c75ee1ab6511d0758aa22f8fd85d6a4`.
  Its handler cap returns HTTP 503 rather than preventing the process-wide
  startup recovery from exhausting memory.
- Atlas retries `synergy_getBlockNumber` at approximately one-second cadence
  and its block-range requests repeatedly abort while the authority dies.

### Confirmed cause

The earlier bounded 8,192-record tail was applied only after complete durable
history had already been reconstructed. Authority startup read every finality
frame into a vector, then read the same log again; it also materialized every
committed block body into a `BlockChain` and every receipt frame into a map.
The RPC fallback repeated equivalent full finality/body recovery on cache
misses. At more than 633,000 heights these transient whole-history allocations
grew to 22.8 GiB anonymous RSS and caused the kernel OOM restart loop.

### Recovery actions and outcomes

1. **Captured authority service state, kernel OOM evidence, active-process
memory, Atlas summary, and Atlas/tunnel failures without changing service
state.**
   **Outcome:** confirmed an active authority OOM restart loop and a stalled
public indexer; no validator, Atlas, or chain-derived data was modified.

2. **Implemented streaming, bounded authority recovery and verified the
replacement runtime.**
   **Outcome:** finality frames, committed block bodies, and receipt frames are
now streamed and validated without reconstructing their complete histories;
only an 8,192-block finality/body suffix and a compact greatest-nonce-per-
sender index remain resident. The RPC fallback is likewise bounded to the
startup-reconciled cache instead of reopening full history on a cache miss.
`cargo check -p synergy-testnet --lib` passed, as did bounded finality-tail,
bounded committed-body-tail, authority restart/no-resign, and real signed
transaction restart tests. The verified Linux x86_64 artifact is SHA-256
`d1336198df04301281fcaef327f1504298a37b215cf340e0ad745c20936eff1d`,
built from base `c3429743c3ff4e78b44e020672d23a10ac988172` with runtime
source-diff SHA-256
`b6abb7a86f5d69d9710166ec726d4995df8b1ee97472d5b50ffc323f8caa6c5b`.

3. **Prepared a rollback-safe authority cutover.**
   **Outcome:** the artifact was staged through the approved `synergy-val`
connection, where its SHA-256 and x86_64 Linux ELF identity matched exactly.
The deployed `5017f7b...` binary was retained unchanged as the rollback
target; no chain data reset or mutation occurred.

4. **Observed the first guarded cutover and corrected its service-counter
criterion before a second replacement.**
   **Outcome:** the bounded runtime reached finalized height 633,460 with zero
new failure and approximately 3.2 GiB RSS, but the guard compared
`NRestarts` across an intentional `systemctl stop`. systemd resets that
counter on an explicit stop, so the guard falsely restored the retained
`5017f7b...` binary. This was a rollback-control defect, not a chain-data or
runtime failure; the new binary, finality archive, committed blocks, receipts,
and execution state remain intact. The second cutover will use service state,
process identity, memory bound, and durable-head advance instead of that
resettable counter.

5. **Prepared corrected bounded-recovery cutover.**
   **Outcome:** the mistakenly restored binary was stopped and the verified
`d1336198...eff1d` replacement was atomically reinstalled at 13:35 UTC; the
retained `5017f7b...` binary remains available at
`/usr/local/bin/synergy-validator-node.pre-bounded-recovery-20260816T1332Z`.
No finality, committed-body, receipt, execution-state, or signing data was
modified. After one streaming recovery pass over the 3.3 GiB finality log,
12 GiB committed-body archive, and 231 MiB receipt log, the durable head
advanced from 633,460 to 633,479. The service has zero restarts, 10 threads,
and approximately 2.9 GiB process RSS; the larger cgroup reading is file cache
from the sequential archive scan rather than anonymous runtime allocation.

6. **Prepared Atlas reconnect after sustained authority recovery.**
   **Outcome:** started only `synergy-chain1266-rpc-tunnel.service` on
`synergy-index`. The actual Atlas indexer,
`synergy-testnet-v3-atlas-indexer.service`, remained active (the generic
explorer-indexer units are intentionally inactive). It indexed contiguous
ranges from 633,539 onward at roughly one-to-two blocks per poll with no new
timeout or 503 entry.

7. **Verified sustained authority and Atlas progress.**
   **Outcome:** `synergy_getBlockNumber` returned height 633,588 directly on
the authority; its durable head matched that height. Atlas's public summary
reported 633,587 one sample later, and subsequent Atlas logs recorded through
633,605. The authority stayed active with zero restarts, ten threads, and
approximately 2.9 GiB RSS; no post-cutover OOM, panic, fatal, or safety-halt
entry was present. Atlas indexer memory was approximately 44 MiB. The final
live parity check reported exactly height 633,700 from both authority RPC and
the Atlas public API; the tunnel and actual Atlas indexer were active.

### Final outcome

Resolved. The authority now streams and validates the complete durable archive
while retaining only an 8,192-block hot body/finality suffix plus a compact
nonce index. Its RPC path never reconstructs complete history on cache misses.
This removed the OOM restart loop, restored block production, and allowed
Atlas to catch up. This is evidence only for the temporary one-authority
configuration, not a declaration that a six-validator chain is healthy.

### Residual risks and next observation

- Startup still performs a full sequential integrity scan of the 3.3 GiB
  finality and 12 GiB body archives. It is bounded-memory but I/O-bound; an
  indexed checkpoint would reduce recovery time in a future release.
- Historical RPC queries outside the hot tail now fail closed rather than
  rebuilding the archive in the authority process. They need a separate
  durable/indexed historical-query path before being relied on publicly.

### Source evidence

- `synergy-chain1266-authority.service`, kernel journal, and
  `/var/log/synergy/chain1266-authority.log` on `synergy-val`
- Atlas API/indexer and RPC-tunnel journals on `synergy-index`
- `runtime/src/consensus/single_authority_finality_store.rs`
- `runtime/src/consensus/single_authority_execution.rs`
- `runtime/src/consensus/single_authority_driver.rs`
- `runtime/src/rpc/single_authority_finality_rpc.rs`
