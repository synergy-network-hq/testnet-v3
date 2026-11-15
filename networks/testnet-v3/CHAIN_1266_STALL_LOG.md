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

**Status:** Resolved  
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



## C1266-2026-10-06-001 - Single-authority restart OOM and public RPC outage

**Status:** Open
**Severity:** P0 chain liveness
**Detected:** 2026-10-06 03:16 UTC
**First bad height:** 2632441
**Last agreed finalized height:** 2632440
**Last agreed finalized block ID:** `abf7c01857d229d6ce373028784332cea15b8193dc2d3629fe2f48d45a928e8e`

### Affected and responsible nodes

Val1 authority-node-01, Chain 1266 incarnation 5, single_authority_v1.
Index database retains the same last block. RPC gateway has a separate outage.
Val4's failed legacy five-validator service is unrelated to this diagnosis.

### Symptoms and evidence

Last production: 2026-09-10 06:19:00 UTC / 01:19 CDT, about 26 days ago.
Val1 durable head, last committed block, live RPC and synergy-index's
synergy_explorer_v3 blocks table agree on the height and hash above.
Index insertion time: 06:19:00.738856 UTC on September 10.
Val1 has over 18891 restarts, approximately 22.9 GiB process memory peaks and
repeated kernel OOM/SIGKILL deaths. Host RAM is about 23 GiB; swap is absent.
Finality log is 14512838669 bytes; committed blocks are 50985951398 bytes.
PID 2322890 was observed reading the finality log: offset grew from
8589918208 to 10737397760 while RSS grew from 8600464 to 12548584 KiB.

### Confirmed cause and inference

Ubuntu unattended-upgrade updated libc6 from 2.43-2ubuntu2.3 to
2.43-2ubuntu2.4, ending September 10 at 06:18:59 UTC. Its dpkg log explicitly
lists systemctl restart synergy-chain1266-authority.service among restarted
services. Systemd records clean stop at 06:19:00-01 and immediate restart;
first recovery process was OOM-killed at 06:21:45. Automatic retries continue.
Confirmed blocker: memory exhaustion during restart history recovery.
Strong inference: excessive history materialization in the deployed runtime;
the exact allocating source function has not been verified.
Binary SHA-256: d1336198df04301281fcaef327f1504298a37b215cf340e0ad745c20936eff1d.

### Recovery actions and outcomes

1. Read required instructions, memory and complete incident log; checked live
services, kernel/service logs, history sizes, file descriptors, durable tip,
RPC, index DB and package-update records. Outcome: diagnosis established.
No runtime restart, stop, reset, key, config, binary or DB mutation performed.
2. Appended this diagnostic entry in place on other-mini's external SSD.

### Final outcome, residual risks and next observation

Unresolved. Index's authority RPC tunnel returns the same stopped tip;
its explorer service is active but old Atlas API port 3020 has no listener.
RPC role service is inactive, ports 5640/5660 have no listener and nginx
proxies to those ports. Public rpc.synergy-network.io returns HTTP 502.
Gateway systemd retains an August 3 exit timestamp but no recent unit log;
that does not establish the entire outage duration or current front-end routing.
Next repair: locate exact deployed source and implement bounded history
recovery preserving finalized state; prove advancing successor blocks, stable
memory and restart recovery. Verify Atlas and public RPC separately.

### Source evidence

Val1 journalctl service/kernel logs; /var/log/apt/history.log.1.gz;
/var/log/unattended-upgrades/unattended-upgrades-dpkg.log.1.gz;
/var/lib/synergy/node/data/consensus/chain-1266-incarnation-5/;
/proc/2322890/fdinfo/10 and status; index synergy_explorer_v3.blocks;
index RPC tunnel; gateway service/listeners/nginx and public RPC request.

### Source-location and allocation follow-up - 2026-10-06

The single-authority source is retained in the existing SSD repository:
/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/testnet-v3,
branch release/chain1266-single-authority,
commit bc6a7ea3febc4abc63429da9954fb958e53500d7.
Local branch and origin-tracking branch both resolve to this commit;
GitHub independently retains the same branch and commit. The working tree
is on main, so filename searches of the checkout do not expose this source.
No clone, copied source tree, checkout switch or pull was performed.

The branch's historical C1266-2026-08-16-009 entry binds the currently
installed d1336198...eff1d binary to the August 16 bounded-recovery build:
base c3429743c3ff4e78b44e020672d23a10ac988172 plus recorded runtime
diff digest b6abb7a86f5d69d9710166ec726d4995df8b1ee97472d5b50ffc323f8caa6c5b.
The later August 17 checkpoint is source lineage, not yet a proven exact
byte-for-byte reconstruction of that build's source diff.

A remaining full-history allocation is visible in the retained source:
role_runtime.rs:2533 calls require_durable_binding_agreement before
constructing authority worker inputs. single_authority_startup.rs:308
calls store.recover(); single_authority_finality_store.rs:441-449 reads
the entire finality log into a byte vector, then lines 450-472 deserialize
all records into a second vector. This preflight precedes the bounded
WritableStore/driver path and matches the observed finality-file read and
rising process RSS. It is a concrete missed bounded-recovery path; exact
runtime-to-checkpoint equivalence remains subject to source-diff verification.

Repair must stream the preflight while preserving validation of every
record's chain identity, release identity, linkage and durable-head binding.
No validator runtime, binary, service, chain state, keys or configuration
was changed during this source investigation. Incident remains open.

### Repair execution - 2026-10-06T10:09:58.182721+00:00

User authorized code repair, replacement binary deployment and chain restart.
Pre-action gate: canonical instructions, memory and full incident log read.
Val1 remains in OOM recovery loop at height 2632440; SHA d1336198...eff1d.
Plan: stop only the failing authority unit to end OOM churn, repair the
release branch preflight with streaming validation, use the existing Linux
build cache, run safety/recovery regressions, install a checksum-verified
replacement and prove successor finality plus restart recovery. No reset.

#### Action: stop OOM churn - 2026-10-06T10:10:49.056156+00:00

Stopped only synergy-chain1266-authority.service on Val1. Verified
ActiveState=inactive, SubState=dead, MainPID=0. Host available memory
returned to about 22 GiB. Existing chain data and binary are untouched.

#### Recovery progress: source repair and Atlas services - 2026-10-06T10:21:00Z
- Canonical SSD Git branch release/chain1266-single-authority now contains repair commit 2b66f096e7f75841b597cca19b590bc36d74766c. Shared streaming finality inspection validates every record without retaining history or modifying the durable head; durable-binding preflight uses that inspector. Regression tests cover 10,000-record bounded inspection, old foreign release records, stale-head nonmutation, and real startup preflight beyond the 8,192-record tail.
- Existing /root/launch-src Linux build cache on Val1 synchronized to that source; no new source clone or checkout was created. Release-profile single-authority regression tests are compiling. Production authority remains stopped, with data, genesis, signing journal and keys preserved.
- On synergy-index, verified deployed Atlas API/indexer support incarnation 5, single_authority_v1 and canonical genesis 2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74. Started existing synergy-testnet-v3-atlas-api.service and synergy-testnet-v3-atlas-indexer.service. Database was last indexed at 2632440 with hash abf7c01857d229d6ce373028784332cea15b8193dc2d3629fe2f48d45a928e8e. New ingestion remains dependent on authority RPC recovery.
- RPC gateway installed native runtime units bind older incarnation-4 release. They have not been started as incarnation 5; current public RPC still needs restoration.

#### Recovery progress: regression fixtures and gateway transport - 2026-10-06T10:26:00Z
- First Linux release regression run: 91 passed, 2 failed. New long-history test fixture generated a zero block hash after 255 records; corrected to domain-derived height hashes. Existing head-ahead test had an impossible log offset, triggering committed-history truncation before intended height guard; corrected offset to actual committed log length. Production checks were not relaxed. Follow-up canonical SSD commit 59e72d16c84156f5042519af549c6028c625b0ed. Re-running all single-authority tests.
- Gateway forwarding restored via enabled synergy-chain1266-rpc-tunnel.service, matching the index's existing authority-forwarding model. Reused its existing transport key; Val1 authorization constrained to gateway source address, RPC/WS permitopen ports and no shell. Val1 host key strictly pinned against existing trusted operator known_hosts (ED25519 SHA256:GZuZgyT5hDPXwPCU1zfig/rqu5eJHBJoZ/EYGrT2wlc). Older native gateway runtimes remain stopped.
- Val1 existing authority override now limits failed startups to three per 30 minutes with 30-second retry spacing. This contains repeated failure; bounded recovery repair addresses the cause. Security package updates remain enabled.

#### Recovery progress - 2026-10-06T10:30:46.176665+00:00
- Follow-up regression result: 92 passed; one newly added fixture still used the wrapping hash expression because an initial textual substitution matched an earlier test. Corrected the exact 10,000-record fixture; restored unrelated existing fixture. Canonical repair tip is now 5388907e521bb806235cc5a9bb6d1c03ed586529. Tests and production binary build are running; deployment remains gated on passing tests.
- Found Val1 authority unit disabled at boot and Atlas API/indexer units static with no boot dependency. Existing Atlas units now have Install/WantedBy=multi-user.target and are enabled. Val1 will be enabled when the repaired binary is installed.

#### Recovery progress - 2026-10-06T10:36:00.042185+00:00
- Linux production build completed successfully (cargo build --locked --release -p synergy-testnet --bin synergy-validator-node; 5m15s). Source parity verified across every runtime/src Rust file plus workspace/package Cargo manifests, Cargo.lock and embedded runtime-binding JSON: 181 files match canonical SSD commit 5388907e521bb806235cc5a9bb6d1c03ed586529 byte-for-byte. Final test compile now owns the build lock.

#### Deployment attempt: bounded durable-binding preflight - 2026-10-06T10:41:57.383732+00:00
- All 93 Linux release-profile single-authority tests passed, 0 failed (2.62s test execution). Production build successful. New Linux x86-64 validator v20.0.0 SHA256 dc40b4044a63599f8d3b6fbee782e3f1e34b77b9d2db5f25e1c0d0d7f1b61143, canonical source tip 5388907e521bb806235cc5a9bb6d1c03ed586529.
- Install atomically; retain previous d1336198df04301281fcaef327f1504298a37b215cf340e0ad745c20936eff1d binary for rollback. Enable and start existing authority service. Signed desired state, start authorization, genesis, authority identity/key, durable logs and execution state remain unchanged. Resume expected from finalized height 2632440, hash abf7c01857d229d6ce373028784332cea15b8193dc2d3629fe2f48d45a928e8e. Verify bounded recovery memory, continuity and actual production, then controlled restart.

#### Recovery progress - 2026-10-06T10:45:31.250626+00:00
- Repaired binary installed and authority started at 2026-10-06T10:41:59Z, PID 2333034, NRestarts=0. Startup finality preflight traversed complete 14,512,838,669-byte log with approximately 60 MiB RSS; bounded driver scan then held approximately 70 MiB RSS. Original finalized head remains 2632440 pending completed body/state recovery.
- Repair Git commits published to GitHub existing release/chain1266-single-authority branch at exact tip 5388907e521bb806235cc5a9bb6d1c03ed586529. Used existing local GitHub account and in-memory Git pack; no credential files, clones, worktrees or source copies created. SSD main HEAD/working tree/index preserved.

#### Live recovery evidence - 2026-10-06T10:50:49.159659+00:00
- PID 2333034 completed both full finality-log scans without restart. Body scan progressed past 25,353,478,144 bytes (approximately half of 50,985,951,398 bytes) with VmRSS/VmHWM approximately 115 MiB. Durable head remains 2632440 until completed recovery. NRestarts=0. Existing driver production path caps its body tail and RPC cache; no full-history retention in ordinary block production.

### Recovery verified / incident C1266-2026-10-06-001 restored - 2026-10-06T10:59:49.353655+00:00
- Cause confirmed: require_durable_binding_agreement used full-history recover(), allocating the entire 14.5 GB finality log and decoded records before bounded driver startup. Automatic libc-update service restart exposed the historical-memory growth; subsequent startup attempts OOM-killed at approximately 22.8 GiB, repeating over 19,000 times. Repair replaces preflight with read-only streaming inspection of every record, retaining zero history while preserving binding/linkage/checksum/head validation.
- Repaired Linux binary SHA256 dc40b4044a63599f8d3b6fbee782e3f1e34b77b9d2db5f25e1c0d0d7f1b61143 installed on Val1. Original binary retained at /usr/local/bin/synergy-validator-node.pre-streaming-preflight-20261006. Canonical SSD and GitHub release/chain1266-single-authority source tip 5388907e521bb806235cc5a9bb6d1c03ed586529. All 93 single-authority release regression tests passed.
- Authority started 2026-10-06T10:41:59Z; first resumed finalized block 2632441 timestamp 2026-10-06T10:55:35Z (13m36s full-history startup). First successor hash ce2dee7841906936b1d01a86604faa37384fad60fa023e3942eb83754aa8dd2e, parent abf7c01857d229d6ce373028784332cea15b8193dc2d3629fe2f48d45a928e8e exactly matching old stopped tip. Genesis remains 2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74. No reset, truncation, genesis replacement or authority-key change.
- Verified continuing finalized production through at least height 2632638, hash d34b4c379909725feab7b2b296f338b3534767d631ff8e88f17ae9d0590c619e, PID 2333034, NRestarts=0. Full finality scans approximately 60-70 MiB RSS; body recovery approximately 115 MiB; steady production approximately 244 MiB RSS, observed VmHWM approximately 325 MiB. No new OOM or service restart since deployment.
- Atlas API/indexer resumed ingestion. Database successor 2632441 matches validator hash and parent. Readiness HTTP 200 locally and publicly, database/RPC checks true, one-block lag, index age approximately 1 second. Public HTTP RPC returns advancing height and exact successor block using decimal-string block parameter; public WebSocket handshake 101 and live block-number reply verified. Public endpoint is an existing read-only facade; transaction submission was not tested. Gateway local authority-forwarded RPC verifies incarnation 5 and correct genesis.
- Authority, Atlas API/indexer, and gateway tunnel are enabled at boot. Authority restart cap three starts per 30 minutes, with 30-second failure retries. Existing security updates remain enabled. Gateway older incarnation-4 native runtimes remain stopped; current-chain reads use restricted SSH forwarding with pinned host key.
- Validation decision: completed deployment startup exercised the entire existing finality/body/receipt corpus and then produced approximately 200 continuing blocks, beyond the previous OOM window. An additional manual stop/restart after production was not performed because measured full-history replay would add another approximately 14 minutes of chain downtime. Production is left running. Startup remains linear in retained history; this repair bounds memory and does not introduce a checkpoint shortcut or discard validation.


## C1266-2026-10-08-001 — PoSy validator fleet restoration and authority transition

**Status:** Open
**Severity:** P0 launch liveness
**Detected:** 2026-10-08T05:39:44.003779+00:00
**First bad height:** No non-Genesis finality yet established for val2–val6.
**Last agreed finalized height:** Not yet established; val4 finality directory has metadata only.
**Last agreed finalized block ID:** Not established for PoSy. Existing single-authority chain remains separate and live.

### Affected and responsible nodes

Validators 02–06; shared transport publisher/configuration binding. Val1's
single-authority service is active, zero restarts since October 6, RPC height
2768141 observed. User requests reliable PoSy on val2–val6 before replacing
the single-authority role on val1. No reset or identity rotation is authorized
as a debugging shortcut.

### Symptoms and evidence

All five PoSy units failed September 10 at readiness (3 remote validators
required; 0 observed). All five installed Genesis files have SHA-256
`a0e64b155dc8e0c48534b20e4f3d9ca3450e569b0a796b79afa982e1ed95ba6b`;
PoSy semantic Genesis is `cf33d53f5c98c079480f4b45d2ac6b85728aa5d216e553e01289839e9c7b50a9`.
VPN addresses remain 10.69.10.2–6; val4 can ping every other validator.
The live signed transport snapshot resolves a different ceremony's identities,
so it has no routes for the installed Genesis members. Hub's preserved
`pre-20260905-launch/validator-vpn-provider-r2.json` has the exact installed
identities and transport addresses, SHA-256
`00d779cb66709e6574c17bed17f2f6b32f9fe0b3ef278981e82da75d4b1418fc`.
Current incompatible provider plan hash is
`67b67bbec6d1db7720a1353f238c40b7cfd9bed19ee4fdc610ced82711b72b56`.

### Confirmed cause

First broken boundary: configured peer identity to authenticated transport
resolution. Publisher plan and deployed Genesis bind different ceremonies.
This does not yet establish that transport repair alone restores finality.

### Recovery actions and outcomes

1. Read instructions, canonical memory and full incident log; inspected all six
   services, Genesis bindings, provider publisher and live snapshot, and VPN reachability.
   Outcome: mismatch verified without node mutation.
2. User corrected the canonical workspace location to this Mac's external SSD.
   Updated applicable workspace/Core Protocol/Testnet instructions and local entry points.
   No source clones, checkout resets or validator state changes.
3. Planned recovery: preserve current public publisher artifacts/configuration;
   restore the existing Genesis-compatible provider plan; sign a monotonically
   newer snapshot with the existing transport-attestation key; verify signature,
   exact routes and plan bindings; align five stopped validators' plan pins;
   then launch and trace the next broken boundary with safety history preserved.

### Final outcome, residual risks and next observation

Open. No PoSy chain-running claim. Public Val1 Genesis is different
(`2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`);
public cutover and val1 membership activation need verified transition handling.
Do not replace public routing or delete single-authority history during five-node qualification.

### Source evidence

SSH journals/config hashes on synergy-val2..6; hub public publisher and provider
plan; val4 installed Genesis and finality directory; val1 local RPC/service.

### Transport repair applied — 2026-10-08

Restored the preserved Genesis-compatible public provider plan on synergy-vpn.
Retained the existing attestation key; verified its public key and signature.
Publisher now increments snapshot generation instead of hardcoding 1. Published
generation 2, snapshot SHA-256
`f915a3b866404e4b1f14afbc1857be86d6ecc1400f9839662cd281aed9a8c6f4`.
All five validator loopback proxies independently returned these exact bytes.
Updated only the provider-plan hash pin in each transport-snapshot.env to
`00d779cb66709e6574c17bed17f2f6b32f9fe0b3ef278981e82da75d4b1418fc`.
Prior public provider/snapshot/publisher and each previous environment file retained
at `/var/backups/synergy/posy-transport-20261008` on the corresponding host.
No identity, Genesis, quorum, release binary, or safety state changed. Coordinated
existing-release startup is next; finality remains unverified.

### Transport registry refresh planned — 2026-10-08

Observation after the generation-2 transport publication: the loopback proxy on val2–val6 serves the repaired signed snapshot and the pinned provider-plan hash is correct, but each validator's persisted `data/validator_transport_registry.json` remains generation 1 with the retired provider-plan hash. The validator binary therefore rejects the configured fresh provider plan and fails closed after waiting for three remote PoSy validators. The next bounded repair is an atomic replacement of only that derived transport-registry file from the locally verified generation-2 snapshot, with per-node backups; safety stores, identities, genesis, quorum, release artifacts, and validator keys remain untouched. Validation gates are exact snapshot/hash comparison, service readiness, mutual P2P handshakes, and sustained advancing finality.

### Public-only validator identity/custody mismatch confirmed — 2026-10-08

Read-only verification of the deployed PoSy validator configuration and the preserved
public identity/custody records found that the running val2–val6 release is not
backed by the preserved validator ceremony identities. The deployed Genesis freezes
operator identities beginning `synv11s5vvm...`, `synv11pveg...`,
`synv11gswn...`, `synv11u0tf...`, and `synv11gkx...`; the preserved workbook and
public ceremony records identify val2–val6 with a different public identity set.
The deployed validator TOML files are explicitly public-only and set
`producer_ids = []`, while each node has only a local ML-DSA-65 private file that
is not provenance-bound to the frozen Genesis identity in the release metadata.

The five nodes remain online at Genesis height 0 with authenticated four-peer
meshes and five ready validators, but simplified target-admission/ETDAG producers
are not installed and `consensus_ready` remains 0. No key was generated, rotated,
replaced, decrypted, or copied; no Genesis, quorum, safety state, or Val1 service
was changed. The next action requires locating the exact custody bundle that
produced the deployed Genesis or authorizing a fresh, governance-bound Genesis
rebuild; the preserved workbook alone does not establish that mapping.

### Authorized validator identity rebuild initiated — 2026-10-08

The operator explicitly authorized rebuilding val2–val6 validator identities and
updating the existing desktop credentials workbook in place. This is a governed
identity/Genesis replacement, not a liveness shortcut: the current five-node
release will remain isolated at height 0 until the replacement public identities,
consensus keys, Genesis, deployment artifacts, and workbook records are
consistent. No copy of `/Users/jhutzler/Desktop/node-machine-credentials.xlsx`
will be created.

The rebuild must preserve five-validator 4/5 quorum, PQC verification, one PoSy
control plane, and three-QC finality. Existing Val1 single-authority state and
all old validator safety state remain preserved until the replacement fleet has
passed independent Genesis and finality checks.

### Rebuild tooling compile blocker — 2026-10-08

The canonical local `synergy-keytool` build stopped on a malformed uncommitted
`node-platform/crates/synergy-address/src/snts_registry.rs`: an extra duplicated
tail caused an unexpected closing delimiter, and a required canonical constant was
missing. The file is outside the validator runtime change and is being restored to
its repository version so the existing key tooling can compile. No validator host,
Genesis, safety state, or workbook data changed in this repair step.

### Diagnostic correction and continuation — 2026-10-08

The earlier identity/custody entry overstated the cause: `producer_ids = []` is
required by the simplified PoSy profile and is not evidence of missing signing
material. A different preserved public ceremony is confirmed, but an absent
public-key byte sequence inside a private-key encoding does not prove a key
mismatch. No cryptographic correspondence test has yet established mismatch.
Current val4 journal reaches authenticated peer readiness and starts the PoSy
worker without a reported key error; the driver then remains uninstalled.
Read-only thread backtrace inspection is the next diagnostic action. Val1 remains
active, NRestarts=0, and RPC height 2772298; no public cutover is authorized by
these observations. The operator has already authorized the identity rebuild.
The original Desktop workbook remains the only permitted workbook target.


## C1266-2026-10-08-002 — Fresh PoSy replacement qualification

**Status:** Open; source repaired, deployment not qualified.  
**Severity:** P0 replacement-chain launch blocker; existing Val1 service retained.  
**Detected:** 2026-10-08; live confirmation through 12:31 UTC.  
**First bad height:** H1 in the deployed replacement cluster.  
**Last observed finalized block:** H0, `cf33d53f5c98c079480f4b45d2ac6b85728aa5d216e553e01289839e9c7b50a9` on Val4. Fresh five-node agreement is not claimed.

### Authority and diagnostic amendments

The operator explicitly confirmed that the replacement is a completely fresh
chain. Val2–Val6 must qualify first; Val1 conversion follows that qualification.
The earlier claim that the simplified driver remains uninstalled is retracted:
read-only GDB backtraces show the driver alive in its receive loop. Two broadcast
workers wait on writes; incoming message handling repeatedly validates finality
state. Val4 safety state contains 251 timeout certificates, no QCs, no last vote,
and finalized H0. Network logs contain framed-write deadline failures. These
observations do not establish a key mismatch or one faulty validator.

The earlier claim that the removed address-registry constant was required is
also retracted. The unused constant removal is preserved; duplicated trailing
source was the compile failure. No safety-state reset was performed.

### Actions and exact results

1. Repaired corrupted duplicated/garbled source regions in canonical
   node-platform (identity, authority, RPC, network session, PoSy service,
   execution state diff, storage WAL/disk guard, ETDAG admission/ordering,
   roles, snapshot, address registry, keytool, and vendored ML-DSA test tail).
   Valid surrounding edits were retained. Scoped cargo check passed; the
   initial node/PoSy/storage/state test run passed 24 tests. No runtime deployed.
2. Fixed node keytool address derivation: require an FN-DSA-1024 identity-root
   public key and derive canonical SNTS addresses independently of the ML-DSA-65
   operational P2P pair. Two real key-generation/signature tests passed.
3. Built node/keytool release binaries on the backing host against the same
   physical SSD checkout. The local mount is SMB; SHA256 comparison confirmed
   shared source bytes. No copied source checkout was created. These are macOS
   build artifacts, not Linux deployment artifacts.
4. Edited exactly 42 relocated path cells in the original Desktop credentials
   workbook. Verified unrelated OOXML parts byte-for-byte and retained inode.
   No workbook copy was created. No passphrase changed.
5. Added read-only Address Engine custody verification using existing crypto
   primitives, bounded files/stdin, memory-only decryption and zeroization.
   All six bundles successfully decrypted using their workbook passphrases;
   all 30 key pairs and all six canonical addresses verified cryptographically.
   Updated six status cells in that same workbook with candidate-only status.
   No validator identity regeneration is necessary to recover these bundles;
   they remain distinct from the currently deployed Genesis roster.
6. Corrected canonical ETDAG target validation to permit Genesis H0 -> H3/H4/H5
   while preserving strict F+5 thereafter and overflow rejection.
7. Removed the execution fallback that allowed uncertified empty candidates
   beyond H2 as finality advanced. H3 onward now waits for verified protected
   material. Tests across node/ETDAG/PoSy/keytool passed 30/30.

### Outcome and remaining boundary

The canonical runtime still needs qualified protected-material production and
signed fresh-network artifact integration. ETDAG service currently receives
certificates/handoffs but has no complete production path for creating them;
its prepared-batch and ordering types reject empty batches. Do not disguise
this gap by restoring the unsafe execution fallback or fabricating evidence.
The network JSON launch files are empty placeholders and are not deployment
inputs. No new Genesis, release, key deployment, or Val1 cutover occurred.

Val1 remains active/running with NRestarts=0; RPC height advanced from 2772298 to
2788320, Genesis `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`.
Next required proof: real protected material -> proposal -> votes -> QC ->
three-QC finality across five processes, then Linux build/deployment, sustained
matching finalized tips, restart/rejoin, and public-tier agreement.

### Contract review amendment and focused validation — 2026-10-08

The protected-material gap must not be filled by adding a batch-vote producer.
`protocol/posy-v3/PROTECTED_PIPELINE_PROTOCOL.md` and
`CURRENT_PROTECTED_FLOW.md` explicitly remove active DCC/BVC/BOC/BTC dependence
in favor of authenticated cutoff evidence, deterministic cut/order, and the
exact parent-PoSy reveal authorization. Their older H+3 language is superseded
by the current governing H+5 startup rules. Canonical ETDAG still depends on
`BatchValidationCertificate` in `CertifiedExecutionHandoff`; PoSy proposal and
execution-candidate types do not yet carry the complete H/H+1/H+2 commitment
contract. This requires completing the canonical caller migration, not signing
new launch artifacts around the incomplete path. No incompatible implementation
was deployed and no fabricated certificates or empty-batch bypass was added.

Focused validation: node/ETDAG/keytool Clippy passed with warnings denied.
Address Engine custody verifier passed cargo check, release build, Clippy with
warnings denied, and 34 library tests. Six real custody bundles also passed
memory-only cryptographic correspondence checks. The operator requested efficient
execution to conserve usage; avoid repeating these checks absent relevant changes.

### Service liveness and recovery qualification amendment — 2026-10-08

Status remains OPEN/P0 for replacement launch. No fresh fleet finalized block
is claimed; H1 remains the first unresolved deployed production boundary and
the prior H0 observation remains the last recorded replacement finalized tip.
Responsible component is the shared runtime, not an individual validator.

Actions and evidence, in order:

1. Added bounded exact-byte retries for PoSy proposals, votes, QCs and timeout
   certificates. Remote malformed, unauthenticated, stale and premature events
   are rejected without failing the service. Verified certified conflicts and
   local durability/signing failures still fail closed. Initial real-signature
   loss/reordering, timeout and restart service tests passed.
2. Read-only Val4 refresh: role service active, PID 3590310, NRestarts=0. Its
   2026-10-08 14:02:08 UTC metrics still reported zero completed protected
   inputs, zero BVC traffic and 48,658 received BOCs. This does not prove chain
   health or identify an operator/key failure; no live mutation was attempted.
3. Added a queue-pressure regression leaving only one free outbound slot per
   tick. It failed: only the first peer received the first retained message.
   Fixed retry scheduling to resume after the last accepted delivery. The same
   test then passed, delivering every retained signed message to every peer
   without resigning or exceeding the queue bound.
4. Four real ML-DSA signers certified 22 heights with the initial proposer
   offline and first vote deliveries dropped, reaching identical finalized H20.
   Source inspection found Sync incorrectly demanding timeout certificates at
   every height instead of carrying them across the governed leader lease.
   Changed witness assembly to follow exact signed takeover IDs to their
   original slots; verification checks contiguous rounds, previous IDs and
   same-lease monotonic heights. No fictitious timeout certificates are added.
   The offline service then replayed verified Sync to the same finalized H20
   and preserved that state across durable restart. Removing the required
   timeout proof is rejected.
5. A broader parallel test run failed because wall-clock timestamps collided
   in test directory names. Added a process-local atomic sequence; rerun passed
   all 35 tests (node 12, PoSy 11, ETDAG 12). Node/PoSy all-target Clippy passed
   with warnings denied. These are real-cryptography service tests using
   deterministic execution fixtures, not ETDAG or socket-fleet qualification.

Remaining launch boundary is unchanged: governed protected cutoff/commitment/
reveal production, signed fresh-network artifacts, Linux release and deployment,
sustained matching fleet finality, public-tier agreement and Val1 conversion.
The protected-material implementation was not completed in this amendment.
No service, validator key, chain database, or credentials workbook was mutated
in this checkpoint. Prior in-place workbook changes remain the canonical record.

Release validation: `CARGO_INCREMENTAL=0 cargo build --locked --release -p synergy-node` completed successfully in 38 seconds on the backing macOS host against the canonical SSD checkout. Focused `git diff --check` passed. This is not a Linux release or a deployment.

## C1266-2026-10-08-002 — source-only protected pipeline checkpoint

Status: OPEN/P0. Responsible component: shared replacement runtime.
Last recorded replacement finalized height remains H0; no new live observation.


### 2026-10-08 protected-pipeline verification checkpoint (C1266-2026-10-08-002)

IMPLEMENTED / VALIDATED_LOCAL: authenticated count-and-weight cutoff verification,
complete certified ancestor closure, deterministic protected batch commitments,
parent-PoSy-proof reveal authorization, and bounded atomic per-target recovery.
Recovery now requires the caller's expected cutoff commitment rather than trusting
the stored record to choose its own authority. Execution additionally waits for the
matching parent QC in the local verified PoSy store; an unrelated parent is rejected.

Validation: node 16/16 and ETDAG 12/12 tests passed. The four real-ML-DSA protected
qualification tests passed again after the recovery and local-parent corrections.
Node/ETDAG all-target Clippy with `-D warnings` passed (the filesystem emitted
incremental-cache hard-link fallback warnings). These are local service/crypto
checks, not live network qualification.

CALLERS_MIGRATED: PARTIAL. The ETDAG runtime still uses its old ordering/batch
certificate handoff. The new durable pipeline is not yet registered as the runtime
owner. Missing production boundaries include governed target-context creation,
durable cutoff signing and gossip, H/H+1/H+2 candidate commitments, parent-proof
handoff, and nonempty reveal preparation. Different cutoff-frontier subsets also
require qualification against the protocol's single semantic-cut requirement.
Do not infer that identical empty-frontier test results prove that property for
heterogeneous frontiers. Fresh signed network artifacts, Linux release, deployment,
sustained matching finalized tips, restart/rejoin, public tiers and Val1 conversion
remain unverified. No live service, key, chain database or workbook changed here.

Release check: `CARGO_INCREMENTAL=0 cargo build --locked --release -p synergy-node` passed on the backing macOS host in 41.05 seconds. Changed Rust-file whitespace checks passed. The broader log diff reports four existing Markdown hard-break whitespace lines at 4247-4250; append-only incident history was preserved. This build is not a Linux release or deployment.

### 2026-10-08 19:00 UTC — parallel launch implementation and qualification (C1266-2026-10-08-002)

Status remains OPEN/P0. First unresolved replacement height remains H1; last
recorded replacement finality is H0, with no newly verified finalized block ID.
Responsible component is the shared replacement runtime, not a validator host.
The operator explicitly authorized consensus subagents.

Recovery actions and exact outcomes:

1. Implemented ECHO/READY delivery and immutable proposal-validation evidence,
   historical READY proof recovery, exact signature replay, height-wide vote
   guards and verified-finalized-floor journal compaction. Added regressions for
   Byzantine split evidence, stale-slot isolation and missing historical proof.
2. Integrated signed complete protected epoch policy, initial state and KEM
   registry; verified durable finality history; durable collecting/cutoff/VAC
   ownership and authenticated marker retries. Nonempty threshold reveal still
   lacks a production crypto provider and complete authenticated wire schema.
3. Found a protocol circularity: existing proposal H requires completed cutoff
   H+2, but authoritative POSY-00D 0D.11 closes H+2 only on VC(H). Documented a
   concrete pending clarification in PROTECTED_PIPELINE_PROTOCOL.md and asked
   operator approval required by AGENTS Section19.3. No amendment is active;
   H/H+1/H+2 proposal-material integration and signing/deployment remain gated.
4. First combined test attempts failed at two keytool ambiguous Into literals
   and one old VC fixture field. Corrected those specific compilation errors.
   Next node run passed19/20; sole failure was obsolete retry-tail bound9 after
   adding bounded historical proof delivery. Corrected bound19 and eliminated
   repeated cryptographic verification of already verified exact proof bytes.
5. Shared authority signing test initially failed because its fixture had only
   one validator; the real minimum-five check correctly rejected it. Corrected
   the fixture without weakening validation. Latest combined suite PASSED:
   node22, ETDAG12, PoSy14, keytool5 (53 total), Genesis/updater compiled with
   zero tests. Node service suite took87.55seconds and still uses deterministic
   execution fixtures, not complete protected sockets or live validators.
6. Release Clippy found test-module ordering in keytool release.rs. Moved tests
   after production functions without suppressing the warning. Rerun pending.
   First Linux preflight failed because cargo zigbuild --version is unsupported;
   corrected to cargo-zigbuild --version. Linux build rerun is pending.
7. Read-only host preflight at18:59–19:00UTC verified strict BatchMode SSH,
   passwordless sudo availability, synchronized clocks, sufficient memory/disk,
   VPN addresses10.69.10.2–.6 and listening5622 on allfive. Existing role services
   remain active with NRestarts0: Val2 PID90992, Val3 PID3646962,
   Val4 PID3590310, Val5 PID4132383, Val6 PID3619060. Established TCP sockets
   exist across the mesh, with queued data; this does not prove authenticated
   message processing, QC advancement or finality. No live mutation occurred.
8. SMB source operations intermittently blocked for tens ofseconds. Pending
   in-place writes eventually completed; root verified authority file intact
   on the backing host. No source mirror, worktree, alternate ledger or workbook
   copy was created. Five canonical migration ledgers were updated in place.

Next required observations: approved cutoff authority, complete proposal/material
wiring, authenticated socket-runtime finality/restart qualification, verified
Linux artifacts and live deployment, advancing matching finalized tips and public
tiers, then Val1 membership conversion. No validator service, identity, chain
state or credentials workbook changed during this checkpoint.

### Additional restart/transport qualification — 2026-10-08 (C1266-2026-10-08-002)

Status remains OPEN/P0; no fresh finalized block is claimed. Subsequent attempts:

1. Real closed-target restart regression exposed service ordering: ETDAG starts
   before PoSy and required VCs restored only in PoSy.start. Moved independently
   verified last-eight-height VC restoration to registration before any service
   starts. Genuine closed-target regression passed.
2. Reserved the existing global64 outbound frames: PoSy16, ETDAG16, Sync8,
   six other protocols4each. A full peer channel now retains exact queued frames
   and services other peers instead of dropping work and removing the sender.
   Authenticated inbound capacity bursts no longer fail the networking service;
   router bounds/telemetry and protocol verification remain unchanged. Queue
   isolation/exact-retention/burst regressions passed.
3. Sync previously failed after every eligible source had been attempted once,
   including locally congested sends. Added a bounded exact outgoing queue,
   excluded local queue wait from request timers and revisited only independently
   verified sources after timeout. Both congestion/revisit regressions passed.
   Execution restores a consumed authenticated Sync request when its response
   cannot enter the queue, then yields rather than failing or forgetting it.
4. Node suite24/24 passed before the final Sync/inbound additions; focused Sync2
   and ingress2 tests then passed. Together with the earlier combined53 suite,
   five additional distinct regressions passed (58 distinct tests total).
   Existing bounded-router4/4 tests also passed. Strict package Clippy passed;
   node all-target Clippy with clippy::all denied passed, retaining only the
   two intentionally unwired protected-material Rust dead-code warnings.
5. Latest Linux x86-64 ELF release built successfully in41.74seconds:
   SHA256 f83774e08d38634919d13d80ae392c79de68156a2c3ade792f6c938b8be4c9e6.
   This candidate includes the restart and transport fixes, but no approved
   cutoff clarification or complete protected proposal-material integration.
   Native Linux execution is not verified. A control-socket check for an in-memory
   smoke transfer found no multiplex socket; no second SSH connection or transfer
   was opened. Trusted-host keytool executable was separately built successfully.
6. Focused changed-source git diff --check passed. Five canonical ledgers were
   reconciled in place. Signed artifacts were not generated, validators were not
   restarted or changed, and the Desktop credentials workbook was untouched.

The cutoff clarification still requires explicit operator approval. Nonempty
reveal also needs the governed provider/schema migration; current source must
not advertise that path as production ready. Complete socket runtime, signed
fresh launch artifacts, deployment, sustained matching finality, public tiers
and Val1 conversion remain open.

### Protected crypto/custody checkpoint — 2026-10-09 UTC (C1266-2026-10-08-002)

Status OPEN/P0. Three parallel agents implemented canonical protected crypto/schema, keytool/config support and durable nonempty recovery hooks. Governed ML-KEM-1024 uses AES-256-GCM and legacy GF256 semantics; count quorum remains4/5 and reveal threshold derives n-Q+1 (2/5), with exact role/commitment/context checks. Fixed AES tag padding and static registry/target context confusion; added key schedule coverage validation to reject delayed H3 activation and rotation gaps.

Validation: ETDAG18/client1/config4 tests passed; keytool7/Genesis1 passed in separate scoped run. Earlier node27 suite had25 passes and two structurally stale one-byte KEM ciphertext fixtures failing new1568-byte validation; fixtures were corrected. The subsequent focused node attempt intersected an explicitly in-progress runtime integration (missing accept_reveal_share/reconcile_reveals), so node qualification is pending a coherent checkpoint, not claimed passed. A first combined package build also encountered a module declaration before its provider file landed; after source coherency the package tests passed. New AES dependencies were resolved into the existing Cargo.lock.

The former custody keys are768 and are not launch-compatible with1024. No real keys were generated, no credential/workbook copy was created, and no validator mutation/deployment occurred. Existing Linux hash is historical to the preceding transport checkpoint. Cutoff amendment approval, complete runtime/socket qualification, signed launch artifacts, live matching finality/public tiers and Val1 conversion remain open.

### Approved cutoff clarification — 2026-10-08 America/Chicago (C1266-2026-10-08-002)

Operator explicitly approved the linked concrete clarification: proposal H names the H+2 boundary and VC(H) closes it. Fresh signed policy now requires versioned cutoff_relationship=vc_event_context_v1; runtime assembly/independent verification is assigned in parallel. No quorum, signatures, leases or three-QC finality change. This supersedes the prior pending-approval status only. Deployment/fresh finality remain unverified.

### Public custody role correction and V2 checkpoint — 2026-10-08 America/Chicago (C1266-2026-10-08-002)

Public-only inspection of the five canonical identity.pub.json records at workbook-referenced paths proves existing ML-KEM-768 is entropy_contribution_key, NOT protected ingress. Those bundles have no ingress KEM role. Their existing consensus ML-DSA-65 and FN-DSA-1024 identity remain valid; node_identity_key is Ed25519, while the new runtime transport requires a separate operational ML-DSA-65 role. Do not replace entropy768 as an ingress fix. Provision only the missing roles bound to existing identity, and update the original workbook when actual custody changes occur. Earlier wording conflating768 with ingress is superseded. No encrypted custody or secret content was read in this inspection.

Full node28/28 tests passed after materialV2 fixture migration, including nonemptyreveal restart/tamper and prior transport/PoSy tests. Keytool9/9 passed including publicfreshauthority preparation/nooverwrite. StrictClippy passed crypto/client/Genesis/keytool/config; nodealltargetClippy with clippy::all denied passed before newestV2material assembly. The approved H/H+1/H+2 production assembly is implemented; causalH1-H6test and authenticatedsocketqualification are in progress. Independent source review fixed actual envelope-vs-vertex lookup in both nonemptyruntime reveal paths; a real distinct-ID regression now covers selection. No deployment or fresh finality claim.

### Approved material causal validation — 2026-10-08 America/Chicago (C1266-2026-10-08-002)

Production H1-through-H6 assembly regression passed with genuine ML-DSA VC/cutoff evidence. Protected cache regression passed through 200 heights; genuine nonempty threshold reveal/restart/disk-tamper regression passed with distinct envelope and vertex IDs. The first socket harness compile failed ambiguous KeyId conversion and the first fixture execution failed wrong identity-address key algorithm; fixture corrections were applied before retry. Full authenticated socket qualification is currently running; no result or live deployment is claimed. Independent inspection identified a potential ordinary transaction contract mismatch between FN-DSA address derivation and ML-DSA-87 transaction verification, now under source review. Original Desktop credentials workbook and live validators remain untouched in this checkpoint.

### Authenticated socket finality and rejoin boundary — 2026-10-09 America/Chicago (C1266-2026-10-08-002)

Accepted macOS TCP sockets inherited nonblocking listener mode, causing immediate handshake WouldBlock and zero peers. configure_tcp_stream now explicitly sets blocking mode with deadlines; delayed-byte regression passed. Real five-service authenticated socket fleet independently matched finalized H6 and H70 across five validators, then H74 across four after one validator stopped (governed quorum unchanged). Restarting that validator recovered H70 but PoSy polling fatally rejected a newer QC before verified catch-up: quorum certificate is not for the next certified height. Full qualification FAILED at that rejoin boundary; minimal bounded recovery fix and shorter socket regression assigned, no deployment claim. The first 180-second H70 fixture budget also timed out during healthy progression at H28; fixture now uses height-range overall limit plus a separate60-second no-finality-progress watchdog.

Real identity dual-possession and transaction scoped binding tests passed (identity5, transaction4, Genesis2). Canonical public identity loader4 tests passed; no root public key copies or actual custody generation occurred. Signed deterministic epoch timestamp fields migrate existing frozen protected-material semantics; production execution/replay/sync now uses externally governed time and finalized authorization state, with full node integration still awaiting central validation. All five hosts revalidated trustedSSH, sudo-n availability, NTP sync, overlay10.69.10.2..6 and listening5622; existing immutable role services remain active. Original workbook and live node state remain untouched.

### Nonempty execution and bounded recovery checkpoint — 2026-10-09 (C1266-2026-10-08-002)

Genuine authenticated five-node nonempty socket qualification PASSED through H8 (107.34 seconds): committed dual FN-DSA identity/ML-DSA-87 account authorization, funded signed transfer, ML-KEM-1024 encrypted envelope, independently verified durable VACs on all five, genuine authenticated threshold reveal, exact duplicate receipt, closed-target rejection and continued matching finality. First attempts exposed test-only signer/provider and absent-pending-file assumptions; those were corrected. Actual runtime H3 stalled because exact reveal transcript proof variants entered execution authority. Execution now binds the stable independently verified parent reveal authorization while retaining every exact transcript and all threshold/crypto/recovery verification. All five produced identical H3 state/material roots despite different valid transcript roots. The production causal/semantic/tamper regression passed.

Updated non-socket node suite PASSED33/33, including authenticated reordered future-QC/canonical-witness recovery. Canonical fresh Genesis producer PASSED6/6; independently signed identical-snapshot/content-conflict regression PASSED. Focused rejoin first stayed alive but stuck at H6, then exposed finality-before-local-candidate and legitimate snapshot signer-proof collisions. Sync now requests from durable Execution commits, keeps canonical prefix replay alongside snapshot download, and installs only the exact local verified prefix; Execution retains queued finality until its matching candidate is durably committed. Snapshot content equality excludes independently verified signer-proof variants but preserves exact finalized block/context/state/chunk bindings and the initial proof. Latest real focused test has caught the returning validator up to matching H11; complete durable Execution H16 acceptance remains pending.

Linux release build and current strict Clippy are in progress. The typed local signed-vertex admission boundary remains internally qualified; an external transaction submission owner is not yet wired. No real custody generation, artifact signing, live deployment, node restart or original Desktop workbook mutation occurred. Live stability, public-tier migration and Val1 replacement remain open.

### Fresh custody provisioning preflight — 2026-10-09T11:03:03.399256+00:00 (C1266-2026-10-08-002)

Focused authenticated restart/rejoin PASSED through matching PoSy and durable Execution H16 (147.01s). Existing-key import possession/no-overwrite tests PASSED2/2. Current Linux keytool SHA256 fb3e1e1942e726eeea8e0db7050708f271a8cdfbe0cfd05a213b64f4b16857dc. Long five-node qualification continues advancing; below-quorum halt/recovery test is running separately.

Pre-action plan: provision only missing operational P2P ML-DSA-65 and ingress ML-KEM-1024 directly in final root-owned /etc/synergy/posy-stability/custody on val2–val6; import existing verified consensus custody through bounded non-PTY stdin. Export public bundles only to canonical identity operational directories. Use one authenticated pinned ControlMaster per host with fallback disabled. All five final deployment namespaces were absent at preflight; sudo and wt0 verified. Existing services and chain history remain retained until fresh signed deployment. Original Desktop workbook remains sole allowed workbook. No live-chain claim.

### Signed fresh deployment preparation — 2026-10-09T14:18:11.472811+00:00

Full authenticated socket qualification PASSED617.76s: matching durable H70/four-nodeH74/rejoinH80. Separate below-quorum halt/recovery PASSED175.06s, restores to matching durableH12. Missing transport65/ingress1024 generated directly final custody on all5; existing consensus imported with genuine possession verified. Initial completion-ordering receiver defect corrected before continuing; no private bytes logged or copied to repository. Public operational exports complete. Runtime requires owner-only0600 private files; corrected provisioning/service custody permissions accordingly.

Actual signed Genesis/complete authority and signed Linux release prepared using val2 existing consensus65 with distinct governed signature contexts; native Linux signature/digest verification passed. Dedicated fresh transport locator snapshot signed by newly generated protected Ed25519 attestation custody, unchanged locator signature contract, separate from PQC consensus; pins are in fresh configs. Canonical public artifacts: node-platform/networks/testnet/posy-stability. Manifest hash explicitly commits exact signed Genesis file SHA256; it is not claimed independently signed.

Next controlled action: after all5 installed signature/hash/unit checks, stop only old validator02..06 role units, daemon-reload and start/enable dedicated synergy-posy-stability.service concurrently, preserving old services/data and Val1 authority. Read actual logs/admin/RPC/durable finality; no running-chain claim until matching advancement.

### Native fleet started / live Sync repair — 2026-10-09T14:26:30.630221+00:00

All5 native signed sequence1 releases verified and dedicated services enabled/started; old validator role units stopped without state deletion. All services initially healthy/ready; actual RPC independently matched H5 block/state/protected roots on4. Val3 failed on ordinary delayed or superseded finalized-candidate responses; Val5/Val6 also restarted. Four remained advancing through independently matching durable/RPC H107 (block7b0204058a338e9473a605a72109f15343e7a68896d9648a618f812461e7c855); Val3 stopped at durableH16 after restart cap. This is live production but not stable five-node acceptance.

Repair rejects unactionable delayed/wrong-source/old-request candidate and snapshot responses before ingress mutation, recording rejection without failing Sync; current-request signature/context/execution validation remains unchanged. Authenticated focused restart/rejoin PASSED162.71s, strict Clippy passed, Linux repair SHA2566b94606a3509e7482388ac90028e04a7116f2ccbe3ed16230dcc2e01b1448d1e. Signed sequence2 repair staged and verification underway. Next start repaired Val3 and prove catch-up before sequential fleet rollout. No history reset or quorum change.

Original Desktop workbook edited55targetedcells in place, original inode retained; all unrelated OOXML parts preserved. Custody passphrases reconciled from cryptographically successful original-envelope column without secret output; operational paths/ports/root0600 custody/releaseGenesis binding and pending live qualification recorded. No workbook copy/backup.

### Guarded rolling repair progress — 2026-10-09T14:34:33.954841+00:00

Sequence2 repair signatures/digests independently verified on all5 hosts. Val3 started repaired binary with retained durableH16/custody; advanced through independently matchingH130 with NRestarts0 while other nodes approachedH193. Val5 old binary then reached bounded restart cap and failed on the same superseded response boundary. Suspended original rolling waiter (no mutation had occurred), started already-verified repaired Val5 from its retained near-current durable state, NRestarts0. Remaining guarded rollout order6,2,4 requires all5 running and matching actual finalized RPC block/state/certificate before every subsequent restart; cannot reset or skip safety history. Public evidence remains append-only live-observations.jsonl.

### Certified recovery path defect — 2026-10-09

Four native validators independently match durable/RPC H340 and continue advancing; Val5 retained durableH194 but failed after the restart cap. Its stored timeout H196/r0 was accepted before the compatible older-round QC196/r0. Startup incorrectly replays every stored timeout before the QC, although that QC does not reference this timeout; Sync then rejects the different certified H197 timeout chain. Guarded rollout remains paused. Planned repair selects only the verified timeout closure required by each stored QC during certified-history replay, retaining outstanding timeout replay at the uncertified tip, all signing journals, all original records and exact quorum/signature/finality checks. No validator state reset or consensus policy change.

### Recovery amendment approval boundary — 2026-10-09

Live4 independently matched finalizedH405, with unchanged healthy service PIDs/restart counts; Val5 remains failed at retainedH194. R1 proposal appended to canonical POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md; inactive, pending operator approval. Existing Section10/12 TC persistence/conflict semantics and AOS19.6 prohibit activating the proposed supersession as an ordinary caller repair. Preliminary ordering experiment passed focused restart118.71s, Clippy and Linuxbuild but did not validate superseded local TC mandatory carry or complete finalized-history authority; root reverted only its experimental source diff. No new signed release, runtime deployment or state deletion. Guarded rolling owner was interrupted by validated PID38183 and cannot restart Val2/4 while approval is pending. Existing signed deployed sequence1/2 runtime and original workbook remain unchanged this continuation.

### R1 approved implementation checkpoint — 2026-10-09

Operator explicitly approved exact R1 recovery amendment. Complete instruction/memory/incident gate read this continuation. Four validators match actual durable/RPC H479; Val5 retains failedH194. Three subagents assigned isolated proof verifier, genuine-signature regression and independent review; root alone owns runtime/build/SSH/workbook. Implement only certified three-QC-backed timeout supersession with exact parent/mandatory carry, durable finality equality, no extra certified closure proofs and preserved uncertified-tip state. No deployed change or reset yet.

### R1 causal and Sync projection validation — 2026-10-09

R1 operator approval implemented with pure three-QC/carry/parent/quorum/closure verifier and staged startup/authenticated Sync reconstruction. Genuine ML-DSA-65 four-of-five regression reproduces local timeout-before-older-QC and alternate next-height timeout; canonical referenced-carry, early one-QC restart, missing/invalid/conflicting proof and immutable-prefix tests passed4.19s. Journal namespaces unchanged in tests. Strict node/PoSy all-target Clippy passed after factoring recovery-transition return type. PoSy14tests and genuine execution bootstrap2tests passed. Focused full-runtime restart/rejoin and Linux release build now in progress; no R1 deployment yet.

Livefour matchedH683. Val3 had one spontaneous restart caused by delayed/queued verified execution Sync candidate failing next-transition check; it rejoined with exactmatchingRPCfinality. Repair validates historical candidate against exact durable block/state commitments, retains future gaps, deduplicates matching pending transitions and reexecutes from finalized parent, with wrongroot/block/height/payload negatives. Val5 remainsfailedH194. SHA256-only pre-recovery inventory captured1524originalconsensusJSONrecords for later preservation comparison; no original data copied or reset.

### R1 signed release staging and controlled Val5 recovery — 2026-10-09

Focused genuine authenticated restart/rejoin PASSED119.55s with five matchingH16; strict Clippy and Linux release build PASSED51.94s. Genuine R1 startup/Sync alternate-timeout, canonical referenced carry, early restart and negatives PASSED4.19s. Sequence3 release id posy-stability-20261009-r1-recovery governance-signed by existing ML-DSA-65 authority, protocol_activation_commitment posy-r1:sha3-256:059a958368d57440379d2480e411f2693acf42e148d424821d665b8e43de20d8. Binary7179656bytes SHA256b9e373ef2681c92b575885e8cf3330c1573371eb2c9244b36c3cae987eeddcdc. Identical immutable synergy-node-r1-recovery and release-r1.json installed and native pinned release signature/artifact verification PASSED all5. No source copied.

Next controlled action: only failedVal5 dedicatedunit selects signedR1 binary; add pinnedreleaseverification ExecStartPre; daemonreload/resetfailed/start with ALL original state/custody/signing evidence retained. Require actual sustainedcatchup and preservation before another validator restart. Val1/publicrouting untouched.

### Val5 R1 first activation failure and certified-tip preservation — 2026-10-09

Sequence3 Val5 activation retainedoriginaldata but startup failedclosed at ProposalDelivery activation: delivery journal rollback. No QCdescendant above196 was stored, yet backwardthreeQC194..196 let projectionomit outstandingTC196 and dropactive197round1toround0. Stopped dedicatedservice after observed secondretry; nootherhostrestart. Fix requires storedQCdescendant beforestartup supersedeslocaltiptimeout; otherwise normalTCfirstrestore retained. Genuine certified-tipQC1..3+TC3carryQC3/noQC4 regression PASSED; combinedR1regression4.45s andstrictClippy passed. Linuxbuild47.62spassed. Governance-signedsequence4 posy-stability-20261009-r1-tip-recovery retains exactR1commitment; binarySHA2560d973f24e1984d0dac9dd1f14872f0e1a8158f222ac103a722da8365954fd323. Stagedidenticalrelease all5, nativepinnedsignature/artifactcheckspassed. NextretryVal5only withpreservedtipTC; noreset/journaledit.

### Val5 retained-state progression and Atlas staff dashboard — 2026-10-09

Signed sequence4 Val5 recovered from finalized194 through902 with zero automatic restarts; at common902 allfive independent RPC finalized block/state commitments exactly matched. Current records3108; all1524 pre-recovery consensusJSON records remain, only legitimately evolving delivery.json/sign-once.json digests changed. Original state/custody retained. Four peers independently advanced1494; five-node tip parity/reliability acceptance remains open.

Atlas production staff page deployed and target-browser verified at https://atlas.synergy-network.io/staff/posy. Only footer Staff Login link; existing secure password/cookie gate and authenticated-only origin telemetry route. Unauthorized telemetry401. Real15 animated charts:5chain series +2histories pervalidator, status timelines and actualtest evidence. Backend authenticated200 fresh5roster; publisher uses actual durable finalized pointer and existing ownerSSH masters. No fabricated verified quorum/soak pass. Local launchagent io.synergy.atlas-posy-telemetry owns observation publication; stale readings explicitly surfaced if publisher stops. Canonical public source assets preserved; compressed generateddeploymentmedia satisfy Pages25MiB limit. Worker redirect:error failed beforeoriginrequest; manual redirect with explicitnon2xxfailclosed fixedtarget200, no bearerforwarding toredirectdestination. Source/build/scopedlint and focusedauth/securitytests passed; fullfrontendlint remains blocked by preexisting AppleDouble files.

Catchup source review found canonical multi-TC ancestry incorrectly compared to active terminalTC, causing repeated full-prefix recovery. Minimal round-aware detection preserves realdivergence/oldslotrestoration, allsignature/quorum/staging/durablechecks. GenuineMLDSA65 R1regression passed4.57s including repeatednormalwitness no-restage and realwrongterminal/oldslotcases. StrictClippy passed. DirectLinuxCargo build failed missingcrossCcompiler; canonical build-linux.sh correctedtargettoolchain, passed69s. Sequence5 candidate binarySHA256c248f713ed35af6392766eb58e6b2687de66bb7b95fae4188147580898d9c925 prepared with unchanged approvedR1commitment. Plan: sign/stage/nativeverify all5, controlledVal5only restart preservingalljournals, require actualcatchup/preservation before anyotherrestart. Val1 and publicchain unchanged.

### Val5 sequence5 restart boundary — 2026-10-09

Sequence5 signedstaging/nativeartifactverification passedall5. Fourpeers exactmatchingcanonicalRPC H1570 confirmed before Val5only unit changed to verified release-r1-performance.json floor4. Val5 startup Execution refused `certified H1048 lacks durable executed candidate`; retained durablefinalized1047, certifiedSyncprefixahead. Two automatic retries observed then rootstopped dedicatedservice toavoidchurn; no state/custody/journal deletion or otherhostrestart. Previous seq4 runtime had advanced to1047 whilecandidates/certifiedhistorywere asynchronously catchingup. Existing restarttestdidnotcoverpersistedverifiedQCprefix ahead ofexecutedcandidates. Repair must retain verified consensus/finalityauthority whilequeueing exactnot-yet-executed certified transitions until authenticatedSynccandidate arrives, validateeverycandidate against certifiedcommitments beforeexecution/finality. Source-only causalrepair delegated; chainfourcontinuesadvancing1581. Atlas stafftelemetry reportsactualoffline/recovery state, notcompletion.

### Certified execution-gap restart and block cadence repair — 2026-10-09

Genuine authenticated five-service certified-execution-gap restart/rejoin regression PASSED104.04s: retain genuineQC/journals, restart with missingunfinalizedcandidate, fetch/reexecute exact authenticatedtransition, resume matchingfinality. Startup now waits at missingcandidate instead of rejectinglegitimateQCahead; anypresentinvalidcandidate still fails. Ordered historicalfinality uses existing independently verifiedthreeQC authority, never skips candidate/rootexecution.

Operator reiterated wallclockblocktarget0.5–1.5s. Signed target_block_time_ms1000 is deterministicconsensustimestamp metadata, not a wallclockpacer. Actual finalizedcadence above target. NativeVal2 NetBirdstatus subprocess measured70.71/70.38/135.25ms and was called every50ms synchronousruntimepoll. VPNstatus/registry observation now1scadence withforcedstartupverification, independent authenticateddials, preservedfailclosedfresherrors/readiness. Causalprocess-cadenceregression passed1/1; genuineexecutionbootstrap2/2 passed11.05s; strictClippy passed1.71s; canonicalLinuxbuild passed49.02s. Signedsequence6 planned/staged binarySHA256ffd122b0d6ca55b23f578cc70a43e4a8314545d8b1936a586198d144ebd77761, unchangedR1activationcommitment. NextactionVal5only afterallnativeverification, preserveeveryrecord; laterall-fiveguardedrollingupdate and actualcadenceacceptance. No 0.5–1.5s achievement claimed. Atlas nowdisplaysactualseconds and explicitlylabelledoperator targetband/above-targetreading.

### Sequence6 retained-state recovery resumed — 2026-10-09

All5 signedsequence6 nativeartifactverification passed. FourpeerexactcommonRPC H1762 confirmed before Val5unitselectedrelease-r1-startup-performance.json floor5. Val5startedPID781915 withzeroautorestarts, actualexecutedfinality1047→1137 whiletip1806. Nojournal/state/identityreset. Originalothernodeunits retaineduntilall-fivecatchupguard. Atlas productiondeployment74a1cf50 targetbrowser verifiedactualblocktime3.126s, operator0.5–1.5s shadedtargetband/above-targetflag, live15charts. Runtime targetnotmetyet; nofinalacceptanceclaim. Catchupthroughput source inspection underway beforeanyfurtheroptimization.


### 2026-10-09T16:41:22.877134+00:00 — H1931 stalled Val3 retained-state R1 repair

All five durable execution pointers now report H1931. Older Val3 has seven automatic restarts and a retained TC1933/r2 beyond the peers timeout projection; chain has stopped advancing. Signed seq7 r1-gap-wait has been installed and native signature/hash verified on Val2–Val6 (SHA256 3f70e98b2982bd4c28c185cc62f836243c38cb436ac62c79aa14f3d7e6eca8f7). Genuine authenticated execution-gap restart test passed in 101.18s, strict Clippy passed, Linux release build passed. Seq7 avoids repeated historical proof loading while the next executed candidate is missing; approved R1 semantics and all journals/quorum checks retained. Unstripped symbols support instruction-address profiling. Root will first restart only already divergent Val3 onto seq7 using pinned signed release verification floor6; waiting for all-five advancement before this repair would deadlock recovery. No data, identity, timeout or QC journals reset. Healthy remaining rollout still requires all-five matching advancing durable finality. User block interval requirement is measured 0.5–1.5 seconds, still unproven.


### 2026-10-09T16:45:59.639440+00:00 — retained Val3 recovery progressing; timing target still unmet

Val3 sequence7 PID695566/restarts0 advanced1931→2010 without resetting any retained history. Otherfour reached2045. Allfive RPC responses at commonH1970 matched exactly. Peer QC arrival spacing over30observations was median1.97–2.02s/mean2.29s with8.5–8.8s maximum, outside required measured0.5–1.5s. These arrival measurements do not substitute for finalized cadence acceptance. Root instruction-address-only perf observation on unstripped Val3 showed30.58%Keccak permutation,13.68%MLDSA65 Montgomery reduction,3.58%NTT and3.67%JSON integer parse over432samples; no raw stacks/private data captured. Source review additionally found native readiness remainsfalse on otherwise all-service-ready signer nodes because lifecycle never leavesShadowing; healthy rollout gate remains closed while proper authorized lifecycle transition is investigated. No readiness gate weakened.


### 2026-10-09T17:02:00.127161+00:00 — bounded recovery queues caused repeated Val3 exits

Continuation live verification: Val2/4/5 finalized H2418; Val3 retained H2353 with four automatic restarts on signed sequence7. Val3 journals report alternating `PoSy finality queue is full` and `protected material cache full` during catch-up. Val6 remains active at original PID153812/restarts0; one compound admin observation failed, so its current height is not claimed from that call. No runtime mutation performed in this continuation. Separate source agents are investigating recoverable bounded queue pressure, the failed exact-signature-cache negative test, and a narrowly authenticated legacy readiness migration gate. Initial cache test command was terminal exit101 (one pass, one failure), so dependent Clippy/build/deployment did not execute. Fresh validation is required before any sequence8 release.


### 2026-10-09T17:08:06.577056+00:00 — repair failed legacy Val2 with verified sequence7

Val3/4/5/6 reached H2450 and their native service observations are all healthy/ready (legacy lifecycle remains shadowing). Val2 retained H2424, failed seven times on `stale, skipped, or non-sequential timeout certificate`, and hit systemd restart limit. Root will verify and activate already-signed sequence7 R1 on failed Val2, preserving original identity/configuration and all safety/history data. This is recovery of a failed validator, not a healthy rolling restart; the remaining four are preserved. Sequence8 source validation/build is concurrently running only on canonical build host; no sequence8 runtime activation is authorized by a mere build start.


### 2026-10-09T17:13:52.098383+00:00 — local disk capacity failure isolated; recovery validation rerun on SSD

Sequence8 focused checks passed: exact-signature-cache2/2, authorized-readiness2/2, durable finality backpressure1/1, execution cache-pruning1/1 and prior pipeline-cache regression1/1. Expanded genuine offline/rejoin test reached H48 then failed writing its owned temporary signing journal: ENOSPC. Build host internal Data volume had only220MiB free; canonical external SSD had1.2TiB free. This is a test-environment capacity failure, not successful consensus qualification. No production data was removed. Rerun uses TMPDIR at canonical node-platform/target/test-tmp (mode0700), with fresh owned fixtures and normal test cleanup; output target/r1-stable-recovery-validation.log. Dependent Clippy/Linuxbuild remain gated on genuine test success. Live Val2 sequence7 recovered to matching all-five H2572; sustained/target-cadence and complete resilience proof still pending.


### 2026-10-09T17:34:12.265678+00:00 — sequence8 validated; signed staging and retained Val3 repair

Sequence8 r1-stable-recovery passed the genuine 70-block offline/execution-gap/rejoin test (978.49s), with all five agreeing on durable block/world-state at H84 and zero full Sync projection rebuilds in that fixture. This is historical common-height agreement, not a claim that the test lagging node reached the peers live tip. Strict Clippy passed2.87s; native Linux build passed49.28s; approved R1 timeout-before-older-QC causal regression passed6.10s with journals retained. Focused signature-cache2, lifecycle-readiness2, durable-notification coalescing1, execution cache-pruning1 and prior cache regression1 passed. Artifact length12374768; SHA256 ed886294d19513476cca707a83bd1c9b3d868208f9b113acee05983d688a2b53; SHA3-256 2d5777eae2eee5c73db85b1ff13bab46bba2635e5084be7afc8dcef086958b8c. Same approved R1 activation commitment; no quorum, identity, finality, or cutoff semantics changed. Root will stage immutable signed sequence8 on allfive, verify native artifact/signature/trust pins, then repair recurrently failing/lagging Val3 with all journals retained. Healthy remaining rolling restarts require allfive matching advancing finality and actual service readiness; known legacy readiness defect is narrowly authenticated, while sequence8 must report native ready=true.


### 2026-10-09T17:46:42.951243+00:00 — sequence8 Val3 caught live tip; guarded fleet rollout

Native signature/artifact verification passed allfive before Val3 activation. Val3 PID708917 sequence8 retained all state, recovered from H3116 through H3418 with zero automatic restarts, lifecycle active and native ready=true. Root all-five matching advancing finality guard passed at H3417; observed heights3417/3418. Root next updates Val5 to already-signed/staged sequence8 after a fresh all-five gate, then guarded sequential rollout to2/4/6 (skip already-correct3). Each restart must regain all-five matching advancing finality with no automatic retry before the next mutation. Measured0.5–1.5s and sustained resilience remain unproven. Source-only bounded authenticated candidate prefetch is separately under test/review and is not included in sequence8.


### 2026-10-09T17:59:05.420787+00:00 — Val5 sequence8 rejoined; remaining rollout waits for Val3

Fresh all-five matching advancement H3477 preceded Val5 activation. Val5 signed sequence8 native readiness and all-five matching advancement H3512 verified with retained state, PID809645/restarts0. Remaining guarded rollout started but has not passed its initial all-five gate: later peersH3782, Val3H3686/PID708917/restarts0/Sync pending. No further validator restart until gate passes. Last100 Val5 durable world-state file commit intervals median1.94s/mean2.15s/max7.92s,16/100within0.5–1.5s; this is filesystem commit timing evidence and not a timestamp-derived claim. Source-only bounded prefetch passed4focusedtests +source retry1 +strictClippy. Independent review found queued response could be purged on reconnect after bookkeeping marked it awaiting; root added current-session invalidation and5s retry of still-uncommitted height, exact durable parent/proofs unchanged. Genuine70gap/restart/reordered-response qualification running; not released.


### 2026-10-09T18:07:13.412383+00:00 — Atlas observation bounded; prefetch qualification continues

Publisher previously parsed all candidate history H1..tip on allfive everypoll and stopped cumulative totals aboveH10000. Replaced with per-node RAM cursor anchored against exact durable finalized-history, max256 new committed candidates/16MiB perprobe, checked height/block/state/parent, unknown total until complete. Synthetic incremental/reset/fork/missing/bound checks and root source/syntax review passed. Launchagent restarted, fresh origintelemetry verified H3979 with five actual synchronization rows and completed sequence8 local-regression evidence. Soak/below-quorum remain pending. No consensus/runtime state changed by this telemetry repair. It reduces proven O(height) observation work; not claimed root cause of cadence. Root genuine prefetch qualification progressed beyond64; dependent release signing/deployment awaits terminal success.


### 2026-10-09T18:47:43.583306+00:00 — H4076 historical Sync witness overflow; recovery scope

Observed Val3/4/6 failed at durableH4076; Val2 activeH4076 after3automaticrestarts; Val5 activeH4075/restarts0. Val2/3 journals identify Execution serve_sync_requests fatal: Sync candidate witness exceeds protocol bound. Val3 QC4078 isround46 with exacttakeoverTC; full FinalitySyncWitness includes referenced46TCleaseclosure, eachTCincludesauthenticatedreportsandhighestQCproofs. Onelegitimatehistoricalresponse exceeds1MiB; nestedJSONbytearraysalsoexpandagainst1MiBframebound. Allproofs/TCjournalsretained. Rootsourcecontainsoversizedresponse nonfatally andchecksfullserializedframe beforeoutbound; thiscontainscrashbutdoesnotyetdeliverlargeproof. Fullproofchunkedtransport remainsrequired. Prefetchlongtestfailed661.71sonfixtureonly: secondimmediaterestartdialsallrejected1–3speerbackoff withnoVPNretryowner. Focused8gapfixture nowretriesmissingpeersatproduction5scadence; rootcausaltest+Clippy+buildrunning. No newrelease deployed. Remainingseq8rolloutterminaltimeoutatinitialallfivegate, noadditionalmutations.

OperatoraddedmaximumETDAGorderedTPSloadqualificationandAtlasTPSstats: measureaccepted/ordered/finalizedratesseparately, sustainedandpeakwithwindows, latency/backlog/errors/resourceuse; progressiveloadonlyafterbaselinechainreliability. NoTPScapacityclaimyet.


### 2026-10-09T18:51:54.642537+00:00 — sequence9 verified; failed validator recovery

Focused genuine8gap/outstanding-request restart/reorderedresponse test passed201.13s afterfixturemissing-peerredialrepair; allfiveexactdurablestatequalificationpassed. StrictClippy1.75s andLinuxbuild51.23spassed. Seq9binary12421728bytes SHA2563887f72cd246b5b83771a1244ca80a543b17debf71ac0b813cc1cf5d297e6087 SHA3bfedf400d8b76ff9473f2f23ad6c4cddd4a9832c81ddd189eeaf00960ca93845; nativeexistingauthoritysignatures/artifactverificationspassedallfive. Includesbounded4heightprefetch/sequentialexecution/session-lossretry andnonfataloversizedhistoricalresponsecontainment. Fulllargeproofdeliverynotimplemented; skipsunsupportedoversizedresponsewithouttruncatingauthority. RootwillrecoverfailedVal3/4/6 sequentiallywithoriginalstate/custody usingpinnedseq9floor8. ThisisfailedfleetrecoveryatH4076, nothealthyrollingrestart; requiringadvancementbeforebringingbackquorumwoulddeadlock. NohealthyVal2/5restartinthestep.


### 2026-10-09T18:58:39.898095+00:00 — Val2 failed legacy release recovery

Seq9 Val3/4/6 stayed native ready atH4080/restarts0. Legacyseq7Val2 nowfailedH4080/restarts7; Val5behind4075. RootwillrecoverfailedVal2usingalreadyverifiedsignedseq9withoriginalstate/custody. LargeprooftransportstillrequiredforVal5. Userpriority: onceallfiveatadvancingtip, runboundedTPSbaselinebeforeadditionalrecoverytests/maxload.


### 2026-10-09T19:27:33.871698+00:00 — full-proof chunk recovery qualification and sequence10 staging

Genuine 46-TC oversized-proof causal regression passed9.38s: exact reversed-chunk reconstruction, normal PoSy staging, preserved journals, and rejection of altered TC signature even with recomputed transport digest. Authenticated8gap/outstanding-request restart/reordered chunk responses passed224.69s; strict node/sync all-target Clippy passed3.50s. Linux release build passed52.26s. Sequence10 candidate r1-chunk-recovery artifact12511440bytes SHA256951c39b55c98744ebda44ee2044ce8349df804bd198d7ce4044b4d7b6a6d2144 SHA3-25694d9b97520d1fbb7c15daaa564938c66e853472a14f54b9c57a3054f42e88bec retains exact approvedR1 activation commitment. Bounded chunk assembly retains complete proof and existing signatures/quorum/sequential execution checks. Immutable staging/signing/native verification is in progress; no sequence10 service activation yet.

Compatibility review establishes old seq9 Sync decoder rejects new V2 requests and propagates fatal polling error. Therefore no mixed-version rolling activation: after all-five native verification and guarded unit preflight, stop all five old services, verify stopped, install pinned sequence10 unit commands, then start upgraded fleet. Preserve all original state/custody/journals. This is an operational transport upgrade, not a chain reset or semantic amendment. All-five advancing matching finality, actual0.5–1.5s cadence and retained-state live recovery remain unproven. User-requested bounded TPS baseline follows all-five tip synchronization before further recovery tests.

### 2026-10-09 — sequence10 coordinated activation completed

Before activation, Val2/3/4/6 matched durable H5797 and Val5 retained H4075; all had zero automatic restarts. Native release signature/artifact verification and unit-command preflight passed on all five. Root stopped all five dedicated services and verified inactive/MainPID0 before changing any unit. All five units then bound signed release-r1-chunk-recovery.json, sequence10/floor9; systemd unit validation and daemon reload passed before starting the upgraded fleet. Initial live executable checks show the expected binary on all five, PIDs Val2=1295954, Val3=764805, Val4=888600, Val5=876440, Val6=723512, all NRestarts0. Initial retained heights were unchanged while startup loaded state; native readiness was not yet available. No state, custody, identity or journal reset. Read-only all-five matching advancement guard is running; activation alone is not recovery or chain-stability acceptance.

### 2026-10-10 — all-five catch-up and reproduced live lease split

Val5 recovered to H5797; all five native-ready validators match exact finalized block/state with original PIDs and zero automatic restarts. They remain stalled. Operator authorizes fresh H0 reset if needed, but now requires causal permanent repair and automatic recovery before TPS baseline. Administrative disconnect of all ten peer edges succeeded through the existing exact-session control; no subsequent advancement observed. No reset performed.

Live journals identify Val2/3 active delivery H5800/r1 with retained TC5799/r0; Val4/6 H5800/r0 without that TC, despite matching QC5799 stable subject. Source admits a TC only at its original current slot, retains takeover across same-lease QC advancement, and drops old-height TC retries. Genuine-signature causal test authenticated_live_tc_qc_arrival_order_reproduces_successor_round_split passed0.87s, proving identical certified ancestry but different successor rounds and mutually rejected next-height timeout votes. This is unresolved-defect evidence, not a successful repair. Proposed R2 in the canonical simplified-consensus amendment awaits explicit operator approval because R1 clause4 leaves live TC admission unchanged.

Separate transport cleanup hardening now shuts both socket clones before writer join and cleans failed session admission; blocked-writer regression passed0.11s. Earlier indefinite-deadlock hypothesis is corrected: TCP setup already supplies a configured write timeout. The cleanup improvement is source-only and is not claimed as this consensus stall's root cause or deployed repair. TPS admission work is incomplete; current Genesis has no funded accounts and RPC has no live wallet admission. No TPS result claimed.

### 2026-10-10 — approved R2 convergence repair qualified; sequence11 staging

Operator explicitly approved canonical R2. Four focused R2 state-machine tests, complete PoSy unit suite21/21, genuine signed opposite-order/restart/continued-finality test1.01s, authenticated dropped-TC production-retry convergence6.75s, and existing R1 genuine retained-history recovery10.21s passed. The socket convergence qualification polls Network and PoSy only; executable live chain recovery remains an activation acceptance gate. All-target strict node/PoSy Clippy passed4.20s. First Linux build hit internal Zig-cache ENOSPC; rerun with external qualification-volume temporary/cache paths passed57.84s. No production storage was deleted.

Sequence11 r2-lease-convergence artifact12560728bytes SHA2562f0484dfd4f5e4cc8070a6de3433c6eb6e7d7ff285cb370a73418f2bd34a4b5f SHA3-256151d3eb37f16aeb0c018d9f02dd59f224753f5942e6056e45e4c19c12f85cd73. Activation commitment posy-r1-r2:sha3-256:66c5487be69d182733d24998b24ea5b0707674f9325a77526278d206a22bc945 hashes canonical JSON (sorted keys, compact separators) containing prior ratified r1_commitment and complete approved R2 section as ratified_r2_utf8 (trailing single newline). Runtime preserves R1 supersession and original immutable journals; retries admitted TC closure throughout current lease and restores compatible original-height carry after certified-prefix replay. Network cleanup shuts both sockets before writer join. Guard self-test passed compatibility1positive10negative and readiness3positive25negative.

Root will stage/sign/native-verify exact sequence11 on allfive, preflight pinned unit commands, and perform coordinated stalled-fleet activation with original identities/state/custody. No H0 reset, quorum reduction, history deletion or public routing change. Live matching advancement and automatic recovery are not yet claimed.

### 2026-10-10 — signed sequence11 coordinated activation completed

Allfive prior seq10 native-ready validators agreed exact durableH5797/restarts0 before mutation. Every sequence11 native signature/artifact verification and pinned unit preflight passed. Root stopped allfive and verified inactive/MainPID0 before any unit edit; allfive signed sequence11/floor10 unit commands validated and reloaded before starts. NewPIDs Val2=1699845 Val3=1128226 Val4=1349481 Val5=1232876 Val6=1126755, initial allNRestarts0. All original state/journals/custody retained; no chain reset or identity change. Root is observing native readiness and all-five RPC/durable matching advancement beyond the originalH5797 stall. Activation alone is not a live recovery claim.

### 2026-10-10 — R2 live advancement; remaining execution catch-up and Atlas TPS deployment

Sequence11 resumed the original chain without reset; all-five exact matching RPC/durable finalized H5808 and native readiness were verified. Subsequent sustained observation failed the all-five live-tip gate: Val3 execution fell behind while consensus delivery slots converged. Latest read observes Val2/4/5/6 exact H6512/block377b4943ba51f1077a683ad10682e0a37fd7e7f0c034c32a32980e47bfaee25c and Val3 H5993. All retain activation PIDs and NRestarts0; Val3 native readiness is false. Do not claim stable all-five operation or TPS baseline.

Source causal control demonstrates NetworkService reads128 events before draining router capped16 per peer, dropping an authenticated Sync frame behind32 PoSy frames. Incremental eight-event drain regression passes and production-TC retry convergence passes5.81s. Broader genuine eight-gap/outstanding-request restart/reordered-prefetch test failed237.04s solely at concurrent-response capture qualification; exact cause remains under investigation. Diagnostic rerun records received response heights and restart cursor. No new release, node activation or reset while this gate is unresolved. Temporary SMB/build-host filesystem responsiveness interruption recovered; source size/content verified after write completion.

Atlas TPS frontend deployed to Pages deploymentb18cc3e6 (build1791582957356). Live production index200 and StaffPosyPage-DjH288__.js exact local/remote SHA256 verified; TPS labels/animated chart bundle present. Unauthenticated staff telemetry remains401. Existing canonical/public/generated workers reconciled in place, retaining newer API proxy routes and authenticated private telemetry. Authenticated rendered metrics were not checked. Accepted/ordered TPS instrumentation and funded submission remain incomplete; no capacity result claimed.

### C1266-20261010-NETWORK-DRAIN — sequence12 staging and retained Val3 repair

Detected 2026-10-10; severityP0 reliability; statusOPEN. First observed new lag after matching H5808; latest exact four-validatorH6512 block377b4943ba51f1077a683ad10682e0a37fd7e7f0c034c32a32980e47bfaee25c, Val3H5993. Responsible shared NetworkService staging drops confirmed by old-order causal control; this is not validator misconduct. Its contribution to sustained live catch-up remains an inference until activation observation.

Diagnostic rerun genuine authenticated outstanding-request restart/reordered-prefetch qualification passed249.83s with execution/finality assertions unchanged. Previous237.04s concurrent-capture failure remains recorded; diagnostic-only change does not establish its exact cause. Strict node all-target Clippy passed1.63s; Linux release build52.40s. Seq12 r2-network-drain12562424bytes SHA25671e6fdc81f0e6e45bce085e59675fdc4a148f86c05f44c25cb2c51b6130bccc7 SHA3ddbabd6969e12ce0b8140ece11ff8229a9f32a9479cb153fd59830f5eb357928, approved R1/R2 activation commitment unchanged. Rollout guard self-tests pass1positive10negative compatibility/3positive25negative readiness. Root stages immutable signed release allfive, native verifies signature/hash, then repairs only lagging Val3 with original safety/identity/custody retained and remainingfour preserved. All-five native-ready matching advancement is required before healthy rolling restart. No reset or TPS baseline claimed.

### 2026-10-10 — Val3 stopped with VPN polling failure; activation resumed after PID0 verification

Val3 preflight and signed seq12 verification passed at retainedH6056/blockd5f5dce5e1dc6980d2a0652f34f287fe6f65196c829be6ced528b2e5af7ea210. systemctl stop returned nonzero; independent show confirmsfailed/MainPID0/NRestarts0. Journal reports VPN NetBird polling failure during stop. No unit edit had occurred. Root resumes only after confirming no process remains, preservingstate and remainingfour. This stop failure remains recorded, not successful normal shutdown.

### 2026-10-10 — Val3 sequence12 activation completed

Pinned signed seq12/floor11 unit edit, systemd validation/reload/start passed. Retained execution {"finalized_height": 6059, "finalized_block_id": "82bc7e5a41b03c21824b330934263ff60fb04cd09096744a92013be8b3a99de3", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}; service {"ActiveState": "active", "SubState": "running", "MainPID": "1136326", "NRestarts": "0"}. Otherfour unchanged; no reset. Live catch-up gate pending.

### C1266-20261010-PREFETCH-ASSEMBLY — bounded concurrent recovery qualified

StatusOPEN/P0; retained chain production slowed/stopped aroundH7100 while Val3 continuescatchup. Exactcurrentdurabledeliveryshows Val2/4/5/6 shareH7103/r12, subsequentlyVal2/5H7104/r15: no same-height round split established. Val5 missingdeliveryECHO evidence while otherthree holdsamecandidate; sharednetworkloss remains plausible, not provedfromslot alone. Allautomaticrestartsremain0.

ConfirmedsharedSyncadapterdefect: fourheightprefetchhadone64MiBassembly; authenticatedinterleavedchunksforothereligibleheightswereignored. Rootreplacedwithfourheightmap sharing the original64MiBaggregatecap, exactpeer/session/requestbinding, progress/agepruningandunchangedPoSy/sequentialexecutionchecks. Causalcontrol oldassemblyrejectssecondheight; interleaved4response/changedsession/count/aggregateboundregressionpasses0.13s. Genuineauthenticatedoutstandingrequestrestart withauthenticchunksinterleavedacrossheights passed208.71s; strictClippy2.28s/Linuxbuild52.35s. Seq13 r2-prefetch-assembly12578552bytes SHA2562b8f67c8622574537801841999efde5558fb398540c6a86b6fff8da9be8e436b SHA345134dbf7064b3869c7dbaad3d30df895f3c71e4ea6eccc28ffc576dced89387, unchangedapprovedR1/R2commitment. Anembeddedguardquotingerrorcaughtbydirectcompile before anyremoteeditwasfixed; self-testnowcompilesallremote code to preventrepetition.

Rootwillimmutable-stage/sign/nativeverifyallfive, thenrepairlaggingVal3retainedstate. Additionalstalleddeliveryrepairrequirescurrentexactevidenceandpreflight; healthyrolloutstillrequiresallfiveadvancing. No reset, identitychangeorquorumreduction; noTPSresult. Operatorprovidedexistingarchivealias synergy-archiveforfutureverifiedsnapshotwork; noarchivechangeorcredentialretention.

### 2026-10-10 — sequence13 staged; retained Val3 repair started

Allfive native signatures/artifact verifications passed. Val3 before {"finalized_height": 6558, "finalized_block_id": "ae99626c9f18aa79137b2ae13946c7751d3fe31a2648c19495adca005afad500", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}; service {"ActiveState": "active", "SubState": "running", "MainPID": "1136326", "NRestarts": "0"}. Pinned unit preflight passed. Root updates onlylaggingVal3 with original journals/custody; otherfour retained.

Val3 seq13 stop attempt: {"stop_returncode": 0, "stopped_state": {"ActiveState": "inactive", "MainPID": "0"}}; processabsence verified beforeunitmutation.

Val3 sequence13 activation complete: {"commitment": {"finalized_height": 6559, "finalized_block_id": "d0b43e4754d2b7a3c6846a48b9ddb36e38d1c5b8ae2831ecf376b9178540eac8", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1140111", "NRestarts": "0"}, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-r2-prefetch-assembly"}. Startup/catch-up/all-five advancing acceptancepending.

### C1266-20261010-FLEET-DELIVERY — coordinated retained-state network repair

StatusOPEN/P0. Fourleadingvalidators retainmatchingproposal7299/blockd8e19612b382319cd2981c25986bc5de7a14608827ae7730648b42c125d5ee5b andprotectedrootba1a614b936f0d456c8eddae3de7d9a4935baca741768c43a1deac4538de8262; ECHOdeliveryincomplete duringrepeatedlongtimeouts. Allfourstillseq11withconfirmedburstloss mechanism; Val3seq13continuescatchup. Thisisdegraded/stalled-fleet deliveryrepair, nothealthyrollingacceptance. Allfour signedseq13/artifact/unitpreflights passed. Rootstopsthefourlegacyservices, confirmsPID0beforealledits, validates/reloadsallfourbeforestarts; Val3staysrunningwithoriginalPID. No reset, quorumchangeorhistorydeletion. Before {"2": {"commitment": {"finalized_height": 7308, "finalized_block_id": "1ae0b18ad0291fb0b0966cf3b590784647b30e28aa4bd968e82308946da71d03", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1699845", "NRestarts": "0"}}, "4": {"commitment": {"finalized_height": 7308, "finalized_block_id": "1ae0b18ad0291fb0b0966cf3b590784647b30e28aa4bd968e82308946da71d03", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1349481", "NRestarts": "0"}}, "5": {"commitment": {"finalized_height": 7308, "finalized_block_id": "1ae0b18ad0291fb0b0966cf3b590784647b30e28aa4bd968e82308946da71d03", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1232876", "NRestarts": "0"}}, "6": {"commitment": {"finalized_height": 7308, "finalized_block_id": "1ae0b18ad0291fb0b0966cf3b590784647b30e28aa4bd968e82308946da71d03", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1126755", "NRestarts": "0"}}}.

Val2 coordinatedseq13stop: {"stop_returncode": 0, "stopped_state": {"ActiveState": "inactive", "MainPID": "0"}}.

Val4 coordinatedseq13stop: {"stop_returncode": 0, "stopped_state": {"ActiveState": "inactive", "MainPID": "0"}}.

Val5 coordinatedseq13stop: {"stop_returncode": 0, "stopped_state": {"ActiveState": "inactive", "MainPID": "0"}}.

Val6 coordinatedseq13stop: {"stop_returncode": 0, "stopped_state": {"ActiveState": "inactive", "MainPID": "0"}}.

Fourremainingseq13activationcomplete; Val3originalPID1140111preserved. After {"2": {"commitment": {"finalized_height": 7309, "finalized_block_id": "e146ca5090c8da05b3054f9234cf12b9d30922ae3e2e8ca487912d1bede78f4d", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1719354", "NRestarts": "0"}}, "4": {"commitment": {"finalized_height": 7309, "finalized_block_id": "e146ca5090c8da05b3054f9234cf12b9d30922ae3e2e8ca487912d1bede78f4d", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1372278", "NRestarts": "0"}}, "5": {"commitment": {"finalized_height": 7309, "finalized_block_id": "e146ca5090c8da05b3054f9234cf12b9d30922ae3e2e8ca487912d1bede78f4d", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1250578", "NRestarts": "0"}}, "6": {"commitment": {"finalized_height": 7309, "finalized_block_id": "e146ca5090c8da05b3054f9234cf12b9d30922ae3e2e8ca487912d1bede78f4d", "state_root": "b061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20"}, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1146215", "NRestarts": "0"}}}. All-five actualready/commonadvancingtipacceptancepending.

### C1266-20261010-SEQ13-COMMON-HEAD

All five retained-state validators passed native readiness and exact matching finalized block/state verification at H7541 and then H7558 with zero restart deltas. This establishes advancing common finality after seq13; sustained stability, target block timing, and genuine transaction TPS remain unqualified. No reset or identity changes occurred.

Archive host alias synergy-archive passed strict-host-key BatchMode SSH: Darwin 27.0.0, approximately 115 GiB available on root volume. No synergy-node executable was found on PATH; passwordless sudo is unavailable. No archive installation, authority changes, snapshots, or credential storage occurred. Archive custody credentials remain user-provided and were not written into this incident log.

### C1266-20261010-WALLET-ADMISSION — genuine TPS prerequisite

Status OPEN; severity P1 baseline blocker. Recorded at 2026-10-10T21:41:42.963552+00:00. Last previously proven all-five finalized agreement H7558; first bad transaction height unavailable because current Genesis has no funded wallet accounts and protected wallet submission was unwired. Responsible component is shared node admission integration, not validator misconduct.

Actions: implemented bounded owner admission queue, canonical signed wallet proof and ciphertext commitment, actual ingress-key context RPC, receipt RPC, and accepted/ordered process counters. Wallet tooling generates verified FNDSA root/ML-DSA-87 account bindings and encrypted signed transfers without secret output. HTTP accepted streams now explicitly enter blocking mode under existing bounded timeouts; genuine macOS socket qualification had proven inherited nonblocking mode could discard request bodies. Historical vertices retain their original transcript. Later wallet rounds use the owner’s authenticated quorum-parent checks; an accidental pure-carrier round-zero-only restriction was removed before deployment.

Validation: final genuine HTTP five-validator transfer test passed 131.59s, exact applied account state and canonical receipt on all five; tampered signed metadata rejected; duplicate submission did not increment accepted count; actual ordered counter checked. Four focused ETDAG transcript/commitment/shape tests passed 0.04s. Node/keytool/client all-target Clippy passed. Linux node and keytool built successfully; final node SHA256 197e81ea73e0e635a0a514f9c7e1e4d3cc6696fd27ba2d9e805275556c1efd62. Rollout guard passed 1 positive/10 negative compatibility and 3 positive/25 negative readiness cases. Telemetry counter-delta, restart, and reset checks passed. No live activation, funded Genesis reset, or TPS result yet. Next action is immutable signed staging, funded launch qualification, then bounded finalized-success TPS baseline before additional recovery testing.

### C1266-20261010-VAL5-TC-VARIANT — automatic retained-state restart

Status OPEN; severity P1 reliability. Detected journal failure 2026-10-10 18:20:19: authenticated timeout proof variant changes accepted parent or carry. First bad height and exact offending proof remain uncollected; last earlier proven common finality H7558. Shared certified-peer conflict classification is responsible for service termination; legitimate-versus-conflicting variant causality remains unproven. Val5 restarted automatically at 18:20:34 and rejoined with retained journals; no manual reset or history deletion. Latest service probes show Val2/3/4/6 original PIDs and NRestarts0, Val5 PID1255497 NRestarts1 with no additional restart. A running service is not sufficient to close this incident. Preserve fail-closed certified conflict checks while collecting exact proof context; do not claim a clean stability soak or permanent repair.

Wallet baseline preparation: immutable node sequence14 (12878680 bytes, SHA3 47340f2d40f88703c1beee3e9aa2aba9526e19a61fb959b9a2f5388183dcdd35) staged and natively signature-verified on all five machines; no activation. Signed wallet helper verified on Val2. Generated 32 funded FNDSA/ML-DSA-87 wallet bindings on Val2 with exclusive private files; no private bytes exported. Fresh funded Genesis hash6cf3f8467e4fc6dc8293b8f4fb3aa56f7e641261e66e3703b423e105624cc144 and authority natively verified on Val2, same existing validators and governed parameters. Initial all-host public configuration staging attempt failed because the standalone synergy-genesis verifier is installed only on Val2; Val3 direct check confirms executable absent. Existing validator processes/configurations stayed unchanged. Retrying only public/configuration preflight using each host’s existing native authority verifier and the exact Val2-verified signed Genesis bytes; no verifier installation or signature bypass.

### C1266-20261010-FUNDED-BASELINE-LAUNCH

Status OPEN/P1 TPS qualification; original empty-account chain is advancing and not being reset to conceal a stall. Preflight proves exact common finalized RPC block/state at H14361 then H14367; Val2/3/4/6 restart counters0, Val5 counter1 unchanged from recorded automatic TC-variant recovery. Last common H14367 block220698df8667d878576c5d184dd2c0618b9415d8b83537778bf98bbd8a250763; stateb061c812b068a55c332cd4c4aecd545398c0081c14d26ec2d45017be56846a20. All five native readiness/health pass. First bad transaction height is not applicable: baseline has not begun. Root will use the user's explicit fresh-chain/H0 authorization to activate signed funded network synergy-posy-baseline-20261010 with the same five validators, identity/key custody, governed parameters, and approved R1/R2 commitment. Native authority verification and strict sequence14 unit preflight pass on all five. Original /var/lib/synergy/posy-stability/data and its QCs, TCs, safety/signing journals remain untouched; fresh network writes only new baseline-data. Stop all five and prove PID0 before changing canonical node configuration; compare exact original/desired configuration hashes; strict signed artifact unit edit; validate/reload all before any start. Next gate is exact advancing all-five finality, followed by a genuine transfer canary and bounded TPS baseline. No maximum-TPS or clean stability claim is authorized by these preflights.

Funded launch stopped services [{"validator": 2, "state": {"ActiveState": "inactive", "MainPID": "0"}}, {"validator": 3, "state": {"ActiveState": "inactive", "MainPID": "0"}}, {"validator": 4, "state": {"ActiveState": "inactive", "MainPID": "0"}}, {"validator": 5, "state": {"ActiveState": "inactive", "MainPID": "0"}}, {"validator": 6, "state": {"ActiveState": "inactive", "MainPID": "0"}}].

Funded launch configuration and signed units activated [{"validator": 2, "config": {"config_replaced": true, "original_data_preserved": true}, "unit": {"unit_commands_verified": true, "change_required": true, "execute": true}}, {"validator": 3, "config": {"config_replaced": true, "original_data_preserved": true}, "unit": {"unit_commands_verified": true, "change_required": true, "execute": true}}, {"validator": 4, "config": {"config_replaced": true, "original_data_preserved": true}, "unit": {"unit_commands_verified": true, "change_required": true, "execute": true}}, {"validator": 5, "config": {"config_replaced": true, "original_data_preserved": true}, "unit": {"unit_commands_verified": true, "change_required": true, "execute": true}}, {"validator": 6, "config": {"config_replaced": true, "original_data_preserved": true}, "unit": {"unit_commands_verified": true, "change_required": true, "execute": true}}].

Funded launch initial start [{"validator": 2, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1796096", "NRestarts": "0"}, "commitment": null, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission"}, {"validator": 3, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1204916", "NRestarts": "0"}, "commitment": null, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission"}, {"validator": 4, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1460833", "NRestarts": "0"}, "commitment": null, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission"}, {"validator": 5, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1317294", "NRestarts": "0"}, "commitment": null, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission"}, {"validator": 6, "service": {"ActiveState": "active", "SubState": "running", "MainPID": "1223219", "NRestarts": "0"}, "commitment": null, "exe": "/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission"}].

### C1266-20261010-FUNDED-CUT-SPLIT — first genuine live transfer exposes cutoff liveness failure

Status OPEN/P0 block-production stall. Detected during the genuine canary; last agreed/first stalled finalized height H47, block6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27, state65dc252a3d62b7b982c1e15ccf9ecf30e06ce220ab986b32c31e5f61d479ca66. All five current sequence14 services retain activation PIDs/NRestarts0. Earlier journal error lines are historical and do not establish a new fatal event.

Canary: native wallet-tool signed/encrypted request accepted for targetH51, vertex44bc8c49682230f3a8e6e890bc6c377eea3bb172ef0ed7c6e1d69a44b72e52c7ff6cf001b07851ee924da6b31fb45a04e10f266b6e9e682b30dc183ae73f770c. Process accepted_total1, ordered_total0. The 90-second finalized-transfer observation failed; no TPS load applied. A diagnostic helper initially failed because its nested newline was not escaped; corrected read-only probe collected durable evidence, without node changes.

Confirmed boundary: targetH51 certificate present on all five; five votes observed for the vertex. Exact cutoff context176a418cd0dcfa7bab4f5219e7d1c89ce59981f2eda96cefbb2af5284162c4d92d89ff3af3e8b7371aff8cc089fec66ec644d4dee0217abe1b5cb92615ba5cb3. Val2/4/6 retained empty marker frontiers; Val3/5 retained the wallet vertex frontier. Both groups lack required4-of5 identical semantic closure. All five have no committed cut forH51. The current code groups closures and the core verifier correctly prohibits counting conflicting closures as one quorum. Delayed certificate arrival cannot replace signed marker history. Responsible component is shared cutoff-generation/recovery orchestration, not validator misconduct. Exact intra-poll ordering remains a regression-test obligation.

Recovery: no restart, reset, marker deletion, quorum reduction or semantic bypass attempted. Proposed recovery amendmentR3 appended to canonical POSY-00E document; pending operator approval under AOS19.6 before implementation. It proposes existing verified timeout authority for a new uncommitted close generation, retaining all original history and existing quorums. Next required boundary is approval, genuine counterexample/rejection/restart qualification, signed activation, then successful canary and finalized-success TPS baseline.

### C1266-20261010-R3-APPROVAL — timeout-path predicate qualified; runtime activation pending

Direct operator message `approved` authorizes the six R3 requirements at canonical POSY-00E line209. Updated that section status in place; no requirement relaxed. Incident remains OPEN/P0. Read-only live verification: all five sequence14 processes retain original activation PIDs, NRestarts0, finalizedH47 block6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27 and identical state65dc252a3d62b7b982c1e15ccf9ecf30e06ce220ab986b32c31e5f61d479ca66. No service, chain state, key, configuration, signing history or workbook mutation. No TPS load.

Source implementation: existing SimplifiedConsensusStateMachine exports verified_cut_recovery_timeout_path. Requires current unfinalized/uncertified targetH+1, accepted advancing complete timeout closure, exact terminal height/round/parent, reverified domain/lease/quorum/signatures, absent mandatory carry and absent current accepted proposal. Rejects repeated generation TC or a previous TC outside the accepted path. Export does not mutate the control plane. This is explicitly only the timeout-path predicate, not sufficient recovery authorization; no runtime caller is enabled.

Validation on canonical backing-host checkout b338dcc: three new focused R3 tests plus complete synergy-posy library suite24/24 passed; all-target synergy-posy Clippy with warnings denied passed. Tests use existing unit signature stub and do NOT satisfy genuine-signature/live R3 activation gates. Focused cases cover path advancement/completeness, wrong target/unknown previous generation, mandatory carry, accepted proposal, inherited earlier-height timeout, wrong network/parent, strict quorum and export immutability.

Independent subagent review confirmed persistence currently retains one marker per target, marker retry frames are height-keyed, and generation-aware history plus external PoSy verification are required. Critical remaining boundary: retained VC/READY/QC/proposal/cut/consumed exclusions and historical verification on restart, followed by immutable per-generation markers and atomic authorization persistence. Then all six R3 qualification gates, signed activation, live successful canary, and measured finalized-success TPS baseline. No release built/staged/deployed for R3.

Efficiency notes: one nonexistent test-path lookup corrected by scoped rg file inventory; one malformed sed range corrected before reread. Broad SMB git status was terminated after no output; exact backing-host revision/scoped diff inspection succeeded. No repeated broad scan, release build or fleet restart.

R3 durable-store review: original cutoff is VC(T-2); prohibiting affected-cut certificate is VC(T-1). Check immutable validation-hH.json, ready-hH.json optional VC, verified QC store including crash-atomic transition recovery, retained lease TC carry, protected batch/prepared/consumed records and finalized execution, plus pending/deferred/RAM bindings. Successful later certification means restart cannot require current absence of VC/QC; it must verify historical authorization against the certified parent prefix and require later material to bind the selected replacement generation. Compact delivery.json/READY journals may be overwritten by later rounds and cannot alone prove historical absence. This remains an implementation/qualification obligation, not a deployed fix.

2026-10-10T23:30:32.424090+00:00

### C1266-20261010-R3-RUNTIME-QUALIFICATION — source implementation; activation pending

R3 approval remains in force. Implemented durable generation selection/retained original markers, compact native TC/VC journal references, explicit authority-domain verification, retained candidate/VC/READY/QC batch-binding checks, private driver-to-ETDAG authorization queue and acknowledgement draining. PoSy remains the sole timeout/round owner. No live validator mutation, release, signing-key change, chain reset or TPS load in this qualification step.

Validation: three structural persistence tests passed (0.13s); genuine ML-DSA cut qualification passed initially (3.62s), then passed with two retained generations, restart and wrong-network rejection. The extended test initially expected an error on a previously authorized generation; API correctly returns idempotent false, and the assertion now verifies no transition/current marker unchanged. Production socket H51 genuine wallet regression is running; all five reached matching QC13 during setup. Completion, successful transfer, retained-state restart and deployment remain unverified.

Engineering corrections: the initial test filter matched zero tests and was not accepted as evidence; mock fixture digest widths were corrected; compact proof borrow-check errors were corrected. An overlapping SMB source write/remote formatter left a duplicate file tail; the proven tail was removed in place and compilation passed. One remote Python edit had shell quoting failure before mutation and was rerun with full shell quoting. No source or credentials workbook copies were created. Future writes/formatting/builds must remain sequential.

R3 socket qualification result: setup timed out after902.54s before H51 canary admission; focused two-generation cryptographic test passed. This does not establish recovery success. Fixture halted the whole PoSy service at F46, including candidate/sync/deferred processing. Removing that fixture-only halt while retaining authenticated H49+ packet delay and adding 60s no-progress diagnostics; no production deployment or live node mutation.

R3 qualification update: second socket setup attempt failed546.17s with all five finalized/executed46 and no initial H51 file. Confirmed open_collecting is in-memory until evidence persistence; disk-file-existence was an invalid fixture gate. Replace with published governed wallet admission context target51/source46. Explicit original VC-to-terminal certified parent linkage and same-lease verified TC cache refresh added; genuine two-generation restart/domain test passed4.15s after changes. Deployment, genuine socket recovery, and TPS baseline remain pending.

R3 genuine socket regression passed: authenticated five-validator H51 real-wallet transfer reproduced 3-empty/2-transaction original marker split, both delayed VAC arrival orders, automatic PoSy TC→R3 recovery, retained old markers, validator restart/rejoin, matching finalized transaction/balance/nonce and continued finality through H58. Test duration682.85s. This is local socket qualification only. Explicit 4/5-online and 3/5-fail-closed R3 variants, invalid/stale/missing/conflicting TC/parent/carry, VC/QC/consumed exclusions, signed R3 activation and live deployment remain incomplete. No TPS baseline or live validator change.

R3 safety gate update: focused genuine timeout-path test passed with same-lease cache refresh for newly arrived round1/round2 certificates and rejection of a genuine mandatory-carry timeout; test duration4.77s. Existing authenticated socket 3/5 test passed: held finalized H6 and QC H8 unchanged for full configured30s timeout, then recovered to matching finality/execution after validators rejoined (187.14s). Existing authenticated four-validator restart/rejoin test passed: four online validators progressed through finality H10, the restarted fifth rejoined, chain advanced through H16 (154.68s). Whole-repository Clippy had one cloned-ref lint in qualification test; corrected to slice::from_ref and clean rerun pending. Invalid/stale/missing/conflicting parent/QC/protected-record R3 variants, signed release/activation, live deployment, and TPS baseline remain outstanding.
Whole-workspace cargo clippy --locked --all-targets -- -D warnings passes after the qualification lint correction. The first post-edit clippy attempt correctly failed on cloned_ref_to_slice_refs; fixed with std::slice::from_ref and clean rerun.
R3 focused durable-evidence checks: genuine signed H1 QC candidate conflict rejected by native QC-store invariant; durable H2 VC and H2 QC independently reject a missing selected batch; retained execution-candidate proof accepts only the exact recovered batch and rejects no-batch/wrong-batch. Combined with prior timeout identity/signature/missing/domain/carry and repeated-generation/restart tests, focused genuine R3 qualification passes5.06s before execution-candidate additions and4.92s with them. Whole-target Clippy rerun pending.


2026-10-11 UTC live refresh: Val2–Val6 services are active/running, admin health and readiness are healthy/ready, and all five systemd restart counts are 0. All five durable finalized-state records match H47 block 6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27 and state root 65dc252a3d62b7b982c1e15ccf9ecf30e06ce220ab986b32c31e5f61d479ca66. Installed authority and manifest report network_id synergy-posy-stability-20261009; Atlas telemetry schema is configured for the same id. No transfer or TPS baseline has been run. Sequence-15 R3 unsigned release metadata was prepared for the current Linux artifact (SHA3-256 601d67bcd727b5a0c14a0d3b251520a1e29c38c38bcc7f8bdabbc85cb962a273), binding the cumulative canonical R1/R2/R3 rule text (UTF-8 section bodies before each Status line; SHA3-256 233f4634a74497ee88ebf267eb6d89604a864c25f891741943baf69e7c057989). It remains unsigned and undeployed: SSH to other-mini is available, but noninteractive sudo requires a password to access the governed release signer. No production configuration, process, or chain state was changed during this refresh.

### 2026-10-11T04:04:38Z — R3 recovery qualification checkpoint; activation still gated

Direct read-only verification through each existing Val2–Val6 SSH master: all five services are active/running, healthy/ready, with systemd restart count 0. All five use network_id synergy-posy-baseline-20261010 and report the same finalized H47 block 6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27, state root 65dc252a3d62b7b982c1e15ccf9ecf30e06ce220ab986b32c31e5f61d479ca66. RPC queries at H48 and H51 return null on all five. Durable H51 protected-pipeline records retain the same original cutoff context; Val2/Val4/Val6 signed empty frontiers, Val3/Val5 signed the wallet vertex frontier; all five show zero replacement generations and no committed cut. No process, config, safety journal, database, or chain state was changed.

R3 qualification checks rerun: PoSy R3 timeout-path tests 3/3 passed; ETDAG generation persistence tests 3/3 passed; genuine-signature native-store H47/H51 split recovery test passed (2.95s). Strict Clippy for synergy-node, synergy-posy, and synergy-etdag all targets passed with warnings denied. Canonical Linux release build completed successfully; artifact length 7,776,072, SHA3-256 37824aa46bb7791cda0efd8ce946786176e1e3a54b57551ae874ff5b630369ec, SHA-256 568a8d5c0add5a55189cb5fcbeef88219ad4110b6804a5d0e13a54691bfd4549. Zig emitted target-version warnings during dependency compilation, but the build script completed its ELF check and returned success.

Activation remains blocked: R3-specific 4/5 progress and 3/5 fail-closed coverage, remaining invalid/stale/missing/conflicting proof and retained-evidence exclusion cases, and canonical commitment derivation are not yet independently complete. Existing seq15 unsigned metadata does not match the rebuilt artifact. No release was signed/staged/deployed; no live canary or TPS load was run.


### 2026-10-11 — R3 authenticated 4/5 recovery gate remains unverified

Verified the canonical SSD over SSH at `/Volumes/PortableSSD/Synergy-Network`. The genuine-signature socket qualification was extended to exercise 3/5 fail-closed followed by 4/5 recovery while preserving the active target slot. The 3/5 phase retained all original H51 markers and produced no recovery generation or committed cut. The 4/5 phase did not commit within its 180-second bound: all four participating fixtures remained at finalized H47 with the same marker root, zero recovery generations, and no committed cut. This is a local qualification failure; no validator runtime, release signing, staging, or deployment was changed. The sequence-15 activation commitment encoding remains unverified, so R3 signing/activation stays gated. No successful transfer or TPS baseline has been run.


### C1266-2026-10-11-R3-QUALIFICATION — 2026-10-11T08:35:57.210851+00:00

Status: OPEN; severity P0; qualification checkpoint for the existing H51 protected-cut stall. First affected target H51; last live verified finalized height H47, block `6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27`. Affected Val2–Val6; responsibility remains shared PoSy/ETDAG cutoff recovery, not validator misconduct. Live state was not rechecked or mutated in this checkpoint.

Actions/results in chronological order: (1) The earlier interactive-shell qualification ended without a terminal result at setup H34; process absence was verified before replacement. (2) Detached genuine-signature socket qualification `authenticated_socket_r3_h51_late_vac_split_recovers_real_wallet_and_restart` completed successfully: 1 passed, 0 failed, 611.73 seconds, exit 0; remote log `/tmp/r3-h51-current-2.log`. It recovered the split with four participating owners, rejoined/restarted the fifth with retained markers, reached matching H58, and asserted sender nonce1, receiver balance7, and applied transaction receipt on all five. (3) Review found its 3/5 observation was only five seconds versus configured 30-second timeout. Source now derives full configured timeout plus one second; corrected qualification is running on other-mini as cargo PID38809, log `/tmp/r3-h51-full-timeout.log`, exit file `/tmp/r3-h51-full-timeout.exit`. Its result is PENDING. (4) Independent read-only commitment verifier and three tests passed: sequence15 commitment is SHA3-256 of concatenated UTF-8 pre-Status R1/R2/R3 sections, each with one final LF, exactly matching `233f4634a74497ee88ebf267eb6d89604a864c25f891741943baf69e7c057989`. (5) Bounded TPS harness now compares common finalized history and measures load-window versus drain rates separately; three mock-RPC tests passed. No transactions submitted.

Outcome: successful local recovery evidence, not live recovery or launch acceptance. Remaining gates include corrected full-timeout qualification, remaining activation coverage audit, current artifact metadata/build/signature verification, guarded live deployment, successful live transfer, sustained finality/recovery, and measured TPS baseline. No signing, staging, reset, node restart, public routing change, or validator state mutation occurred in this checkpoint.


### 2026-10-11 — R3 full-timeout qualification exposes fifth-validator rejoin failure

Follow-up to C1266-2026-10-11-R3-QUALIFICATION; status OPEN, severity P0. Existing live last-agreed finalized H47 block remains the prior observation; no live mutation or fresh live claim. Corrected full-timeout socket qualification exited101 after661.03s (0passed/1failed), log `/tmp/r3-h51-full-timeout.log`. Failure at socket_qualification.rs3822: `production PoSy timeout did not automatically recover the H51 cut`. Four participating fixtures recovered and progressed to finalized H60 while fifth remained finalized H47, activeH50/r0 without accepted TC. This supersedes any interpretation of the prior short-observation pass as complete rejoin qualification. Cause remains under investigation: timeout/recovered-cut authority delivery or reconstruction for the lagging fifth; no validator fault is established. No automatic retry was started. Source-only causal inspection continues; signing/deployment/TPS remain gated on resolving and validating this retained-state rejoin failure.


### 2026-10-11 — retained-TC transport repair qualification

Continuation of C1266-2026-10-11-R3-QUALIFICATION, OPEN/P0; prior live H47 block unchanged as last verified observation. Source inspection confirmed retry pruning dropped exact verified H50 timeout evidence once the advanced validators changed proposer lease, despite a frozen validator with unknown/lagging verified progress. `posy.rs` now retains signed timeout evidence across lease boundaries until every frozen peer's verified finalized progress exceeds that timeout height. Native signature, quorum, original-slot/ancestry checks are unchanged. Focused `timeout_retry_waits_for_every_validator_to_verify_progress_past_its_height` test PASSED1/1 after7.21s compilation; covers activeH63/TC H50 with lagging, unknown and all-advanced peers. Full authenticated H47/H51 recovery qualification now running as cargoPID86890, log `/tmp/r3-h51-retained-tc.log`, exitfile `/tmp/r3-h51-retained-tc.exit`; result PENDING. No live node mutation, release signing, or TPS submission. Historical recovered-generation reconstruction remains unproven until the full rejoin result.


### 2026-10-11 — sequence15 rollout tooling offline checkpoint

Existing R3 incident remains OPEN/P0; no live observation/change in this checkpoint. `roll-r1-tip.py --self-test` independently PASSED R3 EDIT2positive/10negative, chunk compatibility1positive/10negative, readiness3positive/25negative. Source supports sequence15 candidate hash/approvedR3commitment and exact oldrelease/binary/floor tuples including installedsequence14/floor13. Advancing-only rollout gates remain in force; this is not a stalled-fleet activation authorization or execution. Candidate artifact pin currently references pre-retention-fix ELF and MUST be refreshed after final Linux build; unsigned metadata is not release authority. Full retention-fix recovery qualification remains activePID86890, log `/tmp/r3-h51-retained-tc.log`; terminal result pending.


### 2026-10-11 — retained-TC full recovery result and bounded admission diagnostics

R3 incident remains OPEN/P0. Full authenticated retention-fix qualification FAILED after667.88s, exit101, log `/tmp/r3-h51-retained-tc.log`; four progressed beyond finalizedH69 while fifth remainedH47/active50/r0 without accepted TC. Transport retention alone does not establish recovery. No live validator mutation. Added opt-in cfg(test)-only H50 timeout receipt/admission diagnostics bounded12 receipts and12 rejections per validator. Focused retention regression passed after6.42s compilation. New full qualification includes four-only matching H54 finalized execution before fifth rejoin; running cargoPID91650 with diagnostics, `/tmp/r3-h51-diagnostic.log`, exitfile `/tmp/r3-h51-diagnostic.exit`. No unchanged blind retry: new instrumentation separates delivery absence from native admission rejection.

Linux candidate build PASSED exit0 (74s), artifact7798408bytes, SHA3-256 `0a3641624e7039881918a02b3a1ad3e6bae43585e450b79350870406b3d0a035`, SHA256 `d13b80deef93fec9217226b970f71fe561b4c5ce81924e53712fa5e473d5ba47`. Unsigned sequence15 metadata and rollout pin refreshed; activation commitment independently MATCH. Strict scoped Clippy passed; strengthened genuine R3 committed-cut negative/restart test passed3.43s. No signed activation, staging, deployment, reset or TPS load; fifth rejoin remains the gating failure.

Diagnostic runPID91650 was deliberately interrupted during setup (child91652 terminated, no terminal recovery result) after review found native TC verification failures preceded its logging. Extended same bounded cfg(test) diagnostics to native verification rejection, then launched replacement cargoPID92431, `/tmp/r3-h51-diagnostic-complete.log`, exitfile `/tmp/r3-h51-diagnostic-complete.exit`. Production behavior unchanged. Sequence15 immutable staging tool local artifact checks and create-new/path/idempotence guards independently passed; no remote staging or signing. Current recovery result remains pending.


### 2026-10-11 — genuine four-validator finality proven; socket fixture reconnect repaired

R3 incident OPEN/P0; no live recovery claim or validator runtime mutation. Instrumented full test `/tmp/r3-h51-diagnostic-complete.log` FAILED727.45s exit101. Four fixtures passed explicit exact H54 finalized-state equality, applied wallet balance7/nonce1/receipt and retainedmarkers before fifth returned, then advancedH71. Fifth remainedH47/active50/r0 with no decoded H50 TC receipt/native rejection. Logs show outboundconnection4 EAGAIN timeout and inbound buffer failures. Scoped source comparison establishes socketfixture idle60s, fifth allservicespaused longer, production VPN reconnect service omitted; unlike existing socketrecovery fixtures, R3 return loop never requested missingpeer redial.

Corrected fixture-only fifth return/restart to use established immediate/every5s `redial_missing_socket_peers`, matching production VPN's existing authenticated registry redial owner. Focused retention regression compiled/passed13.48s. Production consensus unchanged. Corrected full genuine socket test running cargoPID1072, log `/tmp/r3-h51-peer-redial.log`, exitfile `/tmp/r3-h51-peer-redial.exit`. Native TC admission diagnostics remain bounded and opt-in cfg(test).

Parallel preparation: strict diagnostic Clippy passed3.32s; immutable staging and exactseq14->15 stalledactivation offlineguards independently passed, no signedmanifest or liveactivation. TPSremote signer public binding verified on actualVal2 existingwallet-01; all32 fundedwallet publicfile paths discovered, noprivatebytesread/exported. Harnessremote-native authoring/offlinechecks and6mocktests passed. Reestablished missingVal2SSHmaster once, after authoritative socketabsence; allMac-to-Mac control remainsThunderboltmaster. No transactions submitted. A direct find withoutsudo failedpermission before metadata discovery; corrected using existing owner sudo-n policy.


### 2026-10-11 — fifth peer reconnected but H50 timeout remains undelivered

Corrected socket fixture fulltest `/tmp/r3-h51-peer-redial.log` FAILED771.27s exit101 at socket_qualification.rs3930. Four finalizedH76; fifth synv11p233zx946f89j4afw9kczrk3hsddm5s8l6d remainedF47/active50/r0. Periodic redial confirmed fifth authenticatedpeers4, yet bounded decodedH50TC receipt/nativeverification logs contain onlyfouradvancedowners, nofifth. Reconnection was necessaryfixture repair but insufficient; exact nextbrokenboundary is signedTCretrycache/publish/networkdelivery beforefifthdecodedadmission. No livechange, signing, staging orTPS. Do not claim redialfixedrejoin.

FinalLinuxbuild and strictClippy passed. Candidate7798472bytes SHA3beb03723d21117f8f76e90597257e542eff691f5f86edb00b0ca8fdc0a2b8184 SHA256a8331e2016077da9a9774479288a661f6b6b09817ae50d9420bfe6876fccb441. Unsignedmetadata/rolloutpin refreshed; offlineguards andR3commitmentMATCH. Other-mini master expired, exactsocketabsence verified, bridge0route verified and single replacementmasterestablished. Atlasreportintegration subagent hitusage limit; nocompletionclaim/sourcechangesassumed.


### 2026-10-11 — asymmetric ghost sessions explain failed timeout redelivery

R3 incident OPEN/P0. Delivery-boundary qualification `/tmp/r3-h51-delivery-boundary.log` FAILED773.77s exit101. Four advancing owners retained H50/r0 and H50/r1 timeout retry bytes but authenticated peer inventories excluded the fifth. Fifth active50/r0 reported four stale authenticated peers and verified heads46/47, preventing fixture redial. Source review confirms NetworkSession close can drop Closed on a full bounded event channel; NetworkService finished-thread cleanup removes senders without discarding exact router/ingress sessions. This leaves ghost authenticated entries after socket death. Causal production cleanup and focused exact-session/replacement regressions are being implemented; no deployment or passing recovery claim. Added short genuine signed socket idle-expiry/lease-change regression to avoid repeated H46 setup during causal validation; execution pending. Atlas baseline report source integration verified with three Python tests and frontend TypeScript check; backend check pending. No live validator mutation, reset, signing, transaction submission or workbook changes.


Session cleanup implemented in network.rs: finished-reader and disconnected-sender cleanup discard exact ingress/router sessions; queued authentication cannot resurrect a finished connection; replacement sessions remain intact. All4 network regressions PASS (0.01s); strict scoped Clippy PASS. Genuine signed socket idle-expiry/lease-change retry regression PASS65.41s, `/tmp/r3-short-reconnect.log`, exit0; confirms automatic delivery of retained original TC after actual expiry/reconnect without manual replay. Full H47/H51 wallet/finality/restart qualification now running `/tmp/r3-h51-session-cleanup.log`; result pending. Linux rebuild running `/tmp/r3-session-cleanup-linux.log`; prior artifact pin is stale until refreshed. No signing, activation or live mutation. Atlas frontend and backend TypeScript checks PASS; no Atlas deployment claimed.


Host restart interruption: user restarted other-mini during full qualification; Thunderbolt link became inactive and SSH closed. User unlocked Mac; bridge0 route and single SSH master restored. Previous detached full qualification was interrupted (no terminal result) and /tmp logs cleared by reboot; it is PARTIAL/UNKNOWN, not failed or passed. No VPS validator was changed by this developer-host restart. Restarted full unchanged-source qualification after this corrected host precondition as wrapperPID1358, now persistently logging canonical node-platform/target/r3-h51-session-cleanup.log and exitfile. Linux build already PASSED60s; current artifact7798856bytes SHA3e09a7dbe13cffd73b632ff093fc2c186fb8fc0ab5afc64877fe773156d8651f6 SHA2564bc5a40a2a8a751ea21b0487514e799bfb2b81c95e5ffa36989ae62fa4a3e81b; unsigned metadata/pin refreshed. All9 ETDAG tests PASS7.17s including genuine recovery and consumed exclusion; strict scopedClippy PASS after final source. Temporary prior logs lost in restart; completed tool outputs remain evidence but no qualification manifest fabricated. SSD SMB remounted via existing stored credentials over172.31.77.2; no source copy.


Post-reboot live read-only observation: Val2–6 all active/running, zero NRestarts, exact durable/RPC H47 block6cd3635b2f4505ed244f57cd05d34a72515caa8275124d95e4e331575c377f27 and root65dc252a3d62b7b982c1e15ccf9ecf30e06ce220ab986b32c31e5f61d479ca66. Restored exactly one SSH master per validator and index on other-mini after socketabsence; no validator runtime mutation. Atlas canonical backend bundled and syntax checked; deployed only /opt/synergy/atlas-posy-staff/staffServer.mjs, restarted only synergy-atlas-posy-staff.service, active. Publisher restarted once PID1933, canonical target/atlas-posy-telemetry.log. Authenticated private endpoint HTTP200, baseline20261010, stale=false, TPSfields present. Browser https://atlas.synergy-network.io/staff/posy independently shows Live telemetry/H47/32wallets, accepted/ordered/finalizedTPS0, allfive cards status stalled after30s. Baseline remains pending; zero traffic is not capacity. New baseline summary UI fields sourcevalidated but no frontend deployment claimed. Local SMB-native esbuild execution stalled after remount quarantine; terminated exactchild and rebuilt on backinghost with login-resolved nvmNode24.21.0, no sourcecopy/securitybypass. Full recovery qualification wrapper1358 remains running with persistent logs.


Full post-reboot qualification FAILED710.79s exit101 at4123, canonical target/r3-h51-session-cleanup.log. Unlike prior transport failure, allfive native Sync owners advanced beyondH58 (lastdiagnosticF72); allpeerinventories4 and verifiedheadsadvanced. Remaining test predicate required fifth localR3generation+committedcut beforeF51 while normalSync consumed finalizedhistory first. To preserve ratherthan weaken the explicit retained-generation prefinality restart gate, fixture-only fifthreturn now polls network/ETDAG/PoSy with nativeTCtraffic while holding H50+ nontimeoutPoSyframes and skipping fifthSync until durablecut+restart; then normalauthenticatedretry/Sync resumes. All original generation, marker, commit, prefinality assertions retained. Productionartifact unchanged. No signing/staging/livevalidator change orTPS. Corrected scheduling fulltest pending.

Prefinality scheduling run wrapper2567 child2569 intentionallyinterrupted after fourfinalizedH58 and fifthnativeTC50received but rejected active49/parentQC48. Fixture retained all previouslyheld fifthPoSyframes, including requiredH49QC; skippingSync exposed this predecessor delivery dependency. Correcting hold to retain onlyH50+nontimeout and deliver authentic prior-height certificates/timeouts. No safetyassertionremoved, productioncodeunchanged, no validatorruntimechanges. Prior terminalresult PARTIAL/UNKNOWN because interrupted; notactivationproof. StrictClippyPASS; governedVal2signercustodymode0600/root/4032bytes and matching publicauthority verified read-only, no secretbytes exported/signing.

Review BEFORE rerun found ETDAG prunes historical retryframes at ownfinality(etdag.rs1118-1133), so fifthlocalH51cut reconstruction afterfourF54 was an invalidfixture requirement; verifiedfinalizedSync is nativepermitted recovery and finalizedcut replacement mustremainrejected. R3clauses4/6 independently reviewed: test now restarts an actualfour-quorum R3author BEFOREH51finality, compares completegenerationarray/exactauthorization, retainedmarkers andcommittedbatch immediatelynativeopen; thenfouronlyfinalizeH54/exactwallet. FifthusesnormalverifiedSync, exactH54state/wallet/receipt/originalmarker, thenretainedstaterestart/allfiveH58. No obsoletehistoricalgenerationisfabricated orclaimed, no additionalETDAGhistorydeliveryengineintroduced. Earlierexperimentalscheduling removed. All3/5failclosed/4/5gatesretained; sourcecompile/fullresultpending.

Full separated-author restart qualification FAILED539.84s exit101,target/r3-h51-author-restart-rejoin.log595: fifthfirstnetworkpoll acceptnetworkconnection IoInvalidargument22. Priorassertions passed nativeR3authorpre-finalityrestart exactgeneration/marker/committed equality andfour-onlyH54wallet/exactstate. Source listener.accept conflates actualaccept andacceptedstreamconfiguration. SmallcausalTCPprobe onothermini proved FINaccepted/configured normally; clientSO_LINGER(1,0)RSTbeforeaccept ->actualacceptsuccess,setblockingtruepass,TCP_NODELAYEINVAL22. Thus deadqueuedconnection configuration was escalating toservicefatal whilelistenerhealthy. Scoped fix will classifyacceptedstreamconfigurationfailure anddiscardonlythatconnection withinexistingboundedacceptloop, preserving genuineaccept/listenerfailure. No fullrerun untilfocusedregression; previousLinuxartifactnowwillrequire rebuild afterproductionfix. No livevalidatorchange/signing/TPS.

AcceptedStreamConfiguration classification fix implemented; onlyindividualstreamsetupfailure isdiscarded byboundednetworkacceptloop, genuineIo listenererrors preserved. Portableunit firstpassedthenfullsuite exposed nonblockingacceptqueue race(OkNone beforeconnectqueued); bounded2swait added, all19synergy-network tests PASS0.06s. Initialnodefilterservices::network::tests matched0, correctedburst_tests matches4/4PASS0.00s. StrictscopedClippyPASS. Fullgenuinequalification wrapper3778 target/r3-h51-listener-recovery.log+exit running; Linuxbuildwrapper3781 target/r3-listener-linux-build.log+exit running. Candidateunsignedpinwillrefresh onlyafterbuildsuccess. No releaseauthoritysigned or livevalidatorchange/TPS.

Fullgenuinequalification PASSED602.49s exit0,target/r3-h51-listener-recovery.log:3/5fulltimeoutfailclosed,4/5R3recovery,actualauthorpre-finalityrestart exactgeneration/authorization/history/batch,4onlyH54exactwallet, fifthnormalSync+restart,allfiveH58exactfinalizedexecution/worldstate. All19network+4sessiontests andstrictClippyPASS. LinuxbuildPASS60s7795592bytes SHA3ed2d34d55d845949218c50bac2dedbda77714a9f6e5e8ef149e6a3871159fded SHA256c8b61a65e06484210dabbb7f8bb3c5bbac8ed5ccdf45953ded27b7122016e7d0. Unsignedpin/offlineguards/activationcommitmentMATCH(verificationfirstcalledwithoutrequiredargs exit2,correctedcanonicalargsPASS). Rootreviewed seven-category qualificationmanifestcreate-new r3-qualification.json references exactsource/loghashes+prior9ETDAGnegativepass. Nextauthorizedactions: nativeVal2release signinginexistingcustody;immutablecandidatefilesstage;exactseq14H47fleetpreflight;stopallPID0/editverify/startall;preserveeveryjournal/key/configdata;verifyadvancingidenticalfinality+firstliveappliedtransfer beforeTPS. No protocolcertredesignactivation; userrequestedfewer certificates reviewed separately.

Qualifiedseq15 signed nativelyexistingVal2custody; immutablecandidatebinary/release staged+nativeverifiedall5. Othermini masterexpired;socketabsence+bridge0routeverified thenexactonereplacementmaster3600, noWiFi. Activationwrapper4754 target/r3-live-activation.log FAILEDexit1 afterexactH47preflight stopallPID0/unitverify/startall: Val4restartcountincrease triggeredabort. Actualjournald startupfailure registerposy/loadretainedR2timeoutleaseevidencelimitexceeded. No rollback/journaldeletion. Containedrestartloop bystopall5; independentlyMainPID0everyhost,Val2/4/6failed Val3/5inactive. Data/keys/configbaselinepreserved. Signedseq15 installedunits remain. LivechainNOTRUNNING,TPSNOTRUN. Sourcecausalboundedretainedhistoryloaderinvestigationstarted; donotblindlyraiselimit/reset.


### 2026-10-11 — retained-timeout loader repair and sequence16 staging

R3 incident remains OPEN/P0; fleet last verified intentionally stopped at identical H47 after sequence15 startup failed closed. Root cause: R2 loaded/budgeted entire lease including active-height retained TC tail before filtering historical evidence. R2 now selects older slots before bounded loading; R3 resolves required ancestry using exact native-verified slots, with bounded RAM cache and original proof checks. No journal deletion, quorum/signature change or protocol amendment. Five timeout-store tests PASS0.15s including unrelated oversized tail, required invalid/missing proof and original namespace/integrity limits; initial parallel-test path collision corrected with test-only atomic fixture uniqueness, standalone failing test PASS before full rerun. Strict Clippy PASS. Linux build PASS; sequence16 ELF7781576bytes SHA3 `8850162e502467e75e661c9817fd8bc6a8f7aa63343bd21f7461621f7c8cd003`, SHA256 `28163ae00b86defe4db3a0c195961b65220a2e03d1cd35458e3999fdb5691cb3`. Genuine authenticated H51 recovery qualification running: target/r3-retained-h51-recovery.log, terminal result PENDING. Sequence16 signed natively existing Val2 custody, immutable candidate/release staged and native signature/artifact verified all five; no services started. Canonical signed-envelope write initially failed bytes/text TypeError leaving empty file; exact zero-byte partial file repaired in place from a second native signing result and metadata equality verified. Sequence15 files retained unchanged. Stopped-fleet guarded activation tools offline tests PASS; qualified hash pin/manifest and runtime activation await full result. Live chain NOTRUNNING; TPS NOTRUN.


### 2026-10-11 — sequence16 live recovery and first applied transfer verified

Full genuine H51 retained-loader recovery qualification PASS628.01s exit0 (target/r3-retained-h51-recovery.log); root-reviewed artifact-bound canonical r3-retained-qualification.json created. Guarded sequence16 activation PASSexit0 after two exact stopped H47/native signed sequence15 snapshots, stopallPID0, native stagedsignature/hash/unit verification, then startall. Four matching advancing finality gates H48,H53,H80,H94; allfiveactive, zero automaticrestarts. First live H51 transfer appliedidenticalallfive: block `6128509cf9e849658a72fe5e42600d9fad99195ad44c384a79a430988c185970`, state `a6536dccd9df3bdb70dcc3505f824a522ec439efe221b3bbe97712ffbf6a2e73`, tx `2cc625115d20f18156597e6b4159f2759b75e815baf7a1ecef91cd81c42d5950`, receipt applied/gas21000/noerror. Subsequent fiveobservations matching finalized history H182, zero restarts; Atlas publisher observed allfiveH211 thenH217/218. Node keys/history/config preserved, Val1 untouched. TPS harness firstcall rejected relativeoutputpath beforehostcalls; corrected absolutepath attempt failedpreflight val3readyfalse, report tps-baseline-1tps-30s.json has failureonly/no transaction submissions. Subsequent chainadvancedH189allready but Val4 admissioncontexttemporarilyunavailable. Bounded sampler repair is in progress; baselineTPS remains NOTMEASURED. Do not conflate recovered advancing fleet with completed live restart/rejoin soak or TPS.


### 2026-10-11 — bounded ETDAG primitive cache qualification, sequence17 preparation

Sequence16 livefleetcontinuesadvancing zero restarts, AtlasallfiveH334. TPSattempts beforeload failed readiness/contexttransitions and nodeStatusRPCtimeout; all three failure-only reports contain no submittedtransactions. Sampler nowretries only exacttransition errors up tooriginal5sRPCbudget, keepswrongchain/quorum/root/F+5/stalllimits, uses alreadyverifiedsampledcontext toavoidfreshcontextvsoldtiprace. Val3loopback nodeStatusmeasure includes5.225sreadyfalse (notSSHlatency); sourceRPCblockingparser architecturalrisk identified but noidleconnections observed, no broadRPCrewriteactivated. NativeETDAGduplicateverification proven in certificatepath: availabilityvalidation followed constituentvotevalidation. authority.rs exactsuccess-only boundedcache reuses existing primitivecache afterfrozenkey/status/algorithm checks; all certificateauthority/quorum/context checksretained. Threecachetests PASS0.53s, nineETDAGtests PASS6.99s, genuinewalletauthenticatedsocket PASS112.58s, strictClippyPASS, LinuxbuildPASS62s. Initialtestfixture minimumvalidator failure corrected tofive testidentities beforepassingrerun. Sequence17 artifact7783176bytes SHA3 `fabd22210e371020c4571a9a4c1d46c96967825c370a8841635b6e89f1fcdd9b`, SHA256 `28eab9b8486391e1c26e4f190338cee342c6cc0faf9f15602ab99f940e34b78e`; nativeVal2custodysigned, staginginprogress. SameR1/R2/R3activationcommitment; nosemanticamendment. PlannedVal5pilotretainedstaterestart/rejoin thencompatiblequorumpreservingrollingupgrade; performanceimprovement/TPS remainunverified. Priorseq16fullrecoveryqualification retainedasitsownartifactevidence, notmisreportedasseq17fullR3rerun.


### 2026-10-11 — sequence17 all-five restart/rejoin verified; RPC isolation qualification

Sequence17 Val5 retained-state restart/rejoin PASS through H763/H783, followed guarded quorum-preserving Val3/2/4/6 upgrades with matching advancing finality H941,H960,H1001,H1018, zero automatic restarts; target/r3-etdag-cache-rollout.exit=0. Every validator now has a genuine live retained-state restart/rejoin proof. Baseline attempt tps-baseline-cache-1tps-30s.json failed before submission on protected admission context RPC timeout; TPS remains NOTMEASURED. Blocking HTTP reads/writes in the shared managed-service poll loop are a confirmed architectural defect, not yet proven sole cause of observed loopback delays. rpc.rs now retains bounded nonblocking HTTP connections, absolute deadlines and partial responses; existing handler work remains synchronous, no protocol changes. Causal idle/partial-body vs healthy HTTP test and split WebSocket handshake/ping/disconnect tests PASS (2/2,0.01s). Wallet integration initially failed because test helper assumed a single blocking poll; fixture changed to nonblocking reads with bounded service pumping, rerun pending. Strict Clippy initially rejected unnecessary usize cast, corrected. Linux build and genuine wallet qualification pending; no sequence18 signing/staging/live activation yet. Keys, journals, Val1 and workbook preserved.

Sequence18 qualified: HTTP/WebSocket2testsPASS0.01s; genuinewalletsocketPASS114.59s after causal fixturepump correction; strictClippyPASS; LinuxbuildPASS57.10s. ELF7785704bytes SHA3 5e359fa39688198586e5ddb3b755e5058012e8d905b666aeb87e3e83c0226e34 SHA256 42c288ccad433c49d8cbc653de0838042d02ee77727dc38c253a7297b5a89d9f. Canonicalunsignedmetadata/pin updated, existingVal2custodynativesigned canonicalenvelope; stagingallfive underway. SameR1/R2/R3commitment, floor17, no protocolchange. AuthorizedVal5pilotthenquorumpreservingrollingupgradeplanned; TPS onlyaftermatchingadvancingallfiveproof.

Sequence18 live rollout PASSexit0: Val5pilotH3140/sustained3163, Val3rejoin3327, Val2rejoin3372, Val4rejoin3416, Val6rejoin3470; allfiveAtlas3476 zero automaticrestarts. Baseline rpc-isolated attempt passedRPC sampling but preflight failed cadence outside0.5–1.5s beforetxsubmission. Performancegoal now measured explicitly using new --measure-outside-cadence-target flag (default remainsstrict), reportseparatecadence_target_met; originalquorum/hash/state/6sfinalitystall/30stxdeadline retained. Offlineharness+6mockHTTPtestsPASS. New boundedmeasured1TPS30sattempt underway, resultpending. Livequorumlossprocedure prepared/offlineguardsPASS, notexecuted.

Postseq18 baseline evidence: initialcadencegatefailedbeforeload; measuredattemptstatsRPCtimeoutwasbudget-shrink samplerdefect (eachrequestnoworiginal5s, transientretrybounded); nextattemptVal3ingresscontexttemporarilyunavailable despiteverifiedadvancingfinality. Sampler nowrequiresliveF+5ingressonlysubmittingVal2 andobservesnon-submitcanonicaldurableheight+RPChash/state/cert withsame2blockbound/domain. LatestBlocknullAPI unsupported; correctedtoexistingAtlasdurablepointermethod, notnewRPC. Preflightcadencemetadatafirstincorrectfleetdictshape producedTypeError beforeload; fixednestedmetadata+regression. AlignedheightobservationsnowreadallfivepublicdurablepointersafterRPCsampling toavoidstalecontextvsfreshpeerfalse spread. Nativeauthoring initiallypointedoldreleasekeytoolwithoutwalletcommand; existingrootownedELFwallet-admissionkeytool verified5269352bytesSHA2567b440ff52393b5b4957ae43b1ed744def674d2385495b698af7caddb03678b5b, runnerpathcorrected. Firstloadqueuedone tx0b95b24c9ae6261daf681989daaf08da36bbace25d31d7b23fa2e232417e3085 nonce0, rejectedbeforeadmission; nofinalizedTPSclaim. Reportnowretainstarget/receipt/rejectionreason. Hotpathrefreshescontextimmediatelybeforeauthoring withVal2sourcefinality; allfivesourceproofretainedatfinalization. Pendingtxlookupgatedoncommontipreachingtarget topreventguaranteednegativefullhistoryscans. Eightmocktests+offlinePASS; freshadmissionbaselinepending. Noquorum/protocol/journalchanges.

Baselinecurrentloadboundary: correctednativewalletcommandqueuestransactionbutETDAGrejects freshlocaladmissionclosed (bounded-snapshot reporttarget4068, nonce0, txe9665e66e28ae89f7e009d888b969012223f1f9579ec167b4cba6a61ad3b71ca). Nativeauthoringmeasured0.439s; waitnewtargetwindowattempt insteadRPCsubmissionerror beforequeue response, noresultclaim. No repeatedunchangedattemptplanned. Chainallfivecontinuesadvancing >H4133. Livequorumrecoverytest nowauthorizednextindependentvalidation, exactseq18guardsandcleanupinplace; target/live-quorum-recovery-seq18.log planned. Preservealljournals/config/identities; Val1untouched.

Livequorumloss/recovery seq18 PASSexit0,target/live-quorum-recovery-seq18.log: all5preflightH4194nativehash/unit/domainverified; exactVal5+6stopPID0; after20ssettle+10sobservation remaining3identicalstationaryH4200block0837a566a1cf55525d03caec4643ce8ab0b053da2bf56827b58b86dc7a12f0ff/statea6536dcc...; startVal5 restored4matchingcommonfinalityH4201 automatically; startVal6 all5advancingverifiedcommonH4225 thenAtlasall5H4243. Allzeroautomaticrestarts; noreset/historyloss/TCinjection/manualreplay. SourceTPSfirstbrokenboundary nowconfirmed same-tickstalecontext: ETDAGpublishopentarget→PoSyverifiedVCcloses→RPCcachedcontextserved. NarrowAdmissionHandlelivecutoffguardimplementedbyagentpendingqualification, nosemanticamendment. AtlaslivequorumcardhistoricalPASSupdateinprogress; sustainedsoakpending; baselineTPSstillNOTMEASURED.

### 2026-10-11T17:20:06.469419+00:00 — sequence 19 live admission cutoff guard qualified

Confirmed same-tick ETDAG cached-context/PoSy verified-cutoff race. Bound AdmissionHandle to existing authenticated ingress; context retrieval and fresh enqueue consult live verified cutoff, preserving duplicate receipts and final ETDAG cutoff enforcement. Genuine signed VC regression: 2 tests pass. Real wallet authenticated five-validator socket transfer: PASS111.23s. Strict Clippy PASS; native Linux build PASS58.41s. Signed sequence19 same R1/R2/R3 activation commitment; ELF7792488bytes SHA3 eb7c8182c971b7d3bc893fa7c8b2fec50c095520efa366a825cbd4d9ef84fdb3. Staging underway; live deployment and TPS baseline not yet established. Runner exact closed-context transient classification qualified with10 offline tests; submission rejection remains fatal.

## C1266-2026-10-14-FAUCET — Testnet v3 Genesis faucet transaction admission

Status OPEN; operational repair for the running chain-1266 authority on Val1. The user confirmed that PoSy and ETDAG are not active on this chain and authorized a narrowly scoped current-chain admission upgrade and authority restart to enable the funded faucet, without a Genesis reset. The public Forge faucet remained gated because its legacy upstream advertised chain 1264.

Pre-change evidence: the Val1 authority was active with PID 2333034, zero automatic restarts, and advancing finalized head above height 3,249,645. The chain context was chain ID 1266, incarnation 5, Genesis hash `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`. Genesis funded ECO-A02 `syns10a8prj2pvm3lwtd2zf8ke54zhq8ux3804kl2` with 1,000,000,000,000,000 nwei; its FN-DSA encrypted custody bundle and passphrase were located in the testnet-v3 identity archive and the node-machine credentials workbook. No secret bytes were logged.

The current runtime rejects public transaction submission at the RPC guard and accepts only ML-DSA account Aegis carriers in the execution path; plain transfers and DAG/batch submit routes remain gated. A source patch on release branch commit `be59ca4` adds only a signed-Genesis-address FN-DSA carrier exception and enables `synergy_submitAegisTransaction` when the loaded canonical Genesis binds this chain. A purpose-built signer verifies the custody identity and caps each payout at 10 SNRG. Local `cargo check` and the focused RPC exposure test passed; a real custody signing-envelope check passed without broadcasting. Exact matching source files were staged on Val1 and the Linux release build passed, producing authority SHA-256 `e12e2c4daaa7556dc2dc0f1e9f81ee8650fa256c0d2f3f68a89ebd91b621ef4e` and signer SHA-256 `3dd55108c9da58c73ea4c186b939caafc06279da165187ee6ac952cf852af523`. The pre-change installed authority SHA-256 is `dc40b4044a63599f8d3b6fbee782e3f1e34b77b9d2db5f25e1c0d0d7f1b61143`.

Next gate: retain the installed binary for rollback; perform one guarded authority restart with durable-head and state checks; submit one signed, bounded canary; verify an applied receipt and recipient balance before enabling the public faucet. No on-chain payout or completed activation is claimed in this entry.

### 2026-10-15 00:06 UTC amendment — guarded upgrade and canary outcome

The guarded `be59ca4` authority cutover completed after durable-history replay: `/root/chain1266-faucet-cutover.log` reports `CUTOVER_PASS` and advancing height 3,253,790. The installed authority SHA-256 is `e12e2c4daaa7556dc2dc0f1e9f81ee8650fa256c0d2f3f68a89ebd91b621ef4e`; the prior binary remains preserved at `/usr/local/bin/synergy-validator-node.pre-faucet-be59ca4-20261014`. At 00:06 UTC the service was active, PID 2180500, `NRestarts=0`, finalized height 3,255,053, block ID `cf956cddc988065f9c0e12c3d351cc8d62cffbc2ba651ca5a90a8fd3ebf105dc`. No signing conflict was observed in the guarded cutover.

A bounded 1 SNRG canary from the Genesis-funded ECO-A02 account was accepted and durably finalized in block 3,254,301. The canonical execution snapshot shows the recipient balance increased to 1,000,000,000 nwei and the sender balance decreased to 999,998,999,799,960 nwei; the durable receipt reports `SUCCESS`, gas used 21,000, and the transfer's fee. This proves on-chain settlement, but the public receipt, nonce, and balance methods still read legacy state and reported null, zero, and zero. Faucet cutover therefore remained gated. Runtime commit `90fb15e` now projects these reads from finalized execution state, the recovered committed nonce index, and the bounded durable receipt tail; it also updates public Testnet v3 labels. Local `cargo check --lib` and the focused finalized-head RPC test passed. The next required action is a guarded build/restart of that commit, followed by receipt/balance/nonce verification and a second payout through the actual faucet service before public cutover.

### 2026-10-15 UTC amendment — canonical read-path cutover and live faucet payout

The guarded deployment of `90fb15e` on Val1 installed authority SHA-256 `123884913335b1156d1fc67892eb6ec0a6cb028459e7074ad2599a247473d72a`. Durable history replay completed, the service stayed active with zero automatic restarts, and finality advanced past height 3,255,398. The cutover script reported failure only because the generic RPC wrapper placed a successful finalized receipt in `error.data` when its receipt object included an empty `error` field; no rollback was attempted after the authority resumed finalizing. Canonical balance, nonce, and receipt reads were verified against the 1 SNRG canary. A source-level wrapper fix changes that receipt field to `executionError`, but is not yet deployed; preserve this compatibility caveat for clients.

Forge faucet service commit `585201a2` accepts only a matching finalized successful receipt from that compatibility field. One live public 10 SNRG request to `synw1zp7cxme7xm838663yrd43lxtxlw0ck90z4am` finalized as `syntxn-441013965ff89449f66d0d62b0f3efacb42d595f23ff13ddddd74efa7fe3241a`. The v3 faucet replaced the chain-1264 PM2 process on the established public hostname. Live direct and Forge GET routes reported chain 1266 and the funded ECO-A02 balance; repeat POSTs returned HTTP 429 cooldown. No further payout was sent.

## C1266-2026-10-20-001 — Single-authority signed-slot replay conflict at height 3556906

**Status:** Open  
**Severity:** P0 chain liveness  
**Detected:** 2026-10-20 03:54 UTC  
**First bad height:** 3556906  
**Last agreed finalized height:** 3556905  
**Last agreed finalized block ID:** `f67e0504769bc3ecb8d39a445cb987a6f74ba282cbb89a4c91201b5a3ef139f9`

### Affected and responsible nodes

Val1 `synergy-chain1266-authority.service`, Chain 1266 incarnation 5,
`single_authority_v1`. The public RPC, Atlas ingestion, STS activation and all
new transaction ingress remain downstream of this stopped finalized tip. No
other validator is responsible for the single-authority failure.

### Symptoms and evidence

The installed authority binary remains SHA-256
`123884913335b1156d1fc67892eb6ec0a6cb028459e7074ad2599a247473d72a`.
Systemd reports 100 automatic restarts, approximately 19.3–22.5 GiB peak
memory per full-history startup, and repeated process exits after about
15–17 minutes. The authority log repeatedly fails closed with:
`single-authority height 3556906 is already bound to a different signing
subject; refusing to authorize a second block for one height`.

The durable finality head and committed-block tail agree at height 3556905,
block `f67e0504...39f9`, state root
`fd980674eec186a86c6a0ed37b3af39310511218ac7b5251c8e9bbbf933dd441`.
The compact signing journal already contains a verified ML-DSA-65 signature
for height 3556906, parent `f67e0504...39f9`, canonical block hash
`2ef836db353bd0df214a38f978de4500975d3b902221ed6a1a62d78001785430`,
and signing-payload digest
`daddbfb1a9add66fc6f9f35779b5958c98835d783ddda00ef8dfd65064e4379d`.
Its hot state correctly remains `finalized_through: 3556905`. No height-3556906
committed block or finality record exists.

### Confirmed cause

The immediate safety boundary is confirmed: startup reaches the already-signed
active slot, but `produce_next_block` constructs a new block with the current
wall-clock timestamp before consulting the sign-once journal. The resulting
block hash differs from the durable signed subject, so the journal correctly
rejects a second subject. Exact reconstruction/replay of the already-authorized
block remains to be proven before repair; the signing guard must not be bypassed
or the journal edited to permit a new signature.

### Recovery actions and outcomes

1. **Read the complete incident ledger and captured service, finality-head,
   committed-tail, signing-journal and binary evidence through one persistent
   Val1 connection.**  
   **Outcome:** the chain is safely stopped at one finalized parent with one
   durable signed successor subject. No service, binary, journal, chain state,
   Genesis, key or configuration mutation occurred.
2. **Stopped only `synergy-chain1266-authority.service` to contain the repeated
   19–22.5 GiB full-history recovery loop.**  
   **Outcome:** the unit is inactive/dead with `MainPID=0`; approximately
   22 GiB is available. Finality, committed bodies, receipts, execution state,
   signing journal, Genesis, custody and installed binary remain unchanged.
3. **Implemented source-only exact-candidate durability and replay in the
   existing release worktree.** Each new unsigned block body is atomically
   staged before sign-once authorization. Restart loads and verifies that exact
   height/parent/hash/payload/binding before replaying the durable signature.
   The pre-existing orphaned height 3556906 may use only a bounded empty-block
   timestamp reconstruction that must equal the already-signed hash; all other
   legacy bodies fail closed.  
   **Outcome:** compilation and crash-after-signature regression are in
   progress; no binary has been installed and the authority remains stopped.
4. **Prepared to stage the two reviewed repair source files into the existing
   Val1 `/root/launch-src` build tree for Linux compilation and focused tests.**
   The remote files were first proven byte-identical to the release-worktree
   base revisions; the existing SSH multiplex connection will be reused.
   **Outcome:** this is build-source staging only. The installed authority
   binary, service, chain data, journal, Genesis, keys and configuration remain
   unchanged, and the authority remains stopped. Local compilation was unable
   to proceed on the SMB-backed workspace because that filesystem does not
   support Rust incremental lock files, so validation is moving to Val1's
   existing native build cache with `CARGO_INCREMENTAL=0`.
5. **Compiled and tested the exact-candidate repair on Val1's Linux build
   host.** The five first-block/restart cases passed, including exact
   reconstruction of live height 3556906 at timestamp `1792359665`, replay of
   a legacy signed orphan without re-signing, and replay of the new staged
   candidate format. The complete focused `single_authority` suite passed:
   96 passed, 0 failed. Source checksums matched the canonical worktree before
   compilation. **Outcome:** validation passed; only pre-existing compiler
   warnings remain. No release binary has yet been installed and the authority
   remains stopped.
6. **Prepared the validated Linux release for an atomic authority install and
   one guarded recovery start.** The release artifact reports Synergy Testnet
   Node v20.0.0, is 47,009,448 bytes, and has SHA-256
   `80135fca6635fa4eed15a1df02dc9683634335e573b231fc5c6be84938293067`.
   The still-installed v20.0.0 binary remains 46,970,160 bytes with SHA-256
   `123884913335b1156d1fc67892eb6ec0a6cb028459e7074ad2599a247473d72a`.
   **Outcome:** build provenance and artifact identity are recorded before the
   install. The next action is an atomic replacement followed by exactly one
   service start; no chain data, journal, Genesis, keys or configuration will
   be rewritten.
7. **Atomically installed the validated release and started the authority once
   at 2026-10-20 21:22:55 UTC.** The installed SHA-256 is
   `80135fca6635fa4eed15a1df02dc9683634335e573b231fc5c6be84938293067`;
   systemd reported `active/running`, `MainPID=492763`, and `NRestarts=0`
   immediately after start. **Outcome:** full-history replay is in progress.
   Do not restart again during this observation window. The durable head and
   signed journal have not been manually altered.
8. **Completed the guarded full-history replay and exact signed-slot recovery.**
   At 2026-10-20 21:39 UTC the same service process remained active with
   `NRestarts=0` and resumed advancing finality. Canonical RPC returned height
   3556906 as the exact pre-existing signed block
   `2ef836db353bd0df214a38f978de4500975d3b902221ed6a1a62d78001785430`,
   parent `f67e0504769bc3ecb8d39a445cb987a6f74ba282cbb89a4c91201b5a3ef139f9`,
   timestamp `1792359665`, with zero transactions. Two observations three
   seconds apart advanced from height 3556922 to 3556925; the signing-journal
   compact file contained no pending entries or safety halts and its hot state
   subsequently reported `finalized_through: 3556941`. **Outcome:** the
   already-authorized subject was finalized exactly once, no second subject
   was signed, and successor finality resumed. A controlled retained-state
   restart proof remains required before closing the incident.
9. **Verified the controlled retained-state restart and sustained recovery on
   2026-10-23.** The authority remained on the process started at
   2026-10-20 21:40:01 UTC (`MainPID=497934`, `NRestarts=0`) with installed
   SHA-256
   `80135fca6635fa4eed15a1df02dc9683634335e573b231fc5c6be84938293067`.
   Canonical loopback RPC bound the running node to chain ID 1266,
   incarnation 5, and Genesis hash
   `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`.
   Two observations four seconds apart advanced finalized height from 3741799
   to 3741803. The compact signing journal contained no entries or safety
   halts and its hot state subsequently reported `finalized_through: 3741822`.
   **Outcome:** retained-state restart recovery and sustained successor
   finality are proven without rewriting history, Genesis, keys, or the
   signing journal. The incident is closed; STS activation is tracked as
   separate deployment work.

### Final outcome

Resolved. The repair deterministically reconstructed the exact signed
height-3556906 block, verified and finalized the already-authorized subject
once, resumed successor finality, and passed a retained-state restart with
sustained finality and no automatic restart.

### Residual risks and next observation

Continue preserving the signed journal, exact recovered block, Genesis, keys,
and finalized history. The installed repair and crash-after-signature
regression remain required for future releases; never reset or truncate this
history as an operational shortcut.

### Source evidence

- Val1 `/var/log/synergy/chain1266-authority.log`
- Val1 `/var/lib/synergy/node/data/consensus/chain-1266-incarnation-5/`
- `runtime/src/consensus/single_authority_driver.rs`
- `runtime/src/consensus/single_authority_signing_journal.rs`

---

## C1266-2026-10-23-STS-001 — Activate Synergy Token System on single authority

**Status:** In progress  
**Severity:** P0 release activation  
**Detected:** 2026-10-23 07:01:35 UTC  
**First bad height:** Not applicable; this is a feature activation on an advancing chain  
**Last agreed finalized block ID:** To be captured immediately before the guarded restart

### Affected and responsible components

- `synergy-chain1266-authority.service` on `synergy-val1`.
- The Chain 1266 STS execution path, finalized read-only STS RPC, public native
  Aegis transaction ingress, and `synergy-sts` CLI.
- This is not validator misconduct. The deployed v20.0.0 runtime still binds
  STS to legacy chain 1264 metadata and lets a legacy standalone STS snapshot
  shadow consensus-owned finalized execution state.

### Symptoms and evidence

- The live native RPC reports Chain 1266, incarnation 5, network
  `synergy-testnet-v3`, and Genesis
  `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`.
- Before activation, `sts_getNativeAsset` reports the legacy chain 1264 STS
  identity, so token creation must not be attempted against the deployed
  authority.
- The public native RPC reaches the typed
  `synergy_submitAegisTransaction` validation path, but the existing CLI does
  not enforce the exact Chain 1266 identity, receipt success, or finalized
  token visibility before reporting success.

### Activation actions and outcomes

1. **Bound STS to Chain 1266 and network `synergy-testnet-v3`, while preserving
   the `synergy-sts-v1:` wire prefix and explicitly rejecting legacy chain
   1264/generic-testnet semantics.**  
   **Outcome:** source and unit tests pass; no transaction has been broadcast.
2. **Changed single-authority STS RPC reads to the consensus-owned finalized
   execution state and prevented the legacy standalone snapshot from
   shadowing it.**  
   **Outcome:** focused STS RPC tests pass, including finalized-state source
   selection.
3. **Hardened `synergy-sts` submission with exact chain/incarnation/network/
   Genesis and Aegis-capability preflight, local and RPC envelope verification,
   finalized receipt validation, and post-create token lookup.**  
   **Outcome:** all six CLI tests pass. Focused Aegis admission, role-runtime,
   launch-identity, public-gateway, and retained-state tests also pass.
4. **Built the exact staged source on Val1 with Cargo locked dependencies.**
   Source SHA-256 values match the canonical release worktree. The candidate
   validator is v20.0.0, 45 MiB, SHA-256
   `7e801d60edb54093b31f5e98e13f39a560d911f03af8cfeea6b137ee99a2e196`;
   the candidate CLI is v20.0.0, 12 MiB, SHA-256
   `d287be9cff510ea2f7054faf831ad1790eac5caa7d5a553bfc649003f12fd9ce`.
   **Outcome:** optimized build completed successfully. The running authority
   remains unchanged at PID 497934, `NRestarts=0`, pending one guarded install
   and restart.
5. **Atomically installed candidate
   `7e801d60edb54093b31f5e98e13f39a560d911f03af8cfeea6b137ee99a2e196`
   and started the authority once at 2026-10-23 07:02:09 UTC.** The prior
   installed binary was moved intact to the one rollback path
   `/usr/local/bin/synergy-validator-node.pre-sts-80135fca`.
   **Outcome:** full retained-history replay completed on PID 1648355 with
   `NRestarts=0`; finalized height advanced from the pre-restart 3745528 to
   3745828 in a four-second observation, the signing journal remained empty,
   and STS reads became available from
   `finalized_chain1266_execution_state`. The response correctly reported only
   native SNRG before the first STS token, but its replay metadata incorrectly
   reported height 0 and the Genesis hash.
6. **Corrected finalized STS read metadata to bind the durable
   single-authority finalized-head height and block hash, not the compact
   in-memory chain placeholder.**
   **Outcome:** the four focused STS RPC tests pass. The rebuilt v20.0.0
   validator candidate has SHA-256
   `49369281473320ec27031cb2031360ff21824620bfff4885a8943d95a27d5d57`.
   One final guarded retained-state restart is required to install and prove
   this metadata correction.
7. **Activated the exact STS network domain in the Atlas indexer.** The
   canonical TypeScript source now accepts only chain 1266 and network
   `synergy-testnet-v3`. A full local build was rejected for deployment because
   it lacked newer live RPC-tail changes; the original indexer was restored
   immediately. The first upload also had owner-only permissions, causing
   three automatic service restart attempts before restoration; no chain or
   database state was lost. The deployed live artifact was then changed only
   at the two network-domain constants, preserving its working bounded RPC
   ingest path. Its SHA-256 is
   `a7d00e2b6effff0537d54ef7ec0253fb6962454fdf9769d399d570b0a271db34`.
   **Outcome:** `synergy-testnet-v3-atlas-indexer.service` is active on PID
   2035585 with `NRestarts=0` since the successful start and is indexing
   advancing Chain 1266 block ranges. The pre-change artifact is retained as
   one rollback file.

### Required completion evidence

- Record the exact pre-restart finalized head and installed/candidate hashes.
- Atomically install once, restart once, and wait for full retained-history
  replay without a second restart.
- Prove the same Chain 1266 identity, advancing finalized tips, empty signing
  journal/safety halts, and finalized STS read source.
- Prove the public gateway and v20.0.0 CLI preflight against the deployed
  runtime without broadcasting a real token transaction.
- A real create/transfer canary remains a separate explicit-approval gate.

### 2026-10-23 16:25 UTC amendment — runtime and CLI activation verified

8. **Installed the finalized-head metadata correction and performed the one
   guarded retained-state restart.** Immediately before the restart, finalized
   height was 3746309. The installed v20.0.0 authority now has SHA-256
   `49369281473320ec27031cb2031360ff21824620bfff4885a8943d95a27d5d57`.
   **Outcome:** `synergy-chain1266-authority.service` has remained
   `active/running` on PID 1655202 since 2026-10-23 07:32:38 UTC with
   `NRestarts=0`. A later four-second observation advanced finalized height
   from 3774442 to 3774446. The signing journal contained zero entries and
   zero safety halts; its compact hot state reported finalized-through 3774429.
   No fatal, panic, signing-conflict, safety-halt, or OOM line was observed
   after this start.
9. **Verified the finalized STS runtime boundary on the live authority.** The
   node reports chain ID 1266, incarnation 5, network
   `synergy-testnet-v3`, and Genesis
   `2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74`.
   `sts_getTokens` reports source `finalized_chain1266_execution_state`, a
   current finalized height and block hash, and exactly one native SNRG entry
   before the first user-created STS token. **Outcome:** the legacy snapshot
   no longer shadows consensus-owned finalized state and its metadata is no
   longer pinned to height zero or Genesis.
10. **Installed and exercised the v20.0.0 `synergy-sts` CLI without a chain
    mutation.** `/usr/local/bin/synergy-sts` has SHA-256
    `d287be9cff510ea2f7054faf831ad1790eac5caa7d5a553bfc649003f12fd9ce`.
    `--version` and `native-info` passed against Chain 1266. An offline
    token-create exercise correctly rejected an unbounded default mint
    authority, then succeeded with `--no-mint-authority`, producing a valid
    deterministic Chain 1266 B1 payload, token address and fee estimate.
    **Outcome:** authoring and safety preflight work; no transaction was
    submitted or broadcast.
11. **Verified both public RPC hostnames.**
    `https://testnet-rpc.synergy-network.io` and
    `https://rpc.synergy-network.io` returned the exact chain identity,
    advancing finalized height, native SNRG, and finalized STS token state.
    A deliberately malformed `synergy_submitAegisTransaction` request reached
    native envelope validation and was rejected for the missing envelope. The
    legacy `synergy_sendTransaction` route remained denied/fail-closed.
    **Outcome:** the public gateway exposes the intended native path without
    accepting a legacy or malformed transaction.
12. **Verified the Atlas materializer after the scoped domain patch.** The
    live artifact remains SHA-256
    `a7d00e2b6effff0537d54ef7ec0253fb6962454fdf9769d399d570b0a271db34`.
    PostgreSQL terminated one connection with administrator-command code
    `57P01` at 06:32:31 CDT; systemd restarted the indexer after five seconds.
    **Outcome:** the same patched artifact is currently `active/running` on
    PID 2048961 with `NRestarts=1` and continuously indexed through heights
    3774411--3774452 during the final observation. The restart was a database
    administration event, not a reverted STS patch or chain-state loss.
13. **Pushed the activation source and repaired the public CLI release path.**
    Commit `4be183d55cc3123674526c0e1ca76dc34caa4ebb` contains the Chain 1266
    STS activation. A workflow-only default-branch PR added the manual release
    entry point without merging the release branch's divergent history. The
    first run, `39985595881`, failed before compilation because the locked
    sibling SynQ tree was absent; no release was created. Commit
    `3d877dd180d0ba67a75d93fe3249a2ce25f2be38` adds the same exact locked
    dependency checkout used by the immutable Chain 1266 release workflow.
    **Outcome:** replacement run `39986046460` passed dependency checkout on
    the active Linux AMD64, Linux ARM64, and macOS ARM64 runners and is
    compiling; macOS AMD64 is queued. Publication remains pending this run's
    terminal result.

**Activation status:** The STS runtime, finalized read path, public ingress,
CLI authoring path, and Atlas materializer are activated and live-verified.
The only intentionally unexecuted acceptance boundary is the first real
token-create and transfer canary, because that mutates Chain 1266 and remains
behind explicit approval.

### 2026-10-23 19:53 UTC amendment — local CLI build and release verification

14. **Stopped relying on GitHub Actions for subsequent CLI builds at the
    operator's direction.** Run `39987352360` had already reached a terminal
    success before its cancellation request was accepted and had published
    the immutable `synergy-sts-v20.0.0` release. Its four Unix assets were
    therefore left intact; they were not deleted or overwritten.
15. **Built both macOS architectures locally on the Mac mini from the
    canonical release worktree and locked dependency graph.** The Apple
    Silicon binary is v20.0.0, Mach-O arm64, SHA-256
    `af5fa11a44b56d89b5991aa4a0d438544a6115056005f715f0dd386cbff330c0`.
    The Intel binary is v20.0.0, Mach-O x86_64, SHA-256
    `48a439fc5e2ce1ac4e16c97a07de70a552d59b490d33b0e6ddf4bc74a899d89c`.
    **Outcome:** the Intel binary executed successfully through Rosetta and
    both architectures reported the correct Chain 1266 native asset against
    `https://testnet-rpc.synergy-network.io`.
16. **Retained the locally built Linux AMD64 artifact already installed on
    Val1.** `/usr/local/bin/synergy-sts` remains v20.0.0, ELF x86_64, SHA-256
    `d287be9cff510ea2f7054faf831ad1790eac5caa7d5a553bfc649003f12fd9ce`.
    The Ubuntu host `synergy-dev-tower` was verified as Ubuntu 26.04 x86_64,
    but it does not mount the canonical SSD and has no Rust toolchain, so no
    duplicate source checkout was created there. **Outcome:** the Val1 Linux
    binary queried finalized STS state successfully at height 3784479.
17. **Attempted a local Windows AMD64 cross-build on the Mac mini using
    Rust's `x86_64-pc-windows-gnu` target and Homebrew MinGW-w64.** The build
    reached the upstream `pqcrypto-sphincsplus` C sources, which include the
    Linux-only header `features.h`; MinGW correctly rejected that source.
    **Outcome:** no cryptographic compatibility bypass was introduced and no
    unverified Windows executable was published. A native Windows-tower build
    remains required for the Windows asset.
18. **Exercised the published shell installer in an isolated install
    directory.** It selected `synergy-sts-macos-arm64`, verified the published
    checksum, installed v20.0.0, passed its post-install smoke check, and
    returned the exact Chain 1266 / `synergy-testnet-v3` native metadata from
    the public RPC. The installed release asset's SHA-256 is
    `af1dcdfa665a3c0f73692b10279e55991155ac100a0ad7c92568d6caa424d0eb`.
19. **Repeated the live service boundary checks after local builds.** At
    19:53 UTC the authority remained active on PID 1655202 with `NRestarts=0`
    since 07:32:38 UTC. Public `sts_getTokens` reported finalized source,
    height 3784515, the current snapshot hash, and only native SNRG before the
    first STS token. Atlas API and indexer services remained active on PIDs
    2048954 and 2048961, and both local and public token endpoints returned
    the native Chain 1266 registry.

**Remaining acceptance gates:** Build and run the Windows AMD64 CLI natively
on the Windows tower, then publish its executable, checksum, and PowerShell
installer without replacing the verified Unix assets. The first real token
create and transfer remain separate explicit-approval mutations.


## C1266-2026-10-24-R8-001 — Approved isolated transport transition

**Status:** Authorized, preflight complete; rolling activation next.
**Severity:** P0 isolated stability recovery.
**Detected/authorization recorded:** 2026-10-24T23:32:10.824544+00:00
**First bad height:** Historical isolated H131034; approximately43s pause, next QC H131037 round2. Exact causal operation remains UNPROVED.
**Last agreed finalized block ID:** Exact common commitment will be captured by the guarded transition before staging; preflight heads H179863–179865.

Affected: isolated Val2–Val6 only, production excluded. Shared runtime redundant-proof queue mechanism independently demonstrated; no validator misconduct attribution. Human explicitly approved pinned r8 SHA25645c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e, standard sequence13, order4/6/2/3/5, one restart each, original qualification then conditional new24h soak. Fresh exact preflight preserves original PIDs except approved Val4r7, NRestarts0,1GiB/swap0/OOM0. Evidence: /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/transport-sparse1-r7-post-activation-inventory-20261024T233149Z.json.

Attempt1 planned: create-only binary/release/drop-in, native all-five signature verification, one guarded rolling restart per approved host, original5s Sync readiness from actual process start and matching advancing finality after each. No state/custody/config/old-unit removal, no automatic retry or rollback. Original qualification pending; no new soak running. Failed sync-prune1 run and incomplete r7 capture remain preserved. Outcome and exact identities will be appended after action.

### 2026-10-24T23:35:51.154070+00:00 — R8 attempt1 rolling result

Standard native signed sequence13 verified allfive. Rolling4/6/2/3/5 completed maximum one restart each; actual new PIDs {'4': 1856184, '6': 1528981, '2': 1609905, '3': 1539009, '5': 1583633}. Exact runtime45c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e, original5s Sync readiness everyhost PASS, matching advancing native common commitments checked aftereach; details /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/sync-known-head1-r8-transition-20261024T233210Z.jsonl. State/custody/config/oldunits preserved, caps1GiB/swap0/OOM0 and NRestarts0. Finite original qualification next; no newsoak started, no43s rootcause closure claim.

### 2026-10-24T23:55:05.711838+00:00 — R8 qualification FAILED; new native33s pause

Memory30 passed30/30/30 and allfive effects;64height retirement passed. Sustained600s0.1TPS qualification failed23:46:49.941981 with32 submitted/admitted,31 observed finalized,1 pending, on Val4 relayed synergy_chainTelemetry5.00851s timeout. No newsoak began and no further restart/load retry/rollback occurred. All5 original one-restart approvals consumed. Native allfive finalityH180871→180872 gap33.089601–33.292433s independently violates unchanged30s. NextQC180874round3, verifiedTC0/1/2 timedoutproposersVal6/4/5. SavedTCP shows multi-MB queues toward Val4 and retransmission/backoff; exact causal operation remains unproved, including whether relayedRPCtimeout shares cause. Validators recovered without operator restart; exact23:48:45r8/PIDs/caps/OOM0 preserved. Review: /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/sync-known-head1-r8-distributed-qualification-failed-review-20261024.json. Single exact pending NEW32 transfer lookup nullallfive; no effect/finality inference or resubmission. NEXT bounded nativeowner/proposal/outbox/read evidence forH180874 plus savedTCP peer sequence, preserving all failed/raw evidence and original gates.

### 2026-10-25T00:08:31.539861+00:00 — H180874 signed-slot boundary narrowed

Read-only exact native signed-slot filenames (canonical runtime BLAKE3 domain/order) show Val6r0proposal before its own timeout by4.819918s, while Val2/3/5 ECHOs followed their own timeout0.831–1.231s. Val4r1proposal signature absent. R2 block-vote signatures exist only on Val3/5/6,3<4quorum; Val2/4 r2ECHOs followed own timeout5.627924/4.587945s. All signed-slot hashes/mtimes and same-host interval limitations retained in E/sync-known-head1-r8-height180874-handoff-timeline-review-20261024.json. Val3 retained native owner polls continued subsecond through failure, not all-host scheduling proof. Exact network/read/processing-input delay still unproved; no speculative runtime edit or further restart/load. Two-host same-r8 diagnostic packet prepared fe918f2da910fd24131dd5630efa9d402b6c51d065f5bfa006a826ab650e54c7; new explicit authorization required before staging/restarts. No newsoak.

### 2026-10-25T13:19:00.518878+00:00 — R8 diagnostic attempt2 authorized, before mutation

Human explicitly answered “Approve two-host r8 diagnostic capture” to reviewed packet SHA256fe918f2da910fd24131dd5630efa9d402b6c51d065f5bfa006a826ab650e54c7. Exactly one same sequence13/r8 diagnostic restart each isolated Val6 then Val4; fresh exact allfive preflight and advancing identical common commitments required before staging and after each restart. Fixed3600s native sparse trace, bounded passive TCP/detector and exact resource observers only; no load, resubmission, qualification retry, soak, binary replacement or automatic rollback. Existing state/custody/config/old units and original5s readiness/30s finality/1GiB/swap0 preserved. Write-ahead restart markers required. No restart or capture yet. Authority: /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/r8-handoff-diagnostic1-20261025T000754Z-human-authority.json.

### 2026-10-25T13:26:27.136351+00:00 — R8 diagnostic attempt2 launch outcome

Approved same-r8 restarts executed exactly once orderVal6thenVal4. NewPIDs1801096/2163528; original5s Sync ready0.530366/0.432972s from actual process starts PASS. Existing sequence13/binary/config/custody/oldunits preserved, NRestarts0/1GiB/swap0/OOM0 at guarded checks; other3 PIDs unchanged. Native advancing identical allfive commitments aftereach and pre-armH238894 PASS. Passive TCP armed13:23:14.210640/13:23:15.622024UTC; two3600s resource streams started13:23:14.621139/13:23:16.027573. Four bounded64MiB/swap0/CPU25% observer units active at13:24 initialaudit; Val6 passive max1212/oom0 at initialaudit, preserve pressure/completeness caveat. Native and passive windows fixed, no extension/rearm/returnrestart. Both fresh restart approvals consumed. No workload, qualification retry, binary replacement or soak. Review /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/r8-handoff-diagnostic1-20261025T000754Z-launch-review.json. Capture outcome and causal findings pending actual terminal records.

### 2026-10-25T13:29:23.282956+00:00 — R8 diagnostic bounded13:27 audit; retention limitation

Val4 sparse8192 retained completions reached in43.777345s,8126 failed records and8116 dispatch records; dispatch failures indicate nonblocking queue admission rejection, not TCP loss. No full-hour per-frame coverage claim; total dropped/open/expired counters pending native end. Val6 retained183records; all4 passive/resource observers active and no end records yet. Both sampled validator caps/swap/OOM remained unchanged; Val6 passive observer bounded64MiB memory.max hit(max7520),oom/kill0. No adjustment/rearm/restart/extension; preserve pressure and incompleteness. Evidence /Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/r8-handoff-diagnostic1-20261025T000754Z-readonly-audit-20261025T132749Z.json. Native/resource actual terminal audit due after14:23:20UTC, not timer-only completion.

### 2026-10-25T13:49:46.964612+00:00 — R8 diagnostic first-trigger passive freeze; new H239861 timeout

Both passive rings naturally froze on FIRST armed stagnation at finalizedH239858: Val6 end13:36:14.604141UTC/elapsed780.398804s; Val4 end13:36:15.504247UTC/779.889583s. Both passive units inactive/success and original PIDs absent at13:40:22–23 read-only check. Resource PIDs1801613/2163807 still live then; native/resource3600s windows NOT yet verified ended. No rearm/restart/extension. Val6 tcpdump reports163741 kernel drops; Val4 reports0, but retained rings cover only13:36:04.135680–14.240597 and13:36:02.699840–14.254715 respectively, before round1 recovery. All8 PCAP files copied read-only to canonicalSSD with matching source hashes. Structural parsing is NOT independent signature verification or proof of application receipt/completeness.

New H239861 round0 selected proposer Val3; retained allfive signed-slot history has no r0proposal/ECHO and no Val3r0timeout. Other4 timeout votes formedTC0; Val6 signedr1proposal13:36:14.403937, followed by allfive votes/QC. Durable native finality file intervals H239858→239859 are5.086163sVal3 and6.277889–6.295900sothers; this new~6.3s event is NOT the historical33s/43s failure. Frozen wire shows byte-identical ProposalDelivery/QC payloads repeatedly sent towardVal3 at distinct authenticated-frame sequence numbers (e.g. Val6 H239858 delivery28copies70202B/QC27copies48756B). This establishes repeated wire work, NOT why Val3 lacked proposal authorization or a historical root cause. Val3 processing input/parent/proposal gating remains unproved; no speculative fix. Review E/r8-handoff-diagnostic1-20261025T000754Z-h239861-freeze-review-20261025.json SHA2564fa6c1bdeec38dac640bbdd19a5c5cfa639f3676d7c543f955a8b668a47298e0 pins source streams, native history, signing slots and structural analysis. NEXT after14:23:20UTC one bounded actual native transport-window-end +resource end+all4 recorded observerPIDs absent audit; before then offline frozen/source analysis only, no unchanged active polling. Both restart permissions consumed, no workload/qualification retry/soak/binary change/rollback. Earlier active-passive statements are historical snapshots superseded by this amendment.

---

## C1266-2026-10-27-RECOVERY-001 — Authorized retained-state Linux recovery after storage qualification failure

**Status:** Open; source integration and pre-deployment safety qualification in progress; actual fleet remains stopped.  
**Severity:** P0 functional and resource qualification blocker.  
**Detected:** Storage failure and operator stop recorded 2026-10-26 22:52:09.966412 UTC; this recovery entry recorded 2026-10-27 11:06:25 UTC before recovery host mutations.  
**First bad height:** Not established as one consensus height. The storage defect is cumulative; the transaction failure occurred before admission.  
**Last agreed finalized height:** Not yet independently established for this recovery entry. The fresh stopped preflight does not read finalized heads.  
**Last agreed finalized block ID:** Not yet independently established; must be captured from native retained-state evidence before a continuity claim.

### Network identity and authorization boundary

This entry concerns only Val2–Val6 on selected network
`synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99`, numeric chain ID
`1266`, with signed Genesis file SHA-256
`a34547918d494bb35b0eca9fc26bacb5ccbaf6bf4f49d58e0154391224bf6a20`.
It is a distinct network from the preceding historical r8 isolated chain and
Val1's single-authority chain. Reuse of numeric ID1266 does not identify those
histories as one chain. Historical H180871/H239858 and the current sign-once
floor10167 are not substituted for a verified current finalized head.

The current [emergency execution directive](/Users/jhutzler/.codex/attachments/19d07aa7-d8a3-486d-9962-63d5c0934344/goal-objective.md),
SHA-256 `0dd36d097d3ce307a1a1288e7a38b9793d8f1a9fc04a95ed05769258be609984`,
explicitly authorizes completing the shared corrections, one uniform tested
non-destructive Linux upgrade on Val2 then Val3/4/5/6, all-five package and
safety-state verification before controlled coordinated startup, legitimate
encrypted transaction qualification, and then a new remotely supervised24h
soak and controlled TPS ladder. This supersedes the earlier engineering
report's pending-approval boundary for that workflow. It does not authorize
data wipes, new identities/keys/Genesis/network, signing-journal resets,
history deletion, authorization bypass, weaker consensus, or irreversible
migration without verified recovery. Old interrupted soak intervals may not
be reused as a new24h result.

### Affected and responsible nodes

All five validators Val2–Val6 share the historical-file proliferation defect
and workload authorization integration gap. Responsibility is in the common
runtime and workload preparation, not an individual validator or operator.
VPN coordinator and Val1/public-chain state are outside this recovery's
mutation scope. The same canonical package and installer are required on
every validator; per-host independent safety state remains distinct.

### Symptoms, confirmed cause and limits of inference

- The Oct26 storage qualification measured approximately7.02–7.21 new PoSy
  files and220–225KB logical history per finalized block. Required history
  cannot be arbitrarily removed to satisfy a file-count gate. Indexed exact
  evidence storage is implemented and isolated-tested; actual complete
  retained-state compatibility remains an explicit deployment safety gate.
- The prior11 workload requests were rejected `invalid_authority` with
  `identity has no canonical finalized authorization binding`; admitted and
  finalized count0 is not measured consensus capacity. Funding32 wallets did
  not authorize them. Legitimate registration through the existing encrypted
  native-action path is being integrated and tested; no wallet exception or
  finalized binding is claimed by this entry.
- The [integrated recovery report](../../docs/refactor/INTEGRATED_LINUX_RECOVERY_REPORT_20261027.md)
  records the memory/retention, exact-byte archive, package and encrypted
  socket-test results and their limits. The old-release570s memory evidence
  attributes growth principally to file cache/slab with stable anonymous
  memory; it is not24h OOM closure. Historical33s/43s stalls still lack a
  proven causal blocking operation.
- The former candidate manifest
  `5a9e87db51f431cf7490806ad98e813206a44e2d34fbb08d3b3a25f4f95a91bf`
  is held pending authorization-registration completion and final integrated
  release qualification. It has not been installed by this recovery entry.

### Recovery actions and outcomes in chronological order

1. **Operator stop on Oct26 after failed storage qualification.**
   `target/qualification-20261026T223352Z/OPERATOR-STOP-RESULT.json` records
   request22:52:09.966412 UTC and all-five inactive/dead/MainPID0 with old PIDs
   absent by22:52:10.516888 UTC, stop exits0, NRestarts0. The qualification
   workload/controller was stopped; data, keys and VPN were not changed.
   **Outcome:** failed prior qualification preserved; no24h completion or
   successful TPS claim.
2. **Offline shared engineering and five-validator comparison.** The linked
   integrated report and [upgrade packet](../../docs/refactor/INTEGRATED_LINUX_UPGRADE_PACKET_20261027.md)
   record completed measured tests, content-bound candidate and exact
   state-preserving upgrade mechanism. **Outcome:** reusable engineering
   evidence exists; corrected-release live conformance/finality is not proven.
3. **Fresh read-only all-five stopped preflight, Oct27 11:02:47.430879–11:02:48.635109 UTC.**
   All five report inactive/dead/MainPID0/NRestarts0, no systemd drop-ins,
   MemoryMax1073741824, swap0, TasksMax512. Owned VPN services remain active.
   Every installed node is SHA-256
   `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`,
   package manifest
   `fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8`;
   selected network/Genesis/authority/transport artifact hashes agree.
   Independent PoSy file counts Val2/3/4/5/6 are
   72865/71606/73258/72195/73093, not expected byte-identical histories.
   **Outcome:** old-release stopped baseline verified; no running-executable,
   current finalized-head, OOM-counter or corrected-release health claim.
4. **Read applicable root/Core/Testnet policy and this full5413-line log;
   append this recovery incident before host mutation.** Global AOS policy
   and supporting package paths referenced by local rules are absent on this
   Mac; no contents or additional permissions are inferred. **Outcome:**
   append-only recovery record established. This action changes only this
   log; deployment, migration, start, transaction submission and new soak are
   still unexecuted in this entry.

### Final outcome, residual risks and next required observation

Open. Complete legitimate registration and final integrated checks, freeze
one new uniform release, rehearse full actual retained public consensus state
without signer/node startup, then execute the authorized non-destructive
upgrade with exact per-host identity/configuration/network/safety-state
preservation evidence. Do not start PoSy until all five pass the corrected
package/state gates. Append each real upgrade/start attempt and exact outcome
separately, including unsuccessful attempts. Startup alone does not establish
recovery: require advancing identical finalized block/state commitments,
unchanged signing/quorum safety, actual encrypted transfer effects and bounded
public-tier/Atlas lag. Original5s readiness,30s finality/maxgap, measured
0.5–1.5s mean cadence,1GiB/swap0/OOM0 gates remain. A fresh soak requires its
own truthful actual UTC start/release identities and full measured interval.

### Source evidence

- Current recovery directory: `node-platform/target/controlled-network-recovery-20261027T110225Z/`.
- `authority.json` SHA-256 `804cbb9a9a0b7df2760f51e3562f0165aedd68514976cc6dfb1bbab82dcfe6a2`.
- `stopped-preflight.json` SHA-256 `a13c890312d3e6eaefb547ef9c5a45634903577628c32503397c80edb12d5a48`.
- Prior terminal stop and interrupted workload: `node-platform/target/qualification-20261026T223352Z/`.
- Prior integrated evidence index: `node-platform/target/engineering-recovery-20261026/COMPLETION-EVIDENCE-MANIFEST.json`.
- Canonical continuation: `docs/refactor/IMPLEMENTATION_STATUS.md`.

### 2026-10-30 — Actual five-validator integration directive, before deployment

The user explicitly prioritizes real Val2–Val6 integration over isolated synthetic
scale benchmarks and authorizes non-destructive deployment, coordinated startup,
real encrypted execution, measured finalized TPS and conditional fresh24h soak.
Existing identity/Genesis/network/history/signing floors/journals and original
quorum/threeQC,5s readiness,30s finality,1GiB/swap0 remain unchanged. The new
`real-fleet-integration-directive-authority-20261030.json` in the current recovery
evidence root records this revised qualification policy, without marking any
incomplete isolated benchmark passed. Successful all-five schema2 copy-only
migration/import/reindex/startup-safety rehearsals are reused. Actual06:40UTC
read-only check found all-five inactive/dead/PID0. Before any deployment, refresh
protected source/archive integrity, authenticated identity/membership and capacity;
then freeze/build/seal one canonical production package and use the universal
upgrade owner. No node start/deployment is claimed by this pre-execution entry.
Append actual attempts/outcomes separately; no automatic rollback after new writes.


### 2026-10-30 — Production package and guarded layout correction

Canonical master `Node-Architecture/Linux/Synergy` sealed release
`synergy-linux-f54ce336d89c2ec1`, package SHA256
`abe5189e9f4b15ed238488133be55ed6ae59a5b02de26a6f31facdab75944e9f`,
node SHA256 `8ef2d886dbabeb59298a2976b2e3c1620d1415a48f7ee031658559abf7fb58ca`.
First Val2 staging rejected a transfer archive missing empty role directories,
before application intent or installed-file changes. Corrected transfer retains
those directories. Guarded `packaging2-20261030` application dispatched after all
five original-package/stopped/no-prior-APPLY checks passed; result remains pending.
No start, rollback, identity replacement or state reset. Latest user evidence
lifecycle policy supersedes prior raw-output retention: used failed-build,
transfer and test artifacts deleted; only immediate upgrade safety inputs remain.


### 2026-10-30 — Operator authorizes fresh-chain reset

All-five uniform package upgrade completed and conformance passed; no node was
started. Operator now explicitly orders old chain files erased and a fresh chain,
superseding the earlier preservation of historical chain data. Preserve existing
validator/authority/transport/wallet custody, VPN enrollment, installation and caps.
Before deletion verify stopped services and native identity possession; remove old
start authorization and selected public chain inputs, erase the full active data
root and initialize empty native storage. Do not resume/sign the old domain.
Commission a fresh authenticated network identity/Genesis at epoch1/H1 with
configured chain1266 retained; ordinary transaction replay isolation requires the
new network identity. Existing wallet keys require correctly re-signed fresh
network authorization, not edited carriers. Actual reset result pending below.


Fresh reset result: all5 old active data deleted and native init completed; only
empty writer lock plus22-byte schema marker remain. First postcheck expected one
file and failed because native AtomicStore also creates the lock; read-only
all5 follow-up confirmed actual completed reset, no retry. All pre-reset custody
file hashes matched (Val2 120, others12), native possession passed, VPN PIDs
unchanged, allnodesPID0/start authorization absent. Fresh authenticated newnetwork
commissioning pending; old-domain startup remains prohibited.

### C1266-2026-10-30-SYNC — pruned execution recovery, controlled upgrade intent

Status: OPEN; shared runtime recovery defect, not a validator identity fault.
The fresh selected network is synergy-testnet-20261030-7dc4b8b008814f428511001f4a43511f,
Genesis164c4a3cc6aa78c7a57d8c676b5f49a3047d90d2f546be5f298d903fb8e8d2dc.
Its prior fresh launch and five accepted encrypted intents are recorded in the
current implementation handoff; the old-domain prohibition above is not a
prohibition on this subsequently authenticated fresh network.
Val5 execution stopped atH5746/block3df321bd04457a12c49393208bc3348a30221a95f656fad3c58bd42935c64bea.
Sync byte-vector overcharging delayed replay; its correction then exposed all
providers exiting on legitimate requests for already-pruned H5747 candidates.
Val5 was intentionally stopped; no accepted intent is being resubmitted.
Latest actual all-five read around21:11UTC: four providers active with unchanged
PIDs2249812/2155001/2769210/2161954 and restart counters4/4/5/5, agreeingH28109,
block58e0632e2f571c4edb9556b09d05cd4358f47647c30af1df8f69eddd4e4b0349.
Val5 inactive/PID0, unchangedH5746. All caps1GiB/swap0. These are point checks.

User explicitly authorizes completing Sync recovery, returning Val5 to agreement,
and testing genuine encrypted effects within30s. Sealed combined release
synergy-linux-9420b7592e7a70bb/packagec27602855ab329a821c7f4854deddad3556d49223bcd86dc3403ec82b12f09a8,
node2afdd9da9537039f3f0e14b14c7d5c783d548ea71f5026129aa6c176ef8084e1,
contains the nonfatal missing-candidate path and native stopped-only certified
checkpoint recovery. Native70-block pruned-gap/rejection/interruption/restart
regression and strict Clippy passed; real-host installation has not yet occurred.
Next actions: protected-state-preserving universal software upgrade; keep Val5
stopped; upgrade providers; stop the final provider during native checkpoint
export/import so remaining three cannot outpace retention. Restore services
through original5s readiness; compare all-five advancing commitments and new
once-only encrypted transaction effects under30s. No reset, identity/key/Genesis
replacement, quorum/finality relaxation, cap increase, or automatic rollback.
Record actual outcomes in the current continuation; no soak/TPS PASS inferred.

Current-source seal update21:39UTC: pure paged/full R1/R2 replay and all retained-byte assertions PASS1/0 after preparing the lazy legacy index and requiring the exact earlier conflict rejection. Production executable unchanged. Final combined release synergy-linux-1d71523b2b371f45, packagea71a1e02ac0f5c726226ca6821c3351bb70e7f7f9afd82653e9fca1c0a19b382, node2afdd9da9537039f3f0e14b14c7d5c783d548ea71f5026129aa6c176ef8084e1 supersedes uninstalled9420 staging. No node install/start yet.

21:42UTC pre-application: final1d71523b2b371f45 staged package verification and authenticated native preflight PASS allfive; obsolete uninstalled9420 stages deleted. Next apply software only to already-stopped Val5, hashing all protected members before/after and retaining VPN PID/executable. No state transfer/start at this step.

2026-10-30T21:42:04.020628+00:00 Val5 software-only universal upgrade PASS:684 protected members unchanged, VPN PID/executable unchanged, installed conformance PASS, remains inactive/PID0. Beginning controlled provider sequence2,3,4,6; final6 held for checkpoint, no load.

2026-10-30T21:42:04.021333+00:00 Val2: attempting one attributed native stop then identical software-only upgrade; protected-state verification before restart. No reset or rollback.

2026-10-30T21:42:13.940098+00:00 Val2: software upgraded, conformance and protected member hashes/inodes/modes unchanged (775), VPN unchanged; PID0. Native checkpoint not yet applied.

2026-10-30T21:42:13.941333+00:00 Val2: attempting one normal start; original5s readiness measured from actual exec, no deadline extension.

2026-10-30T21:42:15.484340+00:00 Val2: start PASS in 0.481944s from actual exec, running /proc hash2afdd9, PID2400784, NRestarts0, originalcaps. Other acceptance remains pending.

2026-10-30T21:42:15.485215+00:00 Val3: attempting one attributed native stop then identical software-only upgrade; protected-state verification before restart. No reset or rollback.

2026-10-30T21:42:26.822265+00:00 Val3: software upgraded, conformance and protected member hashes/inodes/modes unchanged (617), VPN unchanged; PID0. Native checkpoint not yet applied.

2026-10-30T21:42:26.823371+00:00 Val3: attempting one normal start; original5s readiness measured from actual exec, no deadline extension.

2026-10-30T21:42:28.664872+00:00 Val3: start PASS in 0.627021s from actual exec, running /proc hash2afdd9, PID2302997, NRestarts0, originalcaps. Other acceptance remains pending.

2026-10-30T21:42:28.665669+00:00 Val4: attempting one attributed native stop then identical software-only upgrade; protected-state verification before restart. No reset or rollback.

2026-10-30T21:42:46.343723+00:00 Val4: software upgraded, conformance and protected member hashes/inodes/modes unchanged (617), VPN unchanged; PID0. Native checkpoint not yet applied.

2026-10-30T21:42:46.345093+00:00 Val4: attempting one normal start; original5s readiness measured from actual exec, no deadline extension.

2026-10-30T21:42:48.473895+00:00 Val4: start PASS in 0.511659s from actual exec, running /proc hash2afdd9, PID2932365, NRestarts0, originalcaps. Other acceptance remains pending.

2026-10-30T21:42:48.474722+00:00 Val6: attempting one attributed native stop then identical software-only upgrade; protected-state verification before restart. No reset or rollback.

2026-10-30T21:42:59.107668+00:00 Val6: software upgraded, conformance and protected member hashes/inodes/modes unchanged (620), VPN unchanged; PID0. Native checkpoint not yet applied.

2026-10-30T21:43:20.110650+00:00 Val6 remains stopped after protected software upgrade atH29732. Attempting one native certified checkpoint export extending preserved Val5 H5746 anchor, isolated transient1GiB/swap0. No signer opened or state reset.

2026-10-30T21:47:44.601385+00:00 Native checkpoint export result {"unit_exit": 0, "result": "{\"exit\": 0, \"stdout\": \"{\\n  \\\"bytes\\\": 1608877758,\\n  \\\"checkpoint_height\\\": 29732,\\n  \\\"exported\\\": true,\\n  \\\"from_height\\\": 5746,\\n  \\\"pages\\\": 2400,\\n  \\\"signing\\\": false\\n}\\n\", \"stderr\": \"\", \"memory\": {\"memory.max\": \"1073741824\", \"memory.peak\": \"1073741824\", \"memory.events\": \"low 0\\nhigh 0\\nmax 1497\\noom 0\\noom_kill 0\\noom_group_kill 0\\nsock_throttled 0\", \"memory.swap.current\": \"0\"}}\n", "stderr": ""}

2026-10-30T21:48:03.941921+00:00 Native export PASS2400 pages/H5746→29732,1608877758prefix bytes; offline cgroup file-cache reclaim max1497/oom0/swap0, process anonymous memory28MiB at bounded check. Starting exact four-file public bundle streaming transfer V6→V5 with full byte hashes, no Mac copy/archive.

2026-10-30T21:54:17.970171+00:00 Public checkpoint transfer PASS, exact four filenames/sizes/SHA256 and destination fsync; no custody or journal transferred. Native import pending.

2026-10-30T21:55:07.572571+00:00 All four transferred files SHA256/size verified. Precise prefix1608814809 bytes; exporter bytes1608877758 includes candidate+replay. Attempting one stopped native Val5 import under1GiB/swap0, full prefix/native ECHO verification before canonical commits, then forward-only signing floor. No copied private state.

2026-10-30T22:08:42.843842+00:00 Val5 checkpoint import result {"unit_exit": 0, "result": "{\"exit\": 0, \"stdout\": \"{\\n  \\\"block_id\\\": \\\"ef63222f42f8968d97511b5af493d6f4824ab5341a48b377e2a4f78e16634d1f\\\",\\n  \\\"checkpoint_height\\\": 29732,\\n  \\\"from_height\\\": 5746,\\n  \\\"imported\\\": true,\\n  \\\"pages\\\": 2400,\\n  \\\"signing\\\": false,\\n  \\\"signing_floor_advanced_after_verified_commit\\\": true,\\n  \\\"skipped_transitions_locally_reexecuted\\\": false,\\n  \\\"state_root\\\": \\\"59e62288ff69520c35d4be7325c458e9f6212789653c1c2942a1ec1ff66a4ce6\\\"\\n}\\n\", \"stderr\": \"\", \"memory\": {\"memory.max\": \"1073741824\", \"memory.peak\": \"525062144\", \"memory.events\": \"low 0\\nhigh 0\\nmax 0\\noom 0\\noom_kill 0\\noom_group_kill 0\\nsock_throttled 0\", \"memory.swap.current\": \"0\"}}\n", "stderr": "", "observed_utc": "2026-10-30T22:08:42.745362+00:00", "custody_config_network_unchanged": true, "signing_floor_before": 5746, "signing_floor_after": 29732, "above_floor_reservations_preserved": true, "finalized": {"finalized_height": 29732, "finalized_block_id": "ef63222f42f8968d97511b5af493d6f4824ab5341a48b377e2a4f78e16634d1f", "state_root": "59e62288ff69520c35d4be7325c458e9f6212789653c1c2942a1ec1ff66a4ce6"}}

2026-10-30T22:09:00.337394+00:00 Val5: post-import authenticated start preflight PASS; attempting one normal service start, original5s gate from actual exec.

2026-10-30T22:09:03.810892+00:00 Val5: actual running hash2afdd9, PID2234813, readiness1.389351s PASS, NRestarts0, originalcaps. All-five advancing agreement still pending.

2026-10-30T22:09:03.811842+00:00 Val6: post-import authenticated start preflight PASS; attempting one normal service start, original5s gate from actual exec.

2026-10-30T22:09:05.390096+00:00 Val6: actual running hash2afdd9, PID2313108, readiness0.511678s PASS, NRestarts0, originalcaps. All-five advancing agreement still pending.

2026-10-30T22:52:14.458257+00:00 Once-only encrypted nonce5 txe02553056578f82c8853d63b4003140fa62aa45cf2be60498aa52fa10b963dab gate PASS allfive {"2": {"verified": true, "height": 31782, "elapsed": 22.207983291}, "3": {"verified": true, "height": 31782, "elapsed": 22.597352125}, "4": {"verified": true, "height": 31782, "elapsed": 22.948556291}, "5": {"verified": true, "height": 31782, "elapsed": 26.650877958}, "6": {"verified": true, "height": 31782, "elapsed": 22.374629416}} stages {"deadline_started_seconds": 0.0, "context_received_seconds": 0.003262, "native_admission_signed_seconds": 0.073487, "submit_response_seconds": 0.117669}

Independentwallet tx0df20b33e60c44d6f260a253cca50945cee894956a20126b2427367b10f26d5a nonce0 was accepted exactlyonce. Timing verifier aborted on Val6 RPC error finalized state lacks canonical candidate metadata; no30s PASS. Read-only reconciliation all5appliedH31845/block479a032f48c42fd0580dd3a15284caf07cf6b0d080bdfe4879ca143d4e0c46ae/finalityc55ed062946637138ab5fb9eb8a1739eb01a5f1fea772cd9aca717100f46a684, nonce1/exactfee840000/balancesall5. Neverresubmit; source RPC scan race under correction.

2026-10-30T23:06:25.658917+00:00 Stale RPC candidate-pin reader correction verified16 focused tests/strictClippy; async qualification policy correction128 tests PASS. Sealed canonical universal release synergy-linux-d3eedc19c9fb0d66 package5a1bb984234b9a3b63d828ee166f64f698c4ca729c07adb7ce4e8b748b223ed7/node d8a998080632e270d56e179347a1f3d08e88dd6343417d2bc570737fb582d7e0. Preparing non-destructive rolling software upgrade Val2→3→4→5→6, one normal start each with original5s readiness; unchanged keys/genesis/signing history/resourcecaps/VPN, no reset or automaticrollback. Fresh precheck all5 original PIDs/hash2afdd9/NRestarts0/OOM0/swap0; last common sampledH32202/32203, Val5briefSyncpending not a currentfullhealth claim. User explicitly superseded transaction30s acceptance; block gap30s unchanged.

2026-10-30T23:08:41.542108+00:00 Val2: attempt one software-only rolling stop/upgrade to d3eedc19c9fb0d66; original5s launch follows protected-state/conformance checks, no reset/rollback.

2026-10-30T23:08:50.189457+00:00 Val2: upgrade PASS; 737 protected members unchanged; VPN unchanged, conformance PASS; attempting one normal start.

2026-10-30T23:08:51.513277+00:00 Val2: actual running d8a998 PASS PID2431350, readiness0.415437s, NRestarts0/originalcaps.

2026-10-30T23:08:51.514058+00:00 Val3: attempt one software-only rolling stop/upgrade to d3eedc19c9fb0d66; original5s launch follows protected-state/conformance checks, no reset/rollback.

2026-10-30T23:09:02.000785+00:00 Val3: upgrade PASS; 595 protected members unchanged; VPN unchanged, conformance PASS; attempting one normal start.

2026-10-30T23:09:04.457122+00:00 Val3: actual running d8a998 PASS PID2333189, readiness0.692592s, NRestarts0/originalcaps.

2026-10-30T23:09:04.457690+00:00 Val4: attempt one software-only rolling stop/upgrade to d3eedc19c9fb0d66; original5s launch follows protected-state/conformance checks, no reset/rollback.

2026-10-30T23:09:23.351000+00:00 Val4: upgrade PASS; 597 protected members unchanged; VPN unchanged, conformance PASS; attempting one normal start.

2026-10-30T23:09:25.593736+00:00 Val4: actual running d8a998 PASS PID2965286, readiness0.510503s, NRestarts0/originalcaps.

2026-10-30T23:09:25.594282+00:00 Val5: attempt one software-only rolling stop/upgrade to d3eedc19c9fb0d66; original5s launch follows protected-state/conformance checks, no reset/rollback.

2026-10-30T23:09:34.744658+00:00 Val5: upgrade PASS; 663 protected members unchanged; VPN unchanged, conformance PASS; attempting one normal start.

2026-10-30T23:09:36.831167+00:00 Val5: actual running d8a998 PASS PID2252308, readiness0.667729s, NRestarts0/originalcaps.

2026-10-30T23:09:36.831910+00:00 Val6: attempt one software-only rolling stop/upgrade to d3eedc19c9fb0d66; original5s launch follows protected-state/conformance checks, no reset/rollback.

2026-10-30T23:09:44.466960+00:00 Val6: upgrade PASS; 619 protected members unchanged; VPN unchanged, conformance PASS; attempting one normal start.

2026-10-30T23:09:45.718720+00:00 Val6: actual running d8a998 PASS PID2333844, readiness0.332320s, NRestarts0/originalcaps.


## C1266-2026-10-31-RECEIPT — live processing milestone journal/schema recovery

2026-10-31T08:23:09.907962+00:00 Receipt-stage release4996cf15f1caca4a installed allfive with protected state/config/custody unchanged and same normalized configuration153a5881458dc517b839dea409beea825a82738434a69b9ad5cec18261855e8e. Fresh encrypted nonce14 txf0e451042551c6396b6e45f1067a9595836793d7fa6dda798687e4312f8480fe admitted once; never resubmit. Val2 ETDAG failed at unsupported receipt observation authority because durable schema omitted new processing stages. Automatic restart then rejected native128hex certified-group names under erroneous64hex conformance pattern. Otherfour exact appliedH57069/block6b98a0427adfc7effbf1aafb275673e8d945b1c1be4c8ca11f1bb87d3bd552b5, sendernonce15/state92ad4868766a8216499d628bbc0b069ba53890b97408bcb119786e50cb236eb1. No allfive/timing PASS. Source corrections retain original admission finalized=false, require structured finalization observation, support exact native512bit group IDs. Pausing all node services via attributed lifecycle to prevent history outrunning failed Val2 while building, preserving VPN/keys/state. No reset/rollback/newintent/load/soak.

2026-10-31T08:29:07.841188+00:00 Native Val2 checkpoint importH57065→57173 PASS12pages/7.17MB, original signing floor advances only after certified commits; config/custody/network unchanged. Corrected release synergy-linux-ce9cbc5027b20e49 package637180e9cdf5cf433387802f43309c207ce74160a74dce1edd3644dce897fb0b node8bafde8a2af81dad6e31e8100324fe1a5c0af1931c30c958d693edb2a401ff5e installed allfive while stopped, protected files unchanged818/633/645/664/627, VPNPIDs unchanged. Five durable receipt tests and15 conformance tests PASS. Attempting one coordinated normal start each, original5s readiness, no newintent until advancing allfive commitments and consumednonce15 effects verified.

2026-10-31T08:39:49.771516+00:00 Allfive coordinated starts passed original5s readiness, but Val2 then failed ETDAG polling: finalized processing parent is unavailable. Allfive nodes stopped again via attributed lifecycle; synergy-vpn.service remains active. Source/data analysis narrows actual fatal path to retirement scanning unrelated authorization-source pinH32895 (receivernonce4) for pending sendernonce14, demanding already-pruned parentH32894. Correction filters exact sender/nonce before full native retirement verification; it never retires on nonce advancement alone. Pending f0e451 remains preserved; checkpoint-imported equivalent state does not establish an exact local consumption proof. Regression verification in progress; no TPS/soak/newsubmission.

2026-10-31T08:43:46.047164+00:00 Exact-replay-identity retirement-scan correction PASS native encrypted/order/reveal/three-QC regression (including missing unrelated/matching parent rejection) and strict releaseClippy. Sealed new universal package61003cc642d2a712ebc3097a6ed3c4cc21d3e9c4944bb60faac431342ff8c09d. Allfive inactive originalcaps/VPNactive; Val2H57173, Val3/4H57257, Val5/6H57258, commonstate92ad4868. Attempt one native stopped Val6 export→Val2 import H57173→57258 under1GiB/swap0, public four-file bundle only; preserve pending original, custody and signing reservations. Then identical software-only upgrade and coordinated5s starts; no newintent before advancing exactfive agreement.

2026-10-31T08:50:01.710040+00:00 Val2: stopped software-only upgrade61003cc6 PASS; 824 protected members bytes/inode/mode/owner unchanged; VPN unchanged, full installed conformance PASS. No start yet.

2026-10-31T08:50:15.984747+00:00 Val3: stopped software-only upgrade61003cc6 PASS; 673 protected members bytes/inode/mode/owner unchanged; VPN unchanged, full installed conformance PASS. No start yet.

2026-10-31T08:50:22.017549+00:00 Native stopped Val2 import H57173→57258 PASS9pages, certified blockc04b298b/state92ad4868; signing floor advanced only after verified commit, no signing/no local skipped-transition reexecution. Peak15941632/max0/oom0/swap0 under1GiB. Public bundle retained until recovered live verification.

2026-10-31T08:50:50.287290+00:00 Val4: stopped software-only upgrade61003cc6 PASS; 685 protected members bytes/inode/mode/owner unchanged; VPN unchanged, full installed conformance PASS. No start yet.

2026-10-31T08:51:03.851854+00:00 Val5: stopped software-only upgrade61003cc6 PASS; 706 protected members bytes/inode/mode/owner unchanged; VPN unchanged, full installed conformance PASS. No start yet.

2026-10-31T08:51:21.152659+00:00 Val6: stopped software-only upgrade61003cc6 PASS; 669 protected members bytes/inode/mode/owner unchanged; VPN unchanged, full installed conformance PASS. No start yet.

2026-10-31T08:51:34.537424+00:00 {"val": 6, "pid": "2520904", "readiness_seconds": 0.3416904299519956, "running_exe": "d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3", "NRestarts": "0", "startup_passed": true}

2026-10-31T08:51:34.784967+00:00 {"val": 2, "pid": "2620351", "readiness_seconds": 0.5081933690235019, "running_exe": "d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3", "NRestarts": "0", "startup_passed": true}

2026-10-31T08:51:34.786807+00:00 {"val": 3, "pid": "2518830", "readiness_seconds": 0.47619547392241657, "running_exe": "d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3", "NRestarts": "0", "startup_passed": true}

2026-10-31T08:51:35.416079+00:00 {"val": 4, "pid": "3172920", "readiness_seconds": 0.5480278939940035, "running_exe": "d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3", "NRestarts": "0", "startup_passed": true}

2026-10-31T08:51:36.053857+00:00 {"val": 5, "pid": "2408727", "readiness_seconds": 0.7009627500083297, "running_exe": "d6365a0b1421d88375469a9a5b6d5a2650b72fb3816f90dbd8d3ad2c73e7daf3", "NRestarts": "0", "startup_passed": true}

2026-10-31T08:55:00.126883+00:00 Independent encrypted acceptance {"verified": true, "transaction_id": "7486374ca3b3a3d00453ce93e3ff0413834828c16cad9b0054fa87c5ec62f5ae", "block_height": 57395, "block_hash": "062b0e08305d8435e64c353815c473d73b711a7804345171b8e0e98d7890608e", "finality_certificate_id": "ce71a307cee57b48d845852719f7dccb55a1d1c31ee3f7f38b6a9caf70ae13b9", "state_root": "cc23e0c4d5a970d69db3d3824f3fc7685202959ac9c39a2e6cd570ee4c70a96a", "all_five_exact_effects": true, "handoff_consumed": "caller may now delete the remote disposable handoff", "observed_after_controller_start_seconds": {"2": 12.472067, "3": 12.472087, "4": 12.472093, "6": 12.472098, "5": 14.751054}, "sender_nonce": 4, "sender_balance": "997999999995414199", "receiver_balance": "998997999999992508411", "gas_used": 21000, "workdir": "/var/lib/synergy-qualification/latency-20261031T085443Z"}; directly consumed timing {"handoff": true, "transaction_id": "7486374ca3b3a3d00453ce93e3ff0413834828c16cad9b0054fa87c5ec62f5ae", "receipt_id": "006d9d7dde00c8b438bf4597fbcdc7d416f9a8ca0cf95f10ec09041bb1ce9a087423e4e66ad022b96f62a225842fae91fc49ddad710bc3efb8035fb1abb67894", "sender": "syna1v6tv38me46y2sussfgv8f589q3j6q3udckg3", "nonce": 3, "stage_elapsed_seconds": {"context_started_seconds": 0.0, "context_received_seconds": 0.004416, "native_admission_signed_seconds": 0.077239, "submit_response_seconds": 0.113279}, "receipt_stages": [{"stage": "queued", "elapsed_seconds": 0.119963, "proof": null}, {"stage": "accepted", "elapsed_seconds": 0.497433, "proof": null}, {"stage": "certified", "elapsed_seconds": 1.302801, "proof": {"context_root": "fe54a5b0df3a82bd4cf662ae533d8dec12ab2f4c4ee3247630a5297bbd47a1a75ecd46f5d7f8dffc9b6edf578e098d108ab3a3101d2ce1d184f105a57ccfaebe", "finalized": false, "verified_vote_count": 4, "vertex_id": "ae1079e5cc5e044930e89043f7d318e7ab2664f5d31bfd2f3a330c7c209d8ce2647b4faa24d7f4410559fb5c311bb21556c18b2cdd13189919d658aaf54e0ca7"}}, {"stage": "reveal_authorized", "elapsed_seconds": 5.973825, "proof": {"finalized": false, "proposal_block_id": "2ee3e0dfe74fd54bd949cfa20e8c90ea20dd9754acf2599e80fa8418c9e703f5", "proposal_height": 57390}}, {"stage": "execution_completed", "elapsed_seconds": 6.555236, "proof": {"finalized": false}}, {"stage": "finalized", "elapsed_seconds": 11.134117, "proof": {"finalized": true, "finalized_block_id": "062b0e08305d8435e64c353815c473d73b711a7804345171b8e0e98d7890608e", "finalized_height": 57395}}], "observation_error": null, "workdir": "/var/lib/synergy-qualification/latency-20261031T085443Z"}; durable handoff reopened equal.

### Permissionless release preflight detects pre-existing Val2 recovery failure — 2026-10-31T12:28:30.420992+00:00

Sealed candidate synergy-linux-725038bd2ec6ee2f package 750ba62179e77a35e46d344e27927e4054d7ea750be2bf2a083dc31b94b61870 is not staged or deployed. Fresh read-only fleet preflight finds Val2 MainPID0/auto-restart/NRestarts249, startup fail-closed: certified processing archive differs from native QC. Val3–6 retain original active PIDs/NRestarts0; original caps, live VPNs preserved. Parent authorizes stopping only Val2 automatic failure loop to preserve failed state and diagnose archive/QC disagreement; no upgrade, DB mutation, reset or autostart.

Val2 stop verified inactive/MainPID0, VPN2050334 unchanged. Read-only70archive scan isolatesH65187 inputround1>QCround0; exact block/parent/root match, originalarchive unchanged SHA256a6868ad4644c987ec1d787eaa2857af95d824c526469efc54729f8b95a61f9c0. Originalexit11:21:49UTC, firststartupfailure11:22:05. Four peers independently matchedH67645; allfourcgroupmax/oom/kill0/swap0. Candidate deployment paused for exact runtime correction; no archive/state mutation.

### Corrected permissionless/recovery coherent fleet upgrade — 2026-10-31T12:38:31.979658+00:00

Authorized new identical release synergy-linux-628f8ad840cfc4b5/packageaa29d326fed65090e720b4a3721b6f7b95239ce940266ebfa0a68a37fa0637d0/node1120c1d41ff4ecabaca2b431a2bf30ace41382c677cc4c12430ad08364550cc2 staged only after fresh sealed installed conformance, unchanged resource policy and four-live common commitments. Val2 already stopped for demonstrated H65187 replay envelope defect; original archive will remain untouched. Planned controlled action: verify staged identical package allfive, stop remaining four, software-only lifecycle upgrade with protected bytes/metadata comparison, coordinated native startup original5s deadline and exact advancing common commitments. No transactions/workload/reset.

Upgrade completedallfive: protectedbytes/inode/mode/uid/gid unchanged996/816/827/847/809; VPNsunchanged; stagingremoved. Original5s startsPASS at12:42:33UTC readiness.645839/.511239/.546749/.837694/.416464s PIDs2680219/2596129/3257901/2476789/2598464, allnewnodehash/NRestarts0/capsunchanged. Val2 originalH65187archive hash unchanged. LiveSync stuckH65185 requesting65186; ALL4providers reportcandidate-unavailable bytes0. Authorized native stoppedVal6export→Val2import from exactH65185 anchor, no manualDBmutation/signing/reset.


### Val5 certified-input staging exhaustion — 2026-10-31T18:50:14.034437+00:00

Val5 exited13:54:02UTC: processing proposal staging is full; restarted once and remainsH70391 while four peers agree/advanceH76053. Allfour explicitly lack nextcandidateH70392. Native full32-slot certified-import/migration/encrypted-execution regression and strictClippy PASS. New source-frozen universalrelease synergy-linux-dcc9268fc57b95fe package4b6817a54276bd94514c591902ba60fc18e8acb9985abaf93c9415b87c1d7951 noded8e93de8d9aef1bcdaa5ecc4757d512f7b26837706f20bc633c3248aec8ae1aa. Authorized coherent software-only upgrade: stage/verify allfive, stop once, preserve protected bytes/metadata and VPN; native stopped Val6 export→Val5 import authenticated checkpoint, forward signing-floor only, original1GiB/swap0/5s readiness. No new transaction until exact advancing allfive agreement. No reset, key replacement, speculative-slot eviction, quorum/cap changes or workload.

2026-10-31T19:51:40.968296+00:00 Native stopped Val5 checkpoint import H70391→76196 completed: systemd Result=success/ExecMainStatus0, durable execution block3d602e5225ad8382ddb484fe5f4e6c0762e2afe67ec62aea7dc54f9c01ea8af1/state43c3bd615ab3d54be8c6d0c714f7dee8e4de450da56d4b1070146bcf138ad59a, signingfloor76196 forward from70439.581pages,467996433prefixbytes; fourfiletransfer sizes/SHA256 verified. Original1GiB/swap0/TasksMax512; systemd reports226.6MiBpeak/4m10s. Custody/config/network exact snapshot passed before postcheck. Wrapper postcheck wrongly required entire processing directory unchanged; expected new certified checkpoint archive and generation header caused this assertion AFTER successful native import. No retry. Read-only verifies all32 original input files and32VCs still present with pre-import mtimes; no original staged input deletion. Full before/after byte-comparison result for stagedfiles was not returned, so not claimed. No starts yet; awaiting fee/SynID corrected package for one coordinated start.

2026-10-31T19:56UTC Allfive coordinated starts on dcc9268fc57b95fe passed original5s readiness: V2=1.252917,V3=.963964,V4=.565221,V5=3.689084,V6=.696969s; PIDs2798432/2713246/3393802/2574609/2716597. Read-only exact native finalized block/QC/state/protected commitment H76312 matched allfive; Val5 advancing, live sampled lag one block, original caps unchanged. User actual mobile wallet funding1SNRG authored/submitted ONCE from receiver nonce6: f6ff67a010a42c734cf53980b5ee548cfbe596dde9b1f7ca9c56932a4d670345. Sole handoff latency-mobile-fund-20261031T195644Z retained pending immediate allfive exact receipt verification; never resubmit.

2026-10-31T20:03:19.758341+00:00 Funding exact allfive Applied H76350/block edc4b7e86c885536ce4c3a356c1afca5d38234df15d043c6f16f77fde26bc465 verified; mobile balance1SNRG/nonce0/noauthorizationbinding allfive. Consumed handoff and V5/V6 checkpoint bundles deleted. Signed naming + selected-runtime fee-policy correction strictClippy and focused tests PASS, iOS Release build/install PASS; wallet at Unlock, no outbound mobile submission. Sealed identical universal release synergy-linux-58db14bdb6534672 package7e89c7f38044e817c811e1e64c872529cbc1e8e14c98be2626cae35416b64dbe/node10418aad801e298c3c78be0e9661459e77cdeadb0445b5976388324dde9c324c, features[]. Authorized software-only allfive upgrade staged outside managed roots, native authenticated selected-network preflight required before stop; preserve state/custody/VPN/caps, one coordinated original5s start. No reset/rollback/newworkload/soak.

2026-10-31T20:08:23.372752+00:00 Release58db14bdb6534672 allfive installed/running, protectedfiles unchanged1136/885/892/904/874/VPNunchanged, normalizedconfiguration153a5881… allfivePASS. Readiness.619093/.599431/.417798/.808036/.435050s; PIDs2803007/2717706/3399090/2578458/2721195. Exactallfive block/QC/state H76750 verified; Val5 advancing3blocksbehindhealthySyncPending, notzero-lagclaim. Mobilefunding allfiveverified; wallet atUnlockafterinplaceupdate, nooutboundsendyet.

2026-10-31T20:09:04.371126+00:00 Newrelease advancingexactallfive commonH76750→76784; allfiveSyncReady sampled, V5oneblockbehindothers. OriginalPIDs/NRestarts0/memory.events max0/oom0/kill0 and1GiB/swap0. Gateway23ca08f deployed/selectednetworkpubliccontext+nativeSynIDreadsPASS, unsignedwrite/adminblocked; rawruntimefee40/21000/1098576present. MobileatUnlock,useraway; genuineoutboundsend remainsunsubmitted,pendingauthorizeduserunlock. NoTPS/soakclaim.

### C1266-2026-10-31-POST-WALLET-UNLOCK — recurring runtime exit

2026-10-31T20:56:35.904754+00:00 Restored Atlaspublisher revealed V2/3/4/6 originalPIDs gone,NRestarts19,exit1/activating; V5originalPID2578458NRestarts0H78309/state0a9300c9…/gap336s. No manualrestartsoroutboundmobileSend. Walletnormalunlockcompleted; automaticnamingintent possibility unresolved, do not resubmit. Parenthaltsallnodeunitsonce via lifecycle stop tostopfailureloop/preserve failedstate and diagnose native logs; VPN/state/custody/genesis untouched. No rollback/reset/load/soak.

2026-10-31T21:54:57.569168+00:00 Read-only confirmation: allfive inactive/MainPID0 after lifecycle stop. Native V2/3/4/6 repeat ETDAG pending processing verification: UnauthorizedReveal. Exact crypto substage remains under investigation; no reveal bypass or state reset. Dashboard publisher fresh with current recovery/blocked test plan; no workload or outbound mobile Send.

## C1266-2026-11-13-001 — Unattended restart interrupted signature journal publication

**Status:** Recovery authorized; verification pending
**Severity:** P0 single-authority liveness
**Detected:** 2026-11-13 22:18 UTC; last finalized at 06:15:41 UTC
**First unfinalized height:** 5319454
**Last finalized height and block:** 5319453 / `768b8396da84a9b29c3dbace6f6767977210c57a02fe7a2b08f3315d4df64beb`

### Affected components and confirmed cause

Val1 (`synergy-chain1266-authority.service`), Testnet v3, Chain 1266 incarnation 5, `single_authority_v1`. Ubuntu's unattended libc upgrade invoked needrestart, which explicitly restarted the authority at 06:15:42 UTC. The pending block and complete signature were written, but the canonical journal replacement was interrupted. The initial startup and three retries failed closed; systemd stopped retrying at 07:05:02 UTC. The observer's Nginx service independently failed its startup configuration check on 2026-11-05 at 05:51:40 UTC because a Portal upstream hostname did not resolve. The hostname now resolves and the configuration test passes; public RPC still returns 502 before recovery.

### Recovery actions and outcomes

1. Read-only inspection found the exact staged candidate `16b0aee71d0ac77a68123bd4ac2a01bfdcbb59af3f3ce3f5df0775561aaacf6c` and a complete Signed journal entry in `single-authority-signing-journal.tmp-1655202`. Verified the full journal subject matches the halted record and staged candidate; recomputed candidate hash and payload digest; verified the original ML-DSA-65 signature with the public authority key pinned by the deployed configuration and used by the finalized parent. Finalized head, signing hot state and committed block tail agree. No live state changed during diagnosis.
2. User requested restored block production and public RPC until PoSy replacement. Plan: preserve the halted journal for verification, atomically publish only the already verified Signed entry, defer needrestart restarts of this unit, and start the authority once. Start observer Nginx after a successful config check; confirm exact recovered block and advancing public and local finality. No fresh signature at the affected height is authorized.

### Outcome and remaining checks

Pending live actions. Source: Val1 unattended-upgrades dpkg log (line 566), unit journal, canonical/hot/temp signing journal, staged candidate and durable chain tail; observer Nginx unit journal and config check. Verify the two services and public JSON-RPC responses before recording recovery.

### 2026-11-13 22:29 UTC — Recovery started

3. Added a unit-specific needrestart override, validated the effective rule against both unit name forms, rechecked the signed artifacts and stopped service, preserved the halted journal, and atomically published the exact verified Signed journal. Reset the systemd failure counter and started the authority once. At 22:29:06 UTC the unit reported active/running, PID 4116259, NRestarts=0. Startup RPC bound at 22:29:07 UTC; finality verification remains pending.
4. Observer Nginx passed its existing configuration check and started at 22:29:05 UTC, PID 1251254, NRestarts=0. The public RPC health route returned HTTP 200. This confirms the proxy is reachable; finalized block RPC verification remains pending.
5. Correlated the November 5 observer outage with unattended upgrades: Nginx was restarted in the same batch as systemd-resolved and attempted its configuration test while DNS was unavailable. Added and validated a needrestart override for only Nginx on the observer, leaving package updates enabled. Nginx remained active on its original recovery PID.
6. Verified all three public HTTP RPC hostnames returned Chain 1266 incarnation 5 and the pinned Genesis. Finality and range calls still reported the missing bounded RPC cache during startup; val1 was advancing through the retained finality log. The active Atlas indexer was retrying and had indexed through height 5319451 before recovery.
