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

### Final outcome

Open. The coordinator must use authenticated proposal/certificate arrival for
the healthy fast path while retaining governed timeouts as failure deadlines.
Atlas must stop labeling batch-ingestion intervals as block-production time.

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
