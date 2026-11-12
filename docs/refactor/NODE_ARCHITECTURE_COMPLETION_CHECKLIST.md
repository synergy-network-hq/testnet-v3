# Synergy Node Architecture — Expanded Production Completion Checklist (Canonical 20-Role Taxonomy)

## Integrated offline recovery checkpoint — 2026-10-27

Current isolated engineering acceptance and actual five-host stopped-state evidence
are recorded in [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and the
[integrated report](INTEGRATED_LINUX_RECOVERY_REPORT_20261027.md).
The single runtime owns `crates/synergy-posy/src/persistence/evidence_store.rs`;
`tools/linux-node` owns the generated master, installer, conformance and lifecycle.
Indexed consensus archive schema1 preserves untouched legacy history; no alternate
validator architecture or consensus owner exists. Candidate package
`5a9e87db51f431cf7490806ad98e813206a44e2d34fbb08d3b3a25f4f95a91bf`
has passed recorded isolated gates. All five installed OLD packages pass the same
conformance policy and remain stopped, awaiting explicit software-only deployment
approval. Live qualification, signed publication and other role implementations
are not implied. Earlier checkpoints below remain historical.


## Canary critical path — 2026-10-21

The operator has frozen architectural scope. The current evidence, blocker
classification, minimal repairs and next action are maintained in the canonical
[implementation status](IMPLEMENTATION_STATUS.md). Earlier checkpoints below remain historical;
no v43 actual-host pass, deployment, TPS baseline or soak is claimed.

## Resource qualification checkpoint — account World lifetime, 2026-10-21

The memory/OOM gate remains **OPEN**. The sealed v41 runtime passed all28
component cases on each of five actual hosts (140 independently audited
records), under256MiB with zero swap and unchanged OOM counters. Val2/3/5
shared1GiB runs failed the unchanged30-second funded context-to-proof budget.
Val4/6 completed31 funded encrypted transfers and restart/rejoin, with no OOM
or swap; both pass the fixed anonymous/RSS and normalized I/O comparisons.
Their overall journal qualification fails because a few bounded metadata scans
could not obtain coherent snapshots during live writes. These failed records
and the original schema-error audit are preserved; no v41 overall pass is claimed.

The account-read repair releases the fully verified candidate World before
reconstructing the separately archived finalized World. Both archives retain
full validation; only verified scalar block/root commitments survive between
reads. This reduces simultaneous decoded residency, without a historical cache
or any consensus, signature, quorum or admission-policy change. Eight focused
RPC tests pass, including pinned/latest account values and missing candidate
World rejection. Encoded record limits are not a proven universal decoded-heap
bound; the actual-host qualification is explicitly scoped to its declared workload.

The next resource profile will use the canonical storage writer lock in shared
mode for bounded metadata-only observations. It will preregister a60-second
resource proof wait, retain the900-second funded cohort bound and separately
report every transaction exceeding30seconds as an admission timing failure.
This prospective measurement profile does not qualify default5 admission or
waive the canary admission gate. Full source/artifact freezing, all-five component
and shared-runtime requalification remain required. No deployment, initial TPS
baseline, canary launch or24-hour soak has started.


## Current resource qualification checkpoint — telemetry commitment reads, 2026-10-21

The memory/OOM gate remains **OPEN**. The v40 candidate lifetime repair passed
all27 component cases on all five actual hosts (135 independently audited
records), under256MiB with zero swap and unchanged OOM counters. Shared1GiB
runs completed on Val2/4/6; Val3 exceeded its30-second context-to-proof budget
at30.341s and Val5 exceeded native finality timing. All failure evidence is
preserved. No production deployment, TPS baseline or canary soak has started.

The independent v40 audit remains incomplete/failed: the last common native
observations preceded the scheduled1281-second shutdown, while the audit
required an observation at or after it. Val2/4 passed quantitative memory,
journal and I/O checks; Val6 failed the journal mean-count growth threshold
(post-restart34 to39 files during32-height retirement cycles). No v40 overall
qualification is claimed and no acceptance threshold is changed retroactively.

The next source repair exposes a bounded canonical candidate commitment read
for telemetry. It validates protected material, canonical block identity and
transaction/receipt correspondence and binds the result to durable finalized
state and PoSy finality, without reconstructing/hash-checking the archived
account world for every status poll. A telemetry commitment attests finalized
identity, not archived world readability. Block/account/execution/import and
recovery paths retain full world validation. No strong historical-world cache,
consensus owner, quorum, signature or governed admission policy is changed.

The final revised runtime requires focused regressions, a complete source freeze,
sealed artifacts and all-five actual-host qualification. The next measurement
harness parallelizes exactly five independent pinned account-proof reads while
preserving all proof checks and the30-second budget; explicit stage timings
are retained. Startup/end sampling and journal retirement observations must be
qualified before the memory gate can close. Default governed admission/finality,
initial TPS baseline, encrypted ETDAG canary and24-hour soak remain subsequent gates.


## Current memory qualification checkpoint — candidate lifetime repair, 2026-10-21

The memory/OOM gate remains **OPEN**. All26 v35 component cases passed on each
of the five actual hosts under256MiB with zero swap and no OOM. This does not
qualify the final integrated runtime. The v37 four-inflight mixed runs failed
on durable admission rejection; v38 serial runs on Val2/3 failed their300-second
count deadline despite verified wallet effects for19/12 cohort transfers.
Two Val3 transfers also exceeded the30-second context-to-proof budget.

Further source review found that PoSy retained executed candidates indefinitely
by height, pinning historical `Arc<WorldState>` values. Candidate payloads must
retire only after verified finality is durable; delayed finalized handoffs must
not repin them. Current/unfinalized candidates and durable safety commitments
remain required. The v39 successor campaigns were explicitly interrupted on
all five hosts after this defect was found; none is a qualification pass.

The revised candidate requires a new source freeze, sealed artifacts, focused
lifetime regressions and repeated actual-host qualification. Sustained memory,
I/O and protected-journal stabilization, restart/rejoin and funded encrypted
wallet effects remain mandatory. No production deployment, active admission
amendment, canary, TPS baseline or24-hour soak has started. Establish the initial
TPS baseline after the resource and admission gates pass, before stabilization
tuning, then repeat the controlled comparison after the canary soak.

## Current memory qualification checkpoint — v35 test correction, 2026-10-20

The memory/OOM gate remains **OPEN**. The v32 actual-host component campaign
passed single-owner4096-generation maximum-proof recovery but failed the
new three-owner4096 test: the test round-robinned three partial indexes in a
pool sized for two complete owners, then incorrectly assumed an owner had
installed before pressure. The production runtime already drives the earliest
pending recovery to completion before decoding the next owner. Its scheduler,
32MiB aggregate pool,40MiB scratch cap and consensus rules are unchanged.

The v35 test correction follows that runtime scheduling, asserts waiting
owners retain zero decoded history, requires two installed owners before
third-owner pressure, and checks retirement/resume with original journal
hashes unchanged. Local and actual-host qualification of the corrected test
and final sealed candidate remain required. v32 failures remain evidence;
they are not passes. Shared-process v33/v34 packages were staged but never
launched. The next mixed-memory package is v36, including bounded sampled
process I/O and per-device host counters for ZFS hosts whose cgroupio.stat
is empty; empty counters mean unavailable, never zero disk activity.

No deployment, active admission amendment, canary, TPS baseline or24-hour
soak has started. Those remain gated on memory/resource and admission closure.


## Remaining memory allocation audit — 2026-10-20

Overall memory qualification remains OPEN. The v27 Linux candidate is sealed
with matching complete source inventories before and after compilation. Runtime
SHA3-256: `8d1ad0f869f0ae60f0a8b49718907b91369f9d1e317075c3dbc9424b6208f168`.
The previous v22/v24 passes remain limited to their declared workload.

The repaired retry iterator selects at most64 payload/peer pairs before cloning.
Authenticated v3 collecting journal actions append/fsync before memory mutation,
preserve original native signatures and proofs, and replace whole-graph intake
rewrites. Cut/prepare/recovery phase frames retain their required full state;
this does not claim all persistence writes are constant-size.

Aggregate intake reserves completion across live targets, including native quorum
votes/certificates, runtime mirrors and all16 ETDAG outbound queue slots. The
collecting reservation pool is32MiB; transition/recovery scratch is40MiB.
Admission checks prospective per-target phase copies before accepting work.
Rejected, nondurable work restores its exact prior reservation; safety/storage
ambiguity retains reservations. Legacy recovery that cannot fit stops further
decoding with an explicit capacity diagnostic and preserves originals. Other
transport queues, finalized worlds and historical proof caches keep their
separate existing bounds; these two pools are not a whole-process memory bound.

Strict node/ETDAG Clippy passes. All46 ETDAG tests and seven focused collecting
regressions pass. Four resource regressions cover native quorum completion after
same-target saturation, many-target pressure, spare allocation capacities and
64 rejected speculative reservations. The real65536-byte encrypted wallet
carrier completes reveal/execution/finality on all five validators. A131072-byte
wallet carrier exceeds the existing1MiB authenticated-frame bound and is rejected
before durable vertex admission; that bound is preserved. Separate twelve-vertex
maximum131072-byte native collecting/restart tests preserve exact originals.

All23 new-artifact component qualification records pass on each actual Val2–Val6
under256MiB/Swap0: collecting/retries/resource pressure, both wallet cases,
all46 ETDAG tests,96/1024/4096 history and4096 maximum-proof recovery, ten native
runtime/restart cases and live-source proof validation. Final exported evidence
and independent audits remain pending.

V28 combined actual-host qualification FAILED on all five hosts. The isolated
signed-offset16 fleets each finalized the initial transfer, then lost readiness
during the first four concurrent funded submissions; zero of the required30
workload transfers finalized. All five1GiB/Swap0 monitors recorded zero OOM,
OOM-kill and MemoryMax events, with validated cleanup. The runs ended before
the scheduled restart and full native-pressure campaign. Fixed public exports
are preserved under node-platform/target/resource-repair-memory-host-evidence-v28-20261020.
The service-health/resource-pressure cause is under investigation using an
isolated diagnostic repeat; component passes do not close this failure.
No deployment, active policy change, TPS baseline, canary launch or24-hour soak
is qualified by these tests.

The isolated v29 diagnostic repeat captured a prospective intake request for
55,047,536 transition bytes against40MiB, degrading the whole-node readiness
while other validators remained healthy. The v30 source correction counts the
exact cut reference instead of a second full encrypted wallet vertex, separates
ordinary queued intake pressure from durable-phase health failures, and checks
closed queued targets before retrying capacity.32MiB/40MiB limits and exact
pipeline allocation guards remain unchanged. The phase bound also uses the
maximum of collecting and prepared serialization, reserves the one parent proof
actually present in runtime preparation, and separately counts canonical native
share wire instead of treating padded heap charges as JSON. Five resource
regressions and strict node/ETDAG Clippy pass on this candidate. The sealed v30
release four-wallet regression passes on every actual Val2-Val6 under256MiB/Swap0,
verifying all four transfers and all five account states. Peak process RSS is
142,958,592-151,822,336 bytes. The local debug build reached all-four certification
but hit its60-second no-finality-progress guard; that failure is retained. Full
24-case v30 host component qualification is still running.

The aggregate retained-history accounting repair is implemented in the v32 source:
both installed and in-progress owners charge indexes, proof locations, allocation
capacity and their latest proof to the same32MiB retained pool. Replay scratch
also includes resident history before decoding another frame. Prospective live
generation charges precede append; typed pressure preserves journal originals.
Each owner excludes its own existing reservation on retry. Finalization releases
only retired heights and re-enables capacity-blocked recovery when space changes.
The pending PoSy-to-ETDAG generation handoff now has an8MiB shared deep-byte
budget as well as entry caps; normal pressure retries from durable PoSy authority.
Each installed generation acknowledges its exact durable prefix immediately.

All47 ETDAG tests, six runtime resource tests and the shared proof-handoff test
pass locally. Genuine R3 timeout recovery, native empty/nonempty close and restart
also pass. The new three-owner regression verifies shared pressure, maximum1MiB
latest proofs, unchanged original journal hashes, retirement/retry without
self-reservation deadlock, and live append rollback. Fresh final source sealing,
all-five-host qualification and sustained memory/I/O stabilization remain OPEN.
V31 is HELD and will not qualify this revised source. V30 component results are
24/24 on Val3-Val6; Val2's measurement stopped on a disappearing cgroup pseudo-file
(ENODEV) after14 successful records, not a qualified all-host pass. Its failure
evidence and four complete public component exports are preserved under
node-platform/target/resource-repair-component-only-host-evidence-v30-20261020.
No canary or deployment starts before the memory gate closes.

## Live admission proof checkpoint — 2026-10-20 (v21–v24)

Fresh default5 reproduction v21 on actual Val5 uses the sealed v17 runtime and
native signed Genesis verification. It fails with a durable `closed_target`
receipt, not OOM: the target opens at0ms, RPC enqueue occurs at396.44ms and
verified cutoff closes at495.48ms on one native monotonic clock. The complete
failed public export and analysis are retained in
`node-platform/target/resource-repair-default5-host-evidence-v21-20261020/`.

The current v22 source candidate snapshots PoSy's bounded, already committed
live source record/witness instead of reopening the record and three QC files
and repeating the ingress-history QC verification. Publication still verifies
all three QCs against the active signed authority, exact ancestry, finalized
record and governed target context; historical sources keep the authenticated
durable reader. A malformed live witness fails closed without fallback. No
new retained cache, cutoff, quorum or signed lookahead policy is introduced.
A genuine five-validator regression passes locally with and without timing:
no-history live proof succeeds, historical proof remains readable, malformed,
truncated, forged and conflicting proofs fail. Targeted Clippy and format pass.
Complete pre/post Linux build source inventories match. Standalone v22 SHA3-256:
`c927a76e559bf4c6b7984a8732594338f429b817c171a80a5280583184b3e129`.
ETDAG, signing and Genesis artifacts remain byte-identical to v17.

V22 now passes all55 actual-host native/component measurement records across
Val2–Val6 under256MiB MemoryMax, zero swap and zero host/cgroup OOM deltas,
with validated cleanup. Peak native RSS is136.84MiB. Public exports and the
independent audit are retained in
`node-platform/target/resource-repair-node-host-evidence-v22-20261020/`.
The fresh v22 default5 retest fails admission: cutoff closes at330.93ms and
server enqueue-shape processing starts at534.49ms. Its complete failure export
is preserved; the cached source proof optimization does not fix default5.

The separately signed isolated six-height comparison v23 reaches durable
admission but its first transfer does not finalize within30seconds. It is a
failed comparison, not a pass or policy amendment. Its verified public export
is retained in
`node-platform/target/resource-repair-lookahead6-host-evidence-v23-20261020/`.
V24 full-process resource qualification of the current sealed v22 runtime
PASSES on all five actual hosts, using the maximum supported experimental
offset16, the same1GiB/zero-swap five-validator group cap, transfer counts,
deadlines and restart schedule. Each host finalizes1 initial plus30 workload
transfers with all-five effects verified (155 total). The30-transfer workloads
finish in98.68–217.35seconds against the unchanged300-second limit. Independent
public-evidence auditing verifies exact runtime/exporter identity, signed-profile
attestations, native observation and transaction proof streams, zero host/cgroup
OOM deltas, zero swap use, signer death before replacement, continued matching
finality after restart and validated cleanup. Final common heights are1140,659,
1277,578,1267 on Val2–Val6. Anonymous memory peaks are605.84–633.02MiB per
five-validator group. Four groups reach the cap and reclaim file cache; this
is survival under pressure, not spare headroom. Retained protected journals are
contiguous recent tails of25–51 records rather than all finalized heights.
Val4 ZFS ARC is accounted separately (peak8.49GiB; host available minimum108.93GiB).
The complete exports, independent audit and post-cleanup file metadata are in
`node-platform/target/resource-repair-memory-host-evidence-v24-20261020/`.

The declared current-runtime memory gate is now passed, together with the
supported-bound protected-history evidence on unchanged ETDAG artifacts below.
This closes the previously open protected-recovery growth and actual-host OOM
qualification for the declared profiles. It does not prove arbitrary-history
support,24-hour stability, default5 admission or distributed canary readiness.
The default5 and experimental6 failures remain open canary blockers. No
production/canary deployment or TPS/24-hour soak has started. Capture the initial
TPS baseline immediately after canary startup and before performance tuning.

## Admission comparison continuation — 2026-10-20 (v25–v26)

With the declared memory gate passed, the existing architecture comparison
continues using the same sealed v22 runtime and unchanged genuine workloads.
Fresh signed experimental offset7 (v25) fails on all five hosts: Val2 receives
a durable `closed_target` rejection; Val3/Val4/Val5/Val6 exceed the unchanged
30-second per-transaction finality budget during the30-transfer workload.
Initial single transfers pass on all five; none of these failed campaigns has
OOM or swap use. Public archives and envelope-correlated native availability
timings are retained in
`node-platform/target/resource-repair-lookahead7-host-evidence-v25-20261020/`.
The completed offset8 comparison (v26) fails the unchanged30-second loaded
transaction finality budget on all five hosts. Initial single transfers pass;
loaded finalized counts are19,6,0,2,9 on Val2 through Val6. Public manifests,
zero host/cgroup OOM deltas, zero swap and cleanup are independently checked in
`node-platform/target/resource-repair-lookahead8-host-evidence-v26-20261020/ANALYSIS.json`.
These diagnostic failures do not qualify healthy timing or activate a policy.
Further admission-window comparisons are paused for the remaining memory repair.

Native proposal timing hooks conservatively label all current observations
`recovered`; their source explicitly lacks healthy-cohort provenance. The
comparison reports observed latency only and cannot supply the required
healthy/worst-eligible p99 or50-percent admission headroom qualification by
relabeling those observations. This diagnostic limitation remains explicit.

## Memory qualification checkpoint — 2026-10-19 (v17–v20)

The final sealed v17 native candidate removes the consumed-state proof rewrite:
a small hash-chained durable transition replaces cloning and serializing the
full prepared record for a boolean change. Legacy frames, native verification,
original-byte indexes, atomic persistence and torn-tail recovery remain intact.
All39 ETDAG tests and strict targeted Clippy/format checks pass locally. Sealed
standalone SHA3-256:
`0613144c8d997965770e024297976e041fc9e6e1fe18d023d7dc63bcd700b565`.
Complete pre/post build source inventories match. Signing/Genesis companions
are byte-identical to v11. Other phase transitions still persist their bounded
current state; this repair does not remove every persistence write.

Actual Val2–Val6 hardware passes55 final-artifact component/native cases under
256MiB MemoryMax and zero swap (one39-test ETDAG suite plus ten native cases
per host); peak native RSS is131.61MiB. All25 final-artifact recovery/history
cases also pass. Each host verifies96,1024 and4096 generations with256KiB
authorizations,4096 generations with1MiB authorizations, and timeout-prefix
recovery. The maximum journal is8,891,619,937 bytes; peak native history RSS is
25.07MiB, with zero pending historical proof payloads and verified original
reads. Metadata is capped at4096 generation/marker entries; authorization size
is capped at1MiB. Cleanup is validated, every host/cgroup OOM delta is zero,
and swap remains unused. Val4 ZFS ARC is separately accounted (peak7.44GiB,
minimum available host memory110.04GiB); device io.stat cannot attribute ZFS
physical I/O. Four unchanged, exactly pinned libraries retain20 earlier passes;
old ETDAG artifacts receive no final-candidate qualification credit.

Final native full-process memory qualification passes on all five actual hosts
for the declared mixed campaigns. Val2/4/6 completed v18 with concurrent,
separately capped256MiB history pressure; Val3 completed fresh v19 against the
original ongoing history jobs. Val5 completed isolated v20 after validated
history cleanup. Each process unit runs five real validators at1GiB MemoryMax,
zero swap, signed experimental16 lookahead, four wallets, initial transfer plus
30 exact proof-verified transfers and all-five wallet effects within300s, then
stop531s/restart561s and681s total validator lifetime. The complete independent
public evidence audit passes all five, including original-signer stop before
replacement and matching advancing all-five commitments after restart.
Anonymous memory peaks are616.37–630.23MiB per five-validator unit. Four hosts
reach the1GiB cgroup cap and reclaim cache; every cgroup/host OOM delta is zero.
This demonstrates survival under the cap, not unused memory headroom or24-hour
stability. All five also pass the two native R4 exact retirement safety tests
under256MiB/zero swap. Six snapshot-cache pressure, reservation, active-custody,
lease/restart, incremental-cleanup and corrupt-input tests also pass on every
host under the same cap, with at most8MiB native RSS. Post-cleanup metadata confirms contiguous recent tails
of protected journals after hundreds of finalized heights; it does not claim
constant total chain storage or arbitrary-history support.

Failed campaigns remain failed: v18 Val3 stopped before initial transfer on a
bundled native telemetry identity/epoch/height check; source permits a null
finalized height before the first finalized state, but the original report
does not prove the exact invalid field. External v19 tooling adds only a
bounded wait for this valid null startup state, with strict immutable identity,
schema, five-validator finality and deadline checks retained (53 baseline tests
and23 runner tests pass). v18 Val5 finalized12 of16 submitted transfers before
its unchanged30s unresolved-finality budget expired; native finality continued
advancing together, with zero process-cap/OOM events. CPU/I/O contention was
observed, not proven causal. The separately declared v20 Val5 run starts only
after all original history jobs complete and their cgroups are proven empty;
it preserves the same artifact, caps, count, deadlines and restart schedule.
No all-five concurrent-pressure success is claimed.

Public archives, exact proof streams, sampled resource counters and independent
complete auditing are retained under
`node-platform/target/resource-repair-final-host-evidence-v18-20261019/`,
`node-platform/target/resource-repair-final-host-evidence-v19-20261019/` and
`node-platform/target/resource-repair-final-host-evidence-v20-20261019/`.
The complete mixed audit is `independent-audit-final.json` in the v20 directory;
R4 supplemental artifacts are in
`node-platform/target/resource-repair-final-host-r4-v17-20261019/`; snapshot-cache
artifacts are in `node-platform/target/resource-repair-final-host-cache-v17-20261019/`.

Default-lookahead5 funded ingress remains blocked by the reproduced admission
window failure. The experimental16 memory profile does not qualify default5,
production deployment, distributed canary, TPS/capacity or release Gate D/E.
No deployment, initial canary TPS baseline, ETDAG canary test or24-hour soak has
started. Capture the initial canary TPS baseline before tuning, then repeat the
same workload after stability. Earlier checkpoints below remain historical.

## Final memory candidate checkpoint — 2026-10-19 (v11)

Actual Val2–Val6 hardware passes75/75 capped component/native cases:25 cases
reuse the five unchanged, exactly pinned library artifacts;50 cases run the
final node test artifact SHA256
`25c0081f609f4dd8509f30802baef9002b4ca2c0eac1e7df037abef89cc495e1`.
All use256MiB MemoryMax and zero swap, with positive native test counts and
zero cgroup/host OOM events. Maximum native-test RSS is136.875MiB. Both stale
verified-head regressions pass on every host; strict same-height conflict
rejection remains intact. Complete build inventories match before/after;
standalone runtime SHA3-256 is
`2336bf66586f7786557049f086753dd7a9d4e92d38616832df1bae60088a0b02`.
Public archives and independently checked logs/hashes are retained under
`node-platform/target/resource-repair-final-host-evidence-v11-20261019/`,
including `summary-2-3-4-5-6.json`. Earlier checkpoints below remain historical.

The separate-process gate remains OPEN. All five v11 campaigns stopped at
funded-workload observation boundaries despite advancing native finality:
four report admission-context readiness unavailable; Val4 reports an ambiguous
admission response with receipt lookup unavailable. No OOM was observed;
aggregate cgroup peaks were487.32–576.13MiB under the declared1GiB cap. These
short failed runs do not qualify sustained load or restart/rejoin. The workload
harness is being corrected and ambiguous submission must be reconciled without
resubmission. Protected-growth and actual-host memory completion boxes remain
unchecked pending successful integrated qualification. No deployment, initial
canary TPS baseline, ETDAG canary test or24-hour soak has started.


## Resource amplification work — 2026-10-18

- [x] Replace per-transaction full-world cloning with an atomic touched-account write set; prove late failures leave state unchanged and canonical state/root results match.
- [x] Replace full-world finalized publication queues with compact Execution commitments and preserve the unconsumed finality front under acknowledgement backpressure.
- [x] Remove unconditional snapshot generation from every finalized height; materialize requested exact snapshots from verified durable state, outside the steady-state finalization handoff.
- [x] Remove payload clones from immutable storage batches and full-world compare-and-commit preconditions without changing byte/conflict/durability checks.
- [x] Complete scoped local validation of the resource repairs: the2026-10-18 checkpoint covered132 cumulative distinct scoped tests; subsequent candidate-store/cache/root regressions, migrated ETDAG/RPC/R3 callers, native funded transfer, H16 restart/rejoin, missing-payload/outstanding-request restart/reordered prefetch and on-demand snapshot after restart pass. Strict targeted Clippy, rustfmt and diff checks pass. Dated canonical status records exact suites and limits; the v17–v20 checkpoint records the completed actual-host memory qualification and its explicit limits.
- [x] Bound configured history retirement to256 exact height paths per namespace and resume with durable cursors; prove restart, interrupted deletion, symlink/corrupt cursor rejection and no ahead-of-commit pruning.
- [x] Use one consistent state transaction record limit on commit and restart; prove interrupted recovery with a world record above4MiB.
- [x] Borrow the immutable execution parent and move successful overlay state; share immutable candidate worlds and cache finalized authorization state without changing serialized state or consensus commitments.
- [x] Bound ETDAG successfully processed announcement fingerprints; preserve new/altered/session-replaced authentication and response-producing request handling. Native funded-transfer, ETDAG library/owner and strict Clippy validation pass.
- [x] Replace sequential finalized-world writes with bounded checkpoint/delta storage; prove legacy reads, crash recovery, restart, exact full snapshot bytes, idempotent replay, root/corruption rejection and checkpoint-safe pruning.
- [x] Complete bounded incremental candidate persistence with atomic metadata/world records, legacy/wire compatibility, immutable concurrent replay, corrupt-dependency rejection, checkpoint-safe backlog pruning and native missing-payload/outstanding-request restart/reordered prefetch proof. ETDAG, RPC and R3 recovery use the shared reader; native funded transfer and H16 restart/rejoin pass. See2026-10-19 evidence in the canonical status.
- [x] Bound the disposable Sync snapshot cache by four contexts and514MiB of conservative encoded-payload reservations; pin active incoming custody, lease outgoing transfers, drain legacy/orphan files incrementally, bound decoded restore data and verify native eviction/rebuild after restart. The documented64MiB/64-chunk local profile falls back to canonical replay for unsupported authenticated snapshots. All six cache pressure/custody/lease/cleanup tests and native authenticated snapshot restart pass on actual Val2–Val6 under256MiB/zero swap; distributed concurrent-request fairness remains a separate canary qualification.
- [x] Qualify aggregate protected recovery memory and repeated timeout-prefix work against the supported4096-entry/1MiB-authorization bounds: final v17 actual Val2–Val6 capped history cases all pass; exact original reads, bounded pending payloads and zero OOM are evidenced in the dated v17–v20 checkpoint. This is supported-profile resource qualification, not distributed canary or arbitrary-history support.
- [x] Freeze and qualify exact v17 artifacts on actual Val2–Val6 hardware for the declared mixed memory campaigns: capped native/component and supported-history tests, five-process funded execution, stop/restart/catch-up, sampled RSS/cgroup memory/I/O and post-cleanup storage metadata all pass independent evidence auditing. Val5 passes isolated after history cleanup; all-five concurrent-pressure success, default5 ingress, distributed canary and24-hour stability remain unqualified. ZFS physical I/O attribution is unavailable.
- [x] Requalify the changed v22 runtime on actual Val2–Val6:55 capped native/component measurements and five isolated1GiB/zero-swap funded/restart campaigns pass independent audit. Supported protected growth and actual-host OOM qualification are closed for these declared profiles; default5/experimental6 admission, distributed canary, TPS and24-hour soak remain open. See the2026-10-20 v21–v24 checkpoint and exact evidence paths.
- [ ] Eliminate ETDAG retry temporary payload-times-peer cloning, prove bounded backpressure/fairness, audit aggregate live collecting/frame bytes and clone/serialization peaks, then qualify the changed candidate. Overall memory closure remains open until these additional paths are resolved.


## Authorized clean PoSy replacement — 2026-10-14

The CTO explicitly retired the failed Val2–Val6 incarnations and authorized destruction of their validator deployments and custody. The historical recovery observations below are superseded as operational instructions. No retired runtime state or signing identity may be imported into the new chain. Chain ID remains1266; Val1, SSH, shared VPN infrastructure, unrelated roles and the canonical source checkout are excluded from deletion.

Verified first deletion inventory on each of Val2, Val3, Val4, Val5 and Val6: `/usr/local/libexec/synergy/posy-stability`, `/etc/synergy/posy-stability`, `/etc/synergy/posy-baseline`, `/var/lib/synergy/posy-stability`, and `/etc/systemd/system/synergy-posy-stability.service`. The service selects the old `synergy-node-r3-admission-cutoff` binary. All roots are owned by root, are not symlinks and contain no nested mounts. Val4 uses separate ZFS datasets for `/usr/local` and `/var/lib`; the other hosts use ext4. No associated cron jobs were found. Shared NetBird, transport snapshot proxy and SSH service identities were recorded before deletion. Additional legacy validator copies require separate exact ownership inspection before their removal.

- [ ] Verify all retired validator services/signing workers are absent and remove verified old deployment, custody and legacy copies without backups.
- [ ] Finish the existing Sync-owner raw-frame backpressure correction and bounded protected-journal restoration; qualify the coordinated source without new protocol mechanisms.
- [ ] Generate fresh native PQC validator identities on their respective machines; cryptographically verify possession and bind them to one newly signed Genesis and explicit new network incarnation.
- [ ] Install exactly one canonical validator binary, config, Genesis, state directory, identity and service per host, with no imported runtime data.
- [ ] Update the original Desktop credentials workbook in place with new public metadata and custody references; never create a workbook copy or expose private material.
- [ ] Prove all-five authenticated connectivity and identical advancing finalized block/execution commitments across repeated ten-block proposer rotations.
- [ ] Prove sequential proposer takeover, individual restart/rejoin, funded exactly-once ETDAG transactions, bounded resources/persistence and measured actual-host timings.
- [ ] Establish the TPS baseline and start the loaded24-hour soak only after these observable chain-functionality gates pass.

Architecture review limitation: deterministic ten-block turns, sequential failover, seeded epoch slots and authenticated authority transitions are implemented. The current governed profile is a single five-validator cluster. Multi-cluster assignment/rotation and the full automatic security-triggered replacement path have not been qualified; do not represent them as proven or silently bypass them during the reset.


### Verified legacy PoSy deletion inventory — 2026-10-14

These are additional retired validator deployment targets, inspected before deletion. Shared NetBird/NCP/SSH, the generic role launcher, transport snapshot proxy and transport environment are excluded. Legacy source trees are not deletion targets.

**Val2**

- `/opt/synergy/chain1266`
- `/var/lib/synergy/validator/chain-1266/incarnation-5`
- `/var/lib/synergy/validator/config/validator`
- `/etc/synergy/chain1266/private/validator-02`
- `/etc/synergy/chain1266/validator-02.env`
- `/etc/synergy/chain1266/validator-02.toml`
- `/etc/synergy/chain1266/etdag`
- `/etc/synergy/chain1266/staging`
- `/etc/synergy/chain1266/validator-public-bundle`
- `/etc/synergy/chain1266/genesis.json`
- `/etc/synergy/chain1266/release-candidate.json`
- `/etc/synergy/chain1266/release-package-manifest.json`
- `/etc/synergy/chain1266/desired-state.json`
- `/etc/synergy/chain1266/testnet-v3-genesis-release-approval.json`
- `/etc/synergy/chain1266/fresh-genesis-authority-freeze.json`
- `/etc/synergy/chain1266/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json`
- `/home/synergyadmin/posy-v3-release-r9-bootstrap-p1-e0f11d4`
- `/home/synergyadmin/posy-v3-patch-r5`
- `/home/synergyadmin/posy-v3-release-r9-write-9bf22b0`
- `/home/synergyadmin/posy-v3-release-r6-846f8bd`
- `/home/synergyadmin/posy-v3-release-r9-replay-ebfb844`
- `/home/synergyadmin/posy-v3-host-stage-r10-e43f934`
- `/home/synergyadmin/posy-v3-release-r9-serialized-d955c5f`
- `/home/synergyadmin/posy-v3-release-r10-e43f934`
- `/home/synergyadmin/posy-v3-release-r9-bootstrap-v20-e0f11d4`
- `/home/synergyadmin/posy-protected-harness-run.DYmIFA`
- `/home/synergyadmin/posy-v3-release-00dcead`
- `/home/synergyadmin/posy-v3-release-r9-bootstrap-e0f11d4`
- `/home/synergyadmin/posy-v3-release-r11-45d8a39-final`
- `/home/synergyadmin/posy-v3-release-r10-e43f934-final`
- `/home/synergyadmin/posy-v3-host-stage-r11-45d8a39`
- `/home/synergyadmin/posy-v3-release-r9-write-a942189`
- `/home/synergyadmin/posy-v3-release-r9-e2969a1`
- `/home/synergyadmin/posy-v3-release-r8-b6216e5`
- `/home/synergyadmin/posy-protected-harness-run2.TxsqO4`
- `/home/synergyadmin/posy-v3-release-r9-final-e2969a1`
- `/home/synergyadmin/posy-v3-stage-r3`

**Val3**

- `/opt/synergy/chain1266`
- `/var/lib/synergy/validator/chain-1266/incarnation-5`
- `/var/lib/synergy/validator/config/validator`
- `/etc/synergy/chain1266/private/validator-03`
- `/etc/synergy/chain1266/validator-03.env`
- `/etc/synergy/chain1266/validator-03.toml`
- `/etc/synergy/chain1266/etdag`
- `/etc/synergy/chain1266/staging`
- `/etc/synergy/chain1266/validator-public-bundle`
- `/etc/synergy/chain1266/genesis.json`
- `/etc/synergy/chain1266/release-candidate.json`
- `/etc/synergy/chain1266/release-package-manifest.json`
- `/etc/synergy/chain1266/desired-state.json`
- `/etc/synergy/chain1266/testnet-v3-genesis-release-approval.json`
- `/etc/synergy/chain1266/fresh-genesis-authority-freeze.json`
- `/etc/synergy/chain1266/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json`
- `/home/synergyadmin/posy-v3-patch-r5`
- `/home/synergyadmin/posy-r8-preflight`
- `/home/synergyadmin/posy-v3-stage-r3`

**Val4**

- `/opt/synergy/chain1266`
- `/var/lib/synergy/validator/chain-1266/incarnation-5`
- `/var/lib/synergy/validator/config/validator`
- `/etc/synergy/chain1266/private/validator-04`
- `/etc/synergy/chain1266/validator-04.env`
- `/etc/synergy/chain1266/validator-04.toml`
- `/etc/synergy/chain1266/etdag`
- `/etc/synergy/chain1266/staging`
- `/etc/synergy/chain1266/validator-public-bundle`
- `/etc/synergy/chain1266/genesis.json`
- `/etc/synergy/chain1266/release-candidate.json`
- `/etc/synergy/chain1266/release-package-manifest.json`
- `/etc/synergy/chain1266/testnet-v3-genesis-release-approval.json`
- `/etc/synergy/chain1266/fresh-genesis-authority-freeze.json`
- `/etc/synergy/chain1266/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json`

**Val5**

- `/opt/synergy/chain1266`
- `/var/lib/synergy/validator/chain-1266/incarnation-5`
- `/var/lib/synergy/validator/config/validator`
- `/etc/synergy/chain1266/private/validator-05`
- `/etc/synergy/chain1266/validator-05.env`
- `/etc/synergy/chain1266/validator-05.toml`
- `/etc/synergy/chain1266/etdag`
- `/etc/synergy/chain1266/staging`
- `/etc/synergy/chain1266/validator-public-bundle`
- `/etc/synergy/chain1266/genesis.json`
- `/etc/synergy/chain1266/release-candidate.json`
- `/etc/synergy/chain1266/release-package-manifest.json`
- `/etc/synergy/chain1266/desired-state.json`
- `/etc/synergy/chain1266/testnet-v3-genesis-release-approval.json`
- `/etc/synergy/chain1266/fresh-genesis-authority-freeze.json`
- `/etc/synergy/chain1266/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json`
- `/home/synergyadmin/posy-v3-patch-r5`
- `/home/synergyadmin/posy-r8-preflight`
- `/home/synergyadmin/posy-v3-stage-r3`

**Val6**

- `/opt/synergy/chain1266`
- `/var/lib/synergy/validator/chain-1266/incarnation-5`
- `/var/lib/synergy/validator/config/validator`
- `/etc/synergy/chain1266/private/validator-06`
- `/etc/synergy/chain1266/validator-06.env`
- `/etc/synergy/chain1266/validator-06.toml`
- `/etc/synergy/chain1266/etdag`
- `/etc/synergy/chain1266/staging`
- `/etc/synergy/chain1266/validator-public-bundle`
- `/etc/synergy/chain1266/genesis.json`
- `/etc/synergy/chain1266/release-candidate.json`
- `/etc/synergy/chain1266/release-package-manifest.json`
- `/etc/synergy/chain1266/desired-state.json`
- `/etc/synergy/chain1266/testnet-v3-genesis-release-approval.json`
- `/etc/synergy/chain1266/fresh-genesis-authority-freeze.json`
- `/etc/synergy/chain1266/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json`
- `/home/synergyadmin/posy-v3-patch-r5`
- `/home/synergyadmin/posy-r8-preflight`
- `/home/synergyadmin/posy-v3-stage-r3`

### Qualification topology correction — 2026-10-13
Actual-host result (2026-10-14, candidate23): exact SHA3-256 `6fbd05f27aaaac23d2afa6fb2a115791637cfbbcbd4d870cd55ef4185477485a` was installed and natively verified on Val2–Val6 using the existing paths and signed R1/R2/R3+R4 commitment. The completed-response handoff is bounded and retained through preparation/downstream pressure. Actual acceptance FAILED: Val3 remains H10870 with repeated incomplete H10871 assemblies; Val5 again exceeded startup/shutdown deadlines after recovery evidence accumulated and was intentionally stopped after one restart. Leading durable finality remains H27239. Protected target files are12 on Val2/Val4/Val5/Val6 and5 on Val3. Further releases are frozen pending the integrated ownership/restoration review in `protocol/posy-v3/ARCHITECTURE.md`; funded execution, TPS and soak are not complete. Current state is recorded in each existing `VALIDATOR_ISSUES.md`.

Actual-host evidence update (2026-10-14, candidate22): all five hosts natively verified and started exact SHA3-256 `00c01a73d0a9fcbfada2d5a04b308cb970fa7c4e5c3ecff307119952bcffa314` with approved R4 bound in the signed release. Val5 completed startup, serves RPC and has zero restarts. Protected journal counts fell to12 on Val2/Val4/Val5/Val6 and5 on Val3; finalized/state commitments did not change. Val3's first broken boundary is now directly observed: complete valid H10871 responses are discarded on shared preparation-mailbox backpressure, repeatedly downloading the same block. The bounded existing-owner handoff correction is in progress. Leading finality remains H27239; TPS and soak are pending.

- [ ] Complete the separate genuine simplification review, preserving clustered security, epoch rotation and security-triggered validator replacement. Scope recorded in the existing `protocol/posy-v3/ARCHITECTURE.md` section dated2026-10-14; no new recovery/certificate architecture is authorized.
- [ ] Apply the historical-file/full-history-processing review to all Synergy node-platform roles after immediate validator recovery/soak entry; retain role-specific safety and recovery evidence. Validator R4 is not blanket deletion authority.

Source qualification (2026-10-14, candidate22 pending build): approved R4 retirement, single-pass original recovery authentication and bounded existing-owner Sync diagnostics are implemented together. ETDAG34, R4 safety/cleanup2, Sync11, execution2 and genuine R3 recovery1 tests passed; strict Clippy and scoped formatting passed. R4 has not yet removed live journals. The exact Linux build, R4-bound native release verification, actual five-host finality/catch-up and transactions remain required before TPS or soak.

Actual-host evidence update (2026-10-14): signed candidate sequence21, Linux SHA3-256 `2c630ae43a78e6b48b6021ce0b3a7654a4019af900a860582bf1df4537549f84`, was installed and natively verified on all five existing hosts. The coordinated recovery checks passed (PoSy30, native anchor1, compact-cache2, native R3 restart1, timeout-subset1), TPS tooling23 tests and strict Clippy passed. Bounded lease reconstruction reduced Val2/Val4/Val6 resident memory from about1.1GiB to234–238MiB; Val3 started near53MiB. Finality still stalls at H27239, Val3 remains H10870, and Val5 still exceeds its owner lifecycle deadline (31-second total failed attempt including cleanup, versus approximately8minutes before; candidate23 provenance confirms10seconds per owner command). Val5 repeat startup was stopped; no durable state was reset/deleted. A duplicate generation/marker authentication pass was identified and corrected in source, pending joint validation with R4. Operator explicitly approved R4 retirement on2026-10-14; its implementation and qualification remain pending. No TPS baseline or soak has started.

Actual-host evidence update (2026-10-13 19:21 UTC): signed candidate sequence20, Linux SHA3-256 `bfd30ab021ea07785fc0152b7e56e6e553f8b95a776de208be7e23421666e89d`, was installed in the existing binary/release paths and natively verified on Val2–Val6. One process per host was checked; keys, Genesis and durable journals were preserved. Val3 passed its old timeout boundary and committed existing certified history from H10863 through H10870 without T1. This does not prove new distributed block production. The leading finalized tip remains H27239. Val5 hit the ETDAG owner startup deadline while restoring retained generations; its repeat startup was stopped. T1 necessity is unproven. Actual-host TPS and soak gates remain open.

- [x] Restore fresh Atlas observations using the existing configured SSH masters. Publisher output and the live telemetry file were independently verified; the soak card remains pending.
- [ ] Complete bounded recovery verification and lease-scoped PoSy reconstruction together, preserving exact verified parents, rounds, carry, finality and signer restrictions. Qualify full-replay equivalence before installing another candidate.
- [ ] Prove a safe retirement boundary for obsolete protected target records before enabling automatic removal. The per-target append journal fixes rewrite amplification and the 16MiB snapshot boundary; it does not bound total retained files.

- [ ] Use Val2–Val6 for representative timing, admission-window sizing, TPS baseline/capacity and the loaded24-hour soak. A single12CPU/approximately6.6GiB Linux host running five validators shares CPU, memory and storage; its performance cannot qualify distributed production capacity or select production timing.
- [ ] Preserve single-host native tests as functional/fault regressions only, then qualify the unchanged candidate on five independent validator hosts before activation and soak entry. Genuine funded effects and common finalized commitments remain mandatory.
- [ ] Resolve and qualify the actual-host failures observed2026-10-13: Val3 timeout-proof variant rejection; Val5 durable admission-close InvalidCapacity. Do not erase journals or repeatedly restart a safety failure.
- [ ] Ensure Atlas reports actual-host service/chain status and fresh observations independently of isolated tests.

## Approved architecture execution gates — 2026-10-11

Operator-authorized scope as of2026-10-13: complete the coordinated source implementation before running consolidated tests and qualification. Current qualification scope is chain stability, validator recovery and encrypted ETDAG native transactions; new system-contract deployment, protected-wallet profiles and multisig architecture are deferred. Gate A timing/design evidence remains open and must be completed before parameter selection or activation. Source implementation does not close any qualification gate. Historical seq19 rollout and earlier diagnostics remain evidence with their original limitations.

Owners: architecture lead owns design and review; scoped source owners implement their modules; qualification owner owns deterministic and full-process evidence; release owner owns exact artifact provenance; fleet operator alone owns live actions; protocol authority approves concrete semantic amendments; operator reviews soak progression and Val1 cutover. Root coordinates assignments and canonical evidence pointers.

- [ ] **A — Design and measured contracts** (architecture lead; current authorized gate).
  - [x] Revise the original remediation DOCX in place and visually verify its27 repaired pages plus the two scheduling-adjustment pages; update canonical execution gates without another workbook or source copy.
  - [x] Implement and locally test the measurement reducer, fixture/process safety guards, opt-in supervisor timing and native read-only preflight. These tools are not actual Linux timing or funded-transfer qualification.
  - [x] Issue the fresh synthetic fixture, verify transport attestation, execute native diagnostic phase hooks, and resume the isolated Linux process fleet with one namespace/IP per validator. The bounded 60-second diagnostic reached identical finalized H93 on all five with retained journals; simulated provider status and placeholder Genesis anchors remain explicit limitations.
  - [x] Verify genuine steady-state protected transfers with identical finalized receipts and wallet effects on all five isolated processes (A1 D=6, D=7, D=8).
  - [ ] Complete client-origin admission distributions, healthy-cohort classification and load/degradation/outage headroom before selecting a timing profile.
  - Evidence (2026-10-12, run9): matching isolated finalized H728 on all five; target596 window224.383ms, measured HTTP intake274.791ms, dispatch7.178ms, signing15.480ms. Submission rejected; durable admission/availability and funded finality remain unmeasured. Exact artifact and trace pointers: `IMPLEMENTATION_STATUS.md` HTTP intake checkpoint and `protocol/posy-v3/ARCHITECTURE.md`.
  - Evidence (2026-10-12, run10): controlled100ms egress delay admitted target744 locally but did not form availability quorum before cutoff; all five finalized an empty batch and unchanged wallet effects, then advanced to common H809. Public reached-boundary evidence: `node-platform/target/posy-isolated-control-20261012/linux-admission-boundary-measurements.json`. Complete admission-to-VAC timing and healthy cohort remain open.
  - Evidence (2026-10-12): `dev:/tmp/posy-isolated-measurements-20261012/process-observations-5.json`, `process-run-5.log`, per-node `timing-resume1.jsonl`, and `node-platform/target/posy-isolated-control-20261012/linux-resume-measurements.json`. Gate A remains open; no live deployment, TPS baseline or soak qualification.
  - [ ] Measure proposer/consensus/pipeline timing, context publication, cutoff lifetime, RPC/remote signing/submission latency, durable writes, replay and scheduling delay; record distributions and actual observation windows.
  - [ ] Draw dependency graph and identify every authority owner, queue, certificate prerequisite, cross-thread handoff and progress/recovery trigger.
  - [ ] Specify executable contracts for admission availability, bounded work, PoSy height/round ownership, durable acknowledgements and recovery; select budgets from measurements rather than a fixed cadence target.
  - [x] Add initial abstract scheduling contracts for closed-target races, immutable target binding, restart persistence, duplicate/nonce replay, expiry/backpressure, below-quorum availability, authorized reveal, three-QC finality and certified empty-material gating. Seven deterministic regressions passed2026-10-12 in `node-platform/tools/validator/test_model_posy_admission_scheduling.py`.
  - [x] Extend the abstract model with retained pre-cutoff availability votes, local-admission-without-quorum nonexecution, and late reconstruction from existing votes only. Nine deterministic tests pass; global cutoff/trusted verification assumptions remain explicit and do not close Gate C.
  - [ ] Extend the initial model with actual authorization/evidence verification, fair assignment, retention, full fault traces and comparative measured performance. The nine abstract tests do not close Gate C or qualify cryptography, timings, production persistence or the10,000-seed campaign.
  - [ ] Compare current F+5, measurement-derived larger lookahead and durable encrypted ingress/eligible-batch queues under the same workload; specify target assignment, expiry, replay, fairness, confidentiality and empty-height eligibility. Keep block cadence and admission budgets separate. See `protocol/posy-v3/ARCHITECTURE.md` scheduling adjustment dated2026-10-12.
  - [ ] Review the integrated design, certificate reductions and any concrete protocol amendment. Explicit amendment approval and governed authority updates are mandatory before semantic activation.
  - Evidence: approved architecture plan; canonical `protocol/posy-v3/ARCHITECTURE.md`, `PROTECTED_PIPELINE_PROTOCOL.md`, `POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md`; existing incident/TPS logs. Gate A permits measurement instrumentation and isolated diagnostic fixtures; it does not authorize live deployment or runtime architecture changes.
- [ ] **B — Integrated implementation** (assigned source owners).
  - [ ] Freeze the exercised legacy/current address profile and canonical bytes across Genesis/runtime/admission/execution/client; prohibit node-local consensus derivation selection and prefix-derived authority.
  - [ ] Verify signed chain/incarnation/account/target/nonce/payload binding, existing canonical encoding, distinct-authority counting where applicable and no alternate native authorization bypass.
  - [ ] Verify rejection/duplicate/ambiguous-response reconciliation, exactly-once durable wallet effects and the selected profile's nonce/fee/revert/max-fee behavior; do not silently activate blueprint semantics.
  - [ ] Preserve authorized private signer custody, explicitly version future unsupported account profiles and label baseline/soak as current native ETDAG traffic rather than protected-wallet or multisig performance.
  - [ ] Confirm qualification Genesis/transfer dependencies do not require new executable system contracts; reconcile any actually exercised contract's address/class/authority before freezing.
  - Scope reference: `protocol/posy-v3/ARCHITECTURE.md`, Qualification scope and shared authorization requirements dated2026-10-13. Deferred feature work can begin after soak starts only in source/isolated environments; soaking bytes/configuration remain frozen.

  - [ ] Implement thread ownership and bounded work; isolate I/O and cryptographic work without introducing another consensus authority.
  - [ ] Implement measured admission lifecycle, durable recovery contracts and telemetry together; cover timeout, overload, shutdown and restart boundaries.
  - [ ] Complete caller migration and source review against approved contracts; preserve all signing guards, journals and quorum semantics unless explicitly amended.
  - Evidence: canonical source revision/diff, module ownership map, focused tests and telemetry schema; `IMPLEMENTATION_STATUS.md` distinguishes implemented from verified.
- [ ] **C — Protocol qualification** (qualification owner).
  - [ ] Execute a state model and deterministic fault scenarios within declared class assumptions: partitions, dropped/reordered/duplicate messages, restarts, rounds, cut/reveal and recovery exclusions.
  - [ ] Complete a 10,000-seed campaign with reproducible seed/configuration manifests and recorded failures; review coverage rather than counting passing seeds alone.
  - Evidence: genuine authenticated fixtures in `node-platform/bin/synergy-node/src/services/{socket_qualification,posy_qualification,etdag_qualification}.rs`, exact test names, logs and campaign exit status.
- [ ] **D — Exact Linux artifact qualification** (release and qualification owners).
  - [ ] Build the reviewed revision using pinned Rust 1.97 and locked dependencies; record toolchain, lockfile/source hashes, build command and provenance.
  - [ ] Qualify the exact resulting bytes in isolated full-process validators with real networking, storage and production signing/admission paths; identify any missing facility before implementation.
  - [ ] Pin artifact digest and signed release identity only after qualification; review journal compatibility and explicit rollback safety.
  - Evidence: `node-platform/tools/release/build-linux.sh`, canonical signed release metadata and full-process logs. In-process socket tests alone do not satisfy this gate.
- [ ] **E — Five-host qualification** (fleet operator).
  - [ ] Verify all five exact signed artifacts, configuration and membership; prove advancing common finalized block/state commitments and funded transfers with identical applied receipts and wallet effects.
  - [ ] Qualify three-validator halt, four-validator automatic recovery, fifth rejoin and individual restarts with retained journals and zero unexplained automatic retries.
  - Evidence: `node-platform/tools/validator/test-posy-live-quorum-recovery.py`, canonical live observations, journal cursors and exact RPC/durable proofs. Historical seq18 recovery PASS is prior evidence, not approval of a new architecture release.
- [ ] **F — TPS baseline and measured capacity** (load qualification owner and fleet operator).
  - [ ] Capture the initial canary baseline before tuning, preserve its exact artifact/configuration, workload and host/resource context, then repeat the same workload after stabilization for a direct comparison (operator direction2026-10-19). Memory qualification remains a prerequisite.
  - [ ] Finalize the first funded transfer, then 1 TPS / 30 transactions / 30 seconds; then 1 TPS for 10 minutes.
  - [ ] Run 2, 4, 8 TPS and subsequent doubling rungs for two minutes each under declared stop conditions; validate the highest clean rung for 10 minutes.
  - [ ] Report offered/accepted/executed/finalized TPS, queue/backlog, latency, resources, observed cadence and rejection reasons. Remove or separately characterize generator constraints before capacity claims.
  - Evidence: canonical TPS JSON/logs and `node-platform/tools/validator/run-posy-tps-baseline.py`; existing short-run caps do not establish network capacity and must not be silently stretched.
- [ ] **G — Reliability qualification** (fleet operator; operator review).
  - [ ] Complete a 24-hour loaded fault soak with declared workload/fault schedule, matching commitments and recorded progress/recovery/resource measurements.
  - [ ] Review the complete 24-hour evidence before proceeding; run seven days only if clean. Record failures and restart qualification as required by reviewed changes.
  - Evidence: canonical soak observations, fault events, journal cursors, TPS/receipt accounting and explicit review decision. Cadence is measured; no invented fixed target is a completion substitute.
- [ ] **H — Separate Val1 cutover** (operator and fleet operator).
  - [ ] Prepare and review the exact membership/identity/network/release transition, archive/snapshot requirements and rollback compatibility.
  - [ ] Obtain separate concrete approval; execute and verify the approved transition only after preceding gates meet their documented acceptance criteria.
  - Evidence: approved cutover procedure and canonical identity/authority/workbook records; no implicit authorization from architecture implementation approval.


## Authenticated socket checkpoint — 2026-10-09

Historical observation (2026-10-10; superseded by the dated actual-host evidence above): approved R2 resumed the retained chain beyond H5797 without reset and exact all-five finality matched H5808; subsequent sustained gate failed Val3 execution lag. At that observation sequence13 was verified and active on allfive, preserving identities/state/journals. It included qualified network burst drain and four-prefetch chunk assembly with unchanged64MiBaggregatebound. Genuine interleaved-chunk/outstanding-request restart qualification208.71s and strictClippy/Linuxbuildpassed. All-five matching advancing finality, measured cadence, sustained resilience, public-tier cutover and Val1 transition remained open; these historical checks do not qualify the current candidate.

Continuation: canonical fresh Genesis producer passed six tests; authenticated future-QC/witness replay regression passed. Genuine nonempty socket admission/execution/duplicate/cutoff test PASSED through H8: full dual-authorized ML-DSA-87 transfer, ML-KEM-1024 envelope, all-five durable VACs and genuine threshold reveal. The old H3 divergence came from subset-specific transcript roots entering execution authority; stable verified reveal authorization now binds the semantic candidate while exact authenticated transcripts remain audit/recovery evidence. Same-state/material roots across different proof subsets were observed. First focused restart test stayed alive but remained at H6 while peers reached H18; later runs exposed finality-before-candidate and independently signed snapshot collisions. Both source boundaries repaired; genuine snapshot-variant/content-conflict regression passed, full focused rejoin rerun remains pending. No live deployment or workbook changes.

VALIDATED_LOCAL: genuine five-service TCP/PQC fleet matched finalized H70 across all five validators and continued to matching H74 with one offline at unchanged4/5 quorum. Full qualification fails when the restarted validator receives a newer QC before verified catch-up; L11 remains open until that recovery boundary passes. Accepted macOS stream inheritance fixed and delayed-byte transport regression passed. Identity/transaction/Genesis11 tests and canonical public identity loader4 tests passed. No fresh artifacts, custody generation, deployment or workbook changes in this checkpoint.

## Protected crypto and custody checkpoint — 2026-10-09 UTC

IMPLEMENTED / VALIDATED_LOCAL: governed ML-KEM-1024 + AES-256-GCM + Shamir consumer, separate consensus/ingress key roles, exact target/registry/membership verification, AES tag-aware canonical padding, optional absolute custody path schema, explicit generate-etdag-1024 command, and signed-policy key coverage checks. Scoped package tests passed: ETDAG18, client1, config4, keytool7, Genesis1. Durable nonempty preparation/recovery hooks are implemented; runtime share delivery and its new integration regression remain in progress. No fresh signed artifacts, deployment, live finality, or Val1 conversion is claimed. The prior Linux binary predates these crypto changes and is not the current deployable candidate. The operator approved the cutoff clarification on2026-10-08; signed policy activation and runtime integration remain in progress.

## Historical parallel fresh-chain implementation checkpoint — 2026-10-08

Validated checkpoint: combined53tests and five additional distinct restart/queue/Sync regressions passed; four existing router regressions passed. Linux x86-64 candidate built successfully (SHA256 f83774e08d38634919d13d80ae392c79de68156a2c3ade792f6c938b8be4c9e6), but native execution/deployment remains unverified. L04 awaits explicit approval of the concrete cutoff clarification. L05–L10 have implemented, locally tested source boundaries; full signed launch authority and complete proposal/reveal integration remain open. All five target hosts passed read-only access/clock/resource/mesh checks. L11 and L14–L21 remain incomplete; no live service or workbook change occurred in this checkpoint.

## Fresh PoSy launch execution checklist — 2026-10-08

Scope: start the completely fresh val2–val6 chain, prove sustained finality and
fault recovery, then replace the Val1 single authority with PoSy val1. This is
the active launch checklist; the broader architecture backlog below is separate.
A checked launch item requires the stated evidence, not merely a source file.

- [x] L01 — Establish the canonical SSD checkout and update workspace pointers; preserve the single Desktop credentials workbook. Evidence: root AGENTS and prior in-place workbook verification.
- [x] L02 — Validate launch-compatible validator custody and key bindings. Existing six bundles/30 key pairs were verified. Public-only reinspection confirms ML-KEM-768 belongs to entropy contribution, not ingress; existing bundles have no protected ingress role. Fresh launch requires additional ML-KEM-1024 ingress custody and ML-DSA-65 transport keys bound to the existing FN-DSA identity. Preserve all existing identity/entropy keys; update only the canonical Desktop workbook if custody changes.
- [x] L03 — Repair PoSy delivery, backpressure fairness, timeout witness replay and restart handling. Evidence: real-signature service qualification through finalized H20/H28; these fixtures do not qualify the protected runtime.
- [x] L04 — Operator approved the concrete cutoff relationship on 2026-10-08; activated through signed fresh authority and verified live protected H3+ finality. Reconcile the protected protocol contract: H0 opens H3/H4/H5, F opens F+5, proposal H commits H/H+1/H+2; establish one semantic cutoff across different valid marker subsets and the exact parent reveal proof.
- [x] L05 — Load and validate complete signed fresh Genesis/parameter authority, initial world state, frozen validators/weights, cluster schedule and ingress KEM registry; derive target contexts solely from that authority.
- [x] L06 — Make the durable protected pipeline the ETDAG runtime owner: restore target records, retain signed cutoff decisions across restart, ingest verified VAC/markers, and reconcile idempotently.
- [x] L07 — Wire authenticated protected gossip, bounded fair retries and missing-artifact recovery; reject stale/wrong-target messages before mutation without crashing on ordinary invalid peer input.
- [x] L08 — Generate and independently verify deterministic cut, order, batch and H/H+1/H+2 proposal commitments; empty ordinary batches require genuine authenticated empty-cut evidence.
- [x] L09 — Connect accepted parent PoSy evidence to reveal, verify/decrypt threshold shares, and produce exact protected execution inputs for empty and nonempty batches. Remove old BVC/BOC/ordering certificates as active liveness prerequisites.
- [x] L10 — Connect finalized commits to F+5 admission exactly once; verify restart replay, bounded persistence and retention without discarding safety records.
- [ ] L11 — Run the real complete runtime locally over authenticated sockets: bootstrap past H3, sustained nonempty and empty blocks, identical finality, packet loss/reordering, proposer failure, one offline validator/rejoin, restart, and below-quorum halt/recovery.
- [x] L12 — Recheck all target hosts, trusted SSH access, time synchronization, resources, transport addresses, service ownership, custody permissions and port/firewall reachability; record exact current deployment targets.
- [x] L13 — Build and validate the native Linux release from this canonical source without Docker or source mirrors; verify binary architecture, version and hashes.
- [x] L14 — Produce one internally consistent signed fresh-network artifact set and per-node configuration for val2–val6; verify chain/genesis/parameter roots, unique identities and all key possession before starting.
- [ ] L15 — Deploy identical verified release/artifacts and supervised services to val2–val6; verify installed hashes/configuration and startup health.
- [ ] L16 — Prove live startup: all five agree on advancing finalized height and hash, normal protected H3+ execution, QC progression, and no signing/consensus conflicts.
- [ ] L17 — Prove live resilience: sustained finality across proposer leases, sequential process restarts, one validator offline/rejoin, and controlled below-quorum halt/recovery; inspect memory/disk/log growth and stalls.
- [ ] L18 — Move RPC/observer/indexer/Atlas to the fresh chain and verify matching finalized hashes and bounded lag; confirm bootseed/VPN management outages do not stop the established validator mesh.
- [ ] L19 — Replace Val1 authority only after L16–L18 pass; prepare/join val1 using the governed membership transition, verify catch-up, repeat quorum and restart checks for the resulting membership, and verify public routing no longer uses the old authority.
- [ ] L20 — Update changed host/configuration/passphrase/custody information only in /Users/jhutzler/Desktop/node-machine-credentials.xlsx, in place, without a copy or backup; validate unchanged workbook structure and secret-free reporting.
- [ ] L22 — First establish a genuine signed-transaction baseline after allfive match the advancing tip, then measure maximum sustainable ETDAG ordered TPS under progressive genuine signed transaction load; separately report accepted, ordered and finalized TPS, latency, backlog, errors and resource saturation with reproducible load windows.
- [ ] L23 — TPS statistics and animated chart bundle deployed to protected Atlas PoSy (Pages b18cc3e6); exact live asset and unauthenticated401 verified. Complete authenticated rendered-data verification and accepted/ordered instrumentation; keep explicit unavailable values until measured.
- [ ] L21 — Final acceptance: record release/configuration identifiers, matching live finalized tips, elapsed stability window, recovery results and remaining limitations; leave no launch-critical unchecked item.

Current dependency: complete the genuine >64-height recovery test, strict Clippy and Linux build for sequence 8; sign, verify and stage the exact artifact. Roll out serially after all-five matching advancing finality, using the narrowly signed legacy readiness bridge only for known sequences 1–7. Sequence 8 must report native readiness. Then prove measured 0.5–1.5-second cadence and sustained resilience before public routing or the Val1 transition. L11 and L15–L21 remain open. The original Desktop workbook remains the sole credential source.
No final completion percentage is claimed while these boundaries remain open.


## Verified continuation — 2026-10-08

[x] Real ML-DSA five-service qualification: 30-height packet loss/reordering with restart; four signers certify 22 heights while one remains offline, followed by verified catch-up to finalized H20 and restart; three signers cannot advance timeout; saturated queue delivery is fair. [x] 35 node/PoSy/ETDAG tests and node/PoSy all-target Clippy with warnings denied. [ ] Production protected-material generation. [ ] Real socket fleet qualification. [ ] Linux deployment. [ ] Val1 conversion.

[x] Scoped node/keytool build and 30 node/ETDAG/PoSy/keytool tests. [ ] Production protected-material generation. [ ] Signed fresh Genesis integration. [ ] Linux release. [ ] Five-node finality and restart/rejoin. [ ] Val1 conversion.

Evidence and diagnostic corrections: `networks/testnet-v3/CHAIN_1266_STALL_LOG.md`, incident C1266-2026-10-08-002. The operator confirmed a completely fresh replacement chain. Older entries below are historical.


> **Canonical repository ledger:**
> `docs/refactor/NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md` is the one canonical
> version. Every canonical clone contains this same tracked file. Update it in
> place and never create alternate, renamed, or divergent copies. An absolute
> checkout path never defines canonical file identity.

> This replaces the narrower working checklist. It preserves Codex's verified progress while adding the architecture, role, security, operator, packaging, simulation, fuzzing, versioning, and production-validation work that was missing.

**Implementation rule:** `[x]` means the assigned production responsibility is
implemented. `[~]` means real implementation exists but required behavior is
incomplete. `[ ]` means absent or mostly scaffold. Testing is tracked separately
in Phase 2 and is not required to mark implementation progress.


> **Historical-name note:** References to removed/renamed roles below are migration instructions only. The only valid target node roles are the 20 roles in the canonical taxonomy section.

**Overall completion rule:** the software migration cannot be called complete
while a required implementation item is unchecked/partial, callers still depend
on legacy ownership, or `synergy-node` does not own the new runtime. Production
readiness is a later claim requiring Phase 2 build, test, integration, new-network
artifact generation, and launch evidence.

**Current reconciliation (2026-09-15):** 125 of 314 checklist items are complete,
30 are partial, and 159 are open. Using `complete = 1`, `partial = 0.5`, and
`open = 0`, overall weighted completion is **44.6%**. The production-source queue
is separately 100% implemented; the remaining percentage is dominated by caller
migration, legacy retirement, canonical-role completion, packaging/operations,
and deferred Phase 2 verification. Newly reconciled source includes concrete
SynQ/PQSynQ/AIVM, SXCP/UMA, governance/system dispatch, cross-epoch Sync,
authenticated ETDAG shard serving, and deterministic finalized-world-state
execution callers for node ownership, naming, and owner-authorized reward
withdrawal. The shared Admin API and CLI inspect finalized state or prepare the
same native transaction actions without mutating local caches. No live evidence
is implied. The
2026-09-15 architecture expansion below adds newly approved Core Protocol root,
Node Address/NodeID, ownership, rewards, exact interface parity, updater,
simplification, onboarding, and production-acceptance requirements; the weighted
percentage includes these expanded requirements.

## Canonical Core Protocol reorganization and approved architecture expansion

- [x] Move the sole canonical implementation from `01-Core-Protocol/testnet-v3/node-platform/` to `01-Core-Protocol/node-platform/` on Val4.
- [x] Lift the existing Git repository metadata to `01-Core-Protocol/` without creating a second repository or implementation.
- [x] Prove that no second `node-platform/` tree remains under `networks/testnet-v3/`.
- [x] Create the sibling `networks/`, `protocol/`, and `tooling/` ownership roots and all four required network directories.
- [~] Redistribute the former Testnet-v3 root so `networks/testnet-v3/` retains only network-specific governed artifacts and explicitly frozen migration reference material.
- [ ] Reconcile existing Devnet governed artifacts under `networks/devnet/` without fabricating values.
- [ ] Reconcile existing Testnet-v3 governed manifest, Genesis, bootseed, version, role, and ETDAG artifacts under `networks/testnet-v3/`.
- [ ] Keep unauthorized Mainnet Beta and Mainnet artifacts absent or explicitly blocked; never fabricate parameters.
- [ ] Move normative PoSy, ETDAG, SXCP, UMA, Aegis, transaction, block/state, address, naming, ownership, reward, manifest, lifecycle, and wire/schema ownership under `protocol/` without duplicating Rust engines.
- [ ] Reconcile executable operator/developer/release/Genesis/DB/key tooling under `tooling/` while keeping reusable Rust libraries in `node-platform`.
- [~] Repair every Cargo, CI, script, package, service, configuration, documentation, and operator path to the canonical Core Protocol root.
- [ ] Remove generated `target/`, AppleDouble, backup, temporary, and duplicate-vendored residue only after exact source/use checks permit removal.
- [~] Replace protocol-critical uses of `NodeId`/validator ID as the canonical `synv...` identity with `NodeAddress`. The validator Admin/CLI/RPC public boundary is actively moving to typed `NodeAddress`/`--node-address`; remaining networking, PoSy, persistence, telemetry, GUI, and legacy fields still require classification and cutover.
- [x] Reserve `NodeID` exclusively for normalized human-readable `<name>.node` Synergy Naming System aliases.
- [x] Implement first-class NodeID normalization, availability checking, registration, forward resolution, reverse resolution, rename/update, duplicate refusal, and owner authorization. Deterministic actions update the execution overlay stored in canonical `WorldState.protocol`; only the existing PoSy-finalized state commit makes them authoritative. Local persistence is a rebuildable finalized cache and ownership comes from `synergy-node-ownership`.
- [~] Prove NodeID changes cannot alter Node Address, consensus keys/authority, rewards, ownership, transport identity, stake, or sync state. Source boundaries and focused tests prove NodeAddress/ownership/reward independence; end-to-end caller and acceptance evidence remains.
- [x] Implement durable cryptographic Node Address to owner-wallet binding without storing the wallet private key. Claims require the wallet-signed transaction plus a detached Aegis node-possession proof, transfers require replacement-owner acceptance, and only the PoSy-finalized world-state path establishes authoritative state.
- [x] Implement governed/owner-authorized ownership transfer rather than editable local configuration. Current-owner proof and replacement-owner acceptance are required before a transfer can enter finalized state.
- [x] Implement reward attribution to Node Address without inventing an unapproved reward formula. `synergy-rewards` applies externally supplied canonical credits and never calculates economics.
- [x] Require linked owner-wallet authorization for every reward withdrawal transition. The execution caller binds the transaction sender to its public key, queries the independent ownership state, and applies the withdrawal transition only within the finality-gated world-state path.
- [~] Establish one typed management dispatcher and machine-readable capability registry shared by CLI and Node Control Panel.
- [ ] Achieve EXACT CAPABILITY PARITY between backend, CLI, and Node Control Panel for every supported operation.
- [ ] Prove the GUI never shells out to or scrapes the CLI and neither interface owns separate protocol decisions.
- [ ] Implement signed automatic update discovery, channels, policy, staging, Aegis verification, compatibility, disk preflight, drain/restart, health validation, rollback, audit, and activation awareness.
- [ ] Prove software installation cannot activate future protocol behavior before its governed activation boundary.
- [x] Document the retained/removed PoSy mechanism classification, exact invariant, failure scenario, and rejected simpler alternative in `protocol/posy-v3/PO_SY_SIMPLIFICATION_AUDIT.md`.
- [ ] Build the retained-mechanism dependency map so a future proven simplification can remove an entire derived chain from its root invariant.
- [~] Complete caller, persisted-state, wire, and test evidence before removing any remaining PoSy mechanism or legacy coordinator.
- [~] Simplify the operator lifecycle to `Create -> Join -> Sync -> Ready -> Active` while retaining required internal safety states.
- [ ] Resolve the authoritative classification of the historical 1,000-block shadow requirement and implement the decision.
- [ ] Implement zero-touch node/validator onboarding through the same typed CLI and GUI operations without modifying existing validators.
- [ ] Prove restart/double-sign safety, rolling upgrades, governed activation, sixth-validator onboarding, removal/jailing continuity, bootseed independence, and VPN-control-plane outage tolerance in the production-equivalent acceptance scenario.

## Canonical Synergy Node Role Taxonomy — 20 Roles

This taxonomy is now authoritative for the node-platform architecture. A **node role** exists only when it has a materially different trust boundary, networking responsibility, persistence requirement, authority model, or operator/resource responsibility. Individual jobs within one trust/resource boundary are modeled as **capabilities**, not separate node roles.

| Class | Canonical Node Role | Exact Function | Key Boundary / Notes |
|---|---|---|---|
| **I — Consensus & Chain Integrity** | **Validator Node** | Runs Proof-of-Synergy consensus; validates state transitions; performs proposal/vote/certificate/finality duties; performs validator-side ETDAG duties; maintains current canonical state. | PoSy authority only after canonical authorization/activation. Stake is accountability/economic security, not PoS voting power. |
| **I — Consensus & Chain Integrity** | **Sentry Node** | Hardened dual-homed perimeter between the public Synergy P2P network and validators on the private validator VPN; forwards permitted authenticated protocol traffic, shields validator endpoints, rate-limits/filters abuse, and provides redundant validator ingress/egress. | **No PoSy signing/finality authority.** Sentry compromise must not expose validator signing keys. Validators independently verify everything received through sentries. |
| **I — Consensus & Chain Integrity** | **Archive Node** | Preserves full/long-term chain history; serves historical blocks/state/proofs; creates and serves verified snapshots; supports recovery and synchronization. | Renamed from **Archive Validator** because archival storage does not itself grant validator authority. |
| **I — Consensus & Chain Integrity** | **Consensus Audit Node** | Independently revalidates PoSy artifacts, finalized blocks, state transitions, divergence, equivocation, and validator behavior; emits audit findings/alerts. | Renamed from **Audit Validator**; non-signing audit role. |
| **II — Interoperability** | **Cross-Chain Node** | Provides SXCP relay and verification capabilities: observes/consumes external-chain proofs, relays packages, validates proof/finality/scope/receipts, and submits accepted interoperability work. | Replaces separate Relayer + Cross-Chain Verifier roles. `relay` and `verify` remain separate capabilities; a node's own relay artifact cannot independently satisfy the verification requirement for that same acceptance decision. |
| **II — Interoperability** | **Witness Node** | Independently observes external-chain events and produces signed observation/proof material. | Separate evidence source from Cross-Chain Node acceptance logic. |
| **II — Interoperability** | **Oracle Node** | Acquires approved off-chain/external data, authenticates sources, normalizes data, and publishes signed feed attestations. | Oracle/data-attestation scope only. |
| **II — Interoperability** | **UMA Coordinator Node** | Maintains and verifies UMA identity/address mappings, refreshes mappings, handles consistency/recovery, and emits auditable mapping records. | Mapping/identity coordination only. |
| **III — Execution, Data & Cryptography** | **SynQ Execution Node** | Provides deterministic SynQ execution, contract verification, trace generation, simulation/pre-execution, and execution-job capacity. | Service execution does not decide PoSy finality. |
| **III — Execution, Data & Cryptography** | **Network Analytics Node** | Performs network/chain simulations, anomaly detection, performance analysis, risk modeling, and approved analytical workloads. | Renamed from Analytics & Simulation; advisory output is not protocol truth. |
| **III — Execution, Data & Cryptography** | **Aegis Cryptography Node** | Provides Aegis/PQC verification, cryptographic attestations, key lifecycle, threshold/KMS/HSM support, and authorized cryptographic services. | High-security cryptographic role with isolated key custody. |
| **III — Execution, Data & Cryptography** | **Data Availability Node** | Stores/serves required availability data, maintains shards/objects, proves retrievability, performs repair/recovery, and provides availability proofs. | Distinct from Archive: DA is protocol/current retrievability; Archive is long-term history/recovery. |
| **IV — AI & Intelligence** | **AI Compute Node** | Performs inference, embeddings, multimodal inference, training, fine-tuning, and bounded AI-agent execution according to advertised capabilities/GPU class. | Replaces AI Inference + AI Training/Fine-Tuning + AI Agent Execution. |
| **IV — AI & Intelligence** | **AI Coordination Node** | Handles AI workload routing, GPU scheduling/placement, quotas, model-policy matching, capacity coordination, utilization metering, and federated-learning coordination. | Replaces AI Routing + GPU Scheduler + Federated Learning Coordinator. |
| **IV — AI & Intelligence** | **AI Data Node** | Provides model artifact storage/metadata/hash verification, dataset provenance/rights/redaction metadata, vector/embedding memory storage/retrieval, and deletion/retention receipts. | Replaces Model Repository + Dataset Provenance + Vector Memory. Data namespaces/policies remain isolated internally. |
| **IV — AI & Intelligence** | **AI Assurance Node** | Independently verifies AI receipts/results, replay/reproducibility where possible, model/runtime/dataset policy, benchmarks, safety/evaluation, provider reputation, latency/cost/quality evidence. | Replaces AI Verification + AI Reputation & Evaluation; assurance should be independent of the workload it validates where settlement/security requires independence. |
| **V — Service & Access** | **RPC Gateway Node** | Exposes public/internal RPC and WebSocket access with rate limiting, auth where required, caching, request isolation, and API availability. | Public RPC remains separate from privileged Admin API. |
| **V — Service & Access** | **Indexer Node** | Indexes finalized chain data for transactions, accounts, contracts, tokens, NFTs, events, analytics, search, and Explorer APIs. | Renamed from Indexer & Explorer. Explorer is an application consuming indexed data, not a separate node role. |
| **V — Service & Access** | **Observer / Light Node** | Synchronizes headers/finality proofs and minimal state/proofs; verifies light proofs; supplies wallet/light-client feeds. | Non-signing observer. |
| **V — Service & Access** | **Bootseed Node** | Provides initial authenticated P2P discovery, peer exchange, bootstrap availability, and peer advertisement. | Discovery only; no consensus authority and no permanent liveness dependency after peer mesh establishment. |

### Node-role totals

| Class | Count |
|---|---:|
| I — Consensus & Chain Integrity | 4 |
| II — Interoperability | 4 |
| III — Execution, Data & Cryptography | 4 |
| IV — AI & Intelligence | 4 |
| V — Service & Access | 4 |
| **Total** | **20** |

### Explicitly not canonical node roles

The following remain modules, capabilities, applications, or infrastructure services rather than canonical `NodeRole` values:

- **Committee** — removed entirely as a node role. Any legitimate quorum/rotation/coordination duty defined by PoSy is a dynamically assigned Validator duty/capability.
- **Governance Auditor / Treasury Controller / Security Council** — cross-cutting governance/security control-plane functions, not public node roles.
- **Explorer** — application consuming Indexer data.
- **VPN Enrollment Broker** — control-plane service supporting zero-touch validator/sentry overlay enrollment.
- **Validator Transport Registry** — signed transport/lease control-plane service.
- **Snapshot Publisher** — Archive capability/service, not a canonical node role.
- **Seed server** — legacy/auxiliary infrastructure; Bootseed Node is the canonical discovery role.


## Phase 0 — Migration governance and evidence

- [x] Declare `01-Core-Protocol/node-platform/` the canonical universal runtime and the network-nested legacy runtime a semantic reference only.
- [x] Remove old Genesis/wire/validator-set/storage/runtime interoperability from the implementation blocker list.
- [x] Separate implementation states from deferred build/test/integration/network-verification states.
- [x] Current architecture inventory and dependency map.
- [x] Target architecture and migration-map documents.
- [x] Consensus, ETDAG, P2P, VPN, Admin API, and genesis-change audits.
- [x] Durable implementation status ledger.
- [x] Refresh inventory/migration/status after every major extraction completed through the 2026-09-12 direct migration wave; continue this gate for future waves.
- [ ] Record every retired legacy module and prove all callers/state migrations are accounted for.
- [ ] Maintain a protocol-change ledger for consensus/ETDAG/wire/storage-format changes.

## Phase 1 — Workspace, shared types, and dependency direction

- [x] `synergy-node-core` foundation exists.
- [x] `synergy-admin-api` foundation exists.
- [~] Create all first-class crates in the complete target tree. Canonical node-platform crates are now present and registered in the workspace; remaining standalone infrastructure services and caller retirement are still open.
- [ ] Enforce one-way dependency direction; no P2P↔PoSy↔ETDAG↔execution circular ownership.
- [~] Split oversized `synergy_types.rs` into focused canonical types. The new authority-neutral protocol-types crate now owns chain, height, epoch, validator identity, cluster, hash, block/transaction, transaction/certificate references, and bounded frame descriptors; subsystem caller migration and retirement of the legacy aggregate remain.
- [ ] Remove obsolete cross-subsystem runtime ownership.
- [ ] Pin supported Rust toolchain and repository formatting/lint/security policies.
- [ ] Define reproducible release/test Cargo profiles with safe disk headroom.

## Phase 2 — Configuration, manifests, schemas, and version compatibility

- [x] Create typed `synergy-config` using the clean canonical schema v1 with no legacy adapters.
- [x] Validate node/network/P2P/PoSy/ETDAG/storage/RPC/telemetry/role/VPN config before startup using bounded loading, strict unknown-field rejection, and borrowed cross-field checks.
- [x] Create signed `synergy-manifest` library/tooling. Source ownership now includes the canonical manifest model, hash, verifier, and signed CLI boundaries; runtime caller migration remains.
- [x] Implement strict canonical network-manifest build, deterministic hashing, governed ML-DSA-65 signing/PQVM verification, safe inspection, and bounded structural diff tooling.
- [ ] Bind chain/network/genesis/PoSy/ETDAG/P2P/bootstrap/release/role schema in signed manifest.
- [x] Separate software, P2P, PoSy, ETDAG, sync, snapshot, Admin, DB, and config versions in `synergy-version`.
- [x] Implement explicit compatibility matrix and governed epoch/finalized-height activation metadata with a required governance commitment.
- [x] Implement offline canonical Chain 1266 Genesis validation, deterministic hashing, governed ML-DSA-65 authority signing, and PQVM verification without creating launch artifacts.
- [ ] Create machine-readable schemas for network manifest, node config, role profiles, leases, snapshots, genesis, ETDAG, validator membership.
- [ ] Add explicit canonical role-taxonomy schema/version and role-profile hash migration for the 20-role model.

## Phase 3 — Identity, key custody, cryptography, and Aegis

- [x] Create `synergy-identity` and enforce Node ID = Synergy node address identity rule in the source owner; runtime callers remain to migrate.
- [~] Implement Aegis-backed proof-of-possession and identity rotation/storage contracts. Node/P2P runtime binding exists; consensus/VPN caller migration remains.
- [x] Implement duplicate/conflicting-key identity protection and authorization-bound rotation contracts.
- [x] Define `synergy-crypto` as the protocol-neutral facade over the single Aegis Cryptography Engine; raw PQVM/KEM/digest/entropy implementations remain owned below `synergy-aegis`, and facade callers remain to migrate.
- [ ] Support encrypted filesystem, remote KMS, HSM, and TPM provider boundaries where applicable.
- [ ] Never expose raw validator/private signing keys via CLI/Admin API/GUI.
- [x] Create first-class node-facing `synergy-aegis` boundary with explicit PQ policy, key-ID-only custody, signer/verifier providers, attestation, lifecycle, and secret-free audit contracts.
- [x] Implement the offline synergy-keytool for non-overwriting ML-DSA-65 node/consensus keys, ML-KEM-768 ETDAG keys, public inspection, strict private-file custody, and governed rotation-plan generation.
- [ ] Add key/provider outage, rotation, backup/restore, and recovery tests.

## Phase 4 — Unified node core, lifecycle, supervisor, and roles

- [x] Runtime-owned management dispatcher serves status, health, readiness, diagnostics, canonical configuration validation, role inspection, and actual service-derived capability discovery.
- [x] Local Admin API lifecycle wiring exists.
- [x] Implement service supervisor, dependency graph, criticality, restart/fail-closed policy, cancellation, concrete runtime registrations, and reverse-order shutdown on signal, startup observation failure, or runtime tick failure.
- [x] Implement explicit node lifecycle states through ready/active/degraded/draining/failed and drive them from the retained supervised runtime.
- [x] Implement role-specific readiness gates for PoSy, ETDAG, network, storage, verified sync, and role-scoped VPN evidence; remote Sync head claims now carry bounded three-QC evidence that only PoSy verifies.
- [~] Create declarative `synergy-roles` capability/service/port/key/storage model. Source ownership exists; node caller migration remains.
- [x] Ensure role selection alone never grants validator authority; voting requires explicit authority binding, safe recovery, key custody, sync, and H+5 evidence.
- [x] Ensure non-validator roles cannot request consensus voting mode.
- [ ] Use one primary node distribution for all node roles.

## Phase 5 — CLI, Admin API, Control Panel, and event parity

- [x] Owner-only Unix Admin API with bounded typed requests.
- [x] macOS accepted-socket race fixed and stress-tested.
- [x] Initial headless CLI consumes shared management dispatcher.
- [x] Control Panel typed Admin API client and authenticated read-only bridge.
- [x] Control Panel canonical validator authorization semantics; stake/VPN do not grant authority.
- [~] Modularize CLI into complete init/start/stop/restart/join/leave/identity/keys/peers/sync/snapshot/config/manifest/role/validator/VPN/PoSy/ETDAG/storage/telemetry/upgrade/version commands. Ownership, naming, and rewards now have typed inspect/resolve/availability and transaction-preparation commands through the shared Admin contract; broader operation groups, protected transaction submission, audit, and subsystem runtime handlers remain.
- [~] Implement safe idempotent Admin API mutation operations with authorization/audit logging. Validator lifecycle mutations now use permission checks, idempotency, durable canonical management state, and frozen-authority binding; remaining subsystem operations and audit persistence remain.
- [ ] Implement typed Admin event streaming with bounded subscriber queues/backpressure.
- [ ] Route all practical Control Panel operations through the same shared operation/event model.
- [ ] Implement Node Control Panel node creation, lifecycle, config, peers, sync, validator, VPN, PoSy, ETDAG, storage/snapshots, telemetry/diagnostics, and upgrade UI.
- [ ] Add automated CLI/Admin/GUI capability-parity tests.

## Phase 6 — P2P transport, handshake, peer lifecycle, discovery, framing, and routing

- [x] Canonical dial/endpoint parsing extracted.
- [x] Handshake signing bytes/PQ algorithm policy extracted.
- [x] VPN route policy extracted.
- [x] Signed validator transport registry preserved.
- [x] Initial peer admission/duplicate/backoff lifecycle policy extracted.
- [x] Create first-class `synergy-network` and core `synergy-p2p-protocols`, with new-node authenticated runtime caller cutover for Sync, ETDAG, and PoSy.
- [x] Complete raw TCP transport/listener/dialer/connection/timeouts/resource limits with nonblocking accept, bounded-time dialing, and configured I/O.
- [x] Complete handshake identity/chain/network/role/version challenge verification and wire the governed PQVM/Aegis provider into inbound and outbound runtime admission.
- [~] Complete peer manager states, health, quarantine/ban, duplicate resolution, persistence, and bounded exponential retry. Governed signed-overlay inbound/outbound admission and bounded retry dialing are wired; jitter and remaining persistence callers remain.
- [x] Implement prioritized bootseeds, authenticated peer exchange input validation, signed transport-registry discovery boundary, and bounded expiring cache.
- [x] Implement protocol envelope/codec/framing/size limits/version registry and compatibility policy. Replay enforcement remains exact-session runtime work.
- [x] Implement bounded per-subsystem queues, watermarked backpressure, fair peer mailboxes, and attempt/capacity-bounded retransmission.
- [x] Extract transport-only PoSy, ETDAG, and sync network adapters; none can determine finality.
- [x] Implement the dual-homed **Sentry** perimeter source path with authenticated public/validator links, protocol/size filtering, bounded forwarding, and health-based failover.
- [x] Implement Sentry forwarding ACLs so only explicitly permitted opaque protocols/messages cross the public↔validator boundary; three focused policy/overload tests pass.
- [x] Implement redundant deterministic healthy multi-Sentry path selection per Validator; no mandatory 1:1 Sentry-to-Validator topology.
- [x] Ensure Sentry peer/network scoring and transport metadata cannot become PoSy authority or determine finality.
- [ ] Retire/reduce `networking.rs` god module.
- [ ] Add malicious/stale/slow/duplicate/protocol mismatch/churn/oversized-frame tests and fuzzing.

## Phase 7 — Validator VPN, NetBird, transport leases, and zero-touch enrollment

- [x] VPN route is transport only, not authority.
- [x] Current Control Panel onboarding uses canonical registration + authorization.
- [x] Dynamic routes reconcile without static validator peer mappings.
- [~] Create first-class `synergy-vpn` and `synergy-transport-registry`. Production source owns enrollment/leases/NetBird control/cache/reconciliation/revocation; the universal node verifies pinned snapshots, persists accepted generations, checks active-authority coverage, installs signed overlay admission, and schedules bounded dials. Enrollment/lease publication, deployment bindings, and live verification remain.
- [~] Implement VPN enrollment broker. Challenge, eligibility, proof, authorization, response, resume, and revocation owners exist; the Admin/runtime broker endpoint remains.
- [x] Implement synv/node challenge-response possession proof with caller-supplied finalized eligibility and injected signature verification.
- [~] Issue one-use/short-lived NetBird enrollment material with redacted diagnostics; guaranteed in-memory credential destruction remains.
- [~] Automatically establish overlay route and publish signed identity-bound transport lease. NetBird daemon observation and signed-registry route establishment are wired into authenticated network dialing/admission; lease publication remains.
- [x] Implement lease expiry/generation/stale rejection/revocation and deterministic route/key/IP reconciliation ownership.
- [x] Implement distinct **Validator** and **Sentry** overlay membership scopes/identity-route binding; neither grants PoSy authority.
- [~] Automate Sentry overlay enrollment/rotation/revocation using role-bound identity and approved policy. Source operations exist; runtime orchestration remains.
- [x] Ensure VPN management-plane status degradation does not automatically tear down an established transport.
- [ ] Test unauthorized/replayed enrollment, broker restart, management outage, IP/key changes, revocation, simultaneous joins, mass restart, split-brain lease state.
- [ ] Prove new validator joins require no manual edits/restarts on existing validators.

## Phase 8 — Verified head, block/state sync, snapshots, and recovery

- [x] Create first-class `synergy-sync` and wire authenticated head claims, PoSy evidence verification, source planning, local advertisement, and readiness into the node runtime.
- [x] Collect/verify authenticated head/finality views through the runtime PoSy owner with monotonic per-peer collection and conflict refusal.
- [x] Implement bounded block range scheduling/request/verification/import/failover. The runtime requests one parent-anchored finalized candidate at a time, transports complete transactions/receipts/account state, verifies QC/TC safety evidence through the single PoSy driver, deterministically re-executes it, commits only matching finality, and uses bounded source timeout/failover with durable request resume.
- [x] Implement finality-bound checkpoint/chunk state sync with durable resume. Candidate and snapshot state have verified sequential import, bounded integrity-checked chunks, conflict-safe durable acquisition, Aegis verification, execution restore handoff/commit/receipt, finalized publication, and fail-closed trust-root-signed cross-epoch authority transition.
- [x] Implement archive/snapshot/peer source scoring and automatic failover. Source adapters, deterministic scoring, bounded runtime failover, and authenticated transport/storage callers are wired.
- [x] Create first-class `synergy-snapshot` build/sign/publish/verify/restore/retention subsystem. Production source and callers own finality-bound build, Aegis signing/verification, peer chunk serving, resumable acquisition, restore handoff, durable execution commit/receipt, finalized publication, and successor-epoch handoff. External object-store deployment is Phase 2 integration, not missing Phase 1 ownership.
- [ ] Integrate configured archive/object-store publication without hard-coded secrets.
- [~] Test dishonest heads, corrupt blocks/snapshots, interrupted restore, source loss, restart, and partition healing. Dishonest advertised height, wrong response anchor/range, and ineligible/conflicting support-source cases are covered; recovery and partition scenarios remain.

## Phase 9 — Proof-of-Synergy isolation, membership, persistence, recovery, and liveness

- [x] Audit frozen validator weight semantics.
- [x] Remove unsupported equal-numeric-weight guard.
- [x] Preserve approved non-uniform frozen PoSy weights where current specification requires them.
- [ ] Classify every legacy weight/power field by actual source/meaning before commitment migration.
- [x] Create first-class `synergy-posy` and wire the single proposal/vote/QC/TC/finality driver into the universal node; no foreign consensus model is imported.
- [x] Preserve explicit rules: stake is not PoSy authority; stake is unrelated to Synergy Score; Synergy Score does not determine finality. Canonical validator-management, PoSy, Sync, VPN, transport-registry, governance, and execution callers preserve these authority separations.
- [x] Implement deterministic PoSy engine, proposal, voting, quorum/certificates, finality, timeout/progress recovery exactly per authoritative spec. The final owner pipelines QC heights, applies three-QC finality, preserves strict count+frozen-weight quorum, advances takeover only from a verified TC, replays verified QC/TC state, and carries the verified two-QC boundary tail across a trust-root-signed epoch transition.
- [x] Implement validator Registered/Authorized/Synchronizing/Shadowing/Ready/ActivationScheduled/Active/Jailed/Removed/Expelled lifecycle. Admin and CLI mutations, durable persistence/reload, frozen-authority reconciliation, and governed future-epoch activation use the canonical validator-management owner.
- [~] Verify and implement 1,000-block shadow requirement if still authoritative; governed required-progress enforcement, atomic persistence, and bypass refusal exist, but the authoritative numeric requirement and runtime evidence caller remain.
- [x] Apply validator-set changes only at valid governed epoch boundaries. Finalized epoch-closure evidence, future registry assembly, trust-root-signed successor bindings, exact boundary-QC anchoring, durable transition persistence, and builtin service-graph reconstruction are wired.
- [x] Separate slashing/economic stake logic from PoSy authority. Canonical management and PoSy lifecycle callers keep penalties outside frozen voting weight/finality; remaining work is legacy-owner retirement.
- [~] Implement durable signing authority, safety journal, vote/proposal/certificate/finality/prepared-state persistence and explicit fsync boundaries. Verify-before-persist proposal/vote stores, contiguous finality records, prepared checkpoints, sign-once records, per-height QCs, and exact-slot TCs have canonical owners. Runtime proposal/vote/timeout signing uses durable sign-once authority; cross-process writer ownership and multi-record crash atomicity remain.
- [x] Disable signing until startup recovery proves safe state. Prepared checkpoints, authenticated peer reports, strict count+non-uniform-weight recovery quorum, rollback/conflict-safe reconciliation, verified QC/TC replay, durable-finality matching, and the runtime signing gate are wired.
- [ ] Test crash before/after persist/send/partial broadcast/certificate/final commit and prove no double-sign.
- [ ] Test proposer failure, dropped/delayed/reordered/duplicate votes, timeout recovery, certificate conflict, join/leave/jail/activation/epoch transition.

## Phase 10 — ETDAG first-class protected transaction subsystem

- [ ] Finish authority-field classification before changing versioned ETDAG commitments.
- [ ] Preserve approved non-stake PoSy authority commitments; remove only traced legacy PoS leakage.
- [x] Create `synergy-etdag` and `synergy-etdag-client`; authenticated runtime DAG, availability, order, reveal-certificate, exact-H+5, and execution handoff callers are wired.
- [x] Extract profile/parameters/domains/digests, provider-bound KEM/AEAD, canonical padding/nonce/key registry, exact-H+5 target admission, and check-before-mutation protected ingress.
- [x] Extract DAG vertices/identifiers/parents/dependencies/cycle checks/bounded traversal/certified cuts/deterministic ordering.
- [x] Extract availability and all certificate types with frozen quorum, canonical roots, deduplicated signers, and injected membership/signature verification.
- [x] Extract reveal authorization/decrypt shares/transcript/decryption with finality-bound authorization, threshold verification, and no plaintext persistence. Concrete PQ reconstruction remains provider-owned.
- [x] Extract deterministic execution handoff with exact protected order, aggregate reveal-transcript binding, bounded plaintext validation, and an execution-only adapter that cannot determine finality.
- [x] Extract ETDAG governance manifests, frozen exact-H+5 parameters, fee schedules, activation succession, KEM key activation, and explicit governance-authority verification.
- [x] Implement atomic safety/admission/protected-input/DAG/certificate/reveal persistence and bounded startup reconciliation/replay. Multi-record transactions, runtime callers, and crash testing remain later verification/integration work.
- [x] Extract authenticated ETDAG P2P transport adapter, bounded deduplicated gossip, and bounded retransmission; transport grants no authority or finality.
- [ ] Retire monolithic `runtime/src/etdag.rs` only after state/caller/test migration.
- [~] Preserve the ordinary-user ETDAG path and explicitly authorize any system/governance/internal bypass. The wallet request is being rebound to chain/network context, target context/height, sender wallet, nonce, algorithm, presented public key, and the complete encrypted-envelope commitment; client construction, Aegis provider wiring, RPC/transport admission, and negative/end-to-end evidence remain.
- [~] Add encryption, malformed input, replay, DAG dependency/cycle, deterministic order, availability, reveal, restart, delayed-input, resource exhaustion, and full e2e tests. Ten focused admission/order/persistence tests pass; crypto, availability, reveal, restart, exhaustion, and e2e coverage remain.

## Phase 11 — Transaction ingress, execution, block/state, SynQ, and AIVM

- [~] Create canonical transaction and ingress crates. The new transaction action, class authorization, nonce, validation, and receipt model is implemented; transaction ingress remains.
- [x] Route runtime ordinary-user transaction plaintext into execution only through a quorum-certified ETDAG protected-batch handoff.
- [x] Define explicit authorized system/governance/internal ingress. Protected/user ingress remains separate; system-class governance and supported system actions require canonical proposal/constitution commitments, frozen-authority Aegis votes, threshold/delay/activation checks, and deterministic state mutation. Unknown system actions fail closed.
- [x] Create deterministic execution engine with admission context, PQVM transaction verification, scheduling, governed Testnet-v3 fees, receipts, speculative candidates, rollback isolation, and finality-gated state commit. New-node callers persist candidates before PoSy publication and re-execute only frozen-authority-QC-bound candidates on restart.
- [x] Route every canonical transaction action through the execution dispatcher. `ExecutionService` wires concrete native, Aegis/PQSynQ+AIVM, dual-quorum SXCP+UMA, governance, and narrow governance-delegating system providers; unsupported operations fail closed at their owning boundary.
- [~] Create canonical block and state crates with deterministic roots/commitments/proofs. Canonical blocks bind ordered transactions and receipts, validate parent/network/height/timestamp continuity and proposer signatures, and use a bounded versioned codec. Finalized account state now persists with its root-checked commitment and reloads for execution restart; state proof and speculative-candidate recovery remain.
- [x] Integrate SynQ through the narrow deterministic adapter. Aegis verifies the PQSynQ account-domain authorization and exact artifact/input commitments; AIVM executes supported QVM bytecode with bounded gas and deterministic host behavior; deployment/call state changes flow through the canonical scheduler.
- [x] Integrate AIVM through a narrow sandbox/resource/determinism adapter. The concrete SynQ runtime executes bounded deterministic QVM bytecode; unsupported cryptographic/KEM opcodes fail closed pending an injected Aegis provider.
- [x] Prove by ownership that execution accepts only certified ETDAG order and commits only an exact PoSy finality record; execution exposes no finality action. PoSy validator votes are now withheld until the signed proposal matches a locally executed ETDAG candidate; early valid proposals are deferred to candidate arrival.
- [~] Add cross-node deterministic execution/state-root and rollback/restart tests. Focused forged-input, transition-failure, invalid-root, state-history, and interrupted-pointer retry tests pass; cross-node and restart integration remain.

## Phase 12 — Storage durability, integrity, pruning, and disk safety

- [~] Create first-class `synergy-storage`. Atomic bounded-file and WAL primitives compile and have focused tests; runtime stores and full keyspaces remain.
- [ ] Define keyspaces for blocks/state/consensus/ETDAG/peers/metadata.
- [~] Implement atomic writes, WAL/intent journaling where required, fsync durability, migrations, integrity checks, corruption handling. Atomic replacement, bounded reads, directory fsync, sequenced checksummed WAL replay, and truncated-record failure are tested; multi-file transactions and runtime schema/caller migration remain.
- [ ] Implement safe pruning/retention.
- [ ] Implement disk free-space guards and bounded evidence/log/cache/snapshot growth.
- [~] Add disk-full, partial-write, fsync failure, migration crash, corruption, and pruning tests. Oversize/traversal/truncated-WAL cases are covered; injected disk-full/fsync/migration/pruning scenarios remain.

## Phase 13 — SXCP, UMA, DA, governance, and role-specific services

- [x] Create first-class `synergy-sxcp`, `synergy-uma`, `synergy-data-availability`, `synergy-governance`, and validator-management libraries. Production callers now cover validator lifecycle/Admin, ETDAG custody/retention/serving, canonical UMA resolution, finalized SXCP relay intents, and governed execution/state mutation.
- [ ] Define `CrossChainCapability::{Relay, Verify, ...}` and supported-chain capabilities under one **Cross-Chain Node** role.
- [ ] Enforce relay/verification independence in SXCP acceptance and receipts.
- [x] Create common `synergy-ai` service contracts for the four canonical AI roles. Capability, job, policy, provider, compute, coordination, data, assurance, receipt, and metrics owners are populated.
- [x] Model inference/training/agent, routing/scheduling/federated coordination, model/dataset/vector data, and assurance/evaluation as capabilities/work types rather than additional node roles. The canonical enum remains exactly four AI roles.
- [ ] Implement external-chain adapters/proof/finality boundaries required by SXCP.
- [x] Implement UMA registry/mapping/coordinator/verifier and required BTC/ETH/SOL destination adapters; the SXCP execution caller applies its dual-quorum-covered mapping and resolves the exact destination through the canonical registry.
- [x] Implement DA store/shard/proof/serve/audit/retention. Durable custody stores the proof with the shard; authenticated ETDAG admission and bounded recovery responses enforce exact vertex/object/shard/proof bindings, governed Aegis verification, conflict safety, and finalized-height retention.
- [x] Implement node-side governance proposal/vote/authorization/activation/constitution/emergency validation. The node dispatcher verifies canonical roots, frozen-authority Aegis votes, constitutional threshold and delay, exact activation height and payload binding, then applies only the authorized deterministic protocol-state mutation.
- [ ] Add role-specific service tests and prove none can acquire PoSy signing authority without canonical validator membership.

## Phase 14 — Public RPC/WS, telemetry, health/readiness, stall diagnosis, and doctor

- [x] Create public `synergy-rpc` and `synergy-ws`; keep privileged Admin API separate. Crate source owners and bounded auth/rate-limit/server/method/subscription boundaries exist; runtime endpoint qualification remains.
- [ ] Implement rate/body/concurrency/time limits and auth for restricted methods.
- [x] Create `synergy-telemetry` with node/P2P/sync/PoSy/ETDAG/VPN/storage/resource metrics. Source owners and metric families exist; exporter/provider caller qualification remains.
- [ ] Publish Sentry public/VPN path, forwarding, queue, drop/filter, validator-link, and failover metrics.
- [ ] Publish Cross-Chain relay/verify/adapter/receipt/independence metrics.
- [ ] Publish AI role/capability/workload/GPU/data/receipt/assurance metrics.
- [x] Create shared `synergy-health` diagnostic engine used by CLI and Control Panel. Typed status/check/liveness/readiness/stall/dependency owners exist; remaining client cutover remains.
- [ ] Implement precise chain-stall reason classification rather than generic failure.
- [ ] Implement only safe automatic remediation; never auto-wipe/reset/sign/bypass finality.
- [ ] Create alerts/runbooks for no-finalization, peer collapse, sync lag, VPN outage, disk pressure, DB integrity, ETDAG backlog, protocol mismatch.

## Phase 15 — Canonical 20-Role Taxonomy, Capability Boundaries, and Role Completion

### Taxonomy migration

- [x] Replace canonical production-source role references to the old 19-role runtime and NORS-03 28-role taxonomy with the new 20-role taxonomy. Historical migration text is not an active role definition.
- [x] Remove **Committee** as a canonical `NodeRole`, role profile, onboarding option, Admin/CLI node type, and standalone operator role. Control Panel parity remains tracked separately.
- [ ] Trace any legitimate committee/quorum/rotation behavior in current PoSy and migrate it to dynamically assigned **Validator duties/capabilities** without changing authoritative PoSy semantics.
- [x] Rename the validator-perimeter **Relayer** role to **Sentry Node** in the canonical production-source taxonomy.
- [x] Introduce **Cross-Chain Node** as the single canonical SXCP interoperability role replacing separate Cross-Chain Relayer and Cross-Chain Verifier node roles in the production-source taxonomy.
- [ ] Preserve `relay` and `verify` as separate Cross-Chain capabilities and enforce that one operator/node cannot independently satisfy the verification requirement for its own relayed package in the same acceptance decision.
- [x] Rename **Archive Validator** → **Archive Node** in the canonical production-source taxonomy.
- [x] Rename **Audit Validator** → **Consensus Audit Node** in the canonical production-source taxonomy.
- [x] Rename **Analytics & Simulation** → **Network Analytics Node** in the canonical production-source taxonomy.
- [x] Rename **Indexer & Explorer** → **Indexer Node** in the canonical production-source taxonomy; Explorer remains an application consuming the Indexer.
- [x] Rename **Bootstrap Node** → **Bootseed Node** in the canonical production-source taxonomy.
- [x] Remove Governance Auditor, Treasury Controller, and Security Council from canonical `NodeRole`; their source ownership remains cross-cutting governance/security control-plane behavior.
- [x] Consolidate the 11 prior AI node roles into exactly four canonical roles: **AI Compute**, **AI Coordination**, **AI Data**, **AI Assurance**.
- [x] Preserve the prior AI jobs as capabilities/work types rather than canonical node identities. Reward/accounting caller integration remains part of role completion.
- [ ] Add a versioned role-taxonomy/config migration so legacy role names fail safely or map only where the mapping is unambiguous and approved.
- [ ] Update signed role/profile manifests, schemas, Admin API enums, CLI values, Control Panel options, metrics labels, telemetry, dashboards, tests, docs, deployment configuration, and reward/service eligibility code to use the new canonical names.

### Class I — Consensus & Chain Integrity

- [ ] **Validator Node** production-complete.
- [ ] **Sentry Node** production-complete.
- [ ] **Archive Node** production-complete.
- [ ] **Consensus Audit Node** production-complete.

### Class II — Interoperability

- [ ] **Cross-Chain Node** production-complete.
- [ ] **Witness Node** production-complete.
- [ ] **Oracle Node** production-complete.
- [ ] **UMA Coordinator Node** production-complete.

### Class III — Execution, Data & Cryptography

- [ ] **SynQ Execution Node** production-complete.
- [ ] **Network Analytics Node** production-complete.
- [ ] **Aegis Cryptography Node** production-complete.
- [ ] **Data Availability Node** production-complete.

### Class IV — AI & Intelligence

- [ ] **AI Compute Node** production-complete with capability flags for inference, embeddings, multimodal, training, fine-tuning, and bounded agent execution.
- [ ] **AI Coordination Node** production-complete with capability flags for routing, GPU scheduling/placement, quota/policy matching, capacity metering, and federated-learning coordination.
- [ ] **AI Data Node** production-complete with capability flags for model repository, dataset provenance, vector memory, retention, and deletion receipts.
- [ ] **AI Assurance Node** production-complete with capability flags for verification/replay, evaluation, safety testing, benchmarking, provider reputation, and latency/cost/quality scoring.

### Class V — Service & Access

- [ ] **RPC Gateway Node** production-complete.
- [ ] **Indexer Node** production-complete.
- [ ] **Observer / Light Node** production-complete.
- [ ] **Bootseed Node** production-complete.

### Cross-cutting role gates

- [ ] Every canonical role has a role profile, capability graph, required/forbidden service graph, key requirements, networking policy, storage policy, hardware/resource profile, health contract, readiness contract, telemetry, CLI/Admin visibility, Control Panel support, operator documentation, and tests.
- [ ] Sentry Nodes can be members of the validator transport overlay with a **Sentry scope** that never grants PoSy signing/finality authority.
- [ ] Validators can use multiple Sentry paths with automatic failover; Sentry loss must not create a one-to-one validator single point of failure.
- [ ] Sentry Nodes validate framing/network/genesis/protocol/identity and apply filtering/rate limits before forwarding, but Validators still independently verify all consensus-critical artifacts.
- [ ] Cross-Chain Node relay and verification capabilities remain independently attributable in receipts/evidence/rewards even though they share one canonical node role.
- [ ] AI capability advertisement controls workload eligibility; operators do not need separate node identities for each AI workload.
- [ ] Capability-isolation tests prove roles cannot access forbidden services or signing authority.
- [ ] Remove obsolete role files/tests/config values after compatibility migration is verified.

## Phase 16 — Native community packaging and operator documentation

- [ ] Native Linux headless install is first-class; Docker is not required.
- [ ] Create systemd hardening, Debian package, RPM/supported equivalent, signed tarball, install/upgrade/uninstall/release-verification tooling.
- [ ] Provide safe examples for Validator, Sentry, Archive, Cross-Chain, AI Compute, RPC Gateway, Indexer, Observer/Light, and other roles where specialized configuration is useful.
- [ ] Document CLI, Control Panel, every role, validator VPN, backup/restore/snapshots, monitoring, troubleshooting, upgrades, incident response, key custody, architecture, PoSy, ETDAG.
- [ ] Verify a fresh community operator does not need internal source-tree knowledge.

## Phase 17 — Test/simulation/fuzz/benchmark infrastructure

- [x] Management core/Admin IPC tests pass.
- [x] Control Panel Admin bridge/lifecycle semantic tests pass.
- [x] Current runtime cargo-check/test-compilation evidence exists for exercised paths.
- [x] Current `node-platform` workspace formatting and focused unit suite pass on `synergy-val4` (101 passed, 0 failed; source-only, not live-chain evidence).
- [ ] Complete unit/integration suites for all subsystems.
- [ ] Build deterministic virtual-clock/virtual-network multi-node simulator.
- [ ] Test 3/5/7 and larger practical validator clusters.
- [ ] Inject proposer failure, drops/delay/reorder/duplicates, latency/jitter/loss/bandwidth, partitions, crashes, disk/fsync failures, corruption, bootseed/VPN outages, validator lifecycle changes, ETDAG failures.
- [ ] Add fuzz targets for P2P, handshake, block/tx, PoSy, ETDAG, snapshot, network manifest.
- [ ] Add performance regression benchmarks without weakening correctness.

## Phase 18 — Upgrade and release security

- [ ] Implement signed release/checksum verification and compatibility windows.
- [ ] Implement governed protocol activation and pre-activation compatibility.
- [ ] Test mixed compatible/incompatible versions, activation boundary, DB/config migration, interrupted upgrade, supported rollback.
- [ ] Run rustfmt, Clippy, dependency/security, reproducible-build, and signed-artifact gates.
- [ ] Generate SBOM/dependency inventory if adopted.

## Phase 19 — Community validator zero-touch end-to-end acceptance

- [ ] Clean host installs signed node package.
- [ ] Initialize validator/network/identity and pass host/config/manifest/genesis/protocol checks.
- [ ] Verify canonical validator registration/authorization.
- [ ] Automatically complete VPN challenge-response, one-use enrollment, overlay connection, and signed transport lease.
- [ ] Automatically discover/authenticate peers and verified network head.
- [ ] Complete state/block/snapshot sync.
- [ ] Recover PoSy and ETDAG persistent state.
- [ ] Complete shadow/readiness; persist progress across restart.
- [ ] Activate only at valid PoSy epoch boundary.
- [ ] Participate in PoSy and finalize subsequent blocks.
- [ ] Process ETDAG protected transactions.
- [ ] Require no manual existing-validator VPN/config edit or restart.
- [ ] Prove both headless CLI and Control Panel can perform/observe the same workflow.

## Phase 20 — Multi-node stall prevention, recovery, and soak

- [ ] Run production-equivalent multi-validator network with sustained finalization and ETDAG load.
- [ ] Verify consistent finalized heights/state roots.
- [ ] Exercise repeated single/multiple validator restarts, proposer failure, message faults, bootseed loss, sync-source loss, VPN management outage, endpoint change, live validator join/shadow/activation, jail/remove, partitions/heal, snapshots, DB recovery, rolling upgrades.
- [ ] Exercise Sentry failover, Sentry loss, Sentry overload/filtering, and validator migration between healthy Sentry paths without exposing Validator public endpoints.
- [ ] Prove no double-signing, early ETDAG reveal, unauthorized VPN/validator enrollment, or unbounded disk growth.
- [ ] Run long-duration randomized-fault soak.
- [ ] Fail soak if chain stops without legitimate PoSy safety reason; every legitimate halt must surface precise diagnostics.
- [ ] Record duration, workload, faults, recovery times, failures, and final consistency.

## Phase 21 — Legacy retirement and final production evidence

- [ ] Retire/reduce `networking.rs`, monolithic ETDAG, scattered consensus ownership, duplicated CLI/GUI management logic, legacy stake-based onboarding semantics, static validator VPN mappings, and duplicate role binaries.
- [ ] Verify no ordinary-user path bypasses ETDAG.
- [ ] Verify no foreign/non-PoSy consensus remains active.
- [ ] Verify no stake-derived PoS authority, Synergy Score→finality, or VPN→validator authority path remains.
- [ ] Verify final workspace matches target tree or documents an explicitly approved equivalent boundary.
- [ ] Verify exactly 20 canonical `NodeRole` values are exposed after migration, with former granular AI roles represented only as capabilities/work types.
- [ ] Verify every authoritative node type is represented.
- [ ] Verify all release-gate tests actually executed; compile-only is not pass evidence.
- [ ] Verify full builds/tests/rustfmt/Clippy/security/native install/CLI parity/GUI parity/community onboarding/repeated finalization/recovery/ETDAG/activation/soak.
- [ ] Produce final implementation report and do not call production-ready until all required gates have evidence.

## Non-negotiable production invariants

- [ ] Proof-of-Synergy is the sole Synergy consensus/finality authority.
- [ ] PoSy is not Proof-of-Stake.
- [ ] Stake remains economic/security participation logic, not PoSy consensus authority.
- [ ] Approved non-uniform PoSy weights come only from authoritative PoSy semantics, never inferred from stake.
- [ ] Stake has nothing to do with Synergy Score.
- [ ] Synergy Score does not determine finality.
- [ ] VPN membership never grants validator authority.
- [ ] Sentry Nodes are transport-security perimeter nodes, never PoSy consensus participants merely because they share the validator overlay.
- [ ] Cross-Chain relay and verification are capabilities of one Cross-Chain Node role, with independent acceptance evidence where required.
- [ ] AI has exactly four canonical node roles—Compute, Coordination, Data, Assurance—while individual AI services remain capabilities/work types.
- [ ] Committee is not a canonical node role; any legitimate committee-like PoSy work is a Validator duty.
- [ ] Node/P2P/VPN/consensus identities are cryptographically verified and safely separated.
- [ ] Validator-set changes activate only at valid governed PoSy boundaries.
- [ ] Consensus signing is crash-safe and cannot double-sign under the required crash suite.
- [ ] ETDAG ordinary-user transactions cannot bypass protected ingress.
- [ ] ETDAG cannot reveal plaintext before authorized reveal.
- [ ] Sync never decides finality and never blindly trusts one peer's height.
- [ ] P2P never implements consensus decisions.
- [ ] CLI and GUI use one shared management implementation.
- [ ] Community validator onboarding requires no manual changes on existing validators.
- [ ] VPN management-plane and bootseed outages are not liveness dependencies for an established healthy validator mesh.
- [ ] Disk/log/evidence/cache/snapshot growth is bounded.
- [ ] Process-alive, VPN-connected, and P2P-connected are not equivalent to validator readiness/activation.
- [ ] Safety is never weakened simply to make a stalled chain appear live.


> **Canonical-root migration note (2026-09-11):** node-platform is the replacement implementation root. Target-path scaffolding is not completion: use SCAFFOLDED, MIGRATING, IMPLEMENTED, and VERIFIED in the implementation ledger. A checkbox remains unchecked until actual ownership, callers, and required evidence meet this checklist's existing rule.


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

- [ ] L24 — Prepare the operator-provided `synergy-archive` machine for archive-node and verified chain snapshots after validator stability; preserve the canonical chain authority and validate snapshot restore. No archive machine changes have been made.

### 2026-10-12 isolated A1 checkpoint

- [x] Record explicit operator approval for isolated signed lookahead D=6–16
  experiments only; production activation remains unapproved.
- [x] Implement and locally validate consistent experimental offset binding
  without changing legacy F+5 signing bytes or frozen activation policy.
- [x] Verify one genuine protected funded transfer at common finalized H28
  on all five isolated native processes for each of D=6 and D=7, including
  matching commitments, receipts and exactly-once wallet effects.
- [ ] Complete healthy admission/cycle percentile coverage and 50% window
  headroom under declared load, degradation and one-validator outage.
- [ ] Execute and verify retained-journal individual restart/rejoin; launcher
  scheduling is implemented with 20 offline tests, not runtime-qualified.
- [ ] Close genuine Genesis/provider, source-evidence client verification,
  persistent signer and independent funded-wallet qualification gaps.
- [ ] Review measured production amendment, complete integrated gates B–F,
  and begin the loaded 24-hour soak only after those gates pass.

Evidence: `node-platform/target/posy-isolated-control-20261012/a1-lookahead-measurements.json`.
D=6/D=7 single-sample successes do not establish TPS or sufficient headroom.

- [x] A1 D=8 declared isolated retained-journal restart: four continued producing; fifth automatically rejoined; repeated common commitments and funded exactly-once effects verified. Evidence: `node-platform/target/posy-isolated-control-20261012/a1-retained-state-recovery.json`. Five-host recovery remains open.

## Compact PoSy timeout history — 2026-10-19 final source checkpoint

IMPLEMENTED / VALIDATED_LOCAL; final Linux actual-host qualification pending.
Accepted timeout certificates retain sealed authenticated summaries, bounded to
4096 entries and64MiB conservative metadata; obsolete timeout-vote signatures
are released. Exact native originals remain immutable on disk. Retry frames hold
compact references and load one original at a time; active retry work reads at
most four originals per poll and historical work reads at most one. Historical
scans inspect at most64 directory entries per poll and paginate4096 slot locators
for one historical lease, without omitting larger retained histories. Alternating
current/history priority preserves progress with a one-frame outbound queue.
Startup replay and cold recovery suffix verification no longer retain full proof
bundles. Typed resource pressure preserves valid QC processing. Canonical signed
V1 roots, native signatures, quorum, carry, contradiction checks and exact retry
bytes remain unchanged.

Validation:36 PoSy tests,10 native runtime qualification tests, genuine signed
R3/restart,4096-reference exact-original variant/contradiction regression and
15000-slot/three-lease pagination pass. Independent Einstein review cleared the
Hercules runtime integration; strict targeted Clippy and formatting pass.
These are local results, not final actual-host OOM closure. Nothing deployed.

### Actual-process resource qualification follow-up — 2026-10-19

All70 final component/native cases passed on five actual hosts under256MiB and
zero swap/OOM. Separate five-process units under1GiB/zero swap exposed a runtime
stale verified-head notification failure before sustained qualification; no OOM
was observed. The scoped Sync fix preserves native PoSy verification and strict
collector conflict checks, discarding only lower already-verified observations
without changing the selected head. Actual-process memory closure remains open
until the resulting artifact passes sustained restart qualification.
