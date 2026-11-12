# Migration map

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


## Protected recovery resource repair — 2026-10-19

IMPLEMENTED / CALLERS_MIGRATED in canonical source: compact authenticated history
and exact-frame lookup remain owned by
`crates/synergy-etdag/src/persistence/protected_pipeline.rs`; native timeout
verification and its bounded verified prefix remain in
`bin/synergy-node/src/services/cut_recovery.rs`. Existing ETDAG consumers use
selected-proof and compact-context APIs. The existing ETDAG owner retains only
active peer-marker payloads and compact historical equivocation fingerprints.
Original proofs remain on disk; wire
bytes, quorum, signatures and PoSy authority are unchanged.
`tools/validator/measure-posy-memory.py` qualifies pinned Linux test artifacts in
isolated capped transient units on Val2–Val6. This does not migrate production
services or activate a chain. Exact current results and remaining gates belong
to `IMPLEMENTATION_STATUS.md`.

## Protected crypto and custody checkpoint — 2026-10-09 UTC

IMPLEMENTED / VALIDATED_LOCAL: governed ML-KEM-1024 + AES-256-GCM + Shamir consumer, separate consensus/ingress key roles, exact target/registry/membership verification, AES tag-aware canonical padding, optional absolute custody path schema, explicit generate-etdag-1024 command, and signed-policy key coverage checks. Scoped package tests passed: ETDAG18, client1, config4, keytool7, Genesis1. Durable nonempty preparation/recovery hooks are implemented; runtime share delivery and its new integration regression remain in progress. No fresh signed artifacts, deployment, live finality, or Val1 conversion is claimed. The prior Linux binary predates these crypto changes and is not the current deployable candidate. The operator approved the cutoff clarification on2026-10-08; signed policy activation and runtime integration remain in progress.

## Parallel fresh-chain implementation checkpoint — 2026-10-08

CALLERS_MIGRATED (source): ETDAG now owns durable collecting/VAC/cutoff state and uses verified VC evidence for cutoff and exact parent authorization; old batch/ordering certificates are not its active liveness prerequisites. PoSy registration restores verified historical VCs before ETDAG starts. Networking reserves the existing64frame budget across protocols, retains exact frames when peer senders are full, and treats bounded inbound bursts as retryable loss. Sync retains exact outgoing work across congestion and revisits independently verified sources after timeout. Complete protected proposal material remains pending the documented cutoff clarification. No deployed caller migration or legacy-service removal is claimed.

## Verified continuation — 2026-10-08

Canonical callers migrated: PoSy retry delivery in services/posy.rs; Sync witness assembly in services/execution.rs and verification/replay in services/posy.rs use synergy-posy/src/sync_witness.rs lease-aware timeout closure. No deployed binary or legacy service changed.

Canonical node-platform remains the production owner. Existing legacy services are retained until replacement qualification. No caller deployment or legacy removal is claimed from the macOS build.

Evidence and diagnostic corrections: `networks/testnet-v3/CHAIN_1266_STALL_LOG.md`, incident C1266-2026-10-08-002. The operator confirmed a completely fresh replacement chain. Older entries below are historical.


> **Canonical repository ledger:** `docs/refactor/MIGRATION_MAP.md` is the one
> canonical version. Every canonical clone contains this same tracked file.
> Update it in place and never create alternate, renamed, or divergent copies.
> An absolute checkout path never defines canonical file identity.

## Canonical Core Protocol ownership — 2026-09-15

The one canonical runtime now physically lives at
`synergy-val4:/home/node/Synergy-Network/01-Core-Protocol/node-platform/`.
It is owned by the Core Protocol root, not by an individual network. The former
Testnet-v3 repository and frozen legacy runtime now live under
`01-Core-Protocol/networks/testnet-v3/`; the legacy runtime remains a semantic
reference only while its remaining production ownership is retired.

The required Core Protocol ownership layout is:

```text
01-Core-Protocol/
├── node-platform/
├── networks/{devnet,testnet-v3,mainnet-beta,mainnet}/
├── protocol/
└── tooling/
```

The physical root move and Git-root lift are complete. Network-artifact,
protocol-specification, tooling, path-reference, and legacy ownership
reconciliation remain active and must not be confused with the completed move.

The implementation phase uses `OPEN`, `PARTIAL`, `IMPLEMENTED`,
`CALLERS_MIGRATED`, `LEGACY_REMOVED`, and `VERIFIED`. Build, test, integration,
and production-equivalent acceptance remain distinct evidence gates after
source/caller migration; they are required before the expanded architecture can
be called fully complete.

## Current reconciliation — 2026-09-15

The persistent production-source queue is 100% implemented. Direct source
inspection in the canonical Val4 checkout confirms concrete SynQ/PQSynQ/AIVM,
SXCP/UMA, governance, and supported system-action providers; finalized-state and
snapshot callers; trust-root-signed cross-epoch authority handoff; and
authenticated ETDAG shard request/response serving. These responsibilities have
advanced to `CALLERS_MIGRATED` below. No responsibility is marked
`LEGACY_REMOVED` until the old production owner is unreachable or reduced to an
explicitly non-authoritative reference/facade. Phase 2 build/test/deployment
evidence is deliberately not inferred from source presence. The canonical
completion checklist currently records 125 complete, 30 partial, and 159 open
items: **44.6% weighted overall completion** with partial items counted as half.
That percentage includes the expanded root, naming, ownership, rewards, parity,
updater, onboarding, and acceptance requirements now itemized in the completion
checklist.

| Current owner | Extracted/current target | Migration rule |
| --- | --- | --- |
| `01-Core-Protocol/testnet-v3/node-platform` transitional path | `01-Core-Protocol/node-platform` | **MOVED 2026-09-15.** Repair all repository, build, service, package, documentation, and operator references; do not recreate a network-owned implementation. |
| Network-specific artifacts mixed into the former repository root | `01-Core-Protocol/networks/<network>` | Keep only governed per-network manifest/Genesis/bootseed/version/role/ETDAG artifacts here; never fabricate mainnet values. |
| Protocol documents mixed with network history | `01-Core-Protocol/protocol` | Move normative PoSy, ETDAG, SXCP, UMA, Aegis, transaction, state, identity, naming, ownership, reward, manifest, lifecycle, and wire definitions without duplicating Rust engines. |
| Dispersed operational binaries/scripts | `01-Core-Protocol/tooling` plus reusable `node-platform` crates | Preserve one implementation of each tool and keep reusable libraries in the Rust workspace. |
| `role_runtime.rs` lifecycle switches | `node_management` and node-core | Move observable state first; add mutating actions only with idempotency and recovery semantics. |
| manual `synergy-node.rs` command matcher | `node-platform/bin/synergy-node` Admin API client | Core reads, validator lifecycle, and ownership/naming/reward finalized-state inspection plus wallet-transaction preparation use the typed local dispatcher/socket. Protected submission, remaining subsystem commands, and GUI callers remain. |
| `p2p/networking.rs` | `p2p::transport`, `p2p::handshake`, `p2p::peer_lifecycle`, `p2p::discovery`, `p2p::router`, adapters, VPN | Transport parsing, handshake policy, lifecycle admission, DNS/dnsaddr discovery, and bounded fair mailbox ownership have moved. Move consumers and tests with each next boundary; do not rename the monolith. |
| `sync/*` plus P2P selection | sync subsystem | Verify source/finality separately from transport routing. |
| `etdag.rs` | ETDAG admission/DAG/certification/order/reveal/persistence | Preserve protected-input binding to finalized context. |
| frozen validator-weight semantics | clean canonical PoSy and ETDAG context types | Preserve approved non-uniform weight behavior plus independent count and weight quorums. Do not preserve the old serialization/root representation merely for compatibility. |
| Node Control Panel local control code | `synergy-admin-api` client | Replace duplicate management decisions with the shared contract. |


## Canonical node-platform ownership ledger

LEGACY means the old runtime still owns production behavior. PARTIAL means real
new implementation exists but the assigned responsibility is incomplete.
IMPLEMENTED means the new file owns its assigned behavior. CALLERS_MIGRATED
means real production callers use that owner. LEGACY_REMOVED means the old owner
no longer carries required production behavior. Test evidence is recorded only
as historical context during this phase; it is not part of these states.

| Responsibility | Legacy owner | New owner | Status | Tests | Legacy callers remaining | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Core Protocol root ownership | Network-owned transitional path | `01-Core-Protocol/{node-platform,networks,protocol,tooling}` | IMPLEMENTED (physical/Git-root move); CALLERS_MIGRATING | Path/build verification pending | Repository path consumers and ownership redistribution | The only node-platform tree is now the Core Protocol sibling implementation. The former Testnet-v3 tree is under `networks/testnet-v3`; its non-network material must still be redistributed. |
| Canonical Node Address terminology | `NodeId`/validator-ID terminology used for `synv...` identity | `NodeAddress` as the one canonical `synv<class>...` protocol identity | PARTIAL; ACTIVE CUTOVER | Newest Admin/CLI/RPC changes not yet verified | Identity, networking, PoSy, persistence, transport, telemetry, GUI, and legacy callers | Validator Admin operations and the CLI are being changed to a typed NodeAddress and `--node-address`; `--validator-id` must not remain an independent node-identity input. Consensus-key IDs remain subordinate credentials and operator identity remains a separate human principal. |
| Synergy Naming System NodeID | No first-class owner | `synergy-naming` plus typed Admin/CLI/GUI callers | IMPLEMENTED; CALLERS_MIGRATING | 6 focused tests plus focused `synergy-node` check pass | GUI, RPC/WS, protected user submission, legacy SynID/naming callers | NodeID is only a `.node` alias to NodeAddress. Registration/rename execute against canonical ownership and `WorldState.protocol`; PoSy-finalized state is authoritative. Admin/CLI only query or prepare wallet-signed actions, and local persistence is a rebuildable finalized cache. |
| Node owner-wallet binding | No first-class owner | `synergy-node-ownership` plus typed management callers | IMPLEMENTED; CALLERS_MIGRATING | 2 focused tests plus focused `synergy-node` check pass | Onboarding, GUI, protected user submission, legacy ownership callers | Claim/transfer actions route through deterministic execution with wallet sender-key binding, detached Aegis node proof, and replacement-owner acceptance. Admin/CLI never write ownership locally. |
| Reward withdrawal authorization | Dispersed/undefined | `synergy-rewards` plus canonical ownership authorization | IMPLEMENTED; CALLERS_MIGRATING | 2 focused tests plus focused `synergy-node` check pass | Canonical reward producers, GUI, protected user submission, audit, legacy callers | Accounts remain keyed solely by NodeAddress. Owner withdrawal executes against canonical ownership in finality-gated world state; Admin/CLI inspect or prepare the action and cannot mutate the cache. |
| Exact CLI/GUI capability parity | Partial Admin/CLI/Control Panel operations | One machine-readable Admin capability registry consumed by both interfaces | PARTIAL | Automated parity evidence not run | Control Panel ownership/naming/reward callers, remaining operation groups, parity test | The shared typed operation enum now covers ownership, naming, and rewards and CLI consumes it; Control Panel callers and registry-based parity proof remain open. |
| Automatic signed updater | Upgrade scaffolding and manual operator flow | Canonical updater service with signed staged rollout and rollback | OPEN | Not started | Admin, CLI, GUI, lifecycle, telemetry, activation | Software installation remains distinct from governed protocol activation. |
| Simplified PoSy control plane | Legacy overlapping orchestration | One `synergy-posy` driver with explicitly justified retained mechanisms | PARTIAL | Full source/caller/persistence/test audit pending | Dependency map, timeout carry, prepared state, reconstruction, scheduling, shadow/activation residue | `protocol/posy-v3/PO_SY_SIMPLIFICATION_AUDIT.md` now records the invariant/failure/simpler-alternative classification and prohibited derived complexity. The retained-mechanism dependency map and evidence-backed application remain open. |
| Shared management contract | runtime/crates/synergy-node-core, synergy-admin-api | node-platform/crates/synergy-node-core, synergy-admin-api, synergy-validator-management plus bin/synergy-node/src/services/admin.rs | IMPLEMENTED (read, validator lifecycle, node-state query/preparation); CALLERS_MIGRATING | Focused `synergy-node` check passes; Phase 2 qualification remains | Audit persistence, protected submission, remaining operation groups, and Control Panel consumers | The owner-local Admin dispatcher reads finalized ownership/naming/reward state and prepares the exact native actions used by execution. It cannot bypass ETDAG or mutate cache state. |
| Universal node CLI and startup ownership | runtime/src/bin/synergy-node.rs command matcher/startup | node-platform/bin/synergy-node | IMPLEMENTED; CALLERS_MIGRATING | No current migration gate | Legacy startup/command callers | `start` loads canonical configuration and verified authority, registers every configured identity/storage/network/sync/Admin/ETDAG/execution/PoSy/RPC/WS/VPN/Sentry/telemetry/health service, refuses incomplete coverage, supervises the retained run loop, and shuts down in reverse order. |
| Canonical shared protocol types | Runtime-local message/session types and oversized synergy_types aggregate | node-platform/crates/synergy-protocol-types | IMPLEMENTED | No current migration gate | Subsystem callers and legacy aggregate retirement | Chain context/height/epoch, bounded identity, fixed hashes, block/transaction/certificate references, frame descriptors, and route/session identity are authority-neutral; PoSy and ETDAG retain certificate verification and final authority. |
| Independent version domains and activation | Legacy release-coupled version checks | node-platform/crates/synergy-version | IMPLEMENTED | No current migration gate | Manifest/runtime callers | Release, protocol-component, database, and config versions are separate; compatibility is explicit and governed activation is commitment-bound. |
| Node-facing Aegis boundary | runtime/aegis-pqvm direct consumers | node-platform/crates/synergy-aegis | IMPLEMENTED; CALLERS_MIGRATED | No current migration gate | Established legacy hash/utility callers and legacy retirement | Aegis is the single cryptographic engine and raw PQVM/PQSynQ integration owner. Network, ETDAG/DA, PoSy, SynQ, SXCP/UMA, snapshot, and governance callers use its provider boundary; `synergy-crypto` remains a protocol-neutral facade. |
| Canonical storage runtime adapter | Legacy runtime storage startup | node-platform/bin/synergy-node/src/services/storage.rs | CALLERS_MIGRATING | No current migration gate | Remaining runtime services | Real configured data directory, canonical schema marker, strict durability/pruning support checks, and live health are registered as a critical supervised service. |
| TCP transport ownership | runtime/src/p2p/transport.rs and networking socket ownership | node-platform crates/synergy-network/src/transport plus bin/synergy-node/src/services/network.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Legacy networking callers | Canonical endpoints feed the supervised `NetworkService` nonblocking listener, bounded-time dialer, authenticated sessions, limits, routing, and protocol egress; transport remains authority-neutral. |
| Peer lifecycle/session ownership | runtime/src/p2p/peer_lifecycle.rs plus networking.rs caches | node-platform crates/synergy-network/src/peer | SOURCE IMPLEMENTED | Verification deferred for new files | Runtime callers and socket integration | Exact-session ownership, legal transitions, health, scoring, limits, bans/quarantine, deterministic duplicate resolution, persistence boundary, and bounded retry are implemented with no consensus authority. |
| Bounded P2P router | runtime/src/p2p/router.rs and networking.rs consumers | node-platform crates/synergy-network/src/router plus bin/synergy-node/src/services/network.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Legacy runtime dispatch | Per-peer/global bounds, fair drain, watermarked backpressure, typed handlers, exact-session discard, bounded retransmission, and authenticated runtime drain/egress are wired. |
| Protocol adapters | runtime/src/p2p/networking.rs dispatch | node-platform/crates/synergy-p2p-protocols plus bin/synergy-node/src/services/{network,sync,etdag,posy}.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Legacy protocol dispatch | PoSy, ETDAG, and sync frames route through authenticated transport-only adapters and cannot make protocol decisions. |

## Pre-release integration gate

The active migration branch remains based on 4aa6ae8 while origin/main is 84869dc. Do not rebase during ownership transfer. Before any immutable replacement release: fetch upstream, enumerate and semantically reconcile intervening commits, rerun the relevant complete suite, and prove upstream fixes were retained.
| Canonical authenticated handshake | runtime/src/p2p/handshake.rs | node-platform/crates/synergy-network/src/handshake plus bin/synergy-node/src/services/network_session.rs | IMPLEMENTED | Phase 2 verification deferred | None for runtime ownership | Challenges, identity/capability/role checks, exact chain/network/genesis/version compatibility, transcript binding, signing/verification, and rejection types are implemented without old wire compatibility. |
| Authenticated discovery | runtime/src/p2p/discovery.rs | node-platform crates/synergy-network/src/discovery | SOURCE IMPLEMENTED | Verification deferred | Runtime resolver and candidate dialer | Prioritized bootseeds, TCP DNS candidates, validated peer exchange, signed-registry boundary, and bounded expiring cache are implemented; discovery grants no authority. |

| Validator and Sentry VPN ownership | runtime/src/p2p/vpn.rs | node-platform/crates/synergy-vpn plus bin/synergy-node/src/services/vpn.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Enrollment/lease publication, deployment bindings, and legacy retirement | Exact scopes, signed expiring leases, challenge-response enrollment, NetBird control/readiness, and peer binding are implemented. The universal node observes NetBird, schedules signed-route dials, and cannot derive authority from VPN membership. |
| Identity-complete transport registry | runtime/src/p2p/validator_transport_registry.rs | node-platform/crates/synergy-transport-registry plus bin/synergy-node/src/services/{vpn,ingress,network_session}.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Remote fetch, deployment bindings, and legacy retirement | The runtime verifies pinned snapshot signatures/provider-plan roots, checks active-authority coverage, persists rollback-resistant accepted generations, and enforces signed identity/IP routes on inbound/outbound authenticated sessions. Leases, revocation, reconciliation, and custody remain authority-neutral. |

| Sentry bounded forwarding perimeter | runtime/src/p2p/networking.rs | node-platform crates/synergy-network/src/sentry | SOURCE IMPLEMENTED | Verification deferred for new files | Runtime socket/session integration | Authenticated public/validator sets, protocol/size filters, bounded forwarding, deterministic multi-link failover, and metrics prohibit PoSy engine ownership, signing, and finality. |

| Signed provider snapshot verification and exact route binding | runtime/src/p2p/validator_transport_registry.rs plus networking admission | node-platform/crates/synergy-transport-registry/{verifier,binding}.rs plus bin/synergy-node/src/services/{vpn,ingress,network_session}.rs | IMPLEMENTED; CALLERS_MIGRATING | Existing focused tests only; new caller paths deferred to Phase 2 | Remote fetch, deployment bindings, and legacy retirement | Pinned Ed25519 verification, plan binding, active coverage, durable accepted generation, exact outbound route and inbound identity/IP enforcement are fail closed. Transport evidence cannot grant PoSy authority or membership. |

| PoSy proposal/vote/QC/TC/finality driver, sign-once persistence, and recovery | runtime PoSy state/driver/certificates | node-platform/crates/synergy-posy/{engine,proposal,voting,quorum,finality,timeout,persistence,recovery} plus bin/synergy-node/src/services/posy.rs | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Cross-process persistence safety and legacy retirement | One supervised driver owns governed proposal/vote/QC/TC/three-QC-finality progression, authenticated ingress/egress, durable sign-once authority, verified QC/TC persistence before broadcast, frozen-authority restart replay, Sync witness verification, execution-candidate handoff, and verified successor-epoch reconstruction with two-QC-tail continuity. No supporting service gains finality authority. |
| ETDAG protect/certify/order/reveal | runtime ETDAG pipeline | node-platform/crates/synergy-etdag plus bin/synergy-node/src/services/etdag.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Ordinary-user client ingress and provider/store hardening | The supervised runtime owns exact-H+5 authenticated protected ingress, provider-bound crypto, DAG/cuts, availability, certificate families, content-blind ordering, finality-authorized reveal, deterministic execution handoff, governance, persistence boundaries, recovery, and metrics. ETDAG has no finality authority. |
| ETDAG protected client ingress | Governed-validator sender allowlist/request fields and legacy client-side protected submission helpers | `synergy-etdag` wallet admission contract plus `synergy-etdag-client` and public RPC/transport caller | PARTIAL; SECURITY CORRECTION IN PROGRESS | New request changes not yet verified | Client signed-request construction, Aegis provider, public RPC/transport caller, negative tests, finality evidence | The server request is being rebound to chain/network, target context/height, wallet, nonce, signature algorithm, presented public key, and the full encrypted envelope. The old governed-validator sender-policy path is being retired; no unprotected ownership/naming/reward route is permitted. |
| Data-availability shard custody | runtime ETDAG availability and ad hoc shard persistence | node-platform/crates/synergy-data-availability plus synergy-etdag/src/availability/custody.rs and bin/synergy-node/src/services/etdag.rs | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Legacy caller retirement | Authenticated ETDAG frames carry custody and bounded recovery requests/responses; governed Aegis proof, exact sender/key, chain/network, vertex/shard roots, and index are verified before durable admission, serving, receiver re-verification, and conflict-safe re-admission. Finalized-height retention uses the canonical storage window. |
| Authorized execution handoff | runtime execution pipeline | node-platform/crates/synergy-execution plus bin/synergy-node/src/services/{execution,posy,authority}.rs | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Native external-chain proof adapters, ordinary-user ingress, cross-process safety, and legacy retirement | Revalidates ETDAG-certified transactions through Aegis/PQVM and routes every supported action through concrete native, SynQ/PQSynQ/AIVM, SXCP/UMA, governance, or narrow governance-delegating system providers. It persists candidates before PoSy publication, re-executes only QC-bound candidates, and commits root-checked state only after matching finality. |
| Canonical transaction and block representation | runtime transaction/block types and encoding | node-platform/crates/synergy-transaction and synergy-block plus new-node execution/PoSy callers | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Ordinary-user ingress, state proofs, and legacy retirement | Versioned bounded actions and block codec, authorization, nonce safety, receipt commitments, ordered roots, continuity, proposer verification, concrete action dispatch, and PoSy proposal/import callers are wired. |
| Atomic bounded-file and WAL persistence | runtime file writes | node-platform/crates/synergy-storage/{database,fsync,wal} | BEHAVIOR_MIGRATING | 5 focused tests pass | Runtime persistence callers | Atomic fsync/rename/directory-sync, bounded reads, traversal rejection, sequence/integrity-bound WAL replay, and truncated-record refusal have final owners; traps/injected failures and runtime caller cutover remain. |
| Finalized state commit | runtime state persistence | node-platform/crates/synergy-state/{state,transition} plus bin/synergy-node/src/services/{execution,sync}.rs | IMPLEMENTED; CALLERS_MIGRATED | New world-state path not tested | Cross-process safety, state proofs, pruning, and legacy retirement | Durable finalized-state ownership writes root-checked account/protocol bytes before immutable per-height commitment history and latest pointer, supports conflict-safe retry, and requires caller-supplied PoSy finality. Execution and Sync restore exact state, refuse missing bytes, and QC-check/re-execute stored candidates. |
| PoSy persistence and recovery | runtime PoSy persistence/restart | node-platform/crates/synergy-posy/{persistence,recovery} plus bin/synergy-node/src/services/posy.rs | IMPLEMENTED (runtime batch); CALLERS_MIGRATING | Phase 2 verification deferred | Epoch-transition, cross-process writer ownership, and crash-atomicity queue | Immutable proposal/vote/prepared/QC/TC/finality records, authenticated peer reports, strict count+non-uniform-weight recovery quorum, fail-closed QC/TC replay and durable-finality reconciliation, durable sign-once runtime calls, and the signing gate are wired. |
| PoSy failed-write atomicity | runtime safety journal semantics | node-platform/crates/synergy-posy | MIGRATING | focused regression passes | Runtime PoSy callers | Memory advances only after durable atomic write succeeds; a storage failure cannot suppress later signing/recovery action. |
| ETDAG durable state and recovery | runtime ETDAG persistence | node-platform/crates/synergy-etdag plus bin/synergy-node/src/services/etdag.rs | IMPLEMENTED; CALLERS_MIGRATING | Phase 2 verification deferred | Multi-record durable store/backend and ordinary-user callers | Atomic admission, encrypted-input, DAG, certificate, safety, and no-plaintext reveal stores plus supervised recovery/handoff validate context and roots without execution or finality authority. |
| Deterministic execution transition sequencing | runtime execution path | node-platform/crates/synergy-execution plus bin/synergy-node/src/services/execution.rs | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Ordinary-user ingress, native external-chain proof adapters, state proofs, and legacy retirement | The runtime revalidates protected input, routes supported native/SynQ/SXCP/governance/system actions through concrete canonical providers, applies ETDAG order through a borrowed-parent speculative overlay, produces receipts/candidates, and commits only after matching PoSy finality without acquiring finality authority. Candidate persistence uses atomic checkpoint/delta worlds behind shared verified readers, preserves legacy/wire compatibility, and retires only behind durable finality with dependency-safe cursors. |

| Canonical Genesis utility | legacy Genesis ceremony utilities and runtime-local formats | node-platform/bin/synergy-genesis | IMPLEMENTED | Phase 2 verification deferred | Manifest/schema and launch-artifact generation | Strict Chain 1266 network, active validator, H+5 ETDAG, initial-state and authority bindings have deterministic hashing plus governed ML-DSA-65 sign/verify ownership; no launch artifact was generated. |
| Offline key lifecycle utility | dispersed runtime and ceremony key scripts | node-platform/bin/synergy-keytool | IMPLEMENTED | Phase 2 verification deferred | Runtime custody providers and governed activation callers | Non-overwriting 0600 secret generation for PQVM ML-DSA-65 node/consensus and ML-KEM-768 ETDAG keys, public metadata inspection, and offline active-to-generated rotation plans; it never mutates PoSy membership or finality authority. |

| Canonical manifest CLI | legacy manifest/launch scripts | node-platform/bin/synergy-manifest | IMPLEMENTED | Phase 2 verification deferred | Full library/schema and runtime callers | Strict Chain 1266 Genesis, validator/key, PoSy, ETDAG, role, transport, bootseed, release, protocol, and schema bindings have deterministic hash, governed ML-DSA-65 sign/PQVM verify, inspection, and bounded diff ownership; no network artifact was generated. |

| Aegis engine and public cryptography facade | scattered raw PQVM consumers | node-platform/crates/synergy-aegis plus synergy-crypto facade | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Established legacy hash/utility callers and legacy retirement | Aegis is the sole engine and raw Aegis-module integration owner. `synergy-crypto` exposes only protocol-neutral facade types/delegation. Network, ETDAG/DA, PoSy, SynQ/PQSynQ, SXCP/UMA, snapshot, and governance production callers use the canonical boundary. |
| Canonical Synergy address engine | runtime address.rs and snts_registry.rs | node-platform/crates/synergy-address; synergy-transaction validation caller | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 verification deferred | Legacy address owner retirement | Address Engine v1/SNTS-01 derivation and Bech32m validation are owned by `synergy-address`; transaction sender/receiver admission delegates to it. Validator identity and signed transport-route identifiers are governed identities, not address-engine address callers. |

## Implementation-first ownership additions - 2026-09-11

| Responsibility | Legacy owner | New owner | Status | Verification posture | Legacy callers remaining | Notes |
| --- | --- | --- | --- | --- | --- |
| Node lifecycle / readiness types | runtime node_management | node-platform/crates/synergy-node-core/{lifecycle,readiness,node,context} | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 qualification deferred | Legacy node-management retirement | Management data types, the Admin provider, supervised services, lifecycle transitions, readiness snapshots, and the retained universal-node run loop use the canonical owners. |
| Service supervision | runtime role/startup orchestration | node-platform/crates/synergy-node-core/supervisor | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 qualification deferred | Legacy startup retirement | The universal node registers the complete configured builtin graph through deterministic dependency ordering, criticality, bounded restart, cancellation, health/fail-closed inspection, and reverse-order shutdown. |
| Node lifecycle evidence and transitions | runtime role/startup orchestration | node-platform/crates/synergy-node-core/lifecycle | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 qualification deferred | Legacy lifecycle retirement | Canonical preflight, startup, bootstrap, finality-bound synchronization, readiness, degradation, drain, successor-epoch graph reconstruction, shutdown, and permitted-transition callers are wired. |


| Canonical node configuration | runtime configuration handling | node-platform/crates/synergy-config | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 qualification deferred | Broader manifest/utility callers and legacy retirement | Strict JSON schema v1, bounded loader, typed service sections, cross-field validation, explicit authority binding, H+5 enforcement, and universal-node subsystem construction are wired with no legacy adapter. |
| Node lifecycle/readiness contract | runtime node_management | node-platform/crates/synergy-node-core/{node,context,lifecycle,readiness} | IMPLEMENTED; CALLERS_MIGRATED | Phase 2 qualification deferred | Legacy management-provider retirement | Authority-neutral management types, supervisor, lifecycle driver, runtime snapshot publication, Admin reads, and health/readiness callers use the canonical contract. |
| Verified head/block/state synchronization | runtime sync/P2P selection and import | node-platform/crates/synergy-sync plus synergy-execution/src/candidate.rs plus bin/synergy-node/src/services/{sync,posy,execution,authority,ingress}.rs | IMPLEMENTED; CALLERS_MIGRATED | New caller verification deferred to Phase 2 | Configured external archive/object-store integration and legacy retirement | Authenticated verified heads select sources. The runtime requests parent-anchored finalized candidates with bounded failover and durable resume, verifies all QC/TC evidence through the sole PoSy driver, re-executes and finality-gates state, carries finality-bound snapshot chunks through durable restore with a four-context byte-budgeted cache, active transfer pins/leases and incremental legacy cleanup, and admits a successor authority only after exact epoch-end three-QC and trust-root-signed binding verification. The builtin service graph is reconstructed atomically for the successor epoch. |


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
