# PoSy / ETDAG asynchronous conformance audit

Date: 2026-10-21. Status: **AUDIT COMPLETE; IMPLEMENTATION APPROVED AND PARTIAL; RUNTIME NOT QUALIFIED.**

The operator subsequently approved the proposed versioned profile for the
isolated canary. The approval-pending passages below describe the audit's
original decision boundary. Implementation approval does not activate a profile,
authorize production changes or qualify the canary. Processing-specific signed
carriers and shared native crypto now have local regression evidence; runtime
publication, recovery, governed activation and host qualification remain open.

The operator's required architecture is authoritative for the intended correction:
transaction processing can span several block intervals; PoSy continues normal
proposal/QC/finality progression, including valid empty blocks, while unfinished
work remains pending. Preparation and inclusion eligibility are not finality.

**Finding:** current workers are asynchronous, but the protocol lifecycle is
height-bound. Both the maintained specification and current source contradict
the operator's requested target-independent inclusion behavior. This is not
evidence that a formerly implemented cross-height ready pool regressed. Faster
signing or a larger lookahead cannot establish conformance to the requested
architecture. Removing cutoff checks or accepting arbitrary empty material under
the current profile would violate authenticated protocol semantics.

## 1. Evidence and historical architecture

Canonical checkout: `01-Core-Protocol`; implementation: `node-platform`.
HEAD at audit: `b338dcc223c1ce33599e12c424858cd000772637`, with substantial
pre-existing uncommitted changes. HEAD alone does not identify the audited tree.
Current source-file digests are recorded in
`node-platform/target/posy-async-conformance-audit-20261021/current-source-pins.json`.
No release approval or clean-source claim follows from these pins.

Historical DOCX sources are in the workspace's `24-Technical-Documentation/current/protocol-documentation/`.
Read-only paragraph extracts and complete SHA-256 pins are preserved in
`node-platform/target/posy-async-conformance-audit-20261021/`:

| Source | SHA-256 | Relevant extracted paragraphs |
|---|---|---|
| PoSy `00D-Encrypted-DAG-Mempool-and-Fair-Ordering-Amendment-v2.2.docx` | `8e1cb16e4eb85485e4c015d2cf703508c29949fe9b04b6dd5d73cb26be24788d` | `posy-00d.txt` P84–112: exact target, VC(h−2) cutoff, order-before-reveal; P127 and P185: no carryover and fresh encryption after a missed target; P243/P314: authenticated empty batches; P368: no silent migration. |
| PoSy `03-Section-03-Protocol-Architecture-Overview.docx` | `c6b37825526753fd2c0dc34bbb75d74c6dabec1ba746335b26ad1200c931288b` | `posy-03.txt` P97–103: future-height admission and separation of dissemination from consensus, retaining the exact-height pipeline. |
| `Synergy_ETDAG_and_Compartmentalized_AIVM_Execution_Environment_Technical_Specification_v0.2.docx` | `bcad1c870fc708d40a71cebe0520ad29d6bd7c0e8af7ebe0e7d01651593005fc` | `etdag-aivm-v02.txt` P21/P158/P225/P279: 00D authority, target namespace, cutoff and no carryover; P571: execution against canonical parent. Its asynchronous cross-compartment messages do not establish a target-independent ETDAG inclusion pool. |

The maintained `protocol/posy-v3/PROTECTED_PIPELINE_PROTOCOL.md` deliberately
requires material for normal heights, including certified empty batches. Its
approved replacement profile binds proposal H to execution H, next batch H+1,
and cutoff descriptor H+2; VC(H) closes H+2 and VC(H+1) authorizes its reveal.
The approved F+5 profile replaced the older F+3 profile without removing these
bindings. `POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md` preserves protected
validation while simplifying PoSy to ordinary three-QC finality.

Historical prose says the inner transaction signs the target height. Current
`SignedTransaction` has no target/expiry field: its signed fields are network,
class, sender/receiver, amount, nonce, fees, timestamp and payload. The current
height binding is in the signed outer admission request and authenticated
encryption context. This difference must not be hidden in a migration design.

## 2. Implemented lifecycle and couplings

All code references below are relative to `node-platform/`, at the pinned tree.
Line numbers are navigation aids; symbols and file digests identify the evidence.

| Boundary | Current evidence | Meaning and classification |
|---|---|---|
| Wallet authorization/encryption | `crates/synergy-etdag/src/admission/request.rs:123` (`signing_bytes`); `crypto/envelope.rs:23` (`canonical_bytes`); `bin/synergy-keytool/src/wallet.rs:309` | Outer signature, envelope and AEAD AAD bind exact target/context. Cryptographically necessary under the current profile; inclusion-height binding is a profile choice requiring a versioned change. |
| Inner transaction | `crates/synergy-transaction/src/transaction.rs:33`, `:77`, `:103` | No inner target/expiry field. Existing user execution authorization can potentially remain unchanged; outer/profile formats still change. |
| Context acquisition | `bin/synergy-node/src/services/etdag.rs:1443` and `:1486` | Finalized authority derives F+5 and outstanding-nonce limits. Authenticated authority is necessary; a fleeting inclusion target need not be the identity of admitted work in the new profile. |
| Enqueue and asynchronous preparation | `services/protected_admission.rs:502`, `:580`; `services/etdag.rs:1863` | Enqueue checks live cutoff and returns queued, admitted=false, durable=false. Bounded workers exist, but processing completion can lose the target race. This does not implement cross-height acceptance. |
| Durable authoring | `services/etdag.rs:2497–2531`; `services/protected_admission.rs:669` | Checks closure around vertex persistence; durable receipt precedes completion publication. Retained closed staging is not accepted reusable work. Preserve durable acknowledgement distinctions. |
| Cut and deterministic order | `services/etdag.rs:3208`, `:3318`, `:3431` | Authenticated causal closure and dependency completeness fix an exact-target commitment. Determinism and authenticated completeness stay necessary; assignment to an inclusion height is separable. |
| Reveal | `services/ingress.rs:1540`, `:1631`; `crates/synergy-etdag/src/reveal/authorization.rs:26`; `reveal/decrypt.rs:56` | Cutoff at VC(target−2), reveal via exact committed parent at target−1, exact envelope/root checks. Order-before-reveal and public authenticated disclosure are necessary; exact adjacent-height coupling is current profile semantics. |
| Durable ready material | `services/etdag.rs:3758–3835`; `crates/synergy-etdag/src/persistence/protected_pipeline.rs:2660` | Prepared batch and reveal evidence persist for the original target. No independently selectable durable cross-height ready pool was found. |
| Block assembly | `services/execution.rs:1064` (`transactions_for_candidate`), `:1120`, `:1138`, `:1402` | Missing batch permits empty execution only at H1/H2; normal height requires exact-target material plus future commitments. `only_h1_h2_can_execute_without_protected_material` explicitly tests this coupling. |
| PoSy proposal/voting | `services/posy.rs:2182–2200`, `:1788` | Proposal needs active-height executed candidate; voting verifies candidate. ETDAG not-ready can stop PoSy's normal progression. PoSy must still validate all included material after decoupling. |
| Empty batch | `crates/synergy-etdag/src/persistence/protected_pipeline.rs:2603` (`prepare_empty`) | Requires authenticated empty cut/parent; unfinished ETDAG alone is not permission for an ordinary empty block under the old profile. |
| Recovery | `services/etdag.rs:2620`, `:2680`, `:4324` | Reinstalls original-target owners and proof-backed acceptance; recovery pauses ETDAG reconciliation/context publication until complete. Durable recovery exists, but not arbitrary later inclusion. |
| Actual execution/finality/retirement | `services/execution.rs:2028–2079`; `services/posy.rs:1284–1317`; `services/etdag.rs:2814–2854` | Matching candidate committed through ordinary crash-atomic three-QC finality. Target-based retirement must become actual-consumption/finality-based for cross-height work. Never reuse speculative state effects against a different parent. |

## 3. Mismatch and root cause of the observed rejection

The same target currently binds authorization, disclosure context, deterministic
batch identity, execution material and actual block inclusion. These are distinct
responsibilities in the operator's required architecture. Worker scheduling is
asynchronous; authenticated eligibility and proposal construction remain coupled
to specific heights. The mismatch therefore crosses signed protocol boundaries,
not just a queue timeout or polling interval.

The last instrumented Val5 diagnostic is terminal FAILED, not still running.
Its wrapper completed at `2026-10-21T21:30:56.820410+00:00`, exit 1, with cleanup
complete. Two transfer reports were captured; the planned third did not complete.
No success is inferred from starting a run or from an RPC enqueue receipt.

| Target63 measurement | Result |
|---|---:|
| Native opening → cutoff | 974.891187 ms |
| Opening → native RPC enqueue | 634.358323 ms |
| Enqueue → cutoff headroom | 340.532864 ms |
| Client native-sign call wall time | 225.175883 ms |
| Parent/native signer CPU | 18.616267 / 79.651703 ms |
| Parent/native signer run-queue wait | 73.356092 / 56.279629 ms |
| Signer response JSON decode | 73.826033 ms |
| Admission outcome | Durably rejected `closed_target`; no accepted transaction |

Evidence directory:
`node-platform/target/canary-critical-path-default5-host-evidence-v43-sched-20261021/val5/`,
particularly `native-evidence-v43-sched/steady-state-transfer-diagnostic-1.json`
and `timing/default5-critical-v43-sched-public-phases-val5.jsonl`.
The verified export archive SHA-256 is
`474b9f042039883856a7d7157a5365f4f8e3fcf688474babe78f136001084962`.
Instrumented runtime SHA3-256:
`845076fd14452d22f1a0421473aac164c44c9333180e542d8e591d1d2cf29efa`.

Earlier target40 had a 732.719 ms window, enqueue after 589.538 ms, and only
143.181 ms remaining; it also rejected. Subsequent samples sometimes submitted
after closure. Measured live CPU/run-queue/serialization costs contribute to the
late arrival. The data do not establish one exclusive scheduling/crypto cause,
nor demonstrate incorrect deadline arithmetic. The final diagnostic's enqueue
preceded cutoff but durable admission did not finish in time.

Under the existing profile, `closed_target` protects a real signed cutoff rule.
It cannot be waived or its ciphertext silently retargeted. Under the required
architecture, a transaction's original authorization must instead permit its
processing to outlive block progression. That requires changing what is bound,
while preserving authenticated processing and replay protection. This is the
causal reason to stop timing-only attempts. The separate 30-second end-to-end
contract remains unevaluated by this rejected transaction; later finalization
of target63 did not finalize it.

## 4. Smallest coherent correction proposal

**Propose one versioned asynchronous protected-pipeline profile for the fresh
isolated canary.** Reuse the existing ETDAG owner, bounded workers, durable
journals, cryptography and sole PoSy consensus engine. This is a bounded protocol
correction candidate, not a completed security proof or an approved activation.
Do not introduce another batch consensus, leader, quorum or finality mechanism.

1. **Separate processing identity from inclusion height.** A newly authenticated
   processing context binds chain/incarnation, governed profile and parameter
   roots, authorized key/validator scope, immutable request/envelope identity and
   replay identity. It must not promise execution at one block height. Separate
   protocol-assigned ordering groups from the inclusion block. Admission before
   group assignment must be durable and bounded; an assignment deadline cannot
   become another hidden one-slot user-authorization deadline.
2. **Keep admission, order and reveal authenticated.** Use immutable certified
   group commitments and existing PoSy evidence to anchor ordering and authorize
   public reveal. Preserve the security relation that the relevant subsequent
   admission group closes before prior plaintext disclosure. Different valid
   signer subsets and local arrival orders must yield the same semantic result.
   Merely revealing early or picking from a local plaintext cache is insufficient.
3. **Make pending work optional for block production.** Replace mandatory
   H/H+1/H+2 transaction material with explicit, versioned commitments for the
   certified transitions/material actually included. A block may contain no user
   transactions and no unfinished ETDAG work. PoSy still verifies every supplied
   transition, state root, parent, signature and quorum normally. A new-profile
   empty block is not a fabricated old-profile empty-cut certificate.
4. **Durable bounded eligibility and deterministic consumption.** Retain exact
   authenticated ready groups, ordered transactions and proof references. Define
   selection from common PoSy-committed eligible state with a canonical order and
   dependency-closed gas/byte prefix; local completion time cannot define the
   consensus eligible set. Persist selection/consumption with actual inclusion
   identity; retire only after durable finality and required recovery retention.
   Readiness evidence needed to prevent selecting unavailable work remains a
   design obligation, not an assumed property of an in-memory ready flag.
5. **Execute against the actual canonical parent.** Reuse state-independent
   verification and ordering; recheck nonce, balance, authorization and stateful
   conditions at inclusion. Commit deterministic receipts/failure effects.
   Never reuse a cached speculative success or silently reorder conflicting
   transactions to fit a new parent. A finalized consumption identity prevents
   replay/double effects even after restart or reorg of an unfinalized candidate.
6. **Reserve resources before acceptance/decoding.** Aggregate pending, ready,
   recovery and installed-owner reservations; enforce existing workload bounds
   and safe backpressure before durable acknowledgement. Acknowledged work must
   not be discarded to free space. Define authenticated retirement/cancellation
   and key-epoch behavior, including bounded history; no implicit expiry merely
   because several blocks passed. Full pools may reject new admission safely.

### Exact compatibility and authorization boundary

The proposal changes outer request signing domains, envelope/AAD and derived
key/share context bindings, ordering/reveal identity, proposal protected-material
commitments/validation, journal ownership/consumption schema, and governed
profile/Genesis activation. These are protocol changes, not an adjustable timer.
All affected hashes/signatures must be consistently versioned in wallet, node,
proof verification and recovery. Exact canonical schemas/bytes and transition
rules must be specified and reviewed before they are treated as stable formats.
The existing inner transaction format need not acquire a target field solely
for this change. Any new user-signed validity limit requires its own explicit
semantics; existing identity-authorization expiry is not silently removed.

Old-profile signatures/ciphertexts retain old semantics and cannot be converted
by editing heights. No in-place reinterpretation of durable old records, fallback
to cleartext, production migration, identity regeneration or quorum reduction is
proposed. A fresh isolated chain can select the new profile explicitly after
authorization; production state and historical failed evidence remain intact.

The operator has established the asynchronous architectural requirement. Their
audit directive separately says: **“Report the findings and any proposed
protocol-level change requiring authorization before implementing it.”** The
concrete scope above therefore requires approval before changing these signed
rules. Approval to implement this profile would not authorize production
deployment, signing with operator keys, or changing production Genesis/state.

### Follow-up boundary check: moving prepared batches is insufficient

The compatibility review found two additional enforcing layers, beyond the
admission deadline. They support the versioned correction rather than a local
timer or ready-queue patch:

- `crates/synergy-etdag/src/execution/deterministic_batch.rs:32`
  (`PreparedProtectedBatch::validate`) requires the original context/target,
  reveal target, committed parent height+1, exact ordered IDs and matching
  transaction authorizations. Its immutable order-position hash also includes
  the original context and target (`prepare_deterministic_batch`, line158).
- `bin/synergy-node/src/services/execution.rs:1250`
  (`protected_parent_ready`) requires the reveal VC to equal the locally
  accepted parent VC and that parent's height+1 to equal the batch target.
  A valid older reveal proof cannot simply accompany later block execution.

`crates/synergy-etdag/src/execution/proposal_material.rs:9` separately fixes
material version2 and requires all three nonzero roots; its commitment domain
is `SYNERGY_POSY_PROTECTED_MATERIAL_V2`. Replacing future material with an empty
list is therefore a new authenticated proposal format, not a compatible missing
field. The exact format must distinguish no ETDAG transition from a certified
empty ordering group.

The correction must separate three identities explicitly:

| Identity | Immutable meaning | Validation at later inclusion |
|---|---|---|
| Wallet request/envelope | What the wallet actually authorized, including network/profile, replay and encryption context. | Verify original bytes and scope; no height edits or signature reuse under a new domain. |
| Ordered/revealed processing group | Exact member set, order, authenticated closure and original PoSy reveal anchor. | Verify original evidence and its permitted canonical ancestry; do not substitute the current parent for the reveal anchor or accept an unrelated fork. |
| Execution candidate | Actual inclusion height, canonical execution parent, selected prefix, receipts and resulting state root. | Validate against the actual parent and commit through the existing PoSy rules. This identity cannot be precomputed as a final state transition while the parent is changing. |

Two semantics remain to be specified inside the proposed profile before code
is considered implementation-ready: (1) authenticated publication of completed
group eligibility into common PoSy state, with deterministic consumption and no
dependency on an unfinished group; (2) key/identity validity and replay reservation
across the longer lifecycle. Current admission verifies identity authority at
the *target's* governed consensus timestamp (`services/etdag.rs:1474` and
`services/protected_admission.rs:48`). Removing the target must not accidentally
disable expiry/revocation checks or give different validators different validity
times. These are required contract definitions, not a request to optimize queues
or add another consensus certificate/round.

In particular, readiness is neither a local boolean nor a requirement to wait for
every older unfinished group. A later proposal's eligible set must be verifiable
from its canonical input and bounded authenticated evidence. Missing local cache
data may require retrieval, but cannot redefine that set. Any proposal mechanism
that permits a proposer to skip already-mandatory eligible work, or that requires
all pending groups to finish before an empty block, fails this correction.

## 5. Focused validation before release

These are direct consequences of the requested correction and existing safety,
resource and release contracts, not an expanded unrelated qualification matrix.

| Boundary | Required observation |
|---|---|
| Asynchronous conformance | Deliberately hold genuine encrypted processing across multiple normal heights; block/QC/three-QC finality continues with valid empty blocks, then the unchanged authorized request becomes eligible and is included exactly once later. |
| Deterministic availability/order | Validators with different message arrival and local ready-cache contents validate the same committed eligible set, dependency closure, capacity prefix and block effects. Incomplete/unavailable proof cannot become eligibility. |
| Confidentiality/replay | Premature/wrong-group reveal rejected; required admission closure precedes disclosure; wrong profile/root/epoch and duplicate/cross-group replay rejected before mutation. |
| Parent correctness | Change balances/nonces after preparation; inclusion rechecks actual parent and yields matching roots and deterministic receipts without duplicated effects. |
| Crash/restart | Interrupt pending admission, group assignment, readiness, selection, execution and finalization boundaries; recover without loss, duplicate inclusion, orphan reservations or self-blocked retry. |
| Bounded operation | Full pending/ready/recovering capacities backpressure before acknowledgement; aggregate rollback and retirement remain bounded. Apply existing actual-host memory/I/O/journal criteria to the final changed runtime. |
| End-to-end contract | Qualify the explicitly approved new-profile admission semantics and separately the existing 30-second transaction-finality contract. No resource-test timeout extension constitutes a timing pass. |

## 6. Accepted evidence, blockers and canary impact

Existing evidence is retained at its actual scope. V43's 80 affected-library
tests, strict Clippy and focused repairs are useful regression evidence; the
interrupted full node suite is not a pass. The instrumented diagnostic's four
timing tests do not qualify transaction correctness or asynchronous conformance.
The unchanged 10,000-seed abstract model remains reusable only for modeled
behavior, not new native protocol semantics or cryptography.

V42 independently FAILED. Its 140 actual-host component passes and Val2/3/5
31-transfer/restart runs, with their passing plateau comparisons, remain genuine
historical scoped evidence. Metadata observation timeouts rejected journal
qualification; Val4/6 mixed runs were incomplete after fixture port collisions.
Zero OOM counters do not establish sustained bounded operation. Neither these
records nor a new protocol proposal closes the v43 memory/OOM gate.

| Classification | Remaining issue | Smallest next action |
|---|---|---|
| BLOCKER | Implemented height-bound lifecycle conflicts with operator requirement. | Approve the versioned correction scope; specify exact group/reveal/selection/recovery contracts, implement the affected seams and run focused conformance/security regressions. No further old-profile timing campaign. |
| BLOCKER | Final integrated resource/OOM and coherent journal retirement are unqualified. | Retain existing thresholds and failed records; fix observation method prospectively, then qualify changed boundaries of the frozen final candidate on all five hosts. Avoid campaigning on intermediate protocol bytes. |
| BLOCKER | New-profile admission and separate 30-second finality contract unqualified. | Prove repeatable genuine encrypted admission and finality with native provenance under the approved profile; preserve all old-profile failures as failures. |
| BLOCKER | No reviewed/signed final release or designated distributed canary qualification. | Freeze exact source, binaries and configuration, then follow guarded isolated deployment and authenticated matching finality/root/wallet/restart checks. Obtain required deployment/signing authorization. |
| BLOCKER before baseline | Recorder/resource integration lacks the complete requested baseline output. | Preserve raw timestamps and external CPU/RSS/disk/network samples; report submitted/admitted/finalized TPS, p50/p95/p99 latency, rejections and backlog/drain on unchanged qualified bytes. |
| POST-BASELINE | Throughput tuning, extra caches, queue redesign and further I/O optimization. | Use initial raw measurements to justify any change; do not optimize before the baseline. |
| POST-SOAK | Broader roles, arbitrary-World claims, multisig expansion, additional contracts and larger unrelated historical experiment matrices. | Defer unless a reproduced defect affects the declared supported workload's safety or stability. |

After the correction and established resource/admission/release gates pass:
deploy the designated isolated distributed canary, verify matching finalized
block IDs/state roots/finality evidence and real wallet effects, record initial
TPS, complete genuine encrypted ETDAG qualification and begin the frozen-candidate
24-hour soak. Preserve its exact start time and raw monitoring. No TPS baseline,
distributed canary deployment or soak has begun. The full observation period
must finish before any soak-success claim.
