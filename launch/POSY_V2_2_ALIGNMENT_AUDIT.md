# Testnet-v3 PoSy v2.2 Alignment Audit

Status: **BLOCKED — typed protocol implementation is advancing, but the operational validator engine, wallet sealing, genesis binding, security qualification, and launch gates are not complete**

Audit date: 2026-07-25

## Authoritative sources

- `protocol_docs/Proof of Synergy (PoSy) Technical Specification/00C-Consensus-Safety-Hardening-Amendment-v2.1.docx`
- `protocol_docs/Proof of Synergy (PoSy) Technical Specification/00D-Encrypted-DAG-Mempool-and-Fair-Ordering-Amendment-v2.2.docx`
- `protocol_docs/PoSy_Consensus_Parameter_Control_Workbook_v2.2.xlsx`
- Testnet-v3 runtime under `runtime/src/`
- Testnet-v3 launch configuration under `runtime/config/`

The v2.1 amendment supersedes percentage-only quorum, inclusive two-thirds
comparisons, floating-point quorum comparisons, timer-based lock deletion,
local membership repair, and local cluster reassignment. The v2.2 amendment
makes encrypted transaction ingress and certified content-blind ordering
normative for ordinary user transactions.

## Workbook gate status

The authoritative workbook is a control register, not proof of launch
readiness.

- `Dashboard!A1:N37` reports 844 controls, 136 nonconforming or unknown
  deployment settings, and 42 known divergences.
- `Remediation Summary!A1:O62` identifies 110 P0 validator-restart and ETDAG
  activation blockers.
- `Activation Checklist!A1:K53` leaves the general activation checklist Not
  Started, the v2.1 signer-safety gates Blocked, and every v2.2 ETDAG gate
  Blocked.
- `Dynamic Cluster Safety!A1:D39` requires one cluster of six validators with
  strict quorum `q=5`.
- `Encrypted DAG Mempool!A1:D48` requires strict certificate quorum `q=5`,
  decryption threshold `t_dec=2`, and atomic network-wide activation.

No workbook row has been changed to Passed by this audit.

## Identity-workstream boundary

Fresh Testnet-v3 wallet, validator, node, consensus, ingress, and fee-collector
identities are generated and recorded by a separate user-controlled workstream.
This implementation workstream does not generate, replace, or edit those
identities and does not edit `node-machine-credentials.xlsx`. It will consume
and validate only the completed public registry and genesis inputs. The
identity-assigned JSON files and `testnet-v3-identity-files/` currently present
in the worktree are therefore excluded from this audit's changes.

Testnet-v3 is a new chain from genesis. A height-scoped consensus context is a
new-chain protocol object derived at height 1 from genesis and thereafter from
the prior finalized transition; it is not a pending historical snapshot import.

## Requirement-to-runtime findings

The table in this section is the original v2.2 audit snapshot. Its statements
that validator startup lacked an operational typed coordinator are historical
and are superseded by the current role-runtime status: finalized typed v2.2 is
wired, and the Genesis-bound initial simplified-v3 driver now supports either
the deferred core-material path or a finalized-permit protected-material path.
The applied Genesis still defers ETDAG. Full-profile and launch gates stay
blocked for the protected-input producer, verified later-epoch transition
authority, and autonomous distributed qualification. The current v3 evidence
is recorded in the 2026-08-12 addendum below.

| Requirement | Evidence at original v2.2 audit snapshot | Status | Required closure at that snapshot |
| --- | --- | --- | --- |
| Unique Testnet-v3 identity | Chain ID `1266` and runtime network ID `synergy-testnet-v3` appear in current templates. | BLOCKED | Bind both values into every signed consensus object and finalized genesis roots. |
| Strict distinct-signer and voting-weight quorum | The inherited runtime used inclusive two-thirds and treated every validator's weight as `1.0`. Count quorum now computes `floor(2n/3)+1`, and QC formation/verification additionally requires integer bonded weight satisfying `3 * signed_weight > 2 * total_weight`. Tests prove 5-of-6, 4-of-5, unequal-weight fail-closed behavior, and fail-closed chaos behavior. The weights are still resolved independently from the height-scoped registry path rather than one signed consensus-context root. | BLOCKED | Bind the exact membership and bonded weights into the common height-scoped context used by proposals, votes, QCs, VCs, and TCs; replace the legacy floating-point QC compatibility field with the canonical v2 integer schema. |
| Height-scoped consensus context binding (not a chain-state snapshot) | `runtime/src/synergy_types.rs` now defines one canonical `HeightConsensusContext` and root containing the exact active set, keys, integer weights, cluster schedule/map/membership, leader schedule, 512-bit parameter root, crypto profile, and prior finalized transition. Typed proposal, vote, VC, QC, TC, state-sync, archive, recovery, and replay validation paths bind that root. Validator startup now refuses the inherited `ProofOfSynergy` engine, but the typed replacement is not yet a complete cross-process coordinator. | BLOCKED | Wire the typed path as the sole operational coordinator, derive height 1 from the final external public genesis inputs, and add cross-process transition vectors. |
| Durable signer journal | `runtime/src/consensus/signing_authority.rs` implements an atomic process-wide phase-separated signing journal with round-scoped proposal/validation/timeout authorization and height-scoped finality authorization. Typed proposal, validate, finality, and timeout signing paths use it; conflict, restart, phase-separation, and carry-forward tests pass. The inherited engine is disabled rather than allowed to bypass it. | PASS | Parent engine-convergence gate remains blocked until the typed coordinator is operational and crash-between-persist-and-broadcast vectors pass cross-process. |
| Stable CandidateID and proof-carrying view change | The typed engine separates stable CandidateID from mutable proposal-envelope round/proposer fields and implements VC-prepared exact carry-forward after TC. Focused conflict/carry-forward tests pass, and the inherited one-stage live loop is disabled. | PASS | Make the typed VC/QC/TC state machine the sole operational cross-process engine and qualify restart/state-sync behavior. |
| Durable SafetyHalt on conflicting valid QCs/BOCs | A conflicting verified QC or BOC persists both evidence roots in the process-wide signing journal before returning. The halt is irreversible through the runtime API, survives restart, is idempotent, and blocks proposal, validation, finality, timeout, ETDAG availability/vote/vertex, and decrypt-share signing. Read-only `synergy_getConsensusSafetyHalt` reports fail-closed status and incident evidence without signing material. Focused QC, BOC, all-phase, restart, RPC, and exposure tests pass. | PASS | Add distributed crash/restart/partition qualification; the parent operational engine gate remains BLOCKED. |
| Candidate validator consensus signatures | Testnet-v3 consensus domains require ML-DSA-65, matching the checked-in candidate's six active and 21 preconfigured validator identities. Typed parsing and validator-set validation enforce the exact 1,952-byte public-key size; the historical `MLDSA`-to-FN-DSA alias remains rejected. | PASS | Cross-process signing and verification with the final approved validator key stores/HSMs remain required before launch. |
| Dynamic cluster schedule | Runtime topology assigns one cluster for 1–9 validators, two for 10–20, three for 21–27, four at 28, and one additional cluster at every subsequent seven-validator boundary (`floor(N/7)` for `N >= 21`). The six-validator Testnet-v3 set therefore remains one cluster. | BLOCKED | Bind the deterministic cluster schedule, map root, member roots, counts, and weights into the common height-scoped consensus context and every signed consensus object. |
| Leader authority | Runtime code contains liveness-based leader fallback and stale-lock recovery behavior. PoSy requires one proposer per round from a frozen schedule and a valid TC before a later leader gains authority. | BLOCKED | Remove local live-set authority from consensus decisions and bind the complete schedule into the height snapshot. |
| Canonical parameter manifest | Decision `TV3-POSY-PARAMS-2026-07-28-01` finalizes the deny-unknown-fields schema-v2 canonical JSON manifest at 1,000 epoch slots, 2,000 ms block target, 1,500 ms proposal/prevote/precommit stages, and a 10,000 ms maximum round. The separately typed healthy-network targets are 450 ms proposal, 1,850 ms QC, 2,250 ms commit, 2,500 ms p95 finality, and 3,000 ms p99 finality; they are not consensus timeouts. Activation is restricted to Genesis or a declared epoch boundary. The canonical manifest SHA-256 is `5451f7084bfd97d136a1ab035d70b09ddc3262e6cc4e142b90091bac3a3ea854`; its SHA3-512 root is `2e6760bed60c8f8e44b3b693254367f0da9a8aa9efae46c517856fb78be7402cf232c064083116b805278e95a952660f7a92e16ca9cd9349aa74467d577127cd`. Genesis and the test fixture now bind the exact manifest and reject mismatches. | PARTIAL | Complete the operational typed-coordinator startup path and publish a fresh deployment-bound Genesis from new ceremony evidence. |
| Fresh Testnet-v3 genesis boundary | The historical checkpointed FN-DSA fork-migration default is now ignored by Testnet-v3 production code. Any explicit `SYNERGY_CONSENSUS_FORK_MIGRATION_FILE` import is rejected, and ambiguous ML-DSA labels are rejected by the retired parser rather than treated as FN-DSA. | PASS | Keep the retired migration path excluded from the typed coordinator and generated launch bundle. |
| Protocol and schema version | Genesis templates declare `schema_version: v1`; PoSy requires the v2 signer-safety schema and explicit critical feature bits. | BLOCKED | Define and enforce protocol/schema v2 plus critical feature bits at genesis. |
| Epoch length | Decision `TV3-POSY-PARAMS-2026-07-28-01` approves the currently exercised 1,000-slot profile. The 3,600-slot proposal is deferred pending epoch-transition and production-path soak testing; the 7,200-slot test fixture has been removed. | PASS | A different value may activate only through a new finalized manifest at Genesis or a declared epoch boundary. |
| Healthy finality | The 2-second target appears in some configs, but no 10,000-finalized-block production-cryptography soak evidence exists for P95 <= 2.5 seconds and P99 <= 3.0 seconds. | BLOCKED | Run the release binary on minimum node hardware and retain raw monotonic traces and telemetry. |
| Immutable H+3 target-admission context and ingress-key discovery | `TargetAdmissionContext` freezes every admission-relevant validator/key/weight/cluster/parameter/crypto root without requiring or inventing the target height's future prior-QC reference. A strict dual-quorum `TargetAdmissionCertificate`, exact assigned-cluster ML-KEM registry validation, append-only restart-safe package store, and public `synergy_getEtdagAdmissionPackage` discovery method are implemented. The later height context must match every overlapping root. | PASS | Focused tests prove H+3 linkage, a changed weight root, incomplete/malformed key registry, 4-of-6 certificate, store conflict, restart, and corruption behavior. Final public records and signed packages must still be supplied and installed by the external identity/operational workstreams. |
| Wallet-local encrypted transaction | `runtime/src/etdag.rs` implements AES-256-GCM full-payload sealing, ML-KEM-1024 validator capsules, Shamir sharing, outer authorization, deterministic envelope commitments, and certified target-admission package discovery. The network RPC accepts only sealed envelopes. The Wallet application and STS wallet path are not yet integrated with that discovery and sealer. | BLOCKED | Use the certified package and native sealer in every Wallet platform before any network call. |
| Content-blind ordering | The ETDAG path derives a DCC-anchored order seed and canonical topological order that excludes fees, proposer identity, and arrival order; fee/proposer/arrival invariance tests pass. The legacy plaintext `DagMempool` remains only in disabled inherited code and local test tooling. | BLOCKED | Exercise ETDAG ordering through the full typed node network and prove no production selection path can reactivate plaintext ordering. |
| VAC/DCC/BVC/BOC/BTC state machines | Canonical phase domains, strict dual-quorum certificates, DCC causal-union reconstruction, BVC/BOC/BTC wrappers, height-scoped batch finality, and persistent vote slots are implemented in `runtime/src/etdag.rs`. The full distributed service coordinator is not yet wired into the operational node loop. | BLOCKED | Wire the state machines to P2P workers, add withholding/equivocation/partition tests, and prove cross-process recovery. |
| Threshold reveal | ML-KEM share capsules, governed Shamir thresholds, `RevealGate`, durable `DecryptReleaseSlot`, signed public shares, authenticated ciphertext reconstruction, and exact public plaintext equality are implemented and tested. Public propagation/resource isolation and whole-node anti-sweeper qualification remain. | BLOCKED | Implement the public reveal service, h+1 close/h+2 open coordinator, resource bounds, and distributed adversarial tests. |
| Plaintext rejection | Public RPC rejects all legacy plaintext send/simulation/pending-content paths with `ERR_PLAINTEXT_USER_TX_DISABLED`; CLI live submit paths fail closed and `synergy-node tx submit-etdag` accepts only a sealed envelope. The external Wallet still contains legacy submission methods. | BLOCKED | Convert all Wallet/service/extension/mobile/web/desktop paths and prove no network-facing plaintext path remains. |
| Exact protected execution | Typed consensus now proposes and validates header version 2 only from a verified DCC causal union, deterministic BOC, authenticated public reveal, locally derived Execution Manifest, receipt root, and state root. Insertion/substitution/reordering/manifest-root attacks fail. The inherited engine is disabled, leaving validator startup fail-closed until the typed coordinator is wired. | BLOCKED | Wire the operational proposer/validator coordinator and add full-network replay/state-sync tests. |

The historical H+3 target-admission `PASS` was backed at the original audit
snapshot by
`runtime/src/etdag.rs` SHA-256
`337c1fcd7c54ef5e173a84de6146b5e4577d8c7fff404902eaa8e9b334169416`
and `runtime/src/rpc/rpc_server.rs` SHA-256
`13ca9b3cc991553fa3e052a750b778b6fe9e4f46ee49280eb8ee976ac2da766d`.
These hashes intentionally preserve that dated evidence snapshot; they are not
hashes of the current working tree and are not final-release hashes. A frozen
candidate release must publish a new release-manifest hash set rather than
silently rewriting this historical record.

## Historical v2.2 implementation evidence at the audit snapshot

- General stateful SynQ IR v2 and AIVM execution are implemented without
  contract-name handlers. All eight native genesis contracts deploy, execute,
  persist, restart, and replay through the general engine.
- Compiler, SynQ admission, and AIVM focused suites pass.
- ETDAG focused suite: 13 passed, 0 failed.
- Protected PoSy proposal/validation end-to-end test: 1 passed, 0 failed.
- Durable signer-authority suite: 4 passed, 0 failed.
- Conflicting verified QC SafetyHalt test: 1 passed, 0 failed.
- Conflicting verified BOC SafetyHalt test: 1 passed, 0 failed.
- Read-only SafetyHalt status and public exposure tests: 2 passed, 0 failed.
- Inherited production consensus-loop refusal test: 1 passed, 0 failed.
- RPC plaintext rejection and encrypted-client exposure tests pass.
- `cargo check --lib`, `cargo check --bin synergy-node --bin synergy-sts`, and
  `cargo fmt --all -- --check` pass.

These were focused implementation results, not full launch qualification. At
that snapshot the typed operational runtime coordinator, production
target-package issuance and propagation, final external ingress-key records,
Wallet sealing, Security v7, full-suite regression, deterministic genesis,
reproducible release, chaos/performance profiles, and 10,000-block soak were
mandatory blockers. Current engine integration and remaining blockers are
described in the v3 addendum below.

## Changes completed during this audit

The consensus count-quorum primitive and its directly affected conformance
tests were changed from inclusive two-thirds to strict greater-than-two-thirds:

- 5 of 6 validators are now required.
- 4 of 5 validators are now required.
- 5 of 7 validators are required.
- Two unavailable validators in a six-validator cluster now halt safely rather
  than lowering quorum.
- Count quorum cannot override insufficient bonded voting weight.
- QC formation and verification use overflow-checked integer strict-weight
  arithmetic; Synergy Score remains excluded from finality power.

The dynamic cluster schedule was also aligned to the workbook:

- 1–9 active validators use one cluster.
- 10–20 use two balanced clusters.
- 21–27 use three balanced clusters.
- 28–34 use four balanced clusters.
- One cluster is added at every subsequent seven-validator boundary.

The inherited timer-based vote-lock erasure path and inherited production
consensus loop were disabled:

- Signer-journal inspection APIs are now read-only above the finalized head.
- Recovery age, leader selection, diagnostics, and checkpoint forks cannot
  delete a same-height signing authorization.
- A conflicting candidate remains rejected until the required exact
  prepared-certificate view-change model is implemented and verified.
- Validator role startup fails closed instead of running the inherited
  `ProofOfSynergy`/`DualQuorumConsensus` loop.
- Proposal signatures now pass through the same durable signing authority as
  validate, finality, and timeout signatures.
- Conflicting verified QCs or BOCs durably enter an irreversible SafetyHalt
  that prevents every typed consensus and ETDAG signing phase.

Focused evidence:

- `cargo fmt -- --check` passed.
- Four quorum-threshold tests passed.
- Seven community cluster-preview tests passed.
- Twenty-six chaos-harness tests passed.
- Multi-cluster strict-quorum finalization test passed.
- Synergy Score independence test passed using five of six signers.
- Five focused cluster-boundary, balancing, assignment, and onboarding tests
  passed.
- Seven focused signer-journal preservation and conflicting-candidate rejection
  tests passed.
- The 90-test quorum-focused run passed 89 tests. Its single failure is the
  separately recorded placeholder-genesis parse error
  `missing path header.timestamp`.

This is only the count half of PoSy's strict dual-quorum rule. It does not
close the frozen-weight or immutable-snapshot requirements. The corrected
cluster count is likewise incomplete until its complete schedule and roots are
frozen in the height snapshot.

## Full-suite evidence

The first full `cargo test --lib -- --test-threads=1` run after applying the
strict count-quorum primitive reported 926 passed and 107 failed. Some failures
were expected obsolete 4-of-6 assertions and were corrected afterward. Many
others cascade from a separate launch blocker: the current placeholder genesis
cannot be loaded as canonical because required header data such as
`header.timestamp` is absent, poisoning shared test locks in later tests.

The full suite is therefore not green and is not launch evidence.

## Launch ordering decision

Do not modify or start live nodes yet. Fresh identity generation is owned by
the separate user-controlled workstream; this workstream must not alter it.
The next required implementation work is:

1. Complete the remaining PoSy v2.1 signer-safety and dynamic-topology runtime
   implementation.
2. Implement and validate the PoSy v2.2 ETDAG profile across runtime, Wallet,
   RPC, explorer, and verifier components.
3. Finalize the canonical parameter manifest and its root.
4. Complete the Security Specification v7 control audit and remediate every
   network-wide gap.
5. Only then generate fresh identities and prepare signed genesis inputs.

## 2026-08-12 proposed PoSy v3 simplified profile

This branch adds an epoch-gated `posy/3.0` proposal; it does not change the
currently finalized v2.2 parameter manifest or activate validator duties. The
proposal replaces the future healthy-path `VALIDATE -> VC -> FINALITY -> QC`
ceremony with `PROPOSAL -> VOTE -> QC`, retains strict count and frozen-weight
quorum verification, and uses a three-certified-block commit rule. Exceptional
recovery uses only a quorum-certified TC.

The proposed leader authority is one immutable, full-SHA3-512-ranked ring per
epoch with fixed ten-block leases. Sequential TCs forfeit only the remainder of
the current lease; local clocks, health observations, live-set inference,
floating-point stake priority, and fallback loops have no authority. The next
lease starts from the original frozen schedule.

Implementation evidence produced in this branch:

- The focused simplified-consensus suites exercise real ML-DSA-65 proposal and
  QC signatures, strict 4-of-5 plus strict frozen-weight quorum, lease
  inheritance, chained finality, restart, verified state-sync reconstruction,
  lock rejection, protected-execution-root binding, signer-independent
  certificate subjects, and conflicting-QC SafetyHalt. Aggregate counts are
  intentionally omitted from this moving branch audit; the PR verification
  record must retain the exact command output from the final candidate commit.
- Proposal envelopes do not authorize ECHO, READY, or VOTE without their exact
  full material. The branch now includes an immutable content-addressed material
  store, independent core/protected replay, bounded request-correlated
  `MaterialRequest`/`MaterialChunk` transfer, peer/session/replay controls, and
  durable install before reliable delivery. Component and driver tests cover
  canonical replay, restart, idempotence/conflict, missing-material request,
  unsolicited/cross-peer/replayed chunks, and exact-root correlation.
- Finalized commits can be written to an immutable fsynced WAL whose records
  contain complete QCs and the exact three-QC finality witness while referring
  to separately immutable proposal material. Startup replay pins the epoch,
  anchor, and boundary state, then re-verifies every QC and material record and
  re-executes the chain. Component tests cover idempotent restart replay and
  reject missing material and anchor substitution. The transition-aware sink
  also retains the exact previous-epoch tail inputs, commits across the distinct
  finalized-seed/certified-parent boundary, reopens the combined WAL, and
  rejects missing prior material.
- Proof-aware v3-to-v3 state sync is implemented and tested at state-machine
  scope. The verified durable transition proof carries the exact previous-epoch
  three-QC tail, distinguishes the certified parent from the finalized seed,
  and binds the transition subject plus dynamic next set. Transition-aware
  chunk staging, install, and restart succeed, while a bare bundle without that
  proof and a substituted transition-tail finality claim are rejected. The
  transition authorization is now a non-circular schema-v2 subject that omits
  the block/QC identifiers derived after execution. Role-runtime transition
  traversal and exact prior replay loading are implemented; production still
  fails closed until finalized execution supplies an inclusion/receipt proof
  for that subject.
- Simplified-consensus P2P ingress now classifies the exact message kind from a
  bounded prefix and enforces its tighter frame limit before allocating the
  full payload. Targeted responses require the current authenticated session's
  validator identity to match the frozen-set target; a socket address is not
  authority, and address rebinding to another validator is rejected. Focused
  tests cover the exact per-kind budgets and rebinding rejection, but not an
  autonomous five-node network rehearsal.
- The protected-ETDAG material adapter and schedule-neutral coordinator APIs
  are implemented and tested. They re-verify certified target admission and
  protected input without importing a proposer schedule, execute the exact
  candidate, bind its state/receipt/protected roots, independently replay
  received material, survive durable restart, reject substituted body/context/
  input/execution/finality, and wait without proposing when input is incomplete.
  Role runtime now constructs the adapter's authority from the durable
  finality WAL and bounded certified-material tail, selects it only from a
  finalized ETDAG permit, and installs authenticated schedule-neutral ingress
  transactionally with the execution snapshot and simplified-consensus ingress.
  Cleanup prevents a failed startup or worker from leaving a stale ingress.
  Protected startup now also constructs the dynamic schedule-neutral H+3
  producer, requires the exact canonical externally provisioned public ML-KEM
  registry, journals its ML-DSA vote before signing, broadcasts vote/package
  traffic only to the frozen set, and stops the auxiliary worker with the main
  consensus lifecycle. Missing/substituted registries fail closed, while a
  next-epoch target waits for verified transition authority.
- The transition-aware driver builds the first cross-epoch finalization
  transaction only from its receiver-owned verified transition. A focused
  restart test proves the first current-epoch QC finalizes the prior parent and
  that a post-commit local failure retries the same durable transaction before
  advancing consensus state; omitting the transition capability is rejected.
- The validator role runtime now constructs and spawns the authenticated
  simplified driver for the Genesis-bound initial epoch in either material
  mode. It replays the v2 boundary execution state, requires the real frozen-set
  ML-DSA signing authority, opens durable safety, material, and finality stores,
  publishes execution snapshots after verified finality, and attaches
  authenticated P2P ingress/egress. A finalized ETDAG permit selects only the
  protected adapter and schedule-neutral ingress; no permit selects only the
  core adapter. The applied Genesis currently takes the deferred core path.
  Later-epoch loading walks adjacent durable transition proofs and prior replay
  inputs, then stops at the intentionally fail-closed finalized-execution
  transition-authority verifier.
- The autonomous five-OS-process driver harness passes. Every child owns the
  production `SimplifiedPosyDriver`, real timers, an ephemeral ML-DSA-65 key,
  and distinct durable signer-journal, safety, proposal-material, and finality
  stores. The parent is only a bounded authenticated router/fault injector and
  does not create proposals, votes, QCs, TCs, or state-sync evidence. The run
  proves four-of-five progress, three-of-five fail-closed at height 1004,
  three-chain finality at 1001, real-timer takeover, proposal-material recovery,
  future-QC state-sync healing to height 1003, and exact durable restart roots.
  Ephemeral private-key files are removed at exit.
- The passing harness is still not five full `synergy-node` deployments using
  the production role-runtime and socket stack. It does not qualify live
  ETDAG/BOC/reveal execution, production identity/deployment bundles, real
  socket churn/backpressure, five node databases, Byzantine/model coverage, or
  performance/soak/release readiness.
- The schema-4 manifest proposal is canonical and deliberately refuses
  activation. Its SHA3-512 parameter root is
  `2c8be6837fa49c160887cc1fcf2b741eadd72172bdeed27c9645c08ebe88be5fb562ca82e89af7cbe821157aba6d0e20a7727f0ff9e191a14dff5744fd4de101`.
  This is the protocol's SHA3-512 `ConsensusParameterRoot`; a conventional
  SHA-512 file digest is a different value.
- A standalone v3 parameter-control workbook proposal records five-validator
  count/weight liveness and keeps the activation result `BLOCKED`. Its five
  rows are explicitly first-epoch hardware inputs; the protocol derives
  membership and quorum from every finalized epoch set and has no five-validator
  ceiling.

The specifically named `posy_v3_five_process_harness_passed` launch-readiness
gate is now `true` based on the autonomous production-driver process run. This
does not imply full qualification or activation: those gates remain `false`.
Specification approval, a finalized canonical manifest, activation
coordinates, final initial public topology and weights, five full
role-runtime/socket nodes, live protected ETDAG execution and public registry
provisioning, and the production finalized-execution transition-authority proof
needed to onboard later validators remain open. Signed release artifacts, full
regression/chaos/performance/soak qualification, and live activation also remain
false. The inherited production engine remains disabled. The implemented
Genesis-bound deferred-ETDAG path cannot create a launch path around existing
Testnet-v3 blockers.
