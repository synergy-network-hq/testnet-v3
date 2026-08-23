# PoSy v3 requirements-to-code-and-test crosswalk

Status legend: Implemented means present in the current branch; prior evidence means a focused test or harness passed in an earlier branch snapshot; open means current-build, release, or activation evidence remains. No row marked implemented is by itself launch authorization.

| Requirement | Implementation / artifact | Evidence | Status |
|---|---|---|---|
| Fresh block-zero activation; reject retired-chain authority | `posy_simplified_parameters.rs`; schema-4 manifest; typed Genesis parent; atomic P3 Genesis builder | Loader requires Chain 1266, network `testnet`, `posy/3.0`, epoch 0/height 1, five-validator activation, governed ETDAG, and rejects retired P2 markers | Implemented; current build and signed candidate open |
| `PROPOSAL -> VOTE -> QC` | `BlockVote`, `SimplifiedQuorumCertificate` | Focused QC tests | Implemented/evidenced |
| Dynamic strict count quorum | `verify_strict_dual_quorum` derives the smallest `q` with `3*q > 2*n` from the frozen epoch set | 4/5 succeeds, 3/5 fails; 5/7 succeeds, 4/7 fails; five-process initial-profile cases | Implemented/evidenced |
| Strict frozen weight | checked `u128` verifier arithmetic | 4 signers with 60% weight fail | Implemented/evidenced |
| Duplicate/invalid signer exclusion | canonical participant/key checks and Aegis verifier | arrival-order and signature tests | Implemented/evidenced |
| Native ML-DSA-65 | `PoSy/Consensus/v3/*` domains in Aegis policy | real journaled proposal signature and four-signature QC | Implemented/evidenced |
| Full SHA3-512 epoch ring | `derive_epoch_leader_ring` | five input orderings produce identical ring | Implemented/evidenced |
| No health/clock/stake leader input | `SimplifiedEpochContext::authorized_proposer` | divergent process clocks/health derive identical owner | Implemented/evidenced |
| Authenticated consistent proposal delivery | bounded `ProposalEcho`/`ProposalReady` evidence before the one block vote | threshold, split-proposer, bad-signature, wrong-sender, restart-retransmit, later-delivered-value tests, and autonomous five-driver traffic | Implemented/evidenced; full socket-stack qualification open |
| Immutable proposal material and bounded sync | content-addressed `VerifiedSimplifiedProposalMaterial`, durable non-overwriting store, request-correlated `MaterialRequest`/`MaterialChunk` chain | canonical replay, idempotence/conflict, source recovery, peer/session/replay rejection, plus autonomous partition recovery | Implemented/evidenced; protected live-input qualification open |
| Fixed ten-block leases | `lease_index`, `scheduled_owner` | same owner 1000-1009; partial final lease | Implemented/evidenced |
| TC lease inheritance and view change | heterogeneous self-contained `SimplifiedTimeoutCertificate`, stable closure ID, mandatory carry/no-carry rule, durable takeover | all valid report subsets, hidden-QC intersection, mixed HQCs, first/second TC, stale replay, successor inheritance | Implemented/evidenced; formal review open |
| Lease-boundary reset | `takeover_for_height` lease match | B inherits remainder then begins own lease | Implemented/evidenced |
| No redundant certificates | v3 module defines ordinary QC and exceptional TC only | schema inspection | Implemented |
| Highest/locked QC and safe proposal | `SimplifiedSafetyState`, `validate_proposal` | lock/restart/three-chain tests | Implemented/evidenced |
| Three-certified-block commit | `try_three_chain_commit` plus mandatory `SimplifiedFinalizationSink` | autonomous five-driver run finalizes certified ancestors and persists the exact finality WAL | Implemented/evidenced for the driver/WAL; full node-database publication open |
| Replay-verified finality WAL | `DurableSimplifiedFinalitySink` with complete commitment QCs, exact three-QC witness, immutable material references, typed Genesis parent, execution snapshot publication, and verified-transition prior-tail replay | same-epoch commit/idempotence/restart, autonomous exact tree-root preservation, cross-epoch seed/parent separation, first-boundary commit, and missing-prior-material rejection | Implemented/prior evidence; current build and full node-database convergence open |
| Conflicting-QC SafetyHalt | existing durable signing authority plus v3 QC evidence | conflicting valid QCs halt irreversibly | Implemented/evidenced |
| Durable restart | rooted atomic state plus signer journal | a real ML-DSA-65 voter process preserves last-vote and signer-journal authority across restart | Implemented/evidenced |
| State-sync reconstruction | bounded request-correlated chunk staging, contiguous verified QC/TC reconstruction, material recovery, conflict/rollback guards | autonomous lagging driver requests and installs future-QC state sync, fetches missing certified material, and rejoins at height 1003 | Implemented/evidenced; real socket churn qualification open |
| Proof-aware v3-to-v3 state sync | transition-aware reconstruction, chunk staging, durable install, and restart require an independently verified durable transition proof with the exact previous-epoch three-QC tail | cross-epoch test distinguishes certified parent from finalized seed and rejects a bare bundle or substituted transition-tail claim; role runtime traverses and re-verifies adjacent durable transition proofs | Implemented/evidenced; production executed-transition authority proof open |
| Genesis and cross-epoch finality | epoch zero starts from `GenesisFinalityReference`; later P3 transitions replay prior-tail material and consume the exact receiver-owned transition | block 1 requires Genesis, blocks 2+ require QC parent; WAL commits/reopens across distinct finalized seed and certified parent; deterministic retry reuses one transaction | Implemented/prior evidence; current build and later-epoch deployment rehearsal open |
| Dynamic validator count, immutable per epoch | epoch context derives ring/quorum from its complete finalized set; initial activation manifest declares five | five- and seven-validator ring/quorum tests; 5-to-7 verified transition, frozen transport/key negatives, and dynamic role readiness | Implemented/evidenced; production transition authorization and onboarding deployment open |
| One-failure weight preflight | `validate_single_validator_failure_liveness` | one-third holder rejected | Implemented/evidenced with model weights |
| Five-OS-process autonomous-driver harness | `posy-simplified-five-driver-harness` | every child owns the production driver, timers, real ML-DSA-65, and distinct durable stores; parent is bounded authenticated routing/fault injection only | Implemented/prior evidence; current harness rerun open |
| Autonomous lag and heal without leader forcing | immutable schedule plus bounded material/state sync | parent drops authenticated frames only; lagging child autonomously requests material/state evidence and heals to height 1003 | Implemented/evidenced in driver processes; real socket partition test open |
| Two unavailable fail closed in initial epoch | strict dual-quorum verifier | a three-signature set cannot form an accepted five-validator QC or advance any worker | Implemented/evidenced |
| ETDAG/protected execution preserved | governed Genesis parameter/fee binding, protected adapter, schedule-neutral coordinator/ingress, and dynamic H+3 producer bind exact finality, public ML-KEM registry, certified input, execution, proposal material, vote, and QC without importing proposer authority | P3 startup cannot issue its permit without the governed binding; producer 5/7 dynamic quorum, registry substitution, restart, ingress routing, and adapter replay/tamper tests exist | Implemented/prior evidence; current build, signed roots, live protected execution, and registry provisioning qualification open |
| Authenticated validator role-runtime driver | Genesis activation constructs epoch zero; P3 always loads governed ETDAG and installs durable authority, schedule-neutral ingress, governed fees, and H+3 producer/egress in one owned lifecycle | P3 resolver returns a protected permit or errors; auxiliary fatal propagation and cleanup are owned by `FinalizedPosyWorker` | Implemented for initial epoch; current build and full node qualification open |
| P2P predecode and target identity binding | bounded prefix classification applies the exact simplified message-kind limit before full payload allocation; targeted replies require the current authenticated session's validator identity to match the frozen-set target | exact-kind budget, hidden-kind padding, payload-substring, partial-UTF-8, and rebound-address rejection tests | Implemented/evidenced; autonomous reconnect and network qualification open |
| Autonomous driver convergence | distinct wire family, authenticated ingress/fanout, bounded state/material sync, retries, timers, and shutdown handling | a prior snapshot reported five production-driver child-process coverage for 4/5 progress, 3/5 fail-closed, takeover, finality, partition heal, and exact restart; parent supplies transport only | Implemented/prior evidence; current rerun and full role-runtime/socket/node qualification open |
| Observability | `metrics.rs` | deterministic integer summary test | Implemented; 10,000-block evidence open |
| Fresh-chain staging/preflight | P3 runbooks, public templates, strict legacy-input rejection, and unsigned governance builders | no live action performed | Prepared/open |
| Parameter workbook/register | v3 proposal XLSX | formulas scanned; all sheets rendered | Prepared/open |
| Engineering/public explanation | whitepaper update proposals | cross-repo publication pending | Prepared/open |

## Deliberately open activation evidence

- frozen-governance V4 signature over the exact candidate and ETDAG roots;
- approved five-validator public identities, actual weights, activation record,
  and canonical roots;
- fresh P3 executed-deployment Genesis source and resulting public membership
  anchor; retired P2/P2.2 candidate state is not an input;
- later-epoch finalized-execution transition authority and onboarding rehearsal;
- autonomous proof-aware transition state-sync rehearsal across later-epoch
  validators, including disconnect, rejoin, and durable restart;
- all-five full `synergy-node` role-runtime/socket convergence, reconnect,
  backpressure, and state-sync rehearsal beyond the passing driver-process harness;
- ETDAG-derived protected execution, block application, receipt/state-root
  verification, and finalized node-database commit across five validators;
- externally provisioned production public ML-KEM registry artifacts and live
  protected H+3 input generation across all validators;
- all-five node-database convergence after finality-WAL replay, execution
  snapshot publication, process restart, disconnect, and rejoin;
- formal model review and exhaustive Byzantine/partition analysis;
- full repository test suite and signed reproducible release;
- 10,000-block latency, PQC, certificate-size, restart and failure qualification;
- ETDAG end-to-end activation evidence and all existing launch controls.
