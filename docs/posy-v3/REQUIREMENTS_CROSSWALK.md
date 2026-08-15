# PoSy v3 requirements-to-code-and-test crosswalk

Status legend: Implemented means present in the proposed, non-activated module; evidenced means a focused test/harness has passed; open means activation evidence remains.

| Requirement | Implementation / artifact | Evidence | Status |
|---|---|---|---|
| Versioned activation; preserve v2.2 root | `posy_simplified_parameters.rs`; schema-4 proposal | Loader rejects noncanonical, weakened, and unapproved activation | Implemented/evidenced |
| `PROPOSAL -> VOTE -> QC` | `BlockVote`, `SimplifiedQuorumCertificate` | Focused QC tests | Implemented/evidenced |
| Dynamic strict count quorum | `verify_strict_dual_quorum` derives the smallest `q` with `3*q > 2*n` from the frozen epoch set | 4/5 succeeds, 3/5 fails; 5/7 succeeds, 4/7 fails; five-process initial-profile cases | Implemented/evidenced |
| Strict frozen weight | checked `u128` verifier arithmetic | 4 signers with 60% weight fail | Implemented/evidenced |
| Duplicate/invalid signer exclusion | canonical participant/key checks and Aegis verifier | arrival-order and signature tests | Implemented/evidenced |
| Native ML-DSA-65 | `PoSy/Consensus/v3/*` domains in Aegis policy | real journaled proposal signature and four-signature QC | Implemented/evidenced |
| Full SHA3-512 epoch ring | `derive_epoch_leader_ring` | five input orderings produce identical ring | Implemented/evidenced |
| No health/clock/stake leader input | `SimplifiedEpochContext::authorized_proposer` | divergent process clocks/health derive identical owner | Implemented/evidenced |
| Authenticated consistent proposal delivery | bounded `ProposalEcho`/`ProposalReady` evidence before the one block vote | threshold, split-proposer, bad-signature, wrong-sender, restart-retransmit, and later-delivered-value driver tests | Implemented/evidenced in driver tests; autonomous network rehearsal open |
| Fixed ten-block leases | `lease_index`, `scheduled_owner` | same owner 1000-1009; partial final lease | Implemented/evidenced |
| TC lease inheritance and view change | heterogeneous self-contained `SimplifiedTimeoutCertificate`, stable closure ID, mandatory carry/no-carry rule, durable takeover | all valid report subsets, hidden-QC intersection, mixed HQCs, first/second TC, stale replay, successor inheritance | Implemented/evidenced; formal review open |
| Lease-boundary reset | `takeover_for_height` lease match | B inherits remainder then begins own lease | Implemented/evidenced |
| No redundant certificates | v3 module defines ordinary QC and exceptional TC only | schema inspection | Implemented |
| Highest/locked QC and safe proposal | `SimplifiedSafetyState`, `validate_proposal` | lock/restart/three-chain tests | Implemented/evidenced |
| Three-certified-block commit | `try_three_chain_commit` | state-machine harness finalizes certified ancestors across takeover and a scheduled boundary | Implemented/evidenced at consensus-state scope; execution commit open |
| Conflicting-QC SafetyHalt | existing durable signing authority plus v3 QC evidence | conflicting valid QCs halt irreversibly | Implemented/evidenced |
| Durable restart | rooted atomic state plus signer journal | a real ML-DSA-65 voter process preserves last-vote and signer-journal authority across restart | Implemented/evidenced |
| State-sync reconstruction | contiguous verified QC/TC bundle reconstruction and rollback guard | lagging worker verifies a driver-relayed peer bundle while preserving local-only vote state | Implemented/evidenced; autonomous P2P rehearsal open |
| Dynamic validator count, immutable per epoch | epoch context derives ring/quorum from its complete finalized set; initial activation manifest declares five | five- and seven-validator ring/quorum tests; epoch roots bind membership | Implemented/evidenced in primitives; future v3 epoch-transition source open |
| One-failure weight preflight | `validate_single_validator_failure_liveness` | one-third holder rejected | Implemented/evidenced with model weights |
| Five-OS-process state-machine harness | `posy-simplified-five-node-harness` | five durable workers, ephemeral real ML-DSA-65 signing, QC/TC verification, state sync, restart, and 40 repeated takeovers | Implemented/evidenced at state-machine scope |
| Driver-simulated lag and heal without leader forcing | immutable schedule plus verified state-sync bundle | parent withholds artifacts from one worker, then relays verified evidence; divergent health/clock observations never affect authority | Implemented/evidenced; transport partition test open |
| Two unavailable fail closed in initial epoch | strict dual-quorum verifier | a three-signature set cannot form an accepted five-validator QC or advance any worker | Implemented/evidenced |
| ETDAG/protected execution preserved | proposal, vote, and QC bind one nonzero protected-execution root | harness uses a synthetic deterministic root; existing v2.2 execution gates remain open | Implemented binding; end-to-end execution open |
| Autonomous validator driver and P2P convergence | `driver.rs`, activation selector, distinct wire family, authenticated ingress/fanout | the driver module exists, but role runtime deliberately fails closed instead of spawning it; the harness parent substitutes for driver/network | Open/blocking |
| Observability | `metrics.rs` | deterministic integer summary test | Implemented; 10,000-block evidence open |
| Migration/preflight | v3 runbooks and proposal templates | no live action performed | Prepared/open |
| Parameter workbook/register | v3 proposal XLSX | formulas scanned; all sheets rendered | Prepared/open |
| Engineering/public explanation | whitepaper update proposals | cross-repo publication pending | Prepared/open |

## Deliberately open activation evidence

- governance approval ID, activation epoch and activation height;
- approved five-validator public identities, actual weights, and canonical roots;
- the production finalized v3-to-v3 epoch-transition source used to onboard later validators and derive the next immutable ring;
- production role-runtime/network integration and all-five state-sync bundle rehearsal;
- autonomous proposal production, vote/TC collection, authenticated P2P fanout,
  retry/backpressure, peer disconnect/rejoin, and driver shutdown/restart;
- ETDAG-derived protected execution, block application, receipt/state-root
  verification, and finalized node-database commit across five validators;
- formal model review and exhaustive Byzantine/partition analysis;
- full repository test suite and signed reproducible release;
- 10,000-block latency, PQC, certificate-size, restart and failure qualification;
- ETDAG end-to-end activation evidence and all existing launch controls.
