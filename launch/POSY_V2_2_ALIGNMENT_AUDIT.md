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

| Requirement | Current evidence | Status | Required closure |
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
| Canonical parameter manifest | `runtime/src/consensus_parameters.rs` implements one deny-unknown-fields canonical JSON schema, exact-byte loader, and SHA3-512 parameter root. The 512-bit root is bound into typed consensus/ETDAG objects, and mutation without a newly bound manifest fails closed. Four focused tests pass. The epoch value is intentionally unresolved, no governance approval ID exists, the production manifest is therefore absent, and competing legacy constants/configs remain. | BLOCKED | Approve every governed value including epoch length, emit the exact canonical production manifest, make operational startup load only that file, remove competing constants, and bind its root into genesis. |
| Fresh Testnet-v3 genesis boundary | The historical checkpointed FN-DSA fork-migration default is now ignored by Testnet-v3 production code. Any explicit `SYNERGY_CONSENSUS_FORK_MIGRATION_FILE` import is rejected, and ambiguous ML-DSA labels are rejected by the retired parser rather than treated as FN-DSA. | PASS | Keep the retired migration path excluded from the typed coordinator and generated launch bundle. |
| Protocol and schema version | Genesis templates declare `schema_version: v1`; PoSy requires the v2 signer-safety schema and explicit critical feature bits. | BLOCKED | Define and enforce protocol/schema v2 plus critical feature bits at genesis. |
| Epoch length | Runtime hard-codes 1000 blocks. The workbook marks this nonconforming and proposes 3600 slots for an approximately two-hour epoch at the 2-second target, while preserving the decision as governed. | BLOCKED | Finalize the Testnet-v3 value in the parameter manifest, then remove competing constants and templates. |
| Healthy finality | The 2-second target appears in some configs, but no 10,000-finalized-block production-cryptography soak evidence exists for P95 <= 2.5 seconds and P99 <= 3.0 seconds. | BLOCKED | Run the release binary on minimum node hardware and retain raw monotonic traces and telemetry. |
| Immutable H+3 target-admission context and ingress-key discovery | `TargetAdmissionContext` freezes every admission-relevant validator/key/weight/cluster/parameter/crypto root without requiring or inventing the target height's future prior-QC reference. A strict dual-quorum `TargetAdmissionCertificate`, exact assigned-cluster ML-KEM registry validation, append-only restart-safe package store, and public `synergy_getEtdagAdmissionPackage` discovery method are implemented. The later height context must match every overlapping root. | PASS | Focused tests prove H+3 linkage, a changed weight root, incomplete/malformed key registry, 4-of-6 certificate, store conflict, restart, and corruption behavior. Final public records and signed packages must still be supplied and installed by the external identity/operational workstreams. |
| Wallet-local encrypted transaction | `runtime/src/etdag.rs` implements AES-256-GCM full-payload sealing, ML-KEM-1024 validator capsules, Shamir sharing, outer authorization, deterministic envelope commitments, and certified target-admission package discovery. The network RPC accepts only sealed envelopes. The Wallet application and STS wallet path are not yet integrated with that discovery and sealer. | BLOCKED | Use the certified package and native sealer in every Wallet platform before any network call. |
| Content-blind ordering | The ETDAG path derives a DCC-anchored order seed and canonical topological order that excludes fees, proposer identity, and arrival order; fee/proposer/arrival invariance tests pass. The legacy plaintext `DagMempool` remains only in disabled inherited code and local test tooling. | BLOCKED | Exercise ETDAG ordering through the full typed node network and prove no production selection path can reactivate plaintext ordering. |
| VAC/DCC/BVC/BOC/BTC state machines | Canonical phase domains, strict dual-quorum certificates, DCC causal-union reconstruction, BVC/BOC/BTC wrappers, height-scoped batch finality, and persistent vote slots are implemented in `runtime/src/etdag.rs`. The full distributed service coordinator is not yet wired into the operational node loop. | BLOCKED | Wire the state machines to P2P workers, add withholding/equivocation/partition tests, and prove cross-process recovery. |
| Threshold reveal | ML-KEM share capsules, governed Shamir thresholds, `RevealGate`, durable `DecryptReleaseSlot`, signed public shares, authenticated ciphertext reconstruction, and exact public plaintext equality are implemented and tested. Public propagation/resource isolation and whole-node anti-sweeper qualification remain. | BLOCKED | Implement the public reveal service, h+1 close/h+2 open coordinator, resource bounds, and distributed adversarial tests. |
| Plaintext rejection | Public RPC rejects all legacy plaintext send/simulation/pending-content paths with `ERR_PLAINTEXT_USER_TX_DISABLED`; CLI live submit paths fail closed and `synergy-node tx submit-etdag` accepts only a sealed envelope. The external Wallet still contains legacy submission methods. | BLOCKED | Convert all Wallet/service/extension/mobile/web/desktop paths and prove no network-facing plaintext path remains. |
| Exact protected execution | Typed consensus now proposes and validates header version 2 only from a verified DCC causal union, deterministic BOC, authenticated public reveal, locally derived Execution Manifest, receipt root, and state root. Insertion/substitution/reordering/manifest-root attacks fail. The inherited engine is disabled, leaving validator startup fail-closed until the typed coordinator is wired. | BLOCKED | Wire the operational proposer/validator coordinator and add full-network replay/state-sync tests. |

The H+3 target-admission `PASS` is backed by
`runtime/src/etdag.rs` SHA-256
`337c1fcd7c54ef5e173a84de6146b5e4577d8c7fff404902eaa8e9b334169416`
and `runtime/src/rpc/rpc_server.rs` SHA-256
`13ca9b3cc991553fa3e052a750b778b6fe9e4f46ee49280eb8ee976ac2da766d`.
These are implementation snapshots, not final release hashes.

## Current implementation evidence

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

These are focused implementation results, not full launch qualification. The
typed operational runtime coordinator, production target-package issuance and propagation,
final external ingress-key records, Wallet sealing, Security v7, full-suite
regression, deterministic genesis, reproducible release, chaos/performance
profiles, and 10,000-block soak are still mandatory blockers.

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
