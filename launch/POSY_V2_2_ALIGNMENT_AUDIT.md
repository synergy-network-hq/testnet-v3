# Testnet-v3 PoSy v2.2 Alignment Audit

Status: **BLOCKED — not ready for identity generation, validator signing, genesis, or launch**

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

## Requirement-to-runtime findings

| Requirement | Current evidence | Status | Required closure |
| --- | --- | --- | --- |
| Unique Testnet-v3 identity | Chain ID `1264` and runtime network ID `synergy-testnet-v3` appear in current templates. | Partial | Bind both values into every signed consensus object and finalized genesis roots. |
| Strict distinct-signer and voting-weight quorum | The inherited runtime used inclusive two-thirds and treated every validator's weight as `1.0`. Count quorum now computes `floor(2n/3)+1`, and QC formation/verification additionally requires integer bonded weight satisfying `3 * signed_weight > 2 * total_weight`. Tests prove 5-of-6, 4-of-5, unequal-weight fail-closed behavior, and fail-closed chaos behavior. The weights are still resolved independently from the height-scoped registry path rather than one signed consensus-context root. | Partial | Bind the exact membership and bonded weights into the common height-scoped context used by proposals, votes, QCs, VCs, and TCs; replace the legacy floating-point QC compatibility field with the canonical v2 integer schema. |
| Height-scoped consensus context binding (not a chain-state snapshot) | Testnet-v3 starts from a clean genesis and requires no historical snapshot import. For each proposed height, however, PoSy requires every validator to use the same frozen active set, keys, bonded weights, parameters, cluster map, and leader schedule. The current proposal/vote/QC paths do not yet sign one common root proving that context. | Blocked | Derive the height-1 context directly from Testnet-v3 genesis, derive later contexts only from finalized state transitions, calculate one deterministic root, and bind it into every signed proposal, vote, VC, QC, and TC with cross-node vectors. |
| Durable signer journal | Timeout-, age-, leader-selection-, diagnostics-, and checkpoint-fork recovery paths can no longer erase a persisted same-height vote lock. Conflicting candidates remain fail-closed, and focused preservation tests pass. The runtime still uses a single `LocalVoteLock`; it does not yet implement the complete normative phase-scoped `SigningSlot`, height-scoped `FinalitySlot`, or exact prepared-certificate carry-forward model. | Partial | Implement the canonical phase and finality slot schemas, atomic write-ahead persistence, exact VC-prepared carry-forward, restart vectors, and durable SafetyHalt integration. |
| Stable CandidateID and proof-carrying view change | The complete v2 proposal/vote/certificate schema and exact VC-prepared carry-forward proof are not evidenced. | Blocked | Implement CandidateHeader/CandidateID separation, VC/QC/TC v2 schemas, exact carry-forward, and conflict vectors. |
| SafetyHalt on conflicting valid QCs | Some anti-divergence handling exists, but a complete durable SafetyHalt that stops every signing path across restart is not evidenced. | Blocked | Implement and test durable global signing halt with evidence retention. |
| Dynamic cluster schedule | Runtime topology assigns one cluster for 1–9 validators, two for 10–20, three for 21–27, four at 28, and one additional cluster at every subsequent seven-validator boundary (`floor(N/7)` for `N >= 21`). The six-validator Testnet-v3 set therefore remains one cluster. | Partial | Bind the deterministic cluster schedule, map root, member roots, counts, and weights into the common height-scoped consensus context and every signed consensus object. |
| Leader authority | Runtime code contains liveness-based leader fallback and stale-lock recovery behavior. PoSy requires one proposer per round from a frozen schedule and a valid TC before a later leader gains authority. | Blocked | Remove local live-set authority from consensus decisions and bind the complete schedule into the height snapshot. |
| Canonical parameter manifest | `runtime/config/consensus-config.toml` still contains legacy values such as block time 5 seconds, cluster size 30, epoch length 1000, and floating-point `0.67` quorum thresholds. Other node configs use different values. | Blocked | Create one machine-readable governed manifest, make its hash the `parameter_root`, and make the runtime load exactly that source. |
| Protocol and schema version | Genesis templates declare `schema_version: v1`; PoSy requires the v2 signer-safety schema and explicit critical feature bits. | Blocked | Define and enforce protocol/schema v2 plus critical feature bits at genesis. |
| Epoch length | Runtime hard-codes 1000 blocks. The workbook marks this nonconforming and proposes 3600 slots for an approximately two-hour epoch at the 2-second target, while preserving the decision as governed. | Blocked decision | Finalize the Testnet-v3 value in the parameter manifest, then remove competing constants and templates. |
| Healthy finality | The 2-second target appears in some configs, but no 10,000-finalized-block production-cryptography soak evidence exists for P95 <= 2.5 seconds and P99 <= 3.0 seconds. | Blocked | Run the release binary on minimum node hardware and retain raw monotonic traces and telemetry. |
| Wallet-local encrypted transaction | `runtime/src/dag_mempool.rs` accepts a plaintext canonical `Transaction`. | Blocked | Implement the Encrypted Transaction Envelope and wallet-side sealing of the complete signed InnerTransaction. |
| Content-blind ordering | `runtime/src/dag_mempool.rs` includes `max_fee_nwei` in its order key. PoSy v2.2 prohibits fee, tip, proposer identity, and network proximity as ordering inputs. | Blocked | Implement DCC-anchored commitment ordering using the governed order seed. |
| VAC/DCC/BVC/BOC/BTC state machines | No runtime implementation of these certificates or their durable journal slots was found. | Blocked | Implement canonical schemas, strict dual-quorum verification, persistence, restart behavior, and adversarial vectors. |
| Threshold reveal | No `RevealGate`, validator share capsule, Shamir threshold, `DecryptReleaseSlot`, or public ordered-reveal feed was found. | Blocked | Implement and independently review the complete threshold-reveal pipeline. |
| Plaintext rejection | `ERR_PLAINTEXT_USER_TX_DISABLED` is absent. | Blocked | Reject every ordinary plaintext user-send path after atomic activation, with no automatic transparent fallback. |
| Exact protected execution | Current block execution is not bound to a BOC, DCC, reveal transcript, or index-preserving Execution Manifest. | Blocked | Bind the protected batch and every required root into CandidateID and deterministic execution. |

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

The inherited timer-based vote-lock erasure path was disabled:

- Signer-journal inspection APIs are now read-only above the finalized head.
- Recovery age, leader selection, diagnostics, and checkpoint forks cannot
  delete a same-height signing authorization.
- A conflicting candidate remains rejected until the required exact
  prepared-certificate view-change model is implemented and verified.

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

Do not generate Testnet-v3 key material or modify live nodes yet. The next
required work is:

1. Complete the remaining PoSy v2.1 signer-safety and dynamic-topology runtime
   implementation.
2. Implement and validate the PoSy v2.2 ETDAG profile across runtime, Wallet,
   RPC, explorer, and verifier components.
3. Finalize the canonical parameter manifest and its root.
4. Complete the Security Specification v7 control audit and remediate every
   network-wide gap.
5. Only then generate fresh identities and prepare signed genesis inputs.
