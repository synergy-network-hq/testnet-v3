# Testnet-v3 Security v7 alignment audit

Audit date: 2026-07-25

Launch decision: **NOT READY**

Authoritative source:
`/Volumes/xcode/Synergy-Network-Projects/protocol_docs/Synergy_Network_Security_Specification_v7.docx`

Source SHA-256:
`8f3e478f7d686c5f6517c5dd4fb344024a659a5f808e8b8d69e839cf4caf520e`

The source is present and identified. This file records only controls for which
the current Testnet-v3 worktree has been inspected or for which Security v7
defines an explicit hard stop. It does not treat document discovery, successful
compilation, or an isolated unit test as full security qualification.

The external identity workstream owns identity and key generation. This audit
does not generate, replace, or modify validator, node, wallet, consensus,
ingress, or fee-collector identities.

## Release-blocking control status

| ID | Security v7 requirement | Status | Current evidence | Closure required |
| --- | --- | --- | --- | --- |
| SEC-V7-SOURCE-01 | Authoritative Security v7 source identified and hash-pinned | PASS | The v7.0 DOCX is present at the path and SHA-256 above | Re-pin the source hash in the final release manifest |
| SEC-V7-TRACE-01 | Every defense maps to enforcement class, component, verification, residual risk, and owner | BLOCKED | This initial audit and the P0/P1 blocker matrix establish the schema for launch-critical controls, but all 32 attack categories are not yet mapped | Complete the category-by-category traceability matrix; missing fields block release under TEST SUITE TAX-3 |
| SEC-V7-TIME-01 | Consensus security uses finalized height/epoch; monotonic timers; authenticated production time | BLOCKED | Typed PoSy and ETDAG safety objects use height/epoch, but a repository-wide timestamp-only schema audit and NTS production-participation gate have not passed | Run TIME-A through TIME-D; reject production validator duty without authenticated time |
| SEC-V7-DAG-G1 | Canonical parameter freeze | BLOCKED | A canonical deny-unknown-fields loader, exact-byte enforcement, SHA3-512 root, typed-object binding, and mutation rejection are implemented and pass four focused tests. The epoch length and production governance approval remain unresolved, and competing constants still exist | Finalize governance decisions, emit and genesis-bind the exact manifest, make it the sole operational source, and remove competing constants |
| SEC-V7-DAG-G2 | Final object formats, signature domains, and deterministic cut vectors | PASS | Typed PoSy VC/QC/TC and ETDAG VAC/DCC/BVC/BOC/BTC objects use phase-separated canonical transcripts; focused negative vectors pass | Parent distributed and cross-client qualification remains blocked |
| SEC-V7-CRYPTO-01 | Validator consensus signatures use the approved post-quantum profile with no algorithm downgrade | PASS | Consensus signing and verification domains require ML-DSA-65; validator-set imports require canonical algorithm labeling and the exact 1,952-byte public-key encoding; inherited FN-DSA keys are rejected before signature release | Validate the external genesis consensus-key records and complete HSM, cross-process, and side-channel qualification |
| SEC-V7-DAG-G3 | Authenticated P2P transport, queue budgets, and message-family rate limits | BLOCKED | No production-equivalent resource-isolation or authenticated distributed ETDAG result exists | Implement bounded lanes and run flood/starvation tests before load qualification |
| SEC-V7-DAG-G4 | Every validator recomputes DAG roots before QC voting | PASS | Typed protected proposal validation reconstructs the causal cut, ordering, reveal, execution manifest, receipts, and state root; mutation tests reject mismatches | Prove the same path in the sole operational cross-process coordinator |
| SEC-V7-DAG-G5 | Recovery, archive, evidence retention, and prune gates | BLOCKED | Durable ETDAG safety slots and admission-package store pass restart/corruption tests, but archive acknowledgement, forensic export, and prune-gate qualification are incomplete | Run Security v7 suites 18A, 18B, 18D, 18E, and recovery lineage tests |
| SEC-V7-DAG-G6 | RPC exposure profiles externally audited | BLOCKED | Public plaintext and pre-reveal content methods fail closed; certified admission packages and SafetyHalt status are safe read-only methods; no complete external enumeration scan exists | Enumerate every public profile endpoint and run Security v7 suites 16F, 18C, and 30F |
| SEC-V7-S1 | AIVM/SynQ architecture and canonical semantics freeze | BLOCKED | General stateful SynQ IR/AIVM execution exists, but no reviewed semantics-freeze approval is recorded | Produce and approve the normative execution/host/state semantics |
| SEC-V7-S2 | Compiler/proof TCB, independent checker, vacuity analysis, reproducible releases | BLOCKED | Compiler and focused parser/artifact tests pass; independent parser/checker, vacuity analysis, and reproducible toolchain release evidence are absent | Execute Security v7 suite 28A through 28E |
| SEC-V7-S3 | Canonical artifact admission and cryptographic binding | PASS | Chain/network/algorithm/profile/manifest/source/bytecode/ABI binding is enforced; malformed and substituted artifacts are rejected by focused tests | Add differential verifier and fuzz corpora before release |
| SEC-V7-S4 | AIVM production hardening and admin/debug isolation | BLOCKED | Deterministic host capabilities and public RPC exposure policy exist, but OS isolation, production debug refusal, memory bounds, and full host-sandbox tests have not passed | Execute Security v7 suite 30A through 30F |
| SEC-V7-S5 | Cross-platform determinism, metering, serial semantics, and crash consistency | BLOCKED | General execution restart/replay and atomic rollback tests pass locally; cross-platform parity, commit-step crash injection, worst-case metering, and concurrency serializability are absent | Execute Security v7 suite 31A through 31F |
| SEC-V7-S6 | Authority attenuation, revocation/version binding, facts, replay/nullifiers, multi-fact atomicity | BLOCKED | Some identity, capability, chain/network, and replay bindings exist, but the complete AuthorityEnvelope and verified-fact matrix is not evidenced | Execute Security v7 suite 32A through 32D |
| SEC-V7-S7 | Contract initialization, upgrades, quarantine, and scoped recovery | BLOCKED | Genesis constructors and rollback execute, but upgrade semantic diff, quarantine, corrective transition/rollback proof, and incident runbooks are incomplete | Execute Security v7 suite 32E and 32F |
| SEC-V7-S8 | Independent audit and continuous assurance | BLOCKED | No independent Security v7 audit approval, differential fuzz campaign, or resolved Critical/High record exists | Obtain independent review and close all Critical/High findings |
| SEC-V7-POSY-HALT-01 | Conflicting finality evidence stops signing and preserves evidence | PASS | Durable process-wide SafetyHalt covers conflicting verified QCs/BOCs, survives restart, blocks every typed signing phase, and exposes read-only incident status | Run distributed partition and crash-between-persist-and-broadcast qualification |
| SEC-V7-LAUNCH-01 | Full red-team, recovery, replay, performance, and deployment gates | BLOCKED | Focused implementation tests pass, but the complete Security v7 matrix, production-equivalent chaos profiles, and 10,000-block soak have not run | All mandatory rows must be PASS before validator startup |

## Immediate audit sequence

1. Freeze the canonical governed parameter manifest.
2. Wire the typed PoSy v2.2 and ETDAG implementation as the sole operational
   coordinator while retaining fail-closed startup.
3. Implement queue/resource isolation and authenticated ETDAG transport.
4. Complete the public/private/operator/audit RPC enumeration scan.
5. Run DAG withholding, equivocation, replay, pruning, recovery, and flood
   suites.
6. Run SynQ/AIVM differential, fuzz, sandbox, metering, crash-consistency,
   authority, lifecycle, and recovery suites.
7. Obtain independent audit approval and then run the production-equivalent
   performance and 10,000-block qualification.
