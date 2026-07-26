# Testnet-v3 component test results

Date: 2026-07-26

## Confirmed

- Component packaging and wiring audit: 19 of 19 component groups passed,
  including the explicit encrypted-ETDAG group. Operational readiness remains
  blocked by the active blockers in `component-parity-manifest.json`.
- Repository structure validation passed.
- AIVM and SynQ are vendored as normal repository content; no nested `.git`
  pointers remain.
- All eight genesis contracts are native `.synq` sources.
- All eight pass SynQ parsing, semantic analysis, bytecode generation, ABI
  generation, and manifest generation.
- Deterministic verification confirmed that every `.compiled.synq` artifact
  exactly matches its source.
- Every manifest is bound to chain `1266`, network `synergy-testnet-v3`, and
  `ML-DSA-65`; source, bytecode, and ABI hashes match their artifacts.
- No Solidity source or compatibility preview is included in Testnet-v3.

Focused behavior suites:

| Suite | Result |
| --- | ---: |
| Synergy Token System | 18 passed |
| Transaction execution, fee collector, burn, and SynQ/AIVM path | 12 passed |
| Native token, fee distribution, and reward lifecycle | 17 passed |
| Reward allocation, settlement, reliability, and invariants | 21 passed |
| SynQ admission and PQ envelope verification | 11 passed |
| AIVM core, deterministic state, SynQ runtime, and STS host calls | 38 passed |
| Gas and network fee model | 14 passed |
| Wallet fee reserve, SNRG/custom-token transfer, and staking | 10 passed |
| Validator lifecycle and stake gates | 26 passed |
| Reward, STS, SynQ/AIVM receipt, and burn RPCs | 8 passed |

Total focused capability tests: 175 passed.

These inherited tests are supplemented by the new general stateful SynQ and
ETDAG suites described below.

## Genesis-dependent integration status

The checked-in Testnet-v3 candidate is a complete, deterministic fresh-genesis
artifact rather than a placeholder. It is bound to chain and network ID `1266`,
Testnet-v3 metadata, PoSy `v2.2`, six active genesis validators in one cluster
with a strict quorum of five,
and 21 pre-generated control-panel validator identities that require explicit
on-chain activation. The dynamic `dynamic-v3-floor7` schedule creates the
second cluster only when validator 10 activates. All eight native SynQ contract
artifacts are bound. Its current candidate hash is
`ac5186cb4a95130d22986c73c20d0eedd73821a735d944184c94691860008407`,
with derived network magic `845e8eca`.

The repository structure and contract-binding validators pass. Runtime tests
recompute every bound candidate root, reject a mutated network magic, and load
the artifact through the canonical genesis loader. This does not promote the
artifact to final: its status remains unsigned and pending the external
contract-deployment, custody, and genesis-approval records.

The reward audit and invariant RPCs, STS payload/materialization RPCs,
SynQ/AIVM receipt and replay RPCs, and burn-ledger RPC were rerun individually:
all eight passed. A final deterministic clean-room rebuild plus the complete
broad integration suite is still required after the external approval records
are bound.

## AIVM/SynQ deployment status

The compiler now emits stateful SynQ IR v2 and the AIVM executes the serialized
general AST rather than dispatching on contract names. The engine provides
constructor execution, ABI dispatch, isolated persistent storage, mappings and
arrays, deterministic host calls, nested contract calls, events, checked
arithmetic, gas accounting, rollback, chain/network/manifest policy, restart
persistence, and replay determinism.

All eight native genesis contracts deploy and execute through that same path:

- ValidatorRegistry
- Staking
- RewardDistributor
- Governance
- Treasury
- SynergyOracle
- Identity
- Slashing

Focused current results:

| Suite | Result |
| --- | ---: |
| SynQ compiler/stateful parser/artifact tests | 6 passed |
| General AIVM core and all-contract execution/restart/replay | 42 passed |
| Root SynQ admission and artifact binding | 13 passed |
| ETDAG cryptography, certified H+3 admission, persistence, DCC/order/reveal/exact execution | 13 passed |
| Opaque ETDAG RPC ingress byte/count hard-limit and saturation rejection | 1 passed |
| Typed protected PoSy proposal/validation | 1 passed |
| Durable phase-separated signer authority and restart SafetyHalt | 4 passed |
| Conflicting verified QC SafetyHalt | 1 passed |
| Conflicting verified BOC SafetyHalt | 1 passed |
| Read-only SafetyHalt status and public exposure | 2 passed |
| Inherited production consensus-loop refusal | 1 passed |
| Typed PoSy wire, Genesis-bound ML-DSA-65 peer-key authentication and session binding, bounded fail-closed ingress worker, final-input height-one context derivation and state-root-bound coordinator construction, identity-assigned Genesis bootstrap/activation planning, canonical epoch-transition roots, verified 6-to-10 topology transition, SynQ artifact preparation, and typed finality persistence/recovery | 21 passed |
| PQC manager ML-DSA-65 keygen/sign/verify and algorithm parsing | 7 passed |
| Consensus-domain FN-DSA rejection | 1 passed |
| Candidate validator-key parsing, ML-DSA-65 algorithm, and exact public-key length validation | 4 passed |
| Canonical governed-parameter loader, SHA3-512 root, downgrade and unresolved-governance rejection | 4 passed |
| Fresh-genesis guard and legacy fork-parser ambiguity rejection | 6 passed |

The H+3 admission tests use generated keys only inside isolated unit fixtures.
Production ingress-key records remain external identity-workstream inputs. The
runtime itself contains no final-key generator: it validates exact
assigned-cluster membership, ML-KEM-1024 public-key encoding, strict 5-of-6
target-admission certification, append-only persistence, public discovery, and
later height-context compatibility.

The current PoSy implementation requires ML-DSA-65 for every Testnet-v3
validator consensus key and rejects the inherited FN-DSA algorithm before
signature release. The checked-in candidate's six active and 21 preconfigured
validator identities use that same profile. Focused checks parse every assigned
public key at the exact 1,952-byte ML-DSA-65 size and exercise sign/verify.
Cross-process signing and HSM/key-store qualification remain launch gates.

The typed runtime now carries the workbook-required 512-bit SHA3-512 parameter
root through height contexts, block headers, H+3 admission contexts, ETDAG
vertices and decrypt shares, peer hellos, and anti-divergence commit records.
The loader rejects noncanonical bytes, unknown fields, unfinalized governance,
an unresolved epoch length, weakened quorum/ETDAG values, and runtime parameter
mutation that no longer matches the loaded manifest. This is an implementation
pass only: no epoch value has been selected, and no production parameter
manifest is finalized.

The old checkpointed FN-DSA consensus-fork migration is now explicitly
historical-only. Testnet-v3 production code does not load the checked-in
default migration and rejects an explicit migration-import environment setting.
This confirms the fresh-genesis boundary; it does not replace the remaining
typed cross-process consensus coordinator.

The runtime now also reads the identity-assigned Genesis candidate directly,
checks every one of the eight committed native SynQ source, bytecode, ABI, and
manifest hashes, and admits the artifacts through AIVM validation. This is a
strict pre-deployment check: it leaves the deployed-contract map empty and
refuses to present its preparation root as a finalized Genesis state. The
remaining AIVM launch dependency is deterministic binding of the final
external public genesis inputs and deployment receipts into the canonical
genesis package, not missing general execution capability.

## Remaining binding work

Fee collector, validator reward pool, DAO treasury, treasury recovery, burn
sink, and the six active validator bindings are already resolved from the
Testnet-v3 candidate genesis at runtime; production has no fallback to the
inherited wallet constants. All 21 pre-generated validator identities remain
in the candidate as control-panel configuration records, with activation kept
explicitly on-chain. An activation-plan check now proves that the four next
pending records activate validator 10 and deterministically create the second
cluster. The typed coordinator separately verifies a current-validator
ML-DSA-65 transition quorum, preserves the immutable preconfigured identities,
persists the transition after its finalized block, and installs that derived
topology. This is exercised in-process only. Final launch approval, SynQ
deployment receipts, the live typed coordinator lifecycle and authenticated
P2P binding, and the remaining security/performance evidence still need to be
completed before any node is started.
