# Testnet-v3 Cryptographic Identity Profile

Date: 2026-07-26. Status: profile determination with evidence; one documented
specification conflict; one externally-owned missing key class.

## Authoritative determination

The operative Testnet-v3 validator consensus-signature profile is **ML-DSA-65**
(FIPS 204, exact 1,952-byte public keys), used exclusively and
domain-separated (`SNRG_CONS`).

Evidence, in precedence order:

1. Security Specification v7 (current, `protocol_docs/Synergy_Network_Security_Specification_v7.docx`):
   "PoSy consensus signing uses ML-DSA-65 exclusively"; it further mandates
   documenting that "PoSy validator consensus uses ML-DSA-65 … per FIPS 204".
2. Runtime enforcement (`runtime/src/consensus/validator_keys.rs`): consensus
   key algorithm must be ML-DSA-65; public key must be exactly 1,952 bytes;
   Aegis self-test requires ML-DSA-65; FN-DSA is rejected for the consensus
   domain. Negative tests present in the same file.
3. Canonical genesis: `crypto.key_types.validator = ML-DSA-65`; all 21
   preconfigured validator `consensus_key_type` fields are ML-DSA-65 and all 21
   consensus public keys decode to exactly 1,952 bytes (verified,
   `launch/identity-validation-results.json`).
4. Launch controls: `posy_mldsa65_consensus_policy_implemented: true`;
   POSY-CRYPTO-01 evidence row.

### Documented conflict (not silently resolved)

The PoSy v2.x specification body (§7, §12, §15, §19.2) and the PoSy Parameter
Control Workbook v2.2 (`CRYPTO-001`, `QC-013`, `QC-022`) state **ML-DSA-87**
for ordinary consensus. The workbook itself lists CRYPTO-001 under
"Unresolved Decisions" ("Confirm exact deployment value"), and its
"Known Divergences" row D-13 predates the ML-DSA-65 remediation (it complains
about FN-DSA). Security Specification v7 is the later, remediation-level
document and states ML-DSA-65 exclusively.

Resolution recorded here: **ML-DSA-65 governs Testnet-v3**. Required follow-up
(externally owned, document-custodian): amend PoSy spec §19.2 and workbook
CRYPTO-001/QC-013/QC-022 to ML-DSA-65 for Testnet-v3, or explicitly ratify
ML-DSA-87 — which would require approved regeneration of all 21 validator
consensus identities and is NOT authorized by any current record. No identity
material was relabeled or regenerated under this determination.

## Key-type register

| Role | Algorithm | Public-key bytes | Encoding | Domain / use | Genesis field | Runtime loader/verifier | Cross-use prohibition |
|---|---|---|---|---|---|---|---|
| Validator consensus authorization (proposals, VALIDATE, FINALITY, TIMEOUT, VC/QC/TC, batch certificates, typed P2P validator handshake) | ML-DSA-65 | 1,952 | base64 | `SNRG_CONS` domain | `validators[].consensus_public_key`, `consensus_key_type` | `consensus/validator_keys.rs`, `crypto/aegis_pqvm.rs`, typed coordinator handshake | FN-DSA, ML-DSA-87, Ed25519 rejected for consensus; exact-length check |
| Validator account key | ML-DSA-87 | 2,592 | base64 | account/reserve authority (`reserve_algorithms`) | `validators[].account_public_key`, `account_key_type` | account-key paths; not accepted by consensus loader | Must never be interpreted as ML-DSA-65/consensus; length check (2,592 ≠ 1,952) makes silent aliasing impossible |
| Transaction / governance signing | **ML-DSA-87** | 2,592 | base64 | `SNRG_TX` / `SNRG_GOV` domains | `crypto.key_types.transaction`, `.governance`; contract artifacts bind `required_signature_algorithm: ML-DSA-65` | tx verification, SynQ admission | Domain separation distinguishes from consensus use of same algorithm |
| Address identities (wallets, nodes, contracts) | FN-DSA-1024 | 1,793 | base64 | address derivation only | `crypto.key_types.address`; `node_identities[].algorithm`; `contract_identities[].algorithm` | address engine | Explicitly invalid for consensus signatures |
| Entropy contribution | ML-KEM-768 | 1,184 | base64 | validator entropy exchange (encapsulation) | `validators[].entropy_contribution_key`, `entropy_key_type: ML-KEM-768` | entropy beacon paths | Not an ingress key; wrong size for ETDAG ingress (1,184 ≠ 1,568) |
| P2P peer identity | Ed25519 | 32 | base64 (+ hex peer_id) | libp2p-style peer identity only | `validators[].node_identity_key`, `peer_id`; `node_identities[]` | P2P transport | Never validator consensus authorization; consensus handshake additionally requires the genesis ML-DSA-65 key |
| ETDAG ingress encryption | **ML-KEM-1024** | 1,568 | raw bytes in registry schema | sealed-transaction validator capsules | ingress registry root (to be bound) | `etdag.rs` `IngressKemPublicKey` → `mlkem1024::PublicKey::from_bytes`, share_index + ingress_key_id uniqueness | ML-KEM-768 entropy keys are structurally rejected (wrong length) |
| Encrypted key-bundle storage | ML-KEM-1024 hybrid + AES-256-GCM (Argon2id KDF) | n/a | base64 envelope | at-rest custody encryption of `identity.enc.json` | not a genesis binding | identity engine only | storage-only; never a network protocol key |

Rotation policy: workbook CRYPTO-012 specifies 90-day validator consensus-key
rotation; no operational rotation rule is implemented yet (pre-existing
workbook remediation REM-D-020, P1, unchanged by this document).

## ETDAG ingress-key finding (gate stays BLOCKED)

The runtime's ingress registry (`IngressKemKeyRegistry`) requires, per active
validator: an ML-KEM-1024 public key (1,568 bytes), a non-zero `share_index`,
and a unique `ingress_key_id`, with a computed registry root. **No ML-KEM-1024
ingress public-key records exist anywhere in `testnet-v3-identity-files/`, the
public registry, or the genesis.** The existing ML-KEM-768 keys are
entropy-contribution keys — a different role — and are structurally unusable
as ingress keys. Existing keys were not relabeled.

Exact missing external input: per-validator ML-KEM-1024 ingress public-key
records (6 active validators for the launch snapshot; 21 for the full
preconfigured set if policy requires) with share indices and key IDs, produced
by the identity workstream's secret-owning machine, delivered as public
records for binding into `IngressKemKeyRegistry`, genesis, target-admission
context, and discovery RPC. Validation on delivery: ML-KEM-1024 parse, length
1,568, uniqueness of validator/key-ID/share-index, cluster/epoch correctness,
registry-root recomputation, and no private material.


## Amendment 2026-07-27 — transaction domain

User/account transaction and governance signing is **ML-DSA-87**, superseding the
earlier ML-DSA-65 entry (operator decision: prefer the stronger parameter set).
Consensus signing remains ML-DSA-65. Enforced in `runtime/src/transaction.rs`
and `runtime/src/wallet.rs`; ML-DSA-65 is accepted on the transaction path **only**
for a structurally-identified internal Aegis carrier envelope, which cannot be
interpreted as a user transaction. Cross-domain negative tests:
`consensus_mldsa65_key_cannot_sign_a_user_transaction`,
`fndsa_address_material_cannot_sign_a_user_transaction`,
`admission_rejects_non_mldsa87_declared_algorithms`.


## Amendment 2026-07-27 (b) — SXCP relayer attestation domain (SETTLED)

Operator ruling for the Testnet-v3 launch: SXCP relayer attestations remain
**FN-DSA-1024**. This is a *separate cryptographic domain*, not a leftover.
It is not migrated to ML-DSA-87 for this launch. This is no longer an open
launch-governance question.

Complete Testnet-v3 domain table:

| Domain | Algorithm |
|---|---|
| User / account transactions | ML-DSA-87 |
| Validator consensus | ML-DSA-65 |
| **SXCP relayer attestations** | **FN-DSA-1024** |
| P2P transport identity | Ed25519 |
| ETDAG ingress encryption | ML-KEM-1024 |
| Address derivation | SHA3-256 over FN-DSA-1024 public-key material |

Enforcement: `sxcp/mod.rs::parse_signature_algorithm` accepts FN-DSA labels only
and rejects everything else; `transaction.rs` rejects both FN-DSA and ML-DSA-65
for user transactions; `rpc_server.rs::normalize_signature_algorithm` rejects
FN-DSA and ML-DSA-65 with distinct, domain-naming errors.
