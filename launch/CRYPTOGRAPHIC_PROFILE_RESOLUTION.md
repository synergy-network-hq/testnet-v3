# Cryptographic Profile Resolution — Testnet-v3

Date: 2026-07-26. This resolves the ML-DSA-87 vs ML-DSA-65 consensus-profile
conflict formally. Companion register: `launch/CRYPTOGRAPHIC_IDENTITY_PROFILE.md`.

## 1. Document precedence (determined, with rationale)

1. **Security Specification v7** — most recent governing security document;
   written as a remediation/hardening layer over PoSy v2.x; contains explicit,
   repeated, unambiguous language: "PoSy consensus signing uses ML-DSA-65
   exclusively", plus an instruction to add a Quantum Consensus Safety Proof
   documenting ML-DSA-65 per FIPS 204.
2. **PoSy v2.2 specification package** — governs consensus mechanics; its
   §19.2 crypto mandate is expressed as "PoSy **v2.0** mandates ML-DSA-87",
   i.e., a version-scoped statement predating v7.
3. **Parameter workbook v2.2** — itself lists CRYPTO-001 under "Unresolved
   Decisions" ("Confirm exact deployment value"), so it did not treat
   ML-DSA-87 as settled; its D-13 divergence row targets FN-DSA (an even
   earlier state), showing the workbook predates the ML-DSA-65 remediation.
4. **Canonical genesis** and **runtime implementation** — implement ML-DSA-65
   with exact 1,952-byte enforcement, consensus-domain separation, FN-DSA
   rejection, and negative tests.

## 2. Intentional decision vs accidental divergence

Evidence of intent: (a) v7's "exclusively" phrasing and its directive to
document ML-DSA-65; (b) the runtime migrated FN-DSA → ML-DSA-65 (not to
ML-DSA-87), with a dedicated launch gate
`posy_mldsa65_consensus_policy_implemented`; (c) all 21 validator consensus
identities were generated as ML-DSA-65 by the identity workstream; (d) the
workbook explicitly left CRYPTO-001 unresolved. Conclusion: **ML-DSA-65 is an
intentional later protocol decision**, not an implementation accident.

## 3. Validity of existing identities

All 21 validator consensus identities are ML-DSA-65 with exact 1,952-byte
public keys (verified in `launch/identity-validation-results.json`). Under the
governing decision they are **valid and unchanged**. No key was relabeled or
regenerated.

## 4. Impact of the alternative

Switching to ML-DSA-87 would invalidate all 21 consensus identities, the
genesis validator/consensus-key roots, the candidate genesis hash, handshake
capability checks, and every consensus-domain test — with no current record
authorizing it. It is not adopted.

## 5. Actions taken (supersession recorded)

- PoSy spec §19 (`19-Section-19-Compatibility-and-Interoperability.docx`):
  bold supersession paragraph inserted directly after the v2.0 ML-DSA-87
  mandate, stating the Testnet-v3 ML-DSA-65 rule and citing v7.
- Parameter workbook: Deployment Settings `SET-0018`/CRYPTO-001 target value
  updated to ML-DSA-65 with supersession note; "Unresolved Decisions"
  CRYPTO-001 marked RESOLVED FOR TESTNET-V3; Change Log entry
  `CHG-TNV3-CRYPTO-001` appended (row 405).
- No genesis, runtime, or identity file was altered by this resolution.

## 6. Full profile (exact statements)

- Consensus authorization: ML-DSA-65, 1,952-byte public keys, `SNRG_CONS`
  domain, used for proposals, VALIDATE/FINALITY/TIMEOUT, VC/QC/TC, batch
  certificates, and typed validator handshake capability proof.
- Account keys: ML-DSA-87 (2,592 bytes) — account/reserve authority only.
- **Address derivation (exact)**: a Synergy address is
  `Bech32m(prefix, SHA3-256(FN-DSA-1024 public key))` — the address is a
  SHA3-256 digest of FN-DSA-1024 public-key material, Bech32m-encoded with a
  class prefix (`runtime/src/synergy-address-engine/testnet_generator.rs`,
  `derive_synergy_address`). Addresses are hashes; "FN-DSA-1024" names the
  keypair whose public key is hashed, not an address format.
- P2P identity: Ed25519 (32 bytes) — transport peer identity only; never
  consensus authorization.
- Entropy: ML-KEM-768 (1,184 bytes) — entropy-contribution encapsulation only.
- ETDAG ingress: ML-KEM-1024 (1,568 bytes) — required by
  `runtime/src/etdag.rs::IngressKemPublicKey`; records do not yet exist
  (external input; see CRYPTOGRAPHIC_IDENTITY_PROFILE.md).
- Transaction/governance signing: ML-DSA-65 under `SNRG_TX`/`SNRG_GOV`
  domains; SynQ artifacts bind `required_signature_algorithm: ML-DSA-65`.

## 7. Required negative cross-domain tests (to add with the toolchain)

Existing: consensus loader rejects non-ML-DSA-65 algorithms and wrong lengths
(`validator_keys.rs` tests); FN-DSA rejected for consensus domain. To add as
explicit cases: account-key(ML-DSA-87)→consensus rejection (length 2,592 ≠
1,952 already guarantees this; make the test explicit); consensus-key→wallet
transaction rejection (domain separation); Ed25519→consensus rejection;
ML-KEM-as-signature rejection; ML-KEM-768→ingress rejection (1,184 ≠ 1,568;
make explicit against `IngressKemPublicKey::validate`); FN-DSA-derived
address material → ML-DSA consensus rejection. Tracked in
`launch/CLAUDE_HANDOFF.md` under toolchain-dependent work.


## Superseded 2026-07-27

Section 'Transaction/governance signing: ML-DSA-65' is **superseded**: the
governing decision is now **ML-DSA-87** for user/account transactions and
governance. Consensus remains ML-DSA-65 under `SNRG_CONS`. Domain separation is
now enforced structurally rather than by convention.
