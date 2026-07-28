# Identity Private↔Public Correspondence Ceremony

Purpose: prove every custody-held private credential corresponds to the public
identity committed in the canonical Testnet-v3 genesis, without exposing any
private material. Tool: `scripts/run-identity-correspondence-ceremony.py`
(ceremony version `tnv3-correspondence-1`; fixture-tested 2026-07-26).

## Procedure

1. `python3 scripts/run-identity-correspondence-ceremony.py prepare`
   — generates `launch/ceremony/challenges.json`: one unique challenge per
   required identity/key-role, binding chain ID 1266, network
   `synergy-testnet-v3`, the genesis hash, identity role, public key,
   timestamp, a 256-bit nonce, and the ceremony version. Public data only.
2. Transfer `challenges.json` to the secret-owning custody machine (offline
   transfer supported).
3. The custody holder signs each challenge's canonical JSON payload locally
   (e.g. with the aegis-pqvm CLI after decrypting the relevant
   `identity.enc.json` bundle in place). Passphrases and private keys never
   leave that machine; nothing secret is written into the response file.
4. Return `responses.json`:
   `{"responses": [{"identity_id","key_role","signature_b64"}, ...]}`
5. `python3 scripts/run-identity-correspondence-ceremony.py verify --responses responses.json`
   — verifies every signature against the genesis-committed public key via a
   pluggable verifier (default: aegis-pqvm CLI; supports ML-DSA-65, ML-DSA-87,
   FN-DSA-1024, Ed25519), and writes
   `launch/identity-correspondence-results.json` recording only public key,
   challenge, signature, result, and an evidence hash per identity.

## Current coverage (16 challenges)

Six active validators × (ML-DSA-65 consensus key + Ed25519 node identity),
fee collector SYS-01, treasury recovery SYS-02, slashing settlement SYS-03,
and deployer/admin authority DAO-A01. ETDAG ingress keys will be added when
the ML-KEM-1024 ingress records exist (see
`launch/CRYPTOGRAPHIC_IDENTITY_PROFILE.md`).

## Status

- Tooling: ready; fixture-test PASS (deterministic canonicalization,
  sign/verify roundtrip).
- Operator step: **BLOCKED** — requires the custody passphrases on the
  secret-owning machine. This is the only remaining input for this gate; it is
  externally owned, and startup remains fail-closed until
  `identity-correspondence-results.json` shows all-PASS.
