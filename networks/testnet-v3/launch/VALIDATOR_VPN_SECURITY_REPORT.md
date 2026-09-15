# Testnet-v3 Validator VPN Security Report

Generated: 2026-07-27T08:51:20.984575+00:00

## Key handling

- 25 X25519 keypairs generated (24 participants + coordinator) via
  `cryptography` X25519 (RFC 7748), one keypair per participant.
- Every public key was **independently re-derived** from its stored private key
  and compared; all 25 match.
- Uniqueness enforced and verified: WireGuard public keys, VPN IPs, `synv…`
  addresses — no duplicates.
- Private keys are stored **only** in each node's identity folder at
  `…/wireguard/wireguard-private.key`, mode `0600`, directory `0700`.
- Shipped `sy-vpn.conf` files contain `PrivateKey = <loaded from …>` — the
  private key is **never inlined**. The validator asserts no private key
  appears in any config or in public evidence.
- No private key appears in the public registry, checksums, or any report.

## Validation

`scripts/validate-validator-vpn.py` — **0 failures**, 6 checks skipped
(handshake and reachability require live machines).

Covered offline: population (21+3), index completeness, key uniqueness, VPN-IP
uniqueness and subnet conformance, private→public derivation, registry↔stored
key agreement, identity-folder↔manifest `synv…` agreement, full-mesh peer
completeness, self-not-a-peer, coordinator peer presence, per-peer `synv…`
binding, file permissions, private-key leakage, config syntax, activation policy
(6 active validators with routes; 15 provisioned without endpoints).

## Residual risks

1. **Plaintext credentials.** `documentation/unorganized-files/node-machine-credentials.xlsx`
   stores SSH and sudo passwords in clear text. Recommend moving to a secret
   manager and rotating before public launch. *(Not blocking VPN correctness.)*
2. **Shared public IP.** Val4 and the Archive Validator share `73.79.66.255`.
   Safe inside the VPN, but any code keying peers by `ip:port` will conflate
   them — see the peer-identity defect tracked in `CLAUDE_HANDOFF.md`.
3. **Live checks outstanding.** Handshake, reachability, and unauthorized-peer
   rejection must be run on the machines before public exposure.
4. **No partial rotation.** The full replacement set was generated atomically;
   do not deploy a subset to a live VPN.
