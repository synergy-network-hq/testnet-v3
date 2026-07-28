# Genesis Hash and Network Magic Provenance Report

Date: 2026-07-26. Status: discrepancy resolved by independent recomputation.

## Values in question

| Pair | Genesis hash | Network magic | Where found |
|---|---|---|---|
| A (handover briefs) | `601263ff11354293cb91cc1e401be65c4e565e3d7b5518c999e8ae47d333b16f` | `10583b30` | Only in agent-handover text. **Not present in any file, any of the repo's 2 commits (`git log -S` over full history), or any launch/bootstrap/topology artifact.** |
| B (on-disk) | `ac5186cb4a95130d22986c73c20d0eedd73821a735d944184c94691860008407` | `845e8eca` | `genesis.testnet-v3.identity-assigned.json` (`integrity.genesis_hash`, `network_magic_bytes.value`); referenced by `launch/BLOCKER_EVIDENCE_MATRIX.md` |

## Independent recomputation (this session)

- Canonical serialization: deterministic JSON, sorted keys, no insignificant
  whitespace, over exactly the 22 sections listed in
  `canonicalization.genesis_hash_inputs` (header, network, token, accounts,
  allocations, balances, address_assignment_register, validators,
  node_identities, contract_identities, consensus, execution, crypto,
  contracts, modules, governance, security, synergy_state,
  system_reserved_addresses, vesting, custody_controls, upgrade), excluding
  `integrity.genesis_hash`, `integrity.signed_by`, `network_magic_bytes`.
- Hash algorithm: blake3-256.
- Result: **`ac5186cb…008407` — byte-exact match with the embedded value.**
- Network magic is DERIVED, not assigned:
  `first_4_bytes(blake3("synergy-network-magic-v1" || "synergy:testnet-v3" || candidate_genesis_hash))`
  → recomputed **`845e8eca`** — exact match.

Both on-disk values are therefore *derived and reproducible* from the current
canonical content, and they carry: chain ID 1266 ✓, all 36 address
assignments ✓, all 21 validator identities ✓, all 10 contract addresses ✓.
They do NOT yet include: final parameter root, deployment receipts /
post-deployment AIVM state root, or an ETDAG ingress-registry root — which is
why both remain **CANDIDATE**, exactly as labeled in the file
(`candidate_unsigned_pending_deployment_and_approval`).

## Why pair A exists

Pair A cannot be reproduced from the current canonical content and appears in
no tracked or untracked file and no commit. Conclusion: it was computed from
an earlier or different genesis revision (prior agent session, content since
superseded by the identity-assigned genesis) and survived only in summary
text. It has no standing. No file was edited to force agreement; agreement was
established by recomputation only.

## Ruling

Current candidate pair: **`ac5186cb…008407` / `845e8eca` (CANDIDATE, not
FINALIZED)**. Final values must be recomputed after binding the parameter
root, the ten deployment receipts, the post-deployment AIVM state root, and
the ETDAG ingress-registry root. Any future report quoting a hash must quote a
value reproducible by `canonicalization`-spec recomputation against the
then-current file.
