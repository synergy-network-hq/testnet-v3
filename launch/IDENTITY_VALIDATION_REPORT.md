# Testnet-v3 Identity, Wallet, and Contract-Address Validation Report

Date: 2026-07-26
Scope: cross-validation of the existing canonical genesis
(`genesis.testnet-v3.identity-assigned.json`, candidate hash
`ac5186cb4a95130d22986c73c20d0eedd73821a735d944184c94691860008407`) against the
public identity registry (`testnet-v3-identity-files/identity-registry.public.json`,
64 identities), per-identity public files and manifests, on-disk SynQ artifacts,
and runtime configuration. No identities, keys, addresses, or genesis records
were generated, replaced, or modified. Re-run with:
`TNV3_ROOT=$(pwd) python3 scripts/validate-identity-records.py`
(machine-readable results: `launch/identity-validation-results.json`).

Result: **54 PASS / 4 BLOCKED / 0 FAIL** at the record level, plus **1 FAIL** at
the runtime-configuration level (inherited v2 bindings, already gated).

## Validators — PASS

All 21 preconfigured validators and the 6 active-at-genesis validators verified:

- Operator address matches genesis, registry, per-identity public file, and manifest.
- Consensus public key matches the identity file; algorithm is the
  protocol-authorized ML-DSA-65 (`crypto.key_types.validator`) with exact
  1,952-byte public keys after base64 decoding.
- Account keys are ML-DSA-87 (2,592 bytes); entropy/ingress contribution keys are
  ML-KEM-768 (1,184 bytes); node identity keys are 32-byte Ed25519.
- P2P peer ID matches the assigned node identity file.
- Bonded stake matches the address-assignment register amount for each
  VNS allocation account; voting power recorded for all six active validators.
- The 6 entries in `validators` are byte-identical to their
  `preconfigured_validators` records, and the `active_at_genesis` sets agree.
- Initial cluster membership consistent: 6 active validators, 1 cluster,
  quorum threshold 5, per `consensus`.
- No duplicate validator IDs, operator addresses, consensus keys, node identity
  keys, or peer IDs.

## Network and system wallets — PASS

- All 36 `address_assignment_register` entries match the registry on address,
  role/alias, and allocation amount; all addresses are 41 characters.
- Register, `accounts`, and `balances` have matching cardinality; genesis
  balances equal register amounts; register total matches `allocation_sum_check`.
- No two roles share an address.
- Fee-collector routing → SYS-01 (`synf1pnchsrnyral0u9r65xusjrexuctfh465h06l`);
  treasury recovery → SYS-02; slashing settlement → SYS-03; canonical burn →
  all-zero sentinel. All verified against `custody_controls`.
- `sale_claim`/`team_vesting` admin authority resolves to DAO-A01.
- No Testnet-v2 reference address appears in v3 assignments (the shared all-zero
  burn sentinel is explicitly intended).
- All 34 `node_identities` match the registry and public files; FN-DSA-1024
  address keys are 1,793 bytes.

## Genesis contracts

- PASS: contract name/address mapping unique across all 10 contracts; each
  address matches `contract_identities` and the registry.
- PASS (8 artifact-bound contracts — Governance, Identity, RewardDistributor,
  Slashing, Staking, SynergyOracle, Treasury, ValidatorRegistry): recomputed
  SHA-256 of `*.compiled.synq`, `*.abi.json`, and `*.manifest.json` match the
  genesis artifact bindings; `required_chain_id` 1266 and `required_network_id`
  `synergy-testnet-v3` on every artifact.
- BLOCKED: `sale_claim` and `team_vesting` — addresses assigned and
  registry-consistent, but SynQ artifacts are not yet compiled/bound
  (`identity_assigned_pending_deployment`).
- BLOCKED: deterministic SynQ genesis deployment has not been executed, so no
  deployment receipts, verified storage roots, or post-deployment AIVM state
  root exist yet. Per the contract-address preservation rule, the deployment
  must **reproduce** the existing configured addresses; any derivation
  discrepancy stops finalization, preserves both values as evidence, and
  requires explicit approval before any address change.

## Secret hygiene and permissions

- PASS: no private-key, mnemonic, or passphrase material in the genesis, the
  public registry, or any `identity.pub.json`.
- PASS: no `identity.enc.json` is Git-tracked (ignored via
  `testnet-v3-identity-files/.gitignore`); registry public/encrypted file
  SHA-256 hashes all match on-disk files.
- PASS: tracked `.env` files (v2 reference bundles and runtime defaults)
  contain configuration only — no secret values.
- PASS: all identity files are owner-only (0600/0700).
- BLOCKED: private↔public key correspondence cannot be proven here — the 63
  encrypted bundles are ML-KEM-1024 hybrid AES-256-GCM and require the custody
  passphrases. Closure requires a signing ceremony on the secret-owning machine
  (sign a challenge with each consensus/account key; verify against the genesis
  public keys). This is a validation gate, not a creation gate.

## Runtime-configuration conformance — FAIL (pre-existing, gated)

Six files still contain 6 retired Testnet-v2 validator addresses and conflict
with the genesis assignment record (existing-record precedence: runtime config
must match genesis, never override it):

`runtime/config/node_config.toml`, `runtime/config/bootnode1.toml`,
`runtime/config/bootnode2.toml`, `runtime/config/bootnode3.toml`,
`runtime/config/network-config.toml`,
`runtime/config/consensus-fork-migration.json`.

Remediation: replace with the genesis-assigned v3 values (do not alter genesis).
Tracked by `gates.inherited_identity_bindings_removed`. Additionally,
`runtime/config/testnet/network-topology.toml` contains no validator addresses
yet and still needs population from genesis (existing checklist item).

## Launch-blocker accounting changes

Removed (basis was "identities/wallets/addresses not yet created" — records now
exist and validate): `new_validator_identities`, `new_node_identities`,
`external_identity_mldsa65_consensus_keys_validated`,
`external_identity_workstream_public_inputs_validated`,
`system_wallet_bindings_finalized` are now `true` in
`launch/launch-readiness.json`; ETDAG-KEY-BIND-01 in
`launch/BLOCKER_EVIDENCE_MATRIX.md` reworded from "records not supplied" to a
binding gate.

Remaining genuine gates (unchanged): genesis approval and signatures,
deterministic contract deployment reproducing the existing addresses (receipts,
storage roots, post-deployment AIVM state root), `sale_claim`/`team_vesting`
artifact binding, height-1 consensus context, final parameter manifest/root,
ETDAG runtime binding and activation evidence, inherited v2 binding removal,
topology finalization, release signing, bootstrap regeneration, and the
custody signing ceremony. The candidate genesis hash and network magic
(`845e8eca`) may change only if canonical genesis content legitimately changes
during final binding.
