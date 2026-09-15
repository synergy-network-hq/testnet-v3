# Synergy Testnet-v3 identity custody

This directory contains the public identity registry and the canonical encrypted
custody bundles used to prepare the independent PoSy Testnet-v3 Genesis.

## Canonical network identity

- Chain ID: `1266`
- Network ID: `testnet`
- Release ID: `testnet-v3`
- Protocol version: `posy/3.0`
- Token: `SNRG`

No prior-chain identity, state, snapshot, or Genesis data is authoritative for
this launch.

## Validator identities

The canonical validator IDs are exactly `validator-01` through `validator-21`.
All 21 identities and their Genesis stake allocations are prepared before
launch. The initial active validator set is `validator-02` through
`validator-06`. `validator-01` and `validator-07` through `validator-21` remain
inactive until admitted by a governed validator-set transition.

Encrypted bundles are custody material and are not committed. Public records may
be committed only after they have been regenerated from the fresh bundles and
validated against the canonical roster.

Never place decrypted keys, passphrases, passwords, environment files, live chain
state, or machine credentials in this repository.
