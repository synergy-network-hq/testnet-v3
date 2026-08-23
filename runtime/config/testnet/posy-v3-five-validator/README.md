# PoSy v3 five-validator configuration proposal

These files are public-only preparation templates. They do not contain
approved identities, keys, endpoints, an activation epoch, or an authorization
to deploy. Do not copy them over a live node configuration.

Before rendering five node-specific configurations, replace every `REQUIRED_`
placeholder from approved public topology and custody records, calculate the
active-set/key/weight/ring roots, and attach the finalized parameter and ETDAG
roots. The canonical initial validator IDs are `posy-validator-01` through
`posy-validator-05`; do not replace those IDs with machine names. All five
rendered nodes must match on every frozen field. Each node differs only in its
approved local validator identity and public transport binding.

The profile must remain disabled unless all checks in
`runtime/docs/runbooks/posy-v3-five-validator-preflight.md` pass and the
schema-4 manifest is finalized through governance. Private keys remain in the
existing custody system and must never be rendered into these files.

Files:

- `consensus-profile.example.toml`: one node's public consensus projection.
- `five-validator-topology.public.example.json`: five public identity/weight
  slots; no hosts or private material.
- `observability.md`: metric names and alert expectations.

The local independent-process qualification commands are distinct and both
must be retained as evidence:

```bash
runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh
runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh
```
