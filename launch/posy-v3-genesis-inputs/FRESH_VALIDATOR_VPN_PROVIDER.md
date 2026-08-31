# Fresh PoSy v3 Validator VPN provider

The fresh block-zero Testnet-v3 VPN is a public desired state for an external,
authenticated NetBird management plane. It is not an Innernet migration, it
does not contain a candidate bundle, and it must never carry a private tunnel
key, enrollment token, or provider credential.

The generated desired state binds the completed fresh 21-validator ceremony and
the fresh three-authority freeze. It reserves `validator-01` at `10.69.10.1`,
assigns the Genesis-active `validator-02` through `validator-06` to
`10.69.10.2` through `10.69.10.6`, and preserves the relayer assignments
`10.69.1.1` through `10.69.1.3`. The public VPN hub is `68.183.139.56:51820`.

Build public desired state and its offline proof only after using the exact
fresh ceremony and authority freeze selected for the release:

```bash
python3 scripts/generate-fresh-posy-v3-validator-vpn-provider.py build \
  --validator-inputs launch/posy-v3-genesis-inputs/authority-rotation-20260823/fresh-validator-genesis-source-inputs.json \
  --authority-freeze launch/posy-v3-genesis-inputs/authority-rotation-20260823/fresh-genesis-authority-freeze.json \
  --output-registry "$P3_RELEASE/fresh-validator-vpn-provider-plan.json" \
  --output-proof "$P3_RELEASE/fresh-validator-vpn-provider-proof.json"
```

Verify both files before making them inputs to deployment bundle generation:

```bash
python3 scripts/generate-fresh-posy-v3-validator-vpn-provider.py verify \
  --validator-inputs launch/posy-v3-genesis-inputs/authority-rotation-20260823/fresh-validator-genesis-source-inputs.json \
  --authority-freeze launch/posy-v3-genesis-inputs/authority-rotation-20260823/fresh-genesis-authority-freeze.json \
  --registry "$P3_RELEASE/fresh-validator-vpn-provider-plan.json" \
  --proof "$P3_RELEASE/fresh-validator-vpn-provider-proof.json"
```

Before a host may activate, an external provider attestation must bind the
management-plane network, desired-state SHA-256, routes, and UDP `51820`. The
NetBird management endpoint and its least-privilege reconciliation credential
remain external operational custody and are intentionally not guessed,
generated, stored, or invoked by this repository. Provider transport is never
consensus authority: new validator enrollment requires a finalized governed
membership transition, validator-registry authorization, a unique public
identity, and an explicit activation epoch or height.

The plan also contains the exact five active `synv`-to-`10.69.10.x:5622`
transport request. The external transport publisher must turn that request into
a signed snapshot using the fresh-P3 network and registry IDs, bind the final
plan SHA-256, and configure its URL and public attestation key under the two
`SYNERGY_TESTNET_V3_*TRANSPORT*` runtime variables. The runtime has no legacy
fallback: without that fresh, correctly signed snapshot it refuses production
validator-network start.
