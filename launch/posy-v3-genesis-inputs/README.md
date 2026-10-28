# Fresh PoSy v3 Genesis inputs

This directory is the public-input staging area for the separate Chain-1266
Testnet-v3 PoSy chain. Its canonical identity tuple is:

- Chain ID: `1266`
- technical network ID: `testnet`
- release ID: `testnet-v3`
- consensus protocol: `posy/3.0`
- Genesis epoch: `0`
- first consensus height: `1`

The validator identity ceremony creates 21 independent validator bundles,
numbered `validator-01` through `validator-21`. Only `validator-02` through
`validator-06` are active at Genesis. `validator-01` and `validator-07` through
`validator-21` remain funded but inactive until a finalized governed epoch transition.

`validator-roster.json` is the non-secret roster and activation policy.
`runtime/testnet-allocation-manifest.json` is the current public allocation
plan. Its non-burn addresses and allocation hash deliberately remain null until
the fresh identity and deterministic deployment ceremonies bind them.

`scripts/build-fresh-testnet-v3-validator-genesis-inputs.py` validates the
completed Address Engine ceremony, all 21 canonical public bundles, this
roster, and the allocation plan. It emits:

- `fresh-validator-genesis-source-inputs.json` — public accounts, allocation
  bindings, 21 preconfigured runtime validator records, the exact five active
  Genesis validators, and validator-registry constructor inputs;
- `fresh-validator-genesis-source-inputs.complete.json` — manifest-last
  completion evidence binding the source-input SHA-256;
- `five-validator-genesis-activation.json` — the Rust-serde-compatible
  `GenesisBoundSimplifiedActivation` for epoch 0/height 1, frozen to
  `validator-02` through `validator-06` and the finalized P3 parameter root.

The adapter is public-only and fail-closed. It hashes but never parses the
encrypted custody envelopes, refuses symlinked inputs, rederives every address
and peer ID, rejects noncanonical key profiles, and refuses to overwrite any
output.

The following required builder inputs are not valid until their indicated
ceremonies complete:

- `fresh-p3-genesis-with-executed-deployment.json` — produced by a fresh
  deterministic deployment using only P3 identities and the revised 12B-SNRG
  allocation plan;
- `five-validator-genesis-activation.json` — produced from `validator-02` through `validator-06`
  and the finalized P3 consensus manifest.

The historical six-validator PoSy 2.2 Genesis artifacts are not inputs to this
flow. No old chain database, state root, Genesis hash, network magic, receipt,
validator key, peer ID, or deployment execution state may be copied into these
files.

## Fresh Genesis authority freeze

The three Genesis authorities are separate SNTS-v1.3 FN-DSA-1024 identity
roots with bound ML-DSA-87 operational authorization keys. Freeze the existing
public records and encrypted-bundle hashes without opening custody material:

```bash
python3 scripts/build-fresh-testnet-v3-genesis-authority-freeze.py \
  --authority-root /path/to/testnet-v3-identity-files \
  --output launch/posy-v3-genesis-inputs/fresh-genesis-authority-freeze.json \
  --completion launch/posy-v3-genesis-inputs/fresh-genesis-authority-freeze.complete.json \
  --production-authorities-output launch/posy-v3-genesis-inputs/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.json \
  --production-authorities-completion launch/posy-v3-genesis-inputs/TESTNET_V3_PRODUCTION_AUTHORITIES.fresh.complete.json \
  --bundle-dir-prefix testnet-v3-identity-files
```

The `bundle_dir` entries are deliberately repository-relative. Before Core's
release-approval loader consumes the production-authorities view, the exact
hash-matched custody directories must exist at that prefix under the Core
repository root. Do not replace them with the obsolete key-derived authority
bundles.
