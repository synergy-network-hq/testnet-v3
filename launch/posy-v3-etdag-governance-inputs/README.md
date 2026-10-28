# Fresh PoSy v3 ETDAG governance inputs

These are public, unsigned inputs for the separate Testnet-v3 PoSy chain
(technical network ID `testnet`, Chain ID 1266, protocol `posy/3.0`). They
replace the former deferred-ETDAG placeholder. They are not trust artifacts
until the frozen governance authority signs the V4 Genesis release request
that commits to the three derived roots.

The initial parameters preserve the implemented P3 ETDAG envelope: H+3
admission, four outstanding nonce slots, 30,000,000 protected gas, and an
8 MiB protected-byte cap. The fee input contains both the transaction fee
table and dynamic base-fee policy. That means the wallet's live price is
derived from policy rooted in the signed release rather than inherited from a
runtime default.

`posy-simplified-parameter-manifest.for-release.json` is the matching
canonical consensus manifest for block one. It is a staged input to the same
release approval, not evidence that approval has already occurred. Its
separate decision identifier is intentional: the V4 authority request binds
the consensus decision and the ETDAG decision together to one exact Genesis
candidate.

Build the public artifacts with a new output directory:

```text
testnet-v3-etdag-governed-artifacts --build-binding \
  --parameter-manifest launch/posy-v3-etdag-governance-inputs/etdag-parameter-manifest.input.json \
  --fee-schedule-manifest launch/posy-v3-etdag-governance-inputs/etdag-fee-schedule-manifest.input.json \
  --parameter-artifact-out RELEASE/etdag-parameter-artifact.json \
  --fee-schedule-artifact-out RELEASE/etdag-fee-schedule-artifact.json \
  --binding-out RELEASE/etdag-governed-genesis-binding.json
```

After the fresh P3 Genesis candidate has its final Genesis hash and deployment
execution-state root, derive the public membership anchor from that exact
candidate:

```text
testnet-v3-etdag-governed-artifacts --build-membership-anchor \
  --candidate RELEASE/genesis.testnet-v3.posy-pre-anchor.json \
  --governance-decision-id SNRG-GOV-ETDAG-P3-GENESIS-20260823-01 \
  --output RELEASE/etdag-membership-anchor.json
```

Attach that public anchor to a new final candidate without adding it to the
Genesis hash inputs, then write the V4 request from that anchored candidate:

```text
testnet-v3-etdag-governed-artifacts --attach-membership-anchor \
  --candidate RELEASE/genesis.testnet-v3.posy-pre-anchor.json \
  --membership-anchor RELEASE/etdag-membership-anchor.json \
  --output RELEASE/genesis.testnet-v3.posy-final-candidate.json

testnet-v3-genesis-release-approval --write-request \
  --candidate RELEASE/genesis.testnet-v3.posy-final-candidate.json \
  --authorities INPUT/TESTNET_V3_PRODUCTION_AUTHORITIES.json \
  --output RELEASE/testnet-v3-genesis-release-approval-request.json
```

No private key, passphrase, signature, or wallet trust value belongs in this
directory.

`prepare-fresh-posy-v3-genesis` is the only public-input builder for the
pre-anchor candidate. It refuses consensus-only and ETDAG-only Genesis files:
the finalized P3 consensus manifest, exact five-validator activation binding,
and ETDAG binding are passed together and recomputed as a single integrity
operation. The anchor is then derived from that staged candidate before the
V4 release request is written.

```text
prepare-fresh-posy-v3-genesis \
  --source-genesis INPUT/fresh-p3-genesis-with-executed-deployment.json \
  --consensus-manifest launch/posy-v3-etdag-governance-inputs/posy-simplified-parameter-manifest.for-release.json \
  --consensus-decision launch/posy-v3-etdag-governance-inputs/posy-p3-consensus-decision.for-release.md \
  --activation INPUT/five-validator-genesis-activation.json \
  --etdag-binding RELEASE/etdag-governed-genesis-binding.json \
  --output RELEASE/genesis.testnet-v3.posy-pre-anchor.json
```

`INPUT/fresh-p3-genesis-with-executed-deployment.json` and
`INPUT/five-validator-genesis-activation.json` must be newly created public
P3 records. They must not be copied from the retired chain.
The builder rejects the retired `posy/2.2`, `synergy-testnet-v3`, and
`ProofOfSynergy` markers before it writes anything.
