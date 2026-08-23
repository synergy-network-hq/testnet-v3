# PoSy v3 fresh-chain launch preparation

Status: source and public-artifact preparation only. This runbook does not
authorize signing, deployment, identity generation, or live-node changes.

## Fixed identity

- Chain ID: `1266`
- Display release: `Testnet v3`
- Technical network ID: `testnet`
- Protocol: `posy/3.0`
- Genesis boundary: `fresh_genesis_block_zero`
- Initial epoch: `0`
- First consensus block: `1`
- Initial validators: exactly five approved public identities; the protocol
  derives later epoch counts and quorum dynamically.

The new Genesis must not reuse a retired-chain block, state root, QC, validator
identity, deployment receipt, parameter root, or data directory. The public P3
builder rejects the retired markers `posy/2.2`, `synergy-testnet-v3`, and
`ProofOfSynergy` before writing output.

## Public artifact sequence

1. Finalize the five public validator identities, ML-DSA-65 consensus public
   keys, frozen weights, and the Genesis-bound activation record.
2. Produce a fresh executed-deployment source Genesis whose public deployment
   record already identifies `testnet`, `testnet-v3`, and `posy/3.0`.
3. Build the ETDAG parameter artifact, fee artifact, and atomic Genesis binding
   from `launch/posy-v3-etdag-governance-inputs/`.
4. Run `prepare-fresh-posy-v3-genesis` with the canonical P3 manifest, decision
   record, five-validator activation, governed ETDAG binding, and fresh
   executed-deployment source.
5. Derive the public ETDAG membership anchor from that exact candidate, attach
   it outside the Genesis hash inputs, and independently revalidate the
   candidate.
6. Generate the V4 release-approval request. Verify it commits the exact
   candidate bytes, Genesis and deployment roots, consensus manifest/root, all
   three ETDAG roots, and frozen public governance authority record.
7. Obtain the governance signature through the separately authorized custody
   workflow, then verify it using only the frozen public authority.
8. Render public-only node configuration and perform the offline all-five
   preflight. A configuration is not permission to start a validator.

## RAM-safe source checks

Run these from the repository root:

```bash
git diff --check
cd runtime/src
cargo metadata --no-deps --format-version 1
cargo fmt --all -- --check
```

When a machine with adequate memory is available, run the focused tests and
both independent-process harnesses:

```bash
cd runtime/src
CARGO_BUILD_JOBS=1 cargo test -p synergy-testnet --lib consensus::simplified_posy::tests --no-fail-fast
CARGO_BUILD_JOBS=1 cargo run -p synergy-testnet --bin posy-simplified-five-node-harness -- run --work-dir /tmp/posy-five-node
CARGO_BUILD_JOBS=1 cargo run -p synergy-testnet --bin posy-simplified-five-driver-harness -- run --work-dir /tmp/posy-five-driver
```

## Abort conditions

Stop preparation if any canonical bytes or root differ, any validator is
missing or duplicated, four-of-five does not retain strict weight quorum, a
P3 artifact contains a retired marker, the ETDAG binding is absent, the public
governance identity differs from the frozen authority, a signature fails, or
any node derives a different epoch context or leader ring. Never work around a
failure by lowering quorum, clearing the signer journal, forcing a leader,
substituting a key, or accepting a local configuration as authority.

## Launch evidence still required

Before any separately authorized deployment, record successful current-build
tests, the two harness reports, all-five offline preflight, reproducible binary
hashes, restart/state-sync and one-unavailable-validator rehearsals, protected
ETDAG execution, node-database convergence, performance/soak evidence, and a
go/no-go decision that references the exact signed artifact hashes.
