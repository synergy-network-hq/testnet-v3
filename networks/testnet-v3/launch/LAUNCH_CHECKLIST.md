# Testnet-v3 launch checklist

Every item must be complete before any node joins Testnet-v3.

## Identity and genesis

- [ ] The approved ML-DSA-65 validator consensus profile is recorded with the final launch approval.
- [ ] Every validator consensus public key matches the approved profile and is bound to the canonical Testnet-v3 genesis input.
- [x] Fresh node and P2P identities generated for every node (validated against genesis 2026-07-26; see `launch/IDENTITY_VALIDATION_REPORT.md`).
- [ ] Validator addresses replaced in `runtime/config/testnet/network-topology.toml`.
- [ ] Canonical genesis configuration uses the final validator set and allocations.
- [ ] Genesis timestamp matches the approved launch window.
- [ ] Genesis integrity hashes are computed by the canonical tool.
- [ ] Genesis has the required release signatures.
- [ ] All three active genesis copies are byte-identical.
- [ ] No active file has the retired v2 genesis SHA-256.

## Runtime and artifacts

- [ ] Runtime enforces chain ID `1266`.
- [ ] Runtime enforces network ID `synergy-testnet-v3`.
- [ ] Complete test suite passes from the v3 source tree.
- [ ] Linux AMD64, macOS ARM64, and required Windows artifacts are built.
- [ ] Release artifacts are signed and listed in `artifacts/SHA256SUMS`.
- [ ] Artifact hashes are independently verified.

## Topology and deployment

- [ ] Public DNS endpoints resolve to the approved hosts.
- [ ] Validator VPN transports are generated from the current inventory.
- [ ] Firewall rules match the v3 topology.
- [ ] Bootstrap bundles are regenerated from the signed v3 genesis and binaries.
- [ ] Bundle genesis files are byte-identical to the canonical genesis.
- [ ] Monitoring targets and labels identify `testnet-v3`.
- [ ] Prepare-only dry run passes without joining consensus.

## Launch sequence

- [ ] Bootnodes and seed services pass readiness checks.
- [ ] Core validator quorum launches first.
- [ ] Twenty consecutive canonical blocks finalize before expansion.
- [ ] Remaining validators join only after the quorum gate.
- [ ] RPC, archive, observer, relayers, indexer, and Atlas start after validator stability.
- [ ] Launch transaction and final evidence are archived with hashes.

Final command:

```bash
python3 scripts/validate-testnet-v3.py
```
