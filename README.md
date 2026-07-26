# Synergy Testnet-v3

Dedicated, fail-closed preparation workspace for Synergy Testnet-v3.

## Frozen network identity

- Release ID: `testnet-v3`
- Runtime network ID: `synergy-testnet-v3`
- Chain ID: `1266`
- Numeric network ID: `1266`
- Token: `SNRG`

The chain and numeric network IDs remain `1266`. The runtime network ID changes
to prevent Testnet-v3 nodes, transactions, snapshots, and recovery artifacts
from being accepted by the Testnet-v2 runtime.

## Layout

- `runtime/` — source and operational files derived from `../01-Testnet/synergy-testnet`
- `validator-workspace/` — secret-free validator filesystem template
- `observability/` — monitoring definitions and validation tools
- `genesis-contracts/` — native `.synq` source, compiled SynQ bytecode, ABI,
  manifest, and deployment inputs for the eight genesis contracts
- `launch/` — launch manifest, functional component parity evidence, checklist, and retired v2 reference files
- `artifacts/` — destination for signed Testnet-v3 binaries, checksums, and generated installers
- `scripts/validate-testnet-v3.py` — structure and full launch-readiness gate

## Current status

The workspace contains the Testnet-v2 protocol feature set for Testnet-v3
validation. Launch-specific genesis values, validator identities, system-wallet
bindings, release binaries, and bootstrap bundles are still separate prelaunch
inputs. Testnet-v2 identity material retained under
`launch/reference/testnet-v2/` is reference-only and must not be reused.

Inherited Testnet-v2 bindings have not yet all been removed from runtime
configuration, manifests, templates, or the node-control-panel copy. They are
not approved Testnet-v3 identities and must be replaced with newly generated
values before launch.

Run the safe structural check:

```bash
python3 scripts/validate-testnet-v3.py --structure
```

Run the full launch gate:

```bash
python3 scripts/validate-testnet-v3.py
```

The full gate must continue to fail until the approved Testnet-v3 genesis
configuration, new validator and node identities, signed release binaries,
regenerated bootstrap bundles, and launch approvals are present.

Check component packaging and the operational blockers independently of launch
identity:

```bash
python3 scripts/check-component-parity.py
```

This gate verifies native stateful SynQ IR v2 artifacts, their hashes and
manifest-bound host capabilities, and the resolved local AIVM execution
evidence for the eight genesis contracts. It does not approve identities,
genesis, binaries, or a network launch; those remain under the full launch gate.

## Source repository

This directory is intended to be the checkout for:

`https://github.com/synergy-network-hq/testnet-v3.git`

Do not copy private keys, decrypted key files, passwords, `.env` files, live
chain state, or machine credentials into this repository.
