# Testnet-v3 functional component parity

This audit separates source packaging from operational capability. A component
is not considered operational merely because its files compile or its wiring
symbols exist.

It does not approve launch identities, genesis allocations, system-wallet
addresses, validator membership, or deployment timing.

## Machine-verifiable inventory

Run:

```bash
python3 scripts/check-component-parity.py
```

The manifest covers:

- native SNRG and the complete Synergy Token System;
- transaction fees and fee-collector accounting;
- epoch, cluster, validator, and reliability rewards;
- staking and validator lifecycle;
- all eight native SynQ genesis contracts with `.synq` source, compiled SynQ
  bytecode, ABI, manifest, and deployment inputs;
- SynQ admission, deployment, calls, receipts, compiler, and VM;
- AIVM execution, deterministic state, security policy, and STS host calls;
- Aegis PQVM and post-quantum transaction security;
- governance, treasury, oracle, slashing, identity, recovery, and burn;
- consensus, DAG, P2P, synchronization, RPC, archives, validator onboarding,
  SXCP, SynID, address classes, role services, and observability.

## Important launch boundary

The fee and reward mechanisms are present and testable. The copied Testnet-v2
runtime still names concrete system-wallet constants in `runtime/src/token.rs`.
Those values are not approved as Testnet-v3 identities. Before launch, the
final Testnet-v3 system-wallet bindings must be installed and the same focused
fee/reward tests rerun.

The copied configuration, manifest, template, and node-control-panel material
also contains inherited Testnet-v2 validator/node identity bindings. The
component audit deliberately does not approve them. Testnet-v3 must replace
those bindings with new identities rather than preserve the old ones.

The genesis contract suite is native SynQ source plus compiler-produced
artifacts. No Solidity contract is part of the Testnet-v3 package.
`runtime/scripts/testnet/genesis_tool.py` builds chain-1266 genesis documents
from public inputs, recomputes their integrity values, and validates them. The
contracts are not claimed to be deployed merely because they are present in
this repository; deployment belongs to the final Testnet-v3 genesis
configuration.

## Operational blocker

The inherited AIVM is not operational for general stateful SynQ contracts. Its
generic deployment path records metadata but does not execute constructors, and
its generic call path does not provide canonical calldata, caller/value context,
persistent contract storage, events, or host functions to bytecode. Therefore:

- SynQ source and artifact packaging: **pass**;
- eight-contract SynQ compilation: **pass**;
- general AIVM execution: **blocked**;
- genesis-contract deployment and stateful call verification: **blocked**.

The component checker exits nonzero while these operational blockers remain.
