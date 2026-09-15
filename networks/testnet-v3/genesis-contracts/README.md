# Testnet-v3 native SynQ genesis contracts

This directory contains the eight Testnet-v3 system contracts in Synergy's
native SynQ language. Solidity is not a deployment format for Synergy Network.

For each contract, `contracts/` contains:

- `<Name>.synq` - canonical source;
- `<Name>.compiled.synq` - SynQ bytecode;
- `<Name>.abi.json` - deterministic SynQ ABI;
- `<Name>.manifest.json` - chain, network, AIVM, and PQ-signature requirements.

The suite contains:

1. `ValidatorRegistry`
2. `Staking`
3. `RewardDistributor`
4. `Governance`
5. `Treasury`
6. `SynergyOracle`
7. `Identity`
8. `Slashing`

Governance configuration methods require ML-DSA verification. Operational
contract-to-contract and runtime-authority calls are explicitly capability
gated by each compiled artifact manifest.
Authorities and addresses in `deployment-config.example.json` are placeholders
for newly generated Testnet-v3 values; no Testnet-v2 identity is approved.

The contracts are native SynQ adaptations of the functional responsibilities
described by the legacy files, not Solidity compatibility outputs. Native SNRG
movement, cross-contract calls, validator-registry access, staking access, and
SynID normalization are expressed as required AIVM host capabilities. The
stateful SynQ IR v2 AIVM path implements that host surface and enforces the
per-contract allowlist emitted in each manifest. The canonical capability
registry is `host-capabilities.json`.

## Rebuild and verify

From `runtime/synq-language`:

```bash
for source in ../../genesis-contracts/contracts/*.synq; do
  case "$source" in *.compiled.synq) continue ;; esac
  cargo run -p cli -- check "$source"
done
```

Any locally generated `.sol` compatibility preview is not production-deployable
and must not be included in this package. Synergy deployment artifacts are the
native `.compiled.synq`, ABI, and manifest files.

## Deployment evidence

Compilation alone is not deployment proof. The Testnet-v3 AIVM now executes
constructors and general stateful SynQ IR v2 with canonical calldata,
caller/value and block context, persistent storage, events, PQ verification,
native transfers, capability-gated host calls, and transaction-scoped nested
contract calls. The `aivm-core` test
`all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`
deploys all eight artifacts, exercises representative calls, restores the
serialized state, and proves deterministic receipt and state-root replay.

This local execution evidence does not mark the contracts deployed to the
network. Public Testnet-v3 deployment remains gated on the separately generated
and approved identity/genesis inputs, complete launch validation, and controlled
network start.
