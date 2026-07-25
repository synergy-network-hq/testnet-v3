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
contract-to-contract and runtime-authority calls remain explicitly gated.
Authorities and addresses in `deployment-config.example.json` are placeholders
for newly generated Testnet-v3 values; no Testnet-v2 identity is approved.

The contracts are native SynQ adaptations of the functional responsibilities
described by the legacy files, not Solidity compatibility outputs. Native SNRG
movement, cross-contract calls, validator-registry access, staking access, and
SynID normalization are expressed as required AIVM host capabilities. The
current AIVM does not yet provide the complete general host environment. The
required host surface is enumerated in `host-capabilities.json`.

## Rebuild and verify

From `runtime/synq-language`:

```bash
for source in ../../genesis-contracts/contracts/*.synq; do
  case "$source" in *.compiled.synq) continue ;; esac
  cargo run -p cli -- check "$source"
done
```

The current `synq build` command additionally emits a `.sol` compatibility
preview. That preview is not production-deployable and must not be included in
this package.

## Deployment blocker

Compilation is not deployment proof. The inherited AIVM currently records
generic contract metadata but does not execute constructors or provide general
stateful SynQ bytecode with calldata, caller/value context, persistent storage,
events, or host calls. These contracts must not be marked deployed until that
general AIVM execution path is implemented and an end-to-end deployment/call/
restart/replay test passes for this suite.
