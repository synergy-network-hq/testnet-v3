# Testnet-v3 genesis configuration boundary

Functional component parity is audited independently from launch identities and
genesis values.

The Testnet-v3 genesis configuration must eventually supply the new validator,
node, system-wallet, allocation, and contract-deployment inputs. This repository
does not require or prescribe a genesis ceremony. It does require the final
configuration to be reproducible, internally consistent, and identical across
all nodes.

The native SynQ genesis contract sources and compiler-produced artifacts live
in `genesis-contracts/`. They are not yet deployable as functioning stateful
contracts because the inherited AIVM general execution path is incomplete.
Testnet-v2 identities must not be copied into the final Testnet-v3
configuration.
