# testnet/runtime — quarantined Testnet-v2 state

The Testnet-v2 operational runtime copy previously here (per-validator configs,
v2 genesis.json, consensus-fork-migration.json, operational manifest, node
address CSV) was moved to
`launch/reference/testnet-v2/node-control-panel/runtime/` as historical
evidence. It carried retired Testnet-v2 validator identities and must not seed
Testnet-v3 nodes. Testnet-v3 control-panel runtime state must be regenerated
from the canonical Testnet-v3 genesis and signed release bundles during the
bootstrap-regeneration launch gate.
