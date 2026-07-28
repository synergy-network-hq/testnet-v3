# consensus-fork-migration.json — quarantined

The Testnet-v2 fork-recovery document previously at this path is retained as
historical evidence only, now at
`launch/reference/testnet-v2/consensus-fork-migration.json`.

Testnet-v3 is a fresh-genesis chain. The runtime rejects
`SYNERGY_CONSENSUS_FORK_MIGRATION_FILE` unconditionally
(`runtime/src/consensus/consensus_fork.rs`, fresh-genesis policy), and the
migration schema only admits FN-DSA consensus keys, which are invalid for
Testnet-v3 consensus (ML-DSA-65). This file must never become an active
Testnet-v3 input.
