# Superseded: single-authority migration is not the P3 launch plan

This design was rejected when Testnet-v3 P3 became a separate fresh Chain-1266
network starting at block zero. It is retained only so historical links fail
safely instead of directing an operator into an obsolete procedure.

Do not import a single-authority block, QC, state root, validator identity,
parameter root, deployment receipt, data directory, or continuity claim into
P3. Do not run a boundary migration or use retired-chain state as a bootstrap,
rollback, recovery, or state-sync source.

The operative source-only preparation plan is
`posy-v3-fresh-chain-launch-preparation.md`. It requires the signed fresh P3
Genesis, exact five-validator activation, governed ETDAG artifacts, and all
launch/preflight evidence before any separately authorized deployment.
