# Consensus Migration Runbook

Status: **historical coordinated-consensus migration record; not a PoSy v3
runbook.** This document preserves the former six-validator
`synergy-testnet-v3` procedure for audit only. It must not be used to prepare,
start, recover, or extend the fresh Chain `1266` / network `testnet` /
`posy/3.0` chain. Use
`runtime/docs/runbooks/posy-v3-fresh-chain-launch-preparation.md` for the P3
source-preparation sequence.

## Release gates before a fresh start

1. Build and test the coordinated role-runtime lifecycle, canonical block
   construction, transaction path, chain/RPC persistence, P2P egress, and
   six-validator integration harness.
2. Verify immutable inputs: chain ID 1266, network ID
   `synergy-testnet-v3`, canonical genesis hash, six active validator
   identities and consensus keys, protocol compatibility, and the exact
   coordinated configuration.
3. Produce a promotable, signed release and desired-state signature accepted
   by `scripts/chain1266/control-plane.py`.
4. Obtain the required controlled-operation authority. The controller acquires
   its lock and rereads `CHAIN_1266_STALL_LOG.md` before every remote mutation.

The active codebase is not yet through step 1. Do not reset a running fleet
until a startable qualified release is ready to take its place.

## Required fresh-genesis reset

The requested launch semantics preserve the canonical immutable genesis block
at height 0 and remove all later chain-derived state. The first coordinated
block is height 1. Never delete validator keys, peer identities, credentials,
or genesis artifacts.

Use the existing controller in this order, with the exact promotable release,
signature, fleet inventory, and generated deletion-manifest path for that
release:

1. `stop-for-reset` stops every configured chain role and verifies it is not
   active.
2. `dry-run-wipe` connects through the inventory's workbook-backed aliases and
   writes a checksummed, release-bound deletion manifest. It rejects active services,
   non-allowlisted paths, and any protected key/identity/credential material.
3. Review the manifest. It must cover exactly the controller's configured
   chain-derived roots for all roles, including validators, relayers, RPC,
   observer/indexer support, and no protected material.
4. `wipe-all-chain-state --deletion-manifest …` deletes only those approved
   roots, recreates each state directory mode `0700`, and writes `.reset_flag`.
   At first validator startup, the P1 worker refuses the marker if the loaded
   chain is not exactly canonical Genesis at height 0 or if any coordinated
   finality, coordinator-state, signing, or retired typed-finality journal
   remains.
5. `reset-atlas-offline` drops only the explicit Atlas chain-derived tables and
   recreates the empty incarnation-4 schema; it does not drop PostgreSQL
   `public` or user-facing non-chain tables.
6. Stage the immutable release, start support roles, and start validators in
   their signed paused state. Assert all six report the same paused barrier and
   height 0 before releasing consensus.
7. Distribute the signed start command, then prove an identical advancing
   finalized tip across all six validators. Bind and start Atlas only after the
   controller's 100-block operational gate.

The controller enforces exact `/var/lib/synergy*` or `/var/cache/synergy*`
`data`, `cache`, `chain`, or `snapshots` roots; it does not accept broad home,
project, or system directories. The launch service consumes `.reset_flag` to
skip peer sync once and begin from fresh genesis.

## Qualification and promotion

Run the release's real six-host qualification and collect the machine-readable
evidence. A Phase-One pass requires 5,000 consecutive finalized coordinated
blocks, identical validator tips, recorded producer rotation and missed turns,
restart/rejoin evidence, and Atlas indexing/display backed by real chain data.
No Phase-Two implementation or activation is authorized by a shorter local
test, service liveness, or a running process.

## Progress report fields

Every major checkpoint reports: files changed, behavior added, behavior
bypassed, tests run/passed/failed, live height, all validator heads, Atlas
height, known risks, and next action. State unavailable values explicitly;
never substitute stale or synthetic telemetry.
