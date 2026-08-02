# Coordinated Round Robin v1

Status: **Phase One implementation in progress; not deployable or qualified.**

`coordinated_round_robin_v1` is the temporary Testnet-v3 consensus mode. It
replaces the PoSy v2.2 certificate lifecycle for one configured range of
heights. It is not an extension of the typed PoSy driver, and the two engines
must never authorize work at the same height.

## Fixed authority

- Chain ID: `1266`
- Network ID: `synergy-testnet-v3`
- Coordinator: `validator-1` only
- Normal producer order: `validator-2`, `validator-3`, `validator-4`,
  `validator-5`, `validator-6`, then repeat
- Target interval: 2,000 ms
- Producer turn timeout: 4,000 ms by the current explicit configuration

The coordinator assigns a producer; it does not produce ordinary blocks. A
missing coordinator pauses the chain safely. There is no coordinator election,
backup coordinator, vote, QC, VC, TC, aggregator, or certificate recovery
path in this mode.

The configuration parser in `runtime/src/config/mod.rs` rejects a coordinated
mode configuration unless the exact coordinator and ordered five producers are
supplied. `runtime/src/consensus/coordinated_round_robin.rs` verifies that the
six configured identities and their consensus keys are the active, finalized
Testnet-v3 validator records.

## Height and turn lifecycle

1. Val1 durably signs one `ProducerAssignment` for the next unfinalized
   height.
2. The assigned producer selects admissible transactions through the normal
   transaction path, builds and signs the ordinary block, and sends the
   existing block plus the signed assignment to Val1.
3. Val1 verifies the assignment, producer identity and signature, block
   parent, transaction order/count/root, execution roots, and transaction
   signatures. It executes the block before committing it.
4. Val1 durably signs one `CoordinatorCommit`, persists the final package,
   then broadcasts it. Every recipient independently repeats verification and
   execution before accepting the package.
5. Only a committed package advances the block height and producer cursor.

If the assigned producer does not deliver in time, Val1 durably records the
missed turn and signs an assignment for the next producer at the **same**
height. A signed replacement assignment is the durable evidence of the skip;
no height is skipped and no unsigned local inference is permitted.

## Current code boundary

The following components are implemented and covered by focused unit tests:

- strict configuration, producer rotation, timeout skip recording, and
  coordinator restart state in `coordinated_round_robin.rs`;
- exact coordinator signing envelopes in `signing_authority.rs`;
- independently recoverable coordinated finality in
  `coordinated_finality_store.rs`;
- authenticated P2P message validation and ingress routing in
  `p2p/messages.rs` and `p2p/networking.rs`;
- assignment, proposal, commit, execution, idempotence, and finality sync in
  `coordinated_runtime.rs`.

The role runtime intentionally still rejects a production coordinated-mode
start. The remaining work is to connect this runtime to canonical block
construction, canonical chain/RPC persistence, bounded P2P egress and the
six-validator integration harness. This prevents a release from appearing
healthy while only producing test-shaped or unobservable blocks.

## Epochs and initial height

Height zero is the genesis/pre-block state. Blocks 1 through 1,000 are epoch
zero; height 1,001 starts epoch one. This is defined in
`runtime/src/epoch.rs`. A fresh start therefore preserves the immutable
genesis block at height 0 and has its first coordinated block at height 1.

## Related documents

- [Message schemas](CONSENSUS_MESSAGE_SCHEMAS.md)
- [Persistence invariants](CONSENSUS_PERSISTENCE_INVARIANTS.md)
- [Failure and recovery](CONSENSUS_FAILURE_RECOVERY.md)
- [Operational runbook](CONSENSUS_MIGRATION_RUNBOOK.md)
