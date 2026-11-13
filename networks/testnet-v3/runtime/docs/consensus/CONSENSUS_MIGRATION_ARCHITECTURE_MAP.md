# Consensus Migration Architecture Map

Status: Phase One implementation in progress. This map is based on the
Testnet-v3 runtime and deployment tree as inspected on 2026-08-01. It is an
implementation inventory, not a qualification claim.

## Canonical network inputs that must remain unchanged

The runtime configuration and topology identify the canonical Testnet-v3
network as chain ID `1266`, network ID `synergy-testnet-v3`, a two-second
target block interval, a 1,000-block epoch, and six configured validator
addresses. The validator order is derived from
`config/testnet/network-topology.toml`, not from peer address order or IP
address. Validator consensus authentication continues to use the registered
ML-DSA-65 consensus keys; transaction signing and peer transport identities
remain separate domains.

## Runtime architecture

| Area | Current responsibility | Phase One treatment |
| --- | --- | --- |
| `src/config/mod.rs` and `config/*.toml` | Parses node, network, consensus, identity, and role configuration. | Add an explicit consensus-mode configuration and validate the coordinator and producer identities against the canonical validator set. |
| `src/role_runtime.rs` | Selects validator role services, starts P2P, and currently starts the typed PoSy worker. | Introduce the sole consensus-mode dispatcher. Coordinated mode must start only its coordinator/producer worker; the typed PoSy worker must remain inactive. |
| `src/consensus/typed_coordinator.rs` | Current typed PoSy v2.2 proposal, validation certificate, finality QC, timeout certificate, and recovery driver. | Bypass completely while coordinated mode is active. Retain source only as a Phase-Two reference. |
| `src/consensus/posy.rs`, `dual_quorum.rs`, `typed_prepared_store.rs`, and `typed_finality_store.rs` | Existing PoSy state, quorum/certificate assembly, and QC-based persistence. | Do not invoke from coordinated mode and do not adapt their certificate formats for API compatibility. |
| `src/consensus/signing_authority.rs` and `src/crypto/aegis_pqvm.rs` | Durable signing authorization, key lifecycle, and domain-separated Aegis PQC signing/verification. | Reuse for coordinator assignments and coordinator commits, with distinct coordinated-mode signing domains and a non-equivocation journal. |
| `src/p2p/messages.rs` and `src/p2p/networking.rs` | Typed consensus transport, authenticated peer routing, and block/sync messages. | Add a separate coordinated-mode message family and dispatch only it in coordinated mode. Reuse the existing authenticated transport and bounded fanout. |
| `src/synergy_types.rs`, `src/block.rs`, `src/execution.rs`, `src/token.rs`, `src/aivm`, `src/synq`, and receipt/mempool modules | Canonical blocks, transaction execution, state, fees, receipts, AIVM, SynQ, and token semantics. | Reuse without semantic changes. Phase One replaces ordering/finalization only. |
| `src/sync/*` | Block and state synchronization. | Extend with a committed-block package that contains the block, producer assignment, producer signature, coordinator commit, and execution artifacts. Do not turn sync into a second consensus phase. |
| `src/rpc/rpc_server.rs` and WebSocket paths | Public RPC and subscription compatibility. | Extend metadata responses for the consensus version and coordinated commit proof without fabricating a QC. |
| `../atlas/` | Atlas database schema, API, indexer, and block-list/detail views. | Extend real ingestion and display to decode coordinated commit proof data from chain/RPC input. Do not insert synthetic rows or hardcoded production data. |
| `config/testnet/network-topology.toml`, deployment configuration, `scripts/chain1266/`, and `scripts/testnet/` | Six-validator topology, service builds, qualification, and operational evidence. | Add an explicit coordinated-mode deployment profile, preflight, and a 5,000-block evidence harness only after local/integration gates pass. |

## Phase One components

The following components are new and deliberately small:

1. `coordinated_round_robin` consensus state: a durable producer cursor,
   pending assignment, one coordinator commitment per height, and deterministic
   missed-turn handling. The cursor advances after a missed producer without
   advancing the block height.
2. `ProducerAssignment`, `CoordinatorCommit`, and `CommittedBlockPackage`:
   the only coordinated-mode consensus objects besides the existing block.
3. A coordinator signer journal and coordinated finality store, separate from
   QC/VC/TC persistence.
4. A mode dispatcher that ensures old PoSy timers, voters, aggregators,
   certificates, recovery loops, and height advancement cannot run alongside
   coordinated mode.

## Existing tests to retain or extend

Retain the canonical execution, AIVM, SynQ, transaction, signing, P2P, and
finality safety suites. Extend `src/consensus/tests.rs` and add focused tests
next to the coordinated-mode state machine for rotation, missed turns,
idempotence, coordinator restart, producer restart, invalid proposals,
equivocation, duplicate/reordered messages, and safe pause during a
coordinator outage. The existing six-node local mesh and launch stability
scripts are the starting point for later integration and soak harnesses; they
are not qualification evidence until they exercise the new mode.

## Deployment and Atlas sequence

No live deployment configuration is changed by the initial state-machine work.
Before Phase-One deployment, the release must gain a configuration preflight,
validator identity agreement check, a six-validator integration run, actual
Atlas ingestion/display tests, a 5,000-block continuous soak harness, and a
machine-verifiable qualification report. Only a passed report permits the
Phase-Two simplified PoSy implementation to begin.
