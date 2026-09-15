# Atlas Consensus Indexing

Status: Phase One integration requirement; no coordinated-mode Atlas ingestion
or display implementation is claimed by the checked-in Atlas operations tree.

Atlas must index and display blocks from the real chain only. No fake rows,
synthetic height values, hardcoded consensus proofs, or mock production data
may satisfy the qualification gate.

## Existing operational boundary

`atlas/schema/001_atlas_v3.sql` defines the incarnation-4 chain-derived
schema. It stores block height, hash, parent hash, proposer, finalization
status, transaction count, and an extensible JSON payload. `indexer_state`
starts at `indexed_height = -1`, so a fresh genesis reset has no fabricated
block data.

`atlas/ops/reset-schema.sh` requires an explicit `--apply`, a validated signed
network configuration, and an empty evidence directory. In offline-reset
mode it validates the immutable network identity, drops only the listed
chain-derived tables with `RESTRICT`, recreates the schema, and leaves
`atlas_network` unbound. In normal mode it first runs the live RPC preflight
and then binds the canonical incarnation-4 network row.

The fleet controller performs offline Atlas reset before a fresh start and
does not activate Atlas until all six direct validators have passed its
100-block operational gate.

## Coordinated-mode requirements

Before the 5,000-block Phase-One qualification can pass, the real indexer/API
and user-facing block views must expose, from chain or RPC responses:

- consensus version `coordinated_round_robin_v1`;
- block height, hash, parent, timestamp, producer, and transaction count;
- the signed producer assignment and signed coordinator commit, or safe
  identifiers/hashes of those artifacts;
- coordinator ID, assigned producer, producer round, assignment/commit hash,
  and missed-turn evidence where applicable;
- an indexed height that is continuous with the real finalized chain.

Older QC-only display fields must be nullable or versioned. Do not populate a
fake QC for a coordinated commit.

## Current blocking work

This checkout contains schema, validation, preflight, reset, and tests for the
Atlas operations boundary, but not a checked-in coordinated block decoder,
indexer ingestion handler, or display component. Those components must be
located in the release source or implemented and tested before Atlas can be
counted as Phase-One evidence.
