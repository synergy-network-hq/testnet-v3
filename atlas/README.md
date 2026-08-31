# Atlas Testnet-v3 operations

This directory is the clean Atlas data boundary for Testnet-v3. It contains no
Testnet-v2 migrations, seed data, identifiers, snapshots, or fallback values.

`schema/001_atlas_v3.sql` creates an empty schema only. It does not insert
network metadata, genesis records, validators, contracts, tokens, or any other
chain-derived data. `scripts/validate-network-config.mjs` rejects a deployment
configuration unless its final genesis identity, endpoints, registries,
economics, and PoSy/ETDAG inputs are complete.

`scripts/preflight-live-rpc.mjs` then checks the configured RPC's chain ID,
network ID, genesis hash, finalized head, validator registry, fee schedule,
ETDAG status, and token endpoint before Atlas is permitted to ingest data.

The full-reset controller first runs `ops/reset-schema.sh --offline-reset`
while every chain role is stopped. That mode validates the signed-release
network configuration, destroys all old chain-derived tables, creates an
empty incarnation-aware schema, and deliberately leaves `atlas_network`
unbound. After the direct validator 100-block OPERATIONAL gate, the controller
runs the normal mode: it verifies the live RPC identity, recreates the still
empty schema, binds the incarnation-4 network row, and only then starts Atlas
ingestion.
