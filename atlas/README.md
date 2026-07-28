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

Do not run `ops/reset-schema.sh` until the signed final Testnet-v3 network
manifest and a live Testnet-v3 RPC endpoint are available. The script verifies
the RPC identity before it writes metadata or enables indexer work.
