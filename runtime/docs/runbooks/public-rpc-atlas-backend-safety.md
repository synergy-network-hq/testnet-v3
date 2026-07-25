# Public RPC And Atlas Backend Safety

This runbook covers offline confidence evaluation for public RPC and Atlas
backend evidence. It does not authorize validator restarts, backend routing
changes, archive re-enable, snapshot publication, quorum changes, or chain-state
mutation.

## Command

```bash
synergy-node fleet status \
  --snapshot fleet-status.json \
  --strict \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The snapshot should contain current validator heads plus public RPC and Atlas
backend evidence. The evaluator derives cluster size, BFT quorum, and liveness
margin from the validator rows in the snapshot; it does not assume a fixed
six-validator topology.

## Backend Evidence Fields

Each backend row may include:

- `backend_id`: stable backend identifier. Falls back to `name`.
- `role`: `public_rpc`, `atlas`, `rpc_gateway`, `validator`,
  `validator_peer`, `canonical_validator`, or `archive`.
- `cluster_id`: dynamic validator cluster the backend evidence belongs to.
- `latest_finalized_height` and `latest_finalized_hash`.
- `latest_observed_height` and `latest_observed_hash`.
- `config_digest`, `validator_set_digest`, and `binary_digest`.
- `lifecycle_state`.
- `qrpc_status`.
- `lag_tolerance_blocks`.
- `timed_out`, `quarantined`, `archive_contained`, `minority_fork`, and
  `synthetic_height` exclusion flags.

Legacy `height` and `block_hash` remain accepted as fallback finalized-head
fields for existing offline fixtures.

## Confidence Output

The JSON report includes `backend_confidence` entries with:

- backend id, backend role, and cluster id;
- finalized and observed height/hash evidence;
- config, validator-set, and binary digests;
- lifecycle and qRPC status;
- lag blocks;
- hash-agreement status;
- canonical confidence;
- `trusted_for_public_reads`;
- `trusted_for_repair`;
- stale, minority, and quarantined reasons when present.

`public_surface_summary` repeats the dynamic cluster status and reports trusted
public-read backend count, trusted repair backend count, and whether public
surfaces were ambiguous.

## Fail-Closed Rules

Strict mode fails closed when:

- chain ID or network ID is not Testnet v3;
- any dynamic cluster cannot satisfy BFT quorum;
- any validator is inactive;
- active validators disagree on head height/hash;
- public RPC or Atlas evidence is unavailable, synthetic, ahead of canonical
  validator height, too far behind, or hash-mismatched at the same height;
- a backend is marked minority-fork or quarantined;
- public backends disagree and validator quorum proof is unavailable.

Timed-out public RPC evidence is excluded from public-read trust and recorded as
`backend_timeout_surface_jitter`. It is not treated as proof that the chain
itself failed.

Archive-contained evidence is never trusted for repair. Archive snapshots remain
out of validator recovery unless the archive canonical reseed gates pass in
`docs/runbooks/archive-canonical-reseed.md`.

## Public RPC Router Upstreams

Atlas reads fresh blocks through `https://testnet-rpc.synergy-network.io`, which
is fronted by `synergy-rpc-router` on the RPC gateway host. The router read pool
must point at the three relayer JSON-RPC endpoints on port `5640`:

```bash
SYNERGY_RPC_READ_UPSTREAMS=http://195.26.241.95:5640,http://94.72.117.108:5640,http://209.145.48.117:5640
```

Do not use retired relayer proxy ports such as `15640` for the public read pool.
The router fails startup validation for non-loopback read upstreams that do not
match `SYNERGY_RPC_RELAYER_RPC_PORT`, which defaults to `5640`.

After any router config change, prove both the local router and Atlas readiness:

```bash
curl -fsS http://127.0.0.1:5655 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'

curl -fsS https://testnet-atlas-api.synergy-network.io/readyz
```
