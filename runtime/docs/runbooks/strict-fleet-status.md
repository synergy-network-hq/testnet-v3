# Strict Fleet Status Runbook

Status: **historical pre-P3 offline tooling reference.** The Chain `1264` /
`synergy-testnet-v3` command below is not a valid command for fresh Chain
`1266` / network `testnet` / `posy/3.0`. A P3 fleet-status command and evidence
schema must be qualified separately before operational use.

This runbook covers the offline fleet doctor. It does not authorize live
validator restarts, binary deployment, or chain-state mutation.

## Command

```bash
synergy-node fleet status \
  --snapshot fleet-status.json \
  --strict \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The snapshot is JSON containing validator heads, public RPC backend heads, and
Atlas head evidence. The command prints a machine-readable report and exits
nonzero when strict checks fail. See
`docs/runbooks/public-rpc-atlas-backend-safety.md` for the backend confidence
fields emitted for public RPC and Atlas surfaces.

## Strict Checks

Strict mode fails closed when:

- chain ID or network ID is not Testnet v3;
- any cluster cannot satisfy dynamic BFT quorum;
- any validator is inactive;
- active validators disagree on head height/hash;
- public RPC or Atlas evidence is missing, unavailable, synthetic, ahead of
  canonical validator height, too far behind, hash-mismatched at the same
  height, minority-fork, quarantined, or ambiguous without validator quorum
  proof.

The evaluator derives quorum from cluster size and does not assume a fixed
six-validator topology.

Public RPC timeouts are reported as surface jitter and excluded from public-read
trust; they are not classified as chain failure by themselves.
