# qRPC Read Isolation Runbook

This runbook describes public read behavior when consensus state is busy. It
does not authorize live validator restarts, state mutation, or binary
deployment.

## Public Read Boundary

qRPC status methods must not block consensus mutation paths. When the shared
chain mutex is busy, the read path returns explicit fail-closed metadata instead
of waiting or synthesizing height `0`.

Covered read surfaces:

- `synergy_getHealth`
- `synergy_getReadiness`
- `synergy_syncing`
- `synergy_blockNumber`
- `synergy_getBlockNumber`
- `synergy_nodeInfo`
- finalized-head fallback when canonical-lock file data is unavailable

## Expected Fail-Closed Shape

When chain state is busy, responses include:

- `fail_closed: true`
- `chain_state_available: false`
- `chain_state_error` or `error` explaining that qRPC returned without blocking
- `latest_height`, `current_block`, or `currentBlock` as `null` rather than a
  fabricated value

## Operational Rule

Do not restart validators or mutate chain data for qRPC-only lock contention.
Treat the public read as degraded, keep consensus isolated, and inspect metrics
or local logs separately.
