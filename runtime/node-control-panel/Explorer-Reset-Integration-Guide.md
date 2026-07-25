# Explorer Reset Integration Guide

## Problem

When the testnet chain is reset to genesis via the control panel, the explorer and indexer services continue to display stale blockchain data from the previous chain. This is because the explorer maintains its own internal database of indexed blocks, and there is no mechanism to signal it to clear that data when a chain reset occurs.

## What the Control Panel Now Does

As of this update, the control panel's bulk `reset_chain` action will attempt to send a POST request to a configurable explorer API endpoint after all nodes have been successfully reset. This is a best-effort, non-blocking call — if the explorer is unreachable or the endpoint is not configured, the chain reset still succeeds for all nodes.

### Configuration

Set the explorer reset endpoint in one of these locations (checked in order):

1. **Environment variable:** `SYNERGY_EXPLORER_RESET_ENDPOINT`
2. **hosts.env file:** Add `SYNERGY_EXPLORER_RESET_ENDPOINT=https://your-explorer-api.example.com/v1/admin/reindex-from-genesis` to `testnet/runtime/hosts.env`

### Request Format

The control panel sends:

```http
POST <SYNERGY_EXPLORER_RESET_ENDPOINT>
Content-Type: application/json

{
  "action": "reindex_from_genesis",
  "reason": "chain_reset",
  "timestamp_utc": "2026-03-08T12:00:00Z"
}
```

## What the Explorer Service Needs to Implement

The explorer/indexer service needs to expose an HTTP endpoint that accepts the above POST request and performs the following:

### Required Endpoint

**`POST /v1/admin/reindex-from-genesis`**

### Required Behavior

1. **Clear the indexed block database** — drop or truncate all tables/collections that store indexed block data, transaction data, and any derived state (token balances, validator stats, etc.)

2. **Clear any caches** — invalidate or flush in-memory caches, Redis caches, CDN caches, or any other layer that may serve stale data to the frontend

3. **Reset the indexer cursor** — set the last-indexed block height back to 0 so the indexer starts scanning from the genesis block on its next cycle

4. **Restart the indexer process** (if applicable) — some indexer architectures require a process restart to pick up the new cursor position

5. **Return appropriate HTTP status:**
   - `200 OK` — reindex initiated successfully
   - `202 Accepted` — reindex queued (if the operation is async)
   - `500 Internal Server Error` — reindex failed (include error details in response body)

### Recommended Response Format

```json
{
  "status": "accepted",
  "message": "Reindex from genesis initiated. Explorer will show new chain data within ~60 seconds.",
  "previous_block_height": 3955,
  "new_block_height": 0
}
```

### Authentication

If the endpoint requires authentication, the control panel currently does not send auth headers. Options:

- Use IP-based allowlisting for the approved management network only
- Add a bearer token via the `SYNERGY_EXPLORER_RESET_TOKEN` env var (requires a small code addition to `monitor.rs`)
- Use a shared secret in a custom header

### Additional Considerations

- The endpoint should be idempotent — calling it multiple times should be safe
- Consider adding a rate limit (e.g., max 1 reset per minute) to prevent accidental repeated reindexing
- The indexer should handle the case where the chain has been reset to a height lower than its current index — this means blocks it previously indexed no longer exist
- If the explorer frontend shows cached data, it should either poll the indexer for freshness or accept a cache-bust signal

## Manual Reset (Fallback)

If the automated endpoint is not configured, the explorer must be reindexed manually after each chain reset. The exact steps depend on your explorer's architecture, but generally:

1. Stop the indexer service
2. Clear the database (e.g., `DROP DATABASE explorer_db; CREATE DATABASE explorer_db;`)
3. Reset any cursor/checkpoint files
4. Restart the indexer service
5. Wait for it to re-scan from block 0

## Testing

After implementing the endpoint, test the full flow:

1. Start the testnet and produce some blocks (wait for block height > 10)
2. Verify the explorer shows the current block height
3. From the control panel dashboard, click "Reset Chain" (global)
4. Verify all nodes stop and chain data is erased
5. Verify the explorer no longer shows the old block data
6. Start the testnet via "Start All"
7. Verify the explorer picks up the new genesis and starts indexing fresh blocks
