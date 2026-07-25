# SXCP Relayer Daemon

Production-grade post-quantum cryptography (PQC) enabled relayer daemon for cross-chain intent execution on Synergy Testnet.

## Overview

The SXCP Relayer implements the watch→finalize→sign→submit→report loop for processing cross-chain intents with PQC-based attestations:

1. **Watch**: Monitor source chains (Sepolia, Amoy) for `IntentCommitted` events
2. **Finalize**: Collect PQC signatures from peer relayers via quorum coordination
3. **Sign**: Generate ML-DSA/FN-DSA signatures via Aegis-PQVM
4. **Submit**: Submit attestation bundles to destination chain once 2/3 BFT threshold reached
5. **Report**: Report results back to Synergy Testnet

## Architecture

### Core Components

- **index.js**: Main daemon orchestrator and event loop
- **watcher.js**: Source chain event monitoring (WebSocket + polling fallback)
- **coordinator.js**: Quorum management and PQC signature coordination
- **submitter.js**: Destination chain transaction submission with gas management
- **reporter.js**: Synergy Testnet reporting and heartbeat
- **store.js**: SQLite persistence layer for state management

### Key Features

- **PQC-Only Cryptography**: All signing uses ML-DSA-65 or FN-DSA-1024 via Aegis-PQVM
- **Dual-Chain Monitoring**: Concurrent event watchers for Sepolia and Amoy
- **Resilient Event Streaming**: WebSocket with automatic polling fallback
- **BFT Quorum Coordination**: 2/3 threshold-based attestation finalization
- **Exponential Backoff Retry**: Intelligent retry strategy for submission failures
- **Block Checkpoint Management**: Prevents duplicate event processing
- **Graceful Shutdown**: Clean resource cleanup with signal handling

## Installation

```bash
npm install
```

Dependencies:
- ethers v6.15.0 - EVM interaction
- better-sqlite3 v11.0.0 - Local state persistence
- dotenv v16.4.5 - Environment configuration

## Configuration

### Environment Variables

Create a `.env` file from `.env.example`:

```bash
# Source Chain RPC Endpoints
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
SEPOLIA_WS_URL=wss://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
AMOY_RPC_URL=https://polygon-amoy.g.alchemy.com/v2/YOUR_KEY
AMOY_WS_URL=wss://polygon-amoy.g.alchemy.com/v2/YOUR_KEY

# Synergy Testnet
SYNERGY_RPC_URL=http://127.0.0.1:5640

# Relayer Identity
RELAYER_ADDRESS=0x...

# PQC Configuration
PQC_ALGORITHM=fndsa                    # fndsa, mldsa, or slhdsa
PQC_PUBLIC_KEY_B64=...                 # Base64 encoded public key
PQC_PRIVATE_KEY_PATH=./keys/relayer.pqc.enc

# Paths
SXCP_RELAYER_CONFIG_PATH=../../sxcp/sxcp_external_chains/evm/runtime/testnet-sxcp-relayer-config.json
SQLITE_DB_PATH=./data/relayer.db
```

### Runtime Configuration

Optional `testnet-sxcp-relayer-config.json`:

```json
{
  "sepoliaChainId": 11155111,
  "amoyChainId": 80002,
  "destinationChainId": 1264,
  "sxcpIntentHubAddress": "0x...",
  "sxcpVaultAddress": "0x...",
  "threshold": 2,
  "maxRetries": 5,
  "pollInterval": 12000,
  "confirmationBlocks": 12
}
```

## Running

### Development Mode (with file watching)

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

### As a Systemd Service

Create `/etc/systemd/system/sxcp-relayer.service`:

```ini
[Unit]
Description=SXCP Relayer Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sxcp
WorkingDirectory=/opt/sxcp-relayer
ExecStart=/usr/bin/node src/index.js
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment="NODE_ENV=production"
EnvironmentFile=/opt/sxcp-relayer/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable sxcp-relayer
sudo systemctl start sxcp-relayer
sudo systemctl status sxcp-relayer
```

View logs:

```bash
sudo journalctl -u sxcp-relayer -f
```

## Database Schema

### processed_events
Tracks IntentCommitted events to prevent duplicates
- chain_id, tx_hash, event_index, intent_id, sender, nonce, block_number

### bundles
Attestation bundle state tracking
- status: pending, submitted, finalized, failed
- signature_count, threshold, pqc_algorithm

### retry_state
Exponential backoff tracking for failed submissions
- retry_count, last_attempt, next_retry, last_error

### replay_cache
Deduplication cache for event processing
- Aged out after 7 days

### checkpoints
Last processed block per chain
- last_block_number, last_finalized_block

## Event Flow

### 1. Event Detection

```
IntentCommitted on Sepolia/Amoy
    ↓
WatcherJS: Subscribe via WebSocket (fallback: polling)
    ↓
ProcessLog: Verify finality (12 confirmations)
    ↓
Store: Record in processed_events table
    ↓
Emit: 'IntentCommitted' event to main loop
```

### 2. Quorum Coordination

```
Main Loop: Collect signatures from peers
    ↓
Coordinator: Verify PQC signatures via Aegis-PQVM
    ↓
Store: Increment signature_count
    ↓
Check: Is 2/3 threshold reached?
    ↓
If yes: Move to submission phase
```

### 3. Local Signing

```
Coordinator.signBundleLocally(bundleHash)
    ↓
RPC Call: aegis_signPQC on Synergy node
    ↓
Returns: { signature, publicKey, algorithm }
    ↓
submitSignature(bundleId, signature, pubKey, algo)
```

### 4. Attestation Submission

```
processPendingBundle(bundleId)
    ↓
Submitter: estimateGas for verifyAttestationBundle
    ↓
Apply: 1.2x gas multiplier
    ↓
Submit: Transaction to SXCPIntentHub
    ↓
On success: Update bundle status to 'submitted'
    ↓
On failure: recordRetry with exponential backoff
```

### 5. Reporting

```
Reporter.submitAttestation(attestation)
    ↓
RPC Call: synergy_submitAttestation
    ↓
Synergy: Records attestation on-chain
    ↓
Periodic: synergy_relayerHeartbeat (60s)
```

## PQC Integration

All cryptographic operations use post-quantum algorithms:

- **ML-DSA-65**: Primary algorithm for most operations
- **FN-DSA-1024**: Alternative for compatibility
- **SLH-DSA**: Stateless hash-based signatures

Signing happens via Aegis-PQVM RPC calls to the Synergy node:

```javascript
// Sign a bundle hash
const sig = await synergyProvider.send('aegis_signPQC', [
  bundleHash,
  'fndsa',        // algorithm
  relayerAddress
]);

// Verify a signature
const valid = await synergyProvider.send('aegis_verifyPQC', [
  bundleHash,
  signature,
  publicKey,
  'fndsa'
]);
```

PQC commitment is computed as:

```
keccak256(abi.encodePacked(
  algorithmId,      // uint32
  pqcPublicKey,     // bytes
  pqcSignature,     // bytes
  bundleHash        // bytes32
))
```

## Error Handling

### Transient Failures

- WebSocket disconnect: Automatic fallback to polling
- RPC rate limit: Exponential backoff with max 5 retries
- Transaction revert: Gas limit increase (1.2x) and retry

### Fatal Errors

- Missing configuration: Exit with error
- Database corruption: Exit and alert
- PQC signing failure: Skip bundle, report to Synergy
- Synergy connectivity loss: Log warning, continue monitoring

## Monitoring

### Logs

All events are logged to stdout/stderr with ISO timestamps:

```
[Relayer] Starting SXCP Relayer daemon...
[Watcher:11155111] Initialized on chain 11155111 at block 5123456
[Watcher:80002] IntentCommitted: 0x... from 0x... (nonce: 42)
[Coordinator] Registered bundle 0x... with threshold 2
[Coordinator] Bundle 0x... reached quorum!
[Submitter] Bundle 0x... submitted to chain 1264: 0x...
[Reporter] Submitted attestation for bundle 0x...
```

### Metrics (via Reporter)

Track in Synergy Testnet:
- Bundle submission rate
- Average quorum time
- Signature verification failures
- Submission retry rates

### Database Queries

Check pending bundles:

```sql
SELECT bundle_id, status, signature_count, threshold
FROM bundles WHERE status = 'pending'
ORDER BY created_at DESC;
```

Check retry state:

```sql
SELECT bundle_id, retry_count, next_retry, last_error
FROM retry_state
WHERE next_retry < datetime('now')
ORDER BY next_retry ASC;
```

## Security Considerations

1. **Private Key Protection**: Store encrypted PQC keys with restricted permissions
2. **RPC Endpoint Validation**: Use authenticated RPC endpoints with rate limiting
3. **Relay Node Isolation**: Run relayer in isolated VM with network segmentation
4. **Quorum Integrity**: Verify peer signatures cryptographically before accepting
5. **Replay Protection**: Block hash + block number prevents event replay
6. **State Isolation**: SQLite WAL mode prevents concurrent write corruption

## Development

### Testing

```bash
npm test  # (Test suite to be implemented)
```

### Debugging

Enable verbose logging:

```bash
DEBUG=* npm start
```

Monitor database:

```bash
sqlite3 ./data/relayer.db
sqlite> SELECT COUNT(*) FROM bundles WHERE status = 'pending';
```

## Performance Tuning

### Database Optimization

```sql
-- Rebuild indices
REINDEX;

-- Vacuum to reclaim space
VACUUM;

-- Check pragma settings
PRAGMA journal_mode;        -- Should be WAL
PRAGMA synchronous;         -- Should be NORMAL
PRAGMA cache_size;          -- Adjust for available RAM
```

### Network Optimization

- Increase `CONFIRMATION_BLOCKS` to reduce false starts
- Tune `POLL_INTERVAL_MS` based on source chain block time
- Use dedicated RPC endpoints for each chain

### Throughput Scaling

For multiple relayers:
- Each relayer instance maintains separate SQLite database
- Peer-to-peer signature gossip (not yet implemented)
- Sharded bundle processing by source chain

## Troubleshooting

### No events detected

1. Check RPC endpoints: `curl -X POST $SEPOLIA_RPC_URL -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`
2. Verify contract address: `sqlite3 data/relayer.db "SELECT * FROM checkpoints;"`
3. Check WebSocket connectivity: Look for fallback to polling in logs

### Submission failures

1. Check gas price: `eth_gasPrice` on destination chain
2. Verify account balance: Ensure relayer account has sufficient native token
3. Check contract state: `SXCPIntentHub.verifyAttestationBundle()` may be paused

### PQC signing errors

1. Verify Aegis-PQVM is running on Synergy node
2. Check PQC algorithm configuration matches key material
3. Validate public key format (base64 encoded)

## License

Proprietary - Synergy Protocol

## Support

For issues and questions, contact the Synergy core team.
