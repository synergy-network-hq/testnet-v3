# SXCP Relayer Quick Start Guide

## 1. Setup (5 minutes)

```bash
cd /Users/devpup/Desktop/Testnet/synergy-testnet/services/sxcp-relayer

# Copy environment template
cp .env.example .env

# Edit .env with your values
nano .env
# Required variables:
# - SEPOLIA_RPC_URL / SEPOLIA_WS_URL
# - AMOY_RPC_URL / AMOY_WS_URL
# - SYNERGY_RPC_URL
# - RELAYER_ADDRESS
# - PQC_ALGORITHM (fndsa, mldsa, or slhdsa)
# - PQC_PUBLIC_KEY_B64
# - PQC_PRIVATE_KEY_PATH
```

## 2. Install Dependencies

```bash
npm install
# Creates node_modules/ with ethers, better-sqlite3, dotenv
```

## 3. Setup Keys and Database

```bash
# Create key storage directory
mkdir -p keys

# Create database directory
mkdir -p data

# Place your encrypted PQC key
cp /path/to/relayer.pqc.enc keys/

# Database will be created automatically on first run
```

## 4. Run the Relayer

### Development Mode (with file watching)
```bash
npm run dev
```

### Production Mode
```bash
npm start
```

### Check Logs
```bash
# If running in foreground, you'll see logs immediately
# If running in background:
tail -f nohup.out
```

## 5. Verify It's Working

### Check Database
```bash
sqlite3 data/relayer.db
sqlite> .tables
sqlite> SELECT COUNT(*) FROM bundles;
sqlite> SELECT COUNT(*) FROM processed_events;
sqlite> .quit
```

### Monitor Events
Look for log lines like:
```
[Relayer] Starting SXCP Relayer daemon...
[Watcher:11155111] Initialized on chain 11155111 at block XXXXX
[Watcher:80002] Initialized on chain 80002 at block XXXXX
[Reporter] Connected to Synergy Testnet: ...
[Relayer] Running...
```

## 6. Configuration Reference

### Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| SEPOLIA_RPC_URL | Sepolia HTTP RPC | https://eth-sepolia.g.alchemy.com/v2/KEY |
| SEPOLIA_WS_URL | Sepolia WebSocket RPC | wss://eth-sepolia.g.alchemy.com/v2/KEY |
| AMOY_RPC_URL | Amoy HTTP RPC | https://polygon-amoy.g.alchemy.com/v2/KEY |
| AMOY_WS_URL | Amoy WebSocket RPC | wss://polygon-amoy.g.alchemy.com/v2/KEY |
| SYNERGY_RPC_URL | Synergy Testnet RPC | http://127.0.0.1:5640 |
| RELAYER_ADDRESS | Your relayer address | 0x... |
| PQC_ALGORITHM | PQC algorithm | fndsa / mldsa / slhdsa |
| PQC_PUBLIC_KEY_B64 | Base64 public key | ... |
| PQC_PRIVATE_KEY_PATH | Path to encrypted key | ./keys/relayer.pqc.enc |
| SXCP_RELAYER_CONFIG_PATH | Config file path | ../../sxcp/... |
| SQLITE_DB_PATH | Database file path | ./data/relayer.db |

### Runtime Configuration (testnet-sxcp-relayer-config.json)

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

## 7. Common Operations

### View Pending Bundles
```bash
sqlite3 data/relayer.db << EOF
SELECT bundle_id, status, signature_count, threshold
FROM bundles
WHERE status = 'pending'
ORDER BY created_at DESC
LIMIT 10;
EOF
```

### Check Last Processed Block
```bash
sqlite3 data/relayer.db << EOF
SELECT chain_id, last_block_number, updated_at
FROM checkpoints;
EOF
```

### View Retry Queue
```bash
sqlite3 data/relayer.db << EOF
SELECT bundle_id, retry_count, next_retry, last_error
FROM retry_state
WHERE next_retry < datetime('now')
ORDER BY next_retry;
EOF
```

### Reset Database
```bash
# CAREFUL: This deletes all history
rm data/relayer.db
```

## 8. Troubleshooting

### "Cannot connect to RPC"
- Check SEPOLIA_RPC_URL, AMOY_RPC_URL in .env
- Test: `curl -X POST $SEPOLIA_RPC_URL -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`

### "No events detected"
- Verify SXCPIntentHub contract address is correct
- Check contract is deployed on the chain
- Look for "Initialized on chain" log messages

### "PQC signing failed"
- Verify Aegis-PQVM is running on Synergy node
- Check PQC_ALGORITHM matches your key material
- Validate PQC_PUBLIC_KEY_B64 is properly base64 encoded

### "WebSocket disconnected"
- This is normal - relayer automatically falls back to polling
- Check logs for "WebSocket disconnected" followed by "Started polling"

### Database is locked
- Another instance may be running
- Check: `ps aux | grep node`
- If stale process: `kill -9 <PID>`
- Consider using systemd service for proper lifecycle

## 9. Production Deployment

### Option A: Systemd Service

Create `/etc/systemd/system/sxcp-relayer.service`:
```ini
[Unit]
Description=SXCP Relayer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sxcp
WorkingDirectory=/opt/sxcp-relayer
ExecStart=/usr/bin/node src/index.js
Restart=on-failure
RestartSec=10
Environment="NODE_ENV=production"
EnvironmentFile=/opt/sxcp-relayer/.env

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sxcp-relayer
sudo systemctl start sxcp-relayer
sudo systemctl status sxcp-relayer
```

View logs:
```bash
sudo journalctl -u sxcp-relayer -f
```

### Option B: Docker

```dockerfile
FROM node:20-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY src ./src

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "src/index.js"]
```

Build and run:
```bash
docker build -t sxcp-relayer .
docker run --env-file .env -v ./data:/app/data -v ./keys:/app/keys sxcp-relayer
```

### Option C: PM2

```bash
npm install -g pm2

pm2 start src/index.js --name sxcp-relayer --env production
pm2 save
pm2 startup

# Monitor
pm2 logs sxcp-relayer
pm2 monit
```

## 10. Performance Tips

### Database Optimization
```bash
# Periodic maintenance
sqlite3 data/relayer.db << EOF
PRAGMA optimize;
VACUUM;
EOF
```

### Network Optimization
- Use dedicated RPC endpoints (Alchemy, Infura, etc.)
- Set higher CONFIRMATION_BLOCKS for high-throughput chains
- Tune POLL_INTERVAL_MS based on block time

### Memory Tuning
- Increase SQLite cache: `PRAGMA cache_size = 10000;`
- Monitor with: `ps aux | grep node`

## 11. Monitoring & Alerts

### Key Metrics to Track
- Bundle submission rate (bundles/hour)
- Average finalization time (seconds)
- Signature collection efficiency (signatures/threshold)
- Retry rate (failed submissions %)
- Database size (data/relayer.db)

### Setup Alerts For
- Process down (systemd auto-restart)
- High error rate in logs
- Database growth > 1GB
- RPC endpoint failures
- Synergy connection loss

## Next Steps

1. Read full documentation: `README.md`
2. Test with mock chains first
3. Monitor carefully in production
4. Set up proper logging and alerting
5. Plan upgrade strategy

For issues: Check README.md troubleshooting section or contact team.
