# Synergy Testnet - RPC Node Setup Guide
**For Setting Up Remote RPC Nodes**

---

## Overview

This guide explains how to set up a dedicated RPC node on a remote system. RPC nodes serve the Synergy network by providing high-availability JSON-RPC endpoints for clients, wallets, dApps, and developers.

### RPC Node Characteristics

- **Purpose**: Provide JSON-RPC and WebSocket endpoints for blockchain queries
- **Does NOT participate in consensus**: No validator requirements
- **Syncs full blockchain state**: Requires substantial disk space
- **High bandwidth**: Serves many concurrent client requests
- **Optional indexing**: Can maintain transaction index for historical queries

---

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32+ GB |
| **Storage** | 500 GB SSD | 1 TB+ NVMe SSD |
| **Network** | 100 Mbps | 1 Gbps |
| **OS** | Ubuntu 22.04+ | Ubuntu 24.04 LTS |

### Network Requirements

**Incoming Ports:**
- **5640**: HTTP RPC endpoint
- **5660**: WebSocket endpoint

**Outgoing Ports:**
- **5622**: P2P connection to bootnodes

---

## Step 1: Environment Setup

### Clone Repository

```bash
# Install dependencies
sudo apt update && sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  git \
  curl \
  jq

# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone Synergy Testnet
cd ~
git clone https://github.com/synergy-network-hq/synergy-testnet.git
cd synergy-testnet
```

### Build Binaries

```bash
# Build the node binary
cargo build --release

# Verify build
./target/release/synergy-testnet --version
```

---

## Step 2: Node Configuration

### Create RPC Node Configuration

```bash
# Create config directory
mkdir -p config/rpc-node

# Copy RPC node template
cp templates/rpc.toml config/rpc-node/node_config.toml
```

### Edit Configuration

Edit `config/rpc-node/node_config.toml`:

```toml
[node]
name = "My RPC Node"
node_type = "rpc"  # Class II node (no consensus participation)
data_dir = "./data/rpc-node"

[network]
id = 1264  # Testnet chain ID
p2p_port = 5622
rpc_port = 5640
ws_port = 5660

[p2p]
# Listen on all interfaces for P2P sync
listen_address = "0.0.0.0:5622"

# Your public IP or DNS (for peer discovery)
# Replace with your actual public IP or domain
public_address = "YOUR_PUBLIC_IP:5622"

# Connect to testnet bootnodes
bootnodes = [
  "snr://synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv@bootnode1.synergy-network.io:5620",
  "snr://synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04@bootnode2.synergy-network.io:5620",
  "snr://synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4@bootnode3.synergy-network.io:5620"
]

# Peer limits
max_inbound_peers = 50
max_outbound_peers = 20

[rpc]
# Enable HTTP RPC
enabled = true
http_port = 5640
bind_address = "0.0.0.0:5640"  # Bind to all interfaces

# Enable WebSocket
ws_enabled = true
ws_port = 5660
ws_bind_address = "0.0.0.0:5660"

# CORS settings (adjust for your use case)
cors_origins = ["*"]  # For testnet - restrict in production!

# Rate limiting
max_connections = 1000
request_timeout_secs = 30

# Batch request limits
max_batch_size = 100

[sync]
# Full sync with all state
sync_mode = "full"  # Options: "full", "fast", "light"

# Start from genesis
start_from_genesis = false  # Sync from bootnodes

[storage]
# Database backend
db_backend = "rocksdb"
db_path = "./data/rpc-node/db"

# State pruning (disable for RPC nodes)
pruning_enabled = false  # Keep full historical state

# Transaction indexing
tx_index_enabled = true  # Enable tx lookups by hash

[logging]
level = "info"  # Options: "trace", "debug", "info", "warn", "error"
log_file = "./data/logs/rpc-node.log"
```

**Important:** Replace `YOUR_PUBLIC_IP` with your actual server's public IP address or domain name.

---

## Step 3: Firewall Configuration

### UFW Firewall Setup

```bash
# Allow SSH (if not already allowed)
sudo ufw allow 22/tcp

# Allow P2P
sudo ufw allow 5622/tcp

# Allow RPC HTTP
sudo ufw allow 5640/tcp

# Allow RPC WebSocket
sudo ufw allow 5660/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

---

## Step 4: Start RPC Node

### Initial Sync

```bash
# Create data directory
mkdir -p data/rpc-node data/logs

# Start node
./target/release/synergy-testnet node start \
  --config config/rpc-node/node_config.toml
```

### Expected Output

```
[INFO] Synergy RPC Node starting...
[INFO] Chain ID: 1264 (Testnet)
[INFO] P2P listening on 0.0.0.0:5622
[INFO] RPC HTTP listening on 0.0.0.0:5640
[INFO] RPC WebSocket listening on 0.0.0.0:5660
[INFO] Connecting to bootnodes...
[INFO] Connected to bootnode1.synergy-network.io:5620
[INFO] Connected to bootnode2.synergy-network.io:5620
[INFO] Starting blockchain sync...
[INFO] Current block: 0 / Network height: 15234
[INFO] Syncing... (Block 1523 / 15234 - 10%)
```

**Note:** Initial sync may take several hours depending on blockchain size and network speed.

---

## Step 5: Verify RPC Functionality

### Test RPC Endpoint

```bash
# Get current block height
curl -X POST http://YOUR_PUBLIC_IP:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "chain_getBlockHeight",
    "id": 1
  }' | jq

# Expected response:
# {
#   "jsonrpc": "2.0",
#   "result": {
#     "height": 15234
#   },
#   "id": 1
# }
```

### Test WebSocket Endpoint

```bash
# Install websocat for WebSocket testing
cargo install websocat

# Subscribe to new blocks
echo '{"jsonrpc":"2.0","method":"chain_subscribeNewHeads","id":1}' | \
  websocat ws://YOUR_PUBLIC_IP:5660

# Expected: Stream of new block headers as they arrive
```

### Additional RPC Methods

```bash
# Get account balance
curl -s -X POST http://YOUR_PUBLIC_IP:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "account_getBalance",
    "params": ["synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07"],
    "id": 1
  }' | jq

# Get transaction by hash
curl -s -X POST http://YOUR_PUBLIC_IP:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tx_getByHash",
    "params": ["TX_HASH_HERE"],
    "id": 1
  }' | jq

# Get peer count
curl -s -X POST http://YOUR_PUBLIC_IP:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "net_peerCount",
    "id": 1
  }' | jq
```

---

## Step 6: Configure as Systemd Service

### Create Service File

```bash
sudo nano /etc/systemd/system/synergy-rpc.service
```

Add the following content:

```ini
[Unit]
Description=Synergy Testnet RPC Node
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/synergy-testnet
ExecStart=/home/YOUR_USERNAME/synergy-testnet/target/release/synergy-testnet node start --config config/rpc-node/node_config.toml
Restart=on-failure
RestartSec=10
StandardOutput=append:/home/YOUR_USERNAME/synergy-testnet/data/logs/rpc-node.log
StandardError=append:/home/YOUR_USERNAME/synergy-testnet/data/logs/rpc-node-error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

**Replace:**
- `YOUR_USERNAME` with your actual Linux username
- Paths if you installed in a different location

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable synergy-rpc

# Start service
sudo systemctl start synergy-rpc

# Check status
sudo systemctl status synergy-rpc

# View logs
sudo journalctl -u synergy-rpc -f
```

---

## Step 7: Monitoring & Maintenance

### Monitor Sync Progress

```bash
# Check sync status
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sync_status","id":1}' | jq
```

### Monitor Resource Usage

```bash
# CPU and memory
htop

# Disk usage
df -h ./data/rpc-node

# Disk I/O
iotop
```

### Log Rotation

Create `/etc/logrotate.d/synergy-rpc`:

```
/home/YOUR_USERNAME/synergy-testnet/data/logs/rpc-node*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 YOUR_USERNAME YOUR_USERNAME
}
```

### Health Check Script

Create `scripts/rpc-health-check.sh`:

```bash
#!/bin/bash
# RPC Node Health Check

RPC_ENDPOINT="http://localhost:5640/rpc"

# Check if RPC is responding
HEIGHT=$(curl -s -X POST "$RPC_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHeight","id":1}' \
  | jq -r '.result.height // "error"')

if [ "$HEIGHT" == "error" ]; then
    echo "❌ RPC node is not responding!"
    exit 1
fi

echo "✅ RPC node is healthy - Block height: $HEIGHT"

# Check peer count
PEERS=$(curl -s -X POST "$RPC_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","id":1}' \
  | jq -r '.result.count // 0')

echo "📡 Connected peers: $PEERS"

if [ "$PEERS" -lt 3 ]; then
    echo "⚠️  Low peer count!"
fi
```

Make executable:

```bash
chmod +x scripts/rpc-health-check.sh
```

Add to cron for periodic checks:

```bash
# Run every 5 minutes
*/5 * * * * /home/YOUR_USERNAME/synergy-testnet/scripts/rpc-health-check.sh >> /home/YOUR_USERNAME/synergy-testnet/data/logs/health-check.log 2>&1
```

---

## Step 8: Optional - Enable HTTPS

For production RPC nodes, use HTTPS with Let's Encrypt.

### Install Nginx

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Configure Nginx Reverse Proxy

Create `/etc/nginx/sites-available/synergy-rpc`:

```nginx
server {
    listen 80;
    server_name YOUR_DOMAIN.com;

    location / {
        proxy_pass http://localhost:5640;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /ws {
        proxy_pass http://localhost:5660;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Enable site and get SSL certificate:

```bash
sudo ln -s /etc/nginx/sites-available/synergy-rpc /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Get SSL certificate
sudo certbot --nginx -d YOUR_DOMAIN.com
```

---

## Available RPC Methods

### Chain Queries

| Method | Description |
|--------|-------------|
| `chain_getBlockHeight` | Get current block height |
| `chain_getBlockByNumber` | Get block by number |
| `chain_getBlockByHash` | Get block by hash |
| `chain_getLatestBlock` | Get most recent block |

### Account Queries

| Method | Description |
|--------|-------------|
| `account_getBalance` | Get account balance |
| `account_getNonce` | Get account nonce |
| `account_getTransactions` | Get account transaction history |

### Transaction Queries

| Method | Description |
|--------|-------------|
| `tx_getByHash` | Get transaction by hash |
| `tx_send` | Submit signed transaction |
| `tx_estimateFee` | Estimate transaction fee |

### Network Queries

| Method | Description |
|--------|-------------|
| `net_peerCount` | Get connected peer count |
| `net_peerInfo` | Get peer information |
| `net_version` | Get network version |

### Validator Queries

| Method | Description |
|--------|-------------|
| `validator_getAll` | Get all validators |
| `validator_getInfo` | Get specific validator info |
| `synergy_getScore` | Get validator Synergy Score |

### WebSocket Subscriptions

| Method | Description |
|--------|-------------|
| `chain_subscribeNewHeads` | Subscribe to new blocks |
| `tx_subscribe` | Subscribe to transactions |
| `logs_subscribe` | Subscribe to contract logs |

---

## Troubleshooting

### Node Won't Start

**Check configuration syntax:**
```bash
./target/release/synergy-testnet node validate-config \
  --config config/rpc-node/node_config.toml
```

**Check port availability:**
```bash
sudo netstat -tulpn | grep -E "5622|5640|5660"
```

### Cannot Connect to Bootnodes

**Check DNS resolution:**
```bash
nslookup bootnode1.synergy-network.io
nslookup bootnode2.synergy-network.io
nslookup bootnode3.synergy-network.io
```

**Test connectivity:**
```bash
nc -zv bootnode1.synergy-network.io 5622
```

### Sync is Slow

- Increase `max_outbound_peers` in config
- Ensure SSD storage (not HDD)
- Check network bandwidth
- Verify sufficient RAM available

### RPC Requests Timing Out

- Increase `request_timeout_secs` in config
- Check database performance
- Monitor CPU/RAM usage
- Consider rate limiting clients

---

## Security Best Practices

1. **Firewall**: Only expose necessary ports (5640, 5660, 5622)
2. **CORS**: Restrict `cors_origins` to trusted domains in production
3. **Rate Limiting**: Configure `max_connections` and request limits
4. **DDoS Protection**: Use Cloudflare or similar CDN for public endpoints
5. **Monitoring**: Set up alerts for unusual traffic patterns
6. **Updates**: Regularly update to latest Synergy release
7. **Backups**: Backup critical configuration files

---

## Performance Tuning

### Database Optimization

```toml
[storage]
# Increase cache size (default 512 MB)
cache_size_mb = 2048

# Increase write buffer
write_buffer_size_mb = 256

# Parallel compaction
max_background_jobs = 4
```

### Network Optimization

```toml
[p2p]
# Increase peer limits for better connectivity
max_inbound_peers = 100
max_outbound_peers = 50

# Increase message buffer
message_buffer_size = 10240
```

---

## Next Steps

1. **Monitor performance** using health check script
2. **Join Synergy Discord** for RPC operator support
3. **Consider** running multiple RPC nodes with load balancer for redundancy
4. **Share** your RPC endpoint with the Synergy community (optional)

---

**Your RPC node is now operational! 🚀**

For questions or support, reach out to the Synergy development team.
