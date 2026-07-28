# Synergy Testnet - Relayer Node Setup Guide
**For SXCP Bridgeless Cross-Chain Protocol**

---

## Overview

This guide explains how to set up **Relayer Nodes** for the **Synergy Cross-Chain Protocol (SXCP)** - a **bridgeless** cross-chain communication system. Unlike traditional bridge architectures that use smart contracts to lock funds, SXCP relayers facilitate direct message verification and state proofs between chains using post-quantum cryptographic verification.

### Key SXCP Characteristics

- **Bridgeless Architecture**: No bridge contracts holding locked funds
- **Direct Cryptographic Verification**: Uses ML-DSA signatures and Merkle proofs
- **Post-Quantum Secure**: Quantum-resistant message verification
- **Cluster-Based Relaying**: Multiple relayers form consensus clusters
- **State Proof Verification**: Relays cryptographic proofs, not tokens

### Relayer Node Purpose

Relayers in SXCP:
1. Monitor source chain for cross-chain messages
2. Verify message authenticity using ML-DSA signatures
3. Generate Merkle proofs of message inclusion
4. Submit verified messages to destination chain
5. Participate in relayer cluster consensus
6. Earn rewards for successful message delivery

---

## Prerequisites

### System Requirements (Per Relayer Node)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 16 GB | 32 GB |
| **Storage** | 500 GB SSD | 1 TB NVMe SSD |
| **Network** | 100 Mbps | 1 Gbps symmetric |
| **OS** | Ubuntu 22.04+ | Ubuntu 24.04 LTS |

### Network Requirements

**Incoming Ports:**
- **5622**: P2P (Synergy network)
- **5650**: Relayer cluster communication
- **5670**: Relayer RPC endpoint

**Outgoing Connections:**
- **Synergy Testnet**: Port 5622 to bootnodes
- **Sepolia Testnet**: Port 30303 (Ethereum P2P)
- **Target Testnet**: Chain-specific ports

### Required Accounts

For testnet testing, you'll need:
1. **Synergy Testnet Account**: For transaction fees and relayer registration
2. **Sepolia ETH**: For interacting with Sepolia testnet
3. **Target Chain Account**: For the second testnet you're integrating

---

## SXCP Architecture Overview

```
┌─────────────────────┐          ┌─────────────────────┐
│  Source Chain       │          │  Destination Chain  │
│  (e.g., Sepolia)    │          │  (Synergy Testnet)   │
│                     │          │                     │
│  User submits TX ───┼──┐    ┌──┼──→ Message verified │
│  with cross-chain   │  │    │  │     and executed    │
│  message            │  │    │  │                     │
└─────────────────────┘  │    │  └─────────────────────┘
                         │    │
                         ▼    ▼
                  ┌──────────────────┐
                  │ Relayer Cluster  │
                  │  (5 Relayers)    │
                  │                  │
                  │  • Monitor TX    │
                  │  • Verify Proof  │
                  │  • Submit to     │
                  │    Destination   │
                  │  • Cluster       │
                  │    Consensus     │
                  └──────────────────┘
```

### Bridgeless Verification Flow

1. **User Action**: User submits transaction on Source Chain with cross-chain intent
2. **Event Emission**: Source chain emits verifiable event with ML-DSA signature
3. **Relayer Monitoring**: Relayers detect event via RPC monitoring
4. **Proof Generation**: Relayer generates Merkle proof of event inclusion in source block
5. **Cluster Consensus**: Relayer cluster reaches consensus on proof validity (67% threshold)
6. **Destination Submission**: Lead relayer submits message + proof to destination chain
7. **On-Chain Verification**: Destination chain verifies proof cryptographically (no trust required)
8. **Execution**: Message executed on destination chain
9. **Relayer Rewards**: Successful relayers earn SNRG rewards

**No Bridge Contracts**: Funds never locked in intermediate contracts. Cryptographic proofs ensure authenticity.

---

## Setup Instructions for 5-Node Relayer Cluster

We'll set up **5 relayer nodes** to form a SXCP relayer cluster for testing.

---

## Step 1: Environment Setup (All 5 Nodes)

### On Each Relayer Server

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
  build-essential \
  pkg-config \
  libssl-dev \
  git \
  curl \
  jq \
  clang

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
cd ~
git clone https://github.com/synergy-network-hq/synergy-testnet.git
cd synergy-testnet

# Build binaries
cargo build --release
```

---

## Step 2: Generate Relayer Identities

### On Each Node (1-5)

Each relayer needs a unique identity with ML-DSA keypair.

```bash
# Build address engine if not already built
cd src/synergy-address-engine
cargo build --release
cd ../..

# Generate relayer identity (Class II node)
./src/synergy-address-engine/target/release/synergy-address-engine \
  --address-type relayer \
  --output config/relayer${NODE_NUMBER}/identity.json

# Example for node 1:
mkdir -p config/relayer1
./src/synergy-address-engine/target/release/synergy-address-engine \
  --address-type relayer \
  --output config/relayer1/identity.json
```

**Node Number Assignment:**
- Relayer 1: `NODE_NUMBER=1`
- Relayer 2: `NODE_NUMBER=2`
- Relayer 3: `NODE_NUMBER=3`
- Relayer 4: `NODE_NUMBER=4`
- Relayer 5: `NODE_NUMBER=5`

### Save Relayer Information

Each node should save its identity information:

```bash
# View and save your relayer info
cat config/relayer${NODE_NUMBER}/identity.json | jq

# Output example:
# {
#   "address": "synr1abc123def456...",  # Relayer address (synr prefix)
#   "public_key": "MIIBIjANBg...",
#   "private_key": "[REDACTED]",
#   "algorithm": "FN-DSA-1024",
#   "node_type": "Class II - Relayer"
# }
```

**Share with coordinator:**
- Relayer address (synr1...)
- Public key
- Server public IP

---

## Step 3: Configure Relayer Nodes

### Relayer 1 Configuration

Create `config/relayer1/node_config.toml`:

```toml
[node]
name = "SXCP Relayer 1"
node_type = "relayer"
identity_file = "config/relayer1/identity.json"
data_dir = "./data/relayer1"

[network]
id = 1266  # Synergy Testnet chain ID
p2p_port = 5622
rpc_port = 5650
ws_port = 5670

[p2p]
listen_address = "0.0.0.0:5622"
public_address = "RELAYER1_PUBLIC_IP:5622"

# Connect to Synergy bootnodes
bootnodes = [
  "snr://synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv@bootnode1.synergy-network.io:5620",
  "snr://synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04@bootnode2.synergy-network.io:5620",
  "snr://synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4@bootnode3.synergy-network.io:5620"
]

max_inbound_peers = 50
max_outbound_peers = 20

[relayer]
# Enable SXCP relaying
enabled = true
cluster_id = "sxcp-testnet-cluster-1"

# Relayer cluster members (will be populated after all identities generated)
cluster_members = [
  "synr1_RELAYER1_ADDRESS",
  "synr1_RELAYER2_ADDRESS",
  "synr1_RELAYER3_ADDRESS",
  "synr1_RELAYER4_ADDRESS",
  "synr1_RELAYER5_ADDRESS"
]

# Cluster consensus settings
cluster_threshold = 0.67  # required relayers = ceil(active relayer count * 67 / 100)

# Relayer cluster communication
cluster_rpc_port = 5650
cluster_bind = "0.0.0.0:5650"

# Other cluster member endpoints
cluster_peers = [
  "RELAYER2_PUBLIC_IP:5650",
  "RELAYER3_PUBLIC_IP:5650",
  "RELAYER4_PUBLIC_IP:5650",
  "RELAYER5_PUBLIC_IP:5650"
]

[sxcp]
# SXCP protocol configuration

# Source chains to monitor (Sepolia + one more testnet)
[[sxcp.source_chains]]
chain_id = 11155111  # Sepolia testnet
name = "sepolia"
rpc_endpoint = "https://ethereum-sepolia.publicnode.com"
ws_endpoint = "wss://ethereum-sepolia.publicnode.com"
confirmation_blocks = 12  # Wait for 12 confirmations
poll_interval_ms = 12000  # Poll every 12 seconds (Sepolia block time)

# Message verification
verification_type = "merkle_proof"  # Use Merkle proofs for verification
require_ml_dsa_signature = true     # Require post-quantum signatures

[[sxcp.source_chains]]
chain_id = 80002  # Polygon Amoy testnet (example)
name = "polygon-amoy"
rpc_endpoint = "https://rpc-amoy.polygon.technology"
ws_endpoint = "wss://polygon-amoy-bor-rpc.publicnode.com"
confirmation_blocks = 32
poll_interval_ms = 2000  # Polygon is faster

# Destination chain (Synergy Testnet)
[sxcp.destination]
chain_id = 1266
name = "synergy-testnet"
rpc_endpoint = "https://testnet-core-rpc.synergy-network.io"
ws_endpoint = "wss://testnet-core-ws.synergy-network.io"

# Local RPC if running validator/RPC node
local_rpc = "http://localhost:5640"

# Message submission settings
max_gas_price_gwei = 100  # Maximum gas to pay for submission
submission_timeout_secs = 60

[sxcp.verification]
# Cryptographic verification settings
signature_algorithm = "ML-DSA-87"  # NIST Level 5 post-quantum
merkle_tree_depth = 32
proof_cache_size_mb = 256

# Enable proof aggregation (multiple messages in one submission)
enable_proof_aggregation = true
max_messages_per_batch = 50

[sxcp.monitoring]
# Message monitoring settings
scan_from_block = "latest"  # Start from latest block (or specify number)
max_blocks_per_scan = 100
event_topics = [
  "CrossChainMessage",
  "CrossChainCall",
  "CrossChainTransfer"
]

[storage]
db_backend = "rocksdb"
db_path = "./data/relayer1/db"
pruning_enabled = true
pruning_keep_recent = 10000  # Keep recent 10k blocks

[logging]
level = "info"
log_file = "./data/logs/relayer1.log"
```

**Replace in config:**
- `RELAYER1_PUBLIC_IP` through `RELAYER5_PUBLIC_IP` with actual IPs
- `synr1_RELAYER1_ADDRESS` through `synr1_RELAYER5_ADDRESS` with actual addresses from step 2

### Replicate for Relayers 2-5

Create similar configs for relayers 2-5, changing:
- `name`: "SXCP Relayer 2", "SXCP Relayer 3", etc.
- `identity_file`: path to respective identity.json
- `data_dir`: "./data/relayer2", "./data/relayer3", etc.
- `public_address`: Each relayer's own public IP
- `cluster_peers`: List other 4 relayers (exclude self)
- `log_file`: "./data/logs/relayer2.log", etc.

---

## Step 4: Request SNRG Tokens (All Relayers)

Each relayer needs SNRG tokens for:
- Relayer registration on-chain
- Transaction fees for message submission
- Cluster participation bonds

### Generate Relayer Info File

On each node:

```bash
cat > relayer${NODE_NUMBER}-info.txt <<EOF
Relayer Registration Information
==================================

Relayer Number: ${NODE_NUMBER}
Relayer Address: $(jq -r '.address' config/relayer${NODE_NUMBER}/identity.json)
Public Key: $(jq -r '.public_key' config/relayer${NODE_NUMBER}/identity.json)
Algorithm: FN-DSA-1024
Node Type: Class II Relayer (SXCP)
Server IP: $(curl -s ifconfig.me)
Cluster: sxcp-testnet-cluster-1
Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

cat relayer${NODE_NUMBER}-info.txt
```

### Send to Coordinator

Share `relayer${NODE_NUMBER}-info.txt` with the testnet coordinator who will:
1. Register your relayer on-chain
2. Send initial SNRG allocation (recommended: 100,000 SNRG per relayer)
3. Add relayer to cluster registry

---

## Step 5: Configure Sepolia Testnet Access

### Get Sepolia ETH

Each relayer needs Sepolia ETH for monitoring (no transactions needed, just RPC access).

**Public Sepolia RPC** (already configured):
- `https://ethereum-sepolia.publicnode.com`
- `wss://ethereum-sepolia.publicnode.com`

**Alternative**: Run your own Sepolia archive node (optional, for production)

### Verify Sepolia Connection

```bash
# Test Sepolia RPC
curl -X POST https://ethereum-sepolia.publicnode.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_blockNumber",
    "params": [],
    "id": 1
  }' | jq

# Expected: Current Sepolia block number
```

---

## Step 6: Configure Second Testnet (Polygon Amoy Example)

The configuration already includes Polygon Amoy as a second testnet. You can replace with any EVM-compatible testnet.

### Alternative Testnets

**Arbitrum Sepolia:**
```toml
[[sxcp.source_chains]]
chain_id = 421614
name = "arbitrum-sepolia"
rpc_endpoint = "https://sepolia-rollup.arbitrum.io/rpc"
ws_endpoint = "wss://sepolia-rollup.arbitrum.io/rpc"
confirmation_blocks = 10
poll_interval_ms = 3000
```

**Optimism Sepolia:**
```toml
[[sxcp.source_chains]]
chain_id = 11155420
name = "optimism-sepolia"
rpc_endpoint = "https://sepolia.optimism.io"
ws_endpoint = "wss://sepolia.optimism.io"
confirmation_blocks = 10
poll_interval_ms = 2000
```

**Base Sepolia:**
```toml
[[sxcp.source_chains]]
chain_id = 84532
name = "base-sepolia"
rpc_endpoint = "https://sepolia.base.org"
ws_endpoint = "wss://sepolia.base.org"
confirmation_blocks = 10
poll_interval_ms = 2000
```

---

## Step 7: Firewall Configuration (All Nodes)

```bash
# SSH
sudo ufw allow 22/tcp

# Synergy P2P
sudo ufw allow 5622/tcp

# Relayer cluster communication
sudo ufw allow 5650/tcp

# Relayer RPC
sudo ufw allow 5670/tcp

# Enable firewall
sudo ufw enable
sudo ufw status
```

---

## Step 8: Start Relayer Nodes

### Start Relayer 1

```bash
# Create data directories
mkdir -p data/relayer1 data/logs

# Start relayer
./target/release/synergy-testnet relayer start \
  --config config/relayer1/node_config.toml
```

### Expected Output

```
[INFO] Synergy SXCP Relayer starting...
[INFO] Relayer Address: synr1abc123...
[INFO] Cluster ID: sxcp-testnet-cluster-1
[INFO] Cluster Members: 5 relayers
[INFO] Cluster Threshold: 67% (4/5 signatures required)
[INFO] Connecting to Synergy bootnodes...
[INFO] Connected to bootnode1.synergy-network.io:5620
[INFO] Syncing Synergy blockchain...
[INFO] Current block: 15432
[INFO] Starting SXCP monitoring...
[INFO] Monitoring Sepolia (chain 11155111) from block 5234567
[INFO] Monitoring Polygon Amoy (chain 80002) from block 8765432
[INFO] Relayer cluster RPC listening on 0.0.0.0:5650
[INFO] Waiting for cluster quorum...
[INFO] Cluster status: 1/5 relayers online
```

### Start Relayers 2-5

Repeat on each server with respective configs:

```bash
# Relayer 2
./target/release/synergy-testnet relayer start --config config/relayer2/node_config.toml

# Relayer 3
./target/release/synergy-testnet relayer start --config config/relayer3/node_config.toml

# Relayer 4
./target/release/synergy-testnet relayer start --config config/relayer4/node_config.toml

# Relayer 5
./target/release/synergy-testnet relayer start --config config/relayer5/node_config.toml
```

Once all 5 are online:

```
[INFO] Cluster status: 5/5 relayers online ✅
[INFO] Cluster quorum achieved (67% threshold met)
[INFO] SXCP relaying active - monitoring for cross-chain messages
```

---

## Step 9: Verify Cluster Formation

### Check Cluster Status

From any relayer node:

```bash
curl -s -X POST http://localhost:5650/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sxcp_clusterStatus",
    "id": 1
  }' | jq

# Expected output:
# {
#   "result": {
#     "cluster_id": "sxcp-testnet-cluster-1",
#     "total_members": 5,
#     "online_members": 5,
#     "threshold": 0.67,
#     "quorum_met": true,
#     "leader": "synr1abc123...",
#     "members": [
#       {"address": "synr1...", "status": "online", "last_seen": 1234567890},
#       ...
#     ]
#   }
# }
```

### Test Cross-Chain Monitoring

```bash
# Check monitored chains
curl -s -X POST http://localhost:5650/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sxcp_getMonitoredChains",
    "id": 1
  }' | jq

# Check recent messages detected
curl -s -X POST http://localhost:5650/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sxcp_getRecentMessages",
    "params": [{"limit": 10}],
    "id": 1
  }' | jq
```

---

## Step 10: Configure as Systemd Service

### Create Service File (Each Node)

```bash
sudo nano /etc/systemd/system/synergy-relayer.service
```

```ini
[Unit]
Description=Synergy SXCP Relayer Node ${NODE_NUMBER}
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/home/YOUR_USERNAME/synergy-testnet
ExecStart=/home/YOUR_USERNAME/synergy-testnet/target/release/synergy-testnet relayer start --config config/relayer${NODE_NUMBER}/node_config.toml
Restart=on-failure
RestartSec=10
StandardOutput=append:/home/YOUR_USERNAME/synergy-testnet/data/logs/relayer${NODE_NUMBER}.log
StandardError=append:/home/YOUR_USERNAME/synergy-testnet/data/logs/relayer${NODE_NUMBER}-error.log

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable synergy-relayer
sudo systemctl start synergy-relayer
sudo systemctl status synergy-relayer
```

---

## Testing SXCP Cross-Chain Messages

### Test Message Flow

You'll need to submit a cross-chain message from Sepolia that the relayers will detect and relay to Synergy Testnet.

**Message Flow:**
1. Deploy test contract on Sepolia
2. Emit cross-chain event
3. Relayers detect event
4. Relayers generate Merkle proof
5. Relayers reach cluster consensus
6. Leader submits to Synergy Testnet
7. Synergy verifies proof and executes

### Monitor Relayer Activity

```bash
# Watch logs for message detection
tail -f data/logs/relayer1.log | grep "CrossChainMessage"

# Check message queue
curl -s -X POST http://localhost:5650/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sxcp_getPendingMessages",
    "id": 1
  }' | jq

# Check relayer statistics
curl -s -X POST http://localhost:5650/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "sxcp_getRelayerStats",
    "params": ["synr1YOUR_RELAYER_ADDRESS"],
    "id": 1
  }' | jq
```

---

## Cluster Leader Selection

The relayer cluster uses **PoSy consensus** to select leaders for message submission:

1. **Synergy Score telemetry**: Each relayer may expose an observational Synergy Score based on:
   - Successful message relays
   - Uptime and reliability
   - Cluster participation

2. **Leader Selection**: The protocol's consensus rules choose the leader. Synergy Score telemetry does not affect leader selection, quorum, or eligibility.

3. **Leader Rotation**: Leader changes each epoch (~1 hour) to ensure fairness

4. **Backup Leaders**: 2-3 backup leaders selected automatically

---

## Relayer Rewards

Relayers earn SNRG rewards for successful message delivery:

**Reward Structure:**
- **Base reward**: 10 SNRG per message
- **Complexity bonus**: Up to 50 SNRG for complex proofs
- **Speed bonus**: 2x multiplier for fast relay (< 5 min)
- **Cluster bonus**: Rewards split among all cluster members who participated

**Example:**
- Message relayed in 3 minutes with complex proof
- Base: 10 SNRG
- Complexity: +20 SNRG
- Speed bonus: 2x = 60 SNRG total
- Split among 5 relayers = 12 SNRG each

---

## Monitoring & Maintenance

### Health Check Script

Create `scripts/relayer-health-check.sh`:

```bash
#!/bin/bash

RELAYER_RPC="http://localhost:5650/rpc"

echo "=== SXCP Relayer Health Check ==="

# Check cluster status
CLUSTER_STATUS=$(curl -s -X POST "$RELAYER_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sxcp_clusterStatus","id":1}' \
  | jq -r '.result.quorum_met')

if [ "$CLUSTER_STATUS" == "true" ]; then
    echo "✅ Cluster quorum: ACTIVE"
else
    echo "❌ Cluster quorum: FAILED"
    exit 1
fi

# Check monitored chains
SEPOLIA=$(curl -s -X POST "$RELAYER_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sxcp_getChainStatus","params":["sepolia"],"id":1}' \
  | jq -r '.result.synced')

echo "📡 Sepolia monitoring: $SEPOLIA"

# Check pending messages
PENDING=$(curl -s -X POST "$RELAYER_RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"sxcp_getPendingMessages","id":1}' \
  | jq -r '.result | length')

echo "📬 Pending messages: $PENDING"

echo "✅ Relayer health check complete"
```

---

## Troubleshooting

### Cluster Quorum Not Met

**Problem**: Less than 67% of relayers online

**Solution:**
1. Check all 5 relayers are running
2. Verify network connectivity between relayers
3. Check firewall allows port 5650
4. Verify `cluster_peers` configured correctly

### Not Detecting Sepolia Messages

**Problem**: Relayer not monitoring Sepolia events

**Solution:**
1. Verify Sepolia RPC endpoint is responding
2. Check `scan_from_block` is set correctly
3. Ensure `event_topics` match your contract events
4. Monitor logs: `tail -f data/logs/relayer1.log | grep Sepolia`

### Message Submission Failing

**Problem**: Cannot submit messages to Synergy Testnet

**Solution:**
1. Check relayer has sufficient SNRG for gas fees
2. Verify connection to Synergy RPC
3. Check nonce synchronization
4. Review error logs for specific failure reason

---

## Security Considerations

1. **Private Keys**: Protect `identity.json` files (chmod 600)
2. **RPC Endpoints**: Use authenticated RPC endpoints for production
3. **Rate Limiting**: Configure to prevent DoS attacks
4. **Cluster Authentication**: All cluster messages ML-DSA signed
5. **Proof Verification**: Always verify Merkle proofs before submission
6. **Gas Limits**: Set reasonable max gas to prevent fund drainage

---

## Cluster Coordination

The 5-relayer cluster operates using **PoSy consensus**:

### Cluster Consensus Process

1. **Message Detection**: Any relayer detecting a message broadcasts to cluster
2. **Proof Generation**: Each relayer independently generates Merkle proof
3. **Proof Sharing**: Relayers share proofs via cluster RPC
4. **Verification**: Each relayer verifies others' proofs
5. **Voting**: Relayers vote on proof validity (ML-DSA signed votes)
6. **Quorum Check**: Requires `ceil(active_relayer_count * 67 / 100)` agreement
7. **Submission**: Leader submits proof to destination chain
8. **Confirmation**: All relayers monitor submission success

### Cluster Communication

Relayers communicate via authenticated P2P:
- **Message Format**: JSON-RPC over TCP
- **Authentication**: ML-DSA signatures on all messages
- **Encryption**: TLS 1.3 with post-quantum ciphersuites
- **Heartbeats**: Every 10 seconds to detect offline nodes

---

## Performance Optimization

### For High-Volume Relaying

```toml
[sxcp.verification]
# Increase cache for better performance
proof_cache_size_mb = 1024

# Enable batching
enable_proof_aggregation = true
max_messages_per_batch = 100

[storage]
# Faster database settings
cache_size_mb = 2048
write_buffer_size_mb = 256
```

### For Low-Latency

```toml
[sxcp.source_chains]
# Reduce polling interval
poll_interval_ms = 1000  # Poll every second

[sxcp.destination]
# Reduce submission timeout
submission_timeout_secs = 30
```

---

## Next Steps

1. **Monitor cluster performance** using health checks
2. **Test cross-chain messages** from Sepolia to Synergy
3. **Optimize relayer settings** based on message volume
4. **Join relayer coordinator channel** for cluster coordination
5. **Track rewards** and relayer statistics

---

**Your SXCP relayer cluster is operational! 🚀**

The bridgeless architecture ensures secure cross-chain communication without custodial risks.

For questions or support, reach out to the Synergy development team.
