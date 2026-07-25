# Synergy Testnet Startup Guide

## 📋 Table of Contents

1. [Quick Start](#quick-start)
2. [Building the Testnet](#building-the-testnet)
3. [Starting the Testnet](#starting-the-testnet)
4. [Working with Bootnodes](#working-with-bootnodes)
5. [Verifying Block Production](#verifying-block-production)
6. [Verifying Validator Activity](#verifying-validator-activity)
7. [Sending Test Transactions](#sending-test-transactions)
8. [Managing Multiple Nodes](#managing-multiple-nodes)
9. [Monitoring & Troubleshooting](#monitoring--troubleshooting)

---

## 🚀 Quick Start

### Prerequisites

- **Rust**: Latest stable toolchain (1.70+)
- **Operating System**: macOS, Linux, or Windows with WSL2
- **Hardware**: 4+ CPU cores, 8GB+ RAM
- **Ports**: 5622 (P2P), 5640 (RPC), 5660 (WebSocket), 6030 (Metrics)

### Installation

```bash
# Clone the repository (if not already done)
cd ~/Desktop/Synergy/synergy-testnet

# Install Rust if not installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

---

## 🔨 Building the Testnet

### Build the Binary

```bash
# Build in release mode for optimal performance
cargo build --release

# Verify the build
./target/release/synergy-testnet version
```

**Expected Output:**
```
Synergy Testnet Node v0.1.0
Build: 0.1.0 (darwin)
```

### Alternative: Using the Management Script

```bash
# Make the script executable
chmod +x testnet.sh

# Build using the script
./testnet.sh build
```

---

## ▶️ Starting the Testnet

### Method 1: Using Node Templates (Recommended)

The testnet supports multiple node types via templates:

```bash
# List available node templates
./target/release/synergy-testnet list-templates

# Start a validator node
./target/release/synergy-testnet start --node-type validator

# Start an oracle node
./target/release/synergy-testnet start --node-type oracle

# Start an RPC gateway node
./target/release/synergy-testnet start --node-type rpc-gateway
```

**Available Node Templates:**
- `validator` - Block validator node
- `oracle` - Oracle data provider
- `ai-inference` - AI inference node
- `compute` - Compute node
- `witness` - Witness node
- `rpc-gateway` - RPC gateway
- `relayer` - Cross-chain relayer
- And many more... (see `templates/` directory)

### Method 2: Using the Management Script

```bash
# Start a validator node
./testnet.sh start validator

# Check node status
./testnet.sh status

# View logs in real-time
./testnet.sh logs follow
```

### Method 3: Using Custom Configuration

```bash
# Start with a custom config file
./target/release/synergy-testnet start --config config/node_config.toml
```

---

## 🌐 Working with Bootnodes

### Understanding Bootnode Addresses

Bootnode addresses use the SNR protocol format:
```
snr://<synergy-address>@<ip>:<port>
```

**Current Testnet Bootnode:**
```
snr://sYnV5um22g62fwrnq6zh92msp9ek7lqrjrw3hpukd@bootnode1.synergy-network.io:5620
```

This is the RPC Gateway node that other nodes connect to initially.

### Viewing Bootnode Configuration

```bash
# Check network configuration
cat config/network-config.toml | grep bootnode

# View node identity (contains address)
cat testnet/rpc-gateway/node_identity.toml
```

### Creating New Bootnode Identities

If you need to generate new bootnode addresses:

#### Method 1: Generate Individual Node Keys

```bash
# Generate keys for a new node (Class 5 = RPC Gateway)
./target/release/synergy-testnet keygen --class 5 --output ./new-bootnode-keys

# The address will be printed to stdout
# Example output: sYnV5abc123def456...
```

**Node Classes:**
- Class 1: `sYnV1` - Validators
- Class 2: `sYnV2` - Reserved
- Class 3: `sYnV3` - Reserved
- Class 4: `sYnV4` - Relayers
- Class 5: `sYnV5` - RPC Gateways

#### Method 2: Generate Complete Testnet Identity Set

```bash
# Use the address generation engine
cd src/synergy-address-engine
cargo run

# Or use the testnet key generation tool
cd ../..
cargo run --bin generate_node_keys
```

This will regenerate all node identities in the `testnet/` directory.

### Updating Bootnode Configuration

After generating a new bootnode address:

1. **Update network configuration:**
   ```bash
   # Edit config/network-config.toml
   nano config/network-config.toml
   ```

   Update the bootnodes array:
   ```toml
   bootnodes = [
     "snr://YOUR-NEW-ADDRESS@YOUR-IP:5622"
   ]
   ```

2. **Update all template files:**
   ```bash
   # The generate_templates.sh script can help
   ./tools/generate_templates.sh
   ```

3. **Update genesis.json** (if needed):
   ```bash
   nano config/genesis.json
   # Update the rpc_gateway section with new address and public_key
   ```

---

## ✅ Verifying Block Production

### Method 1: Check Block Number via RPC

```bash
# Get current block number
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}'
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": 42
}
```

### Method 2: Get Latest Block Details

```bash
# Get the latest block
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getLatestBlock","params":[],"id":1}'
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "block_index": 42,
    "timestamp": 1701234567,
    "previous_hash": "0x...",
    "validator_id": "sYnV1...",
    "transactions": []
  }
}
```

### Method 3: Monitor Block Production in Real-Time

```bash
# Watch block production
watch -n 1 'curl -s -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_blockNumber\",\"params\":[],\"id\":1}" \
  | jq .result'
```

This will update every second showing the latest block number.

### Method 4: Check Node Logs

```bash
# View logs for block production messages
./testnet.sh logs follow | grep -i "block"

# Or directly:
tail -f data/logs/synergy-node.log | grep -i "block"
```

Look for messages like:
```
[INFO] consensus: Block #42 produced by sYnV1abc123...
[INFO] consensus: Block validated successfully
```

---

## 🔍 Verifying Validator Activity

### Check Active Validators

```bash
# Get list of active validators
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getValidators","params":[],"id":1}' | jq
```

### Check Specific Validator Details

```bash
# Get validator by address
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_getValidator",
    "params":["sYnV1jdy5tm3q8jhpf9adt5gzvp7ae6q96uzssuvk"],
    "id":1
  }' | jq
```

### Check Validator Activity and Performance

```bash
# Get detailed validator activity
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getValidatorActivity","params":[],"id":1}' | jq
```

**Expected Output:**
```json
{
  "validators": [
    {
      "address": "sYnV1jdy5tm3q8jhpf9adt5gzvp7ae6q96uzssuvk",
      "name": "Control Panel Node",
      "synergy_score": 85.5,
      "blocks_produced": 42,
      "uptime": "99.9%",
      "cluster_id": 1,
      "stake_amount": 1000
    }
  ],
  "total_active": 1,
  "average_synergy_score": 85.5
}
```

### Check Block Validation Status

```bash
# Get recent block validation info
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getBlockValidationStatus","params":[],"id":1}' | jq
```

### Monitor Validator Stats

```bash
# Get comprehensive validator statistics
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getValidatorStats","params":[],"id":1}' | jq
```

---

## 💸 Sending Test Transactions

### Step 1: Create a Wallet

```bash
# Create a new wallet
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_createWallet","params":[],"id":1}' | jq

# Save the returned address for later use
```

**Expected Output:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "address": "sYnS1abc123def456ghi789jkl012mno345pqr678",
    "message": "Wallet created successfully"
  }
}
```

### Step 2: Check Token Balance

```bash
# Check SNRG balance (native token)
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_getTokenBalance",
    "params":["sYnS1abc123def456ghi789jkl012mno345pqr678", "SNRG"],
    "id":1
  }' | jq
```

### Step 3: Send a Simple Token Transfer Transaction

```bash
# Transfer tokens between addresses
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_sendTokens",
    "params":[
      "sYnS1abc123...sender",
      "sYnS1def456...recipient",
      "SNRG",
      100
    ],
    "id":1
  }' | jq
```

### Step 4: Create and Send a Raw Transaction

```bash
# Create a transaction object
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_sendTransaction",
    "params":[{
      "from": "sYnS1abc123...sender",
      "to": "sYnS1def456...recipient",
      "amount": 100,
      "token": "SNRG",
      "nonce": 1,
      "timestamp": 1701234567
    }],
    "id":1
  }' | jq
```

### Step 5: Verify Transaction in Pool

```bash
# Check transaction pool
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getTransactionPool","params":[],"id":1}' | jq
```

### Quick Test Script

Create a file `test-transaction.sh`:

```bash
#!/bin/bash

RPC_URL="http://localhost:5640"

echo "1. Creating sender wallet..."
SENDER=$(curl -s -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_createWallet","params":[],"id":1}' \
  | jq -r '.result.address')
echo "Sender: $SENDER"

echo "2. Creating recipient wallet..."
RECIPIENT=$(curl -s -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_createWallet","params":[],"id":1}' \
  | jq -r '.result.address')
echo "Recipient: $RECIPIENT"

echo "3. Sending test transaction..."
curl -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d "{
    \"jsonrpc\":\"2.0\",
    \"method\":\"synergy_sendTokens\",
    \"params\":[\"$SENDER\", \"$RECIPIENT\", \"SNRG\", 100],
    \"id\":1
  }" | jq

echo "4. Checking transaction pool..."
curl -X POST $RPC_URL \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getTransactionPool","params":[],"id":1}' | jq
```

Make it executable and run:
```bash
chmod +x test-transaction.sh
./test-transaction.sh
```

---

## 🔧 Managing Multiple Nodes

### Running Multiple Node Types Simultaneously

Each node needs unique ports. You can run multiple nodes on the same machine:

#### Terminal 1: Start Validator Node
```bash
# Uses default ports from templates/validator.toml
./target/release/synergy-testnet start --node-type validator
```

#### Terminal 2: Start Oracle Node (different ports)
```bash
# Edit templates/oracle.toml to use different ports first
# Then start the oracle
./target/release/synergy-testnet start --node-type oracle
```

#### Terminal 3: Start RPC Gateway
```bash
./target/release/synergy-testnet start --node-type rpc-gateway
```

### Port Configuration for Multiple Nodes

When running multiple nodes, ensure each has unique ports:

| Node Type | P2P Port | RPC Port | WS Port | Metrics Port |
|-----------|----------|----------|---------|--------------|
| Validator-01 |  5622 | 5640 | 5660 | 6030 |
| Validator-02 | 33864 | 5624 | 5625 | 9091 |
| Oracle | 33865 | 5626 | 5627 | 9092 |
| RPC Gateway | 33866 | 5628 | 5629 | 9093 |

### Managing Node Processes

```bash
# List running nodes
ps aux | grep synergy-testnet

# Stop a specific node (find its PID first)
kill <PID>

# Stop all nodes
pkill synergy-testnet

# Or use the management script
./testnet.sh stop
```

---

## 📊 Monitoring & Troubleshooting

### Check Node Status

```bash
# Get comprehensive node information
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_nodeInfo","params":[],"id":1}' | jq
```

**Expected Output:**
```json
{
  "name": "Synergy Testnet Node",
  "version": "1.0.0",
  "protocolVersion": 1,
  "networkId": 1264,
  "chainId": 1264,
  "consensus": "Proof of Synergy",
  "syncing": false,
  "currentBlock": 42,
  "timestamp": 1701234567
}
```

### Check Network Statistics

```bash
# Get comprehensive network stats
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getNetworkStats","params":[],"id":1}' | jq
```

### View Real-Time Logs

```bash
# Follow logs
./testnet.sh logs follow

# Or directly
tail -f data/logs/synergy-node.log

# Filter for specific information
tail -f data/logs/synergy-node.log | grep -i "error"
tail -f data/logs/synergy-node.log | grep -i "block"
tail -f data/logs/synergy-node.log | grep -i "validator"
```

### Check Port Availability

```bash
# Check if ports are in use
lsof -i :5640  # RPC port
lsof -i : 5622  # P2P port
lsof -i :5660   # WebSocket port
lsof -i :6030   # Metrics port

# Or on Linux:
netstat -tulpn | grep -E '5622|33863|5660|6030'
```

### Check Prometheus Metrics

```bash
# View metrics endpoint
curl http://localhost:6030/metrics

# Get specific metrics
curl http://localhost:6030/metrics | grep synergy_
```

### Common Issues and Solutions

#### Issue: Port Already in Use
```bash
# Find what's using the port
lsof -i :5622

# Kill the process
kill -9 <PID>

# Or stop all Synergy nodes
pkill synergy-testnet
```

#### Issue: Node Won't Start
```bash
# Check logs for errors
cat data/logs/synergy-node.log

# Verify binary exists
ls -lh ./target/release/synergy-testnet

# Rebuild if necessary
cargo build --release
```

#### Issue: No Blocks Being Produced
```bash
# Check consensus logs
tail -f data/logs/synergy-node.log | grep consensus

# Verify validators are active
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getValidators","params":[],"id":1}' | jq

# Check if node is synced
curl -X POST http://localhost:5640 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_nodeInfo","params":[],"id":1}' | jq .result.syncing
```

#### Issue: RPC Connection Refused
```bash
# Check if RPC server is running
curl http://localhost:5640

# Verify node is running
ps aux | grep synergy-testnet

# Check firewall
sudo ufw status
```

### Clean Restart

If you need to completely reset the testnet:

```bash
# Stop the node
./testnet.sh stop

# Clean all data
./testnet.sh clean  # This will ask for confirmation

# Or manually:
rm -rf data/chain data/logs
rm -f data/synergy-testnet.pid

# Rebuild and restart
./testnet.sh build
./testnet.sh start validator
```

---

## 📝 Quick Reference Commands

### Essential Commands

```bash
# Build
cargo build --release

# Start validator
./target/release/synergy-testnet start --node-type validator

# Check block height
curl -s -X POST http://localhost:5640 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_blockNumber","params":[],"id":1}' | jq .result

# Get validators
curl -s -X POST http://localhost:5640 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_getValidators","params":[],"id":1}' | jq

# Create wallet
curl -s -X POST http://localhost:5640 -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_createWallet","params":[],"id":1}' | jq

# View logs
tail -f data/logs/synergy-node.log

# Stop node
pkill synergy-testnet
```

---

## 🔗 Related Documentation

- [Validator Guide](validator-guide.md) - Detailed validator setup for mainnet
- [API Reference](docs/api-reference.md) - Complete RPC API documentation
- [Configuration Guide](docs/config-guide.md) - Detailed configuration options
- [Token System](docs/token-system.md) - Token operations and management
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

---

## 🆘 Support

For issues or questions:
- GitHub Issues: [synergy-network/testnet](https://github.com/synergy-network/testnet/issues)
- Documentation: [docs/](docs/)
- Community: Discord, Forum, Telegram

---

**Happy Building! 🚀**
