# Synergy Testnet - Team Validator Onboarding Guide
**For Team Members Setting Up Remote Validator Nodes**

> Current post-fork onboarding requires the Synergy Node Control Panel flow, explicit FN-DSA validator keys, and `50,000 SNRG` bonded stake. This legacy guide is retained for historical context; use `guides/CONTROL_PANEL_INSTALL_AND_NEW_VALIDATOR_ONBOARDING.md` for launch-current validator setup.

---

## 🎯 Purpose

This guide is specifically for Synergy team members who want to set up their own validator nodes on remote systems to participate in the Testnet. Unlike bootnode validators that are included in the genesis block, your validator will:

1. ✅ Connect to the existing running blockchain
2. ✅ Sync with the network from current state
3. ✅ Register as a validator dynamically (not in genesis)
4. ✅ Have a Synergy Score calculated based on participation
5. ✅ Receive SNRG tokens manually from the coordinator
6. ✅ Bond the launch-current **50,000 SNRG minimum stake** before activation

---

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu 20.04 LTS or later (22.04 LTS recommended)
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Storage**: 100+ GB SSD
- **Network**: Stable internet connection, static IP or dynamic DNS

### Required Open Ports
- **5622/tcp** - P2P (SNR Gossip Protocol)
- **5640/tcp** - RPC (optional, for monitoring)
- **5660/tcp** - WebSocket (optional)
- **6030/tcp** - Metrics (optional, localhost only)

---

## 🚀 Step 1: Environment Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y build-essential pkg-config libssl-dev git curl jq

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup default stable

# Verify installation
rustc --version
cargo --version

# Create working directory
mkdir -p ~/synergy
cd ~/synergy
```

---

## 📦 Step 2: Clone and Build Synergy Testnet

```bash
# Clone the repository
git clone https://github.com/synergy-network-hq/synergy-testnet.git
cd synergy-testnet

# Build the node binary
cargo build --release

# Build the address engine
cd src/synergy-address-engine
cargo build --release
cd ../..

# Verify builds
./target/release/synergy-testnet --version
./target/release/synergy-address-engine --help
```

**Expected build time:** 10-30 minutes depending on your system.

---

## 🔑 Step 3: Generate Your Validator Identity

Your validator identity consists of:
- **Validator Address** (lowercase, starts with `synv1`)
- **Public Key** (FN-DSA-1024, 1793 bytes)
- **Private Key** (FN-DSA-1024, 2305 bytes) - **KEEP SECRET!**

```bash
# Create validator config directory
mkdir -p config/my-validator

# Generate your validator identity
./target/release/synergy-address-engine \
  --node-type validator \
  --output config/my-validator/identity.json

# The output will look like:
# 🔐 Synergy Network Address Engine - FN-DSA-1024 (NIST Level 5)
#
# Generating NodeClass1 identity...
#
# ✅ Identity Generated Successfully!
#
# Address:      synv1abc123def456...
# Algorithm:    FN-DSA-1024
# Type:         NodeClass1
# Public Key:   1793 bytes
# Private Key:  2305 bytes
# Created:      2025-12-06T...
#
# ⚠️  SECURITY WARNING:
#    Store the private key securely and never share it!

# Set proper permissions
chmod 600 config/my-validator/identity.json

# Extract and display your validator info
VALIDATOR_ADDRESS=$(jq -r '.address' config/my-validator/identity.json)
VALIDATOR_PUBKEY=$(jq -r '.public_key' config/my-validator/identity.json)

echo "================================"
echo "YOUR VALIDATOR INFORMATION"
echo "================================"
echo "Address: $VALIDATOR_ADDRESS"
echo ""
echo "Public Key (first 64 chars):"
echo "$VALIDATOR_PUBKEY" | head -c 64
echo "..."
echo ""
echo "⚠️  SAVE THIS INFORMATION!"
echo "================================"

# Save to a file for easy sharing
cat > config/my-validator/validator-info.txt <<EOF
Validator Registration Information
===================================

Validator Address: $VALIDATOR_ADDRESS
Public Key: $VALIDATOR_PUBKEY
Algorithm: FN-DSA-1024
Node Type: Class 1 Validator
Server IP: $(curl -s ifconfig.me)
Operator: $(whoami)
Generated: $(date)

SHARE THIS FILE (NOT identity.json!) WITH THE TESTNET COORDINATOR
EOF

echo ""
echo "✅ Validator info saved to: config/my-validator/validator-info.txt"
```

---

## 📡 Step 4: Configure Your Validator Node

Create your node configuration file:

```bash
# Create validator configuration
cat > config/my-validator-config.toml <<'EOF'
[network]
node_name = "my-validator"
listen_address = "0.0.0.0:5622"
public_address = "YOUR_IP_OR_DOMAIN:5622"  # CHANGE THIS!
bootnodes = [
  "snr://synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv@bootnode1.synergy-network.io:5620",
  "snr://synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04@bootnode2.synergy-network.io:5620",
  "snr://synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4@bootnode3.synergy-network.io:5620"
]

[validator]
address = "VALIDATOR_ADDRESS_HERE"  # Will be auto-filled
identity_file = "config/my-validator/identity.json"
enabled = true
name = "My Testnet Validator"
auto_register = true
min_stake = 0  # No stake required for testnet onboarding

[consensus]
algorithm = "PoSy"
block_time_secs = 3
max_validators = 4
synergetic_mode = true
vrf_enabled = true

[blockchain]
chain_id = 1264
sync_mode = "fast"  # Fast sync from existing blockchain
start_from_genesis = false

[rpc]
http_port = 5640
ws_port = 5660
enable_cors = true
external_http = "https://testnet-core-rpc.synergy-network.io"
external_ws = "wss://testnet-core-ws.synergy-network.io"

[logging]
log_level = "info"
log_file = "data/logs/my-validator.log"
enable_console = true

[node]
role = "validator"
enable_rpc = true
enable_metrics = true
metrics_port = 6030

[synergy_score]
enabled = true
initial_score = 0.0
participation_weight = 0.40
uptime_weight = 0.30
accuracy_weight = 0.30
EOF

# Auto-fill your validator address
sed -i "s/VALIDATOR_ADDRESS_HERE/$VALIDATOR_ADDRESS/g" config/my-validator-config.toml

# Update with your server's public IP
YOUR_IP=$(curl -s ifconfig.me)
sed -i "s/YOUR_IP_OR_DOMAIN/$YOUR_IP/g" config/my-validator-config.toml

echo "✅ Configuration created: config/my-validator-config.toml"
echo ""
echo "⚠️  IMPORTANT: Verify your public_address is correct:"
grep "public_address" config/my-validator-config.toml
```

---

## 🔥 Step 5: Configure Firewall

```bash
# Enable UFW firewall
sudo ufw enable

# Allow SSH (CRITICAL - do this first!)
sudo ufw allow ssh

# Allow Synergy P2P port (required)
sudo ufw allow 5622/tcp comment 'Synergy P2P'

# Optional: Allow RPC for remote monitoring
sudo ufw allow from YOUR_MONITORING_IP to any port 5640 proto tcp

# Optional: Allow WebSocket
sudo ufw allow from YOUR_MONITORING_IP to any port 5660 proto tcp

# Check firewall status
sudo ufw status verbose
```

---

## 🎬 Step 6: Start Your Validator

### Option A: Run Directly (for testing)

```bash
# Create logs directory
mkdir -p data/logs

# Start the validator
./target/release/synergy-testnet start \
  --config config/my-validator-config.toml

# You should see:
# [INFO] Synergy Network Validator Starting...
# [INFO] Chain ID: 1264
# [INFO] Validator Address: synv1...
# [INFO] Connecting to bootnodes...
# [INFO] Syncing blockchain... (this may take a while)
# [INFO] Current block: 0 / 12450
# [INFO] Peer connections: 3
# [INFO] Synergy Score: 0.00 (not yet active)
```

### Option B: Run as systemd Service (recommended)

```bash
# Create systemd service
sudo tee /etc/systemd/system/synergy-validator.service > /dev/null <<EOF
[Unit]
Description=Synergy Testnet Validator Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/synergy/synergy-testnet
ExecStart=$HOME/synergy/synergy-testnet/target/release/synergy-testnet start --config config/my-validator-config.toml
Restart=on-failure
RestartSec=10
StandardOutput=append:$HOME/synergy/synergy-testnet/data/logs/validator.log
StandardError=append:$HOME/synergy/synergy-testnet/data/logs/validator-error.log
Environment="PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.cargo/bin"
Environment="RUST_LOG=info"

# Security
NoNewPrivileges=true
PrivateTmp=true

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable synergy-validator

# Start the service
sudo systemctl start synergy-validator

# Check status
sudo systemctl status synergy-validator

# View logs
journalctl -u synergy-validator -f
```

---

## 📊 Step 7: Verify Your Validator is Syncing

```bash
# Check sync status via RPC
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_syncStatus","id":1}' | jq

# Expected response:
# {
#   "jsonrpc": "2.0",
#   "id": 1,
#   "result": {
#     "isSyncing": true,
#     "currentBlock": 523,
#     "highestBlock": 12450,
#     "syncProgress": 4.19
#   }
# }

# Check peer connections
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_peers","id":1}' | jq

# Check your validator info
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_validatorInfo","id":1}' | jq
```

---

## 📝 Step 8: Register Your Validator

Once your node is synced, send your validator information to the testnet coordinator:

```bash
# Display your validator registration info
cat config/my-validator/validator-info.txt

# Or email/DM this information:
echo "Subject: Testnet Validator Registration Request"
echo ""
echo "Validator Address: $VALIDATOR_ADDRESS"
echo "Public Key: $(jq -r '.public_key' config/my-validator/identity.json)"
echo "Server IP: $(curl -s ifconfig.me)"
echo "Hostname: $(hostname)"
echo "Operator: $(whoami)"
echo ""
echo "Node is synced and ready for activation."
```

**Send this information via:**
- Discord DM to testnet coordinator
- Email to: testnet-coordinator@synergy.network
- Telegram: @synergy_testnet

---

## 💰 Step 9: Receive SNRG Tokens

After your validator is registered, the coordinator will send you SNRG tokens from the faucet:

```bash
# Check your balance
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"account_getBalance\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" | jq

# Expected response after tokens are sent:
# {
#   "jsonrpc": "2.0",
#   "id": 1,
#   "result": {
#     "address": "synv1...",
#     "balance": "1000000",
#     "nonce": 0
#   }
# }
```

**Default allocation for team validators:**
- **1,000,000 SNRG** - Initial allocation for testing
- Additional tokens available upon request

---

## 🏆 Step 10: Monitor Your Synergy Score

Your Synergy Score is calculated based on:
- **Participation** (40%) - Block proposals, votes, task completion
- **Uptime** (30%) - Node availability and responsiveness
- **Accuracy** (30%) - Correct validation and consensus participation

```bash
# Check your Synergy Score
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getScore\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" | jq

# Expected response:
# {
#   "jsonrpc": "2.0",
#   "id": 1,
#   "result": {
#     "validator": "synv1...",
#     "synergyScore": 0.00,  # Starts at 0, increases with participation
#     "components": {
#       "participation": 0.00,
#       "uptime": 0.00,
#       "accuracy": 0.00
#     },
#     "rank": 12,
#     "totalValidators": 12
#   }
# }

# Monitor your score over time
watch -n 60 "curl -s -X POST http://localhost:5640/rpc \
  -H 'Content-Type: application/json' \
  -d '{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getScore\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}' | jq '.result.synergyScore'"
```

---

## 🔧 Monitoring & Maintenance

### Health Checks

```bash
# Check service status
sudo systemctl status synergy-validator

# View recent logs
journalctl -u synergy-validator -n 100

# Follow logs in real-time
journalctl -u synergy-validator -f

# Check sync status
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_syncStatus","id":1}' | jq

# Check peer count
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","id":1}' | jq
```

### Performance Monitoring

```bash
# Monitor resource usage
htop

# Check disk usage
df -h ~/synergy/synergy-testnet/data/

# Monitor network connections
ss -tuln | grep -E '5622|5640|5660'

# View metrics (if enabled)
curl -s http://localhost:6030/metrics
```

### Restart/Update Procedures

```bash
# Stop the validator
sudo systemctl stop synergy-validator

# Pull latest changes
cd ~/synergy/synergy-testnet
git pull origin main

# Rebuild
cargo build --release

# Restart
sudo systemctl start synergy-validator

# Verify it's running
sudo systemctl status synergy-validator
journalctl -u synergy-validator -f
```

---

## ❓ Troubleshooting

### Node Won't Sync

```bash
# Check bootnode connectivity
ping bootnode1.synergy-network.io
ping bootnode2.synergy-network.io

# Check if port 5622 is open
sudo netstat -tuln | grep 5622

# Check for firewall issues
sudo ufw status

# Try manual bootnode connection
./target/release/synergy-testnet peers add \
  snr://synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv@bootnode1.synergy-network.io:5620
```

### Low Synergy Score

Your score starts at 0.00 and increases as you participate:
- **Wait for full sync** - You must be synced before participating
- **Stay online** - Uptime is 30% of your score
- **Participate in consensus** - Vote on blocks, propose when selected
- **Maintain accuracy** - Validate correctly

### Not Receiving Tokens

```bash
# Verify your address
echo $VALIDATOR_ADDRESS

# Check if registration was received
# Contact coordinator with your address

# Verify blockchain is synced
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_syncStatus","id":1}' | jq
```

---

## 🔒 Security Best Practices

1. **Secure Your Private Key**
   ```bash
   chmod 600 config/my-validator/identity.json
   # NEVER share identity.json with anyone
   ```

2. **Restrict RPC Access**
   ```bash
   # Only allow RPC from specific IPs
   sudo ufw delete allow 5640/tcp
   sudo ufw allow from YOUR_MONITORING_IP to any port 5640
   ```

3. **Enable Automatic Updates**
   ```bash
   sudo apt install -y unattended-upgrades
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```

4. **Monitor Logs for Suspicious Activity**
   ```bash
   journalctl -u synergy-validator | grep -i "error\|warn\|attack"
   ```

---

## 📞 Support & Resources

### Get Help
- **Discord**: #testnet-validators channel
- **Telegram**: @synergy_testnet
- **Email**: testnet-support@synergy.network

### Useful Commands Reference

```bash
# Start validator
sudo systemctl start synergy-validator

# Stop validator
sudo systemctl stop synergy-validator

# Restart validator
sudo systemctl restart synergy-validator

# View logs
journalctl -u synergy-validator -f

# Check balance
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"account_getBalance\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" | jq

# Check Synergy Score
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_getScore\",\"params\":[\"$VALIDATOR_ADDRESS\"],\"id\":1}" | jq

# Check sync status
curl -s -X POST http://localhost:5640/rpc -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_syncStatus","id":1}' | jq
```

---

## ✅ Checklist

Before contacting the coordinator, ensure:

- [ ] Node is fully synced (`isSyncing: false`)
- [ ] Firewall allows port 5622
- [ ] Connected to at least 3 peers
- [ ] `validator-info.txt` has been shared
- [ ] Identity file has proper permissions (600)
- [ ] Public address in config matches your actual IP

---

**Welcome to the Synergy Testnet validator network! 🎉**

Your participation helps test and strengthen the network before mainnet launch.
