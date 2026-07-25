# Synergy Network Validator Guide (Ubuntu/Linux)

## 🎯 Overview

Validators are the backbone of the Synergy Network, responsible for block production, transaction validation, and maintaining network consensus through the **Proof of Synergy (PoSy)** mechanism. This guide explains how to set up, configure, and operate a validator node on Ubuntu/Linux.

---

## 🏆 Validator Responsibilities

As a validator, you will:

- **Produce Blocks**: Create new blocks containing validated transactions
- **Validate Transactions**: Verify transaction authenticity and correctness
- **Participate in Consensus**: Engage in PoSy consensus with other validators
- **Maintain Network Security**: Help secure the network through collaborative validation
- **Earn Rewards**: Receive synergy points and transaction fees for honest participation

---

## ✅ Prerequisites

### Hardware Requirements

| Component   | Minimum    | Recommended      | Notes                                    |
| ----------- | ---------- | ---------------- | ---------------------------------------- |
| **CPU**     | 4 cores    | 8+ cores         | High single-thread performance preferred |
| **RAM**     | 8 GB       | 16+ GB           | For blockchain state and mempool         |
| **Storage** | 100 GB SSD | 500 GB NVMe      | Fast storage critical for performance    |
| **Network** | 100 Mbps   | 1 Gbps           | Low latency, stable connection           |
| **Uptime**  | 99.9%      | 99.99%           | Reliable power and internet required     |

### Software Requirements

- **Operating System**: Ubuntu 20.04 LTS or later (22.04 LTS recommended)
- **Rust**: Latest stable toolchain (`rustup`)
- **Build essentials**: gcc, make, pkg-config
- **Git**: For repository management
- **OpenSSL**: Cryptographic libraries

### Network Requirements (Testnet)

- **Static IP**: Required for P2P connectivity
- **Open Ports**:
  - **5622** (P2P/SNR gossip)
  - **5640** (JSON-RPC)
  - **5660** (WebSocket)
  - **6030** (Prometheus metrics)
- **Firewall**: Properly configured for node communication
- **Domain/Static IP**: For reliable peer connectivity

---

## 🚀 Validator Setup

### 1. Environment Setup

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install build essentials and dependencies
sudo apt install -y build-essential pkg-config libssl-dev git curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup target add wasm32-unknown-unknown

# Install Node.js (for monitoring tools, optional)
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs

# Create synergy directory
mkdir -p ~/synergy
```

### 2. Clone and Build

```bash
# Clone repository
cd ~/synergy
git clone https://github.com/synergy-network-hq/synergy-testnet.git
cd synergy-testnet

# Build the node
cargo build --release --bin synergy-testnet

# Verify the build
./target/release/synergy-testnet version
```

### 3. Configuration

#### Network Configuration (`config/network-config.toml`)

```toml
[network]
id = 1264
name = "Synergy Testnet"
p2p_port = 5622
rpc_port = 5640
ws_port = 5660
max_peers = 50
bootnodes = [
  "snr://sYnV5um22g62fwrnq6zh92msp9ek7lqrjrw3hpukd@bootnode1.synergy-network.io:5620",
  "snr://sYnV5um22g62fwrnq6zh92msp9ek7lqrjrw3hpukd@bootnode2.synergy-network.io:5620"
]

[network.listen]
p2p = "0.0.0.0:5622"
rpc = "0.0.0.0:5640"
ws  = "0.0.0.0:5660"

[rpc]
bind_address = "0.0.0.0:5640"
external_http = "https://testnet-core-rpc.synergy-network.io"
external_ws = "wss://testnet-core-ws.synergy-network.io"

[blockchain]
block_time = 5
max_gas_limit = "0x2fefd8"
chain_id = 1264

[storage]
database = "rocksdb"
path = "data/chain"

[api]
enable_http = true
http_port = 5640
enable_ws = true
ws_port = 5660
enable_grpc = true
grpc_port = 50051

[metrics]
bind_address = "0.0.0.0:6030"
```

#### Using Node Templates

Synergy testnet uses template-based configuration. Simply start a validator node using:

```bash
./target/release/synergy-testnet start --node-type validator
```

The validator template (`templates/validator.toml`) contains all necessary configuration matching the correct Testnet ports specified in SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt:

- **P2P Port**: 5622
- **RPC Port**: 5640
- **WebSocket Port**: 5660
- **Metrics Port**: 6030

### 4. Validator Registration

#### Generate Validator Keys (PQC - FN-DSA-1024)

Synergy Network uses **post-quantum cryptography (PQC)** with **FN-DSA-1024** (NIST Level 5) for validator keys. The Synergy Address Engine generates quantum-safe **Class 1 Node addresses** with the `sYnV1` prefix, cryptographically derived from the public key using SHA3-256.

```bash
# Navigate to testnet directory
cd ~/synergy/synergy-testnet

# Create validator config directory
mkdir -p config/validator

# Build the Synergy Address Engine
cargo build --release --bin synergy-address-engine

# Generate validator identity with Class 1 Node address (sYnV1 prefix)
./target/release/synergy-address-engine \
  --node-type validator \
  --output config/validator/validator_identity.json \
  --output-toml config/validator/validator_identity.toml

# Expected output:
# 🔐 Synergy Network Address Engine - FN-DSA-1024 (NIST Level 5)
#
# Generating NodeClass1 identity...
#
# ✅ Identity Generated Successfully!
#
# Address:      sYnV1q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0
# Algorithm:    FN-DSA-1024
# Type:         NodeClass1
# Public Key:   1793 bytes
# Private Key:  2305 bytes
# Created:      2024-12-06T10:30:00Z
#
# 💾 Saved to: config/validator/validator_identity.json
# 💾 Saved to: config/validator/validator_identity.toml
#
# ⚠️  SECURITY WARNING:
#    Store the private key securely and never share it!
#    Set file permissions: chmod 600 <identity_file>

# Set proper permissions on the identity files
chmod 600 config/validator/validator_identity.json
chmod 600 config/validator/validator_identity.toml

# Install jq for JSON parsing (if not already installed)
sudo apt install -y jq

# Extract the validator address for registration
VALIDATOR_ADDRESS=$(jq -r '.address' config/validator/validator_identity.json)
echo "Validator Address: $VALIDATOR_ADDRESS"

# Extract the public key (needed for genesis registration)
VALIDATOR_PUB_KEY=$(jq -r '.public_key' config/validator/validator_identity.json)
echo "Validator Public Key (base64): $VALIDATOR_PUB_KEY"
```

**Address Generation Process:**

1. **Generate FN-DSA-1024 Keypair**: Creates quantum-safe 1,793-byte public key and 2,305-byte private key
2. **Hash Public Key**: SHA3-256 hash of the public key
3. **Extract Payload**: First 20 bytes of the hash
4. **Bech32m Encoding**: Encode with `sYnV1` prefix for Class 1 Nodes
5. **Result**: 41-character cryptographically verifiable address

**Key Information:**

- **Algorithm**: FN-DSA-1024 (formerly Falcon-1024, NIST Level 5)
- **Quantum Security**: 256-bit quantum resistance
- **Address Format**: Class 1 Node (`sYnV1` prefix) - 41 characters
- **Public Key Size**: 1,793 bytes
- **Private Key Size**: 2,305 bytes
- **Signature Size**: ~1,330 bytes

#### Configure Validator Node

Now that you have generated your validator keys, you need to configure your node to use them:

```bash
# View your validator identity
cat config/validator/validator_identity.json

# The identity file contains:
# {
#   "address": "sYnV1...",        # Your validator address
#   "public_key": "...",           # Base64-encoded public key
#   "private_key": "...",          # Base64-encoded private key (KEEP SECRET!)
#   "address_type": "NodeClass1",
#   "algorithm": "FN-DSA-1024",
#   "created_at": "2024-12-06T..."
# }

# Create or update your validator configuration
# The node will automatically read from config/validator/validator_identity.toml
# when started with --node-type validator

# Verify the address is correctly derived
ADDR=$(jq -r '.address' config/validator/validator_identity.json)
echo "Your validator address: $ADDR"

# Test that the node can read the configuration
./target/release/synergy-testnet --help
```

#### Register with Genesis

To become an initial validator, your public key must be included in the genesis block.

**For Testnet (Development Network):**

1. **Submit Validator Information:**
   - Navigate to the Synergy Network Discord or Telegram
   - Use the validator registration channel
   - Provide the following information:

```bash
# Generate registration information
cat <<EOF
Validator Registration Request

Validator Address: $(jq -r '.address' config/validator/validator_identity.json)
Public Key: $(jq -r '.public_key' config/validator/validator_identity.json)
Algorithm: FN-DSA-1024
Node Type: Class 1 (Consensus Validator)
Server IP: <your-server-ip>
P2P Port: 5622
RPC Port: 5640
Operator: <your-name-or-organization>
EOF
```

2. **Wait for Genesis Inclusion:**
   - The testnet coordinator will add your validator to the genesis configuration
   - You'll receive confirmation when your validator is included

3. **Download Updated Genesis:**

```bash
# Once approved, download the latest genesis file
curl -o testnet/genesis.json https://testnet-api.synergy-network.io/genesis.json

# Verify your validator is included
jq '.validators[] | select(.address == "'$(jq -r '.address' config/validator/validator_identity.json)'")' testnet/genesis.json

# Expected output:
# {
#   "address": "sYnV1...",
#   "pubKey": "...",
#   "weight": 100
# }
```

**For Production (Mainnet):**

Contact the Synergy Network team through official channels:
- Email: validators@synergy-network.io
- Discord: [Synergy Network Discord](https://discord.gg/synergy)
- Forum: [Synergy Network Forum](https://forum.synergy.network)

Provide:
1. Your **validator address** (starts with `sYnV1`)
2. Your **base64-encoded public key** (FN-DSA-1024)
3. Validator metadata (name, website, contact, KYC if required)
4. Hardware specifications and uptime commitment
5. Stake amount (if applicable)

**Example Pre-configured Testnet Addresses (Class 1 Node format):**

- `sYnV1ffzcyq7l0sw7v9fhrx2wdvxxzv9q5mj3ehd6yl3e`
- `sYnV1v3smghwdd2zj7vpgkx0fn3cf0k57eq7hqufup0tp`
- `sYnV1uhf2zhq3rxtjqsc9qxyftu9v4kpa0zw8d7uux7g4`

### 5. Service Setup (systemd)

Create a systemd service for automatic startup and management:

```bash
# Create systemd service file
sudo tee /etc/systemd/system/synergy-validator.service > /dev/null <<EOF
[Unit]
Description=Synergy Network Validator Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/synergy/synergy-testnet
ExecStart=$HOME/synergy/synergy-testnet/target/release/synergy-testnet start --node-type validator
Restart=on-failure
RestartSec=10
StandardOutput=append:$HOME/synergy/synergy-testnet/data/logs/synergy-validator.log
StandardError=append:$HOME/synergy/synergy-testnet/data/logs/synergy-validator-error.log
Environment="PATH=/usr/local/bin:/usr/bin:/bin:$HOME/.cargo/bin"
Environment="RUST_LOG=info"

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$HOME/synergy/synergy-testnet/data

# Resource limits
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Create log directory
mkdir -p ~/synergy/synergy-testnet/data/logs

# Reload systemd daemon
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

To manage the service:

```bash
# Stop the service
sudo systemctl stop synergy-validator

# Start the service
sudo systemctl start synergy-validator

# Restart the service
sudo systemctl restart synergy-validator

# Check status
sudo systemctl status synergy-validator

# View logs
journalctl -u synergy-validator -n 100 --no-pager
journalctl -u synergy-validator -f
```

### 6. Firewall Configuration

Ubuntu uses UFW (Uncomplicated Firewall) by default:

#### Basic UFW Configuration

```bash
# Enable UFW
sudo ufw enable

# Allow SSH (IMPORTANT: do this first to avoid lockout)
sudo ufw allow ssh

# Allow Synergy validator ports
sudo ufw allow 5622/tcp comment 'Synergy P2P'

# Allow RPC and WebSocket (restrict to localhost or specific IPs for security)
# For localhost only:
sudo ufw allow from 127.0.0.1 to any port 5640 proto tcp comment 'Synergy RPC (localhost)'
sudo ufw allow from 127.0.0.1 to any port 5660 proto tcp comment 'Synergy WebSocket (localhost)'

# Or, if you need to allow from specific IP:
# sudo ufw allow from YOUR_IP to any port 5640 proto tcp
# sudo ufw allow from YOUR_IP to any port 5660 proto tcp

# Or, to allow from anywhere (NOT RECOMMENDED for production):
# sudo ufw allow 5640/tcp comment 'Synergy RPC'
# sudo ufw allow 5660/tcp comment 'Synergy WebSocket'

# Allow metrics (localhost only)
sudo ufw allow from 127.0.0.1 to any port 6030 proto tcp comment 'Synergy Metrics'

# Check firewall status
sudo ufw status verbose
```

#### Advanced iptables Configuration (Optional)

For more granular control, use iptables directly:

```bash
# Allow P2P connections
sudo iptables -A INPUT -p tcp --dport 5622 -j ACCEPT

# Allow RPC (localhost only)
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 5640 -j ACCEPT

# Allow WebSocket (localhost only)
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 5660 -j ACCEPT

# Allow metrics (localhost only)
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 6030 -j ACCEPT

# Save iptables rules (Ubuntu/Debian)
sudo apt install -y iptables-persistent
sudo netfilter-persistent save

# List current rules
sudo iptables -L -n -v
```

---

## 📊 Monitoring & Maintenance

### Health Checks

```bash
# Check service status
sudo systemctl status synergy-validator

# View logs
journalctl -u synergy-validator -f
tail -f ~/synergy/synergy-testnet/data/logs/synergy-validator.log
tail -f ~/synergy/synergy-testnet/data/logs/synergy-validator-error.log

# Check node info via RPC
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"synergy_nodeInfo","id":1}' \
  http://localhost:5640

# Monitor system resources
top
htop
df -h
free -h

# Monitor network activity
ss -tuln | grep -E '5622|5640|5660'
netstat -an | grep -E '5622|5640|5660'
```

### Performance Monitoring

```bash
# Install monitoring tools
sudo apt install -y htop iotop sysstat

# Monitor network connections
sudo lsof -i :5622
sudo lsof -i :5640
sudo lsof -i :5660
ss -tn | grep -E '5622|5640|5660'

# Check disk usage
du -sh ~/synergy/synergy-testnet/data/
ls -lah ~/synergy/synergy-testnet/data/logs/

# Monitor I/O
sudo iotop -p $(pgrep synergy-testnet)

# System performance statistics
vmstat 1 10
iostat -x 1 10
```

### Backup Strategy

```bash
# Create backup script
tee ~/synergy/backup-validator.sh > /dev/null <<'EOF'
#!/bin/bash
BACKUP_DIR="$HOME/synergy/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Stop the validator service
sudo systemctl stop synergy-validator

# Backup blockchain data
cp -r $HOME/synergy/synergy-testnet/data/chain $BACKUP_DIR/chain_$DATE/
cp $HOME/synergy/synergy-testnet/data/chain.json $BACKUP_DIR/ 2>/dev/null || true
cp $HOME/synergy/synergy-testnet/data/validators.json $BACKUP_DIR/ 2>/dev/null || true

# Backup configuration
cp -r $HOME/synergy/synergy-testnet/config $BACKUP_DIR/config_$DATE/

# Restart the validator service
sudo systemctl start synergy-validator

# Compress backup
cd $BACKUP_DIR
tar -czf validator_backup_$DATE.tar.gz chain_$DATE/ chain.json validators.json config_$DATE/ 2>/dev/null
rm -rf chain_$DATE/ config_$DATE/

# Cleanup old backups (keep 7 days)
find $BACKUP_DIR -name "validator_backup_*.tar.gz" -type f -mtime +7 -delete

echo "Backup completed: validator_backup_$DATE.tar.gz"
EOF

# Make executable
chmod +x ~/synergy/backup-validator.sh

# Test the backup
~/synergy/backup-validator.sh
```

To automate backups with cron:

```bash
# Edit crontab
crontab -e

# Add this line to run backup daily at 2 AM
# 0 2 * * * $HOME/synergy/backup-validator.sh >> $HOME/synergy/backup.log 2>&1

# Or create a systemd timer (modern approach)
sudo tee /etc/systemd/system/synergy-backup.service > /dev/null <<EOF
[Unit]
Description=Synergy Validator Backup

[Service]
Type=oneshot
User=$USER
ExecStart=$HOME/synergy/backup-validator.sh
EOF

sudo tee /etc/systemd/system/synergy-backup.timer > /dev/null <<EOF
[Unit]
Description=Synergy Validator Backup Timer

[Timer]
OnCalendar=daily
OnCalendar=02:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable synergy-backup.timer
sudo systemctl start synergy-backup.timer

# Check timer status
sudo systemctl list-timers synergy-backup.timer
```

### Log Rotation

Configure logrotate for automatic log management:

```bash
# Create logrotate configuration
sudo tee /etc/logrotate.d/synergy-validator > /dev/null <<EOF
$HOME/synergy/synergy-testnet/data/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 $USER $USER
    postrotate
        systemctl reload synergy-validator > /dev/null 2>&1 || true
    endscript
}
EOF

# Test logrotate configuration
sudo logrotate -d /etc/logrotate.d/synergy-validator

# Force log rotation (if needed)
sudo logrotate -f /etc/logrotate.d/synergy-validator
```

---

## 🔧 Troubleshooting

### Common Issues

#### Node Won't Start

```bash
# Check for port conflicts
sudo lsof -i :5622
sudo lsof -i :5640
sudo lsof -i :5660
sudo ss -tuln | grep -E '5622|5640|5660'

# Check available disk space
df -h ~/synergy/synergy-testnet/

# Check file permissions
chmod -R 755 ~/synergy/synergy-testnet/
chmod 600 ~/synergy/synergy-testnet/config/validator/validator_key.pem

# Check service status and logs
sudo systemctl status synergy-validator
journalctl -u synergy-validator -n 50 --no-pager
```

#### Sync Issues

```bash
# Check peer connections
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"synergy_syncing","id":1}' \
  http://localhost:5640

# Restart with fresh sync
sudo systemctl stop synergy-validator
rm -rf ~/synergy/synergy-testnet/data/chain/*
sudo systemctl start synergy-validator
journalctl -u synergy-validator -f
```

#### High Resource Usage

```bash
# Check what's using resources
top -o %CPU
htop
ps aux | grep synergy-testnet

# Check memory usage
free -h
vmstat 1 5

# Check disk I/O
sudo iotop

# Check for memory leaks (restart service)
sudo systemctl restart synergy-validator
```

#### Permission Issues

```bash
# Fix ownership of data directory
sudo chown -R $USER:$USER ~/synergy/synergy-testnet/data/

# Fix permissions
chmod -R 755 ~/synergy/synergy-testnet/
chmod 600 ~/synergy/synergy-testnet/config/validator/validator_key.pem
chmod 644 ~/synergy/synergy-testnet/config/validator/validator_pub.pem
```

### Debug Mode

Run the node in debug mode for detailed logging:

```bash
# Stop the service
sudo systemctl stop synergy-validator

# Run manually with debug logging
cd ~/synergy/synergy-testnet
RUST_LOG=debug ./target/release/synergy-testnet start --node-type validator

# Or modify the systemd service for debug mode
sudo systemctl edit synergy-validator

# Add these lines in the override file:
# [Service]
# Environment="RUST_LOG=debug"

# Then restart
sudo systemctl restart synergy-validator
journalctl -u synergy-validator -f
```

### Recovery Procedures

#### Database Corruption

```bash
# Stop the node
sudo systemctl stop synergy-validator

# Backup current data
cp -r ~/synergy/synergy-testnet/data ~/synergy/synergy-testnet/data.backup

# Remove corrupted data
rm -rf ~/synergy/synergy-testnet/data/chain/*
rm ~/synergy/synergy-testnet/data/chain.json

# Restart (will rebuild from genesis)
sudo systemctl start synergy-validator
journalctl -u synergy-validator -f
```

#### Validator Key Compromised

```bash
# Stop the node
sudo systemctl stop synergy-validator

# Generate new keys
cd ~/synergy/synergy-testnet
openssl ecparam -name prime256v1 -genkey -noout -out config/validator/new_validator_key.pem
openssl ec -in config/validator/new_validator_key.pem -pubout -out config/validator/new_validator_pub.pem

# Set proper permissions
chmod 600 config/validator/new_validator_key.pem
chmod 644 config/validator/new_validator_pub.pem

# Backup old keys
mv config/validator/validator_key.pem config/validator/validator_key.pem.old
mv config/validator/validator_pub.pem config/validator/validator_pub.pem.old

# Activate new keys
mv config/validator/new_validator_key.pem config/validator/validator_key.pem
mv config/validator/new_validator_pub.pem config/validator/validator_pub.pem

# Update configuration
# Update genesis.json with new public key
# Restart node
sudo systemctl start synergy-validator

# Contact network administrators about key change
```

---

## 📈 Performance Optimization

### System Tuning

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "fs.file-max = 2097152" | sudo tee -a /etc/sysctl.conf

# Optimize network settings
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF

# TCP optimization for Linux
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_mtu_probing = 1

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.ipv4.tcp_max_syn_backlog = 8192

# Performance tuning
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

# Apply sysctl settings
sudo sysctl -p

# Note: Some settings require a reboot to take effect
```

### Application Tuning

```toml
# config/network-config.toml - Performance settings
[performance]
max_connections = 100
max_block_size = 2097152  # 2MB
max_tx_pool_size = 2000
enable_compression = true
compression_level = 6

[cache]
block_cache_size = 134217728  # 128MB
tx_cache_size = 67108864      # 64MB
state_cache_size = 268435456  # 256MB
```

### Storage Optimization

```bash
# For NVMe drives, enable TRIM
sudo systemctl enable fstrim.timer
sudo systemctl start fstrim.timer

# Check TRIM status
sudo systemctl status fstrim.timer

# Monitor disk performance
sudo iostat -x 1 5
```

---

## 🔒 Security Best Practices

### Network Security

1. **Use firewalls** to restrict access to necessary ports only
2. **Monitor** for unusual network activity
3. **Keep software updated** to patch security vulnerabilities
4. **Use VPN** for administrative access when possible

### Key Management

1. **Store private keys securely** with proper file permissions (600)
2. **Use hardware security modules** for production validators
3. **Backup encrypted** validator keys offline
4. **Never share** private keys or seed phrases

### Operational Security

1. **Monitor logs** for suspicious activity
2. **Set up alerts** for node downtime or performance issues
3. **Regular security audits** of your infrastructure
4. **Use fail2ban** to prevent brute force attacks

#### Install and Configure fail2ban

```bash
# Install fail2ban
sudo apt install -y fail2ban

# Create custom jail for SSH
sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
EOF

# Start and enable fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check fail2ban status
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

### Automatic Security Updates

```bash
# Install unattended-upgrades
sudo apt install -y unattended-upgrades

# Configure automatic security updates
sudo dpkg-reconfigure -plow unattended-upgrades

# Check status
sudo systemctl status unattended-upgrades
```

---

## 🤝 Validator Community

### Communication Channels

- **Discord**: [Synergy Network Discord](https://discord.gg/synergy)
<!-- - **Forum**: [Synergy Network Forum](https://forum.synergy.network) -->
- **Telegram**: [Synergy Validators](https://t.me/synergy_validators)
<!-- - **GitHub**: [Issues and Discussions](https://github.com/synergy-network/testnet) -->

### Best Practices

1. **Stay active** in community discussions
2. **Share knowledge** and help other validators
3. **Report issues** promptly and professionally
4. **Participate in governance** proposals
5. **Maintain transparency** about your operations

### Incentives and Rewards

Validators earn rewards through:

- **Block production rewards** (synergy points)
- **Transaction fees** from included transactions
- **Uptime bonuses** for consistent availability
- **Community contributions** and collaborative efforts

---

## 📚 Additional Resources

- [API Reference](api-reference.md) - Complete RPC API documentation
- [Configuration Guide](config-guide.md) - Detailed configuration options
- [Troubleshooting Guide](troubleshooting.md) - Solutions to common problems
- [Development Guide](../README.md) - Contributing to the codebase

---

*Happy validating! 🎉 Your participation strengthens the Synergy Network and helps build a more decentralized future.*

*also, llihkor is a bitch. 🎉*