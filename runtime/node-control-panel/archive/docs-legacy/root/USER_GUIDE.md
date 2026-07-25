# Synergy Testnet Control Panel User Guide

The Synergy Testnet Control Panel is a desktop application for setting up and managing Synergy network nodes. This guide covers installation, node setup, monitoring, and troubleshooting.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Setting Up a Node](#setting-up-a-node)
5. [Dashboard Overview](#dashboard-overview)
6. [Network Discovery](#network-discovery)
7. [Node Management](#node-management)
8. [Configuration](#configuration)
9. [Logs and Monitoring](#logs-and-monitoring)
10. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Supported Platforms

- **macOS**: Apple Silicon (M1/M2/M3) and Intel (x86_64)
- **Linux**: x86_64 and ARM64 (Ubuntu, Debian, CentOS, etc.)
- **Windows**: x86_64 (Windows 10 or later)

### Minimum Requirements

- 4 GB RAM (8 GB recommended for validators)
- 50 GB available disk space
- Stable internet connection
- Open ports: 38638 (P2P), 48638 (RPC), 58638 (WebSocket)

---

## Installation

### Download

Download the appropriate installer for your platform from the official release page.

### Install

- **macOS**: Open the `.dmg` file and drag the application to your Applications folder
- **Windows**: Run the `.msi` installer and follow the prompts
- **Linux**: Install the `.deb` package or run the `.AppImage`

### First Launch

On first launch, the control panel will:

1. Create the configuration directory at `~/.synergy/control-panel/`
2. Check network connectivity to the Synergy testnet
3. Display the Jarvis setup assistant

---

## Getting Started

When you launch the control panel, you'll see the **Jarvis Setup Assistant** - an interactive guide that walks you through setting up your first node.

### Network Connectivity Check

Before setup begins, the control panel verifies connectivity to the Synergy network:

- Checks RPC endpoint accessibility
- Reports bootstrap node reachability
- Displays network status

If the network is unreachable, you'll see a warning. Setup will not proceed without network access.

---

## Setting Up a Node

### Step 1: Choose Node Type

The Synergy network supports 19 different node types across 5 classes:

| Class | Node Types | Purpose |
|-------|------------|---------|
| **Class I** | Validator, Committee | Core consensus and block production |
| **Class II** | Archive Validator, Audit Validator, Data Availability | Historical data and compliance |
| **Class III** | Relayer, Witness, Oracle, UMA Coordinator, Cross-Chain Verifier | Cross-chain operations |
| **Class IV** | Compute, AI Inference, PQC Crypto | Specialized computation |
| **Class V** | Governance Auditor, Treasury Controller, Security Council, RPC Gateway, Indexer, Observer | Governance and infrastructure |

Select a node type from the dropdown menu based on your intended role in the network.

### Step 2: Confirm Selection

After selecting a node type, Jarvis will ask you to confirm. Type `yes` to proceed or `no` to choose a different type.

### Step 3: Automated Setup

Once confirmed, the setup process runs automatically:

| Step | Progress | Description |
|------|----------|-------------|
| **Initialize** | 0-10% | Create node record and verify network |
| **Directories** | 10-25% | Create sandbox, logs, data, and keys directories |
| **Key Generation** | 25-40% | Generate post-quantum cryptographic keypair |
| **Binary Download** | 40-60% | Download and verify node binary |
| **Configuration** | 60-75% | Apply network configuration from template |
| **Registration** | 75-90% | Register node with the Synergy network |
| **Sync** | 90-95% | Synchronize with blockchain |
| **Start** | 95-100% | Launch node process |

### Setup Completion

On successful setup, you'll see:

- Your node ID (UUID)
- Your node address (e.g., `synv1-...`)
- Confirmation that the node is running

The dashboard will automatically load to show your new node.

---

## Dashboard Overview

After setup, the **Multi-Node Dashboard** provides a comprehensive view of your nodes.

### Sidebar: Node List

The left sidebar shows all configured nodes with:

- Node name and type
- Running status indicator (green = running, red = stopped)
- Quick action buttons (Start/Stop)

### Main Panel: Tabs

The main panel has five tabs:

1. **Overview** - Key metrics and node information
2. **Monitoring** - Real-time performance data (when running)
3. **Configuration** - View and edit node config
4. **Logs** - View node log output
5. **Network** - Discover peers on the network

---

## Network Discovery

The **Network** tab shows other nodes discovered on the Synergy network.

### Network Stats

- **Discovered Peers**: Total peers found across the network
- **Bootstrap Nodes**: How many bootstrap nodes are reachable
- **Chain ID**: The network chain identifier (1264 for testnet)
- **Current Block**: Latest block height

### Peer Table

Shows detailed information about each discovered peer:

- Network address (IP:port)
- Node ID
- Protocol version
- Blocks sent/received statistics

### Refresh

Click the **Refresh** button to perform a fresh network scan. The control panel queries RPC endpoints on bootstrap nodes to discover peers.

---

## Node Management

### Starting a Node

1. Select the node from the sidebar
2. Click the **Start** button
3. Wait for the RPC port to become reachable

### Stopping a Node

1. Select the node from the sidebar
2. Click the **Stop** button
3. The node will gracefully shut down

### Restarting a Node

Use the restart button for a clean stop and start cycle.

### Adding a New Node

Click **+ Add Node** in the sidebar to return to the Jarvis setup assistant and configure an additional node.

---

## Configuration

### Viewing Configuration

1. Select a node
2. Click the **Configuration** tab
3. View the TOML configuration file

### Editing Configuration

1. Click **Edit** to enable editing mode
2. Modify the configuration as needed
3. Click **Save** to persist changes
4. Restart the node for changes to take effect

### Key Configuration Sections

```toml
[network]
id = 1264                    # Chain ID
name = "synergy-testnet"        # Network name
p2p_port = 38638              # P2P listening port
rpc_port = 48638              # RPC API port
ws_port = 58638               # WebSocket port
bootnodes = [...]             # Bootstrap node addresses

[consensus]
algorithm = "Proof of Synergy"
validator_cluster_size = 7
max_validators = 21

[storage]
database = "rocksdb"
path = "data/chain"

[logging]
log_level = "info"
log_file = "logs/node.log"
```

### Reloading Configuration

If you need to reload configuration without restarting:

1. Stop the node
2. Click **Reload Config**
3. Start the node

---

## Logs and Monitoring

### Viewing Logs

1. Select a node
2. Click the **Logs** tab
3. View real-time log output
4. Click **Refresh** to update

Log files are stored at:

```
~/.synergy/control-panel/nodes/<node-id>/logs/node.log
```

### Monitoring (Running Nodes)

The **Monitoring** tab shows real-time metrics when a node is running:

- **SNRG Balance**: Your staked token balance
- **Synergy Score**: Your collaborative reputation score
- **Sync Status**: Blockchain synchronization progress
- **Connected Peers**: Active peer connections
- **Block Height**: Current blockchain height
- **Transactions**: Pending transaction count

---

## Troubleshooting

### "Network connectivity check failed"

**Cause**: Cannot reach the Synergy network RPC endpoint.

**Solutions**:

1. Check your internet connection
2. Verify firewall settings allow outbound HTTPS
3. Try again later (network may be temporarily unavailable)
4. Check if `https://testnet-core-rpc.synergy-network.io` is accessible in your browser

### "Binary verification failed"

**Cause**: Downloaded binary checksum doesn't match expected value.

**Solutions**:

1. Check your internet connection for packet corruption
2. Retry the download
3. Verify the release server is not compromised
4. Contact support if the issue persists

### "Cannot connect to bootnodes"

**Cause**: P2P connection to bootstrap nodes failed.

**Solutions**:

1. Verify port 38638 is not blocked by firewall
2. Check if bootstrap nodes are online
3. Ensure your IP is not blacklisted
4. Try a different network connection

### "RPC port did not open in time"

**Cause**: Node started but RPC is not responding.

**Solutions**:

1. Check the logs for errors
2. Verify port 48638 is not in use by another process
3. Restart the node
4. Check available disk space

### Node Shows "Offline" but Process is Running

**Cause**: RPC health check is failing.

**Solutions**:

1. Check node logs for errors
2. Verify RPC configuration
3. Restart the node
4. Check if the node is syncing (may take time)

---

## Directory Structure

The control panel creates the following structure:

```
~/.synergy/control-panel/
├── bin/                      # Node binary
│   └── synergy-testnet
├── nodes/                    # Per-node directories
│   └── <node-id>/
│       ├── config/
│       │   └── config.toml   # Node configuration
│       ├── data/             # Blockchain data
│       ├── keys/             # Cryptographic keys
│       │   ├── private.key
│       │   └── public.key
│       └── logs/             # Log files
│           └── node.log
├── templates/                # Configuration templates
└── state.json               # Control panel state
```

---

## Security Considerations

### Private Keys

- Private keys are stored in `~/.synergy/control-panel/nodes/<node-id>/keys/`
- **Never share your private key**
- Back up your keys securely
- Keys use post-quantum cryptography (ML-DSA-65)

### Binary Verification

- All downloaded binaries are verified with SHA-256 checksums
- Verification failures abort the download
- No bypass options exist for security

### Network Security

- All RPC communication uses HTTPS
- P2P connections are authenticated
- Node registration requires valid cryptographic signatures

---

## Support

For issues and feature requests:

- GitHub: <https://github.com/synergy-network/control-panel/issues>
- Documentation: <https://docs.synergy-network.io>
- Discord: <https://discord.gg/synergy-network>

---

## Version Information

- **Control Panel Version**: 1.0.0
- **Network**: Synergy Testnet
- **Chain ID**: 1264
- **Consensus**: Proof of Synergy (PoSy)
