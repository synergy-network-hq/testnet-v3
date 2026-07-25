# Synergy Testnet Control Panel - Setup Wizard Guide

## Overview

The Synergy Testnet Control Panel features an enhanced Jarvis-powered setup wizard that guides users through the process of setting up and managing Synergy network nodes. This document provides a comprehensive guide to the setup wizard's features, functionality, and architecture.

---

## Features

### 🤖 Conversational Interface
- **Jarvis AI Assistant**: Friendly, conversational setup experience
- **Real-time guidance**: Step-by-step instructions with clear explanations
- **Interactive chat**: Users respond to prompts and questions naturally

### 🖥️ Integrated Terminal
- **Split-screen view**: Chat interface on the left, terminal output on the right
- **Real-time feedback**: See exactly what Jarvis is doing during setup
- **Color-coded output**: Success (green), errors (red), warnings (yellow), info (white)
- **Progress tracking**: Visual progress bar showing setup completion percentage

### 🔐 Post-Quantum Security
- **FN-DSA-1024**: NIST Level 5 quantum-resistant signatures
- **Automated key generation**: Secure cryptographic identity creation
- **Address derivation**: Unique Synergy addresses with class-specific prefixes

### 🏗️ Isolated Environment
- **Sandboxed nodes**: Each node runs in its own isolated directory
- **Safe operation**: Nodes cannot interact with the user's system
- **Clean architecture**: Organized directory structure at `~/.synergy/control-panel/`

---

## Supported Node Types

The setup wizard currently supports three node types:

### 1. **Validator Node** (Class I)
- **Purpose**: Core network validator that validates transactions and produces blocks
- **Responsibilities**:
  - Validate transactions
  - Produce new blocks
  - Participate in Proof of Synergy (PoSy) consensus
  - Earn SNRG rewards and transaction fees
- **Address Prefix**: `sYnV1`
- **Requirements**: FN-DSA-1024 keypair, network registration

### 2. **RPC Node** (Class II)
- **Purpose**: Provides JSON-RPC and WebSocket endpoints for blockchain queries
- **Responsibilities**:
  - Serve HTTP RPC requests (port 48638)
  - Provide WebSocket connections (port 58638)
  - Maintain full blockchain state
  - Support dApps, wallets, and developers
- **Address Prefix**: `sYnR2`
- **Note**: Does not participate in consensus

### 3. **Relayer Node** (Class II)
- **Purpose**: Facilitates cross-chain communication through SXCP
- **Responsibilities**:
  - Monitor source chains (Sepolia, etc.) for cross-chain events
  - Generate and verify Merkle proofs
  - Participate in relayer cluster consensus
  - Relay messages to destination chains
  - Earn SNRG rewards for successful relays
- **Address Prefix**: `sYnR2`
- **Architecture**: Bridgeless - no funds locked in intermediate contracts

---

## Setup Flow

### Step-by-Step Process

#### **Step 1: Greeting & Introduction**
- Jarvis introduces himself and explains the setup process
- **Key Message**: Nodes will run in isolated environments
- **User Action**: Read and understand

#### **Step 2: Node Type Selection**
- Jarvis presents the three supported node types
- Detailed descriptions of each node's purpose and responsibilities
- **User Action**: Type 1, 2, or 3 to select node type

#### **Step 3: Detailed Explanation**
- Jarvis provides in-depth information about the selected node type
- Explains what the node will do and how it contributes to the network
- Outlines the 7-step setup process

#### **Step 4: Setup Confirmation**
- Jarvis asks for confirmation to proceed
- **User Action**: Type 'yes' to continue or 'no' to go back

#### **Step 5: Automated Setup** (Terminal Visible)
The wizard performs these steps automatically:

##### **5.1 Initialize Environment**
```
[Jarvis] Creating isolated environment at ~/.synergy/control-panel
[System] Creating directory structure...
[System] ✓ Created ~/.synergy/control-panel/nodes
[System] ✓ Created ~/.synergy/control-panel/bin
[System] ✓ Created ~/.synergy/control-panel/templates
```

##### **5.2 Generate PQC Keys**
```
[Jarvis] Generating FN-DSA-1024 keypair (NIST Level 5 security)...
[Crypto] Algorithm: FN-DSA-1024 (Falcon-1024)
[Crypto] Security Level: NIST Level 5 (256-bit quantum resistance)
[Crypto] Generating 1,793-byte public key...
[Crypto] Generating 2,305-byte private key...
[Crypto] ✓ Keypair generated successfully!
```

##### **5.3 Create Synergy Address**
```
[Jarvis] Deriving Synergy address from public key...
[AddressEngine] Computing SHA3-256 hash of public key...
[AddressEngine] Extracting 20-byte payload from hash...
[AddressEngine] Encoding with Bech32m (prefix: sYnV1)...
[AddressEngine] ✓ Address created: sYnV1q2w3e4r5t6y7u8i9o0p1a2s3d4f5g6h7j8k9l0
```

##### **5.4 Configure Node**
```
[Jarvis] Loading configuration template...
[Config] Template: validator.toml
[Config] Setting network ID: 1264 (Synergy Testnet)
[Config] Setting P2P port: 38638
[Config] Setting RPC port: 48638
[Config] Setting WebSocket port: 58638
[Config] Adding bootnode addresses...
[Config] ✓ Configuration file created!
```

##### **5.5 Register with Network**
```
[Jarvis] Connecting to Synergy Testnet...
[Network] Resolving testnet-api.synergy-network.io...
[Network] Connected to registration endpoint
[Network] Submitting Validator Node registration...
[Network] Sending public key and address...
[Network] ✓ Registration confirmed!
[Network] ✓ Node added to testnet registry
```

##### **5.6 Blockchain Sync**
```
[Jarvis] Starting blockchain synchronization...
[Sync] Connecting to bootnodes...
[Sync] ✓ Connected to bootnode1.synergy-network.io
[Sync] ✓ Connected to bootnode2.synergy-network.io
[Sync] Requesting blockchain headers...
[Sync] Current network height: 15,432 blocks
[Sync] Downloading blocks...
[Sync] Synced: 3,856 / 15,432 blocks (25%)
[Sync] Synced: 7,716 / 15,432 blocks (50%)
[Sync] Synced: 11,574 / 15,432 blocks (75%)
[Sync] Synced: 15,432 / 15,432 blocks (100%)
[Sync] ✓ Blockchain fully synchronized!
```

##### **5.7 Start Node**
```
[Jarvis] Launching node process...
[Process] Starting Validator Node...
[Process] Loading configuration...
[Process] Initializing database...
[Process] Starting P2P listener on 0.0.0.0:38638...
[Process] Starting consensus engine...
[Process] Loading validator keys...
[Process] ✓ Node is running!
[Process] ✓ Validator Node is now active on the network!
```

#### **Step 6: Completion & Dashboard Transition**
- Jarvis congratulates the user
- Brief transition screen with loading animation
- Automatic redirect to the node dashboard

---

## Dashboard Features

### Overview Tab

#### **Key Metrics** (Top Section)
Displays four critical metrics in highlighted cards:

1. **💰 SNRG Balance**
   - Current token balance
   - Unit: SNRG
   - Updates in real-time when node is running

2. **⚡ Synergy Score**
   - Node's performance score (0-100)
   - Affects validator selection and rewards
   - Updates based on node activity

3. **🔄 Sync Status**
   - Current synchronization state
   - Shows percentage if syncing
   - States: Offline, Syncing, Synced

4. **🌐 Connected Peers**
   - Number of active peer connections
   - Indicates network health
   - Real-time updates

#### **Node Identity Section**
- **Node Address**: Full Synergy address (sYnV1... or sYnR2...)
- **Node Type**: Validator, RPC, or Relayer
- **Node Class**: Class I or Class II
- **Algorithm**: FN-DSA-1024 (NIST Level 5)

#### **Status Overview**
Three cards showing:
- **⏱️ Uptime**: How long the node has been running
- **📦 Current Block**: Local and network block heights
- **🌍 Network**: Synergy Testnet (Chain ID: 1264)

#### **Node Information**
- Config path
- Logs path
- Data path

### Monitoring Tab

Only available when the node is running. Shows:

#### **🧱 Block Validation Status**
- Current block height
- Active validators
- Total validators
- Active clusters
- Recent blocks table

#### **👥 Validator Activity**
- Total active validators
- Average Synergy Score
- Top validators list with:
  - Address
  - Name
  - Synergy Score
  - Blocks produced
  - Uptime

#### **🌐 Network Status**
- Connected peers count
- Network topology
- Connection quality (Good/Fair/Poor)
- Bootstrap nodes count

### Configuration Tab
- View configuration file location
- Edit configuration (placeholder)
- Reload configuration (placeholder)
- Node restart warning

### Logs Tab
- Log directory path
- Real-time log viewer (placeholder)
- Indicates if node is running

---

## Directory Structure

```
~/.synergy/control-panel/
├── bin/
│   └── synergy-testnet          # Node binary
├── templates/
│   ├── validator.toml          # Validator config template
│   ├── rpc_gateway.toml        # RPC node config template
│   └── relayer.toml            # Relayer config template
├── nodes/
│   └── {node-id}/              # Each node gets its own sandbox
│       ├── config/
│       │   └── node.toml       # Node-specific configuration
│       ├── keys/
│       │   ├── public.key      # FN-DSA-1024 public key
│       │   └── private.key     # FN-DSA-1024 private key (encrypted)
│       ├── logs/
│       │   └── node.log        # Node operation logs
│       └── data/
│           └── blockchain/     # Blockchain state data
└── state.json                  # Control panel state persistence
```

---

## Technical Architecture

### Frontend Components

#### **JarvisSetupWizard.jsx**
Main setup wizard component with:
- **State Management**:
  - Chat messages
  - User input
  - Current step
  - Terminal output
  - Setup progress
- **Event Handling**:
  - User input submission
  - Node type selection
  - Setup confirmation
- **Terminal Integration**:
  - Real-time output display
  - Color-coded messages
  - Timestamp tracking
  - Auto-scroll

#### **MultiNodeDashboard.jsx**
Dashboard component featuring:
- **Node List Sidebar**: All configured nodes
- **Tab Navigation**: Overview, Monitoring, Config, Logs
- **Real-time Updates**: 5-second refresh for node list, 3-second for monitoring
- **Metric Display**: Key metrics with live data
- **Control Functions**: Start, stop, add nodes

### Backend Commands (Electron)

#### **init_multi_node_environment()**
- Creates control panel directory structure
- Sets up bin, templates, and nodes directories
- Returns initialization status

#### **setup_node(nodeType, displayName)**
- Creates node sandbox directory
- Generates PQC keypair using synergy-address-engine
- Derives Synergy address from public key
- Copies configuration template
- Registers node with testnet
- Initiates blockchain sync
- Returns node ID

#### **get_all_nodes()**
- Retrieves list of all configured nodes
- Returns node instances with status

#### **start_node_by_id(nodeId)**
- Launches node process
- Updates node status
- Returns success/failure

#### **stop_node_by_id(nodeId)**
- Gracefully stops node process
- Updates node status
- Returns success/failure

#### **get_node_by_id(nodeId)**
- Retrieves specific node details
- Returns node instance

### Cryptographic Operations

#### **generate_pqc_keypair(nodeClass, keysDir)**
- Uses synergy-address-engine binary
- Generates FN-DSA-1024 keypair
- NIST Level 5 security (256-bit quantum resistance)
- Public key: 1,793 bytes
- Private key: 2,305 bytes
- Returns node identity with address

#### **register_node_with_network(binaryPath, nodeIdentity, configPath)**
- Connects to testnet-api.synergy-network.io
- Submits node public key and address
- Waits for registration confirmation
- Returns registration status

#### **connect_and_sync(binaryPath, configPath)**
- Connects to bootnodes
- Requests blockchain headers
- Downloads blocks sequentially
- Updates sync progress
- Returns sync status

---

## Network Configuration

### Testnet Ports
- **38638**: P2P/SNR gossip
- **48638**: JSON-RPC HTTP
- **58638**: WebSocket
- **9090**: Prometheus metrics (optional)

### Bootnodes
```
bootnode1.synergy-network.io:38638
bootnode2.synergy-network.io:38638
bootnode3.synergy-network.io:38638
```

### Chain ID
- **Testnet**: 1264

---

## Styling & UX

### Chat Interface
- **Split-screen layout**: 50/50 when terminal is visible
- **Full-width chat**: Before terminal appears
- **Smooth transitions**: CSS transitions for layout changes
- **Typing indicators**: Animated dots while Jarvis is "thinking"
- **Message animations**: Slide-in effect for new messages
- **Markdown support**: Bold text using `**text**`

### Terminal Interface
- **macOS-style header**: Red, yellow, green dots
- **Dark theme**: VS Code-inspired color scheme
- **Monospace font**: Courier New
- **Color coding**:
  - Success: #4ec9b0 (teal)
  - Error: #f48771 (red)
  - Warning: #dcdcaa (yellow)
  - Info: #d4d4d4 (light gray)
  - Timestamps: #858585 (gray)
- **Progress bar**: Gradient purple/blue with percentage

### Dashboard
- **Responsive grid**: Auto-fit columns for metrics
- **Gradient borders**: Using ::before pseudo-element trick
- **Hover effects**: Translateы upward on hover
- **Live updates**: Subtle color changes for active metrics
- **Status badges**: Color-coded (green=running, red=stopped)

---

## Error Handling

### Setup Errors
- Environment initialization failure → Clear error message + restart instructions
- PQC key generation failure → Crypto error details + troubleshooting
- Network registration failure → Connection details + retry option
- Sync failure → Bootnode connectivity check + manual sync option

### Runtime Errors
- Node start failure → Port conflict detection + resolution
- Node crash → Automatic detection + restart prompt
- Connection loss → Reconnection attempts + fallback bootnodes

---

## Future Enhancements

### Planned Features
1. **Multi-node setup in one session**: Set up multiple compatible nodes at once
2. **Advanced node configuration**: Edit config files directly in UI
3. **Log streaming**: Real-time log viewer with filtering
4. **Performance metrics**: CPU, RAM, disk usage graphs
5. **Backup & restore**: Node state backup and migration
6. **Update management**: Automatic updates for node software
7. **Alert system**: Notifications for node events
8. **Node clustering**: Set up validator clusters automatically

### Additional Node Types
Once validator, RPC, and relayer nodes are fully tested:
- Archive Validator
- Audit Validator
- Witness
- Oracle
- Compute
- AI Inference
- And 11 more node types!

---

## Troubleshooting

### Common Issues

#### **Setup wizard stuck on "Initializing environment"**
- **Cause**: Permission issues with `~/.synergy` directory
- **Solution**: Check directory permissions, ensure write access

#### **Terminal shows "Failed to generate PQC keypair"**
- **Cause**: synergy-address-engine binary not found or not executable
- **Solution**: Verify binary exists in `bin/` directory, check execute permissions

#### **"Failed to register with network"**
- **Cause**: Network connectivity issues or testnet API unavailable
- **Solution**: Check internet connection, verify firewall settings

#### **Sync progress stuck at X%**
- **Cause**: Bootnode connection lost or slow network
- **Solution**: Check bootnode connectivity, wait for automatic reconnection

#### **Dashboard shows "---" for all metrics**
- **Cause**: Node not running or monitoring data unavailable
- **Solution**: Start the node, wait for initial sync to complete

---

## Development Notes

### Testing Checklist
- [ ] Validator node setup end-to-end
- [ ] RPC node setup end-to-end
- [ ] Relayer node setup end-to-end
- [ ] Terminal output appears correctly
- [ ] Progress bar updates smoothly
- [ ] Dashboard loads with correct metrics
- [ ] Start/stop node functionality
- [ ] Multiple node management
- [ ] Error handling for all failure scenarios
- [ ] Responsive layout on different screen sizes

### Code Organization
```
src/
├── components/
│   ├── JarvisSetupWizard.jsx    # Main setup wizard
│   ├── MultiNodeDashboard.jsx   # Dashboard
│   ├── Layout.jsx               # App layout wrapper
│   └── ...
├── styles.css                    # All application styles
└── App.jsx                       # Main app component

control-service/src/
├── node_manager/
│   ├── commands.rs              # Electron command handlers
│   ├── crypto.rs                # PQC operations
│   ├── multi_node.rs            # Node management
│   ├── multi_node_process.rs   # Process control
│   ├── types.rs                 # Data structures
│   └── node_classes.rs          # Node class definitions
└── main.rs                      # Electron entry point
```

---

## References

- [Validator Guide](guides/validator-guide-ubuntu.md) - Complete validator setup documentation
- [RPC Node Guide](guides/RPC_NODE_SETUP_GUIDE.md) - RPC node configuration details
- [Relayer Guide](guides/RELAYER_NODE_SETUP_GUIDE.md) - SXCP relayer setup instructions
- [Testnet Ports](guides/SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt) - Network port specifications

---

## Support

For issues, questions, or feature requests:
- **Discord**: [Synergy Network Discord](https://discord.gg/synergy)
- **GitHub Issues**: [control-panel/issues](https://github.com/synergy-network-hq/control-panel/issues)
- **Email**: support@synergy-network.io

---

*Built with ❤️ for the Synergy Network community*
