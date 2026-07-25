# Synergy Testnet Control Panel - Setup Guide

## Overview

The Synergy Testnet Control Panel is a sophisticated desktop application built with Electron (Rust + React) that provides an intuitive chat-based interface for setting up and managing multiple Synergy Network nodes with complete isolation and security.

## Features

### 🤖 Jarvis AI Assistant
- Interactive chat-based setup wizard
- Natural conversation flow with typing indicators
- Smart compatibility checking between node types
- Custom node naming and configuration

### 🔒 Security & Isolation
- **Complete Isolation**: Control panel runs in `~/.synergy/control-panel/`
- **Node Separation**: Each node gets its own isolated directory structure
- **Sandbox Architecture**: Nodes cannot interact with the host system directly
- **Safe Binary Management**: All binaries stored in isolated directories

### 🚀 19 Node Types Supported
1. Validator
2. Committee
3. Archive Validator
4. Audit Validator
5. Relayer
6. Witness
7. Oracle
8. UMA Coordinator
9. Cross Chain Verifier
10. Compute
11. AI Inference
12. PQC Crypto
13. Data Availability
14. Governance Auditor
15. Treasury Controller
16. Security Council
17. RPC Gateway
18. Indexer
19. Observer

### 📊 Multi-Node Dashboard
- Real-time monitoring of all configured nodes
- Individual control: Start, Stop, Restart
- Status indicators with live updates
- Detailed node information panels
- Log viewing and configuration management

## Prerequisites

- **Node.js** 18+ and npm
- **Rust** 1.70+ (for Electron)
- **macOS/Linux/Windows** with appropriate development tools

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd control-panel
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Place Node Binary

Ensure the `synergy-testnet` binary is in the project root:

```
control-panel/
├── synergy-testnet          # Node binary (executable)
├── templates/              # 19 node config templates
├── public/
│   └── snrg.gif           # Loading animation
├── src/
└── control-service/
```

### 4. Verify Templates

The `templates/` directory should contain 19 TOML configuration files:
- validator.toml
- committee.toml
- archive-validator.toml
- audit-validator.toml
- relayer.toml
- witness.toml
- oracle.toml
- uma-coordinator.toml
- cross-chain-verifier.toml
- compute.toml
- ai-inference.toml
- pqc-crypto.toml
- data-availability.toml
- governance-auditor.toml
- treasury-controller.toml
- security-council.toml
- rpc-gateway.toml
- indexer.toml
- observer.toml

## Development

### Run in Development Mode

```bash
npm run dev:electron
```

This will:
1. Start the Vite development server (React frontend)
2. Launch the Electron application (Rust backend)
3. Enable hot-reload for both frontend and backend changes

### Build Frontend Only

```bash
npm run build
```

### Build Backend Only

```bash
cd control-service
cargo build
```

## Building for Production

### Create Production Build

```bash
npm run dist:electron
```

This will create platform-specific installers in `control-service/target/release/bundle/`:

- **macOS**: `.dmg` and `.app`
- **Windows**: `.msi` and `.exe`
- **Linux**: `.deb`, `.AppImage`, etc.

## Project Structure

```
control-panel/
├── src/                          # React frontend
│   ├── components/
│   │   ├── JarvisWizard.jsx     # Chat-based setup wizard
│   │   ├── MultiNodeDashboard.jsx # Multi-node dashboard
│   │   └── Layout.jsx
│   ├── App.jsx                   # Main application
│   └── styles.css                # Complete styling
├── control-service/                    # Rust backend
│   ├── src/
│   │   ├── main.rs              # Electron entry point
│   │   └── node_manager/
│   │       ├── types.rs         # Data structures
│   │       ├── multi_node.rs    # Multi-node manager
│   │       ├── multi_node_process.rs # Process control
│   │       ├── commands.rs      # Electron commands
│   │       └── ...
│   ├── Cargo.toml               # Rust dependencies
│   └── electron-builder.yml          # Electron configuration
├── templates/                    # Node configuration templates
├── public/                       # Static assets
│   └── snrg.gif
├── synergy-testnet               # Node binary
└── package.json
```

## Usage

### First Launch

1. **Welcome Screen**: Jarvis greets you and explains the setup process
2. **Environment Initialization**: Creates isolated control panel directory
3. **Node Selection**: Choose from 19 node types via chat
4. **Compatibility Check**: Jarvis ensures nodes are compatible
5. **Custom Naming**: Optional custom names for nodes
6. **Multiple Nodes**: Add as many compatible nodes as needed
7. **Loading Screen**: Animated progress bar during setup
8. **Auto-Start**: All nodes start automatically
9. **Dashboard**: Monitor and control all nodes

### Managing Nodes

From the dashboard you can:
- **View Status**: Real-time status of each node
- **Start/Stop**: Control individual nodes
- **View Logs**: Access node logs
- **Check Configuration**: Review node settings
- **Monitor Metrics**: See node performance data

### Compatibility Rules

The compatibility matrix ensures only compatible nodes can run together:

- **Validator** can run with: Committee, Archive Validator, Audit Validator
- **Relayer** can run with: Witness, Oracle
- **UMA Coordinator** can run with: Cross Chain Verifier
- **Compute** can run with: AI Inference, PQC Crypto
- **Security Council** can run with: Governance Auditor, Treasury Controller
- **RPC Gateway** can run with: Indexer, Observer

## Directory Structure (Runtime)

When running, the control panel creates:

```
~/.synergy/control-panel/
├── bin/
│   └── synergy-testnet           # Node binary
├── templates/                    # Config templates
├── nodes/
│   ├── <node-id-1>/
│   │   ├── config/
│   │   │   └── node.toml
│   │   ├── logs/
│   │   ├── data/
│   │   └── keys/
│   ├── <node-id-2>/
│   │   └── ...
│   └── ...
└── state.json                    # Control panel state
```

## Troubleshooting

### Build Fails

```bash
# Clean and rebuild
cd control-service
cargo clean
cargo build
```

### Node Won't Start

1. Check the node binary has execute permissions
2. Verify config file exists in node's config directory
3. Check logs in `~/.synergy/control-panel/nodes/<node-id>/logs/`

### Permission Errors

On Unix systems, ensure the binary is executable:

```bash
chmod +x synergy-testnet
```

## Development Tips

### Hot Reload

Changes to React components will hot-reload automatically in dev mode.

### Rust Changes

Rust changes require a rebuild, but Electron will detect and recompile automatically in dev mode.

### Debugging

- **Frontend**: Use browser DevTools (F12 in the app window)
- **Backend**: Check console output where you ran `npm run dev:electron`
- **Logs**: Node logs are in `~/.synergy/control-panel/nodes/<node-id>/logs/`

### Adding New Node Types

1. Add enum variant in `control-service/src/node_manager/types.rs`
2. Update compatibility rules in `compatible_nodes()` method
3. Create template file in `templates/` directory
4. Update node type descriptions in `commands.rs`

## API Reference

### Electron Commands

The frontend can invoke these Rust commands:

- `check_multi_node_initialization()` - Check if control panel is initialized
- `init_multi_node_environment()` - Initialize control panel environment
- `get_available_node_types()` - Get list of available node types
- `setup_node(nodeType, displayName)` - Set up a new node
- `get_all_nodes()` - Get all configured nodes
- `get_node_by_id(nodeId)` - Get specific node details
- `start_node_by_id(nodeId)` - Start a node
- `stop_node_by_id(nodeId)` - Stop a node
- `restart_node_by_id(nodeId)` - Restart a node
- `get_node_logs(nodeId)` - Get node logs
- `remove_node(nodeId)` - Remove a node

## License

[Your License Here]

## Support

For issues and feature requests, please use the GitHub issue tracker.
