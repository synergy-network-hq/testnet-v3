# Synergy Testnet - Setup & Management Guide

A comprehensive guide for building and running the Synergy blockchain testnet with support for 19 different node types.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Building the Testnet](#building-the-testnet)
- [Node Types](#node-types)
- [Quick Start](#quick-start)
- [Management Commands](#management-commands)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## Prerequisites

- Rust 1.70 or higher
- Cargo (comes with Rust)
- macOS, Linux, or Windows with WSL2

## Building the Testnet

### Option 1: Using the Management Script (Recommended)

```bash
./testnet.sh build
```

### Option 2: Using Cargo Directly

```bash
cargo build --release
```

The binary will be located at: `./target/release/synergy-testnet`

## Node Types

The Synergy testnet supports 19 specialized node types:

| Type | Class | Description |
|------|-------|-------------|
| validator | Class I | Core blockchain validator |
| oracle | Class II | External data provider |
| ai-inference | Class III | AI model execution node |
| archive-validator | Class I | Validator with full history |
| audit-validator | Class I | Validator with audit capabilities |
| committee | Class I | Governance committee member |
| compute | Class III | General computation node |
| cross-chain-verifier | Class II | Cross-chain bridge verifier |
| data-availability | Class II | Data availability layer |
| governance-auditor | Class I | Governance oversight |
| indexer | Class II | Blockchain indexer |
| observer | Class II | Read-only observer node |
| pqc-crypto | Class III | Post-quantum crypto operations |
| relayer | Class II | Cross-chain message relayer |
| rpc | Class II | RPC endpoint provider |
| rpc-gateway | Class II | High-capacity RPC gateway |
| security-council | Class I | Security oversight |
| treasury-controller | Class I | Treasury management |
| uma-coordinator | Class III | UMA coordination |
| witness | Class II | Event witness node |

## Quick Start

### 1. Build the Binary

```bash
./testnet.sh build
```

### 2. List Available Node Templates

```bash
./testnet.sh list
```

### 3. Start a Node

Start a validator node:

```bash
./testnet.sh start validator
```

Start an oracle node:

```bash
./testnet.sh start oracle
```

### 4. Check Node Status

```bash
./testnet.sh status
```

### 5. View Logs

View recent logs:

```bash
./testnet.sh logs
```

Follow logs in real-time:

```bash
./testnet.sh logs follow
```

### 6. Stop the Node

```bash
./testnet.sh stop
```

## Management Commands

### Using the Management Script (`testnet.sh`)

The `testnet.sh` script provides a convenient interface:

| Command | Description | Example |
|---------|-------------|---------|
| `build` | Build the testnet binary | `./testnet.sh build` |
| `start <type>` | Start a node | `./testnet.sh start validator` |
| `stop` | Stop the running node | `./testnet.sh stop` |
| `restart <type>` | Restart the node | `./testnet.sh restart oracle` |
| `status` | Check node status | `./testnet.sh status` |
| `logs [follow]` | View logs | `./testnet.sh logs` |
| `list` | List node templates | `./testnet.sh list` |
| `clean` | Clean data and logs | `./testnet.sh clean` |
| `help` | Show help message | `./testnet.sh help` |

### Using the Binary Directly

You can also use the binary directly:

```bash
# Show help
./target/release/synergy-testnet help

# Start a specific node type
./target/release/synergy-testnet start --node-type validator

# Start with custom config
./target/release/synergy-testnet start --config config/custom.toml

# List available templates
./target/release/synergy-testnet list-templates

# Generate a keypair
./target/release/synergy-testnet generate-keypair

# Check status
./target/release/synergy-testnet status

# View logs
./target/release/synergy-testnet logs --follow
./target/release/synergy-testnet logs --lines 100

# Show version
./target/release/synergy-testnet version
```

## Configuration

### Using Templates

Each node type has a pre-configured template in the `templates/` directory:

```
templates/
├── validator.toml
├── oracle.toml
├── ai-inference.toml
├── archive-validator.toml
└── ... (19 templates total)
```

To start a node with a template:

```bash
./target/release/synergy-testnet start --node-type <template-name>
```

### Custom Configuration

You can create custom configuration files based on the templates:

1. Copy a template:
```bash
cp templates/validator.toml config/my-custom-node.toml
```

2. Edit the configuration:
```bash
nano config/my-custom-node.toml
```

3. Start with custom config:
```bash
./target/release/synergy-testnet start --config config/my-custom-node.toml
```

### Environment Variables

You can override configuration values with environment variables:

```bash
export SYNERGY_LOG_LEVEL=debug
export SYNERGY_RPC_PORT=5660
export SYNERGY_P2P_PORT=30304
./target/release/synergy-testnet start --node-type validator
```

Supported environment variables:
- `SYNERGY_NETWORK_ID` - Network ID
- `SYNERGY_P2P_PORT` - P2P port
- `SYNERGY_RPC_PORT` - RPC HTTP port
- `SYNERGY_WS_PORT` - WebSocket port
- `SYNERGY_LOG_LEVEL` - Log level (debug, info, warn, error)
- `SYNERGY_LOG_FILE` - Log file path
- `SYNERGY_DATA_PATH` - Data directory path
- `SYNERGY_CONFIG_PATH` - Configuration file path

## Directory Structure

```
synergy-testnet/
├── target/
│   └── release/
│       └── synergy-testnet          # Main binary
├── templates/                       # Node configuration templates
│   ├── validator.toml
│   ├── oracle.toml
│   └── ...
├── config/                          # User configurations
│   └── node.toml                    # Default config
├── data/                            # Runtime data (created on first run)
│   ├── chain/                       # Blockchain data
│   ├── logs/                        # Log files
│   └── synergy-testnet.pid           # Process ID file
├── testnet.sh                        # Management script
└── TESTNET_GUIDE.md                # This guide
```

## Running Multiple Nodes

To run multiple nodes simultaneously, use different ports:

### Terminal 1 - Validator Node
```bash
export SYNERGY_RPC_PORT=5640
export SYNERGY_P2P_PORT=5622
./target/release/synergy-testnet start --node-type validator
```

### Terminal 2 - Oracle Node
```bash
export SYNERGY_RPC_PORT=5660
export SYNERGY_P2P_PORT=30304
./target/release/synergy-testnet start --node-type oracle
```

### Terminal 3 - RPC Gateway
```bash
export SYNERGY_RPC_PORT=8547
export SYNERGY_P2P_PORT=30305
./target/release/synergy-testnet start --node-type rpc-gateway
```

## Troubleshooting

### Binary Not Found

**Problem**: `Error: Binary not found`

**Solution**:
```bash
cargo build --release
```

### Port Already in Use

**Problem**: `Error: Address already in use`

**Solution**: Change the port using environment variables:
```bash
export SYNERGY_RPC_PORT=5660
./testnet.sh start validator
```

### Node Won't Stop

**Problem**: Node continues running after stop command

**Solution**: Force kill the process:
```bash
pkill -9 synergy-testnet
rm -f data/synergy-testnet.pid
```

### Logs Not Found

**Problem**: Cannot view logs

**Solution**: Ensure the node has been started at least once:
```bash
mkdir -p data/logs
./testnet.sh start validator
```

### Clean Start

To completely reset the testnet:

```bash
./testnet.sh stop
./testnet.sh clean
./testnet.sh start validator
```

## Development Workflow

### 1. Make Code Changes

Edit files in `src/`

### 2. Rebuild

```bash
./testnet.sh build
```

### 3. Restart Node

```bash
./testnet.sh restart validator
```

### 4. Monitor Logs

```bash
./testnet.sh logs follow
```

## Advanced Usage

### Generate PQC Keypair

```bash
./target/release/synergy-testnet generate-keypair
```

Output format (JSON):
```bash
./target/release/synergy-testnet generate-keypair --format json
```

### Initialize Configuration Directory

```bash
./target/release/synergy-testnet init
```

### Custom Log Viewing

```bash
# View specific number of lines
./target/release/synergy-testnet logs --lines 200

# Follow logs
./target/release/synergy-testnet logs --follow

# View with grep
./testnet.sh logs | grep ERROR
```

## Network Information

- **Network Name**: synergy-testnet
- **Chain ID**: 1264
- **Default P2P Port**: 5622
- **Default RPC Port**: 5640
- **Default WS Port**: 5660
- **Consensus**: Proof of Synergy

## Support

For issues, questions, or contributions:
- GitHub Issues: [Create an issue]
- Documentation: See inline code documentation

## Version

Current Version: 0.1.0
Platform: macOS, Linux, Windows (WSL2)

---

Built with Rust and the Synergy blockchain framework.
