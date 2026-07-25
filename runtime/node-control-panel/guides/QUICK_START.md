# Synergy Testnet - Quick Start

## Build & Run in 3 Steps

```bash
# 1. Build the binary
./testnet.sh build

# 2. Start a node (choose any of the 19 types)
./testnet.sh start validator

# 3. Check status
./testnet.sh status
```

## Common Commands

```bash
# List all available node types
./testnet.sh list

# Start different node types
./testnet.sh start validator      # Core validator
./testnet.sh start oracle          # Oracle node
./testnet.sh start ai-inference    # AI inference node
./testnet.sh start rpc-gateway     # RPC gateway

# View logs
./testnet.sh logs                  # View recent logs
./testnet.sh logs follow           # Follow logs in real-time

# Control nodes
./testnet.sh stop                  # Stop the node
./testnet.sh restart validator     # Restart with new type
./testnet.sh status                # Check if running

# Maintenance
./testnet.sh clean                 # Clean all data (requires confirmation)
```

## Available Node Types (19 Total)

**Class I - Validators & Governance:**
- validator
- archive-validator
- audit-validator
- committee
- governance-auditor
- security-council
- treasury-controller

**Class II - Data & Infrastructure:**
- oracle
- observer
- indexer
- data-availability
- cross-chain-verifier
- relayer
- rpc
- rpc-gateway
- witness

**Class III - Compute & AI:**
- ai-inference
- compute
- pqc-crypto
- uma-coordinator

## Binary Commands (Alternative)

```bash
# Direct binary usage
./target/release/synergy-testnet start --node-type validator
./target/release/synergy-testnet list-templates
./target/release/synergy-testnet generate-keypair
./target/release/synergy-testnet version
./target/release/synergy-testnet logs --follow
./target/release/synergy-testnet stop
```

## Default Ports

- **P2P**: 5622
- **RPC**: 5640
- **WebSocket**: 5660

## Files & Directories

- **Binary**: `./target/release/synergy-testnet`
- **Templates**: `./templates/`
- **Config**: `./config/node.toml`
- **Data**: `./data/chain/`
- **Logs**: `./data/logs/`
- **PID File**: `./data/synergy-testnet.pid`

## Troubleshooting

```bash
# If node won't stop
pkill -9 synergy-testnet
rm -f data/synergy-testnet.pid

# Clean restart
./testnet.sh stop
./testnet.sh clean
./testnet.sh start validator

# Change ports (if in use)
export SYNERGY_RPC_PORT=5660
export SYNERGY_P2P_PORT=30304
./testnet.sh start validator
```

## Running Multiple Nodes

Open multiple terminals:

```bash
# Terminal 1: Validator
export SYNERGY_RPC_PORT=5640 && export SYNERGY_P2P_PORT=5622
./target/release/synergy-testnet start --node-type validator

# Terminal 2: Oracle
export SYNERGY_RPC_PORT=5660 && export SYNERGY_P2P_PORT=30304
./target/release/synergy-testnet start --node-type oracle

# Terminal 3: RPC Gateway
export SYNERGY_RPC_PORT=8547 && export SYNERGY_P2P_PORT=30305
./target/release/synergy-testnet start --node-type rpc-gateway
```

## Next Steps

For detailed documentation, see [TESTNET_GUIDE.md](TESTNET_GUIDE.md)
