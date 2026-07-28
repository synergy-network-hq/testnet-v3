# Synergy Testnet Quick Reference

## Network Configuration

- **Chain ID**: 1266
- **P2P Port**: 5622
- **RPC Port**: 5640
- **WebSocket Port**: 5660
- **Metrics Port**: 6030

## Endpoints

- **Core RPC**: https://testnet-core-rpc.synergy-network.io
- **Core WebSocket**: wss://testnet-core-ws.synergy-network.io
- **EVM RPC**: https://testnet-evm-rpc.synergy-network.io
- **EVM WebSocket**: wss://testnet-evm-ws.synergy-network.io
- **API**: https://testnet-api.synergy-network.io
- **Explorer**: https://testnet-explorer.synergy-network.io
- **Indexer**: https://testnet-indexer.synergy-network.io
- **Faucet**: https://testnet-faucet.synergy-network.io

## Bootnodes

### Bootnode 1
- **Address**: `synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv`
- **P2P**: `snr://synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv@bootnode1.synergy-network.io:5620`
- **Config**: `config/bootnode1.toml` or `config/node_config.toml`
- **Keys**: `config/bootnode1/identity.json`

### Bootnode 2
- **Address**: `synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04`
- **P2P**: `snr://synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04@bootnode2.synergy-network.io:5620`
- **Config**: `config/bootnode2.toml`
- **Keys**: `config/bootnode2/identity.json`

### Bootnode 3
- **Address**: `synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4`
- **P2P**: `snr://synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4@bootnode3.synergy-network.io:5620`
- **Config**: `config/bootnode3.toml`
- **Keys**: `config/bootnode3/identity.json`

## Wallets

### Faucet
- **Address**: `synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07`
- **Balance**: 2,000,000,000 SNRG (2 Billion)
- **Keys**: `config/faucet/identity.json`

### Treasury (DAO)
- **Address**: `synw14lswrh8z7kremft633xym9wtr5l9vkm3rd6lvd`
- **Balance**: 9,997,000,000 SNRG (9.997 Billion)
- **Keys**: `config/treasury/identity.json`

## Cluster

- **Cluster ID**: `syngrp116xlcwtcuwd8cdkqrftdww5dpqvm699uanux4mc`
- **Name**: Testnet Bootstrap Cluster
- **Class**: 1 (Consensus Nodes)

## Network

- **Total Supply**: 12,000,000,000 SNRG
- **Burn Address**: `synergy00000000000000000000000burn`
- **Chain ID**: `1266`
- **Runtime Network ID**: `synergy-testnet-v3`

## Quick Commands

```bash
# Start primary bootnode
./testnet.sh start validator

# Check status
./testnet.sh status

# View logs
./testnet.sh logs

# Clean and reset
./testnet.sh clean

# Build project
./testnet.sh build
```

## Generate New Address

```bash
# Validator address
./target/release/synergy-address-engine --node-type validator

# Wallet address
./target/release/synergy-address-engine --node-type wallet

# Cluster address
./target/release/synergy-address-engine --node-type cluster1
```
