# Synergy Testnet - Node Deployment Summary
**Complete Guide Index for All Node Types**

> Current post-fork onboarding requires the Synergy Node Control Panel flow, explicit FN-DSA validator keys, and `50,000 SNRG` bonded stake. Legacy deployment references below are historical; use `guides/CONTROL_PANEL_INSTALL_AND_NEW_VALIDATOR_ONBOARDING.md` for launch-current validator setup.

---

## Overview

This document provides a comprehensive index of all available node setup guides for the Synergy Testnet, organized by node type and use case.

---

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Synergy Testnet Network                   │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │          Consensus Layer (PoSy)                    │    │
│  │                                                     │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │    │
│  │  │  Bootnode 1  │  │  Bootnode 2  │  │Bootnode 3│ │    │
│  │  │  (Genesis)   │  │  (Genesis)   │  │(Genesis) │ │    │
│  │  └──────────────┘  └──────────────┘  └──────────┘ │    │
│  │         +                +                +        │    │
│  │  ┌──────────────────────────────────────────────┐ │    │
│  │  │   Team Validators (Dynamic Registration)     │ │    │
│  │  │   • Cluster-based consensus                  │ │    │
│  │  │   • Synergy Score weighted voting            │ │    │
│  │  │   • Dynamic cluster rotation each epoch      │ │    │
│  │  └──────────────────────────────────────────────┘ │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │          Infrastructure Layer                       │    │
│  │                                                     │    │
│  │  ┌───────────┐  ┌───────────┐  ┌────────────────┐ │    │
│  │  │ RPC Nodes │  │ Indexers  │  │ Data Avail.    │ │    │
│  │  │ (Public   │  │ (Query    │  │ (Archive)      │ │    │
│  │  │ Endpoints)│  │ Service)  │  │                │ │    │
│  │  └───────────┘  └───────────┘  └────────────────┘ │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │     Cross-Chain Layer (SXCP - Bridgeless)          │    │
│  │                                                     │    │
│  │  ┌──────────────────────────────────────────────┐  │    │
│  │  │      Relayer Cluster (5 nodes)               │  │    │
│  │  │  • Monitors Sepolia, Polygon Amoy, etc.      │  │    │
│  │  │  • Verifies messages with Merkle proofs      │  │    │
│  │  │  • No bridge contracts (bridgeless)          │  │    │
│  │  │  • Post-quantum signatures (ML-DSA)          │  │    │
│  │  └──────────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Quick Navigation

### For Team Members

| I Want To... | Read This Guide | Difficulty | Estimated Time |
|--------------|----------------|------------|----------------|
| **Set up a validator node** | [VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md) | Medium | 2-3 hours |
| **Provide RPC endpoints** | [RPC_NODE_SETUP_GUIDE.md](RPC_NODE_SETUP_GUIDE.md) | Easy | 1-2 hours |
| **Run cross-chain relayer** | [RELAYER_NODE_SETUP_GUIDE.md](RELAYER_NODE_SETUP_GUIDE.md) | Advanced | 3-4 hours |
| **Test PoSy consensus** | [POSY_CLUSTER_TESTING_GUIDE.md](POSY_CLUSTER_TESTING_GUIDE.md) | Advanced | Ongoing |

### For Coordinators

| I Need To... | Read This Guide |
|--------------|----------------|
| **Manage validator onboarding** | [COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md) |
| **Send SNRG tokens** | [COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md) - Token Distribution |
| **Monitor network health** | [COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md) - Monitoring |
| **Register validators** | [COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md) - Registration |

---

## Node Type Details

### 1. Bootnode Validators

**Status**: ✅ Operational (3 bootnodes)

**Purpose**: Validators that bootstrap the network

**Characteristics:**
- **Participate in consensus**: Yes (PoSy)
- **Earn Synergy Score**: Yes
- **Required stake**: 50,000 SNRG (validator allocation)
- **Public endpoints**: Yes (bootnodes for peer discovery)

**Configuration Files:**
- [config/node_config.toml](config/node_config.toml) - Bootnode 1
- [config/bootnode2.toml](config/bootnode2.toml) - Bootnode 2
- [config/bootnode3.toml](config/bootnode3.toml) - Bootnode 3

**Bootnode DNS:**
- `bootnode1.synergy-network.io:5620`
- `bootnode2.synergy-network.io:5620`
- `bootnode3.synergy-network.io:5620`

**Initial Cluster:**
- Cluster ID: `syngrp116xlcwtcuwd8cdkqrftdww5dpqvm699uanux4mc`
- Members: All 3 bootnodes

---

### 2. Team Validator Nodes (Dynamic Registration)

**Status**: ✅ Ready for onboarding

**Purpose**: Allow team members to run validators on remote systems

**Setup Guide**: [VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md)

**Key Features:**
- **Dynamic registration**: Register after network launch (no need to be in the genesis block)
- **Stake requirement**: 50,000 SNRG bonded before activation
- **Synergy Score participation**: Earn rewards and voting power based on performance
- **Cluster assignment**: Automatically assigned to clusters each epoch
- **Blockchain sync**: Download and verify existing blockchain state

**Requirements:**
- Ubuntu 22.04+ server
- 4+ CPU cores
- 16+ GB RAM
- 200+ GB SSD storage
- Public IP or port forwarding

**Workflow:**
1. Team member follows validator setup guide
2. Generates validator identity (FN-DSA-1024 keypair)
3. Shares `validator-info.txt` with coordinator
4. Coordinator registers validator and sends SNRG
5. Team member starts node and syncs blockchain
6. Validator automatically participates in consensus

**Coordinator Tools:**
- `scripts/register-validator.sh` - Register new validators
- `scripts/send-tokens.sh` - Send SNRG to validators
- `scripts/list-validators.sh` - Monitor all validators

---

### 3. RPC Nodes

**Status**: ✅ Guide available

**Purpose**: Provide public JSON-RPC and WebSocket endpoints

**Setup Guide**: [RPC_NODE_SETUP_GUIDE.md](RPC_NODE_SETUP_GUIDE.md)

**Key Features:**
- **Does NOT participate in consensus** (Class II node)
- **Full blockchain sync**: Maintains complete state
- **Transaction indexing**: Enable fast tx lookups by hash
- **High availability**: Serve many concurrent client requests
- **No staking required**: No SNRG needed to operate

**Use Cases:**
- Wallet backends
- dApp infrastructure
- Block explorers
- Developer testing
- Public API endpoints

**Ports:**
- **HTTP RPC**: 5640
- **WebSocket**: 5660
- **P2P**: 5622 (sync only, not consensus)

**Performance Considerations:**
- Recommended: 8+ CPU cores, 32+ GB RAM
- NVMe SSD for best database performance
- Disable state pruning (keep full history)
- Enable transaction indexing

**Optional Features:**
- HTTPS via Nginx reverse proxy
- Load balancing with multiple RPC nodes
- Cloudflare DDoS protection
- Custom rate limiting

---

### 4. Relayer Nodes (SXCP Cross-Chain)

**Status**: ✅ Guide available

**Purpose**: Enable bridgeless cross-chain communication via SXCP

**Setup Guide**: [RELAYER_NODE_SETUP_GUIDE.md](RELAYER_NODE_SETUP_GUIDE.md)

**Key Features:**
- **Bridgeless protocol**: No custodial bridge contracts
- **Cryptographic verification**: Merkle proofs + ML-DSA signatures
- **Multi-chain monitoring**: Sepolia, Polygon Amoy, etc.
- **Cluster consensus**: 5-node relayer clusters with 67% quorum
- **Post-quantum secure**: All signatures use ML-DSA-87

**Architecture:**
```
Source Chain (Sepolia)
       ↓
  Event Emission
       ↓
Relayer Detection → Merkle Proof Generation
       ↓
Cluster Consensus (5 relayers vote)
       ↓
Proof Submission → Destination Chain (Synergy)
       ↓
Cryptographic Verification (on-chain)
       ↓
Message Execution
```

**Recommended Deployment:**
- **5 relayer nodes** for full cluster
- Each node monitors same source chains
- Cluster achieves 67% quorum (4/5 signatures)
- Leader selection and quorum follow the protocol consensus rules; Synergy Score is observational telemetry only.

**Supported Source Chains:**
- Ethereum Sepolia (testnet)
- Polygon Amoy (testnet)
- Arbitrum Sepolia (optional)
- Optimism Sepolia (optional)
- Base Sepolia (optional)

**Relayer Rewards:**
- Base: 10 SNRG per message
- Complexity bonus: Up to 50 SNRG
- Speed multiplier: 2x for fast relay
- Split among cluster members

**Ports:**
- **Relayer P2P (SXCP)**: 5622 + assignment
- **Relayer RPC (SXCP)**: 5640 + assignment
- **Relayer WS (SXCP)**: 5660 + assignment

---

### 5. PoSy Consensus Testing

**Status**: ✅ Documentation available

**Purpose**: Test cluster-based PoSy consensus mechanics

**Testing Guide**: [POSY_CLUSTER_TESTING_GUIDE.md](POSY_CLUSTER_TESTING_GUIDE.md)

**Test Scenarios:**
1. **Single Cluster Consensus** (3 bootnodes)
   - Verify dual-quorum (67% validation + 51% cooperation)
   - Test validator failure tolerance
   - Monitor block production

2. **Multi-Cluster Formation** (10+ validators)
   - Dynamic cluster distribution
   - Leader selection via protocol consensus rules; Synergy Score remains observational telemetry
   - Round-robin leadership rotation

3. **Epoch Boundary & Cluster Rotation**
   - Entropy beacon generation (ML-KEM)
   - Validator reassignment
   - Leader re-selection
   - Zero downtime rotation

4. **Synergy Score Calculation**
   - Stake weight (capped at 5%)
   - Reputation (uptime × accuracy × slashing)
   - Contribution (proposals + relays + network quality)
   - Cartelization penalty

5. **Cartel Detection**
   - Pairwise correlation analysis
   - Timing similarity detection
   - Automatic penalty application
   - Cluster separation on rotation

6. **Inter-Cluster Bridge Communication**
   - Bridge validator selection
   - ML-DSA message authentication
   - Rate limiting (1000 msg/min)
   - Redundant bridge failover

**Key Metrics:**
- Block time: ~6 seconds
- Finality: < 5 seconds
- Target TPS: 1000+
- Validator participation: > 95%
- Cluster quorum: 67% (weighted) + 51% (count)

---

## Network Endpoints

### Testnet Endpoints

| Service | URL | Purpose |
|---------|-----|---------|
| **RPC** | `https://testnet-core-rpc.synergy-network.io` | JSON-RPC HTTP |
| **WebSocket** | `wss://testnet-core-ws.synergy-network.io` | Real-time subscriptions |
| **REST API** | `https://testnet-api.synergy-network.io` | RESTful queries |
| **Explorer** | `https://testnet-explorer.synergy-network.io` | Block explorer |
| **Indexer** | `https://testnet-indexer.synergy-network.io` | Query service |
| **Faucet** | `https://testnet-faucet.synergy-network.io` | Request test SNRG |

### Port Configuration

| Service | Port | Protocol |
|---------|------|----------|
| **P2P** | 5622 | TCP |
| **RPC HTTP** | 5640 | HTTP |
| **WebSocket** | 5660 | WebSocket |
| **Metrics** | 6030 | HTTP (Prometheus) |
| **Discovery** | 5680 | TCP |
| **Bootnode listener** | 5620 | TCP |
| **Seed-service listener** | 5621 | HTTP |

**Reference**: [SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt](SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt)

---

## Configuration Files Reference

### Network Configuration

| File | Purpose | Used By |
|------|---------|---------|
| [config/network-config.toml](config/network-config.toml) | Global network settings | All nodes |
| [config/genesis.json](config/genesis.json) | Genesis block & initial state | All nodes |
| [config/consensus-config.toml](config/consensus-config.toml) | PoSy consensus parameters | Validators |

### Bootnode Configurations

| File | Node | Address |
|------|------|---------|
| [config/node_config.toml](config/node_config.toml) | Bootnode 1 | synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv |
| [config/bootnode2.toml](config/bootnode2.toml) | Bootnode 2 | synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04 |
| [config/bootnode3.toml](config/bootnode3.toml) | Bootnode 3 | synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4 |

### Identity Files

| File | Entity | Type |
|------|--------|------|
| config/bootnode1/identity.json | Bootnode 1 | Validator (Class I) |
| config/bootnode2/identity.json | Bootnode 2 | Validator (Class I) |
| config/bootnode3/identity.json | Bootnode 3 | Validator (Class I) |
| config/faucet/identity.json | Faucet | Wallet |
| config/treasury/identity.json | Treasury | Wallet |
| config/cluster_identity.json | Genesis Cluster | Group |

### Templates

All node type templates available in [templates/](templates/) directory:

- `validator.toml` - Standard validator
- `rpc.toml` - RPC node
- `relayer.toml` - Cross-chain relayer
- `oracle.toml` - Oracle node
- `indexer.toml` - Blockchain indexer
- `cross-chain-verifier.toml` - Cross-chain verifier
- And 14 more specialized node types...

---

## Token Distribution

### Genesis Allocation (12 Billion SNRG)

| Recipient | Address | Amount | Purpose |
|-----------|---------|--------|---------|
| **Bootnode 1** | synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv | 1,000,000 | Genesis validator |
| **Bootnode 2** | synv11csyhf60yd6gp8n4wflz99km29g7fh8guxrmu04 | 1,000,000 | Genesis validator |
| **Bootnode 3** | synv110y3fuyvqmjdp02j6m6y2rceqjp2dexwu3p6np4 | 1,000,000 | Genesis validator |
| **Faucet** | synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07 | 2,000,000,000 | Token distribution |
| **Treasury** | synw14lswrh8z7kremft633xym9wtr5l9vkm3rd6lvd | 9,997,000,000 | DAO governance |

**Total**: 1,150,000 SNRG

**Burn Address**: `synergy00000000000000000000000burn`

### Recommended Allocations (From Faucet)

| Purpose | Amount | Recipient |
|---------|--------|-----------|
| Initial validator allocation | 1,000,000 SNRG | New team validators |
| Additional testing | 500,000 - 5,000,000 SNRG | Active validators |
| Contract deployment | 10,000 - 100,000 SNRG | Smart contract developers |
| Transaction testing | 10,000 - 50,000 SNRG | General testers |
| Relayer operations | 100,000 SNRG | Each relayer node |

---

## Security & Cryptography

### Post-Quantum Algorithms

All network operations use NIST-standardized post-quantum cryptography:

| Function | Algorithm | Security Level |
|----------|-----------|----------------|
| **Signatures** | FN-DSA-1024 (Falcon) | NIST Level 5 |
| **Key Encapsulation** | ML-KEM-1024 | NIST Level 5 |
| **Fallback Signatures** | SLH-DSA (SPHINCS+) | NIST Level 5 |
| **Address Encoding** | Bech32m | - |
| **Hashing** | SHA3-256 | - |

**Equivalent Security**: AES-256 (256-bit symmetric security)

### Address Prefixes

| Prefix | Type | Example |
|--------|------|---------|
| `synw` | Wallet (primary) | synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07 |
| `syns` | Wallet (secondary) | syns1... |
| `syna` | Wallet (account) | syna1... |
| `synv1` | Validator (Class I) | synv11lylxla8qjcrk3ef8gjlyyhew3z4mjswwwsn6zv |
| `synr` | Relayer (Class II) | synr1... |
| `syngrp1` | Validator Group | syngrp116xlcwtcuwd8cdkqrftdww5dpqvm699uanux4mc |
| `synb1-3` | Fungible Tokens | synb1... |
| `synnft` | NFT Collections | synnft... |
| `syngas` | Gas Tokens | syngas... |

**Reference**: [Synergy Network Address Formatting Standard.pdf](Synergy%20Network%20Address%20Formatting%20Standard.pdf)

---

## Onboarding Checklist

### For Team Members Setting Up Validators

- [ ] Read [VALIDATOR_ONBOARDING_GUIDE.md](VALIDATOR_ONBOARDING_GUIDE.md)
- [ ] Prepare Ubuntu server with requirements
- [ ] Clone repository and build binaries
- [ ] Generate validator identity with address engine
- [ ] Share `validator-info.txt` with coordinator
- [ ] Wait for coordinator to register and send SNRG
- [ ] Configure firewall (ports 5622, 5640, 5660)
- [ ] Start validator node and sync blockchain
- [ ] Monitor Synergy Score and participation
- [ ] Join team communication channels

### For Coordinators Onboarding Validators

- [ ] Read [COORDINATOR_GUIDE.md](COORDINATOR_GUIDE.md)
- [ ] Receive `validator-info.txt` from team member
- [ ] Validate address format (lowercase, synv1 prefix)
- [ ] Run `scripts/register-validator.sh`
- [ ] Send initial SNRG via `scripts/send-tokens.sh` (1M SNRG)
- [ ] Notify team member of successful registration
- [ ] Monitor validator participation via `scripts/list-validators.sh`
- [ ] Check validator Synergy Score after 24 hours

---

## Monitoring & Maintenance

### Essential Monitoring Commands

**Check Network Height:**
```bash
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getBlockHeight","id":1}' | jq
```

**List All Validators:**
```bash
./scripts/list-validators.sh
```

**Check Validator Info:**
```bash
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"validator_getInfo",
    "params":["VALIDATOR_ADDRESS"],
    "id":1
  }' | jq
```

**Check Synergy Score:**
```bash
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc":"2.0",
    "method":"synergy_getScore",
    "params":["VALIDATOR_ADDRESS"],
    "id":1
  }' | jq
```

**Check Cluster Status:**
```bash
curl -s -X POST http://localhost:5640/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"consensus_getClusterInfo","id":1}' | jq
```

### Health Check Scripts

| Script | Purpose |
|--------|---------|
| `scripts/send-tokens.sh` | Send SNRG tokens |
| `scripts/register-validator.sh` | Register new validator |
| `scripts/list-validators.sh` | List all validators |
| `scripts/rpc-health-check.sh` | Check RPC node health |
| `scripts/relayer-health-check.sh` | Check relayer cluster |

---

## Troubleshooting

### Common Issues

**Issue**: Validator not producing blocks
**Solution**: Verify the node's sync, cluster assignment, and protocol-reported quorum. A Synergy Score of zero or unavailable score telemetry does not determine consensus eligibility.

**Issue**: Cannot connect to bootnodes
**Solution**: Verify DNS resolution, check firewall allows port 5622, test with `nc -zv bootnode1.synergy-network.io 5622`

**Issue**: Blockchain sync is slow
**Solution**: Increase peer connections, verify SSD storage, check network bandwidth

**Issue**: RPC requests timing out
**Solution**: Increase `request_timeout_secs`, check database performance, monitor CPU/RAM

**Issue**: Relayer cluster quorum not met
**Solution**: Ensure all relayers online, verify relayer-to-relayer connectivity, and confirm the assigned Synergy node slot is reachable on its frozen beta ports (**5622 + assignment P2P**, **5640 + assignment RPC**, **5660 + assignment WS**).

**Issue**: SXCP not detecting messages
**Solution**: Verify source chain RPC endpoint responding, check event topics match contract events, review relayer logs

---

## Support & Resources

### Documentation

- **Main README**: [README.md](README.md)
- **Port Specification**: [SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt](SYNERGY_TESTNET_PORTS_AND_PROTOCOLS.txt)
- **Port Audit Report**: [PORT_AUDIT_REPORT.md](PORT_AUDIT_REPORT.md)
- **PoSy Consensus**: [PoSy.txt](PoSy.txt)
- **SXCP Protocol**: [SXCP.txt](SXCP.txt)
- **Final Status**: [FINAL_CONFIGURATION_STATUS.md](FINAL_CONFIGURATION_STATUS.md)

### Quick Reference

- **Chain ID**: 1264 (Testnet)
- **Block Time**: ~6 seconds
- **Epoch Length**: ~1000 blocks (~1 hour)
- **Minimum Stake**: 50,000 SNRG bonded before activation
- **Cluster Size Target**: 30 validators
- **Quorum Thresholds**: 67% (validation) + 51% (cooperation)

### Contact

- **GitHub**: https://github.com/synergy-network-hq/synergy-testnet
- **Discord**: Synergy Network Development
- **Coordinator**: Contact via team channels

---

## Next Steps

### Immediate Actions

1. **Team Members**: Choose your node type and follow the respective setup guide
2. **Coordinators**: Familiarize yourself with validator onboarding workflow
3. **Developers**: Set up local RPC node for dApp development
4. **Cross-Chain Team**: Deploy 5-node relayer cluster for SXCP testing

### Future Development

- Scale to 50+ validators for true multi-cluster testing
- Deploy production relayers for mainnet cross-chain bridging
- Implement additional SXCP source chains (Avalanche, BNB Chain, etc.)
- Optimize PoSy parameters based on testnet performance data
- Launch public RPC endpoints with load balancing
- Develop blockchain explorer and analytics dashboard

---

**Welcome to the Synergy Testnet! 🚀**

All systems are configured and ready for team validator onboarding, RPC deployment, and cross-chain relayer testing.

---

**Last Updated**: December 6, 2025
**Network Status**: ✅ Operational
**Active Validators**: 3 (Genesis Bootnodes) + Dynamic Registration
**Ready for**: Team Onboarding, RPC Deployment, SXCP Testing
