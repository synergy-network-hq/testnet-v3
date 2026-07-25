# Synergy Testnet

This repository contains the Synergy public testnet implementation and canonical chain `1264` genesis artifacts. Operational keys, generated installers, and other machine-local artifacts are intentionally excluded from this repository. Generate fresh identities and bootstrap material before deployment.

## 🚀 Overview

The **Synergy Network** is a next-generation blockchain platform featuring revolutionary **Proof of Synergy (PoSy)** consensus mechanism, comprehensive token system, advanced wallet management, and powerful block explorer capabilities. This platform provides a complete blockchain ecosystem for decentralized applications, digital assets, and secure transactions.

## ✨ Key Features

### 🔗 Proof of Synergy Consensus
- **Collaborative Validation**: Validators work together in clusters
- **Synergy Scoring**: Performance-based reward distribution
- **Dynamic Clustering**: Automatic validator grouping optimization
- **VRF Integration**: Fair and unpredictable validator selection

### 🔗 Blockchain Consensus
- **Proof of Synergy**: Collaborative validator consensus mechanism
- **Validator Clustering**: Automatic validator grouping optimization
- **Synergy Scoring**: Performance-based reward distribution
- **Staking Rewards**: Token-based validator incentives

### 💰 Advanced Token System
- **Multi-Token Support**: Create and manage multiple token types
- **Native Token (SNRG)**: 12,000,000,000 fixed testnet supply with 9 decimals
- **Staking Integration**: Lock tokens to earn rewards
- **Token Operations**: Mint, burn, transfer, and query balances

### 🔐 Comprehensive Wallet Management
- **Secure Key Generation**: Cryptographically secure wallet creation
- **Multi-Format Support**: Bech32m addresses with human-readable format
- **Transaction Signing**: Secure transaction signing and verification
- **Balance Tracking**: Real-time token balance management

### 📊 Block Explorer
- **Transaction History**: Complete transaction tracking and analysis
- **Validator Information**: Real-time validator performance metrics
- **Network Statistics**: Comprehensive network health monitoring
- **Advanced Analytics**: Performance metrics and economic data

### 🌐 Rich API Ecosystem
- **JSON-RPC 2.0**: Complete API for all blockchain operations
- **Token Operations**: Full token lifecycle management
- **Staking APIs**: Complete staking functionality
- **AIVM APIs**: AI contract deployment and execution
- **Explorer Data**: Rich blockchain analytics and queries

## 🏗️ Architecture

- **🦀 Rust-Based**: High-performance, memory-safe implementation
- **🔒 Post-Quantum Security**: Future-proof cryptographic signatures
- **📊 Persistent Storage**: RocksDB for reliable state management
- **🌐 Advanced Networking**: Libp2p-based P2P with auto-discovery
- **📈 Structured Logging**: Comprehensive logging with rotation
- **⚙️ Flexible Configuration**: TOML-based configuration system
- **🧠 Distributed AI**: Consensus-based AI computation across validator clusters
- **🔗 Universal Interoperability**: Validator-mediated cross-chain communication
- **🔒 Post-Quantum Cryptography**: 5 NIST PQC algorithms for quantum-resistant security
- **💻 SynQ Programming Language**: Native quantum-safe smart contract language

## 🚀 Quick Start

### Prerequisites
```bash
# System Requirements
- Ubuntu 20.04+ / macOS 12+ / Windows 10+ with WSL2
- 4+ CPU cores, 8GB+ RAM, 50GB+ storage
- Stable internet connection

# Install Dependencies
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Installation & Setup
```bash
# Clone repository into a hyphen-safe local directory
git clone https://github.com/synergy-network-hq/testnet.git synergy-testnet
cd synergy-testnet

# Initialize configuration
cargo run --release -- init

# Build the node
cargo build --release --bin synergy-testnet

# Start the node
cargo run --release --bin synergy-testnet -- start
```

### API Usage Examples
```bash
# Get network statistics
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_getNetworkStats","params":[],"id":1}'

# Create a new token
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_createToken","params":["MYTOKEN","My Token",18,1000000,"sYn..."],"id":1}'

# Stake tokens
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"synergy_stakeTokensDirect","params":["sYn...","sYn...", "SNRG",1000000],"id":1}'
```

## 📚 Documentation

### Core Documentation
- **[Setup Guide](./docs/setup-guide.md)**: Complete installation and configuration
- **[API Reference](./docs/api-reference.md)**: Comprehensive API documentation
- **[Token System](./docs/token-system.md)**: Token creation and management guide
- **[Wallet Usage](./docs/wallet-usage.md)**: Wallet management and security
- **[Staking Guide](./docs/staking-guide.md)**: Staking mechanics and strategies
- **[Block Explorer](./docs/explorer-guide.md)**: Explorer features and usage
- **[How to Set Up an Indexer & Explorer Node](./docs/how-to-set-up-indexer-explorer-node.md)**: Step-by-step guide for live explorer indexing, API, and UI
- **[AIVM Guide](./docs/aivm-guide.md)**: Artificial Intelligence Virtual Machine documentation

### Technical Documentation
- **[Validator Guide](./docs/validator-guide.md)**: Running validator nodes
- **[Synergy Testnet Validator Onboarding](./docs/synergy-testnet-validator-onboarding.md)**: Chain `1264` genesis verification, preflight, admission, and failure modes
- **[Configuration Guide](./docs/config-guide.md)**: Configuration options
- **[Troubleshooting](./docs/troubleshooting.md)**: Common issues and solutions

## 🔧 Configuration

### Network Configuration
```toml
# config/network-config.toml
[network]
name = "synergy-testnet"
chain_id = 1264
p2p_port = 5622
rpc_port = 5640
ws_port = 5660

[consensus]
algorithm = "proof_of_synergy"
block_time = 5
min_validators = 4
validator_vote_threshold = 0
max_validators = 0
```

### Node Configuration
```toml
# config/node_config.toml
[logging]
log_level = "info"
enable_console = true
log_file = "data/logs/synergy-node.log"

[rpc]
http_port = 5640
ws_port = 5660
max_connections = 100
```

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test token
cargo test consensus
cargo test rpc

# Performance testing
cargo test --release -- --ignored

# Integration testing
cargo test --test integration_tests
```

## 🤝 Contributing

We welcome contributions from the community! Here's how to get involved:

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes with comprehensive tests
4. Submit a pull request

### Areas for Contribution
- **Core Protocol**: Consensus mechanism improvements
- **API Development**: New RPC methods and features
- **Documentation**: Guides, tutorials, and examples
- **Testing**: Unit tests, integration tests, and benchmarks
- **Tooling**: Developer tools and utilities

## 📊 Network Statistics

### Current Metrics
- **Network ID**: 1264
- **Chain ID**: 1264
- **Block Time**: 5 seconds
- **Consensus**: Proof of Synergy
- **Native Token**: SNRG (9 decimals)
- **Total Supply**: 12,000,000,000 SNRG
- **Total Supply (nWei)**: 12000000000000000000

### Performance Metrics
- **Average TPS**: Variable based on network load
- **Finality Time**: ~15 seconds
- **Validator Uptime**: 99.9% target
- **Network Security**: Post-quantum cryptography

## 🔒 Security

### Cryptographic Features
- **Post-Quantum Signatures**: Dilithium-3 implementation
- **Secure Key Generation**: Cryptographically secure randomness
- **Address Format**: Bech32m with checksum validation
- **Transaction Verification**: Multi-layer validation

### Network Security
- **Validator Incentives**: Economic penalties for misbehavior
- **Slashing Protection**: Automated penalty system
- **Network Monitoring**: Real-time security monitoring
- **Audit Trail**: Complete transaction and operation logging

## 🌐 Ecosystem

### Developer Tools
- **SDKs**: JavaScript, Python, Rust
- **Block Explorer**: Web and API interfaces
- **Wallet Libraries**: Integration libraries
- **Testing Framework**: Comprehensive test suites

### Community
- **Developer Forum**: Technical discussions and support
- **Discord**: Real-time community chat
- **GitHub**: Issue tracking and contributions
- **Documentation**: Comprehensive guides and tutorials

## 📜 License

This project uses a proprietary license to protect the intellectual property and ensure controlled distribution of the Synergy Network technology. See [LICENSE](./LICENSE) for details.

## 🆘 Support

### Getting Help
- **Documentation**: [docs/](./docs/) folder
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community discussions and Q&A
- **Email**: support@synergynetwork.io

### Resources
- [API Reference](./docs/api-reference.md)
- [Token System Guide](./docs/token-system.md)
- [Wallet Usage Guide](./docs/wallet-usage.md)
- [Staking Guide](./docs/staking-guide.md)
- [Block Explorer Guide](./docs/explorer-guide.md)

## 🗺️ Roadmap

### Phase 1 (Current) ✅
- Core blockchain implementation
- Proof of Synergy consensus
- Basic token system
- Wallet management
- Block explorer

### Phase 2 (Next)
- **Distributed AI Enhancement**: Advanced model sharding and federated AI training
- **Zero-Knowledge AI**: Privacy-preserving AI computations with consensus
- **Smart Contract Expansion**: Multi-language smart contract support
- **Cross-Chain Optimization**: Enhanced validator-mediated interoperability
- **Mobile Applications**: iOS and Android wallet applications
- **Enhanced Governance**: Distributed AI-assisted decision making

### Phase 3 (Future)
- **Layer 2 Scaling**: Advanced scaling solutions with AI optimization
- **Privacy Features**: Zero-knowledge proofs and private AI computations
- **Enterprise Integration**: Corporate blockchain solutions
- **Global Expansion**: Multi-region deployment and localization
- **Advanced Analytics**: Machine learning-powered network insights

## 🎯 Mission

The Synergy Network aims to create a more collaborative, secure, and efficient blockchain ecosystem that prioritizes:

- **Collaboration**: Over competition in consensus mechanisms
- **Sustainability**: Long-term economic incentives
- **Accessibility**: Easy-to-use tools and interfaces
- **Innovation**: Cutting-edge cryptographic research
- **Community**: Decentralized governance and participation

---

*Built with ❤️ by the Synergy Network team for a more collaborative blockchain future.*
