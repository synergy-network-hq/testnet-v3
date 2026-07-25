# Synergy Network Address Formatting

Based on the official Synergy Network Address Formatting Specification (Updated Nov 29, 2025).

## Wallet Address Format

**Format**: `sYnQ` + 40 hexadecimal characters

**Example**: `sYnQXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

**Notes**:
- Bech32m, 41 chars
- Default wallet prefix
- Also supports: sYnU/sYnA/sYnZ

## Node Address Format (Class-Based)

The control panel now generates **class-based node addresses** with proper PQC cryptography.

### Five Node Classes

Each node type belongs to one of five classes, with designated address prefixes:

#### **Class I - Core Validators & Committee Members**
- **Prefix**: `sYnV1-`
- **Node Types**: Validator, Committee
- **Description**: Core network validators and consensus participants

#### **Class II - Archive, Audit & Data Availability**
- **Prefix**: `sYnV2-`
- **Node Types**: Archive Validator, Audit Validator, Data Availability
- **Description**: Historical data, compliance, and data availability nodes

#### **Class III - Relayers & Cross-Chain Infrastructure**
- **Prefix**: `sYnV3-`
- **Node Types**: Relayer, Witness, Oracle, UMA Coordinator, Cross Chain Verifier
- **Description**: Cross-chain infrastructure and data relay nodes

#### **Class IV - Compute & Specialized Processing**
- **Prefix**: `sYnV4-`
- **Node Types**: Compute, AI Inference, PQC Crypto
- **Description**: Specialized computation and processing nodes

#### **Class V - Governance & RPC Infrastructure**
- **Prefix**: `sYnV5-`
- **Node Types**: Governance Auditor, Treasury Controller, Security Council, RPC Gateway, Indexer, Observer
- **Description**: Governance, treasury, and public infrastructure nodes

### Current Implementation

The control panel generates addresses using **post-quantum cryptography**:

```rust
// Backend (Rust) implementation
pub async fn generate_pqc_keypair(
    binary_path: &PathBuf,
    node_class: NodeClass,
    keys_dir: &PathBuf,
) -> Result<NodeIdentity, String> {
    // Call synergy-testnet binary to generate ML-DSA-65 keypair
    let output = Command::new(binary_path)
        .arg("keygen")
        .arg("--type").arg("ml-dsa-65")
        .arg("--output").arg(keys_dir)
        .arg("--class").arg(node_class.class_number().to_string())
        .output()?;

    // Parse output and return NodeIdentity with class-based address
}
```

**Key Features**:
- **Key Generation**: ML-DSA-65 (signing) and ML-KEM-768 (encryption)
- **Address Derivation**: Class-based prefix + cryptographically derived identifier
- **Network Registration**: Automatic registration with Synergy testnet
- **Blockchain Sync**: Initial sync upon node creation

### Format Details
- **Prefix**: `sYnV1-`, `sYnV2-`, `sYnV3-`, `sYnV4-`, or `sYnV5-` (based on node class)
- **Length**: Variable (prefix + derived identifier from public key)
- **Cryptography**: ML-DSA-65 (digital signatures), ML-KEM-768 (key encapsulation)
- **Example**: `sYnV1-<pqc-derived-identifier>`

## Other Address Types (For Reference)

### Public Key Example
**Format**: 64-character hex string
**Example**: `6fd47f3a8dca7e47c5f9a9128b3a45dc1f91de789da3e69f54a8a13fd0a937a2`
**Algorithm**: ML-DSA/Aegis public key (verification)

### Private Key Example
**Format**: 64-character hex string
**Example**: `d14e8d2e5b3f7a9a0f2b3c8d1e2f3a7c6d5e4f2a1b9c3d7e8a01b2c3d4e5f67`
**Storage**: Keep offline/secure; recoverable via UMA rotation & guardians

### Smart Contract Address
**Format**: `sYnS-CONTRACT-` + identifier
**Example**: `sYnS-CONTRACT-8a7b5c9f3d6e1a2b4c7d8f9e0a5b6c3d`
**Use**: System-level contract (governance, treasury, bridge)

### Transaction Identifier
**Format**: `sYnTXn-` + hash
**Example**: `sYnTXn-abcdef1234567890abcdef1234567890`
**Use**: Core-chain transaction (PoSy)

### Cross-Chain TX Identifier
**Format**: `sYnXXn-` + hash
**Example**: `sYnXXn-abcdef1234567890abcdef1234567890`
**Use**: SXCP cross-chain transaction (relayers)

### Synergy Naming
**Format**: Human-readable alias
**Example**: `alice.syn`
**Use**: Alias mapped on-chain to addresses

## Implementation Notes

1. **Current**: Using `sYnV` prefix for validator/node addresses
2. **Generation**: Cryptographically random 40-character hex string
3. **Validation**: Should match `^sYnV[0-9a-f]{40}$` regex pattern
4. **Display**: Full address shown in chat interface
5. **Storage**: Used as `displayName` for nodes

## Future Enhancements

Consider implementing:
- Address validation function
- Checksum verification (Bech32m)
- Support for multiple address types based on node role
- Human-readable naming (.syn aliases)
- QR code generation for addresses
