// ============================================================================
// Synergy Network Address Generation Engine
// Supports all 35+ address types - Uses FN-DSA-1024 (NIST Level 5)
// ============================================================================

use base64::{engine::general_purpose, Engine as _};
use bech32::{FromBase32, ToBase32, Variant};
use chrono::Utc;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;

// ADDRESS TYPE DEFINITIONS (35+ types) - Per Synergy Network Address Formatting Standard
#[derive(Debug, Clone, Copy)]
pub enum AddressType {
    // Wallet Addresses
    WalletPrimary,   // synw - Primary wallet
    WalletSecondary, // syns - Secondary/utility wallet
    WalletAccount,   // syna - Account wallet
    WalletSmart,     // synz - UMA-linked smart wallet

    // Transaction Identifiers
    TransactionStandard,   // syntxn - Standard on-chain
    TransactionCrossChain, // synxxn - SXCP cross-chain
    TransactionInternal,   // synixn - Internal infrastructure

    // Fungible Tokens (STS-9)
    TokenFungibleB1, // synb1
    TokenFungibleB2, // synb2
    TokenFungibleB3, // synb3

    // Non-Fungible Tokens (STS-NF)
    TokenNonFungibleN1, // synn1
    TokenNonFungibleN2, // synn2

    // Multi-Asset & Identity Tokens
    TokenMultiAsset, // synj - STS-MA
    TokenIdentity,   // synk - STS-ID

    // Smart Contracts
    ContractSystem, // synq - System-level (with -contract- separator)
    ContractCustom, // sync - Custom deployed (with -contract- separator)

    // Node Addresses
    NodeClass1, // synv1 - Consensus Nodes
    NodeClass2, // synv2 - Interoperability Nodes
    NodeClass3, // synv3 - Intelligence & Computation
    NodeClass4, // synv4 - Governance & Treasury
    NodeClass5, // synv5 - Service & Support

    // Cluster Addresses
    ClusterGroup1, // syngrp1
    ClusterGroup2, // syngrp2
    ClusterGroup3, // syngrp3
    ClusterGroup4, // syngrp4
    ClusterGroup5, // syngrp5

    // DAO Addresses
    DaoProposal,  // syndao - Proposal identifier
    DaoOversight, // syno - Oversight auditor
    DaoCommittee, // syny - Committee address

    // Multisig Wallets
    MultisigGeneral,   // synm - General multisig
    MultisigTreasury,  // synu - DAO treasury multisig
    MultisigValidator, // synl - Validator/council multisig

    // Special Addresses
    FeeCollector, // synf - Network fee collector
    BurnAddress,  // syne - Network burn address

    // Reserved Prefixes
    ReservedR, // synr - Future use
    ReservedI, // syni - Future use
    ReservedP, // synp - Future use
}

impl AddressType {
    pub fn prefix(&self) -> &'static str {
        match self {
            // Wallet Addresses
            AddressType::WalletPrimary => "synw",
            AddressType::WalletSecondary => "syns",
            AddressType::WalletAccount => "syna",
            AddressType::WalletSmart => "synz",

            // Transaction Identifiers
            AddressType::TransactionStandard => "syntxn",
            AddressType::TransactionCrossChain => "synxxn",
            AddressType::TransactionInternal => "synixn",

            // Fungible Tokens (STS-9)
            AddressType::TokenFungibleB1 => "synb1",
            AddressType::TokenFungibleB2 => "synb2",
            AddressType::TokenFungibleB3 => "synb3",

            // Non-Fungible Tokens (STS-NF)
            AddressType::TokenNonFungibleN1 => "synn1",
            AddressType::TokenNonFungibleN2 => "synn2",

            // Multi-Asset & Identity
            AddressType::TokenMultiAsset => "synj",
            AddressType::TokenIdentity => "synk",

            // Smart Contracts (note: -contract- added during generation)
            AddressType::ContractSystem => "synq",
            AddressType::ContractCustom => "sync",

            // Node Addresses
            AddressType::NodeClass1 => "synv1",
            AddressType::NodeClass2 => "synv2",
            AddressType::NodeClass3 => "synv3",
            AddressType::NodeClass4 => "synv4",
            AddressType::NodeClass5 => "synv5",

            // Cluster Addresses
            AddressType::ClusterGroup1 => "syngrp1",
            AddressType::ClusterGroup2 => "syngrp2",
            AddressType::ClusterGroup3 => "syngrp3",
            AddressType::ClusterGroup4 => "syngrp4",
            AddressType::ClusterGroup5 => "syngrp5",

            // DAO Addresses
            AddressType::DaoProposal => "syndao",
            AddressType::DaoOversight => "syno",
            AddressType::DaoCommittee => "syny",

            // Multisig Wallets
            AddressType::MultisigGeneral => "synm",
            AddressType::MultisigTreasury => "synu",
            AddressType::MultisigValidator => "synl",

            // Special Addresses
            AddressType::FeeCollector => "synf",
            AddressType::BurnAddress => "syne",

            // Reserved Prefixes
            AddressType::ReservedR => "synr",
            AddressType::ReservedI => "syni",
            AddressType::ReservedP => "synp",
        }
    }

    pub fn is_contract(&self) -> bool {
        matches!(
            self,
            AddressType::ContractSystem | AddressType::ContractCustom
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct SynergyIdentity {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub address_type: String,
    pub algorithm: String,
    pub created_at: String,
}

/// Derives address from FN-DSA-1024 public key
/// Process: SHA3-256(public_key) -> First 20 bytes -> Bech32m
/// For contracts, format is: prefix-contract-address
pub fn derive_address(public_key: &[u8], address_type: AddressType) -> Result<String, String> {
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    let payload = &hash[..20];

    let base_address = bech32::encode(address_type.prefix(), payload.to_base32(), Variant::Bech32m)
        .map_err(|e| format!("Failed to encode: {}", e))?;

    // For contract addresses, insert "-contract-" after the prefix
    if address_type.is_contract() {
        let prefix = address_type.prefix();
        let address_part = &base_address[prefix.len()..];
        Ok(format!("{}-contract-{}", prefix, address_part))
    } else {
        Ok(base_address)
    }
}

pub fn generate_identity(address_type: AddressType) -> Result<SynergyIdentity, String> {
    if matches!(address_type, AddressType::BurnAddress) {
        return Ok(SynergyIdentity {
            address: "synergy00000000000000000000000burn".to_string(),
            public_key: String::new(),
            private_key: String::new(),
            address_type: "Burn Address".to_string(),
            algorithm: "FN-DSA-1024".to_string(),
            created_at: Utc::now().to_rfc3339(),
        });
    }

    let (pk, sk) = falcon1024::keypair();
    let public_b64 = general_purpose::STANDARD.encode(pk.as_bytes());
    let private_b64 = general_purpose::STANDARD.encode(sk.as_bytes());
    let address = derive_address(pk.as_bytes(), address_type)?;

    Ok(SynergyIdentity {
        address,
        public_key: public_b64,
        private_key: private_b64,
        address_type: format!("{:?}", address_type),
        algorithm: "FN-DSA-1024".to_string(),
        created_at: Utc::now().to_rfc3339(),
    })
}

pub fn verify_address(address: &str, public_key_b64: &str) -> Result<bool, String> {
    let pk_bytes = general_purpose::STANDARD
        .decode(public_key_b64)
        .map_err(|e| format!("Decode error: {}", e))?;

    let (_, data, _) = bech32::decode(address).map_err(|e| format!("Bech32 error: {}", e))?;

    let payload = Vec::<u8>::from_base32(&data).map_err(|e| format!("Base32 error: {}", e))?;

    let mut hasher = Sha3_256::new();
    hasher.update(&pk_bytes);
    let hash = hasher.finalize();

    Ok(payload == &hash[..20])
}

fn parse_node_type(node_type: &str) -> Option<AddressType> {
    match node_type.to_lowercase().as_str() {
        // Node types
        "validator" | "class1" | "node-class1" | "synv1" => Some(AddressType::NodeClass1),
        "class2" | "node-class2" | "synv2" => Some(AddressType::NodeClass2),
        "class3" | "node-class3" | "synv3" => Some(AddressType::NodeClass3),
        "class4" | "node-class4" | "synv4" => Some(AddressType::NodeClass4),
        "class5" | "node-class5" | "synv5" => Some(AddressType::NodeClass5),

        // Wallet types
        "wallet" | "wallet-primary" | "synw" => Some(AddressType::WalletPrimary),
        "wallet-secondary" | "syns" => Some(AddressType::WalletSecondary),
        "wallet-account" | "syna" => Some(AddressType::WalletAccount),
        "wallet-smart" | "synz" => Some(AddressType::WalletSmart),

        // Cluster types
        "cluster1" | "cluster-group1" | "syngrp1" => Some(AddressType::ClusterGroup1),
        "cluster2" | "cluster-group2" | "syngrp2" => Some(AddressType::ClusterGroup2),
        "cluster3" | "cluster-group3" | "syngrp3" => Some(AddressType::ClusterGroup3),
        "cluster4" | "cluster-group4" | "syngrp4" => Some(AddressType::ClusterGroup4),
        "cluster5" | "cluster-group5" | "syngrp5" => Some(AddressType::ClusterGroup5),

        // Contract types
        "contract" | "contract-system" | "synq" => Some(AddressType::ContractSystem),
        "contract-custom" | "sync" => Some(AddressType::ContractCustom),

        // Multisig types
        "multisig" | "multisig-general" | "synm" => Some(AddressType::MultisigGeneral),
        "multisig-treasury" | "synu" => Some(AddressType::MultisigTreasury),
        "multisig-validator" | "synl" => Some(AddressType::MultisigValidator),

        // Special addresses
        "fee-collector" | "synf" => Some(AddressType::FeeCollector),
        "burn" | "burn-address" | "syne" => Some(AddressType::BurnAddress),

        // DAO types
        "dao-proposal" | "syndao" => Some(AddressType::DaoProposal),
        "dao-oversight" | "syno" => Some(AddressType::DaoOversight),
        "dao-committee" | "syny" => Some(AddressType::DaoCommittee),

        _ => None,
    }
}

fn print_usage() {
    println!("Synergy Network Address Engine - FN-DSA-1024 (NIST Level 5)\n");
    println!("Usage:");
    println!("  synergy-address-engine [OPTIONS]\n");
    println!("Options:");
    println!("  --node-type <type>    Generate keys for specific address type");
    println!("  --output <path>       Save identity to file (JSON format)");
    println!("  --output-toml <path>  Save identity to file (TOML format)");
    println!("  --help                Show this help message\n");
    println!("Address Types:");
    println!("  Nodes:      validator, class1-5");
    println!("  Wallets:    wallet, wallet-secondary, wallet-account, wallet-smart");
    println!("  Clusters:   cluster1-5, cluster-group1-5");
    println!("  Contracts:  contract, contract-system, contract-custom");
    println!("  Multisig:   multisig, multisig-treasury, multisig-validator");
    println!("  DAO:        dao-proposal, dao-oversight, dao-committee");
    println!("  Special:    fee-collector, burn-address\n");
    println!("Examples:");
    println!("  synergy-address-engine --node-type validator --output validator_identity.json");
    println!("  synergy-address-engine --node-type fee-collector --output fee_collector.json");
    println!("  synergy-address-engine --node-type dao-proposal");
    println!("  synergy-address-engine --help\n");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Check for help flag
    if args.len() > 1 && (args[1] == "--help" || args[1] == "-h") {
        print_usage();
        return;
    }

    // Parse arguments
    let mut node_type_str: Option<String> = None;
    let mut output_json: Option<String> = None;
    let mut output_toml: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--node-type" | "-t" => {
                if i + 1 < args.len() {
                    node_type_str = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --node-type requires a value");
                    print_usage();
                    std::process::exit(1);
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_json = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --output requires a value");
                    std::process::exit(1);
                }
            }
            "--output-toml" => {
                if i + 1 < args.len() {
                    output_toml = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: --output-toml requires a value");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Error: Unknown argument: {}", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
    }

    // Determine address type
    let address_type = if let Some(ref nt) = node_type_str {
        match parse_node_type(nt) {
            Some(t) => t,
            None => {
                eprintln!("Error: Invalid address type: {}", nt);
                eprintln!("Run with --help to see all valid address types");
                std::process::exit(1);
            }
        }
    } else {
        // Default: Generate Class 1 Node (Validator)
        AddressType::NodeClass1
    };

    println!("🔐 Synergy Network Address Engine - FN-DSA-1024 (NIST Level 5)\n");
    println!("Generating {} identity...\n", format!("{:?}", address_type));

    // Generate identity
    let identity = match generate_identity(address_type) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Error generating identity: {}", e);
            std::process::exit(1);
        }
    };

    // Display results
    println!("✅ Identity Generated Successfully!\n");
    println!("Address:      {}", identity.address);
    println!("Algorithm:    {}", identity.algorithm);
    println!("Type:         {}", identity.address_type);
    println!(
        "Public Key:   {} bytes",
        general_purpose::STANDARD
            .decode(&identity.public_key)
            .unwrap()
            .len()
    );
    println!(
        "Private Key:  {} bytes",
        general_purpose::STANDARD
            .decode(&identity.private_key)
            .unwrap()
            .len()
    );
    println!("Created:      {}\n", identity.created_at);

    // Save to files if requested
    if let Some(ref path) = output_json {
        match fs::write(path, serde_json::to_string_pretty(&identity).unwrap()) {
            Ok(_) => println!("💾 Saved to: {}", path),
            Err(e) => eprintln!("Error saving JSON: {}", e),
        }
    }

    if let Some(ref path) = output_toml {
        match toml::to_string_pretty(&identity) {
            Ok(toml_str) => match fs::write(path, toml_str) {
                Ok(_) => println!("💾 Saved to: {}", path),
                Err(e) => eprintln!("Error saving TOML: {}", e),
            },
            Err(e) => eprintln!("Error serializing TOML: {}", e),
        }
    }

    println!("\n⚠️  SECURITY WARNING:");
    println!("   Store the private key securely and never share it!");
    println!("   Set file permissions: chmod 600 <identity_file>");
}
