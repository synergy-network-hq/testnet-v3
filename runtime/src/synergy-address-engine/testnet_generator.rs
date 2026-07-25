// ============================================================================
// Synergy Testnet Key Generation Tool
// Uses FN-DSA-1024 with proper cryptographic address derivation
// ============================================================================

use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use serde::{Serialize, Deserialize};
use std::fs;
use base64::{engine::general_purpose, Engine as _};
use sha3::{Sha3_256, Digest};
use bech32::{ToBase32, Variant};
use serde_json::json;
use chrono::Utc;

// Address derivation using SHA3-256 + Bech32m
fn derive_synergy_address(public_key: &[u8], prefix: &str) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(public_key);
    let hash = hasher.finalize();
    let payload = &hash[..20];

    bech32::encode(prefix, payload.to_base32(), Variant::Bech32m)
        .expect("Failed to encode address")
}

#[derive(Serialize, Deserialize)]
pub struct JsonIdentity {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub role: String,
    pub algorithm: String,
    pub created_at: String,
}

fn create_identity_files(base_path: &str, role: &str, prefix: &str, description: &str) {
    let (pk, sk) = falcon1024::keypair();

    let public_b64 = general_purpose::STANDARD.encode(pk.as_bytes());
    let private_b64 = general_purpose::STANDARD.encode(sk.as_bytes());
    let address = derive_synergy_address(pk.as_bytes(), prefix);

    let json = JsonIdentity {
        address: address.clone(),
        public_key: public_b64,
        private_key: private_b64,
        role: role.to_string(),
        algorithm: "FN-DSA-1024".to_string(),
        created_at: Utc::now().to_rfc3339(),
    };

    fs::create_dir_all(base_path).unwrap();
    fs::write(
        format!("{}/node_identity.json", base_path),
        serde_json::to_string_pretty(&json).unwrap()
    ).unwrap();

    println!("✓ Created {} identity: {}", role, address);
}

fn write_genesis_file() {
    let mut validators = vec![];
    let mut relayers = vec![];

    // Load validators
    for i in 1..=9 {
        let data = fs::read_to_string(format!("testnet/validator-{:02}/node_identity.json", i)).unwrap();
        let ident: JsonIdentity = serde_json::from_str(&data).unwrap();
        validators.push(json!({
            "address": ident.address,
            "pubKey": ident.public_key,
            "weight": 100,
            "role": "consensus"
        }));
    }

    // Load relayers
    for i in 1..=5 {
        let data = fs::read_to_string(format!("testnet/relayer-{:02}/node_identity.json", i)).unwrap();
        let ident: JsonIdentity = serde_json::from_str(&data).unwrap();
        relayers.push(json!({
            "address": ident.address,
            "role": "interoperability"
        }));
    }

    // Load RPC gateway
    let data = fs::read_to_string("testnet/rpc-gateway/node_identity.json").unwrap();
    let ident: JsonIdentity = serde_json::from_str(&data).unwrap();

    let genesis = json!({
        "meta": {
            "network": "Synergy Testnet",
            "version": "1.0.0",
            "description": "Auto-generated with FN-DSA-1024",
            "dateGenerated": Utc::now().to_rfc3339()
        },
        "config": {
            "chainId": 1264,
            "synergyConsensus": {
                "algorithm": "Proof of Synergy",
                "parameters": {
                    "blockTime": 5,
                    "epoch": 30000,
                    "validatorClusterSize": 3,
                    "pqcSignatureScheme": "FN-DSA-1024",
                    "vrfScheme": "FN-DSA-1024",
                    "addressEncoding": "Bech32m",
                    "addressDerivation": "SHA3-256 + Bech32m"
                }
            }
        },
        "alloc": {
            "faucet": {"balance": "1000000000000000000000"},
            "treasury": {"balance": "5000000000000000000000"},
            "rpc_gateway": {
                "address": ident.address,
                "balance": "1000000000000000000000"
            }
        },
        "validators": validators,
        "relayers": relayers,
        "cryptography": {
            "addressDerivation": {
                "hashFunction": "SHA3-256",
                "encoding": "Bech32m",
                "payloadLength": 160
            },
            "signatures": {
                "algorithm": "FN-DSA-1024",
                "publicKeySize": 1793,
                "privateKeySize": 2305,
                "signatureSize": 1330
            }
        }
    });

    fs::write("testnet/genesis.json", serde_json::to_string_pretty(&genesis).unwrap()).unwrap();
    println!("✓ Created genesis.json");
}

fn write_node_configs() {
    // Validator configs
    let validator_ports = vec![
        (8545, 30303, 9090), (8546, 30304, 9091), (8547, 30305, 9092),
        (8548, 30306, 9093), (8549, 30307, 9094), (8550, 30308, 9095),
        (8551, 30309, 9096), (8552, 30310, 9097), (8553, 30311, 9098),
    ];

    for i in 1..=9 {
        let (rpc, p2p, metrics) = validator_ports[i - 1];
        let cfg = format!(
            "[node]\nrole='validator'\nchain_id=1264\naddress_file='node_identity.json'\n\n\
             [network]\nrpc_port={}\np2p_port={}\nmetrics_port={}\n\n\
             [consensus]\nalgorithm='Proof of Synergy'\nblock_time=5\ncluster_size=3\n\n\
             [cryptography]\nsignature_scheme='FN-DSA-1024'\n",
            rpc, p2p, metrics
        );
        fs::write(format!("testnet/validator-{:02}/node_config.toml", i), cfg).unwrap();
    }

    // Relayer configs
    let relayer_ports = vec![
        (8601, 31000, 9200), (8602, 31001, 9201), (8603, 31002, 9202),
        (8604, 31003, 9203), (8605, 31004, 9204),
    ];

    for i in 1..=5 {
        let (rpc, p2p, metrics) = relayer_ports[i - 1];
        let cfg = format!(
            "[node]\nrole='relayer'\nchain_id=1264\naddress_file='node_identity.json'\n\n\
             [network]\nrpc_port={}\np2p_port={}\nmetrics_port={}\n\n\
             [sxcp]\nthreshold='3-of-5'\n\n\
             [cryptography]\nsignature_scheme='FN-DSA-1024'\n",
            rpc, p2p, metrics
        );
        fs::write(format!("testnet/relayer-{:02}/node_config.toml", i), cfg).unwrap();
    }

    // RPC Gateway config
    let cfg = "[node]\nrole='rpc-gateway'\nchain_id=1264\naddress_file='node_identity.json'\n\n\
               [network]\nrpc_port=8600\np2p_port=31400\nmetrics_port=9300\n\n\
               [cryptography]\nsignature_scheme='FN-DSA-1024'\n";
    fs::write("testnet/rpc-gateway/node_config.toml", cfg).unwrap();
    println!("✓ Created all node configs");
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║   Synergy Testnet FN-DSA-1024 Identity Generator              ║");
    println!("║   Cryptographic Address Derivation: SHA3-256 + Bech32m       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    println!("Generating validator identities (Class I - synv1)...");
    for i in 1..=9 {
        create_identity_files(
            &format!("testnet/validator-{:02}", i),
            "validator",
            "synv1",
            "Class I Nodes – Consensus"
        );
    }

    println!("\nGenerating relayer identities (Class II - synv2)...");
    for i in 1..=5 {
        create_identity_files(
            &format!("testnet/relayer-{:02}", i),
            "relayer",
            "synv2",
            "Class II Nodes – Interoperability"
        );
    }

    println!("\nGenerating RPC gateway (Class V - synv5)...");
    create_identity_files(
        "testnet/rpc-gateway",
        "rpc-gateway",
        "synv5",
        "Class V Nodes – Service"
    );

    println!("\n═══════════════════════════════════════════════════════════════");
    write_genesis_file();
    write_node_configs();

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║   Testnet generation complete!                                 ║");
    println!("║   ✓ 9 Validators (synv1)                                      ║");
    println!("║   ✓ 5 Relayers (synv2)                                        ║");
    println!("║   ✓ 1 RPC Gateway (synv5)                                     ║");
    println!("║   ✓ Genesis + Configs                                         ║");
    println!("║   All addresses cryptographically derived via FN-DSA-1024     ║");
    println!("╚═══════════════════════════════════════════════════════════════╝");
}
