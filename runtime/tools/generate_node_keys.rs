// ============================================================================
// Synergy Testnet Key Generation Tool (FN-DSA / Falcon-1024)
// ============================================================================

use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use pqcrypto_falcon::falcon1024;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;

// ------------------- Address Generation -------------------

fn bech32m_charset() -> &'static [u8] {
    b"023456789acdefghjklmnpqrstuvwxyz"
}

fn generate_payload(len: usize) -> String {
    let charset = bech32m_charset();
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

fn generate_synergy_address(prefix: &str) -> String {
    let payload = generate_payload(41 - prefix.len());
    format!("{}{}", prefix, payload)
}

// ------------------- Identity Structures -------------------

#[derive(Serialize, Deserialize)]
pub struct JsonIdentity {
    pub address: String,
    pub public_key: String,
    pub private_key: String,
    pub role: String,
}

#[derive(Serialize, Deserialize)]
pub struct TomlIdentity {
    pub address: AddressSection,
    pub keys: KeySection,
    pub role: RoleSection,
}

#[derive(Serialize, Deserialize)]
pub struct AddressSection {
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeySection {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct RoleSection {
    pub r#type: String,
}

// ------------------- Identity Generation -------------------

fn create_identity_files(base_path: &str, role: &str, prefix: &str) {
    let (pk, sk) = falcon1024::keypair();

    let public_b64 = general_purpose::STANDARD.encode(pk.as_bytes());
    let private_b64 = general_purpose::STANDARD.encode(sk.as_bytes());

    let address = generate_synergy_address(prefix);

    let json = JsonIdentity {
        address: address.clone(),
        public_key: public_b64.clone(),
        private_key: private_b64.clone(),
        role: role.to_string(),
    };

    let toml = TomlIdentity {
        address: AddressSection {
            value: address.clone(),
        },
        keys: KeySection {
            public_key: public_b64,
            private_key: private_b64,
        },
        role: RoleSection {
            r#type: role.to_string(),
        },
    };

    fs::create_dir_all(base_path).unwrap();
    fs::write(
        format!("{}/node_identity.json", base_path),
        serde_json::to_string_pretty(&json).unwrap(),
    )
    .unwrap();
    fs::write(
        format!("{}/node_identity.toml", base_path),
        toml::to_string(&toml).unwrap(),
    )
    .unwrap();
}

// ------------------- Genesis Generation -------------------

fn write_genesis_file() {
    let mut validators = vec![];
    let mut relayers = vec![];
    let rpc_gateway: String;

    // Validators
    for i in 1..=9 {
        let data =
            fs::read_to_string(format!("testnet/validator-{:02}/node_identity.json", i)).unwrap();
        let ident: JsonIdentity = serde_json::from_str(&data).unwrap();
        validators.push(json!({
            "address": ident.address,
            "pubKey": ident.public_key,
            "weight": 100
        }));
    }

    // Relayers
    for i in 1..=5 {
        let data =
            fs::read_to_string(format!("testnet/relayer-{:02}/node_identity.json", i)).unwrap();
        let ident: JsonIdentity = serde_json::from_str(&data).unwrap();
        relayers.push(json!({ "address": ident.address }));
    }

    // RPC Gateway
    let data = fs::read_to_string("testnet/rpc-gateway/node_identity.json").unwrap();
    let ident: JsonIdentity = serde_json::from_str(&data).unwrap();
    rpc_gateway = ident.address;

    let genesis = json!({
        "meta": {
            "network": "Synergy Testnet",
            "version": "1.0.0",
            "description": "Auto-generated Synergy Testnet Genesis",
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
                    "pqcSignatureScheme": "FN-DSA (Falcon-1024)",
                    "vrfScheme": "FN-DSA (Falcon-1024)",
                    "addressEncoding": "Bech32m"
                }
            }
        },
        "alloc": {
            "faucet": {"balance": "1000000000000000000000"},
            "treasury": {"balance": "5000000000000000000000"},
            "rpc_gateway": {"address": rpc_gateway, "balance": "1000000000000000000000"}
        },
        "validators": validators,
        "relayers": relayers
    });

    fs::write(
        "testnet/genesis.json",
        serde_json::to_string_pretty(&genesis).unwrap(),
    )
    .unwrap();
}

// ------------------- Node Config Templates -------------------

fn write_node_configs() {
    // Validator ports
    let validator_ports = vec![
        (8545, 30303, 9090),
        (8546, 30304, 9091),
        (8547, 30305, 9092),
        (8548, 30306, 9093),
        (8549, 30307, 9094),
        (8550, 30308, 9095),
        (8551, 30309, 9096),
        (8552, 30310, 9097),
        (8553, 30311, 9098),
    ];

    for i in 1..=9 {
        let (rpc, p2p, metrics) = validator_ports[i - 1];
        let cfg = format!(
            "[node]\nrole='validator'\nchain_id=1264\naddress_file='node_identity.toml'\n\n\
             [network]\nrpc_port={}\np2p_port={}\nmetrics_port={}\nbootstrap=[]\n\n\
             [consensus]\nalgorithm='Proof of Synergy'\nblock_time=5\ncluster_size=3\n",
            rpc, p2p, metrics
        );

        fs::write(format!("testnet/validator-{:02}/node_config.toml", i), cfg).unwrap();
    }

    // Relayers
    let relayer_ports = vec![
        (8601, 31000, 9200),
        (8602, 31001, 9201),
        (8603, 31002, 9202),
        (8604, 31003, 9203),
        (8605, 31004, 9204),
    ];

    for i in 1..=5 {
        let (rpc, p2p, metrics) = relayer_ports[i - 1];
        let cfg = format!(
            "[node]\nrole='relayer'\nchain_id=1264\naddress_file='node_identity.toml'\n\n\
             [network]\nrpc_port={}\np2p_port={}\nmetrics_port={}\nbootstrap=[]\n\n\
             [sxcp]\nthreshold='3-of-5'\n",
            rpc, p2p, metrics
        );

        fs::write(format!("testnet/relayer-{:02}/node_config.toml", i), cfg).unwrap();
    }

    // RPC Gateway
    let cfg = "[node]\nrole='rpc-gateway'\nchain_id=1264\naddress_file='node_identity.toml'\n\n\
               [network]\nrpc_port=8600\np2p_port=31400\nmetrics_port=9300\nbootstrap=[]\n";

    fs::write("testnet/rpc-gateway/node_config.toml", cfg).unwrap();
}

// ------------------- MAIN -------------------

fn main() {
    println!("Generating Synergy Testnet FN-DSA identities...");

    for i in 1..=9 {
        create_identity_files(&format!("testnet/validator-{:02}", i), "validator", "synv1");
    }
    for i in 1..=5 {
        create_identity_files(&format!("testnet/relayer-{:02}", i), "relayer", "synv4");
    }
    create_identity_files("testnet/rpc-gateway", "rpc-gateway", "synv5");

    write_genesis_file();
    write_node_configs();

    println!("Synergy Testnet generation complete.");
}
