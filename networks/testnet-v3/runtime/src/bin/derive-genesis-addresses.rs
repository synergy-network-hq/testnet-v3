//! Derives the nine production Testnet-v3 contract addresses from public
//! inputs only. No private key and no custody passphrase is involved: a deploy
//! address is a function of the deployer address, nonce, artifact hashes and
//! constructor-args hash. Signing authorizes execution, not derivation.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use synergy_testnet::genesis_deployment::*;
use synergy_testnet::synq_execution::SynQContractArtifact;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn frozen_authorities() -> Value {
    let path = repo().join("launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json");
    serde_json::from_slice(&std::fs::read(&path).expect("read frozen authorities")).unwrap()
}

fn authority(doc: &Value, role: &str, field: &str) -> String {
    doc["authorities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role_id"] == role)
        .unwrap_or_else(|| panic!("frozen authorities missing {role}"))[field]
        .as_str()
        .unwrap()
        .to_string()
}

fn role_identity_authorization(
    role: &str,
) -> synergy_testnet::identity_auth::IdentityAuthorizationCarrier {
    let path = repo()
        .join("testnet-v3-identity-files")
        .join(role)
        .join("genesis-authorization-binding.json");
    let binding = serde_json::from_slice(&std::fs::read(&path).expect("read identity binding"))
        .expect("parse canonical identity binding");
    synergy_testnet::identity_auth::IdentityAuthorizationCarrier::new(
        synergy_testnet::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
        binding,
    )
    .expect("construct canonical genesis identity authorization carrier")
}

fn base64_decode(input: &str) -> Vec<u8> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input
        .bytes()
        .filter(|c| *c != b'=' && !c.is_ascii_whitespace())
    {
        let v = T.iter().position(|t| *t == c).expect("base64") as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

fn staged_artifact(contract: GenesisContract) -> SynQContractArtifact {
    let dir = repo().join("genesis-contracts/staged-governance-v1");
    let name = contract.name();
    let read = |ext: &str| std::fs::read(dir.join(format!("{name}.{ext}"))).expect("artifact");
    SynQContractArtifact::new(
        read("compiled.synq"),
        String::from_utf8(read("abi.json")).unwrap(),
        String::from_utf8(read("manifest.json")).unwrap(),
    )
}

fn main() {
    let frozen = frozen_authorities();
    assert_eq!(frozen["status"], "FROZEN");
    assert_eq!(frozen["test_fixture"], false);

    // Authority Address constructor arguments use the SynQ signer form,
    // because that is what the runtime presents as `msg.sender` for a SynQ
    // contract call. A `syna1...` value here would never match the caller.
    let deployer_public_key = role_public_key("SNRG-TESTNET-V3-GENESIS-DEPLOYER");
    let deployer_account = authority(
        &frozen,
        "SNRG-TESTNET-V3-GENESIS-DEPLOYER",
        "standard_account_address",
    );

    let authorities = GenesisAuthorities {
        genesis_deployer: GenesisSigner {
            public_key: deployer_public_key.clone(),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                "SNRG-TESTNET-V3-GENESIS-DEPLOYER",
            )),
        },
        governance: GenesisSigner {
            public_key: role_public_key("SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY"),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                "SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY",
            )),
        },
        emergency_slashing_authority: authority(
            &frozen,
            "SNRG-TESTNET-V3-EMERGENCY-SLASHING",
            "standard_account_address",
        ),
        validator_registry_authority: authority(
            &frozen,
            "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
            "standard_account_address",
        ),
        validator_registry_authority_key: GenesisSigner {
            public_key: role_public_key("SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY"),
            private_key: Vec::new(),
            identity_authorization: Some(role_identity_authorization(
                "SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY",
            )),
        },
        reward_distributor_authority: authority(
            &frozen,
            "SNRG-TESTNET-V3-REWARD-DISTRIBUTOR-AUTHORITY",
            "standard_account_address",
        ),
        identity_fee_collector: "synf1pnchsrnyral0u9r65xusjrexuctfh465h06l".to_string(),
        team_vesting_admin: "synu18tmdavp9yskftz4lldshrxvzwyg0tpnu23n9".to_string(),
        oracle_publisher: authority(
            &frozen,
            "SNRG-TESTNET-V3-EMERGENCY-PAUSE-AUTHORITY",
            "standard_account_address",
        ),
    };

    let parameters = production_parameters();
    let artifacts: BTreeMap<GenesisContract, SynQContractArtifact> =
        GenesisContract::APPROVED_ORDER
            .iter()
            .map(|c| (*c, staged_artifact(*c)))
            .collect();
    let plan = GenesisDeploymentPlan::new(&artifacts).expect("plan");

    // Sanity: the frozen account address must be the one this key derives to.
    let recomputed =
        synergy_testnet::address::derive_standard_account_address(&deployer_public_key)
            .expect("canonical deployer FN-DSA public key derives an account address");
    assert_eq!(
        recomputed, deployer_account,
        "deployer account address mismatch"
    );

    let derived = derive_genesis_addresses(&plan, &deployer_public_key, &authorities, &parameters)
        .expect("derive");

    println!("{}", serde_json::to_string_pretty(&derived).unwrap());
}

fn role_public_key(role: &str) -> Vec<u8> {
    let path = repo()
        .join("testnet-v3-identity-files")
        .join(role)
        .join("identity.pub.json");
    let doc: Value = serde_json::from_slice(&std::fs::read(&path).expect("read pub")).unwrap();
    let pk = base64_decode(doc["public_key"].as_str().unwrap());
    assert_eq!(pk.len(), 2592, "{role} must be ML-DSA-87");
    pk
}

fn production_parameters() -> GenesisParameters {
    let g: Value = serde_json::from_slice(
        &std::fs::read(repo().join("genesis.testnet-v3.identity-assigned.json")).unwrap(),
    )
    .unwrap();
    let c = &g["contracts"];
    let s = |v: &Value| v.as_str().unwrap().to_string();
    let n = |v: &Value| v.as_u64().unwrap().to_string();

    let validators = c["validator_registry"]["init_params"]["validators"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| GenesisValidator {
            id_hash: format!("0x{}", s(&v["validator_id_hash"])),
            operator_address: s(&v["operator_address"]),
            reward_address: s(&v["reward_address"]),
            voting_power: n(&v["voting_power"]),
            self_stake_nwei: s(&v["stake_nwei"]),
            metadata_hash: format!("0x{}", s(&v["metadata_hash"])),
            key_bundle_hash: format!("0x{}", s(&v["key_bundle_hash"])),
            activation_height: n(&v["activation_height"]),
        })
        .collect();

    GenesisParameters {
        identity_registration_fee_nwei: s(&c["identity"]["init_params"]["registration_fee_nwei"]),
        identity_reserved_names: c["identity"]["init_params"]["reserved_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        validator_max_count: n(&c["validator_registry"]["init_params"]["max_validator_count"]),
        validator_min_count: n(&c["validator_registry"]["init_params"]["min_validator_count"]),
        validator_min_self_stake_nwei: s(
            &c["validator_registry"]["init_params"]["min_self_stake_nwei"]
        ),
        validators,
        staking_min_stake_nwei: s(&c["staking"]["init_params"]["min_stake_nwei"]),
        staking_max_stake_nwei: s(&c["staking"]["init_params"]["max_stake_nwei"]),
        staking_unbonding_blocks: "302400".to_string(),
        governance_quorum_bps: "6000".to_string(),
        governance_approval_bps: "5000".to_string(),
        governance_veto_bps: "3300".to_string(),
        governance_min_deposit_nwei: s(&c["governance"]["init_params"]["min_deposit_nwei"]),
        governance_voting_blocks: "302400".to_string(),
        governance_timelock_blocks: "43200".to_string(),
        treasury_required_signers: n(&c["treasury"]["init_params"]["required_signers"]),
        treasury_signers: c["treasury"]["init_params"]["signers"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        slashing_double_sign_bps: "500".to_string(),
        slashing_downtime_bps: "100".to_string(),
        slashing_invalid_block_bps: "500".to_string(),
        slashing_missed_blocks_threshold: n(
            &c["slashing"]["init_params"]["downtime_missed_blocks_threshold"]
        ),
        slashing_jail_blocks: "43200".to_string(),
        oracle_quorum_threshold: n(&c["synergy_oracle"]["init_params"]["quorum_threshold"]),
        oracle_replay_protection: true,
        oracle_source_domains: c["synergy_oracle"]["init_params"]["accepted_source_domains"]
            .as_array()
            .unwrap()
            .iter()
            .map(s)
            .collect(),
        team_vesting_start_time: "1775044800".to_string(),
        team_allocation_nwei: "60000000000000000".to_string(),
        support_allocation_nwei: "10000000000000000".to_string(),
        team_count: "5".to_string(),
        support_count: "4".to_string(),
    }
}
