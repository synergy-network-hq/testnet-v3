//! Public isolated fixture compiler bridge. No signing, generation or file writes.
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{PinnedBootstrapAuthority, PinnedBootstrapInput},
    crypto_engine::CryptoEngine,
    network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
    provider::{
        variants::{Mldsa65, Mldsa87},
        PqProvider, Profile,
    },
};
use synergy_genesis::r1::{
    compiler::{self, GenesisCoreInput, InitialVoter},
    policy::NodeRecord,
    profiles::{ProfileCatalog, ProfileDefinition, ProfileKind},
};
use synergy_protocol_types::{c14n02::Decoder, R1NetworkRef};
use synergy_state::r1::*;
fn bytes(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|x| format!("{x:02x}")).collect()
}
fn read_public(path: &str, max: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;
    let metadata = std::fs::symlink_metadata(path)?;
    if !std::path::Path::new(path).is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max
    {
        return Err("bounded absolute public fixture required".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("public fixture changed size".into());
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bootstrap:serde_json::Value=serde_json::from_str(include_str!("../../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_signed_bootstrap_public.json"))?;
    let provider_pin = bytes("06dbd772bd335da463d6befbaef8aa4bf9e0e342af0fc281eed143e347fdad9d")
        .try_into()
        .unwrap();
    let provider65_pin = bytes("6dbd9741d717ee5c40fd22bfa11c1e734b90af6727df61042d21f621105d8fa6")
        .try_into()
        .unwrap();
    let kem_pin = bytes("11522b9e7063fce234bdf4d755092feb8ae8896779aacc38ddb7f3e189d45cd0")
        .try_into()
        .unwrap();
    let catalog = ProfileCatalog::new(
        ProfileKind::ALL
            .iter()
            .map(|kind| {
                ProfileDefinition::from_selected_source(
                    *kind,
                    provider65_pin,
                    provider_pin,
                    kem_pin,
                )
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let profile_commitment = catalog.commitment()?;
    let keys: Vec<Vec<u8>> = bootstrap["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect();
    let roots: Vec<_> = bootstrap["roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&keys)
        .map(|(r, k)| BootstrapKeyRecord {
            role: r["role"].as_str().unwrap(),
            algorithm: r["algorithm"].as_str().unwrap(),
            key_generation: r["key_generation"].as_u64().unwrap(),
            full_public_key: k,
        })
        .collect();
    let birth = NetworkBirth {
        chain_id: u64::MAX - 1,
        incarnation_nonce: &[3; 32],
        genesis_schema: ProfileRef {
            name: "SYNERGY-GENESIS-R1",
            revision: 1,
        },
        initial_profile_set_commitment: &profile_commitment,
        bootstrap_roots: &roots,
        network_label: "PUBLIC-SYNTHETIC-COMPILED-GENESIS-ONLY",
    };
    let pins = PinnedBootstrapInput {
        birth,
        threshold: 2,
    };
    let authority = PinnedBootstrapAuthority::from_preparation_pins(&pins, &birth)
        .map_err(|e| format!("pinned fixture: {e:?}"))?;
    let mut output = serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_COMPILED_GENESIS_FIXTURE_ONLY","production_import_permitted":false,"chain_id":u64::MAX-1,"nonce_hex":hex(&[3;32]),"network_label":birth.network_label,"threshold":2,"roots":bootstrap["roots"],"profile_set_commitment_hex":hex(&profile_commitment),"profile_catalog_frame_hex":hex(&catalog.canonical_frame()?),"nic_hex":hex(&authority.network().nic),"profiles_are_production_qualified":false,"authority_granted":false});
    if let Some(path) = std::env::args().nth(1) {
        let metadata = std::fs::symlink_metadata(&path)?;
        if !std::path::Path::new(&path).is_absolute()
            || !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 256 * 1024
        {
            return Err("bounded absolute public fixture required".into());
        }
        let data: serde_json::Value = serde_json::from_slice(&read_public(&path, 256 * 1024)?)?;
        if data["production_import_permitted"] != false || data["chain_id"] != u64::MAX - 1 {
            return Err("isolated public fixture only".into());
        }
        let node_bytes = bytes(
            data["node_record_c14n02_hex"]
                .as_str()
                .ok_or("missing public node bytes")?,
        );
        let n = authority.network();
        let mut d = Decoder::new(&node_bytes, 1024 * 1024)?;
        let node = NodeRecord::decode_from(&mut d, n)?;
        d.finish()?;
        let dir=std::path::PathBuf::from("/Volumes/PortableSSD/02-Synergy-Network/24-Technical-Documentation/testnet-9969-preparation/revisions/r2/provider-validation");
        let pin65 = bytes("6dbd9741d717ee5c40fd22bfa11c1e734b90af6727df61042d21f621105d8fa6")
            .try_into()
            .unwrap();
        // Canonical locally built validation-only native artifacts, actual verification only.
        let engine = unsafe {
            CryptoEngine::new()
                .with_mldsa65(PqProvider::<Mldsa65>::open_verified(
                    dir.join("libaegismldsa65.dylib"),
                    pin65,
                    Profile::Validation,
                )?)
                .with_mldsa87(PqProvider::<Mldsa87>::open_verified(
                    dir.join("libaegismldsa87.dylib"),
                    provider_pin,
                    Profile::Validation,
                )?)
        };
        let restricted_records = [
            RestrictedRecordKind::Treasury,
            RestrictedRecordKind::TreasuryRecovery,
            RestrictedRecordKind::SecurityForfeiture,
            RestrictedRecordKind::FeeRoundingEscrow,
        ]
        .into_iter()
        .map(|kind| R1RestrictedOpening {
            kind,
            balance_nwei: 0,
            policy_commitment: [kind as u8 + 1; 64],
        })
        .collect();
        let voter = InitialVoter {
            identity: node.identity.clone(),
            weight: 1,
        };
        let mut accounts = Vec::new();
        let mut allocations = vec![R1GenesisAllocation {
            allocation_id: "PUBLIC-SYNTHETIC-SOURCE-0".into(),
            amount_nwei: 1,
            destination: R1GenesisDestination::UnassignedValidatorFunding,
        }];
        if let Some(path) = std::env::args().nth(2) {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !std::path::Path::new(&path).is_absolute()
                || !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 128 * 1024
            {
                return Err("bounded public account fixture required".into());
            }
            let account_data: serde_json::Value =
                serde_json::from_slice(&read_public(&path, 128 * 1024)?)?;
            if account_data["production_import_permitted"] != false
                || account_data["chain_id"] != u64::MAX - 1
            {
                return Err("isolated account fixture only".into());
            }
            let account_bytes = bytes(
                account_data["account_record_c14n02_hex"]
                    .as_str()
                    .ok_or("missing account bytes")?,
            );
            let mut d = Decoder::new(&account_bytes, 1024 * 1024)?;
            let account = synergy_genesis::r1::account::AccountRecord::decode_from(&mut d, n)?;
            d.finish()?;
            allocations.push(R1GenesisAllocation {
                allocation_id: "PUBLIC-SYNTHETIC-SOURCE-1".into(),
                amount_nwei: 2,
                destination: R1GenesisDestination::Account {
                    identity: account.identity.clone(),
                },
            });
            accounts.push(account);
            output["account_record_c14n02_hex"] = account_data["account_record_c14n02_hex"].clone();
        }
        let input = GenesisCoreInput {
            network: R1NetworkRef {
                chain_id: n.chain_id,
                nic: n.nic,
            },
            genesis_time: 1,
            catalog: catalog.clone(),
            nodes: vec![node],
            accounts,
            initial_voters: vec![voter],
            allocations,
            restricted_records,
        };
        let compiled = compiler::compile(input, &catalog, &engine)?;
        output["genesis_digest48_hex"] = hex(&compiled.coordinate().genesis.digest).into();
        output["genesis_core_c14n02_hex"] = hex(compiled.canonical_bytes()).into();
        output["state_root48_hex"] = hex(&compiled.state().root).into();
        output["receipts_root48_hex"] = hex(&compiled.state().receipts_root).into();
        output["node_record_c14n02_hex"] = data["node_record_c14n02_hex"].clone();
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
