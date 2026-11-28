//! Complete public synthetic Genesis through actual APQE/native/state owners.
mod common;
use common::*;
use synergy_address_engine::apqe::{
    bootstrap_approvals_r1::{IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput},
    network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
    r1_framing::NetworkRef,
};
use synergy_genesis::r1::{self, account::AccountRecord};
use synergy_protocol_types::{c14n02::Decoder, R1NetworkRef};
use synergy_state::r1::*;
fn fixture() -> serde_json::Value {
    let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_compiled_genesis_public.json");
    let input = std::fs::read(path)
        .expect("actual public signed compiled fixture required, never skip qualification");
    assert!(input.len() <= 1024 * 1024);
    let v: serde_json::Value = serde_json::from_slice(&input).unwrap();
    assert_eq!(
        v["purpose"],
        "PUBLIC_SYNTHETIC_COMPILED_GENESIS_FIXTURE_ONLY"
    );
    assert_eq!(v["production_import_permitted"], false);
    assert_eq!(v["chain_id"], u64::MAX - 1);
    v
}
#[test]
fn actual_compiled_genesis_recomputes_state_and_requires_both_native_quorums() {
    let f = fixture();
    let catalog = catalog();
    assert_eq!(
        catalog.canonical_frame().unwrap(),
        bytes(f["profile_catalog_frame_hex"].as_str().unwrap())
    );
    let commitment = catalog.commitment().unwrap();
    assert_eq!(
        commitment.to_vec(),
        bytes(f["profile_set_commitment_hex"].as_str().unwrap())
    );
    let public_keys: Vec<_> = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect();
    let roots: Vec<_> = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&public_keys)
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
        initial_profile_set_commitment: &commitment,
        bootstrap_roots: &roots,
        network_label: "PUBLIC-SYNTHETIC-COMPILED-GENESIS-ONLY",
    };
    let pins = PinnedBootstrapInput {
        birth,
        threshold: 2,
    };
    let authority = PinnedBootstrapAuthority::from_preparation_pins(&pins, &birth).unwrap();
    assert_eq!(
        authority.network().nic.to_vec(),
        bytes(f["nic_hex"].as_str().unwrap())
    );
    let signatures: Vec<_> = f["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect();
    assert_eq!(signatures.len(), 4);
    let approvals = |offset: usize| {
        (0..2)
            .map(|i| IndexedRootApproval {
                root_index: i as u32,
                signature: signatures[offset + i].as_slice(),
            })
            .collect::<Vec<_>>()
    };
    let nic = approvals(0);
    let genesis = approvals(2);
    let core = bytes(f["genesis_core_c14n02_hex"].as_str().unwrap());
    let engine = engine();
    let verified = r1::verify_bytes(&core, &catalog, &authority, &nic, &genesis, &engine).unwrap();
    assert_eq!(
        verified.coordinate().genesis.digest.to_vec(),
        bytes(f["genesis_digest48_hex"].as_str().unwrap())
    );
    assert_eq!(
        verified.initial_state_root().to_vec(),
        bytes(f["state_root48_hex"].as_str().unwrap())
    );
    assert_eq!(
        verified.initial_receipts_root().to_vec(),
        bytes(f["receipts_root48_hex"].as_str().unwrap())
    );
    assert_eq!(verified.initial_validator_keys().len(), 1);
    assert_eq!(
        verified.block_profile().name,
        synergy_posy::r1::BLOCK_PROFILE_NAME
    );
    assert!(r1::verify_bytes(&core, &catalog, &authority, &[], &genesis, &engine).is_err());
    assert!(r1::verify_bytes(&core, &catalog, &authority, &nic, &[], &engine).is_err());
    assert!(r1::verify_bytes(&core, &catalog, &authority, &genesis, &nic, &engine).is_err());
    let mut changed = core.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(r1::verify_bytes(&changed, &catalog, &authority, &nic, &genesis, &engine).is_err());
    let mut changed = core.clone();
    changed.push(0);
    assert!(r1::verify_bytes(&changed, &catalog, &authority, &nic, &genesis, &engine).is_err());
    assert!(r1::verify_bytes(
        &core,
        &catalog,
        &authority,
        &nic,
        &genesis,
        &synergy_address_engine::apqe::crypto_engine::CryptoEngine::new()
    )
    .is_err());
    let mut bad = signatures[0].clone();
    bad[0] ^= 1;
    let corrupt = [
        IndexedRootApproval {
            root_index: 0,
            signature: &bad,
        },
        IndexedRootApproval {
            root_index: 1,
            signature: &signatures[1],
        },
    ];
    assert!(r1::verify_bytes(&core, &catalog, &authority, &corrupt, &genesis, &engine).is_err());
}
fn state_input(f: &serde_json::Value) -> R1GenesisStateInput {
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: bytes(f["nic_hex"].as_str().unwrap()).try_into().unwrap(),
    };
    let raw = bytes(f["account_record_c14n02_hex"].as_str().unwrap());
    let mut d = Decoder::new(&raw, 1024 * 1024).unwrap();
    let account = AccountRecord::decode_from(&mut d, n).unwrap();
    d.finish().unwrap();
    let policy = account.verify(n, &engine()).unwrap();
    let identity = policy.identity.clone();
    R1GenesisStateInput {
        network: R1NetworkRef {
            chain_id: n.chain_id,
            nic: n.nic,
        },
        accounts: vec![policy],
        allocations: vec![
            R1GenesisAllocation {
                allocation_id: "FIXED-PUBLIC-0".into(),
                amount_nwei: 2,
                destination: R1GenesisDestination::Account { identity },
            },
            R1GenesisAllocation {
                allocation_id: "FIXED-PUBLIC-1".into(),
                amount_nwei: 1,
                destination: R1GenesisDestination::UnassignedValidatorFunding,
            },
        ],
        restricted_records: [
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
        .collect(),
        profile_definitions: vec![],
    }
}
#[test]
fn actual_complete_account_policy_and_financial_conservation() {
    let f = fixture();
    let input = state_input(&f);
    let state = compile_genesis(&input).unwrap();
    assert_eq!(state.total_issued_nwei, 3);
    let key =
        R1StateKey::native(R1StateDomain::NativeBalance, &input.accounts[0].identity).unwrap();
    assert_eq!(
        state.state.get(&key),
        Some(&R1StateValue::NativeBalance { amount_nwei: 2 })
    );
    assert_eq!(state.receipts_root, empty_receipts_root().unwrap());
    let mut bad = state_input(&f);
    bad.accounts[0].birth_nonce32[0] ^= 1;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.network.nic[0] ^= 1;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.accounts[0].policy_epoch = 2;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.accounts[0].nonce = 1;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.allocations[1].allocation_id = bad.allocations[0].allocation_id.clone();
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.allocations[0].amount_nwei = u128::MAX;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.restricted_records[0].balance_nwei = 1;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.restricted_records[3].kind = RestrictedRecordKind::Treasury;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.accounts[0].policy_commitment[0] ^= 1;
    assert!(compile_genesis(&bad).is_err());
    let mut bad = state_input(&f);
    bad.network.chain_id = 9969;
    assert!(matches!(
        compile_genesis(&bad),
        Err(R1StateError::CeremonyRequired)
    ));
}
