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
    assert!(catalog.canonical_frame().unwrap() == bytes(f["profile_catalog_frame_hex"].as_str().unwrap()), "current complete catalog differs from public fixture; refresh exact signed synthetic fixture");
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
    let expected_nic: [u8; 64] = bytes(f["nic_hex"].as_str().unwrap()).try_into().unwrap();
    let authority =
        PinnedBootstrapAuthority::from_received_pins(&pins, &birth, &expected_nic).unwrap();
    let mut wrong_nic = expected_nic;
    wrong_nic[0] ^= 1;
    assert!(PinnedBootstrapAuthority::from_received_pins(&pins, &birth, &wrong_nic).is_err());
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
    let mut actual_received_context = n;
    actual_received_context.chain_id = 9969;
    assert!(matches!(
        account.validate_birth(actual_received_context),
        Err(synergy_genesis::r1::policy::PolicyError::Identity)
    ));
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

#[test]
fn actual_provider_must_match_its_own_target_slot_without_cross_platform_fallback() {
    use synergy_genesis::r1::{artifact_matrix::ArtifactTarget, profiles::ProfileCatalog};
    let engine = engine();
    let selected = catalog();
    selected.validate_provider(&engine).unwrap();
    let mut definitions = selected.definitions().to_vec();
    for d in &mut definitions {
        let pins = *d.artifact_matrix.get(ArtifactTarget::MacosArm64).unwrap();
        d.artifact_matrix.macos.arm64 = None;
        d.artifact_matrix.linux.x86_64_gnu = Some(pins);
    }
    let misplaced = ProfileCatalog::new(definitions).unwrap();
    assert!(misplaced.validate_provider(&engine).is_err());
    let mut definitions = selected.definitions().to_vec();
    for d in &mut definitions {
        d.artifact_matrix.macos.arm64.as_mut().unwrap().mldsa65[0] ^= 1;
    }
    let wrong = ProfileCatalog::new(definitions).unwrap();
    assert!(wrong.validate_provider(&engine).is_err());
}

#[cfg(unix)]
#[test]
fn installed_received_bundle_checks_actual_signatures_and_confines_public_files() {
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use synergy_genesis::r1::received_bundle::{load_received_bundle, BundleError};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct PublicTemporary(PathBuf);
    impl Drop for PublicTemporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let base = PathBuf::from("/private/tmp").join(format!(
        "synergy-public-received-bundle-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&base).unwrap();
    let temporary = PublicTemporary(base);
    std::fs::set_permissions(&temporary.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let f = fixture();
    let birth = serde_json::json!({"schema_version":1,"chain_id":f["chain_id"],"incarnation_nonce_hex":f["nonce_hex"],"genesis_schema":{"name":"SYNERGY-GENESIS-R1","revision":1},"initial_profile_set_commitment_hex":f["profile_set_commitment_hex"],"bootstrap_roots":f["roots"],"network_label":f["network_label"],"threshold":f["threshold"]});
    let approvals = |purpose: &str| {
        f["approvals"].as_array().unwrap().iter().filter(|a|a["purpose"]==purpose).map(|a|serde_json::json!({"root_index":a["root_index"],"signature_hex":a["signature_hex"]})).collect::<Vec<_>>()
    };
    let approved = serde_json::json!({"schema_version":1,"nic":approvals("nic"),"genesis":approvals("genesis")});
    let pinbytes = serde_json::to_vec(&birth).unwrap();
    let approvalbytes = serde_json::to_vec(&approved).unwrap();
    let catalog = bytes(f["profile_catalog_frame_hex"].as_str().unwrap());
    for (name, content) in [
        ("birth.json", pinbytes.clone()),
        ("approvals.json", approvalbytes.clone()),
        ("catalog.cbor", catalog.clone()),
        (
            "genesis.core",
            bytes(f["genesis_core_c14n02_hex"].as_str().unwrap()),
        ),
    ] {
        let path = temporary.0.join(name);
        std::fs::write(&path, content).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let hash = |input: &[u8]| {
        synergy_address_engine::apqe::Primitives
            .hash(synergy_address_engine::apqe::HashAlgorithm::Sha256, input)
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let selection = synergy_config::R1GenesisSelection {
        managed_root: temporary.0.clone(),
        core_path: "genesis.core".into(),
        approvals_path: "approvals.json".into(),
        pinned_bootstrap_input_path: "birth.json".into(),
        pinned_bootstrap_input_sha256: hash(&pinbytes),
        profile_catalog_path: "catalog.cbor".into(),
        profile_catalog_sha256: hash(&catalog),
        expected_nic_hex: f["nic_hex"].as_str().unwrap().into(),
        expected_genesis_hex: f["genesis_digest48_hex"].as_str().unwrap().into(),
    };
    let engine = engine();
    let verified = load_received_bundle(&selection, u64::MAX - 1, &engine).unwrap();
    assert_eq!(
        verified.coordinate().genesis.digest.to_vec(),
        bytes(&selection.expected_genesis_hex)
    );
    assert_eq!(
        verified.nic_approvals().purpose(),
        synergy_address_engine::apqe::bootstrap_approvals_r1::VerifiedApprovalPurpose::Nic
    );
    assert_eq!(
        verified.genesis_approvals().genesis_digest(),
        Some(&verified.coordinate().genesis.digest)
    );
    // Pre-Genesis authentication uses the same protected pin parser, but never
    // opens the future core or accepts a placeholder final-Genesis field.
    let nic_path = temporary.0.join("nic-approvals.json");
    let nic_transport = serde_json::json!({"schema_version":1,"nic":approved["nic"]});
    std::fs::write(&nic_path, serde_json::to_vec(&nic_transport).unwrap()).unwrap();
    std::fs::set_permissions(&nic_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let nic_selection = synergy_config::R1NicSelection {
        managed_root: selection.managed_root.clone(),
        approvals_path: "nic-approvals.json".into(),
        pinned_bootstrap_input_path: selection.pinned_bootstrap_input_path.clone(),
        pinned_bootstrap_input_sha256: selection.pinned_bootstrap_input_sha256.clone(),
        profile_catalog_path: selection.profile_catalog_path.clone(),
        profile_catalog_sha256: selection.profile_catalog_sha256.clone(),
        expected_nic_hex: selection.expected_nic_hex.clone(),
    };
    std::fs::rename(
        temporary.0.join("genesis.core"),
        temporary.0.join("unused-future-genesis.core"),
    )
    .unwrap();
    let nic_verified = synergy_genesis::r1::received_bundle::load_received_nic_bundle(
        &nic_selection,
        u64::MAX - 1,
        &engine,
    )
    .unwrap();
    assert_eq!(
        nic_verified.approvals().purpose(),
        synergy_address_engine::apqe::bootstrap_approvals_r1::VerifiedApprovalPurpose::Nic
    );
    assert_eq!(nic_verified.catalog(), &common::catalog());
    assert!(matches!(
        synergy_genesis::r1::received_bundle::load_received_nic_bundle(
            &nic_selection,
            u64::MAX - 1,
            &synergy_address_engine::apqe::crypto_engine::CryptoEngine::new()
        ),
        Err(BundleError::Catalog)
    ));
    let mut mixed_selection = serde_json::to_value(&nic_selection).unwrap();
    mixed_selection["expected_genesis_hex"] = "00".repeat(48).into();
    assert!(serde_json::from_value::<synergy_config::R1NicSelection>(mixed_selection).is_err());
    let mixed_transport =
        serde_json::json!({"schema_version":1,"nic":approved["nic"],"genesis":[]});
    std::fs::write(&nic_path, serde_json::to_vec(&mixed_transport).unwrap()).unwrap();
    assert!(matches!(
        synergy_genesis::r1::received_bundle::load_received_nic_bundle(
            &nic_selection,
            u64::MAX - 1,
            &engine
        ),
        Err(BundleError::Encoding)
    ));
    std::fs::write(
        &nic_path,
        serde_json::to_vec(&serde_json::json!({"schema_version":1,"nic":approved["genesis"]}))
            .unwrap(),
    )
    .unwrap();
    assert!(matches!(
        synergy_genesis::r1::received_bundle::load_received_nic_bundle(
            &nic_selection,
            u64::MAX - 1,
            &engine
        ),
        Err(BundleError::Approval)
    ));
    std::fs::rename(
        temporary.0.join("unused-future-genesis.core"),
        temporary.0.join("genesis.core"),
    )
    .unwrap();
    // The independently approved NIC is usable before any final Genesis file.
    // The NIC carrier must not pretend an empty/future Genesis already exists.
    let nic_path = temporary.0.join("nic-approvals.json");
    std::fs::write(
        &nic_path,
        serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"nic":approvals("nic")
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&nic_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let nic_selection = synergy_config::R1NicSelection {
        managed_root: selection.managed_root.clone(),
        approvals_path: "nic-approvals.json".into(),
        pinned_bootstrap_input_path: selection.pinned_bootstrap_input_path.clone(),
        pinned_bootstrap_input_sha256: selection.pinned_bootstrap_input_sha256.clone(),
        profile_catalog_path: selection.profile_catalog_path.clone(),
        profile_catalog_sha256: selection.profile_catalog_sha256.clone(),
        expected_nic_hex: selection.expected_nic_hex.clone(),
    };
    std::fs::remove_file(temporary.0.join("genesis.core")).unwrap();
    use synergy_genesis::r1::received_bundle::load_received_nic_bundle;
    let nic = load_received_nic_bundle(&nic_selection, u64::MAX - 1, &engine).unwrap();
    assert_eq!(
        nic.approvals().network(),
        verified.nic_approvals().network()
    );
    assert_eq!(
        nic.catalog().commitment().unwrap(),
        verified.coordinate().activated_profiles.commitment
    );
    assert!(load_received_nic_bundle(&nic_selection, 9969, &engine).is_err());
    let mut future = nic_selection.clone();
    future.approvals_path = "approvals.json".into();
    assert!(matches!(
        load_received_nic_bundle(&future, u64::MAX - 1, &engine),
        Err(BundleError::Encoding)
    ));
    std::fs::write(
        temporary.0.join("genesis.core"),
        bytes(f["genesis_core_c14n02_hex"].as_str().unwrap()),
    )
    .unwrap();
    std::fs::set_permissions(
        temporary.0.join("genesis.core"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let mut bad = selection.clone();
    bad.core_path = "../genesis.core".into();
    assert!(matches!(
        load_received_bundle(&bad, u64::MAX - 1, &engine),
        Err(BundleError::Path)
    ));
    bad = selection.clone();
    bad.expected_genesis_hex = "00".repeat(48);
    assert!(matches!(
        load_received_bundle(&bad, u64::MAX - 1, &engine),
        Err(BundleError::Context)
    ));
    bad = selection.clone();
    bad.profile_catalog_sha256 = "00".repeat(32);
    assert!(matches!(
        load_received_bundle(&bad, u64::MAX - 1, &engine),
        Err(BundleError::Integrity)
    ));
    assert!(load_received_bundle(&selection, 9969, &engine).is_err());
    symlink(
        temporary.0.join("genesis.core"),
        temporary.0.join("linked.core"),
    )
    .unwrap();
    bad = selection.clone();
    bad.core_path = "linked.core".into();
    assert!(matches!(
        load_received_bundle(&bad, u64::MAX - 1, &engine),
        Err(BundleError::Path)
    ));
    let duplicate = String::from_utf8(approvalbytes.clone()).unwrap().replacen(
        "{",
        "{\"schema_version\":1,",
        1,
    );
    std::fs::write(temporary.0.join("approvals.json"), duplicate).unwrap();
    assert!(matches!(
        load_received_bundle(&selection, u64::MAX - 1, &engine),
        Err(BundleError::Encoding)
    ));
    std::fs::write(temporary.0.join("approvals.json"), &approvalbytes).unwrap();
    std::fs::set_permissions(
        temporary.0.join("genesis.core"),
        std::fs::Permissions::from_mode(0o622),
    )
    .unwrap();
    assert!(matches!(
        load_received_bundle(&selection, u64::MAX - 1, &engine),
        Err(BundleError::Protection)
    ));
    std::fs::set_permissions(
        temporary.0.join("genesis.core"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::write(
        temporary.0.join("approvals.json"),
        br#"{"schema_version":1,"nic":[],"genesis":[]}"#,
    )
    .unwrap();
    assert!(matches!(
        load_received_bundle(&selection, u64::MAX - 1, &engine),
        Err(BundleError::Approval)
    ));
    // All public test inputs are deleted by the RAII guard, including on panic.
}
