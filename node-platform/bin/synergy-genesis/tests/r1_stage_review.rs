//! Pure review over existing PUBLIC synthetic bytes, never issuance or approval.
mod common;

use common::*;
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput,
            VerifiedBootstrapApprovals,
        },
        crypto_engine::CryptoEngine,
        network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::{
    formation::{FormationError, FormationRegistration, Population},
    policy::{IndexedProof, KeyRecord, NodeRecord},
    profiles::ProfileCatalog,
    stage_review::{review_complete_genesis, review_formation},
    GenesisError,
};
use synergy_protocol_types::c14n02::Decoder;

fn fixture(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures")
        .join(name);
    let raw = std::fs::read(path).expect("published signed public fixture required");
    assert!(raw.len() <= 2 * 1024 * 1024);
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(value["production_import_permitted"], false);
    value
}

fn with_nic(
    check: impl FnOnce(
        &serde_json::Value,
        &ProfileCatalog,
        &PinnedBootstrapAuthority,
        &VerifiedBootstrapApprovals,
        &CryptoEngine,
    ),
) {
    let f = fixture("r1_compiled_genesis_public.json");
    assert_eq!(
        f["purpose"],
        "PUBLIC_SYNTHETIC_COMPILED_GENESIS_FIXTURE_ONLY"
    );
    assert_eq!(f["chain_id"], u64::MAX - 1);
    let catalog = catalog();
    assert_eq!(
        catalog.canonical_frame().unwrap(),
        bytes(f["profile_catalog_frame_hex"].as_str().unwrap()),
        "fixture must match the exact current catalog"
    );
    let commitment = catalog.commitment().unwrap();
    let keys = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let roots = f["roots"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&keys)
        .map(|(r, key)| BootstrapKeyRecord {
            role: r["role"].as_str().unwrap(),
            algorithm: r["algorithm"].as_str().unwrap(),
            key_generation: r["key_generation"].as_u64().unwrap(),
            full_public_key: key,
        })
        .collect::<Vec<_>>();
    let nonce: [u8; 32] = bytes(f["nonce_hex"].as_str().unwrap()).try_into().unwrap();
    let birth = NetworkBirth {
        chain_id: u64::MAX - 1,
        incarnation_nonce: &nonce,
        genesis_schema: ProfileRef {
            name: "SYNERGY-GENESIS-R1",
            revision: 1,
        },
        initial_profile_set_commitment: &commitment,
        bootstrap_roots: &roots,
        network_label: f["network_label"].as_str().unwrap(),
    };
    let pins = PinnedBootstrapInput {
        birth,
        threshold: 2,
    };
    let expected: [u8; 64] = bytes(f["nic_hex"].as_str().unwrap()).try_into().unwrap();
    let authority = PinnedBootstrapAuthority::from_received_pins(&pins, &birth, &expected).unwrap();
    let entries = f["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["purpose"] == "nic")
        .collect::<Vec<_>>();
    let signatures = entries
        .iter()
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let approvals = entries
        .iter()
        .zip(&signatures)
        .map(|(a, signature)| IndexedRootApproval {
            root_index: a["root_index"].as_u64().unwrap().try_into().unwrap(),
            signature,
        })
        .collect::<Vec<_>>();
    let engine = engine();
    let nic = authority
        .verify_approvals(&engine, ApprovalPurpose::Nic, &approvals)
        .unwrap();
    // The only capability admitted by this helper is the genuine received NIC.
    // Neither future Formation nor Genesis signatures are passed to review.
    let mut wrong_nic = expected;
    wrong_nic[0] ^= 1;
    assert!(PinnedBootstrapAuthority::from_received_pins(&pins, &birth, &wrong_nic).is_err());
    check(&f, &catalog, &authority, &nic, &engine);
}

fn registrations(f: &serde_json::Value, network: NetworkRef) -> Vec<FormationRegistration> {
    assert_eq!(f["purpose"], "PUBLIC_SYNTHETIC_FORMATION_FIXTURE_ONLY");
    assert_eq!(f["beacon_or_seed_produced"], false);
    let mut result = f["input"]["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let raw = bytes(r["node_record_c14n02_hex"].as_str().unwrap());
            let mut decoder = Decoder::new(&raw, 1024 * 1024).unwrap();
            let node = NodeRecord::decode_from(&mut decoder, network).unwrap();
            decoder.finish().unwrap();
            FormationRegistration {
                node,
                formation_key: KeyRecord {
                    role: "formation_authentication".into(),
                    algorithm: Algorithm::MlDsa87,
                    generation: 1,
                    public_key: bytes(r["formation_public_key_hex"].as_str().unwrap()),
                },
                registration_nonce: [20 + index as u8; 32],
                key_possession: bytes(r["key_possession_signature_hex"].as_str().unwrap()),
                controller_approvals: vec![IndexedProof {
                    index: 0,
                    signature: bytes(r["controller_signature_hex"].as_str().unwrap()),
                }],
            }
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|r| *synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&r.node.identity).unwrap().raw48());
    result
}

#[test]
fn genuine_nic_reviews_exact_formation_without_future_root_approval() {
    with_nic(|_, catalog, _, nic, engine| {
        let f = fixture("r1_formation_public.json");
        let reviewed = review_formation(
            nic,
            catalog,
            Population::ConditionalFive,
            registrations(&f, nic.network()),
            engine,
        )
        .unwrap();
        assert_eq!(reviewed.network(), nic.network());
        assert_eq!(
            reviewed.activated_profiles(),
            &catalog.commitment().unwrap()
        );
        assert_eq!(
            reviewed.canonical_registry(),
            bytes(f["verified"]["registry_frame_hex"].as_str().unwrap())
        );
        assert_eq!(
            reviewed.registry_commitment().to_vec(),
            bytes(f["verified"]["registry_commitment_hex"].as_str().unwrap())
        );
        assert_eq!(
            reviewed.canonical_preseed().unwrap(),
            bytes(f["verified"]["preseed_frame_hex"].as_str().unwrap())
        );
        assert_eq!(
            reviewed.preseed_commitment().to_vec(),
            bytes(f["verified"]["input_commitment_hex"].as_str().unwrap())
        );
    });
}

#[test]
fn formation_review_rejects_tampering_wrong_population_and_missing_provider() {
    with_nic(|_, catalog, _, nic, engine| {
        let f = fixture("r1_formation_public.json");
        let rows = registrations(&f, nic.network());
        let review = |r, population| review_formation(nic, catalog, population, r, engine);
        let mut changed = rows.clone();
        changed[0].key_possession[0] ^= 1;
        assert!(matches!(
            review(changed, Population::ConditionalFive),
            Err(FormationError::Proof)
        ));
        let mut changed = rows.clone();
        changed[0].controller_approvals.clear();
        assert!(matches!(
            review(changed, Population::ConditionalFive),
            Err(FormationError::Proof)
        ));
        let mut changed = rows.clone();
        changed[0].registration_nonce[0] ^= 1;
        assert!(matches!(
            review(changed, Population::ConditionalFive),
            Err(FormationError::Proof)
        ));
        let mut changed = rows.clone();
        changed[0].formation_key.public_key = changed[1].node.birth_root.public_key.clone();
        assert!(matches!(
            review(changed, Population::ConditionalFive),
            Err(FormationError::Key)
        ));
        assert!(matches!(
            review(rows.clone(), Population::ReferenceSeven),
            Err(FormationError::Population)
        ));
        assert!(matches!(
            review_formation(
                nic,
                catalog,
                Population::ConditionalFive,
                rows,
                &CryptoEngine::new()
            ),
            Err(FormationError::Profile)
        ));
    });
}

#[test]
fn complete_genesis_review_refuses_genuinely_approved_schema_one() {
    with_nic(|g, catalog, authority, nic, engine| {
        let core = bytes(g["genesis_core_c14n02_hex"].as_str().unwrap());
        let signed = |purpose: &str| {
            g["approvals"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|a| a["purpose"] == purpose)
                .map(|a| {
                    (
                        a["root_index"].as_u64().unwrap() as u32,
                        bytes(a["signature_hex"].as_str().unwrap()),
                    )
                })
                .collect::<Vec<_>>()
        };
        let nic_signatures = signed("nic");
        let genesis_signatures = signed("genesis");
        fn approvals(rows: &[(u32, Vec<u8>)]) -> Vec<IndexedRootApproval<'_>> {
            rows.iter()
                .map(|(index, signature)| IndexedRootApproval {
                    root_index: *index,
                    signature,
                })
                .collect::<Vec<_>>()
        }
        let verified = synergy_genesis::r1::verify_bytes(
            &core,
            catalog,
            authority,
            &approvals(&nic_signatures),
            &approvals(&genesis_signatures),
            engine,
        )
        .unwrap();
        assert_eq!(verified.coordinate().network.nic, nic.network().nic);
        assert!(matches!(
            review_complete_genesis(&core, catalog, authority, nic, engine),
            Err(GenesisError::FormationUnavailable)
        ));
        let mut trailing = core.clone();
        trailing.push(0);
        assert!(review_complete_genesis(&trailing, catalog, authority, nic, engine).is_err());
        let mut changed_network = core;
        // Locate the typed chain field with the sole owning C14N-02 encoder,
        // preserving the domain and schema rather than guessing a byte offset.
        let mut prefix =
            synergy_protocol_types::c14n02::Encoder::with_domain("SYNERGY/GENESIS/01", 128)
                .unwrap();
        prefix.u16(1).unwrap();
        prefix.u64(u64::MAX - 1).unwrap();
        let prefix = prefix.finish().unwrap();
        assert_eq!(&changed_network[..prefix.len()], prefix);
        changed_network[prefix.len() - 1] ^= 1;
        // Decode rederives the first Node identity under the changed N before
        // the later explicit NIC comparison; that earlier policy rejection is
        // the expected source-owned failure, not a fabricated approval result.
        assert!(matches!(
            review_complete_genesis(&changed_network, catalog, authority, nic, engine),
            Err(GenesisError::Policy)
        ));
    });
}
