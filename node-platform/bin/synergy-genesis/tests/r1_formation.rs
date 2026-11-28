//! Five-participant public synthetic registry through the actual native verifier.
//! Root-approved registration is deliberately not a qualified randomness proof.
mod common;
use common::*;
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput,
            VerifiedApprovalPurpose,
        },
        network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::{
    formation::{
        CandidateSeedEvidence, FormationError, FormationRegistration, FormationRegistrySnapshot,
        Population,
    },
    policy::{IndexedProof, KeyRecord, NodeRecord},
};
use synergy_protocol_types::c14n02::Decoder;
fn data(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures")
        .join(name);
    let bytes = std::fs::read(path)
        .expect("published genuine public fixture required, never skip qualification");
    assert!(bytes.len() < 2 * 1024 * 1024);
    serde_json::from_slice(&bytes).unwrap()
}
#[test]
fn actual_five_member_registry_root_approval_and_cross_participant_isolation() {
    let f = data("r1_formation_public.json");
    assert_eq!(f["purpose"], "PUBLIC_SYNTHETIC_FORMATION_FIXTURE_ONLY");
    assert_eq!(f["production_import_permitted"], false);
    let g = data("r1_compiled_genesis_public.json");
    assert_eq!(g["chain_id"], u64::MAX - 1);
    let catalog = catalog();
    assert!(
        catalog.canonical_frame().unwrap()
            == bytes(g["profile_catalog_frame_hex"].as_str().unwrap()),
        "refresh genuine public fixture after a catalog change"
    );
    let commitment = catalog.commitment().unwrap();
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: bytes(g["nic_hex"].as_str().unwrap()).try_into().unwrap(),
    };
    let public_keys = g["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| bytes(r["public_key_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let roots = g["roots"]
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
        .collect::<Vec<_>>();
    let birth = NetworkBirth {
        chain_id: n.chain_id,
        incarnation_nonce: &[3; 32],
        genesis_schema: ProfileRef {
            name: "SYNERGY-GENESIS-R1",
            revision: 1,
        },
        initial_profile_set_commitment: &commitment,
        bootstrap_roots: &roots,
        network_label: "PUBLIC-SYNTHETIC-COMPILED-GENESIS-ONLY",
    };
    let authority = PinnedBootstrapAuthority::from_preparation_pins(
        &PinnedBootstrapInput {
            birth,
            threshold: 2,
        },
        &birth,
    )
    .unwrap();
    assert_eq!(authority.network(), n);
    let nic_sigs = g["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["purpose"] == "nic")
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let nic_approvals = nic_sigs
        .iter()
        .enumerate()
        .map(|(i, s)| IndexedRootApproval {
            root_index: i as u32,
            signature: s,
        })
        .collect::<Vec<_>>();
    let engine = engine();
    let nic = authority
        .verify_approvals(&engine, ApprovalPurpose::Nic, &nic_approvals)
        .unwrap();
    let mut registrations = f["input"]["registrations"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, r)| {
            let raw = bytes(r["node_record_c14n02_hex"].as_str().unwrap());
            let mut d = Decoder::new(&raw, 1024 * 1024).unwrap();
            let node = NodeRecord::decode_from(&mut d, n).unwrap();
            d.finish().unwrap();
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
    registrations.sort_by_key(|r|*synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&r.node.identity).unwrap().raw48());
    let build = |r: Vec<FormationRegistration>, population| {
        FormationRegistrySnapshot::build(&nic, &birth, &catalog, population, r, &engine)
    };
    let registry = build(registrations.clone(), Population::ConditionalFive).unwrap();
    assert_eq!(registry.registrations().len(), 5);
    assert_eq!(
        registry.canonical_bytes(),
        bytes(f["verified"]["registry_frame_hex"].as_str().unwrap())
    );
    assert_eq!(
        registry.preseed_frame().unwrap(),
        bytes(f["verified"]["preseed_frame_hex"].as_str().unwrap())
    );
    assert_eq!(
        registry.commitment().to_vec(),
        bytes(f["verified"]["registry_commitment_hex"].as_str().unwrap())
    );
    let signatures = f["input"]["formation_approvals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| bytes(a["signature_hex"].as_str().unwrap()))
        .collect::<Vec<_>>();
    let approvals = f["input"]["formation_approvals"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&signatures)
        .map(|(a, s)| IndexedRootApproval {
            root_index: a["root_index"].as_u64().unwrap() as u32,
            signature: s,
        })
        .collect::<Vec<_>>();
    let verified = registry
        .authenticate(&authority, &approvals, &engine)
        .unwrap();
    assert!(matches!(
        verified.approvals().purpose(),
        VerifiedApprovalPurpose::Formation { .. }
    ));
    // Consume the actual Core-verified original bytes through the APQE session
    // owner. Do not substitute fixture metadata or a candidate authority flag.
    let preseed = verified.registry().preseed_frame().unwrap();
    let channel = synergy_address_engine::apqe::formation_channel::FormationAuthority::from_approved_registry(verified.approvals(),verified.registry().canonical_bytes(),&preseed).unwrap();
    assert_eq!(channel.network(), n);
    assert_eq!(channel.profiles(), &commitment);
    assert_eq!(
        channel.registry_commitment(),
        verified.registry().commitment()
    );
    assert_eq!(
        channel.input_commitment(),
        &verified.registry().preseed_commitment().unwrap()
    );
    assert_eq!(channel.target_epoch(), 1);
    assert_eq!(channel.participants().count(), 5);
    for registration in verified.registry().registrations() {
        let id=synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&registration.node.identity).unwrap();
        let participant = channel.participant(id.raw48()).unwrap();
        assert_eq!(
            participant.public_key(),
            registration.formation_key.public_key
        );
        assert_eq!(
            participant.key_generation(),
            registration.formation_key.generation
        );
    }
    let evidence = CandidateSeedEvidence {
        network: n,
        registry_commitment: *verified.registry().commitment(),
        preseed_commitment: verified.registry().preseed_commitment().unwrap(),
        target_epoch: 1,
        construction: "APQE-RAND-HASHRAND-FULL-P1",
        transcript: b"PUBLIC-NONPROOF-NOT-A-HASHRAND-TRANSCRIPT",
        candidate_output: b"PUBLIC-NONPROOF-NOT-A-SEED",
    };
    assert!(matches!(
        verified.verify_seed(&evidence),
        Err(FormationError::ConstructionUnavailable)
    ));
    let mut wrong = evidence;
    wrong.network.nic[0] ^= 1;
    assert!(matches!(
        verified.verify_seed(&wrong),
        Err(FormationError::Context)
    ));
    // This attack used to escape the own-node check: its dedicated key is an
    // otherwise distinct peer's node key. Reject before any stale signature is
    // examined, proving full-population role separation rather than accidental
    // rejection of an unchanged signature over a changed key.
    let mut cross = registrations.clone();
    cross[0].formation_key.public_key = cross[1].node.birth_root.public_key.clone();
    assert!(matches!(
        build(cross, Population::ConditionalFive),
        Err(FormationError::Key)
    ));
    let mut corrupt = registrations.clone();
    corrupt[0].key_possession[0] ^= 1;
    assert!(matches!(
        build(corrupt, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    let mut missing = registrations.clone();
    missing[0].controller_approvals.clear();
    assert!(matches!(
        build(missing, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    let mut generation = registrations.clone();
    generation[0].formation_key.generation += 1;
    assert!(matches!(
        build(generation, Population::ConditionalFive),
        Err(FormationError::Proof)
    ));
    assert!(matches!(
        build(registrations.clone(), Population::ReferenceSeven),
        Err(FormationError::Population)
    ));
    assert!(matches!(
        build(registrations.clone(), Population::ConditionalFive)
            .unwrap()
            .authenticate(&authority, &nic_approvals, &engine),
        Err(FormationError::Proof)
    ));
    assert!(matches!(
        build(registrations, Population::ConditionalFive)
            .unwrap()
            .authenticate(&authority, &approvals[..1], &engine),
        Err(FormationError::Proof)
    ));
}
