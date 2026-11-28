//! Public existing KAT keys only; no provider/RNG/signing or actual coordinate.
use synergy_address_engine::apqe::{
    managed_creation::identity_proof::{IdentityProofInput, ValidatedIdentityProofPlan},
    native_identity_derivation_r1::{
        canonical_received_policy_frame, AccessRule, BirthPolicy, Controller,
    },
    network_birth_r1::BootstrapKeyRecord,
    r1_framing::NetworkRef,
};
use synergy_execution::r1_enrollment::InitialWalletIntent;
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let d:serde_json::Value=serde_json::from_slice(&std::fs::read(root.join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_compiled_genesis_public.json")).unwrap()).unwrap();
    assert_eq!(d["production_import_permitted"], false);
    assert_eq!(d["chain_id"].as_u64(), Some(u64::MAX - 1));
    let decode = |k: &str| hex::decode(d[k].as_str().unwrap()).unwrap();
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: decode("nic_hex").try_into().unwrap(),
    };
    let pk = d["roots"]
        .as_array()
        .unwrap()
        .iter()
        .take(2)
        .map(|r| hex::decode(r["public_key_hex"].as_str().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(pk.len(), 2);
    assert_ne!(pk[0], pk[1]);
    let controllers = [
        Controller {
            key: BootstrapKeyRecord {
                role: "D",
                algorithm: "ML-DSA-87",
                key_generation: 1,
                full_public_key: &pk[0],
            },
            asserted_independence_domain: "PUBLIC-SYNTHETIC-D",
        },
        Controller {
            key: BootstrapKeyRecord {
                role: "P",
                algorithm: "ML-DSA-87",
                key_generation: 1,
                full_public_key: &pk[1],
            },
            asserted_independence_domain: "PUBLIC-SYNTHETIC-P",
        },
    ];
    let policy = BirthPolicy {
        namespace: "synw",
        controllers: &controllers,
        ordinary: AccessRule {
            threshold: 2,
            controller_indices: &[0, 1],
        },
        recovery: None,
    };
    let frame = canonical_received_policy_frame(n, &policy, 131072).unwrap();
    let mut input = IdentityProofInput {
        namespace: "synw".into(),
        expected_identity: String::new(),
        birth_nonce_hex: "91".repeat(32),
        enrollment_nonce_hex: "92".repeat(32),
        birth_policy_frame_hex: hex::encode(frame),
        current_policy_frame_hex: String::new(),
        node: None,
    };
    input.current_policy_frame_hex = input.birth_policy_frame_hex.clone();
    let plan = ValidatedIdentityProofPlan::for_public_fixture(n, &input).unwrap();
    input.expected_identity = plan.identity().into();
    let coordinate = R1NetworkCoordinate {
        network: R1NetworkRef {
            chain_id: n.chain_id,
            nic: n.nic,
        },
        genesis: R1GenesisReference {
            profile: R1ProfileRef {
                name: "SYNERGY-GENESIS-R1".into(),
                revision: 1,
            },
            digest: decode("genesis_digest48_hex").try_into().unwrap(),
        },
        activated_profiles: R1ProfileSetReference {
            profile: R1ProfileRef {
                name: "APQE-PROFILE-SET".into(),
                revision: 1,
            },
            commitment: decode("profile_set_commitment_hex").try_into().unwrap(),
        },
    };
    let intent = InitialWalletIntent {
        coordinate,
        identity: input,
    };
    let messages=plan.messages().iter().map(|m|serde_json::json!({"index":m.index(),"key_generation":m.key().key_generation,"public_key_hex":m.key().full_public_key_hex,"exact_message_hex":hex::encode(m.frame()),"context":"SYNERGY.ACCOUNT.POP.R1","domain":"IDENTITY.ACCOUNT.POSSESSION","profile":"APQE-ACCOUNT-POSSESSION"})).collect::<Vec<_>>();
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_R1_INITIAL_WALLET_ENROLLMENT_ONLY","production_import_permitted":false,"chain_id":n.chain_id,"nic_hex":hex::encode(n.nic),"coordinate":{"network":{"chain_id":n.chain_id,"nic":n.nic.to_vec()},"genesis":{"profile":{"name":intent.coordinate.genesis.profile.name,"revision":intent.coordinate.genesis.profile.revision},"digest":intent.coordinate.genesis.digest.to_vec()},"activated_profiles":{"profile":{"name":intent.coordinate.activated_profiles.profile.name,"revision":intent.coordinate.activated_profiles.profile.revision},"commitment":intent.coordinate.activated_profiles.commitment.to_vec()}},"identity_input":intent.identity,"proof_plan_frame_hex":hex::encode(plan.canonical_frame()),"transaction_id":intent.identifier().unwrap().to_text(),"exact_intent_hex":hex::encode(intent.canonical_intent().unwrap()),"messages":messages})).unwrap());
}
