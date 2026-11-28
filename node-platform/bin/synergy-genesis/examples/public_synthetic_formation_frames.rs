//! Existing public synthetic key fixture bridge, no signer/RNG/writes.
//! All canonical framing and verification belongs to the actual Core/APQE APIs.
#[path = "../tests/common/mod.rs"]
mod common;
use serde::Deserialize;
use synergy_address_engine::{
    apqe::{
        bootstrap_approvals_r1::{
            ApprovalPurpose, IndexedRootApproval, PinnedBootstrapAuthority, PinnedBootstrapInput,
        },
        network_birth_r1::{BootstrapKeyRecord, NetworkBirth, ProfileRef},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::{
    formation::{
        FormationRegistration, FormationRegistrySnapshot, Population, INPUT_PROFILE,
        REGISTRY_PROFILE,
    },
    policy::{IndexedProof, KeyRecord, NodeRecord},
};
use synergy_protocol_types::c14n02::Decoder;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    node_record_c14n02_hex: String,
    formation_public_key_hex: String,
    #[serde(default)]
    key_possession_signature_hex: Option<String>,
    #[serde(default)]
    controller_signature_hex: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approval {
    root_index: u32,
    signature_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    purpose: String,
    production_import_permitted: bool,
    stage: String,
    registrations: Vec<Registration>,
    #[serde(default)]
    formation_approvals: Vec<Approval>,
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if s.len() > 2 * 1024 * 1024
        || !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("bounded lowercase public hex required".into());
    }
    Ok(s.as_bytes()
        .chunks_exact(2)
        .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16))
        .collect::<Result<Vec<_>, _>>()?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Read;
    let path = std::env::args()
        .nth(1)
        .ok_or("public fixture path required")?;
    let metadata = std::fs::symlink_metadata(&path)?;
    if !std::path::Path::new(&path).is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 1024 * 1024
    {
        return Err("bounded absolute public fixture required".into());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("public fixture exceeds bound".into());
    }
    let input: Input = serde_json::from_slice(&bytes)?;
    if input.purpose != "PUBLIC_SYNTHETIC_FORMATION_FIXTURE_INPUT_ONLY"
        || input.production_import_permitted
        || input.registrations.len() != 5
        || !matches!(
            input.stage.as_str(),
            "registration_frames" | "registry_frames" | "verify_registry"
        )
    {
        return Err("exact isolated public five-participant fixture required".into());
    }
    let public:serde_json::Value=serde_json::from_str(include_str!("../../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_compiled_genesis_public.json"))?;
    if public["purpose"] != "PUBLIC_SYNTHETIC_COMPILED_GENESIS_FIXTURE_ONLY"
        || public["production_import_permitted"] != false
        || public["chain_id"] != u64::MAX - 1
    {
        return Err("isolated source public fixture required".into());
    }
    let catalog = common::catalog();
    if catalog.canonical_frame()?
        != decode(
            public["profile_catalog_frame_hex"]
                .as_str()
                .ok_or("public catalog")?,
        )?
    {
        return Err("public fixture must match current exact catalog".into());
    }
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: decode(public["nic_hex"].as_str().ok_or("public NIC")?)?
            .try_into()
            .map_err(|_| "NIC width")?,
    };
    let mut registrations = Vec::new();
    let mut messages = Vec::new();
    for (index, r) in input.registrations.iter().enumerate() {
        let bytes = decode(&r.node_record_c14n02_hex)?;
        let mut d = Decoder::new(&bytes, 1024 * 1024)?;
        let node = NodeRecord::decode_from(&mut d, n).map_err(|e| e.to_string())?;
        d.finish()?;
        let registration = FormationRegistration {
            node,
            formation_key: KeyRecord {
                role: "formation_authentication".into(),
                algorithm: Algorithm::MlDsa87,
                generation: 1,
                public_key: decode(&r.formation_public_key_hex)?,
            },
            registration_nonce: [20 + index as u8; 32],
            key_possession: r
                .key_possession_signature_hex
                .as_deref()
                .map(decode)
                .transpose()?
                .unwrap_or_default(),
            controller_approvals: r
                .controller_signature_hex
                .as_deref()
                .map(decode)
                .transpose()?
                .map(|signature| {
                    vec![IndexedProof {
                        index: 0,
                        signature,
                    }]
                })
                .unwrap_or_default(),
        };
        messages.push(serde_json::json!({"input_index":index,"identity":registration.node.identity,"formation_public_key_hex":hex(&registration.formation_key.public_key),"key_possession_frame_hex":hex(&registration.message(n,false)?),"key_possession_context":"SYNERGY.FORMATION.POP.R1","controller_frame_hex":hex(&registration.message(n,true)?),"controller_context":"SYNERGY.FORMATION.AUTH.R1","controller_public_key_hex":hex(&registration.node.current_policy.controllers[0].key.public_key)}));
        registrations.push(registration);
    }
    let mut output = serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_FORMATION_FRAMES_ONLY","production_import_permitted":false,"chain_id":u64::MAX-1,"nic_hex":hex(&n.nic),"registrations":messages,"registration_proofs_verified":false,"root_approvals_verified":false,"formation_randomness_verified":false,"runtime_authority_granted":false});
    if input.stage != "registration_frames" {
        let commitment = catalog.commitment()?;
        let keys = public["roots"]
            .as_array()
            .ok_or("public roots")?
            .iter()
            .map(|r| decode(r["public_key_hex"].as_str().ok_or("public key")?))
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let roots = public["roots"]
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
        .map_err(|e| format!("public pinned authority: {e:?}"))?;
        if authority.network() != n {
            return Err("public birth mismatch".into());
        }
        let sigs = public["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["purpose"] == "nic")
            .map(|a| decode(a["signature_hex"].as_str().unwrap()))
            .collect::<Result<Vec<_>, _>>()?;
        let approvals = sigs
            .iter()
            .enumerate()
            .map(|(i, s)| IndexedRootApproval {
                root_index: i as u32,
                signature: s,
            })
            .collect::<Vec<_>>();
        let engine = common::engine();
        let nic = authority
            .verify_approvals(&engine, ApprovalPurpose::Nic, &approvals)
            .map_err(|e| format!("public NIC approvals: {e:?}"))?;
        registrations.sort_by_key(|r|*synergy_address_engine::apqe::native_identity_presentation_r1::NativeIdentityPresentation::parse(&r.node.identity).unwrap().raw48());
        let registry = FormationRegistrySnapshot::build(
            &nic,
            &birth,
            &catalog,
            Population::ConditionalFive,
            registrations,
            &engine,
        )?;
        let preseed = registry.preseed_frame()?;
        let input_commitment = registry.preseed_commitment()?;
        let purpose = ApprovalPurpose::Formation {
            registry_profile: ProfileRef {
                name: REGISTRY_PROFILE,
                revision: 1,
            },
            registry_commitment: registry.commitment(),
            input_profile: ProfileRef {
                name: INPUT_PROFILE,
                revision: 1,
            },
            input_commitment: &input_commitment,
        };
        let root_frames=(0..2).map(|i|Ok(serde_json::json!({"root_index":i,"frame_hex":hex(&authority.approval_frame(i,purpose).map_err(|e|format!("public formation frame: {e:?}"))?),"context":"SYNERGY/APQE/FORMATION-APPROVAL/1"}))).collect::<Result<Vec<_>,Box<dyn std::error::Error>>>()?;
        output["registration_proofs_verified"] = true.into();
        output["registry_frame_hex"] = hex(registry.canonical_bytes()).into();
        output["registry_commitment_hex"] = hex(registry.commitment()).into();
        output["preseed_frame_hex"] = hex(&preseed).into();
        output["input_commitment_hex"] = hex(&input_commitment).into();
        output["formation_approval_frames"] = root_frames.into();
        if input.stage == "verify_registry" {
            let sigs = input
                .formation_approvals
                .iter()
                .map(|a| decode(&a.signature_hex))
                .collect::<Result<Vec<_>, _>>()?;
            let approvals = input
                .formation_approvals
                .iter()
                .zip(&sigs)
                .map(|(a, s)| IndexedRootApproval {
                    root_index: a.root_index,
                    signature: s,
                })
                .collect::<Vec<_>>();
            let verified = registry.authenticate(&authority, &approvals, &engine)?;
            output["root_approvals_verified"] = true.into();
            output["authenticated_participant_count"] =
                verified.registry().registrations().len().into();
        }
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
