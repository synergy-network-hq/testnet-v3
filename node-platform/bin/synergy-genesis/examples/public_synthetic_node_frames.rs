//! Public fixture bridge for the actual APQE verifier. No provider, secret,
//! signing, keypair generation, RNG or output-file writes. Network is hardcoded
//! isolated u64MAX-1; this program cannot produce an actual9969 identity.
use serde::Deserialize;
use synergy_address_engine::{
    apqe::{
        native_identity_derivation_r1::{derive_candidate, BirthBody},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::policy::*;
use synergy_protocol_types::{c14n02::Encoder, NodeClass, NodeRole};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    purpose: String,
    production_import_permitted: bool,
    nic_hex: String,
    root_public_key_hex: String,
    consensus_public_key_hex: String,
    transport_public_key_hex: String,
    #[serde(default)]
    possession_signatures_hex: Option<Vec<String>>,
    #[serde(default)]
    ordinary_controller_signature_hex: Option<String>,
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("public fixture requires lowerhex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                .map_err(|_| "invalid public bytes".into())
        })
        .collect()
}
fn main() -> Result<(), String> {
    use std::io::Read;
    let path = std::env::args()
        .nth(1)
        .ok_or("expected bounded public fixture input")?;
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| "public input unavailable")?;
    if !std::path::Path::new(&path).is_absolute()
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 128 * 1024
    {
        return Err("public input must be bounded absolute regular file".into());
    }
    let mut input = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "public input unavailable")?
        .take(128 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "public input unavailable")?;
    if input.len() > 128 * 1024 {
        return Err("public input exceeds bound".into());
    }
    let input: Input =
        serde_json::from_slice(&input).map_err(|_| "invalid public fixture schema")?;
    if input.purpose != "PUBLIC_SYNTHETIC_NODE_FIXTURE_INPUT_ONLY"
        || input.production_import_permitted
    {
        return Err("public fixture marker required".into());
    }
    let network = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: bytes(&input.nic_hex)?
            .try_into()
            .map_err(|_| "NIC fixture width")?,
    };
    let root = KeyRecord {
        role: "node_birth_root".into(),
        algorithm: Algorithm::MlDsa87,
        generation: 1,
        public_key: bytes(&input.root_public_key_hex)?,
    };
    let policy = CompletePolicy {
        namespace: "synv1".into(),
        controllers: vec![PolicyController {
            key: root.clone(),
            declared_independence_domain: "PUBLIC-SYNTHETIC-NODE".into(),
        }],
        ordinary: PolicyRule {
            threshold: 1,
            controller_indices: vec![0],
        },
        recovery: None,
    };
    let mut node = NodeRecord {
        identity: String::new(),
        class: NodeClass::ConsensusAndChainIntegrity,
        primary_role: NodeRole::Validator,
        birth_nonce: [7; 32],
        birth_root: root,
        birth_policy: policy.clone(),
        current_policy: policy,
        policy_epoch: 1,
        enrollment_nonce: [8; 32],
        role_keys: vec![
            RoleKey {
                kind: RoleKeyKind::Consensus,
                key: KeyRecord {
                    role: RoleKeyKind::Consensus.label().into(),
                    algorithm: Algorithm::MlDsa65,
                    generation: 1,
                    public_key: bytes(&input.consensus_public_key_hex)?,
                },
            },
            RoleKey {
                kind: RoleKeyKind::TransportPrivate,
                key: KeyRecord {
                    role: RoleKeyKind::TransportPrivate.label().into(),
                    algorithm: Algorithm::MlDsa65,
                    generation: 1,
                    public_key: bytes(&input.transport_public_key_hex)?,
                },
            },
        ],
        possession_proofs: vec![],
        ordinary_controller_approvals: vec![],
    };
    node.identity = node
        .birth_policy
        .with_apqe(|policy| {
            derive_candidate(
                network,
                &BirthBody::Node {
                    namespace: "synv1",
                    node_class: 1,
                    nonce32: &node.birth_nonce,
                    birth_root: node.birth_root.as_apqe()?,
                    policy,
                },
                1024 * 1024,
            )
            .map(|r| r.presentation.to_text())
            .map_err(|_| PolicyError::Identity)
        })
        .map_err(|e| e.to_string())?;
    if let Some(signatures) = input.possession_signatures_hex {
        node.possession_proofs = signatures
            .iter()
            .enumerate()
            .map(|(index, signature)| {
                Ok(IndexedProof {
                    index: index as u32,
                    signature: bytes(signature)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
    }
    if let Some(signature) = input.ordinary_controller_signature_hex {
        node.ordinary_controller_approvals = vec![IndexedProof {
            index: 0,
            signature: bytes(&signature)?,
        }];
    }
    let mut e = Encoder::new(1024 * 1024);
    node.encode_into(&mut e, network)
        .map_err(|e| e.to_string())?;
    let public_keys = node.possession_keys().map_err(|e| e.to_string())?;
    let frames=public_keys.iter().enumerate().map(|(index,key)|Ok(serde_json::json!({"index":index,"algorithm":key.algorithm.display_name(),"public_key_hex":hex(&key.public_key),"frame_hex":hex(&node.possession_frame(network,index as u32).map_err(|e|e.to_string())?),"context":std::str::from_utf8(POP_CONTEXT).unwrap()}))).collect::<Result<Vec<_>,String>>()?;
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_NODE_FRAMES_ONLY","production_import_permitted":false,"chain_id":network.chain_id,"nic_hex":hex(&network.nic),"identity":node.identity,"policy_frame_hex":hex(&node.current_policy.frame(network).map_err(|e|e.to_string())?),"node_record_c14n02_hex":hex(&e.finish().map_err(|e|e.to_string())?),"proofs_verified":false,"authority_granted":false,"possession_frames":frames,"role_binding_frame_hex":hex(&node.role_binding_frame(network).map_err(|e|e.to_string())?),"role_binding_context":std::str::from_utf8(ROLE_BINDING_CONTEXT).unwrap()})).map_err(|_|"public output encode")?);
    Ok(())
}
