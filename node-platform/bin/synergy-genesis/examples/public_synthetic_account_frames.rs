//! Fixed isolated public account PoP frame bridge. No provider, signing or RNG.
use serde::Deserialize;
use synergy_address_engine::{
    apqe::{
        native_identity_derivation_r1::{derive_candidate, BirthBody},
        r1_framing::NetworkRef,
    },
    types::Algorithm,
};
use synergy_genesis::r1::{
    account::AccountRecord,
    policy::{CompletePolicy, IndexedProof, KeyRecord, PolicyController, PolicyRule},
};
use synergy_protocol_types::c14n02::Encoder;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    purpose: String,
    production_import_permitted: bool,
    nic_hex: String,
    public_key_hex: String,
    #[serde(default)]
    signature_hex: Option<String>,
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|x| format!("{x:02x}")).collect()
}
fn bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2)
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("lowerhex required".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|x| {
            u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).map_err(|_| "hex error".into())
        })
        .collect()
}
fn main() -> Result<(), String> {
    use std::io::Read;
    let path = std::env::args()
        .nth(1)
        .ok_or("public fixture input required")?;
    let m = std::fs::symlink_metadata(&path).map_err(|_| "input unavailable")?;
    if !std::path::Path::new(&path).is_absolute()
        || !m.is_file()
        || m.file_type().is_symlink()
        || m.len() > 65536
    {
        return Err("bounded absolute public fixture required".into());
    }
    let mut data = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "input unavailable")?
        .take(65537)
        .read_to_end(&mut data)
        .map_err(|_| "read failed")?;
    if data.len() > 65536 {
        return Err("input bound".into());
    }
    let input: Input = serde_json::from_slice(&data).map_err(|_| "invalid input")?;
    if input.purpose != "PUBLIC_SYNTHETIC_ACCOUNT_FIXTURE_INPUT_ONLY"
        || input.production_import_permitted
    {
        return Err("public synthetic marker required".into());
    }
    let n = NetworkRef {
        chain_id: u64::MAX - 1,
        nic: bytes(&input.nic_hex)?.try_into().map_err(|_| "NIC width")?,
    };
    let policy = CompletePolicy {
        namespace: "syns".into(),
        controllers: vec![PolicyController {
            key: KeyRecord {
                role: "account_controller".into(),
                algorithm: Algorithm::MlDsa87,
                generation: 1,
                public_key: bytes(&input.public_key_hex)?,
            },
            declared_independence_domain: "PUBLIC-SYNTHETIC-ACCOUNT-ONLY".into(),
        }],
        ordinary: PolicyRule {
            threshold: 1,
            controller_indices: vec![0],
        },
        recovery: None,
    };
    let candidate = policy
        .with_apqe(|p| {
            derive_candidate(
                n,
                &BirthBody::Account {
                    nonce32: &[9; 32],
                    policy: p,
                },
                1024 * 1024,
            )
            .map_err(|_| synergy_genesis::r1::policy::PolicyError::Identity)
        })
        .map_err(|e| e.to_string())?;
    let proofs = input
        .signature_hex
        .map(|s| {
            bytes(&s).map(|signature| {
                vec![IndexedProof {
                    index: 0,
                    signature,
                }]
            })
        })
        .transpose()?
        .unwrap_or_default();
    let account = AccountRecord {
        identity: candidate.presentation.to_text(),
        birth_nonce: [9; 32],
        policy,
        policy_epoch: 1,
        transaction_nonce: 0,
        enrollment_nonce: [10; 32],
        possession_proofs: proofs,
    };
    let mut e = Encoder::new(1024 * 1024);
    account.encode_into(&mut e, n).map_err(|e| e.to_string())?;
    let out = serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_ACCOUNT_FRAMES_ONLY","production_import_permitted":false,"chain_id":u64::MAX-1,"nic_hex":input.nic_hex,"identity":account.identity,"account_record_c14n02_hex":hex(&e.finish().map_err(|_|"encoding")?),"possession_frame_hex":hex(&account.possession_frame(n,0).map_err(|e|e.to_string())?),"context":"SYNERGY.ACCOUNT.POP.R1","proofs_verified":false,"authority_granted":false});
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|_| "output")?
    );
    Ok(())
}
