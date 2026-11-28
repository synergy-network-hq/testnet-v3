//! Public-only existing compiled Genesis fixture -> actual owning intent codec.
use synergy_address::r1_public::NativeIdentityPresentation;
use synergy_protocol_types::{
    R1GenesisReference, R1NetworkCoordinate, R1NetworkRef, R1ProfileRef, R1ProfileSetReference,
};
use synergy_transaction::r1::{R1Action, R1TransactionIntent};
fn bytes<const N: usize>(v: &serde_json::Value) -> Result<[u8; N], Box<dyn std::error::Error>> {
    Ok(hex::decode(v.as_str().ok_or("missing public hex")?)?
        .try_into()
        .map_err(|_| "public width")?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../21-Aegis-Engine/synergy-address-engine/tests/fixtures/r1_compiled_genesis_public.json");
    let d: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if d["production_import_permitted"] != false || d["chain_id"].as_u64() != Some(u64::MAX - 1) {
        return Err("public-only fixture required".into());
    }
    let sender =
        NativeIdentityPresentation::parse(d["account_identity"].as_str().ok_or("public account")?)?;
    let tx = R1TransactionIntent {
        coordinate: R1NetworkCoordinate {
            network: R1NetworkRef {
                chain_id: u64::MAX - 1,
                nic: bytes(&d["nic_hex"])?,
            },
            genesis: R1GenesisReference {
                profile: R1ProfileRef {
                    name: "SYNERGY-GENESIS-R1".into(),
                    revision: 1,
                },
                digest: bytes(&d["genesis_digest48_hex"])?,
            },
            activated_profiles: R1ProfileSetReference {
                profile: R1ProfileRef {
                    name: "APQE-PROFILE-SET".into(),
                    revision: 1,
                },
                commitment: bytes(&d["profile_set_commitment_hex"])?,
            },
        },
        sender: sender.clone(),
        policy_epoch: 1,
        nonce: 0,
        valid_from_height: 1,
        valid_until_height: 1000,
        gas_limit: 1,
        max_fee_per_gas_nwei: 1,
        action: R1Action::Transfer {
            recipient: sender,
            amount_nwei: 1,
        },
    };
    let controllers = d["account_controllers"]
        .as_array()
        .ok_or("public policy handoff missing")?;
    let out = serde_json::json!({"purpose":"PUBLIC_SYNTHETIC_R1_TRANSACTION_FRAMES_ONLY","production_import_permitted":false,"chain_id":u64::MAX-1,"nic_hex":d["nic_hex"],"policy_frame_hex":d["account_policy_frame_hex"],"policy_commitment_hex":d["account_policy_commitment_hex"],"exact_message_hex":hex::encode(tx.signing_frame()?),"transaction_id":tx.identifier()?.to_text(),"sender":tx.sender.to_text(),"controller_public_keys_hex":controllers.iter().map(|c|c["public_key_hex"].clone()).collect::<Vec<_>>(),"controller_key_generations":controllers.iter().map(|c|c["key_generation"].clone()).collect::<Vec<_>>(),"pure_context":"QACE/TRANSACTION/R1","authority_granted":false});
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
