//! Shared canonical Genesis and runtime authority artifact contracts.
pub mod authority;
pub mod builder;
pub mod etdag;
pub mod network;
pub mod signing;
pub mod validator_set;
pub mod verify;
pub use synergy_etdag::{certificate_quorum, EtdagDigest};
pub use synergy_state::state_root;

/// Verify actual Genesis and initial authority against one pinned trust root.
/// This checks artifact agreement; it does not qualify runtime liveness.
pub fn verify_binding(
    signed: &signing::SignedGenesis,
    trust: &[u8],
    binding: &authority::SignedAuthorityBinding,
) -> Result<(), String> {
    let verifier = synergy_aegis::PqvmVerifier::new(synergy_aegis::AegisPolicy {
        allowed_algorithms: vec![synergy_aegis::SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 16 * 1024 * 1024,
        maximum_signature_bytes: 16 * 1024,
    })
    .map_err(|e| e.to_string())?;
    verify_binding_with_verifier(signed, trust, binding, &verifier)
}
pub fn verify_binding_with_verifier(
    signed: &signing::SignedGenesis,
    trust: &[u8],
    binding: &authority::SignedAuthorityBinding,
    verifier: &impl synergy_aegis::AegisVerifier,
) -> Result<(), String> {
    use synergy_aegis::{KeyId, Signature, SignatureAlgorithm, SigningContext};
    signing::verify(signed, verifier, trust)?;
    let payload = &binding.payload;
    payload.validate()?;
    let policy = payload
        .protected
        .as_ref()
        .ok_or("Genesis binding lacks protected policy")?;
    let genesis = &signed.unsigned;
    if genesis.network.protocol_version != synergy_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
        || binding.signer_key_id != genesis.authority_trust_key_id
        || payload.chain_id != genesis.network.chain_id
        || payload.network_id != genesis.network.network_id
        || payload.epoch != 1
        || payload.epoch_start_height != 1
        || genesis.network.activation_unix.checked_mul(1000)
            != Some(policy.epoch_start_timestamp_ms)
        || genesis.etdag.parameters != policy.parameters
        || genesis.etdag.cryptographic_profile_root != policy.cryptographic_profile_root
        || genesis.etdag.ingress_kem_registry_root
            != policy
                .ingress_kem_registry
                .root()
                .map_err(|e| format!("{e:?}"))?
        || genesis.initial_state_root
            != state_root(&policy.initial_world_state).map_err(|e| format!("{e:?}"))?
        || genesis.validators.len() != payload.validators.len()
        || !genesis
            .validators
            .iter()
            .zip(&payload.validators)
            .all(|(a, b)| {
                a.record == b.record && a.algorithm == b.algorithm && a.public_key == b.public_key
            })
    {
        return Err("signed Genesis and initial authority disagree".into());
    }
    match &payload.anchor_parent {
        synergy_posy::SimplifiedFinalityParent::Genesis {
            genesis_hash,
            block_id,
            reference_id,
        } if genesis_hash == &signed.genesis_hash
            && block_id == &signed.genesis_hash
            && reference_id
                == &synergy_posy::canonical_hash(
                    "SYNERGY_FRESH_GENESIS_REFERENCE_V1",
                    &(
                        payload.chain_id,
                        &payload.network_id,
                        payload.epoch,
                        &signed.genesis_hash,
                        &genesis.initial_state_root,
                    ),
                )
                .map_err(|e| e.to_string())? => {}
        _ => return Err("initial authority lacks exact signed Genesis anchor".into()),
    }
    verifier
        .verify(
            &SigningContext {
                domain: authority::AUTHORITY_SIGNING_DOMAIN.into(),
                chain_id: payload.chain_id,
                epoch: Some(payload.epoch),
                height: None,
            },
            &payload.signing_bytes()?,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa65,
                key_id: KeyId::new(binding.signer_key_id.clone()).map_err(|e| e.to_string())?,
                bytes: binding.signature.clone(),
            },
            trust,
        )
        .map_err(|e| e.to_string())
}
