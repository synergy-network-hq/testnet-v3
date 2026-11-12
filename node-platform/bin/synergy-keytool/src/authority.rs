//! Signs the same typed authority transcript consumed by the universal node.
use crate::aegis_keys::{read_bounded, write_public_json, MAX_KEY_BYTES, MAX_METADATA_BYTES};
use std::fs;
use std::path::Path;
use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext,
};
use synergy_genesis::authority::{
    AuthorityPayload, SignedAuthorityBinding, AUTHORITY_SIGNING_DOMAIN,
};

fn policy() -> AegisPolicy {
    AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_METADATA_BYTES as usize,
        maximum_signature_bytes: 16 * 1024,
    }
}

fn context(payload: &AuthorityPayload) -> SigningContext {
    SigningContext {
        domain: AUTHORITY_SIGNING_DOMAIN.into(),
        chain_id: payload.chain_id,
        epoch: Some(payload.epoch),
        height: None,
    }
}

#[cfg(test)]
fn check(
    binding: &SignedAuthorityBinding,
    key_id: &KeyId,
    trust: &[u8],
    engine: &crate::provider::Engine,
) -> Result<(), String> {
    check_with_provider(binding, key_id, trust, Some(engine.clone()))
}

fn check_with_provider(
    binding: &SignedAuthorityBinding,
    key_id: &KeyId,
    trust: &[u8],
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    if binding.signer_key_id != key_id.as_str() {
        return Err("authority signer differs from explicit pinned key ID".into());
    }
    binding.payload.validate()?;
    crate::provider::verifier(policy(), engine)
        .map_err(|e| e.to_string())?
        .verify(
            &context(&binding.payload),
            &binding.payload.signing_bytes()?,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa65,
                key_id: key_id.clone(),
                bytes: binding.signature.clone(),
            },
            trust,
        )
        .map_err(|e| format!("authority signature verification refused: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub fn sign_with_provider(
    input: &Path,
    key_id: KeyId,
    secret: &Path,
    trust: &Path,
    output: &Path,
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let payload: AuthorityPayload = serde_json::from_slice(&read_bounded(
        input,
        MAX_METADATA_BYTES,
        "unsigned authority",
    )?)
    .map_err(|e| format!("decode typed authority: {e}"))?;
    payload.validate()?;
    if payload.protected.is_none() {
        return Err("fresh authority requires complete protected policy".into());
    }
    let metadata = fs::symlink_metadata(secret)
        .map_err(|e| format!("inspect authority signing secret: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("authority signing secret must be accessible only to its owner".into());
        }
    }
    let public_key = read_bounded(trust, MAX_KEY_BYTES, "pinned authority public key")?;
    let signer = crate::provider::signer(
        policy(),
        key_id.clone(),
        &public_key,
        read_bounded(secret, MAX_KEY_BYTES, "authority signing secret")?,
        engine.clone(),
    )
    .map_err(|e| e.to_string())?;
    let signature = signer
        .sign(&key_id, &context(&payload), &payload.signing_bytes()?)
        .map_err(|e| e.to_string())?;
    let binding = SignedAuthorityBinding {
        payload,
        signer_key_id: key_id.as_str().into(),
        signature: signature.bytes,
    };
    check_with_provider(&binding, &key_id, &public_key, engine)?;
    write_public_json(output, &binding)
}

pub fn verify(
    input: &Path,
    chain_id: u64,
    network_id: &str,
    key_id: KeyId,
    trust: &Path,
) -> Result<(), String> {
    verify_with_provider(input, chain_id, network_id, key_id, trust, None)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_with_provider(
    input: &Path,
    chain_id: u64,
    network_id: &str,
    key_id: KeyId,
    trust: &Path,
    engine: Option<crate::provider::Engine>,
) -> Result<(), String> {
    let binding: SignedAuthorityBinding = serde_json::from_slice(&read_bounded(
        input,
        MAX_METADATA_BYTES,
        "signed authority",
    )?)
    .map_err(|e| format!("decode typed signed authority: {e}"))?;
    if binding.payload.chain_id != chain_id
        || binding.payload.network_id != network_id
        || binding.payload.protected.is_none()
    {
        return Err("authority differs from expected fresh chain/network policy".into());
    }
    check_with_provider(
        &binding,
        &key_id,
        &read_bounded(trust, MAX_KEY_BYTES, "pinned authority public key")?,
        engine,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_address_engine::types::Algorithm;
    use synergy_genesis::authority::AuthorityValidator;

    #[test]
    fn typed_authority_signature_binds_domain_payload_and_pinned_key() {
        let engine = crate::provider::native_test_engine();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let public = pair.public_key;
        let key_id = KeyId::new("authority-root").unwrap();
        let validator = serde_json::from_value::<AuthorityValidator>(serde_json::json!({
            "record": {"validator_id": "validator", "consensus_key_id": "consensus", "frozen_voting_weight": 1,
                "status": "active"}, "algorithm": "ml_dsa65", "public_key": public.as_slice()
        })).unwrap();
        let payload = AuthorityPayload {
            version: 1,
            chain_id: 1266,
            network_id: "fresh".into(),
            epoch: 1,
            epoch_start_height: 1,
            epoch_end_height: 1000,
            finalized_epoch_seed_root: "a".repeat(64),
            consensus_parameter_root: "b".repeat(64),
            validators: (0..5)
                .map(|index| {
                    let mut record = validator.clone();
                    record.record.validator_id = format!("validator-{index}");
                    record.record.consensus_key_id = format!("consensus-{index}");
                    record
                })
                .collect(),
            anchor_parent: synergy_posy_parent(),
            protected: None,
        };
        let signer = crate::provider::signer(
            policy(),
            key_id.clone(),
            &public,
            pair.private_key.as_bytes().to_vec(),
            Some(engine.clone()),
        )
        .unwrap();
        let signature = signer
            .sign(
                &key_id,
                &context(&payload),
                &payload.signing_bytes().unwrap(),
            )
            .unwrap();
        let binding = SignedAuthorityBinding {
            payload,
            signer_key_id: key_id.as_str().into(),
            signature: signature.bytes,
        };
        check(&binding, &key_id, public.as_slice(), &engine)
            .expect("valid five-validator authority fixture");
        let wrong = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap()
            .public_key;
        assert!(check(&binding, &key_id, wrong.as_slice(), &engine).is_err());
        assert!(check(
            &binding,
            &KeyId::new("another-authority").unwrap(),
            public.as_slice(),
            &engine
        )
        .is_err());
        let mut other_chain = binding.clone();
        other_chain.payload.chain_id = 1267;
        assert!(check(&other_chain, &key_id, public.as_slice(), &engine).is_err());
        let mut changed = binding.clone();
        changed.payload.network_id.push('x');
        assert!(check(&changed, &key_id, public.as_slice(), &engine).is_err());
        let mut wrong_domain = binding;
        wrong_domain.signature = signer
            .sign(
                &key_id,
                &context(&wrong_domain.payload),
                &serde_json::to_vec(&wrong_domain.payload).unwrap(),
            )
            .unwrap()
            .bytes;
        assert!(check(&wrong_domain, &key_id, public.as_slice(), &engine).is_err());
    }

    fn synergy_posy_parent() -> synergy_genesis::authority::AuthorityParent {
        synergy_genesis::authority::AuthorityParent::Genesis {
            genesis_hash: "c".repeat(64),
            block_id: "d".repeat(64),
            reference_id: "e".repeat(64),
        }
    }
}
