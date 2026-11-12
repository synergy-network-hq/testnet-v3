use std::collections::BTreeSet;

use crate::{crypto::SignatureVerifier, DecryptShareMessage, EtdagError};

use super::{authorization::ProtectedRevealAuthorization, decrypt_share::VerifiedDecryptShare};

pub const DECRYPT_SHARE_DOMAIN: &str = "SYNERGY_ETDAG_REVEAL_SHARE_V2";

/// Verifies one reveal share without exposing plaintext or mutating collection
/// state.
///
/// The supplied verifier must resolve `validator_id` and `key_id` against the
/// governed consensus-key registry bound by the authorization context.
pub fn verify_decrypt_share(
    message: &DecryptShareMessage,
    expected_authorization: &ProtectedRevealAuthorization,
    allowed_validators: &BTreeSet<String>,
    envelope: &crate::EncryptedTransactionEnvelope,
    ingress_keys: &crate::IngressKemKeyRegistry,
    target_context: &crate::TargetAdmissionContextV3,
    verifier: &impl SignatureVerifier,
) -> Result<VerifiedDecryptShare, EtdagError> {
    expected_authorization.validate()?;
    message.validate()?;
    envelope.validate()?;
    ingress_keys.validate_protected_profile()?;

    if &message.authorization != expected_authorization
        || envelope.envelope_id != message.envelope_id
        || envelope.target_context_root != expected_authorization.context_root
        || envelope.target_height != expected_authorization.target_height
        || target_context.root()? != expected_authorization.context_root
        || ingress_keys.root()? != target_context.ingress_kem_registry_root
        || allowed_validators.len() as u64 != target_context.assigned_cluster_validator_count
        || envelope.share_capsules.len() != allowed_validators.len()
        || envelope
            .share_capsules
            .iter()
            .any(|capsule| !allowed_validators.contains(&capsule.validator_id))
    {
        return Err(EtdagError::UnauthorizedReveal);
    }

    let capsule = envelope
        .share_capsules
        .iter()
        .find(|capsule| capsule.validator_id == message.validator_id)
        .ok_or(EtdagError::UnauthorizedReveal)?;
    if capsule.ingress_kem_key_id != message.ingress_kem_key_id
        || capsule.share_index != message.share_index
        || capsule.share_commitment != message.share_commitment
        || !ingress_keys.records.iter().any(|key| {
            key.validator_id == message.validator_id
                && key.key_id == message.ingress_kem_key_id
                && key.public_key.algorithm == "ML-KEM-1024"
                && key.activation_height <= expected_authorization.target_height
                && key
                    .retirement_height
                    .is_none_or(|height| expected_authorization.target_height < height)
        })
    {
        return Err(EtdagError::UnauthorizedReveal);
    }
    if !allowed_validators.contains(&message.validator_id) {
        return Err(EtdagError::UnauthorizedValidator(
            message.validator_id.clone(),
        ));
    }

    let signing_bytes = message.signing_bytes()?;
    verifier.verify(
        &message.validator_id,
        &message.key_id,
        &signing_bytes,
        &message.signature,
    )?;

    Ok(VerifiedDecryptShare::new(message.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::{EnvelopeAad, ShamirShare},
        EncryptedTransactionEnvelope, EtdagDigest, IngressKemKeyRecord, IngressKemKeyRegistry,
        IngressKemPublicKey, ShareCapsule, TargetAdmissionContextV3,
    };

    struct ConsensusVerifier;
    impl SignatureVerifier for ConsensusVerifier {
        fn verify(
            &self,
            validator: &str,
            key: &str,
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), EtdagError> {
            if validator == "val2" && key == "consensus-val2" && message == signature {
                Ok(())
            } else {
                Err(EtdagError::UnauthorizedReveal)
            }
        }
    }

    #[test]
    fn reveal_requires_exact_governed_capsule_and_consensus_key_role() {
        let d = EtdagDigest::from_domain_bytes("fixture", b"root");
        let registry = IngressKemKeyRegistry {
            context_root: d.clone(),
            records: vec![IngressKemKeyRecord {
                key_id: "ingress-val2".into(),
                validator_id: "val2".into(),
                public_key: IngressKemPublicKey {
                    algorithm: "ML-KEM-1024".into(),
                    public_key: vec![1; 1568],
                },
                activation_height: 1,
                retirement_height: None,
            }],
        };
        let target = TargetAdmissionContextV3 {
            target_height_offset: 5,
            context_version: 1,
            chain_id: 1266,
            network_id: "testnet-v3".into(),
            protocol_version: "v3".into(),
            epoch: 1,
            target_height: 3,
            source_finalized_height: 0,
            source_finality_context_root: "root".into(),
            active_validator_set_root: "root".into(),
            validator_consensus_key_root: "root".into(),
            frozen_voting_weight_root: "root".into(),
            cluster_schedule_version: "v1".into(),
            finalized_epoch_seed_root: "root".into(),
            assigned_height_schedule_root: "root".into(),
            cluster_map_root: "root".into(),
            assigned_cluster_id: 1,
            assigned_cluster_membership_root: "root".into(),
            assigned_cluster_validator_count: 1,
            assigned_cluster_total_voting_weight: 1,
            consensus_parameter_root: "root".into(),
            cryptographic_profile_root: "root".into(),
            ingress_kem_registry_root: registry.root().unwrap(),
        };
        let context = target.root().unwrap();
        assert_ne!(context, registry.context_root);
        let share = ShamirShare {
            index: 1,
            value: vec![7; 32],
        };
        let commitment = share.commitment("val2", &context, 3).unwrap();
        let mut envelope = EncryptedTransactionEnvelope {
            envelope_version: 2,
            envelope_id: d.clone(),
            target_context_root: context.clone(),
            target_height: 3,
            aad: EnvelopeAad {
                profile_id: crate::ETDAG_PROFILE_ID.into(),
                chain_id: 1266,
                network_id: "testnet-v3".into(),
                protocol_version: "v3".into(),
                epoch: 1,
                target_height: 3,
                target_context_root: context.clone(),
                assigned_cluster_id: 1,
                lane_id: "ordinary-user".into(),
                sender_id: "sender".into(),
                nonce_slot: 0,
            },
            aead_nonce: [1; 12],
            key_commitment: d.clone(),
            share_commitment_root: d.clone(),
            share_capsule_root: d.clone(),
            ciphertext: vec![1; 32],
            content_blind_order_key: d.clone(),
            share_capsules: vec![ShareCapsule {
                validator_id: "val2".into(),
                ingress_kem_key_id: "ingress-val2".into(),
                share_index: 1,
                share_commitment: commitment.clone(),
                kem_ciphertext: vec![1; 1568],
                aead_nonce: [2; 12],
                encrypted_share: vec![1; 32],
            }],
        };
        envelope.refresh_capsule_roots().unwrap();
        let auth = ProtectedRevealAuthorization {
            authorization_version: 1,
            context_root: context,
            target_height: 3,
            protected_batch_root: d.clone(),
            finality_reference: d,
        };
        let mut message = DecryptShareMessage {
            share_version: 2,
            authorization: auth.clone(),
            envelope_id: envelope.envelope_id.clone(),
            validator_id: "val2".into(),
            key_id: "consensus-val2".into(),
            ingress_kem_key_id: "ingress-val2".into(),
            share_index: 1,
            share_commitment: commitment,
            encrypted_share: share.canonical_bytes().unwrap(),
            signature: vec![],
        };
        message.signature = message.signing_bytes().unwrap();
        let allowed = BTreeSet::from(["val2".into()]);
        let verify = |m: &DecryptShareMessage, r: &IngressKemKeyRegistry| {
            verify_decrypt_share(
                m,
                &auth,
                &allowed,
                &envelope,
                r,
                &target,
                &ConsensusVerifier,
            )
        };
        assert!(verify(&message, &registry).is_ok());
        let mut wrong = message.clone();
        wrong.key_id = wrong.ingress_kem_key_id.clone();
        wrong.signature = wrong.signing_bytes().unwrap();
        assert!(verify(&wrong, &registry).is_err());
        wrong = message.clone();
        wrong.ingress_kem_key_id = "substituted".into();
        wrong.signature = wrong.signing_bytes().unwrap();
        assert!(verify(&wrong, &registry).is_err());
        wrong = message.clone();
        let mut altered_share = share.clone();
        altered_share.value[0] ^= 1;
        wrong.encrypted_share = altered_share.canonical_bytes().unwrap();
        wrong.signature = wrong.signing_bytes().unwrap();
        assert!(verify(&wrong, &registry).is_err());
        wrong = message.clone();
        wrong.share_version = 1;
        wrong.signature = wrong.signing_bytes().unwrap();
        assert!(verify(&wrong, &registry).is_err());
        let mut wrong_registry = registry.clone();
        wrong_registry.context_root =
            EtdagDigest::from_domain_bytes("fixture", b"different governance");
        assert!(verify(&message, &wrong_registry).is_err());
    }
}
