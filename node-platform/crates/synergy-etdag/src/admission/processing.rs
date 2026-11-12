//! Versioned processing authorization, separate from eventual block inclusion.
//!
//! These are cryptographic carriers and shape/binding checks, not registry-proof,
//! wallet-signature, admission, group-assignment, reveal or finality authority.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::crypto::{canonical_signing_bytes, ShareCapsule, ShareCommitment};
use crate::{EtdagDigest, EtdagError, TargetAdmissionContextV3};

pub const PROCESSING_PROFILE_ID: &str = "etdag-async-processing-v1";
const CONTEXT_DOMAIN: &str = "SYNERGY_ETDAG_PROCESSING_CONTEXT_V1";
const AAD_DOMAIN: &str = "SYNERGY_ETDAG_PROCESSING_AAD_V1";
const ENVELOPE_DOMAIN: &str = "SYNERGY_ETDAG_PROCESSING_ENVELOPE_V1";
const ADMISSION_DOMAIN: &str = "SYNERGY_ETDAG_PROCESSING_ADMISSION_V1";
const MAX_ID_BYTES: usize = 256;
const MAX_NETWORK_BYTES: usize = 128;
const MAX_KEY_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
// The shared canonical Shamir-share decoder accepts at most 1024 bytes;
// AES-GCM adds exactly one 16-byte tag.
const MAX_ENCRYPTED_SHARE_BYTES: usize = 1024 + 16;

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains(char::is_control)
}

fn invalid(message: &str) -> EtdagError {
    EtdagError::InvalidEnvelope(message.into())
}

/// Frozen finalized snapshot, schedule and key authority. The embedded legacy
/// `target_height` is an authorization/key-validity anchor only. It is never
/// an inclusion height, processing deadline or permission to retarget old bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingContext {
    pub context_version: u32,
    pub profile_id: String,
    pub authority: TargetAdmissionContextV3,
}

impl ProcessingContext {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.authority.validate()?;
        let authority_text = [
            &self.authority.source_finality_context_root,
            &self.authority.active_validator_set_root,
            &self.authority.validator_consensus_key_root,
            &self.authority.frozen_voting_weight_root,
            &self.authority.cluster_schedule_version,
            &self.authority.finalized_epoch_seed_root,
            &self.authority.assigned_height_schedule_root,
            &self.authority.cluster_map_root,
            &self.authority.assigned_cluster_membership_root,
            &self.authority.consensus_parameter_root,
            &self.authority.cryptographic_profile_root,
        ];
        if authority_text
            .iter()
            .any(|value| !valid_text(value, MAX_ID_BYTES))
            || self.authority.ingress_kem_registry_root.is_zero()
            || self.context_version != 1
            || self.profile_id != PROCESSING_PROFILE_ID
            || self.authority.epoch == 0
            || self.authority.assigned_cluster_validator_count > 255
            || !valid_text(&self.authority.network_id, MAX_NETWORK_BYTES)
            || !valid_text(&self.authority.protocol_version, MAX_ID_BYTES)
        {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(())
    }

    pub fn root(&self) -> Result<EtdagDigest, EtdagError> {
        self.validate()?;
        EtdagDigest::from_canonical(CONTEXT_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingEnvelopeAad {
    pub profile_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub processing_context_root: EtdagDigest,
    /// Immutable snapshot/key-validity anchor, not an inclusion deadline.
    pub authorization_height: u64,
    pub assigned_cluster_id: u64,
    pub lane_id: String,
    pub sender_id: String,
    pub nonce_slot: u64,
}

impl ProcessingEnvelopeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.processing_context_root.validate()?;
        if self.profile_id != PROCESSING_PROFILE_ID
            || self.chain_id == 0
            || self.epoch == 0
            || self.authorization_height < 3
            || self.processing_context_root.is_zero()
            || self.lane_id != "ordinary-user"
            || !valid_text(&self.network_id, MAX_NETWORK_BYTES)
            || !valid_text(&self.protocol_version, MAX_ID_BYTES)
            || !valid_text(&self.sender_id, MAX_ID_BYTES)
        {
            return Err(invalid("invalid processing envelope AAD"));
        }
        // Explicit domain and every field are authenticated; no inclusion slot
        // or protocol-assigned group is part of this wallet-owned transcript.
        serde_json::to_vec(&(AAD_DOMAIN, self))
            .map_err(|e| EtdagError::Corrupt(format!("encode processing AAD: {e}")))
    }

    pub fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        self.canonical_bytes()?;
        let authority = &context.authority;
        if self.processing_context_root != context.root()?
            || self.profile_id != context.profile_id
            || self.chain_id != authority.chain_id
            || self.network_id != authority.network_id
            || self.protocol_version != authority.protocol_version
            || self.epoch != authority.epoch
            || self.authorization_height != authority.target_height
            || self.assigned_cluster_id != authority.assigned_cluster_id
        {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingEnvelope {
    pub envelope_version: u32,
    pub envelope_id: EtdagDigest,
    pub aad: ProcessingEnvelopeAad,
    pub aead_nonce: [u8; 12],
    pub key_commitment: EtdagDigest,
    pub share_commitment_root: EtdagDigest,
    pub share_capsule_root: EtdagDigest,
    pub ciphertext: Vec<u8>,
    pub content_blind_order_key: EtdagDigest,
    pub share_capsules: Vec<ShareCapsule>,
}

#[derive(Serialize)]
struct EnvelopeCommitment<'a> {
    envelope_version: u32,
    aad: &'a ProcessingEnvelopeAad,
    aead_nonce: &'a [u8; 12],
    key_commitment: &'a EtdagDigest,
    share_commitment_root: &'a EtdagDigest,
    share_capsule_root: &'a EtdagDigest,
    ciphertext: &'a [u8],
    content_blind_order_key: &'a EtdagDigest,
    share_capsules: &'a [ShareCapsule],
}

impl ProcessingEnvelope {
    pub fn capsule_roots(&self) -> Result<(EtdagDigest, EtdagDigest), EtdagError> {
        let commitments = self
            .share_capsules
            .iter()
            .map(|capsule| ShareCommitment {
                validator_id: capsule.validator_id.clone(),
                share_index: capsule.share_index,
                share_commitment: capsule.share_commitment.clone(),
            })
            .collect::<Vec<_>>();
        Ok((
            EtdagDigest::from_canonical(
                "SYNERGY_ETDAG_PROCESSING_SHARE_COMMITMENTS_V1",
                &commitments,
            )?,
            EtdagDigest::from_canonical(
                "SYNERGY_ETDAG_PROCESSING_SHARE_CAPSULES_V1",
                &self.share_capsules,
            )?,
        ))
    }

    pub fn refresh_capsule_roots(&mut self) -> Result<(), EtdagError> {
        (self.share_commitment_root, self.share_capsule_root) = self.capsule_roots()?;
        Ok(())
    }

    /// Commit every envelope field except the identifier itself without cloning
    /// the ciphertext or constructing an intermediate JSON value tree.
    pub fn commitment(&self) -> Result<EtdagDigest, EtdagError> {
        EtdagDigest::from_canonical(
            ENVELOPE_DOMAIN,
            &EnvelopeCommitment {
                envelope_version: self.envelope_version,
                aad: &self.aad,
                aead_nonce: &self.aead_nonce,
                key_commitment: &self.key_commitment,
                share_commitment_root: &self.share_commitment_root,
                share_capsule_root: &self.share_capsule_root,
                ciphertext: &self.ciphertext,
                content_blind_order_key: &self.content_blind_order_key,
                share_capsules: &self.share_capsules,
            },
        )
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.aad.canonical_bytes()?;
        for digest in [
            &self.envelope_id,
            &self.key_commitment,
            &self.share_commitment_root,
            &self.share_capsule_root,
            &self.content_blind_order_key,
        ] {
            digest.validate()?;
            if digest.is_zero() {
                return Err(EtdagError::InvalidDigest);
            }
        }
        if self.envelope_version != 1
            || !crate::CIPHERTEXT_SIZE_CLASSES.contains(&self.ciphertext.len())
            || self.share_capsules.is_empty()
            || self.share_capsules.len() > 255
            || self
                .share_capsules
                .windows(2)
                .any(|pair| pair[0].validator_id >= pair[1].validator_id)
        {
            return Err(invalid("invalid processing envelope shape"));
        }
        let mut indices = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for capsule in &self.share_capsules {
            capsule.share_commitment.validate()?;
            if !valid_text(&capsule.validator_id, MAX_ID_BYTES)
                || !valid_text(&capsule.ingress_kem_key_id, MAX_ID_BYTES)
                || capsule.share_index == 0
                || capsule.share_commitment.is_zero()
                || !indices.insert(capsule.share_index)
                || !keys.insert(&capsule.ingress_kem_key_id)
                || capsule.kem_ciphertext.len() != crate::crypto::ML_KEM_1024_CIPHERTEXT_BYTES
                || !(17..=MAX_ENCRYPTED_SHARE_BYTES).contains(&capsule.encrypted_share.len())
            {
                return Err(invalid("invalid processing share capsule"));
            }
        }
        if self.capsule_roots()?
            != (
                self.share_commitment_root.clone(),
                self.share_capsule_root.clone(),
            )
            || self.commitment()? != self.envelope_id
        {
            return Err(invalid("processing envelope commitment differs"));
        }
        Ok(())
    }

    /// Registry membership/key proof verification is external: this context
    /// contains committed roots, not the registry or a member list.
    pub fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        self.validate()?;
        self.aad.validate_context(context)?;
        if self.share_capsules.len() as u64 != context.authority.assigned_cluster_validator_count {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingAdmissionRequest {
    pub request_version: u32,
    pub context_root: EtdagDigest,
    pub sender_wallet: String,
    pub sender_nonce: u64,
    pub gas_class_units: u64,
    pub fee_class: u32,
    pub signature_algorithm: String,
    pub signer_public_key: Vec<u8>,
    pub envelope: ProcessingEnvelope,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedProcessingAdmission<'a> {
    request_version: u32,
    context_root: &'a EtdagDigest,
    sender_wallet: &'a str,
    sender_nonce: u64,
    gas_class_units: u64,
    fee_class: u32,
    signature_algorithm: &'a str,
    signer_public_key: &'a [u8],
    envelope: &'a ProcessingEnvelope,
}

impl ProcessingAdmissionRequest {
    fn validate_unsigned(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.envelope.validate()?;
        if self.request_version != 1
            || self.gas_class_units == 0
            // Terminal current-nonce execution consumes the nonce. Never
            // authorize a value that cannot advance without wrapping.
            || self.sender_nonce == u64::MAX
            || self.context_root != self.envelope.aad.processing_context_root
            || self.sender_wallet != self.envelope.aad.sender_id
            || self.sender_nonce != self.envelope.aad.nonce_slot
            || !valid_text(&self.sender_wallet, MAX_ID_BYTES)
            || self.signature_algorithm != "ML-DSA-87"
            || self.signer_public_key.is_empty()
            || self.signer_public_key.len() > MAX_KEY_BYTES
        {
            return Err(invalid("invalid processing admission request"));
        }
        Ok(())
    }

    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.validate_unsigned()?;
        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE_BYTES {
            return Err(EtdagError::InvalidSignature);
        }
        Ok(())
    }

    pub fn envelope_commitment(&self) -> Result<EtdagDigest, EtdagError> {
        self.envelope.commitment()
    }

    pub fn validate_context(&self, context: &ProcessingContext) -> Result<(), EtdagError> {
        self.validate_shape()?;
        self.envelope.validate_context(context)
    }

    /// Signature verification and governed identity validity remain the caller's
    /// responsibility. Empty signature is allowed while producing its transcript.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.validate_unsigned()?;
        canonical_signing_bytes(
            ADMISSION_DOMAIN,
            &UnsignedProcessingAdmission {
                request_version: self.request_version,
                context_root: &self.context_root,
                sender_wallet: &self.sender_wallet,
                sender_nonce: self.sender_nonce,
                gas_class_units: self.gas_class_units,
                fee_class: self.fee_class,
                signature_algorithm: &self.signature_algorithm,
                signer_public_key: &self.signer_public_key,
                envelope: &self.envelope,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletProcessingAdmission {
    pub request: ProcessingAdmissionRequest,
    pub identity_authorization: synergy_identity::authorization::IdentityAuthorizationCarrier,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{verify_processing_admission_request, AdmissionSignatureVerifier};
    use aegis_pqvm::pqc::signatures::mldsa::mldsa87;
    use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
    use std::cell::Cell;

    // This deliberately small identity fixture pins one expected wallet/key.
    // It exercises the canonical verification trait with real ML-DSA, not the
    // production wallet's governed identity-carrier or registry proof path.
    struct BoundProcessingSigner<'a> {
        sender: &'a str,
        public_key: &'a [u8],
        calls: Cell<usize>,
    }

    impl AdmissionSignatureVerifier for BoundProcessingSigner<'_> {
        fn verify_wallet_signature(
            &self,
            sender_wallet: &str,
            signature_algorithm: &str,
            signer_public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), EtdagError> {
            self.calls.set(self.calls.get() + 1);
            if sender_wallet != self.sender
                || signer_public_key != self.public_key
                || signature_algorithm != "ML-DSA-87"
            {
                return Err(EtdagError::InvalidSignature);
            }
            let public = mldsa87::PublicKey::from_bytes(signer_public_key)
                .map_err(|_| EtdagError::InvalidSignature)?;
            let signature = mldsa87::DetachedSignature::from_bytes(signature)
                .map_err(|_| EtdagError::InvalidSignature)?;
            mldsa87::verify_detached_signature(&signature, message, &public)
                .map_err(|_| EtdagError::InvalidSignature)
        }
    }

    fn root(value: &str) -> EtdagDigest {
        EtdagDigest::from_domain_bytes("processing-test", value.as_bytes())
    }

    fn context() -> ProcessingContext {
        ProcessingContext {
            context_version: 1,
            profile_id: PROCESSING_PROFILE_ID.into(),
            authority: TargetAdmissionContextV3 {
                context_version: 1,
                chain_id: 1266,
                network_id: "isolated-processing-test".into(),
                protocol_version: "v3".into(),
                epoch: 1,
                target_height: 15,
                target_height_offset: 5,
                source_finalized_height: 10,
                source_finality_context_root: "finality".into(),
                active_validator_set_root: "validators".into(),
                validator_consensus_key_root: "keys".into(),
                frozen_voting_weight_root: "weights".into(),
                cluster_schedule_version: "1".into(),
                finalized_epoch_seed_root: "seed".into(),
                assigned_height_schedule_root: "schedule".into(),
                cluster_map_root: "clusters".into(),
                assigned_cluster_id: 7,
                assigned_cluster_membership_root: "members".into(),
                assigned_cluster_validator_count: 2,
                assigned_cluster_total_voting_weight: 2,
                consensus_parameter_root: "parameters".into(),
                cryptographic_profile_root: "cryptography".into(),
                ingress_kem_registry_root: root("registry"),
            },
        }
    }

    fn request() -> ProcessingAdmissionRequest {
        let context = context();
        let mut envelope = ProcessingEnvelope {
            envelope_version: 1,
            envelope_id: root("placeholder"),
            aad: ProcessingEnvelopeAad {
                profile_id: PROCESSING_PROFILE_ID.into(),
                chain_id: 1266,
                network_id: context.authority.network_id.clone(),
                protocol_version: "v3".into(),
                epoch: 1,
                processing_context_root: context.root().unwrap(),
                authorization_height: 15,
                assigned_cluster_id: 7,
                lane_id: "ordinary-user".into(),
                sender_id: "sender".into(),
                nonce_slot: 3,
            },
            aead_nonce: [9; 12],
            key_commitment: root("key"),
            share_commitment_root: root("placeholder"),
            share_capsule_root: root("placeholder"),
            ciphertext: vec![7; crate::CIPHERTEXT_SIZE_CLASSES[0]],
            content_blind_order_key: root("order"),
            share_capsules: (1..=2)
                .map(|index| ShareCapsule {
                    validator_id: format!("validator-{index}"),
                    ingress_kem_key_id: format!("kem-{index}"),
                    share_index: index,
                    share_commitment: root(&format!("share-{index}")),
                    kem_ciphertext: vec![4; crate::crypto::ML_KEM_1024_CIPHERTEXT_BYTES],
                    aead_nonce: [5; 12],
                    encrypted_share: vec![6; 128],
                })
                .collect(),
        };
        envelope.refresh_capsule_roots().unwrap();
        envelope.envelope_id = envelope.commitment().unwrap();
        ProcessingAdmissionRequest {
            request_version: 1,
            context_root: context.root().unwrap(),
            sender_wallet: "sender".into(),
            sender_nonce: 3,
            gas_class_units: 21_000,
            fee_class: 0,
            signature_algorithm: "ML-DSA-87".into(),
            signer_public_key: vec![8; 32],
            envelope,
            signature: vec![1; 32],
        }
    }

    #[test]
    fn processing_authorization_has_no_inclusion_or_assignment_field() {
        let request = request();
        request.validate_context(&context()).unwrap();
        let bytes = serde_json::to_vec(&request).unwrap();
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("target_height").is_none());
        assert!(json.get("group_id").is_none());
        assert!(json["envelope"].get("target_height").is_none());
        assert!(json["envelope"]["aad"].get("target_height").is_none());
        let restored: ProcessingAdmissionRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            restored.signing_bytes().unwrap(),
            request.signing_bytes().unwrap()
        );
        assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
        // Unknown height/group fields cannot silently enter signed carriers.
        for field in ["inclusion_height", "target_height", "group_id"] {
            let mut changed = json.clone();
            changed[field] = 999.into();
            assert!(serde_json::from_value::<ProcessingAdmissionRequest>(changed).is_err());
        }
    }

    #[test]
    fn frozen_authority_changes_require_fresh_context_not_retargeting() {
        let request = request();
        let original = context();
        assert_ne!(original.root().unwrap(), original.authority.root().unwrap());
        let mutations: [fn(&mut TargetAdmissionContextV3); 8] = [
            |a| a.network_id.push_str("-other"),
            |a| a.protocol_version.push_str("-other"),
            |a| a.epoch += 1,
            |a| a.assigned_cluster_id += 1,
            |a| a.assigned_cluster_membership_root.push_str("-other"),
            |a| a.ingress_kem_registry_root = root("other-registry"),
            |a| {
                a.source_finalized_height += 1;
                a.target_height += 1;
            },
            |a| a.assigned_cluster_validator_count += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.authority);
            assert!(request.validate_context(&changed).is_err());
        }
        let mut changed = original;
        changed.profile_id = crate::ETDAG_PROFILE_ID.into();
        assert!(changed.validate().is_err());
    }

    #[test]
    fn every_aad_field_is_authenticated_and_context_fields_are_checked() {
        let original = request();
        let bytes = original.envelope.aad.canonical_bytes().unwrap();
        let mutations: [fn(&mut ProcessingEnvelopeAad); 11] = [
            |a| a.profile_id = crate::ETDAG_PROFILE_ID.into(),
            |a| a.chain_id += 1,
            |a| a.network_id.push_str("-other"),
            |a| a.protocol_version.push_str("-other"),
            |a| a.epoch += 1,
            |a| a.processing_context_root = root("other"),
            |a| a.authorization_height += 1,
            |a| a.assigned_cluster_id += 1,
            |a| a.lane_id = "other".into(),
            |a| a.sender_id = "other".into(),
            |a| a.nonce_slot += 1,
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed.envelope.aad);
            if let Ok(changed_bytes) = changed.envelope.aad.canonical_bytes() {
                assert_ne!(changed_bytes, bytes);
            }
            changed.envelope.envelope_id = changed.envelope.commitment().unwrap();
            assert!(changed.validate_context(&context()).is_err());
        }
    }

    #[test]
    fn envelope_tampering_and_malformed_capsules_are_rejected() {
        let original = request();
        let mutations: [fn(&mut ProcessingEnvelope); 9] = [
            |e| e.ciphertext[0] ^= 1,
            |e| e.content_blind_order_key = root("other-order"),
            |e| e.share_capsules.reverse(),
            |e| {
                e.share_capsules[0].kem_ciphertext.pop();
            },
            |e| e.share_capsules[0].share_index = 0,
            |e| e.share_capsules[1].share_index = e.share_capsules[0].share_index,
            |e| {
                e.share_capsules[1].ingress_kem_key_id =
                    e.share_capsules[0].ingress_kem_key_id.clone()
            },
            |e| {
                e.share_capsules[0]
                    .encrypted_share
                    .resize(MAX_ENCRYPTED_SHARE_BYTES + 1, 0)
            },
            |e| {
                e.ciphertext.pop();
            },
        ];
        for mutate in mutations {
            let mut changed = original.envelope.clone();
            mutate(&mut changed);
            assert!(changed.validate().is_err());
        }
        // Even recomputed roots cannot turn duplicate indices into valid shape.
        let mut changed = original.envelope;
        changed.share_capsules[1].share_index = changed.share_capsules[0].share_index;
        changed.refresh_capsule_roots().unwrap();
        changed.envelope_id = changed.commitment().unwrap();
        assert!(changed.validate().is_err());
    }

    #[test]
    fn request_transcript_binds_policy_replay_and_key_but_excludes_signature() {
        let original = request();
        let signed = original.signing_bytes().unwrap();
        let mutations: [fn(&mut ProcessingAdmissionRequest); 4] = [
            |r| r.gas_class_units += 1,
            |r| r.fee_class += 1,
            |r| r.signer_public_key[0] ^= 1,
            |r| {
                r.sender_nonce += 1;
                r.envelope.aad.nonce_slot += 1;
                r.envelope.envelope_id = r.envelope.commitment().unwrap();
            },
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(changed.signing_bytes().unwrap(), signed);
        }
        let mut unsigned = original;
        unsigned.signature.clear();
        assert_eq!(unsigned.signing_bytes().unwrap(), signed);
        assert!(unsigned.validate_shape().is_err());
    }

    #[test]
    fn exhausted_nonce_cannot_enter_processing_authorization() {
        let mut exhausted = request();
        exhausted.sender_nonce = u64::MAX;
        exhausted.envelope.aad.nonce_slot = u64::MAX;
        exhausted.envelope.envelope_id = exhausted.envelope.commitment().unwrap();
        assert!(exhausted.signing_bytes().is_err());
        assert!(exhausted.validate_shape().is_err());
    }

    #[test]
    fn real_processing_signature_requires_original_bytes_context_and_bound_wallet_key() {
        let (public, secret) = mldsa87::keypair();
        let mut original = request();
        original.signer_public_key = public.as_bytes().to_vec();
        original.signature = mldsa87::detached_sign(&original.signing_bytes().unwrap(), &secret)
            .as_bytes()
            .to_vec();
        let verifier = BoundProcessingSigner {
            sender: "sender",
            public_key: public.as_bytes(),
            calls: Cell::new(0),
        };
        verify_processing_admission_request(&original, &context(), &verifier).unwrap();
        assert_eq!(verifier.calls.get(), 1);

        // Valid shape and unchanged wallet key cannot authenticate changed fees.
        let mut changed = original.clone();
        changed.fee_class += 1;
        changed.validate_context(&context()).unwrap();
        assert_eq!(
            verify_processing_admission_request(&changed, &context(), &verifier),
            Err(EtdagError::InvalidSignature)
        );

        // Recomputing a ciphertext commitment cannot preserve the outer signature.
        let mut changed = original.clone();
        changed.envelope.ciphertext[0] ^= 1;
        changed.envelope.envelope_id = changed.envelope.commitment().unwrap();
        changed.validate_context(&context()).unwrap();
        assert_eq!(
            verify_processing_admission_request(&changed, &context(), &verifier),
            Err(EtdagError::InvalidSignature)
        );

        // Context mismatch is rejected before the identity/crypto callback.
        let mut wrong_context = context();
        wrong_context.authority.network_id.push_str("-other");
        let before = verifier.calls.get();
        assert_eq!(
            verify_processing_admission_request(&original, &wrong_context, &verifier),
            Err(EtdagError::ContextMismatch)
        );
        assert_eq!(verifier.calls.get(), before);

        // A real, valid signature by another key still lacks this wallet binding.
        let (other_public, other_secret) = mldsa87::keypair();
        let mut changed = original.clone();
        changed.signer_public_key = other_public.as_bytes().to_vec();
        changed.signature =
            mldsa87::detached_sign(&changed.signing_bytes().unwrap(), &other_secret)
                .as_bytes()
                .to_vec();
        assert_eq!(
            verify_processing_admission_request(&changed, &context(), &verifier),
            Err(EtdagError::InvalidSignature)
        );

        // Possession of the pinned key does not authorize another sender label.
        let mut changed = original.clone();
        changed.sender_wallet = "other-sender".into();
        changed.envelope.aad.sender_id = changed.sender_wallet.clone();
        changed.envelope.envelope_id = changed.envelope.commitment().unwrap();
        changed.signature = mldsa87::detached_sign(&changed.signing_bytes().unwrap(), &secret)
            .as_bytes()
            .to_vec();
        assert_eq!(
            verify_processing_admission_request(&changed, &context(), &verifier),
            Err(EtdagError::InvalidSignature)
        );

        let mut changed = original;
        changed.signature[0] ^= 1;
        assert_eq!(
            verify_processing_admission_request(&changed, &context(), &verifier),
            Err(EtdagError::InvalidSignature)
        );
    }
}
