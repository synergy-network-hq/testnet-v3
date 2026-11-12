use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeAad {
    pub profile_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub epoch: u64,
    pub target_height: u64,
    pub target_context_root: EtdagDigest,
    pub assigned_cluster_id: u64,
    pub lane_id: String,
    pub sender_id: String,
    pub nonce_slot: u64,
}

impl EnvelopeAad {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.target_context_root.validate()?;
        if !matches!(
            self.profile_id.as_str(),
            crate::ETDAG_PROFILE_ID | crate::ETDAG_EXPERIMENTAL_PROFILE_ID
        ) || self.chain_id == 0
            || self.network_id.trim().is_empty()
            || self.protocol_version.trim().is_empty()
            || self.epoch == 0
            || self.target_height < 3
            || self.lane_id != "ordinary-user"
            || self.sender_id.trim().is_empty()
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid protected envelope AAD".into(),
            ));
        }
        serde_json::to_vec(&(
            &self.profile_id,
            self.chain_id,
            &self.network_id,
            &self.protocol_version,
            self.epoch,
            self.target_height,
            &self.target_context_root,
            self.assigned_cluster_id,
            &self.lane_id,
            &self.sender_id,
            self.nonce_slot,
        ))
        .map_err(|e| EtdagError::Corrupt(format!("encode protected AAD: {e}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareCapsule {
    pub validator_id: String,
    pub ingress_kem_key_id: String,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
    pub kem_ciphertext: Vec<u8>,
    pub aead_nonce: [u8; 12],
    pub encrypted_share: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareCommitment {
    pub validator_id: String,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedTransactionEnvelope {
    pub envelope_version: u32,
    pub envelope_id: EtdagDigest,
    pub target_context_root: EtdagDigest,
    pub target_height: u64,
    pub aad: EnvelopeAad,
    pub aead_nonce: [u8; 12],
    pub key_commitment: EtdagDigest,
    pub share_commitment_root: EtdagDigest,
    pub share_capsule_root: EtdagDigest,
    pub ciphertext: Vec<u8>,
    pub content_blind_order_key: EtdagDigest,
    pub share_capsules: Vec<ShareCapsule>,
}

impl EncryptedTransactionEnvelope {
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
            EtdagDigest::from_canonical("PoSy/ETDAG/ShareCommitmentRoot/v3", &commitments)?,
            EtdagDigest::from_canonical("PoSy/ETDAG/ShareCapsuleRoot/v3", &self.share_capsules)?,
        ))
    }

    pub fn refresh_capsule_roots(&mut self) -> Result<(), EtdagError> {
        (self.share_commitment_root, self.share_capsule_root) = self.capsule_roots()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.aad.canonical_bytes()?;
        self.envelope_id.validate()?;
        self.target_context_root.validate()?;
        self.content_blind_order_key.validate()?;
        self.key_commitment.validate()?;
        self.share_commitment_root.validate()?;
        self.share_capsule_root.validate()?;
        let mut validators = BTreeSet::new();
        let mut indices = BTreeSet::new();
        if self.envelope_version != 2
            || self.target_height != self.aad.target_height
            || self.target_context_root != self.aad.target_context_root
            || self.ciphertext.len() < 16
            || self.share_capsules.len() > 255
            || self.share_capsules.is_empty()
            || self
                .share_capsules
                .windows(2)
                .any(|pair| pair[0].validator_id >= pair[1].validator_id)
            || self.share_capsules.iter().any(|capsule| {
                capsule.validator_id.trim().is_empty()
                    || capsule.ingress_kem_key_id.trim().is_empty()
                    || capsule.share_index == 0
                    || capsule.share_commitment.validate().is_err()
                    || !validators.insert(&capsule.validator_id)
                    || !indices.insert(capsule.share_index)
                    || capsule.kem_ciphertext.len() != super::ML_KEM_1024_CIPHERTEXT_BYTES
                    || capsule.encrypted_share.len() < 16
            })
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid encrypted transaction envelope".into(),
            ));
        }
        if self.capsule_roots()?
            != (
                self.share_commitment_root.clone(),
                self.share_capsule_root.clone(),
            )
        {
            return Err(EtdagError::InvalidEnvelope(
                "protected capsule roots differ".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod aad_profile_tests {
    use super::*;

    #[test]
    fn aad_accepts_only_supported_profiles_and_binds_their_bytes() {
        let mut aad = EnvelopeAad {
            profile_id: crate::ETDAG_PROFILE_ID.into(),
            chain_id: 1266,
            network_id: "isolated".into(),
            protocol_version: "v3".into(),
            epoch: 1,
            target_height: 6,
            target_context_root: EtdagDigest::from_domain_bytes("test", b"context"),
            assigned_cluster_id: 0,
            lane_id: "ordinary-user".into(),
            sender_id: "sender".into(),
            nonce_slot: 0,
        };
        let legacy = aad.canonical_bytes().unwrap();
        aad.profile_id = crate::ETDAG_EXPERIMENTAL_PROFILE_ID.into();
        let experimental = aad.canonical_bytes().unwrap();
        assert_ne!(legacy, experimental);
        aad.profile_id = "unknown".into();
        assert!(aad.canonical_bytes().is_err());
    }
}
