//! Versioned asynchronous carriers. Shape checks grant no release authority;
//! native validation binds these to PoSy-authenticated candidate state.
use crate::{CertifiedEnvelopeRef, EtdagDigest, EtdagError, WalletProcessingAdmission};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingVertex {
    pub vertex_version: u32,
    pub admission: WalletProcessingAdmission,
    pub envelope_ref: CertifiedEnvelopeRef,
    pub parents: Vec<EtdagDigest>,
    pub author_id: String,
    pub key_id: String,
    pub author_signature: Vec<u8>,
}
impl ProcessingVertex {
    pub fn authorization_root(&self) -> Result<EtdagDigest, EtdagError> {
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROCESSING_WALLET_AUTHORIZATION_V1",
            &self.admission,
        )
    }

    pub fn id(&self) -> Result<EtdagDigest, EtdagError> {
        self.admission.request.validate_shape()?;
        let request = &self.admission.request;
        if self.vertex_version != 1
            || self.parents.len() > 64
            || self.author_id.is_empty()
            || self.author_id.len() > 256
            || self.key_id.is_empty()
            || self.key_id.len() > 256
            || self.envelope_ref.protocol_dependencies.len() > 64
            || self.envelope_ref.sender_id.len() > 256
            || request.envelope.envelope_id != self.envelope_ref.tx_commitment
            || request.sender_wallet != self.envelope_ref.sender_id
            || request.sender_nonce != self.envelope_ref.nonce_slot
            || request.gas_class_units != self.envelope_ref.gas_class_units
            || request.fee_class != self.envelope_ref.fee_class
            || request.envelope.ciphertext.len() as u64 != self.envelope_ref.ciphertext_bytes
            || (self.envelope_ref.certified_dag_round == 0 && !self.parents.is_empty())
            || (self.envelope_ref.certified_dag_round != 0 && self.parents.is_empty())
            || crate::dag::canonical_parents(&self.parents, 64)? != self.parents
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        self.envelope_ref.validate()?;
        EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_PROCESSING_VERTEX_V1",
            &(
                self.vertex_version,
                &request.context_root,
                self.authorization_root()?,
                &self.envelope_ref,
                &self.parents,
                &self.author_id,
                &self.key_id,
            ),
        )
    }
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        crate::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_PROCESSING_VERTEX_SIGNATURE_V1",
            &self.id()?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingRevealPermission {
    pub namespace_root: EtdagDigest,
    pub group_number: u64,
    pub group_root: EtdagDigest,
    pub successor_root: EtdagDigest,
    pub processing_context_root: EtdagDigest,
    pub envelope_id: EtdagDigest,
    pub parent_block_id: String,
    /// Existing PoSy semantic validation ID, independent of ECHO signer subset.
    pub validation_id: String,
}
impl ProcessingRevealPermission {
    pub fn validate(&self) -> Result<(), EtdagError> {
        for root in [
            &self.namespace_root,
            &self.group_root,
            &self.successor_root,
            &self.processing_context_root,
            &self.envelope_id,
        ] {
            root.validate()?;
            if root.is_zero() {
                return Err(EtdagError::UnauthorizedReveal);
            }
        }
        if self.group_number == 0
            || self.parent_block_id.len() != 64
            || self.validation_id.len() != 64
            || !self.parent_block_id.bytes().all(|b| b.is_ascii_hexdigit())
            || !self.validation_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessingDecryptShare {
    pub share_version: u32,
    pub permission: ProcessingRevealPermission,
    pub validator_id: String,
    pub key_id: String,
    pub ingress_kem_key_id: String,
    pub share_index: u8,
    pub share_commitment: EtdagDigest,
    pub share_bytes: Vec<u8>,
    pub signature: Vec<u8>,
}
impl ProcessingDecryptShare {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        self.permission.validate()?;
        if self.share_version != 1
            || self.share_index == 0
            || self.share_bytes.len() > 1024
            || [&self.validator_id, &self.key_id, &self.ingress_kem_key_id]
                .iter()
                .any(|id| id.is_empty() || id.len() > 256 || id.contains(char::is_control))
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        crate::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_PROCESSING_DECRYPT_SHARE_V1",
            &(
                self.share_version,
                &self.permission,
                &self.validator_id,
                &self.key_id,
                &self.ingress_kem_key_id,
                self.share_index,
                &self.share_commitment,
                &self.share_bytes,
            ),
        )
    }
}
