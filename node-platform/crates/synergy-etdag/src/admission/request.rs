use serde::{Deserialize, Serialize};

use crate::crypto::canonical_signing_bytes;
use crate::domains::ADMISSION_REQUEST;
use crate::{EncryptedTransactionEnvelope, EtdagDigest, EtdagError};

pub const ADMISSION_REQUEST_VERSION: u16 = 1;
const MAX_NETWORK_ID_BYTES: usize = 128;
const MAX_WALLET_BYTES: usize = 256;
const MAX_ALGORITHM_BYTES: usize = 64;
const MAX_PUBLIC_KEY_BYTES: usize = 16 * 1024;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionRequest {
    pub request_version: u16,
    pub chain_id: u64,
    pub network_id: String,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub sender_wallet: String,
    pub sender_nonce: u64,
    pub signature_algorithm: String,
    pub signer_public_key: Vec<u8>,
    pub envelope: EncryptedTransactionEnvelope,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedAdmissionRequest<'a> {
    request_version: u16,
    chain_id: u64,
    network_id: &'a str,
    context_root: &'a EtdagDigest,
    target_height: u64,
    sender_wallet: &'a str,
    sender_nonce: u64,
    signature_algorithm: &'a str,
    signer_public_key: &'a [u8],
    envelope: &'a EncryptedTransactionEnvelope,
}

impl AdmissionRequest {
    pub fn validate_shape(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.envelope.validate()?;
        if self.request_version != ADMISSION_REQUEST_VERSION
            || self.chain_id == 0
            || self.network_id.trim().is_empty()
            || self.network_id.len() > MAX_NETWORK_ID_BYTES
            || self.network_id.contains(char::is_control)
            || self.target_height == 0
            || self.target_height != self.envelope.target_height
            || self.context_root != self.envelope.target_context_root
            || self.sender_wallet.trim().is_empty()
            || self.sender_wallet.len() > MAX_WALLET_BYTES
            || self.sender_wallet.contains(char::is_control)
            || self.signature_algorithm.trim().is_empty()
            || self.signature_algorithm.len() > MAX_ALGORITHM_BYTES
            || self.signature_algorithm.contains(char::is_control)
            || self.signer_public_key.is_empty()
            || self.signer_public_key.len() > MAX_PUBLIC_KEY_BYTES
            || self.signature.is_empty()
            || self.signature.len() > MAX_SIGNATURE_BYTES
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid ETDAG admission request".into(),
            ));
        }
        Ok(())
    }

    /// Canonical outer signature transcript. The encrypted envelope binds the
    /// protected transaction and all destination/amount/native-action bytes;
    /// execution verifies the inner transaction signature after reveal.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, EtdagError> {
        canonical_signing_bytes(
            ADMISSION_REQUEST,
            &UnsignedAdmissionRequest {
                request_version: self.request_version,
                chain_id: self.chain_id,
                network_id: &self.network_id,
                context_root: &self.context_root,
                target_height: self.target_height,
                sender_wallet: &self.sender_wallet,
                sender_nonce: self.sender_nonce,
                signature_algorithm: &self.signature_algorithm,
                signer_public_key: &self.signer_public_key,
                envelope: &self.envelope,
            },
        )
    }
}
