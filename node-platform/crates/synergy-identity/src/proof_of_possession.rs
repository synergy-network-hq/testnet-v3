use serde::{Deserialize, Serialize};
use synergy_aegis::{AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext};

use crate::{IdentityError, NodeAddress};

pub const POSSESSION_DOMAIN: &str = "SYNERGY-NODE-IDENTITY-POSSESSION-V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfPossession {
    #[serde(alias = "node_id")]
    pub node_address: NodeAddress,
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub challenge: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ProofOfPossession {
    pub fn verify(
        &self,
        chain_id: u64,
        verifier: &impl AegisVerifier,
    ) -> Result<(), IdentityError> {
        if self.algorithm != SignatureAlgorithm::MlDsa65
            || self.public_key.is_empty()
            || self.challenge.len() < 32
            || self.challenge.len() > 1024
            || self.signature.is_empty()
        {
            return Err(IdentityError::InvalidPossessionProof);
        }
        let key_id =
            KeyId::new(self.key_id.clone()).map_err(|_| IdentityError::InvalidPossessionProof)?;
        let mut message = self.node_address.as_str().as_bytes().to_vec();
        message.extend_from_slice(&(self.challenge.len() as u64).to_be_bytes());
        message.extend_from_slice(&self.challenge);
        verifier
            .verify(
                &SigningContext {
                    domain: POSSESSION_DOMAIN.into(),
                    chain_id,
                    epoch: None,
                    height: None,
                },
                &message,
                &Signature {
                    algorithm: self.algorithm,
                    key_id,
                    bytes: self.signature.clone(),
                },
                &self.public_key,
            )
            .map_err(|_| IdentityError::InvalidPossessionProof)
    }
}
