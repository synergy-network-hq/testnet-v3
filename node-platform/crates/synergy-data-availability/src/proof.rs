use serde::{Deserialize, Serialize};
use synergy_crypto::{AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityProof {
    pub chain_id: u64,
    pub network_id: String,
    pub object_root: String,
    pub shard_root: String,
    pub shard_index: u32,
    pub custodian_id: String,
    pub key_id: String,
    pub expires_at_height: u64,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

pub trait ProofVerifier: AegisVerifier {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String>;
}

impl AvailabilityProof {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id != 1266
            || self.network_id.trim().is_empty()
            || self.object_root.trim().is_empty()
            || self.shard_root.trim().is_empty()
            || self.custodian_id.trim().is_empty()
            || self.key_id.trim().is_empty()
            || self.expires_at_height == 0
            || self.signature.is_empty()
            || self.signature.len() > 65_536
        {
            return Err("invalid availability proof".into());
        }
        Ok(())
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            chain_id: u64,
            network_id: &'a str,
            object_root: &'a str,
            shard_root: &'a str,
            shard_index: u32,
            custodian_id: &'a str,
            key_id: &'a str,
            expires_at_height: u64,
            signature_algorithm: SignatureAlgorithm,
        }
        serde_json::to_vec(&Unsigned {
            chain_id: self.chain_id,
            network_id: &self.network_id,
            object_root: &self.object_root,
            shard_root: &self.shard_root,
            shard_index: self.shard_index,
            custodian_id: &self.custodian_id,
            key_id: &self.key_id,
            expires_at_height: self.expires_at_height,
            signature_algorithm: self.signature_algorithm,
        })
        .map_err(|error| format!("serialize availability proof: {error}"))
    }
}

pub fn verify_availability_proof(
    verifier: &impl ProofVerifier,
    proof: &AvailabilityProof,
    current_height: u64,
) -> Result<(), String> {
    proof.validate()?;
    if proof.expires_at_height < current_height {
        return Err("availability proof is expired".into());
    }
    let key_id = KeyId::new(proof.key_id.clone()).map_err(|error| error.to_string())?;
    let public_key = verifier.governed_public_key(&key_id)?;
    verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-DATA-AVAILABILITY-PROOF-V1".into(),
                chain_id: proof.chain_id,
                epoch: None,
                height: Some(proof.expires_at_height),
            },
            &proof.signing_bytes()?,
            &Signature {
                algorithm: proof.signature_algorithm,
                key_id,
                bytes: proof.signature.clone(),
            },
            &public_key,
        )
        .map_err(|error| format!("Aegis availability proof verification failed: {error}"))
}
