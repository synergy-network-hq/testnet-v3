use serde::{Deserialize, Serialize};
use synergy_aegis::{
    AegisSigner, AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext,
};

use crate::builder::UnsignedGenesis;

pub const GENESIS_SIGNING_DOMAIN: &str = "SYNERGY-CHAIN1266-GENESIS-SIGNING-V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGenesis {
    pub unsigned: UnsignedGenesis,
    pub genesis_hash: String,
    pub signer_key_id: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

pub fn sign(
    unsigned: UnsignedGenesis,
    signer: &impl AegisSigner,
    signer_key_id: KeyId,
) -> Result<SignedGenesis, String> {
    let genesis_hash = unsigned.genesis_hash()?;
    if signer_key_id.as_str() != unsigned.authority_trust_key_id {
        return Err("genesis signing key is not the governed authority trust key".into());
    }
    let bytes = unsigned.canonical_bytes()?;
    let signature = signer
        .sign(
            &signer_key_id,
            &SigningContext {
                domain: GENESIS_SIGNING_DOMAIN.into(),
                chain_id: unsigned.network.chain_id,
                epoch: Some(0),
                height: Some(0),
            },
            &bytes,
        )
        .map_err(|error| error.to_string())?;
    if signature.algorithm != SignatureAlgorithm::MlDsa65
        || signature.key_id != signer_key_id
        || signature.bytes.is_empty()
    {
        return Err("genesis signer returned unsupported material".into());
    }
    Ok(SignedGenesis {
        unsigned,
        genesis_hash,
        signer_key_id: signer_key_id.as_str().to_string(),
        signature_algorithm: signature.algorithm,
        signature: signature.bytes,
    })
}

pub fn verify(
    signed: &SignedGenesis,
    verifier: &impl AegisVerifier,
    trust_public_key: &[u8],
) -> Result<(), String> {
    signed.unsigned.validate()?;
    if signed.genesis_hash != signed.unsigned.genesis_hash()?
        || signed.signature_algorithm != SignatureAlgorithm::MlDsa65
        || signed.signer_key_id != signed.unsigned.authority_trust_key_id
        || trust_public_key.is_empty()
    {
        return Err("signed genesis commitment mismatch".into());
    }
    let key_id = KeyId::new(signed.signer_key_id.clone()).map_err(|error| error.to_string())?;
    verifier
        .verify(
            &SigningContext {
                domain: GENESIS_SIGNING_DOMAIN.into(),
                chain_id: signed.unsigned.network.chain_id,
                epoch: Some(0),
                height: Some(0),
            },
            &signed.unsigned.canonical_bytes()?,
            &Signature {
                algorithm: signed.signature_algorithm,
                key_id,
                bytes: signed.signature.clone(),
            },
            trust_public_key,
        )
        .map_err(|error| error.to_string())
}
