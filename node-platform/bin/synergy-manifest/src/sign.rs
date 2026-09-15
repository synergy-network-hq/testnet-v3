use serde::{Deserialize, Serialize};
use synergy_aegis::{
    AegisSigner, AegisVerifier, KeyId, Signature, SignatureAlgorithm, SigningContext,
};

use crate::build::UnsignedManifest;

pub const MANIFEST_SIGNING_DOMAIN: &str = "SYNERGY-CHAIN1266-NETWORK-MANIFEST-SIGNING-V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedManifest {
    pub unsigned: UnsignedManifest,
    pub manifest_hash: String,
    pub signer_key_id: String,
    pub signature_algorithm: SignatureAlgorithm,
    pub signature: Vec<u8>,
}

pub fn sign(
    unsigned: UnsignedManifest,
    signer: &impl AegisSigner,
    signer_key_id: KeyId,
) -> Result<SignedManifest, String> {
    unsigned.validate()?;
    if signer_key_id.as_str() != unsigned.manifest_authority_key_id {
        return Err("manifest signer is not the bound governance authority key".into());
    }
    let bytes = unsigned.canonical_bytes()?;
    let manifest_hash = unsigned.manifest_hash()?;
    let signature = signer
        .sign(
            &signer_key_id,
            &SigningContext {
                domain: MANIFEST_SIGNING_DOMAIN.into(),
                chain_id: unsigned.chain_id,
                epoch: None,
                height: None,
            },
            &bytes,
        )
        .map_err(|error| error.to_string())?;
    if signature.algorithm != SignatureAlgorithm::MlDsa65
        || signature.key_id != signer_key_id
        || signature.bytes.is_empty()
    {
        return Err("manifest signer returned unsupported material".into());
    }
    Ok(SignedManifest {
        unsigned,
        manifest_hash,
        signer_key_id: signer_key_id.as_str().into(),
        signature_algorithm: signature.algorithm,
        signature: signature.bytes,
    })
}

pub fn verify(
    signed: &SignedManifest,
    verifier: &impl AegisVerifier,
    trust_public_key: &[u8],
) -> Result<(), String> {
    signed.unsigned.validate()?;
    if signed.manifest_hash != signed.unsigned.manifest_hash()?
        || signed.signer_key_id != signed.unsigned.manifest_authority_key_id
        || signed.signature_algorithm != SignatureAlgorithm::MlDsa65
        || signed.signature.is_empty()
        || trust_public_key.is_empty()
    {
        return Err("signed manifest commitment mismatch".into());
    }
    let key_id = KeyId::new(signed.signer_key_id.clone()).map_err(|error| error.to_string())?;
    verifier
        .verify(
            &SigningContext {
                domain: MANIFEST_SIGNING_DOMAIN.into(),
                chain_id: signed.unsigned.chain_id,
                epoch: None,
                height: None,
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
