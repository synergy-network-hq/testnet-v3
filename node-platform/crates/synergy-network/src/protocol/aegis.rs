//! Aegis PQVM signature authentication for canonical session-bound frames.
use synergy_aegis::{
    AegisSigner, AegisVerifier, GovernedNodeKeyBinding, KeyId, Signature, SignatureAlgorithm,
    SigningContext,
};

use super::{FrameSigner, FrameVerifier};

pub struct AegisFrameSigner<S> {
    signer: S,
    key_id: KeyId,
    chain_id: u64,
}

impl<S> AegisFrameSigner<S> {
    pub fn new(signer: S, key_id: KeyId, chain_id: u64) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("frame signer requires a nonzero chain id".into());
        }
        Ok(Self {
            signer,
            key_id,
            chain_id,
        })
    }
}

impl<S: AegisSigner> FrameSigner for AegisFrameSigner<S> {
    type Error = String;

    fn sign_frame(&self, transcript: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-P2P-FRAME-AUTH-V1".into(),
                    chain_id: self.chain_id,
                    epoch: None,
                    height: None,
                },
                transcript,
            )
            .map_err(|error| error.to_string())?;
        if signature.algorithm != SignatureAlgorithm::MlDsa65
            || signature.key_id != self.key_id
            || signature.bytes.is_empty()
        {
            return Err("Aegis frame signer returned an unexpected signature".into());
        }
        Ok(signature.bytes)
    }
}

pub struct AegisFrameVerifier<V> {
    verifier: V,
    binding: GovernedNodeKeyBinding,
    chain_id: u64,
}

impl<V> AegisFrameVerifier<V> {
    pub fn new(
        verifier: V,
        binding: GovernedNodeKeyBinding,
        chain_id: u64,
    ) -> Result<Self, String> {
        binding.validate().map_err(|error| error.to_string())?;
        if chain_id == 0 || binding.algorithm != SignatureAlgorithm::MlDsa65 {
            return Err("frame verifier requires a governed ML-DSA-65 binding and chain id".into());
        }
        Ok(Self {
            verifier,
            binding,
            chain_id,
        })
    }
}

impl<V: AegisVerifier> FrameVerifier for AegisFrameVerifier<V> {
    type Error = String;

    fn verify_frame(&self, transcript: &[u8], authenticator: &[u8]) -> Result<(), Self::Error> {
        self.verifier
            .verify(
                &SigningContext {
                    domain: "SYNERGY-P2P-FRAME-AUTH-V1".into(),
                    chain_id: self.chain_id,
                    epoch: None,
                    height: None,
                },
                transcript,
                &Signature {
                    algorithm: self.binding.algorithm,
                    key_id: self.binding.key_id.clone(),
                    bytes: authenticator.to_vec(),
                },
                &self.binding.public_key,
            )
            .map_err(|error| error.to_string())
    }
}
