use std::collections::BTreeMap;

use synergy_protocol_types::NodeAddress;

use synergy_aegis::{
    AegisSigner, AegisVerifier, GovernedNodeKeyBinding, KeyId, Signature, SignatureAlgorithm,
    SigningContext,
};

use super::{HandshakeSignatureVerifier, HandshakeSigner, PeerKeyAlgorithm};

/// Canonical Aegis-backed verifier for P2P handshake transcripts. The caller
/// supplies governed public-key bindings; this type authenticates identity only.
pub struct AegisHandshakeVerifier<V> {
    verifier: V,
    chain_id: u64,
    keys: BTreeMap<NodeAddress, GovernedNodeKeyBinding>,
}

impl<V> AegisHandshakeVerifier<V> {
    pub fn new(
        verifier: V,
        chain_id: u64,
        keys: BTreeMap<NodeAddress, GovernedNodeKeyBinding>,
    ) -> Result<Self, String> {
        if chain_id == 0
            || keys.iter().any(|(node_address, binding)| {
                node_address != &binding.node_address || binding.validate().is_err()
            })
        {
            return Err(
                "Aegis handshake verifier requires a chain id and nonempty public keys".into(),
            );
        }
        Ok(Self {
            verifier,
            chain_id,
            keys,
        })
    }
}

impl<V: AegisVerifier> HandshakeSignatureVerifier for AegisHandshakeVerifier<V> {
    type Error = String;

    fn verify_handshake_signature(
        &self,
        peer_id: &str,
        algorithm: PeerKeyAlgorithm,
        transcript: &[u8],
        signature: &[u8],
    ) -> Result<(), Self::Error> {
        let algorithm =
            match algorithm {
                PeerKeyAlgorithm::Mldsa65 => SignatureAlgorithm::MlDsa65,
                _ => return Err(
                    "requested handshake algorithm is not yet exposed by the Aegis PQVM provider"
                        .into(),
                ),
            };
        let binding = self
            .keys
            .get(peer_id)
            .ok_or_else(|| "no governed Aegis public-key binding for peer".to_string())?;
        if binding.node_address.as_str() != peer_id || binding.algorithm != algorithm {
            return Err(
                "handshake algorithm or peer id differs from governed Aegis binding".into(),
            );
        }
        self.verifier
            .verify(
                &SigningContext {
                    domain: "SYNERGY-P2P-HANDSHAKE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: None,
                    height: None,
                },
                transcript,
                &Signature {
                    algorithm,
                    key_id: binding.key_id.clone(),
                    bytes: signature.to_vec(),
                },
                &binding.public_key,
            )
            .map_err(|e| e.to_string())
    }
}

/// Local Aegis signer for the exact canonical handshake transcript.
pub struct AegisHandshakeSigner<S> {
    signer: S,
    key_id: KeyId,
    chain_id: u64,
}

impl<S> AegisHandshakeSigner<S> {
    pub fn new(signer: S, key_id: KeyId, chain_id: u64) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("handshake signer requires a nonzero chain id".into());
        }
        Ok(Self {
            signer,
            key_id,
            chain_id,
        })
    }
}

impl<S: AegisSigner> HandshakeSigner for AegisHandshakeSigner<S> {
    type Error = String;

    fn sign_handshake(
        &self,
        algorithm: PeerKeyAlgorithm,
        transcript: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        if algorithm != PeerKeyAlgorithm::Mldsa65 {
            return Err(
                "Aegis PQVM signer does not support the requested handshake algorithm".into(),
            );
        }
        let signature = self
            .signer
            .sign(
                &self.key_id,
                &SigningContext {
                    domain: "SYNERGY-P2P-HANDSHAKE-V1".into(),
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
            return Err("Aegis handshake signer returned an unexpected signature".into());
        }
        Ok(signature.bytes)
    }
}
