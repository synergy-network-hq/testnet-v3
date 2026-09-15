use synergy_protocol_types::NodeAddress;

/// A peer public-key algorithm accepted by the Aegis handshake boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerKeyAlgorithm {
    Fndsa,
    Mldsa65,
    Mldsa87,
}

/// Parses only peer algorithms accepted by the existing authenticated
/// handshake. This is compatibility policy, not a signature verifier.
pub fn parse_peer_key_algorithm(value: &str) -> Result<PeerKeyAlgorithm, HandshakeError> {
    match value.trim() {
        "fndsa" | "FN-DSA-1024" => Ok(PeerKeyAlgorithm::Fndsa),
        "mldsa65" | "ML-DSA-65" => Ok(PeerKeyAlgorithm::Mldsa65),
        "mldsa87" | "ML-DSA-87" => Ok(PeerKeyAlgorithm::Mldsa87),
        _ => Err(HandshakeError::UnsupportedPeerKeyAlgorithm),
    }
}

/// Signed-handshake metadata required to prove transport compatibility. The
/// Aegis verifier is separate; this comparison grants no validator authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMetadata {
    pub node_address: NodeAddress,
    pub network_id: String,
    pub genesis_hash: String,
    pub protocol_version: String,
    pub key_algorithm: PeerKeyAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    NetworkMismatch,
    GenesisMismatch,
    ProtocolMismatch,
    UnsupportedPeerKeyAlgorithm,
}

impl HandshakeMetadata {
    pub fn validate_against(&self, expected: &Self) -> Result<(), HandshakeError> {
        if self.network_id != expected.network_id {
            return Err(HandshakeError::NetworkMismatch);
        }
        if self.genesis_hash != expected.genesis_hash {
            return Err(HandshakeError::GenesisMismatch);
        }
        if self.protocol_version != expected.protocol_version {
            return Err(HandshakeError::ProtocolMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> HandshakeMetadata {
        HandshakeMetadata {
            node_address: NodeAddress::parse("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn").unwrap(),
            network_id: "synergy-testnet-v3".into(),
            genesis_hash: "genesis".into(),
            protocol_version: "v3".into(),
            key_algorithm: PeerKeyAlgorithm::Mldsa65,
        }
    }

    #[test]
    fn accepts_only_authorized_aegis_peer_key_algorithms() {
        assert_eq!(
            parse_peer_key_algorithm("mldsa65"),
            Ok(PeerKeyAlgorithm::Mldsa65)
        );
        assert!(parse_peer_key_algorithm("slhdsa").is_err())
    }

    #[test]
    fn handshake_requires_network_genesis_and_protocol_compatibility() {
        let expected = expected();
        let mut remote = expected.clone();
        remote.node_address =
            NodeAddress::parse("synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n").unwrap();
        assert!(remote.validate_against(&expected).is_ok());
        remote.genesis_hash = "other".into();
        assert_eq!(
            remote.validate_against(&expected),
            Err(HandshakeError::GenesisMismatch)
        );
    }
}
