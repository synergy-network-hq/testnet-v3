use crate::{hash::hex64, NetworkManifest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    WrongChain,
    NetworkMismatch,
    GenesisMismatch,
    ProtocolMismatch,
    InvalidHash,
}

impl NetworkManifest {
    pub fn validate_against(&self, expected: &Self) -> Result<(), ManifestError> {
        if self.chain_id == 0 || self.chain_id != expected.chain_id {
            return Err(ManifestError::WrongChain);
        }
        if self.network_id != expected.network_id {
            return Err(ManifestError::NetworkMismatch);
        }
        if self.genesis_hash != expected.genesis_hash {
            return Err(ManifestError::GenesisMismatch);
        }
        if self.protocol_version != expected.protocol_version {
            return Err(ManifestError::ProtocolMismatch);
        }
        if !hex64(&self.manifest_hash) {
            return Err(ManifestError::InvalidHash);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> NetworkManifest {
        NetworkManifest {
            chain_id: 1266,
            network_id: "testnet".into(),
            genesis_hash: "genesis".into(),
            protocol_version: "posy/3.0".into(),
            manifest_hash: "a".repeat(64),
        }
    }

    #[test]
    fn binds_chain_genesis_and_protocol_context() {
        let manifest = manifest();
        assert!(manifest.validate_against(&manifest).is_ok());
        let mut other = manifest.clone();
        other.genesis_hash = "other".into();
        assert_eq!(
            other.validate_against(&manifest),
            Err(ManifestError::GenesisMismatch)
        );
    }

    #[test]
    fn expected_chain_is_selected_and_cannot_be_taken_from_the_candidate() {
        for chain_id in [1266, 9001, 9002] {
            let mut expected = manifest();
            expected.chain_id = chain_id;
            assert!(expected.validate_against(&expected).is_ok());
            let mut other = expected.clone();
            other.chain_id += 1;
            assert_eq!(
                other.validate_against(&expected),
                Err(ManifestError::WrongChain)
            );
            other.chain_id = 0;
            assert_eq!(
                other.validate_against(&other),
                Err(ManifestError::WrongChain)
            );
        }
    }

    #[test]
    fn malformed_hash_is_not_accepted() {
        let mut manifest = manifest();
        manifest.manifest_hash = "invalid".into();
        assert_eq!(
            manifest.validate_against(&NetworkManifest {
                chain_id: 1266,
                network_id: "testnet".into(),
                genesis_hash: "genesis".into(),
                protocol_version: "posy/3.0".into(),
                manifest_hash: "a".repeat(64),
            }),
            Err(ManifestError::InvalidHash)
        );
    }
}
