use super::{ChainBinding, ChainBindingError, HandshakeMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeCompatibilityError {
    Chain(ChainBindingError),
    Metadata(super::HandshakeError),
}

pub fn verify_handshake_compatibility(
    local_chain: &ChainBinding,
    remote_chain: &ChainBinding,
    local_metadata: &HandshakeMetadata,
    remote_metadata: &HandshakeMetadata,
) -> Result<(), HandshakeCompatibilityError> {
    local_chain
        .verify_remote(remote_chain)
        .map_err(HandshakeCompatibilityError::Chain)?;
    remote_metadata
        .validate_against(local_metadata)
        .map_err(HandshakeCompatibilityError::Metadata)
}
