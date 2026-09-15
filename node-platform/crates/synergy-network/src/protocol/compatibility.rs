use super::{ProtocolRegistration, ProtocolVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolCompatibilityError {
    ProtocolMismatch,
    VersionMismatch {
        local: ProtocolVersion,
        remote: ProtocolVersion,
    },
    RemotePayloadLimitTooSmall,
}

pub fn check_protocol_compatibility(
    local: ProtocolRegistration,
    remote: ProtocolRegistration,
) -> Result<(), ProtocolCompatibilityError> {
    if local.kind != remote.kind {
        return Err(ProtocolCompatibilityError::ProtocolMismatch);
    }
    if !local.version.is_compatible_with(remote.version) {
        return Err(ProtocolCompatibilityError::VersionMismatch {
            local: local.version,
            remote: remote.version,
        });
    }
    if remote.max_payload_bytes == 0 {
        return Err(ProtocolCompatibilityError::RemotePayloadLimitTooSmall);
    }
    Ok(())
}
