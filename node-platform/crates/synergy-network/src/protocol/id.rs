//! Stable identifiers for authority-neutral P2P protocol routing.

use synergy_protocol_types::ProtocolKind;

/// Error returned when a wire protocol identifier is not registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolIdError(pub u8);

impl std::fmt::Display for ProtocolIdError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "unknown P2P protocol identifier {}", self.0)
    }
}

impl std::error::Error for ProtocolIdError {}

/// Returns the stable wire identifier for a protocol adapter.
pub const fn protocol_id(protocol: ProtocolKind) -> u8 {
    match protocol {
        ProtocolKind::Status => 1,
        ProtocolKind::Discovery => 2,
        ProtocolKind::Sync => 3,
        ProtocolKind::Posy => 4,
        ProtocolKind::Etdag => 5,
        ProtocolKind::Transaction => 6,
        ProtocolKind::Snapshot => 7,
        ProtocolKind::Observer => 8,
        ProtocolKind::Sxcp => 9,
    }
}

/// Resolves a stable wire identifier to an authority-neutral protocol kind.
///
/// # Errors
/// Returns [`ProtocolIdError`] for identifiers not registered by this version.
pub const fn protocol_kind(identifier: u8) -> Result<ProtocolKind, ProtocolIdError> {
    match identifier {
        1 => Ok(ProtocolKind::Status),
        2 => Ok(ProtocolKind::Discovery),
        3 => Ok(ProtocolKind::Sync),
        4 => Ok(ProtocolKind::Posy),
        5 => Ok(ProtocolKind::Etdag),
        6 => Ok(ProtocolKind::Transaction),
        7 => Ok(ProtocolKind::Snapshot),
        8 => Ok(ProtocolKind::Observer),
        9 => Ok(ProtocolKind::Sxcp),
        value => Err(ProtocolIdError(value)),
    }
}
