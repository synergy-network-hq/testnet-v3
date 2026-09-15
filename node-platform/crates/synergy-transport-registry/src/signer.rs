use crate::{SignedTransportSnapshot, SnapshotError};

/// Implemented by the approved custody provider. This crate never stores or
/// exposes private signing material.
pub trait TransportSnapshotSigner {
    fn authority_id(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign_snapshot(&self, snapshot: &SignedTransportSnapshot) -> Result<Vec<u8>, SnapshotError>;
}
