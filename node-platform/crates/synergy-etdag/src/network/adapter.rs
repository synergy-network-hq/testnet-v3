use crate::{AuthenticatedEtdagMessage, EtdagDigest, EtdagError};

/// Transport-only boundary. Implementations cannot grant validator authority
/// or determine ordering/finality by delivering a message.
pub trait EtdagTransport {
    fn broadcast(&mut self, message: &AuthenticatedEtdagMessage) -> Result<(), EtdagError>;

    fn send_to(
        &mut self,
        peer_id: &str,
        message: &AuthenticatedEtdagMessage,
    ) -> Result<(), EtdagError>;

    fn request_artifact(
        &mut self,
        peer_id: &str,
        artifact_id: &EtdagDigest,
    ) -> Result<(), EtdagError>;

    fn may_determine_finality(&self) -> bool {
        false
    }
}
