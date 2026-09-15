use synergy_network::peer::{AuthenticatedTransportAdmissionPolicy, PeerAdmissionPolicyError};
use synergy_protocol_types::AuthenticatedPeer;

use crate::{OverlayScope, SignedTransportLease};

pub struct SentryPeerBinding<'a> {
    pub lease: &'a SignedTransportLease,
    pub observed_dial: &'a str,
}

impl AuthenticatedTransportAdmissionPolicy for SentryPeerBinding<'_> {
    fn permit(&self, peer: &AuthenticatedPeer) -> Result<(), PeerAdmissionPolicyError> {
        if self.lease.scope != OverlayScope::Sentry
            || self.lease.identity != peer.node_address.as_str()
            || self.lease.dial_address != self.observed_dial
        {
            return Err(PeerAdmissionPolicyError::Denied(
                "Sentry peer does not match verified VPN lease".into(),
            ));
        }
        Ok(())
    }
}
