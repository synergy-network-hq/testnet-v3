//! Fail-closed binding from a verified route snapshot to peer authentication.
//! The binding admits transport for one authenticated overlay identity only; it
//! cannot activate a validator or otherwise alter PoSy membership.

use crate::{OverlayScope, VerifiedSnapshot};
use synergy_network::peer::{AuthenticatedTransportAdmissionPolicy, PeerAdmissionPolicyError};
use synergy_protocol_types::AuthenticatedPeer;

pub struct ValidatorOverlayAdmission<'a> {
    snapshot: &'a VerifiedSnapshot,
    observed_dial: String,
}
impl VerifiedSnapshot {
    pub fn validator_overlay_admission(
        &self,
        observed_dial: impl Into<String>,
    ) -> ValidatorOverlayAdmission<'_> {
        ValidatorOverlayAdmission {
            snapshot: self,
            observed_dial: observed_dial.into(),
        }
    }
}
impl AuthenticatedTransportAdmissionPolicy for ValidatorOverlayAdmission<'_> {
    fn permit(&self, peer: &AuthenticatedPeer) -> Result<(), PeerAdmissionPolicyError> {
        let route = self
            .snapshot
            .registry()
            .route_for(peer.node_address.as_str())
            .ok_or_else(|| {
                PeerAdmissionPolicyError::Denied(
                    "identity is absent from verified transport snapshot".into(),
                )
            })?;
        if route.scope != OverlayScope::Validator {
            return Err(PeerAdmissionPolicyError::Denied(
                "route is not in Validator overlay scope".into(),
            ));
        }
        if route.dial_address != self.observed_dial {
            return Err(PeerAdmissionPolicyError::Denied(
                "observed route does not match verified identity binding".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransportRoute;
    use synergy_network::peer::{
        PeerDirection, PeerManager, PeerState, TransportAuthenticationError,
    };
    fn snapshot() -> VerifiedSnapshot {
        VerifiedSnapshot::from_routes_for_test(
            1,
            vec![TransportRoute {
                identity: "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into(),
                dial_address: "10.69.10.1:5622".into(),
                scope: OverlayScope::Validator,
            }],
        )
    }
    #[test]
    fn verified_route_is_required_before_overlay_peer_authentication() {
        let snapshot = snapshot();
        let mut peers = PeerManager::new("local", 2);
        let session = peers
            .admit(
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                PeerDirection::Outbound,
                1,
            )
            .unwrap()
            .session_id;
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            session,
            vec!["posy".into()],
        )
        .unwrap();
        assert!(peers
            .authenticate_with_transport_policy(
                peer,
                &snapshot.validator_overlay_admission("10.69.10.1:5622"),
                2
            )
            .is_ok());
        assert_eq!(
            peers
                .snapshot("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn")
                .unwrap()
                .state,
            PeerState::Authenticated
        );
    }
    #[test]
    fn mismatched_route_fails_closed_without_authenticating_peer() {
        let snapshot = snapshot();
        let mut peers = PeerManager::new("local", 2);
        let session = peers
            .admit(
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                PeerDirection::Outbound,
                1,
            )
            .unwrap()
            .session_id;
        let peer =
            AuthenticatedPeer::new("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn", session, vec![])
                .unwrap();
        assert!(matches!(
            peers.authenticate_with_transport_policy(
                peer,
                &snapshot.validator_overlay_admission("10.69.10.2:5622"),
                2
            ),
            Err(TransportAuthenticationError::Policy(_))
        ));
        assert_eq!(
            peers
                .snapshot("synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn")
                .unwrap()
                .state,
            PeerState::Connecting
        );
    }
}
