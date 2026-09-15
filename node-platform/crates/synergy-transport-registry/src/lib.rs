//! Verified identity-to-route registry state.
//!
//! Signature verification is an input boundary owned by the attestation
//! verifier. This crate retains only snapshots that were already verified and
//! enforces identity-complete transport coverage without making membership
//! decisions.

use std::collections::{BTreeMap, BTreeSet};
use synergy_vpn::{OverlayScope, VpnRouteError, VpnRoutePolicy};

mod binding;
mod cache;
mod generation;
mod lease;
mod reconciliation;
mod registry;
mod revocation;
mod signer;
mod verifier;
pub use binding::ValidatorOverlayAdmission;
pub use cache::TransportSnapshotCache;
pub use generation::{GenerationDecision, GenerationGate};
pub use lease::TransportLease;
pub use reconciliation::{reconcile_registries, RegistryDelta};
pub use registry::TransportRegistryState;
pub use revocation::{Revocation, RevocationSet};
pub use signer::TransportSnapshotSigner;
pub use verifier::{
    verify_snapshot, verify_snapshot_bytes, SignedTransportSnapshot, SnapshotAcceptance,
    SnapshotError, SnapshotInstall, SnapshotTransport, SnapshotTrust, VerifiedSnapshot,
    MAX_SNAPSHOT_BYTES,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportRoute {
    pub identity: String,
    pub dial_address: String,
    pub scope: OverlayScope,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    EmptyIdentitySet,
    DuplicateIdentity(String),
    DuplicateDialAddress(String),
    InvalidRoute(VpnRouteError),
    MissingActiveIdentities(Vec<String>),
}
#[derive(Debug, Clone)]
pub struct VerifiedTransportRegistry {
    generation: u64,
    routes: BTreeMap<String, TransportRoute>,
}

impl VerifiedTransportRegistry {
    pub(crate) fn from_verified_snapshot(
        generation: u64,
        routes: Vec<TransportRoute>,
    ) -> Result<Self, RegistryError> {
        let mut normalized = BTreeMap::new();
        let mut dial_addresses = BTreeSet::new();
        for mut route in routes {
            let dial = VpnRoutePolicy::new(route.scope)
                .validate(&route.identity, &route.dial_address)
                .map_err(RegistryError::InvalidRoute)?;
            route.dial_address = dial;
            if !dial_addresses.insert(route.dial_address.clone()) {
                return Err(RegistryError::DuplicateDialAddress(route.dial_address));
            }
            if normalized.insert(route.identity.clone(), route).is_some() {
                return Err(RegistryError::DuplicateIdentity(
                    "duplicate route identity".into(),
                ));
            }
        }
        Ok(Self {
            generation,
            routes: normalized,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn route_for(&self, identity: &str) -> Option<&TransportRoute> {
        self.routes.get(identity)
    }
    pub fn routes(&self) -> impl Iterator<Item = &TransportRoute> {
        self.routes.values()
    }
    pub(crate) fn same_routes(&self, other: &Self) -> bool {
        self.routes == other.routes
    }
    /// Requires coverage for an active set supplied by the membership authority.
    /// This check does not alter, validate, or activate that set.
    pub fn require_coverage(&self, active: &[String]) -> Result<(), RegistryError> {
        if active.is_empty() {
            return Err(RegistryError::EmptyIdentitySet);
        }
        let missing = active
            .iter()
            .filter(|id| !self.routes.contains_key(id.as_str()))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        missing
            .is_empty()
            .then_some(())
            .ok_or(RegistryError::MissingActiveIdentities(missing))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn route(id: &str, dial: &str) -> TransportRoute {
        TransportRoute {
            identity: id.into(),
            dial_address: dial.into(),
            scope: OverlayScope::Validator,
        }
    }
    #[test]
    fn requires_identity_complete_coverage_without_deciding_membership() {
        let registry = VerifiedTransportRegistry::from_verified_snapshot(
            7,
            vec![route(
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                "10.69.10.2:5622",
            )],
        )
        .unwrap();
        assert_eq!(registry.generation(), 7);
        assert!(registry
            .require_coverage(&["synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into()])
            .is_ok());
        assert_eq!(
            registry.require_coverage(&[
                "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".into(),
                "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n".into()
            ]),
            Err(RegistryError::MissingActiveIdentities(vec![
                "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n".into()
            ]))
        );
    }
    #[test]
    fn rejects_duplicate_or_non_overlay_routes() {
        assert!(matches!(
            VerifiedTransportRegistry::from_verified_snapshot(
                1,
                vec![
                    route(
                        "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                        "10.69.10.2:5622"
                    ),
                    route(
                        "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                        "10.69.10.3:5622"
                    )
                ]
            ),
            Err(RegistryError::DuplicateIdentity(_))
        ));
        assert!(matches!(
            VerifiedTransportRegistry::from_verified_snapshot(
                1,
                vec![route(
                    "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                    "10.70.3.2:5622"
                )]
            ),
            Err(RegistryError::InvalidRoute(_))
        ));
        assert!(matches!(
            VerifiedTransportRegistry::from_verified_snapshot(
                1,
                vec![
                    route(
                        "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
                        "10.69.10.2:5622"
                    ),
                    route(
                        "synv21lrh6jcxaejkj4zv994j7qwn2rk6u3zat22n",
                        "10.69.10.2:5622"
                    )
                ]
            ),
            Err(RegistryError::DuplicateDialAddress(_))
        ));
    }
}
