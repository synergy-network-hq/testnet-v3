//! Validator-overlay transport policy. VPN reachability is never PoSy authority.

pub mod client;
pub mod enrollment;
pub mod lease_verifier;
pub mod metrics;
pub mod netbird;
pub mod overlay_scope;
pub mod peer_binding;
pub mod readiness;
mod route_policy;
pub mod sentry_binding;
pub mod state;
pub mod transport_lease;

pub use client::VpnClient;
pub use lease_verifier::{verify_transport_lease, LeaseSignatureVerifier};
pub use metrics::VpnMetrics;
pub use netbird::{NetbirdDaemon, NetbirdProfile, NetbirdStatus};
pub use peer_binding::ValidatorPeerBinding;
pub use readiness::{evaluate_readiness, VpnReadiness};
pub use route_policy::{normalize_validator_address, OverlayScope, VpnRouteError, VpnRoutePolicy};
pub use sentry_binding::SentryPeerBinding;
pub use state::VpnState;
pub use transport_lease::SignedTransportLease;
