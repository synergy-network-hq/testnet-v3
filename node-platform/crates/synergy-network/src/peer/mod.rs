//! Authenticated peer/session lifecycle ownership.

mod admission;
mod backoff;
mod ban;
mod connection_limits;
mod duplicate;
mod health;
mod manager;
mod peer;
mod persistence;
mod quarantine;
mod score;
mod session;
mod state;

pub use admission::{AuthenticatedTransportAdmissionPolicy, PeerAdmissionPolicyError};
pub use backoff::{BackoffPolicy, PeerBackoff};
pub use ban::{BanRecord, BanTable};
pub use connection_limits::{ConnectionLimitError, ConnectionLimits};
pub use duplicate::preferred_direction;
pub use health::{PeerHealth, PeerHealthState};
pub use manager::{
    AdmissionError, ConnectionAdmission, DisconnectReason, PeerDirection, PeerManager,
    PeerSnapshot, PeerState, TransportAuthenticationError,
};
pub use peer::PeerDescriptor;
pub use persistence::{PeerSnapshotStore, PersistedPeerState};
pub use quarantine::{QuarantineRecord, QuarantineTable};
pub use score::PeerScore;
pub use session::PeerSession;
pub use state::{validate_peer_transition, PeerTransitionError};
