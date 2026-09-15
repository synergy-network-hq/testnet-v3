//! Dual-homed Sentry forwarding boundary. A Sentry transports only permitted
//! authenticated frames; it never owns PoSy, signs votes, or determines finality.

mod failover;
mod filter;
mod forwarder;
mod metrics;
mod policy;
mod public_peers;
mod validator_link;

pub use failover::select_validator_link;
pub use filter::{SentryFilter, SentryFilterError};
pub use forwarder::{SentryForwardError, SentryForwarder};
pub use metrics::SentryMetrics;
pub use policy::SentryCapabilities;
pub use public_peers::PublicPeerSet;
pub use validator_link::ValidatorLink;
