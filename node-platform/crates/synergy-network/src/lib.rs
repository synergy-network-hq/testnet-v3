//! Authenticated P2P transport boundaries for the Synergy node platform.
//!
//! This crate owns transport admission, peer-session lifecycle and bounded
//! routing. It deliberately does not validate PoSy or ETDAG semantics, grant
//! validator authority, calculate quorum, or determine finality.

pub mod discovery;
pub mod handshake;
pub mod metrics;
pub mod peer;
pub mod protocol;
pub mod router;
pub mod sentry;
pub mod transport;

pub use metrics::NetworkMetrics;
