//! Canonical Proof-of-Synergy v3 consensus core.
//!
//! PoSy retains frozen non-uniform validator weights and an independent
//! validator-count quorum. It is not Proof-of-Stake; stake, Synergy Score,
//! role configuration, VPN membership, and transport presence never grant
//! authority or determine finality.

pub mod clustering;
pub mod domains;
pub mod engine;
pub mod errors;
pub mod finality;
pub mod membership;
pub mod metrics;
pub mod network;
pub mod parameters;
pub mod persistence;
pub mod proposal;
pub mod protocol;
pub mod quorum;
pub mod recovery;
mod sync_witness;
pub mod timeout;
pub mod version;
pub mod voting;

pub use clustering::*;
pub use domains::*;
pub use engine::*;
pub use errors::PosyError;
pub use finality::*;
pub use membership::*;
pub use metrics::*;
pub use network::*;
pub use parameters::*;
pub use persistence::{
    JournalError, SignOnceJournal, SigningSlot, VerifiedQuorumCertificateStore,
    VerifiedTimeoutCertificateStore,
};
pub use proposal::*;
pub use protocol::*;
pub use quorum::*;
pub use recovery::{PosyRecoveryJournal, RecoveryRecordKind, RecoverySlot};
pub use sync_witness::FinalitySyncWitness;
pub use timeout::*;
pub use version::*;
pub use voting::*;

pub type PosyResult<T> = Result<T, PosyError>;
