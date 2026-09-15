mod archive;
mod failover;
mod peer;
mod scoring;
mod snapshot;

pub use archive::{request_authenticated_archive, ArchiveSyncSource};
pub use failover::{SupportSourceFailover, SupportSourceFailoverError};
pub use peer::{request_authenticated_peer, PeerSyncSource};
pub use scoring::{support_source_score, SourceObservation};
pub use snapshot::{
    fetch_verified_production_snapshot, request_authenticated_snapshot, ProductionSnapshotSource,
    SnapshotSyncSource,
};
