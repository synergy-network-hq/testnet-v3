//! Authority-neutral data-availability shard custody and proof contracts.
pub mod audit;
pub mod proof;
pub mod retention;
pub mod serve;
pub mod shard;
pub mod store;
pub use proof::{verify_availability_proof, AvailabilityProof, ProofVerifier};
pub use retention::RetentionPolicy;
pub use shard::DataShard;
pub use store::{CustodiedShard, FilesystemShardStore, ShardStore};
