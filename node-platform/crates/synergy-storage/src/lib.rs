//! Durable bounded-file, WAL, integrity, and disk-pressure primitives.
//!
//! Higher layers own consensus, ETDAG, schema semantics, and pruning decisions.
//! No storage component can create a vote, QC, validator authority, or finality.

mod column;
mod database;
mod disk_guard;
mod fsync;
mod integrity;
mod migration;
mod pruning;
mod recovery;
mod transaction;
mod wal;

pub use column::*;
pub use database::{AtomicStore, StorageError};
pub use disk_guard::{DiskGuard, DiskObservation};
pub use integrity::IntegrityDigest;
pub use migration::{write_schema_version, SchemaVersion};
pub use pruning::{PruneBoundary, PruneReport};
pub use recovery::{recover_wal, RecoveryReport};
pub use transaction::{
    GuardedTransactionBackend, RequiredRecord, StoragePrecondition, StorageTransaction,
    StorageWrite, TransactionBackend,
};
pub use wal::{WalRecord, WriteAheadLog};
