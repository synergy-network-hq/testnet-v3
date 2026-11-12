use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};

use crate::{
    fsync::sync_directory, transaction::MAXIMUM_TRANSACTION_WRITES, GuardedTransactionBackend,
    IntegrityDigest, RequiredRecord, StoragePrecondition, StorageWrite, TransactionBackend,
};

#[cfg(unix)]
use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const TRANSACTION_VERSION: u32 = 1;
const TRANSACTION_DOMAIN: &str = "SYNERGY_STORAGE_TRANSACTION_WRITE_V1";
const TRANSACTION_DIRECTORY: &str = ".transactions";
const WRITER_LOCK: &str = ".synergy-writer.lock";

#[derive(Debug, Clone)]
pub struct AtomicStore {
    root: PathBuf,
    max_record_bytes: usize,
    maximum_manifest_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    InvalidPath,
    RecordTooLarge { actual: usize, maximum: usize },
    Io(String),
    IntegrityMismatch,
    CorruptWal,
    CorruptTransaction,
    ConflictingWrite,
    TooManyTransactionWrites { actual: usize, maximum: usize },
    InvalidDiskThreshold,
    DiskPressure { available: u64, required: u64 },
    InvalidSchemaVersion,
    InvalidPruneBoundary,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath => write!(formatter, "invalid storage path"),
            Self::RecordTooLarge { actual, maximum } => {
                write!(formatter, "storage record {actual} exceeds limit {maximum}")
            }
            Self::Io(message) => write!(formatter, "storage I/O error: {message}"),
            Self::IntegrityMismatch => write!(formatter, "storage integrity mismatch"),
            Self::CorruptWal => write!(formatter, "corrupt write-ahead log"),
            Self::CorruptTransaction => write!(formatter, "corrupt storage transaction"),
            Self::ConflictingWrite => write!(formatter, "conflicting immutable storage write"),
            Self::TooManyTransactionWrites { actual, maximum } => write!(
                formatter,
                "storage transaction has {actual} writes; maximum is {maximum}"
            ),
            Self::InvalidDiskThreshold => write!(formatter, "invalid disk threshold"),
            Self::DiskPressure {
                available,
                required,
            } => write!(
                formatter,
                "disk pressure: {available} available, {required} required"
            ),
            Self::InvalidSchemaVersion => write!(formatter, "invalid schema version"),
            Self::InvalidPruneBoundary => write!(formatter, "invalid prune boundary"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Read-only view valid for one consistent checkpoint/delta traversal. The
/// writer lock is retained by `inspect_consistent` for the callback lifetime.
pub struct AtomicStoreReader<'a> {
    store: &'a AtomicStore,
    maximum_bytes: usize,
}

impl AtomicStoreReader<'_> {
    /// Narrows record allocations without changing the transaction recovery limit.
    pub fn with_maximum_bytes(&self, maximum_bytes: usize) -> AtomicStoreReader<'_> {
        AtomicStoreReader {
            store: self.store,
            maximum_bytes: maximum_bytes.min(self.maximum_bytes),
        }
    }

    /// Obtain the payload length without allocating its contents. This view
    /// retains the canonical writer lock, so cooperative writers cannot replace
    /// the record between a capacity reservation and its bounded read.
    pub fn optional_record_bytes(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<Option<usize>, StorageError> {
        let path = self.store.resolve(relative.as_ref())?;
        let metadata = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io_error(error)),
            Ok(metadata) => metadata,
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StorageError::InvalidPath);
        }
        let length = usize::try_from(metadata.len()).map_err(|_| StorageError::RecordTooLarge {
            actual: usize::MAX,
            maximum: self.maximum_bytes,
        })?;
        if length > self.maximum_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: length,
                maximum: self.maximum_bytes,
            });
        }
        Ok(Some(length))
    }

    pub fn read_optional_bounded(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.store
            .read_optional_bounded_with_limit_locked(relative.as_ref(), self.maximum_bytes)
    }
}

impl AtomicStore {
    pub fn new(root: impl Into<PathBuf>, max_record_bytes: usize) -> Result<Self, StorageError> {
        Self::new_with_manifest_limit(root, max_record_bytes, max_record_bytes.saturating_mul(2))
    }

    /// A fixed-shape owner can bound transaction metadata independently from
    /// its large payload records. The same limit applies before recovery decode
    /// and before a commit intent is written; payload compatibility is unchanged.
    pub fn new_with_manifest_limit(
        root: impl Into<PathBuf>,
        max_record_bytes: usize,
        maximum_manifest_bytes: usize,
    ) -> Result<Self, StorageError> {
        if maximum_manifest_bytes == 0 {
            return Err(StorageError::RecordTooLarge {
                actual: 1,
                maximum: 0,
            });
        }
        if max_record_bytes == 0 {
            return Err(StorageError::RecordTooLarge {
                actual: 1,
                maximum: 0,
            });
        }
        let result = Self {
            root: root.into(),
            max_record_bytes,
            maximum_manifest_bytes,
        };
        result.ensure_root()?;
        {
            let _lock = result.exclusive_lock()?;
            result.recover_transactions_locked()?;
        }
        Ok(result)
    }

    /// Read an existing canonical journal under the same writer lock. The caller
    /// owns framing, bounded allocation and authentication; this grants no authority.
    pub fn inspect_append_journal<T>(
        &self,
        relative: impl AsRef<Path>,
        inspect: impl FnOnce(&mut File) -> T,
    ) -> Result<T, StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let file = self.resolve(relative.as_ref())?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let mut handle = options.open(file).map_err(io_error)?;
        if !handle.metadata().map_err(io_error)?.is_file() {
            return Err(StorageError::InvalidPath);
        }
        Ok(inspect(&mut handle))
    }

    /// Append one bounded frame only to the exact retained length seen by its
    /// sole owner. Signatures/commits may be acknowledged only after success.
    pub fn append_journal_frame(
        &self,
        relative: impl AsRef<Path>,
        expected_length: u64,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        if bytes.is_empty() || bytes.len() > self.max_record_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: bytes.len(),
                maximum: self.max_record_bytes,
            });
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let file = self.resolve(relative.as_ref())?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let mut handle = options.open(file).map_err(io_error)?;
        let metadata = handle.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(StorageError::InvalidPath);
        }
        if metadata.len() != expected_length {
            return Err(StorageError::ConflictingWrite);
        }
        handle.seek(SeekFrom::End(0)).map_err(io_error)?;
        handle.write_all(bytes).map_err(io_error)?;
        handle.sync_all().map_err(io_error)
    }

    /// Explicit crash recovery for a higher-layer-verified committed prefix.
    /// Never called for complete corrupt frames; metadata races fail closed.
    pub fn trim_uncommitted_journal_tail(
        &self,
        relative: impl AsRef<Path>,
        expected_length: u64,
        verified_prefix: u64,
    ) -> Result<(), StorageError> {
        if verified_prefix >= expected_length {
            return Err(StorageError::InvalidPath);
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let file = self.resolve(relative.as_ref())?;
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let handle = options.open(file).map_err(io_error)?;
        let metadata = handle.metadata().map_err(io_error)?;
        if !metadata.is_file() {
            return Err(StorageError::InvalidPath);
        }
        if metadata.len() != expected_length {
            return Err(StorageError::ConflictingWrite);
        }
        handle.set_len(verified_prefix).map_err(io_error)?;
        handle.sync_all().map_err(io_error)
    }

    pub fn write_atomic(
        &self,
        relative: impl AsRef<Path>,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        self.write_atomic_locked(relative.as_ref(), bytes)
    }

    fn write_atomic_locked(&self, relative: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        if bytes.len() > self.max_record_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: bytes.len(),
                maximum: self.max_record_bytes,
            });
        }

        let target = self.resolve(relative)?;
        let parent = target.parent().ok_or(StorageError::InvalidPath)?;
        fs::create_dir_all(parent).map_err(io_error)?;
        let temporary = target.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(io_error)?;
            file.write_all(bytes).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
            fs::rename(&temporary, &target).map_err(io_error)?;
            sync_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn exists(&self, relative: impl AsRef<Path>) -> Result<bool, StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        Ok(self.resolve(relative.as_ref())?.exists())
    }

    pub fn read_bounded(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        self.read_bounded_locked(relative.as_ref())
    }

    /// Missing records are normal during retention. Resolve presence and read
    /// under one writer lock so a concurrent pruner cannot race the two steps.
    pub fn read_optional_bounded(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        self.read_optional_bounded_locked(relative.as_ref())
    }

    /// One writer-lock/recovery boundary for all reads in a dependent record
    /// chain. Retention cannot remove a parent between checkpoint/delta reads.
    pub fn inspect_consistent<T>(
        &self,
        inspect: impl FnOnce(&AtomicStoreReader<'_>) -> T,
    ) -> Result<T, StorageError> {
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        Ok(inspect(&AtomicStoreReader {
            store: self,
            maximum_bytes: self.max_record_bytes,
        }))
    }

    fn read_optional_bounded_locked(
        &self,
        relative: &Path,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.read_optional_bounded_with_limit_locked(relative, self.max_record_bytes)
    }

    fn read_optional_bounded_with_limit_locked(
        &self,
        relative: &Path,
        maximum_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let path = self.resolve(relative)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error(error)),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err(StorageError::InvalidPath)
            }
            Ok(_) => self
                .read_bounded_with_limit_locked(relative, maximum_bytes)
                .map(Some),
        }
    }

    fn read_bounded_locked(&self, relative: &Path) -> Result<Vec<u8>, StorageError> {
        self.read_bounded_with_limit_locked(relative, self.max_record_bytes)
    }

    fn read_bounded_with_limit_locked(
        &self,
        relative: &Path,
        maximum_bytes: usize,
    ) -> Result<Vec<u8>, StorageError> {
        let path = self.resolve(relative)?;
        let metadata = fs::metadata(&path).map_err(io_error)?;
        let len = usize::try_from(metadata.len()).map_err(|_| StorageError::RecordTooLarge {
            actual: usize::MAX,
            maximum: maximum_bytes,
        })?;
        if len > maximum_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: len,
                maximum: maximum_bytes,
            });
        }
        // Keep allocation at the checked record length. read_to_end can grow a
        // full Vec before discovering EOF, even when a caller reserved only
        // this exact payload length under inspect_consistent.
        let mut bytes = vec![0; len];
        let mut file = fs::File::open(path).map_err(io_error)?;
        file.read_exact(&mut bytes).map_err(io_error)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra).map_err(io_error)? != 0 {
            return Err(StorageError::Io(
                "record length changed during bounded read".into(),
            ));
        }
        Ok(bytes)
    }

    fn ensure_root(&self) -> Result<(), StorageError> {
        match fs::symlink_metadata(&self.root) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                Err(StorageError::InvalidPath)
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.root).map_err(io_error)?;
                if let Some(parent) = self
                    .root
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                {
                    sync_directory(parent)?;
                }
                Ok(())
            }
            Err(error) => Err(io_error(error)),
        }
    }

    fn exclusive_lock(&self) -> Result<StoreLock, StorageError> {
        self.ensure_root()?;
        let lock_path = self.root.join(WRITER_LOCK);
        #[cfg(unix)]
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)
            .map_err(io_error)?;
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(io_error)?;
        StoreLock::exclusive(file)
    }

    fn recover_transactions_locked(&self) -> Result<(), StorageError> {
        let transactions = self.root.join(TRANSACTION_DIRECTORY);
        match fs::symlink_metadata(&transactions) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(StorageError::CorruptTransaction);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(io_error(error)),
        }
        let mut entries = fs::read_dir(&transactions)
            .map_err(io_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error)?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let file_type = entry.file_type().map_err(io_error)?;
            if !file_type.is_dir() || file_type.is_symlink() {
                return Err(StorageError::CorruptTransaction);
            }
            let directory = entry.path();
            let intent = directory.join("intent");
            match fs::symlink_metadata(&intent) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(StorageError::CorruptTransaction);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    fs::remove_dir_all(&directory).map_err(io_error)?;
                    sync_directory(&transactions)?;
                    continue;
                }
                Err(error) => return Err(io_error(error)),
            }
            let staged_directory = directory.join("staged");
            let staged_metadata = fs::symlink_metadata(&staged_directory).map_err(io_error)?;
            if staged_metadata.file_type().is_symlink() || !staged_metadata.is_dir() {
                return Err(StorageError::CorruptTransaction);
            }
            let manifest_bytes = read_file_bounded(
                &directory.join("manifest.json"),
                self.maximum_manifest_bytes,
            )?;
            let manifest: TransactionManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|_| StorageError::CorruptTransaction)?;
            if manifest.version != TRANSACTION_VERSION
                || manifest.writes.is_empty()
                || manifest.writes.len() > MAXIMUM_TRANSACTION_WRITES
            {
                return Err(StorageError::CorruptTransaction);
            }
            let mut targets = BTreeSet::new();
            for (index, write) in manifest.writes.iter().enumerate() {
                let target = self.resolve(Path::new(&write.relative_path))?;
                if !targets.insert(target.clone()) {
                    return Err(StorageError::CorruptTransaction);
                }
                let staged = staged_directory.join(format!("{index:020}"));
                match fs::symlink_metadata(&staged) {
                    Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                        return Err(StorageError::CorruptTransaction);
                    }
                    Ok(_) => {
                        let bytes = read_file_bounded(&staged, self.max_record_bytes)?;
                        write.verify(&bytes)?;
                        let parent = target.parent().ok_or(StorageError::InvalidPath)?;
                        fs::create_dir_all(parent).map_err(io_error)?;
                        fs::rename(&staged, &target).map_err(io_error)?;
                        sync_directory(parent)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        let bytes = read_file_bounded(&target, self.max_record_bytes)
                            .map_err(|_| StorageError::CorruptTransaction)?;
                        write.verify(&bytes)?;
                    }
                    Err(error) => return Err(io_error(error)),
                }
            }
            fs::remove_dir_all(&directory).map_err(io_error)?;
            sync_directory(&transactions)?;
        }
        Ok(())
    }

    fn commit_writes_locked(&self, writes: &[&StorageWrite]) -> Result<(), StorageError> {
        if writes.is_empty() || writes.len() > MAXIMUM_TRANSACTION_WRITES {
            return Err(StorageError::TooManyTransactionWrites {
                actual: writes.len(),
                maximum: MAXIMUM_TRANSACTION_WRITES,
            });
        }
        self.recover_transactions_locked()?;
        let transactions = self.root.join(TRANSACTION_DIRECTORY);
        fs::create_dir_all(&transactions).map_err(io_error)?;
        sync_directory(&self.root)?;
        let directory = loop {
            let candidate = transactions.join(format!(
                "{:010}-{:020}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_error(error)),
            }
        };
        sync_directory(&transactions)?;
        let staged = directory.join("staged");
        fs::create_dir(&staged).map_err(io_error)?;
        let mut manifest = TransactionManifest {
            version: TRANSACTION_VERSION,
            writes: Vec::with_capacity(writes.len()),
        };
        for (index, write) in writes.iter().enumerate() {
            let target = self.resolve(&write.relative_path)?;
            let relative_path = target
                .strip_prefix(&self.root)
                .map_err(|_| StorageError::InvalidPath)?
                .to_str()
                .ok_or(StorageError::InvalidPath)?
                .to_string();
            if write.bytes.len() > self.max_record_bytes {
                return Err(StorageError::RecordTooLarge {
                    actual: write.bytes.len(),
                    maximum: self.max_record_bytes,
                });
            }
            write_file_durable(&staged.join(format!("{index:020}")), &write.bytes)?;
            manifest.writes.push(TransactionManifestWrite {
                relative_path,
                length: write.bytes.len() as u64,
                digest: IntegrityDigest::of(TRANSACTION_DOMAIN, &write.bytes).0,
            });
        }
        sync_directory(&staged)?;
        let encoded =
            serde_json::to_vec(&manifest).map_err(|_| StorageError::CorruptTransaction)?;
        if encoded.len() > self.maximum_manifest_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: encoded.len(),
                maximum: self.maximum_manifest_bytes,
            });
        }
        write_file_durable(&directory.join("manifest.json"), &encoded)?;
        write_file_durable(&directory.join("intent"), b"commit")?;
        sync_directory(&directory)?;
        sync_directory(&transactions)?;
        self.recover_transactions_locked()
    }

    /// Atomically creates one or more immutable records. Identical replay is
    /// accepted, while any existing different byte sequence fails without
    /// committing the other writes. The compare and commit share the same
    /// cross-process writer lock.
    pub fn put_once_atomic(&self, writes: &[StorageWrite]) -> Result<bool, StorageError> {
        if writes.is_empty() || writes.len() > MAXIMUM_TRANSACTION_WRITES {
            return Err(StorageError::TooManyTransactionWrites {
                actual: writes.len(),
                maximum: MAXIMUM_TRANSACTION_WRITES,
            });
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let mut targets = BTreeSet::new();
        let mut missing = Vec::new();
        for write in writes {
            if write.bytes.len() > self.max_record_bytes {
                return Err(StorageError::RecordTooLarge {
                    actual: write.bytes.len(),
                    maximum: self.max_record_bytes,
                });
            }
            let target = self.resolve(&write.relative_path)?;
            if !targets.insert(target.clone()) {
                return Err(StorageError::InvalidPath);
            }
            match fs::symlink_metadata(&target) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(StorageError::InvalidPath);
                }
                Ok(_) => {
                    if self.read_bounded_locked(&write.relative_path)? != write.bytes {
                        return Err(StorageError::ConflictingWrite);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(write);
                }
                Err(error) => return Err(io_error(error)),
            }
        }
        if missing.is_empty() {
            return Ok(false);
        }
        self.commit_writes_locked(&missing)?;
        Ok(true)
    }

    pub fn prune_height_records_through(
        &self,
        relative_directory: impl AsRef<Path>,
        through_height: u64,
    ) -> Result<crate::PruneReport, StorageError> {
        if through_height == 0 {
            return Ok(crate::PruneReport::default());
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let directory = self.resolve_directory(relative_directory.as_ref())?;
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(crate::PruneReport::default());
            }
            Err(error) => return Err(io_error(error)),
        };
        let mut report = crate::PruneReport::default();
        for entry in entries {
            let entry = entry.map_err(io_error)?;
            let file_type = entry.file_type().map_err(io_error)?;
            if file_type.is_symlink() {
                return Err(StorageError::InvalidPath);
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(height) = canonical_height_file(&entry.file_name()) else {
                continue;
            };
            report.examined_records = report.examined_records.saturating_add(1);
            if height <= through_height {
                fs::remove_file(entry.path()).map_err(io_error)?;
                report.removed_records = report.removed_records.saturating_add(1);
            }
        }
        if report.removed_records > 0 {
            sync_directory(&directory)?;
        }
        Ok(report)
    }

    /// Retire at most 256 exact height paths, without enumerating retained
    /// history. The durable cursor advances only after deleted entries are
    /// directory-synced; a crash before cursor commit safely repeats the range.
    pub fn prune_height_records_incremental(
        &self,
        relative_directory: impl AsRef<Path>,
        through_height: u64,
    ) -> Result<crate::PruneReport, StorageError> {
        if through_height == 0 {
            return Ok(crate::PruneReport::default());
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        self.prune_height_records_incremental_locked(relative_directory.as_ref(), through_height)
            .map(|(report, _)| report)
    }

    /// Retire the index first, then only dependencies below the caller's safe
    /// checkpoint boundary for the index range actually completed this batch.
    /// Readers cannot see a surviving index lose its checkpoint during catch-up.
    pub fn prune_dependent_height_records_incremental(
        &self,
        index_directory: impl AsRef<Path>,
        dependent_directory: impl AsRef<Path>,
        through_height: u64,
        dependency_boundary: impl FnOnce(u64) -> Option<u64>,
    ) -> Result<crate::PruneReport, StorageError> {
        if through_height == 0 {
            return Ok(crate::PruneReport::default());
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let (index, completed) =
            self.prune_height_records_incremental_locked(index_directory.as_ref(), through_height)?;
        let completed = completed.min(through_height);
        let dependent = if let Some(boundary) = dependency_boundary(completed) {
            if boundary > completed {
                return Err(StorageError::InvalidPruneBoundary);
            }
            self.prune_height_records_incremental_locked(dependent_directory.as_ref(), boundary)?
                .0
        } else {
            crate::PruneReport::default()
        };
        Ok(crate::PruneReport {
            examined_records: index
                .examined_records
                .saturating_add(dependent.examined_records),
            removed_records: index
                .removed_records
                .saturating_add(dependent.removed_records),
        })
    }

    fn prune_height_records_incremental_locked(
        &self,
        relative: &Path,
        through_height: u64,
    ) -> Result<(crate::PruneReport, u64), StorageError> {
        const MAX_HEIGHTS: u64 = 256;
        let directory = self.resolve_directory(relative)?;
        let cursor_path = relative.join(".pruned-through");
        let cursor_file = self.resolve(&cursor_path)?;
        let previous = match fs::symlink_metadata(&cursor_file) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(io_error(error)),
            Ok(_) => {
                let bytes = read_file_bounded(&cursor_file, 8)?;
                u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| StorageError::InvalidPruneBoundary)?,
                )
            }
        };
        if previous >= through_height {
            return Ok((crate::PruneReport::default(), previous));
        }
        let end = previous.saturating_add(MAX_HEIGHTS).min(through_height);
        let mut report = crate::PruneReport::default();
        for height in previous + 1..=end {
            let target = directory.join(format!("{height:020}.json"));
            report.examined_records += 1;
            match fs::symlink_metadata(&target) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(StorageError::InvalidPath)
                }
                Ok(_) => {
                    fs::remove_file(&target).map_err(io_error)?;
                    report.removed_records += 1;
                }
            }
        }
        if report.removed_records > 0 {
            sync_directory(&directory)?;
        }
        self.write_atomic_locked(&cursor_path, &end.to_be_bytes())?;
        Ok((report, end))
    }

    /// Removes explicitly selected disposable cache records under the writer lock.
    pub fn remove_cache_records(&self, paths: &[PathBuf]) -> Result<(), StorageError> {
        if paths.len() > 260 {
            return Err(StorageError::InvalidPruneBoundary);
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let mut parents = BTreeSet::new();
        for relative in paths {
            let path = self.resolve(relative)?;
            match fs::remove_file(&path) {
                Ok(()) => {
                    parents.insert(
                        path.parent()
                            .ok_or(StorageError::InvalidPath)?
                            .to_path_buf(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        for parent in parents {
            sync_directory(&parent)?;
        }
        Ok(())
    }

    /// Incremental orphan cleanup for a caller-owned disposable cache directory.
    /// Kept records are bounded by the caller's cache index, never chain history.
    pub fn prune_cache_directory(
        &self,
        relative: &Path,
        keep: &BTreeSet<PathBuf>,
    ) -> Result<bool, StorageError> {
        if keep.len() > 260 {
            return Err(StorageError::InvalidPruneBoundary);
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let directory = self.resolve_directory(relative)?;
        let mut entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(io_error(error)),
        };
        let mut removed = 0;
        // At most all kept paths plus64 orphans can be encountered before yielding.
        while removed < 64 {
            let Some(entry) = entries.next() else {
                if removed > 0 {
                    sync_directory(&directory)?;
                }
                return Ok(true);
            };
            let entry = entry.map_err(io_error)?;
            let path = relative.join(entry.file_name());
            if keep.contains(&path) {
                continue;
            }
            let path = self.resolve(&path)?;
            if !fs::symlink_metadata(&path).map_err(io_error)?.is_file() {
                return Err(StorageError::InvalidPath);
            }
            fs::remove_file(path).map_err(io_error)?;
            removed += 1;
        }
        sync_directory(&directory)?;
        Ok(false)
    }

    fn resolve_directory(&self, relative: &Path) -> Result<PathBuf, StorageError> {
        if relative.as_os_str().is_empty() || relative.is_absolute() {
            return Err(StorageError::InvalidPath);
        }
        let components = relative.components().collect::<Vec<_>>();
        if components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StorageError::InvalidPath);
        }
        let mut resolved = self.root.clone();
        for component in components {
            let Component::Normal(component) = component else {
                return Err(StorageError::InvalidPath);
            };
            resolved.push(component);
            match fs::symlink_metadata(&resolved) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(StorageError::InvalidPath);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(resolved)
    }

    fn resolve(&self, relative: &Path) -> Result<PathBuf, StorageError> {
        if relative.as_os_str().is_empty() || relative.is_absolute() {
            return Err(StorageError::InvalidPath);
        }
        let components = relative.components().collect::<Vec<_>>();
        if components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(StorageError::InvalidPath);
        }
        let mut resolved = self.root.clone();
        for (index, component) in components.iter().enumerate() {
            let Component::Normal(component) = component else {
                return Err(StorageError::InvalidPath);
            };
            resolved.push(component);
            match fs::symlink_metadata(&resolved) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(StorageError::InvalidPath);
                }
                Ok(metadata) if index + 1 < components.len() && !metadata.is_dir() => {
                    return Err(StorageError::InvalidPath);
                }
                Ok(metadata) if index + 1 == components.len() && metadata.is_dir() => {
                    return Err(StorageError::InvalidPath);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(resolved)
    }
}

impl TransactionBackend for AtomicStore {
    fn commit_atomic(&mut self, writes: &[StorageWrite]) -> Result<(), StorageError> {
        if writes.is_empty() {
            return Err(StorageError::InvalidPath);
        }
        let _lock = self.exclusive_lock()?;
        self.commit_writes_locked(&writes.iter().collect::<Vec<_>>())
    }
}

impl GuardedTransactionBackend for AtomicStore {
    fn commit_atomic_if(
        &mut self,
        preconditions: &[StoragePrecondition],
        writes: &[StorageWrite],
    ) -> Result<(), StorageError> {
        if preconditions.is_empty() {
            return Err(StorageError::InvalidPath);
        }
        let _lock = self.exclusive_lock()?;
        self.recover_transactions_locked()?;
        let mut paths = BTreeSet::new();
        for precondition in preconditions {
            let target = self.resolve(&precondition.relative_path)?;
            if !paths.insert(target.clone()) {
                return Err(StorageError::InvalidPath);
            }
            // Resolve references before checking existence, so a malformed
            // guard cannot succeed merely because the target is absent.
            let required = match &precondition.required {
                RequiredRecord::MissingOrSameWrite => Some(
                    writes
                        .iter()
                        .find(|write| write.relative_path == precondition.relative_path)
                        .ok_or(StorageError::InvalidPath)?
                        .bytes
                        .as_slice(),
                ),
                RequiredRecord::Exact(bytes) | RequiredRecord::MissingOrExact(bytes) => {
                    Some(bytes.as_slice())
                }
                RequiredRecord::Missing => None,
            };
            if required.is_some_and(|bytes| bytes.len() > self.max_record_bytes) {
                return Err(StorageError::ConflictingWrite);
            }
            match (&precondition.required, fs::symlink_metadata(&target)) {
                (
                    RequiredRecord::Missing
                    | RequiredRecord::MissingOrExact(_)
                    | RequiredRecord::MissingOrSameWrite,
                    Err(error),
                ) if error.kind() == std::io::ErrorKind::NotFound => {}
                (
                    RequiredRecord::Exact(_)
                    | RequiredRecord::MissingOrExact(_)
                    | RequiredRecord::MissingOrSameWrite,
                    Ok(metadata),
                ) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    if self
                        .read_bounded_locked(&precondition.relative_path)?
                        .as_slice()
                        != required.ok_or(StorageError::InvalidPath)?
                    {
                        return Err(StorageError::ConflictingWrite);
                    }
                }
                (_, Err(error)) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(io_error(error));
                }
                _ => return Err(StorageError::ConflictingWrite),
            }
        }
        self.commit_writes_locked(&writes.iter().collect::<Vec<_>>())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionManifest {
    version: u32,
    writes: Vec<TransactionManifestWrite>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionManifestWrite {
    relative_path: String,
    length: u64,
    digest: String,
}

impl TransactionManifestWrite {
    fn verify(&self, bytes: &[u8]) -> Result<(), StorageError> {
        if self.length != bytes.len() as u64 {
            return Err(StorageError::CorruptTransaction);
        }
        IntegrityDigest(self.digest.clone())
            .verify(TRANSACTION_DOMAIN, bytes)
            .map_err(|_| StorageError::CorruptTransaction)
    }
}

struct StoreLock {
    file: File,
}

impl StoreLock {
    fn exclusive(file: File) -> Result<Self, StorageError> {
        #[cfg(unix)]
        loop {
            // SAFETY: `file` owns a valid descriptor for the lifetime of the lock.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(io_error(error));
            }
        }
        Ok(Self { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            // SAFETY: `self.file` still owns the descriptor while Drop runs.
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn canonical_height_file(name: &std::ffi::OsStr) -> Option<u64> {
    let name = name.to_str()?;
    let height = name.strip_suffix(".json")?;
    if height.len() != 20 || !height.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    height.parse().ok()
}

fn write_file_durable(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn read_file_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StorageError::InvalidPath);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(io_error)?
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > maximum {
        return Err(StorageError::RecordTooLarge {
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn io_error(error: std::io::Error) -> StorageError {
    StorageError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "synergy-storage-{name}-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn fixed_manifest_limit_preserves_large_payloads_and_rejects_metadata_before_intent() {
        let root = root("fixed-manifest-limit");
        let mut store = AtomicStore::new_with_manifest_limit(&root, 1024 * 1024, 4096).unwrap();
        let bytes = vec![42; 1024 * 1024];
        store
            .commit_atomic(&[StorageWrite {
                relative_path: "inputs/00.json".into(),
                bytes: bytes.clone(),
            }])
            .unwrap();
        assert_eq!(store.read_bounded("inputs/00.json").unwrap(), bytes);
        let writes = (0..64)
            .map(|i| StorageWrite {
                relative_path: format!("new/{i:04}").into(),
                bytes: vec![7],
            })
            .collect::<Vec<_>>();
        assert!(matches!(
            store.commit_atomic(&writes),
            Err(StorageError::RecordTooLarge { maximum: 4096, .. })
        ));
        assert!(!store.exists("new/0000").unwrap());
        assert_eq!(store.read_bounded("inputs/00.json").unwrap(), bytes);
        let tx = root.join(TRANSACTION_DIRECTORY).join("interrupted");
        fs::create_dir_all(tx.join("staged")).unwrap();
        fs::write(tx.join("manifest.json"), vec![b' '; 4097]).unwrap();
        fs::write(tx.join("intent"), b"commit").unwrap();
        drop(store);
        assert!(matches!(
            AtomicStore::new_with_manifest_limit(&root, 1024 * 1024, 4096),
            Err(StorageError::RecordTooLarge { maximum: 4096, .. })
        ));
        assert_eq!(fs::read(tx.join("manifest.json")).unwrap().len(), 4097);
        assert_eq!(fs::read(root.join("inputs/00.json")).unwrap(), bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn consistent_reader_keeps_dependent_records_in_one_writer_view() {
        let root = root("consistent-reader");
        let store = AtomicStore::new(&root, 1024).unwrap();
        store.write_atomic("parent", b"old").unwrap();
        let writer = AtomicStore::new(&root, 1024).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let thread = store
            .inspect_consistent(|reader| {
                let thread = std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    writer.write_atomic("parent", b"new").unwrap();
                    done_tx.send(()).unwrap();
                });
                started_rx.recv().unwrap();
                assert!(done_rx.try_recv().is_err());
                assert_eq!(
                    reader.read_optional_bounded("parent").unwrap(),
                    Some(b"old".to_vec())
                );
                assert_eq!(reader.read_optional_bounded("absent").unwrap(), None);
                thread
            })
            .unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        thread.join().unwrap();
        assert_eq!(store.read_bounded("parent").unwrap(), b"new");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_write_guard_preserves_immutable_bytes_and_rejects_unbound_guard() {
        let root = root("same-write");
        let mut store = AtomicStore::new(&root, 1024).unwrap();
        let guard = [StoragePrecondition {
            relative_path: "world".into(),
            required: RequiredRecord::MissingOrSameWrite,
        }];
        let writes = [StorageWrite {
            relative_path: "world".into(),
            bytes: vec![1; 1024],
        }];
        assert_eq!(
            store.commit_atomic_if(&guard, &[]),
            Err(StorageError::InvalidPath)
        );
        assert!(!store.exists("world").unwrap());
        store.commit_atomic_if(&guard, &writes).unwrap();
        store.commit_atomic_if(&guard, &writes).unwrap();
        let conflict = [
            StorageWrite {
                relative_path: "world".into(),
                bytes: vec![2; 1024],
            },
            StorageWrite {
                relative_path: "must-not-commit".into(),
                bytes: vec![3],
            },
        ];
        assert_eq!(
            store.commit_atomic_if(&guard, &conflict),
            Err(StorageError::ConflictingWrite)
        );
        assert_eq!(store.read_bounded("world").unwrap(), writes[0].bytes);
        assert!(!store.exists("must-not-commit").unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_batch_replay_checks_all_records_before_writing_any() {
        let root = root("immutable-batch");
        let store = AtomicStore::new(&root, 1024).unwrap();
        let writes = [StorageWrite {
            relative_path: "first".into(),
            bytes: vec![1; 1024],
        }];
        assert!(store.put_once_atomic(&writes).unwrap());
        assert!(!store.put_once_atomic(&writes).unwrap());
        let mixed = [
            StorageWrite {
                relative_path: "second".into(),
                bytes: vec![2; 1024],
            },
            StorageWrite {
                relative_path: "first".into(),
                bytes: vec![3; 1024],
            },
        ];
        assert_eq!(
            store.put_once_atomic(&mixed),
            Err(StorageError::ConflictingWrite)
        );
        assert!(!store.exists("second").unwrap());
        let valid = [mixed[0].clone(), writes[0].clone()];
        assert!(store.put_once_atomic(&valid).unwrap());
        assert_eq!(store.read_bounded("second").unwrap(), mixed[0].bytes);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disposable_cache_cleanup_is_bounded_and_rejects_traversal() {
        let root = root("cache-cleanup");
        let store = AtomicStore::new(&root, 64).unwrap();
        fs::create_dir(root.join("cache")).unwrap();
        fs::write(root.join("outside"), b"preserve").unwrap();
        for i in 0..150 {
            fs::write(root.join(format!("cache/{i}.json")), b"cache").unwrap();
        }
        let keep = BTreeSet::from([PathBuf::from("cache/0.json")]);
        assert!(!store
            .prune_cache_directory(Path::new("cache"), &keep)
            .unwrap());
        assert_eq!(fs::read_dir(root.join("cache")).unwrap().count(), 86);
        while !store
            .prune_cache_directory(Path::new("cache"), &keep)
            .unwrap()
        {}
        assert_eq!(fs::read_dir(root.join("cache")).unwrap().count(), 1);
        assert_eq!(
            store.remove_cache_records(&["../outside".into()]),
            Err(StorageError::InvalidPath)
        );
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("outside"), root.join("cache/link")).unwrap();
            assert_eq!(
                store.prune_cache_directory(Path::new("cache"), &keep),
                Err(StorageError::InvalidPath)
            );
        }
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"preserve");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn optional_read_tolerates_retirement_but_rejects_invalid_and_oversized_records() {
        let root = root("optional");
        let store = AtomicStore::new(&root, 3).unwrap();
        assert_eq!(store.read_optional_bounded("retired").unwrap(), None);
        store.write_atomic("record", b"one").unwrap();
        assert_eq!(
            store.read_optional_bounded("record").unwrap(),
            Some(b"one".to_vec())
        );
        store
            .inspect_consistent(|reader| {
                assert_eq!(reader.optional_record_bytes("record").unwrap(), Some(3));
                assert_eq!(reader.optional_record_bytes("absent").unwrap(), None);
                assert_eq!(
                    reader.optional_record_bytes("../escape"),
                    Err(StorageError::InvalidPath)
                );
                assert!(matches!(
                    reader.with_maximum_bytes(2).optional_record_bytes("record"),
                    Err(StorageError::RecordTooLarge { maximum: 2, .. })
                ));
                #[cfg(unix)]
                {
                    std::os::unix::fs::symlink(root.join("record"), root.join("link")).unwrap();
                    assert_eq!(
                        reader.optional_record_bytes("link"),
                        Err(StorageError::InvalidPath)
                    );
                }
                assert!(matches!(
                    reader.with_maximum_bytes(2).read_optional_bounded("record"),
                    Err(StorageError::RecordTooLarge { maximum: 2, .. })
                ));
                assert_eq!(
                    reader
                        .with_maximum_bytes(8)
                        .read_optional_bounded("record")
                        .unwrap(),
                    Some(b"one".to_vec())
                );
            })
            .unwrap();
        fs::remove_file(root.join("record")).unwrap();
        assert_eq!(store.read_optional_bounded("record").unwrap(), None);
        fs::write(root.join("record"), b"four").unwrap();
        assert!(matches!(
            store.read_optional_bounded("record"),
            Err(StorageError::RecordTooLarge { .. })
        ));
        assert_eq!(
            store.read_optional_bounded("../escape"),
            Err(StorageError::InvalidPath)
        );
        fs::create_dir(root.join("directory")).unwrap();
        assert_eq!(
            store.read_optional_bounded("directory"),
            Err(StorageError::InvalidPath)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn incremental_retirement_bounds_work_and_resumes_exact_range_after_restart() {
        let root = root("incremental-retirement");
        let store = AtomicStore::new(&root, 64).unwrap();
        let directory = root.join("history");
        fs::create_dir_all(&directory).unwrap();
        for height in [1u64, 256, 257, 600, 601, 50_000] {
            fs::write(directory.join(format!("{height:020}.json")), b"original").unwrap();
        }
        let first = store
            .prune_height_records_incremental("history", 600)
            .unwrap();
        assert_eq!(first.examined_records, 256);
        assert_eq!(first.removed_records, 2);
        assert!(directory.join(format!("{:020}.json", 257)).exists());
        drop(store);
        let store = AtomicStore::new(&root, 64).unwrap();
        let second = store
            .prune_height_records_incremental("history", 600)
            .unwrap();
        assert_eq!(second.examined_records, 256);
        assert_eq!(second.removed_records, 1);
        // Simulate a crash after deleting a record but before cursor commit.
        fs::remove_file(directory.join(format!("{:020}.json", 600))).unwrap();
        let third = store
            .prune_height_records_incremental("history", 600)
            .unwrap();
        assert_eq!(third.examined_records, 88);
        assert_eq!(
            store
                .prune_height_records_incremental("history", 600)
                .unwrap(),
            crate::PruneReport::default()
        );
        assert_eq!(
            store
                .prune_height_records_incremental("history", 500)
                .unwrap(),
            crate::PruneReport::default()
        );
        assert!(directory.join(format!("{:020}.json", 601)).exists());
        assert!(directory.join(format!("{:020}.json", 50_000)).exists());
        assert_eq!(
            store
                .prune_height_records_incremental("history", 601)
                .unwrap()
                .examined_records,
            1
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn incremental_retirement_rejects_symlinks_and_invalid_cursor_without_advancing() {
        let root = root("retirement-invalid");
        let store = AtomicStore::new(&root, 64).unwrap();
        fs::create_dir(root.join("history")).unwrap();
        fs::write(root.join("keep"), b"keep").unwrap();
        std::os::unix::fs::symlink(
            root.join("keep"),
            root.join("history/00000000000000000001.json"),
        )
        .unwrap();
        assert_eq!(
            store.prune_height_records_incremental("history", 10),
            Err(StorageError::InvalidPath)
        );
        assert!(!root.join("history/.pruned-through").exists());
        assert_eq!(fs::read(root.join("keep")).unwrap(), b"keep");
        fs::remove_file(root.join("history/00000000000000000001.json")).unwrap();
        fs::write(root.join("history/.pruned-through"), b"bad").unwrap();
        assert_eq!(
            store.prune_height_records_incremental("history", 10),
            Err(StorageError::InvalidPruneBoundary)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_replacement_is_durable_and_readable() {
        let root = root("atomic");
        let store = AtomicStore::new(&root, 64).unwrap();
        store.write_atomic("safety/journal", b"one").unwrap();
        store.write_atomic("safety/journal", b"two").unwrap();
        assert_eq!(store.read_bounded("safety/journal").unwrap(), b"two");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn traversal_and_oversize_records_are_rejected() {
        let root = root("reject");
        let store = AtomicStore::new(&root, 3).unwrap();
        assert_eq!(
            store.write_atomic("../escape", b"x"),
            Err(StorageError::InvalidPath)
        );
        assert_eq!(
            store.write_atomic("safe", b"four"),
            Err(StorageError::RecordTooLarge {
                actual: 4,
                maximum: 3
            })
        );
    }

    #[test]
    fn read_rejects_record_larger_than_bound() {
        let root = root("read-bound");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("record"), b"12345").unwrap();
        let store = AtomicStore::new(&root, 4).unwrap();
        assert_eq!(
            store.read_bounded("record"),
            Err(StorageError::RecordTooLarge {
                actual: 5,
                maximum: 4
            })
        );
        fs::remove_dir_all(root).unwrap();
    }
}
