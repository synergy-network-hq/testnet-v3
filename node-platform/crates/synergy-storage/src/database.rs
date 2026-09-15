use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
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

impl AtomicStore {
    pub fn new(root: impl Into<PathBuf>, max_record_bytes: usize) -> Result<Self, StorageError> {
        if max_record_bytes == 0 {
            return Err(StorageError::RecordTooLarge {
                actual: 1,
                maximum: 0,
            });
        }
        let result = Self {
            root: root.into(),
            max_record_bytes,
        };
        result.ensure_root()?;
        {
            let _lock = result.exclusive_lock()?;
            result.recover_transactions_locked()?;
        }
        Ok(result)
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

    fn read_bounded_locked(&self, relative: &Path) -> Result<Vec<u8>, StorageError> {
        let path = self.resolve(relative)?;
        let metadata = fs::metadata(&path).map_err(io_error)?;
        let len = usize::try_from(metadata.len()).map_err(|_| StorageError::RecordTooLarge {
            actual: usize::MAX,
            maximum: self.max_record_bytes,
        })?;
        if len > self.max_record_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: len,
                maximum: self.max_record_bytes,
            });
        }
        let mut bytes = Vec::with_capacity(len);
        fs::File::open(path)
            .map_err(io_error)?
            .take((self.max_record_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(io_error)?;
        if bytes.len() > self.max_record_bytes {
            return Err(StorageError::RecordTooLarge {
                actual: bytes.len(),
                maximum: self.max_record_bytes,
            });
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
                self.max_record_bytes.saturating_mul(2),
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

    fn commit_writes_locked(&self, writes: &[StorageWrite]) -> Result<(), StorageError> {
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
                    missing.push(write.clone());
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
        self.commit_writes_locked(writes)
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
            match (&precondition.required, fs::symlink_metadata(&target)) {
                (RequiredRecord::Missing | RequiredRecord::MissingOrExact(_), Err(error))
                    if error.kind() == std::io::ErrorKind::NotFound => {}
                (
                    RequiredRecord::Exact(expected) | RequiredRecord::MissingOrExact(expected),
                    Ok(metadata),
                ) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    if expected.len() > self.max_record_bytes
                        || self.read_bounded_locked(&precondition.relative_path)? != *expected
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
        self.commit_writes_locked(writes)
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
