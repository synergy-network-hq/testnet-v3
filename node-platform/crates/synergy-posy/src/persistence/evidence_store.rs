//! Indexed historical evidence. SQLite pages replace individual message files;
//! protocol owners still authenticate every record before granting authority.
//! Existing JSON is read in place, never removed or silently rewritten.
use super::archive_segments::{self, Location, Segments};
use crate::{PosyError, PosyResult};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use synergy_storage::{AtomicStore, StorageWrite};

pub(crate) const ARCHIVE_FILE: &str = "consensus-evidence-v1.sqlite3";
const MAX_BYTES: usize = 16 * 1024 * 1024;
const FORMAT: i64 = 2;

#[derive(Debug, Clone)]
pub(crate) struct EvidenceStore {
    connection: std::sync::Arc<Mutex<Connection>>,
    legacy: AtomicStore,
    segments: std::sync::Arc<Mutex<Segments>>,
}

type SharedConnection = std::sync::Arc<Mutex<Connection>>;
type WeakConnection = std::sync::Weak<Mutex<Connection>>;
type WeakSegments = std::sync::Weak<Mutex<Segments>>;
type StoredEvidence = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);
type ArchiveObjects = std::collections::BTreeMap<[u8; 32], (u8, Vec<u8>)>;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordBinding {
    key: String,
    object_hash: [u8; 32],
    digest: [u8; 32],
    legacy_digest: Option<[u8; 32]>,
    bytes: usize,
    revision: bool,
}
static CONNECTIONS: std::sync::OnceLock<
    Mutex<std::collections::BTreeMap<PathBuf, (WeakConnection, WeakSegments)>>,
> = std::sync::OnceLock::new();

impl EvidenceStore {
    pub(crate) fn open(root: impl Into<PathBuf>) -> PosyResult<Self> {
        Self::open_mode(root.into(), false)
    }
    fn open_mode(root: PathBuf, rebuild: bool) -> PosyResult<Self> {
        let legacy = AtomicStore::new(&root, MAX_BYTES).map_err(storage_error)?;
        // Refuse symlinks, including SQLite's own recovery sidecars. The root
        // is private application state, never an attacker-writable directory.
        for path in [
            &root,
            &root.join(ARCHIVE_FILE),
            &root.join(format!("{ARCHIVE_FILE}-journal")),
            &root.join(format!("{ARCHIVE_FILE}-wal")),
            &root.join(format!("{ARCHIVE_FILE}-shm")),
        ] {
            match fs::symlink_metadata(path) {
                Ok(m) if m.file_type().is_symlink() || (path != &root && !m.is_file()) => {
                    return Err(PosyError::invalid("non-regular consensus archive path"))
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(PosyError::NotReady(e.to_string())),
            }
        }
        // macOS /var is itself a system symlink. Canonicalize the already
        // validated private root before SQLite's component-wise NOFOLLOW check.
        let root = root
            .canonicalize()
            .map_err(|e| PosyError::NotReady(e.to_string()))?;
        let mut connections = CONNECTIONS
            .get_or_init(|| Mutex::new(std::collections::BTreeMap::new()))
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned archive connection registry".into()))?;
        connections.retain(|_, (connection, segments)| {
            connection.strong_count() > 0 && segments.strong_count() > 0
        });
        if let Some((connection, segments)) = connections
            .get(&root)
            .and_then(|(connection, segments)| connection.upgrade().zip(segments.upgrade()))
        {
            if rebuild {
                return Err(PosyError::NotReady(
                    "offline reindex requires all archive owners closed".into(),
                ));
            }
            return Ok(Self {
                connection,
                legacy,
                segments,
            });
        }
        let existed = root.join(ARCHIVE_FILE).exists();
        if !rebuild
            && !existed
            && root
                .join("archive/segment-00000000000000000001.sya")
                .exists()
        {
            return Err(PosyError::invalid(
                "consensus archive exists without index; explicit offline rebuild required",
            ));
        }
        if existed
            && fs::metadata(root.join(ARCHIVE_FILE))
                .map_err(|e| PosyError::NotReady(e.to_string()))?
                .len()
                == 0
        {
            return Err(PosyError::invalid(
                "empty existing consensus archive; recover from authenticated backup",
            ));
        }
        if !existed {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options
                .open(root.join(ARCHIVE_FILE))
                .map_err(archive_error)?;
        }
        let connection = Connection::open_with_flags(
            root.join(ARCHIVE_FILE),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql_error)?;
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_BYTES + 4096) as i32,
        );
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(sql_error)?;
        // Rollback journal works on local Linux filesystems without persistent
        // WAL reader pins. EXTRA syncs the containing directory after unlink;
        // fullfsync additionally requests the stronger macOS barrier.
        connection
            .execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;
            PRAGMA fullfsync=ON; PRAGMA mmap_size=0; PRAGMA cache_size=-512;
            PRAGMA temp_store=FILE; PRAGMA cell_size_check=ON;",
            )
            .map_err(sql_error)?;
        let version: i64 = connection
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql_error)?;
        if version != 0 && version != 1 && version != FORMAT {
            return Err(PosyError::invalid("unsupported consensus archive version"));
        }
        connection.execute_batch("BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS evidence (
                key TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL, digest BLOB NOT NULL,
                legacy_digest BLOB, height TEXT
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS revisions (
                key TEXT NOT NULL, digest BLOB NOT NULL, bytes BLOB NOT NULL,
                PRIMARY KEY(key,digest)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS legacy_timeout (
                key TEXT PRIMARY KEY NOT NULL, height TEXT NOT NULL, bytes INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS legacy_timeout_height ON legacy_timeout(height,key);
            CREATE INDEX IF NOT EXISTS timeout_height ON evidence(height,key) WHERE height IS NOT NULL;
            CREATE TABLE IF NOT EXISTS archive_objects (
                hash BLOB PRIMARY KEY NOT NULL, kind INTEGER NOT NULL, segment INTEGER NOT NULL,
                offset INTEGER NOT NULL, length INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS archive_records (
                key TEXT PRIMARY KEY NOT NULL, object_hash BLOB NOT NULL, digest BLOB NOT NULL,
                legacy_digest BLOB, height TEXT, bytes INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS archive_timeout_height ON archive_records(height,key) WHERE height IS NOT NULL;
            CREATE TABLE IF NOT EXISTS archive_revisions (
                key TEXT NOT NULL, digest BLOB NOT NULL, object_hash BLOB NOT NULL,
                PRIMARY KEY(key,digest)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS archive_segments (
                segment INTEGER PRIMARY KEY, committed_bytes INTEGER NOT NULL, sealed INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS archive_finality (
                height TEXT PRIMARY KEY NOT NULL, finality_hash BLOB NOT NULL,
                qc1_hash BLOB NOT NULL, qc2_hash BLOB NOT NULL, qc3_hash BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS hot_evidence (
                key TEXT PRIMARY KEY NOT NULL, bytes BLOB NOT NULL, digest BLOB NOT NULL,
                legacy_digest BLOB, height TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS hot_evidence_height ON hot_evidence(height,key);
            CREATE TABLE IF NOT EXISTS archive_lifecycle (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), floor TEXT NOT NULL
            );
            INSERT OR IGNORE INTO archive_lifecycle VALUES(1,'00000000000000000000');
            PRAGMA user_version=2; COMMIT;").map_err(sql_error)?;
        let rebuilt = if rebuild {
            connection.execute_batch("BEGIN IMMEDIATE; DELETE FROM archive_objects; DELETE FROM archive_records;
                DELETE FROM archive_revisions; DELETE FROM archive_segments; DELETE FROM archive_finality;").map_err(sql_error)?;
            let last = archive_segments::scan(
                &root.join("archive"),
                |location, bytes| {
                    insert_location(&connection, &location)
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    if location.kind == archive_segments::BATCH_COMMIT {
                        for hash in archive_segments::batch_bindings(&bytes)? {
                            let location = location_for_hash(&connection, &hash)
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            if location.kind != archive_segments::RECORD_BINDING {
                                return Err(std::io::Error::other(
                                    "batch footer references nonbinding",
                                ));
                            }
                            let encoded =
                                archive_segments::read_location(&root.join("archive"), &location)?;
                            let binding: RecordBinding =
                                serde_json::from_slice(&encoded).map_err(std::io::Error::other)?;
                            key(Path::new(&binding.key))
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                            if binding.bytes > MAX_BYTES {
                                return Err(std::io::Error::other("oversized record binding"));
                            }
                            Self::publish_binding(&connection, &binding)
                                .map_err(|e| std::io::Error::other(e.to_string()))?;
                        }
                    }
                    Ok(())
                },
                |id, length, sealed| {
                    insert_segment(&connection, id, length, sealed)
                        .map_err(|e| std::io::Error::other(e.to_string()))
                },
            )
            .map_err(archive_error)?;
            Some(if last.2 {
                (last.0 + 1, 0)
            } else {
                (last.0, last.1)
            })
        } else {
            None
        };
        let (last_segment, committed): (u64, u64) = if let Some(last) = rebuilt {
            last
        } else {
            connection.query_row(
            "SELECT segment,committed_bytes FROM archive_segments ORDER BY segment DESC LIMIT 1", [],
            |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(sql_error)?.unwrap_or((1,0))
        };
        if !rebuild && committed == 0 {
            let indexed: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM archive_objects LIMIT 1)",
                    [],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if indexed {
                return Err(PosyError::invalid(
                    "archive segment metadata missing; explicit offline rebuild required",
                ));
            }
            if fs::metadata(root.join("archive/segment-00000000000000000001.sya"))
                .is_ok_and(|metadata| metadata.len() > 16)
            {
                return Err(PosyError::invalid(
                    "unindexed consensus archive requires explicit offline rebuild",
                ));
            }
        }
        let (segments, recovered, states) =
            Segments::open(&root.join("archive"), last_segment, committed)
                .map_err(archive_error)?;
        if !rebuild {
            connection
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(sql_error)?;
        }
        for location in recovered {
            insert_location(&connection, &location)?;
        }
        for (id, length, sealed) in states {
            insert_segment(&connection, id, length, sealed)?;
        }
        if !rebuild {
            connection.execute_batch("COMMIT").map_err(sql_error)?;
        }
        fs::File::open(&root)
            .and_then(|f| f.sync_all())
            .map_err(|e| PosyError::NotReady(e.to_string()))?;
        let connection: SharedConnection = std::sync::Arc::new(Mutex::new(connection));
        let segments = std::sync::Arc::new(Mutex::new(segments));
        let store = Self {
            connection: connection.clone(),
            legacy,
            segments: segments.clone(),
        };
        if rebuild {
            let connection = connection
                .lock()
                .map_err(|_| PosyError::NotReady("poisoned offline reindex".into()))?;
            store.verify_cold_index(&connection)?;
            rebuild_finality_refs(&connection)?;
            connection.execute_batch("COMMIT").map_err(sql_error)?;
        }
        connections.insert(
            root,
            (
                std::sync::Arc::downgrade(&connection),
                std::sync::Arc::downgrade(&segments),
            ),
        );
        Ok(store)
    }
    fn verify_cold_index(&self, connection: &Connection) -> PosyResult<()> {
        let mut after = String::new();
        loop {
            let mut query=connection.prepare("SELECT key,object_hash,digest,legacy_digest,bytes FROM archive_records WHERE key>?1 ORDER BY key LIMIT 64").map_err(sql_error)?;
            let rows = query
                .query_map([&after], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                        row.get::<_, u64>(4)?,
                    ))
                })
                .map_err(sql_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_error)?;
            if rows.is_empty() {
                break;
            }
            for (key, object, digest, legacy, size) in rows {
                let bytes = self.decoded_object(connection, &object)?;
                if bytes.len() as u64 != size || hash(&key, &bytes) != digest {
                    return Err(PosyError::invalid(
                        "offline rebuild record bytes/digest mismatch",
                    ));
                }
                if let Some(original) = self
                    .legacy
                    .read_optional_bounded(&key)
                    .map_err(storage_error)?
                {
                    let expected = legacy.as_ref().unwrap_or(&digest);
                    if *expected != hash(&key, &original) {
                        return Err(PosyError::invalid("offline rebuild legacy binding changed"));
                    }
                }
                after = key;
            }
        }
        let mut after_key = String::new();
        let mut after_digest = Vec::<u8>::new();
        loop {
            let mut query=connection.prepare("SELECT key,digest,object_hash FROM archive_revisions WHERE key>?1 OR (key=?1 AND digest>?2) ORDER BY key,digest LIMIT 64").map_err(sql_error)?;
            let rows = query
                .query_map(params![after_key, after_digest], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(sql_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_error)?;
            if rows.is_empty() {
                break;
            }
            for (key, digest, object) in rows {
                let bytes = self.decoded_object(connection, &object)?;
                if hash(&key, &bytes) != digest {
                    return Err(PosyError::invalid(
                        "offline rebuild revision digest mismatch",
                    ));
                }
                after_key = key;
                after_digest = digest;
            }
        }
        Ok(())
    }

    fn object(&self, connection: &Connection, hash: &[u8]) -> PosyResult<(u8, Vec<u8>)> {
        let location = connection
            .query_row(
                "SELECT kind,segment,offset,length FROM archive_objects WHERE hash=?1",
                [hash],
                |row| {
                    Ok((
                        row.get::<_, u8>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, usize>(3)?,
                    ))
                },
            )
            .map_err(sql_error)?;
        if hash.len() != 32 || location.3 > MAX_BYTES || location.2 < 16 {
            return Err(PosyError::invalid("invalid archive object locator"));
        }
        let location = Location {
            hash: hash.try_into().unwrap(),
            kind: location.0,
            segment: location.1,
            offset: location.2,
            length: location.3,
        };
        let bytes = self
            .segments
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned archive writer".into()))?
            .read(&location)
            .map_err(archive_error)?;
        Ok((location.kind, bytes))
    }
    fn decoded_object(&self, connection: &Connection, hash: &[u8]) -> PosyResult<Vec<u8>> {
        let (kind, bytes) = self.object(connection, hash)?;
        self.decode_payload(connection, kind, &bytes)
    }
    fn decode_payload(
        &self,
        connection: &Connection,
        kind: u8,
        bytes: &[u8],
    ) -> PosyResult<Vec<u8>> {
        archive_segments::decode(kind, bytes, |hash| {
            let (kind, bytes) = self
                .object(connection, hash)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            if kind != archive_segments::BYTE_ARRAY {
                return Err(std::io::Error::other(
                    "template dependency is not byte array",
                ));
            }
            Ok(bytes)
        })
        .map_err(archive_error)
    }
    fn stage_record(
        &self,
        key: &str,
        bytes: &[u8],
        revision: bool,
        objects: &mut ArchiveObjects,
    ) -> PosyResult<RecordBinding> {
        let (object_hash, encoded) = archive_segments::encode(bytes);
        objects.extend(encoded);
        let legacy_digest = self
            .legacy
            .read_optional_bounded(key)
            .map_err(storage_error)?
            .map(|bytes| hash(key, &bytes).try_into().unwrap());
        let binding = RecordBinding {
            key: key.into(),
            object_hash,
            digest: hash(key, bytes).try_into().unwrap(),
            legacy_digest,
            bytes: bytes.len(),
            revision,
        };
        let encoded =
            serde_json::to_vec(&binding).map_err(|e| PosyError::invalid(e.to_string()))?;
        objects.insert(
            archive_segments::object_hash(archive_segments::RECORD_BINDING, &encoded),
            (archive_segments::RECORD_BINDING, encoded),
        );
        Ok(binding)
    }
    fn persist_objects(&self, connection: &Connection, objects: ArchiveObjects) -> PosyResult<()> {
        let bindings = objects
            .iter()
            .filter_map(|(hash, (kind, _))| {
                (*kind == archive_segments::RECORD_BINDING).then_some(*hash)
            })
            .collect::<Vec<_>>();
        let footer = archive_segments::batch_footer(&bindings).map_err(archive_error)?;
        let marker = archive_segments::object_hash(archive_segments::BATCH_COMMIT, &footer);
        let committed: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM archive_objects WHERE hash=?1)",
                [marker.as_slice()],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let mut pending = ArchiveObjects::new();
        for (hash, object) in objects {
            let exists: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM archive_objects WHERE hash=?1)",
                    [hash.as_slice()],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            if !exists {
                pending.insert(hash, object);
            }
        }
        if pending.is_empty() && (bindings.is_empty() || committed) {
            return Ok(());
        }
        let aggregate = pending
            .values()
            .try_fold(0usize, |sum, (_, bytes)| sum.checked_add(bytes.len() + 44))
            .and_then(|sum| {
                sum.checked_add(if bindings.is_empty() {
                    0
                } else {
                    footer.len() + 44
                })
            })
            .ok_or_else(|| {
                PosyError::ResourcePressure("archive transaction byte overflow".into())
            })?;
        if aggregate > 32 * 1024 * 1024 {
            return Err(PosyError::ResourcePressure(
                "archive transaction exceeds32MiB; import legacy proofs in smaller offline batches"
                    .into(),
            ));
        }
        #[cfg(test)]
        archive_crash_checkpoint("before-append");
        let (locations, segments) = self
            .segments
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned archive writer".into()))?
            .append(&pending, &bindings)
            .map_err(archive_error)?;
        #[cfg(test)]
        archive_crash_checkpoint("after-append");
        for location in locations {
            insert_location(connection, &location)?;
        }
        for (id, length, sealed) in segments {
            insert_segment(connection, id, length, sealed)?;
        }
        Ok(())
    }
    fn publish_binding(connection: &Connection, binding: &RecordBinding) -> PosyResult<()> {
        if binding.revision {
            connection.execute("INSERT OR IGNORE INTO archive_revisions(key,digest,object_hash) VALUES(?1,?2,?3)",
                params![binding.key,binding.digest.as_slice(),binding.object_hash.as_slice()]).map_err(sql_error)?;
        } else {
            connection.execute("INSERT INTO archive_records(key,object_hash,digest,legacy_digest,height,bytes) VALUES(?1,?2,?3,?4,?5,?6)
                ON CONFLICT(key) DO UPDATE SET object_hash=excluded.object_hash,digest=excluded.digest,bytes=excluded.bytes
                WHERE object_hash<>excluded.object_hash OR digest<>excluded.digest OR bytes<>excluded.bytes",
                params![binding.key,binding.object_hash.as_slice(),binding.digest.as_slice(),binding.legacy_digest.as_ref().map(|v|v.as_slice()),height_key(&binding.key),binding.bytes as u64]).map_err(sql_error)?;
        }
        Ok(())
    }

    pub(crate) fn get(&self, path: impl AsRef<Path>) -> PosyResult<Option<Vec<u8>>> {
        let key = key(path.as_ref())?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let transaction = connection.transaction().map_err(sql_error)?;
        let result = self.read(&transaction, &key)?;
        transaction.commit().map_err(sql_error)?;
        Ok(result)
    }

    fn read(&self, connection: &Connection, key: &str) -> PosyResult<Option<Vec<u8>>> {
        let hot: Option<StoredEvidence> = connection
            .query_row(
                "SELECT bytes,digest,legacy_digest FROM hot_evidence WHERE key=?1",
                [key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(sql_error)?;
        let cold: Option<StoredEvidence> = if hot.is_none() {
            connection
                .query_row(
                    "SELECT object_hash,digest,legacy_digest FROM archive_records WHERE key=?1",
                    [key],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(sql_error)?
        } else {
            None
        };
        if let Some((value, digest, legacy_digest)) = hot.or_else(|| cold.clone()) {
            let bytes = if cold.is_some() {
                self.decoded_object(connection, &value)?
            } else if value.starts_with(b"SNPHT002") {
                let kind = *value
                    .get(8)
                    .ok_or_else(|| PosyError::invalid("truncated hot payload"))?;
                self.decode_payload(connection, kind, &value[9..])?
            } else {
                value
            };
            validate_bytes(&bytes)?;
            let legacy = self
                .legacy
                .read_optional_bounded(key)
                .map_err(storage_error)?;
            if digest != hash(key, &bytes)
                || legacy.as_ref().is_some_and(|original| {
                    let original_hash = hash(key, original);
                    legacy_digest
                        .as_ref()
                        .map_or(original_hash != digest, |expected| {
                            *expected != original_hash
                        })
                })
            {
                return Err(PosyError::invalid(
                    "archive record or legacy binding mismatch",
                ));
            }
            return Ok(Some(bytes));
        }
        let saved: Option<(i64, Vec<u8>, Option<Vec<u8>>)> = connection
            .query_row(
                "SELECT length(bytes),digest,legacy_digest FROM evidence WHERE key=?1",
                [key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(sql_error)?;
        let legacy = self
            .legacy
            .read_optional_bounded(key)
            .map_err(storage_error)?;
        let Some((size, digest, legacy_digest)) = saved else {
            return Ok(legacy);
        };
        if !(0..=MAX_BYTES as i64).contains(&size) {
            return Err(PosyError::invalid("oversized archived evidence"));
        }
        let bytes: Vec<u8> = connection
            .query_row("SELECT bytes FROM evidence WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .map_err(sql_error)?;
        if digest != hash(key, &bytes)
            || legacy.as_ref().is_some_and(|b| {
                let digest = hash(key, b);
                legacy_digest
                    .as_ref()
                    .map_or(digest != hash(key, &bytes), |original| *original != digest)
            })
        {
            return Err(PosyError::invalid(
                "consensus evidence integrity or legacy binding mismatch",
            ));
        }
        Ok(Some(bytes))
    }

    /// One durable transaction for all immutable records. Every conflict is
    /// checked before any insert; commit success is the only acknowledgement.
    pub(crate) fn put_once_atomic(&self, writes: &[StorageWrite]) -> PosyResult<bool> {
        self.put_internal(writes, None, false)
    }
    pub(crate) fn commit_finality_atomic(
        &self,
        writes: &[StorageWrite],
        height: u64,
    ) -> PosyResult<bool> {
        self.put_internal(writes, Some(height), false)
    }
    fn put_internal(
        &self,
        writes: &[StorageWrite],
        finality_height: Option<u64>,
        force_cold: bool,
    ) -> PosyResult<bool> {
        if writes.is_empty() || writes.len() > 64 {
            return Err(PosyError::invalid("invalid evidence batch"));
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let mut pending = std::collections::BTreeMap::new();
        let mut changed = false;
        let mut batch_bytes = 0usize;
        for write in writes {
            let key = key(&write.relative_path)?;
            validate_bytes(&write.bytes)?;
            batch_bytes = batch_bytes.checked_add(write.bytes.len()).ok_or_else(|| {
                PosyError::ResourcePressure("evidence batch byte overflow".into())
            })?;
            if batch_bytes > 32 * 1024 * 1024 {
                return Err(PosyError::ResourcePressure(
                    "evidence batch exceeds 32MiB".into(),
                ));
            }
            if pending
                .insert(key.clone(), &write.bytes)
                .is_some_and(|prior| prior != &write.bytes)
            {
                return Err(PosyError::Conflict(
                    "conflicting evidence batch keys".into(),
                ));
            }
            match self.read(&transaction, &key)? {
                Some(prior) if prior != write.bytes => {
                    return Err(PosyError::Conflict(
                        "conflicting immutable consensus evidence".into(),
                    ))
                }
                Some(_) => (),
                None => changed = true,
            }
        }
        let mut objects = ArchiveObjects::new();
        let mut bindings = Vec::new();
        for (key, bytes) in pending {
            if ready_height(&key).is_some() && !force_cold {
                self.publish_hot(&transaction, &key, bytes, &mut objects)?;
            } else {
                bindings.push(self.stage_record(&key, bytes, false, &mut objects)?);
            }
        }
        let mut finality_refs = None;
        if let Some(height) = finality_height {
            let finality_key = format!("finality/h{height}.json");
            let mut refs = Vec::with_capacity(4);
            for key in std::iter::once(finality_key)
                .chain((0..3).map(|offset| format!("verified-qcs/qc/{:020}.json", height + offset)))
            {
                if let Some(binding) = bindings.iter().find(|binding| binding.key == key) {
                    refs.push(binding.object_hash);
                } else {
                    let archived: Option<Vec<u8>> = transaction
                        .query_row(
                            "SELECT object_hash FROM archive_records WHERE key=?1",
                            [&key],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(sql_error)?;
                    if let Some(archived) = archived {
                        refs.push(
                            archived
                                .try_into()
                                .map_err(|_| PosyError::invalid("invalid finality object hash"))?,
                        );
                        continue;
                    }
                    let original = self.read(&transaction, &key)?.ok_or_else(|| {
                        PosyError::invalid("finality index lacks exact QC record")
                    })?;
                    let binding = self.stage_record(&key, &original, false, &mut objects)?;
                    refs.push(binding.object_hash);
                    bindings.push(binding);
                }
            }
            finality_refs = Some((height, refs));
        }
        // One aggregate append bound covers the whole SQL transaction,
        // including legacy QC promotion. A failed capacity check appends none.
        self.persist_objects(&transaction, objects)?;
        for binding in bindings {
            Self::publish_binding(&transaction, &binding)?;
        }
        if let Some((height, refs)) = finality_refs {
            transaction.execute("INSERT OR IGNORE INTO archive_finality(height,finality_hash,qc1_hash,qc2_hash,qc3_hash) VALUES(?1,?2,?3,?4,?5)",
                params![format!("{height:020}"),refs[0].as_slice(),refs[1].as_slice(),refs[2].as_slice(),refs[3].as_slice()]).map_err(sql_error)?;
        }
        #[cfg(test)]
        archive_crash_checkpoint("before-index-commit");
        transaction.commit().map_err(sql_error)?;
        #[cfg(test)]
        archive_crash_checkpoint("after-index-commit");
        Ok(changed)
    }

    /// Mutable *locator* updates only, authorized by the PoSy caller. All old
    /// exact bytes remain immutable in revisions; stale owners fail the CAS.
    pub(crate) fn replace_guarded(
        &self,
        path: impl AsRef<Path>,
        expected: Option<&[u8]>,
        bytes: &[u8],
    ) -> PosyResult<()> {
        let key = key(path.as_ref())?;
        validate_bytes(bytes)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let prior = self.read(&transaction, &key)?;
        if prior.as_deref() != expected {
            return Err(PosyError::Conflict(
                "stale consensus evidence locator".into(),
            ));
        }
        let mut objects = ArchiveObjects::new();
        let mut bindings = Vec::new();
        if let Some(prior) = prior.filter(|prior| prior != bytes) {
            bindings.push(self.stage_record(&key, &prior, true, &mut objects)?);
        }
        if ready_height(&key).is_some() {
            self.publish_hot(&transaction, &key, bytes, &mut objects)?;
        } else {
            bindings.push(self.stage_record(&key, bytes, false, &mut objects)?);
        }
        self.persist_objects(&transaction, objects)?;
        for binding in bindings {
            Self::publish_binding(&transaction, &binding)?;
        }
        transaction.commit().map_err(sql_error)
    }

    fn publish_hot(
        &self,
        connection: &Connection,
        key: &str,
        bytes: &[u8],
        objects: &mut ArchiveObjects,
    ) -> PosyResult<()> {
        let height =
            ready_height(key).ok_or_else(|| PosyError::invalid("hot record is not READY"))?;
        let floor: String = connection
            .query_row(
                "SELECT floor FROM archive_lifecycle WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let floor: u64 = floor
            .parse()
            .map_err(|_| PosyError::invalid("invalid archive lifecycle floor"))?;
        if floor >= 8 && height <= floor - 8 {
            return Ok(());
        }
        let (object_hash, mut encoded) = archive_segments::encode(bytes);
        let (kind, payload) = encoded.remove(&object_hash).expect("encoder returns root");
        objects.extend(encoded);
        let mut hot = b"SNPHT002".to_vec();
        hot.push(kind);
        hot.extend_from_slice(&payload);
        let legacy = self
            .legacy
            .read_optional_bounded(key)
            .map_err(storage_error)?;
        connection.execute("INSERT INTO hot_evidence(key,bytes,digest,legacy_digest,height) VALUES(?1,?2,?3,?4,?5)
            ON CONFLICT(key) DO UPDATE SET bytes=excluded.bytes,digest=excluded.digest",
            params![key,hot,hash(key,bytes),legacy.map(|bytes|hash(key,&bytes)),format!("{height:020}")]).map_err(sql_error)?;
        Ok(())
    }

    /// The caller supplies ordinary independently verified finality. Eight is
    /// the existing startup READY replay lookback; retaining eight below the
    /// finalized floor also retains every active−8 predecessor. Only v2 hot
    /// rows are removed. Legacy files/v1 evidence/revisions never change.
    pub(crate) fn retire_ready(&self, floor: u64) -> PosyResult<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        tx.execute(
            "UPDATE archive_lifecycle SET floor=max(floor,?1) WHERE singleton=1",
            [format!("{floor:020}")],
        )
        .map_err(sql_error)?;
        if let Some(boundary) = floor.checked_sub(8) {
            tx.execute("DELETE FROM hot_evidence WHERE key IN (SELECT key FROM hot_evidence WHERE height<=?1 ORDER BY height,key LIMIT 64)",
                [format!("{boundary:020}")]).map_err(sql_error)?;
        }
        tx.commit().map_err(sql_error)
    }

    /// B-tree keyset cursor: bounded index work, no OFFSET/full-history rebuild.
    pub(crate) fn keys_after(
        &self,
        prefix: &str,
        after: &str,
        limit: usize,
    ) -> PosyResult<Vec<(String, u64)>> {
        if limit == 0 || limit > 4097 {
            return Err(PosyError::invalid("invalid evidence cursor limit"));
        }
        let connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let mut statement = connection.prepare("SELECT key,size FROM (
            SELECT key,length(bytes) AS size FROM evidence WHERE key>=?1 AND key<?2 AND key>?3
            UNION SELECT key,bytes AS size FROM archive_records WHERE key>=?1 AND key<?2 AND key>?3
            UNION SELECT key,length(bytes) AS size FROM hot_evidence WHERE key>=?1 AND key<?2 AND key>?3
            ) ORDER BY key LIMIT ?4").map_err(sql_error)?;
        let rows = statement
            .query_map(
                params![prefix, format!("{prefix}\u{7f}"), after, limit as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error);
        rows
    }

    /// Legacy files are immutable after upgrade. Rebuild only on startup or an
    /// observed directory-generation change, using O(1) record memory. Ordinary
    /// lease selection subsequently uses the on-disk height index.
    pub(crate) fn index_legacy_timeouts(&self, directory: &Path) -> PosyResult<()> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        transaction
            .execute("DELETE FROM legacy_timeout", [])
            .map_err(sql_error)?;
        for (index, entry) in fs::read_dir(directory)
            .map_err(|e| PosyError::NotReady(e.to_string()))?
            .enumerate()
        {
            if index >= 100_000 {
                return Err(PosyError::ResourcePressure(
                    "legacy timeout index limit exceeded".into(),
                ));
            }
            let entry = entry.map_err(|e| PosyError::NotReady(e.to_string()))?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| PosyError::invalid("non UTF-8 legacy timeout name"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|e| PosyError::NotReady(e.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(PosyError::invalid("non-regular legacy timeout record"));
            }
            if name.starts_with("._") {
                continue;
            }
            let key = format!("verified-timeouts/{name}");
            let height = height_key(&key)
                .ok_or_else(|| PosyError::invalid("noncanonical legacy timeout name"))?;
            transaction
                .execute(
                    "INSERT INTO legacy_timeout(key,height,bytes) VALUES(?1,?2,?3)",
                    params![key, height, metadata.len()],
                )
                .map_err(sql_error)?;
        }
        transaction.commit().map_err(sql_error)
    }

    pub(crate) fn timeout_keys(
        &self,
        first: u64,
        last: u64,
        limit: usize,
    ) -> PosyResult<Vec<(String, u64)>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let mut statement = connection.prepare("SELECT key,size FROM (
                SELECT key,height,length(bytes) AS size FROM evidence WHERE height>=?1 AND height<=?2
                UNION SELECT key,height,bytes AS size FROM archive_records WHERE height>=?1 AND height<=?2
                UNION SELECT key,height,bytes AS size FROM legacy_timeout WHERE height>=?1 AND height<=?2
            ) ORDER BY height,key LIMIT ?3").map_err(sql_error)?;
        let rows = statement
            .query_map(
                params![format!("{first:020}"), format!("{last:020}"), limit as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error);
        rows
    }

    fn read_revision(&self, path: &str, digest: &[u8; 32]) -> PosyResult<Option<Vec<u8>>> {
        let key = key(Path::new(path))?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let archived: Option<Vec<u8>> = connection
            .query_row(
                "SELECT object_hash FROM archive_revisions WHERE key=?1 AND digest=?2",
                params![key, digest.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        if let Some(object_hash) = archived {
            let bytes = self.decoded_object(&connection, &object_hash)?;
            if hash(&key, &bytes) != digest {
                return Err(PosyError::invalid("corrupt archived revision"));
            }
            return Ok(Some(bytes));
        }
        let size: Option<i64> = connection
            .query_row(
                "SELECT length(bytes) FROM revisions WHERE key=?1 AND digest=?2",
                params![key, digest.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        let Some(size) = size else {
            return Ok(None);
        };
        if !(0..=MAX_BYTES as i64).contains(&size) {
            return Err(PosyError::invalid("oversized historical revision"));
        }
        let saved: Vec<u8> = connection
            .query_row(
                "SELECT bytes FROM revisions WHERE key=?1 AND digest=?2",
                params![key, digest.as_slice()],
                |r| r.get(0),
            )
            .map_err(sql_error)?;
        if hash(&key, &saved) != digest {
            return Err(PosyError::invalid("corrupt evidence revision"));
        }
        Ok(Some(saved))
    }
    #[cfg(test)]
    fn revision(&self, path: &str, bytes: &[u8]) -> PosyResult<Option<Vec<u8>>> {
        self.read_revision(path, &hash(path, bytes).try_into().unwrap())
    }
}

/// Offline inspection of exact historical bytes. This reader grants no
/// consensus authority: normal typed stores still verify roots, domains,
/// membership, signatures and three-QC finality before using returned evidence.
#[derive(Debug)]
pub struct ConsensusEvidenceReader(EvidenceStore);
impl ConsensusEvidenceReader {
    pub fn open(root: impl Into<PathBuf>) -> PosyResult<Self> {
        EvidenceStore::open(root).map(Self)
    }
    /// Explicit offline recovery: stream every immutable segment, rebuild its
    /// locator/binding index transactionally, and verify every reconstructed
    /// exact-byte record/revision. No signer/node is opened. This does not
    /// replace typed signature/epoch/three-QC startup verification, and refuses
    /// execution while any in-process archive owner remains open.
    /// This rebuilds cold bindings only. It cannot restore missing v1-only
    /// SQLite rows, hot READY/lifecycle, local journals or execution state.
    pub fn rebuild_archive_index(root: impl Into<PathBuf>) -> PosyResult<Self> {
        EvidenceStore::open_mode(root.into(), true).map(Self)
    }
    /// Explicit qualification/inspection only: aggregate index scans are not
    /// an ordinary per-height runtime or telemetry API.
    pub fn inspection_statistics(&self) -> PosyResult<serde_json::Value> {
        let connection = self
            .0
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned inspection".into()))?;
        let count = |table: &str| -> PosyResult<u64> {
            connection
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .map_err(sql_error)
        };
        let binary_signature_bytes: u64 = connection
            .query_row(
                "SELECT coalesce(sum(length),0) FROM archive_objects WHERE kind=2 AND length=3309",
                [],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let mut cache = 0;
        let mut high = 0;
        // SAFETY: the connection mutex is held and outputs point to valid i32s.
        let status = unsafe {
            rusqlite::ffi::sqlite3_db_status(
                connection.handle(),
                rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
                &mut cache,
                &mut high,
                0,
            )
        };
        if status != rusqlite::ffi::SQLITE_OK {
            return Err(PosyError::NotReady("SQLite cache inspection failed".into()));
        }
        Ok(
            serde_json::json!({"schema":2,"archive_objects":count("archive_objects")?,"archive_records":count("archive_records")?,
            "archive_revisions":count("archive_revisions")?,"archive_finality":count("archive_finality")?,"segments":count("archive_segments")?,
            "hot_ready_rows":count("hot_evidence")?,"raw_3309_byte_array_bytes":binary_signature_bytes,"cache_bytes":cache,
            "scope":"Explicit index aggregate;3309-byte arrays count storage blobs, not cryptographic verification. SQLite writes/fsyncs are not measured here."}),
        )
    }
    /// Explicit offline import only: index exact existing historical files in
    /// one atomic batch, leaving every original byte and locator untouched.
    /// Active delivery/sign-once journals continue to use their original owner.
    pub fn import_legacy_records(&self, paths: &[PathBuf]) -> PosyResult<()> {
        if paths.is_empty() || paths.len() > 64 {
            return Err(PosyError::invalid("invalid legacy import batch"));
        }
        let mut writes = Vec::new();
        let mut total = 0usize;
        for path in paths {
            let key = key(path)?;
            if key == "delivery.json" || key == "sign-once.json" || key == "recovery.json" {
                return Err(PosyError::invalid(
                    "active journal is not historical evidence",
                ));
            }
            let bytes = self.0.legacy.read_bounded(path).map_err(storage_error)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| PosyError::ResourcePressure("legacy import byte overflow".into()))?;
            if total > 32 * 1024 * 1024 {
                return Err(PosyError::ResourcePressure(
                    "legacy import exceeds 32MiB".into(),
                ));
            }
            writes.push(StorageWrite {
                relative_path: path.clone(),
                bytes,
            });
        }
        self.0.put_internal(&writes, None, true).map(|_| ())
    }
    pub fn read_exact(&self, relative: impl AsRef<Path>) -> PosyResult<Option<Vec<u8>>> {
        self.0.get(relative)
    }
    /// Require a cold archive copy; unlike read_exact this never falls back
    /// to the original legacy file. Used to prove lossless offline imports.
    pub fn read_archived_exact(&self, relative: impl AsRef<Path>) -> PosyResult<Option<Vec<u8>>> {
        let key = key(relative.as_ref())?;
        let connection = self
            .0
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned archived reader".into()))?;
        let row: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT object_hash,digest FROM archive_records WHERE key=?1",
                [&key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(sql_error)?;
        let Some((object, digest)) = row else {
            return Ok(None);
        };
        let bytes = self.0.decoded_object(&connection, &object)?;
        if hash(&key, &bytes) != digest {
            return Err(PosyError::invalid(
                "cold archive exact-byte digest mismatch",
            ));
        }
        Ok(Some(bytes))
    }
    pub fn read_revision(&self, relative: &str, digest: &[u8; 32]) -> PosyResult<Option<Vec<u8>>> {
        self.0.read_revision(relative, digest)
    }
    /// At most 64 digests per call; keyset pagination never loads history.
    pub fn revision_digests(
        &self,
        relative: &str,
        after: &[u8],
        limit: usize,
    ) -> PosyResult<Vec<[u8; 32]>> {
        let key = key(Path::new(relative))?;
        if limit == 0 || limit > 64 || (!after.is_empty() && after.len() != 32) {
            return Err(PosyError::invalid("invalid revision cursor"));
        }
        let connection = self
            .0
            .connection
            .lock()
            .map_err(|_| PosyError::NotReady("poisoned evidence lock".into()))?;
        let mut statement = connection
            .prepare(
                "SELECT digest FROM (SELECT digest FROM revisions WHERE key=?1 AND digest>?2
                 UNION SELECT digest FROM archive_revisions WHERE key=?1 AND digest>?2) ORDER BY digest LIMIT ?3",
            )
            .map_err(sql_error)?;
        let rows = statement
            .query_map(params![key, after, limit as i64], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .map_err(sql_error)?;
        let mut digests = Vec::new();
        for row in rows {
            digests.push(
                row.map_err(sql_error)?
                    .try_into()
                    .map_err(|_| PosyError::invalid("corrupt revision digest"))?,
            );
        }
        Ok(digests)
    }
}

fn key(path: &Path) -> PosyResult<String> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(PosyError::invalid("invalid evidence key"));
    }
    let key = path
        .to_str()
        .ok_or_else(|| PosyError::invalid("non UTF-8 evidence key"))?;
    if key.len() > 512
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
    {
        return Err(PosyError::invalid("invalid evidence key bytes"));
    }
    Ok(key.into())
}
fn height_key(key: &str) -> Option<String> {
    let name = key
        .strip_prefix("verified-timeouts/h")?
        .strip_suffix(".json")?;
    let (height, round) = name.split_once('r')?;
    let height: u64 = height.parse().ok()?;
    let round: u64 = round.parse().ok()?;
    if key != format!("verified-timeouts/h{height}r{round}.json") {
        return None;
    }
    Some(format!("{height:020}"))
}
fn validate_bytes(bytes: &[u8]) -> PosyResult<()> {
    if bytes.len() > MAX_BYTES {
        return Err(PosyError::ResourcePressure(
            "consensus evidence exceeds record budget".into(),
        ));
    }
    Ok(())
}
fn hash(key: &str, bytes: &[u8]) -> Vec<u8> {
    let mut hash = blake3::Hasher::new_derive_key("Synergy/PoSy/v3/evidence-archive-v1");
    hash.update(&(key.len() as u64).to_le_bytes());
    hash.update(key.as_bytes());
    hash.update(bytes);
    hash.finalize().as_bytes().to_vec()
}
fn sql_error(e: rusqlite::Error) -> PosyError {
    PosyError::NotReady(format!("consensus evidence database: {e}"))
}
fn archive_error(e: std::io::Error) -> PosyError {
    PosyError::NotReady(format!("consensus archive segment: {e}"))
}
#[cfg(test)]
fn archive_crash_checkpoint(point: &str) {
    if std::env::var("SYNERGY_ARCHIVE_CRASH_POINT").ok().as_deref() == Some(point) {
        std::process::exit(91);
    }
}
fn insert_location(connection: &Connection, location: &Location) -> PosyResult<()> {
    connection.execute("INSERT OR IGNORE INTO archive_objects(hash,kind,segment,offset,length) VALUES(?1,?2,?3,?4,?5)",
        params![location.hash.as_slice(),location.kind,location.segment,location.offset,location.length as u64]).map_err(sql_error)?;
    Ok(())
}
fn location_for_hash(connection: &Connection, hash: &[u8; 32]) -> PosyResult<Location> {
    let (kind, segment, offset, length): (u8, u64, u64, usize) = connection
        .query_row(
            "SELECT kind,segment,offset,length FROM archive_objects WHERE hash=?1",
            [hash.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(sql_error)?;
    if length > MAX_BYTES || offset < 16 {
        return Err(PosyError::invalid("invalid archive index location"));
    }
    Ok(Location {
        hash: *hash,
        kind,
        segment,
        offset,
        length,
    })
}
fn insert_segment(connection: &Connection, id: u64, length: u64, sealed: bool) -> PosyResult<()> {
    connection.execute("INSERT INTO archive_segments(segment,committed_bytes,sealed) VALUES(?1,?2,?3)
        ON CONFLICT(segment) DO UPDATE SET committed_bytes=excluded.committed_bytes,sealed=excluded.sealed",
        params![id,length,sealed]).map_err(sql_error)?;
    Ok(())
}
fn ready_height(key: &str) -> Option<u64> {
    let height = key
        .strip_prefix("ready-h")?
        .strip_suffix(".json")?
        .parse::<u64>()
        .ok()?;
    (key == format!("ready-h{height}.json")).then_some(height)
}
fn rebuild_finality_refs(connection: &Connection) -> PosyResult<()> {
    let mut after = String::new();
    loop {
        let mut query=connection.prepare("SELECT key,object_hash FROM archive_records WHERE key>?1 AND key>='finality/' AND key<'finality0' ORDER BY key LIMIT 64").map_err(sql_error)?;
        let rows = query
            .query_map([&after], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sql_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_error)?;
        if rows.is_empty() {
            break;
        }
        for (key, object_hash) in rows {
            let height = key
                .strip_prefix("finality/h")
                .and_then(|key| key.strip_suffix(".json"))
                .and_then(|height| height.parse::<u64>().ok())
                .filter(|height| key == format!("finality/h{height}.json"))
                .ok_or_else(|| PosyError::invalid("noncanonical archived finality key"))?;
            let mut refs = Vec::with_capacity(3);
            for offset in 0..3 {
                let qc_height = height
                    .checked_add(offset)
                    .ok_or_else(|| PosyError::invalid("finality height overflow"))?;
                let qc_key = format!("verified-qcs/qc/{qc_height:020}.json");
                let object: Option<Vec<u8>> = connection
                    .query_row(
                        "SELECT object_hash FROM archive_records WHERE key=?1",
                        [qc_key],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sql_error)?;
                let Some(object) = object else {
                    break;
                };
                refs.push(object);
            }
            if refs.len() == 3 {
                connection
                    .execute(
                        "INSERT INTO archive_finality VALUES(?1,?2,?3,?4,?5)",
                        params![
                            format!("{height:020}"),
                            object_hash,
                            refs[0],
                            refs[1],
                            refs[2]
                        ],
                    )
                    .map_err(sql_error)?;
            }
            after = key;
        }
    }
    Ok(())
}
fn storage_error(e: synergy_storage::StorageError) -> PosyError {
    PosyError::NotReady(format!("legacy consensus evidence: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Instant,
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn fixture(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "posy-archive-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }
    fn write(key: &str, bytes: &[u8]) -> StorageWrite {
        StorageWrite {
            relative_path: key.into(),
            bytes: bytes.into(),
        }
    }

    #[test]
    fn missing_index_fails_closed_and_explicit_streaming_rebuild_restores_exact_records() {
        let root = fixture("reindex");
        let archive = EvidenceStore::open(&root).unwrap();
        let signature = vec![123u8; 3309];
        let a =
            serde_json::to_vec(&serde_json::json!({"signature":signature,"transcript":"first"}))
                .unwrap();
        let b =
            serde_json::to_vec(&serde_json::json!({"signature":signature,"transcript":"second"}))
                .unwrap();
        archive
            .put_once_atomic(&[write("proof/a.json", &a), write("proof/b.json", &b)])
            .unwrap();
        archive
            .replace_guarded("validation-h7.json", None, &a)
            .unwrap();
        archive
            .replace_guarded("validation-h7.json", Some(&a), &b)
            .unwrap();
        assert!(ConsensusEvidenceReader::rebuild_archive_index(&root).is_err());
        let binary_count: u64 = archive
            .connection
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM archive_objects WHERE kind=2 AND length=3309",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            binary_count, 1,
            "same signature must be stored once physically"
        );
        let segment = root.join("archive/segment-00000000000000000001.sya");
        let original_segment = fs::read(&segment).unwrap();
        drop(archive);
        fs::remove_file(root.join(ARCHIVE_FILE)).unwrap();
        assert!(EvidenceStore::open(&root).is_err());
        assert!(
            !root.join(ARCHIVE_FILE).exists(),
            "ordinary open recreated a missing index"
        );
        let rebuilt = ConsensusEvidenceReader::rebuild_archive_index(&root).unwrap();
        assert_eq!(
            rebuilt
                .read_archived_exact("proof/a.json")
                .unwrap()
                .unwrap(),
            a
        );
        assert_eq!(
            rebuilt
                .read_archived_exact("proof/b.json")
                .unwrap()
                .unwrap(),
            b
        );
        assert_eq!(
            rebuilt.read_exact("validation-h7.json").unwrap().unwrap(),
            b
        );
        assert_eq!(
            rebuilt
                .read_revision(
                    "validation-h7.json",
                    &hash("validation-h7.json", &a).try_into().unwrap()
                )
                .unwrap()
                .unwrap(),
            a
        );
        assert_eq!(
            fs::read(&segment).unwrap(),
            original_segment,
            "offline reindex rewrote immutable payloads"
        );
        drop(rebuilt);
        let reopened = EvidenceStore::open(&root).unwrap();
        assert_eq!(reopened.get("proof/a.json").unwrap().unwrap(), a);
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn ready_retirement_preserves_legacy_vc_exact_signatures_and_recent_hot_window() {
        let root = fixture("ready-floor");
        let archive = EvidenceStore::open(&root).unwrap();
        let bytes = serde_json::to_vec(&serde_json::json!({"signature":vec![99u8;3309]})).unwrap();
        archive
            .legacy
            .write_atomic("ready-h1.json", &bytes)
            .unwrap();
        for height in [1, 2, 32, 33, 40] {
            archive
                .replace_guarded(
                    format!("ready-h{height}.json"),
                    None.or_else(|| (height == 1).then_some(bytes.as_slice())),
                    &bytes,
                )
                .unwrap();
        }
        archive
            .put_once_atomic(&[
                write("validation-h2.json", &bytes),
                write("signature-kept.json", &bytes),
            ])
            .unwrap();
        archive.retire_ready(40).unwrap();
        assert_eq!(
            archive.get("ready-h1.json").unwrap().unwrap(),
            bytes,
            "legacy original remains visible"
        );
        for height in [2, 32] {
            assert!(archive
                .get(format!("ready-h{height}.json"))
                .unwrap()
                .is_none());
        }
        for height in [33, 40] {
            assert_eq!(
                archive
                    .get(format!("ready-h{height}.json"))
                    .unwrap()
                    .unwrap(),
                bytes
            );
        }
        for key in ["validation-h2.json", "signature-kept.json"] {
            assert_eq!(archive.get(key).unwrap().unwrap(), bytes);
        }
        archive
            .replace_guarded("ready-h2.json", None, &bytes)
            .unwrap();
        assert!(
            archive.get("ready-h2.json").unwrap().is_none(),
            "late READY regenerated retired hot state"
        );
        let connection = archive.connection.lock().unwrap();
        let (rows, hot_bytes): (u64, u64) = connection
            .query_row(
                "SELECT count(*),sum(length(bytes)) FROM hot_evidence",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(rows, 2);
        assert!(hot_bytes < 1000, "hot state repeated decimal signatures");
        drop(connection);
        drop(archive);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn aggregate_legacy_promotion_rejects_capacity_before_any_archive_append() {
        let root = fixture("aggregate-bound");
        let archive = EvidenceStore::open(&root).unwrap();
        for (height, byte) in [(1, b'a'), (2, b'b')] {
            archive
                .legacy
                .write_atomic(
                    format!("verified-qcs/qc/{height:020}.json"),
                    &vec![byte; 12 * 1024 * 1024],
                )
                .unwrap();
        }
        let segment = root.join("archive/segment-00000000000000000001.sya");
        let before = fs::metadata(&segment).unwrap().len();
        let result = archive.commit_finality_atomic(
            &[
                write(
                    "verified-qcs/qc/00000000000000000003.json",
                    &vec![b'c'; 12 * 1024 * 1024],
                ),
                write("finality/h1.json", b"finality"),
            ],
            1,
        );
        assert!(matches!(result, Err(PosyError::ResourcePressure(_))));
        assert_eq!(fs::metadata(segment).unwrap().len(), before);
        assert!(archive.get("finality/h1.json").unwrap().is_none());
        drop(archive);
        assert!(EvidenceStore::open(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hybrid_archive_crash_boundaries_publish_both_records_or_neither() {
        for point in [
            "before-append",
            "after-one-binding",
            "partial-batch-footer",
            "after-append",
            "before-index-commit",
            "after-index-commit",
        ] {
            let root = fixture(point);
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "persistence::evidence_store::tests::hybrid_archive_crash_child",
                    "--ignored",
                ])
                .env("SYNERGY_ARCHIVE_CRASH_ROOT", &root)
                .env("SYNERGY_ARCHIVE_CRASH_POINT", point)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(91),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let archive = EvidenceStore::open(&root).unwrap();
            let committed = point == "after-index-commit";
            assert_eq!(archive.get("paired/qc").unwrap().is_some(), committed);
            assert_eq!(archive.get("paired/finality").unwrap().is_some(), committed);
            drop(archive);
            // Normal startup ignores unindexed locators. Explicit offline
            // redo may promote a complete durable batch only, never a pair
            // with merely one binding frame or a partial footer.
            let rebuilt = ConsensusEvidenceReader::rebuild_archive_index(&root).unwrap();
            let redo = matches!(
                point,
                "after-append" | "before-index-commit" | "after-index-commit"
            );
            assert_eq!(
                rebuilt.read_exact("paired/qc").unwrap().is_some(),
                redo,
                "{point}"
            );
            assert_eq!(
                rebuilt.read_exact("paired/finality").unwrap().is_some(),
                redo,
                "{point}"
            );
            drop(rebuilt);
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn direct_offline_reindex_reestablishes_segment_sync_without_normal_open_first() {
        let root = fixture("direct-reindex");
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "persistence::evidence_store::tests::hybrid_archive_crash_child",
                "--ignored",
            ])
            .env("SYNERGY_ARCHIVE_CRASH_ROOT", &root)
            .env("SYNERGY_ARCHIVE_CRASH_POINT", "before-segment-sync")
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(91),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        // Deliberately no ordinary EvidenceStore::open before rebuilding.
        let rebuilt = ConsensusEvidenceReader::rebuild_archive_index(&root).unwrap();
        assert_eq!(
            rebuilt.read_archived_exact("paired/qc").unwrap().unwrap(),
            b"qc"
        );
        assert_eq!(
            rebuilt
                .read_archived_exact("paired/finality")
                .unwrap()
                .unwrap(),
            b"finality"
        );
        drop(rebuilt);
        let reopened = EvidenceStore::open(&root).unwrap();
        assert_eq!(reopened.get("paired/qc").unwrap().unwrap(), b"qc");
        assert_eq!(
            reopened.get("paired/finality").unwrap().unwrap(),
            b"finality"
        );
        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "invoked by isolated hybrid crash test"]
    fn hybrid_archive_crash_child() {
        let root = std::env::var_os("SYNERGY_ARCHIVE_CRASH_ROOT").expect("child root");
        EvidenceStore::open(PathBuf::from(root))
            .unwrap()
            .put_once_atomic(&[
                write("paired/qc", b"qc"),
                write("paired/finality", b"finality"),
            ])
            .unwrap();
        panic!("crash failpoint was not reached");
    }
    #[cfg(unix)]
    #[test]
    fn new_archive_modes_do_not_depend_on_private_umask() {
        let root = fixture("modes");
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "persistence::evidence_store::tests::archive_modes_child",
                "--ignored",
            ])
            .env("SYNERGY_ARCHIVE_MODE_ROOT", &root)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    #[ignore = "isolated umask subprocess only"]
    fn archive_modes_child() {
        use std::os::unix::fs::PermissionsExt;
        unsafe extern "C" {
            fn umask(mask: u32) -> u32;
        }
        // SAFETY: this selected-test subprocess has no other application owner.
        unsafe {
            umask(0);
        }
        let root =
            PathBuf::from(std::env::var_os("SYNERGY_ARCHIVE_MODE_ROOT").expect("child mode root"));
        let archive = EvidenceStore::open(&root).unwrap();
        for file in [
            root.join(ARCHIVE_FILE),
            root.join("archive/segment-00000000000000000001.sya"),
        ] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::metadata(root.join("archive"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        drop(archive);
    }

    #[test]
    fn exact_legacy_and_indexed_history_replay_conflict_and_corruption() {
        let root = fixture("mixed");
        let legacy = AtomicStore::new(&root, MAX_BYTES).unwrap();
        let original = b"{ \"signed\" : [1, 2, 3] }\n";
        legacy.write_atomic("old/first.json", original).unwrap();
        let archive = EvidenceStore::open(&root).unwrap();
        assert_eq!(archive.get("old/first.json").unwrap().unwrap(), original);
        assert!(!archive
            .put_once_atomic(&[write("old/first.json", original)])
            .unwrap());
        assert_eq!(fs::read(root.join("old/first.json")).unwrap(), original);
        assert!(archive
            .put_once_atomic(&[
                write("new/qc.json", b"exact-qc"),
                write("new/finality.json", b"exact-finality")
            ])
            .unwrap());
        assert!(!archive
            .put_once_atomic(&[write("new/qc.json", b"exact-qc")])
            .unwrap());
        assert!(archive
            .put_once_atomic(&[
                write("new/uncommitted.json", b"must-not-exist"),
                write("new/qc.json", b"conflict")
            ])
            .is_err());
        assert_eq!(archive.get("new/uncommitted.json").unwrap(), None);
        drop(archive);
        let archive = EvidenceStore::open(&root).unwrap();
        assert_eq!(
            archive.get("new/finality.json").unwrap(),
            Some(b"exact-finality".to_vec())
        );
        assert_eq!(archive.get("old/first.json").unwrap().unwrap(), original);
        legacy
            .write_atomic("old/first.json", b"changed legacy")
            .unwrap();
        assert!(archive.get("old/first.json").is_err());
        archive
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE archive_records SET digest=?1 WHERE key='new/qc.json'",
                [b"changed archive".as_slice()],
            )
            .unwrap();
        assert!(archive.get("new/qc.json").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn guarded_locator_keeps_old_exact_bytes_and_rejects_stale_owners() {
        let root = fixture("locator");
        let a = EvidenceStore::open(&root).unwrap();
        a.legacy
            .write_atomic("validation-h7.json", b"old-exact")
            .unwrap();
        let b = EvidenceStore::open(&root).unwrap();
        assert!(std::sync::Arc::ptr_eq(&a.connection, &b.connection));
        a.replace_guarded("validation-h7.json", Some(b"old-exact"), b"new-exact")
            .unwrap();
        assert_eq!(
            a.revision("validation-h7.json", b"old-exact").unwrap(),
            Some(b"old-exact".to_vec())
        );
        assert_eq!(
            fs::read(root.join("validation-h7.json")).unwrap(),
            b"old-exact"
        );
        assert_eq!(
            b.get("validation-h7.json").unwrap(),
            Some(b"new-exact".to_vec())
        );
        assert!(b
            .replace_guarded("validation-h7.json", Some(b"old-exact"), b"stale")
            .is_err());
        assert_eq!(
            a.get("validation-h7.json").unwrap(),
            Some(b"new-exact".to_vec())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_immutable_writers_and_readers_share_one_winner() {
        let root = fixture("concurrent");
        let initial = EvidenceStore::open(&root).unwrap();
        let a = EvidenceStore::open(&root).unwrap();
        let b = EvidenceStore::open(&root).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for (owner, value) in [(a, vec![1; 4096]), (b, vec![2; 4096])] {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                owner.put_once_atomic(&[write("signature-slot.json", &value)])
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|r| r.is_err()).count(), 1);
        let saved = initial.get("signature-slot.json").unwrap().unwrap();
        assert!(saved == vec![1; 4096] || saved == vec![2; 4096]);
        let reader = initial.clone();
        let worker = std::thread::spawn(move || {
            for i in 0..128 {
                reader
                    .replace_guarded(format!("ready-h{i}.json"), None, &vec![i as u8; 4096])
                    .unwrap();
            }
        });
        for _ in 0..128 {
            assert_eq!(initial.get("signature-slot.json").unwrap().unwrap(), saved);
        }
        worker.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_paths_versions_and_truncated_database_fail_closed() {
        let root = fixture("invalid");
        let archive = EvidenceStore::open(&root).unwrap();
        for invalid in ["../escape", "/absolute", "a/../b", ""] {
            assert!(archive.get(invalid).is_err());
        }
        assert!(archive
            .put_once_atomic(&[write("oversized", &vec![0; MAX_BYTES + 1])])
            .is_err());
        archive
            .connection
            .lock()
            .unwrap()
            .pragma_update(None, "user_version", 99)
            .unwrap();
        drop(archive);
        assert!(EvidenceStore::open(&root).is_err());
        fs::write(root.join(ARCHIVE_FILE), b"truncated").unwrap();
        assert!(EvidenceStore::open(&root).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn archive_and_legacy_symlinks_fail_closed() {
        let root = fixture("symlinks");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("outside"), b"untouched").unwrap();
        std::os::unix::fs::symlink("outside", root.join(ARCHIVE_FILE)).unwrap();
        assert!(EvidenceStore::open(&root).is_err());
        fs::remove_file(root.join(ARCHIVE_FILE)).unwrap();
        let archive = EvidenceStore::open(&root).unwrap();
        std::os::unix::fs::symlink("outside", root.join("legacy.json")).unwrap();
        assert!(archive.get("legacy.json").is_err());
        assert_eq!(fs::read(root.join("outside")).unwrap(), b"untouched");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crash_atomicity_before_between_and_after_paired_commit() {
        for mode in ["after-first", "after-second", "after-commit"] {
            let root = fixture(mode);
            let archive = EvidenceStore::open(&root).unwrap();
            archive
                .put_once_atomic(&[write("previous", b"preserve")])
                .unwrap();
            drop(archive);
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "persistence::evidence_store::tests::crash_writer_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SYNERGY_STORAGE_CRASH_ROOT", &root)
                .env("SYNERGY_STORAGE_CRASH_MODE", mode)
                .output()
                .unwrap();
            assert_eq!(
                result.status.code(),
                Some(91),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let archive = EvidenceStore::open(&root).unwrap();
            assert_eq!(archive.get("previous").unwrap(), Some(b"preserve".to_vec()));
            let committed = mode == "after-commit";
            assert_eq!(archive.get("paired/qc").unwrap().is_some(), committed);
            assert_eq!(archive.get("paired/finality").unwrap().is_some(), committed);
            // Restart/replay is idempotent whether the prior commit acknowledged.
            archive
                .put_once_atomic(&[
                    write("paired/qc", b"qc"),
                    write("paired/finality", b"finality"),
                ])
                .unwrap();
            assert!(!archive
                .put_once_atomic(&[
                    write("paired/qc", b"qc"),
                    write("paired/finality", b"finality")
                ])
                .unwrap());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    #[ignore = "child process failpoint, invoked by crash_atomicity test"]
    fn crash_writer_child() {
        let Ok(root) = std::env::var("SYNERGY_STORAGE_CRASH_ROOT") else {
            return;
        };
        let mode = std::env::var("SYNERGY_STORAGE_CRASH_MODE").unwrap();
        let archive = EvidenceStore::open(root).unwrap();
        let mut connection = archive.connection.lock().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        for (key, bytes) in [
            ("paired/qc", b"qc".as_slice()),
            ("paired/finality", b"finality".as_slice()),
        ] {
            transaction
                .execute(
                    "INSERT INTO evidence(key,bytes,digest) VALUES(?1,?2,?3)",
                    params![key, bytes, hash(key, bytes)],
                )
                .unwrap();
            if mode == "after-first" {
                std::process::exit(91);
            }
        }
        if mode == "after-second" {
            std::process::exit(91);
        }
        transaction.commit().unwrap();
        std::process::exit(91);
    }

    fn inventory(root: &Path) -> (u64, u64, Option<u64>) {
        let mut count = 0;
        let mut bytes = 0;
        let mut allocated = Some(0u64);
        for entry in fs::read_dir(root).unwrap() {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() {
                let (c, b, blocks) = inventory(&entry.path());
                count += c;
                bytes += b;
                allocated = allocated.zip(blocks).map(|(a, b)| a + b);
            } else {
                count += 1;
                bytes += meta.len();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    allocated = allocated.map(|a| a + meta.blocks() * 512);
                }
                #[cfg(not(unix))]
                {
                    allocated = None;
                }
            }
        }
        (count, bytes, allocated)
    }
    fn process_io() -> Option<std::collections::BTreeMap<String, u64>> {
        let text = fs::read_to_string("/proc/self/io").ok()?;
        text.lines()
            .map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_owned(), value.trim().parse().ok()?))
            })
            .collect()
    }
    fn qualification_count(value: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("expected unsigned decimal height count".into());
        }
        let value: u64 = value.parse().map_err(|_| "height count overflow")?;
        if !(minimum..=maximum).contains(&value) {
            return Err(format!("height count must be {minimum}..={maximum}"));
        }
        Ok(value)
    }
    fn qualification_count_env(name: &str, default: u64, minimum: u64, maximum: u64) -> u64 {
        match std::env::var(name) {
            Ok(value) => qualification_count(&value, minimum, maximum)
                .unwrap_or_else(|error| panic!("{name}: {error}")),
            Err(std::env::VarError::NotPresent) => default,
            Err(error) => panic!("{name}: {error}"),
        }
    }
    fn qualification_heights(candidates: &[u64], maximum: u64) -> Vec<u64> {
        candidates
            .iter()
            .copied()
            .filter(|height| *height > 0 && *height <= maximum)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
    #[test]
    fn storage_growth_parameters_are_bounded_and_samples_cover_tail() {
        assert_eq!(qualification_count("10000", 1, 100000).unwrap(), 10000);
        assert_eq!(qualification_count("100000", 1, 100000).unwrap(), 100000);
        assert_eq!(qualification_count("0", 0, 1024).unwrap(), 0);
        for invalid in [
            "",
            "0",
            "100001",
            "-1",
            "+1",
            " 10",
            "10 ",
            "18446744073709551616",
        ] {
            assert!(
                qualification_count(invalid, 1, 100000).is_err(),
                "{invalid:?}"
            );
        }
        assert!(qualification_count("1025", 0, 1024).is_err());
        assert_eq!(qualification_heights(&[1, 2, 1024, 1, 0], 1), vec![1]);
        assert_eq!(
            qualification_heights(&[1, 10000, 5000, 10000], 10000),
            vec![1, 5000, 10000]
        );
    }
    fn db_status(connection: &Connection, op: i32) -> i32 {
        let mut current = 0;
        let mut high = 0;
        // SAFETY: connection's mutex is held; SQLite writes two valid i32 outputs.
        let result = unsafe {
            rusqlite::ffi::sqlite3_db_status(connection.handle(), op, &mut current, &mut high, 0)
        };
        assert_eq!(result, rusqlite::ffi::SQLITE_OK);
        current
    }

    #[test]
    #[ignore = "substantial isolated disk qualification; run explicitly"]
    fn storage_growth_qualification() {
        // Validate before creating files. Legacy stays capped: the scale test
        // must not create hundreds of thousands of old per-message files.
        let heights =
            qualification_count_env("SYNERGY_STORAGE_QUALIFICATION_HEIGHTS", 8192, 1, 100000);
        let legacy_heights = qualification_count_env(
            "SYNERGY_STORAGE_QUALIFICATION_LEGACY_HEIGHTS",
            1024,
            0,
            1024,
        );
        let base = std::env::var_os("SYNERGY_STORAGE_QUALIFICATION_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| fixture("growth"));
        fs::create_dir_all(&base).unwrap();
        let old_root = base.join("legacy");
        let new_root = base.join("indexed");
        assert!(
            !old_root.exists() && !new_root.exists(),
            "qualification roots must be new"
        );
        let payload = vec![0x5a; 4096];
        let paths = |height: u64| {
            [
                format!("ready-h{height}.json"),
                format!("validation-h{height}.json"),
                format!("verified-qcs/qc/{height:020}.json"),
                format!("finality/h{height}.json"),
                format!("signature-echo-{height}.json"),
                format!("signature-ready-{height}.json"),
                format!("signature-vote-{height}.json"),
            ]
        };
        let io_before_legacy = process_io();
        let old = AtomicStore::new(&old_root, MAX_BYTES).unwrap();
        let start = Instant::now();
        for height in 1..=legacy_heights {
            for key in paths(height) {
                old.put_once_atomic(&[write(&key, &payload)]).unwrap();
            }
        }
        let old_time = start.elapsed().as_secs_f64();
        let old_inventory = inventory(&old_root);
        drop(old);
        let io_after_legacy = process_io();
        let archive = EvidenceStore::open(&new_root).unwrap();
        let io_before_indexed_writes = process_io();
        let start = Instant::now();
        let mut samples = Vec::new();
        let sample_heights =
            qualification_heights(&[1024, 2048, 4096, 8192, 10000, 100000, heights], heights);
        for height in 1..=heights {
            let writes = paths(height)
                .iter()
                .map(|k| write(k, &payload))
                .collect::<Vec<_>>();
            archive.put_once_atomic(&writes).unwrap();
            if sample_heights.contains(&height) {
                let connection = archive.connection.lock().unwrap();
                let (files, logical_bytes, allocated_bytes) = inventory(&new_root);
                samples.push(serde_json::json!({"height":height,"files":files,
                    "logical_bytes":logical_bytes,"allocated_bytes":allocated_bytes,
                    "cache_bytes":db_status(&connection,rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED),
                    "page_writes":db_status(&connection,rusqlite::ffi::SQLITE_DBSTATUS_CACHE_WRITE),
                    "page_misses":db_status(&connection,rusqlite::ffi::SQLITE_DBSTATUS_CACHE_MISS),
                    "process_io":process_io(),"elapsed_seconds":start.elapsed().as_secs_f64()}));
            }
        }
        let new_time = start.elapsed().as_secs_f64();
        let io_after_indexed_writes = process_io();
        let owner_clone = archive.clone();
        assert!(std::sync::Arc::ptr_eq(
            &archive.connection,
            &owner_clone.connection
        ));
        drop(owner_clone);
        let lookup_heights = qualification_heights(&[1, 2, 1024, heights / 2, heights], heights);
        let connection = archive.connection.lock().unwrap();
        let mut query = connection
            .prepare("SELECT key FROM archive_records WHERE key=?1 UNION SELECT key FROM hot_evidence WHERE key=?1 UNION SELECT key FROM evidence WHERE key=?1")
            .unwrap();
        for height in &lookup_heights {
            for key in paths(*height) {
                assert_eq!(
                    query.query_row([&key], |r| r.get::<_, String>(0)).unwrap(),
                    key
                );
                assert_eq!(archive.read(&connection, &key).unwrap().unwrap(), payload);
            }
        }
        assert_eq!(query.get_status(rusqlite::StatementStatus::FullscanStep), 0);
        let lookup_vm_steps = query.get_status(rusqlite::StatementStatus::VmStep);
        drop(query);
        drop(connection);
        drop(archive);
        let io_before_restart = process_io();
        let restart = Instant::now();
        let archive = EvidenceStore::open(&new_root).unwrap();
        let restart_seconds = restart.elapsed().as_secs_f64();
        let restart_heights = qualification_heights(&[1, 1024, heights / 2, heights], heights);
        for height in &restart_heights {
            for key in paths(*height) {
                assert_eq!(archive.get(key).unwrap().unwrap(), payload);
            }
        }
        let io_after_restart_lookup = process_io();
        let indexed_inventory = inventory(&new_root);
        let report = serde_json::json!({"format":"posy-indexed-storage-qualification-v2",
            "payload_kind":"synthetic repeated0x5a bytes; not signed protocol records",
            "payload_bytes_per_record":payload.len(),"records_per_height":7,"payload_bytes_per_height":7*payload.len(),
            "legacy":{"heights":legacy_heights,"files":old_inventory.0,"logical_bytes":old_inventory.1,"allocated_bytes":old_inventory.2,"seconds":old_time},
            "indexed":{"heights":heights,"records":7*heights,"raw_payload_bytes":7*heights*payload.len() as u64,
                "files":indexed_inventory.0,"logical_bytes":indexed_inventory.1,"allocated_bytes":indexed_inventory.2,
                "seconds":new_time,"samples":samples,"restart_seconds":restart_seconds,
                "historical_lookup_heights":lookup_heights,"historical_lookup_records":7*lookup_heights.len(),
                "historical_lookup_fullscan_steps":0,"historical_lookup_vm_steps":lookup_vm_steps,
                "restart_lookup_heights":restart_heights},
            "process_io_snapshots":{"before_legacy":io_before_legacy,"after_legacy":io_after_legacy,
                "before_indexed_writes":io_before_indexed_writes,"after_indexed_writes":io_after_indexed_writes,
                "before_restart":io_before_restart,"after_restart_lookup":io_after_restart_lookup},
            "io_scope":"SQLite page-write counters exclude rollback journals, fsync syscalls, metadata and device writes. Linux /proc/self/io counters are process-wide cumulative snapshots including harness overhead; null when unavailable. allocated_bytes sums regular-file st_blocks*512, excludes directory allocation, and is not cumulative writes. No fsync count is measured by this harness.",
            "recovery_scope":"All archive owners dropped then reopened in same process; exact early/middle/tail bytes checked. OS page cache remains warm/unknown. This is not crash recovery; crash_atomicity is a separate test.",
            "limits":"Synthetic28KiB/height exact-byte storage fixture. Not actual signed record sizes/compression, protocol/PQ correctness, live soak, host cgroup or sustainable TPS evidence."});
        fs::write(
            base.join("storage-growth.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
        println!("{}", serde_json::to_string(&report).unwrap());
        // Preserve measurements; disposable data can be removed after review.
    }
}
