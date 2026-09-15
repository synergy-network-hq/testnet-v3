use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::{AvailabilityProof, DataShard};

const STORE_VERSION: u32 = 2;
const MAX_STORED_SHARD_BYTES: u64 = 80 * 1024 * 1024;
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub trait ShardStore: Send + Sync {
    fn put_custody_if_absent(
        &self,
        proof: &AvailabilityProof,
        shard: &DataShard,
        custody_height: u64,
    ) -> Result<(), String>;
    fn get_custody(&self, object_root: &str, index: u32) -> Result<Option<CustodiedShard>, String>;
    fn remove_below(&self, height: u64) -> Result<u64, String>;
}

#[derive(Debug, Clone)]
pub struct FilesystemShardStore {
    root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredShard {
    version: u32,
    custody_height: u64,
    proof: AvailabilityProof,
    shard: DataShard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodiedShard {
    pub proof: AvailabilityProof,
    pub shard: DataShard,
}

impl FilesystemShardStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(&root)
            .map_err(|error| format!("create shard store {}: {error}", root.display()))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| format!("inspect shard store {}: {error}", root.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("shard store root must be a real directory".into());
        }
        Ok(Self { root })
    }

    fn object_directory(&self, object_root: &str) -> Result<PathBuf, String> {
        validate_object_root(object_root)?;
        Ok(self.root.join(object_root))
    }

    fn shard_path(&self, object_root: &str, index: u32) -> Result<PathBuf, String> {
        Ok(self
            .object_directory(object_root)?
            .join(format!("{index}.json")))
    }

    fn read_record(path: &Path) -> Result<Option<StoredShard>, String> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("inspect shard {}: {error}", path.display())),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_STORED_SHARD_BYTES
        {
            return Err(format!("invalid stored shard {}", path.display()));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)
            .and_then(|file| {
                file.take(MAX_STORED_SHARD_BYTES + 1)
                    .read_to_end(&mut bytes)
            })
            .map_err(|error| format!("read shard {}: {error}", path.display()))?;
        if bytes.len() as u64 > MAX_STORED_SHARD_BYTES {
            return Err(format!("stored shard {} exceeds limit", path.display()));
        }
        let record: StoredShard = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode shard {}: {error}", path.display()))?;
        if record.version != STORE_VERSION {
            return Err(format!("unsupported shard version in {}", path.display()));
        }
        Ok(Some(record))
    }
}

impl ShardStore for FilesystemShardStore {
    fn put_custody_if_absent(
        &self,
        proof: &AvailabilityProof,
        shard: &DataShard,
        custody_height: u64,
    ) -> Result<(), String> {
        shard.validate(crate::serve::MAX_SHARD_BYTES)?;
        proof.validate()?;
        if proof.object_root != shard.object_root
            || proof.shard_root != shard.payload_root
            || proof.shard_index != shard.index
        {
            return Err("availability proof is not bound to stored shard".into());
        }
        let object_directory = self.object_directory(&shard.object_root)?;
        fs::create_dir_all(&object_directory).map_err(|error| {
            format!(
                "create shard object directory {}: {error}",
                object_directory.display()
            )
        })?;
        let object_metadata = fs::symlink_metadata(&object_directory)
            .map_err(|error| format!("inspect shard object directory: {error}"))?;
        if object_metadata.file_type().is_symlink() || !object_metadata.is_dir() {
            return Err("shard object path must be a real directory".into());
        }
        let final_path = self.shard_path(&shard.object_root, shard.index)?;
        if let Some(existing) = Self::read_record(&final_path)? {
            return if existing.shard == *shard && existing.proof == *proof {
                Ok(())
            } else {
                Err("conflicting shard already exists".into())
            };
        }
        let record = StoredShard {
            version: STORE_VERSION,
            custody_height,
            proof: proof.clone(),
            shard: shard.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| format!("encode availability shard: {error}"))?;
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging_path = object_directory.join(format!(
            ".{}.{}.{}.tmp",
            shard.index,
            std::process::id(),
            sequence
        ));
        let mut staging = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging_path)
            .map_err(|error| format!("create shard staging file: {error}"))?;
        let write_result = staging
            .write_all(&bytes)
            .and_then(|_| staging.sync_all())
            .map_err(|error| format!("persist shard staging file: {error}"));
        drop(staging);
        if let Err(error) = write_result {
            let _ = fs::remove_file(&staging_path);
            return Err(error);
        }
        let link_result = fs::hard_link(&staging_path, &final_path);
        let _ = fs::remove_file(&staging_path);
        match link_result {
            Ok(()) => File::open(&object_directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync shard object directory: {error}")),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let existing = Self::read_record(&final_path)?
                    .ok_or("shard disappeared during concurrent admission")?;
                if existing.shard == *shard && existing.proof == *proof {
                    Ok(())
                } else {
                    Err("conflicting shard admitted concurrently".into())
                }
            }
            Err(error) => Err(format!("commit availability shard: {error}")),
        }
    }

    fn get_custody(&self, object_root: &str, index: u32) -> Result<Option<CustodiedShard>, String> {
        let object_directory = self.object_directory(object_root)?;
        let metadata = match fs::symlink_metadata(&object_directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("inspect shard object directory: {error}")),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("shard object path must be a real directory".into());
        }
        let path = self.shard_path(object_root, index)?;
        let Some(record) = Self::read_record(&path)? else {
            return Ok(None);
        };
        record.shard.validate(crate::serve::MAX_SHARD_BYTES)?;
        if record.shard.object_root != object_root || record.shard.index != index {
            return Err("stored shard path binding mismatch".into());
        }
        record.proof.validate()?;
        if record.proof.object_root != object_root
            || record.proof.shard_root != record.shard.payload_root
            || record.proof.shard_index != index
        {
            return Err("stored custody proof binding mismatch".into());
        }
        Ok(Some(CustodiedShard {
            proof: record.proof,
            shard: record.shard,
        }))
    }

    fn remove_below(&self, height: u64) -> Result<u64, String> {
        if height == 0 {
            return Ok(0);
        }
        let mut removed = 0u64;
        for object in fs::read_dir(&self.root)
            .map_err(|error| format!("list shard store {}: {error}", self.root.display()))?
        {
            let object = object.map_err(|error| format!("read shard store entry: {error}"))?;
            let metadata = fs::symlink_metadata(object.path())
                .map_err(|error| format!("inspect shard object entry: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("shard object directory must not be a symlink".into());
            }
            if !metadata.is_dir() {
                continue;
            }
            for entry in fs::read_dir(object.path())
                .map_err(|error| format!("list shard object directory: {error}"))?
            {
                let entry = entry.map_err(|error| format!("read shard object entry: {error}"))?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let Some(record) = Self::read_record(&path)? else {
                    continue;
                };
                if record.custody_height < height {
                    fs::remove_file(&path).map_err(|error| {
                        format!("remove expired shard {}: {error}", path.display())
                    })?;
                    removed = removed
                        .checked_add(1)
                        .ok_or("removed shard count overflow")?;
                }
            }
        }
        if removed > 0 {
            File::open(&self.root)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync shard store after retention: {error}"))?;
        }
        Ok(removed)
    }
}

fn validate_object_root(object_root: &str) -> Result<(), String> {
    if matches!(object_root.len(), 64 | 128)
        && object_root
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("invalid availability object root".into())
    }
}
