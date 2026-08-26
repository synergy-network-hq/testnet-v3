//! Durable exact-material store for the normal protected pipeline.
//!
//! Certified vertices carry transaction commitments, not ciphertext bytes.
//! This store is the restart-safe retrieval authority for the complete
//! wallet-authenticated submission matching each commitment.

use crate::etdag::EtdagDigest;
use crate::p2p::messages::{
    ProtectedPipelineSemanticObject, MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES,
    MAX_PROTECTED_PIPELINE_REQUEST_IDS,
};
use crate::synergy_types::{Hash, Height};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const PROTECTED_CIPHERTEXT_STORE_FORMAT: &str = "synergy-posy-protected-ciphertext-material-v1";
pub const MAX_PROTECTED_CIPHERTEXT_STORE_OBJECTS: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredProtectedCiphertext {
    format: String,
    semantic_id: EtdagDigest,
    target_height: Height,
    target_context_root: Hash,
    object: ProtectedPipelineSemanticObject,
}

/// One-object-per-file durable store. Files are installed with a hard-link
/// no-replace operation, making a second byte-distinct value for the same
/// transaction commitment a permanent conflict rather than last-writer-wins.
#[derive(Debug, Clone)]
pub struct DurableProtectedCiphertextStore {
    directory: PathBuf,
}

static STORE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableProtectedCiphertextStore {
    pub fn at_directory(directory: impl Into<PathBuf>) -> Result<Self, String> {
        let directory = directory.into();
        if directory.as_os_str().is_empty() {
            return Err("protected ciphertext store directory is empty".to_string());
        }
        Ok(Self { directory })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn install(&self, object: &ProtectedPipelineSemanticObject) -> Result<(), String> {
        object.validate_shape()?;
        if object.encrypted_submission().is_none() {
            return Err(
                "protected ciphertext store accepts exact encrypted material only".to_string(),
            );
        }
        let semantic_id = object.declared_semantic_id().clone();
        let (target_height, target_context_root) = object.target_binding();
        let record = StoredProtectedCiphertext {
            format: PROTECTED_CIPHERTEXT_STORE_FORMAT.to_string(),
            semantic_id: semantic_id.clone(),
            target_height,
            target_context_root,
            object: object.clone(),
        };
        let bytes = serde_json::to_vec(&record)
            .map_err(|error| format!("encode protected ciphertext material: {error}"))?;
        if bytes.len().saturating_add(4) > MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES {
            return Err("protected ciphertext material exceeds its exact wire budget".to_string());
        }

        let _guard = STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "protected ciphertext store lock is poisoned".to_string())?;
        fs::create_dir_all(&self.directory).map_err(|error| {
            format!(
                "create protected ciphertext directory {}: {error}",
                self.directory.display()
            )
        })?;
        let path = self.object_path(&semantic_id)?;
        if path.exists() {
            let existing = self.load_unlocked(&semantic_id)?;
            if existing == *object {
                return Ok(());
            }
            return Err("PROTECTED_CIPHERTEXT_MATERIAL_CONFLICT".to_string());
        }
        if self.object_count_unlocked()? >= MAX_PROTECTED_CIPHERTEXT_STORE_OBJECTS {
            return Err("protected ciphertext durable capacity is exhausted".to_string());
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("clock failure for ciphertext persistence: {error}"))?
            .as_nanos();
        let temp = self.directory.join(format!(
            ".{}.tmp-{}-{nonce}",
            semantic_id.0,
            std::process::id()
        ));
        let result = (|| -> Result<(), String> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|error| format!("create ciphertext temp {}: {error}", temp.display()))?;
            file.write_all(&bytes)
                .map_err(|error| format!("write ciphertext temp {}: {error}", temp.display()))?;
            file.sync_all()
                .map_err(|error| format!("sync ciphertext temp {}: {error}", temp.display()))?;
            match fs::hard_link(&temp, &path) {
                Ok(()) => {
                    fs::remove_file(&temp).map_err(|error| {
                        format!("remove linked ciphertext temp {}: {error}", temp.display())
                    })?;
                    sync_directory(&self.directory)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self.load_unlocked(&semantic_id)?;
                    if existing != *object {
                        return Err("PROTECTED_CIPHERTEXT_MATERIAL_CONFLICT".to_string());
                    }
                    fs::remove_file(&temp).map_err(|remove_error| {
                        format!(
                            "remove idempotent ciphertext temp {}: {remove_error}",
                            temp.display()
                        )
                    })?;
                    Ok(())
                }
                Err(error) => Err(format!(
                    "atomically install protected ciphertext {}: {error}",
                    path.display()
                )),
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn load(
        &self,
        semantic_id: &EtdagDigest,
    ) -> Result<Option<ProtectedPipelineSemanticObject>, String> {
        let _guard = STORE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| "protected ciphertext store lock is poisoned".to_string())?;
        let path = self.object_path(semantic_id)?;
        if !path.exists() {
            return Ok(None);
        }
        self.load_unlocked(semantic_id).map(Some)
    }

    pub fn load_for_target(
        &self,
        target_height: Height,
        target_context_root: Hash,
        semantic_ids: &[EtdagDigest],
    ) -> Result<Vec<ProtectedPipelineSemanticObject>, String> {
        if target_height.0 == 0
            || target_context_root.is_zero()
            || semantic_ids.is_empty()
            || semantic_ids.len() > MAX_PROTECTED_PIPELINE_REQUEST_IDS
        {
            return Err("invalid protected ciphertext retrieval request".to_string());
        }
        let mut objects = Vec::new();
        for semantic_id in semantic_ids {
            if let Some(object) = self.load(semantic_id)? {
                if object.target_binding() == (target_height, target_context_root) {
                    objects.push(object);
                }
            }
        }
        Ok(objects)
    }

    fn load_unlocked(
        &self,
        semantic_id: &EtdagDigest,
    ) -> Result<ProtectedPipelineSemanticObject, String> {
        let path = self.object_path(semantic_id)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| format!("open protected ciphertext {}: {error}", path.display()))?;
        let length = file
            .metadata()
            .map_err(|error| format!("stat protected ciphertext {}: {error}", path.display()))?
            .len();
        if length == 0 || length > MAX_PROTECTED_PIPELINE_EVIDENCE_FRAME_BYTES as u64 {
            return Err("protected ciphertext durable record has invalid length".to_string());
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.read_to_end(&mut bytes)
            .map_err(|error| format!("read protected ciphertext {}: {error}", path.display()))?;
        let record: StoredProtectedCiphertext = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode protected ciphertext {}: {error}", path.display()))?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| format!("re-encode protected ciphertext: {error}"))?;
        if canonical != bytes {
            return Err("protected ciphertext record is not canonically serialized".to_string());
        }
        if record.format != PROTECTED_CIPHERTEXT_STORE_FORMAT
            || &record.semantic_id != semantic_id
            || record.object.declared_semantic_id() != semantic_id
            || record.object.target_binding() != (record.target_height, record.target_context_root)
            || record.object.encrypted_submission().is_none()
        {
            return Err("protected ciphertext durable binding mismatch".to_string());
        }
        record.object.validate_shape()?;
        Ok(record.object)
    }

    fn object_path(&self, semantic_id: &EtdagDigest) -> Result<PathBuf, String> {
        semantic_id.validate("protected ciphertext semantic id")?;
        if semantic_id.is_zero() {
            return Err("protected ciphertext semantic id is zero".to_string());
        }
        Ok(self.directory.join(format!("{}.json", semantic_id.0)))
    }

    fn object_count_unlocked(&self) -> Result<usize, String> {
        let mut count = 0usize;
        for entry in fs::read_dir(&self.directory).map_err(|error| {
            format!(
                "read protected ciphertext directory {}: {error}",
                self.directory.display()
            )
        })? {
            let entry =
                entry.map_err(|error| format!("read ciphertext directory entry: {error}"))?;
            if entry.path().extension().and_then(|value| value.to_str()) == Some("json") {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}

fn sync_directory(directory: &Path) -> Result<(), String> {
    OpenOptions::new()
        .read(true)
        .open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|error| format!("sync protected ciphertext directory: {error}"))
}
