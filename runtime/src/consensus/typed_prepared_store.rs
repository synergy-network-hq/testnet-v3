//! Crash-safe persistence for the active typed PoSy prepared candidate.
//!
//! Finality and active-round state have different lifecycles.  The finality
//! store remains the sole canonical chain record, while this store retains only
//! the verified proposal/VC and latest TC needed to resume an incomplete
//! height.  It is cleared atomically after the height finalizes.

use crate::consensus::typed_finality_store::TypedFinalityStore;
use crate::synergy_types::{Block, Hash, Height, TimeoutCertificate, ValidationCertificate};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TYPED_PREPARED_RECORD_VERSION: u32 = 1;
const STORE_VERSION: u32 = TYPED_PREPARED_RECORD_VERSION;
const TYPED_PREPARED_FILE: &str = "typed-posy-prepared.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedPreparedRecord {
    pub record_version: u32,
    pub height: Height,
    pub height_context_root: Hash,
    pub block: Block,
    pub validation_certificate: ValidationCertificate,
    pub timeout_certificate: Option<TimeoutCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TypedPreparedState {
    store_version: u32,
    genesis_anchor: Hash,
    prepared: Option<TypedPreparedRecord>,
}

#[derive(Debug, Clone)]
pub struct TypedPreparedStore {
    path: PathBuf,
    genesis_anchor: Hash,
}

impl TypedPreparedStore {
    pub fn for_finality_store(finality_store: &TypedFinalityStore) -> Result<Self, String> {
        let finality_path = finality_store.path();
        let parent = finality_path.parent().ok_or_else(|| {
            "typed finality store path has no directory for prepared state".to_string()
        })?;
        let path = if finality_path.file_name().and_then(|name| name.to_str())
            == Some("typed-posy-finality.json")
        {
            parent.join(TYPED_PREPARED_FILE)
        } else {
            // Explicit test/transient finality paths must not collapse into
            // one shared sibling store.
            finality_path.with_extension("prepared.json")
        };
        Self::at_path(path, finality_store.genesis_anchor())
    }

    pub fn at_path(path: PathBuf, genesis_anchor: Hash) -> Result<Self, String> {
        if path.as_os_str().is_empty() || genesis_anchor.is_zero() {
            return Err("typed prepared store requires a path and Genesis anchor".to_string());
        }
        Ok(Self {
            path,
            genesis_anchor,
        })
    }

    pub fn recover(&self) -> Result<Option<TypedPreparedRecord>, String> {
        Ok(self.load_state()?.prepared)
    }

    pub fn persist_verified(
        &self,
        block: &Block,
        validation_certificate: &ValidationCertificate,
        timeout_certificate: Option<&TimeoutCertificate>,
    ) -> Result<TypedPreparedRecord, String> {
        let record = TypedPreparedRecord {
            record_version: STORE_VERSION,
            height: block.header.height,
            height_context_root: block.header.height_context_root,
            block: block.clone(),
            validation_certificate: validation_certificate.clone(),
            timeout_certificate: timeout_certificate.cloned(),
        };
        validate_record(&record)?;
        let mut state = self.load_state()?;
        if let Some(existing) = &state.prepared {
            if existing.height == record.height
                && existing.block.candidate_id()? != record.block.candidate_id()?
            {
                if record.validation_certificate.round.0 <= existing.validation_certificate.round.0
                {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: durable prepared candidates disagree in the same or an older round"
                            .to_string(),
                    );
                }
            }
            if existing.height.0 > record.height.0 {
                return Err("typed prepared store refuses a stale height".to_string());
            }
            if let (Some(old), Some(new)) = (
                existing.timeout_certificate.as_ref(),
                record.timeout_certificate.as_ref(),
            ) {
                if old.height == new.height && old.next_round.0 > new.next_round.0 {
                    return Err(
                        "typed prepared store refuses a stale timeout certificate".to_string()
                    );
                }
            }
        }
        state.prepared = Some(record.clone());
        self.persist_state(&state)?;
        Ok(record)
    }

    pub fn clear_after_finality(&self, finalized_height: Height) -> Result<(), String> {
        let mut state = self.load_state()?;
        if let Some(record) = &state.prepared {
            if record.height.0 > finalized_height.0 {
                return Err("typed prepared store refuses to clear a future height".to_string());
            }
        }
        state.prepared = None;
        self.persist_state(&state)
    }

    fn empty_state(&self) -> TypedPreparedState {
        TypedPreparedState {
            store_version: STORE_VERSION,
            genesis_anchor: self.genesis_anchor,
            prepared: None,
        }
    }

    fn load_state(&self) -> Result<TypedPreparedState, String> {
        if !self.path.exists() {
            return Ok(self.empty_state());
        }
        let bytes = fs::read(&self.path).map_err(|error| {
            format!(
                "read typed PoSy prepared store {}: {error}",
                self.path.display()
            )
        })?;
        let state: TypedPreparedState = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse typed PoSy prepared store {}: {error}",
                self.path.display()
            )
        })?;
        let canonical = serde_json::to_vec(&state)
            .map_err(|error| format!("canonicalize typed PoSy prepared store: {error}"))?;
        if bytes != canonical {
            return Err(
                "typed PoSy prepared store is not canonical; refusing mutable or torn state"
                    .to_string(),
            );
        }
        validate_state(&state, self.genesis_anchor)?;
        Ok(state)
    }

    fn persist_state(&self, state: &TypedPreparedState) -> Result<(), String> {
        validate_state(state, self.genesis_anchor)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "typed prepared store path has no parent".to_string())?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create typed PoSy prepared directory {}: {error}",
                parent.display()
            )
        })?;
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("clock failure for typed prepared persistence: {error}"))?
            .as_nanos();
        let temp_path = self
            .path
            .with_extension(format!("tmp-{}-{nonce}", std::process::id()));
        let bytes = serde_json::to_vec(state)
            .map_err(|error| format!("encode typed PoSy prepared state: {error}"))?;
        let result = (|| -> Result<(), String> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp_path).map_err(|error| {
                format!(
                    "open typed PoSy prepared temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            file.write_all(&bytes).map_err(|error| {
                format!(
                    "write typed PoSy prepared temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "sync typed PoSy prepared temp file {}: {error}",
                    temp_path.display()
                )
            })?;
            fs::rename(&temp_path, &self.path).map_err(|error| {
                format!(
                    "atomically replace typed PoSy prepared store {}: {error}",
                    self.path.display()
                )
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    format!(
                        "sync typed PoSy prepared directory {}: {error}",
                        parent.display()
                    )
                })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }
}

fn validate_state(state: &TypedPreparedState, expected_genesis_anchor: Hash) -> Result<(), String> {
    if state.store_version != STORE_VERSION {
        return Err(format!(
            "unsupported typed PoSy prepared store version {}; expected {}",
            state.store_version, STORE_VERSION
        ));
    }
    if state.genesis_anchor != expected_genesis_anchor {
        return Err(
            "typed PoSy prepared store Genesis anchor does not match this node".to_string(),
        );
    }
    if let Some(record) = &state.prepared {
        validate_record(record)?;
    }
    Ok(())
}

fn validate_record(record: &TypedPreparedRecord) -> Result<(), String> {
    if record.record_version != STORE_VERSION
        || record.height.0 == 0
        || record.height_context_root.is_zero()
        || record.block.header.height != record.height
        || record.block.header.height_context_root != record.height_context_root
        || record.validation_certificate.height != record.height
        || record.validation_certificate.height_context_root != record.height_context_root
        || record.validation_certificate.candidate_id != record.block.candidate_id()?
    {
        return Err("typed PoSy prepared record has inconsistent block/VC bindings".to_string());
    }
    if let Some(tc) = &record.timeout_certificate {
        let carries_prepared = tc.carry_forward_candidate_id.as_ref()
            == Some(&record.validation_certificate.candidate_id)
            && tc.highest_prepared_vc_root == Some(record.validation_certificate.root()?);
        let authorizes_prepared_round = tc.carry_forward_candidate_id.is_none()
            && tc.highest_prepared_vc_root.is_none()
            && tc.next_round == record.block.header.round
            && record.validation_certificate.round == record.block.header.round;
        if tc.height != record.height
            || tc.height_context_root != record.height_context_root
            || tc.next_round.0 <= tc.closing_round.0
            || (!carries_prepared && !authorizes_prepared_round)
        {
            return Err("typed PoSy prepared record has inconsistent TC bindings".to_string());
        }
    }
    Ok(())
}
