//! Append-only finality store for the Chain 1266 `single_authority_v1` engine.
//!
//! This store deliberately does NOT reuse `TypedFinalityStore`: that type
//! structurally requires a `QuorumCertificate` per record, and single-authority
//! finality has no quorum, no votes, and no certificate. Synthesising a
//! one-signature QC purely to satisfy that shape would reintroduce the exact
//! consensus concepts this engine removes.
//!
//! Durability model:
//!   * finality log  - append-only framed records, fsynced on append
//!   * head pointer  - separate file, atomically replaced (tmp+fsync+rename+dir fsync)
//!
//! The head is advanced only after the log frame is durable, so a crash can
//! leave an un-referenced trailing frame (safe, recoverable) but never a head
//! pointing at data that is not fully on disk.

use crate::synergy_types::Hash;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION: u32 = 1;
pub const SINGLE_AUTHORITY_FRAME_VERSION: u32 = 1;
pub const SINGLE_AUTHORITY_CONSENSUS_PROTOCOL: &str = "single_authority_v1";

/// Frame layout: MAGIC(4) | frame_version(4 BE) | payload_len(8 BE) | payload | checksum(32)
const FRAME_MAGIC: [u8; 4] = *b"S1FR";
const FRAME_PREFIX_LEN: usize = 4 + 4 + 8;
const FRAME_CHECKSUM_LEN: usize = 32;
/// Defensive bound so a corrupt length field cannot request a huge allocation.
const MAX_FRAME_PAYLOAD_LEN: u64 = 4 * 1024 * 1024;

const FRAME_CHECKSUM_DOMAIN: &str = "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_FINALITY_FRAME_V1";

/// One finalized single-authority block. The canonical block *body* lives in
/// `chain_durability`'s committed-block log; this record carries only the
/// identity/roots/signature needed to verify and recover the finalized head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthorityFinalityRecord {
    pub schema_version: u32,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub consensus_protocol: String,
    pub release_id: String,
    pub height: u64,
    pub block_hash: Hash,
    pub parent_hash: Hash,
    pub state_root: Hash,
    pub transaction_root: Hash,
    pub receipt_root: Hash,
    pub authority_id: String,
    pub authority_public_key_fingerprint: String,
    pub authority_signature_base64: String,
    pub finalized_timestamp_ms: u64,
}

/// Immutable chain identity every record in one log must agree with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleAuthorityChainBinding {
    /// The first height this log contains. Genesis (height 0) is bound by the
    /// ML-DSA-87 start authorization and is NOT an authority-produced record,
    /// so a production chain starts this log at height 1.
    pub first_authority_height: u64,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub authority_id: String,
    pub authority_public_key_fingerprint: String,
}

/// Durable finalized-head pointer. Atomically replaced; never references a
/// finality frame that is not already fsynced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthorityFinalizedHead {
    pub schema_version: u32,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub height: u64,
    pub block_hash: Hash,
    pub state_root: Hash,
    /// Byte offset one past the end of the durable frame for `height`.
    pub finality_log_end_offset: u64,
}

/// Outcome of scanning the log during recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleAuthorityRecovery {
    pub records: Vec<SingleAuthorityFinalityRecord>,
    /// Offset one past the last intact, fully-verified frame.
    pub durable_end_offset: u64,
    /// True when a torn/short trailing frame was found and ignored.
    pub truncated_trailing_frame: bool,
}

impl SingleAuthorityRecovery {
    pub fn latest(&self) -> Option<&SingleAuthorityFinalityRecord> {
        self.records.last()
    }

    pub fn next_height_or(&self, first_authority_height: u64) -> u64 {
        self.records
            .last()
            .map(|r| r.height + 1)
            .unwrap_or(first_authority_height)
    }
}

fn frame_checksum(payload: &[u8]) -> Hash {
    Hash::from_domain_bytes(FRAME_CHECKSUM_DOMAIN, payload)
}

fn encode_frame(record: &SingleAuthorityFinalityRecord) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(record)
        .map_err(|error| format!("encode single-authority finality record: {error}"))?;
    if payload.len() as u64 > MAX_FRAME_PAYLOAD_LEN {
        return Err("single-authority finality record exceeds maximum frame size".to_string());
    }
    let mut frame = Vec::with_capacity(FRAME_PREFIX_LEN + payload.len() + FRAME_CHECKSUM_LEN);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&SINGLE_AUTHORITY_FRAME_VERSION.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.extend_from_slice(&frame_checksum(&payload).0);
    Ok(frame)
}

/// Frame decode outcome.
///
/// `IncompleteEof` means the frame is physically cut short by end-of-file —
/// the only class that may ever be discarded, and only when it begins strictly
/// after the durable head. Every other defect (bad magic, bad version,
/// oversized length, undecodable payload, or a COMPLETE-length frame whose
/// checksum does not verify) is returned as `Err` and fails closed, because a
/// full-length bad-checksum frame is indistinguishable from interior
/// corruption and must never be silently dropped.
enum FrameRead {
    Complete {
        record: Box<SingleAuthorityFinalityRecord>,
        end_offset: u64,
    },
    IncompleteEof,
}

fn read_frame_at(bytes: &[u8], offset: u64) -> Result<FrameRead, String> {
    let start = offset as usize;
    if start + FRAME_PREFIX_LEN > bytes.len() {
        return Ok(FrameRead::IncompleteEof);
    }
    if bytes[start..start + 4] != FRAME_MAGIC {
        return Err(format!(
            "single-authority finality log frame magic mismatch at offset {offset}"
        ));
    }
    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&bytes[start + 4..start + 8]);
    let frame_version = u32::from_be_bytes(version_bytes);
    if frame_version != SINGLE_AUTHORITY_FRAME_VERSION {
        return Err(format!(
            "unsupported single-authority finality frame version {frame_version} at offset {offset}"
        ));
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[start + 8..start + FRAME_PREFIX_LEN]);
    let payload_len = u64::from_be_bytes(len_bytes);
    if payload_len > MAX_FRAME_PAYLOAD_LEN {
        return Err(format!(
            "single-authority finality frame length {payload_len} exceeds maximum at offset {offset}"
        ));
    }
    let payload_start = start + FRAME_PREFIX_LEN;
    let payload_end = payload_start + payload_len as usize;
    let frame_end = payload_end + FRAME_CHECKSUM_LEN;
    if frame_end > bytes.len() {
        return Ok(FrameRead::IncompleteEof);
    }
    let payload = &bytes[payload_start..payload_end];
    let mut checksum = [0u8; 32];
    checksum.copy_from_slice(&bytes[payload_end..frame_end]);
    if frame_checksum(payload) != Hash(checksum) {
        return Err(format!(
            "single-authority finality frame checksum mismatch at offset {offset}: \
             the frame is complete-length, so this is treated as corruption, not a torn tail"
        ));
    }
    let record: SingleAuthorityFinalityRecord = serde_json::from_slice(payload).map_err(|error| {
        format!("decode single-authority finality record at offset {offset}: {error}")
    })?;
    Ok(FrameRead::Complete {
        record: Box::new(record),
        end_offset: frame_end as u64,
    })
}

fn validate_record_shape(
    record: &SingleAuthorityFinalityRecord,
    binding: &SingleAuthorityChainBinding,
) -> Result<(), String> {
    if record.schema_version != SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION {
        return Err(format!(
            "single-authority finality record schema {} is unsupported",
            record.schema_version
        ));
    }
    if record.consensus_protocol != SINGLE_AUTHORITY_CONSENSUS_PROTOCOL {
        return Err(format!(
            "single-authority finality record has consensus protocol {}",
            record.consensus_protocol
        ));
    }
    if record.chain_id != binding.chain_id {
        return Err(format!(
            "single-authority finality record chain id {} does not match bound chain {}",
            record.chain_id, binding.chain_id
        ));
    }
    if record.chain_incarnation != binding.chain_incarnation {
        return Err(format!(
            "single-authority finality record incarnation {} does not match bound incarnation {}",
            record.chain_incarnation, binding.chain_incarnation
        ));
    }
    if record.authority_id != binding.authority_id {
        return Err("single-authority finality record has a foreign authority id".to_string());
    }
    if record.authority_public_key_fingerprint != binding.authority_public_key_fingerprint {
        return Err(
            "single-authority finality record has a foreign authority key fingerprint".to_string(),
        );
    }
    if record.block_hash.is_zero() {
        return Err("single-authority finality record has a zero block hash".to_string());
    }
    if record.authority_signature_base64.is_empty() {
        return Err("single-authority finality record is unsigned".to_string());
    }
    if record.release_id.is_empty() {
        return Err("single-authority finality record has no release id".to_string());
    }
    Ok(())
}

fn validate_linkage(
    previous: Option<&SingleAuthorityFinalityRecord>,
    next: &SingleAuthorityFinalityRecord,
    first_authority_height: u64,
) -> Result<(), String> {
    match previous {
        None => {
            if next.height != first_authority_height {
                return Err(format!(
                    "single-authority finality log must begin at height {first_authority_height}, \
                     found {}",
                    next.height
                ));
            }
        }
        Some(previous) => {
            if next.height != previous.height + 1 {
                return Err(format!(
                    "single-authority finality height {} does not follow {}",
                    next.height, previous.height
                ));
            }
            if next.parent_hash != previous.block_hash {
                return Err(format!(
                    "single-authority finality record at height {} has a broken parent link",
                    next.height
                ));
            }
        }
    }
    Ok(())
}

fn sync_parent_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("path {} has no parent directory", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync directory {}: {error}", parent.display()))
}

/// Append-only single-authority finality store.
#[derive(Debug, Clone)]
pub struct SingleAuthorityFinalityStore {
    log_path: PathBuf,
    head_path: PathBuf,
    binding: SingleAuthorityChainBinding,
}

impl SingleAuthorityFinalityStore {
    pub fn at_paths(
        log_path: PathBuf,
        head_path: PathBuf,
        binding: SingleAuthorityChainBinding,
    ) -> Result<Self, String> {
        if log_path.as_os_str().is_empty() || head_path.as_os_str().is_empty() {
            return Err("single-authority finality store paths must not be empty".to_string());
        }
        if log_path == head_path {
            return Err(
                "single-authority finality log and head must be distinct files".to_string()
            );
        }
        if binding.authority_id.is_empty() {
            return Err("single-authority finality store requires an authority id".to_string());
        }
        if binding.authority_public_key_fingerprint.is_empty() {
            return Err(
                "single-authority finality store requires an authority key fingerprint".to_string(),
            );
        }
        Ok(Self {
            log_path,
            head_path,
            binding,
        })
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn head_path(&self) -> &Path {
        &self.head_path
    }

    pub fn binding(&self) -> &SingleAuthorityChainBinding {
        &self.binding
    }
}

impl SingleAuthorityFinalityStore {
    /// Scans the append-only log, verifying every frame and every linkage.
    /// A torn or checksum-invalid FINAL frame is reported (and ignorable);
    /// any inconsistency inside committed history fails closed.
    pub fn recover(&self) -> Result<SingleAuthorityRecovery, String> {
        let head = self.load_head()?;
        self.recover_with_head(head.as_ref())
    }

    /// Head-aware scan. The durable head is the commitment boundary: an
    /// incomplete tail frame may only be discarded when it begins strictly
    /// after the byte range the head has committed to.
    pub fn recover_with_head(
        &self,
        head: Option<&SingleAuthorityFinalizedHead>,
    ) -> Result<SingleAuthorityRecovery, String> {
        if !self.log_path.exists() {
            return Ok(SingleAuthorityRecovery {
                records: Vec::new(),
                durable_end_offset: 0,
                truncated_trailing_frame: false,
            });
        }
        let mut bytes = Vec::new();
        File::open(&self.log_path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|error| {
                format!(
                    "read single-authority finality log {}: {error}",
                    self.log_path.display()
                )
            })?;
        let mut records: Vec<SingleAuthorityFinalityRecord> = Vec::new();
        let mut offset: u64 = 0;
        let mut truncated = false;
        while (offset as usize) < bytes.len() {
            match read_frame_at(&bytes, offset)? {
                FrameRead::IncompleteEof => {
                    if let Some(head) = head {
                        if head.finality_log_end_offset > offset {
                            return Err(format!(
                                "single-authority finality log is truncated inside committed \
                                 history: durable head commits to offset {} but the frame at \
                                 offset {offset} is incomplete",
                                head.finality_log_end_offset
                            ));
                        }
                    }
                    truncated = true;
                    break;
                }
                FrameRead::Complete { record, end_offset } => {
                    validate_record_shape(&record, &self.binding)?;
                    validate_linkage(records.last(), &record, self.binding.first_authority_height)?;
                    records.push(*record);
                    offset = end_offset;
                }
            }
        }
        Ok(SingleAuthorityRecovery {
            records,
            durable_end_offset: offset,
            truncated_trailing_frame: truncated,
        })
    }
}

impl SingleAuthorityFinalityStore {
    /// Appends one finalized record and fsyncs the log. Does NOT advance the
    /// head: callers advance the head only after this returns durably.
    ///
    /// Idempotent for an exact duplicate of the current tail (crash between
    /// append-fsync and head-advance replays safely without rewriting).
    pub fn append_finalized(
        &self,
        record: &SingleAuthorityFinalityRecord,
    ) -> Result<u64, String> {
        validate_record_shape(record, &self.binding)?;
        let recovery = self.recover()?;
        if let Some(tail) = recovery.records.last() {
            if tail.height == record.height {
                if tail == record {
                    return Ok(recovery.durable_end_offset);
                }
                return Err(format!(
                    "single-authority finality height {} is already finalized with a different block",
                    record.height
                ));
            }
        }
        validate_linkage(recovery.records.last(), record, self.binding.first_authority_height)?;
        if recovery.truncated_trailing_frame {
            self.truncate_to(recovery.durable_end_offset)?;
        }
        let frame = encode_frame(record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|error| {
                format!(
                    "open single-authority finality log {}: {error}",
                    self.log_path.display()
                )
            })?;
        file.write_all(&frame)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("append single-authority finality frame: {error}"))?;
        Ok(recovery.durable_end_offset + frame.len() as u64)
    }

    /// O(1) frame append used by the cached writable store. The caller has
    /// ALREADY validated shape and linkage against its cached tail, so this
    /// performs no scan. `expected_end_offset` guards against a cache that has
    /// drifted from the file: the append is refused if the file length differs.
    pub fn append_frame_at(
        &self,
        record: &SingleAuthorityFinalityRecord,
        expected_end_offset: u64,
    ) -> Result<u64, String> {
        validate_record_shape(record, &self.binding)?;
        let actual_len = match fs::metadata(&self.log_path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("stat single-authority finality log: {error}")),
        };
        if actual_len < expected_end_offset {
            return Err(format!(
                "single-authority finality log is shorter ({actual_len}) than the cached durable \
                 end offset ({expected_end_offset}); refusing to append"
            ));
        }
        if actual_len > expected_end_offset {
            // Uncommitted trailing bytes beyond the cached durable boundary.
            self.truncate_to(expected_end_offset)?;
        }
        let frame = encode_frame(record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|error| format!("open single-authority finality log: {error}"))?;
        file.write_all(&frame)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("append single-authority finality frame: {error}"))?;
        Ok(expected_end_offset + frame.len() as u64)
    }

    fn truncate_to(&self, length: u64) -> Result<(), String> {
        let file = OpenOptions::new()
            .write(true)
            .open(&self.log_path)
            .map_err(|error| format!("open finality log for truncation: {error}"))?;
        file.set_len(length)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("truncate torn finality frame: {error}"))
    }
}

impl SingleAuthorityFinalityStore {
    /// Atomically replaces the durable finalized-head pointer.
    /// Must only be called after `append_finalized` has returned.
    pub fn commit_head(
        &self,
        record: &SingleAuthorityFinalityRecord,
        finality_log_end_offset: u64,
    ) -> Result<SingleAuthorityFinalizedHead, String> {
        validate_record_shape(record, &self.binding)?;
        let head = SingleAuthorityFinalizedHead {
            schema_version: SINGLE_AUTHORITY_FINALITY_SCHEMA_VERSION,
            chain_id: record.chain_id,
            chain_incarnation: record.chain_incarnation,
            height: record.height,
            block_hash: record.block_hash,
            state_root: record.state_root,
            finality_log_end_offset,
        };
        let bytes = serde_json::to_vec(&head)
            .map_err(|error| format!("encode single-authority finalized head: {error}"))?;
        let temp_path = self.head_path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            record.height
        ));
        if let Some(parent) = self.head_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create head directory {}: {error}", parent.display()))?;
        }
        {
            let mut file = File::create(&temp_path)
                .map_err(|error| format!("create temporary head file: {error}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write temporary head file: {error}"))?;
        }
        fs::rename(&temp_path, &self.head_path)
            .map_err(|error| format!("replace single-authority head: {error}"))?;
        sync_parent_directory(&self.head_path)?;
        Ok(head)
    }

    pub fn load_head(&self) -> Result<Option<SingleAuthorityFinalizedHead>, String> {
        if !self.head_path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&self.head_path)
            .map_err(|error| format!("read single-authority head: {error}"))?;
        let head: SingleAuthorityFinalizedHead = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode single-authority head: {error}"))?;
        Ok(Some(head))
    }
}

/// Reconciled startup state: the exact height the authority may produce next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleAuthorityStartupState {
    pub finalized: Option<SingleAuthorityFinalityRecord>,
    pub next_height: u64,
    pub head_advanced_during_recovery: bool,
    pub truncated_trailing_frame: bool,
}

impl SingleAuthorityFinalityStore {
    /// Resolves log-vs-head disagreement deterministically and fails closed on
    /// any state that could produce a fork.
    ///
    /// Legal crash window: log frame durable, head not yet advanced. The log is
    /// authoritative there, and the head is rolled forward.
    /// Illegal: head ahead of the log (head must never outrun durable data).
    pub fn recover_startup_state(&self) -> Result<SingleAuthorityStartupState, String> {
        let head = self.load_head()?;
        let recovery = self.recover_with_head(head.as_ref())?;
        let latest = recovery.records.last().cloned();
        let mut head_advanced = false;

        match (&head, &latest) {
            (Some(head), None) => {
                return Err(format!(
                    "single-authority head claims height {} but the finality log is empty",
                    head.height
                ));
            }
            (Some(head), Some(latest)) => {
                if head.chain_id != latest.chain_id
                    || head.chain_incarnation != latest.chain_incarnation
                {
                    return Err(
                        "single-authority head chain identity disagrees with the finality log"
                            .to_string(),
                    );
                }
                if head.height > latest.height {
                    return Err(format!(
                        "single-authority head height {} exceeds durable finality height {}",
                        head.height, latest.height
                    ));
                }
                if head.height == latest.height && head.block_hash != latest.block_hash {
                    return Err(format!(
                        "single-authority head hash disagrees with the finalized block at height {}",
                        head.height
                    ));
                }
                if head.height < latest.height {
                    self.commit_head(latest, recovery.durable_end_offset)?;
                    head_advanced = true;
                }
            }
            (None, Some(latest)) => {
                self.commit_head(latest, recovery.durable_end_offset)?;
                head_advanced = true;
            }
            (None, None) => {}
        }

        Ok(SingleAuthorityStartupState {
            next_height: recovery.next_height_or(self.binding.first_authority_height),
            finalized: latest,
            head_advanced_during_recovery: head_advanced,
            truncated_trailing_frame: recovery.truncated_trailing_frame,
        })
    }
}
