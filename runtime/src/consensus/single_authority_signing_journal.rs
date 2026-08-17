//! Durable sign-once journal for `single_authority_v1` block production.
//!
//! `ConsensusSigningAuthorization` cannot be reused here: it structurally
//! requires epoch/round/cluster/validator/BFT-phase and rejects height 0.
//! Fabricating those values would reintroduce the consensus concepts this
//! engine removes, so this journal is dedicated - but it deliberately mirrors
//! the canonical safety discipline of `sign_consensus_vote`:
//! ML-DSA-65 signatures in this codebase are RANDOMIZED, therefore a restart
//! must REPLAY the exact durable signature and must never produce a second
//! signature for the same subject.
//!
//! Genesis/height 0 is NOT signed here - it is bound by the separate ML-DSA-87
//! chain-start/governance authorization. This journal covers authority-produced
//! post-Genesis blocks only.

use crate::synergy_types::Hash;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Signing domain for single-authority block production.
pub const SYNERGY_CHAIN1266_SINGLE_AUTHORITY_BLOCK_V1: &str =
    "SYNERGY_CHAIN1266_SINGLE_AUTHORITY_BLOCK_V1";

pub const SINGLE_AUTHORITY_JOURNAL_SCHEMA_VERSION: u32 = 1;
pub const SINGLE_AUTHORITY_SIGNATURE_ALGORITHM: &str = "mldsa65";
/// The authority journal never covers Genesis; production starts here.
pub const FIRST_AUTHORITY_PRODUCED_HEIGHT: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SingleAuthorityJournalState {
    Authorized,
    Signed,
    Finalized,
    SafetyHalt,
}

/// The immutable subject a signature is bound to. Two different blocks can
/// never share a subject, so one height admits exactly one payload digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthoritySigningSubject {
    pub schema_version: u32,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub consensus_protocol: String,
    pub authority_id: String,
    pub authority_key_id: String,
    pub release_id: String,
    pub height: u64,
    pub parent_hash: Hash,
    pub canonical_block_hash: Hash,
    pub canonical_signing_payload_digest: Hash,
}

impl SingleAuthoritySigningSubject {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SINGLE_AUTHORITY_JOURNAL_SCHEMA_VERSION {
            return Err("single-authority signing subject schema is unsupported".to_string());
        }
        if self.consensus_protocol
            != super::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL
        {
            return Err("single-authority signing subject has a foreign protocol".to_string());
        }
        if self.height < FIRST_AUTHORITY_PRODUCED_HEIGHT {
            return Err(format!(
                "height {} is not authority-produced: Genesis is authorized by the ML-DSA-87 \
                 chain-start authorization, not the block signing journal",
                self.height
            ));
        }
        if self.authority_id.trim().is_empty() || self.authority_key_id.trim().is_empty() {
            return Err("single-authority signing subject identity is missing".to_string());
        }
        if self.release_id.trim().is_empty() {
            return Err("single-authority signing subject release id is missing".to_string());
        }
        if self.canonical_block_hash.is_zero() || self.canonical_signing_payload_digest.is_zero() {
            return Err("single-authority signing subject digests must be nonzero".to_string());
        }
        Ok(())
    }

    /// Stable identity for the height slot - one per height, per incarnation.
    pub fn slot_key(&self) -> (u64, u64, u64) {
        (self.chain_id, self.chain_incarnation, self.height)
    }
}

/// The exact public signature material needed to replay a produced signature.
/// The private key must never appear here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthoritySignatureRecord {
    pub signature_algorithm: String,
    pub signature_base64: String,
    pub authority_public_key_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthorityJournalEntry {
    pub subject: SingleAuthoritySigningSubject,
    pub state: SingleAuthorityJournalState,
    pub signature: Option<SingleAuthoritySignatureRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SingleAuthoritySafetyHalt {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub consensus_protocol: String,
    pub authority_id: String,
    pub release_id: String,
    pub height: u64,
    pub reason: String,
    pub recorded_unix_ms: u64,
}

/// The active signer identity. A halt only blocks signing when every field
/// matches: a halt from another incarnation, protocol, authority, or release
/// stays visible for audit but must never block the active chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleAuthorityHaltNamespace {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub consensus_protocol: String,
    pub authority_id: String,
    pub release_id: String,
}

impl SingleAuthorityHaltNamespace {
    pub fn matches(&self, halt: &SingleAuthoritySafetyHalt) -> bool {
        halt.chain_id == self.chain_id
            && halt.chain_incarnation == self.chain_incarnation
            && halt.consensus_protocol == self.consensus_protocol
            && halt.authority_id == self.authority_id
            && halt.release_id == self.release_id
    }

    pub fn from_subject(subject: &SingleAuthoritySigningSubject) -> Self {
        Self {
            chain_id: subject.chain_id,
            chain_incarnation: subject.chain_incarnation,
            consensus_protocol: subject.consensus_protocol.clone(),
            authority_id: subject.authority_id.clone(),
            release_id: subject.release_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    #[serde(default)]
    entries: Vec<SingleAuthorityJournalEntry>,
    #[serde(default)]
    safety_halts: Vec<SingleAuthoritySafetyHalt>,
}

/// Small, separate progress marker for the compact journal.  The canonical
/// journal deliberately remains a V1 `JournalFile` so a verified emergency
/// rollback can continue to decode it with the previous runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHotState {
    schema_version: u32,
    finalized_through: u64,
}

const SINGLE_AUTHORITY_JOURNAL_HOT_STATE_SCHEMA_VERSION: u32 = 1;

/// What the driver must do for a height after inspecting the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingleAuthoritySigningDecision {
    /// No durable record - safe to authorize and sign fresh.
    SignFresh,
    /// A signature was durably recorded for this exact subject: replay it.
    ReplayExisting(SingleAuthoritySignatureRecord),
    /// Authorized but no durable signature: signing may or may not have
    /// occurred, and ML-DSA-65 is randomized, so re-signing could create a
    /// second distinct signature for one height. Fail closed.
    SafetyHalt(String),
}

/// Durable, atomically-replaced sign-once journal.
#[derive(Debug, Clone)]
pub struct SingleAuthoritySigningJournal {
    path: PathBuf,
}

impl SingleAuthoritySigningJournal {
    /// Reconcile the compact journal with the already-recovered durable
    /// finality head.  Migration is ordered archive -> compact journal -> hot
    /// state; every interrupted point can be recovered without authorizing a
    /// second signature for a height.
    pub fn reconcile_finalized_head(
        &self,
        namespace: &SingleAuthorityHaltNamespace,
        finalized_height: u64,
        finalized_hash: Option<&Hash>,
    ) -> Result<(), String> {
        let mut journal = self.load()?;
        match self.load_hot_state()? {
            Some(hot_state) => {
                if finalized_height < hot_state.finalized_through {
                    return Err(format!(
                        "single-authority finalized head regressed from {} to {}",
                        hot_state.finalized_through, finalized_height
                    ));
                }
                let changed = Self::compact_entries_for_finality_head(
                    &mut journal,
                    namespace,
                    finalized_height,
                    finalized_hash,
                )?;
                if changed {
                    self.persist(&journal)?;
                }
                if finalized_height != hot_state.finalized_through {
                    self.persist_hot_state(finalized_height)?;
                }
            }
            None => {
                // A non-empty V1 journal must be bound to recovered finality
                // before it can be used again.  Preserve its exact bytes first.
                let archive_matches_canonical = self.archive_legacy_journal()?;
                let changed = Self::compact_entries_for_finality_head(
                    &mut journal,
                    namespace,
                    finalized_height,
                    finalized_hash,
                )?;

                // If the archive already differed, a prior process completed
                // the canonical compaction but crashed before writing hot
                // state.  Validating the compact current file above makes it
                // safe to complete that interrupted migration.
                if changed || archive_matches_canonical {
                    self.persist(&journal)?;
                }
                self.persist_hot_state(finalized_height)?;
            }
        }
        Ok(())
    }

    fn compact_entries_for_finality_head(
        journal: &mut JournalFile,
        namespace: &SingleAuthorityHaltNamespace,
        finalized_height: u64,
        finalized_hash: Option<&Hash>,
    ) -> Result<bool, String> {
        let mut retained = Vec::with_capacity(1);
        let mut seen_heights = std::collections::BTreeSet::new();
        let original_len = journal.entries.len();
        for entry in std::mem::take(&mut journal.entries) {
            entry.subject.validate()?;
            if entry.subject.chain_id != namespace.chain_id
                || entry.subject.chain_incarnation != namespace.chain_incarnation
                || entry.subject.consensus_protocol != namespace.consensus_protocol
                || entry.subject.authority_id != namespace.authority_id
                || entry.subject.release_id != namespace.release_id
            {
                return Err(
                    "signing journal contains an entry outside the active authority binding"
                        .to_string(),
                );
            }
            if !seen_heights.insert(entry.subject.height) {
                return Err(format!(
                    "signing journal contains multiple entries for height {}",
                    entry.subject.height
                ));
            }
            if entry.subject.height <= finalized_height {
                if !matches!(
                    entry.state,
                    SingleAuthorityJournalState::Signed | SingleAuthorityJournalState::Finalized
                ) || entry.signature.is_none()
                {
                    return Err(format!(
                        "signing journal entry at finalized height {} is not a durable signature",
                        entry.subject.height
                    ));
                }
                if entry.subject.height == finalized_height
                    && finalized_hash
                        .is_some_and(|hash| entry.subject.canonical_block_hash != *hash)
                {
                    return Err(format!(
                        "signing journal entry at finalized height {} disagrees with the durable finality head",
                        finalized_height
                    ));
                }
                continue;
            }
            if entry.subject.height != finalized_height.saturating_add(1) {
                return Err(format!(
                    "signing journal contains out-of-window height {} while durable finality is {}",
                    entry.subject.height, finalized_height
                ));
            }
            if entry.state == SingleAuthorityJournalState::Finalized {
                return Err(format!(
                    "signing journal marks height {} finalized but durable finality is still {}",
                    entry.subject.height, finalized_height
                ));
            }
            retained.push(entry);
        }
        let changed = retained.len() != original_len;
        journal.entries = retained;
        Ok(changed)
    }

    fn active_hot_state_for(&self, journal: &JournalFile) -> Result<JournalHotState, String> {
        match self.load_hot_state()? {
            Some(state) => Ok(state),
            None if journal.entries.is_empty() => {
                // Direct journal users (including an empty fresh installation)
                // have no historical V1 state to migrate.  The driver performs
                // the stricter finality-bound reconciliation before production.
                self.persist_hot_state(0)?;
                Ok(JournalHotState {
                    schema_version: SINGLE_AUTHORITY_JOURNAL_HOT_STATE_SCHEMA_VERSION,
                    finalized_through: 0,
                })
            }
            None => Err(
                "single-authority signing journal has legacy entries but no finalized-head reconciliation"
                    .to_string(),
            ),
        }
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn archive_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.legacy-v1-archive.json", self.path.display()))
    }

    fn hot_state_path(&self) -> PathBuf {
        PathBuf::from(format!("{}.hot-state.json", self.path.display()))
    }

    fn load(&self) -> Result<JournalFile, String> {
        if !self.path.exists() {
            return Ok(JournalFile::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| format!("read single-authority signing journal: {error}"))?;
        serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode single-authority signing journal: {error}"))
    }

    fn persist(&self, journal: &JournalFile) -> Result<(), String> {
        self.atomic_write_json(&self.path, journal, "signing journal")
    }

    fn load_hot_state(&self) -> Result<Option<JournalHotState>, String> {
        let path = self.hot_state_path();
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&path)
            .map_err(|error| format!("read single-authority journal hot state: {error}"))?;
        let state: JournalHotState = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode single-authority journal hot state: {error}"))?;
        if state.schema_version != SINGLE_AUTHORITY_JOURNAL_HOT_STATE_SCHEMA_VERSION {
            return Err(format!(
                "single-authority journal hot state schema {} is unsupported",
                state.schema_version
            ));
        }
        Ok(Some(state))
    }

    fn persist_hot_state(&self, finalized_through: u64) -> Result<(), String> {
        self.atomic_write_json(
            &self.hot_state_path(),
            &JournalHotState {
                schema_version: SINGLE_AUTHORITY_JOURNAL_HOT_STATE_SCHEMA_VERSION,
                finalized_through,
            },
            "journal hot state",
        )
    }

    fn atomic_write_json<T: Serialize>(
        &self,
        path: &Path,
        value: &T,
        description: &str,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| format!("encode single-authority {description}: {error}"))?;
        self.atomic_write_bytes(path, &bytes, description)
    }

    fn atomic_write_bytes(
        &self,
        path: &Path,
        bytes: &[u8],
        description: &str,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create {description} directory: {error}"))?;
        }
        let temp = path.with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = File::create(&temp)
                .map_err(|error| format!("create temporary {description}: {error}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write temporary {description}: {error}"))?;
        }
        fs::rename(&temp, path).map_err(|error| format!("replace {description}: {error}"))?;
        if let Some(parent) = path.parent() {
            let _ = File::open(parent).and_then(|dir| dir.sync_all());
        }
        Ok(())
    }

    /// Persist an immutable byte-for-byte V1 archive before compacting the
    /// canonical journal.  Streaming copy/comparison avoids a second large
    /// allocation during the one-time migration.
    fn archive_legacy_journal(&self) -> Result<bool, String> {
        if !self.path.exists() {
            return Ok(false);
        }
        let archive = self.archive_path();
        if archive.exists() {
            return Self::files_equal(&self.path, &archive)
                .map_err(|error| format!("compare single-authority journal archive: {error}"));
        }

        if let Some(parent) = archive.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create journal archive directory: {error}"))?;
        }
        let temp = archive.with_extension(format!("tmp-{}", std::process::id()));
        let mut source = File::open(&self.path)
            .map_err(|error| format!("open legacy signing journal for archive: {error}"))?;
        let mut destination = File::create(&temp)
            .map_err(|error| format!("create temporary journal archive: {error}"))?;
        io::copy(&mut source, &mut destination)
            .and_then(|_| destination.sync_all())
            .map_err(|error| format!("write journal archive: {error}"))?;
        fs::rename(&temp, &archive).map_err(|error| format!("replace journal archive: {error}"))?;
        if let Some(parent) = archive.parent() {
            let _ = File::open(parent).and_then(|dir| dir.sync_all());
        }
        Ok(true)
    }

    fn files_equal(left: &Path, right: &Path) -> Result<bool, io::Error> {
        if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
            return Ok(false);
        }
        let mut left = File::open(left)?;
        let mut right = File::open(right)?;
        let mut left_buf = [0u8; 64 * 1024];
        let mut right_buf = [0u8; 64 * 1024];
        loop {
            let left_read = left.read(&mut left_buf)?;
            let right_read = right.read(&mut right_buf)?;
            if left_read != right_read {
                return Ok(false);
            }
            if left_read == 0 {
                return Ok(true);
            }
            if left_buf[..left_read] != right_buf[..right_read] {
                return Ok(false);
            }
        }
    }
}

impl SingleAuthoritySigningJournal {
    /// Mirrors `require_signing_allowed()`: any recorded halt disables signing.
    /// Only halts inside the active namespace block signing. Halts from other
    /// incarnations/protocols/authorities/releases remain readable via
    /// `safety_halts()` for audit but never gate the active signer.
    pub fn require_signing_allowed(
        &self,
        namespace: &SingleAuthorityHaltNamespace,
    ) -> Result<(), String> {
        let journal = self.load()?;
        if let Some(halt) = journal
            .safety_halts
            .iter()
            .find(|halt| namespace.matches(halt))
        {
            return Err(format!(
                "SINGLE_AUTHORITY_SAFETY_HALT: signing disabled for chain {} incarnation {} \
                 authority {} at height {}: {}",
                halt.chain_id, halt.chain_incarnation, halt.authority_id, halt.height, halt.reason
            ));
        }
        Ok(())
    }

    pub fn safety_halts(&self) -> Result<Vec<SingleAuthoritySafetyHalt>, String> {
        Ok(self.load()?.safety_halts)
    }

    /// Every durable journal entry, for startup binding verification.
    pub fn entries(&self) -> Result<Vec<SingleAuthorityJournalEntry>, String> {
        Ok(self.load()?.entries)
    }

    pub fn enter_safety_halt(
        &self,
        namespace: &SingleAuthorityHaltNamespace,
        height: u64,
        reason: &str,
    ) -> Result<(), String> {
        let mut journal = self.load()?;
        journal.safety_halts.push(SingleAuthoritySafetyHalt {
            chain_id: namespace.chain_id,
            chain_incarnation: namespace.chain_incarnation,
            consensus_protocol: namespace.consensus_protocol.clone(),
            authority_id: namespace.authority_id.clone(),
            release_id: namespace.release_id.clone(),
            height,
            reason: reason.to_string(),
            recorded_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or_default(),
        });
        if let Some(entry) = journal
            .entries
            .iter_mut()
            .find(|entry| entry.subject.height == height)
        {
            entry.state = SingleAuthorityJournalState::SafetyHalt;
        }
        self.persist(&journal)
    }

    pub fn entry_for_height(
        &self,
        height: u64,
    ) -> Result<Option<SingleAuthorityJournalEntry>, String> {
        Ok(self
            .load()?
            .entries
            .into_iter()
            .find(|entry| entry.subject.height == height))
    }

    /// True only when the journal holds this exact subject.
    pub fn contains_exact(&self, subject: &SingleAuthoritySigningSubject) -> Result<bool, String> {
        Ok(self
            .entry_for_height(subject.height)?
            .is_some_and(|entry| &entry.subject == subject))
    }
}

impl SingleAuthoritySigningJournal {
    /// Step 5 of the signing order: durably record intent BEFORE signing.
    /// Rejects any attempt to authorize a different subject at a height that
    /// already has one.
    pub fn authorize_before_signature(
        &self,
        subject: &SingleAuthoritySigningSubject,
    ) -> Result<SingleAuthoritySigningDecision, String> {
        subject.validate()?;
        self.require_signing_allowed(&SingleAuthorityHaltNamespace::from_subject(subject))?;
        let mut journal = self.load()?;
        let hot_state = self.active_hot_state_for(&journal)?;
        let expected_height = hot_state.finalized_through.saturating_add(1);
        if subject.height != expected_height {
            return Err(format!(
                "single-authority signing subject height {} is outside the active slot {}; reconcile durable finality before signing",
                subject.height, expected_height
            ));
        }

        if let Some(existing) = journal
            .entries
            .iter()
            .find(|entry| entry.subject.slot_key() == subject.slot_key())
        {
            if &existing.subject != subject {
                return Err(format!(
                    "single-authority height {} is already bound to a different signing subject; \
                     refusing to authorize a second block for one height",
                    subject.height
                ));
            }
            return Ok(match (&existing.state, &existing.signature) {
                (SingleAuthorityJournalState::SafetyHalt, _) => {
                    SingleAuthoritySigningDecision::SafetyHalt(format!(
                        "height {} is halted",
                        subject.height
                    ))
                }
                (_, Some(signature)) => {
                    SingleAuthoritySigningDecision::ReplayExisting(signature.clone())
                }
                (SingleAuthorityJournalState::Authorized, None) => {
                    SingleAuthoritySigningDecision::SafetyHalt(format!(
                        "height {} was authorized but no durable signature exists; ML-DSA-65 is \
                         randomized, so re-signing could produce a second distinct signature for \
                         one height",
                        subject.height
                    ))
                }
                (_, None) => SingleAuthoritySigningDecision::SafetyHalt(format!(
                    "height {} has an inconsistent journal state",
                    subject.height
                )),
            });
        }

        journal.entries.push(SingleAuthorityJournalEntry {
            subject: subject.clone(),
            state: SingleAuthorityJournalState::Authorized,
            signature: None,
        });
        self.persist(&journal)?;
        Ok(SingleAuthoritySigningDecision::SignFresh)
    }
}

impl SingleAuthoritySigningJournal {
    /// Step 8: persist the exact produced signature. Must be called with the
    /// signature already verified against the canonical payload.
    pub fn record_signature(
        &self,
        subject: &SingleAuthoritySigningSubject,
        signature: &SingleAuthoritySignatureRecord,
    ) -> Result<(), String> {
        subject.validate()?;
        if signature.signature_algorithm != SINGLE_AUTHORITY_SIGNATURE_ALGORITHM {
            return Err(format!(
                "single-authority block signature must be {}, found {}",
                SINGLE_AUTHORITY_SIGNATURE_ALGORITHM, signature.signature_algorithm
            ));
        }
        if signature.signature_base64.trim().is_empty() {
            return Err("single-authority signature record is empty".to_string());
        }
        let mut journal = self.load()?;
        let hot_state = self.active_hot_state_for(&journal)?;
        if subject.height != hot_state.finalized_through.saturating_add(1) {
            return Err(format!(
                "cannot record a signature outside the active height {}",
                hot_state.finalized_through.saturating_add(1)
            ));
        }
        let entry = journal
            .entries
            .iter_mut()
            .find(|entry| entry.subject.slot_key() == subject.slot_key())
            .ok_or_else(|| {
                format!(
                    "cannot record a signature for unauthorized height {}",
                    subject.height
                )
            })?;
        if &entry.subject != subject {
            return Err("recorded signature does not match the authorized subject".to_string());
        }
        if let Some(existing) = &entry.signature {
            if existing != signature {
                return Err(format!(
                    "height {} already has a different durable signature",
                    subject.height
                ));
            }
            return Ok(());
        }
        entry.signature = Some(signature.clone());
        entry.state = SingleAuthorityJournalState::Signed;
        self.persist(&journal)
    }

    /// Step 12: mark the height finalized, after the durable head is committed.
    pub fn mark_finalized(&self, subject: &SingleAuthoritySigningSubject) -> Result<(), String> {
        let mut journal = self.load()?;
        let hot_state = self.active_hot_state_for(&journal)?;
        if subject.height != hot_state.finalized_through.saturating_add(1) {
            return Err(format!(
                "cannot finalize height {} while durable journal is at {}",
                subject.height, hot_state.finalized_through
            ));
        }
        let entry_index = journal
            .entries
            .iter()
            .position(|entry| entry.subject.slot_key() == subject.slot_key())
            .ok_or_else(|| format!("cannot finalize unknown height {}", subject.height))?;
        let entry = &journal.entries[entry_index];
        if &entry.subject != subject {
            return Err("finalized subject does not match the journal".to_string());
        }
        if entry.signature.is_none() {
            return Err("cannot finalize a height with no durable signature".to_string());
        }
        // The exact signature is now durable in the finality record.  Removing
        // this completed entry keeps the canonical V1 journal bounded.  If we
        // crash before its hot-state marker is advanced, startup reconciliation
        // observes the durable finality head and completes the same transition.
        journal.entries.remove(entry_index);
        self.persist(&journal)?;
        self.persist_hot_state(subject.height)
    }
}
