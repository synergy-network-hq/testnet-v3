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
use std::io::Write;
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
        if self.consensus_protocol != super::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL {
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
    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
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
        let bytes = serde_json::to_vec(journal)
            .map_err(|error| format!("encode single-authority signing journal: {error}"))?;
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create journal directory: {error}"))?;
        }
        let temp = self
            .path
            .with_extension(format!("tmp-{}", std::process::id()));
        {
            let mut file = File::create(&temp)
                .map_err(|error| format!("create temporary journal: {error}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("write temporary journal: {error}"))?;
        }
        fs::rename(&temp, &self.path)
            .map_err(|error| format!("replace signing journal: {error}"))?;
        if let Some(parent) = self.path.parent() {
            let _ = File::open(parent).and_then(|dir| dir.sync_all());
        }
        Ok(())
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
                halt.chain_id,
                halt.chain_incarnation,
                halt.authority_id,
                halt.height,
                halt.reason
            ));
        }
        Ok(())
    }

    pub fn safety_halts(&self) -> Result<Vec<SingleAuthoritySafetyHalt>, String> {
        Ok(self.load()?.safety_halts)
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
        let entry = journal
            .entries
            .iter_mut()
            .find(|entry| entry.subject.slot_key() == subject.slot_key())
            .ok_or_else(|| format!("cannot finalize unknown height {}", subject.height))?;
        if &entry.subject != subject {
            return Err("finalized subject does not match the journal".to_string());
        }
        if entry.signature.is_none() {
            return Err("cannot finalize a height with no durable signature".to_string());
        }
        entry.state = SingleAuthorityJournalState::Finalized;
        self.persist(&journal)
    }
}
