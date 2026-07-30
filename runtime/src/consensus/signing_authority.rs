use crate::synergy_types::{
    AegisPqKeyId, BlockId, ChainId, Epoch, Hash, Height, NetworkId, Round, ValidatorId,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONSENSUS_SIGNING_JOURNAL_FORMAT: &str = "synergy-consensus-signing-journal-v2";
pub const CONSENSUS_SIGNING_JOURNAL_FILE: &str = "consensus_signing_authorizations.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusSigningPhase {
    Proposal,
    Validate,
    Finality,
    Timeout,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusSigningAuthorization {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub round: Round,
    pub height_context_root: Hash,
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub phase: ConsensusSigningPhase,
    pub candidate_id: Option<BlockId>,
    pub highest_prepared_vc_root: Option<Hash>,
}

impl ConsensusSigningAuthorization {
    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.protocol_version.trim().is_empty() {
            return Err("signing authorization protocol version is empty".to_string());
        }
        if self.height.0 == 0 {
            return Err("consensus signing authorization height must be positive".to_string());
        }
        if self.height_context_root.is_zero() {
            return Err("consensus signing authorization context root is missing".to_string());
        }
        if self.validator_id.0.trim().is_empty() || self.key_id.0.trim().is_empty() {
            return Err("consensus signing authorization identity is missing".to_string());
        }
        match self.phase {
            ConsensusSigningPhase::Proposal
            | ConsensusSigningPhase::Validate
            | ConsensusSigningPhase::Finality => {
                if self
                    .candidate_id
                    .as_ref()
                    .is_none_or(|candidate| candidate.0.trim().is_empty())
                {
                    return Err(
                        "validate/finality authorization requires a candidate id".to_string()
                    );
                }
            }
            ConsensusSigningPhase::Timeout => {}
        }
        if self.highest_prepared_vc_root.is_some_and(Hash::is_zero) {
            return Err("prepared VC root must be absent or nonzero".to_string());
        }
        Ok(())
    }

    fn slot_key(&self) -> SigningSlotKey {
        SigningSlotKey {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            height: self.height,
            round: match self.phase {
                ConsensusSigningPhase::Finality => None,
                ConsensusSigningPhase::Proposal
                | ConsensusSigningPhase::Validate
                | ConsensusSigningPhase::Timeout => Some(self.round),
            },
            height_context_root: self.height_context_root,
            validator_id: self.validator_id.clone(),
            key_id: self.key_id.clone(),
            phase: self.phase,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SigningSlotKey {
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    epoch: Epoch,
    height: Height,
    round: Option<Round>,
    height_context_root: Hash,
    validator_id: ValidatorId,
    key_id: AegisPqKeyId,
    phase: ConsensusSigningPhase,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSigningRecord {
    slot: SigningSlotKey,
    authorization: ConsensusSigningAuthorization,
    authorization_root: Hash,
    persisted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyHaltKind {
    ConflictingFinalityCertificates,
    ConflictingBatchOrderCertificates,
    SigningJournalInconsistency,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SafetyHaltIncident {
    pub incident_version: u32,
    pub kind: SafetyHaltKind,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub context_root: Hash,
    pub first_evidence_root: Hash,
    pub second_evidence_root: Hash,
}

impl SafetyHaltIncident {
    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.incident_version != 1
            || self.protocol_version.trim().is_empty()
            || self.height.0 == 0
            || self.context_root.is_zero()
            || self.first_evidence_root.is_zero()
            || self.second_evidence_root.is_zero()
            || self.first_evidence_root == self.second_evidence_root
        {
            return Err("invalid consensus SafetyHalt incident".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("serialize SafetyHalt incident: {error}"))?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_CONSENSUS_SAFETY_HALT_INCIDENT_V1",
            &bytes,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSafetyHaltRecord {
    incident: SafetyHaltIncident,
    incident_root: Hash,
    persisted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSigningJournal {
    format: String,
    records: Vec<DurableSigningRecord>,
    safety_halts: Vec<DurableSafetyHaltRecord>,
}

impl Default for DurableSigningJournal {
    fn default() -> Self {
        Self {
            format: CONSENSUS_SIGNING_JOURNAL_FORMAT.to_string(),
            records: Vec::new(),
            safety_halts: Vec::new(),
        }
    }
}

/// Append-only compare-and-set authority for every consensus signature.
///
/// The journal deliberately exposes no delete, expiry, reset, compact, or
/// recovery-bypass operation. A successful authorization is fsync'd before the
/// caller is allowed to release a signature.
#[derive(Debug, Clone)]
pub struct DurableConsensusSigningAuthority {
    path: PathBuf,
}

static PROCESS_WIDE_SIGNING_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

impl DurableConsensusSigningAuthority {
    pub fn process_wide() -> Self {
        Self::at_path(crate::utils::resolve_data_path(&format!(
            "data/{CONSENSUS_SIGNING_JOURNAL_FILE}"
        )))
    }

    pub fn at_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn authorize_before_signature(
        &self,
        authorization: &ConsensusSigningAuthorization,
    ) -> Result<Hash, String> {
        authorization.validate()?;
        let authorization_bytes = serde_json::to_vec(authorization)
            .map_err(|error| format!("serialize signing authorization: {error}"))?;
        let authorization_root = Hash::from_domain_bytes(
            "SYNERGY_CONSENSUS_SIGNING_AUTHORIZATION_V1",
            &authorization_bytes,
        );
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        if let Some(halt) = journal.safety_halts.first() {
            return Err(format!(
                "CONSENSUS_SAFETY_HALT: signing disabled by {:?} incident {}",
                halt.incident.kind,
                halt.incident_root.to_hex()
            ));
        }
        let slot = authorization.slot_key();
        if let Some(existing) = journal.records.iter().find(|record| record.slot == slot) {
            if existing.authorization == *authorization
                && existing.authorization_root == authorization_root
            {
                return Ok(existing.authorization_root);
            }
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: {:?} slot already authorizes candidate {:?}",
                slot.phase, existing.authorization.candidate_id
            ));
        }
        journal.records.push(DurableSigningRecord {
            slot,
            authorization: authorization.clone(),
            authorization_root,
            persisted_at_unix_ms: current_unix_ms(),
        });
        self.persist_unlocked(&journal)?;
        Ok(authorization_root)
    }

    /// Returns the authorization already durably recorded for the same signing
    /// slot, if one exists.
    ///
    /// The slot key deliberately excludes `candidate_id`, so a slot can only
    /// ever be authorized once. A `Timeout` authorization nevertheless commits
    /// to the highest prepared candidate, and the `ValidationCertificate` that
    /// determines it is in-memory only. After a restart the node cannot
    /// recompute that value, so if it derives a fresh authorization it produces
    /// a *different* one for a slot it has already used;
    /// [`Self::authorize_before_signature`] then correctly refuses with
    /// `CONSENSUS_SIGNING_CONFLICT` and the node can never make progress again.
    ///
    /// Callers use this to re-emit exactly what they already committed to,
    /// which is the safest available choice: it reproduces the durable record
    /// byte-for-byte and takes the idempotent path. This never authorizes
    /// anything new and never relaxes the conflict check.
    pub fn recorded_authorization_for_slot(
        &self,
        probe: &ConsensusSigningAuthorization,
    ) -> Result<Option<ConsensusSigningAuthorization>, String> {
        probe.validate()?;
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let slot = probe.slot_key();
        Ok(self
            .load_unlocked()?
            .records
            .into_iter()
            .find(|record| record.slot == slot)
            .map(|record| record.authorization))
    }

    pub fn contains_exact(
        &self,
        authorization: &ConsensusSigningAuthorization,
    ) -> Result<bool, String> {
        authorization.validate()?;
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        Ok(self
            .load_unlocked()?
            .records
            .iter()
            .any(|record| record.authorization == *authorization))
    }

    /// Durably and irreversibly halts this authority before returning.
    ///
    /// There is intentionally no clear/reset/delete API. Resuming after a
    /// safety incident requires a separately governed new-chain or protocol
    /// recovery procedure, never a local runtime toggle.
    pub fn enter_safety_halt(&self, incident: &SafetyHaltIncident) -> Result<Hash, String> {
        incident.validate()?;
        let incident_root = incident.root()?;
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        if let Some(existing) = journal
            .safety_halts
            .iter()
            .find(|record| record.incident_root == incident_root)
        {
            if existing.incident == *incident {
                return Ok(existing.incident_root);
            }
            return Err("CONSENSUS_SAFETY_HALT_ROOT_COLLISION".to_string());
        }
        journal.safety_halts.push(DurableSafetyHaltRecord {
            incident: incident.clone(),
            incident_root,
            persisted_at_unix_ms: current_unix_ms(),
        });
        self.persist_unlocked(&journal)?;
        Ok(incident_root)
    }

    pub fn require_signing_allowed(&self) -> Result<(), String> {
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let journal = self.load_unlocked()?;
        if let Some(halt) = journal.safety_halts.first() {
            return Err(format!(
                "CONSENSUS_SAFETY_HALT: signing disabled by {:?} incident {}",
                halt.incident.kind,
                halt.incident_root.to_hex()
            ));
        }
        Ok(())
    }

    pub fn safety_halt_incidents(&self) -> Result<Vec<SafetyHaltIncident>, String> {
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        Ok(self
            .load_unlocked()?
            .safety_halts
            .into_iter()
            .map(|record| record.incident)
            .collect())
    }

    fn load_unlocked(&self) -> Result<DurableSigningJournal, String> {
        if !self.path.exists() {
            return Ok(DurableSigningJournal::default());
        }
        let bytes = fs::read(&self.path)
            .map_err(|error| format!("read signing journal {}: {error}", self.path.display()))?;
        let journal: DurableSigningJournal = serde_json::from_slice(&bytes)
            .map_err(|error| format!("parse signing journal {}: {error}", self.path.display()))?;
        if journal.format != CONSENSUS_SIGNING_JOURNAL_FORMAT {
            return Err(format!(
                "unsupported signing journal format {}",
                journal.format
            ));
        }
        for halt in &journal.safety_halts {
            halt.incident.validate()?;
            if halt.incident.root()? != halt.incident_root {
                return Err("consensus SafetyHalt incident root mismatch".to_string());
            }
        }
        Ok(journal)
    }

    fn persist_unlocked(&self, journal: &DurableSigningJournal) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "signing journal path has no parent".to_string())?;
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create signing journal directory {}: {error}",
                parent.display()
            )
        })?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "signing journal path has no valid file name".to_string())?;
        let temp_path = parent.join(format!(
            ".{file_name}.tmp-{}-{}",
            std::process::id(),
            current_unix_nanos()
        ));
        let bytes = serde_json::to_vec_pretty(journal)
            .map_err(|error| format!("serialize signing journal: {error}"))?;
        let write_result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)
                .map_err(|error| {
                    format!(
                        "create temporary signing journal {}: {error}",
                        temp_path.display()
                    )
                })?;
            file.write_all(&bytes).map_err(|error| {
                format!(
                    "write temporary signing journal {}: {error}",
                    temp_path.display()
                )
            })?;
            file.sync_all().map_err(|error| {
                format!(
                    "fsync temporary signing journal {}: {error}",
                    temp_path.display()
                )
            })?;
            fs::rename(&temp_path, &self.path).map_err(|error| {
                format!(
                    "atomically replace signing journal {}: {error}",
                    self.path.display()
                )
            })?;
            let directory = OpenOptions::new()
                .read(true)
                .open(parent)
                .map_err(|error| {
                    format!(
                        "open signing journal directory {}: {error}",
                        parent.display()
                    )
                })?;
            directory.sync_all().map_err(|error| {
                format!(
                    "fsync signing journal directory {}: {error}",
                    parent.display()
                )
            })
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn current_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_authority(label: &str) -> DurableConsensusSigningAuthority {
        let path = crate::utils::test_temp_root(format!(
            "synergy-signing-authority-{label}-{}-{}/journal.json",
            std::process::id(),
            current_unix_nanos()
        ));
        DurableConsensusSigningAuthority::at_path(path)
    }

    fn authorization(
        phase: ConsensusSigningPhase,
        round: u64,
        candidate: &str,
    ) -> ConsensusSigningAuthorization {
        ConsensusSigningAuthorization {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/2.2".to_string(),
            epoch: Epoch(0),
            height: Height(1),
            round: Round(round),
            height_context_root: Hash::from_domain_bytes("context", b"one"),
            validator_id: ValidatorId("validator-1".to_string()),
            key_id: AegisPqKeyId("key-1".to_string()),
            phase,
            candidate_id: Some(BlockId(candidate.to_string())),
            highest_prepared_vc_root: None,
        }
    }

    fn conflicting_qc_incident() -> SafetyHaltIncident {
        SafetyHaltIncident {
            incident_version: 1,
            kind: SafetyHaltKind::ConflictingFinalityCertificates,
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/2.2".to_string(),
            epoch: Epoch(0),
            height: Height(1),
            context_root: Hash::from_domain_bytes("context", b"one"),
            first_evidence_root: Hash::from_domain_bytes("qc", b"candidate-a"),
            second_evidence_root: Hash::from_domain_bytes("qc", b"candidate-b"),
        }
    }

    #[test]
    fn finality_slot_is_height_scoped_and_survives_restart() {
        let authority = temp_authority("finality");
        let first = authorization(ConsensusSigningPhase::Finality, 0, "candidate-a");
        authority.authorize_before_signature(&first).unwrap();

        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        let conflicting = authorization(ConsensusSigningPhase::Finality, 4, "candidate-b");
        assert!(restarted
            .authorize_before_signature(&conflicting)
            .unwrap_err()
            .contains("CONSENSUS_SIGNING_CONFLICT"));
        assert!(restarted.contains_exact(&first).unwrap());
    }

    #[test]
    fn recorded_timeout_slot_is_recoverable_after_losing_in_memory_prepared_state() {
        // Regression for the Testnet-v3 height-91 deadlock: a Timeout
        // authorization commits to the highest prepared candidate, but the
        // ValidationCertificate that determines it is in-memory only. A restart
        // therefore derived a *different* authorization for an already-used slot,
        // authorize_before_signature correctly refused with
        // CONSENSUS_SIGNING_CONFLICT, the typed worker failed closed, and systemd
        // replayed the identical failure forever.
        let authority = temp_authority("timeout-slot-recovery");
        let mut committed = authorization(ConsensusSigningPhase::Timeout, 0, "prepared-candidate");
        committed.highest_prepared_vc_root = Some(Hash::from_domain_bytes("vc", b"prepared"));
        let committed_root = authority
            .authorize_before_signature(&committed)
            .expect("first timeout authorization");

        // Exactly what a restarted process derives with no prepared VC in memory.
        let mut rederived = authorization(ConsensusSigningPhase::Timeout, 0, "prepared-candidate");
        rederived.candidate_id = None;
        rederived.highest_prepared_vc_root = None;

        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        let error = restarted
            .authorize_before_signature(&rederived)
            .expect_err("a different candidate must still be refused");
        assert!(
            error.contains("CONSENSUS_SIGNING_CONFLICT"),
            "unexpected error: {error}"
        );

        // The recovery path returns exactly what was committed, so the caller can
        // re-emit it and take the idempotent branch instead of deadlocking.
        let recovered = restarted
            .recorded_authorization_for_slot(&rederived)
            .expect("slot lookup")
            .expect("the slot is already recorded");
        assert_eq!(recovered, committed);
        assert_eq!(
            restarted.authorize_before_signature(&recovered),
            Ok(committed_root),
            "re-emitting the recorded authorization must be idempotent"
        );
    }

    #[test]
    fn unused_timeout_slot_has_no_recorded_authorization() {
        let authority = temp_authority("timeout-slot-absent");
        let mut probe = authorization(ConsensusSigningPhase::Timeout, 0, "unused");
        probe.candidate_id = None;
        assert_eq!(
            authority
                .recorded_authorization_for_slot(&probe)
                .expect("slot lookup"),
            None
        );
    }

    #[test]
    fn validation_is_round_scoped_but_conflicts_within_round() {
        let authority = temp_authority("validation");
        let first = authorization(ConsensusSigningPhase::Validate, 0, "candidate-a");
        authority.authorize_before_signature(&first).unwrap();
        assert!(authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::Validate,
                0,
                "candidate-b"
            ))
            .is_err());
        assert!(authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::Validate,
                1,
                "candidate-b"
            ))
            .is_ok());
    }

    #[test]
    fn idempotent_retry_does_not_append_or_fail() {
        let authority = temp_authority("idempotent");
        let authorization = authorization(ConsensusSigningPhase::Finality, 0, "candidate-a");
        let first = authority
            .authorize_before_signature(&authorization)
            .unwrap();
        let second = authority
            .authorize_before_signature(&authorization)
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn safety_halt_is_durable_idempotent_and_blocks_every_signing_phase() {
        let authority = temp_authority("safety-halt");
        let incident = conflicting_qc_incident();
        let root = authority.enter_safety_halt(&incident).unwrap();
        assert_eq!(authority.enter_safety_halt(&incident).unwrap(), root);
        assert!(authority.require_signing_allowed().is_err());

        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        assert_eq!(restarted.safety_halt_incidents().unwrap(), vec![incident]);
        for phase in [
            ConsensusSigningPhase::Proposal,
            ConsensusSigningPhase::Validate,
            ConsensusSigningPhase::Finality,
            ConsensusSigningPhase::Timeout,
        ] {
            assert!(restarted
                .authorize_before_signature(&authorization(phase, 0, "candidate-a"))
                .unwrap_err()
                .contains("CONSENSUS_SAFETY_HALT"));
        }
    }
}
