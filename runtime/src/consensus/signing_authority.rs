use crate::synergy_types::{
    current_consensus_domain, AegisPqKeyId, AegisPqSignature, Block, BlockId, ChainId, ClusterId,
    ConsensusSubject, ConsensusSubjectPhase, Epoch, Hash, Height, NetworkId, QuorumCertificate,
    Round, TimeoutCertificate, ValidationCertificate, ValidatorId, Vote, VotePhase,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONSENSUS_SIGNING_JOURNAL_FORMAT: &str = "synergy-consensus-signing-journal-v4";
pub const CONSENSUS_SIGNING_JOURNAL_FILE: &str = "consensus_signing_authorizations.json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsensusSigningPhase {
    Proposal,
    /// Authenticated reliable-delivery transport statement. This is not an
    /// ordinary block vote and never contributes directly to finality.
    ProposalEcho,
    /// Authenticated reliable-delivery transport statement. This is not an
    /// ordinary block vote and never contributes directly to finality.
    ProposalReady,
    /// The sole ordinary block-vote phase in the activated PoSy v3 profile.
    Vote,
    Validate,
    Finality,
    Timeout,
}

/// The two signature subjects in temporary coordinator-driven consensus.
/// Unlike the retired certificate phases, an assignment permits one new round
/// at the same height after a timeout, while a commit permits exactly one block
/// hash for that height across all rounds and key rotations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoordinatedSigningPhase {
    Assignment,
    /// The assigned producer's exact canonical block envelope. This remains
    /// distinct from Val1's finality commit: a producer may sign only the
    /// one block bound to its signed assignment and producer round.
    ProducerBlock,
    Commit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatedSigningAuthorization {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub consensus_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub producer_round: Round,
    pub coordinator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub phase: CoordinatedSigningPhase,
    /// The domain-separated assignment or commit hash to be signed.  The
    /// journal never permits an alternate subject for one durable slot.
    pub subject_hash: Hash,
}

impl CoordinatedSigningAuthorization {
    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.consensus_version != "coordinated_round_robin_v1"
            || self.height.0 == 0
            || self.coordinator_id.0.trim().is_empty()
            || self.key_id.0.trim().is_empty()
            || self.subject_hash.is_zero()
        {
            return Err("invalid coordinated consensus signing authorization".to_string());
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| format!("serialize coordinated signing authorization: {error}"))?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_COORDINATED_SIGNING_AUTHORIZATION_V1",
            &bytes,
        ))
    }

    fn slot_key(&self) -> CoordinatedSigningSlotKey {
        CoordinatedSigningSlotKey {
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            consensus_version: self.consensus_version.clone(),
            epoch: self.epoch,
            height: self.height,
            coordinator_id: self.coordinator_id.clone(),
            phase: self.phase,
            // A coordinator may issue a replacement assignment for a later
            // producer round at the same height. Its assigned producer has a
            // separately journaled block slot for that same round. A commit
            // deliberately drops the round so Val1 can never sign two block
            // subjects at one height.
            producer_round: (self.phase != CoordinatedSigningPhase::Commit)
                .then_some(self.producer_round),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusSigningAuthorization {
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub round: Round,
    pub cluster_id: ClusterId,
    pub height_context_root: Hash,
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub phase: ConsensusSigningPhase,
    pub candidate_id: Option<BlockId>,
    pub highest_prepared_vc_root: Option<Hash>,
    /// Verified no-carry TC that proves a prior same-height block vote could
    /// not have formed a hidden QC and therefore permits a new candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_unlock_tc_id: Option<Hash>,
}

impl ConsensusSigningAuthorization {
    pub fn from_vote(vote: &Vote) -> Result<Self, String> {
        let phase = match vote.phase {
            VotePhase::Validate => ConsensusSigningPhase::Validate,
            VotePhase::Finality => ConsensusSigningPhase::Finality,
            VotePhase::Timeout => ConsensusSigningPhase::Timeout,
        };
        let candidate_id = (!vote.block_id.0.is_empty()).then(|| vote.block_id.clone());
        let authorization = Self {
            chain_id: vote.chain_id,
            network_id: vote.network_id.clone(),
            protocol_version: vote.protocol_version.clone(),
            epoch: vote.epoch,
            height: vote.height,
            round: vote.round,
            cluster_id: vote.cluster_id,
            height_context_root: vote.height_context_root,
            validator_id: vote.validator_id.clone(),
            key_id: vote.key_id.clone(),
            phase,
            candidate_id,
            highest_prepared_vc_root: vote.highest_prepared_vc_root,
            conflict_unlock_tc_id: None,
        };
        authorization.validate()?;
        Ok(authorization)
    }

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
            | ConsensusSigningPhase::ProposalEcho
            | ConsensusSigningPhase::ProposalReady
            | ConsensusSigningPhase::Vote
            | ConsensusSigningPhase::Validate
            | ConsensusSigningPhase::Finality => {
                if self
                    .candidate_id
                    .as_ref()
                    .is_none_or(|candidate| candidate.0.trim().is_empty())
                {
                    return Err(
                        "candidate signing authorization requires a candidate id".to_string()
                    );
                }
                if self.highest_prepared_vc_root.is_some() {
                    return Err(
                        "candidate signing authorization cannot carry a prepared VC root"
                            .to_string(),
                    );
                }
            }
            ConsensusSigningPhase::Timeout => {}
        }
        if self.highest_prepared_vc_root.is_some_and(Hash::is_zero) {
            return Err("prepared VC root must be absent or nonzero".to_string());
        }
        if self.conflict_unlock_tc_id.is_some_and(Hash::is_zero) {
            return Err("conflict-unlock TC root must be absent or nonzero".to_string());
        }
        if self.conflict_unlock_tc_id.is_some() && self.phase != ConsensusSigningPhase::Vote {
            return Err("only a block vote can carry conflict-unlock TC authority".to_string());
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
            round: Some(self.round),
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            validator_id: self.validator_id.clone(),
            key_id: self.key_id.clone(),
            phase: self.phase,
        }
    }

    pub fn consensus_subject(&self) -> Result<ConsensusSubject, String> {
        self.validate()?;
        let candidate_id = self
            .candidate_id
            .as_ref()
            .filter(|candidate| !candidate.0.trim().is_empty())
            .cloned();
        let phase = match self.phase {
            ConsensusSigningPhase::Proposal => ConsensusSubjectPhase::Proposal,
            ConsensusSigningPhase::ProposalEcho => ConsensusSubjectPhase::ProposalEcho,
            ConsensusSigningPhase::ProposalReady => ConsensusSubjectPhase::ProposalReady,
            ConsensusSigningPhase::Vote => ConsensusSubjectPhase::Vote,
            ConsensusSigningPhase::Validate => ConsensusSubjectPhase::Validate,
            ConsensusSigningPhase::Finality => ConsensusSubjectPhase::Finality,
            ConsensusSigningPhase::Timeout => ConsensusSubjectPhase::Timeout,
        };
        Ok(ConsensusSubject {
            domain: current_consensus_domain()?,
            chain_id: self.chain_id,
            network_id: self.network_id.clone(),
            protocol_version: self.protocol_version.clone(),
            epoch: self.epoch,
            height: self.height,
            round: self.round,
            cluster_id: self.cluster_id,
            height_context_root: self.height_context_root,
            phase,
            candidate_id,
            prepared_round: matches!(
                self.phase,
                ConsensusSigningPhase::Validate | ConsensusSigningPhase::Finality
            )
            .then_some(self.round),
        })
    }

    pub fn subject_digest(&self) -> Result<Hash, String> {
        self.consensus_subject()?.digest()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SigningSlotKey {
    chain_id: ChainId,
    network_id: NetworkId,
    protocol_version: String,
    epoch: Epoch,
    height: Height,
    round: Option<Round>,
    cluster_id: ClusterId,
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
    subject_digest: Hash,
    #[serde(default)]
    signed_proposal: Option<Block>,
    #[serde(default)]
    signed_vote: Option<Vote>,
    persisted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct CoordinatedSigningSlotKey {
    chain_id: ChainId,
    network_id: NetworkId,
    consensus_version: String,
    epoch: Epoch,
    height: Height,
    coordinator_id: ValidatorId,
    phase: CoordinatedSigningPhase,
    producer_round: Option<Round>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableCoordinatedSigningRecord {
    slot: CoordinatedSigningSlotKey,
    authorization: CoordinatedSigningAuthorization,
    authorization_root: Hash,
    signature: AegisPqSignature,
    /// Exact serialized assignment or commit envelope, including the
    /// randomized signature, for safe restart retransmission.
    #[serde(default)]
    signed_envelope: Vec<u8>,
    persisted_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoordinatedSignedEnvelope {
    pub authorization: CoordinatedSigningAuthorization,
    pub signature: AegisPqSignature,
    pub signed_envelope: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SafetyHaltKind {
    ConflictingQuorumCertificates,
    ConflictingTimeoutCertificates,
    ConflictingTimeoutAndQuorumEvidence,
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

/// One atomic recovery image stored in the same fsync/rename transaction as
/// signing authorizations and exact signed envelopes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DurableConsensusRecoveryCheckpoint {
    pub checkpoint_version: u32,
    pub genesis_anchor: Hash,
    pub chain_id: ChainId,
    pub chain_incarnation: u64,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub finalized_height: Height,
    pub finalized_block: Option<Block>,
    pub highest_qc: Option<QuorumCertificate>,
    pub current_height: Height,
    pub current_round: Round,
    pub height_context_root: Hash,
    pub active_validator_set_hash: Hash,
    pub prepared_block: Option<Block>,
    pub prepared_certificate: Option<ValidationCertificate>,
    pub highest_tc: Option<TimeoutCertificate>,
}

impl DurableConsensusRecoveryCheckpoint {
    pub fn validate(&self) -> Result<(), String> {
        self.chain_id.require_testnet_v3()?;
        self.network_id.require_testnet_v3()?;
        if self.checkpoint_version != 2
            || self.genesis_anchor.is_zero()
            || self.chain_incarnation != crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION
            || self.protocol_version.trim().is_empty()
            || self.current_height.0 != self.finalized_height.0.saturating_add(1)
            || self.height_context_root.is_zero()
            || self.active_validator_set_hash.is_zero()
        {
            return Err("invalid atomic consensus recovery checkpoint".to_string());
        }
        match (
            self.finalized_height.0,
            self.finalized_block.as_ref(),
            self.highest_qc.as_ref(),
        ) {
            (0, None, None) => {}
            (height, Some(block), Some(qc))
                if block.header.height.0 == height
                    && qc.height.0 == height
                    && qc.block_id == block.candidate_id()?
                    && qc.phase == VotePhase::Finality => {}
            _ => {
                return Err("atomic recovery finalized block/QC binding is inconsistent".to_string())
            }
        }
        match (
            self.prepared_block.as_ref(),
            self.prepared_certificate.as_ref(),
        ) {
            (None, None) => {}
            (Some(block), Some(vc))
                if block.header.height == self.current_height
                    && block.header.epoch == self.epoch
                    && block.header.height_context_root == self.height_context_root
                    && block.header.active_validator_set_hash == self.active_validator_set_hash
                    && vc.height == self.current_height
                    && vc.epoch == self.epoch
                    && vc.height_context_root == self.height_context_root
                    && vc.active_validator_set_hash == self.active_validator_set_hash
                    && vc.candidate_id == block.candidate_id()? => {}
            _ => {
                return Err("atomic recovery prepared block/VC binding is inconsistent".to_string())
            }
        }
        if let Some(tc) = &self.highest_tc {
            if tc.height != self.current_height
                || tc.epoch != self.epoch
                || tc.height_context_root != self.height_context_root
                || tc.active_validator_set_hash != self.active_validator_set_hash
                || tc.next_round != self.current_round
            {
                return Err(
                    "atomic recovery timeout-certificate binding is inconsistent".to_string(),
                );
            }
        } else if self.current_round.0 != 0 {
            return Err(
                "atomic recovery nonzero round lacks timeout-certificate authority".to_string(),
            );
        }
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_TYPED_CONSENSUS_RECOVERY_CHECKPOINT_V1",
            &serde_json::to_vec(self)
                .map_err(|error| format!("serialize atomic recovery checkpoint: {error}"))?,
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableRecoveryCheckpointRecord {
    checkpoint: DurableConsensusRecoveryCheckpoint,
    checkpoint_root: Hash,
    persisted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DurableSigningJournal {
    format: String,
    records: Vec<DurableSigningRecord>,
    /// Coordinated-mode authorizations are intentionally stored in their own
    /// sequence so no QC/vote schema can be mistaken for a coordinator commit.
    #[serde(default)]
    coordinated_records: Vec<DurableCoordinatedSigningRecord>,
    safety_halts: Vec<DurableSafetyHaltRecord>,
    /// Every signing slot at or below this finalized height is permanently
    /// retired. Exact randomized envelopes remain durable while their height
    /// is live; the atomic finalized checkpoint then makes those old slots
    /// impossible to sign again and permits bounded compaction.
    #[serde(default)]
    retired_through_height: u64,
    #[serde(default)]
    recovery_checkpoint: Option<DurableRecoveryCheckpointRecord>,
    #[serde(default)]
    coordinator_start_count: u64,
}

impl Default for DurableSigningJournal {
    fn default() -> Self {
        Self {
            format: CONSENSUS_SIGNING_JOURNAL_FORMAT.to_string(),
            records: Vec::new(),
            coordinated_records: Vec::new(),
            safety_halts: Vec::new(),
            retired_through_height: 0,
            recovery_checkpoint: None,
            coordinator_start_count: 0,
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
        let subject_digest = authorization.subject_digest()?;
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
        if matches!(
            authorization.phase,
            ConsensusSigningPhase::Finality | ConsensusSigningPhase::Vote
        ) {
            let conflicting_candidate = journal.records.iter().find(|record| {
                let existing = &record.authorization;
                existing.phase == authorization.phase
                    && existing.chain_id == authorization.chain_id
                    && existing.network_id == authorization.network_id
                    && existing.protocol_version == authorization.protocol_version
                    && existing.epoch == authorization.epoch
                    && existing.height == authorization.height
                    && existing.height_context_root == authorization.height_context_root
                    && existing.validator_id == authorization.validator_id
                    && existing.key_id == authorization.key_id
                    && existing.candidate_id != authorization.candidate_id
            });
            if let Some(existing) = conflicting_candidate {
                if authorization.phase == ConsensusSigningPhase::Vote
                    && authorization.conflict_unlock_tc_id.is_some()
                {
                    // The state machine verifies this TC and its no-carry
                    // intersection proof before reaching the journal.
                } else {
                    return Err(format!(
                        "CONSENSUS_SIGNING_CONFLICT: {:?} height already authorizes candidate {:?}",
                        authorization.phase, existing.authorization.candidate_id
                    ));
                }
            }
        }
        if let Some(existing) = journal.records.iter().find(|record| record.slot == slot) {
            if existing.authorization == *authorization
                && existing.authorization_root == authorization_root
                && existing.subject_digest == subject_digest
            {
                return Ok(existing.authorization_root);
            }
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: {:?} slot already authorizes candidate {:?}",
                slot.phase, existing.authorization.candidate_id
            ));
        }
        if authorization.height.0 <= journal.retired_through_height {
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: height {} is retired through finalized height {}",
                authorization.height.0, journal.retired_through_height
            ));
        }
        journal.records.push(DurableSigningRecord {
            slot,
            authorization: authorization.clone(),
            authorization_root,
            subject_digest,
            signed_proposal: None,
            signed_vote: None,
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

    /// Atomically journals an exact temporary-coordinator signature and wire
    /// envelope before either may be broadcast. A commit's durable slot
    /// excludes producer round and key ID, so Val1 cannot sign a second block
    /// hash at one height even after a timeout, restart, or key rotation.
    pub fn record_coordinated_envelope(
        &self,
        authorization: &CoordinatedSigningAuthorization,
        signature: &AegisPqSignature,
        signed_envelope: &[u8],
    ) -> Result<(), String> {
        authorization.validate()?;
        if !signature.is_present() {
            return Err("cannot journal an empty coordinated consensus signature".to_string());
        }
        if signed_envelope.is_empty() {
            return Err("cannot journal an empty coordinated signed envelope".to_string());
        }
        let authorization_root = authorization.root()?;
        let slot = authorization.slot_key();
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
        if let Some(existing) = journal
            .coordinated_records
            .iter()
            .find(|record| record.slot == slot)
        {
            if existing.authorization == *authorization
                && existing.authorization_root == authorization_root
                && existing.signature == *signature
                && existing.signed_envelope == signed_envelope
            {
                return Ok(());
            }
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: coordinated {:?} slot already contains different durable evidence",
                slot.phase
            ));
        }
        if authorization.height.0 <= journal.retired_through_height {
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: coordinated height {} is retired through finalized height {}",
                authorization.height.0, journal.retired_through_height
            ));
        }
        journal
            .coordinated_records
            .push(DurableCoordinatedSigningRecord {
                slot,
                authorization: authorization.clone(),
                authorization_root,
                signature: signature.clone(),
                signed_envelope: signed_envelope.to_vec(),
                persisted_at_unix_ms: current_unix_ms(),
            });
        self.persist_unlocked(&journal)
    }

    /// Recovers the exact randomized coordinator signature for safe replay.
    /// A different authorization in the same slot is a safety conflict, not a
    /// reason to create a second signature.
    pub fn recorded_coordinated_signature(
        &self,
        authorization: &CoordinatedSigningAuthorization,
    ) -> Result<Option<AegisPqSignature>, String> {
        authorization.validate()?;
        let slot = authorization.slot_key();
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let journal = self.load_unlocked()?;
        let Some(record) = journal
            .coordinated_records
            .into_iter()
            .find(|record| record.slot == slot)
        else {
            return Ok(None);
        };
        if record.authorization != *authorization
            || record.authorization_root != authorization.root()?
        {
            return Err(
                "CONSENSUS_SIGNING_CONFLICT: coordinated signing slot has a different subject"
                    .to_string(),
            );
        }
        Ok(Some(record.signature))
    }

    /// Recovers the exact serialized coordinator artifact for restart replay.
    pub fn recorded_coordinated_envelope(
        &self,
        authorization: &CoordinatedSigningAuthorization,
    ) -> Result<Option<CoordinatedSignedEnvelope>, String> {
        authorization.validate()?;
        let slot = authorization.slot_key();
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let journal = self.load_unlocked()?;
        let Some(record) = journal
            .coordinated_records
            .into_iter()
            .find(|record| record.slot == slot)
        else {
            return Ok(None);
        };
        if record.authorization != *authorization
            || record.authorization_root != authorization.root()?
        {
            return Err(
                "CONSENSUS_SIGNING_CONFLICT: coordinated signing slot has a different subject"
                    .to_string(),
            );
        }
        if record.signed_envelope.is_empty() {
            return Err(
                "coordinated signing journal lacks the exact envelope required for restart replay"
                    .to_string(),
            );
        }
        Ok(Some(CoordinatedSignedEnvelope {
            authorization: record.authorization,
            signature: record.signature,
            signed_envelope: record.signed_envelope,
        }))
    }

    /// Persists the exact signed vote envelope before the caller may broadcast
    /// it. This makes restart retransmission reuse the original randomized
    /// ML-DSA signature rather than creating a second cryptographic
    /// representation for the same logical subject.
    pub fn record_signed_vote(&self, vote: &Vote) -> Result<(), String> {
        if !vote.aegis_pq_signature.is_present() {
            return Err("cannot journal an unsigned consensus vote".to_string());
        }
        let authorization = ConsensusSigningAuthorization::from_vote(vote)?;
        let slot = authorization.slot_key();
        let subject_digest = authorization.subject_digest()?;
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        let record = journal
            .records
            .iter_mut()
            .find(|record| record.slot == slot)
            .ok_or_else(|| "signed vote has no prior durable signing authorization".to_string())?;
        if record.authorization != authorization || record.subject_digest != subject_digest {
            return Err(
                "signed vote does not match its durable consensus subject authorization"
                    .to_string(),
            );
        }
        if let Some(existing) = &record.signed_vote {
            if existing == vote {
                return Ok(());
            }
            return Err(
                "consensus signing journal already contains a different signed envelope"
                    .to_string(),
            );
        }
        record.signed_vote = Some(vote.clone());
        self.persist_unlocked(&journal)
    }

    /// Atomically commits a proposal authorization together with the exact
    /// signed block envelope. The caller may create the randomized signature
    /// before this call, but must not release it to transport until this
    /// method succeeds. A crash before this write leaves no authorization; a
    /// crash after it can only rebroadcast this exact envelope.
    pub fn record_signed_proposal(
        &self,
        authorization: &ConsensusSigningAuthorization,
        block: &Block,
    ) -> Result<(), String> {
        authorization.validate()?;
        if authorization.phase != ConsensusSigningPhase::Proposal
            || !block.proposer_signature.is_present()
            || authorization.candidate_id.as_ref() != Some(&block.candidate_id()?)
            || authorization.chain_id != block.header.chain_id
            || authorization.network_id != block.header.network_id
            || authorization.protocol_version != block.header.protocol_version
            || authorization.epoch != block.header.epoch
            || authorization.height != block.header.height
            || authorization.round != block.header.round
            || authorization.cluster_id != block.header.cluster_id
            || authorization.height_context_root != block.header.height_context_root
            || authorization.validator_id != block.header.proposer_validator_id
            || authorization.key_id != block.header.proposer_key_id
        {
            return Err(
                "signed proposal does not match its durable consensus authorization".to_string(),
            );
        }
        let authorization_bytes = serde_json::to_vec(authorization)
            .map_err(|error| format!("serialize proposal signing authorization: {error}"))?;
        let authorization_root = Hash::from_domain_bytes(
            "SYNERGY_CONSENSUS_SIGNING_AUTHORIZATION_V1",
            &authorization_bytes,
        );
        let subject_digest = authorization.subject_digest()?;
        let slot = authorization.slot_key();
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
        if let Some(existing) = journal.records.iter().find(|record| record.slot == slot) {
            if existing.authorization == *authorization
                && existing.authorization_root == authorization_root
                && existing.subject_digest == subject_digest
                && existing.signed_proposal.as_ref() == Some(block)
            {
                return Ok(());
            }
            return Err(
                "CONSENSUS_SIGNING_CONFLICT: proposal slot already contains different durable evidence"
                    .to_string(),
            );
        }
        if authorization.height.0 <= journal.retired_through_height {
            return Err(format!(
                "CONSENSUS_SIGNING_CONFLICT: proposal height {} is retired through finalized height {}",
                authorization.height.0, journal.retired_through_height
            ));
        }
        journal.records.push(DurableSigningRecord {
            slot,
            authorization: authorization.clone(),
            authorization_root,
            subject_digest,
            signed_proposal: Some(block.clone()),
            signed_vote: None,
            persisted_at_unix_ms: current_unix_ms(),
        });
        self.persist_unlocked(&journal)
    }

    pub fn recorded_signed_proposal_for_slot(
        &self,
        probe: &ConsensusSigningAuthorization,
    ) -> Result<Option<Block>, String> {
        probe.validate()?;
        if probe.phase != ConsensusSigningPhase::Proposal {
            return Err("signed-proposal recovery requires a Proposal slot".to_string());
        }
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let slot = probe.slot_key();
        let journal = self.load_unlocked()?;
        if let Some(halt) = journal.safety_halts.first() {
            return Err(format!(
                "CONSENSUS_SAFETY_HALT: signing disabled by {:?} incident {}",
                halt.incident.kind,
                halt.incident_root.to_hex()
            ));
        }
        Ok(journal
            .records
            .into_iter()
            .find(|record| record.slot == slot)
            .and_then(|record| record.signed_proposal))
    }

    pub fn recorded_signed_vote_for_slot(
        &self,
        probe: &ConsensusSigningAuthorization,
    ) -> Result<Option<Vote>, String> {
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
            .find(|record| record.slot == slot && record.authorization == *probe)
            .and_then(|record| record.signed_vote))
    }

    /// Returns the complete durable authorization set for restart-time
    /// reconciliation by the simplified PoSy state machine. This does not
    /// authorize, mutate, or relax any signing slot.
    pub fn recorded_authorizations(
        &self,
    ) -> Result<Vec<ConsensusSigningAuthorization>, String> {
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        Ok(self
            .load_unlocked()?
            .records
            .into_iter()
            .map(|record| record.authorization)
            .collect())
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

    pub fn commit_recovery_checkpoint(
        &self,
        checkpoint: &DurableConsensusRecoveryCheckpoint,
    ) -> Result<Hash, String> {
        checkpoint.validate()?;
        let checkpoint_root = checkpoint.root()?;
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        if let Some(existing) = &journal.recovery_checkpoint {
            if existing.checkpoint.genesis_anchor != checkpoint.genesis_anchor {
                return Err("atomic recovery checkpoint Genesis anchor cannot change".to_string());
            }
            if existing.checkpoint.finalized_height.0 > checkpoint.finalized_height.0 {
                return Err("atomic recovery checkpoint refuses finalized rollback".to_string());
            }
            if existing.checkpoint.finalized_height == checkpoint.finalized_height
                && existing
                    .checkpoint
                    .finalized_block
                    .as_ref()
                    .map(Block::block_id)
                    .transpose()?
                    != checkpoint
                        .finalized_block
                        .as_ref()
                        .map(Block::block_id)
                        .transpose()?
            {
                return Err(
                    "TYPED_DRIVER_SOURCE_CONFLICT: atomic recovery finalized envelopes disagree"
                        .to_string(),
                );
            }
            if existing.checkpoint.current_height == checkpoint.current_height
                && existing
                    .checkpoint
                    .prepared_block
                    .as_ref()
                    .map(Block::candidate_id)
                    .transpose()?
                    != checkpoint
                        .prepared_block
                        .as_ref()
                        .map(Block::candidate_id)
                        .transpose()?
                && existing.checkpoint.prepared_certificate.is_some()
                && checkpoint.prepared_certificate.is_some()
            {
                let existing_round = existing
                    .checkpoint
                    .prepared_certificate
                    .as_ref()
                    .map(|certificate| certificate.round.0)
                    .unwrap_or_default();
                let incoming_round = checkpoint
                    .prepared_certificate
                    .as_ref()
                    .map(|certificate| certificate.round.0)
                    .unwrap_or_default();
                if incoming_round <= existing_round {
                    return Err(
                        "TYPED_DRIVER_SOURCE_CONFLICT: atomic recovery prepared candidates disagree"
                            .to_string(),
                    );
                }
            }
        }
        journal.recovery_checkpoint = Some(DurableRecoveryCheckpointRecord {
            checkpoint: checkpoint.clone(),
            checkpoint_root,
            persisted_at_unix_ms: current_unix_ms(),
        });
        journal.retired_through_height = journal
            .retired_through_height
            .max(checkpoint.finalized_height.0);
        journal
            .records
            .retain(|record| record.authorization.height.0 > journal.retired_through_height);
        self.persist_unlocked(&journal)?;
        Ok(checkpoint_root)
    }

    pub fn recovery_checkpoint(
        &self,
    ) -> Result<Option<DurableConsensusRecoveryCheckpoint>, String> {
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        Ok(self
            .load_unlocked()?
            .recovery_checkpoint
            .map(|record| record.checkpoint))
    }

    /// Records one successful typed-coordinator initialization in the same
    /// durable journal that anchors signing and recovery state. The returned
    /// value is the number of restarts after the first successful start, so a
    /// fresh chain reports zero and the value survives process replacement.
    pub fn record_coordinator_start(&self) -> Result<u64, String> {
        let lock = PROCESS_WIDE_SIGNING_LOCK.get_or_init(|| Mutex::new(()));
        let _guard = lock
            .lock()
            .map_err(|_| "consensus signing authority lock poisoned".to_string())?;
        let mut journal = self.load_unlocked()?;
        journal.coordinator_start_count = journal
            .coordinator_start_count
            .checked_add(1)
            .ok_or_else(|| "typed coordinator start counter overflow".to_string())?;
        let restarts = journal.coordinator_start_count.saturating_sub(1);
        self.persist_unlocked(&journal)?;
        Ok(restarts)
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
        let mut slots = std::collections::BTreeSet::new();
        for record in &journal.records {
            record.authorization.validate()?;
            if record.slot != record.authorization.slot_key() {
                return Err("consensus signing journal slot binding mismatch".to_string());
            }
            if record.authorization.height.0 <= journal.retired_through_height {
                return Err(
                    "consensus signing journal retains a finalized retired signing slot"
                        .to_string(),
                );
            }
            let authorization_bytes = serde_json::to_vec(&record.authorization)
                .map_err(|error| format!("serialize persisted signing authorization: {error}"))?;
            let expected_root = Hash::from_domain_bytes(
                "SYNERGY_CONSENSUS_SIGNING_AUTHORIZATION_V1",
                &authorization_bytes,
            );
            if record.authorization_root != expected_root
                || record.subject_digest != record.authorization.subject_digest()?
            {
                return Err("consensus signing journal subject binding mismatch".to_string());
            }
            if let Some(vote) = &record.signed_vote {
                if !vote.aegis_pq_signature.is_present()
                    || ConsensusSigningAuthorization::from_vote(vote)? != record.authorization
                    || vote.consensus_subject()?.digest()? != record.subject_digest
                {
                    return Err(
                        "consensus signing journal signed-envelope binding mismatch".to_string()
                    );
                }
            }
            if let Some(block) = &record.signed_proposal {
                if record.authorization.phase != ConsensusSigningPhase::Proposal
                    || !block.proposer_signature.is_present()
                    || record.authorization.candidate_id.as_ref() != Some(&block.candidate_id()?)
                    || record.authorization.chain_id != block.header.chain_id
                    || record.authorization.network_id != block.header.network_id
                    || record.authorization.protocol_version != block.header.protocol_version
                    || record.authorization.epoch != block.header.epoch
                    || record.authorization.height != block.header.height
                    || record.authorization.round != block.header.round
                    || record.authorization.cluster_id != block.header.cluster_id
                    || record.authorization.height_context_root != block.header.height_context_root
                    || record.authorization.validator_id != block.header.proposer_validator_id
                    || record.authorization.key_id != block.header.proposer_key_id
                {
                    return Err(
                        "consensus signing journal signed-proposal binding mismatch".to_string()
                    );
                }
            }
            if record.signed_vote.is_some() && record.signed_proposal.is_some() {
                return Err(
                    "consensus signing journal record contains two envelope kinds".to_string(),
                );
            }
            if !slots.insert(record.slot.clone()) {
                return Err("consensus signing journal contains a duplicate slot".to_string());
            }
        }
        let mut coordinated_slots = std::collections::BTreeSet::new();
        for record in &journal.coordinated_records {
            record.authorization.validate()?;
            if record.slot != record.authorization.slot_key()
                || record.authorization_root != record.authorization.root()?
                || !record.signature.is_present()
                || record.signed_envelope.is_empty()
            {
                return Err("coordinated signing journal record binding mismatch".to_string());
            }
            if record.authorization.height.0 <= journal.retired_through_height {
                return Err(
                    "coordinated signing journal retains a finalized retired signing slot"
                        .to_string(),
                );
            }
            if !coordinated_slots.insert(record.slot.clone()) {
                return Err(
                    "coordinated signing journal contains duplicate signing slots".to_string(),
                );
            }
        }
        for halt in &journal.safety_halts {
            halt.incident.validate()?;
            if halt.incident.root()? != halt.incident_root {
                return Err("consensus SafetyHalt incident root mismatch".to_string());
            }
        }
        if let Some(recovery) = &journal.recovery_checkpoint {
            recovery.checkpoint.validate()?;
            if recovery.checkpoint.root()? != recovery.checkpoint_root {
                return Err("atomic consensus recovery checkpoint root mismatch".to_string());
            }
            if journal.retired_through_height != recovery.checkpoint.finalized_height.0 {
                return Err(
                    "signing retirement watermark disagrees with atomic recovery checkpoint"
                        .to_string(),
                );
            }
        } else if journal.retired_through_height != 0 {
            return Err(
                "signing retirement watermark exists without an atomic recovery checkpoint"
                    .to_string(),
            );
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
        // This is machine-owned durable state. Compact JSON materially lowers
        // copy and fsync latency for large ML-DSA envelopes; incident tooling
        // renders selected records separately for operators.
        let bytes = serde_json::to_vec(journal)
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
            cluster_id: ClusterId(0),
            height_context_root: Hash::from_domain_bytes("context", b"one"),
            validator_id: ValidatorId("validator-1".to_string()),
            key_id: AegisPqKeyId("key-1".to_string()),
            phase,
            candidate_id: Some(BlockId(candidate.to_string())),
            highest_prepared_vc_root: None,
            conflict_unlock_tc_id: None,
        }
    }

    fn coordinated_authorization(
        phase: CoordinatedSigningPhase,
        round: u64,
        subject: &str,
    ) -> CoordinatedSigningAuthorization {
        CoordinatedSigningAuthorization {
            chain_id: ChainId::synergy_testnet_v3(),
            network_id: NetworkId::synergy_testnet_v3(),
            consensus_version: "coordinated_round_robin_v1".to_string(),
            epoch: Epoch(0),
            height: Height(51),
            producer_round: Round(round),
            coordinator_id: ValidatorId("validator-1".to_string()),
            key_id: AegisPqKeyId("validator-1-consensus-key".to_string()),
            phase,
            subject_hash: Hash::from_domain_bytes(
                "SYNERGY_COORDINATED_SIGNING_TEST",
                subject.as_bytes(),
            ),
        }
    }

    fn coordinated_signature(label: &str) -> AegisPqSignature {
        AegisPqSignature {
            algorithm: "mldsa65".to_string(),
            signature_bytes: label.as_bytes().to_vec(),
        }
    }

    #[test]
    fn coordinated_commit_journal_refuses_a_second_block_subject_at_one_height() {
        let authority = temp_authority("coordinated-commit-conflict");
        let first = coordinated_authorization(CoordinatedSigningPhase::Commit, 0, "block-a");
        let signature = coordinated_signature("commit-a");
        let envelope = b"serialized-commit-a";
        authority
            .record_coordinated_envelope(&first, &signature, envelope)
            .expect("persist first coordinator commit before broadcast");
        assert_eq!(
            authority
                .recorded_coordinated_signature(&first)
                .expect("recover recorded signature"),
            Some(signature)
        );
        assert_eq!(
            authority
                .recorded_coordinated_envelope(&first)
                .expect("recover serialized envelope")
                .expect("envelope exists")
                .signed_envelope,
            envelope
        );

        let conflicting = coordinated_authorization(CoordinatedSigningPhase::Commit, 1, "block-b");
        assert!(authority
            .record_coordinated_envelope(
                &conflicting,
                &coordinated_signature("commit-b"),
                b"serialized-commit-b",
            )
            .expect_err("a later producer round cannot authorize a second committed block")
            .contains("CONSENSUS_SIGNING_CONFLICT"));
    }

    #[test]
    fn coordinated_assignment_journal_allows_one_replacement_round_but_not_two_subjects() {
        let authority = temp_authority("coordinated-assignment-rounds");
        let first =
            coordinated_authorization(CoordinatedSigningPhase::Assignment, 0, "assignment-a");
        authority
            .record_coordinated_envelope(
                &first,
                &coordinated_signature("assignment-a"),
                b"serialized-assignment-a",
            )
            .expect("persist initial assignment");
        let replacement =
            coordinated_authorization(CoordinatedSigningPhase::Assignment, 1, "assignment-b");
        authority
            .record_coordinated_envelope(
                &replacement,
                &coordinated_signature("assignment-b"),
                b"serialized-assignment-b",
            )
            .expect("persist replacement assignment after a timeout");
        let conflicting =
            coordinated_authorization(CoordinatedSigningPhase::Assignment, 1, "assignment-c");
        assert!(authority
            .record_coordinated_envelope(
                &conflicting,
                &coordinated_signature("assignment-c"),
                b"serialized-assignment-c",
            )
            .is_err());
    }

    #[test]
    fn coordinated_producer_block_journal_binds_one_block_to_each_assigned_round() {
        let authority = temp_authority("coordinated-producer-block-rounds");
        let first = coordinated_authorization(
            CoordinatedSigningPhase::ProducerBlock,
            0,
            "producer-block-a",
        );
        authority
            .record_coordinated_envelope(
                &first,
                &coordinated_signature("producer-block-a"),
                b"serialized-producer-block-a",
            )
            .expect("persist assigned producer block before it is broadcast");

        let conflicting = coordinated_authorization(
            CoordinatedSigningPhase::ProducerBlock,
            0,
            "producer-block-b",
        );
        assert!(authority
            .record_coordinated_envelope(
                &conflicting,
                &coordinated_signature("producer-block-b"),
                b"serialized-producer-block-b",
            )
            .expect_err("one producer assignment cannot authorize two block subjects")
            .contains("CONSENSUS_SIGNING_CONFLICT"));

        let replacement = coordinated_authorization(
            CoordinatedSigningPhase::ProducerBlock,
            1,
            "producer-block-c",
        );
        authority
            .record_coordinated_envelope(
                &replacement,
                &coordinated_signature("producer-block-c"),
                b"serialized-producer-block-c",
            )
            .expect("a timeout replacement producer round has a separate durable slot");
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

    fn recovery_checkpoint() -> DurableConsensusRecoveryCheckpoint {
        DurableConsensusRecoveryCheckpoint {
            checkpoint_version: 2,
            genesis_anchor: Hash::from_domain_bytes("genesis", b"chain-1266"),
            chain_id: ChainId::synergy_testnet_v3(),
            chain_incarnation: crate::synergy_types::TESTNET_V3_CHAIN_INCARNATION,
            network_id: NetworkId::synergy_testnet_v3(),
            protocol_version: "posy/2.2".to_string(),
            epoch: Epoch(0),
            finalized_height: Height(0),
            finalized_block: None,
            highest_qc: None,
            current_height: Height(1),
            current_round: Round(0),
            height_context_root: Hash::from_domain_bytes("context", b"height-one"),
            active_validator_set_hash: Hash::from_domain_bytes("validators", b"epoch-zero"),
            prepared_block: None,
            prepared_certificate: None,
            highest_tc: None,
        }
    }

    fn finalized_recovery_checkpoint(height: u64) -> DurableConsensusRecoveryCheckpoint {
        let block = Block {
            header: crate::synergy_types::BlockHeader {
                version: 2,
                chain_id: ChainId::synergy_testnet_v3(),
                network_id: NetworkId::synergy_testnet_v3(),
                protocol_version: "posy/2.2".to_string(),
                height: Height(height),
                round: Round(0),
                epoch: Epoch(0),
                cluster_id: ClusterId(0),
                height_context_root: Hash::from_domain_bytes("context", b"finalized"),
                parent_block_hash: Hash::from_domain_bytes("block", b"parent"),
                parent_state_root: Hash::from_domain_bytes("state", b"before"),
                last_finalized_qc_hash: Hash::from_domain_bytes("qc", b"prior"),
                proposer_validator_id: ValidatorId("validator-1".to_string()),
                proposer_uma_id: crate::synergy_types::UmaId("uma-1".to_string()),
                proposer_key_id: AegisPqKeyId("key-1".to_string()),
                active_validator_set_hash: Hash::from_domain_bytes("validators", b"active"),
                eligible_validator_set_hash: Hash::from_domain_bytes("validators", b"eligible"),
                validator_consensus_key_root: Hash::from_domain_bytes("keys", b"consensus"),
                frozen_bonded_weight_root: Hash::from_domain_bytes("weights", b"frozen"),
                cluster_schedule_version: "v1".to_string(),
                cluster_map_hash: Hash::from_domain_bytes("clusters", b"map"),
                assigned_cluster_membership_root: Hash::from_domain_bytes("clusters", b"members"),
                assigned_cluster_validator_count: 6,
                assigned_cluster_total_voting_weight: 6,
                proposer_schedule_hash: Hash::from_domain_bytes("proposers", b"schedule"),
                protocol_config_hash: crate::consensus_parameters::ConsensusParameterRoot::zero(),
                cryptographic_profile_root: Hash::from_domain_bytes("crypto", b"profile"),
                dag_frontier_root: Hash::from_domain_bytes("dag", b"frontier"),
                tx_order_root: Hash::from_domain_bytes("transactions", b"order"),
                tx_count: 0,
                protected_batch: None,
                evidence_root: Hash::from_domain_bytes("evidence", b"none"),
                state_root_before: Hash::from_domain_bytes("state", b"before"),
                state_root_after: Hash::from_domain_bytes("state", b"after"),
                receipt_root: Hash::from_domain_bytes("receipts", b"root"),
                app_version: 1,
                execution_version: 1,
                dag_version: 1,
                aegis_pqvm_version: "aegis-pqvm".to_string(),
                timestamp_ms_consensus_bounded: 1,
                base_fee_per_gas_nwei: 0,
                gas_used: 0,
                gas_limit: 0,
                pq_gas_used: 0,
                pq_gas_limit: 0,
                pq_gas_multiplier: 0,
                fee_market_version: 0,
            },
            transactions: Vec::new(),
            proposer_signature: crate::synergy_types::AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            },
        };
        let quorum_certificate = QuorumCertificate {
            qc_version: 1,
            chain_id: block.header.chain_id,
            network_id: block.header.network_id.clone(),
            protocol_version: block.header.protocol_version.clone(),
            height: block.header.height,
            round: block.header.round,
            epoch: block.header.epoch,
            cluster_id: block.header.cluster_id,
            height_context_root: block.header.height_context_root,
            phase: VotePhase::Finality,
            block_id: block.candidate_id().expect("candidate id"),
            highest_prepared_vc_root: None,
            active_validator_set_hash: block.header.active_validator_set_hash,
            cluster_map_hash: block.header.cluster_map_hash,
            threshold_weight_required: 5,
            signed_weight: 5,
            signer_bitmap: vec![0b0001_1111],
            aegis_pq_signatures: vec![crate::synergy_types::AegisPqSignature {
                algorithm: "mldsa65".to_string(),
                signature_bytes: vec![1],
            }],
            aegis_pq_key_ids: vec![AegisPqKeyId("key-1".to_string())],
        };
        let mut checkpoint = recovery_checkpoint();
        checkpoint.finalized_height = Height(height);
        checkpoint.finalized_block = Some(block);
        checkpoint.highest_qc = Some(quorum_certificate);
        checkpoint.current_height = Height(height.saturating_add(1));
        checkpoint.height_context_root = Hash::from_domain_bytes("context", b"successor");
        checkpoint.active_validator_set_hash = Hash::from_domain_bytes("validators", b"active");
        checkpoint
    }

    #[test]
    fn atomic_recovery_checkpoint_survives_interrupted_temp_write_and_rejects_tampering() {
        let authority = temp_authority("atomic-recovery");
        let checkpoint = recovery_checkpoint();
        authority
            .commit_recovery_checkpoint(&checkpoint)
            .expect("atomic checkpoint commit");

        let interrupted = authority.path().with_extension("tmp-interrupted");
        fs::write(&interrupted, b"partial write").expect("simulate abandoned temp file");
        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        assert_eq!(
            restarted.recovery_checkpoint().unwrap(),
            Some(checkpoint.clone()),
            "an unrenamed partial write cannot alter the committed recovery state"
        );

        let mut encoded: serde_json::Value =
            serde_json::from_slice(&fs::read(authority.path()).unwrap()).unwrap();
        encoded["recovery_checkpoint"]["checkpoint_root"] =
            serde_json::to_value(Hash::zero()).unwrap();
        fs::write(
            authority.path(),
            serde_json::to_vec_pretty(&encoded).unwrap(),
        )
        .unwrap();
        assert!(restarted
            .recovery_checkpoint()
            .unwrap_err()
            .contains("checkpoint root mismatch"));
        let _ = fs::remove_file(interrupted);
    }

    #[test]
    fn retirement_watermark_compacts_long_journals_and_rejects_inconsistent_history() {
        const LONG_RUN_HEIGHT: u64 = 512;
        const COMPACTION_INTERVAL: u64 = 64;

        let authority = temp_authority("retirement-watermark");
        let mut first_record = None;
        for height in 1..=LONG_RUN_HEIGHT {
            let mut record = authorization(ConsensusSigningPhase::Finality, 0, "candidate-a");
            record.height = Height(height);
            record.height_context_root =
                Hash::from_domain_bytes("context", format!("height-{height}").as_bytes());
            authority
                .authorize_before_signature(&record)
                .expect("record live signing authorization");
            if height == 1 {
                first_record = authority
                    .load_unlocked()
                    .expect("load first durable record")
                    .records
                    .into_iter()
                    .next();
            }
            if height % COMPACTION_INTERVAL == 0 && height < LONG_RUN_HEIGHT {
                authority
                    .commit_recovery_checkpoint(&finalized_recovery_checkpoint(height))
                    .expect("compact finalized signing slots");
                let journal = authority.load_unlocked().expect("load compacted journal");
                assert!(journal
                    .records
                    .iter()
                    .all(|entry| entry.authorization.height.0 > height));
                assert!(
                    journal.records.len() < COMPACTION_INTERVAL as usize,
                    "journal must remain bounded between finalized checkpoints"
                );
            }
        }

        authority
            .commit_recovery_checkpoint(&finalized_recovery_checkpoint(LONG_RUN_HEIGHT - 1))
            .expect("final watermark compaction");
        let compacted = authority.load_unlocked().expect("load compacted journal");
        assert_eq!(compacted.retired_through_height, LONG_RUN_HEIGHT - 1);
        assert_eq!(compacted.records.len(), 1, "only the live height remains");
        assert_eq!(compacted.records[0].authorization.height.0, LONG_RUN_HEIGHT);

        let mut retired = authorization(ConsensusSigningPhase::Finality, 0, "candidate-a");
        retired.height = Height(1);
        retired.height_context_root = Hash::from_domain_bytes("context", b"height-1");
        assert!(authority
            .authorize_before_signature(&retired)
            .expect_err("retired finalized height must never sign again")
            .contains("retired through finalized height"));

        let mut retaining_retired_record: serde_json::Value =
            serde_json::from_slice(&fs::read(authority.path()).expect("read compacted journal"))
                .expect("parse compacted journal");
        retaining_retired_record["records"]
            .as_array_mut()
            .expect("journal records array")
            .push(
                serde_json::to_value(first_record.expect("first record")).expect("encode record"),
            );
        fs::write(
            authority.path(),
            serde_json::to_vec(&retaining_retired_record).expect("encode tampered journal"),
        )
        .expect("write tampered journal");
        assert!(authority
            .recovery_checkpoint()
            .expect_err("retained finalized record must fail closed")
            .contains("retains a finalized retired signing slot"));

        let mismatched = temp_authority("retirement-watermark-mismatch");
        mismatched
            .commit_recovery_checkpoint(&finalized_recovery_checkpoint(1))
            .expect("persist checkpoint");
        let mut mismatched_watermark: serde_json::Value =
            serde_json::from_slice(&fs::read(mismatched.path()).expect("read checkpoint"))
                .expect("parse checkpoint");
        mismatched_watermark["retired_through_height"] = serde_json::json!(2);
        fs::write(
            mismatched.path(),
            serde_json::to_vec(&mismatched_watermark).expect("encode mismatch"),
        )
        .expect("write mismatched watermark");
        assert!(mismatched
            .recovery_checkpoint()
            .expect_err("watermark must match its atomic checkpoint")
            .contains("retirement watermark disagrees"));
    }

    #[test]
    fn coordinator_restart_counter_is_durable_and_excludes_the_initial_start() {
        let authority = temp_authority("durable-restart-count");
        assert_eq!(authority.record_coordinator_start().unwrap(), 0);

        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        assert_eq!(restarted.record_coordinator_start().unwrap(), 1);
        assert_eq!(restarted.record_coordinator_start().unwrap(), 2);
    }

    #[test]
    fn finality_slot_is_height_scoped_and_survives_restart() {
        let authority = temp_authority("finality");
        let first = authorization(ConsensusSigningPhase::Finality, 0, "candidate-a");
        authority.authorize_before_signature(&first).unwrap();

        let restarted = DurableConsensusSigningAuthority::at_path(authority.path().to_path_buf());
        let carried = authorization(ConsensusSigningPhase::Finality, 4, "candidate-a");
        assert!(
            restarted.authorize_before_signature(&carried).is_ok(),
            "the exact stable candidate may be finalized again in a TC-authorized later round"
        );
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
    fn simplified_vote_is_height_scoped_across_takeover_rounds() {
        let authority = temp_authority("simplified-vote-height");
        let first = authorization(ConsensusSigningPhase::Vote, 0, "candidate-a");
        authority.authorize_before_signature(&first).unwrap();
        assert!(
            authority
                .authorize_before_signature(&authorization(
                    ConsensusSigningPhase::Vote,
                    1,
                    "candidate-a",
                ))
                .is_ok(),
            "a TC-authorized round may re-emit authority for the same candidate"
        );
        assert!(authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::Vote,
                1,
                "candidate-b",
            ))
            .unwrap_err()
            .contains("CONSENSUS_SIGNING_CONFLICT"));
    }

    #[test]
    fn verified_no_carry_tc_can_unlock_a_same_height_vote_change() {
        let authority = temp_authority("simplified-vote-no-carry-unlock");
        authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::Vote,
                0,
                "candidate-a",
            ))
            .unwrap();
        let mut unlocked = authorization(ConsensusSigningPhase::Vote, 1, "candidate-b");
        unlocked.conflict_unlock_tc_id = Some(Hash::from_domain_bytes(
            "verified-no-carry-tc",
            b"height-1-round-0",
        ));
        authority.authorize_before_signature(&unlocked).unwrap();
    }

    #[test]
    fn reliable_delivery_ready_is_round_scoped() {
        let authority = temp_authority("reliable-delivery-ready-round");
        let first = authorization(ConsensusSigningPhase::ProposalReady, 0, "candidate-a");
        authority.authorize_before_signature(&first).unwrap();
        assert!(authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::ProposalReady,
                0,
                "candidate-b",
            ))
            .unwrap_err()
            .contains("CONSENSUS_SIGNING_CONFLICT"));
        authority
            .authorize_before_signature(&authorization(
                ConsensusSigningPhase::ProposalReady,
                3,
                "candidate-b",
            ))
            .unwrap();
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
    fn restart_rejects_tampered_authorization_roots_and_duplicate_slots() {
        let authority = temp_authority("tampered-journal");
        let authorization = authorization(ConsensusSigningPhase::Vote, 0, "candidate-a");
        authority
            .authorize_before_signature(&authorization)
            .unwrap();

        let original = fs::read(authority.path()).unwrap();
        let mut tampered: serde_json::Value = serde_json::from_slice(&original).unwrap();
        tampered["records"][0]["authorization"]["candidate_id"] = serde_json::json!("candidate-b");
        fs::write(
            authority.path(),
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        assert!(authority
            .recorded_authorizations()
            .unwrap_err()
            .contains("authorization root mismatch"));

        let mut duplicated: serde_json::Value = serde_json::from_slice(&original).unwrap();
        let duplicate = duplicated["records"][0].clone();
        duplicated["records"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        fs::write(
            authority.path(),
            serde_json::to_vec_pretty(&duplicated).unwrap(),
        )
        .unwrap();
        assert!(authority
            .recorded_authorizations()
            .unwrap_err()
            .contains("duplicate slot"));
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
            ConsensusSigningPhase::ProposalEcho,
            ConsensusSigningPhase::ProposalReady,
            ConsensusSigningPhase::Vote,
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
