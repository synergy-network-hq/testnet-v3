//! Authenticated consistent proposal delivery for a frozen validator epoch.
//!
//! This is dissemination, not a second ordinary consensus vote. Validators
//! still emit exactly one block vote that forms the normal QC. ECHO/READY
//! prevents a Byzantine scheduled proposer from splitting honest validators
//! and forcing the protocol to choose between deadlock and cross-round
//! conflicting QCs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    CertifiedCandidateSubject, ConsensusObjectContext, ConsensusSignatureVerifier,
    SimplifiedEpochContext, VerifiedSimplifiedProposalMaterial,
    POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT,
};
use crate::etdag::EtdagDigest;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqSignature, Hash, Round, ValidatorId, ValidatorRecord, ValidatorSet,
};

/// Signature domain for proposal ECHO statements.
pub const POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN: &str = "PoSy/Consensus/v3/ProposalEcho";
/// Signature domain for proposal READY statements.
pub const POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN: &str = "PoSy/Consensus/v3/ProposalReady";
/// Durable serialization format for reliable-delivery state.
pub const POSY_SIMPLIFIED_RELIABLE_DELIVERY_FORMAT: &str =
    "synergy-posy-simplified-reliable-delivery-v2";
/// Canonical n-1 ECHO proof format used as the PoSy proposal VC.
pub const POSY_SIMPLIFIED_PROPOSAL_VC_FORMAT: &str = "synergy-posy-simplified-proposal-vc-v1";
/// Domain for the exact authenticated proposal VC proof bundle.
pub const POSY_SIMPLIFIED_PROPOSAL_VC_DOMAIN: &str =
    "PoSy/Consensus/v3/ProposalValidationCertificate";

/// Canonical n-1 authenticated ECHO proof for one exact proposal view and
/// proposal-authenticated next protected-batch commitment.
///
/// The candidate identity is stable across retransmission rounds, while
/// `context.round` binds this proof to the exact PoSy view in which its ECHOs
/// were signed. READY statements are deliberately absent and cannot be
/// converted into this certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PosyProposalValidationCertificate {
    pub format: String,
    pub context: ConsensusObjectContext,
    pub candidate: CertifiedCandidateSubject,
    pub next_protected_batch_commitment_root: EtdagDigest,
    pub echoes: Vec<ReliableDeliveryStatement>,
}

impl PosyProposalValidationCertificate {
    /// Stable semantic identity shared by every valid n-1 signer subset.
    pub fn semantic_candidate_id(&self) -> Result<Hash, String> {
        self.candidate.id()
    }

    /// Root of this exact canonical ECHO evidence bundle.
    pub fn proof_root(&self) -> Result<EtdagDigest, String> {
        EtdagDigest::from_canonical(POSY_SIMPLIFIED_PROPOSAL_VC_DOMAIN, self)
    }

    /// Construct and authenticate the canonical n-1 subset. Extra valid ECHOs
    /// do not change the semantic candidate identity and are deterministically
    /// omitted by validator ID.
    pub fn from_authenticated_echoes<V: ConsensusSignatureVerifier>(
        context: ConsensusObjectContext,
        candidate: CertifiedCandidateSubject,
        material: &VerifiedSimplifiedProposalMaterial,
        mut echoes: Vec<ReliableDeliveryStatement>,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<Self, String> {
        let next_commitment = material
            .future_protected_batch_commitment
            .as_ref()
            .ok_or_else(|| {
                "proposal VC material has no child protected-batch commitment".to_string()
            })?;
        if material.candidate_subject != candidate {
            return Err("proposal VC material names another proposal candidate".to_string());
        }
        let thresholds =
            ReliableDeliveryThresholds::for_validator_count(epoch_context.leader_ring.len())?;
        echoes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        if echoes.len() < thresholds.echo {
            return Err(format!(
                "proposal VC has {} ECHOs, requires {}",
                echoes.len(),
                thresholds.echo
            ));
        }
        echoes.truncate(thresholds.echo);
        let certificate = Self {
            format: POSY_SIMPLIFIED_PROPOSAL_VC_FORMAT.to_string(),
            context,
            candidate,
            next_protected_batch_commitment_root: next_commitment.root()?,
            echoes,
        };
        certificate.validate_authenticated(material, epoch_context, validator_set, verifier)?;
        Ok(certificate)
    }

    /// Independently validate the exact view, candidate, commitment, frozen
    /// validator identities, canonical n-1 subset, and every ECHO signature.
    pub fn validate_authenticated<V: ConsensusSignatureVerifier>(
        &self,
        material: &VerifiedSimplifiedProposalMaterial,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<(), String> {
        let commitment = material
            .future_protected_batch_commitment
            .as_ref()
            .ok_or_else(|| {
                "proposal VC material has no child protected-batch commitment".to_string()
            })?;
        if material.candidate_subject != self.candidate
            || material.stable_candidate_id != self.candidate.id()?
        {
            return Err("proposal VC material names another proposal candidate".to_string());
        }
        self.validate_authenticated_binding(commitment, epoch_context, validator_set, verifier)
    }

    fn validate_authenticated_binding<V: ConsensusSignatureVerifier>(
        &self,
        commitment: &crate::etdag::NextProtectedBatchCommitment,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_PROPOSAL_VC_FORMAT {
            return Err("unsupported proposal VC format".to_string());
        }
        self.context.validate_against(epoch_context)?;
        epoch_context.validate_against(validator_set)?;
        let mut stable_context = self.context.clone();
        stable_context.round = Round(0);
        if self.candidate.context != stable_context {
            return Err("proposal VC candidate or view binding mismatch".to_string());
        }
        let child_height = crate::synergy_types::Height(
            self.context
                .height
                .0
                .checked_add(1)
                .ok_or_else(|| "proposal VC child height overflow".to_string())?,
        );
        if commitment.target_height != child_height
            || commitment.epoch != self.context.epoch
            || self.next_protected_batch_commitment_root != commitment.root()?
        {
            return Err("proposal VC protected commitment binding mismatch".to_string());
        }
        let threshold =
            ReliableDeliveryThresholds::for_validator_count(epoch_context.leader_ring.len())?.echo;
        if self.echoes.len() != threshold {
            return Err(format!(
                "proposal VC must contain exactly {threshold} canonical ECHOs"
            ));
        }
        let mut previous_validator: Option<&ValidatorId> = None;
        for echo in &self.echoes {
            if previous_validator.is_some_and(|previous| previous >= &echo.validator_id) {
                return Err("proposal VC ECHOs are duplicate or noncanonical".to_string());
            }
            previous_validator = Some(&echo.validator_id);
            if echo.phase != ReliableDeliveryPhase::Echo
                || echo.context != self.context
                || echo.candidate != self.candidate
            {
                return Err(
                    "proposal VC contains a non-ECHO or differently bound statement".to_string(),
                );
            }
            verify_statement(echo, epoch_context, validator_set, verifier)?;
        }
        self.proof_root()?.validate("proposal VC proof root")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReliableDeliveryThresholds {
    echo: usize,
    ready_relay: usize,
    delivery: usize,
    max_candidates: usize,
}

impl ReliableDeliveryThresholds {
    fn for_validator_count(validator_count: usize) -> Result<Self, String> {
        if validator_count < POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT {
            return Err(format!(
                "reliable delivery requires at least {POSY_SIMPLIFIED_MIN_VALIDATOR_COUNT} frozen validators, found {validator_count}"
            ));
        }
        Ok(Self {
            echo: validator_count
                .checked_sub(1)
                .ok_or_else(|| "reliable-delivery ECHO threshold underflow".to_string())?,
            ready_relay: 2,
            delivery: 3,
            max_candidates: validator_count,
        })
    }
}

/// Authenticated dissemination phase preceding the one ordinary block vote.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReliableDeliveryPhase {
    Echo,
    Ready,
}

impl ReliableDeliveryPhase {
    fn domain(self) -> &'static str {
        match self {
            Self::Echo => POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN,
            Self::Ready => POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ReliableDeliverySigningPayload<'a> {
    context: &'a ConsensusObjectContext,
    phase: ReliableDeliveryPhase,
    candidate_id: Hash,
    validator_id: &'a ValidatorId,
    key_id: &'a AegisPqKeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// One validator's authenticated ECHO or READY statement.
pub struct ReliableDeliveryStatement {
    pub context: ConsensusObjectContext,
    pub phase: ReliableDeliveryPhase,
    pub candidate: CertifiedCandidateSubject,
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

impl ReliableDeliveryStatement {
    /// Returns the stable, round-independent candidate identity.
    pub fn candidate_id(&self) -> Result<Hash, String> {
        self.candidate.id()
    }

    /// Returns the canonical bytes covered by the phase-specific signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&ReliableDeliverySigningPayload {
            context: &self.context,
            phase: self.phase,
            candidate_id: self.candidate_id()?,
            validator_id: &self.validator_id,
            key_id: &self.key_id,
        })
        .map_err(|error| format!("serialize reliable-delivery statement: {error}"))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Actions enabled by accepting one reliable-delivery statement.
pub struct ReliableDeliveryDecision {
    pub ready_candidate: Option<CertifiedCandidateSubject>,
    pub delivered_candidate: Option<CertifiedCandidateSubject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
/// Bounded ECHO/READY evidence retained for one height and round.
pub struct ReliableDeliveryState {
    pub format: String,
    pub context: ConsensusObjectContext,
    frozen_validator_count: usize,
    pub local_echo_candidate_id: Option<Hash>,
    pub local_ready_candidate_id: Option<Hash>,
    pub delivered_candidate: Option<CertifiedCandidateSubject>,
    // JSON object keys must be strings. Candidate IDs remain 256-bit hashes
    // in every signing transcript; persisted indexes use their canonical hex
    // encoding so the complete durable state is serializable and reversible.
    candidates: BTreeMap<String, CertifiedCandidateSubject>,
    echoes: BTreeMap<String, BTreeMap<ValidatorId, ReliableDeliveryStatement>>,
    ready: BTreeMap<String, BTreeMap<ValidatorId, ReliableDeliveryStatement>>,
    echo_by_validator: BTreeMap<ValidatorId, String>,
    ready_by_validator: BTreeMap<ValidatorId, String>,
}

impl ReliableDeliveryState {
    /// Creates empty reliable-delivery state for a bounded consensus slot.
    pub fn new(
        context: ConsensusObjectContext,
        epoch_context: &SimplifiedEpochContext,
    ) -> Result<Self, String> {
        context.validate_against(epoch_context)?;
        if context.round.0 > u32::MAX as u64 {
            return Err("reliable-delivery round exceeds the bounded profile".to_string());
        }
        let frozen_validator_count = epoch_context.leader_ring.len();
        ReliableDeliveryThresholds::for_validator_count(frozen_validator_count)?;
        Ok(Self {
            format: POSY_SIMPLIFIED_RELIABLE_DELIVERY_FORMAT.to_string(),
            context,
            frozen_validator_count,
            local_echo_candidate_id: None,
            local_ready_candidate_id: None,
            delivered_candidate: None,
            candidates: BTreeMap::new(),
            echoes: BTreeMap::new(),
            ready: BTreeMap::new(),
            echo_by_validator: BTreeMap::new(),
            ready_by_validator: BTreeMap::new(),
        })
    }

    /// Validates all non-cryptographic invariants of persisted state.
    ///
    /// Use [`Self::validate_authenticated`] when loading state from storage so
    /// every retained statement is also checked against the frozen validator
    /// set and its signature.
    pub fn validate(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        if self.format != POSY_SIMPLIFIED_RELIABLE_DELIVERY_FORMAT {
            return Err("unsupported reliable-delivery state format".to_string());
        }
        self.context.validate_against(epoch_context)?;
        let frozen_validator_count = epoch_context.leader_ring.len();
        if self.frozen_validator_count != frozen_validator_count {
            return Err(
                "reliable-delivery state validator count does not match its frozen epoch"
                    .to_string(),
            );
        }
        let thresholds = ReliableDeliveryThresholds::for_validator_count(frozen_validator_count)?;
        if self.candidates.len() > thresholds.max_candidates {
            return Err("reliable-delivery candidate bound exceeded".to_string());
        }
        for (candidate_id, candidate) in &self.candidates {
            self.require_candidate_slot(candidate)?;
            if candidate.id()?.to_hex() != *candidate_id {
                return Err("reliable-delivery candidate index is inconsistent".to_string());
            }
        }
        self.validate_local_candidate_id(self.local_echo_candidate_id, "ECHO")?;
        self.validate_local_candidate_id(self.local_ready_candidate_id, "READY")?;
        self.validate_statement_index(
            ReliableDeliveryPhase::Echo,
            &self.echoes,
            &self.echo_by_validator,
        )?;
        self.validate_statement_index(
            ReliableDeliveryPhase::Ready,
            &self.ready,
            &self.ready_by_validator,
        )?;

        let deliverable_ids: Vec<String> = self
            .ready
            .iter()
            .filter_map(|(candidate_id, statements)| {
                (statements.len() >= thresholds.delivery).then_some(candidate_id.clone())
            })
            .collect();
        match (&self.delivered_candidate, deliverable_ids.as_slice()) {
            (None, []) => {}
            (Some(delivered), [deliverable_id])
                if delivered.id()?.to_hex() == *deliverable_id
                    && self.candidates.get(deliverable_id) == Some(delivered) => {}
            (None, [_]) => {
                return Err("deliverable candidate was not recorded as delivered".to_string());
            }
            (Some(_), []) => {
                return Err(format!(
                    "delivered candidate lacks {} READY statements",
                    thresholds.delivery
                ));
            }
            _ => {
                return Err(
                    "reliable-delivery state contains conflicting delivery evidence".to_string(),
                );
            }
        }
        Ok(())
    }

    /// Validates persisted state, its frozen validator set, and every signature.
    pub fn validate_authenticated<V: ConsensusSignatureVerifier>(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<(), String> {
        self.validate(epoch_context)?;
        epoch_context.validate_against(validator_set)?;
        for statements in self.echoes.values().chain(self.ready.values()) {
            for statement in statements.values() {
                verify_statement(statement, epoch_context, validator_set, verifier)?;
            }
        }
        Ok(())
    }

    /// Returns the exact persisted local statement for crash-safe
    /// retransmission. The original signature bytes are reused; ML-DSA
    /// signatures are not assumed deterministic.
    pub fn local_statement(
        &self,
        phase: ReliableDeliveryPhase,
        local_validator_id: &ValidatorId,
    ) -> Result<Option<ReliableDeliveryStatement>, String> {
        let candidate_id = match phase {
            ReliableDeliveryPhase::Echo => self.local_echo_candidate_id,
            ReliableDeliveryPhase::Ready => self.local_ready_candidate_id,
        };
        let Some(candidate_id) = candidate_id else {
            return Ok(None);
        };
        let statements = match phase {
            ReliableDeliveryPhase::Echo => &self.echoes,
            ReliableDeliveryPhase::Ready => &self.ready,
        };
        statements
            .get(&candidate_id.to_hex())
            .and_then(|by_validator| by_validator.get(local_validator_id))
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                "persisted local reliable-delivery authorization lacks its signed statement"
                    .to_string()
            })
    }

    /// Return the canonical authenticated n-1 ECHO proof for the exact
    /// proposal material once the threshold exists. READY delivery is not
    /// consulted and cannot authorize protected reveal.
    pub fn proposal_validation_certificate<V: ConsensusSignatureVerifier>(
        &self,
        material: &VerifiedSimplifiedProposalMaterial,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<Option<PosyProposalValidationCertificate>, String> {
        self.validate_authenticated(epoch_context, validator_set, verifier)?;
        let candidate = material.candidate_subject.clone();
        self.require_candidate_slot(&candidate)?;
        let candidate_key = candidate.id()?.to_hex();
        let echoes = self
            .echoes
            .get(&candidate_key)
            .map(|statements| statements.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if echoes.len() < self.thresholds()?.echo {
            return Ok(None);
        }
        PosyProposalValidationCertificate::from_authenticated_echoes(
            self.context.clone(),
            candidate,
            material,
            echoes,
            epoch_context,
            validator_set,
            verifier,
        )
        .map(Some)
    }

    /// Registers a proposal candidate before authorizing the local ECHO.
    pub fn observe_candidate(
        &mut self,
        candidate: CertifiedCandidateSubject,
    ) -> Result<Hash, String> {
        self.require_candidate_slot(&candidate)?;
        let candidate_id = candidate.id()?;
        match self.local_echo_candidate_id {
            Some(existing) if existing != candidate_id => Err(
                "local validator already ECHOed another candidate in this delivery slot"
                    .to_string(),
            ),
            _ => {
                self.insert_candidate(candidate_id, candidate)?;
                Ok(candidate_id)
            }
        }
    }

    /// Records that the local ECHO/READY authorization and signature have been
    /// durably persisted before the statement may be broadcast.
    pub fn record_local_statement(
        &mut self,
        statement: &ReliableDeliveryStatement,
    ) -> Result<(), String> {
        if statement.context != self.context {
            return Err("local reliable-delivery statement names another slot".to_string());
        }
        self.require_candidate_slot(&statement.candidate)?;
        let candidate_id = statement.candidate_id()?;
        let existing = match statement.phase {
            ReliableDeliveryPhase::Echo => self.local_echo_candidate_id,
            ReliableDeliveryPhase::Ready => self.local_ready_candidate_id,
        };
        if existing.is_some_and(|existing| existing != candidate_id) {
            return Err(
                "local reliable-delivery phase already authorized another candidate".to_string(),
            );
        }
        self.insert_candidate(candidate_id, statement.candidate.clone())?;
        match statement.phase {
            ReliableDeliveryPhase::Echo => self.local_echo_candidate_id = Some(candidate_id),
            ReliableDeliveryPhase::Ready => self.local_ready_candidate_id = Some(candidate_id),
        }
        Ok(())
    }

    /// Verifies and records one frozen-validator statement.
    pub fn accept_statement<V: ConsensusSignatureVerifier>(
        &mut self,
        statement: ReliableDeliveryStatement,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<ReliableDeliveryDecision, String> {
        self.validate(epoch_context)?;
        epoch_context.validate_against(validator_set)?;
        if statement.context != self.context {
            return Err("reliable-delivery statement names another slot".to_string());
        }
        self.require_candidate_slot(&statement.candidate)?;
        let candidate_id = statement.candidate_id()?;
        let candidate_key = candidate_id.to_hex();
        verify_statement(&statement, epoch_context, validator_set, verifier)?;

        let existing_candidate_id = match statement.phase {
            ReliableDeliveryPhase::Echo => self.echo_by_validator.get(&statement.validator_id),
            ReliableDeliveryPhase::Ready => self.ready_by_validator.get(&statement.validator_id),
        };
        if existing_candidate_id.is_some_and(|existing| existing != &candidate_key) {
            return Err("validator equivocated in reliable proposal delivery".to_string());
        }
        self.insert_candidate(candidate_id, statement.candidate.clone())?;
        let (by_validator, statements) = match statement.phase {
            ReliableDeliveryPhase::Echo => (&mut self.echo_by_validator, &mut self.echoes),
            ReliableDeliveryPhase::Ready => (&mut self.ready_by_validator, &mut self.ready),
        };
        by_validator
            .entry(statement.validator_id.clone())
            .or_insert_with(|| candidate_key.clone());
        let candidate_statements = statements.entry(candidate_key).or_default();
        if let Some(existing) = candidate_statements.get(&statement.validator_id) {
            if existing != &statement {
                return Err("validator changed a reliable-delivery signature".to_string());
            }
        } else {
            candidate_statements.insert(statement.validator_id.clone(), statement);
        }
        self.decision_for(candidate_id)
    }

    fn decision_for(&mut self, candidate_id: Hash) -> Result<ReliableDeliveryDecision, String> {
        let thresholds = self.thresholds()?;
        let candidate_key = candidate_id.to_hex();
        let echo_count = self.echoes.get(&candidate_key).map_or(0, BTreeMap::len);
        let ready_count = self.ready.get(&candidate_key).map_or(0, BTreeMap::len);
        let candidate = self
            .candidates
            .get(&candidate_key)
            .cloned()
            .ok_or_else(|| "reliable-delivery candidate body is missing".to_string())?;
        let ready_candidate = (self.local_ready_candidate_id.is_none()
            && (echo_count >= thresholds.echo || ready_count >= thresholds.ready_relay))
            .then(|| candidate.clone());
        let delivered_candidate = if ready_count >= thresholds.delivery {
            if let Some(existing) = &self.delivered_candidate {
                if existing.id()? != candidate_id {
                    return Err("conflicting candidates reached reliable delivery".to_string());
                }
            } else {
                self.delivered_candidate = Some(candidate.clone());
            }
            Some(candidate)
        } else {
            None
        };
        Ok(ReliableDeliveryDecision {
            ready_candidate,
            delivered_candidate,
        })
    }

    fn thresholds(&self) -> Result<ReliableDeliveryThresholds, String> {
        ReliableDeliveryThresholds::for_validator_count(self.frozen_validator_count)
    }

    fn require_candidate_slot(&self, candidate: &CertifiedCandidateSubject) -> Result<(), String> {
        candidate.validate()?;
        let mut stable_context = self.context.clone();
        stable_context.round = Round(0);
        if candidate.context != stable_context {
            return Err("reliable-delivery candidate names another height/context".to_string());
        }
        Ok(())
    }

    fn insert_candidate(
        &mut self,
        candidate_id: Hash,
        candidate: CertifiedCandidateSubject,
    ) -> Result<(), String> {
        let candidate_key = candidate_id.to_hex();
        if let Some(existing) = self.candidates.get(&candidate_key) {
            return if existing == &candidate {
                Ok(())
            } else {
                Err("candidate hash collision in reliable delivery".to_string())
            };
        }
        if self.candidates.len() >= self.thresholds()?.max_candidates {
            return Err("reliable-delivery candidate pool is full".to_string());
        }
        self.candidates.insert(candidate_key, candidate);
        Ok(())
    }

    fn validate_local_candidate_id(
        &self,
        candidate_id: Option<Hash>,
        phase_name: &str,
    ) -> Result<(), String> {
        if candidate_id.is_some_and(|id| !self.candidates.contains_key(&id.to_hex())) {
            return Err(format!(
                "local {phase_name} authorization names an unknown candidate"
            ));
        }
        Ok(())
    }

    fn validate_statement_index(
        &self,
        phase: ReliableDeliveryPhase,
        statements_by_candidate: &BTreeMap<
            String,
            BTreeMap<ValidatorId, ReliableDeliveryStatement>,
        >,
        candidate_by_validator: &BTreeMap<ValidatorId, String>,
    ) -> Result<(), String> {
        let mut rebuilt_by_validator = BTreeMap::new();
        for (candidate_id, statements) in statements_by_candidate {
            let candidate = self.candidates.get(candidate_id).ok_or_else(|| {
                "reliable-delivery evidence names an unknown candidate".to_string()
            })?;
            if statements.is_empty() {
                return Err(
                    "reliable-delivery evidence contains an empty candidate bucket".to_string(),
                );
            }
            for (validator_id, statement) in statements {
                if statement.context != self.context
                    || statement.phase != phase
                    || &statement.validator_id != validator_id
                    || &statement.candidate != candidate
                    || statement.candidate_id()?.to_hex() != *candidate_id
                {
                    return Err("reliable-delivery statement index is inconsistent".to_string());
                }
                if rebuilt_by_validator
                    .insert(validator_id.clone(), candidate_id.clone())
                    .is_some()
                {
                    return Err(
                        "validator has multiple statements in one delivery phase".to_string()
                    );
                }
            }
        }
        if &rebuilt_by_validator != candidate_by_validator {
            return Err("reliable-delivery validator index is inconsistent".to_string());
        }
        Ok(())
    }
}

fn verify_statement<V: ConsensusSignatureVerifier>(
    statement: &ReliableDeliveryStatement,
    epoch_context: &SimplifiedEpochContext,
    validator_set: &ValidatorSet,
    verifier: &V,
) -> Result<(), String> {
    let validator = active_validator(validator_set, epoch_context, &statement.validator_id)?;
    if statement.key_id != validator.consensus_public_key.key_id {
        return Err("reliable-delivery statement uses the wrong frozen key".to_string());
    }
    verifier.verify_consensus_signature(
        statement.phase.domain(),
        &statement.signing_bytes()?,
        validator,
        &statement.key_id,
        statement.context.epoch,
        &statement.signature,
    )
}

fn active_validator<'a>(
    validator_set: &'a ValidatorSet,
    epoch_context: &SimplifiedEpochContext,
    validator_id: &ValidatorId,
) -> Result<&'a ValidatorRecord, String> {
    validator_set
        .validators
        .iter()
        .find(|validator| {
            &validator.validator_id == validator_id
                && validator.is_active_for_epoch(epoch_context.epoch)
        })
        .ok_or_else(|| "reliable-delivery signer is absent from the frozen set".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::simplified_posy::{
        QuorumCertificateReference, SimplifiedFinalityParent, POSY_SIMPLIFIED_PROTOCOL_VERSION,
    };
    use crate::consensus_parameters::ConsensusParameterRoot;
    use crate::etdag::{NextProtectedBatchCommitment, PROTECTED_PIPELINE_VERSION};
    use crate::synergy_types::{
        AegisPqPublicKey, BlockId, ClusterId, Epoch, Height, Round, UmaId, ValidatorStatus,
        TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
    };

    #[derive(Clone, Copy)]
    struct TestVerifier;

    impl ConsensusSignatureVerifier for TestVerifier {
        fn verify_consensus_signature(
            &self,
            domain: &str,
            payload: &[u8],
            validator: &ValidatorRecord,
            key_id: &AegisPqKeyId,
            _epoch: Epoch,
            signature: &AegisPqSignature,
        ) -> Result<(), String> {
            let expected = Hash::from_domain_bytes(
                domain,
                &[
                    payload,
                    validator.validator_id.0.as_bytes(),
                    key_id.0.as_bytes(),
                ]
                .concat(),
            );
            if signature.signature_bytes == expected.0.to_vec() {
                Ok(())
            } else {
                Err("test delivery signature mismatch".to_string())
            }
        }
    }

    fn validators(validator_count: usize) -> ValidatorSet {
        ValidatorSet {
            epoch: Epoch(4),
            validators: (0..validator_count)
                .map(|index| {
                    let key = AegisPqPublicKey {
                        key_id: AegisPqKeyId(format!("delivery-key-{index}")),
                        algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                        key_bytes: vec![index as u8 + 1; TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES],
                    };
                    ValidatorRecord {
                        validator_id: ValidatorId(format!("delivery-validator-{index}")),
                        validator_uma_id: UmaId(format!("uma:delivery-validator-{index}")),
                        consensus_public_key: key.clone(),
                        peer_public_key: key.clone(),
                        operator_public_key: key,
                        voting_weight: 1,
                        status: ValidatorStatus::Active,
                        cluster_id: ClusterId(0),
                        activation_epoch: Epoch(4),
                    }
                })
                .collect(),
        }
    }

    fn epoch_context(validators: &ValidatorSet) -> SimplifiedEpochContext {
        SimplifiedEpochContext::derive(
            Epoch(4),
            Height(4_001),
            Height(5_000),
            Hash::from_domain_bytes("delivery-seed", b"epoch-4"),
            ConsensusParameterRoot::from_canonical_manifest_bytes(b"delivery-params"),
            validators,
        )
        .unwrap()
    }

    fn context(epoch_context: &SimplifiedEpochContext) -> ConsensusObjectContext {
        ConsensusObjectContext::for_height(epoch_context, Height(4_001), Round(0)).unwrap()
    }

    fn candidate(context: &ConsensusObjectContext, label: &str) -> CertifiedCandidateSubject {
        CertifiedCandidateSubject::new(
            context.clone(),
            BlockId(format!("delivery-block-{label}")),
            BlockId("delivery-anchor".to_string()),
            SimplifiedFinalityParent::quorum_certificate(QuorumCertificateReference {
                height: Height(4_000),
                block_id: BlockId("delivery-anchor".to_string()),
                qc_id: Hash::from_domain_bytes("delivery-anchor", b"qc"),
            })
            .unwrap(),
            Hash::from_domain_bytes("delivery-protected", label.as_bytes()),
        )
        .unwrap()
    }

    fn statement(
        context: &ConsensusObjectContext,
        candidate: &CertifiedCandidateSubject,
        validator: &ValidatorRecord,
        phase: ReliableDeliveryPhase,
    ) -> ReliableDeliveryStatement {
        let mut statement = ReliableDeliveryStatement {
            context: context.clone(),
            phase,
            candidate: candidate.clone(),
            validator_id: validator.validator_id.clone(),
            key_id: validator.consensus_public_key.key_id.clone(),
            signature: AegisPqSignature {
                algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
                signature_bytes: Vec::new(),
            },
        };
        statement.signature.signature_bytes = Hash::from_domain_bytes(
            phase.domain(),
            &[
                statement.signing_bytes().unwrap().as_slice(),
                validator.validator_id.0.as_bytes(),
                statement.key_id.0.as_bytes(),
            ]
            .concat(),
        )
        .0
        .to_vec();
        statement
    }

    fn next_commitment(context: &ConsensusObjectContext) -> NextProtectedBatchCommitment {
        NextProtectedBatchCommitment {
            commitment_version: PROTECTED_PIPELINE_VERSION,
            chain_id: context.chain_id,
            network_id: context.network_id.clone(),
            protocol_version: context.protocol_version.clone(),
            epoch: context.epoch,
            target_height: context.height,
            cluster_id: ClusterId(0),
            target_context_root: Hash::from_domain_bytes("vc-test", b"target-context"),
            validator_set_commitment: context.active_validator_set_root,
            parameter_root: ConsensusParameterRoot::from_hex(&context.consensus_parameter_root)
                .unwrap(),
            cut_root: EtdagDigest::from_domain_bytes("vc-test", b"cut"),
            eligible_set_root: EtdagDigest::from_domain_bytes("vc-test", b"eligible"),
            order_seed: EtdagDigest::from_domain_bytes("vc-test", b"seed"),
            order_root: EtdagDigest::from_domain_bytes("vc-test", b"order"),
            protected_batch_root: EtdagDigest::from_domain_bytes("vc-test", b"batch"),
            protected_count: 1,
            protected_gas: 10,
            protected_bytes: 20,
        }
    }

    fn proposal_vc(
        context: &ConsensusObjectContext,
        candidate: &CertifiedCandidateSubject,
        validators: &ValidatorSet,
    ) -> PosyProposalValidationCertificate {
        PosyProposalValidationCertificate {
            format: POSY_SIMPLIFIED_PROPOSAL_VC_FORMAT.to_string(),
            context: context.clone(),
            candidate: candidate.clone(),
            next_protected_batch_commitment_root: next_commitment(context).root().unwrap(),
            echoes: validators
                .validators
                .iter()
                .take(4)
                .map(|validator| {
                    statement(context, candidate, validator, ReliableDeliveryPhase::Echo)
                })
                .collect(),
        }
    }

    #[test]
    fn five_validator_thresholds_derive_from_the_frozen_epoch() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let state = ReliableDeliveryState::new(context, &epoch_context).unwrap();

        assert_eq!(
            state.thresholds().unwrap(),
            ReliableDeliveryThresholds {
                echo: 4,
                ready_relay: 2,
                delivery: 3,
                max_candidates: 5,
            }
        );
    }

    #[test]
    fn seven_validator_thresholds_derive_from_the_frozen_epoch() {
        let validators = validators(7);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let state = ReliableDeliveryState::new(context, &epoch_context).unwrap();

        assert_eq!(
            state.thresholds().unwrap(),
            ReliableDeliveryThresholds {
                echo: 6,
                ready_relay: 2,
                delivery: 3,
                max_candidates: 7,
            }
        );
    }

    #[test]
    fn five_validator_four_echo_then_three_ready_delivers_one_candidate() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        assert_eq!(
            epoch_context.protocol_version,
            POSY_SIMPLIFIED_PROTOCOL_VERSION
        );
        let context = context(&epoch_context);
        let candidate = candidate(&context, "a");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state.observe_candidate(candidate.clone()).unwrap();
        for validator in validators.validators.iter().take(4) {
            let decision = state
                .accept_statement(
                    statement(&context, &candidate, validator, ReliableDeliveryPhase::Echo),
                    &epoch_context,
                    &validators,
                    &TestVerifier,
                )
                .unwrap();
            if validator == &validators.validators[3] {
                assert_eq!(decision.ready_candidate, Some(candidate.clone()));
            }
        }
        for validator in validators.validators.iter().take(3) {
            let decision = state
                .accept_statement(
                    statement(
                        &context,
                        &candidate,
                        validator,
                        ReliableDeliveryPhase::Ready,
                    ),
                    &epoch_context,
                    &validators,
                    &TestVerifier,
                )
                .unwrap();
            if validator == &validators.validators[2] {
                assert_eq!(decision.delivered_candidate, Some(candidate.clone()));
            }
        }
        state.validate(&epoch_context).unwrap();
    }

    #[test]
    fn n_minus_one_echo_proof_is_the_exact_proposal_vc() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "vc");
        let certificate = proposal_vc(&context, &candidate, &validators);

        certificate
            .validate_authenticated_binding(
                &next_commitment(&context),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        assert_eq!(
            certificate.semantic_candidate_id().unwrap(),
            candidate.id().unwrap()
        );
        assert!(!certificate.proof_root().unwrap().is_zero());
    }

    #[test]
    fn proposal_vc_rejects_wrong_view_proposal_or_commitment() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate_subject = candidate(&context, "vc-bound");
        let certificate = proposal_vc(&context, &candidate_subject, &validators);

        let mut wrong_view = certificate.clone();
        wrong_view.context.round = Round(1);
        assert!(wrong_view
            .validate_authenticated_binding(
                &next_commitment(&context),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err()
            .contains("view"));

        let mut wrong_proposal = certificate.clone();
        wrong_proposal.candidate = candidate(&context, "another-proposal");
        assert!(wrong_proposal
            .validate_authenticated_binding(
                &next_commitment(&context),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .is_err());

        let mut wrong_commitment = next_commitment(&context);
        wrong_commitment.protected_batch_root =
            EtdagDigest::from_domain_bytes("vc-test", b"wrong-batch");
        assert!(certificate
            .validate_authenticated_binding(
                &wrong_commitment,
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err()
            .contains("commitment"));
    }

    #[test]
    fn ready_only_proof_never_becomes_a_proposal_vc() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "ready-only");
        let mut certificate = proposal_vc(&context, &candidate, &validators);
        certificate.echoes = validators
            .validators
            .iter()
            .take(4)
            .map(|validator| {
                statement(
                    &context,
                    &candidate,
                    validator,
                    ReliableDeliveryPhase::Ready,
                )
            })
            .collect();

        assert!(certificate
            .validate_authenticated_binding(
                &next_commitment(&context),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err()
            .contains("non-ECHO"));
    }

    #[test]
    fn seven_validator_sixth_echo_enables_ready() {
        let validators = validators(7);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "seven-echo");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();

        let decision_before_threshold = validators
            .validators
            .iter()
            .take(5)
            .map(|validator| {
                state
                    .accept_statement(
                        statement(&context, &candidate, validator, ReliableDeliveryPhase::Echo),
                        &epoch_context,
                        &validators,
                        &TestVerifier,
                    )
                    .unwrap()
            })
            .last()
            .unwrap();
        assert!(decision_before_threshold.ready_candidate.is_none());

        let decision_at_threshold = state
            .accept_statement(
                statement(
                    &context,
                    &candidate,
                    &validators.validators[5],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        assert_eq!(decision_at_threshold.ready_candidate, Some(candidate));
    }

    #[test]
    fn seven_validator_third_ready_delivers_one_candidate() {
        let validators = validators(7);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "seven-ready");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();

        let decision_before_threshold = validators
            .validators
            .iter()
            .take(2)
            .map(|validator| {
                state
                    .accept_statement(
                        statement(
                            &context,
                            &candidate,
                            validator,
                            ReliableDeliveryPhase::Ready,
                        ),
                        &epoch_context,
                        &validators,
                        &TestVerifier,
                    )
                    .unwrap()
            })
            .last()
            .unwrap();
        assert!(decision_before_threshold.delivered_candidate.is_none());

        let decision_at_threshold = state
            .accept_statement(
                statement(
                    &context,
                    &candidate,
                    &validators.validators[2],
                    ReliableDeliveryPhase::Ready,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        assert_eq!(decision_at_threshold.delivered_candidate, Some(candidate));
    }

    #[test]
    fn byzantine_split_two_two_cannot_deliver_either_candidate() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate_a = candidate(&context, "a");
        let candidate_b = candidate(&context, "b");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        for validator in validators.validators.iter().take(2) {
            state
                .accept_statement(
                    statement(
                        &context,
                        &candidate_a,
                        validator,
                        ReliableDeliveryPhase::Echo,
                    ),
                    &epoch_context,
                    &validators,
                    &TestVerifier,
                )
                .unwrap();
        }
        for validator in validators.validators.iter().skip(2).take(2) {
            state
                .accept_statement(
                    statement(
                        &context,
                        &candidate_b,
                        validator,
                        ReliableDeliveryPhase::Echo,
                    ),
                    &epoch_context,
                    &validators,
                    &TestVerifier,
                )
                .unwrap();
        }
        assert!(state.delivered_candidate.is_none());
        assert!(state.ready.values().all(|statements| statements.len() < 2));
    }

    #[test]
    fn one_validator_cannot_echo_two_candidates() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate_a = candidate(&context, "a");
        let candidate_b = candidate(&context, "b");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state
            .accept_statement(
                statement(
                    &context,
                    &candidate_a,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        let error = state
            .accept_statement(
                statement(
                    &context,
                    &candidate_b,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err();
        assert!(error.contains("equivocated"));
    }

    #[test]
    fn seven_validator_epoch_rejects_echo_equivocation() {
        let validators = validators(7);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate_a = candidate(&context, "seven-equivocation-a");
        let candidate_b = candidate(&context, "seven-equivocation-b");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state
            .accept_statement(
                statement(
                    &context,
                    &candidate_a,
                    &validators.validators[6],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();

        let error = state
            .accept_statement(
                statement(
                    &context,
                    &candidate_b,
                    &validators.validators[6],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err();

        assert!(error.contains("equivocated"));
    }

    #[test]
    fn seven_validator_epoch_retains_at_most_seven_candidates() {
        let validators = validators(7);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        for index in 0..7 {
            let retained = candidate(&context, &format!("retained-{index}"));
            state
                .insert_candidate(retained.id().unwrap(), retained)
                .unwrap();
        }
        let overflow = candidate(&context, "retained-overflow");

        let error = state
            .insert_candidate(overflow.id().unwrap(), overflow)
            .unwrap_err();

        assert!(error.contains("candidate pool is full"));
    }

    #[test]
    fn rejected_equivocation_does_not_consume_a_candidate_slot() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate_a = candidate(&context, "a");
        let candidate_b = candidate(&context, "b");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state
            .accept_statement(
                statement(
                    &context,
                    &candidate_a,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        let _error = state
            .accept_statement(
                statement(
                    &context,
                    &candidate_b,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err();
        assert_eq!(state.candidates.len(), 1);
    }

    #[test]
    fn candidate_must_match_the_complete_slot_context() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let mut mismatched_candidate = candidate(&context, "a");
        mismatched_candidate.context.consensus_parameter_root = "different-parameters".to_string();
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        let error = state
            .accept_statement(
                statement(
                    &context,
                    &mismatched_candidate,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap_err();
        assert!(error.contains("another height/context"));
    }

    #[test]
    fn persisted_validator_index_must_match_statement_evidence() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "a");
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state
            .accept_statement(
                statement(
                    &context,
                    &candidate,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        state.echo_by_validator.clear();
        let error = state.validate(&epoch_context).unwrap_err();
        assert!(error.contains("validator index"));
    }

    #[test]
    fn authenticated_validation_rejects_a_corrupted_persisted_signature() {
        let validators = validators(5);
        let epoch_context = epoch_context(&validators);
        let context = context(&epoch_context);
        let candidate = candidate(&context, "a");
        let candidate_id = candidate.id().unwrap();
        let validator_id = validators.validators[0].validator_id.clone();
        let mut state = ReliableDeliveryState::new(context.clone(), &epoch_context).unwrap();
        state
            .accept_statement(
                statement(
                    &context,
                    &candidate,
                    &validators.validators[0],
                    ReliableDeliveryPhase::Echo,
                ),
                &epoch_context,
                &validators,
                &TestVerifier,
            )
            .unwrap();
        state
            .echoes
            .get_mut(&candidate_id.to_hex())
            .unwrap()
            .get_mut(&validator_id)
            .unwrap()
            .signature
            .signature_bytes = vec![0; 32];
        let error = state
            .validate_authenticated(&epoch_context, &validators, &TestVerifier)
            .unwrap_err();
        assert!(error.contains("signature mismatch"));
    }
}
