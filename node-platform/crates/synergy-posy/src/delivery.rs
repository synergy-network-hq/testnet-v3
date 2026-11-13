//! Authenticated consistent dissemination. This does not create votes or finality.
use crate::{
    AcceptedTimeoutSummary, CertifiedCandidateSubject, ConsensusObjectContext,
    ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError, PosyResult,
    SimplifiedEpochContext,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use synergy_storage::AtomicStore;

pub const PROPOSAL_ECHO_DOMAIN: &str = "PoSy/Consensus/v3/ProposalEcho";
pub const PROPOSAL_READY_DOMAIN: &str = "PoSy/Consensus/v3/ProposalReady";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ProposalDeliveryPhase {
    Echo,
    Ready,
}
impl ProposalDeliveryPhase {
    pub fn domain(self) -> &'static str {
        match self {
            Self::Echo => PROPOSAL_ECHO_DOMAIN,
            Self::Ready => PROPOSAL_READY_DOMAIN,
        }
    }
    pub fn slot_domain(self) -> &'static str {
        match self {
            Self::Echo => "proposal-echo",
            Self::Ready => "proposal-ready",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalDeliveryStatement {
    pub context: ConsensusObjectContext,
    pub phase: ProposalDeliveryPhase,
    pub candidate: CertifiedCandidateSubject,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}
impl ProposalDeliveryStatement {
    pub fn signing_bytes(&self) -> PosyResult<Vec<u8>> {
        serde_json::to_vec(&(
            &self.context,
            self.phase,
            self.candidate.id()?,
            &self.validator_id,
            &self.key_id,
        ))
        .map_err(|e| PosyError::invalid(format!("encode proposal delivery: {e}")))
    }
    pub fn verify(
        &self,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        self.context.validate_against(epoch)?;
        self.candidate.validate()?;
        let mut stable = self.context.clone();
        stable.round = 0;
        if self.candidate.context != stable
            || self.signature.is_empty()
            || self.signature.len() > 16 * 1024
        {
            return Err(PosyError::invalid(
                "delivery candidate context or signature bound mismatch",
            ));
        }
        let validator = registry.active_validator(&self.validator_id)?;
        if validator.consensus_key_id != self.key_id {
            return Err(PosyError::invalid("delivery key is not frozen"));
        }
        verifier.verify_consensus_signature(
            self.phase.domain(),
            &self.signing_bytes()?,
            validator,
            &self.key_id,
            self.context.epoch,
            &self.signature,
        )
    }
}
/// Proof bundle carried by the existing dissemination message. Its optional
/// VC is independently verified; it grants no authority to a stale statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalDeliveryEnvelope {
    pub statement: ProposalDeliveryStatement,
    pub validation_certificate: Option<ProposalValidationCertificate>,
}
impl ProposalDeliveryEnvelope {
    pub fn new(statement: ProposalDeliveryStatement) -> Self {
        Self {
            statement,
            validation_certificate: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalValidationCertificate {
    pub context: ConsensusObjectContext,
    pub candidate: CertifiedCandidateSubject,
    pub echoes: Vec<ProposalDeliveryStatement>,
}
impl ProposalValidationCertificate {
    pub fn id(&self) -> PosyResult<String> {
        self.candidate.id()
    }
    pub fn verify(
        &self,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        self.context.validate_against(epoch)?;
        if self.echoes.len() < registry.active_count() - 1
            || self.echoes.len() > registry.active_count()
        {
            return Err(PosyError::invalid("proposal VC requires n-1 ECHOs"));
        }
        let mut signers = BTreeSet::new();
        for statement in &self.echoes {
            if statement.phase != ProposalDeliveryPhase::Echo
                || statement.context != self.context
                || statement.candidate != self.candidate
                || !signers.insert(&statement.validator_id)
            {
                return Err(PosyError::invalid(
                    "proposal VC has mixed or duplicate ECHOs",
                ));
            }
            statement.verify(epoch, registry, verifier)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeliveryRecord {
    slot: Option<(u64, u64)>,
    statements: Vec<ProposalDeliveryStatement>,
    delivered: Option<String>,
}
/// One compact active-slot record. Authenticated evidence is persisted before use,
/// including exact local signature bytes so restart never re-signs dissemination.
pub struct ProposalDelivery {
    store: AtomicStore,
    evidence: crate::persistence::evidence_store::EvidenceStore,
    record: DeliveryRecord,
    verified_validations: RefCell<BTreeMap<(String, u64), (usize, ProposalValidationCertificate)>>,
    verified_validation_bytes: RefCell<usize>,
}
impl ProposalDelivery {
    /// The caller must authenticate the predecessor through the successor's
    /// finalized transition witness. Historical statements are still verified
    /// with their original authority, never reinterpreted as successor votes.
    pub fn open_after_verified_epoch_transition<V: ConsensusSignatureVerifier>(
        root: &Path,
        current: (&SimplifiedEpochContext, &FrozenValidatorRegistry, &V),
        previous: (&SimplifiedEpochContext, &FrozenValidatorRegistry, &V),
    ) -> PosyResult<Self> {
        if previous.0.epoch.checked_add(1) != Some(current.0.epoch)
            || previous.0.epoch_end_height.checked_add(1) != Some(current.0.epoch_start_height)
            || previous.0.chain_id != current.0.chain_id
            || previous.0.network_id != current.0.network_id
            || previous.0.protocol_version != current.0.protocol_version
        {
            return Err(PosyError::invalid(
                "delivery predecessor is not the sequential epoch",
            ));
        }
        match Self::open(root, current.0, current.1, current.2) {
            Ok(owner) => Ok(owner),
            Err(_) => Self::open(root, previous.0, previous.1, previous.2),
        }
    }

    pub fn open(
        root: &Path,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Self> {
        let store = AtomicStore::new(root, 4 * 1024 * 1024).map_err(storage_error)?;
        let record: DeliveryRecord = if store.exists("delivery.json").map_err(storage_error)? {
            serde_json::from_slice(&store.read_bounded("delivery.json").map_err(storage_error)?)
                .map_err(|e| PosyError::invalid(format!("decode delivery journal: {e}")))?
        } else {
            DeliveryRecord::default()
        };
        if record.statements.len() > registry.active_count() * 2 {
            return Err(PosyError::invalid("oversized delivery journal"));
        }
        let mut slots = BTreeSet::new();
        for statement in &record.statements {
            statement.verify(epoch, registry, verifier)?;
            if record.slot != Some((statement.context.height, statement.context.round))
                || !slots.insert((statement.phase, &statement.validator_id))
            {
                return Err(PosyError::invalid("corrupt delivery journal slot"));
            }
        }
        let owner = Self {
            evidence: crate::persistence::evidence_store::EvidenceStore::open(root)?,
            store,
            record,
            verified_validations: RefCell::new(BTreeMap::new()),
            verified_validation_bytes: RefCell::new(0),
        };
        if let Some(id) = &owner.record.delivered {
            if !owner.record.statements.iter().any(|s| {
                s.candidate.id().as_ref() == Ok(id)
                    && owner.count(&s.candidate, ProposalDeliveryPhase::Ready) >= 3
            }) {
                return Err(PosyError::invalid("delivered journal lacks READY proof"));
            }
        }
        Ok(owner)
    }
    fn persist(&mut self, next: DeliveryRecord) -> PosyResult<()> {
        let bytes = serde_json::to_vec(&next).map_err(|e| PosyError::invalid(e.to_string()))?;
        self.store
            .write_atomic("delivery.json", &bytes)
            .map_err(storage_error)?;
        self.record = next;
        Ok(())
    }
    pub fn activate(&mut self, slot: (u64, u64)) -> PosyResult<()> {
        if self.record.slot == Some(slot) {
            return Ok(());
        }
        if self.record.slot.is_some_and(|old| old > slot) {
            return Err(PosyError::invalid("delivery journal rollback"));
        }
        self.persist(DeliveryRecord {
            slot: Some(slot),
            ..DeliveryRecord::default()
        })
    }
    pub fn admit(
        &mut self,
        statement: ProposalDeliveryStatement,
        active: (u64, u64),
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<bool> {
        // Reject wrong slot before activating or changing durable state.
        if (statement.context.height, statement.context.round) != active {
            return Err(PosyError::invalid("delivery statement is not active"));
        }
        if self
            .record
            .statements
            .iter()
            .any(|existing| existing == &statement)
        {
            return Ok(false);
        }
        statement.verify(epoch, registry, verifier)?;
        if self.record.slot != Some(active) {
            return Err(PosyError::invalid("delivery owner is not active"));
        }
        if let Some(existing) = self.local_statement(&statement.validator_id, statement.phase) {
            if existing.candidate != statement.candidate {
                return Err(PosyError::Conflict("delivery signer equivocation".into()));
            }
            return Ok(false);
        }
        if self.record.statements.len() >= registry.active_count() * 2 {
            return Err(PosyError::invalid("delivery statement bound exceeded"));
        }
        let mut next = self.record.clone();
        next.statements.push(statement);
        self.persist(next)?;
        Ok(true)
    }
    pub fn local_statement(
        &self,
        id: &str,
        phase: ProposalDeliveryPhase,
    ) -> Option<&ProposalDeliveryStatement> {
        self.record
            .statements
            .iter()
            .find(|s| s.validator_id == id && s.phase == phase)
    }
    pub fn count(
        &self,
        candidate: &CertifiedCandidateSubject,
        phase: ProposalDeliveryPhase,
    ) -> usize {
        self.record
            .statements
            .iter()
            .filter(|s| s.phase == phase && &s.candidate == candidate)
            .count()
    }
    pub fn validation_certificate(
        &self,
        candidate: &CertifiedCandidateSubject,
        count: usize,
    ) -> Option<ProposalValidationCertificate> {
        let mut echoes: Vec<_> = self
            .record
            .statements
            .iter()
            .filter(|s| s.phase == ProposalDeliveryPhase::Echo && &s.candidate == candidate)
            .cloned()
            .collect();
        if echoes.len() < count - 1 {
            return None;
        }
        echoes.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        Some(ProposalValidationCertificate {
            context: echoes[0].context.clone(),
            candidate: candidate.clone(),
            echoes,
        })
    }
    pub fn deliver(&mut self, candidate: &CertifiedCandidateSubject) -> PosyResult<bool> {
        if self.count(candidate, ProposalDeliveryPhase::Ready) < 3 {
            return Ok(false);
        }
        let id = candidate.id()?;
        if let Some(existing) = &self.record.delivered {
            if existing != &id {
                return Err(PosyError::Conflict("conflicting stable delivery".into()));
            }
            return Ok(true);
        }
        let mut next = self.record.clone();
        next.delivered = Some(id);
        self.persist(next)?;
        Ok(true)
    }
    pub fn persist_ready_envelope(
        &self,
        envelope: &ProposalDeliveryEnvelope,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        envelope.statement.verify(epoch, registry, verifier)?;
        if envelope.statement.phase != ProposalDeliveryPhase::Ready {
            return Err(PosyError::invalid("READY replay journal received ECHO"));
        }
        if let Some(vc) = &envelope.validation_certificate {
            vc.verify(epoch, registry, verifier)?;
            if vc.candidate != envelope.statement.candidate
                || vc.context.height != envelope.statement.context.height
            {
                return Err(PosyError::invalid("READY proof differs from candidate"));
            }
        }
        let name = format!("ready-h{}.json", envelope.statement.context.height);
        let prior = self.evidence.get(&name)?;
        if let Some(existing) = self.stored_ready_envelope(
            envelope.statement.context.height,
            epoch,
            registry,
            verifier,
        )? {
            if existing.statement.context.round > envelope.statement.context.round {
                return Err(PosyError::invalid("READY replay rollback"));
            }
            if existing == *envelope {
                return Ok(());
            }
        }
        self.evidence.replace_guarded(
            name,
            prior.as_deref(),
            &serde_json::to_vec(envelope).map_err(|e| PosyError::invalid(e.to_string()))?,
        )
    }

    /// Retire only new-format READY locators outside the existing recent
    /// startup replay window. This does not prune VCs, signatures, QCs or any
    /// legacy originals; the caller must already have verified finality.
    pub fn retire_finalized_evidence(&self, height: u64) -> PosyResult<()> {
        self.evidence.retire_ready(height)
    }

    pub fn stored_ready_envelope(
        &self,
        height: u64,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<ProposalDeliveryEnvelope>> {
        let name = format!("ready-h{height}.json");
        let Some(bytes) = self.evidence.get(name)? else {
            return Ok(None);
        };
        let envelope: ProposalDeliveryEnvelope =
            serde_json::from_slice(&bytes).map_err(|e| PosyError::invalid(e.to_string()))?;
        envelope.statement.verify(epoch, registry, verifier)?;
        if envelope.statement.context.height != height
            || envelope.statement.phase != ProposalDeliveryPhase::Ready
        {
            return Err(PosyError::invalid("stored READY mismatch"));
        }
        if let Some(vc) = &envelope.validation_certificate {
            vc.verify(epoch, registry, verifier)?;
            if vc.candidate != envelope.statement.candidate {
                return Err(PosyError::invalid("stored READY VC mismatch"));
            }
        }
        Ok(Some(envelope))
    }

    pub fn stored_validation(
        &self,
        height: u64,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<ProposalValidationCertificate>> {
        epoch.validate_against(registry)?;
        if let Some((_, certificate)) = self
            .verified_validations
            .borrow()
            .get(&(epoch.root()?, height))
        {
            return Ok(Some(certificate.clone()));
        }
        let name = format!("validation-h{height}.json");
        let Some(bytes) = self.evidence.get(name)? else {
            return Ok(None);
        };
        let certificate: ProposalValidationCertificate = serde_json::from_slice(&bytes)
            .map_err(|e| PosyError::invalid(format!("decode stored VC: {e}")))?;
        certificate.verify(epoch, registry, verifier)?;
        if certificate.context.height != height {
            return Err(PosyError::invalid("stored VC height mismatch"));
        }
        self.cache_validation(certificate.clone(), epoch.root()?)?;
        Ok(Some(certificate))
    }

    pub fn persist_validation(
        &self,
        certificate: &ProposalValidationCertificate,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<ProposalValidationCertificate> {
        epoch.validate_against(registry)?;
        if self
            .verified_validations
            .borrow()
            .get(&(epoch.root()?, certificate.context.height))
            .map(|(_, certificate)| certificate)
            == Some(certificate)
        {
            return Ok(certificate.clone());
        }
        certificate.verify(epoch, registry, verifier)?;
        if let Some(existing) =
            self.stored_validation(certificate.context.height, epoch, registry, verifier)?
        {
            if existing.id()? != certificate.id()? {
                return Err(PosyError::Conflict(
                    "conflicting durable proposal VC".into(),
                ));
            }
            return Ok(existing);
        }
        let bytes =
            serde_json::to_vec(certificate).map_err(|e| PosyError::invalid(e.to_string()))?;
        self.evidence
            .put_once_atomic(&[synergy_storage::StorageWrite {
                relative_path: format!("validation-h{}.json", certificate.context.height).into(),
                bytes,
            }])?;
        self.cache_validation(certificate.clone(), epoch.root()?)?;
        Ok(certificate.clone())
    }

    /// Processing candidates may differ after a native takeover. The ordinary
    /// height journal remains bounded to one active VC; replacing it requires
    /// authority already admitted by the sole PoSy state machine. Legacy
    /// callers retain the original immutable-height behavior above.
    pub fn persist_processing_validation(
        &self,
        certificate: &ProposalValidationCertificate,
        takeover: Option<&AcceptedTimeoutSummary>,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<ProposalValidationCertificate> {
        certificate.verify(epoch, registry, verifier)?;
        let Some(previous) =
            self.stored_validation(certificate.context.height, epoch, registry, verifier)?
        else {
            return self.persist_validation(certificate, epoch, registry, verifier);
        };
        if previous.id()? == certificate.id()? {
            return Ok(previous);
        }
        verify_processing_validation_replacement(&previous, certificate, takeover)?;
        let bytes =
            serde_json::to_vec(certificate).map_err(|e| PosyError::invalid(e.to_string()))?;
        // An independently opened stale owner cannot replace a newer journal.
        let name = format!("validation-h{}.json", certificate.context.height);
        let prior_bytes = self
            .evidence
            .get(&name)?
            .ok_or_else(|| PosyError::Conflict("processing VC locator disappeared".into()))?;
        let prior: ProposalValidationCertificate =
            serde_json::from_slice(&prior_bytes).map_err(|e| PosyError::invalid(e.to_string()))?;
        if prior != previous {
            return Err(PosyError::Conflict("stale processing VC cache".into()));
        }
        self.evidence
            .replace_guarded(name, Some(&prior_bytes), &bytes)?;
        self.cache_validation(certificate.clone(), epoch.root()?)?;
        Ok(certificate.clone())
    }

    /// A height alone is insufficient to resolve speculative processing proof.
    pub fn stored_validation_for(
        &self,
        candidate: &CertifiedCandidateSubject,
        epoch: &SimplifiedEpochContext,
        registry: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Option<ProposalValidationCertificate>> {
        Ok(self
            .stored_validation(candidate.context.height, epoch, registry, verifier)?
            .filter(|certificate| &certificate.candidate == candidate))
    }

    fn cache_validation(
        &self,
        certificate: ProposalValidationCertificate,
        epoch_root: String,
    ) -> PosyResult<()> {
        const MAX_CACHE_BYTES: usize = 8 * 1024 * 1024;
        let charge = serde_json::to_vec(&certificate)
            .map_err(|e| PosyError::invalid(e.to_string()))?
            .len();
        let key = (epoch_root, certificate.context.height);
        let mut cache = self.verified_validations.borrow_mut();
        let mut bytes = self.verified_validation_bytes.borrow_mut();
        if let Some((old, _)) = cache.remove(&key) {
            *bytes = bytes.saturating_sub(old);
        }
        // Large valid evidence remains available through indexed reads; cache
        // capacity never changes protocol validity or discards durable proof.
        if charge > MAX_CACHE_BYTES {
            return Ok(());
        }
        *bytes += charge;
        cache.insert(key, (charge, certificate));
        while cache.len() > 64 || *bytes > MAX_CACHE_BYTES {
            if let Some((_, (charge, _))) = cache.pop_first() {
                *bytes = bytes.saturating_sub(charge);
            }
        }
        Ok(())
    }

    pub fn candidate_for_id(&self, id: &str) -> Option<CertifiedCandidateSubject> {
        self.record
            .statements
            .iter()
            .find(|s| s.candidate.id().as_deref() == Ok(id))
            .map(|s| s.candidate.clone())
    }

    pub fn local_statements(&self, id: &str) -> Vec<ProposalDeliveryStatement> {
        self.record
            .statements
            .iter()
            .filter(|s| s.validator_id == id)
            .cloned()
            .collect()
    }
}

/// The sealed summary is produced only by native TC admission. This predicate
/// changes neither quorum nor carry rules and grants no proposal/vote authority.
pub fn verify_processing_validation_replacement(
    previous: &ProposalValidationCertificate,
    next: &ProposalValidationCertificate,
    takeover: Option<&AcceptedTimeoutSummary>,
) -> PosyResult<()> {
    let Some(takeover) = takeover else {
        return Err(PosyError::Conflict(
            "processing VC replacement lacks admitted takeover".into(),
        ));
    };
    let context = takeover.context();
    let mut previous_scope = previous.context.clone();
    previous_scope.round = next.context.round;
    let mut timeout_scope = context.clone();
    timeout_scope.round = next.context.round;
    if previous_scope != next.context
        || timeout_scope != next.context
        || previous.context.height != next.context.height
        || context.height != next.context.height
        || previous.context.round > context.round
        || context.round.checked_add(1) != Some(next.context.round)
        || takeover.highest_parent() != &next.candidate.parent
        || takeover
            .mandatory_carry_candidate()
            .is_some_and(|carry| carry != &next.candidate)
    {
        return Err(PosyError::Conflict(
            "processing VC replacement violates takeover slot/parent/carry".into(),
        ));
    }
    Ok(())
}
fn storage_error(error: synergy_storage::StorageError) -> PosyError {
    PosyError::NotReady(format!("delivery durability: {error}"))
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    struct Accept;
    impl ConsensusSignatureVerifier for Accept {
        fn verify_consensus_signature(
            &self,
            _: &str,
            _: &[u8],
            _: &crate::ValidatorRecord,
            _: &str,
            _: u64,
            _: &[u8],
        ) -> PosyResult<()> {
            Ok(())
        }
    }
    #[test]
    fn successor_reopens_verified_previous_delivery_without_reinterpreting_or_clearing_it() {
        struct Check;
        impl ConsensusSignatureVerifier for Check {
            fn verify_consensus_signature(
                &self,
                _: &str,
                _: &[u8],
                _: &crate::ValidatorRecord,
                _: &str,
                _: u64,
                signature: &[u8],
            ) -> PosyResult<()> {
                if signature == [7] {
                    Ok(())
                } else {
                    Err(PosyError::invalid("bad test signature"))
                }
            }
        }
        let root =
            std::env::temp_dir().join(format!("posy-delivery-successor-{}", std::process::id()));
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        let registry = |epoch| {
            FrozenValidatorRegistry::new(
                epoch,
                (0..5)
                    .map(|i| crate::ValidatorRecord {
                        validator_id: format!("v{i}"),
                        consensus_key_id: format!("k{i}"),
                        frozen_voting_weight: 1,
                        status: crate::ValidatorStatus::Active,
                    })
                    .collect(),
            )
            .unwrap()
        };
        let previous_registry = registry(1);
        let current_registry = registry(2);
        let epoch = |number, start, end, registry: &FrozenValidatorRegistry| {
            SimplifiedEpochContext::from_frozen_registry(
                99999,
                "delivery-transition".into(),
                number,
                start,
                end,
                "a".repeat(64),
                "b".repeat(64),
                registry,
            )
            .unwrap()
        };
        let previous = epoch(1, 1, 10000, &previous_registry);
        let current = epoch(2, 10001, 20000, &current_registry);
        let context = ConsensusObjectContext::for_height(&previous, 10000, 0).unwrap();
        let candidate = CertifiedCandidateSubject::new(
            context.clone(),
            "old-block".into(),
            "parent".into(),
            crate::SimplifiedFinalityParent::QuorumCertificate {
                height: 9999,
                block_id: "parent".into(),
                qc_id: "c".repeat(64),
            },
            "d".repeat(64),
        )
        .unwrap();
        let mut owner =
            ProposalDelivery::open(&root, &previous, &previous_registry, &Check).unwrap();
        owner.activate((10000, 0)).unwrap();
        owner
            .admit(
                ProposalDeliveryStatement {
                    context,
                    phase: ProposalDeliveryPhase::Echo,
                    candidate,
                    validator_id: "v0".into(),
                    key_id: "k0".into(),
                    signature: vec![7],
                },
                (10000, 0),
                &previous,
                &previous_registry,
                &Check,
            )
            .unwrap();
        drop(owner);
        let before = std::fs::read(root.join("delivery.json")).unwrap();
        assert!(ProposalDelivery::open(&root, &current, &current_registry, &Check).is_err());
        let mut owner = ProposalDelivery::open_after_verified_epoch_transition(
            &root,
            (&current, &current_registry, &Check),
            (&previous, &previous_registry, &Check),
        )
        .unwrap();
        assert_eq!(std::fs::read(root.join("delivery.json")).unwrap(), before);
        assert_eq!(owner.record.statements[0].context.epoch, 1);
        assert!(owner.activate((9999, 0)).is_err());
        owner.activate((10001, 0)).unwrap();
        drop(owner);
        assert!(ProposalDelivery::open(&root, &current, &current_registry, &Check).is_ok());
        let mut corrupt: serde_json::Value = serde_json::from_slice(&before).unwrap();
        corrupt["statements"][0]["signature"] = serde_json::json!([8]);
        let corrupt = serde_json::to_vec(&corrupt).unwrap();
        AtomicStore::new(&root, 4 * 1024 * 1024)
            .unwrap()
            .write_atomic("delivery.json", &corrupt)
            .unwrap();
        assert!(ProposalDelivery::open_after_verified_epoch_transition(
            &root,
            (&current, &current_registry, &Check),
            (&previous, &previous_registry, &Check)
        )
        .is_err());
        assert_eq!(std::fs::read(root.join("delivery.json")).unwrap(), corrupt);
        let mut wrong = current.clone();
        wrong.network_id = "other".into();
        assert!(ProposalDelivery::open_after_verified_epoch_transition(
            &root,
            (&wrong, &current_registry, &Check),
            (&previous, &previous_registry, &Check)
        )
        .is_err());
    }
    #[test]
    fn large_verified_validation_cache_evicts_by_bytes_and_reloads_exact_history() {
        let root = std::env::temp_dir().join(format!("posy-vc-byte-cache-{}", std::process::id()));
        let registry = FrozenValidatorRegistry::new(
            1,
            (0..5)
                .map(|i| crate::ValidatorRecord {
                    validator_id: format!("v{i}"),
                    consensus_key_id: format!("k{i}"),
                    frozen_voting_weight: 1,
                    status: crate::ValidatorStatus::Active,
                })
                .collect(),
        )
        .unwrap();
        let epoch = SimplifiedEpochContext::from_frozen_registry(
            1266,
            "cache-fixture".into(),
            1,
            1,
            1000,
            "a".repeat(64),
            "b".repeat(64),
            &registry,
        )
        .unwrap();
        let owner = ProposalDelivery::open(&root, &epoch, &registry, &Accept).unwrap();
        let mut first = None;
        for height in 1..=80 {
            let context = ConsensusObjectContext::for_height(&epoch, height, 0).unwrap();
            let parent = if height == 1 {
                crate::SimplifiedFinalityParent::Genesis {
                    genesis_hash: "c".repeat(64),
                    block_id: "genesis".into(),
                    reference_id: "d".repeat(64),
                }
            } else {
                crate::SimplifiedFinalityParent::QuorumCertificate {
                    height: height - 1,
                    block_id: "genesis".into(),
                    qc_id: "d".repeat(64),
                }
            };
            let candidate = CertifiedCandidateSubject::new(
                context.clone(),
                format!("candidate-{height}"),
                "genesis".into(),
                parent,
                "e".repeat(64),
            )
            .unwrap();
            let certificate = ProposalValidationCertificate {
                context: context.clone(),
                candidate: candidate.clone(),
                echoes: (0..4)
                    .map(|i| ProposalDeliveryStatement {
                        context: context.clone(),
                        phase: ProposalDeliveryPhase::Echo,
                        candidate: candidate.clone(),
                        validator_id: format!("v{i}"),
                        key_id: format!("k{i}"),
                        signature: vec![255; 16384],
                    })
                    .collect(),
            };
            if height == 1 {
                first = Some(certificate.clone());
            }
            owner
                .persist_validation(&certificate, &epoch, &registry, &Accept)
                .unwrap();
            assert!(*owner.verified_validation_bytes.borrow() <= 8 * 1024 * 1024);
            assert!(owner.verified_validations.borrow().len() <= 64);
        }
        assert!(
            owner.verified_validations.borrow().len() < 64,
            "byte cap must bind before entry cap"
        );
        assert!(!owner
            .verified_validations
            .borrow()
            .contains_key(&(epoch.root().unwrap(), 1)));
        assert_eq!(
            owner
                .stored_validation(1, &epoch, &registry, &Accept)
                .unwrap(),
            first
        );
        let mut foreign = epoch.clone();
        foreign.network_id = "other-network".into();
        assert!(
            owner
                .stored_validation(1, &foreign, &registry, &Accept)
                .is_err(),
            "cache must not cross authority domains"
        );
        drop(owner);
        let owner = ProposalDelivery::open(&root, &epoch, &registry, &Accept).unwrap();
        assert_eq!(
            owner
                .stored_validation(1, &epoch, &registry, &Accept)
                .unwrap(),
            first
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
