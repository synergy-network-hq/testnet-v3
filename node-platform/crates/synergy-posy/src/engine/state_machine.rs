use std::collections::BTreeMap;

use crate::{
    merge_compatible_quorum_certificates, timeout_vote_signing_bytes, validate_block_vote,
    validate_proposal, validate_timeout_vote, BlockVote, CertifiedCandidateSubject,
    ConsensusObjectContext, ConsensusSignatureVerifier, ConsensusTransition,
    FrozenValidatorRegistry, PosyError, PosyResult, QuorumCertificateReference,
    SimplifiedEpochContext, SimplifiedFinalityParent, SimplifiedProposal,
    SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate, ThreeQcFinality, TimeoutVote,
    TimeoutVoteCollection, VoteCollection,
};

/// Authenticated projection of an admitted native TC. Fields are private and no
/// deserializer/constructor is exported: this is evidence already verified by
/// the sole PoSy owner, never a substitute wire certificate. Originals remain in
/// immutable storage and are loaded individually when retransmission needs them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AcceptedTimeoutSummary {
    id: String,
    context: ConsensusObjectContext,
    lease_index: u64,
    previous_tc_id: Option<String>,
    highest_parent: SimplifiedFinalityParent,
    mandatory_carry: Option<CertifiedCandidateSubject>,
    report_subjects: BTreeMap<String, [u8; 32]>,
}

impl AcceptedTimeoutSummary {
    fn from_verified(certificate: &SimplifiedTimeoutCertificate) -> PosyResult<Self> {
        Ok(Self {
            id: certificate.id()?,
            context: certificate.context.clone(),
            lease_index: certificate.lease_index,
            previous_tc_id: certificate.previous_tc_id.clone(),
            highest_parent: certificate.highest_parent()?,
            mandatory_carry: certificate.mandatory_carry_candidate()?,
            report_subjects: certificate
                .reports
                .iter()
                .map(|report| {
                    Ok((
                        report.validator_id.clone(),
                        *blake3::hash(&timeout_vote_signing_bytes(report)?).as_bytes(),
                    ))
                })
                .collect::<PosyResult<_>>()?,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn context(&self) -> &ConsensusObjectContext {
        &self.context
    }
    pub fn lease_index(&self) -> u64 {
        self.lease_index
    }
    pub fn previous_tc_id(&self) -> Option<&str> {
        self.previous_tc_id.as_deref()
    }
    pub fn highest_parent(&self) -> &SimplifiedFinalityParent {
        &self.highest_parent
    }
    pub fn mandatory_carry_candidate(&self) -> Option<&CertifiedCandidateSubject> {
        self.mandatory_carry.as_ref()
    }
    /// Compare a separately authenticated original with this admitted semantic
    /// authority. This does not verify a wire certificate or admit new evidence.
    pub fn matches_certificate(
        &self,
        certificate: &SimplifiedTimeoutCertificate,
    ) -> PosyResult<bool> {
        if self.id != certificate.id()?
            || self.context != certificate.context
            || self.lease_index != certificate.lease_index
            || self.previous_tc_id != certificate.previous_tc_id
            || self.highest_parent != certificate.highest_parent()?
            || self.mandatory_carry != certificate.mandatory_carry_candidate()?
        {
            return Ok(false);
        }
        for report in &certificate.reports {
            if let Some(accepted) = self.report_subjects.get(&report.validator_id) {
                if *accepted != *blake3::hash(&timeout_vote_signing_bytes(report)?).as_bytes() {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

const MAX_ACCEPTED_TIMEOUT_SUMMARIES: usize = 4096;
const MAX_ACCEPTED_TIMEOUT_SUMMARY_BYTES: usize = 64 * 1024 * 1024;

/// The single PoSy control plane. It owns proposal admission, vote and
/// timeout collection, QC/TC admission, pipelined height progression, and
/// three-QC finality. Networking, ETDAG, execution, and persistence remain
/// adapters around this state machine rather than independent coordinators.
#[derive(Debug)]
pub struct SimplifiedConsensusStateMachine {
    epoch: SimplifiedEpochContext,
    validators: FrozenValidatorRegistry,
    votes: VoteCollection,
    timeout_votes: TimeoutVoteCollection,
    finality: ThreeQcFinality,
    highest_parent: SimplifiedFinalityParent,
    locked_qc: Option<QuorumCertificateReference>,
    certified_qcs: BTreeMap<u64, SimplifiedQuorumCertificate>,
    accepted_tcs: BTreeMap<String, AcceptedTimeoutSummary>,
    accepted_tc_bytes: usize,
    accepted_proposal: Option<SimplifiedProposal>,
    active_height: u64,
    active_round: u64,
    active_takeover_tc_id: Option<String>,
    mandatory_carry: Option<CertifiedCandidateSubject>,
    epoch_complete: bool,
}

impl SimplifiedConsensusStateMachine {
    pub fn new(
        epoch: SimplifiedEpochContext,
        validators: FrozenValidatorRegistry,
        anchor_parent: SimplifiedFinalityParent,
    ) -> PosyResult<Self> {
        epoch.validate_against(&validators)?;
        anchor_parent.validate_for_child_height(epoch.epoch_start_height)?;
        Ok(Self {
            active_height: epoch.epoch_start_height,
            active_round: 0,
            epoch,
            validators,
            votes: VoteCollection::default(),
            timeout_votes: TimeoutVoteCollection::default(),
            finality: ThreeQcFinality::default(),
            highest_parent: anchor_parent,
            locked_qc: None,
            certified_qcs: BTreeMap::new(),
            accepted_tcs: BTreeMap::new(),
            accepted_tc_bytes: 0,
            accepted_proposal: None,
            active_takeover_tc_id: None,
            mandatory_carry: None,
            epoch_complete: false,
        })
    }

    pub fn seed_epoch_transition_finality(
        &mut self,
        finalized: crate::FinalizedBlockRecord,
        certificates: [SimplifiedQuorumCertificate; 3],
    ) -> PosyResult<()> {
        let boundary = certificates
            .last()
            .ok_or_else(|| PosyError::invalid("epoch transition QC tail is empty"))?;
        let boundary_reference = boundary.reference()?;
        if self.epoch.epoch <= 1
            || boundary.context.height.checked_add(1) != Some(self.epoch.epoch_start_height)
            || self.highest_parent.quorum_certificate_reference().as_ref()
                != Some(&boundary_reference)
        {
            return Err(PosyError::invalid(
                "epoch transition finality prefix differs from successor anchor",
            ));
        }
        let [oldest, middle, newest] = certificates;
        if oldest.context.height != finalized.height
            || oldest.block_id != finalized.block_id
            || oldest.protected_execution_root != finalized.protected_execution_root
            || newest.id()? != finalized.finality_certificate_id
        {
            return Err(PosyError::invalid(
                "epoch transition QC witness differs from finalized record",
            ));
        }
        self.finality
            .seed_verified_prefix(finalized, [middle.clone(), newest.clone()])?;
        self.certified_qcs.insert(oldest.context.height, oldest);
        self.certified_qcs.insert(middle.context.height, middle);
        self.certified_qcs.insert(newest.context.height, newest);
        Ok(())
    }

    /// Reconstructs an already committed same-epoch prefix at a governed lease
    /// boundary. The caller must match `finalized` to its durable commit and
    /// safety floor. No signed evidence, timeout journal or committed record is
    /// replaced; only the bounded live projection is initialized.
    pub fn seed_committed_lease_boundary(
        &mut self,
        finalized: crate::FinalizedBlockRecord,
        witness: crate::FinalitySyncWitness,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        if self.active_slot() != (self.epoch.epoch_start_height, 0)
            || !self.certified_qcs.is_empty()
            || !self.accepted_tcs.is_empty()
            || self.last_finalized().is_some()
            || self.locked_qc.is_some()
            || self.accepted_proposal.is_some()
            || self.epoch_complete
        {
            return Err(PosyError::Conflict(
                "committed lease boundary requires an uninitialized projection".into(),
            ));
        }
        let boundary = witness.quorum_certificates[2]
            .context
            .height
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("committed lease boundary overflows"))?;
        if !self.epoch.contains_height(boundary)
            || boundary <= self.epoch.epoch_start_height
            || !(boundary - self.epoch.epoch_start_height)
                .is_multiple_of(self.epoch.leader_lease_blocks)
        {
            return Err(PosyError::invalid(
                "committed prefix does not end at a governed lease boundary",
            ));
        }
        for qc in &witness.quorum_certificates {
            qc.verify(&self.epoch, &self.validators, verifier)?;
        }
        witness.verified_timeout_closure(&self.epoch, &self.validators, verifier)?;
        let mut verified = ThreeQcFinality::default();
        for qc in &witness.quorum_certificates {
            verified.accept(qc.clone())?;
        }
        if verified.last_finalized() != Some(&finalized) {
            return Err(PosyError::Conflict(
                "committed lease anchor differs from its verified three-QC finality".into(),
            ));
        }
        let newest = &witness.quorum_certificates[2];
        let locked = newest
            .parent
            .quorum_certificate_reference()
            .ok_or_else(|| {
                PosyError::invalid("committed lease anchor lacks its certified lock parent")
            })?;
        let highest = SimplifiedFinalityParent::QuorumCertificate {
            height: newest.context.height,
            block_id: newest.block_id.clone(),
            qc_id: newest.id()?,
        };
        // Normal QC advancement clears lease control at this exact boundary.
        // Its lock is the newest QC's parent, not the newest QC itself.
        self.finality = verified;
        self.highest_parent = highest;
        self.locked_qc = Some(locked);
        self.active_height = boundary;
        for qc in witness.quorum_certificates {
            self.certified_qcs.insert(qc.context.height, qc);
        }
        Ok(())
    }

    pub fn epoch(&self) -> &SimplifiedEpochContext {
        &self.epoch
    }

    pub fn active_slot(&self) -> (u64, u64) {
        (self.active_height, self.active_round)
    }

    pub fn highest_parent(&self) -> &SimplifiedFinalityParent {
        &self.highest_parent
    }

    /// Carry still required at the active height. A lease-wide takeover may
    /// remain active after its original-height carry has been certified.
    pub fn active_mandatory_carry(&self) -> Option<&CertifiedCandidateSubject> {
        self.mandatory_carry.as_ref()
    }

    pub fn locked_qc(&self) -> Option<&QuorumCertificateReference> {
        self.locked_qc.as_ref()
    }

    /// Evidence actually admitted by this state machine, excluding records
    /// superseded during verified recovery projection.
    pub fn accepted_timeout_certificates(&self) -> impl Iterator<Item = &AcceptedTimeoutSummary> {
        self.accepted_tcs.values()
    }

    pub fn accepted_timeout_certificate(&self, id: &str) -> Option<&AcceptedTimeoutSummary> {
        self.accepted_tcs.get(id)
    }

    /// R3 evidence export from the existing control plane. This is only the
    /// timeout-path predicate: the runtime must additionally reject retained
    /// VC/proposal/cut commitments and consumed execution before authorization.
    /// A retained TC or wall-clock timeout alone is never sufficient. Every
    /// summary was sealed after native admission, so exporting this path does
    /// not reauthenticate or clone the retained full signature history.
    pub fn verified_cut_recovery_timeout_path(
        &self,
        target_height: u64,
        previous_generation_tc: Option<&str>,
        _verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<&AcceptedTimeoutSummary>> {
        if self.epoch_complete
            || self.active_height.checked_add(1) != Some(target_height)
            || self.active_round == 0
            || self.accepted_proposal.is_some()
            || self.mandatory_carry.is_some()
            || self.certified_qcs.contains_key(&self.active_height)
            || self
                .last_finalized()
                .is_some_and(|record| record.height >= self.active_height)
        {
            return Err(PosyError::NotReady(
                "R3 target is not an uncertified blocked slot".into(),
            ));
        }
        let terminal_id = self
            .active_takeover_tc_id
            .as_deref()
            .ok_or_else(|| PosyError::NotReady("R3 has no accepted timeout authority".into()))?;
        if previous_generation_tc == Some(terminal_id) {
            return Err(PosyError::invalid(
                "R3 generation requires a strictly later timeout",
            ));
        }
        let closure = self.timeout_closure(
            self.active_round,
            Some(terminal_id),
            self.active_height,
            None,
        )?;
        if previous_generation_tc.is_some_and(|previous| !closure.values().any(|id| id == previous))
        {
            return Err(PosyError::Conflict(
                "R3 previous generation is not in the accepted timeout path".into(),
            ));
        }
        let mut path = Vec::with_capacity(closure.len());
        for id in closure.values() {
            let certificate = self
                .accepted_tcs
                .get(id)
                .ok_or_else(|| PosyError::NotReady("R3 timeout predecessor is missing".into()))?;
            certificate.context.validate_against(&self.epoch)?;
            if certificate.id != *id {
                return Err(PosyError::Conflict(
                    "R3 timeout identity differs from accepted path".into(),
                ));
            }
            path.push(certificate);
        }
        let terminal = path
            .last()
            .ok_or_else(|| PosyError::NotReady("R3 timeout path is empty".into()))?;
        if terminal.context.height != self.active_height
            || terminal.context.round.checked_add(1) != Some(self.active_round)
            || terminal.highest_parent != self.highest_parent
            || terminal.mandatory_carry.is_some()
        {
            return Err(PosyError::Conflict(
                "R3 terminal timeout does not authorize this blocked parent".into(),
            ));
        }
        Ok(path)
    }

    pub fn active_takeover_tc_id(&self) -> Option<&str> {
        self.active_takeover_tc_id.as_deref()
    }

    pub fn last_finalized(&self) -> Option<&crate::FinalizedBlockRecord> {
        self.finality.last_finalized()
    }

    /// Returns the exact three certified heights that witness finality.
    /// This is evidence export only; Sync cannot accept or create a QC.
    pub fn finality_witness(
        &self,
        finalized_height: u64,
    ) -> Option<[SimplifiedQuorumCertificate; 3]> {
        let middle = finalized_height.checked_add(1)?;
        let newest = finalized_height.checked_add(2)?;
        Some([
            self.certified_qcs.get(&finalized_height)?.clone(),
            self.certified_qcs.get(&middle)?.clone(),
            self.certified_qcs.get(&newest)?.clone(),
        ])
    }

    pub fn epoch_complete(&self) -> bool {
        self.epoch_complete
    }

    pub fn accept_proposal(
        &mut self,
        proposal: &SimplifiedProposal,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<ConsensusTransition> {
        validate_proposal(proposal, &self.epoch, &self.validators, verifier)?;
        self.require_current_slot(proposal.context.height, proposal.context.round)?;
        self.require_active_ancestry(
            &proposal.parent,
            proposal.takeover_tc_id.as_deref(),
            proposal.context.round,
        )?;
        if let Some(carried) = &self.mandatory_carry {
            if proposal.candidate_subject()? != *carried {
                return Err(PosyError::Conflict(
                    "takeover proposal did not re-envelope the mandatory carried candidate".into(),
                ));
            }
        }
        if let Some(existing) = &self.accepted_proposal {
            if existing.candidate_subject()? != proposal.candidate_subject()? {
                return Err(PosyError::Conflict(
                    "conflicting proposals for the active consensus slot".into(),
                ));
            }
        } else {
            self.accepted_proposal = Some(proposal.clone());
        }
        Ok(ConsensusTransition::ProposalAccepted {
            height: proposal.context.height,
            round: proposal.context.round,
        })
    }

    pub fn accept_block_vote(
        &mut self,
        vote: BlockVote,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        validate_block_vote(&vote, &self.epoch, &self.validators, verifier)?;
        self.require_current_slot(vote.context.height, vote.context.round)?;
        self.require_active_ancestry(
            &vote.parent,
            vote.takeover_tc_id.as_deref(),
            vote.context.round,
        )?;
        let proposal = self.accepted_proposal.as_ref().ok_or_else(|| {
            PosyError::NotReady("vote arrived before an accepted proposal".into())
        })?;
        if vote_candidate(&vote)? != proposal.candidate_subject()? {
            return Err(PosyError::Conflict(
                "block vote does not match the accepted proposal".into(),
            ));
        }
        if !self.votes.insert(vote.clone())? {
            return Ok(Vec::new());
        }

        let mut transitions = vec![ConsensusTransition::VoteAccepted {
            height: vote.context.height,
            round: vote.context.round,
        }];
        let candidate = format!("{}:{}", vote.block_id, vote.protected_execution_root);
        let certificate =
            self.votes
                .certificate(vote.context.height, vote.context.round, &candidate)?;
        match certificate.verify(&self.epoch, &self.validators, verifier) {
            Ok(()) => transitions.extend(self.accept_verified_quorum_certificate(certificate)?),
            Err(PosyError::Quorum(_)) => {}
            Err(error) => return Err(error),
        }
        Ok(transitions)
    }

    pub fn accept_quorum_certificate(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        certificate.verify(&self.epoch, &self.validators, verifier)?;
        self.accept_verified_quorum_certificate(certificate)
    }

    pub fn accept_timeout_vote(
        &mut self,
        vote: TimeoutVote,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        validate_timeout_vote(&vote, &self.epoch, &self.validators, verifier)?;
        self.require_current_slot(vote.context.height, vote.context.round)?;
        if vote.previous_tc_id != self.active_takeover_tc_id
            || vote.highest_parent != self.highest_parent
        {
            return Err(PosyError::invalid(
                "timeout vote does not match active takeover or highest parent",
            ));
        }
        if !self.timeout_votes.insert(vote.clone())? {
            return Ok(Vec::new());
        }
        let mut transitions = vec![ConsensusTransition::TimeoutVoteAccepted {
            height: vote.context.height,
            round: vote.context.round,
        }];
        let votes = self.timeout_votes.votes(
            vote.context.height,
            vote.context.round,
            &vote.timed_out_proposer,
        );
        let proofs = self.timeout_parent_proofs(&votes)?;
        let certificate = SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(votes, proofs)?;
        match certificate.verify(&self.epoch, &self.validators, verifier) {
            Ok(()) => transitions.extend(self.accept_verified_timeout_certificate(certificate)?),
            Err(error) if is_insufficient_timeout_quorum(&error) => {}
            Err(error) => return Err(error),
        }
        Ok(transitions)
    }

    pub fn accept_timeout_certificate(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        certificate.verify(&self.epoch, &self.validators, verifier)?;
        self.accept_verified_timeout_certificate(certificate)
    }

    fn require_current_slot(&self, height: u64, round: u64) -> PosyResult<()> {
        if self.epoch_complete {
            return Err(PosyError::NotReady(
                "frozen epoch is complete; verified transition authority is required".into(),
            ));
        }
        if (height, round) != self.active_slot() {
            return Err(PosyError::invalid(
                "message does not target active consensus slot",
            ));
        }
        Ok(())
    }

    fn require_active_ancestry(
        &self,
        parent: &SimplifiedFinalityParent,
        takeover_tc_id: Option<&str>,
        proof_round: u64,
    ) -> PosyResult<()> {
        if parent != &self.highest_parent {
            return Err(PosyError::invalid(
                "message does not extend the highest verified parent",
            ));
        }
        if proof_round == self.active_round
            && takeover_tc_id != self.active_takeover_tc_id.as_deref()
        {
            return Err(PosyError::invalid(
                "message does not carry the active takeover certificate",
            ));
        }
        Ok(())
    }

    fn accept_verified_quorum_certificate(
        &mut self,
        certificate: SimplifiedQuorumCertificate,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        if let Some(existing) = self.certified_qcs.get(&certificate.context.height).cloned() {
            if existing.id()? != certificate.id()? {
                return Err(PosyError::Conflict(
                    "conflicting quorum certificates at one height".into(),
                ));
            }
            self.certified_qcs.insert(
                certificate.context.height,
                merge_compatible_quorum_certificates(existing, certificate)?,
            );
            return Ok(Vec::new());
        }

        if certificate.context.height != self.active_height {
            return Err(PosyError::invalid(
                "quorum certificate is not for the next certified height",
            ));
        }
        self.require_active_ancestry(
            &certificate.parent,
            certificate.takeover_tc_id.as_deref(),
            certificate.context.round,
        )?;
        if certificate.context.round != self.active_round {
            let carried = self
                .mandatory_carry
                .as_ref()
                .ok_or_else(|| PosyError::invalid("older-round QC has no mandatory carry proof"))?;
            if certificate.context.round > self.active_round || certificate.subject()? != *carried {
                return Err(PosyError::Conflict(
                    "older-round QC contradicts the active timeout carry".into(),
                ));
            }
        }

        if let Some(parent) = certificate.parent.quorum_certificate_reference() {
            if self
                .locked_qc
                .as_ref()
                .is_none_or(|locked| parent.height > locked.height)
            {
                self.locked_qc = Some(parent);
            }
        }

        let certificate_height = certificate.context.height;
        self.certified_qcs
            .insert(certificate.context.height, certificate.clone());
        self.highest_parent = SimplifiedFinalityParent::QuorumCertificate {
            height: certificate.context.height,
            block_id: certificate.block_id.clone(),
            qc_id: certificate.id()?,
        };
        let mut transitions = vec![ConsensusTransition::QuorumCertified(certificate.clone())];
        if let Some(finalized) = self.finality.accept(certificate)? {
            transitions.push(ConsensusTransition::Finalized(finalized));
        }
        transitions.push(self.advance_after_qc()?);
        self.prune_certified_projection(certificate_height);
        Ok(transitions)
    }

    fn accept_verified_timeout_certificate(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        let certificate_id = certificate.id()?;
        if let Some(existing) = self.accepted_tcs.get(&certificate_id) {
            // Both bundles passed native authentication. A quorum-subset change
            // must not hide contradictory signed subjects from a shared signer.
            for incoming in &certificate.reports {
                if let Some(accepted) = existing.report_subjects.get(&incoming.validator_id) {
                    if *accepted != *blake3::hash(&timeout_vote_signing_bytes(incoming)?).as_bytes()
                    {
                        return Err(PosyError::Conflict(
                            "timeout proof variant contains contradictory signed report".into(),
                        ));
                    }
                }
            }
            let accepted_parent = existing.highest_parent.clone();
            let incoming_parent = certificate.highest_parent()?;
            if accepted_parent != incoming_parent {
                return Err(PosyError::Conflict(format!(
                    "timeout proof variant changes accepted parent or carry: parent mismatch; closure={certificate_id}; proof_slot={}/{}; active_slot={}/{}; accepted_parent={accepted_parent:?}; incoming_parent={incoming_parent:?}",
                    certificate.context.height, certificate.context.round,
                    self.active_height, self.active_round,
                )));
            }
            let accepted_carry = existing.mandatory_carry.clone();
            let incoming_carry = certificate.mandatory_carry_candidate()?;
            if accepted_carry.is_some() && incoming_carry.is_none() {
                // Section 10 permits quorum proof variants and rejects stale
                // duplicates. A weaker subset cannot clear accepted carry.
                // Rejection changes no authority, vote, lock or journal.
                return Err(PosyError::invalid(
                    "weaker duplicate timeout proof cannot clear accepted carry",
                ));
            }
            if accepted_carry.is_none() && certificate.context.height < self.active_height {
                if let (Some(carried), Some(certified)) = (
                    incoming_carry.as_ref(),
                    self.certified_qcs.get(&certificate.context.height),
                ) {
                    if certified.subject()? == *carried && certified.parent == incoming_parent {
                        // Historical proof variation confirms the block already
                        // independently certified. Do not strengthen or replace
                        // accepted timeout authority or any live signing state.
                        return Ok(Vec::new());
                    }
                }
            }
            if accepted_carry.is_none()
                && incoming_carry.is_some()
                && certificate.context.height == self.active_height
            {
                // An authenticated quorum subset may expose additional carry
                // reports without contradicting the accepted closure. Reject
                // this duplicate without replacing its original authority or
                // altering any live carry, lock, vote or signing permission.
                return Err(PosyError::invalid(
                    "stronger live duplicate timeout proof cannot replace accepted carry",
                ));
            }
            if accepted_carry != incoming_carry {
                return Err(PosyError::Conflict(format!(
                    "timeout proof variant changes accepted parent or carry: carry mismatch; closure={certificate_id}; proof_slot={}/{}; active_slot={}/{}; accepted_carry={accepted_carry:?}; incoming_carry={incoming_carry:?}",
                    certificate.context.height, certificate.context.round,
                    self.active_height, self.active_round,
                )));
            }
            return Ok(Vec::new());
        }
        if certificate.context.height < self.active_height {
            return self.reconcile_delayed_timeout(certificate);
        }
        self.require_current_slot(certificate.context.height, certificate.context.round)?;
        if certificate.previous_tc_id != self.active_takeover_tc_id
            || certificate.highest_parent()? != self.highest_parent
        {
            return Err(PosyError::invalid(
                "stale, skipped, or non-sequential timeout certificate",
            ));
        }
        let next_round = certificate
            .context
            .round
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("consensus round overflow"))?;
        let certificate_id = certificate.id()?;
        let summary = AcceptedTimeoutSummary::from_verified(&certificate)?;
        let summary_bytes = self.check_timeout_summary_capacity(&summary)?;
        self.mandatory_carry = certificate.mandatory_carry_candidate()?;
        self.active_round = next_round;
        self.active_takeover_tc_id = Some(certificate_id.clone());
        self.accepted_proposal = None;
        self.accepted_tcs.insert(certificate_id, summary);
        self.accepted_tc_bytes += summary_bytes;
        self.timeout_votes.clear_height(self.active_height);
        Ok(vec![
            ConsensusTransition::TimeoutCertified(certificate),
            ConsensusTransition::RoundAdvanced {
                height: self.active_height,
                round: self.active_round,
            },
        ])
    }

    /// R2 admits only a fully verified original timeout whose carried candidate
    /// is already certified. This changes the live lease projection, never QCs,
    /// finality, locks, or the vote collections.
    fn reconcile_delayed_timeout(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
    ) -> PosyResult<Vec<ConsensusTransition>> {
        if self.epoch_complete
            || self.epoch.lease_index(certificate.context.height)?
                != self.epoch.lease_index(self.active_height)?
        {
            return Err(PosyError::invalid(
                "delayed timeout is outside the active lease",
            ));
        }
        let original = self
            .certified_qcs
            .get(&certificate.context.height)
            .ok_or_else(|| {
                PosyError::NotReady("delayed timeout lacks its original-height QC".into())
            })?;
        if certificate.highest_parent()? != original.parent
            || certificate.mandatory_carry_candidate()?.as_ref() != Some(&original.subject()?)
        {
            return Err(PosyError::Conflict(
                "delayed timeout does not carry the exact certified candidate".into(),
            ));
        }
        let next_round = certificate
            .context
            .round
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("consensus round overflow"))?;
        let certificate_id = certificate.id()?;
        let mut closure = self.timeout_closure(
            next_round,
            Some(&certificate_id),
            certificate.context.height,
            Some(&certificate),
        )?;
        merge_timeout_closure(
            &mut closure,
            self.timeout_closure(
                self.active_round,
                self.active_takeover_tc_id.as_deref(),
                self.active_height,
                Some(&certificate),
            )?,
        )?;

        let mut parent = original.parent.clone();
        for height in certificate.context.height..self.active_height {
            let qc = self.certified_qcs.get(&height).ok_or_else(|| {
                PosyError::NotReady("delayed timeout lacks a contiguous certified suffix".into())
            })?;
            qc.context.validate_against(&self.epoch)?;
            if self.epoch.lease_index(height)? != certificate.lease_index || qc.parent != parent {
                return Err(PosyError::Conflict(
                    "delayed timeout certified suffix changes lease or parent".into(),
                ));
            }
            merge_timeout_closure(
                &mut closure,
                self.timeout_closure(
                    qc.context.round,
                    qc.takeover_tc_id.as_deref(),
                    height,
                    Some(&certificate),
                )?,
            )?;
            parent = SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id: qc.block_id.clone(),
                qc_id: qc.id()?,
            };
        }
        if parent != self.highest_parent {
            return Err(PosyError::Conflict(
                "delayed timeout suffix does not reach the active parent".into(),
            ));
        }

        // Complete all fallible checks before publishing the new projection.
        // A compatible later accepted TC remains authoritative, including its carry.
        let summary = AcceptedTimeoutSummary::from_verified(&certificate)?;
        let summary_bytes = self.check_timeout_summary_capacity(&summary)?;
        self.accepted_tcs.insert(certificate_id.clone(), summary);
        self.accepted_tc_bytes += summary_bytes;
        let mut transitions = vec![ConsensusTransition::TimeoutCertified(certificate)];
        if next_round > self.active_round {
            self.active_round = next_round;
            self.active_takeover_tc_id = Some(certificate_id);
            self.mandatory_carry = None; // The original-height carry is already certified.
            self.accepted_proposal = None;
            transitions.push(ConsensusTransition::RoundAdvanced {
                height: self.active_height,
                round: self.active_round,
            });
        }
        Ok(transitions)
    }

    /// Every stored TC passed full signature/quorum admission. Walk exact IDs,
    /// bounded by available evidence rather than an untrusted round number.
    fn timeout_closure(
        &self,
        round: u64,
        takeover: Option<&str>,
        height: u64,
        incoming: Option<&SimplifiedTimeoutCertificate>,
    ) -> PosyResult<BTreeMap<u64, String>> {
        if round > self.accepted_tcs.len() as u64 + u64::from(incoming.is_some()) {
            return Err(PosyError::NotReady(
                "timeout predecessor closure is incomplete".into(),
            ));
        }
        let incoming = incoming
            .map(AcceptedTimeoutSummary::from_verified)
            .transpose()?;
        let incoming_id = incoming.as_ref().map(|summary| summary.id.as_str());
        let mut expected = takeover;
        let mut last_height = height;
        let mut closure = BTreeMap::new();
        for predecessor_round in (0..round).rev() {
            let id = expected.ok_or_else(|| {
                PosyError::NotReady("timeout predecessor closure is incomplete".into())
            })?;
            let tc = if incoming_id == Some(id) {
                incoming.as_ref()
            } else {
                self.accepted_tcs.get(id)
            }
            .ok_or_else(|| {
                PosyError::NotReady("timeout predecessor certificate is unavailable".into())
            })?;
            if tc.context.round != predecessor_round
                || tc.context.height > last_height
                || tc.lease_index != self.epoch.lease_index(height)?
            {
                return Err(PosyError::Conflict(
                    "incompatible timeout predecessor closure".into(),
                ));
            }
            closure.insert(predecessor_round, id.to_owned());
            last_height = tc.context.height;
            expected = tc.previous_tc_id.as_deref();
        }
        if expected.is_some() {
            return Err(PosyError::Conflict(
                "timeout closure does not begin at round zero".into(),
            ));
        }
        Ok(closure)
    }

    fn check_timeout_summary_capacity(
        &self,
        summary: &AcceptedTimeoutSummary,
    ) -> PosyResult<usize> {
        // Serialization charges every retained variable-length field; the
        // additional fixed charge covers collection nodes, capacities and IDs.
        let bytes = serde_json::to_vec(summary)
            .map_err(|error| PosyError::invalid(format!("encode timeout summary: {error}")))?
            .len()
            .saturating_mul(2)
            .saturating_add(1024);
        if self.accepted_tcs.len() >= MAX_ACCEPTED_TIMEOUT_SUMMARIES
            || self.accepted_tc_bytes.saturating_add(bytes) > MAX_ACCEPTED_TIMEOUT_SUMMARY_BYTES
        {
            return Err(PosyError::ResourcePressure(
                "accepted timeout summary resource budget exhausted".into(),
            ));
        }
        Ok(bytes)
    }

    fn timeout_parent_proofs(
        &self,
        votes: &[TimeoutVote],
    ) -> PosyResult<Vec<SimplifiedQuorumCertificate>> {
        let mut proofs = BTreeMap::<String, SimplifiedQuorumCertificate>::new();
        for vote in votes {
            if let Some(reference) = vote.highest_parent.quorum_certificate_reference() {
                let proof = self
                    .certified_qcs
                    .get(&reference.height)
                    .filter(|proof| proof.reference().ok().as_ref() == Some(&reference))
                    .cloned()
                    .ok_or_else(|| {
                        PosyError::NotReady(
                            "timeout report references a QC unavailable to local state".into(),
                        )
                    })?;
                proofs.entry(reference.qc_id).or_insert(proof);
            }
        }
        Ok(proofs.into_values().collect())
    }

    fn prune_certified_projection(&mut self, newest_height: u64) {
        // Keep the current lease's contiguous R2 suffix and the finality tail
        // spanning a lease boundary. Older authority remains in the immutable
        // store and is checked directly by the runtime owner.
        let lease_start = self.epoch.epoch_start_height
            + ((self.active_height - self.epoch.epoch_start_height)
                / self.epoch.leader_lease_blocks)
                * self.epoch.leader_lease_blocks;
        let retain_from = lease_start.min(newest_height.saturating_sub(2));
        self.certified_qcs
            .retain(|height, _| *height >= retain_from);
    }

    fn advance_after_qc(&mut self) -> PosyResult<ConsensusTransition> {
        let certified_height = self.active_height;
        let next_height = certified_height
            .checked_add(1)
            .ok_or_else(|| PosyError::invalid("certified height overflow"))?;
        self.accepted_proposal = None;
        self.votes.clear_height(certified_height);
        self.timeout_votes.clear_height(certified_height);
        self.mandatory_carry = None;
        if !self.epoch.contains_height(next_height) {
            self.epoch_complete = true;
            return Ok(ConsensusTransition::EpochBoundaryCertified {
                height: certified_height,
            });
        }
        let same_lease =
            self.epoch.lease_index(certified_height)? == self.epoch.lease_index(next_height)?;
        self.active_height = next_height;
        if !same_lease {
            self.active_round = 0;
            self.active_takeover_tc_id = None;
            // This is only the verified live projection cache. Original timeout
            // records and all signing restrictions remain in durable storage.
            self.accepted_tcs.clear();
            self.accepted_tc_bytes = 0;
        }
        Ok(ConsensusTransition::HeightAdvanced {
            height: self.active_height,
            round: self.active_round,
        })
    }
}

fn merge_timeout_closure(
    closure: &mut BTreeMap<u64, String>,
    extension: BTreeMap<u64, String>,
) -> PosyResult<()> {
    for (round, id) in extension {
        if closure.get(&round).is_some_and(|existing| existing != &id) {
            return Err(PosyError::Conflict(
                "certified timeout closures disagree".into(),
            ));
        }
        closure.insert(round, id);
    }
    Ok(())
}

fn vote_candidate(vote: &BlockVote) -> PosyResult<CertifiedCandidateSubject> {
    CertifiedCandidateSubject::new(
        vote.context.clone(),
        vote.block_id.clone(),
        vote.parent_block_id.clone(),
        vote.parent.clone(),
        vote.protected_execution_root.clone(),
    )
}

fn is_insufficient_timeout_quorum(error: &PosyError) -> bool {
    matches!(error, PosyError::Quorum(_)) || error.to_string().contains("timeout quorum failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConsensusObjectContext, ParticipantSignature, ValidatorRecord, ValidatorStatus};

    struct AcceptAllSignatures;

    impl ConsensusSignatureVerifier for AcceptAllSignatures {
        fn verify_consensus_signature(
            &self,
            _domain: &str,
            _payload: &[u8],
            _validator: &ValidatorRecord,
            _key_id: &str,
            _epoch: u64,
            _signature: &[u8],
        ) -> PosyResult<()> {
            Ok(())
        }
    }

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn registry() -> FrozenValidatorRegistry {
        FrozenValidatorRegistry::new(
            7,
            [7u128, 3, 3, 3, 3]
                .into_iter()
                .enumerate()
                .map(|(index, frozen_voting_weight)| ValidatorRecord {
                    validator_id: format!("validator-{index}"),
                    consensus_key_id: format!("key-{index}"),
                    frozen_voting_weight,
                    status: ValidatorStatus::Active,
                })
                .collect(),
        )
        .expect("valid frozen validator registry")
    }

    fn epoch(registry: &FrozenValidatorRegistry) -> SimplifiedEpochContext {
        SimplifiedEpochContext::from_frozen_registry(
            1266,
            "testnet-v3".into(),
            7,
            1,
            20,
            hash('a'),
            hash('b'),
            registry,
        )
        .expect("valid epoch")
    }

    fn genesis_parent() -> SimplifiedFinalityParent {
        SimplifiedFinalityParent::Genesis {
            genesis_hash: hash('c'),
            block_id: "genesis-block".into(),
            reference_id: hash('d'),
        }
    }

    fn machine() -> SimplifiedConsensusStateMachine {
        let registry = registry();
        SimplifiedConsensusStateMachine::new(epoch(&registry), registry, genesis_parent())
            .expect("state machine")
    }

    fn proposal(machine: &SimplifiedConsensusStateMachine) -> SimplifiedProposal {
        let (height, round) = machine.active_slot();
        let proposer_id = machine
            .epoch
            .authorized_proposer(height, round)
            .expect("proposer")
            .to_string();
        let proposer_key_id = machine
            .validators
            .active_validator(&proposer_id)
            .expect("active proposer")
            .consensus_key_id
            .clone();
        SimplifiedProposal {
            context: ConsensusObjectContext::for_height(&machine.epoch, height, round)
                .expect("context"),
            proposer_id,
            block_id: format!("block-{height}"),
            parent_block_id: machine.highest_parent.block_id().into(),
            parent: machine.highest_parent.clone(),
            takeover_tc_id: machine.active_takeover_tc_id.clone(),
            protected_execution_root: if height % 2 == 0 {
                hash('e')
            } else {
                hash('f')
            },
            proposer_key_id,
            proposer_signature: vec![1],
        }
    }

    fn vote(proposal: &SimplifiedProposal, index: usize) -> BlockVote {
        BlockVote {
            context: proposal.context.clone(),
            block_id: proposal.block_id.clone(),
            parent_block_id: proposal.parent_block_id.clone(),
            parent: proposal.parent.clone(),
            takeover_tc_id: proposal.takeover_tc_id.clone(),
            protected_execution_root: proposal.protected_execution_root.clone(),
            validator_id: format!("validator-{index}"),
            key_id: format!("key-{index}"),
            signature: vec![index as u8],
        }
    }

    fn certify_next(machine: &mut SimplifiedConsensusStateMachine) -> SimplifiedQuorumCertificate {
        let verifier = AcceptAllSignatures;
        let proposal = proposal(machine);
        machine
            .accept_proposal(&proposal, &verifier)
            .expect("proposal accepted");
        let mut certified = None;
        for index in 0..4 {
            for transition in machine
                .accept_block_vote(vote(&proposal, index), &verifier)
                .expect("vote accepted")
            {
                if let ConsensusTransition::QuorumCertified(certificate) = transition {
                    certified = Some(certificate);
                }
            }
        }
        certified.expect("strict dual quorum formed")
    }

    #[test]
    fn committed_lease_boundary_matches_full_replay_and_preserves_current_carry() {
        let mut full = machine();
        let mut qcs = Vec::new();
        for height in 1..=10 {
            if height == 8 {
                full.accept_timeout_certificate(timeout_for(&full, None), &AcceptAllSignatures)
                    .unwrap();
            }
            qcs.push(certify_next(&mut full));
        }
        let witness = crate::FinalitySyncWitness {
            quorum_certificates: [qcs[7].clone(), qcs[8].clone(), qcs[9].clone()],
            timeout_certificates: Vec::new(),
        };
        let mut missing = machine();
        assert!(missing
            .seed_committed_lease_boundary(
                full.last_finalized().unwrap().clone(),
                witness.clone(),
                &AcceptAllSignatures,
            )
            .is_err());
        assert_eq!(missing.active_slot(), (1, 0));
        let mut witness = witness;
        // The old lease's closure remains necessary to authenticate the anchor,
        // even though normal advancement no longer retains its live authority.
        let mut before = machine();
        for qc in &qcs[..7] {
            before
                .accept_quorum_certificate(qc.clone(), &AcceptAllSignatures)
                .unwrap();
        }
        witness
            .timeout_certificates
            .push(timeout_for(&before, None));
        let mut bounded = machine();
        bounded
            .seed_committed_lease_boundary(
                full.last_finalized().unwrap().clone(),
                witness.clone(),
                &AcceptAllSignatures,
            )
            .unwrap();
        assert_eq!(bounded.active_slot(), full.active_slot());
        assert_eq!(bounded.highest_parent(), full.highest_parent());
        assert_eq!(bounded.locked_qc(), full.locked_qc());
        assert_eq!(bounded.last_finalized(), full.last_finalized());
        assert_eq!(
            bounded.active_takeover_tc_id(),
            full.active_takeover_tc_id()
        );
        let proposed = proposal(&full);
        let carried = proposed.candidate_subject().unwrap();
        let tc = timeout_for(&full, Some(carried));
        for state in [&mut full, &mut bounded] {
            state
                .accept_timeout_certificate(tc.clone(), &AcceptAllSignatures)
                .unwrap();
        }
        let next = certify_next(&mut full);
        bounded
            .accept_quorum_certificate(next, &AcceptAllSignatures)
            .unwrap();
        assert_eq!(bounded.active_slot(), full.active_slot());
        assert_eq!(bounded.highest_parent(), full.highest_parent());
        assert_eq!(bounded.locked_qc(), full.locked_qc());
        assert_eq!(bounded.last_finalized(), full.last_finalized());
        assert_eq!(
            bounded.active_takeover_tc_id(),
            full.active_takeover_tc_id()
        );
        assert_eq!(bounded.mandatory_carry, full.mandatory_carry);

        let mut conflict = machine();
        let mut wrong_record = witness.quorum_certificates[0].block_id.clone();
        wrong_record.push_str("-wrong");
        let mut committed = full.last_finalized().unwrap().clone();
        committed.height = 8;
        committed.block_id = wrong_record;
        assert!(conflict
            .seed_committed_lease_boundary(committed, witness, &AcceptAllSignatures,)
            .is_err());
        assert_eq!(conflict.active_slot(), (1, 0));
        assert!(conflict.locked_qc().is_none());
    }

    #[test]
    fn committed_anchor_rejects_arbitrary_height_and_wrong_domain() {
        let mut full = machine();
        let qcs = (1..=9).map(|_| certify_next(&mut full)).collect::<Vec<_>>();
        let witness = crate::FinalitySyncWitness {
            quorum_certificates: [qcs[6].clone(), qcs[7].clone(), qcs[8].clone()],
            timeout_certificates: Vec::new(),
        };
        let mut bounded = machine();
        assert!(bounded
            .seed_committed_lease_boundary(
                full.last_finalized().unwrap().clone(),
                witness,
                &AcceptAllSignatures,
            )
            .is_err());
        assert_eq!(bounded.active_slot(), (1, 0));
        let tenth = certify_next(&mut full);
        let mut wrong_domain = crate::FinalitySyncWitness {
            quorum_certificates: [qcs[7].clone(), qcs[8].clone(), tenth],
            timeout_certificates: Vec::new(),
        };
        wrong_domain.quorum_certificates[0]
            .context
            .network_id
            .push_str("-wrong");
        assert!(bounded
            .seed_committed_lease_boundary(
                full.last_finalized().unwrap().clone(),
                wrong_domain,
                &AcceptAllSignatures,
            )
            .is_err());
        assert_eq!(bounded.active_slot(), (1, 0));
    }

    #[test]
    fn live_certified_projection_is_bounded_across_many_leases() {
        let validators = registry();
        let mut governed = epoch(&validators);
        governed.epoch_end_height = 400;
        let mut state =
            SimplifiedConsensusStateMachine::new(governed, validators, genesis_parent()).unwrap();
        let mut first = None;
        for height in 1..=300 {
            if (height - 1) % state.epoch.leader_lease_blocks == 2 {
                let tc = timeout_for(&state, None);
                state
                    .accept_timeout_certificate(tc, &AcceptAllSignatures)
                    .unwrap();
            }
            let qc = certify_next(&mut state);
            first.get_or_insert_with(|| qc.clone());
            assert!(state.certified_qcs.len() <= state.epoch.leader_lease_blocks as usize + 2);
            if let Some(record) = state.last_finalized() {
                let witness = state.finality_witness(record.height).unwrap();
                assert_eq!(witness[0].block_id, record.block_id);
                assert_eq!(witness[2].id().unwrap(), record.finality_certificate_id);
            }
            if height % state.epoch.leader_lease_blocks == 0 {
                assert_eq!(state.active_slot().1, 0);
                assert_eq!(state.active_takeover_tc_id(), None);
                assert_eq!(state.accepted_timeout_certificates().count(), 0);
            }
        }
        let before = (
            state.active_slot(),
            state.highest_parent().clone(),
            state.locked_qc().cloned(),
            state.last_finalized().cloned(),
        );
        assert!(matches!(
            state.accept_quorum_certificate(first.unwrap(), &AcceptAllSignatures),
            Err(PosyError::Invalid(_)),
        ));
        assert_eq!(
            before,
            (
                state.active_slot(),
                state.highest_parent().clone(),
                state.locked_qc().cloned(),
                state.last_finalized().cloned(),
            )
        );
    }

    #[test]
    fn stable_qc_identity_excludes_round_takeover_and_proof_subset() {
        let machine = machine();
        let proposal = proposal(&machine);
        let votes = (0..4).map(|index| vote(&proposal, index)).collect();
        let certificate = SimplifiedQuorumCertificate::from_votes(votes).expect("certificate");
        let mut re_enveloped = certificate.clone();
        re_enveloped.context.round = 1;
        re_enveloped.takeover_tc_id = Some(hash('a'));
        re_enveloped.participants.push(ParticipantSignature {
            validator_id: "validator-4".into(),
            key_id: "key-4".into(),
            signature: vec![4],
        });
        assert_eq!(certificate.id().unwrap(), re_enveloped.id().unwrap());
        assert_eq!(
            merge_compatible_quorum_certificates(certificate.clone(), re_enveloped,).unwrap(),
            certificate
        );
    }

    #[test]
    fn qc_progression_is_pipelined_and_third_qc_finalizes_first_block() {
        let mut machine = machine();
        let first = certify_next(&mut machine);
        assert_eq!(machine.active_slot(), (2, 0));
        let second = certify_next(&mut machine);
        assert_eq!(machine.active_slot(), (3, 0));
        assert_eq!(second.parent.reference_id(), first.id().unwrap());
        let third = certify_next(&mut machine);
        assert_eq!(machine.active_slot(), (4, 0));
        assert_eq!(third.parent.reference_id(), second.id().unwrap());
        let finalized = machine.last_finalized().expect("three-QC finality");
        assert_eq!(finalized.height, 1);
        assert_eq!(finalized.block_id, first.block_id);
    }

    #[test]
    fn strict_timeout_quorum_advances_round_and_persists_takeover_within_lease() {
        let mut machine = machine();
        let verifier = AcceptAllSignatures;
        let context = ConsensusObjectContext::for_height(&machine.epoch, 1, 0).unwrap();
        let timed_out_proposer = machine.epoch.authorized_proposer(1, 0).unwrap().to_string();
        let mut timeout_certificate = None;
        for index in 0..4 {
            let vote = TimeoutVote {
                context: context.clone(),
                lease_index: 0,
                timed_out_proposer: timed_out_proposer.clone(),
                highest_parent: genesis_parent(),
                previous_tc_id: None,
                last_voted_candidate: None,
                validator_id: format!("validator-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![index as u8],
            };
            for transition in machine
                .accept_timeout_vote(vote, &verifier)
                .expect("timeout vote accepted")
            {
                if let ConsensusTransition::TimeoutCertified(certificate) = transition {
                    timeout_certificate = Some(certificate);
                }
            }
        }
        let timeout_certificate = timeout_certificate.expect("strict timeout quorum formed");
        let timeout_certificate_id = timeout_certificate.id().unwrap();
        assert_eq!(machine.active_slot(), (1, 1));
        assert_eq!(
            machine.active_takeover_tc_id.as_deref(),
            Some(timeout_certificate_id.as_str())
        );

        certify_next(&mut machine);
        assert_eq!(machine.active_slot(), (2, 1));
        assert_eq!(machine.active_takeover_tc_id, Some(timeout_certificate_id));
    }

    fn timeout_for(
        machine: &SimplifiedConsensusStateMachine,
        carry: Option<CertifiedCandidateSubject>,
    ) -> SimplifiedTimeoutCertificate {
        let (height, round) = machine.active_slot();
        let reports = (0..4)
            .map(|index| TimeoutVote {
                context: ConsensusObjectContext::for_height(&machine.epoch, height, round).unwrap(),
                lease_index: machine.epoch.lease_index(height).unwrap(),
                timed_out_proposer: machine
                    .epoch
                    .authorized_proposer(height, round)
                    .unwrap()
                    .into(),
                highest_parent: machine.highest_parent.clone(),
                previous_tc_id: machine.active_takeover_tc_id.clone(),
                last_voted_candidate: carry.clone(),
                validator_id: format!("validator-{index}"),
                key_id: format!("key-{index}"),
                signature: vec![index as u8],
            })
            .collect::<Vec<_>>();
        let proofs = machine.timeout_parent_proofs(&reports).unwrap();
        SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, proofs).unwrap()
    }

    #[test]
    fn r3_timeout_path_requires_advancing_complete_current_height_authority() {
        let mut machine = machine();
        let verifier = AcceptAllSignatures;
        assert!(machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
        let first = timeout_for(&machine, None);
        machine
            .accept_timeout_certificate(first.clone(), &verifier)
            .unwrap();
        let path = machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .unwrap();
        assert_eq!(
            path.iter().map(|summary| summary.id()).collect::<Vec<_>>(),
            vec![first.id().unwrap()]
        );
        let first_id = first.id().unwrap();
        assert!(machine
            .verified_cut_recovery_timeout_path(2, Some(&first_id), &verifier)
            .is_err());
        assert!(machine
            .verified_cut_recovery_timeout_path(3, None, &verifier)
            .is_err());
        assert!(machine
            .verified_cut_recovery_timeout_path(2, Some(&hash('9')), &verifier)
            .is_err());
        let second = timeout_for(&machine, None);
        machine
            .accept_timeout_certificate(second.clone(), &verifier)
            .unwrap();
        assert_eq!(
            machine
                .verified_cut_recovery_timeout_path(2, Some(&first_id), &verifier)
                .unwrap()
                .iter()
                .map(|summary| summary.id().to_owned())
                .collect::<Vec<_>>(),
            vec![first.id().unwrap(), second.id().unwrap()]
        );
        machine.accepted_tcs.remove(&first_id);
        assert!(machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
    }

    #[test]
    fn r3_timeout_path_rejects_carry_proposal_and_inherited_height_timeout() {
        let verifier = AcceptAllSignatures;
        let mut carried = machine();
        let candidate = proposal(&carried).candidate_subject().unwrap();
        let tc = timeout_for(&carried, Some(candidate));
        carried.accept_timeout_certificate(tc, &verifier).unwrap();
        assert!(carried
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
        let mut accepted = machine();
        let tc = timeout_for(&accepted, None);
        accepted.accept_timeout_certificate(tc, &verifier).unwrap();
        let next = proposal(&accepted);
        accepted.accept_proposal(&next, &verifier).unwrap();
        assert!(accepted
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
        let mut inherited = machine();
        let tc = timeout_for(&inherited, None);
        inherited.accept_timeout_certificate(tc, &verifier).unwrap();
        certify_next(&mut inherited);
        assert!(inherited
            .verified_cut_recovery_timeout_path(3, None, &verifier)
            .is_err());
    }

    #[test]
    fn r3_timeout_path_preserves_sealed_domain_parent_and_admission_quorum() {
        let verifier = AcceptAllSignatures;
        let mut machine = machine();
        let mut insufficient = timeout_for(&machine, None);
        insufficient.reports.pop();
        assert!(machine
            .accept_timeout_certificate(insufficient, &verifier)
            .is_err());
        assert_eq!(machine.active_slot(), (1, 0));
        assert!(machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
        let tc = timeout_for(&machine, None);
        machine
            .accept_timeout_certificate(tc.clone(), &verifier)
            .unwrap();
        let id = tc.id().unwrap();
        let before = machine.active_slot();
        let accepted_before = machine.accepted_tcs.clone();
        machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .unwrap();
        assert_eq!(machine.active_slot(), before);
        assert_eq!(machine.accepted_tcs, accepted_before);
        machine
            .accepted_tcs
            .get_mut(&id)
            .unwrap()
            .context
            .network_id = "wrong-network".into();
        assert!(machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
        machine.accepted_tcs.insert(
            id.clone(),
            AcceptedTimeoutSummary::from_verified(&tc).unwrap(),
        );
        machine.accepted_tcs.get_mut(&id).unwrap().highest_parent =
            SimplifiedFinalityParent::Genesis {
                genesis_hash: hash('c'),
                block_id: "wrong-parent".into(),
                reference_id: hash('d'),
            };
        assert!(machine
            .verified_cut_recovery_timeout_path(2, None, &verifier)
            .is_err());
    }

    #[test]
    fn accepted_timeout_summary_rejects_native_authentication_failure_atomically() {
        struct RejectSignatures;
        impl ConsensusSignatureVerifier for RejectSignatures {
            fn verify_consensus_signature(
                &self,
                _: &str,
                _: &[u8],
                _: &ValidatorRecord,
                _: &str,
                _: u64,
                _: &[u8],
            ) -> PosyResult<()> {
                Err(PosyError::invalid("test rejected signature"))
            }
        }
        let mut machine = machine();
        let tc = timeout_for(&machine, None);
        assert!(machine
            .accept_timeout_certificate(tc.clone(), &RejectSignatures)
            .is_err());
        assert_eq!(machine.active_slot(), (1, 0));
        assert_eq!(machine.accepted_tc_bytes, 0);
        assert!(machine.accepted_tcs.is_empty());
        let mut wrong_domain = tc.clone();
        wrong_domain.context.network_id = "wrong-network".into();
        assert!(machine
            .accept_timeout_certificate(wrong_domain, &AcceptAllSignatures)
            .is_err());
        machine
            .accept_timeout_certificate(tc.clone(), &AcceptAllSignatures)
            .unwrap();
        // The sealed projection already authenticates admission; the export
        // must not ask a verifier to replay signatures for the entire prefix.
        let path = machine
            .verified_cut_recovery_timeout_path(2, None, &RejectSignatures)
            .unwrap();
        assert_eq!(path[0].id(), tc.id().unwrap());
        assert!(path[0].matches_certificate(&tc).unwrap());
        let mut changed_subject = tc;
        changed_subject.reports[0].highest_parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: hash('c'),
            block_id: "wrong-parent".into(),
            reference_id: hash('d'),
        };
        assert!(!path[0].matches_certificate(&changed_subject).unwrap());
    }

    #[test]
    fn accepted_timeout_history_retains_bounded_metadata_and_capacity_rejection_is_atomic() {
        let mut machine = machine();
        // Signatures are payload-only fixture bytes under the explicit mock
        // verifier; genuine native signatures are covered by runtime fixtures.
        for round in 0..MAX_ACCEPTED_TIMEOUT_SUMMARIES {
            let mut tc = timeout_for(&machine, None);
            for report in &mut tc.reports {
                report.signature = vec![42; 16 * 1024];
            }
            machine
                .accept_timeout_certificate(tc, &AcceptAllSignatures)
                .unwrap();
            assert_eq!(machine.active_slot(), (1, round as u64 + 1));
            assert!(machine.accepted_tc_bytes <= MAX_ACCEPTED_TIMEOUT_SUMMARY_BYTES);
        }
        let before = (
            machine.active_slot(),
            machine.active_takeover_tc_id.clone(),
            machine.accepted_tc_bytes,
            machine.accepted_tcs.len(),
        );
        let tc = timeout_for(&machine, None);
        assert!(matches!(
            machine.accept_timeout_certificate(tc, &AcceptAllSignatures),
            Err(PosyError::ResourcePressure(_))
        ));
        assert_eq!(
            (
                machine.active_slot(),
                machine.active_takeover_tc_id.clone(),
                machine.accepted_tc_bytes,
                machine.accepted_tcs.len()
            ),
            before
        );
        eprintln!(
            "accepted_timeout_resource summaries={} charged_bytes={} retained_signature_bytes=0",
            machine.accepted_tcs.len(),
            machine.accepted_tc_bytes
        );
        let path = machine
            .verified_cut_recovery_timeout_path(2, None, &AcceptAllSignatures)
            .unwrap();
        assert_eq!(path.len(), MAX_ACCEPTED_TIMEOUT_SUMMARIES);
        assert_eq!(
            path.last().unwrap().context().round,
            MAX_ACCEPTED_TIMEOUT_SUMMARIES as u64 - 1
        );
        // Capacity pressure must leave the ordinary valid QC/finality path open.
        certify_next(&mut machine);
        assert_eq!(machine.active_slot().0, 2);
    }

    #[test]
    fn admitted_timeout_releases_collected_signatures_before_the_next_round() {
        let mut machine = machine();
        for _ in 0..4 {
            let tc = timeout_for(&machine, None);
            let old = tc.context.clone();
            let proposer = tc.timed_out_proposer.clone();
            for report in tc.reports {
                machine
                    .accept_timeout_vote(report, &AcceptAllSignatures)
                    .unwrap();
            }
            assert!(machine
                .timeout_votes
                .votes(old.height, old.round, &proposer)
                .is_empty());
        }
        assert_eq!(machine.active_slot(), (1, 4));
        assert_eq!(machine.accepted_tcs.len(), 4);
    }

    fn delayed_timeout_fixture() -> (
        SimplifiedConsensusStateMachine,
        SimplifiedQuorumCertificate,
        SimplifiedQuorumCertificate,
        SimplifiedTimeoutCertificate,
    ) {
        let mut node = machine();
        let q1 = certify_next(&mut node);
        let pending = proposal(&node);
        let q2 = SimplifiedQuorumCertificate::from_votes(
            (0..4).map(|index| vote(&pending, index)).collect(),
        )
        .unwrap();
        let tc = timeout_for(&node, Some(q2.subject().unwrap()));
        (node, q1, q2, tc)
    }

    #[test]
    fn r2_delayed_timeout_converges_both_orders_without_changing_certified_state() {
        let (mut early, q1, q2, tc) = delayed_timeout_fixture();
        early
            .accept_timeout_certificate(tc.clone(), &AcceptAllSignatures)
            .unwrap();
        early
            .accept_quorum_certificate(q2.clone(), &AcceptAllSignatures)
            .unwrap();
        let mut late = machine();
        late.accept_quorum_certificate(q1, &AcceptAllSignatures)
            .unwrap();
        late.accept_quorum_certificate(q2, &AcceptAllSignatures)
            .unwrap();
        let parent = late.highest_parent.clone();
        let lock = late.locked_qc.clone();
        let qcs = late.certified_qcs.clone();
        let transitions = late
            .accept_timeout_certificate(tc.clone(), &AcceptAllSignatures)
            .unwrap();
        assert!(matches!(
            transitions.as_slice(),
            [
                ConsensusTransition::TimeoutCertified(_),
                ConsensusTransition::RoundAdvanced {
                    height: 3,
                    round: 1
                }
            ]
        ));
        assert_eq!(late.active_slot(), early.active_slot());
        assert_eq!(late.active_takeover_tc_id, early.active_takeover_tc_id);
        assert_eq!(late.highest_parent, parent);
        assert_eq!(late.locked_qc, lock);
        assert_eq!(late.certified_qcs, qcs);
        assert!(late.last_finalized().is_none());
        assert!(late
            .accept_timeout_certificate(tc, &AcceptAllSignatures)
            .unwrap()
            .is_empty());
        certify_next(&mut late);
        assert_eq!(late.last_finalized().unwrap().height, 1);
    }

    #[test]
    fn r2_delayed_timeout_checks_complete_suffix_and_preserves_later_round() {
        let (mut late, _, q2, tc) = delayed_timeout_fixture();
        late.accept_quorum_certificate(q2, &AcceptAllSignatures)
            .unwrap();
        certify_next(&mut late);
        let finalized = late.last_finalized().cloned();
        late.accept_timeout_certificate(tc.clone(), &AcceptAllSignatures)
            .unwrap();
        assert_eq!(late.active_slot(), (4, 1));
        assert_eq!(late.last_finalized(), finalized.as_ref());
        let later = timeout_for(&late, None);
        late.accept_timeout_certificate(later.clone(), &AcceptAllSignatures)
            .unwrap();
        // Retained compatible successor evidence must not be rolled back by a replay.
        late.accept_timeout_certificate(tc, &AcceptAllSignatures)
            .unwrap();
        assert_eq!(late.active_slot(), (4, 2));
        assert_eq!(late.active_takeover_tc_id, Some(later.id().unwrap()));
    }

    #[test]
    fn r2_delayed_timeout_rejects_missing_or_conflicting_evidence_atomically() {
        let (mut late, _, q2, tc) = delayed_timeout_fixture();
        late.accept_quorum_certificate(q2, &AcceptAllSignatures)
            .unwrap();
        let mut missing_carry = tc.clone();
        for report in &mut missing_carry.reports {
            report.last_voted_candidate = None;
        }
        let mut conflicting_carry = tc.clone();
        for report in &mut conflicting_carry.reports {
            report
                .last_voted_candidate
                .as_mut()
                .unwrap()
                .protected_execution_root = hash('a');
        }
        let mut missing_predecessor = tc.clone();
        missing_predecessor.context.round = 1;
        missing_predecessor.timed_out_proposer =
            late.epoch.authorized_proposer(2, 1).unwrap().into();
        missing_predecessor.previous_tc_id = Some(hash('9'));
        for report in &mut missing_predecessor.reports {
            report.context = missing_predecessor.context.clone();
            report.timed_out_proposer = missing_predecessor.timed_out_proposer.clone();
            report.previous_tc_id = missing_predecessor.previous_tc_id.clone();
        }
        for invalid in [missing_carry, conflicting_carry] {
            assert!(matches!(
                late.accept_timeout_certificate(invalid, &AcceptAllSignatures),
                Err(PosyError::Conflict(_))
            ));
            assert_eq!(late.active_slot(), (3, 0));
            assert!(late.accepted_tcs.is_empty());
        }
        assert!(matches!(
            late.accept_timeout_certificate(missing_predecessor, &AcceptAllSignatures),
            Err(PosyError::NotReady(_))
        ));
        assert_eq!(late.active_slot(), (3, 0));
        assert!(late.accepted_tcs.is_empty());
        // A separately valid timeout at the successor height is a different branch,
        // even though both certificates claim round zero of the same lease.
        let competing = timeout_for(&late, None);
        late.accept_timeout_certificate(competing.clone(), &AcceptAllSignatures)
            .unwrap();
        assert!(matches!(
            late.accept_timeout_certificate(tc, &AcceptAllSignatures),
            Err(PosyError::Conflict(_))
        ));
        assert_eq!(late.active_slot(), (3, 1));
        assert_eq!(late.active_takeover_tc_id, Some(competing.id().unwrap()));
        assert_eq!(late.accepted_tcs.len(), 1);
    }

    #[test]
    fn r2_delayed_timeout_requires_current_lease_and_every_certified_parent() {
        let (mut late, _, q2, tc) = delayed_timeout_fixture();
        late.accept_quorum_certificate(q2, &AcceptAllSignatures)
            .unwrap();
        certify_next(&mut late);
        let removed = late.certified_qcs.remove(&3).unwrap();
        assert!(matches!(
            late.accept_timeout_certificate(tc.clone(), &AcceptAllSignatures),
            Err(PosyError::NotReady(_))
        ));
        assert_eq!(late.active_slot(), (4, 0));
        assert!(late.accepted_tcs.is_empty());
        late.certified_qcs.insert(3, removed);
        while late.active_slot().0 < 11 {
            certify_next(&mut late);
        }
        assert!(late
            .accept_timeout_certificate(tc, &AcceptAllSignatures)
            .is_err());
        assert_eq!(late.active_slot(), (11, 0));
        assert!(late.accepted_tcs.is_empty());
    }
}
