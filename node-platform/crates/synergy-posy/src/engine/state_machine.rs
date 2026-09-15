use std::collections::BTreeMap;

use crate::{
    merge_compatible_quorum_certificates, validate_block_vote, validate_proposal,
    validate_timeout_vote, BlockVote, CertifiedCandidateSubject, ConsensusSignatureVerifier,
    ConsensusTransition, FrozenValidatorRegistry, PosyError, PosyResult,
    QuorumCertificateReference, SimplifiedEpochContext, SimplifiedFinalityParent,
    SimplifiedProposal, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate, ThreeQcFinality,
    TimeoutVote, TimeoutVoteCollection, VoteCollection,
};

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

    pub fn epoch(&self) -> &SimplifiedEpochContext {
        &self.epoch
    }

    pub fn active_slot(&self) -> (u64, u64) {
        (self.active_height, self.active_round)
    }

    pub fn highest_parent(&self) -> &SimplifiedFinalityParent {
        &self.highest_parent
    }

    pub fn locked_qc(&self) -> Option<&QuorumCertificateReference> {
        self.locked_qc.as_ref()
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
        Ok(transitions)
    }

    fn accept_verified_timeout_certificate(
        &mut self,
        certificate: SimplifiedTimeoutCertificate,
    ) -> PosyResult<Vec<ConsensusTransition>> {
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
        self.mandatory_carry = certificate.mandatory_carry_candidate()?;
        self.active_round = next_round;
        self.active_takeover_tc_id = Some(certificate_id);
        self.accepted_proposal = None;
        Ok(vec![
            ConsensusTransition::TimeoutCertified(certificate),
            ConsensusTransition::RoundAdvanced {
                height: self.active_height,
                round: self.active_round,
            },
        ])
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
        }
        Ok(ConsensusTransition::HeightAdvanced {
            height: self.active_height,
            round: self.active_round,
        })
    }
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
}
