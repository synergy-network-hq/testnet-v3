use super::schedule::{SimplifiedEpochContext, POSY_SIMPLIFIED_PROTOCOL_VERSION};
use super::{POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN, POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN};
use crate::crypto::aegis_pqvm::AegisPqvmVerifier;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqSignature, BlockId, CanonicalSerialize, ChainId, Epoch,
    Hash, Height, NetworkId, Round, ValidatorId, ValidatorRecord, ValidatorSet,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const POSY_SIMPLIFIED_OBJECT_SCHEMA_VERSION: u32 = 1;
pub const POSY_SIMPLIFIED_PROPOSAL_DOMAIN: &str = "PoSy/Consensus/v3/Proposal";
pub const POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN: &str = "PoSy/Consensus/v3/BlockVote";
pub const POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN: &str = "PoSy/Consensus/v3/TimeoutVote";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsensusObjectContext {
    pub schema_version: u32,
    pub chain_id: ChainId,
    pub network_id: NetworkId,
    pub protocol_version: String,
    pub epoch: Epoch,
    pub height: Height,
    pub round: Round,
    pub epoch_context_root: Hash,
    pub consensus_parameter_root: String,
    pub active_validator_set_root: Hash,
    pub validator_consensus_key_root: Hash,
    pub frozen_voting_weight_root: Hash,
}

impl ConsensusObjectContext {
    pub fn for_height(
        epoch_context: &SimplifiedEpochContext,
        height: Height,
        round: Round,
    ) -> Result<Self, String> {
        if !epoch_context.contains_height(height) {
            return Err("consensus object height is outside the epoch".to_string());
        }
        Ok(Self {
            schema_version: POSY_SIMPLIFIED_OBJECT_SCHEMA_VERSION,
            chain_id: epoch_context.chain_id,
            network_id: epoch_context.network_id.clone(),
            protocol_version: POSY_SIMPLIFIED_PROTOCOL_VERSION.to_string(),
            epoch: epoch_context.epoch,
            height,
            round,
            epoch_context_root: epoch_context.root()?,
            consensus_parameter_root: epoch_context.consensus_parameter_root.clone(),
            active_validator_set_root: epoch_context.active_validator_set_root,
            validator_consensus_key_root: epoch_context.validator_consensus_key_root,
            frozen_voting_weight_root: epoch_context.frozen_voting_weight_root,
        })
    }

    pub fn validate_against(&self, epoch_context: &SimplifiedEpochContext) -> Result<(), String> {
        if self.schema_version != POSY_SIMPLIFIED_OBJECT_SCHEMA_VERSION
            || self.chain_id != epoch_context.chain_id
            || self.network_id != epoch_context.network_id
            || self.protocol_version != POSY_SIMPLIFIED_PROTOCOL_VERSION
            || self.epoch != epoch_context.epoch
            || !epoch_context.contains_height(self.height)
            || self.epoch_context_root != epoch_context.root()?
            || self.consensus_parameter_root != epoch_context.consensus_parameter_root
            || self.active_validator_set_root != epoch_context.active_validator_set_root
            || self.validator_consensus_key_root != epoch_context.validator_consensus_key_root
            || self.frozen_voting_weight_root != epoch_context.frozen_voting_weight_root
        {
            return Err("consensus object does not match the frozen epoch context".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuorumCertificateReference {
    pub height: Height,
    pub block_id: BlockId,
    /// Stable certified-candidate identity. The proof round and takeover TC
    /// are deliberately absent: the exact same protected candidate may be
    /// re-enveloped after a timeout, while descendants must still converge on
    /// one parent reference.
    pub qc_id: Hash,
}

impl QuorumCertificateReference {
    pub fn validate(&self) -> Result<(), String> {
        if self.block_id.0.trim().is_empty() || self.qc_id.is_zero() {
            return Err("invalid quorum-certificate reference".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ParticipantSignature {
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct BlockVoteSigningPayload<'a> {
    context: &'a ConsensusObjectContext,
    block_id: &'a BlockId,
    parent_block_id: &'a BlockId,
    parent_qc: &'a QuorumCertificateReference,
    takeover_tc_id: Option<Hash>,
    protected_execution_root: Hash,
    validator_id: &'a ValidatorId,
    key_id: &'a AegisPqKeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BlockVote {
    pub context: ConsensusObjectContext,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub parent_qc: QuorumCertificateReference,
    pub takeover_tc_id: Option<Hash>,
    /// Exact BOC/reveal/protected-execution outcome validated before voting.
    pub protected_execution_root: Hash,
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

impl BlockVote {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&BlockVoteSigningPayload {
            context: &self.context,
            block_id: &self.block_id,
            parent_block_id: &self.parent_block_id,
            parent_qc: &self.parent_qc,
            takeover_tc_id: self.takeover_tc_id,
            protected_execution_root: self.protected_execution_root,
            validator_id: &self.validator_id,
            key_id: &self.key_id,
        })
        .map_err(|error| format!("serialize simplified block-vote transcript: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedQuorumCertificate {
    pub context: ConsensusObjectContext,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub parent_qc: QuorumCertificateReference,
    pub takeover_tc_id: Option<Hash>,
    pub protected_execution_root: Hash,
    pub participants: Vec<ParticipantSignature>,
}

/// Stable, signer-independent statement certified by a QC.
///
/// `context.round` is canonicalized to zero and takeover evidence is excluded
/// because those fields authorize one proof attempt, not the block/execution
/// result itself. `block_id` is the canonical protected block-body commitment;
/// `protected_execution_root` binds the independently recomputed ETDAG/BOC /
/// reveal execution outcome.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CertifiedCandidateSubject {
    pub context: ConsensusObjectContext,
    pub block_id: BlockId,
    pub parent_block_id: BlockId,
    pub parent_qc: QuorumCertificateReference,
    pub protected_execution_root: Hash,
}

impl CertifiedCandidateSubject {
    pub fn new(
        mut context: ConsensusObjectContext,
        block_id: BlockId,
        parent_block_id: BlockId,
        parent_qc: QuorumCertificateReference,
        protected_execution_root: Hash,
    ) -> Result<Self, String> {
        context.round = Round(0);
        let subject = Self {
            context,
            block_id,
            parent_block_id,
            parent_qc,
            protected_execution_root,
        };
        subject.validate()?;
        Ok(subject)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.parent_qc.validate()?;
        if self.context.round != Round(0)
            || self.block_id.0.trim().is_empty()
            || self.parent_block_id != self.parent_qc.block_id
            || self.parent_qc.height.0.checked_add(1) != Some(self.context.height.0)
            || self.protected_execution_root.is_zero()
        {
            return Err("invalid stable certified-candidate subject".to_string());
        }
        Ok(())
    }

    pub fn id(&self) -> Result<Hash, String> {
        self.validate()?;
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_CERTIFIED_CANDIDATE_V1",
            &self.canonical_bytes()?,
        ))
    }
}

/// Signer-independent identity of the statement certified by a QC.
///
/// Honest nodes may first observe different valid 4-of-5 subsets, and
/// ML-DSA signatures are not required to be byte-identical. Consensus
/// references therefore name the certified statement, not one arbitrary
/// proof bundle. Every participant proof remains independently verified by
/// `SimplifiedQuorumCertificate::verify` before this identity has authority.
impl SimplifiedQuorumCertificate {
    pub fn from_votes(mut votes: Vec<BlockVote>) -> Result<Self, String> {
        let first = votes
            .first()
            .cloned()
            .ok_or_else(|| "cannot assemble a QC without votes".to_string())?;
        if votes.iter().any(|vote| {
            vote.context != first.context
                || vote.block_id != first.block_id
                || vote.parent_block_id != first.parent_block_id
                || vote.parent_qc != first.parent_qc
                || vote.takeover_tc_id != first.takeover_tc_id
                || vote.protected_execution_root != first.protected_execution_root
        }) {
            return Err("QC votes do not share one canonical transcript".to_string());
        }
        votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let participants = votes
            .into_iter()
            .map(|vote| ParticipantSignature {
                validator_id: vote.validator_id,
                key_id: vote.key_id,
                signature: vote.signature,
            })
            .collect();
        Ok(Self {
            context: first.context,
            block_id: first.block_id,
            parent_block_id: first.parent_block_id,
            parent_qc: first.parent_qc,
            takeover_tc_id: first.takeover_tc_id,
            protected_execution_root: first.protected_execution_root,
            participants,
        })
    }

    pub fn reference(&self) -> Result<QuorumCertificateReference, String> {
        Ok(QuorumCertificateReference {
            height: self.context.height,
            block_id: self.block_id.clone(),
            qc_id: self.id()?,
        })
    }

    pub fn subject(&self) -> Result<CertifiedCandidateSubject, String> {
        CertifiedCandidateSubject::new(
            self.context.clone(),
            self.block_id.clone(),
            self.parent_block_id.clone(),
            self.parent_qc.clone(),
            self.protected_execution_root,
        )
    }

    pub fn id(&self) -> Result<Hash, String> {
        self.subject()?.id()
    }

    pub fn canonicalized(&self) -> Self {
        let mut certificate = self.clone();
        certificate
            .participants
            .sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        certificate
    }

    pub fn verify<V: ConsensusSignatureVerifier>(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<VerifiedQuorum, String> {
        self.context.validate_against(epoch_context)?;
        self.parent_qc.validate()?;
        if self.block_id.0.trim().is_empty()
            || self.parent_block_id.0.trim().is_empty()
            || self.parent_block_id != self.parent_qc.block_id
            || self.parent_qc.height.0.checked_add(1) != Some(self.context.height.0)
            || self.takeover_tc_id.is_some_and(Hash::is_zero)
            || self.protected_execution_root.is_zero()
        {
            return Err("invalid simplified QC ancestry or takeover evidence".to_string());
        }
        require_canonical_participants(&self.participants)?;
        let active_set = validator_set.active_for_epoch(self.context.epoch);
        epoch_context.validate_against(&active_set)?;
        let mut signed_weight = 0u128;
        for participant in &self.participants {
            let record = validator_record(&active_set, &participant.validator_id)?;
            if participant.key_id != record.consensus_public_key.key_id {
                return Err(format!(
                    "QC signer {} used the wrong consensus key",
                    participant.validator_id.0
                ));
            }
            let vote = BlockVote {
                context: self.context.clone(),
                block_id: self.block_id.clone(),
                parent_block_id: self.parent_block_id.clone(),
                parent_qc: self.parent_qc.clone(),
                takeover_tc_id: self.takeover_tc_id,
                protected_execution_root: self.protected_execution_root,
                validator_id: participant.validator_id.clone(),
                key_id: participant.key_id.clone(),
                signature: participant.signature.clone(),
            };
            verifier.verify_consensus_signature(
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &vote.signing_bytes()?,
                record,
                &participant.key_id,
                self.context.epoch,
                &participant.signature,
            )?;
            signed_weight = signed_weight
                .checked_add(u128::from(record.voting_weight))
                .ok_or_else(|| "QC signed-weight overflow".to_string())?;
        }
        verify_strict_dual_quorum(
            self.participants.len(),
            active_set.validators.len(),
            signed_weight,
            total_weight(&active_set)?,
        )
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TimeoutVoteSigningPayload<'a> {
    context: &'a ConsensusObjectContext,
    lease_index: u64,
    timed_out_proposer: &'a ValidatorId,
    highest_qc: &'a QuorumCertificateReference,
    previous_tc_id: Option<Hash>,
    last_voted_candidate: &'a Option<CertifiedCandidateSubject>,
    validator_id: &'a ValidatorId,
    key_id: &'a AegisPqKeyId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutVote {
    pub context: ConsensusObjectContext,
    pub lease_index: u64,
    pub timed_out_proposer: ValidatorId,
    pub highest_qc: QuorumCertificateReference,
    pub previous_tc_id: Option<Hash>,
    /// Stable candidate this signer has durably voted for at this height, if
    /// any. A heterogeneous TC uses these signed reports to carry forward any
    /// candidate that could already have a hidden QC.
    pub last_voted_candidate: Option<CertifiedCandidateSubject>,
    pub validator_id: ValidatorId,
    pub key_id: AegisPqKeyId,
    pub signature: AegisPqSignature,
}

impl TimeoutVote {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&TimeoutVoteSigningPayload {
            context: &self.context,
            lease_index: self.lease_index,
            timed_out_proposer: &self.timed_out_proposer,
            highest_qc: &self.highest_qc,
            previous_tc_id: self.previous_tc_id,
            last_voted_candidate: &self.last_voted_candidate,
            validator_id: &self.validator_id,
            key_id: &self.key_id,
        })
        .map_err(|error| format!("serialize simplified timeout-vote transcript: {error}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SimplifiedTimeoutCertificate {
    pub context: ConsensusObjectContext,
    pub lease_index: u64,
    pub timed_out_proposer: ValidatorId,
    pub previous_tc_id: Option<Hash>,
    /// Canonical signed reports. Unlike the old homogeneous TC, replicas with
    /// different highest QCs can form one proof after a partial QC delivery.
    pub reports: Vec<TimeoutVote>,
    /// Deduplicated full proofs for every non-anchor highest-QC reference in
    /// `reports`. This makes a TC self-verifying for a lagging receiver.
    pub highest_qc_proofs: Vec<SimplifiedQuorumCertificate>,
}

/// Signer-independent identity of the abandonment statement certified by a
/// TC, so independently formed strict-quorum subsets converge on the same
/// predecessor for the next takeover round.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TimeoutCertificateSubject {
    context: ConsensusObjectContext,
    lease_index: u64,
    timed_out_proposer: ValidatorId,
    previous_tc_id: Option<Hash>,
}

impl SimplifiedTimeoutCertificate {
    pub fn from_votes(votes: Vec<TimeoutVote>) -> Result<Self, String> {
        Self::from_votes_with_qc_proofs(votes, Vec::new())
    }

    pub fn from_votes_with_qc_proofs(
        mut votes: Vec<TimeoutVote>,
        mut highest_qc_proofs: Vec<SimplifiedQuorumCertificate>,
    ) -> Result<Self, String> {
        let first = votes
            .first()
            .cloned()
            .ok_or_else(|| "cannot assemble a TC without timeout votes".to_string())?;
        if votes.iter().any(|vote| {
            vote.context != first.context
                || vote.lease_index != first.lease_index
                || vote.timed_out_proposer != first.timed_out_proposer
                || vote.previous_tc_id != first.previous_tc_id
        }) {
            return Err("TC votes do not close one canonical timeout slot".to_string());
        }
        votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let mut proofs_by_subject = std::collections::BTreeMap::new();
        for proof in highest_qc_proofs {
            proofs_by_subject.entry(proof.id()?).or_insert(proof);
        }
        highest_qc_proofs = proofs_by_subject.into_values().collect();
        Ok(Self {
            context: first.context,
            lease_index: first.lease_index,
            timed_out_proposer: first.timed_out_proposer,
            previous_tc_id: first.previous_tc_id,
            reports: votes,
            highest_qc_proofs,
        })
    }

    pub fn canonicalized(&self) -> Self {
        let mut certificate = self.clone();
        certificate
            .reports
            .sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        certificate.highest_qc_proofs.sort_by(|left, right| {
            (
                left.context.height.0,
                left.id().unwrap_or_else(|_| Hash::zero()).0,
                left.context.round.0,
            )
                .cmp(&(
                    right.context.height.0,
                    right.id().unwrap_or_else(|_| Hash::zero()).0,
                    right.context.round.0,
                ))
        });
        certificate
    }

    pub fn highest_qc(&self) -> Result<QuorumCertificateReference, String> {
        self.reports
            .iter()
            .map(|report| report.highest_qc.clone())
            .max_by(|left, right| {
                (left.height.0, left.qc_id.0).cmp(&(right.height.0, right.qc_id.0))
            })
            .ok_or_else(|| "timeout certificate has no signed reports".to_string())
    }

    /// Returns the unique two-report stable candidate that every successor
    /// must re-envelope under the declared single-fault liveness model. For
    /// q=floor(2n/3)+1 and every supported n>=5, a hidden q-vote QC intersects
    /// every q-report TC in at least two honest reporters after excluding the
    /// one faulty validator. Multiple two-report candidates are inconsistent
    /// with reliable delivery and are rejected fail closed.
    pub fn mandatory_carry_candidate(&self) -> Result<Option<CertifiedCandidateSubject>, String> {
        let mut counts =
            std::collections::BTreeMap::<Hash, (usize, CertifiedCandidateSubject)>::new();
        for report in &self.reports {
            if let Some(candidate) = &report.last_voted_candidate {
                let id = candidate.id()?;
                let entry = counts.entry(id).or_insert_with(|| (0, candidate.clone()));
                entry.0 = entry.0.saturating_add(1);
            }
        }
        let carried = counts
            .into_values()
            .filter(|(count, _)| *count >= 2)
            .map(|(_, candidate)| candidate)
            .collect::<Vec<_>>();
        match carried.as_slice() {
            [] => Ok(None),
            [candidate] => Ok(Some(candidate.clone())),
            _ => Err("TC reports multiple f+1 carry-forward candidates".to_string()),
        }
    }

    pub fn id(&self) -> Result<Hash, String> {
        Ok(Hash::from_domain_bytes(
            "SYNERGY_POSY_SIMPLIFIED_TC_SUBJECT_V1",
            &TimeoutCertificateSubject {
                context: self.context.clone(),
                lease_index: self.lease_index,
                timed_out_proposer: self.timed_out_proposer.clone(),
                previous_tc_id: self.previous_tc_id,
            }
            .canonical_bytes()?,
        ))
    }

    pub fn verify<V: ConsensusSignatureVerifier>(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validator_set: &ValidatorSet,
        verifier: &V,
    ) -> Result<VerifiedQuorum, String> {
        self.context.validate_against(epoch_context)?;
        if self.lease_index != epoch_context.lease_index(self.context.height)?
            || self.previous_tc_id.is_some_and(Hash::is_zero)
            || (self.context.round.0 == 0) != self.previous_tc_id.is_none()
            || epoch_context.authorized_proposer(self.context.height, self.context.round.0)?
                != &self.timed_out_proposer
        {
            return Err("invalid timeout lease, round, predecessor, or proposer".to_string());
        }
        if self.reports.is_empty()
            || self
                .reports
                .windows(2)
                .any(|pair| pair[0].validator_id >= pair[1].validator_id)
        {
            return Err("TC reports must be nonempty, unique, and canonically ordered".to_string());
        }
        self.mandatory_carry_candidate()?;
        let active_set = validator_set.active_for_epoch(self.context.epoch);
        epoch_context.validate_against(&active_set)?;
        for proof in &self.highest_qc_proofs {
            proof.verify(epoch_context, validator_set, verifier)?;
        }
        let referenced_proof_ids = self
            .reports
            .iter()
            .map(|report| report.highest_qc.qc_id)
            .collect::<BTreeSet<_>>();
        if self.highest_qc_proofs.iter().any(|proof| {
            proof
                .id()
                .map_or(true, |id| !referenced_proof_ids.contains(&id))
        }) {
            return Err("TC contains an unreferenced highest-QC proof".to_string());
        }
        let mut signed_weight = 0u128;
        for report in &self.reports {
            if report.context != self.context
                || report.lease_index != self.lease_index
                || report.timed_out_proposer != self.timed_out_proposer
                || report.previous_tc_id != self.previous_tc_id
            {
                return Err("TC report does not match the timeout closure".to_string());
            }
            report.highest_qc.validate()?;
            if report.highest_qc.height.0 >= self.context.height.0 {
                return Err("timeout report carries a future highest QC".to_string());
            }
            if let Some(candidate) = &report.last_voted_candidate {
                candidate.validate()?;
                if candidate.context.height != self.context.height
                    || candidate.context.epoch_context_root != self.context.epoch_context_root
                {
                    return Err(
                        "timeout report carry candidate is from another height/context".to_string(),
                    );
                }
            }
            let is_epoch_anchor = report.highest_qc.height.0.checked_add(1)
                == Some(epoch_context.epoch_start_height.0)
                && epoch_context
                    .v2_boundary_anchor
                    .as_ref()
                    .is_none_or(|anchor| {
                        report.highest_qc.block_id == anchor.block_id
                            && report.highest_qc.qc_id == anchor.qc_finality_context_root
                    });
            let has_proof = self
                .highest_qc_proofs
                .iter()
                .any(|proof| proof.reference().ok().as_ref() == Some(&report.highest_qc));
            // `verify` has no durable-state resolver, so every non-anchor
            // reference must be self-contained. Callers that already hold a
            // proof still supply it here; anchor references are committed by
            // the frozen epoch context and need no embedded QC.
            if !is_epoch_anchor && !has_proof {
                return Err("TC omits a full proof for a reported highest QC".to_string());
            }
            let record = validator_record(&active_set, &report.validator_id)?;
            if report.key_id != record.consensus_public_key.key_id {
                return Err(format!(
                    "TC signer {} used the wrong consensus key",
                    report.validator_id.0
                ));
            }
            verifier.verify_consensus_signature(
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                &report.signing_bytes()?,
                record,
                &report.key_id,
                self.context.epoch,
                &report.signature,
            )?;
            signed_weight = signed_weight
                .checked_add(u128::from(record.voting_weight))
                .ok_or_else(|| "TC signed-weight overflow".to_string())?;
        }
        verify_strict_dual_quorum(
            self.reports.len(),
            active_set.validators.len(),
            signed_weight,
            total_weight(&active_set)?,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedQuorum {
    pub distinct_signer_count: usize,
    pub signed_weight: u128,
    pub total_weight: u128,
}

pub trait ConsensusSignatureVerifier {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        signature: &AegisPqSignature,
    ) -> Result<(), String>;
}

impl ConsensusSignatureVerifier for AegisPqvmVerifier {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &AegisPqKeyId,
        epoch: Epoch,
        signature: &AegisPqSignature,
    ) -> Result<(), String> {
        let role = match domain {
            POSY_SIMPLIFIED_PROPOSAL_DOMAIN => AegisPqKeyRole::ConsensusProposer,
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN
            | POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN
            | POSY_SIMPLIFIED_PROPOSAL_ECHO_DOMAIN
            | POSY_SIMPLIFIED_PROPOSAL_READY_DOMAIN => AegisPqKeyRole::ConsensusVote,
            _ => return Err(format!("unsupported simplified consensus domain {domain}")),
        };
        self.verify_domain_signature(
            domain,
            payload,
            &validator.validator_uma_id.0,
            key_id,
            epoch,
            role,
            signature,
        )
        .map_err(|error| error.to_string())
    }
}

pub fn verify_strict_dual_quorum(
    distinct_signer_count: usize,
    validator_count: usize,
    signed_weight: u128,
    total_weight: u128,
) -> Result<VerifiedQuorum, String> {
    if validator_count == 0 || total_weight == 0 {
        return Err("quorum denominator is zero".to_string());
    }
    let signer_count = u128::try_from(distinct_signer_count)
        .map_err(|_| "distinct signer count exceeds u128".to_string())?;
    let total_count =
        u128::try_from(validator_count).map_err(|_| "validator count exceeds u128".to_string())?;
    let three_signers = signer_count
        .checked_mul(3)
        .ok_or_else(|| "distinct signer quorum multiplication overflow".to_string())?;
    let two_validators = total_count
        .checked_mul(2)
        .ok_or_else(|| "validator count quorum multiplication overflow".to_string())?;
    if three_signers <= two_validators {
        return Err(format!(
            "strict distinct-signer quorum failed: {distinct_signer_count} of {validator_count}"
        ));
    }
    let three_signed_weight = signed_weight
        .checked_mul(3)
        .ok_or_else(|| "signed weight quorum multiplication overflow".to_string())?;
    let two_total_weight = total_weight
        .checked_mul(2)
        .ok_or_else(|| "total weight quorum multiplication overflow".to_string())?;
    if three_signed_weight <= two_total_weight {
        return Err(format!(
            "strict frozen-weight quorum failed: {signed_weight} of {total_weight}"
        ));
    }
    Ok(VerifiedQuorum {
        distinct_signer_count,
        signed_weight,
        total_weight,
    })
}

fn require_canonical_participants(participants: &[ParticipantSignature]) -> Result<(), String> {
    if participants.is_empty() {
        return Err("certificate has no participants".to_string());
    }
    if participants
        .windows(2)
        .any(|pair| pair[0].validator_id >= pair[1].validator_id)
    {
        return Err(
            "certificate participants are duplicate or not canonically ordered".to_string(),
        );
    }
    let unique_keys = participants
        .iter()
        .map(|participant| &participant.key_id)
        .collect::<BTreeSet<_>>();
    if unique_keys.len() != participants.len() {
        return Err("certificate contains duplicate consensus keys".to_string());
    }
    Ok(())
}

fn validator_record<'a>(
    validator_set: &'a ValidatorSet,
    validator_id: &ValidatorId,
) -> Result<&'a ValidatorRecord, String> {
    validator_set
        .validators
        .iter()
        .find(|validator| &validator.validator_id == validator_id)
        .ok_or_else(|| format!("certificate signer {} is not active", validator_id.0))
}

fn total_weight(validator_set: &ValidatorSet) -> Result<u128, String> {
    validator_set
        .validators
        .iter()
        .try_fold(0u128, |total, validator| {
            total
                .checked_add(u128::from(validator.voting_weight))
                .ok_or_else(|| "total frozen voting weight overflow".to_string())
        })
}
