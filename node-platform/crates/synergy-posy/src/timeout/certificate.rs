use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, validate_timeout_vote, verify_strict_dual_quorum, CertifiedCandidateSubject,
    ConsensusObjectContext, ConsensusSignatureVerifier, FrozenValidatorRegistry, PosyError,
    PosyResult, SimplifiedEpochContext, SimplifiedFinalityParent, SimplifiedQuorumCertificate,
    TimeoutVote,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimplifiedTimeoutCertificate {
    pub context: ConsensusObjectContext,
    pub lease_index: u64,
    pub timed_out_proposer: String,
    pub previous_tc_id: Option<String>,
    pub reports: Vec<TimeoutVote>,
    pub highest_qc_proofs: Vec<SimplifiedQuorumCertificate>,
}

impl SimplifiedTimeoutCertificate {
    pub fn from_votes(reports: Vec<TimeoutVote>) -> PosyResult<Self> {
        Self::from_votes_with_qc_proofs(reports, Vec::new())
    }

    pub fn from_votes_with_qc_proofs(
        mut reports: Vec<TimeoutVote>,
        highest_qc_proofs: Vec<SimplifiedQuorumCertificate>,
    ) -> PosyResult<Self> {
        let first = reports
            .first()
            .cloned()
            .ok_or_else(|| PosyError::invalid("cannot assemble TC without timeout votes"))?;
        if reports.iter().any(|report| {
            report.context != first.context
                || report.lease_index != first.lease_index
                || report.timed_out_proposer != first.timed_out_proposer
                || report.previous_tc_id != first.previous_tc_id
        }) {
            return Err(PosyError::invalid(
                "TC reports do not close one timeout slot",
            ));
        }
        reports.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        let mut proofs = BTreeMap::new();
        for proof in highest_qc_proofs {
            proofs.entry(proof.id()?).or_insert(proof);
        }
        let mut highest_qc_proofs = proofs.into_values().collect::<Vec<_>>();
        highest_qc_proofs.sort_by(|left, right| {
            (left.context.height, left.id().ok(), left.context.round).cmp(&(
                right.context.height,
                right.id().ok(),
                right.context.round,
            ))
        });
        Ok(Self {
            context: first.context,
            lease_index: first.lease_index,
            timed_out_proposer: first.timed_out_proposer,
            previous_tc_id: first.previous_tc_id,
            reports,
            highest_qc_proofs,
        })
    }

    pub fn id(&self) -> PosyResult<String> {
        canonical_hash(
            "SYNERGY_POSY_SIMPLIFIED_TC_SUBJECT_V1",
            &(
                self.context.clone(),
                self.lease_index,
                self.timed_out_proposer.clone(),
                self.previous_tc_id.clone(),
            ),
        )
    }

    pub fn highest_parent(&self) -> PosyResult<SimplifiedFinalityParent> {
        self.reports
            .iter()
            .map(|report| report.highest_parent.clone())
            .max_by(|left, right| {
                (left.height(), left.reference_id()).cmp(&(right.height(), right.reference_id()))
            })
            .ok_or_else(|| PosyError::invalid("timeout certificate has no reports"))
    }

    pub fn mandatory_carry_candidate(&self) -> PosyResult<Option<CertifiedCandidateSubject>> {
        let mut candidates = BTreeMap::<String, (usize, CertifiedCandidateSubject)>::new();
        for report in &self.reports {
            if let Some(candidate) = &report.last_voted_candidate {
                let entry = candidates
                    .entry(candidate.id()?)
                    .or_insert_with(|| (0, candidate.clone()));
                entry.0 = entry.0.saturating_add(1);
            }
        }
        let carried = candidates
            .into_values()
            .filter(|(count, _)| *count >= 2)
            .map(|(_, candidate)| candidate)
            .collect::<Vec<_>>();
        match carried.as_slice() {
            [] => Ok(None),
            [candidate] => Ok(Some(candidate.clone())),
            _ => Err(PosyError::Conflict(
                "multiple mandatory timeout carry candidates".into(),
            )),
        }
    }

    pub fn verify(
        &self,
        epoch_context: &SimplifiedEpochContext,
        validators: &FrozenValidatorRegistry,
        verifier: &impl ConsensusSignatureVerifier,
    ) -> PosyResult<()> {
        self.context.validate_against(epoch_context)?;
        if self.lease_index != epoch_context.lease_index(self.context.height)?
            || self.timed_out_proposer
                != epoch_context.authorized_proposer(self.context.height, self.context.round)?
            || (self.context.round == 0) != self.previous_tc_id.is_none()
            || self
                .reports
                .windows(2)
                .any(|pair| pair[0].validator_id >= pair[1].validator_id)
        {
            return Err(PosyError::invalid("invalid timeout certificate closure"));
        }
        self.mandatory_carry_candidate()?;
        let mut proofs = BTreeMap::new();
        for proof in &self.highest_qc_proofs {
            proof.verify(epoch_context, validators, verifier)?;
            if proofs.insert(proof.id()?, proof).is_some() {
                return Err(PosyError::invalid(
                    "timeout certificate repeats a highest-QC proof",
                ));
            }
        }
        let referenced = self
            .reports
            .iter()
            .filter_map(|report| report.highest_parent.quorum_certificate_reference())
            .map(|reference| reference.qc_id)
            .collect::<BTreeSet<_>>();
        if proofs.keys().any(|id| !referenced.contains(id)) {
            return Err(PosyError::invalid(
                "timeout certificate contains an unreferenced highest-QC proof",
            ));
        }
        let mut signers = Vec::new();
        let mut keys = BTreeSet::new();
        for report in &self.reports {
            if report.context != self.context
                || report.lease_index != self.lease_index
                || report.timed_out_proposer != self.timed_out_proposer
                || report.previous_tc_id != self.previous_tc_id
            {
                return Err(PosyError::invalid(
                    "timeout report does not match certificate closure",
                ));
            }
            if !keys.insert(&report.key_id) {
                return Err(PosyError::invalid("duplicate timeout signer key"));
            }
            validate_timeout_vote(report, epoch_context, validators, verifier)?;
            if let Some(reference) = report.highest_parent.quorum_certificate_reference() {
                let Some(proof) = proofs.get(&reference.qc_id) else {
                    return Err(PosyError::invalid(
                        "timeout certificate omits a reported highest-QC proof",
                    ));
                };
                if proof.reference()? != reference {
                    return Err(PosyError::invalid(
                        "timeout highest-QC proof does not match its report",
                    ));
                }
            }
            signers.push(report.validator_id.clone());
        }
        verify_strict_dual_quorum(&validators.quorum_validators(), &signers)
            .map_err(|error| PosyError::invalid(format!("timeout quorum failed: {error:?}")))?;
        Ok(())
    }
}
