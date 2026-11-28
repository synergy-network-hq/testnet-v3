//! Bounded collection of original ordinary approvals for one exact header.
//! Collection grants neither signing permission nor finality.
use std::collections::BTreeMap;

use super::{
    certificate::authenticated_members, R1Approval, R1AuthorityMember, R1ConsensusVerifier,
    R1Header, R1ProofError, R1QuorumCertificate, Result, VerifiedR1QuorumCertificate,
};

/// A replaceable collector with a frozen, authenticated electorate.
/// The native verifier still owns opportunity, ancestry and execution checks.
pub struct R1ApprovalCollector {
    header: R1Header,
    members: Vec<R1AuthorityMember>,
    approvals: BTreeMap<u32, R1Approval>,
}
impl R1ApprovalCollector {
    /// Authenticate and independently validate the exact proposal before keeping votes.
    pub fn new(header: R1Header, verifier: &impl R1ConsensusVerifier) -> Result<Self> {
        header.validate_shape()?;
        let members = authenticated_members(&header, verifier)?;
        verifier.verify_proposal_and_execution(&header)?;
        Ok(Self {
            header,
            members,
            approvals: BTreeMap::new(),
        })
    }
    /// Number of distinct verified original approvals; reconnects add no weight.
    pub fn approval_count(&self) -> usize {
        self.approvals.len()
    }
    /// Validate one original signature before insertion. Return a checked QC only
    /// when the SAME distinct signer set satisfies both frozen quorum predicates.
    /// The complete proposal and original signatures are rechecked at emission.
    pub fn accept(
        &mut self,
        approval: R1Approval,
        verifier: &impl R1ConsensusVerifier,
    ) -> Result<Option<VerifiedR1QuorumCertificate>> {
        if authenticated_members(&self.header, verifier)? != self.members {
            return Err(R1ProofError::Authority);
        }
        let member = self
            .members
            .get(approval.member_index as usize)
            .ok_or(R1ProofError::Signer)?;
        if approval.key_version != member.key_version
            || approval.signature.len() != member.signature_bytes
        {
            return Err(R1ProofError::Signature);
        }
        let subject = R1QuorumCertificate {
            header: self.header.clone(),
            approvals: Vec::new(),
        };
        verifier.verify_approval(
            member,
            &subject.approval_message(member)?,
            &approval.signature,
        )?;
        // Alternate valid signature bytes for this identical message are not a
        // second approval. Keep the first original bytes, never overwrite them.
        self.approvals
            .entry(approval.member_index)
            .or_insert(approval);
        let frozen: Vec<_> = self
            .members
            .iter()
            .enumerate()
            .map(|(i, m)| crate::FrozenValidator {
                validator_id: i.to_string(),
                frozen_voting_weight: m.weight,
            })
            .collect();
        let signers: Vec<_> = self.approvals.keys().map(u32::to_string).collect();
        if crate::verify_strict_dual_quorum(&frozen, &signers).is_err() {
            return Ok(None);
        }
        let approvals = self.approvals.values().cloned().collect();
        R1QuorumCertificate::assemble(self.header.clone(), approvals, verifier).map(Some)
    }
}
