use std::collections::{BTreeMap, BTreeSet};

use crate::{AvailabilityCertificate, AvailabilityVote, EtdagDigest, EtdagError};

#[derive(Debug)]
pub struct AvailabilityCollector {
    context_root: EtdagDigest,
    vertex_id: EtdagDigest,
    members: BTreeSet<String>,
    votes: BTreeMap<String, AvailabilityVote>,
}

impl AvailabilityCollector {
    pub fn new(
        context_root: EtdagDigest,
        vertex_id: EtdagDigest,
        members: BTreeSet<String>,
    ) -> Result<Self, EtdagError> {
        context_root.validate()?;
        vertex_id.validate()?;
        if members.is_empty() {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(Self {
            context_root,
            vertex_id,
            members,
            votes: BTreeMap::new(),
        })
    }
    pub fn add_verified(&mut self, vote: AvailabilityVote) -> Result<(), EtdagError> {
        vote.validate()?;
        if vote.context_root != self.context_root || vote.vertex_id != self.vertex_id {
            return Err(EtdagError::ContextMismatch);
        }
        if !self.members.contains(&vote.validator_id) {
            return Err(EtdagError::UnauthorizedValidator(vote.validator_id));
        }
        if self.votes.contains_key(&vote.validator_id) {
            return Err(EtdagError::DuplicateShare("availability vote".into()));
        }
        self.votes.insert(vote.validator_id.clone(), vote);
        Ok(())
    }
    pub fn certificate(&self) -> Result<AvailabilityCertificate, EtdagError> {
        AvailabilityCertificate::from_votes(
            self.context_root.clone(),
            self.vertex_id.clone(),
            self.votes.values().cloned().collect(),
            self.members.len(),
        )
    }
}
