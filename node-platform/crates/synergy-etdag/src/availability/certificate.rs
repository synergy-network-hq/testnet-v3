use serde::{Deserialize, Serialize};

use crate::{AvailabilityVote, EtdagDigest, EtdagError};

pub fn certificate_quorum(cluster_size: usize) -> Result<usize, EtdagError> {
    if cluster_size == 0 {
        return Err(EtdagError::ContextMismatch);
    }
    Ok((2 * cluster_size) / 3 + 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailabilityCertificate {
    pub context_root: EtdagDigest,
    pub vertex_id: EtdagDigest,
    pub votes: Vec<AvailabilityVote>,
}

impl AvailabilityCertificate {
    pub fn from_votes(
        context_root: EtdagDigest,
        vertex_id: EtdagDigest,
        mut votes: Vec<AvailabilityVote>,
        cluster_size: usize,
    ) -> Result<Self, EtdagError> {
        let required = certificate_quorum(cluster_size)?;
        votes.sort_by(|left, right| left.validator_id.cmp(&right.validator_id));
        if votes.len() < required {
            return Err(EtdagError::InsufficientAvailability {
                signed: votes.len(),
                required,
            });
        }
        if votes
            .windows(2)
            .any(|pair| pair[0].validator_id == pair[1].validator_id)
            || votes.iter().any(|vote| {
                vote.context_root != context_root
                    || vote.vertex_id != vertex_id
                    || vote.validate().is_err()
            })
        {
            return Err(EtdagError::InvalidEnvelope(
                "invalid availability certificate votes".into(),
            ));
        }
        Ok(Self {
            context_root,
            vertex_id,
            votes,
        })
    }
}
