use serde::{Deserialize, Serialize};

use crate::{DeterministicProtectedBatch, EtdagDigest, EtdagError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicProtectedExecutionInput {
    pub material_version: u32,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub protected_batch_root: EtdagDigest,
    pub ordered_vertex_ids: Vec<EtdagDigest>,
    pub reveal_transcript_root: EtdagDigest,
}

impl DeterministicProtectedExecutionInput {
    pub fn from_batch(
        batch: &DeterministicProtectedBatch,
        vertex_envelopes: &std::collections::BTreeMap<EtdagDigest, EtdagDigest>,
        reveal_transcript_root: EtdagDigest,
    ) -> Result<Self, EtdagError> {
        batch.validate()?;
        reveal_transcript_root.validate()?;
        let by_envelope: std::collections::BTreeMap<_, _> = vertex_envelopes
            .iter()
            .map(|(vertex, envelope)| (envelope, vertex))
            .collect();
        if by_envelope.len() != vertex_envelopes.len() {
            return Err(EtdagError::DuplicateEnvelope);
        }
        let ordered_vertex_ids = batch
            .ordered_transaction_ids
            .iter()
            .map(|envelope| {
                by_envelope
                    .get(envelope)
                    .map(|vertex| (*vertex).clone())
                    .ok_or_else(|| EtdagError::MissingArtifact(envelope.0.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            material_version: 1,
            context_root: batch.context_root.clone(),
            target_height: batch.target_height,
            protected_batch_root: batch.protected_batch_root.clone(),
            ordered_vertex_ids,
            reveal_transcript_root,
        })
    }

    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context_root.validate()?;
        self.protected_batch_root.validate()?;
        self.reveal_transcript_root.validate()?;
        if self.material_version != 1 || self.target_height == 0 {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let mut unique = std::collections::BTreeSet::new();
        if self
            .ordered_vertex_ids
            .iter()
            .any(|vertex| vertex.validate().is_err() || !unique.insert(vertex))
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}
