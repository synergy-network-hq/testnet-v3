use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    reveal::RevealedTransaction, DeterministicProtectedExecutionInput, EtdagDigest, EtdagError,
    ProtectedRevealAuthorization, TargetAdmissionContextV3,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedTransaction {
    pub vertex_id: EtdagDigest,
    pub envelope_id: EtdagDigest,
    pub content_blind_order_key: EtdagDigest,
    pub reveal_authorization: ProtectedRevealAuthorization,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedProtectedBatch {
    pub context: TargetAdmissionContextV3,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub protected_batch_root: EtdagDigest,
    pub reveal_transcript_root: EtdagDigest,
    pub transactions: Vec<PreparedTransaction>,
}

impl PreparedProtectedBatch {
    pub fn validate(&self) -> Result<(), EtdagError> {
        self.context.validate()?;
        self.context_root.validate()?;
        self.protected_batch_root.validate()?;
        self.reveal_transcript_root.validate()?;
        if self.context.root()? != self.context_root
            || self.context.target_height != self.target_height
            || self.transactions.is_empty()
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let mut vertices = std::collections::BTreeSet::new();
        let mut envelopes = std::collections::BTreeSet::new();
        let mut order_keys = std::collections::BTreeSet::new();
        let mut previous: Option<&EtdagDigest> = None;
        for transaction in &self.transactions {
            transaction.vertex_id.validate()?;
            transaction.envelope_id.validate()?;
            transaction.content_blind_order_key.validate()?;
            transaction.reveal_authorization.validate()?;
            if transaction.plaintext.is_empty()
                || transaction.reveal_authorization.context_root != self.context_root
                || transaction.reveal_authorization.target_height != self.target_height
                || transaction.reveal_authorization.protected_batch_root
                    != self.protected_batch_root
                || !vertices.insert(&transaction.vertex_id)
                || !envelopes.insert(&transaction.envelope_id)
                || !order_keys.insert(&transaction.content_blind_order_key)
                || previous.is_some_and(|value| value >= &transaction.content_blind_order_key)
            {
                return Err(EtdagError::InvalidExecutionInput);
            }
            previous = Some(&transaction.content_blind_order_key);
        }
        Ok(())
    }
}

pub fn prepare_deterministic_batch(
    context: TargetAdmissionContextV3,
    input: &DeterministicProtectedExecutionInput,
    vertex_envelopes: &BTreeMap<EtdagDigest, EtdagDigest>,
    revealed: &[RevealedTransaction],
) -> Result<PreparedProtectedBatch, EtdagError> {
    input.validate()?;
    context.validate()?;
    if context.root()? != input.context_root || context.target_height != input.target_height {
        return Err(EtdagError::ContextMismatch);
    }
    if vertex_envelopes.len() != input.ordered_vertex_ids.len()
        || revealed.len() != input.ordered_vertex_ids.len()
    {
        return Err(EtdagError::InvalidExecutionInput);
    }

    let mut by_envelope = BTreeMap::new();
    let mut transcript_entries = Vec::with_capacity(revealed.len());
    for transaction in revealed {
        if by_envelope
            .insert(transaction.envelope_id().clone(), transaction)
            .is_some()
        {
            return Err(EtdagError::DuplicateEnvelope);
        }
        transcript_entries.push((
            transaction.envelope_id().clone(),
            transaction.transcript_root().clone(),
        ));
    }
    transcript_entries.sort();
    let transcript_root = EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_BATCH_REVEAL_TRANSCRIPTS_V1",
        &transcript_entries,
    )?;
    if transcript_root != input.reveal_transcript_root {
        return Err(EtdagError::UnauthorizedReveal);
    }

    let mut transactions = Vec::with_capacity(input.ordered_vertex_ids.len());
    for (order_index, vertex_id) in input.ordered_vertex_ids.iter().enumerate() {
        let envelope_id = vertex_envelopes
            .get(vertex_id)
            .ok_or_else(|| EtdagError::MissingArtifact(vertex_id.0.clone()))?;
        let transaction = by_envelope
            .get(envelope_id)
            .ok_or_else(|| EtdagError::MissingArtifact(envelope_id.0.clone()))?;
        if transaction.plaintext().is_empty() {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let order_hash = EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_CERTIFIED_ORDER_POSITION_V1",
            &(
                input.context_root.clone(),
                input.target_height,
                order_index,
                vertex_id,
            ),
        )?;
        let order_key = EtdagDigest(format!("{:016x}{}", order_index, &order_hash.0[16..]));
        transactions.push(PreparedTransaction {
            vertex_id: vertex_id.clone(),
            envelope_id: envelope_id.clone(),
            content_blind_order_key: order_key,
            reveal_authorization: transaction.authorization().clone(),
            plaintext: transaction.plaintext().to_vec(),
        });
    }

    let batch = PreparedProtectedBatch {
        context,
        context_root: input.context_root.clone(),
        target_height: input.target_height,
        protected_batch_root: input.protected_batch_root.clone(),
        reveal_transcript_root: input.reveal_transcript_root.clone(),
        transactions,
    };
    batch.validate()?;
    Ok(batch)
}
