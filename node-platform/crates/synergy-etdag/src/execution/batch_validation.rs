use std::collections::BTreeSet;

use crate::{execution::PreparedProtectedBatch, DeterministicProtectedExecutionInput, EtdagError};

pub fn validate_execution_handoff(
    input: &DeterministicProtectedExecutionInput,
    batch: &PreparedProtectedBatch,
) -> Result<(), EtdagError> {
    input.validate()?;
    if batch.context_root != input.context_root
        || batch.target_height != input.target_height
        || batch.protected_batch_root != input.protected_batch_root
        || batch.transactions.len() != input.ordered_vertex_ids.len()
    {
        return Err(EtdagError::ContextMismatch);
    }
    let mut envelopes = BTreeSet::new();
    for (expected_vertex, transaction) in input
        .ordered_vertex_ids
        .iter()
        .zip(batch.transactions.iter())
    {
        if &transaction.vertex_id != expected_vertex
            || !envelopes.insert(&transaction.envelope_id)
            || transaction.plaintext.is_empty()
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
    }
    Ok(())
}
