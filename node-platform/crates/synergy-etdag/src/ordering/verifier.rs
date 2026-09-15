use std::collections::BTreeSet;

use crate::{protected_order_root, EtdagDigest, EtdagError, ProtectedOrderingProof};

pub fn verify_ordering_proof(proof: &ProtectedOrderingProof) -> Result<(), EtdagError> {
    proof.validate_shape()?;
    let mut seen = BTreeSet::new();
    if proof.ordered_vertex_ids.iter().any(|id| !seen.insert(id)) {
        return Err(EtdagError::DuplicateVertex("ordering proof".into()));
    }
    let mut expected = proof
        .ordered_vertex_ids
        .iter()
        .map(|vertex_id| {
            crate::ordering::derive_content_blind_order_key(&proof.order_seed, vertex_id)
                .map(|key| (key, vertex_id.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    expected.sort();
    let expected = expected
        .into_iter()
        .map(|(_, vertex_id)| vertex_id)
        .collect::<Vec<_>>();
    if expected != proof.ordered_vertex_ids {
        return Err(EtdagError::InvalidExecutionInput);
    }
    if protected_order_root(&proof.ordered_vertex_ids)? != proof.order_root {
        return Err(EtdagError::InvalidExecutionInput);
    }
    Ok(())
}
