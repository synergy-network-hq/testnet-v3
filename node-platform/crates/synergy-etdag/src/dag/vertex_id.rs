use crate::{domains, EtdagDigest, EtdagError, TransactionVertex};

/// Derives the canonical identifier from the immutable, unsigned vertex body.
/// The signature authenticates this identifier and is deliberately excluded.
pub fn derive_vertex_id(vertex: &TransactionVertex) -> Result<EtdagDigest, EtdagError> {
    vertex.target_context_root.validate()?;
    vertex.envelope.validate()?;
    let parents = crate::dag::canonical_parents(&vertex.parents, crate::dag::MAX_VERTEX_PARENTS)?;
    if vertex.target_height == 0 || vertex.author_id.trim().is_empty() {
        return Err(EtdagError::InvalidEnvelope(
            "invalid ETDAG vertex identity fields".into(),
        ));
    }
    let body = (
        &vertex.target_context_root,
        vertex.target_height,
        &vertex.envelope,
        &vertex.envelope_ref,
        parents,
        vertex.author_id.trim(),
    );
    match &vertex.wallet_admission {
        // Preserve the exact historical unsigned-body transcript for bare
        // compatibility vertices; new proofs are part of the signed identity.
        None => EtdagDigest::from_canonical(domains::DAG_VERTEX, &body),
        Some(admission) => EtdagDigest::from_canonical(domains::DAG_VERTEX, &(body, admission)),
    }
}
