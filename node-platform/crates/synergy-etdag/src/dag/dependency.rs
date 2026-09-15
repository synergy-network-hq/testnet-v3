use crate::{EtdagError, EtdagGraph, TransactionVertex};

pub fn validate_dependencies(
    graph: &EtdagGraph,
    vertex: &TransactionVertex,
) -> Result<(), EtdagError> {
    if vertex.target_context_root != *graph.context_root()
        || vertex.target_height != graph.target_height()
    {
        return Err(EtdagError::ContextMismatch);
    }
    for parent in &vertex.parents {
        if !graph.contains(parent) {
            return Err(EtdagError::UnknownParent(parent.0.clone()));
        }
    }
    Ok(())
}
