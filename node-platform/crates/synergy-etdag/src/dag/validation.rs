use crate::{deterministic_topological_order, EtdagError, EtdagGraph, TransactionVertex};

pub fn validate_vertex_identity(vertex: &TransactionVertex) -> Result<(), EtdagError> {
    let expected = crate::dag::derive_vertex_id(vertex)?;
    if expected != vertex.vertex_id {
        return Err(EtdagError::ConflictingArtifact(
            "ETDAG vertex identifier does not match canonical body".into(),
        ));
    }
    Ok(())
}

pub fn validate_graph(graph: &EtdagGraph) -> Result<(), EtdagError> {
    for vertex in graph.vertices() {
        vertex.validate()?;
        validate_vertex_identity(vertex)?;
        crate::dag::validate_dependencies(graph, vertex)?;
    }
    deterministic_topological_order(graph).map(|_| ())
}
