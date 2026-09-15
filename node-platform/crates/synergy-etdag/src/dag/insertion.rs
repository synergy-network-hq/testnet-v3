use crate::{EtdagError, EtdagGraph, TransactionVertex};

pub fn insert_vertex(graph: &mut EtdagGraph, vertex: TransactionVertex) -> Result<(), EtdagError> {
    graph.insert(vertex)
}
