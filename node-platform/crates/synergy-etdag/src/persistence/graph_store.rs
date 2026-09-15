use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, EtdagGraph};

const STATE_PATH: &str = "dag/graph-v1.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DurableGraph {
    format_version: u32,
    graph: EtdagGraph,
}

#[derive(Debug)]
pub struct GraphStore {
    store: synergy_storage::AtomicStore,
    graph: EtdagGraph,
}

impl GraphStore {
    pub fn open(
        root: impl AsRef<Path>,
        context_root: EtdagDigest,
        target_height: u64,
        max_record_bytes: usize,
    ) -> Result<Self, EtdagError> {
        let empty = EtdagGraph::new(context_root.clone(), target_height)?;
        if max_record_bytes == 0 {
            return Err(EtdagError::InvalidCapacity);
        }
        let store = synergy_storage::AtomicStore::new(root.as_ref(), max_record_bytes)
            .map_err(storage_error)?;
        let graph = if store.exists(STATE_PATH).map_err(storage_error)? {
            let bytes = store.read_bounded(STATE_PATH).map_err(storage_error)?;
            let durable: DurableGraph = serde_json::from_slice(&bytes)
                .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
            if durable.format_version != 1
                || durable.graph.context_root() != &context_root
                || durable.graph.target_height() != target_height
            {
                return Err(EtdagError::ContextMismatch);
            }
            crate::dag::validate_graph(&durable.graph)?;
            durable.graph
        } else {
            empty
        };
        Ok(Self { store, graph })
    }

    pub fn graph(&self) -> &EtdagGraph {
        &self.graph
    }

    pub fn insert(&mut self, vertex: crate::TransactionVertex) -> Result<(), EtdagError> {
        let mut next = self.graph.clone();
        next.insert(vertex)?;
        self.persist(&next)?;
        self.graph = next;
        Ok(())
    }

    fn persist(&self, graph: &EtdagGraph) -> Result<(), EtdagError> {
        let bytes = serde_json::to_vec(&DurableGraph {
            format_version: 1,
            graph: graph.clone(),
        })
        .map_err(|error| EtdagError::Corrupt(error.to_string()))?;
        self.store
            .write_atomic(STATE_PATH, &bytes)
            .map_err(storage_error)
    }
}

fn storage_error(error: synergy_storage::StorageError) -> EtdagError {
    EtdagError::Storage(error.to_string())
}
