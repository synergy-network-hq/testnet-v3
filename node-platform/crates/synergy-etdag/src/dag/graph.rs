use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{EtdagDigest, EtdagError, TransactionVertex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtdagGraph {
    context_root: EtdagDigest,
    target_height: u64,
    vertices: BTreeMap<EtdagDigest, TransactionVertex>,
}

impl EtdagGraph {
    pub fn new(context_root: EtdagDigest, target_height: u64) -> Result<Self, EtdagError> {
        context_root.validate()?;
        if target_height == 0 {
            return Err(EtdagError::ContextMismatch);
        }
        Ok(Self {
            context_root,
            target_height,
            vertices: BTreeMap::new(),
        })
    }

    pub fn insert(&mut self, vertex: TransactionVertex) -> Result<(), EtdagError> {
        vertex.validate()?;
        crate::dag::validate_vertex_identity(&vertex)?;
        if vertex.target_context_root != self.context_root
            || vertex.target_height != self.target_height
        {
            return Err(EtdagError::ContextMismatch);
        }
        if self.vertices.contains_key(&vertex.vertex_id) {
            return Err(EtdagError::DuplicateVertex(vertex.vertex_id.0));
        }
        if let Some(parent) = vertex
            .parents
            .iter()
            .find(|parent| !self.vertices.contains_key(*parent))
        {
            return Err(EtdagError::UnknownParent(parent.0.clone()));
        }
        self.vertices.insert(vertex.vertex_id.clone(), vertex);
        Ok(())
    }

    pub fn get(&self, vertex_id: &EtdagDigest) -> Option<&TransactionVertex> {
        self.vertices.get(vertex_id)
    }

    pub fn vertices(&self) -> impl Iterator<Item = &TransactionVertex> {
        self.vertices.values()
    }

    pub fn context_root(&self) -> &EtdagDigest {
        &self.context_root
    }

    pub fn target_height(&self) -> u64 {
        self.target_height
    }

    pub fn len(&self) -> usize {
        self.vertices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }

    pub fn contains(&self, vertex_id: &EtdagDigest) -> bool {
        self.vertices.contains_key(vertex_id)
    }
}
