use std::collections::BTreeSet;

use crate::{EtdagDigest, EtdagError};

pub const MAX_VERTEX_PARENTS: usize = 64;

pub fn canonical_parents(
    parents: &[EtdagDigest],
    max_parents: usize,
) -> Result<Vec<EtdagDigest>, EtdagError> {
    if max_parents == 0 || parents.len() > max_parents {
        return Err(EtdagError::InvalidCapacity);
    }
    let mut unique = BTreeSet::new();
    for parent in parents {
        parent.validate()?;
        if !unique.insert(parent.clone()) {
            return Err(EtdagError::DuplicateVertex(parent.0.clone()));
        }
    }
    Ok(unique.into_iter().collect())
}
