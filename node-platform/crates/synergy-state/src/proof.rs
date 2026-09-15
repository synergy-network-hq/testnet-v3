use serde::{Deserialize, Serialize};

use crate::{FinalizedState, StateError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    pub finalized_height: u64,
    pub state_root: String,
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
    pub proof_nodes: Vec<Vec<u8>>,
}

impl StateProof {
    pub fn validate_shape(&self, finalized: &FinalizedState) -> Result<(), StateError> {
        if self.finalized_height != finalized.finalized_height
            || self.state_root != finalized.state_root
            || self.key.is_empty()
            || self.proof_nodes.len() > 256
            || self.proof_nodes.iter().any(|node| node.is_empty())
        {
            return Err(StateError::InvalidCommitment);
        }
        Ok(())
    }
}

/// State proof verification is supplied by the canonical state commitment
/// implementation. This boundary does not introduce another hash engine.
pub trait StateProofVerifier {
    fn verify(&self, proof: &StateProof) -> Result<(), StateError>;
}

pub fn verify_finalized_state_proof(
    verifier: &impl StateProofVerifier,
    finalized: &FinalizedState,
    proof: &StateProof,
) -> Result<(), StateError> {
    proof.validate_shape(finalized)?;
    verifier.verify(proof)
}
