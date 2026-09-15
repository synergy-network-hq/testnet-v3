use serde::{Deserialize, Serialize};
use synergy_protocol_types::{BlockReference, NodeAddress};

use crate::{
    authorization::validate_proof, validate_wallet, NodeOwnershipBinding, OwnershipAction,
    OwnershipAuthorizationVerifier, OwnershipError, OwnershipRegistrySnapshot,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipClaimRequest {
    pub node_address: NodeAddress,
    pub owner_wallet: String,
    pub nonce: u64,
    pub wallet_proof: Vec<u8>,
    pub node_possession_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipTransferRequest {
    pub node_address: NodeAddress,
    pub current_owner_wallet: String,
    pub new_owner_wallet: String,
    pub nonce: u64,
    pub current_owner_proof: Vec<u8>,
    pub new_owner_acceptance_proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OwnershipTransition {
    Claim { action: OwnershipAction },
    Transfer { action: OwnershipAction },
}

impl OwnershipTransition {
    pub fn action(&self) -> &OwnershipAction {
        match self {
            Self::Claim { action } | Self::Transfer { action } => action,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedOwnershipBatch {
    pub finalized_at: BlockReference,
    pub transitions: Vec<OwnershipTransition>,
}

/// Validates proofs and prepares transitions; it never grants finality.
pub struct OwnershipEngine<V> {
    verifier: V,
}

impl<V> OwnershipEngine<V>
where
    V: OwnershipAuthorizationVerifier,
{
    pub fn new(verifier: V) -> Self {
        Self { verifier }
    }

    pub fn prepare_claim(
        &self,
        state: &OwnershipRegistrySnapshot,
        request: OwnershipClaimRequest,
    ) -> Result<OwnershipTransition, OwnershipError> {
        validate_wallet(&request.owner_wallet)?;
        validate_proof(&request.wallet_proof)?;
        validate_proof(&request.node_possession_proof)?;
        if request.nonce == 0 || request.nonce <= state.last_nonce(&request.node_address) {
            return Err(OwnershipError::InvalidNonce);
        }
        if state.binding(&request.node_address).is_some() {
            return Err(OwnershipError::NodeAlreadyOwned);
        }
        let action = OwnershipAction::Claim {
            node_address: request.node_address,
            owner_wallet: request.owner_wallet,
            nonce: request.nonce,
        };
        let payload = action.signing_payload()?;
        let OwnershipAction::Claim {
            node_address,
            owner_wallet,
            ..
        } = &action
        else {
            return Err(OwnershipError::CorruptState);
        };
        self.verifier
            .verify_wallet_proof(owner_wallet, &payload, &request.wallet_proof)
            .map_err(OwnershipError::Authorization)?;
        self.verifier
            .verify_node_possession(node_address, &payload, &request.node_possession_proof)
            .map_err(OwnershipError::Authorization)?;
        Ok(OwnershipTransition::Claim { action })
    }

    pub fn prepare_transfer(
        &self,
        state: &OwnershipRegistrySnapshot,
        request: OwnershipTransferRequest,
    ) -> Result<OwnershipTransition, OwnershipError> {
        validate_wallet(&request.current_owner_wallet)?;
        validate_wallet(&request.new_owner_wallet)?;
        validate_proof(&request.current_owner_proof)?;
        validate_proof(&request.new_owner_acceptance_proof)?;
        if request.current_owner_wallet == request.new_owner_wallet {
            return Err(OwnershipError::UnchangedOwner);
        }
        if request.nonce == 0 || request.nonce <= state.last_nonce(&request.node_address) {
            return Err(OwnershipError::InvalidNonce);
        }
        let current = state
            .binding(&request.node_address)
            .ok_or(OwnershipError::NodeNotOwned)?;
        if current.owner_wallet != request.current_owner_wallet {
            return Err(OwnershipError::OwnerMismatch);
        }
        let action = OwnershipAction::Transfer {
            node_address: request.node_address,
            current_owner_wallet: request.current_owner_wallet,
            new_owner_wallet: request.new_owner_wallet,
            nonce: request.nonce,
        };
        let payload = action.signing_payload()?;
        let OwnershipAction::Transfer {
            current_owner_wallet,
            new_owner_wallet,
            ..
        } = &action
        else {
            return Err(OwnershipError::CorruptState);
        };
        self.verifier
            .verify_wallet_proof(current_owner_wallet, &payload, &request.current_owner_proof)
            .map_err(OwnershipError::Authorization)?;
        self.verifier
            .verify_wallet_proof(
                new_owner_wallet,
                &payload,
                &request.new_owner_acceptance_proof,
            )
            .map_err(OwnershipError::Authorization)?;
        Ok(OwnershipTransition::Transfer { action })
    }
}

impl OwnershipRegistrySnapshot {
    /// Applies one deterministic transition inside the block execution overlay.
    /// This updates canonical state but does not mark it finalized; PoSy does
    /// that only when the containing WorldState is committed.
    pub fn apply_at_height(
        &mut self,
        height: u64,
        transition: OwnershipTransition,
    ) -> Result<(), OwnershipError> {
        if height == 0 {
            return Err(OwnershipError::CorruptState);
        }
        let mut candidate = self.clone();
        candidate.apply_transition(height, transition)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn apply_finalized(
        &mut self,
        batch: FinalizedOwnershipBatch,
    ) -> Result<(), OwnershipError> {
        if batch.transitions.is_empty() {
            return Err(OwnershipError::EmptyFinalizedBatch);
        }
        self.ensure_next_finalized(&batch.finalized_at)?;
        let mut candidate = self.clone();
        for transition in batch.transitions {
            candidate.apply_transition(batch.finalized_at.height.get(), transition)?;
        }
        candidate.finalized_at = Some(batch.finalized_at);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn apply_transition(
        &mut self,
        height: u64,
        transition: OwnershipTransition,
    ) -> Result<(), OwnershipError> {
        match transition.action() {
            OwnershipAction::Claim {
                node_address,
                owner_wallet,
                nonce,
            } => {
                if self.binding(node_address).is_some() {
                    return Err(OwnershipError::NodeAlreadyOwned);
                }
                self.install_binding(
                    NodeOwnershipBinding {
                        record_version: 1,
                        node_address: node_address.clone(),
                        owner_wallet: owner_wallet.clone(),
                        sequence: 1,
                        effective_height: height,
                    },
                    *nonce,
                )
            }
            OwnershipAction::Transfer {
                node_address,
                current_owner_wallet,
                new_owner_wallet,
                nonce,
            } => {
                let current = self
                    .binding(node_address)
                    .cloned()
                    .ok_or(OwnershipError::NodeNotOwned)?;
                if current.owner_wallet != *current_owner_wallet {
                    return Err(OwnershipError::OwnerMismatch);
                }
                self.install_binding(
                    NodeOwnershipBinding {
                        record_version: 1,
                        node_address: node_address.clone(),
                        owner_wallet: new_owner_wallet.clone(),
                        sequence: current
                            .sequence
                            .checked_add(1)
                            .ok_or(OwnershipError::CorruptState)?,
                        effective_height: height,
                    },
                    *nonce,
                )
            }
        }
    }
}
