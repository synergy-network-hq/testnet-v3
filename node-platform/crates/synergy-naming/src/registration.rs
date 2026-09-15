use serde::{Deserialize, Serialize};
use synergy_node_ownership::NodeOwnerResolver;
use synergy_protocol_types::{BlockReference, NodeAddress};

use crate::{
    ensure_available, NamingAction, NamingAuthorization, NamingAuthorizationVerifier, NamingError,
    NamingRegistrySnapshot, NodeId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamingRecordStatus {
    Active,
}

/// Finalized naming record. Ownership deliberately does not live here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamingRecord {
    pub record_version: u32,
    pub node_id: NodeId,
    pub node_address: NodeAddress,
    pub sequence: u64,
    pub status: NamingRecordStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationRequest {
    pub node_id: NodeId,
    pub node_address: NodeAddress,
    pub authorization: NamingAuthorization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    pub current_node_id: NodeId,
    pub replacement_node_id: NodeId,
    pub node_address: NodeAddress,
    pub authorization: NamingAuthorization,
}

/// Deterministic naming transition admitted into canonical execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NamingTransition {
    Register { action: NamingAction },
    Rename { action: NamingAction },
}

impl NamingTransition {
    pub fn action(&self) -> &NamingAction {
        match self {
            Self::Register { action } | Self::Rename { action } => action,
        }
    }
}

/// Naming transitions proven finalized by the canonical chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedNamingBatch {
    pub finalized_at: BlockReference,
    pub transitions: Vec<NamingTransition>,
}

/// Validates current ownership and wallet proof, but never grants finality.
pub struct NamingEngine<O, V> {
    owners: O,
    verifier: V,
}

impl<O, V> NamingEngine<O, V>
where
    O: NodeOwnerResolver,
    V: NamingAuthorizationVerifier,
{
    pub fn new(owners: O, verifier: V) -> Self {
        Self { owners, verifier }
    }

    pub fn prepare_registration(
        &self,
        state: &NamingRegistrySnapshot,
        request: RegistrationRequest,
    ) -> Result<NamingTransition, NamingError> {
        request.authorization.validate()?;
        ensure_available(state, &request.node_id)?;
        if state.node_id(&request.node_address).is_some() {
            return Err(NamingError::NodeAddressAlreadyNamed);
        }
        self.require_fresh_nonce(state, &request.node_address, request.authorization.nonce)?;
        self.require_current_owner(&request.node_address, &request.authorization.owner_wallet)?;
        let action = NamingAction::Register {
            node_id: request.node_id,
            node_address: request.node_address,
            owner_wallet: request.authorization.owner_wallet.clone(),
            nonce: request.authorization.nonce,
        };
        self.verify(&action, &request.authorization)?;
        Ok(NamingTransition::Register { action })
    }

    pub fn prepare_rename(
        &self,
        state: &NamingRegistrySnapshot,
        request: RenameRequest,
    ) -> Result<NamingTransition, NamingError> {
        request.authorization.validate()?;
        if request.current_node_id == request.replacement_node_id {
            return Err(NamingError::UnchangedNodeId);
        }
        ensure_available(state, &request.replacement_node_id)?;
        let current = state
            .record(&request.current_node_id)
            .ok_or(NamingError::NodeIdNotFound)?;
        if current.node_address != request.node_address {
            return Err(NamingError::NodeAddressMismatch);
        }
        self.require_fresh_nonce(state, &request.node_address, request.authorization.nonce)?;
        self.require_current_owner(&request.node_address, &request.authorization.owner_wallet)?;
        let action = NamingAction::Rename {
            current_node_id: request.current_node_id,
            replacement_node_id: request.replacement_node_id,
            node_address: request.node_address,
            owner_wallet: request.authorization.owner_wallet.clone(),
            nonce: request.authorization.nonce,
        };
        self.verify(&action, &request.authorization)?;
        Ok(NamingTransition::Rename { action })
    }

    fn require_current_owner(
        &self,
        node_address: &NodeAddress,
        wallet: &str,
    ) -> Result<(), NamingError> {
        if self
            .owners
            .is_current_owner(node_address, wallet)
            .map_err(NamingError::Ownership)?
        {
            Ok(())
        } else {
            Err(NamingError::OwnerWalletMismatch)
        }
    }

    fn require_fresh_nonce(
        &self,
        state: &NamingRegistrySnapshot,
        node_address: &NodeAddress,
        nonce: u64,
    ) -> Result<(), NamingError> {
        if nonce <= state.last_nonce(node_address) {
            Err(NamingError::InvalidNonce)
        } else {
            Ok(())
        }
    }

    fn verify(
        &self,
        action: &NamingAction,
        authorization: &NamingAuthorization,
    ) -> Result<(), NamingError> {
        if action.owner_wallet() != authorization.owner_wallet
            || action.nonce() != authorization.nonce
        {
            return Err(NamingError::CorruptRegistry);
        }
        action.signing_payload()?;
        self.verifier
            .verify(action, authorization)
            .map_err(NamingError::Authorization)
    }
}

impl NamingRegistrySnapshot {
    /// Applies one deterministic transition inside the block execution overlay.
    /// The local cache remains ineligible until PoSy finalizes and seals the
    /// resulting canonical WorldState.
    pub fn apply_at_height(
        &mut self,
        height: u64,
        transition: NamingTransition,
    ) -> Result<(), NamingError> {
        if height == 0 {
            return Err(NamingError::CorruptRegistry);
        }
        let mut candidate = self.clone();
        candidate.apply_transition(transition)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    pub fn apply_finalized(&mut self, batch: FinalizedNamingBatch) -> Result<(), NamingError> {
        if batch.transitions.is_empty() {
            return Err(NamingError::EmptyFinalizedBatch);
        }
        self.ensure_next_finalized(&batch.finalized_at)?;
        let mut candidate = self.clone();
        for transition in batch.transitions {
            candidate.apply_transition(transition)?;
        }
        candidate.finalized_at = Some(batch.finalized_at);
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn apply_transition(&mut self, transition: NamingTransition) -> Result<(), NamingError> {
        match transition.action() {
            NamingAction::Register {
                node_id,
                node_address,
                nonce,
                ..
            } => {
                ensure_available(self, node_id)?;
                if self.node_id(node_address).is_some() {
                    return Err(NamingError::NodeAddressAlreadyNamed);
                }
                if *nonce <= self.last_nonce(node_address) {
                    return Err(NamingError::InvalidNonce);
                }
                self.insert(
                    NamingRecord {
                        record_version: 1,
                        node_id: node_id.clone(),
                        node_address: node_address.clone(),
                        sequence: 1,
                        status: NamingRecordStatus::Active,
                    },
                    *nonce,
                )
            }
            NamingAction::Rename {
                current_node_id,
                replacement_node_id,
                node_address,
                nonce,
                ..
            } => {
                if current_node_id == replacement_node_id {
                    return Err(NamingError::UnchangedNodeId);
                }
                ensure_available(self, replacement_node_id)?;
                let current = self
                    .record(current_node_id)
                    .cloned()
                    .ok_or(NamingError::NodeIdNotFound)?;
                if current.node_address != *node_address {
                    return Err(NamingError::NodeAddressMismatch);
                }
                if *nonce <= self.last_nonce(node_address) {
                    return Err(NamingError::InvalidNonce);
                }
                self.rename(
                    current_node_id,
                    NamingRecord {
                        record_version: 1,
                        node_id: replacement_node_id.clone(),
                        node_address: node_address.clone(),
                        sequence: current
                            .sequence
                            .checked_add(1)
                            .ok_or(NamingError::CorruptRegistry)?,
                        status: NamingRecordStatus::Active,
                    },
                    *nonce,
                )
            }
        }
    }
}
