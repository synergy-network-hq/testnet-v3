//! Finalized reward accounting keyed by canonical NodeAddress.
//!
//! Reward formulas are deliberately outside this crate. It applies amounts
//! supplied by canonical finalized execution and authorizes withdrawals only
//! for the current owner supplied by synergy-node-ownership. NodeID is never
//! an account key or authorization input.

mod account;
mod authorization;
mod ledger;
mod store;
mod withdrawal;

use std::fmt;

/// Canonical WorldState.protocol key for node reward accounting.
pub const PROTOCOL_STATE_KEY: &str = "synergy/rewards/v1";

pub use account::RewardAccount;
pub use authorization::{
    RewardAuthorizationVerifier, RewardWithdrawalAction, MAX_WITHDRAWAL_PROOF_BYTES,
};
pub use ledger::{FinalizedRewardBatch, RewardEngine, RewardTransition};
pub use store::{AtomicRewardCache, RewardCache, RewardLedgerSnapshot};
pub use withdrawal::{RewardWithdrawalRequest, WithdrawalRecord, WithdrawalStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewardError {
    InvalidWallet,
    InvalidIdentifier,
    InvalidAmount,
    InvalidNonce,
    MissingProof,
    ProofTooLarge,
    OwnerMismatch,
    InsufficientAvailable,
    DuplicateCredit,
    DuplicateWithdrawal,
    WithdrawalNotFound,
    WithdrawalNotPending,
    AmountOverflow,
    InvalidVersion,
    InvalidFinalizedOrder,
    ConflictingFinalizedState,
    EmptyFinalizedBatch,
    CorruptState,
    Ownership(String),
    Authorization(String),
    Serialization(String),
    Cache(String),
}

impl fmt::Display for RewardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWallet => formatter.write_str("invalid Synergy wallet address"),
            Self::InvalidIdentifier => formatter.write_str("invalid reward operation identifier"),
            Self::InvalidAmount => formatter.write_str("reward amount must be nonzero"),
            Self::InvalidNonce => formatter.write_str("withdrawal nonce must increase"),
            Self::MissingProof => formatter.write_str("withdrawal owner proof is empty"),
            Self::ProofTooLarge => formatter.write_str("withdrawal proof exceeds protocol bound"),
            Self::OwnerMismatch => formatter.write_str("wallet is not the current node owner"),
            Self::InsufficientAvailable => {
                formatter.write_str("insufficient available node rewards")
            }
            Self::DuplicateCredit => formatter.write_str("reward credit source already applied"),
            Self::DuplicateWithdrawal => formatter.write_str("withdrawal identifier already used"),
            Self::WithdrawalNotFound => formatter.write_str("withdrawal was not found"),
            Self::WithdrawalNotPending => formatter.write_str("withdrawal is not pending"),
            Self::AmountOverflow => formatter.write_str("reward amount overflow"),
            Self::InvalidVersion => formatter.write_str("unsupported reward state version"),
            Self::InvalidFinalizedOrder => {
                formatter.write_str("reward update is not after cached finalized state")
            }
            Self::ConflictingFinalizedState => {
                formatter.write_str("conflicting reward state at one finalized block")
            }
            Self::EmptyFinalizedBatch => formatter.write_str("finalized reward batch is empty"),
            Self::CorruptState => formatter.write_str("reward state invariants are corrupt"),
            Self::Ownership(message) => write!(formatter, "ownership lookup failed: {message}"),
            Self::Authorization(message) => {
                write!(formatter, "withdrawal authorization failed: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "reward serialization failed: {message}")
            }
            Self::Cache(message) => write!(formatter, "reward cache failed: {message}"),
        }
    }
}

impl std::error::Error for RewardError {}

#[cfg(test)]
mod tests {
    use super::*;
    use synergy_node_ownership::NodeOwnerResolver;
    use synergy_protocol_types::{BlockReference, Height, NodeAddress, ProtocolHash};

    const NODE: &str = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";

    #[derive(Clone)]
    struct Owners {
        node_address: NodeAddress,
        wallet: String,
    }

    impl NodeOwnerResolver for Owners {
        fn current_owner(&self, node_address: &NodeAddress) -> Result<Option<String>, String> {
            Ok((node_address == &self.node_address).then(|| self.wallet.clone()))
        }
    }

    #[derive(Clone, Copy)]
    struct Verifier;

    impl RewardAuthorizationVerifier for Verifier {
        fn verify_owner_proof(
            &self,
            _wallet: &str,
            _payload: &[u8],
            proof: &[u8],
        ) -> Result<(), String> {
            (proof == b"owner-proof")
                .then_some(())
                .ok_or_else(|| "bad owner proof".into())
        }
    }

    fn wallet(seed: u8) -> String {
        synergy_address::generate_wallet_address(&format!("{seed:02x}").repeat(1_793)).unwrap()
    }

    fn finalized(height: u64) -> BlockReference {
        BlockReference::new(
            Height::new(height),
            ProtocolHash::new([(height + 1) as u8; 32]),
            ProtocolHash::new([height as u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn rewards_exist_without_a_node_id() {
        let node_address = NodeAddress::parse(NODE).unwrap();
        let engine = RewardEngine::new(
            Owners {
                node_address: node_address.clone(),
                wallet: wallet(1),
            },
            Verifier,
        );
        let mut state = RewardLedgerSnapshot::default();
        state
            .apply_finalized(FinalizedRewardBatch {
                finalized_at: finalized(1),
                transitions: vec![engine
                    .prepare_credit(node_address.clone(), 500, "block:1".into())
                    .unwrap()],
            })
            .unwrap();
        assert_eq!(
            state
                .account(&node_address)
                .unwrap()
                .available_nwei()
                .unwrap(),
            500
        );
    }

    #[test]
    fn withdrawal_refuses_a_wallet_that_is_not_current_owner() {
        let node_address = NodeAddress::parse(NODE).unwrap();
        let owner = wallet(1);
        let other = wallet(2);
        let engine = RewardEngine::new(
            Owners {
                node_address: node_address.clone(),
                wallet: owner,
            },
            Verifier,
        );
        let mut state = RewardLedgerSnapshot::default();
        state
            .apply_finalized(FinalizedRewardBatch {
                finalized_at: finalized(1),
                transitions: vec![engine
                    .prepare_credit(node_address.clone(), 500, "block:1".into())
                    .unwrap()],
            })
            .unwrap();
        let error = engine
            .prepare_withdrawal(
                &state,
                RewardWithdrawalRequest {
                    withdrawal_id: "withdrawal-1".into(),
                    node_address,
                    owner_wallet: other.clone(),
                    destination_wallet: other,
                    amount_nwei: 100,
                    nonce: 1,
                    owner_proof: b"owner-proof".to_vec(),
                },
            )
            .unwrap_err();
        assert_eq!(error, RewardError::OwnerMismatch);
    }
}
