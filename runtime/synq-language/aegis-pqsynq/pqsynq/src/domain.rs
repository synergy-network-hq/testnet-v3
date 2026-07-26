//! SynQ chain, network, and domain separation identifiers.

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::error::AegisSynQError;

pub const SYNERGY_TESTNET_CHAIN_ID: u64 = 1266;
pub const SYNERGY_TESTNET_NETWORK: &str = "synergy-testnet";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId(pub u64);

impl ChainId {
    pub const fn testnet_1266() -> Self {
        Self(SYNERGY_TESTNET_CHAIN_ID)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl NetworkId {
    pub fn testnet() -> Self {
        Self(SYNERGY_TESTNET_NETWORK.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn numeric_id(&self) -> Result<u16, AegisSynQError> {
        match self.0.as_str() {
            SYNERGY_TESTNET_NETWORK => Ok(SYNERGY_TESTNET_CHAIN_ID as u16),
            "devnet" => Ok(1),
            "mainnet" => Ok(0),
            _ => Err(AegisSynQError::InvalidNetwork),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainTag {
    SynqTxV1,
    SynqContractDeployV1,
    SynqContractCallV1,
    SynqValidatorMessageV1,
    SynqAivmReceiptV1,
    SynqStateCommitmentV1,
    SynqWalletAuthV1,
    SynqCrossChainMessageV1,
}

impl DomainTag {
    pub const fn code(self) -> u16 {
        match self {
            Self::SynqTxV1 => 1,
            Self::SynqContractDeployV1 => 2,
            Self::SynqContractCallV1 => 3,
            Self::SynqValidatorMessageV1 => 4,
            Self::SynqAivmReceiptV1 => 5,
            Self::SynqStateCommitmentV1 => 6,
            Self::SynqWalletAuthV1 => 7,
            Self::SynqCrossChainMessageV1 => 8,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SynqTxV1 => "SYNQ_TX_V1",
            Self::SynqContractDeployV1 => "SYNQ_CONTRACT_DEPLOY_V1",
            Self::SynqContractCallV1 => "SYNQ_CONTRACT_CALL_V1",
            Self::SynqValidatorMessageV1 => "SYNQ_VALIDATOR_MESSAGE_V1",
            Self::SynqAivmReceiptV1 => "SYNQ_AIVM_RECEIPT_V1",
            Self::SynqStateCommitmentV1 => "SYNQ_STATE_COMMITMENT_V1",
            Self::SynqWalletAuthV1 => "SYNQ_WALLET_AUTH_V1",
            Self::SynqCrossChainMessageV1 => "SYNQ_CROSS_CHAIN_MESSAGE_V1",
        }
    }
}
