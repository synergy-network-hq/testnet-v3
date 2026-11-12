//! SynQ chain, network, and domain separation identifiers.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::error::AegisSynQError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkId(pub String);

impl NetworkId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn numeric_id(&self) -> Result<u16, AegisSynQError> {
        if self.0.trim().is_empty() || self.0.len() > 128 || self.0.contains(char::is_control) {
            return Err(AegisSynQError::InvalidNetwork);
        }
        // Internal signer-format V2 tag. It is not a chain ID and is never
        // used for admission: full chain/network values remain signed and checked.
        use crate::hash::Sha256;
        let mut digest = Sha256::new();
        digest.update(b"SYNERGY_SYNQ_SIGNER_NETWORK_TAG_V2");
        digest.update((self.0.len() as u64).to_be_bytes());
        digest.update(self.0.as_bytes());
        let hash = digest.finalize();
        Ok(u16::from_be_bytes([hash[0], hash[1]]))
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
