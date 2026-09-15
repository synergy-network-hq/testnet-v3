//! SynQ algorithm identifiers and signature purposes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlgorithmId {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    SlhDsaSha2_128s,
    SlhDsaSha2_192s,
    SlhDsaSha2_256s,
    FnDsa,
    Hqc128,
    Hqc192,
    Hqc256,
    ClassicMcEliece348864,
}

impl AlgorithmId {
    pub const fn code(self) -> u16 {
        match self {
            Self::MlDsa44 => 0x0101,
            Self::MlDsa65 => 0x0102,
            Self::MlDsa87 => 0x0103,
            Self::SlhDsaSha2_128s => 0x0301,
            Self::SlhDsaSha2_192s => 0x0302,
            Self::SlhDsaSha2_256s => 0x0303,
            Self::FnDsa => 0x0201,
            Self::Hqc128 => 0x0401,
            Self::Hqc192 => 0x0402,
            Self::Hqc256 => 0x0403,
            Self::ClassicMcEliece348864 => 0x0501,
        }
    }

    pub const fn security_level(self) -> SecurityLevel {
        match self {
            Self::MlDsa44 | Self::SlhDsaSha2_128s | Self::Hqc128 => SecurityLevel::Level1,
            Self::MlDsa65 | Self::SlhDsaSha2_192s | Self::Hqc192 | Self::FnDsa => {
                SecurityLevel::Level3
            }
            Self::MlDsa87 | Self::SlhDsaSha2_256s | Self::Hqc256 | Self::ClassicMcEliece348864 => {
                SecurityLevel::Level5
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SecurityLevel {
    Level1,
    Level3,
    Level5,
}

impl SecurityLevel {
    pub const fn code(self) -> u16 {
        match self {
            Self::Level1 => 1,
            Self::Level3 => 3,
            Self::Level5 => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignaturePurpose {
    Transaction,
    ContractDeploy,
    ContractCall,
    ValidatorMessage,
    AivmReceipt,
    StateCommitment,
    WalletAuth,
    CrossChainMessage,
}

impl SignaturePurpose {
    pub const fn code(self) -> u16 {
        match self {
            Self::Transaction => 1,
            Self::ContractDeploy => 2,
            Self::ContractCall => 3,
            Self::ValidatorMessage => 4,
            Self::AivmReceipt => 5,
            Self::StateCommitment => 6,
            Self::WalletAuth => 7,
            Self::CrossChainMessage => 8,
        }
    }
}
