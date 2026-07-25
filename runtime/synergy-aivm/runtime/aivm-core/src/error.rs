use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AivmErrorCode {
    Bytecode,
    Manifest,
    Abi,
    Verification,
    Gas,
    PqGas,
    RuntimeTrap,
    State,
    HostFunction,
    Receipt,
    InternalInvariant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AivmError {
    pub code: AivmErrorCode,
    pub message: String,
}

impl AivmError {
    pub fn new(code: AivmErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn bytecode(message: impl Into<String>) -> Self {
        Self::new(AivmErrorCode::Bytecode, message)
    }

    pub fn runtime_trap(message: impl Into<String>) -> Self {
        Self::new(AivmErrorCode::RuntimeTrap, message)
    }

    pub fn host_function(message: impl Into<String>) -> Self {
        Self::new(AivmErrorCode::HostFunction, message)
    }

    pub fn gas(message: impl Into<String>) -> Self {
        Self::new(AivmErrorCode::Gas, message)
    }

    pub fn pq_gas(message: impl Into<String>) -> Self {
        Self::new(AivmErrorCode::PqGas, message)
    }
}

impl fmt::Display for AivmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl Error for AivmError {}
