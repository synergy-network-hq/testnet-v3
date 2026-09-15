use serde::{Deserialize, Serialize};

use crate::{FeeLimit, TransactionAction, TransactionClass, TransactionError, TransactionId};

pub const SYNERGY_TESTNET_V3_CHAIN_ID: u64 = 1266;
pub const MAX_ADDRESS_BYTES: usize = 256;
pub const MAX_TRANSACTION_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkBinding {
    pub chain_id: u64,
    pub network_id: String,
}

impl NetworkBinding {
    pub fn testnet_v3(network_id: impl Into<String>) -> Result<Self, TransactionError> {
        let binding = Self {
            chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
            network_id: network_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.chain_id != SYNERGY_TESTNET_V3_CHAIN_ID || self.network_id.trim().is_empty() {
            return Err(TransactionError::InvalidNetworkBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub network: NetworkBinding,
    pub class: TransactionClass,
    pub sender: String,
    pub receiver: String,
    pub amount_nwei: u128,
    pub nonce: u64,
    pub fee_limit: FeeLimit,
    pub timestamp_unix: u64,
    pub payload: Vec<u8>,
}

impl UnsignedTransaction {
    pub fn validate_structure(&self) -> Result<(), TransactionError> {
        self.network.validate()?;
        if self.sender.trim().is_empty()
            || self.receiver.trim().is_empty()
            || self.sender == self.receiver
            || self.sender.len() > MAX_ADDRESS_BYTES
            || self.receiver.len() > MAX_ADDRESS_BYTES
            || !synergy_address::is_valid_address(&self.sender)
            || !synergy_address::is_valid_address(&self.receiver)
        {
            return Err(TransactionError::InvalidAddress);
        }
        if self.payload.len() > MAX_TRANSACTION_PAYLOAD_BYTES {
            return Err(TransactionError::PayloadTooLarge);
        }
        let action = self.action()?;
        if action.requires_system_authority() != matches!(self.class, TransactionClass::System) {
            return Err(TransactionError::UnauthorizedTransactionClass);
        }
        self.fee_limit.validate()?;
        if self.timestamp_unix == 0 {
            return Err(TransactionError::InvalidTimestamp);
        }
        Ok(())
    }

    pub fn action(&self) -> Result<TransactionAction, TransactionError> {
        TransactionAction::decode(&self.payload)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        self.validate_structure()?;
        let mut output = Vec::new();
        output.extend_from_slice(b"SYNERGY_TRANSACTION_SIGNING_V1");
        append_u64(&mut output, self.network.chain_id);
        append_bytes(&mut output, self.network.network_id.as_bytes());
        output.push(match self.class {
            TransactionClass::User => 0,
            TransactionClass::System => 1,
        });
        append_bytes(&mut output, self.sender.as_bytes());
        append_bytes(&mut output, self.receiver.as_bytes());
        output.extend_from_slice(&self.amount_nwei.to_be_bytes());
        append_u64(&mut output, self.nonce);
        append_u64(&mut output, self.fee_limit.gas_limit);
        append_u64(&mut output, self.fee_limit.max_fee_per_gas_nwei);
        append_u64(&mut output, self.timestamp_unix);
        append_bytes(&mut output, &self.payload);
        Ok(output)
    }

    pub fn id(&self) -> Result<TransactionId, TransactionError> {
        TransactionId::from_unsigned(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub unsigned: UnsignedTransaction,
    pub signer_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub signature_algorithm: String,
}

impl SignedTransaction {
    pub fn validate_structure(&self) -> Result<(), TransactionError> {
        self.unsigned.validate_structure()?;
        if self.signer_public_key.is_empty()
            || self.signature.is_empty()
            || self.signature_algorithm.trim().is_empty()
        {
            return Err(TransactionError::MissingSignatureMaterial);
        }
        Ok(())
    }

    pub fn id(&self) -> Result<TransactionId, TransactionError> {
        self.validate_structure()?;
        self.unsigned.id()
    }
}

fn append_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_bytes(output: &mut Vec<u8>, value: &[u8]) {
    append_u64(output, value.len() as u64);
    output.extend_from_slice(value);
}
