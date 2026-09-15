use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

use crate::RewardError;

const WITHDRAWAL_DOMAIN: &[u8] = b"SYNERGY_NODE_REWARD_WITHDRAWAL_V1";
pub const MAX_WITHDRAWAL_PROOF_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewardWithdrawalAction {
    pub withdrawal_id: String,
    pub node_address: NodeAddress,
    pub owner_wallet: String,
    pub destination_wallet: String,
    pub amount_nwei: u128,
    pub nonce: u64,
}

impl RewardWithdrawalAction {
    pub fn signing_payload(&self) -> Result<Vec<u8>, RewardError> {
        let mut bytes = Vec::with_capacity(320);
        append_field(&mut bytes, WITHDRAWAL_DOMAIN)?;
        append_field(&mut bytes, self.withdrawal_id.as_bytes())?;
        append_field(&mut bytes, self.node_address.as_str().as_bytes())?;
        append_field(&mut bytes, self.owner_wallet.as_bytes())?;
        append_field(&mut bytes, self.destination_wallet.as_bytes())?;
        bytes.extend_from_slice(&self.amount_nwei.to_be_bytes());
        bytes.extend_from_slice(&self.nonce.to_be_bytes());
        Ok(bytes)
    }
}

pub trait RewardAuthorizationVerifier {
    fn verify_owner_proof(&self, wallet: &str, payload: &[u8], proof: &[u8]) -> Result<(), String>;
}

pub(crate) fn validate_wallet(wallet: &str) -> Result<(), RewardError> {
    if synergy_address::address_kind(wallet) == synergy_address::AddressKind::Wallet {
        Ok(())
    } else {
        Err(RewardError::InvalidWallet)
    }
}

pub(crate) fn validate_proof(proof: &[u8]) -> Result<(), RewardError> {
    if proof.is_empty() {
        return Err(RewardError::MissingProof);
    }
    if proof.len() > MAX_WITHDRAWAL_PROOF_BYTES {
        return Err(RewardError::ProofTooLarge);
    }
    Ok(())
}

pub(crate) fn validate_id(value: &str) -> Result<(), RewardError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':'))
    {
        return Err(RewardError::InvalidIdentifier);
    }
    Ok(())
}

fn append_field(target: &mut Vec<u8>, value: &[u8]) -> Result<(), RewardError> {
    let length = u32::try_from(value.len())
        .map_err(|_| RewardError::Serialization("authorization field exceeds u32".into()))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}
