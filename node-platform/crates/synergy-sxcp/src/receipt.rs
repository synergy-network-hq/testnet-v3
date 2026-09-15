use serde::{Deserialize, Serialize};

use crate::{ExternalChain, SynergyFinalityAnchor};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayReceipt {
    pub transfer_id: String,
    pub destination_chain: ExternalChain,
    pub destination_transaction: String,
    pub synergy_finality: SynergyFinalityAnchor,
    pub authorization: Vec<u8>,
}
