use serde::{Deserialize, Serialize};

use crate::EtdagDigest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedIngressReceipt {
    pub envelope_id: EtdagDigest,
    pub context_root: EtdagDigest,
    pub target_height: u64,
    pub sender_nonce: u64,
    pub accepted_at_millis: u64,
}

impl ProtectedIngressReceipt {
    pub const fn may_determine_finality(&self) -> bool {
        false
    }
}
