//! Shared EXISTING closed durable record data. Parsing these public fields
//! supplies neither a reservation capability nor membership/signing authority.
//! The sole owning journal validates originals under the retained writer fence.
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Safety {
    pub generation: u64,
    pub last_approval_round: Option<u64>,
    pub pass_fence: Option<u64>,
    pub lock: Option<[Vec<u8>; 2]>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub header: Vec<u8>,
    pub message: Vec<u8>,
    pub subject: Vec<u8>,
    pub safety_generation: u64,
    pub parent_qc: Option<Vec<u8>>,
    pub suppressed: bool,
    pub signature: Option<Vec<u8>>,
}

/// Existing stored cursor data; original proof must be authenticated by PoSy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finalized {
    pub height: u64,
    pub block: Vec<u8>,
    pub state: Vec<u8>,
    pub receipts: Vec<u8>,
    pub original_proof: Vec<u8>,
}
