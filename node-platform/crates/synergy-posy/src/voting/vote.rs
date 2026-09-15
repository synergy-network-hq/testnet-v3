use serde::{Deserialize, Serialize};

use crate::{ConsensusObjectContext, SimplifiedFinalityParent};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVote {
    pub context: ConsensusObjectContext,
    pub block_id: String,
    pub parent_block_id: String,
    pub parent: SimplifiedFinalityParent,
    pub takeover_tc_id: Option<String>,
    pub protected_execution_root: String,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub context: ConsensusObjectContext,
    pub lease_index: u64,
    pub timed_out_proposer: String,
    pub highest_parent: SimplifiedFinalityParent,
    pub previous_tc_id: Option<String>,
    pub last_voted_candidate: Option<crate::CertifiedCandidateSubject>,
    pub validator_id: String,
    pub key_id: String,
    pub signature: Vec<u8>,
}
