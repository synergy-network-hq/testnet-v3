use serde::{Deserialize, Serialize};

use crate::{
    BlockVote, SimplifiedProposal, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
    TimeoutVote,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusEvent {
    Proposal(SimplifiedProposal),
    BlockVote(BlockVote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(SimplifiedQuorumCertificate),
    TimeoutCertificate(SimplifiedTimeoutCertificate),
}
