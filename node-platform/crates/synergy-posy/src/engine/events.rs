use serde::{Deserialize, Serialize};

use crate::{
    BlockVote, SimplifiedProposal, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
    TimeoutVote,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ConsensusEvent {
    Proposal(SimplifiedProposal),
    ProposalDelivery(crate::ProposalDeliveryEnvelope),
    BlockVote(BlockVote),
    TimeoutVote(TimeoutVote),
    QuorumCertificate(SimplifiedQuorumCertificate),
    TimeoutCertificate(SimplifiedTimeoutCertificate),
}
