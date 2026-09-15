use crate::{FinalizedBlockRecord, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusTransition {
    ProposalAccepted { height: u64, round: u64 },
    VoteAccepted { height: u64, round: u64 },
    TimeoutVoteAccepted { height: u64, round: u64 },
    QuorumCertified(SimplifiedQuorumCertificate),
    TimeoutCertified(SimplifiedTimeoutCertificate),
    Finalized(FinalizedBlockRecord),
    HeightAdvanced { height: u64, round: u64 },
    RoundAdvanced { height: u64, round: u64 },
    EpochBoundaryCertified { height: u64 },
}
