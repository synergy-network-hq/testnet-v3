use crate::{BlockVote, PosyResult, SimplifiedQuorumCertificate};

pub fn build_quorum_certificate(votes: Vec<BlockVote>) -> PosyResult<SimplifiedQuorumCertificate> {
    SimplifiedQuorumCertificate::from_votes(votes)
}
