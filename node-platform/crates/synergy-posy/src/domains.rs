//! Canonical domain separation labels owned by the PoSy protocol.
//!
//! These labels name existing PoSy transcripts. They do not grant authority or
//! introduce another consensus state machine.

pub const PROPOSAL_DOMAIN: &str = "PoSy/Consensus/v3/Proposal";
pub const VOTE_DOMAIN: &str = "PoSy/Consensus/v3/BlockVote";
pub const TIMEOUT_VOTE_DOMAIN: &str = "PoSy/Consensus/v3/TimeoutVote";
pub const QUORUM_CERTIFICATE_DOMAIN: &str = "SYNERGY_POSY_SIMPLIFIED_QC_V1";
pub const TIMEOUT_CERTIFICATE_DOMAIN: &str = "SYNERGY_POSY_SIMPLIFIED_TC_V1";
pub const FINALITY_DOMAIN: &str = "SYNERGY_POSY_SIMPLIFIED_FINALITY_V1";

pub fn is_consensus_signing_domain(domain: &str) -> bool {
    matches!(domain, PROPOSAL_DOMAIN | VOTE_DOMAIN | TIMEOUT_VOTE_DOMAIN)
}
