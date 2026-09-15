use serde::{Deserialize, Serialize};

use crate::bounded;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteChoice {
    Approve,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceVote {
    pub proposal_root: String,
    pub authority_id: String,
    pub key_id: String,
    pub choice: VoteChoice,
    pub signature: Vec<u8>,
}

impl GovernanceVote {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate_shape()?;
        serde_json::to_vec(&(
            "SYNERGY_GOVERNANCE_VOTE_V1",
            &self.proposal_root,
            &self.authority_id,
            &self.key_id,
            self.choice,
        ))
        .map_err(|error| format!("encode governance vote transcript: {error}"))
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        if !bounded(&self.proposal_root, 256)
            || !bounded(&self.authority_id, 256)
            || !bounded(&self.key_id, 256)
            || self.signature.is_empty()
            || self.signature.len() > 64 * 1024
        {
            return Err("invalid governance vote".into());
        }
        Ok(())
    }
}

pub trait VoteVerifier {
    fn verify(&self, vote: &GovernanceVote) -> Result<(), String>;
}
