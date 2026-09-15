use serde::{Deserialize, Serialize};

use crate::{Capability, RoleError};

/// Non-authoritative description of where a service is exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityPlane {
    Public,
    Operator,
    ConsensusCandidate,
}

pub fn validate_authority_plane(
    plane: AuthorityPlane,
    capabilities: &[Capability],
) -> Result<(), RoleError> {
    if plane != AuthorityPlane::ConsensusCandidate
        && capabilities.iter().any(|capability| {
            matches!(
                capability,
                Capability::ProposeBlocks | Capability::VoteConsensus
            )
        })
    {
        return Err(RoleError::Invalid(
            "consensus duties require the consensus-candidate plane".into(),
        ));
    }
    Ok(())
}
