use synergy_protocol_types::NodeRole;

use crate::{ConsensusMode, NodeConfiguration};

impl NodeConfiguration {
    /// Reports whether the selected role can host the PoSy signing component.
    /// This is a service-placement decision, not proof of membership.
    pub const fn role_hosts_consensus_signer(&self) -> bool {
        matches!(self.role, NodeRole::Validator)
            && matches!(self.consensus.mode, ConsensusMode::ValidateAndVote)
    }

    /// A local role declaration never creates validator authority.
    pub const fn role_grants_validator_authority(&self) -> bool {
        false
    }
}
