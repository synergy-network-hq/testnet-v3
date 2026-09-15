use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{AuthorityPlane, Capability, NodeRole, RoleError, RolePorts};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleProfile {
    pub role: NodeRole,
    pub plane: AuthorityPlane,
    pub capabilities: BTreeSet<Capability>,
    pub ports: RolePorts,
}

impl RoleProfile {
    pub fn validate(&self) -> Result<(), RoleError> {
        self.ports.validate()?;
        crate::validate_authority_plane(
            self.plane,
            &self.capabilities.iter().copied().collect::<Vec<_>>(),
        )?;
        if !self.role.hosts_posy_signing_component()
            && self.capabilities.iter().any(|capability| {
                matches!(
                    capability,
                    Capability::ProposeBlocks | Capability::VoteConsensus
                )
            })
        {
            return Err(RoleError::Invalid(
                "service role cannot declare PoSy signing duties".into(),
            ));
        }
        if self.role.hosts_posy_signing_component()
            && self.capabilities.contains(&Capability::VoteConsensus)
            && !self.capabilities.contains(&Capability::NetworkTransport)
        {
            return Err(RoleError::Invalid(
                "consensus voting requires network transport".into(),
            ));
        }
        Ok(())
    }

    pub fn supports(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}
