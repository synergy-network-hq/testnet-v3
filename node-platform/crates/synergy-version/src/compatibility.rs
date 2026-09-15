//! Explicit compatibility decisions over independent version domains.

use serde::{Deserialize, Serialize};

use crate::{ConfigSchemaVersion, DatabaseSchemaVersion, ProtocolComponent, ProtocolVersion};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityRequirement {
    pub component: ProtocolComponent,
    pub minimum: ProtocolVersion,
    pub maximum: ProtocolVersion,
}

impl CompatibilityRequirement {
    pub const fn accepts(&self, version: ProtocolVersion) -> bool {
        version.get() >= self.minimum.get() && version.get() <= self.maximum.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub protocols: Vec<CompatibilityRequirement>,
    pub config: ConfigSchemaVersion,
    pub database: DatabaseSchemaVersion,
}

impl CompatibilityMatrix {
    pub fn evaluate(
        &self,
        component: ProtocolComponent,
        version: ProtocolVersion,
    ) -> Compatibility {
        match self
            .protocols
            .iter()
            .find(|requirement| requirement.component == component)
        {
            Some(requirement) if requirement.accepts(version) => Compatibility::Compatible,
            Some(requirement) => Compatibility::UnsupportedProtocol {
                component,
                received: version,
                minimum: requirement.minimum,
                maximum: requirement.maximum,
            },
            None => Compatibility::UnspecifiedProtocol(component),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum Compatibility {
    Compatible,
    UnsupportedProtocol {
        component: ProtocolComponent,
        received: ProtocolVersion,
        minimum: ProtocolVersion,
        maximum: ProtocolVersion,
    },
    UnspecifiedProtocol(ProtocolComponent),
}
