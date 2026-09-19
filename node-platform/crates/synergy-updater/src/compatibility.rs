use std::collections::BTreeMap;

use synergy_version::{
    ConfigSchemaVersion, DatabaseSchemaVersion, ProtocolComponent, ProtocolVersion,
};

use crate::VerifiedRelease;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeVersions {
    pub protocols: BTreeMap<ProtocolComponent, ProtocolVersion>,
    pub config_schema: ConfigSchemaVersion,
    pub database_schema: DatabaseSchemaVersion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityGate;

impl CompatibilityGate {
    pub fn check(
        &self,
        release: &VerifiedRelease,
        runtime: &RuntimeVersions,
    ) -> Result<(), &'static str> {
        if release.signed.release.config_schema != runtime.config_schema
            || release.signed.release.database_schema != runtime.database_schema
        {
            return Err("release schema is incompatible with the running node");
        }
        for (component, version) in &release.signed.release.protocols {
            if runtime.protocols.get(component) != Some(version) {
                return Err("release protocol version is incompatible with the running node");
            }
        }
        Ok(())
    }
}
