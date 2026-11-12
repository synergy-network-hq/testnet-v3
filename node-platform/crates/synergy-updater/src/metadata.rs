use serde::{Deserialize, Serialize};
use synergy_aegis::Signature;
use synergy_version::{
    ConfigSchemaVersion, DatabaseSchemaVersion, ProtocolComponent, ProtocolVersion, ReleaseVersion,
};

use crate::ReleaseChannel;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub platform: String,
    pub length: u64,
    pub sha3_256: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    pub format_version: u32,
    pub release_id: String,
    pub version: ReleaseVersion,
    pub channel: ReleaseChannel,
    pub sequence: u64,
    pub published_at_unix_seconds: u64,
    pub artifact: ArtifactMetadata,
    pub protocols: Vec<(ProtocolComponent, ProtocolVersion)>,
    pub config_schema: ConfigSchemaVersion,
    pub database_schema: DatabaseSchemaVersion,
    pub protocol_activation_commitment: Option<String>,
}

impl ReleaseMetadata {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format_version != 2
            || self.release_id.is_empty()
            || self.release_id.len() > 256
            || self.sequence == 0
            || self.published_at_unix_seconds == 0
            || self.artifact.platform.is_empty()
            || self.artifact.source.is_empty()
            || self.artifact.length == 0
            || self.artifact.length > crate::MAXIMUM_ARTIFACT_BYTES
            || self.artifact.sha3_256.len() != 64
            || !self
                .artifact
                .sha3_256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid release metadata");
        }
        Ok(())
    }

    /// Version 2 binds the software-release domain and chain cryptographically.
    /// Version 1 raw-JSON signatures are deliberately not accepted.
    pub fn signing_bytes(&self, chain_id: u64) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&("synergy.software.release.v2", chain_id, self))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseMetadata {
    pub release: ReleaseMetadata,
    pub signature: Signature,
    pub public_key: Vec<u8>,
}
