//! Deterministic chain-identity namespace derivation.
//!
//! Replaces the hard-coded `chain-1266/incarnation-4` literal. The namespace is
//! DERIVED from signed chain identity, so future incarnations need no source
//! patch, and every surface (Genesis, desired state, activation, runtime
//! config, data path, release manifest, RPC/Atlas network identity) can be
//! cross-checked against one canonical value.

use serde::{Deserialize, Serialize};

/// The canonical Testnet-v3 network identity.
pub const TESTNET_V3_NETWORK_ID: &str = "synergy-testnet-v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainIncarnationIdentity {
    pub chain_id: u64,
    pub chain_incarnation: u64,
}

impl ChainIncarnationIdentity {
    pub fn new(chain_id: u64, chain_incarnation: u64) -> Result<Self, String> {
        if chain_id == 0 {
            return Err("chain id must be nonzero".to_string());
        }
        if chain_incarnation == 0 {
            return Err("chain incarnation must be nonzero".to_string());
        }
        Ok(Self {
            chain_id,
            chain_incarnation,
        })
    }

    /// The one canonical namespace form: `chain-<id>/incarnation-<n>`.
    pub fn directory_namespace(&self) -> String {
        format!(
            "chain-{}/incarnation-{}",
            self.chain_id, self.chain_incarnation
        )
    }

    /// Filesystem-safe variant for data directories.
    pub fn data_directory_component(&self) -> String {
        format!(
            "chain-{}-incarnation-{}",
            self.chain_id, self.chain_incarnation
        )
    }
}

/// Cross-surface consistency check. Every surface that carries a namespace
/// must agree with the identity that was actually signed.
#[derive(Debug, Clone, Default)]
pub struct NamespaceCrossCheck {
    pub genesis: Option<String>,
    pub desired_state: Option<String>,
    pub activation_authorization: Option<String>,
    pub runtime_config: Option<String>,
    pub data_path: Option<String>,
    pub release_manifest: Option<String>,
    pub rpc_network_identity: Option<String>,
    pub atlas_network_identity: Option<String>,
}

impl NamespaceCrossCheck {
    pub fn verify(&self, identity: &ChainIncarnationIdentity) -> Result<(), String> {
        let expected = identity.directory_namespace();
        let surfaces: [(&str, &Option<String>); 8] = [
            ("genesis", &self.genesis),
            ("desired state", &self.desired_state),
            ("activation authorization", &self.activation_authorization),
            ("runtime configuration", &self.runtime_config),
            ("data path", &self.data_path),
            ("release manifest", &self.release_manifest),
            ("RPC network identity", &self.rpc_network_identity),
            ("Atlas network identity", &self.atlas_network_identity),
        ];
        for (label, actual) in surfaces {
            if let Some(actual) = actual {
                if actual != &expected {
                    return Err(format!(
                        "{label} namespace {actual} disagrees with the signed chain identity \
                         {expected}"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Parses a namespace back to its identity, rejecting any malformed form.
pub fn parse_directory_namespace(value: &str) -> Result<ChainIncarnationIdentity, String> {
    let (chain_part, incarnation_part) = value
        .split_once('/')
        .ok_or_else(|| format!("malformed chain namespace: {value}"))?;
    let chain_id = chain_part
        .strip_prefix("chain-")
        .ok_or_else(|| format!("malformed chain namespace: {value}"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid chain id in namespace {value}: {error}"))?;
    let chain_incarnation = incarnation_part
        .strip_prefix("incarnation-")
        .ok_or_else(|| format!("malformed chain namespace: {value}"))?
        .parse::<u64>()
        .map_err(|error| format!("invalid incarnation in namespace {value}: {error}"))?;
    ChainIncarnationIdentity::new(chain_id, chain_incarnation)
}
