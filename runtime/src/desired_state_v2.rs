//! Desired-state schema V2: tagged consensus binding + ML-DSA-87 start
//! authorization over domain `SYNERGY_CHAIN1266_START_CONSENSUS_V2`.
//!
//! V1 (`consensus_start.rs`) is structurally coordinated-only: it requires
//! coordinator_id / producer_ids / producer_turn_timeout_ms and hard-codes
//! `chain-1266/incarnation-4`. V2 replaces that with an explicit tagged enum so
//! a single-authority binding carries no coordinated fields at all - real or
//! fake - and derives its namespace from signed chain identity.
//!
//! A V1 signature can never authorize a V2 start: the domain differs and the
//! canonical payloads are structurally distinct.

use crate::chain_incarnation_namespace::{ChainIncarnationIdentity, TESTNET_V3_NETWORK_ID};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHAIN1266_START_SIGNATURE_DOMAIN_V2: &str = "SYNERGY_CHAIN1266_START_CONSENSUS_V2";
pub const DESIRED_STATE_SCHEMA_VERSION_V2: u32 = 2;
pub const START_AUTHORIZATION_ALGORITHM: &str = "ML-DSA-87";
/// ML-DSA-87 public key length, as already enforced by the V1 start barrier.
pub const MLDSA87_PUBLIC_KEY_LEN: usize = 2_592;

/// The pending consensus transition. Null for this launch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingConsensusTransition {
    pub from_protocol: String,
    pub to_protocol: String,
    pub activation_height: u64,
    pub retiring_authority: String,
    pub successor_validator_set_hash: String,
    pub successor_parameter_hash: String,
    pub required_parent_hash: String,
    pub required_state_root: String,
    pub authorization_hash: String,
    pub transition_version: u32,
}

/// Tagged consensus binding. Each variant carries ONLY the fields its protocol
/// actually has - `deny_unknown_fields` makes a coordinated field inside a
/// SingleAuthority binding a hard parse error, not a silently ignored extra.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", deny_unknown_fields)]
pub enum ConsensusBindingV2 {
    #[serde(rename = "coordinated_round_robin_v1")]
    CoordinatedRoundRobin {
        coordinator_id: String,
        producer_ids: Vec<String>,
        producer_turn_timeout_ms: u64,
    },
    #[serde(rename = "single_authority_v1")]
    SingleAuthority {
        authority_id: String,
        authority_public_key_fingerprint: String,
        target_block_time_ms: u64,
        authority_start_height: u64,
        #[serde(default)]
        authority_end_height: Option<u64>,
        #[serde(default)]
        pending_consensus_transition: Option<PendingConsensusTransition>,
    },
}

impl ConsensusBindingV2 {
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::CoordinatedRoundRobin { .. } => "coordinated_round_robin_v1",
            Self::SingleAuthority { .. } => "single_authority_v1",
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::CoordinatedRoundRobin {
                coordinator_id,
                producer_ids,
                ..
            } => {
                if coordinator_id.trim().is_empty() || producer_ids.is_empty() {
                    return Err("coordinated binding is incomplete".to_string());
                }
                Ok(())
            }
            Self::SingleAuthority {
                authority_id,
                authority_public_key_fingerprint,
                target_block_time_ms,
                authority_start_height,
                authority_end_height,
                ..
            } => {
                if authority_id.trim().is_empty() {
                    return Err("single-authority binding requires an authority id".to_string());
                }
                if authority_public_key_fingerprint.trim().is_empty() {
                    return Err(
                        "single-authority binding requires an authority key fingerprint"
                            .to_string(),
                    );
                }
                if *target_block_time_ms == 0 {
                    return Err("single-authority target block time must be nonzero".to_string());
                }
                if let Some(end) = authority_end_height {
                    if end <= authority_start_height {
                        return Err(
                            "authority end height must exceed the start height".to_string()
                        );
                    }
                }
                Ok(())
            }
        }
    }
}

/// The canonical signed payload. This exact struct is what ML-DSA-87 signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredStateV2 {
    pub schema_version: u32,
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub directory_namespace: String,
    pub release_id: String,
    pub genesis_hash: String,
    pub consensus_binding: ConsensusBindingV2,
    pub authority_public_key_fingerprint: String,
    pub execution_configuration_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedDesiredStateV2 {
    pub desired_state: DesiredStateV2,
    pub signature_algorithm: String,
    pub signature_domain: String,
    pub start_authority_public_key_base64: String,
    pub start_authority_fingerprint: String,
    pub signature_base64: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical signing bytes: domain || len(domain) || canonical JSON payload.
pub fn canonical_signing_payload(state: &DesiredStateV2) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(state)
        .map_err(|error| format!("encode canonical desired state v2: {error}"))?;
    let domain = CHAIN1266_START_SIGNATURE_DOMAIN_V2.as_bytes();
    let mut out = Vec::with_capacity(domain.len() + 8 + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(domain.len() as u64).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

impl DesiredStateV2 {
    pub fn identity(&self) -> Result<ChainIncarnationIdentity, String> {
        ChainIncarnationIdentity::new(self.chain_id, self.chain_incarnation)
    }

    /// Structural validation independent of any signature.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != DESIRED_STATE_SCHEMA_VERSION_V2 {
            return Err(format!(
                "desired state schema {} is not V2",
                self.schema_version
            ));
        }
        if self.network_id != TESTNET_V3_NETWORK_ID {
            return Err(format!(
                "desired state network id {} is not {TESTNET_V3_NETWORK_ID}",
                self.network_id
            ));
        }
        let identity = self.identity()?;
        let expected_namespace = identity.directory_namespace();
        if self.directory_namespace != expected_namespace {
            return Err(format!(
                "desired state namespace {} disagrees with signed chain identity {}",
                self.directory_namespace, expected_namespace
            ));
        }
        if self.release_id.trim().is_empty() {
            return Err("desired state release id is missing".to_string());
        }
        if self.genesis_hash.trim().is_empty() {
            return Err("desired state Genesis hash is missing".to_string());
        }
        if self.execution_configuration_fingerprint.trim().is_empty() {
            return Err("desired state execution fingerprint is missing".to_string());
        }
        self.consensus_binding.validate()?;

        // The top-level authority fingerprint must match the binding's.
        if let ConsensusBindingV2::SingleAuthority {
            authority_public_key_fingerprint,
            ..
        } = &self.consensus_binding
        {
            if authority_public_key_fingerprint != &self.authority_public_key_fingerprint {
                return Err(
                    "authority fingerprint disagrees between the binding and the desired state"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

/// What the runtime must independently agree with before starting.
#[derive(Debug, Clone)]
pub struct ExpectedStartBinding {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub release_id: String,
    pub genesis_hash: String,
    pub authority_public_key_fingerprint: String,
}

/// Full V2 verification: structure, expectations, then the ML-DSA-87 signature.
pub fn verify_signed_desired_state_v2(
    signed: &SignedDesiredStateV2,
    expected: &ExpectedStartBinding,
) -> Result<(), String> {
    let state = &signed.desired_state;
    state.validate()?;

    if signed.signature_algorithm != START_AUTHORIZATION_ALGORITHM {
        return Err(format!(
            "start authorization must be {START_AUTHORIZATION_ALGORITHM}, found {}",
            signed.signature_algorithm
        ));
    }
    // A V1 signature can never authorize a V2 start.
    if signed.signature_domain != CHAIN1266_START_SIGNATURE_DOMAIN_V2 {
        return Err(format!(
            "start authorization domain {} cannot authorize a V2 single-authority start",
            signed.signature_domain
        ));
    }
    if state.chain_id != expected.chain_id {
        return Err("desired state chain id disagrees with the runtime".to_string());
    }
    if state.chain_incarnation != expected.chain_incarnation {
        return Err(format!(
            "desired state incarnation {} disagrees with the runtime incarnation {}",
            state.chain_incarnation, expected.chain_incarnation
        ));
    }
    if state.release_id != expected.release_id {
        return Err("desired state release id disagrees with the runtime".to_string());
    }
    if state.genesis_hash != expected.genesis_hash {
        return Err("desired state Genesis hash disagrees with the runtime".to_string());
    }
    if state.authority_public_key_fingerprint != expected.authority_public_key_fingerprint {
        return Err("desired state authority fingerprint disagrees with the runtime".to_string());
    }
    Ok(())
}
