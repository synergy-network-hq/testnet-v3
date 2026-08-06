//! Chain 1266 startup dispatch.
//!
//! Which start-authorization verifier runs is decided by the canonical Genesis
//! document and by nothing else. Environment variables, local configuration and
//! the presence or absence of an installed artifact can all be wrong; none of
//! them may choose a verifier.
//!
//!   * incarnation 4 + `coordinated_round_robin_v1`
//!         -> the legacy V1 desired-state verifier, unchanged.
//!   * incarnation 5 + `single_authority_v1`
//!         -> the ML-DSA-87 signed `DesiredStateV2` verifier, exclusively.
//!            The V1 verifier is forbidden on this path and is never invoked.
//!
//! Any other Chain 1266 incarnation/protocol pairing fails closed. A missing or
//! invalid V2 authorization on the incarnation-5 path fails closed and must
//! never fall back to V1 or to the coordinated driver.

use super::single_authority_startup::{
    resolve_verified_consensus_startup, StartupExpectation, VerifiedConsensusStartup,
    LAUNCH_AUTHORITY_ID, LAUNCH_CHAIN_ID, LAUNCH_CHAIN_INCARNATION, LAUNCH_NETWORK_ID,
    LAUNCH_TARGET_BLOCK_TIME_MS,
};
use crate::desired_state_v2::SignedDesiredStateV2;

/// The archived incarnation and its protocol. Frozen historical values.
pub const HISTORICAL_V1_CHAIN_INCARNATION: u64 = 4;
pub const HISTORICAL_V1_CONSENSUS_PROTOCOL: &str = "coordinated_round_robin_v1";

/// Launch pins for Chain 1266 incarnation 5.
pub const LAUNCH_GENESIS_HASH: &str =
    "2272fe2b48c6e2019b27223f61ba8d8a82b58656fe9daab50c81f224a301ca74";
pub const LAUNCH_RELEASE_ID: &str = "chain1266-incarnation-5-single-authority-rc1";
pub const LAUNCH_AUTHORITY_ADDRESS: &str = "synv11n57gc4h9tnt3c78crncx46hnlg9vz8eu4lu";
pub const LAUNCH_START_AUTHORITY_FINGERPRINT: &str =
    "sha256:c39e17970a711cadbbb6e43f49f322b14bb1710a2fb6c90822b081fe7f5ce5b4";
pub const LAUNCH_DIRECTORY_NAMESPACE: &str = "chain-1266/incarnation-5";

/// Which start-authorization verifier the Genesis document selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain1266StartupDispatch {
    /// Incarnation 5: signed `DesiredStateV2` only.
    SingleAuthorityV2,
    /// Incarnation 4: the unchanged legacy V1 verifier.
    CoordinatedV1,
    /// Not Chain 1266: existing behaviour is preserved verbatim.
    NonChain1266,
}

/// The dispatch decision. Pure: it reads only trusted Genesis fields.
pub fn dispatch_chain1266_startup(
    genesis_chain_id: u64,
    genesis_chain_incarnation: u64,
    genesis_consensus_protocol: &str,
) -> Result<Chain1266StartupDispatch, String> {
    const SINGLE_AUTHORITY: &str =
        crate::consensus::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL;

    if genesis_chain_id != LAUNCH_CHAIN_ID {
        return Ok(Chain1266StartupDispatch::NonChain1266);
    }
    match (genesis_chain_incarnation, genesis_consensus_protocol) {
        (LAUNCH_CHAIN_INCARNATION, SINGLE_AUTHORITY) => {
            Ok(Chain1266StartupDispatch::SingleAuthorityV2)
        }
        (HISTORICAL_V1_CHAIN_INCARNATION, HISTORICAL_V1_CONSENSUS_PROTOCOL) => {
            Ok(Chain1266StartupDispatch::CoordinatedV1)
        }
        (incarnation, protocol) => Err(format!(
            "unsupported Chain 1266 incarnation/protocol pairing: Genesis binds incarnation \
             {incarnation} with protocol {protocol}; only incarnation \
             {LAUNCH_CHAIN_INCARNATION}/{SINGLE_AUTHORITY} and incarnation \
             {HISTORICAL_V1_CHAIN_INCARNATION}/{HISTORICAL_V1_CONSENSUS_PROTOCOL} can start"
        )),
    }
}

/// The values the incarnation-5 branch pins after the V2 verifier has run.
#[derive(Debug, Clone)]
pub struct SingleAuthorityLaunchPins {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub release_id: String,
    pub directory_namespace: String,
    pub authority_id: String,
    pub authority_address: String,
    pub target_block_time_ms: u64,
    pub authority_start_height: u64,
    pub start_authority_fingerprint: String,
}

impl SingleAuthorityLaunchPins {
    /// The frozen incarnation-5 launch binding.
    pub fn incarnation5() -> Self {
        Self {
            chain_id: LAUNCH_CHAIN_ID,
            chain_incarnation: LAUNCH_CHAIN_INCARNATION,
            network_id: LAUNCH_NETWORK_ID.to_string(),
            genesis_hash: LAUNCH_GENESIS_HASH.to_string(),
            release_id: LAUNCH_RELEASE_ID.to_string(),
            directory_namespace: LAUNCH_DIRECTORY_NAMESPACE.to_string(),
            authority_id: LAUNCH_AUTHORITY_ID.to_string(),
            authority_address: LAUNCH_AUTHORITY_ADDRESS.to_string(),
            target_block_time_ms: LAUNCH_TARGET_BLOCK_TIME_MS,
            authority_start_height: 1,
            start_authority_fingerprint: LAUNCH_START_AUTHORITY_FINGERPRINT.to_string(),
        }
    }
}

/// Verifies an installed incarnation-5 single-authority activation.
///
/// This delegates to the ONE existing V2 verifier
/// (`resolve_verified_consensus_startup`) and then asserts the launch pins.
/// It creates no second verifier and never touches
/// `desired_state::verify_chain1266_desired_state`.
///
/// Returns the verified release id. Every failure is closed: the caller must
/// refuse to start, never retry under V1, and never fall through to the
/// coordinated driver.
pub fn verify_single_authority_v2_activation(
    supplied_desired_state_bytes: &[u8],
    signed: &SignedDesiredStateV2,
    expectation: &StartupExpectation,
    local_validator_address: &str,
    pins: &SingleAuthorityLaunchPins,
) -> Result<String, String> {
    // The bootstrap signer is pinned before the signature is even considered.
    if signed.start_authority_fingerprint != pins.start_authority_fingerprint {
        return Err(format!(
            "start authorization is not signed by the incarnation-5 bootstrap identity: \
             expected {}, found {}",
            pins.start_authority_fingerprint, signed.start_authority_fingerprint
        ));
    }

    // The existing V2 verifier. Canonical form, V2 domain, ML-DSA-87 signature
    // over the canonical payload, chain/incarnation/network/namespace/release/
    // Genesis-hash/authority binding, ML-DSA-65 authority algorithm, start
    // height 1, absent end height and null pending transition are all
    // established here.
    let verified =
        resolve_verified_consensus_startup(supplied_desired_state_bytes, signed, expectation)?;

    let plan = match verified {
        VerifiedConsensusStartup::SingleAuthority(plan) => plan,
        VerifiedConsensusStartup::CoordinatedRoundRobin => {
            return Err(
                "Genesis binds single_authority_v1 but the signed DesiredStateV2 selected \
                 coordinated_round_robin_v1; an incarnation-5 activation must never fall \
                 through to the coordinated path"
                    .to_string(),
            )
        }
    };

    for (label, actual, expected) in [
        ("chain", plan.chain_id.to_string(), pins.chain_id.to_string()),
        (
            "incarnation",
            plan.chain_incarnation.to_string(),
            pins.chain_incarnation.to_string(),
        ),
        ("network", plan.network_id.clone(), pins.network_id.clone()),
        (
            "Genesis hash",
            plan.genesis_hash.clone(),
            pins.genesis_hash.clone(),
        ),
        ("release", plan.release_id.clone(), pins.release_id.clone()),
        (
            "namespace",
            plan.directory_namespace.clone(),
            pins.directory_namespace.clone(),
        ),
        (
            "authority",
            plan.authority_id.clone(),
            pins.authority_id.clone(),
        ),
        (
            "target block time ms",
            plan.target_block_time_ms.to_string(),
            pins.target_block_time_ms.to_string(),
        ),
        (
            "authority start height",
            plan.authority_start_height.to_string(),
            pins.authority_start_height.to_string(),
        ),
        (
            "local authority address",
            local_validator_address.to_string(),
            pins.authority_address.clone(),
        ),
        (
            "local authority identity",
            expectation.authority_id.clone(),
            pins.authority_id.clone(),
        ),
    ] {
        if actual != expected {
            return Err(format!(
                "verified activation {label} {actual} is not the pinned launch value {expected}"
            ));
        }
    }

    Ok(plan.release_id.clone())
}
