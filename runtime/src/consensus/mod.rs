//! Synergy Network Consensus Module
//!
//! This module handles initialization and coordination of the
//! consensus mechanism used to secure the Synergy Testnet blockchain.

pub mod anti_divergence;
pub mod cartel_detection;
pub mod chain_durability;
pub mod consensus_algorithm;
pub mod consensus_fork;
pub mod coordinated_finality_store;
pub mod coordinated_round_robin;
pub mod coordinated_runtime;
pub mod dao_governance;
pub mod diagnostics;
pub mod dual_quorum;
pub mod legacy_canonical_lock;
pub mod posy;
pub mod self_realign;
pub mod signing_authority;
pub mod synergy_score;
pub mod testnet_v3_bootstrap;
pub mod testnet_v3_finality_context;
#[cfg(test)]
pub mod tests;
pub mod timing_trace;
pub mod typed_coordinator;
pub mod typed_finality_observer;
pub mod typed_finality_store;
pub mod typed_prepared_store;
pub mod validator_keys;
pub mod validator_scoring_params;
pub mod vrf;

/// Legacy entry point retained only to fail closed while the typed operational
/// PoSy v2.2 coordinator is completed.
pub fn start_consensus() -> Result<(), String> {
    Err(
        "POSY_V2_2_OPERATIONAL_COORDINATOR_NOT_READY: inherited consensus startup is disabled"
            .to_string(),
    )
}
