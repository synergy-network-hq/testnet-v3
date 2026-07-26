//! SynQ security policy presets.

use alloc::collections::BTreeSet;
use serde::{Deserialize, Serialize};

use crate::{
    algorithms::{AlgorithmId, SecurityLevel},
    domain::{ChainId, NetworkId},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQSecurityPolicy {
    pub min_signature_security_level: SecurityLevel,
    pub allowed_tx_signature_algorithms: BTreeSet<AlgorithmId>,
    pub allowed_deploy_signature_algorithms: BTreeSet<AlgorithmId>,
    pub allowed_call_signature_algorithms: BTreeSet<AlgorithmId>,
    pub require_chain_id_binding: bool,
    pub require_domain_separation: bool,
    pub require_nonce: bool,
    pub require_expiration: bool,
    pub max_signature_size_bytes: usize,
    pub max_public_key_size_bytes: usize,
    pub required_chain_id: Option<ChainId>,
    pub required_network_id: Option<NetworkId>,
}

impl SynQSecurityPolicy {
    pub fn testnet_1266_policy() -> Self {
        let mut tx = BTreeSet::new();
        tx.insert(AlgorithmId::MlDsa65);
        let deploy = tx.clone();
        let call = tx.clone();

        Self {
            min_signature_security_level: SecurityLevel::Level3,
            allowed_tx_signature_algorithms: tx,
            allowed_deploy_signature_algorithms: deploy,
            allowed_call_signature_algorithms: call,
            require_chain_id_binding: true,
            require_domain_separation: true,
            require_nonce: true,
            require_expiration: true,
            max_signature_size_bytes: 8 * 1024,
            max_public_key_size_bytes: 4 * 1024,
            required_chain_id: Some(ChainId::testnet_1266()),
            required_network_id: Some(NetworkId::testnet()),
        }
    }

    pub fn devnet_policy() -> Self {
        let mut policy = Self::testnet_1266_policy();
        policy.required_chain_id = None;
        policy.required_network_id = Some(NetworkId(alloc::string::String::from("devnet")));
        policy
    }

    pub fn mainnet_candidate_policy() -> Self {
        let mut policy = Self::testnet_1266_policy();
        policy.required_chain_id = None;
        policy.required_network_id = Some(NetworkId(alloc::string::String::from("mainnet")));
        policy
    }

    pub fn strict_policy() -> Self {
        Self::testnet_1266_policy()
    }
}

impl Default for SynQSecurityPolicy {
    fn default() -> Self {
        Self::testnet_1266_policy()
    }
}
