//! SynQ security policy presets.

use alloc::collections::BTreeSet;
use serde::{Deserialize, Serialize};

use crate::{
    algorithms::{AlgorithmId, SecurityLevel},
    domain::{ChainId, NetworkId},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynQSecurityPolicy {
    /// Historical serialized policies omit this field. Runtime policies always
    /// select V2; V1 is retained for offline signed-vector verification only.
    #[serde(default = "historical_signer_format")]
    pub signer_format_version: u8,
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

fn historical_signer_format() -> u8 {
    1
}

impl SynQSecurityPolicy {
    /// Mandatory account-domain policy bound to the selected authenticated network.
    pub fn for_network(chain_id: ChainId, network_id: NetworkId) -> Self {
        let mut tx = BTreeSet::new();
        tx.insert(AlgorithmId::MlDsa87);
        let deploy = tx.clone();
        let call = tx.clone();

        Self {
            signer_format_version: 2,
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
            required_chain_id: Some(chain_id),
            required_network_id: Some(network_id),
        }
    }
}
