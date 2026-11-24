//! Canonical application-facing amendment encoding. Constructing a spec or
//! mutation grants no authority: the native owner independently authenticates
//! scope, frozen dual quorum, one-use state and finalized activation height.
use crate::GovernedStateMutation;
use serde::{Deserialize, Serialize};

pub const ETHEREUM_ACTIVATION_ACTION_V1: &str = "aivm-ethereum-activation-v1";
pub const ETHEREUM_ACTIVATION_TARGET_V1: &str = "canonical";
pub const ETHEREUM_ACTIVATION_RECORD_KEY_V1: &str =
    "governance/aivm-ethereum-activation-v1/canonical";
pub const ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthereumActivationSpec {
    pub schema_version: u32,
    pub profile_id: String,
    pub chain_id: u64,
    pub network_id: String,
    pub genesis_hash: String,
    pub frozen_epoch: u64,
    pub frozen_epoch_context_root: String,
    pub install_height: u64,
    pub activation_height: u64,
    pub policy_sha256: String,
    pub policy_bytes: Vec<u8>,
}
impl EthereumActivationSpec {
    /// Exact field order/bytes used by the proposal's signed mutation root.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|error| error.to_string())
    }
    /// Builds only the canonical, unused initial-installation CAS mutation.
    /// Apps must gather genuine frozen approvals and submit it through native
    /// account admission; this helper does not authorize or install the policy.
    pub fn mutation(&self) -> Result<GovernedStateMutation, String> {
        Ok(GovernedStateMutation {
            action_kind: ETHEREUM_ACTIVATION_ACTION_V1.into(),
            target: ETHEREUM_ACTIVATION_TARGET_V1.into(),
            expected_value: None,
            value: self.canonical_bytes()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exported_spec_preserves_signed_wire_contract() {
        let bytes=br#"{"schema_version":1,"profile_id":"aivm-ethereum-eip155-shanghai-v1","chain_id":99999,"network_id":"canary-fixture","genesis_hash":"genesis","frozen_epoch":1,"frozen_epoch_context_root":"epoch","install_height":10,"activation_height":286,"policy_sha256":"policy","policy_bytes":[123,125]}"#;
        // Placeholder hashes deliberately exercise encoding only, not native
        // policy authorization. Native validation rejects this incomplete spec.
        let spec: EthereumActivationSpec = serde_json::from_slice(bytes).unwrap();
        assert_eq!(spec.canonical_bytes().unwrap(), bytes);
        let mutation = spec.mutation().unwrap();
        assert_eq!(mutation.action_kind, "aivm-ethereum-activation-v1");
        assert_eq!(mutation.target, "canonical");
        assert!(mutation.expected_value.is_none());
        assert_eq!(mutation.value, bytes);
        assert_eq!(
            mutation.state_key().unwrap(),
            "governance/aivm-ethereum-activation-v1/canonical"
        );
        let mut unknown = serde_json::from_slice::<serde_json::Value>(bytes).unwrap();
        unknown["caller_threshold"] = serde_json::json!(1);
        assert!(serde_json::from_value::<EthereumActivationSpec>(unknown).is_err());
    }
}
