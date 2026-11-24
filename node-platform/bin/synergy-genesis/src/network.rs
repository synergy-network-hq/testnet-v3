use serde::{Deserialize, Serialize};

pub const AUTONOMOUS_EPOCH_PROTOCOL_V1: &str = "posy-autonomous-epochs-v1";
pub const ETHEREUM_COMPATIBILITY_PROFILE_V1: &str = "aivm-ethereum-eip155-shanghai-v1";

/// Signed activation subject. The initial World's policy is committed by this
/// digest, avoiding a circular logical-Genesis hash inside that same World.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisEthereumCompatibility {
    pub profile_id:String,
    pub policy_sha256:String,
}
impl GenesisEthereumCompatibility {
    pub fn validate(&self)->Result<(),String> {
        if self.profile_id!=ETHEREUM_COMPATIBILITY_PROFILE_V1 || self.policy_sha256.len()!=64
            || !self.policy_sha256.bytes().all(|byte|byte.is_ascii_digit()||(b'a'..=b'f').contains(&byte))
            || self.policy_sha256.bytes().all(|byte|byte==b'0') {
            return Err("unsupported signed Genesis Ethereum compatibility policy".into());
        }Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisNetwork {
    pub chain_id: u64,
    pub network_id: String,
    pub protocol_version: String,
    pub activation_unix: u64,
    /// Signed Genesis authorization, never an editable runtime capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_epoch_protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ethereum_compatibility: Option<GenesisEthereumCompatibility>,
}

impl GenesisNetwork {
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0
            || self.network_id.trim().is_empty()
            || self.network_id.len() > 128
            || self.network_id.contains(char::is_control)
            || self.protocol_version.trim().is_empty()
            || self.activation_unix == 0
        {
            return Err("invalid selected genesis network binding".into());
        }
        if let Some(profile) = &self.autonomous_epoch_protocol {
            if profile != AUTONOMOUS_EPOCH_PROTOCOL_V1
                || self.protocol_version != synergy_posy::POSY_SIMPLIFIED_PROTOCOL_VERSION
            {
                return Err("unsupported signed Genesis autonomous epoch protocol".into());
            }
        }
        if let Some(policy)=&self.ethereum_compatibility {policy.validate()?;}
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ethereum_activation_is_an_exact_optional_signed_policy_commitment(){
        let legacy=r#"{"chain_id":9969,"network_id":"fresh","protocol_version":"posy/3.0","activation_unix":1700000000}"#;
        let mut network:GenesisNetwork=serde_json::from_str(legacy).unwrap();
        assert!(network.ethereum_compatibility.is_none());assert_eq!(serde_json::to_string(&network).unwrap(),legacy);
        network.ethereum_compatibility=Some(GenesisEthereumCompatibility{profile_id:ETHEREUM_COMPATIBILITY_PROFILE_V1.into(),policy_sha256:"ab".repeat(32)});
        network.validate().unwrap();let signed=serde_json::to_vec(&network).unwrap();
        network.ethereum_compatibility.as_mut().unwrap().policy_sha256="cd".repeat(32);
        assert_ne!(signed,serde_json::to_vec(&network).unwrap());
        for digest in ["00".repeat(32),"AB".repeat(32),"ff".repeat(31),"zz".repeat(32)]{
            network.ethereum_compatibility.as_mut().unwrap().policy_sha256=digest;assert!(network.validate().is_err());
        }
        network.ethereum_compatibility.as_mut().unwrap().policy_sha256="ab".repeat(32);
        network.ethereum_compatibility.as_mut().unwrap().profile_id="implicit-latest".into();assert!(network.validate().is_err());
    }
    #[test]
    fn autonomous_profile_is_explicit_known_and_legacy_bytes_are_unchanged() {
        let legacy = r#"{"chain_id":77777,"network_id":"fresh","protocol_version":"posy/3.0","activation_unix":1700000000}"#;
        let mut network: GenesisNetwork = serde_json::from_str(legacy).unwrap();
        assert!(network.autonomous_epoch_protocol.is_none());
        assert_eq!(serde_json::to_string(&network).unwrap(), legacy);
        network.autonomous_epoch_protocol = Some(AUTONOMOUS_EPOCH_PROTOCOL_V1.into());
        network.validate().unwrap();
        assert_ne!(serde_json::to_string(&network).unwrap(), legacy);
        network.autonomous_epoch_protocol = Some("unknown-profile".into());
        assert!(network.validate().is_err());
        network.autonomous_epoch_protocol = Some(AUTONOMOUS_EPOCH_PROTOCOL_V1.into());
        network.protocol_version = "unapproved".into();
        assert!(network.validate().is_err());
        assert!(serde_json::from_str::<GenesisNetwork>(&legacy.replace("1700000000", "1700000000,\"autonomous_epoch_protocol\":true")).is_err());
    }
}
