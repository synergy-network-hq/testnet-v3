use serde::{Deserialize, Serialize};
use synergy_protocol_types::NodeAddress;

pub const VALIDATOR_GET: &str = "synergy_getValidator";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorQuery {
    pub node_address: NodeAddress,
}

impl ValidatorQuery {
    pub fn validate(&self) -> Result<(), crate::RpcError> {
        NodeAddress::parse(self.node_address.to_string())
            .map(|_| ())
            .map_err(|error| crate::RpcError::invalid_params(error.to_string()))
    }
}
