//! Closed request decoding before storage/provider work. These are the existing
//! historical read contracts, not R1 coordinate or identifier qualification.
use serde::de::DeserializeOwned;
use serde_json::Value;

use super::{AccountQuery, BlockQuery, TransactionQuery};
use crate::RpcError;

pub trait ValidatedReadQuery: DeserializeOwned {
    fn validate_read(&self) -> Result<(), RpcError>;

    fn from_params(params: Value) -> Result<Self, RpcError> {
        let query: Self = serde_json::from_value(params)
            .map_err(|_| RpcError::invalid_params("invalid read query parameters"))?;
        query.validate_read()?;
        Ok(query)
    }
}

macro_rules! validated_read {
    ($query:ty) => {
        impl ValidatedReadQuery for $query {
            fn validate_read(&self) -> Result<(), RpcError> {
                self.validate()
            }
        }
    };
}
validated_read!(AccountQuery);
validated_read!(BlockQuery);
validated_read!(TransactionQuery);
