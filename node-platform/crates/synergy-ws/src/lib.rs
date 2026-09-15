//! Bounded public event subscriptions for finalized node data.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod blocks;
pub mod finality;
pub mod node;
pub mod server;
pub mod subscriptions;
pub mod transactions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsTopic {
    Blocks,
    Finality,
    Transactions,
    Node,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WsEvent {
    pub sequence: u64,
    pub topic: WsTopic,
    pub payload: Value,
}

impl WsEvent {
    pub fn validate(&self, max_payload_bytes: usize) -> Result<(), WsError> {
        if self.sequence == 0 || max_payload_bytes == 0 {
            return Err(WsError::InvalidEvent);
        }
        let bytes = serde_json::to_vec(&self.payload).map_err(|_| WsError::InvalidEvent)?;
        if bytes.len() > max_payload_bytes {
            return Err(WsError::PayloadTooLarge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WsError {
    InvalidSubscription,
    InvalidEvent,
    PayloadTooLarge,
    SubscriberCapacity,
    QueueCapacity,
    UnknownSubscriber,
}
