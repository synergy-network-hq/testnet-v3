use std::collections::BTreeSet;
use std::sync::Mutex;

use crate::{subscriptions::SubscriptionHub, WsError, WsEvent, WsTopic};

#[derive(Debug)]
pub struct WsServer {
    hub: Mutex<SubscriptionHub>,
    max_payload_bytes: usize,
}

impl WsServer {
    pub fn new(
        max_subscribers: usize,
        queue_capacity: usize,
        max_payload_bytes: usize,
    ) -> Result<Self, WsError> {
        if max_payload_bytes == 0 {
            return Err(WsError::PayloadTooLarge);
        }
        Ok(Self {
            hub: Mutex::new(SubscriptionHub::new(max_subscribers, queue_capacity)?),
            max_payload_bytes,
        })
    }

    pub fn subscribe(
        &self,
        subscriber_id: impl Into<String>,
        topics: BTreeSet<WsTopic>,
    ) -> Result<(), WsError> {
        self.hub
            .lock()
            .map_err(|_| WsError::InvalidSubscription)?
            .subscribe(subscriber_id, topics)
    }

    pub fn unsubscribe(&self, subscriber_id: &str) -> Result<bool, WsError> {
        Ok(self
            .hub
            .lock()
            .map_err(|_| WsError::InvalidSubscription)?
            .unsubscribe(subscriber_id))
    }

    pub fn publish(&self, event: WsEvent) -> Result<usize, WsError> {
        event.validate(self.max_payload_bytes)?;
        Ok(self
            .hub
            .lock()
            .map_err(|_| WsError::InvalidSubscription)?
            .publish(event))
    }

    pub fn drain(&self, subscriber_id: &str, limit: usize) -> Result<Vec<WsEvent>, WsError> {
        self.hub
            .lock()
            .map_err(|_| WsError::InvalidSubscription)?
            .drain(subscriber_id, limit)
    }
}
