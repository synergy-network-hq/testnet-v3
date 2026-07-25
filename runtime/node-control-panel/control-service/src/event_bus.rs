use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub event: String,
    pub payload: Value,
}

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<ServiceEvent>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity.max(32));
        Self { sender }
    }

    pub fn emit_json(&self, event: impl Into<String>, payload: Value) {
        let _ = self.sender.send(ServiceEvent {
            event: event.into(),
            payload,
        });
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ServiceEvent> {
        self.sender.subscribe()
    }
}
