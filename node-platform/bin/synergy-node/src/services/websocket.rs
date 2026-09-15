use std::sync::Arc;

use synergy_config::RpcConfiguration;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, RuntimeView, ServiceHealth,
    ServiceId, ServiceReadiness, ServiceSpec,
};
use synergy_rpc::{
    methods::BlockQuery,
    provider::{CanonicalReadProvider, FinalizedBlockView},
};
use synergy_ws::{
    blocks::block_event, finality::finality_event, node::node_event, server::WsServer,
    transactions::transaction_event,
};

pub fn registration(
    configuration: &RpcConfiguration,
    runtime: RuntimeView,
    hub: Arc<WsServer>,
    query_store: Arc<dyn CanonicalReadProvider>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if !configuration.enabled {
        return Err("WebSocket service cannot be registered when RPC is disabled".into());
    }
    Ok((
        ServiceSpec {
            id: ServiceId::new("websocket")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("rpc")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(WebSocketService {
            runtime,
            hub,
            query_store,
            sequence: 0,
            last_node_state: None,
            last_finalized_height: None,
            started: false,
        }),
    ))
}

struct WebSocketService {
    runtime: RuntimeView,
    hub: Arc<WsServer>,
    query_store: Arc<dyn CanonicalReadProvider>,
    sequence: u64,
    last_node_state: Option<(String, bool)>,
    last_finalized_height: Option<u64>,
    started: bool,
}

impl ManagedService for WebSocketService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("WebSocket service start was cancelled".into());
        }
        self.started = true;
        self.publish_runtime_state()?;
        self.publish_finalized_events()
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("WebSocket event producer is stopped".into());
        }
        self.publish_runtime_state()?;
        self.publish_finalized_events()
    }

    fn stop(&mut self) -> Result<(), String> {
        self.started = false;
        self.last_node_state = None;
        self.last_finalized_height = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if self.started {
            ServiceHealth::Healthy
        } else {
            ServiceHealth::Unhealthy {
                reason: "WebSocket event producer is stopped".into(),
            }
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        if self.started {
            ServiceReadiness::Ready
        } else {
            ServiceReadiness::Blocked {
                reason: "WebSocket event producer is stopped".into(),
            }
        }
    }
}

impl WebSocketService {
    fn publish_runtime_state(&mut self) -> Result<(), String> {
        let snapshot = self
            .runtime
            .read()
            .map_err(|_| "WebSocket runtime observation state is unavailable")?;
        let state = serde_json::to_value(&snapshot.lifecycle)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", snapshot.lifecycle));
        let ready = snapshot.ready();
        drop(snapshot);
        if self.last_node_state.as_ref() == Some(&(state.clone(), ready)) {
            return Ok(());
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("WebSocket event sequence overflow")?;
        let event = node_event(self.sequence, state.clone(), ready)
            .map_err(|error| format!("construct WebSocket node event: {error:?}"))?;
        self.hub
            .publish(event)
            .map_err(|error| format!("publish WebSocket node event: {error:?}"))?;
        self.last_node_state = Some((state, ready));
        Ok(())
    }

    fn publish_finalized_events(&mut self) -> Result<(), String> {
        let latest = self
            .query_store
            .latest_finalized_height()
            .map_err(|error| format!("read WebSocket finality cursor: {}", error.message))?;
        let Some(latest) = latest else {
            return Ok(());
        };
        if latest == 0 {
            return Ok(());
        }
        let start = match self.last_finalized_height {
            None => latest,
            Some(previous) if previous == latest => return Ok(()),
            Some(previous) if previous < latest => previous
                .checked_add(1)
                .ok_or("WebSocket finalized height overflow")?,
            Some(_) => return Err("canonical finalized height regressed".into()),
        };
        let end = start.saturating_add(15).min(latest);
        for height in start..=end {
            let block = self
                .query_store
                .block(&BlockQuery {
                    height: Some(height),
                    hash: None,
                })
                .map_err(|error| format!("read finalized WebSocket block: {}", error.message))?
                .ok_or_else(|| format!("canonical finalized block H{height} is unavailable"))?;
            self.publish_block_events(&block)?;
            self.last_finalized_height = Some(height);
        }
        Ok(())
    }

    fn publish_block_events(&mut self, block: &FinalizedBlockView) -> Result<(), String> {
        let event = block_event(
            self.next_sequence()?,
            block.height,
            block.block_hash.clone(),
        )
        .map_err(|error| format!("construct WebSocket block event: {error:?}"))?;
        self.hub
            .publish(event)
            .map_err(|error| format!("publish WebSocket block event: {error:?}"))?;

        for receipt in &block.receipts {
            let transaction_id = receipt
                .get("transaction_id")
                .and_then(serde_json::Value::as_str)
                .ok_or("finalized receipt lacks a transaction identifier")?;
            let status = receipt
                .get("status")
                .and_then(serde_json::Value::as_str)
                .ok_or("finalized receipt lacks a status")?;
            let event = transaction_event(
                self.next_sequence()?,
                transaction_id.to_owned(),
                status.to_owned(),
            )
            .map_err(|error| format!("construct WebSocket transaction event: {error:?}"))?;
            self.hub
                .publish(event)
                .map_err(|error| format!("publish WebSocket transaction event: {error:?}"))?;
        }

        let event = finality_event(
            self.next_sequence()?,
            block.height,
            block.finality_certificate_id.clone(),
        )
        .map_err(|error| format!("construct WebSocket finality event: {error:?}"))?;
        self.hub
            .publish(event)
            .map_err(|error| format!("publish WebSocket finality event: {error:?}"))?;
        Ok(())
    }

    fn next_sequence(&mut self) -> Result<u64, String> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("WebSocket event sequence overflow")?;
        Ok(self.sequence)
    }
}
