use synergy_config::P2pConfiguration;
use synergy_network::sentry::SentryForwarder;
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};

/// Owns only the bounded forwarding perimeter for a Sentry role. It does not
/// accept a raw transport stream or acquire any consensus capability.
pub fn registration(
    configuration: &P2pConfiguration,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if configuration.max_authenticated_peers == 0 || configuration.max_pending_handshakes == 0 {
        return Err("Sentry forwarding requires nonzero peer capacities".into());
    }
    Ok((
        ServiceSpec {
            id: ServiceId::new("sentry")?,
            dependencies: vec![ServiceId::new("network")?, ServiceId::new("identity")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(SentryService {
            forwarder: Some(SentryForwarder::new(
                configuration.max_authenticated_peers,
                configuration.max_pending_handshakes,
            )),
        }),
    ))
}

struct SentryService {
    forwarder: Option<SentryForwarder>,
}

impl ManagedService for SentryService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("Sentry service start was cancelled".into());
        }
        if self.forwarder.is_none() {
            return Err("Sentry forwarding perimeter is unavailable".into());
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.forwarder = None;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if self.forwarder.is_some() {
            ServiceHealth::Degraded {
                reason: "Sentry perimeter awaits authenticated network session ownership".into(),
            }
        } else {
            ServiceHealth::Unhealthy {
                reason: "Sentry forwarding perimeter is stopped".into(),
            }
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        ServiceReadiness::Blocked {
            reason: "Sentry accepts only authenticated ingress, which has no runtime owner yet"
                .into(),
        }
    }
}

/// Native worker adapter for a separately authenticated Sentry peer-relay hop.
/// Owns one established APQE driver; it never forwards raw public TCP bytes or
/// dispatches to a destination. Route authority stays with the native route owner.
#[allow(dead_code)]
pub struct CurrentSentryIngress<'a> {
    driver: synergy_address_engine::apqe::engineering_transport::SessionDriver<'a>,
    binding: synergy_address_engine::apqe::current_session::CurrentSessionContext,
    peer: synergy_protocol_types::AuthenticatedPeer,
    maximum: usize,
    policy: synergy_network::sentry::SentryFilter,
}
#[allow(dead_code)]
impl<'a> CurrentSentryIngress<'a> {
    /// `local_node` and the nonzero local connection ID must come from the native
    /// worker's managed identity/session owner, never a public request. IDs are
    /// local queue handles, not truncated cryptographic session identifiers.
    pub fn new(
        mut driver: synergy_address_engine::apqe::engineering_transport::SessionDriver<'a>,
        local_node: &str,
        session: synergy_protocol_types::SessionId,
        maximum: usize,
        policy: synergy_network::sentry::SentryFilter,
    ) -> Result<Self, String> {
        let result = (|| {
            if maximum == 0 || session.0 == 0 {
                return Err("invalid Sentry ingress bounds".to_string());
            }
            if driver
                .current_local_node(std::time::Instant::now())
                .map_err(|e| e.to_string())?
                != local_node
            {
                return Err("Sentry local identity is not the actual session endpoint".into());
            }
            let binding = driver
                .current_context(std::time::Instant::now())
                .map_err(|e| e.to_string())?
                .clone();
            let (peer_node, class) = Self::remote(&binding, local_node)?;
            let peer = synergy_protocol_types::AuthenticatedPeer::new_current(
                peer_node,
                class,
                session,
                Vec::new(),
            )
            .map_err(|e| e.to_string())?;
            Ok((binding, peer))
        })();
        match result {
            Ok((binding, peer)) => Ok(Self {
                driver,
                binding,
                peer,
                maximum,
                policy,
            }),
            Err(e) => {
                driver.retire();
                Err(e)
            }
        }
    }
    fn remote(
        binding: &synergy_address_engine::apqe::current_session::CurrentSessionContext,
        local_node: &str,
    ) -> Result<(String, synergy_protocol_types::NodeClass), String> {
        use synergy_address_engine::apqe::current_session::{SessionHop, SessionPurpose};
        use synergy_protocol_types::NodeClass;
        // Roles are already closed by the authenticated current context codec.
        match binding.hop {
            SessionHop::SentryToValidator
                if binding.initiator.node == local_node
                    && binding.purpose == SessionPurpose::PeerRelay =>
            {
                Ok((
                    binding.responder.node.clone(),
                    NodeClass::ConsensusAndChainIntegrity,
                ))
            }
            _ => Err("current Sentry hop or local identity mismatch".into()),
        }
    }
    /// Decrypt, recheck current trust, then admit through codec/filter/bounded
    /// queue. Failure/close discards this exact old session, preserving replacement.
    pub fn poll(&mut self, forwarder: &mut SentryForwarder) -> Result<bool, String> {
        let result = (|| {
            let current = self
                .driver
                .current_context(std::time::Instant::now())
                .map_err(|e| e.to_string())?;
            if current != &self.binding {
                return Err("current Sentry session binding changed".into());
            }
            let Some(plaintext) = self.driver.poll_io().map_err(|e| e.to_string())? else {
                return Ok(false);
            };
            let current = self
                .driver
                .current_context(std::time::Instant::now())
                .map_err(|e| e.to_string())?;
            if current != &self.binding {
                return Err("current Sentry session binding changed".into());
            }
            forwarder
                .forward_session_payload(
                    self.peer.clone(),
                    plaintext.as_bytes(),
                    self.maximum,
                    &self.policy,
                )
                .map_err(|e| format!("Sentry ingress rejected: {e:?}"))?;
            Ok(true)
        })();
        if result.is_err() || !self.driver.established() {
            self.driver.retire();
            forwarder.discard_session(self.peer.node_address.as_str(), self.peer.session_id);
        }
        result
    }
}

/// An admitted public RPC carrier, separate from peer-relay routing frames.
/// Construction is private: native code receives only exact codec/allowlist
/// checked bytes. This grants no destination, execution or finality authority.
#[allow(dead_code)]
pub struct CurrentRpcRequest {
    transport_id: [u8; 16],
    body: Vec<u8>,
    // Declared after body so its allocation is freed before capacity is released.
    _input_capacity: synergy_state::world_resources::WorldResourcePermit,
}
#[allow(dead_code)]
impl CurrentRpcRequest {
    pub fn transport_id(&self) -> &[u8; 16] {
        &self.transport_id
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
fn admit_rpc_record(
    pending: &mut Option<CurrentRpcRequest>,
    record: &[u8],
    confirmed: &synergy_address_engine::apqe::current_session::CurrentSessionContext,
    budget: &std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<(), String> {
    if pending.is_some() {
        return Err("Sentry RPC carrier queue is full".into());
    }
    let (transport_id, body) = super::apqe_rpc::decode(record, 1)?;
    let input_capacity = reserve_rpc_input(body.len(), budget)?;
    super::apqe_rpc_service::validate_current_public_carrier(body, confirmed)?;
    *pending = Some(CurrentRpcRequest {
        transport_id,
        body: body.to_vec(),
        _input_capacity: input_capacity,
    });
    Ok(())
}
fn reserve_rpc_input(
    encoded_bytes: usize,
    budget: &std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<synergy_state::world_resources::WorldResourcePermit, String> {
    if encoded_bytes > synergy_rpc::current_batch::MAX_DOCUMENT_BYTES {
        return Err("Sentry RPC input exceeds current carrier bound".into());
    }
    // Same conservative current-read input accounting as the native provider:
    // sparse JSON nodes, decoded strings, typed-validation clones and body copy.
    let peak = encoded_bytes.checked_mul(512)
        .and_then(|n| n.checked_add(64 * 1024))
        .ok_or("Sentry RPC input capacity overflow")?;
    budget.reserve(peak).map_err(|_| "Sentry public input capacity unavailable".into())
}
/// One exchange, with correlation selected from the accepted record only.
#[derive(Default)]
struct RpcExchange {
    pending: Option<CurrentRpcRequest>,
    accepted_id: Option<[u8; 16]>,
    response_queued: bool,
}
/// Original encoded response and its real native allocation lease move together.
/// Field order also covers cancellation/drop before the final socket write.
struct RetainedRpcResponse {
    body: Vec<u8>,
    capacity: Option<synergy_rpc::provider::RpcResponseCapacity>,
}
impl RetainedRpcResponse {
    fn new(output: synergy_rpc::server::RpcOutput) -> Result<Self, String> {
        let (body, capacity) = output.into_parts();
        Self::from_parts(body, capacity)
    }
    fn from_parts(
        body: Vec<u8>,
        capacity: Option<synergy_rpc::provider::RpcResponseCapacity>,
    ) -> Result<Self, String> {
        let owned = Self { body, capacity };
        let maximum = owned.capacity.as_ref()
            .ok_or("Sentry RPC response requires native output capacity")?
            .maximum_encoded_bytes();
        if owned.body.len() > maximum || owned.body.len() > super::apqe_rpc::MAX_BODY {
            return Err("Sentry RPC response exceeds retained capacity or carrier bound".into());
        }
        Ok(owned)
    }
}
impl RpcExchange {
    fn accept(
        &mut self,
        record: &[u8],
        confirmed: &synergy_address_engine::apqe::current_session::CurrentSessionContext,
        budget: &std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
    ) -> Result<(), String> {
        if self.accepted_id.is_some() {
            return Err("Sentry RPC session already consumed its request".into());
        }
        admit_rpc_record(&mut self.pending, record, confirmed, budget)?;
        self.accepted_id = Some(
            self.pending
                .as_ref()
                .ok_or("missing admitted RPC carrier")?
                .transport_id,
        );
        Ok(())
    }
    fn response(&mut self, body: &[u8]) -> Result<Vec<u8>, String> {
        let id = self
            .accepted_id
            .as_ref()
            .ok_or("Sentry RPC has no accepted request")?;
        if self.pending.is_some() || self.response_queued {
            return Err("Sentry RPC response is premature or already reserved".into());
        }
        let record = super::apqe_rpc::encode(2, id, body)?;
        // Reserve before encryption/write; uncertain queue outcomes cannot retry.
        self.response_queued = true;
        Ok(record)
    }
}
/// One bounded public RPC request slot on one confirmed Gateway→Sentry driver.
/// The existing native route owner must separately authorize a private link and
/// correlate/verify its response. No opaque TCP forwarding or automatic retry.
#[allow(dead_code)]
pub struct CurrentRpcSentryIngress<'a> {
    driver: synergy_address_engine::apqe::engineering_transport::SessionDriver<'a>,
    binding: synergy_address_engine::apqe::current_session::CurrentSessionContext,
    exchange: RpcExchange,
    public_budget: std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
    response: Option<RetainedRpcResponse>,
}
#[allow(dead_code)]
impl<'a> CurrentRpcSentryIngress<'a> {
    /// Native lifecycle supplies the shared prepaid public worker pool, created
    /// only after its configured quota/protected-headroom reservation succeeds.
    /// This adapter never creates a private pool or chooses production defaults.
    pub fn new(
        mut driver: synergy_address_engine::apqe::engineering_transport::SessionDriver<'a>,
        managed_local_node: &str,
        public_budget: std::sync::Arc<synergy_state::world_resources::WorldResourceBudget>,
    ) -> Result<Self, String> {
        use synergy_address_engine::apqe::current_session::{SessionHop, SessionPurpose};
        let result = (|| {
            if driver
                .current_local_node(std::time::Instant::now())
                .map_err(|e| e.to_string())?
                != managed_local_node
            {
                return Err("Sentry RPC local endpoint mismatch".to_string());
            }
            let binding = driver
                .current_context(std::time::Instant::now())
                .map_err(|e| e.to_string())?
                .clone();
            if binding.hop != SessionHop::GatewayToSentry
                || binding.purpose != SessionPurpose::PublicRpc
                || binding.responder.node != managed_local_node
            {
                return Err("Sentry requires the current public RPC hop".into());
            }
            Ok(binding)
        })();
        match result {
            Ok(binding) => Ok(Self {
                driver,
                binding,
                exchange: RpcExchange::default(),
                public_budget,
                response: None,
            }),
            Err(e) => {
                driver.retire();
                Err(e)
            }
        }
    }
    fn check(&mut self) -> Result<(), String> {
        let current = self
            .driver
            .current_context(std::time::Instant::now())
            .map_err(|e| e.to_string())?;
        if current != &self.binding {
            return Err("Sentry RPC session binding changed".into());
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Result<bool, String> {
        let result = (|| {
            self.check()?;
            if self.exchange.accepted_id.is_some() {
                if self.exchange.response_queued {
                    // Flush the one already sealed response. An extra incoming
                    // application record violates this one-exchange protocol.
                    if self.driver.poll_io().map_err(|e| e.to_string())?.is_some() {
                        return Err("unexpected second Sentry RPC request".into());
                    }
                    if self.driver.can_queue() {
                        self.retire();
                    }
                }
                return Ok(false);
            }
            let Some(plaintext) = self.driver.poll_io().map_err(|e| e.to_string())? else {
                return Ok(false);
            };
            self.check()?;
            self.exchange.accept(plaintext.as_bytes(), &self.binding, &self.public_budget)?;
            Ok(true)
        })();
        if result.is_err() || !self.driver.established() {
            self.retire();
        }
        result
    }
    pub fn take_request(&mut self) -> Result<Option<CurrentRpcRequest>, String> {
        if let Err(e) = self.check() {
            self.retire();
            return Err(e);
        }
        Ok(self.exchange.pending.take())
    }
    /// Caller is the native route owner and must independently verify the
    /// validator response/network/proof context before supplying this body.
    /// This method grants no route or finality authority; it binds the exact
    /// original transport ID and reserves one response before sealing.
    pub fn queue_response(&mut self, output: synergy_rpc::server::RpcOutput) -> Result<(), String> {
        let result = (|| {
            self.check()?;
            if self.response.is_some() {
                return Err("Sentry RPC response already retained".into());
            }
            self.response = Some(RetainedRpcResponse::new(output)?);
            let record = self.exchange.response(
                &self.response.as_ref().ok_or("missing retained RPC response")?.body,
            )?;
            self.driver
                .queue_application(&record)
                .map_err(|e| e.to_string())
        })();
        if result.is_err() {
            self.retire();
        }
        result
    }
    pub fn retire(&mut self) {
        self.driver.retire();
        self.exchange.pending = None;
        self.response = None;
    }
}

#[cfg(test)]
mod current_rpc_tests {
    use super::*;
    fn budget() -> std::sync::Arc<synergy_state::world_resources::WorldResourceBudget> {
        synergy_state::world_resources::WorldResourceBudget::new(48 * 1024 * 1024)
    }
    // Policy-only context fixture; production obtains its binding exclusively
    // from the actual confirmed SessionDriver, never this test constructor.
    fn context() -> synergy_address_engine::apqe::current_session::CurrentSessionContext {
        use synergy_address::r1_public::NativeIdentityPresentation;
        use synergy_address_engine::apqe::{current_session::*, r1_framing::NetworkRef};
        CurrentSessionContext {
            network: NetworkRef {
                chain_id: u64::MAX - 1,
                nic: [0x11; 64],
            },
            genesis: [0x22; 48],
            activated_profiles: [0x33; 64],
            registry_epoch: 1,
            registry_commitment: [0x44; 64],
            hop: SessionHop::GatewayToSentry,
            purpose: SessionPurpose::PublicRpc,
            initiator: SessionEndpoint {
                role: TransportRole::Gateway,
                node: NativeIdentityPresentation::from_raw("synv5", [0x55; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-GATEWAY-KEY".into(),
                key_generation: 1,
            },
            responder: SessionEndpoint {
                role: TransportRole::Sentry,
                node: NativeIdentityPresentation::from_raw("synv1", [0x66; 48])
                    .unwrap()
                    .to_text(),
                transport_key_id: "PUBLIC-SYNTHETIC-SENTRY-KEY".into(),
                key_generation: 1,
            },
        }
    }
    fn request(id: u8, body: &[u8]) -> Vec<u8> {
        super::super::apqe_rpc::encode(1, &[id; 16], body).unwrap()
    }
    const PUBLIC: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"synergy_getBlockReceipts","params":{"api_version":1,"request_id":"public-synthetic-read-only","caller_scope":"public_read","network":{"chain_id":"18446744073709551614","network_incarnation_commitment":{"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"},"genesis_commitment":{"profile":{"name":"SYNERGY-GENESIS-R1","revision":1},"algorithm":"SHA3-384","encoding":"lowercase-hex","value":"222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"},"activated_profiles":{"profile":{"name":"APQE-PROFILE-SET","revision":1},"algorithm":"SHA3-512","encoding":"lowercase-hex","value":"33333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"},"identity_profile":{"name":"APQE-NATIVE-ID","revision":1},"presentation_version":2},"args":{"height":"0"}}}"#;
    #[test]
    fn complete_exchange_uses_original_id_and_cannot_reopen_or_respond_twice() {
        let mut exchange = RpcExchange::default();
        exchange.accept(&request(7, PUBLIC), &context(), &budget()).unwrap();
        assert!(exchange
            .response(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#)
            .is_err());
        let accepted = exchange.pending.take().unwrap();
        assert_eq!(accepted.body(), PUBLIC);
        assert!(exchange.accept(&request(8, PUBLIC), &context(), &budget()).is_err());
        let body = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unavailable"}}"#;
        let record = exchange.response(body).unwrap();
        let (id, returned) = super::super::apqe_rpc::decode(&record, 2).unwrap();
        assert_eq!(id, [7; 16]);
        assert_eq!(returned, body);
        assert!(exchange.response(body).is_err());
        assert!(exchange.accept(&request(9, PUBLIC), &context(), &budget()).is_err());
    }
    #[test]
    fn no_response_without_admission_and_invalid_carrier_never_reserves_exchange() {
        let mut exchange = RpcExchange::default();
        assert!(exchange.response(b"body").is_err());
        assert!(exchange.accept(b"malformed", &context(), &budget()).is_err());
        assert!(exchange.accepted_id.is_none());
        assert!(exchange.pending.is_none());
        assert!(!exchange.response_queued);
        exchange.accept(&request(7, PUBLIC), &context(), &budget()).unwrap();
        exchange.pending.take();
        assert!(exchange
            .response(&vec![0; super::super::apqe_rpc::MAX_BODY + 1])
            .is_err());
        assert!(!exchange.response_queued);
    }
    #[test]
    fn actual_rpc_carrier_preserves_exact_bytes_and_correlation() {
        let mut pending = None;
        admit_rpc_record(&mut pending, &request(7, PUBLIC), &context(), &budget()).unwrap();
        let admitted = pending.unwrap();
        assert_eq!(admitted.transport_id(), &[7; 16]);
        assert_eq!(admitted.body(), PUBLIC);
    }
    #[test]
    fn actual_public_preflight_rejects_management_and_bad_batch_before_queue() {
        for body in [br#"{"jsonrpc":"2.0","method":"synergy_listPeers","params":{},"id":1}"#.as_slice(),br#"[]"#,br#"[{"jsonrpc":"2.0","method":"synergy_chainTelemetry","id":1},{"jsonrpc":"2.0","method":"synergy_chainTelemetry","id":1}]"#,br#"{"jsonrpc":"2.0","method":"synergy_chainTelemetry","id":null}"#] {
            let mut pending=None;assert!(admit_rpc_record(&mut pending,&request(7,body), &context(), &budget()).is_err());assert!(pending.is_none());
        }
        let mut pending = None;
        let response = super::super::apqe_rpc::encode(2, &[7; 16], PUBLIC).unwrap();
        assert!(admit_rpc_record(&mut pending, &response, &context(), &budget()).is_err());
        assert!(pending.is_none());
    }
    #[test]
    fn full_queue_preserves_original_request_without_dispatch_or_retry() {
        let mut pending = None;
        admit_rpc_record(&mut pending, &request(7, PUBLIC), &context(), &budget()).unwrap();
        assert!(admit_rpc_record(&mut pending, &request(8, PUBLIC), &context(), &budget()).is_err());
        assert_eq!(pending.unwrap().transport_id(), &[7; 16]);
    }
    #[test]
    fn confirmed_full_network_is_required_before_queue_without_rewriting_body() {
        let mut wrong = context();
        wrong.network.nic[0] ^= 1;
        let mut pending = None;
        assert!(admit_rpc_record(&mut pending, &request(7, PUBLIC), &wrong, &budget()).is_err());
        assert!(pending.is_none());
        let mut wrong = context();
        wrong.purpose = synergy_address_engine::apqe::current_session::SessionPurpose::PeerRelay;
        assert!(admit_rpc_record(&mut pending, &request(7, PUBLIC), &wrong, &budget()).is_err());
        assert!(pending.is_none());
        admit_rpc_record(&mut pending, &request(7, PUBLIC), &context(), &budget()).unwrap();
        assert_eq!(pending.unwrap().body(), PUBLIC);
    }

    #[test]
    fn public_input_pressure_rejects_before_admission_and_can_retry_after_release() {
        let peak = PUBLIC.len() * 512 + 64 * 1024;
        let budget = synergy_state::world_resources::WorldResourceBudget::new(peak);
        let pressure = budget.reserve(1).unwrap();
        let mut exchange = RpcExchange::default();
        assert!(exchange.accept(&request(7, PUBLIC), &context(), &budget).is_err());
        assert!(exchange.pending.is_none());
        assert!(exchange.accepted_id.is_none());
        assert_eq!(budget.used(), 1);
        drop(pressure);
        exchange.accept(&request(7, PUBLIC), &context(), &budget).unwrap();
        assert_eq!(budget.used(), peak);
        drop(exchange);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn request_lease_survives_handoff_and_parse_failure_releases_capacity() {
        let peak = PUBLIC.len() * 512 + 64 * 1024;
        let budget = synergy_state::world_resources::WorldResourceBudget::new(peak);
        let mut first = RpcExchange::default();
        first.accept(&request(7, PUBLIC), &context(), &budget).unwrap();
        let handed_off = first.pending.take().unwrap();
        drop(first);
        assert_eq!(handed_off.body(), PUBLIC);
        assert_eq!(budget.used(), peak);
        let mut second = RpcExchange::default();
        assert!(second.accept(&request(8, PUBLIC), &context(), &budget).is_err());
        drop(handed_off);
        assert_eq!(budget.used(), 0);
        assert!(second.accept(&request(8, b"not-json"), &context(), &budget).is_err());
        assert_eq!(budget.used(), 0);
        assert!(second.accepted_id.is_none());
        second.accept(&request(8, PUBLIC), &context(), &budget).unwrap();
        assert_eq!(second.pending.unwrap().transport_id(), &[8; 16]);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn response_requires_real_capacity_and_refusal_releases_lease() {
        assert!(RetainedRpcResponse::new(vec![0; 256].into()).is_err());
        let budget = synergy_state::world_resources::WorldResourceBudget::new(4 * (super::super::apqe_rpc::MAX_BODY + 1));
        let capacity = synergy_rpc::provider::RpcResponseCapacity::new(
            256, Box::new(budget.reserve(4096).unwrap()),
        ).unwrap();
        assert!(RetainedRpcResponse::from_parts(vec![0; 257], Some(capacity)).is_err());
        assert_eq!(budget.used(), 0);
        let capacity = synergy_rpc::provider::RpcResponseCapacity::new(
            super::super::apqe_rpc::MAX_BODY + 1,
            Box::new(budget.reserve(3 * (super::super::apqe_rpc::MAX_BODY + 1)).unwrap()),
        ).unwrap();
        assert!(RetainedRpcResponse::from_parts(
            vec![0; super::super::apqe_rpc::MAX_BODY + 1], Some(capacity),
        ).is_err());
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn response_record_keeps_original_output_capacity_until_owned_release() {
        let budget = synergy_state::world_resources::WorldResourceBudget::new(4096);
        let capacity = synergy_rpc::provider::RpcResponseCapacity::new(
            256, Box::new(budget.reserve(4096).unwrap()),
        ).unwrap();
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec();
        let owned = RetainedRpcResponse::from_parts(body.clone(), Some(capacity)).unwrap();
        let mut exchange = RpcExchange::default();
        exchange.accept(&request(7, PUBLIC), &context(), &self::budget()).unwrap();
        let request = exchange.pending.take().unwrap();
        let record = exchange.response(&owned.body).unwrap();
        assert_eq!(super::super::apqe_rpc::decode(&record, 2).unwrap(), ([7; 16], body.as_slice()));
        assert_eq!(budget.used(), 4096);
        drop(request);
        drop(record);
        assert_eq!(budget.used(), 4096);
        drop(owned);
        assert_eq!(budget.used(), 0);
    }
}
