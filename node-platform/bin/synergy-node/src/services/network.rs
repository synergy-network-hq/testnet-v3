//! Governed Aegis-authenticated P2P listener and bounded frame admission.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, GovernedKeyBindings, SignatureAlgorithm,
    SigningContext,
};
use synergy_config::{NodeConfiguration, VpnMode};
use synergy_identity::PublicNodeIdentity;
use synergy_manifest::NetworkManifest;
use synergy_network::handshake::{AegisHandshakeVerifier, HandshakeMetadata, PeerKeyAlgorithm};
use synergy_network::peer::{DisconnectReason, PeerManager};
use synergy_network::protocol::FrameLimits;
use synergy_network::router::BoundedPeerRouter;
use synergy_network::transport::{
    TcpListenerService, TcpTransport, Transport, TransportConnection, TransportError,
    TransportLimits, TransportTimeouts,
};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};

use super::ingress::{AuthenticatedIngress, PeerControlAction};
use super::network_secure::{self, SecureSessionContext};
use super::network_session::{
    run_inbound, run_outbound, NetworkEvent, OutboundPayload, SessionContext,
};

const MAX_ACCEPTS_PER_POLL: usize = 32;
const MAX_BINDINGS_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 8 * 1024;

#[derive(Clone)]
enum SessionOwner {
    Legacy(Arc<SessionContext>),
    Secure(Arc<SecureSessionContext>),
}
impl SessionOwner {
    fn shutdown(&self) -> &Arc<AtomicBool> {
        match self {
            Self::Legacy(c) => &c.shutdown,
            Self::Secure(c) => &c.shutdown,
        }
    }
    fn manager(&self) -> &Arc<Mutex<PeerManager>> {
        match self {
            Self::Legacy(c) => &c.manager,
            Self::Secure(c) => &c.manager,
        }
    }
    fn contains_peer(&self, peer: &str) -> bool {
        match self {
            Self::Legacy(c) => c.bindings.get(peer).is_some(),
            Self::Secure(c) => c.factory.contains_peer(peer),
        }
    }
    fn run_inbound(
        self,
        connection: TransportConnection,
        events: mpsc::SyncSender<NetworkEvent>,
        id: u64,
        accepted_at: Instant,
    ) -> Result<(), String> {
        match self {
            Self::Legacy(c) => run_inbound(c, connection, events, id),
            Self::Secure(c) => network_secure::run(c, connection, events, id, None, accepted_at),
        }
    }
    fn run_outbound(
        self,
        connection: TransportConnection,
        events: mpsc::SyncSender<NetworkEvent>,
        id: u64,
        peer: &str,
        accepted_at: Instant,
    ) -> Result<(), String> {
        match self {
            Self::Legacy(c) => run_outbound(c, connection, events, id, peer),
            Self::Secure(c) => {
                network_secure::run(c, connection, events, id, Some(peer), accepted_at)
            }
        }
    }
}

pub fn registration(
    configuration: &NodeConfiguration,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    #[cfg(not(test))]
    if configuration.apqe_transport.is_none() {
        synergy_network::transport::require_native_session_profile()
            .map_err(|error| error.to_string())?;
    }

    let (spec, service) = registration_service(configuration, ingress)?;
    Ok((
        spec,
        super::owned_service::production(Box::new(service), "network"),
    ))
}

/// Fixture-only ownership handoff. The fixture keeps the same bound sockets
/// across service restarts; production always binds its configured addresses.
#[cfg(test)]
pub(super) fn registration_with_reserved_listeners(
    configuration: &NodeConfiguration,
    ingress: AuthenticatedIngress,
    listeners: Arc<Vec<TcpListenerService>>,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    if listeners.len() != configuration.network.listen_addresses.len()
        || listeners
            .iter()
            .zip(&configuration.network.listen_addresses)
            .any(|(listener, expected)| listener.local_addr().ok().as_ref() != Some(expected))
    {
        return Err("fixture network listener reservation differs from configuration".into());
    }
    let (spec, mut service) = registration_service(configuration, ingress)?;
    service.reserved_listeners = Some(listeners);
    Ok((
        spec,
        super::owned_service::production(Box::new(service), "network"),
    ))
}

fn registration_service(
    configuration: &NodeConfiguration,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, NetworkService), String> {
    let network = &configuration.network;
    let p2p = &configuration.p2p;
    let limits = TransportLimits {
        max_connections: p2p.max_authenticated_peers,
        max_inbound_connections: p2p.max_pending_handshakes,
        max_outbound_connections: p2p.max_authenticated_peers,
        max_frame_bytes: p2p.max_frame_bytes,
    }
    .validate()
    .map_err(|error| error.to_string())?;
    if network.listen_addresses.is_empty() {
        return Err("network requires at least one canonical listen address".into());
    }
    let timeouts = TransportTimeouts {
        connect: Duration::from_millis(network.dial_timeout_ms),
        handshake: Duration::from_millis(network.dial_timeout_ms),
        read: Duration::from_millis(network.idle_connection_timeout_ms),
        write: Duration::from_millis(network.idle_connection_timeout_ms),
    };
    let transport = TcpTransport::new(timeouts).map_err(|error| error.to_string())?;
    let session = build_session_context(
        configuration,
        timeouts,
        p2p.max_frame_bytes,
        ingress.clone(),
    )?
    .ok_or("network requires governed Aegis bindings and a provisioned local signing key")?;
    let (sender, receiver) =
        mpsc::sync_channel(p2p.max_authenticated_peers.saturating_mul(16).max(1));
    Ok((
        ServiceSpec {
            id: ServiceId::new("network")?,
            dependencies: vec![ServiceId::new("identity")?],
            criticality: Criticality::Critical,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        NetworkService {
            addresses: network.listen_addresses.clone(),
            transport,
            limits,
            listeners: Vec::new(),
            #[cfg(test)]
            reserved_listeners: None,
            session: Some(session),
            sender,
            receiver,
            pending: BTreeSet::new(),
            dialing: BTreeMap::new(),
            secure_last_dial: BTreeMap::new(),
            senders: BTreeMap::new(),
            max_pending: p2p.max_pending_handshakes,
            active: BTreeMap::new(),
            next_connection_id: 1,
            router: BoundedPeerRouter::new(
                p2p.max_authenticated_peers.saturating_mul(16).max(1),
                16,
            ),
            ingress,
            started: false,
            failure: None,
        },
    ))
}

fn read_regular_file(path: &std::path::Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err(format!(
            "{label} must be a bounded regular non-symlink file"
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("open {label} {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("inspect opened {label}: {error}"))?;
    if !opened.is_file() || opened.len() == 0 || opened.len() > maximum {
        return Err(format!("opened {label} is not a bounded regular file"));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{label} changed size while loading"));
    }
    Ok(bytes)
}

fn build_session_context(
    configuration: &NodeConfiguration,
    timeouts: TransportTimeouts,
    max_frame_bytes: usize,
    ingress: AuthenticatedIngress,
) -> Result<Option<SessionOwner>, String> {
    if let Some(factory) = super::apqe_transport::factory(configuration)? {
        let local_node_address = factory.local_node_address().clone();
        return Ok(Some(SessionOwner::Secure(Arc::new(SecureSessionContext {
            ingress,
            manager: Arc::new(Mutex::new(PeerManager::new(
                local_node_address.to_string(),
                configuration.p2p.max_authenticated_peers,
            ))),
            local_node_address,
            shutdown: Arc::new(AtomicBool::new(false)),
            max_payload_bytes: max_frame_bytes,
            factory,
        }))));
    }
    #[cfg(not(test))]
    synergy_network::transport::require_native_session_profile().map_err(|e| e.to_string())?;
    build_legacy_session_context(configuration, timeouts, max_frame_bytes, ingress)
        .map(|v| v.map(SessionOwner::Legacy))
}

fn build_legacy_session_context(
    configuration: &NodeConfiguration,
    timeouts: TransportTimeouts,
    max_frame_bytes: usize,
    ingress: AuthenticatedIngress,
) -> Result<Option<Arc<SessionContext>>, String> {
    let (Some(bindings_path), Some(signing_key_path)) = (
        &configuration.aegis_key_bindings_path,
        &configuration.aegis_signing_key_path,
    ) else {
        return Ok(None);
    };
    let bytes = read_regular_file(bindings_path, MAX_BINDINGS_BYTES, "governed Aegis bindings")?;
    let bindings: GovernedKeyBindings = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode governed Aegis bindings: {error}"))?;
    bindings
        .validate()
        .map_err(|error| format!("validate governed Aegis bindings: {error}"))?;
    let bytes = read_regular_file(
        &configuration.public_identity_path,
        MAX_IDENTITY_BYTES,
        "public identity",
    )?;
    let identity = serde_json::from_slice::<PublicNodeIdentity>(&bytes)
        .map_err(|error| format!("decode public identity: {error}"))?
        .validate()
        .map_err(|error| format!("validate public identity: {error:?}"))?;
    let bytes = read_regular_file(
        &configuration.manifest_path,
        MAX_MANIFEST_BYTES,
        "network manifest",
    )?;
    let manifest: NetworkManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode network manifest: {error}"))?;
    if manifest.chain_id != configuration.chain_id
        || manifest.network_id != configuration.network_id
        || manifest.genesis_hash.trim().is_empty()
        || manifest.protocol_version.trim().is_empty()
    {
        return Err("network manifest differs from canonical node configuration".into());
    }
    manifest
        .validate_against(&manifest)
        .map_err(|error| format!("validate network manifest: {error:?}"))?;
    let local_binding = bindings
        .get(identity.node_address.as_str())
        .ok_or("local node has no governed Aegis key binding")?;
    let local_key_id = local_binding.key_id.clone();
    if local_binding.algorithm != SignatureAlgorithm::MlDsa65 {
        return Err("local P2P identity key must use PQVM-backed ML-DSA-65".into());
    }

    let metadata = fs::symlink_metadata(signing_key_path)
        .map_err(|error| format!("inspect provisioned Aegis signing key: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_SIGNING_KEY_BYTES
    {
        return Err(
            "provisioned Aegis signing key must be a bounded regular non-symlink file".into(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "provisioned Aegis signing key must not be accessible to group or others".into(),
            );
        }
    }
    let key_bytes = read_regular_file(
        signing_key_path,
        MAX_SIGNING_KEY_BYTES,
        "provisioned Aegis signing key",
    )?;
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: max_frame_bytes.saturating_add(256),
        maximum_signature_bytes: 16 * 1024,
    };
    let signer = super::apqe_provider::signer(
        configuration,
        policy.clone(),
        local_binding.key_id.clone(),
        &local_binding.public_key,
        key_bytes,
    )
    .map_err(|error| format!("load PQVM signer: {error}"))?
    .serialized_provider();
    let verifier =
        super::apqe_provider::verifier(configuration, policy.clone())?.serialized_provider();
    let proof_context = SigningContext {
        domain: "SYNERGY-P2P-KEY-CHECK-V1".into(),
        chain_id: configuration.chain_id,
        epoch: None,
        height: None,
    };
    let check_message = b"SYNERGY-P2P-KEY-CHECK-V1";
    let check_signature = signer
        .sign(&local_binding.key_id, &proof_context, check_message)
        .map_err(|error| format!("prove provisioned key possession: {error}"))?;
    verifier
        .verify(
            &proof_context,
            check_message,
            &check_signature,
            &local_binding.public_key,
        )
        .map_err(|_| "provisioned signing key does not match governed public binding")?;
    let keys = bindings
        .entries()
        .map(|entry| (entry.node_address.clone(), entry.clone()))
        .collect();
    let frame_verifier = verifier.clone();
    let handshake_verifier = AegisHandshakeVerifier::new(verifier, configuration.chain_id, keys)?;
    let frame_limits =
        FrameLimits::new(max_frame_bytes, 16 * 1024).map_err(|error| error.to_string())?;
    Ok(Some(Arc::new(SessionContext {
        ingress,
        overlay_required: configuration.vpn.mode != VpnMode::Disabled,
        local_node_address: identity.node_address.clone(),
        local_role: configuration.role,
        expected: HandshakeMetadata {
            node_address: identity.node_address.clone(),
            network_id: manifest.network_id,
            genesis_hash: manifest.genesis_hash,
            protocol_version: manifest.protocol_version,
            key_algorithm: PeerKeyAlgorithm::Mldsa65,
        },
        chain_id: configuration.chain_id,
        bindings: Arc::new(bindings),
        verifier: Arc::new(handshake_verifier),
        frame_verifier,
        signer: Arc::new(signer),
        signing_key_id: local_key_id,
        manager: Arc::new(Mutex::new(PeerManager::new(
            identity.node_address.to_string(),
            configuration.p2p.max_authenticated_peers,
        ))),
        limits: frame_limits,
        handshake_timeout: timeouts.handshake,
        idle_timeout: timeouts.read,
        shutdown: Arc::new(AtomicBool::new(false)),
    })))
}

struct NetworkService {
    addresses: Vec<std::net::SocketAddr>,
    transport: TcpTransport,
    limits: TransportLimits,
    listeners: Vec<TcpListenerService>,
    #[cfg(test)]
    reserved_listeners: Option<Arc<Vec<TcpListenerService>>>,
    session: Option<SessionOwner>,
    sender: mpsc::SyncSender<NetworkEvent>,
    receiver: mpsc::Receiver<NetworkEvent>,
    pending: BTreeSet<u64>,
    dialing: BTreeMap<u64, String>,
    secure_last_dial: BTreeMap<String, Instant>,
    senders: BTreeMap<
        String,
        (
            u64,
            synergy_protocol_types::SessionId,
            mpsc::SyncSender<OutboundPayload>,
        ),
    >,
    max_pending: usize,
    active: BTreeMap<u64, (Option<TransportConnection>, std::thread::JoinHandle<()>)>,
    next_connection_id: u64,
    router: BoundedPeerRouter,
    ingress: AuthenticatedIngress,
    started: bool,
    failure: Option<String>,
}

impl NetworkService {
    fn apply_peer_control(&mut self, action: PeerControlAction) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system time predates Unix epoch".to_string())?
            .as_secs();
        let context = self
            .session
            .as_ref()
            .ok_or("authenticated network session owner is unavailable")?;
        if let PeerControlAction::Unban { peer_id } = action {
            return context
                .manager()
                .lock()
                .map_err(|_| "peer manager lock poisoned".to_string())?
                .unban(&peer_id, now)
                .then_some(())
                .ok_or_else(|| "peer is not currently banned".to_string());
        }
        let peer_id = action.peer_id().to_owned();
        let (connection_id, session_id) = self
            .senders
            .get(&peer_id)
            .map(|(connection_id, session_id, _)| (*connection_id, *session_id))
            .ok_or_else(|| "peer has no active authenticated session".to_string())?;
        let changed = {
            let mut manager = context
                .manager()
                .lock()
                .map_err(|_| "peer manager lock poisoned".to_string())?;
            match action {
                PeerControlAction::Disconnect { .. } => manager.disconnect_exact(
                    &peer_id,
                    session_id,
                    DisconnectReason::RemoteClosed,
                    now,
                ),
                PeerControlAction::Quarantine { until, .. } => {
                    if until <= now {
                        return Err("peer quarantine expiry must be in the future".into());
                    }
                    manager.quarantine_exact(&peer_id, session_id, until)
                }
                PeerControlAction::Ban { until, .. } => {
                    if until.is_some_and(|value| value <= now) {
                        return Err("peer ban expiry must be in the future".into());
                    }
                    manager.ban_exact(&peer_id, session_id, until)
                }
                PeerControlAction::Unban { .. } => unreachable!("unban handled above"),
            }
        };
        if !changed {
            return Err("peer session changed before control was applied".into());
        }
        if let Some((Some(connection), _)) = self.active.get(&connection_id) {
            let _ = connection.shutdown();
        }
        self.router.discard_session(&peer_id, session_id);
        self.ingress.discard_session(&peer_id, session_id)?;
        self.senders.remove(&peer_id);
        Ok(())
    }
}

impl ManagedService for NetworkService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        #[cfg(not(test))]
        if !matches!(self.session, Some(SessionOwner::Secure(_))) {
            synergy_network::transport::require_native_session_profile()
                .map_err(|error| error.to_string())?;
        }

        if cancellation.is_cancelled() {
            return Err("network service start was cancelled".into());
        }
        if self.started {
            return Err("network service is already running".into());
        }
        let mut listeners = Vec::with_capacity(self.addresses.len());
        #[cfg(test)]
        let reserved = self.reserved_listeners.is_some();
        #[cfg(not(test))]
        let reserved = false;
        if !reserved {
            for address in &self.addresses {
                listeners.push(
                    self.transport
                        .listen(*address)
                        .map_err(|error| format!("bind network listener {address}: {error}"))?,
                );
            }
        }
        #[cfg(test)]
        if let Some(reserved) = &self.reserved_listeners {
            for listener in reserved.iter() {
                // Stop closes all authenticated sessions. Discard pre-restart
                // unaccepted sockets too; new arrivals still undergo the native
                // fresh authenticated handshake in the normal accept loop.
                let mut drained = false;
                for _ in 0..512 {
                    match listener.accept() {
                        Ok(Some(connection)) => {
                            let _ = connection.shutdown();
                        }
                        Ok(None) => {
                            drained = true;
                            break;
                        }
                        Err(TransportError::AcceptedStreamConfiguration(_)) => continue,
                        Err(error) => return Err(format!("drain fixture listener: {error}")),
                    }
                }
                if !drained {
                    return Err("fixture listener backlog exceeds drain bound".into());
                }
            }
        }
        if let Some(context) = &self.session {
            context.shutdown().store(false, Ordering::Release);
        }
        self.listeners = listeners;
        self.started = true;
        self.failure = None;
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        if !self.started {
            return Err("network service is not started".into());
        }
        for event_index in 0..MAX_ACCEPTS_PER_POLL * 4 {
            for _ in 0..MAX_ACCEPTS_PER_POLL {
                let Some(request) = self.ingress.take_peer_control()? else {
                    break;
                };
                let result = self.apply_peer_control(request.action);
                let _ = request.response.send(result);
            }
            match self.receiver.try_recv() {
                Ok(NetworkEvent::Frame(frame)) => {
                    // The router records bounded global/per-peer rejection.
                    // Remote bursts are packet loss for reliable owners, not a
                    // local service-integrity failure.
                    let _ = self.router.try_admit(frame);
                }
                Ok(NetworkEvent::Closed {
                    peer_id,
                    session_id,
                }) => {
                    self.router.discard_session(&peer_id, session_id);
                    self.ingress.discard_session(&peer_id, session_id)?;
                    if self
                        .senders
                        .get(&peer_id)
                        .is_some_and(|(_, current, _)| *current == session_id)
                    {
                        self.senders.remove(&peer_id);
                    }
                }
                Ok(NetworkEvent::Authenticated {
                    connection_id,
                    peer_id,
                    session_id,
                    sender,
                    control,
                    apqe_engineering_session,
                }) => {
                    // Authentication may have queued before the reader exited.
                    // A lost Closed event must never resurrect that dead session.
                    if !authentication_connection_is_live(
                        self.active
                            .get(&connection_id)
                            .map(|(_, handle)| handle.is_finished()),
                    ) {
                        self.router.discard_session(&peer_id, session_id);
                        self.ingress.discard_session(&peer_id, session_id)?;
                        let _ = control.shutdown();
                        continue;
                    }
                    self.pending.remove(&connection_id);
                    self.dialing.remove(&connection_id);
                    if let Some((connection, _)) = self.active.get_mut(&connection_id) {
                        *connection = Some(control);
                    }
                    self.ingress.admit_session(peer_id.clone(), session_id)?;
                    if apqe_engineering_session {
                        self.ingress.mark_apqe_session(&peer_id, session_id)?;
                    }
                    self.senders
                        .insert(peer_id, (connection_id, session_id, sender));
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("network session event channel closed".into())
                }
            }
            // Drain before the 16-per-peer staging mailbox can fill from one
            // socket burst. Protocol ingress remains independently bounded;
            // repeated PoSy traffic must not discard a valid Sync frame here.
            if (event_index + 1) % 8 == 0 {
                drain_authenticated_router(&mut self.router, &self.ingress, 8)?;
            }
        }
        let finished: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, (_, handle))| handle.is_finished().then_some(*id))
            .collect();
        for id in finished {
            self.pending.remove(&id);
            self.dialing.remove(&id);
            // Closed notifications are best-effort on a bounded channel.
            // Thread completion independently removes exact-session presence.
            reap_finished_connection_sessions(
                id,
                &mut self.senders,
                &mut self.router,
                &self.ingress,
            )?;
            if let Some((_, handle)) = self.active.remove(&id) {
                let _ = handle.join();
            }
        }
        drain_authenticated_router(&mut self.router, &self.ingress, MAX_ACCEPTS_PER_POLL * 4)?;
        let mut disconnected_sessions = Vec::new();
        self.ingress.dispatch_outbound(|outbound| {
            let peer_id = outbound.peer_id;
            #[cfg(feature = "qualification-timing")]
            let diagnostic = super::qualification_timing::transport_span(
                super::qualification_timing::TransportStage::Dispatch,
                &peer_id,
                self.senders
                    .get(&peer_id)
                    .map_or(0, |(_, session, _)| session.0),
                0,
                synergy_network::protocol::protocol_id(outbound.protocol),
                outbound.payload.len(),
                &outbound.payload,
                None,
            );
            let result = match self.senders.get(&peer_id) {
                Some((_, _, sender)) => sender.try_send(OutboundPayload {
                    protocol: outbound.protocol,
                    payload: outbound.payload,
                    #[cfg(feature = "qualification-timing")]
                    diagnostic_enqueued_at: super::qualification_timing::transport_enabled()
                        .then(std::time::Instant::now),
                }),
                None => return None, // Reliable owners retain signed retries.
            };
            #[cfg(feature = "qualification-timing")]
            diagnostic.finish(result.is_ok());
            match result {
                Ok(()) => None,
                Err(mpsc::TrySendError::Full(payload)) => Some(super::ingress::OutboundFrame {
                    peer_id,
                    protocol: payload.protocol,
                    payload: payload.payload,
                }),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    if let Some((_, session, _)) = self.senders.remove(&peer_id) {
                        disconnected_sessions.push((peer_id, session));
                    }
                    None
                }
            }
        })?;
        // Do not lock ingress from inside dispatch_outbound's queue lock.
        for (peer, session) in disconnected_sessions {
            self.router.discard_session(&peer, session);
            self.ingress.discard_session(&peer, session)?;
        }
        #[cfg(test)]
        let reserved = self.reserved_listeners.clone();
        #[cfg(test)]
        let listeners = reserved
            .as_deref()
            .map_or(self.listeners.as_slice(), Vec::as_slice);
        #[cfg(not(test))]
        let listeners = self.listeners.as_slice();
        for listener in listeners {
            for _ in 0..MAX_ACCEPTS_PER_POLL {
                let connection = match listener.accept() {
                    Ok(Some(connection)) => connection,
                    Ok(None) => break,
                    // An accepted peer may reset before stream configuration.
                    // Drop only that stream; the bounded listener loop remains live.
                    Err(TransportError::AcceptedStreamConfiguration(_)) => continue,
                    Err(error) => return Err(format!("accept network connection: {error}")),
                };
                let accepted_at = Instant::now();
                let Some(context) = &self.session else {
                    let _ = connection.shutdown();
                    continue;
                };
                if self.max_pending == 0
                    || self.pending.len() >= self.max_pending
                    || self.active.len() >= self.limits.max_connections
                {
                    let _ = connection.shutdown();
                    continue;
                }
                let copy = connection
                    .try_clone()
                    .map_err(|error| format!("clone accepted session handle: {error}"))?;
                let connection_id = self.next_connection_id;
                self.next_connection_id = self
                    .next_connection_id
                    .checked_add(1)
                    .ok_or("network connection generation exhausted")?;
                self.pending.insert(connection_id);
                let context = context.clone();
                let sender = self.sender.clone();
                let handle = std::thread::spawn(move || {
                    let _result =
                        context.run_inbound(connection, sender, connection_id, accepted_at);
                    #[cfg(test)]
                    if let Err(error) = &_result {
                        eprintln!("inbound connection {connection_id} failed: {error}");
                    }
                });
                self.active.insert(connection_id, (Some(copy), handle));
            }
        }
        if let Some(SessionOwner::Secure(context)) = &self.session {
            let current = Instant::now();
            for (peer, address) in context.factory.dial_peers()? {
                // Same canonical direction as PeerManager duplicate arbitration,
                // selected before APQE's single-pending-peer admission barrier.
                if context.local_node_address.as_str() >= peer.as_str()
                    || self.senders.contains_key(peer.as_str())
                    || self
                        .dialing
                        .values()
                        .any(|pending| pending == peer.as_str())
                    || self
                        .secure_last_dial
                        .get(peer.as_str())
                        .is_some_and(|last| current.duration_since(*last) < Duration::from_secs(1))
                {
                    continue;
                }
                self.ingress.request_dial(super::ingress::DialRequest {
                    peer_id: peer.to_string(),
                    address,
                })?;
                self.secure_last_dial.insert(peer.to_string(), current);
            }
        }
        for _ in 0..MAX_ACCEPTS_PER_POLL {
            let Some(request) = self.ingress.take_dial()? else {
                break;
            };
            let Some(context) = &self.session else {
                continue;
            };
            if matches!(context, SessionOwner::Secure(c) if c.local_node_address.as_str() >= request.peer_id.as_str())
                || self.senders.contains_key(&request.peer_id)
                || self
                    .dialing
                    .values()
                    .any(|pending| pending == &request.peer_id)
                || !context.contains_peer(&request.peer_id)
                || self.pending.len() >= self.max_pending
                || self.active.len() >= self.limits.max_connections
            {
                continue;
            }
            let connection_id = self.next_connection_id;
            self.next_connection_id = self
                .next_connection_id
                .checked_add(1)
                .ok_or("network connection generation exhausted")?;
            self.pending.insert(connection_id);
            self.dialing.insert(connection_id, request.peer_id.clone());
            let context = context.clone();
            let sender = self.sender.clone();
            let transport = self.transport;
            let handle = std::thread::spawn(move || {
                if context.shutdown().load(Ordering::Acquire) {
                    return;
                }
                let accepted_at = Instant::now();
                let connection = match transport.dial(request.address) {
                    Ok(connection) => connection,
                    Err(_error) => {
                        #[cfg(test)]
                        eprintln!("outbound connection {connection_id} dial failed: {_error:?}");
                        return;
                    }
                };
                if context.shutdown().load(Ordering::Acquire) {
                    let _ = connection.shutdown();
                    return;
                }
                let _result = context.run_outbound(
                    connection,
                    sender,
                    connection_id,
                    &request.peer_id,
                    accepted_at,
                );
                #[cfg(test)]
                if let Err(error) = &_result {
                    eprintln!("outbound connection {connection_id} failed: {error}");
                }
            });
            self.active.insert(connection_id, (None, handle));
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(context) = &self.session {
            context.shutdown().store(true, Ordering::Release);
        }
        for (connection, _) in self.active.values() {
            if let Some(connection) = connection {
                let _ = connection.shutdown();
            }
        }
        for (_, (_, handle)) in std::mem::take(&mut self.active) {
            let _ = handle.join();
        }
        self.pending.clear();
        self.dialing.clear();
        self.secure_last_dial.clear();
        self.senders.clear();
        self.listeners.clear();
        self.started = false;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if let Some(reason) = &self.failure {
            return ServiceHealth::Unhealthy {
                reason: reason.clone(),
            };
        }
        #[cfg(test)]
        let listeners = self
            .reserved_listeners
            .as_deref()
            .map_or(self.listeners.as_slice(), Vec::as_slice);
        #[cfg(not(test))]
        let listeners = self.listeners.as_slice();
        if !self.started
            || listeners.len() != self.addresses.len()
            || listeners
                .iter()
                .any(|listener| listener.local_addr().is_err())
        {
            return ServiceHealth::Unhealthy {
                reason: "network listeners are not all bound".into(),
            };
        }
        if self.session.is_none() {
            return ServiceHealth::Degraded {
                reason: "awaiting governed Aegis bindings and provisioned local P2P signing key"
                    .into(),
            };
        }
        ServiceHealth::Healthy
    }

    fn readiness(&self) -> ServiceReadiness {
        match self.health() {
            ServiceHealth::Healthy => ServiceReadiness::Ready,
            ServiceHealth::Degraded { reason } => ServiceReadiness::Pending { reason },
            ServiceHealth::Unhealthy { reason } => ServiceReadiness::Blocked { reason },
        }
    }
}

fn authentication_connection_is_live(finished: Option<bool>) -> bool {
    finished == Some(false)
}

fn reap_finished_connection_sessions(
    connection_id: u64,
    senders: &mut BTreeMap<
        String,
        (
            u64,
            synergy_protocol_types::SessionId,
            mpsc::SyncSender<OutboundPayload>,
        ),
    >,
    router: &mut BoundedPeerRouter,
    ingress: &AuthenticatedIngress,
) -> Result<(), String> {
    let stale: Vec<_> = senders
        .iter()
        .filter(|(_, (owner, _, _))| *owner == connection_id)
        .map(|(peer, (_, session, _))| (peer.clone(), *session))
        .collect();
    for (peer, session) in stale {
        router.discard_session(&peer, session);
        ingress.discard_session(&peer, session)?;
        senders.remove(&peer);
    }
    Ok(())
}

fn drain_authenticated_router(
    router: &mut BoundedPeerRouter,
    ingress: &AuthenticatedIngress,
    maximum: usize,
) -> Result<(), String> {
    for _ in 0..maximum {
        let Some(frame) = router.try_next() else {
            break;
        };
        ingress.publish(frame)?;
    }
    Ok(())
}

#[cfg(test)]
mod burst_tests {
    use super::*;
    use synergy_network::protocol::InboundFrame;
    use synergy_protocol_types::{AuthenticatedPeer, ProtocolKind, SessionId};

    fn listener_fixture(reserved: Option<Arc<Vec<TcpListenerService>>>) -> NetworkService {
        let timeouts = TransportTimeouts {
            connect: Duration::from_secs(1),
            handshake: Duration::from_secs(1),
            read: Duration::from_secs(1),
            write: Duration::from_secs(1),
        };
        let addresses = reserved.as_ref().map_or_else(
            || vec!["127.0.0.1:0".parse().unwrap()],
            |listeners| {
                listeners
                    .iter()
                    .map(|listener| listener.local_addr().unwrap())
                    .collect()
            },
        );
        let (sender, receiver) = mpsc::sync_channel(1);
        NetworkService {
            addresses,
            transport: TcpTransport::new(timeouts).unwrap(),
            limits: TransportLimits {
                max_connections: 1,
                max_inbound_connections: 1,
                max_outbound_connections: 1,
                max_frame_bytes: 1024,
            },
            listeners: Vec::new(),
            reserved_listeners: reserved,
            session: None,
            sender,
            receiver,
            pending: BTreeSet::new(),
            dialing: BTreeMap::new(),
            secure_last_dial: BTreeMap::new(),
            senders: BTreeMap::new(),
            max_pending: 1,
            active: BTreeMap::new(),
            next_connection_id: 1,
            router: BoundedPeerRouter::new(1, 1),
            ingress: AuthenticatedIngress::default(),
            started: false,
            failure: None,
        }
    }

    #[test]
    fn fixture_listener_handoff_drains_restart_backlog_and_production_stop_releases_port() {
        use std::io::Read;
        use std::net::{TcpListener, TcpStream};
        let mut production = listener_fixture(None);
        production.start(&CancellationToken::default()).unwrap();
        let address = production.listeners[0].local_addr().unwrap();
        assert!(TcpListener::bind(address).is_err());
        production.stop().unwrap();
        let released = TcpListener::bind(address).unwrap();
        drop(released);

        let timeouts = TransportTimeouts {
            connect: Duration::from_secs(1),
            handshake: Duration::from_secs(1),
            read: Duration::from_secs(1),
            write: Duration::from_secs(1),
        };
        let reservation = Arc::new(vec![
            TcpListenerService::bind("127.0.0.1:0", timeouts).unwrap()
        ]);
        let address = reservation[0].local_addr().unwrap();
        let mut fixture = listener_fixture(Some(Arc::clone(&reservation)));
        fixture.start(&CancellationToken::default()).unwrap();
        fixture.stop().unwrap();
        assert!(TcpListener::bind(address).is_err());
        let mut stale = TcpStream::connect(address).unwrap();
        stale.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            fixture.start(&CancellationToken::default()).unwrap();
            match stale.read(&mut [0; 1]) {
                Ok(0) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    // connect() can return before a nonblocking listener can
                    // observe the accept queue, notably on Darwin. Retry the
                    // handoff after kernel delivery, under the same deadline.
                    fixture.stop().unwrap();
                    assert!(
                        std::time::Instant::now() < deadline,
                        "stale socket not drained"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                result => panic!("unexpected stale socket read: {result:?}"),
            }
        }
        assert!(reservation[0].accept().unwrap().is_none());
        let _fresh = TcpStream::connect(address).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while reservation[0].accept().unwrap().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "fresh socket not queued"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        fixture.stop().unwrap();
        drop(fixture);
        assert!(TcpListener::bind(address).is_err());
        drop(reservation);
    }

    #[test]
    fn finished_connection_reaps_session_when_closed_notification_is_lost() {
        let peer = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".to_string();
        let session = SessionId(1);
        let ingress = AuthenticatedIngress::default();
        ingress.admit_session(peer.clone(), session).unwrap();
        let mut router = BoundedPeerRouter::new(64, 16);
        let frame = InboundFrame::new(
            AuthenticatedPeer::new(peer.clone(), session, vec![]).unwrap(),
            ProtocolKind::Posy,
            vec![1],
            8,
        )
        .unwrap();
        router.try_admit(frame.clone()).unwrap();
        ingress.publish(frame).unwrap();
        let (sender, _receiver) = mpsc::sync_channel(1);
        let mut senders = BTreeMap::from([(peer.clone(), (7, session, sender))]);
        // No Closed event is delivered: completion is the independent authority.
        reap_finished_connection_sessions(7, &mut senders, &mut router, &ingress).unwrap();
        assert!(senders.is_empty());
        assert!(ingress.authenticated_peers().unwrap().is_empty());
        assert!(ingress.take(ProtocolKind::Posy).unwrap().is_none());
        assert!(router.try_next().is_none());
    }

    #[test]
    fn finished_old_connection_preserves_replacement_session() {
        let peer = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn".to_string();
        let ingress = AuthenticatedIngress::default();
        ingress.admit_session(peer.clone(), SessionId(1)).unwrap();
        ingress.admit_session(peer.clone(), SessionId(2)).unwrap();
        let mut router = BoundedPeerRouter::new(64, 16);
        let replacement = InboundFrame::new(
            AuthenticatedPeer::new(peer.clone(), SessionId(2), vec![]).unwrap(),
            ProtocolKind::Posy,
            vec![2],
            8,
        )
        .unwrap();
        router.try_admit(replacement.clone()).unwrap();
        let (sender, _receiver) = mpsc::sync_channel(1);
        let mut senders = BTreeMap::from([(peer.clone(), (8, SessionId(2), sender))]);
        reap_finished_connection_sessions(7, &mut senders, &mut router, &ingress).unwrap();
        assert_eq!(senders[&peer].0, 8);
        assert_eq!(ingress.authenticated_peers().unwrap(), vec![peer]);
        assert_eq!(router.try_next().unwrap(), replacement);
    }

    #[test]
    fn late_authentication_requires_a_live_connection_owner() {
        assert!(!authentication_connection_is_live(None));
        assert!(!authentication_connection_is_live(Some(true)));
        assert!(authentication_connection_is_live(Some(false)));
    }

    #[test]
    fn authenticated_burst_drain_preserves_sync_behind_consensus_frames() {
        let peer = AuthenticatedPeer::new(
            "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn",
            SessionId(1),
            vec![],
        )
        .unwrap();
        let ingress = AuthenticatedIngress::default();
        ingress
            .admit_session(peer.node_address.to_string(), peer.session_id)
            .unwrap();
        let make = |protocol| InboundFrame::new(peer.clone(), protocol, vec![1], 8).unwrap();
        // Exact old polling order discards Sync while its protocol queue is empty.
        let mut old = BoundedPeerRouter::new(64, 16);
        for _ in 0..32 {
            let _ = old.try_admit(make(ProtocolKind::Posy));
        }
        assert!(old.try_admit(make(ProtocolKind::Sync)).is_err());
        assert!(ingress.take(ProtocolKind::Sync).unwrap().is_none());
        let mut fixed = BoundedPeerRouter::new(64, 16);
        for event in 0..33 {
            fixed
                .try_admit(make(if event == 32 {
                    ProtocolKind::Sync
                } else {
                    ProtocolKind::Posy
                }))
                .unwrap();
            if (event + 1) % 8 == 0 {
                drain_authenticated_router(&mut fixed, &ingress, 8).unwrap();
            }
        }
        drain_authenticated_router(&mut fixed, &ingress, 128).unwrap();
        assert_eq!(
            ingress.take(ProtocolKind::Sync).unwrap().unwrap().peer,
            peer
        );
        assert_eq!(fixed.telemetry().rejected_peer_capacity, 0);
        assert!(fixed.telemetry().queue_high_water_mark <= 8);
    }
}
