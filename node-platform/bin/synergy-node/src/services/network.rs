//! Governed Aegis-authenticated P2P listener and bounded frame admission.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use synergy_aegis::{
    AegisPolicy, AegisSigner, AegisVerifier, GovernedKeyBindings, PqvmSigner, PqvmVerifier,
    SignatureAlgorithm, SigningContext,
};
use synergy_config::{NodeConfiguration, VpnMode};
use synergy_identity::PublicNodeIdentity;
use synergy_manifest::NetworkManifest;
use synergy_network::handshake::{AegisHandshakeVerifier, HandshakeMetadata, PeerKeyAlgorithm};
use synergy_network::peer::PeerManager;
use synergy_network::protocol::FrameLimits;
use synergy_network::router::BoundedPeerRouter;
use synergy_network::transport::{
    TcpListenerService, TcpTransport, Transport, TransportConnection, TransportLimits,
    TransportTimeouts,
};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};

use super::ingress::AuthenticatedIngress;
use super::network_session::{
    run_inbound, run_outbound, NetworkEvent, OutboundPayload, SessionContext,
};

const MAX_ACCEPTS_PER_POLL: usize = 32;
const MAX_BINDINGS_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_IDENTITY_BYTES: u64 = 64 * 1024;
const MAX_SIGNING_KEY_BYTES: u64 = 8 * 1024;

pub fn registration(
    configuration: &NodeConfiguration,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
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
        Box::new(NetworkService {
            addresses: network.listen_addresses.clone(),
            transport,
            limits,
            listeners: Vec::new(),
            session: Some(session),
            sender,
            receiver,
            pending: BTreeSet::new(),
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
        }),
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
    let signer =
        PqvmSigner::from_secret_key_bytes(policy.clone(), local_binding.key_id.clone(), key_bytes)
            .map_err(|error| format!("load PQVM signer: {error}"))?;
    let verifier = PqvmVerifier::new(policy.clone()).map_err(|error| error.to_string())?;
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
        signer: Arc::new(signer),
        signing_key_id: local_key_id,
        policy,
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
    session: Option<Arc<SessionContext>>,
    sender: mpsc::SyncSender<NetworkEvent>,
    receiver: mpsc::Receiver<NetworkEvent>,
    pending: BTreeSet<u64>,
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

impl ManagedService for NetworkService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("network service start was cancelled".into());
        }
        if self.started {
            return Err("network service is already running".into());
        }
        let mut listeners = Vec::with_capacity(self.addresses.len());
        for address in &self.addresses {
            listeners.push(
                self.transport
                    .listen(*address)
                    .map_err(|error| format!("bind network listener {address}: {error}"))?,
            );
        }
        if let Some(context) = &self.session {
            context.shutdown.store(false, Ordering::Release);
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
        for _ in 0..MAX_ACCEPTS_PER_POLL * 4 {
            match self.receiver.try_recv() {
                Ok(NetworkEvent::Frame(frame)) => {
                    self.router.try_admit(frame).map_err(|error| {
                        format!("bounded peer router rejected frame: {error:?}")
                    })?;
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
                }) => {
                    self.pending.remove(&connection_id);
                    if let Some((connection, _)) = self.active.get_mut(&connection_id) {
                        *connection = Some(control);
                    }
                    self.ingress.admit_session(peer_id.clone(), session_id)?;
                    self.senders
                        .insert(peer_id, (connection_id, session_id, sender));
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err("network session event channel closed".into())
                }
            }
        }
        let finished: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(id, (_, handle))| handle.is_finished().then_some(*id))
            .collect();
        for id in finished {
            self.pending.remove(&id);
            self.senders.retain(|_, (owner, _, _)| *owner != id);
            if let Some((_, handle)) = self.active.remove(&id) {
                let _ = handle.join();
            }
        }
        for _ in 0..MAX_ACCEPTS_PER_POLL * 4 {
            let Some(frame) = self.router.try_next() else {
                break;
            };
            self.ingress.publish(frame)?;
        }
        for _ in 0..MAX_ACCEPTS_PER_POLL * 4 {
            let Some(outbound) = self.ingress.take_outbound()? else {
                break;
            };
            let peer_id = outbound.peer_id;
            let failed = match self.senders.get(&peer_id) {
                Some((_, _, sender)) => sender
                    .try_send(OutboundPayload {
                        protocol: outbound.protocol,
                        payload: outbound.payload,
                    })
                    .is_err(),
                None => true,
            };
            if failed {
                self.senders.remove(&peer_id);
            }
        }
        for listener in &self.listeners {
            for _ in 0..MAX_ACCEPTS_PER_POLL {
                let Some(connection) = listener
                    .accept()
                    .map_err(|error| format!("accept network connection: {error}"))?
                else {
                    break;
                };
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
                let context = Arc::clone(context);
                let sender = self.sender.clone();
                let handle = std::thread::spawn(move || {
                    let _ = run_inbound(context, connection, sender, connection_id);
                });
                self.active.insert(connection_id, (Some(copy), handle));
            }
        }
        for _ in 0..MAX_ACCEPTS_PER_POLL {
            let Some(request) = self.ingress.take_dial()? else {
                break;
            };
            let Some(context) = &self.session else {
                continue;
            };
            if context.bindings.get(&request.peer_id).is_none()
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
            let context = Arc::clone(context);
            let sender = self.sender.clone();
            let transport = self.transport;
            let handle = std::thread::spawn(move || {
                if context.shutdown.load(Ordering::Acquire) {
                    return;
                }
                let Ok(connection) = transport.dial(request.address) else {
                    return;
                };
                if context.shutdown.load(Ordering::Acquire) {
                    let _ = connection.shutdown();
                    return;
                }
                let _ = run_outbound(context, connection, sender, connection_id, &request.peer_id);
            });
            self.active.insert(connection_id, (None, handle));
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(context) = &self.session {
            context.shutdown.store(true, Ordering::Release);
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
        if !self.started
            || self.listeners.len() != self.addresses.len()
            || self
                .listeners
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
