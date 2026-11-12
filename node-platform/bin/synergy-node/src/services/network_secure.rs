//! Explicit isolated-canary APQE socket path. No plaintext fallback.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use synergy_address_engine::apqe::{
    engineering_transport::{read_m1_tcp, CurrentTransportTrust, SessionContext, TransportWorker},
    provider::{variants::Mldsa65, PublicKey},
};
use synergy_network::{
    peer::{DisconnectReason, PeerDirection, PeerManager},
    protocol::{decode_session_payload, encode_session_payload, InboundFrame},
    transport::TransportConnection,
};
use synergy_protocol_types::{AuthenticatedPeer, NodeAddress};

use super::{
    ingress::AuthenticatedIngress,
    network_session::{NetworkEvent, OutboundPayload},
};

pub(crate) struct SecureConnectionMaterial {
    pub worker: TransportWorker,
    pub context: SessionContext,
    pub peer_public: PublicKey<Mldsa65>,
    pub trust: Arc<dyn CurrentTransportTrust + Send + Sync>,
}
pub(crate) trait SecureTransportFactory: Send + Sync {
    fn local_node_address(&self) -> &NodeAddress;
    fn contains_peer(&self, peer_id: &str) -> bool;
    fn material(&self, peer_id: &str, inbound: bool) -> Result<SecureConnectionMaterial, String>;
    fn dial_peers(&self) -> Result<Vec<(NodeAddress, std::net::SocketAddr)>, String>;
}
pub(super) struct SecureSessionContext {
    pub ingress: AuthenticatedIngress,
    pub local_node_address: NodeAddress,
    pub manager: Arc<Mutex<PeerManager>>,
    pub shutdown: Arc<AtomicBool>,
    pub max_payload_bytes: usize,
    pub factory: Arc<dyn SecureTransportFactory>,
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "system time predates Unix epoch".into())
}

pub(super) fn run(
    context: Arc<SecureSessionContext>,
    mut connection: TransportConnection,
    events: SyncSender<NetworkEvent>,
    connection_id: u64,
    expected_peer: Option<&str>,
    accepted_at: Instant,
) -> Result<(), String> {
    // This instant is captured before any first-byte wait or provider load.
    let inbound = expected_peer.is_none();
    let initial = if inbound {
        Some(
            read_m1_tcp(connection.stream_mut(), accepted_at)
                .map_err(|e| format!("APQE M1: {e:?}"))?,
        )
    } else {
        None
    };
    let peer_id = match (&initial, expected_peer) {
        (Some(m1), None) => {
            if m1.context().responder_node != context.local_node_address.as_str() {
                return Err("APQE M1 has a different intended responder".into());
            }
            m1.context().initiator_node.clone()
        }
        (None, Some(peer)) => peer.to_owned(),
        _ => return Err("invalid APQE connection direction".into()),
    };
    if !context.factory.contains_peer(&peer_id) {
        return Err("peer is not in authenticated transport registry".into());
    }
    let material = context.factory.material(&peer_id, inbound)?;
    if initial
        .as_ref()
        .is_some_and(|m1| m1.context() != &material.context)
    {
        return Err("APQE M1 context differs from authenticated current state".into());
    }
    context
        .ingress
        .permit_overlay_peer(&peer_id, connection.peer_addr(), inbound, false)?;
    let mut session = match initial {
        Some(m1) => material.worker.responder_from_initial(
            material.trust.as_ref(),
            &material.peer_public,
            m1,
        ),
        None => material.worker.initiator(
            material.trust.as_ref(),
            &material.peer_public,
            material.context,
            accepted_at,
        ),
    }
    .map_err(|e| format!("APQE session initialization: {e:?}"))?;
    if inbound {
        session.handshake_responder_tcp(connection.stream_mut())
    } else {
        session.handshake_initiator_tcp(connection.stream_mut())
    }
    .map_err(|e| format!("APQE four-message handshake: {e:?}"))?;
    if !session.established() {
        return Err("APQE establishment barrier was not completed".into());
    }
    let admission = context
        .manager
        .lock()
        .map_err(|_| "peer manager lock poisoned")?
        .admit(
            peer_id.clone(),
            if inbound {
                PeerDirection::Inbound
            } else {
                PeerDirection::Outbound
            },
            now()?,
        )
        .map_err(|e| format!("APQE authenticated peer admission: {e:?}"))?;
    let peer = AuthenticatedPeer::new(peer_id.clone(), admission.session_id, vec![])
        .map_err(|e| e.to_string())?;
    let socket_control = connection.try_clone().map_err(|e| e.to_string())?;
    let mut driver = session
        .into_driver(connection.into_stream())
        .map_err(|e| format!("APQE record driver: {e:?}"))?;
    let result = (|| {
        let mut manager = context
            .manager
            .lock()
            .map_err(|_| "peer manager lock poisoned")?;
        let timestamp = now()?;
        if !manager.authenticate(&peer_id, peer.session_id, vec![], timestamp)
            || !manager.mark_ready(&peer_id, peer.session_id, timestamp)
        {
            return Err("APQE authenticated session displaced before readiness".into());
        }
        drop(manager);
        let (sender, receiver) = mpsc::sync_channel::<OutboundPayload>(16);
        events
            .try_send(NetworkEvent::Authenticated {
                connection_id,
                apqe_engineering_session: true,
                peer_id: peer_id.clone(),
                session_id: peer.session_id,
                sender,
                control: socket_control.try_clone().map_err(|e| e.to_string())?,
            })
            .map_err(|_| "network session event queue is full")?;
        // One owner alternates bounded nonblocking I/O in both directions.
        // Ciphertext is sealed once; partial writes never re-encrypt/reuse nonces.
        while !context.shutdown.load(Ordering::Acquire) {
            driver
                .poll_lifecycle(Instant::now())
                .map_err(|e| format!("APQE lifecycle: {e:?}"))?;
            let mut progressed = false;
            if driver.can_queue() {
                match receiver.try_recv() {
                    Ok(frame) => {
                        progressed = true;
                        let body = encode_session_payload(
                            frame.protocol,
                            &frame.payload,
                            context.max_payload_bytes,
                        )?;
                        driver
                            .queue_application(&body)
                            .map_err(|e| format!("APQE record queue: {e:?}"))?;
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                    Err(mpsc::TryRecvError::Disconnected) => return Ok(()),
                }
            }
            let incoming = driver
                .poll_io()
                .map_err(|e| format!("APQE record I/O: {e:?}"))?;
            if !driver.established() {
                return Ok(());
            }
            if let Some(body) = incoming {
                progressed = true;
                let (protocol, payload) =
                    decode_session_payload(body.as_bytes(), context.max_payload_bytes)?;
                let frame = InboundFrame::new(
                    peer.clone(),
                    protocol,
                    payload.to_vec(),
                    context.max_payload_bytes,
                )
                .map_err(|e| e.to_string())?;
                match events.try_send(NetworkEvent::Frame(frame)) {
                    Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        return Err("network ingress queue closed".into())
                    }
                }
            }
            std::thread::sleep(if driver.can_queue() && !progressed {
                Duration::from_millis(20)
            } else {
                Duration::from_millis(1)
            });
        }
        Ok(())
    })();
    driver.retire();
    let _ = socket_control.shutdown();
    if let Ok(mut manager) = context.manager.lock() {
        manager.disconnect_exact(
            &peer_id,
            peer.session_id,
            DisconnectReason::RemoteClosed,
            now().unwrap_or_default(),
        );
    }
    let _ = events.try_send(NetworkEvent::Closed {
        peer_id,
        session_id: peer.session_id,
    });
    result
}
