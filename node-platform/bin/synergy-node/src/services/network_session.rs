//! Bounded, mutually authenticated P2P session I/O. No consensus authority.
use std::fs::File;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{
    mpsc::{self, Receiver, SyncSender},
    Arc, Mutex,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use synergy_aegis::{
    AegisPolicy, GovernedKeyBindings, PqvmSigner, PqvmVerifier, SignatureAlgorithm,
};
use synergy_network::handshake::{
    build_handshake_proof, verify_handshake, AegisHandshakeSigner, AegisHandshakeVerifier,
    HandshakeChallenge, HandshakeMetadata, HandshakeOffer, HandshakeProof, PeerKeyAlgorithm,
    TransportIdentity,
};
use synergy_network::peer::{DisconnectReason, PeerDirection, PeerManager};
use synergy_network::protocol::{
    decode_authenticated, encode_authenticated, AegisFrameSigner, AegisFrameVerifier, FrameLimits,
    InboundFrame, OutboundEnvelope, FRAME_HEADER_BYTES,
};
use synergy_network::transport::TransportConnection;
use synergy_protocol_types::{AuthenticatedPeer, NodeAddress, NodeRole, ProtocolKind, SessionId};

use super::ingress::AuthenticatedIngress;

const MAX_HANDSHAKE_RECORD: usize = 64 * 1024;
const MAX_SIGNATURE: usize = 16 * 1024;
const CHALLENGE_LIFETIME: u64 = 30;

#[derive(Clone)]
pub struct SessionContext {
    pub ingress: AuthenticatedIngress,
    pub overlay_required: bool,
    pub local_node_address: NodeAddress,
    pub local_role: NodeRole,
    pub expected: HandshakeMetadata,
    pub chain_id: u64,
    pub bindings: Arc<GovernedKeyBindings>,
    pub verifier: Arc<AegisHandshakeVerifier<PqvmVerifier>>,
    pub signer: Arc<PqvmSigner>,
    pub signing_key_id: synergy_aegis::KeyId,
    pub policy: AegisPolicy,
    pub manager: Arc<Mutex<PeerManager>>,
    pub limits: FrameLimits,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub shutdown: Arc<AtomicBool>,
}

pub struct OutboundPayload {
    pub protocol: ProtocolKind,
    pub payload: Vec<u8>,
}

pub enum NetworkEvent {
    Frame(InboundFrame),
    Closed {
        peer_id: String,
        session_id: SessionId,
    },
    Authenticated {
        connection_id: u64,
        peer_id: String,
        session_id: SessionId,
        sender: SyncSender<OutboundPayload>,
        control: TransportConnection,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOffer {
    node_address: String,
    network_id: String,
    genesis_hash: String,
    protocol_version: String,
    key_algorithm: String,
    role: NodeRole,
    capabilities: Vec<String>,
    nonce: Vec<u8>,
    issued_at: u64,
    lifetime_secs: u64,
}

impl WireOffer {
    fn from_offer(offer: &HandshakeOffer) -> Self {
        Self {
            node_address: offer.metadata.node_address.to_string(),
            network_id: offer.metadata.network_id.clone(),
            genesis_hash: offer.metadata.genesis_hash.clone(),
            protocol_version: offer.metadata.protocol_version.clone(),
            key_algorithm: "ML-DSA-65".into(),
            role: offer.identity.role(),
            capabilities: offer.identity.capabilities().to_vec(),
            nonce: offer.challenge.nonce().to_vec(),
            issued_at: offer.challenge.issued_at(),
            lifetime_secs: offer.challenge.lifetime_secs(),
        }
    }

    fn into_offer(self) -> Result<HandshakeOffer, String> {
        let nonce: [u8; 32] = self
            .nonce
            .try_into()
            .map_err(|_| "handshake challenge nonce is not 32 bytes")?;
        let challenge = HandshakeChallenge::new(nonce, self.issued_at, self.lifetime_secs)
            .map_err(|error| format!("invalid handshake challenge: {error}"))?;
        let algorithm = synergy_network::handshake::parse_peer_key_algorithm(&self.key_algorithm)
            .map_err(|_| "unsupported handshake algorithm")?;
        let identity = TransportIdentity::new(&self.node_address, self.role, &self.capabilities)
            .map_err(|error| format!("invalid transport identity: {error}"))?;
        HandshakeOffer::new(
            HandshakeMetadata {
                node_address: synergy_protocol_types::NodeAddress::parse(self.node_address)
                    .map_err(|error| format!("invalid canonical node address: {error}"))?,
                network_id: self.network_id,
                genesis_hash: self.genesis_hash,
                protocol_version: self.protocol_version,
                key_algorithm: algorithm,
            },
            identity,
            challenge,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAnswer {
    offer: WireOffer,
    session_id: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProof {
    session_id: u64,
    offer_nonce: Vec<u8>,
    answer_nonce: Vec<u8>,
    signature: Vec<u8>,
}

impl WireProof {
    fn from_proof(proof: HandshakeProof) -> Self {
        Self {
            session_id: proof.session_id.0,
            offer_nonce: proof.offer_nonce.to_vec(),
            answer_nonce: proof.answer_nonce.to_vec(),
            signature: proof.signature,
        }
    }

    fn into_proof(self) -> Result<HandshakeProof, String> {
        if self.signature.is_empty() || self.signature.len() > MAX_SIGNATURE {
            return Err("invalid handshake signature length".into());
        }
        Ok(HandshakeProof {
            session_id: SessionId(self.session_id),
            offer_nonce: self
                .offer_nonce
                .try_into()
                .map_err(|_| "invalid offer nonce length")?,
            answer_nonce: self
                .answer_nonce
                .try_into()
                .map_err(|_| "invalid answer nonce length")?,
            signature: self.signature,
        })
    }
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| "system time predates Unix epoch".into())
}

fn challenge() -> Result<HandshakeChallenge, String> {
    let mut nonce = [0u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|error| format!("obtain secure handshake nonce: {error}"))?;
    HandshakeChallenge::new(nonce, now()?, CHALLENGE_LIFETIME).map_err(|error| error.to_string())
}

fn local_offer(
    context: &SessionContext,
    challenge: HandshakeChallenge,
) -> Result<HandshakeOffer, String> {
    let identity =
        TransportIdentity::new(context.local_node_address.as_str(), context.local_role, &[])
            .map_err(|error| error.to_string())?;
    let mut metadata = context.expected.clone();
    metadata.node_address = context.local_node_address.clone();
    metadata.key_algorithm = PeerKeyAlgorithm::Mldsa65;
    HandshakeOffer::new(metadata, identity, challenge).map_err(|error| error.to_string())
}

fn read_record<T: DeserializeOwned>(connection: &mut TransportConnection) -> Result<T, String> {
    let mut header = [0u8; 4];
    connection
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_HANDSHAKE_RECORD {
        return Err("handshake record exceeds the fixed bound".into());
    }
    let mut bytes = vec![0u8; length];
    connection
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode handshake record: {error}"))
}

fn write_record<T: Serialize>(
    connection: &mut TransportConnection,
    value: &T,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_RECORD {
        return Err("handshake record exceeds the fixed bound".into());
    }
    connection
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(|error| error.to_string())?;
    connection
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    connection.flush().map_err(|error| error.to_string())
}

fn sign_proof(
    context: &SessionContext,
    offer: &HandshakeOffer,
    session_id: SessionId,
    answer: &HandshakeChallenge,
) -> Result<HandshakeProof, String> {
    let signer = AegisHandshakeSigner::new(
        Arc::clone(&context.signer),
        context.signing_key_id.clone(),
        context.chain_id,
    )?;
    build_handshake_proof(offer, session_id, answer, &signer)
        .map_err(|error| format!("sign handshake proof: {error:?}"))
}

fn verify_proof(
    context: &SessionContext,
    offer: &HandshakeOffer,
    proof: &HandshakeProof,
    answer: &HandshakeChallenge,
    session_id: SessionId,
) -> Result<AuthenticatedPeer, String> {
    verify_handshake(
        offer,
        proof,
        answer,
        &context.expected,
        session_id,
        now()?,
        context.verifier.as_ref(),
    )
    .map(|verified| verified.into_peer())
    .map_err(|error| format!("verify signed handshake proof: {error:?}"))
}

fn authenticate(context: &SessionContext, peer: &AuthenticatedPeer) -> Result<(), String> {
    let mut manager = context
        .manager
        .lock()
        .map_err(|_| "peer manager lock poisoned")?;
    let current = now()?;
    if !manager.authenticate(
        peer.node_address.as_str(),
        peer.session_id,
        peer.capabilities.clone(),
        current,
    ) || !manager.mark_ready(peer.node_address.as_str(), peer.session_id, current)
    {
        return Err("authenticated session was displaced before readiness".into());
    }
    Ok(())
}

fn read_frames(
    context: &SessionContext,
    connection: &mut TransportConnection,
    peer: &AuthenticatedPeer,
    events: &SyncSender<NetworkEvent>,
) -> Result<(), String> {
    connection
        .set_read_timeout(context.idle_timeout)
        .map_err(|error| error.to_string())?;
    let binding = context
        .bindings
        .get(peer.node_address.as_str())
        .ok_or("authenticated peer has no governed key binding")?
        .clone();
    let verifier = AegisFrameVerifier::new(
        PqvmVerifier::new(context.policy.clone()).map_err(|error| error.to_string())?,
        binding,
        context.chain_id,
    )?;
    let mut next_sequence = 1u64;
    while !context.shutdown.load(Ordering::Acquire) {
        let mut header = [0u8; FRAME_HEADER_BYTES];
        connection
            .read_exact(&mut header)
            .map_err(|error| error.to_string())?;
        let payload_len = u32::from_be_bytes(header[24..28].try_into().unwrap()) as usize;
        let authenticator_len = u16::from_be_bytes(header[28..30].try_into().unwrap()) as usize;
        if payload_len == 0
            || payload_len > context.limits.max_payload_bytes()
            || authenticator_len == 0
            || authenticator_len > context.limits.max_authenticator_bytes()
        {
            return Err("authenticated frame exceeds session bounds".into());
        }
        let total = FRAME_HEADER_BYTES
            .checked_add(payload_len)
            .and_then(|bytes| bytes.checked_add(authenticator_len))
            .ok_or("authenticated frame length overflow")?;
        let mut wire = Vec::with_capacity(total);
        wire.extend_from_slice(&header);
        wire.resize(total, 0);
        connection
            .read_exact(&mut wire[FRAME_HEADER_BYTES..])
            .map_err(|error| error.to_string())?;
        context.ingress.permit_overlay_peer(
            peer.node_address.as_str(),
            connection.peer_addr(),
            connection.is_inbound(),
            context.overlay_required,
        )?;
        let decoded = decode_authenticated(&wire, context.limits, &verifier)
            .map_err(|error| format!("verify authenticated frame: {error:?}"))?;
        if decoded.session_id() != peer.session_id || decoded.sequence() != next_sequence {
            return Err("cross-session or replayed authenticated frame".into());
        }
        next_sequence = next_sequence
            .checked_add(1)
            .ok_or("authenticated frame sequence exhausted")?;
        let frame = decoded
            .into_inbound(peer.clone(), context.limits.max_payload_bytes())
            .map_err(|error| error.to_string())?;
        events
            .try_send(NetworkEvent::Frame(frame))
            .map_err(|_| "bounded network ingress queue is full or closed")?;
    }
    Ok(())
}

fn write_frames(
    context: &SessionContext,
    mut connection: TransportConnection,
    session_id: SessionId,
    outbound: Receiver<OutboundPayload>,
    alive: Arc<AtomicBool>,
) -> Result<(), String> {
    let signer = AegisFrameSigner::new(
        Arc::clone(&context.signer),
        context.signing_key_id.clone(),
        context.chain_id,
    )?;
    let mut sequence = 1u64;
    while alive.load(Ordering::Acquire) && !context.shutdown.load(Ordering::Acquire) {
        let frame = match outbound.recv_timeout(Duration::from_millis(100)) {
            Ok(frame) => frame,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let envelope = OutboundEnvelope::new(frame.protocol, session_id, sequence, &frame.payload)
            .map_err(|error| error.to_string())?;
        let wire = encode_authenticated(envelope, context.limits, &signer)
            .map_err(|error| format!("sign outbound frame: {error:?}"))?;
        connection
            .write_all(&wire)
            .map_err(|error| error.to_string())?;
        connection.flush().map_err(|error| error.to_string())?;
        sequence = sequence
            .checked_add(1)
            .ok_or("outbound frame sequence exhausted")?;
    }
    Ok(())
}

fn run_authenticated_frames(
    context: &SessionContext,
    connection: &mut TransportConnection,
    peer: &AuthenticatedPeer,
    events: &SyncSender<NetworkEvent>,
    connection_id: u64,
) -> Result<(), String> {
    let writer = connection.try_clone().map_err(|error| error.to_string())?;
    let (sender, receiver) = mpsc::sync_channel(16);
    let alive = Arc::new(AtomicBool::new(true));
    let writer_alive = Arc::clone(&alive);
    let writer_context = context.clone();
    let session_id = peer.session_id;
    let handle = std::thread::spawn(move || {
        write_frames(&writer_context, writer, session_id, receiver, writer_alive)
    });
    let control = connection.try_clone().map_err(|error| error.to_string())?;
    events
        .try_send(NetworkEvent::Authenticated {
            connection_id,
            peer_id: peer.node_address.to_string(),
            session_id,
            sender,
            control,
        })
        .map_err(|_| "network session event queue is full")?;
    let result = read_frames(context, connection, peer, events);
    alive.store(false, Ordering::Release);
    let writer_result = handle
        .join()
        .map_err(|_| "outbound frame writer panicked")?;
    result.and(writer_result)
}

fn close(context: &SessionContext, peer: &AuthenticatedPeer, events: &SyncSender<NetworkEvent>) {
    if let Ok(mut manager) = context.manager.lock() {
        let _ = manager.disconnect_exact(
            peer.node_address.as_str(),
            peer.session_id,
            DisconnectReason::RemoteClosed,
            now().unwrap_or_default(),
        );
    }
    let _ = events.try_send(NetworkEvent::Closed {
        peer_id: peer.node_address.to_string(),
        session_id: peer.session_id,
    });
}

pub fn run_inbound(
    context: Arc<SessionContext>,
    mut connection: TransportConnection,
    events: SyncSender<NetworkEvent>,
    connection_id: u64,
) -> Result<(), String> {
    connection
        .set_read_timeout(context.handshake_timeout)
        .map_err(|error| error.to_string())?;
    let remote_offer = read_record::<WireOffer>(&mut connection)?.into_offer()?;
    context.ingress.permit_overlay_peer(
        remote_offer.metadata.node_address.as_str(),
        connection.peer_addr(),
        true,
        context.overlay_required,
    )?;
    remote_offer
        .challenge
        .validate_at(now()?)
        .map_err(|error| error.to_string())?;
    remote_offer
        .metadata
        .validate_against(&context.expected)
        .map_err(|error| format!("incompatible handshake offer: {error:?}"))?;
    if context
        .bindings
        .get(remote_offer.metadata.node_address.as_str())
        .is_none()
    {
        return Err("peer has no governed Aegis key binding".into());
    }
    let local_offer = local_offer(&context, challenge()?)?;
    let admission = context
        .manager
        .lock()
        .map_err(|_| "peer manager lock poisoned")?
        .admit(
            remote_offer.metadata.node_address.to_string(),
            PeerDirection::Inbound,
            now()?,
        )
        .map_err(|error| format!("inbound peer admission: {error:?}"))?;
    let tentative = AuthenticatedPeer::new(
        remote_offer.metadata.node_address.to_string(),
        admission.session_id,
        vec![],
    )
    .map_err(|error| error.to_string())?;
    let result = (|| {
        write_record(
            &mut connection,
            &WireAnswer {
                offer: WireOffer::from_offer(&local_offer),
                session_id: admission.session_id.0,
            },
        )?;
        let proof = read_record::<WireProof>(&mut connection)?.into_proof()?;
        let peer = verify_proof(
            &context,
            &remote_offer,
            &proof,
            &local_offer.challenge,
            admission.session_id,
        )?;
        let response = sign_proof(
            &context,
            &local_offer,
            admission.session_id,
            &remote_offer.challenge,
        )?;
        write_record(&mut connection, &WireProof::from_proof(response))?;
        authenticate(&context, &peer)?;
        run_authenticated_frames(&context, &mut connection, &peer, &events, connection_id)
    })();
    close(&context, &tentative, &events);
    let _ = connection.shutdown();
    result
}

pub fn run_outbound(
    context: Arc<SessionContext>,
    mut connection: TransportConnection,
    events: SyncSender<NetworkEvent>,
    connection_id: u64,
    expected_peer_id: &str,
) -> Result<(), String> {
    connection
        .set_read_timeout(context.handshake_timeout)
        .map_err(|error| error.to_string())?;
    context.ingress.permit_overlay_peer(
        expected_peer_id,
        connection.peer_addr(),
        false,
        context.overlay_required,
    )?;
    let local_offer = local_offer(&context, challenge()?)?;
    write_record(&mut connection, &WireOffer::from_offer(&local_offer))?;
    let answer: WireAnswer = read_record(&mut connection)?;
    let remote_offer = answer.offer.into_offer()?;
    if remote_offer.metadata.node_address.as_str() != expected_peer_id {
        return Err("outbound address returned a different governed peer identity".into());
    }
    remote_offer
        .metadata
        .validate_against(&context.expected)
        .map_err(|error| format!("incompatible handshake offer: {error:?}"))?;
    if context
        .bindings
        .get(remote_offer.metadata.node_address.as_str())
        .is_none()
    {
        return Err("peer has no governed Aegis key binding".into());
    }
    let session_id = SessionId(answer.session_id);
    let proof = sign_proof(&context, &local_offer, session_id, &remote_offer.challenge)?;
    write_record(&mut connection, &WireProof::from_proof(proof))?;
    let remote_proof = read_record::<WireProof>(&mut connection)?.into_proof()?;
    let peer = verify_proof(
        &context,
        &remote_offer,
        &remote_proof,
        &local_offer.challenge,
        session_id,
    )?;
    context
        .manager
        .lock()
        .map_err(|_| "peer manager lock poisoned")?
        .admit_with_session(
            peer.node_address.to_string(),
            PeerDirection::Outbound,
            session_id,
            now()?,
        )
        .map_err(|error| format!("outbound peer admission: {error:?}"))?;
    authenticate(&context, &peer)?;
    let result = run_authenticated_frames(&context, &mut connection, &peer, &events, connection_id);
    close(&context, &peer, &events);
    let _ = connection.shutdown();
    result
}
