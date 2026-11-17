//! Opt-in Canary 99999 relay. Public HTTP terminates on loopback; the native
//! gateway-to-validator hop always uses APQE. The upstream is the validator's
//! existing loopback RPC, with a single dispatch and no alternate routing.
use super::{
    apqe_rpc::{self, Admission, MAX_BODY},
    apqe_transport as transport,
    authority::{self, recovery::successor, VerifiedAuthority},
};
use serde::Deserialize;
use serde_json::{json, value::RawValue};
use std::{
    borrow::Cow,
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Mutex},
    time::{Duration, Instant},
};
use synergy_address_engine::{
    apqe::{
        engineering_transport::{
            load_gateway_transport_worker, load_transport_worker, read_m1_tcp,
            GatewayTransportWorker, TransportWorker,
        },
        provider::{variants::Mldsa65, PublicKey},
        Primitives,
    },
    encrypt::EncryptedEnvelope,
    validator_provisioning::EnrollmentRequest,
};
use synergy_config::NodeConfiguration;
use synergy_protocol_types::NodeRole;
use synergy_rpc::methods::{CHAIN_TELEMETRY, EPOCH_TRANSITION_PROOF_V1};

const HEADER_MAX: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const WORKERS: usize = 4;
const MAX_EPOCH_PROOFS_PER_REQUEST: usize = 4;
const TELEMETRY: &[u8] =
    br#"{"jsonrpc":"2.0","method":"synergy_chainTelemetry","params":{},"id":1}"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema_version: u16,
    node_config_path: PathBuf,
    admission_path: PathBuf,
    listen_address: SocketAddr,
    role: Role,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Role {
    Validator {
        validator_address: String,
        gateway_vpn_ip: IpAddr,
    },
    Gateway {
        gateway_address: String,
        validator_address: String,
        validator_relay_port: u16,
        enrollment_path: PathBuf,
        custody_path: PathBuf,
        custody_unlock_path: PathBuf,
        allowed_origins: Vec<String>,
        #[serde(default)]
        autonomous_bootstrap_sha256: Option<String>,
    },
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<String> = args.collect();
    let path = Path::new;
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["serve", config] => run(path(config), true),
        ["check", config] => run(path(config), false),
        ["provision", config, output, transport_unlock, identity_unlock] => apqe_rpc::provision(
            &synergy_config::load(path(config)).map_err(|e| e.to_string())?,
            path(output), path(transport_unlock), path(identity_unlock),
        ),
        ["issue", config, enrollment, root, unlock, output] => apqe_rpc::issue(
            &synergy_config::load(path(config)).map_err(|e| e.to_string())?,
            path(enrollment), path(root), path(unlock), path(output),
        ),
        _ => Err("usage: canary-rpc-relay serve CONFIG | check CONFIG | provision NODE_CONFIG NEW_DIRECTORY TRANSPORT_UNLOCK OFFLINE_IDENTITY_UNLOCK | issue NODE_CONFIG ENROLLMENT ROOT_CUSTODY ROOT_UNLOCK NEW_ADMISSION".into()),
    }
}

struct Validator {
    worker: TransportWorker,
    local: String,
    upstream: SocketAddr,
    autonomous_bootstrap_sha256: Option<String>,
    genesis_autonomous: bool,
}

struct Gateway {
    worker: GatewayTransportWorker,
    local: String,
    validator: String,
    peer: SocketAddr,
    origins: Vec<String>,
    epoch_trust: Option<GatewayEpochTrust>,
}

/// One independent native verifier per relay worker. Only the small verified
/// high-water mark is shared; neither native verification nor I/O takes its lock.
struct GatewayEpochTrust {
    config: Arc<NodeConfiguration>,
    pin: Option<String>,
    current: Arc<VerifiedAuthority>,
    high_water: Arc<Mutex<VerifiedEpoch>>,
}

#[derive(Clone)]
struct VerifiedEpoch {
    epoch: u64,
    epoch_context_root: String,
}

impl VerifiedEpoch {
    fn from_authority(authority: &VerifiedAuthority) -> Result<Self, String> {
        Ok(Self {
            epoch: authority.epoch.epoch,
            epoch_context_root: authority.epoch.root().map_err(|e| e.to_string())?,
        })
    }

    fn matches(&self, epoch: u64, root: &str) -> Result<(), String> {
        if self.epoch != epoch || self.epoch_context_root != root {
            return Err(
                "gateway has not authenticated the advertised runtime epoch context".into(),
            );
        }
        Ok(())
    }

    fn publish(&self, high_water: &Mutex<Self>) -> Result<(), String> {
        let mut known = high_water
            .lock()
            .map_err(|_| "gateway epoch cache unavailable")?;
        if self.epoch < known.epoch
            || (self.epoch == known.epoch && self.epoch_context_root != known.epoch_context_root)
        {
            return Err("gateway refuses a stale or conflicting epoch context".into());
        }
        if self.epoch > known.epoch {
            *known = self.clone();
        }
        Ok(())
    }
}

enum Worker {
    Validator(Box<Validator>),
    Gateway(Box<Gateway>),
}

fn absolute(paths: &[&Path]) -> Result<(), String> {
    if paths.iter().all(|path| path.is_absolute()) {
        Ok(())
    } else {
        Err("RPC relay paths must be absolute".into())
    }
}

fn local_worker(
    config: &NodeConfiguration,
    admission: &Admission,
    local: &str,
) -> Result<TransportWorker, String> {
    let entry = admission.base.entry(local)?;
    let selected = config
        .apqe_transport
        .as_ref()
        .ok_or("missing validator APQE custody")?;
    let raw = transport::read(&selected.enrollment_path, 128 * 1024, false)?;
    if transport::sha256(&raw) != entry.enrollment_sha256 {
        return Err("validator enrollment differs from current admission".into());
    }
    let enrollment: EnrollmentRequest =
        serde_json::from_slice(&raw).map_err(|_| "invalid validator enrollment")?;
    if enrollment.payload.identity.address != local {
        return Err("validator custody is not local".into());
    }
    let envelope = encrypted(&selected.custody_path)?;
    let unlock = apqe_rpc::unlock(&selected.custody_unlock_path)?;
    let provider = config
        .aegis_provider
        .as_ref()
        .ok_or("missing pinned APQE provider")?;
    // Only independently pinned local native code may handle custody.
    unsafe {
        load_transport_worker(
            &provider.report_path,
            transport::decode_digest(&provider.authenticated_report_sha256)?,
            &enrollment,
            &admission.base.network,
            &envelope,
            apqe_rpc::passphrase(&unlock)?,
            &entry.transport_public_key,
        )
    }
}

fn encrypted(path: &Path) -> Result<EncryptedEnvelope, String> {
    serde_json::from_slice(&transport::read(path, 256 * 1024, true)?)
        .map_err(|_| "invalid encrypted RPC transport custody".into())
}

fn run(path: &Path, listen: bool) -> Result<(), String> {
    absolute(&[path])?;
    let options: Configuration = serde_json::from_slice(&transport::read(path, 64 * 1024, false)?)
        .map_err(|_| "invalid RPC relay configuration")?;
    absolute(&[&options.node_config_path, &options.admission_path])?;
    if options.schema_version != 1 || options.listen_address.port() == 0 {
        return Err("unsupported RPC relay configuration".into());
    }
    let config =
        Arc::new(synergy_config::load(&options.node_config_path).map_err(|e| e.to_string())?);
    let admission = Arc::new(Admission::load(&config, &options.admission_path)?);
    let mut workers = Vec::with_capacity(WORKERS);
    let allowed_source = match &options.role {
        Role::Validator {
            validator_address,
            gateway_vpn_ip,
        } => {
            let admitted = admission.base.entry(validator_address)?.dial_address;
            let upstream = config
                .rpc
                .listen_address
                .filter(|addr| addr.ip().is_loopback())
                .ok_or("validator local RPC must listen on loopback")?;
            if config.role != NodeRole::Validator
                || !config.rpc.enabled
                || options.listen_address.ip() != admitted.ip()
                || admitted.ip().is_unspecified()
                || admitted.ip().is_loopback()
                || admitted.ip().is_multicast()
                || options.listen_address.port() == admitted.port()
                || *gateway_vpn_ip == admitted.ip()
                || gateway_vpn_ip.is_loopback()
                || gateway_vpn_ip.is_unspecified()
                || gateway_vpn_ip.is_multicast()
                || gateway_vpn_ip.is_ipv4() != admitted.ip().is_ipv4()
            {
                return Err(
                    "validator relay must bind its distinct admitted overlay endpoint".into(),
                );
            }
            let autonomous_bootstrap_sha256 = if let Some(activation) =
                &config.consensus.autonomous_epoch_activation
            {
                // Independently verify the local pinned activation before trusting
                // any successor epoch advertised by our loopback runtime.
                let authority = super::authority::load(&config)?
                    .ok_or("autonomous relay lacks verified authority")?;
                if authority.epoch.epoch <= admission.payload.epoch {
                    return Err(
                        "autonomous relay activation did not advance the admitted origin".into(),
                    );
                }
                Some(activation.sha256.clone())
            } else {
                None
            };
            let origin = authority::load_signed(&config)?
                .ok_or("validator relay requires a verified signed authority origin")?;
            let genesis_autonomous = origin.autonomous_epochs_enabled();
            if genesis_autonomous && autonomous_bootstrap_sha256.is_some() {
                return Err("signed Genesis origin cannot also use a legacy bootstrap".into());
            }
            for _ in 0..WORKERS {
                workers.push(Worker::Validator(Box::new(Validator {
                    worker: local_worker(&config, &admission, validator_address)?,
                    local: validator_address.clone(),
                    upstream,
                    autonomous_bootstrap_sha256: autonomous_bootstrap_sha256.clone(),
                    genesis_autonomous,
                })));
            }
            Some(*gateway_vpn_ip)
        }
        Role::Gateway {
            gateway_address,
            validator_address,
            validator_relay_port,
            enrollment_path,
            custody_path,
            custody_unlock_path,
            allowed_origins,
            autonomous_bootstrap_sha256,
        } => {
            absolute(&[enrollment_path, custody_path, custody_unlock_path])?;
            if config.role != NodeRole::RpcGateway
                || !options.listen_address.ip().is_loopback()
                || *validator_relay_port == 0
                || allowed_origins.len() > 16
                || allowed_origins.iter().any(|origin| !valid_origin(origin))
            {
                return Err("gateway relay requires an explicit loopback and valid origins".into());
            }
            let admitted = admission.base.entry(validator_address)?.dial_address;
            if admitted.ip().is_loopback()
                || admitted.ip().is_unspecified()
                || admitted.ip().is_multicast()
                || *validator_relay_port == admitted.port()
            {
                return Err(
                    "gateway requires a distinct admitted validator overlay endpoint".into(),
                );
            }
            let g = admission.gateway(gateway_address)?;
            let (context, _) = admission.material_context(gateway_address, validator_address)?;
            let (enrollment, digest) = apqe_rpc::enrollment(enrollment_path)?;
            if digest != g.enrollment_sha256
                || enrollment.payload.node_address != *gateway_address
                || enrollment.payload.chain_id != admission.payload.chain_id
                || enrollment.payload.network_id != admission.payload.network_id
                || enrollment.payload.genesis_artifact_sha256
                    != admission.payload.genesis_artifact_sha256
                || enrollment.payload.transport_key_id != g.transport_key_id
                || enrollment.payload.transport_key_version != g.transport_key_version
            {
                return Err("gateway enrollment does not match signed admission".into());
            }
            let envelope = encrypted(custody_path)?;
            let unlock = apqe_rpc::unlock(custody_unlock_path)?;
            let provider = config
                .aegis_provider
                .as_ref()
                .ok_or("missing pinned APQE provider")?;
            let origin = authority::load_signed(&config)?
                .ok_or("gateway requires a verified signed authority origin")?;
            let genesis_autonomous = origin.autonomous_epochs_enabled();
            let epoch_inputs = if genesis_autonomous || autonomous_bootstrap_sha256.is_some() {
                if genesis_autonomous && autonomous_bootstrap_sha256.is_some() {
                    return Err("signed Genesis origin cannot also use a legacy bootstrap".into());
                }
                if autonomous_bootstrap_sha256
                    .as_ref()
                    .is_some_and(|pin| !canonical_digest(pin))
                {
                    return Err("gateway bootstrap pin must be a lowercase SHA-256 digest".into());
                }
                if origin.binding_bytes() != admission.authority_bytes
                    || origin.epoch.epoch != admission.payload.epoch
                    || !origin.processing_profile_enabled()
                {
                    return Err("gateway proof origin differs from its signed admission".into());
                }
                let high_water = Arc::new(Mutex::new(VerifiedEpoch::from_authority(&origin)?));
                Some((autonomous_bootstrap_sha256.clone(), origin, high_water))
            } else {
                None
            };
            for _ in 0..WORKERS {
                let epoch_trust = epoch_inputs
                    .as_ref()
                    .map(|(pin, origin, high_water)| -> Result<_, String> {
                        Ok(GatewayEpochTrust {
                            config: config.clone(),
                            pin: pin.clone(),
                            current: VerifiedAuthority::owner_context(origin)?,
                            high_water: high_water.clone(),
                        })
                    })
                    .transpose()?;
                let worker = unsafe {
                    load_gateway_transport_worker(
                        &provider.report_path,
                        transport::decode_digest(&provider.authenticated_report_sha256)?,
                        enrollment.clone(),
                        &envelope,
                        apqe_rpc::passphrase(&unlock)?,
                        &g.transport_public_key,
                        context.genesis_commitment,
                    )
                }?;
                workers.push(Worker::Gateway(Box::new(Gateway {
                    worker,
                    local: gateway_address.clone(),
                    validator: validator_address.clone(),
                    peer: SocketAddr::new(admitted.ip(), *validator_relay_port),
                    origins: allowed_origins.clone(),
                    epoch_trust,
                })));
            }
            None
        }
    };
    admission.check_current()?;
    if !listen {
        return Ok(());
    }
    let listener = TcpListener::bind(options.listen_address).map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::sync_channel::<(TcpStream, Instant)>(WORKERS);
    let rx = Arc::new(Mutex::new(rx));
    for mut worker in workers {
        let (admission, rx) = (admission.clone(), rx.clone());
        std::thread::Builder::new()
            .name("canary-apqe-rpc".into())
            .spawn(move || loop {
                let Ok((mut stream, accepted_at)) = rx.lock().expect("RPC receive lock").recv()
                else {
                    break;
                };
                match &mut worker {
                    Worker::Validator(validator) => {
                        let _ = validator.run(&admission, &mut stream, accepted_at);
                    }
                    Worker::Gateway(gateway) => {
                        let _ = gateway.run(&admission, &mut stream, accepted_at);
                    }
                }
            })
            .map_err(|e| e.to_string())?;
    }
    for stream in listener.incoming() {
        let stream = stream.map_err(|e| e.to_string())?;
        if allowed_source.is_some_and(|ip| stream.peer_addr().map_or(true, |peer| peer.ip() != ip))
        {
            continue;
        }
        // Saturation drops the connection; it never replays or reroutes a call.
        match tx.try_send((stream, Instant::now())) {
            Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err("RPC relay workers stopped".into())
            }
        }
    }
    Err("RPC relay listener stopped".into())
}

fn peer(bytes: &[u8]) -> Result<PublicKey<Mldsa65>, String> {
    PublicKey::from_bytes(bytes).map_err(|_| "malformed admitted transport key".into())
}

impl Validator {
    fn run(
        &self,
        admission: &Admission,
        stream: &mut TcpStream,
        accepted_at: Instant,
    ) -> Result<(), String> {
        admission.check_current()?;
        let initial = read_m1_tcp(stream, accepted_at).map_err(|e| e.to_string())?;
        let remote = admission.gateway(&initial.context().initiator_node)?;
        let (context, trust) = admission.material_context(&remote.node_address, &self.local)?;
        if initial.context() != &context {
            return Err("RPC session differs from signed admission".into());
        }
        let peer = peer(&remote.transport_public_key)?;
        let mut session = self
            .worker
            .responder_from_initial(trust.as_ref(), &peer, initial)
            .map_err(|e| e.to_string())?;
        session
            .handshake_responder_tcp(stream)
            .map_err(|e| e.to_string())?;
        let record = session
            .receive_application_tcp(stream)
            .map_err(|e| e.to_string())?
            .ok_or("RPC gateway closed before dispatch")?;
        let (id, request) = apqe_rpc::decode(record.as_bytes(), 1)?;
        validate_request(request)?;
        admission.check_current()?;
        // Confirm the local process is observing the admitted chain/epoch. Never
        // stamp the pinned Canary context onto a different process's responses.
        let identity = call_loopback(self.upstream, TELEMETRY)?;
        verify_runtime_identity(
            &identity,
            admission,
            self.autonomous_bootstrap_sha256.as_deref(),
            self.genesis_autonomous,
        )?;
        let response = if request == TELEMETRY {
            identity
        } else {
            call_loopback(self.upstream, request)?
        };
        let response = apqe_rpc::encode(2, &id, &response)?;
        session
            .send_application_tcp(stream, &response)
            .map_err(|e| e.to_string())?;
        session.retire();
        Ok(())
    }
}

impl Gateway {
    fn call_raw(
        worker: &GatewayTransportWorker,
        local: &str,
        validator: &str,
        endpoint: SocketAddr,
        admission: &Admission,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        validate_request(body)?;
        admission.check_current()?;
        let (context, trust) = admission.material_context(local, validator)?;
        let peer = peer(&admission.base.entry(validator)?.transport_public_key)?;
        let mut stream =
            TcpStream::connect_timeout(&endpoint, TIMEOUT).map_err(|e| e.to_string())?;
        let mut session = worker
            .initiator(trust.as_ref(), &peer, context, Instant::now())
            .map_err(|e| e.to_string())?;
        session
            .handshake_initiator_tcp(&mut stream)
            .map_err(|e| e.to_string())?;
        let mut id = [0; 16];
        Primitives
            .random_bytes(&mut id)
            .map_err(|e| e.to_string())?;
        let request = apqe_rpc::encode(1, &id, body)?;
        session
            .send_application_tcp(&mut stream, &request)
            .map_err(|e| e.to_string())?;
        let reply = session
            .receive_application_tcp(&mut stream)
            .map_err(|e| e.to_string())?
            .ok_or("validator closed without an RPC result")?;
        let (returned_id, body) = apqe_rpc::decode(reply.as_bytes(), 2)?;
        session.retire();
        if returned_id != id {
            return Err("incorrect authenticated RPC correlation".into());
        }
        admission.check_current()?;
        Ok(body.to_vec())
    }

    fn call(&mut self, admission: &Admission, body: &[u8]) -> Result<Vec<u8>, String> {
        let reply = Self::call_raw(
            &self.worker,
            &self.local,
            &self.validator,
            self.peer,
            admission,
            body,
        )?;
        let request = validate_request(body)?;
        if request.method == CHAIN_TELEMETRY && self.epoch_trust.is_some() {
            self.verify_telemetry(admission, &reply, request.id.get())?;
        }
        bind_response(
            &reply,
            admission.payload.chain_id,
            &admission.payload.network_id,
            &admission.base.payload.genesis_hash,
        )
    }

    fn observe_context(&mut self, admission: &Admission) -> Result<Option<VerifiedEpoch>, String> {
        let reply = Self::call_raw(
            &self.worker,
            &self.local,
            &self.validator,
            self.peer,
            admission,
            TELEMETRY,
        )?;
        self.verify_telemetry(admission, &reply, "1")
    }

    fn verify_telemetry(
        &mut self,
        admission: &Admission,
        bytes: &[u8],
        id: &str,
    ) -> Result<Option<VerifiedEpoch>, String> {
        let runtime: RuntimeIdentity<'_> = serde_json::from_str(rpc_result(bytes, id)?.get())
            .map_err(|_| "validator did not report a runtime identity")?;
        validate_runtime_incarnation(
            &runtime,
            admission.payload.chain_id,
            &admission.payload.network_id,
            admission.payload.epoch,
            &admission.base.payload.genesis_hash,
            self.epoch_trust
                .as_ref()
                .and_then(|trust| trust.pin.as_deref()),
            self.epoch_trust
                .as_ref()
                .is_some_and(|trust| trust.pin.is_none()),
        )?;
        let Some(trust) = self.epoch_trust.as_mut() else {
            return Ok(None);
        };
        let observed = trust.verify_runtime(admission.payload.epoch, &runtime, |epoch| {
            let request = serde_json::to_vec(&json!({
                "jsonrpc": "2.0", "method": EPOCH_TRANSITION_PROOF_V1, "params": {"epoch": epoch}, "id": 1,
            })).map_err(|_| "cannot serialize epoch proof request")?;
            Self::call_raw(&self.worker, &self.local, &self.validator, self.peer, admission, &request)
        })?;
        admission.check_current()?;
        Ok(Some(observed))
    }

    fn run(
        &mut self,
        admission: &Admission,
        stream: &mut TcpStream,
        at: Instant,
    ) -> Result<(), String> {
        let request = match read_http(stream, at + TIMEOUT) {
            Ok(request) => request,
            Err(_) => return send_http(stream, 400, b"{\"error\":\"invalid HTTP request\"}", None),
        };
        let origin = request
            .origin
            .as_deref()
            .filter(|origin| self.origins.iter().any(|s| s == origin));
        if request.origin.is_some() && origin.is_none() {
            return send_http(stream, 403, b"{\"error\":\"origin not admitted\"}", None);
        }
        let reply = match request.line.as_str() {
            "OPTIONS / HTTP/1.1"
            | "OPTIONS /rpc HTTP/1.1"
            | "OPTIONS /network-profile HTTP/1.1"
                if origin.is_some() && request.body.is_empty() =>
            {
                return send_http(stream, 204, b"", origin)
            }
            "GET /network-profile HTTP/1.1" if request.body.is_empty() => {
                if let Some(pin) = self.epoch_trust.as_ref().map(|trust| trust.pin.clone()) {
                    self.observe_context(admission).and_then(|observed| {
                        network_profile(
                            admission,
                            observed.as_ref().map(|context| (context, pin.as_deref())),
                        )
                    })
                } else {
                    network_profile(admission, None)
                }
            }
            "GET /healthz HTTP/1.1" if request.body.is_empty() => {
                // A successful TCP accept does not imply the authenticated hop is healthy.
                self.observe_context(admission)
                    .and_then(|observed| match observed {
                        Some(context) => serde_json::to_vec(&json!({
                            "status": "ready", "epoch": context.epoch,
                            "epoch_context_root": context.epoch_context_root,
                        }))
                        .map_err(|_| "cannot serialize verified health context".into()),
                        None => Ok(br#"{"status":"ready"}"#.to_vec()),
                    })
            }
            "POST / HTTP/1.1" | "POST /rpc HTTP/1.1" => {
                if validate_request(&request.body).is_err() {
                    return send_http(
                        stream,
                        400,
                        b"{\"error\":\"invalid JSON-RPC request\"}",
                        origin,
                    );
                }
                self.call(admission, &request.body)
            }
            _ => return send_http(stream, 404, b"{\"error\":\"unknown relay route\"}", origin),
        };
        match reply {
            Ok(bytes) => send_http(stream, 200, &bytes, origin),
            Err(_) => send_http(stream, 503, b"{\"error\":\"authenticated RPC unavailable; a submitted write may have been accepted\"}", origin),
        }
    }
}

fn valid_origin(origin: &str) -> bool {
    origin.strip_prefix("https://").is_some_and(|host| {
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    })
}

fn network_profile(
    admission: &Admission,
    derived: Option<(&VerifiedEpoch, Option<&str>)>,
) -> Result<Vec<u8>, String> {
    admission.check_current()?;
    let genesis =
        std::str::from_utf8(&admission.base.genesis_bytes).map_err(|_| "non-UTF-8 genesis")?;
    let authority =
        std::str::from_utf8(&admission.authority_bytes).map_err(|_| "non-UTF-8 authority")?;
    let mut profile = json!({ "genesis_raw": genesis, "authority_raw": authority });
    if let Some((context, pin)) = derived {
        profile["derived_context"] = json!({
            "epoch": context.epoch, "epoch_context_root": context.epoch_context_root,
            "origin_epoch": admission.payload.epoch,
            "autonomous_bootstrap_sha256": pin, "proof_method": EPOCH_TRANSITION_PROOF_V1,
        });
        if pin.is_none() {
            profile["derived_context"]["origin_kind"] = json!("signed-genesis-v1");
            profile["derived_context"]["autonomous_epoch_protocol"] =
                json!(synergy_genesis::network::AUTONOMOUS_EPOCH_PROTOCOL_V1);
        }
    }
    serde_json::to_vec(&profile)
        .map_err(|_| "cannot serialize pinned public network profile".into())
}

#[derive(Deserialize)]
struct Request<'a> {
    #[serde(borrow)]
    jsonrpc: &'a str,
    #[serde(borrow)]
    method: &'a str,
    #[serde(borrow)]
    id: &'a RawValue,
}

fn validate_request(bytes: &[u8]) -> Result<Request<'_>, String> {
    let v: Request<'_> =
        serde_json::from_slice(bytes).map_err(|_| "invalid JSON-RPC request envelope")?;
    if v.jsonrpc != "2.0" || v.method.is_empty() || v.method.len() > 128 || v.id.get() == "null" {
        return Err("RPC notifications or invalid methods are not supported".into());
    }
    Ok(v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<'a> {
    jsonrpc: &'a str,
    #[serde(borrow)]
    id: &'a RawValue,
    #[serde(default, deserialize_with = "present", borrow)]
    result: Option<&'a RawValue>,
    #[serde(default, deserialize_with = "present", borrow)]
    error: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct RuntimeIdentity<'a> {
    chain_id: u64,
    #[serde(borrow)]
    network_identity: &'a str,
    epoch: u64,
    #[serde(borrow)]
    genesis_hash: &'a str,
    #[serde(rename = "finalized_height")]
    _finalized_height: u64,
    #[serde(default, borrow)]
    epoch_context_root: Option<&'a str>,
    #[serde(default, borrow)]
    autonomous_bootstrap_sha256: Option<&'a str>,
}

fn verify_runtime_identity(
    bytes: &[u8],
    admission: &Admission,
    autonomous_bootstrap_sha256: Option<&str>,
    genesis_autonomous: bool,
) -> Result<(), String> {
    verify_runtime_incarnation(
        bytes,
        admission.payload.chain_id,
        &admission.payload.network_id,
        admission.payload.epoch,
        &admission.base.payload.genesis_hash,
        autonomous_bootstrap_sha256,
        genesis_autonomous,
    )
}

fn verify_runtime_incarnation(
    bytes: &[u8],
    chain_id: u64,
    network_id: &str,
    epoch: u64,
    genesis_hash: &str,
    autonomous_bootstrap_sha256: Option<&str>,
    genesis_autonomous: bool,
) -> Result<(), String> {
    #[derive(Deserialize)]
    struct RuntimeReply<'a> {
        #[serde(borrow)]
        result: RuntimeIdentity<'a>,
    }
    let identity = serde_json::from_slice::<RuntimeReply<'_>>(bytes)
        .map_err(|_| "local canonical RPC did not report authenticated chain identity")?
        .result;
    validate_runtime_incarnation(
        &identity,
        chain_id,
        network_id,
        epoch,
        genesis_hash,
        autonomous_bootstrap_sha256,
        genesis_autonomous,
    )
}

fn validate_runtime_incarnation(
    identity: &RuntimeIdentity<'_>,
    chain_id: u64,
    network_id: &str,
    epoch: u64,
    genesis_hash: &str,
    autonomous_bootstrap_sha256: Option<&str>,
    genesis_autonomous: bool,
) -> Result<(), String> {
    if identity.chain_id != chain_id
        || identity.network_identity != network_id
        || match (genesis_autonomous, autonomous_bootstrap_sha256) {
            (true, None) => {
                identity.epoch < epoch
                    || identity.autonomous_bootstrap_sha256.is_some()
                    || !identity.epoch_context_root.is_some_and(canonical_digest)
            }
            (true, Some(_)) => true,
            (false, Some(pin)) => {
                identity.epoch <= epoch || identity.autonomous_bootstrap_sha256 != Some(pin)
            }
            (false, None) => identity.epoch != epoch,
        }
        || identity.genesis_hash != genesis_hash
    {
        return Err(
            "local canonical RPC differs from the admitted Canary incarnation or epoch".into(),
        );
    }
    Ok(())
}

fn canonical_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

fn rpc_result<'a>(bytes: &'a [u8], id: &str) -> Result<&'a RawValue, String> {
    if bytes.len() > MAX_BODY {
        return Err("authenticated RPC result exceeds its byte bound".into());
    }
    let reply: Reply<'_> =
        serde_json::from_slice(bytes).map_err(|_| "invalid authenticated JSON-RPC reply")?;
    if reply.jsonrpc != "2.0" || reply.id.get() != id || reply.error.is_some() {
        return Err("incorrect correlated authenticated JSON-RPC result".into());
    }
    reply
        .result
        .ok_or_else(|| "missing authenticated JSON-RPC result".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochProof<'a> {
    chain_id: u64,
    network_id: &'a str,
    epoch: u64,
    epoch_context_root: &'a str,
    kind: &'a str,
    sha256: &'a str,
    #[serde(borrow)]
    artifact_json: Cow<'a, str>,
}

impl<'a> EpochProof<'a> {
    fn parse(
        bytes: &'a [u8],
        chain_id: u64,
        network_id: &str,
        epoch: u64,
        bootstrap_pin: Option<&str>,
    ) -> Result<Self, String> {
        let proof: Self = serde_json::from_str(rpc_result(bytes, "1")?.get())
            .map_err(|_| "missing or invalid epoch transition proof")?;
        if proof.chain_id != chain_id
            || proof.network_id != network_id
            || proof.epoch != epoch
            || proof.kind
                != if bootstrap_pin.is_some() {
                    "bootstrap-v1"
                } else {
                    "derived-v1"
                }
            || !canonical_digest(proof.epoch_context_root)
            || proof.artifact_json.is_empty()
            || proof.sha256 != transport::sha256(proof.artifact_json.as_bytes())
            || bootstrap_pin.is_some_and(|pin| pin != proof.sha256)
        {
            return Err(
                "epoch proof differs from its expected scope, kind, or artifact digest".into(),
            );
        }
        Ok(proof)
    }
}

impl GatewayEpochTrust {
    fn verify_runtime(
        &mut self,
        origin_epoch: u64,
        runtime: &RuntimeIdentity<'_>,
        mut fetch: impl FnMut(u64) -> Result<Vec<u8>, String>,
    ) -> Result<VerifiedEpoch, String> {
        let advertised_root = runtime
            .epoch_context_root
            .filter(|root| canonical_digest(root))
            .ok_or("gateway runtime did not report a canonical epoch context root")?;
        if runtime.epoch < self.current.epoch.epoch
            || runtime.epoch
                < self
                    .high_water
                    .lock()
                    .map_err(|_| "gateway epoch cache unavailable")?
                    .epoch
        {
            return Err("gateway refuses a stale autonomous runtime".into());
        }

        for _ in 0..MAX_EPOCH_PROOFS_PER_REQUEST {
            if self.current.epoch.epoch == runtime.epoch {
                break;
            }
            let epoch = self
                .current
                .epoch
                .epoch
                .checked_add(1)
                .ok_or("gateway epoch overflow")?;
            let pin = (self.current.epoch.epoch == origin_epoch)
                .then_some(self.pin.as_deref())
                .flatten();
            let bytes = fetch(epoch)?;
            let proof = EpochProof::parse(
                &bytes,
                runtime.chain_id,
                runtime.network_identity,
                epoch,
                pin,
            )?;
            let next = match pin {
                Some(pin) => successor::verify_pinned_bootstrap_bytes(
                    &self.config,
                    self.current.clone(),
                    pin,
                    proof.artifact_json.as_bytes(),
                )?,
                None => successor::verify_next_derived_bytes(
                    self.current.clone(),
                    proof.artifact_json.as_bytes(),
                )?,
            };
            if next.epoch.epoch != epoch
                || next.epoch.chain_id != runtime.chain_id
                || next.epoch.network_id != runtime.network_identity
                || next.epoch.root().map_err(|e| e.to_string())? != proof.epoch_context_root
            {
                return Err(
                    "advertised transition scope does not match its verified native proof".into(),
                );
            }
            self.current = next;
        }
        let verified = VerifiedEpoch::from_authority(&self.current)?;
        verified.matches(runtime.epoch, advertised_root)?;
        verified.publish(&self.high_water)?;
        Ok(verified)
    }
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(d).map(Some)
}

/// Reuse the native consensus fixture's real signed proof, rather than creating
/// another validator cohort merely to exercise the independent gateway owner.
#[cfg(test)]
pub(super) fn qualify_fresh_gateway_successor(
    config: &NodeConfiguration,
    origin: Arc<VerifiedAuthority>,
    next: Arc<VerifiedAuthority>,
    artifact: &[u8],
) {
    assert!(origin.autonomous_epochs_enabled());
    let genesis = crate::commands::selected_network::verify(config).unwrap();
    let root = next.epoch.root().unwrap();
    let mut runtime = RuntimeIdentity {
        chain_id: config.chain_id,
        network_identity: &config.network_id,
        epoch: next.epoch.epoch,
        genesis_hash: &genesis,
        _finalized_height: 0,
        epoch_context_root: Some(&root),
        autonomous_bootstrap_sha256: None,
    };
    validate_runtime_incarnation(
        &runtime,
        config.chain_id,
        &config.network_id,
        origin.epoch.epoch,
        &genesis,
        None,
        true,
    )
    .unwrap();
    let reply = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":{
        "chain_id":config.chain_id,"network_id":config.network_id,"epoch":next.epoch.epoch,
        "epoch_context_root":root,"kind":"derived-v1",
        "sha256":transport::sha256(artifact),"artifact_json":std::str::from_utf8(artifact).unwrap(),
    }}))
    .unwrap();
    let high_water = Arc::new(Mutex::new(VerifiedEpoch::from_authority(&origin).unwrap()));
    let mut trust = GatewayEpochTrust {
        config: Arc::new(config.clone()),
        pin: None,
        current: VerifiedAuthority::owner_context(&origin).unwrap(),
        high_water: high_water.clone(),
    };
    let mut bad: serde_json::Value = serde_json::from_slice(artifact).unwrap();
    bad["authorization"]["next_epoch"] = json!(next.epoch.epoch + 1);
    let bad_artifact = serde_json::to_string(&bad).unwrap();
    let mut bad_reply: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    bad_reply["result"]["artifact_json"] = json!(bad_artifact);
    bad_reply["result"]["sha256"] = json!(transport::sha256(bad_artifact.as_bytes()));
    assert!(trust
        .verify_runtime(origin.epoch.epoch, &runtime, |_| Ok(serde_json::to_vec(
            &bad_reply
        )
        .unwrap()))
        .is_err());
    assert_eq!(trust.current.epoch.epoch, origin.epoch.epoch);
    let forged = "f".repeat(64);
    runtime.epoch_context_root = Some(&forged);
    assert!(trust
        .verify_runtime(origin.epoch.epoch, &runtime, |_| Ok(reply.clone()))
        .is_err());
    assert_eq!(high_water.lock().unwrap().epoch, origin.epoch.epoch);
    runtime.epoch_context_root = Some(&root);
    let verified = trust
        .verify_runtime(origin.epoch.epoch, &runtime, |_| {
            panic!("verified proof must not be refetched")
        })
        .unwrap();
    assert_eq!(verified.epoch, next.epoch.epoch);
    runtime.epoch = origin.epoch.epoch;
    assert!(trust
        .verify_runtime(origin.epoch.epoch, &runtime, |_| panic!(
            "stale context must not fetch"
        ))
        .is_err());
}

fn bind_response(
    bytes: &[u8],
    chain_id: u64,
    network_id: &str,
    genesis_hash: &str,
) -> Result<Vec<u8>, String> {
    let envelope: Reply<'_> =
        serde_json::from_slice(bytes).map_err(|_| "invalid JSON-RPC reply envelope")?;
    if envelope.jsonrpc != "2.0"
        || envelope.result.is_some() == envelope.error.is_some()
        || envelope
            .error
            .is_some_and(|error| !error.get().starts_with('{'))
    {
        return Err("invalid canonical JSON-RPC reply".into());
    }
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .ok_or("missing reply object")?;
    let context = serde_json::to_vec(&json!({ "chain_id": chain_id, "network_id": network_id,
        "genesis_hash": genesis_hash }))
    .map_err(|_| "cannot serialize chain context")?;
    let mut response = bytes[..end].to_vec();
    response.extend_from_slice(b",\"chain_context\":");
    response.extend_from_slice(&context);
    response.extend_from_slice(&bytes[end..]);
    Ok(response)
}

struct Http {
    line: String,
    origin: Option<String>,
    body: Vec<u8>,
}

fn read_http(stream: &mut TcpStream, deadline: Instant) -> Result<Http, String> {
    let mut bytes = Vec::with_capacity(4096);
    let mut scratch = [0; 2048];
    let end = loop {
        if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            if i >= HEADER_MAX {
                return Err("RPC HTTP header exceeds limit".into());
            }
            break i;
        }
        if bytes.len() >= HEADER_MAX {
            return Err("RPC HTTP header exceeds limit".into());
        }
        let n = read_until(stream, deadline, &mut scratch)?;
        bytes.extend_from_slice(&scratch[..n]);
    };
    let (line, origin, length) = parse_headers(&bytes[..end])?;
    let body_start = end + 4;
    if bytes.len() - body_start > length {
        return Err("unexpected trailing HTTP request bytes".into());
    }
    let mut body = bytes.split_off(body_start);
    while body.len() < length {
        let room = (length - body.len()).min(scratch.len());
        let n = read_until(stream, deadline, &mut scratch[..room])?;
        body.extend_from_slice(&scratch[..n]);
    }
    Ok(Http { line, origin, body })
}

fn parse_headers(bytes: &[u8]) -> Result<(String, Option<String>, usize), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "HTTP headers are not UTF-8")?;
    let mut lines = text.split("\r\n");
    let line = lines.next().ok_or("missing HTTP start line")?;
    if !line.is_ascii() || line.bytes().any(|b| b.is_ascii_control()) {
        return Err("invalid HTTP start line".into());
    }
    let mut length = None;
    let mut origin = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || value.bytes().any(|b| b.is_ascii_control() && b != b'\t')
        {
            return Err("malformed HTTP header".into());
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("expect") {
            return Err("streamed HTTP bodies and Expect are unsupported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("ambiguous HTTP content length".into());
            }
            let n = value
                .parse::<usize>()
                .map_err(|_| "invalid HTTP body length")?;
            if n > MAX_BODY {
                return Err("RPC HTTP body exceeds limit".into());
            }
            length = Some(n);
        }
        if name.eq_ignore_ascii_case("origin") && origin.replace(value.to_owned()).is_some() {
            return Err("ambiguous origin".into());
        }
    }
    if (line.starts_with("POST ") || line.starts_with("HTTP/")) && length.is_none() {
        return Err("missing HTTP content length".into());
    }
    Ok((line.into(), origin, length.unwrap_or(0)))
}

fn read_until(
    stream: &mut TcpStream,
    deadline: Instant,
    buffer: &mut [u8],
) -> Result<usize, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or("RPC HTTP read deadline")?;
    stream
        .set_read_timeout(Some(remaining.max(Duration::from_millis(1))))
        .map_err(|e| e.to_string())?;
    let n = stream.read(buffer).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("truncated HTTP message".into());
    }
    Ok(n)
}

fn call_loopback(address: SocketAddr, body: &[u8]) -> Result<Vec<u8>, String> {
    if !address.ip().is_loopback() {
        return Err("RPC upstream is not loopback".into());
    }
    let deadline = Instant::now() + TIMEOUT;
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT).map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    write!(stream, "POST / HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len())
        .and_then(|()| stream.write_all(body)).map_err(|e| e.to_string())?;
    let response = read_http(&mut stream, deadline)?;
    if !response.line.starts_with("HTTP/1.1 200 ") || response.body.is_empty() {
        return Err("canonical loopback RPC refused the request".into());
    }
    Ok(response.body)
}

fn send_http(
    stream: &mut TcpStream,
    status: u16,
    bytes: &[u8],
    origin: Option<&str>,
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(CLIENT_WRITE_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Service Unavailable",
    };
    write!(stream, "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\n", bytes.len())
        .map_err(|e| e.to_string())?;
    if let Some(origin) = origin {
        write!(stream, "Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n")
            .map_err(|e| e.to_string())?;
    }
    stream
        .write_all(b"\r\n")
        .and_then(|()| stream.write_all(bytes))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_runtime_with_matching_chain_and_epoch_but_wrong_genesis() {
        let expected = "a".repeat(64);
        let mut reply = json!({"result": {
            "chain_id": 99999, "network_identity": "fresh-canary", "epoch": 1,
            "finalized_height": 0, "genesis_hash": expected,
        }});
        let verify = |value: &serde_json::Value| {
            verify_runtime_incarnation(
                &serde_json::to_vec(value).unwrap(),
                99999,
                "fresh-canary",
                1,
                &expected,
                None,
                false,
            )
        };
        assert!(verify(&reply).is_ok());
        reply["result"]["genesis_hash"] = json!("b".repeat(64));
        assert!(verify(&reply).is_err());
        reply["result"]
            .as_object_mut()
            .unwrap()
            .remove("genesis_hash");
        assert!(verify(&reply).is_err());
    }

    #[test]
    fn autonomous_runtime_requires_matching_pin_and_never_accepts_origin_or_rollback() {
        let pin = "a".repeat(64);
        let genesis = "b".repeat(64);
        let test = |reported_epoch, reported_pin, expected_pin| {
            let value = json!({"result": {
                "chain_id": 99999, "network_identity": "canary", "epoch": reported_epoch,
                "finalized_height": 22998, "genesis_hash": genesis, "autonomous_bootstrap_sha256": reported_pin,
            }});
            verify_runtime_incarnation(
                &serde_json::to_vec(&value).unwrap(),
                99999,
                "canary",
                5,
                &genesis,
                expected_pin,
                false,
            )
        };
        assert!(test(6, Some(pin.as_str()), Some(pin.as_str())).is_ok());
        assert!(test(8, Some(pin.as_str()), Some(pin.as_str())).is_ok());
        assert!(test(5, Some(pin.as_str()), Some(pin.as_str())).is_err());
        assert!(test(4, Some(pin.as_str()), Some(pin.as_str())).is_err());
        assert!(test(6, None, Some(pin.as_str())).is_err());
        assert!(test(6, Some(genesis.as_str()), Some(pin.as_str())).is_err());
        assert!(test(6, Some(pin.as_str()), None).is_err());
    }

    #[test]
    fn gateway_epoch_cache_rejects_rollback_conflict_and_unverified_telemetry() {
        let context = |epoch, byte: &str| VerifiedEpoch {
            epoch,
            epoch_context_root: byte.repeat(64),
        };
        let cache = Mutex::new(context(5, "e"));
        let first = context(6, "a");
        assert!(first.matches(6, &"a".repeat(64)).is_ok());
        assert!(first.matches(6, &"b".repeat(64)).is_err());
        assert!(first.matches(7, &"a".repeat(64)).is_err());
        assert!(first.publish(&cache).is_ok());
        assert!(context(5, "e").publish(&cache).is_err());
        assert!(context(6, "b").publish(&cache).is_err());
        assert!(first.publish(&cache).is_ok());
        assert!(context(7, "b").publish(&cache).is_ok());
        assert!(first.publish(&cache).is_err());
    }

    #[test]
    fn fresh_genesis_runtime_requires_verified_origin_and_has_no_bootstrap() {
        let genesis = "b".repeat(64);
        let root = "c".repeat(64);
        let mut runtime = RuntimeIdentity {
            chain_id: 77777,
            network_identity: "fresh-canary",
            epoch: 1,
            genesis_hash: &genesis,
            _finalized_height: 0,
            epoch_context_root: Some(&root),
            autonomous_bootstrap_sha256: None,
        };
        let check = |r: &RuntimeIdentity<'_>, fresh| {
            validate_runtime_incarnation(r, 77777, "fresh-canary", 1, &genesis, None, fresh)
        };
        assert!(check(&runtime, true).is_ok());
        runtime.epoch = 3;
        assert!(check(&runtime, true).is_ok());
        assert!(check(&runtime, false).is_err());
        runtime.epoch = 0;
        assert!(check(&runtime, true).is_err());
        runtime.epoch = 2;
        runtime.autonomous_bootstrap_sha256 = Some(&root);
        assert!(check(&runtime, true).is_err());
        runtime.autonomous_bootstrap_sha256 = None;
        runtime.epoch_context_root = None;
        assert!(check(&runtime, true).is_err());
        runtime.epoch_context_root = Some(&root);
        runtime.genesis_hash = &root;
        assert!(check(&runtime, true).is_err());
    }

    #[test]
    fn proof_envelope_requires_exact_bytes_pin_scope_and_correlated_request() {
        let artifact = "{\"native\":[1,2]}\n";
        let pin = transport::sha256(artifact.as_bytes());
        let reply = json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "chain_id": 99999, "network_id": "canary", "epoch": 6,
                "epoch_context_root": "a".repeat(64), "kind": "bootstrap-v1",
                "sha256": pin, "artifact_json": artifact,
            },
        });
        let bytes = serde_json::to_vec(&reply).unwrap();
        let proof = EpochProof::parse(&bytes, 99999, "canary", 6, Some(&pin)).unwrap();
        assert_eq!(proof.artifact_json, artifact);
        assert!(EpochProof::parse(&bytes, 1266, "canary", 6, Some(&pin)).is_err());
        assert!(EpochProof::parse(&bytes, 99999, "other", 6, Some(&pin)).is_err());
        assert!(EpochProof::parse(&bytes, 99999, "canary", 7, Some(&pin)).is_err());
        assert!(EpochProof::parse(&bytes, 99999, "canary", 6, Some(&"c".repeat(64))).is_err());
        assert!(EpochProof::parse(&bytes, 99999, "canary", 6, None).is_err());

        for (field, replacement) in [
            ("artifact_json", json!("changed")),
            ("epoch_context_root", json!("A".repeat(64))),
            ("kind", json!("derived-v1")),
            ("sha256", json!("a".repeat(64))),
        ] {
            let mut tampered = reply.clone();
            tampered["result"][field] = replacement;
            let bytes = serde_json::to_vec(&tampered).unwrap();
            assert!(
                EpochProof::parse(&bytes, 99999, "canary", 6, Some(&pin)).is_err(),
                "{field}"
            );
        }
        let mut wrong_id = reply.clone();
        wrong_id["id"] = json!(2);
        let bytes = serde_json::to_vec(&wrong_id).unwrap();
        assert!(EpochProof::parse(&bytes, 99999, "canary", 6, Some(&pin)).is_err());
        assert!(EpochProof::parse(&vec![0; MAX_BODY + 1], 99999, "canary", 6, Some(&pin)).is_err());
        assert!(EpochProof::parse(
            br#"{"jsonrpc":"2.0","id":1,"result":null}"#,
            99999,
            "canary",
            6,
            Some(&pin),
        )
        .is_err());
    }

    #[test]
    #[ignore = "requires retained public signed origin, approved bootstrap, and native APQE"]
    fn native_gateway_accepts_pinned_bootstrap_and_rejects_forged_runtime_root() {
        let config_path = std::env::var("SYNERGY_GATEWAY_TEST_ORIGIN_CONFIG").unwrap();
        let bootstrap_path = std::env::var("SYNERGY_GATEWAY_TEST_BOOTSTRAP").unwrap();
        let pin = std::env::var("SYNERGY_GATEWAY_TEST_BOOTSTRAP_SHA256").unwrap();
        let mut config = synergy_config::load(Path::new(&config_path)).unwrap();
        config.role = NodeRole::RpcGateway;
        assert!(config.consensus.autonomous_epoch_activation.is_none());
        let config = Arc::new(config);
        let origin = authority::load_signed(&config).unwrap().unwrap();
        let bytes = transport::read(Path::new(&bootstrap_path), MAX_BODY as u64, false).unwrap();
        let native =
            successor::verify_pinned_bootstrap_bytes(&config, origin.clone(), &pin, &bytes)
                .unwrap();
        let expected = VerifiedEpoch::from_authority(&native).unwrap();
        let root = expected.epoch_context_root.as_str();
        let genesis = crate::commands::selected_network::verify(&config).unwrap();
        let artifact = std::str::from_utf8(&bytes).unwrap();
        let reply = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 1, "result": {
                "chain_id": config.chain_id, "network_id": config.network_id, "epoch": expected.epoch,
                "epoch_context_root": root, "kind": "bootstrap-v1", "sha256": pin,
                "artifact_json": artifact,
            },
        })).unwrap();
        let origin_epoch = origin.epoch.epoch;
        let high_water = Arc::new(Mutex::new(VerifiedEpoch::from_authority(&origin).unwrap()));
        let mut trust = GatewayEpochTrust {
            config: config.clone(),
            pin: Some(pin.clone()),
            current: origin,
            high_water: high_water.clone(),
        };
        let forged = "f".repeat(64);
        let mut runtime = RuntimeIdentity {
            chain_id: config.chain_id,
            network_identity: &config.network_id,
            epoch: expected.epoch,
            genesis_hash: &genesis,
            _finalized_height: 0,
            epoch_context_root: Some(&forged),
            autonomous_bootstrap_sha256: Some(&pin),
        };
        let mut tampered = serde_json::from_slice::<serde_json::Value>(&reply).unwrap();
        tampered["result"]["epoch_context_root"] = json!(forged);
        assert!(trust
            .verify_runtime(origin_epoch, &runtime, |_| {
                Ok(serde_json::to_vec(&tampered).unwrap())
            })
            .is_err());
        assert_eq!(trust.current.epoch.epoch, origin_epoch);
        assert!(trust
            .verify_runtime(origin_epoch, &runtime, |_| Ok(reply.clone()))
            .is_err());
        assert_eq!(high_water.lock().unwrap().epoch, origin_epoch);
        runtime.epoch_context_root = Some(root);
        let verified = trust
            .verify_runtime(origin_epoch, &runtime, |_| {
                panic!("already authenticated proof should not be fetched again")
            })
            .unwrap();
        assert_eq!(verified.epoch, expected.epoch);
        assert_eq!(verified.epoch_context_root, root);
        assert_eq!(high_water.lock().unwrap().epoch, expected.epoch);
    }

    #[test]
    fn proof_page_method_and_max_page_survive_native_relay_without_reencoding() {
        let request = br#"{"jsonrpc":"2.0","method":"synergy_getFinalizedProofPageV1","params":{"height":1,"kind":"world_state"},"id":1}"#;
        assert_eq!(
            validate_request(request).unwrap().method,
            synergy_rpc::methods::FINALIZED_PROOF_PAGE_V1
        );
        let page = json!({"version":1,"bytes_base64":"A".repeat(65536usize.div_ceil(3)*4),
            "total_bytes":1048576,"offset":0,"next_offset":65536});
        let response = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"result":page})).unwrap();
        let forwarded =
            bind_response(&response, 99999, "selected-network", "pinned-genesis").unwrap();
        assert!(forwarded.len() < MAX_BODY);
        assert!(std::str::from_utf8(&forwarded)
            .unwrap()
            .contains(std::str::from_utf8(&response[1..response.len() - 1]).unwrap()));
    }
    #[test]
    fn binds_null_large_numbers_and_errors_without_reencoding() {
        for raw in [
            br#"{"jsonrpc":"2.0","id":1,"result":null}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"balance":340282366920938463463374607431768211455}}"#,
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad params"}}"#,
        ] {
            let output = bind_response(raw, 99999, "canary-test", "genesis").unwrap();
            assert!(output.starts_with(&raw[..raw.len() - 1]));
            assert!(output.ends_with(br#","chain_context":{"chain_id":99999,"genesis_hash":"genesis","network_id":"canary-test"}}"#));
        }
        assert!(bind_response(
            br#"{"jsonrpc":"2.0","id":1,"result":null,"chain_context":{}}"#,
            99999,
            "canary",
            "genesis"
        )
        .is_err());
        assert!(bind_response(
            br#"{"jsonrpc":"2.0","id":1,"result":null,"error":null}"#,
            99999,
            "canary",
            "genesis"
        )
        .is_err());
    }

    #[test]
    fn refuses_ambiguous_http_and_rpc_batches() {
        assert!(
            parse_headers(b"POST / HTTP/1.1\r\nContent-Length: 1\r\ncontent-length: 1").is_err()
        );
        assert!(parse_headers(
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked"
        )
        .is_err());
        assert!(parse_headers(b"POST / HTTP/1.1\r\nContent-Length : 1").is_err());
        assert!(parse_headers(b"POST / HTTP/1.1").is_err());
        assert!(validate_request(br#"[{"jsonrpc":"2.0","method":"a","id":1}]"#).is_err());
        assert!(validate_request(br#"{"jsonrpc":"2.0","method":"a"}"#).is_err());
    }
}
