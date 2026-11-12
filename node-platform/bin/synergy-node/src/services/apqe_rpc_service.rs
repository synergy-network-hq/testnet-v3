//! Opt-in Canary 99999 relay. Public HTTP terminates on loopback; the native
//! gateway-to-validator hop always uses APQE. The upstream is the validator's
//! existing loopback RPC, with a single dispatch and no alternate routing.
use super::{
    apqe_rpc::{self, Admission, MAX_BODY},
    apqe_transport as transport,
};
use serde::Deserialize;
use serde_json::{json, value::RawValue};
use std::{
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

const HEADER_MAX: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const WORKERS: usize = 4;
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
}

struct Gateway {
    worker: GatewayTransportWorker,
    local: String,
    validator: String,
    peer: SocketAddr,
    origins: Vec<String>,
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
    let config = synergy_config::load(&options.node_config_path).map_err(|e| e.to_string())?;
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
            for _ in 0..WORKERS {
                workers.push(Worker::Validator(Box::new(Validator {
                    worker: local_worker(&config, &admission, validator_address)?,
                    local: validator_address.clone(),
                    upstream,
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
            for _ in 0..WORKERS {
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
    for worker in workers {
        let (admission, rx) = (admission.clone(), rx.clone());
        std::thread::Builder::new()
            .name("canary-apqe-rpc".into())
            .spawn(move || loop {
                let Ok((mut stream, accepted_at)) = rx.lock().expect("RPC receive lock").recv()
                else {
                    break;
                };
                match &worker {
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
        verify_runtime_identity(&identity, admission)?;
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
    fn call(&self, admission: &Admission, body: &[u8]) -> Result<Vec<u8>, String> {
        validate_request(body)?;
        admission.check_current()?;
        let (context, trust) = admission.material_context(&self.local, &self.validator)?;
        let peer = peer(&admission.base.entry(&self.validator)?.transport_public_key)?;
        let mut stream =
            TcpStream::connect_timeout(&self.peer, TIMEOUT).map_err(|e| e.to_string())?;
        let mut session = self
            .worker
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
        bind_response(
            body,
            admission.payload.chain_id,
            &admission.payload.network_id,
            &admission.base.payload.genesis_hash,
        )
    }

    fn run(
        &self,
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
                network_profile(admission)
            }
            "GET /healthz HTTP/1.1" if request.body.is_empty() => {
                // A successful TCP accept does not imply the authenticated hop is healthy.
                self.call(admission, TELEMETRY)
                    .and_then(|reply| verify_runtime_identity(&reply, admission))
                    .map(|()| br#"{"status":"ready"}"#.to_vec())
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

fn network_profile(admission: &Admission) -> Result<Vec<u8>, String> {
    admission.check_current()?;
    let genesis =
        std::str::from_utf8(&admission.base.genesis_bytes).map_err(|_| "non-UTF-8 genesis")?;
    let authority =
        std::str::from_utf8(&admission.authority_bytes).map_err(|_| "non-UTF-8 authority")?;
    serde_json::to_vec(&json!({ "genesis_raw": genesis, "authority_raw": authority }))
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

fn validate_request(bytes: &[u8]) -> Result<(), String> {
    let v: Request<'_> =
        serde_json::from_slice(bytes).map_err(|_| "invalid JSON-RPC request envelope")?;
    if v.jsonrpc != "2.0" || v.method.is_empty() || v.method.len() > 128 || v.id.get() == "null" {
        return Err("RPC notifications or invalid methods are not supported".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply<'a> {
    jsonrpc: &'a str,
    #[serde(rename = "id", borrow)]
    _id: &'a RawValue,
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
    finalized_height: u64,
}

fn verify_runtime_identity(bytes: &[u8], admission: &Admission) -> Result<(), String> {
    #[derive(Deserialize)]
    struct RuntimeReply<'a> {
        #[serde(borrow)]
        result: RuntimeIdentity<'a>,
    }
    let identity = serde_json::from_slice::<RuntimeReply<'_>>(bytes)
        .map_err(|_| "local canonical RPC did not report authenticated chain identity")?
        .result;
    if identity.chain_id != admission.payload.chain_id
        || identity.network_identity != admission.payload.network_id
        || identity.epoch != admission.payload.epoch
    {
        return Err("local canonical RPC differs from the admitted Canary chain/epoch".into());
    }
    let _latest_finalized_height = identity.finalized_height;
    Ok(())
}

fn present<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(d).map(Some)
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
