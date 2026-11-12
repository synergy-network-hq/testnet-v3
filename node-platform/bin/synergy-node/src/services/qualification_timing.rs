//! Explicit isolated-fixture diagnostics. Never initialized by production startup.
use serde::{Deserialize, Serialize};
#[cfg(feature = "qualification-timing")]
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "qualification-timing")]
const MAX_ONCE_OBSERVATIONS: usize = 65_536;
const QUEUE_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
// Schema variants are reserved for actual admission/runtime hooks; no synthetic events.
#[allow(dead_code)]
pub enum Phase {
    TargetOpen,
    ContextRead,
    AuthorStart,
    AuthorEnd,
    SubmitStart,
    RpcEnqueue,
    DurableAdmission,
    DurableAvailability,
    CutoffClose,
    Finalized,
    ProposalStart,
    QcVerified,
    Start,
    End,
    Rejected,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
// Schema variants are reserved for actual admission/runtime hooks; no synthetic events.
#[allow(dead_code)]
pub enum Kind {
    Admission,
    Window,
    Proposal,
    Cadence,
    Runtime,
}

impl Kind {
    fn permits(self, phase: Phase) -> bool {
        if matches!(phase, Phase::Rejected | Phase::Failed) {
            return true;
        }
        matches!(
            (self, phase),
            (
                Self::Admission,
                Phase::TargetOpen
                    | Phase::ContextRead
                    | Phase::AuthorStart
                    | Phase::AuthorEnd
                    | Phase::SubmitStart
                    | Phase::RpcEnqueue
                    | Phase::DurableAdmission
                    | Phase::DurableAvailability
                    | Phase::CutoffClose
                    | Phase::Finalized
            ) | (
                Self::Window,
                Phase::TargetOpen | Phase::CutoffClose | Phase::Finalized
            ) | (Self::Proposal, Phase::ProposalStart | Phase::QcVerified)
                | (Self::Cadence | Self::Runtime, Phase::Start | Phase::End)
        )
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
// Schema variants are reserved for actual admission/runtime hooks; no synthetic events.
#[allow(dead_code)]
pub enum Role {
    Origin,
    Participant,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
// Schema variants are reserved for actual admission/runtime hooks; no synthetic events.
#[allow(dead_code)]
pub enum Classification {
    Healthy,
    Recovered,
    Observed,
}
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
// Schema variants are reserved for actual admission/runtime hooks; no synthetic events.
#[allow(dead_code)]
pub enum Reason {
    AdmissionClosed,
    QueueFull,
    InvalidInput,
    VerificationFailed,
    StorageFailed,
    WorkerFailed,
    Cancelled,
    Timeout,
}

pub struct TraceContext<'a> {
    pub trace_id: &'a str,
    pub attempt: u64,
    pub target_height: u64,
    pub generation: u64,
    pub role: Role,
    pub classification: Classification,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub run_id: String,
    pub artifact_sha3_256: String,
    pub node_id: String,
    pub clock_id: String,
    pub output: PathBuf,
}

#[derive(Serialize)]
struct Event {
    run_id: String,
    artifact_sha3_256: String,
    platform: &'static str,
    isolated: bool,
    node_id: String,
    clock_id: String,
    trace_id: String,
    attempt: u64,
    target_height: u64,
    generation: u64,
    role: Role,
    classification: Classification,
    clock_basis: &'static str,
    collector_instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<Reason>,
    kind: Kind,
    phase: Phase,
    monotonic_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    healthy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_stage: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    processing: Option<ProcessingObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<TransportObservation>,
}

#[derive(Serialize)]
struct ProcessingObservation {
    stage: &'static str,
    block_id: String,
    peer: String,
}

struct Metadata {
    config: Config,
    started: Instant,
    clock_instance: String,
    clock_domain: String,
    clock_basis: &'static str,
    dropped: AtomicU64,
    written: AtomicU64,
    failures: AtomicU64,
    closed: AtomicBool,
    transport_lock_baseline: u64,
    transport_only: bool,
    transport_capture: TransportCapture,
    #[cfg(feature = "qualification-timing")]
    emitted_once: std::sync::Mutex<BTreeSet<(String, Kind, Phase)>>,
}

#[derive(Clone)]
pub struct Handle {
    sender: mpsc::SyncSender<Event>,
    metadata: Arc<Metadata>,
}

pub struct QualificationTiming {
    registered: bool,
    handle: Option<Handle>,
    writer: Option<JoinHandle<()>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub dropped: u64,
    pub written: u64,
    pub failures: u64,
    pub transport: Option<TransportReport>,
}
impl Report {
    pub fn complete(&self) -> bool {
        self.dropped == 0 && self.failures == 0
    }
}

fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl QualificationTiming {
    pub fn start(config: Config) -> Result<Self, String> {
        Self::start_mode(config, false)
    }
    fn start_mode(config: Config, transport_only: bool) -> Result<Self, String> {
        if !label(&config.run_id)
            || !label(&config.node_id)
            || !label(&config.clock_id)
            || !digest(&config.artifact_sha3_256)
        {
            return Err("invalid public qualification metadata".into());
        }
        if !config.output.is_absolute()
            || config.output.components().any(|part| {
                matches!(part, std::path::Component::ParentDir) || part.as_os_str() == "custody"
            })
        {
            return Err("qualification output must be absolute and outside custody".into());
        }
        for ancestor in config
            .output
            .parent()
            .into_iter()
            .flat_map(|parent| parent.ancestors())
        {
            if std::fs::symlink_metadata(ancestor)
                .map_err(|_| "qualification ancestor unavailable")?
                .file_type()
                .is_symlink()
            {
                return Err("qualification output ancestor is a symlink".into());
            }
        }
        let parent = config
            .output
            .parent()
            .ok_or("missing qualification parent")?;
        // Output is deliberately limited to an explicitly created private fixture directory.
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| "qualification parent unavailable")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("unsafe qualification parent".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("qualification parent must be private".into());
            }
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&config.output)
                .map_err(|_| "qualification output must be new")?;
            Self::with_file(config, file, transport_only)
        }
        #[cfg(not(unix))]
        {
            Err("private qualification output requires Unix".into())
        }
    }

    fn with_file(config: Config, mut file: File, transport_only: bool) -> Result<Self, String> {
        static NEXT_CLOCK: AtomicU64 = AtomicU64::new(0);
        let clock_instance = format!(
            "{}-pid{}-{}-{}",
            config.clock_id,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock origin unavailable")?
                .as_nanos(),
            NEXT_CLOCK.fetch_add(1, Ordering::Relaxed)
        );
        let (clock_domain, clock_basis) = clock_domain(&clock_instance)?;
        let metadata = Arc::new(Metadata {
            config,
            clock_instance,
            clock_domain,
            clock_basis,
            started: Instant::now(),
            dropped: AtomicU64::new(0),
            written: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            transport_lock_baseline: transport_lock_skipped(),
            transport_only,
            transport_capture: TransportCapture::default(),
            #[cfg(feature = "qualification-timing")]
            emitted_once: std::sync::Mutex::new(BTreeSet::new()),
        });
        let (sender, receiver) = mpsc::sync_channel::<Event>(QUEUE_CAPACITY);
        let worker_metadata = Arc::clone(&metadata);
        let writer = std::thread::Builder::new()
            .name("qualification-timing".into())
            .spawn(move || {
                let mut bytes = 0u64;
                loop {
                    let event = match receiver.recv_timeout(Duration::from_millis(10)) {
                        Ok(event) => event,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout)
                            if worker_metadata.closed.load(Ordering::Acquire) =>
                        {
                            break
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    };
                    let result = serde_json::to_vec(&event)
                        .ok()
                        .filter(|line| bytes.saturating_add(line.len() as u64 + 1) <= MAX_BYTES);
                    let Some(line) = result else {
                        worker_metadata.failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if file
                        .write_all(&line)
                        .and_then(|_| file.write_all(b"\n"))
                        .is_err()
                    {
                        worker_metadata.failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    bytes += line.len() as u64 + 1;
                    worker_metadata.written.fetch_add(1, Ordering::Relaxed);
                }
                if file.flush().and_then(|_| file.sync_all()).is_err() {
                    worker_metadata.failures.fetch_add(1, Ordering::Relaxed);
                }
            })
            .map_err(|_| "qualification writer unavailable")?;
        Ok(Self {
            registered: false,
            handle: Some(Handle { sender, metadata }),
            writer: Some(writer),
        })
    }

    pub fn handle(&self) -> Handle {
        self.handle.as_ref().unwrap().clone()
    }
    /// Close producers and drain queued events; retained handles are rejected.
    pub fn finish(mut self) -> Report {
        let metadata = Arc::clone(&self.handle.as_ref().unwrap().metadata);
        metadata.closed.store(true, Ordering::Release);
        self.handle.take();
        if self.writer.take().unwrap().join().is_err() {
            metadata.failures.fetch_add(1, Ordering::Relaxed);
        }
        Report {
            dropped: metadata
                .dropped
                .load(Ordering::Relaxed)
                .saturating_add(if self.registered {
                    transport_lock_skipped().saturating_sub(metadata.transport_lock_baseline)
                } else {
                    0
                }),
            written: metadata.written.load(Ordering::Relaxed),
            failures: metadata.failures.load(Ordering::Relaxed),
            transport: metadata.transport_only.then(|| metadata.transport_report()),
        }
    }
}

impl Handle {
    #[cfg(test)]
    pub fn try_emit(
        &self,
        kind: Kind,
        phase: Phase,
        trace_id: &str,
        healthy: Option<bool>,
    ) -> bool {
        self.try_emit_context(
            kind,
            phase,
            TraceContext {
                trace_id,
                attempt: 0,
                target_height: 0,
                generation: 0,
                role: Role::Origin,
                classification: Classification::Healthy,
            },
            healthy,
            None,
        )
    }

    pub fn try_emit_context(
        &self,
        kind: Kind,
        phase: Phase,
        context: TraceContext<'_>,
        healthy: Option<bool>,
        reason: Option<Reason>,
    ) -> bool {
        self.try_emit_context_duration(kind, phase, context, healthy, reason, None, None, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn try_emit_context_duration(
        &self,
        kind: Kind,
        phase: Phase,
        context: TraceContext<'_>,
        healthy: Option<bool>,
        reason: Option<Reason>,
        duration: Option<(&'static str, u64)>,
        processing: Option<ProcessingObservation>,
        transport: Option<TransportObservation>,
    ) -> bool {
        let trace_id = context.trace_id;
        if self.metadata.closed.load(Ordering::Acquire) {
            self.metadata.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if matches!(phase, Phase::Rejected | Phase::Failed) != reason.is_some()
            || !digest(trace_id)
            || !kind.permits(phase)
            || (matches!(kind, Kind::Proposal) && healthy.is_none())
            || (!matches!(kind, Kind::Proposal) && healthy.is_some())
        {
            self.metadata.failures.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        // Transport-only diagnostics cannot fill the bounded writer with unrelated
        // qualification phases. Default qualification recording is unchanged.
        if self.metadata.transport_only && transport.is_none() {
            return true;
        }
        let config = &self.metadata.config;
        let event = Event {
            run_id: config.run_id.clone(),
            artifact_sha3_256: config.artifact_sha3_256.clone(),
            platform: std::env::consts::OS,
            isolated: true,
            node_id: config.node_id.clone(),
            clock_id: self.metadata.clock_domain.clone(),
            trace_id: trace_id.into(),
            attempt: context.attempt,
            target_height: context.target_height,
            generation: context.generation,
            role: context.role,
            classification: context.classification,
            clock_basis: self.metadata.clock_basis,
            collector_instance_id: self.metadata.clock_instance.clone(),
            reason,
            kind,
            phase,
            monotonic_ns: match monotonic_ns(&self.metadata.started) {
                Ok(ns) => ns,
                Err(_) => {
                    self.metadata.failures.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
            },
            healthy,
            runtime_stage: duration.map(|(stage, _)| stage),
            duration_ns: duration.map(|(_, ns)| ns),
            processing,
            transport,
        };
        if self.sender.try_send(event).is_err() {
            self.metadata.dropped.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            true
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn monotonic_ns(_started: &Instant) -> Result<u64, String> {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanoseconds: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, value: *mut Timespec) -> i32;
    }
    let mut value = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // SAFETY: Linux x86_64 timespec ABI is two signed 64-bit fields; the
    // initialized writable local pointer remains valid throughout this call.
    if unsafe { clock_gettime(1, &mut value) } != 0
        || value.seconds < 0
        || !(0..1_000_000_000).contains(&value.nanoseconds)
    {
        return Err("qualification monotonic clock unavailable".into());
    }
    (value.seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(value.nanoseconds as u64))
        .ok_or("qualification monotonic clock overflow".into())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn monotonic_ns(started: &Instant) -> Result<u64, String> {
    u64::try_from(started.elapsed().as_nanos())
        .map_err(|_| "qualification process clock overflow".into())
}

fn clock_domain(instance: &str) -> Result<(String, &'static str), String> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let _ = instance;
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_err(|_| "qualification boot identity unavailable")?;
        let time_namespace = std::fs::read_link("/proc/self/ns/time")
            .map_err(|_| "qualification time namespace unavailable")?;
        let bytes = serde_json::to_vec(&(
            "SYNERGY_QUALIFICATION_CLOCK_V1",
            boot.trim(),
            time_namespace.to_string_lossy(),
        ))
        .map_err(|_| "qualification clock identity serialization")?;
        Ok((
            synergy_block::hash_block_bytes(&bytes),
            "linux_clock_monotonic",
        ))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Ok((instance.into(), "process_instant"))
    }
}

#[cfg(feature = "qualification-timing")]
static PROCESS_HANDLE: std::sync::OnceLock<std::sync::RwLock<Option<Handle>>> =
    std::sync::OnceLock::new();

/// Native test fixtures can profile the existing hooks without production
/// activation. This entry point is absent from deployed binaries.
#[cfg(all(test, feature = "qualification-timing"))]
pub(super) fn start_native_fixture(config: Config) -> Result<QualificationTiming, String> {
    start_native_fixture_mode(config, false)
}
#[cfg(all(test, feature = "qualification-timing"))]
pub(super) fn start_native_transport_fixture(
    config: Config,
) -> Result<QualificationTiming, String> {
    start_native_fixture_mode(config, true)
}
#[cfg(all(test, feature = "qualification-timing"))]
fn start_native_fixture_mode(
    config: Config,
    transport_only: bool,
) -> Result<QualificationTiming, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let size = std::fs::metadata(&executable)
        .map_err(|e| e.to_string())?
        .len();
    if size > 32 * 1024 * 1024 {
        return Err("fixture executable exceeds diagnostic bound".into());
    }
    if artifact_digest(&std::fs::read(executable).map_err(|e| e.to_string())?)?
        != config.artifact_sha3_256
    {
        return Err("fixture diagnostic artifact digest mismatch".into());
    }
    let mut collector = QualificationTiming::start_mode(config, transport_only)?;
    let mut slot = PROCESS_HANDLE
        .get_or_init(|| std::sync::RwLock::new(None))
        .write()
        .map_err(|_| "qualification handle poisoned")?;
    if slot.is_some() {
        return Err("qualification collector already initialized".into());
    }
    *slot = Some(collector.handle());
    collector.registered = true;
    PROCESS_TRANSPORT_ONLY.store(
        collector.handle().metadata.transport_only,
        Ordering::Release,
    );
    PROCESS_ENABLED.store(true, Ordering::Release);
    Ok(collector)
}

/// Diagnostic feature plus explicit private configuration is required. Signed
/// authority verification remains owned by the existing authority loader.
#[cfg(feature = "qualification-timing")]
pub fn from_environment(
    configuration: &synergy_config::NodeConfiguration,
    config_path: &std::path::Path,
) -> Result<Option<QualificationTiming>, String> {
    let Some(path) = std::env::var_os("SYNERGY_POSY_QUALIFICATION_TIMING_CONFIG") else {
        return Ok(None);
    };
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        return Err("qualification runtime requires Linux".into());
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("qualification configuration must be absolute".into());
    }
    let fixture_parent = path
        .parent()
        .ok_or("qualification fixture parent missing")?;
    let parent_metadata = std::fs::symlink_metadata(fixture_parent)
        .map_err(|_| "qualification fixture directory unavailable")?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err("unsafe qualification fixture directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err("qualification fixture directory must be private".into());
        }
    }
    for ancestor in path.ancestors().skip(1) {
        if std::fs::symlink_metadata(ancestor)
            .map_err(|_| "qualification configuration ancestor unavailable")?
            .file_type()
            .is_symlink()
        {
            return Err("qualification configuration symlink ancestor".into());
        }
    }
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|_| "qualification configuration unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 16384 {
        return Err("unsafe qualification configuration".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("qualification configuration must be private".into());
        }
    }
    let config: Config = serde_json::from_slice(
        &std::fs::read(&path).map_err(|_| "read qualification configuration")?,
    )
    .map_err(|_| "invalid qualification configuration")?;
    let canary = exact_canary_paths(configuration, config_path);
    if config.node_id != configuration.node_name
        || !(configuration.network_id.starts_with("posy-isolated-") || canary)
    {
        return Err("qualification configuration network/node mismatch".into());
    }
    if canary {
        // Exact lexical names cannot be redirected through a symlink. Inspect
        // metadata only; never read or export custody material for diagnostics.
        let paths = [
            Some(config_path),
            Some(configuration.storage.data_directory.as_path()),
            Some(configuration.manifest_path.as_path()),
            Some(configuration.public_identity_path.as_path()),
            configuration.aegis_key_bindings_path.as_deref(),
            configuration.aegis_signing_key_path.as_deref(),
            configuration.consensus.authority_binding.as_deref(),
            configuration.consensus.authority_trust_key_path.as_deref(),
            configuration.consensus.signing_key_path.as_deref(),
            configuration.etdag.ingress_kem_secret_key_path.as_deref(),
            configuration.vpn.signed_registry_path.as_deref(),
        ];
        for guarded in paths.into_iter().flatten() {
            for ancestor in guarded.ancestors() {
                if std::fs::symlink_metadata(ancestor)
                    .map_err(|_| "qualification guarded path unavailable")?
                    .file_type()
                    .is_symlink()
                {
                    return Err("qualification guarded path symlink".into());
                }
            }
        }
    }
    let authority =
        super::authority::load(configuration)?.ok_or("qualification requires signed authority")?;
    if authority.epoch.network_id != configuration.network_id
        || (canary && !authority.processing_profile_enabled())
    {
        return Err("qualification authority network mismatch".into());
    }
    if !canary
        && std::fs::read_link("/proc/self/ns/net").map_err(|_| "read qualification netns")?
            == std::fs::read_link("/proc/1/ns/net").map_err(|_| "read host netns")?
    {
        return Err("qualification requires a distinct network namespace".into());
    }
    let parent = path
        .parent()
        .ok_or("qualification configuration parent missing")?;
    if !config.output.starts_with(parent) {
        return Err("qualification output outside fixture directory".into());
    }
    let executable = std::env::current_exe().map_err(|_| "qualification executable unavailable")?;
    let exe_metadata =
        std::fs::metadata(&executable).map_err(|_| "inspect qualification executable")?;
    if !exe_metadata.is_file() || exe_metadata.len() > 32 * 1024 * 1024 {
        return Err("qualification executable exceeds bound".into());
    }
    let bytes = std::fs::read(executable).map_err(|_| "read qualification executable")?;
    if !bytes.starts_with(b"\x7fELF") || artifact_digest(&bytes)? != config.artifact_sha3_256 {
        return Err("qualification executable digest mismatch".into());
    }
    let transport_only = match std::env::var_os("SYNERGY_POSY_TRANSPORT_TRACE_ONLY") {
        None => false,
        Some(value) if value == "1" => true,
        Some(_) => return Err("invalid private transport trace mode".into()),
    };
    let mut collector = QualificationTiming::start_mode(config, transport_only)?;
    let mut slot = PROCESS_HANDLE
        .get_or_init(|| std::sync::RwLock::new(None))
        .write()
        .map_err(|_| "qualification handle poisoned")?;
    if slot.is_some() {
        return Err("qualification collector already initialized".into());
    }
    *slot = Some(collector.handle());
    collector.registered = true;
    PROCESS_TRANSPORT_ONLY.store(
        collector.handle().metadata.transport_only,
        Ordering::Release,
    );
    PROCESS_ENABLED.store(true, Ordering::Release);
    Ok(Some(collector))
}

/// Stable public-context trace ID; never hash keys or transaction plaintext.
#[cfg(feature = "qualification-timing")]
pub fn trace_id(kind: Kind, target: u64, attempt: u64, generation: u64) -> String {
    let bytes = serde_json::to_vec(&(
        "SYNERGY_QUALIFICATION_TRACE_V1",
        kind,
        target,
        attempt,
        generation,
    ))
    .expect("fixed qualification trace serialization");
    synergy_block::hash_block_bytes(&bytes)
}

#[cfg(feature = "qualification-timing")]
pub fn clear_process_handle() {
    PROCESS_ENABLED.store(false, Ordering::Release);
    PROCESS_TRANSPORT_ONLY.store(false, Ordering::Release);
    if let Some(slot) = PROCESS_HANDLE.get() {
        if let Ok(mut slot) = slot.write() {
            *slot = None;
        }
    }
}

impl Drop for QualificationTiming {
    fn drop(&mut self) {
        let _registered = self.registered;
        if let Some(handle) = self.handle.take() {
            handle.metadata.closed.store(true, Ordering::Release);
            #[cfg(feature = "qualification-timing")]
            if self.registered {
                clear_process_handle();
            }
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

#[cfg(feature = "qualification-timing")]
static PROCESS_ENABLED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "qualification-timing")]
pub fn enabled() -> bool {
    diagnostic_mode(
        PROCESS_ENABLED.load(Ordering::Acquire),
        PROCESS_TRANSPORT_ONLY.load(Ordering::Acquire),
        false,
    )
}
#[cfg(feature = "qualification-timing")]
static PROCESS_TRANSPORT_ONLY: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "qualification-timing")]
pub fn transport_enabled() -> bool {
    diagnostic_mode(
        PROCESS_ENABLED.load(Ordering::Acquire),
        PROCESS_TRANSPORT_ONLY.load(Ordering::Acquire),
        true,
    )
}
#[cfg(feature = "qualification-timing")]
fn diagnostic_mode(active: bool, transport_only: bool, transport: bool) -> bool {
    active && transport_only == transport
}

/// Deterministic identifiers from public envelope/target metadata only.
#[cfg(feature = "qualification-timing")]
fn subject_trace_id(
    kind: Kind,
    target: u64,
    attempt: u64,
    generation: u64,
    subject: &str,
) -> String {
    let bytes = serde_json::to_vec(&(
        "SYNERGY_QUALIFICATION_SUBJECT_TRACE_V1",
        kind,
        target,
        attempt,
        generation,
        subject,
    ))
    .expect("fixed qualification subject serialization");
    synergy_block::hash_block_bytes(&bytes)
}

/// Diagnostic-only native stages; no payload, key, or protocol authority is recorded.
#[cfg(feature = "qualification-timing")]
#[derive(Clone, Copy)]
pub enum ProcessingStage {
    VertexNew,
    VertexRetained,
    VertexVerification,
    VertexProgressRead,
    ProgressWrite,
    RevealAdvance,
    CompletionBuild,
    CompletionDurable,
    ProgressVerification,
    CompletionVerification,
    CandidateReplay,
    CandidateBuild,
    CandidateCommit,
    ParentVerification,
    ArchiveCertified,
    ValidationRead,
    ProofInvalidation,
}
#[cfg(feature = "qualification-timing")]
impl ProcessingStage {
    fn label(self) -> &'static str {
        match self {
            Self::VertexNew => "processing_vertex_new",
            Self::VertexRetained => "processing_vertex_retained",
            Self::VertexVerification => "processing_vertex_verification",
            Self::VertexProgressRead => "processing_vertex_progress_read",
            Self::ProgressWrite => "processing_progress_write",
            Self::RevealAdvance => "processing_reveal_advance",
            Self::CompletionBuild => "processing_completion_build",
            Self::CompletionDurable => "processing_completion_durable",
            Self::ProgressVerification => "processing_progress_verification",
            Self::CompletionVerification => "processing_completion_verification",
            Self::CandidateReplay => "processing_candidate_replay",
            Self::CandidateBuild => "processing_candidate_build",
            Self::CandidateCommit => "processing_candidate_commit",
            Self::ParentVerification => "processing_parent_verification",
            Self::ArchiveCertified => "processing_archive_certified",
            Self::ValidationRead => "processing_validation_read",
            Self::ProofInvalidation => "processing_proof_invalidation",
        }
    }
}
/// One end record includes actual duration; bounded writer/drop counters remain authoritative.
/// No once-cache entry is retained per call. This changes no protocol behavior.
#[cfg(feature = "qualification-timing")]
pub struct ProcessingSpan(Option<(Handle, Instant, u64, ProcessingStage)>);
#[cfg(feature = "qualification-timing")]
pub fn processing_span(stage: ProcessingStage) -> ProcessingSpan {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    if !enabled() {
        return ProcessingSpan(None);
    }
    let handle = PROCESS_HANDLE
        .get()
        .and_then(|slot| slot.read().ok().and_then(|slot| slot.clone()));
    ProcessingSpan(handle.map(|handle| {
        (
            handle,
            Instant::now(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            stage,
        )
    }))
}
#[cfg(feature = "qualification-timing")]
impl Drop for ProcessingSpan {
    fn drop(&mut self) {
        let Some((handle, started, id, stage)) = self.0.take() else {
            return;
        };
        let duration = started.elapsed().as_nanos();
        let Ok(duration) = u64::try_from(duration) else {
            handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let trace = subject_trace_id(Kind::Runtime, 0, id, 1, stage.label());
        handle.try_emit_context_duration(
            Kind::Runtime,
            Phase::End,
            TraceContext {
                trace_id: &trace,
                attempt: id,
                target_height: 0,
                generation: 1,
                role: Role::Participant,
                classification: Classification::Observed,
            },
            None,
            None,
            Some((stage.label(), duration)),
            None,
            None,
        );
    }
}

/// Allowlisted HTTP spans carry only an internal public counter, never request data.
#[cfg(feature = "qualification-timing")]
#[derive(Clone, Copy)]
pub enum HttpStage {
    Intake,
    Dispatch,
    Response,
}

#[cfg(feature = "qualification-timing")]
pub fn http_span(request: u64, stage: HttpStage, phase: Phase) -> bool {
    let label = match stage {
        HttpStage::Intake => "http-intake",
        HttpStage::Dispatch => "http-dispatch",
        HttpStage::Response => "http-response",
    };
    emit_subject_once(
        Kind::Runtime,
        phase,
        0,
        request,
        0,
        label,
        Role::Participant,
        Classification::Observed,
        None,
        None,
    )
}

/// Bounded first observations at native boundaries; exact public subject
/// fields permit joining nodes without retaining payloads or protocol authority.
#[cfg(feature = "qualification-timing")]
pub fn processing_boundary(stage: &'static str, height: u64, round: u64, block: &str, peer: &str) {
    if !enabled() {
        return;
    }
    let Some(handle) = PROCESS_HANDLE
        .get()
        .and_then(|slot| slot.read().ok().and_then(|slot| slot.clone()))
    else {
        return;
    };
    processing_boundary_to(&handle, stage, height, round, block, peer);
}

#[cfg(feature = "qualification-timing")]
fn processing_boundary_to(
    handle: &Handle,
    stage: &'static str,
    height: u64,
    round: u64,
    block: &str,
    peer: &str,
) {
    if !matches!(
        stage,
        "input_enqueue"
            | "input_enqueue_partial"
            | "input_authenticated_arrival"
            | "candidate_ready"
            | "own_echo"
    ) || !digest(block)
        || !label(peer)
        || height == 0
    {
        handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let subject = format!("{stage}:{block}:{peer}");
    let trace = subject_trace_id(Kind::Runtime, height, round, 1, &subject);
    if reserve_observation(handle, (trace.clone(), Kind::Runtime, Phase::End)) != Some(true) {
        return;
    }
    handle.try_emit_context_duration(
        Kind::Runtime,
        Phase::End,
        TraceContext {
            trace_id: &trace,
            attempt: round,
            target_height: height,
            generation: 1,
            role: Role::Participant,
            classification: Classification::Observed,
        },
        None,
        None,
        None,
        Some(ProcessingObservation {
            stage,
            block_id: block.to_owned(),
            peer: peer.to_owned(),
        }),
        None,
    );
}

#[cfg(feature = "qualification-timing")]
pub fn processing_input_arrival(bytes: &[u8], peer: &str) {
    if !enabled() {
        return;
    }
    #[derive(Deserialize)]
    struct Slot {
        height: u64,
        round: u64,
    }
    #[derive(Deserialize)]
    struct Input<'a> {
        context: Slot,
        #[serde(borrow)]
        block_id: &'a str,
    }
    // Borrow only public identity; unknown payload fields are skipped, never
    // decoded into a second full proposal or used as protocol authority.
    if let Ok(input) = serde_json::from_slice::<Input<'_>>(bytes) {
        processing_boundary(
            "input_authenticated_arrival",
            input.context.height,
            input.context.round,
            input.block_id,
            peer,
        );
    }
}

#[cfg(feature = "qualification-timing")]
fn exact_canary_paths(
    configuration: &synergy_config::NodeConfiguration,
    config_path: &std::path::Path,
) -> bool {
    use std::path::Path;
    let base = Path::new("/etc/synergy/posy-async-canary-20261022-rc1");
    let Some(number) =
        (2..=6).find(|n| configuration.node_name == format!("synergy-val{n}-posy-stability"))
    else {
        return false;
    };
    configuration.network_id == "synergy-posy-async-canary-20261022-rc1"
        && config_path == base.join("node.json")
        && configuration.storage.data_directory
            == Path::new("/var/lib/synergy/posy-async-canary-20261022-rc1/data")
        && configuration.manifest_path == base.join("network-manifest.json")
        && configuration.aegis_key_bindings_path.as_deref()
            == Some(base.join("p2p-bindings.json").as_path())
        && configuration.consensus.authority_binding.as_deref()
            == Some(base.join("authority.json").as_path())
        && configuration.consensus.authority_trust_key_path.as_deref()
            == Some(base.join("authority-root.pub").as_path())
        && configuration.vpn.signed_registry_path.as_deref()
            == Some(base.join("transport-registry.json").as_path())
        && configuration.admin_socket_path
            == Path::new("/run/synergy-posy-async-canary-20261022-rc1/admin.sock")
        && configuration.public_identity_path
            == base.join(format!("custody/p2p/val{number}-posy-p2p-v1.identity.json"))
        && configuration.aegis_signing_key_path.as_deref()
            == Some(
                base.join(format!("custody/p2p/val{number}-posy-p2p-v1.secret.key"))
                    .as_path(),
            )
        && configuration.consensus.signing_key_path.as_deref()
            == Some(
                base.join(format!(
                    "custody/consensus/val{number}-posy-consensus-v1.secret.key"
                ))
                .as_path(),
            )
        && configuration.etdag.ingress_kem_secret_key_path.as_deref()
            == Some(
                base.join(format!(
                    "custody/ingress/val{number}-posy-ingress-v1.secret.key"
                ))
                .as_path(),
            )
}

/// Deduplicate observations only; this cache grants no protocol authority.
/// Exhaustion invalidates measurement instead of evicting required observations.
#[cfg(feature = "qualification-timing")]
#[allow(clippy::too_many_arguments)]
pub fn emit_once(
    kind: Kind,
    phase: Phase,
    target: u64,
    attempt: u64,
    generation: u64,
    role: Role,
    classification: Classification,
    healthy: Option<bool>,
    reason: Option<Reason>,
) -> bool {
    emit_subject_once(
        kind,
        phase,
        target,
        attempt,
        generation,
        "",
        role,
        classification,
        healthy,
        reason,
    )
}

/// Public subject identity keeps distinct envelopes separate at the same height.
#[cfg(feature = "qualification-timing")]
#[allow(clippy::too_many_arguments)]
pub fn emit_subject_once(
    kind: Kind,
    phase: Phase,
    target: u64,
    attempt: u64,
    generation: u64,
    subject: &str,
    role: Role,
    classification: Classification,
    healthy: Option<bool>,
    reason: Option<Reason>,
) -> bool {
    if !enabled() {
        return false;
    }
    let Some(slot) = PROCESS_HANDLE.get() else {
        return false;
    };
    let Some(handle) = slot.read().ok().and_then(|slot| slot.clone()) else {
        return false;
    };
    if subject.len() > 256 {
        handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let trace = if subject.is_empty() {
        trace_id(kind, target, attempt, generation)
    } else {
        subject_trace_id(kind, target, attempt, generation, subject)
    };
    match reserve_observation(&handle, (trace.clone(), kind, phase)) {
        Some(true) => {}
        Some(false) => return true,
        None => return false,
    }
    handle.try_emit_context(
        kind,
        phase,
        TraceContext {
            trace_id: &trace,
            attempt,
            target_height: target,
            generation,
            role,
            classification,
        },
        healthy,
        reason,
    )
}

#[cfg(feature = "qualification-timing")]
fn reserve_observation(handle: &Handle, key: (String, Kind, Phase)) -> Option<bool> {
    let Ok(mut observed) = handle.metadata.emitted_once.lock() else {
        handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    if observed.contains(&key) {
        return Some(false);
    }
    if observed.len() >= MAX_ONCE_OBSERVATIONS {
        handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    observed.insert(key);
    Some(true)
}

/// Artifact provenance uses raw SHA3-256, not a domain-framed block ID.
#[cfg(any(test, feature = "qualification-timing"))]
fn artifact_digest(bytes: &[u8]) -> Result<String, String> {
    use synergy_aegis::AegisHashEngine;
    let digest = synergy_aegis::AegisSha3_256
        .sha3_256_segments(&[bytes])
        .map_err(|_| "qualification artifact hash unavailable".to_owned())?;
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_digest_matches_raw_sha3_provenance() {
        assert_eq!(
            artifact_digest(b"abc").unwrap(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        assert_ne!(
            artifact_digest(b"abc").unwrap(),
            synergy_block::hash_block_bytes(b"abc")
        );
    }
    #[cfg(feature = "qualification-timing")]
    #[test]
    fn public_subject_keeps_transactions_at_same_target_distinct() {
        let a = subject_trace_id(Kind::Admission, 6, 0, 0, "public-envelope-a");
        let b = subject_trace_id(Kind::Admission, 6, 0, 0, "public-envelope-b");
        assert_ne!(a, b);
        assert_eq!(
            a,
            subject_trace_id(Kind::Admission, 6, 0, 0, "public-envelope-a")
        );
        assert_ne!(
            subject_trace_id(Kind::Runtime, 0, 1, 0, "http-intake"),
            subject_trace_id(Kind::Runtime, 0, 1, 0, "http-dispatch")
        );
        assert_ne!(
            subject_trace_id(Kind::Runtime, 0, 1, 0, "http-intake"),
            subject_trace_id(Kind::Runtime, 0, 2, 0, "http-intake")
        );
        assert!(Kind::Window.permits(Phase::TargetOpen));
        assert!(Kind::Window.permits(Phase::CutoffClose));
        assert!(!Kind::Window.permits(Phase::DurableAdmission));
    }

    #[test]
    fn complete_phase_allowlist_rejects_cross_kind_events() {
        let admission = [
            Phase::TargetOpen,
            Phase::ContextRead,
            Phase::AuthorStart,
            Phase::AuthorEnd,
            Phase::SubmitStart,
            Phase::RpcEnqueue,
            Phase::DurableAdmission,
            Phase::DurableAvailability,
            Phase::CutoffClose,
            Phase::Finalized,
        ];
        for phase in admission {
            assert!(Kind::Admission.permits(phase));
            assert!(!Kind::Proposal.permits(phase));
            assert!(!Kind::Cadence.permits(phase));
            assert!(!Kind::Runtime.permits(phase));
        }
        for phase in [Phase::ProposalStart, Phase::QcVerified] {
            assert!(Kind::Proposal.permits(phase));
            assert!(!Kind::Admission.permits(phase));
            assert!(!Kind::Cadence.permits(phase));
            assert!(!Kind::Runtime.permits(phase));
        }
        for phase in [Phase::Start, Phase::End] {
            assert!(Kind::Cadence.permits(phase));
            assert!(Kind::Runtime.permits(phase));
            assert!(!Kind::Admission.permits(phase));
            assert!(!Kind::Proposal.permits(phase));
        }
    }

    #[cfg(feature = "qualification-timing")]
    #[test]
    fn qualification_exact_canary_guard_rejects_path_scope_and_identity_changes() {
        let base = std::path::Path::new("/etc/synergy/posy-async-canary-20261022-rc1");
        let mut config: synergy_config::NodeConfiguration = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "node_name": "synergy-val2-posy-stability", "role": "validator",
            "chain_id": 1266, "network_id": "synergy-posy-async-canary-20261022-rc1",
            "manifest_path": base.join("network-manifest.json"),
            "public_identity_path": base.join("custody/p2p/val2-posy-p2p-v1.identity.json"),
            "aegis_key_bindings_path": base.join("p2p-bindings.json"),
            "aegis_signing_key_path": base.join("custody/p2p/val2-posy-p2p-v1.secret.key"),
            "admin_socket_path": "/run/synergy-posy-async-canary-20261022-rc1/admin.sock",
            "consensus": {"mode":"validate_and_vote", "authority_binding":base.join("authority.json"),
                "authority_trust_key_path":base.join("authority-root.pub"),
                "signing_key_path":base.join("custody/consensus/val2-posy-consensus-v1.secret.key"),
                "proposal_timeout_ms":2000,"round_timeout_ms":5000,"max_rounds_behind":64},
            "etdag": {"enabled":true,"ingress_kem_secret_key_path":base.join("custody/ingress/val2-posy-ingress-v1.secret.key"),
                "protected_lookahead":16,"admission_queue_capacity":4096,"max_vertex_bytes":1048576,"proposal_material_wait_ms":250},
            "vpn": {"mode":"required","interface_name":"wt0","signed_registry_path":base.join("transport-registry.json")},
            "storage": {"data_directory":"/var/lib/synergy/posy-async-canary-20261022-rc1/data",
                "wal_sync":"every_commit","max_open_files":128,"prune_finalized_history_after_blocks":null}
        })).unwrap();
        assert!(exact_canary_paths(&config, &base.join("node.json")));
        assert!(!exact_canary_paths(&config, &base.join("other.json")));
        config.node_name = "synergy-val3-posy-stability".into();
        assert!(!exact_canary_paths(&config, &base.join("node.json")));
        config.node_name = "synergy-val2-posy-stability".into();
        config.storage.data_directory.push("other");
        assert!(!exact_canary_paths(&config, &base.join("node.json")));
        config.storage.data_directory.pop();
        config.consensus.authority_binding = Some(base.join("old-authority.json"));
        assert!(!exact_canary_paths(&config, &base.join("node.json")));
        config.consensus.authority_binding = Some(base.join("authority.json"));
        config.network_id.push_str("-other");
        assert!(!exact_canary_paths(&config, &base.join("node.json")));
    }

    #[cfg(feature = "qualification-timing")]
    #[test]
    fn processing_span_records_bounded_public_duration_without_once_cache() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "qualification-processing-span-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("timing.jsonl");
        let collector = QualificationTiming::start(Config {
            run_id: "processing-span-test".into(),
            artifact_sha3_256: "a".repeat(64),
            node_id: "test-node".into(),
            clock_id: "test-clock".into(),
            output: path.clone(),
        })
        .unwrap();
        let handle = collector.handle();
        drop(ProcessingSpan(Some((
            handle.clone(),
            Instant::now(),
            7,
            ProcessingStage::VertexRetained,
        ))));
        assert!(handle.metadata.emitted_once.lock().unwrap().is_empty());
        let block = "b".repeat(64);
        for _ in 0..100 {
            processing_boundary_to(&handle, "input_enqueue", 42, 3, &block, "peer-2");
        }
        processing_boundary_to(&handle, "input_enqueue", 42, 3, &block, "peer-3");
        processing_boundary_to(&handle, "input_enqueue_partial", 42, 3, &block, "peer-2");
        assert_eq!(handle.metadata.emitted_once.lock().unwrap().len(), 3);
        let report = collector.finish();
        assert_eq!(report.written, 4);
        assert!(report.complete());
        let bytes = std::fs::read_to_string(&path).unwrap();
        let values: Vec<serde_json::Value> = bytes
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let value = &values[0];
        assert_eq!(values[1]["target_height"], 42);
        assert_eq!(values[1]["attempt"], 3);
        assert_eq!(values[1]["processing"]["block_id"], block);
        assert_eq!(values[1]["processing"]["peer"], "peer-2");
        assert_ne!(values[1]["trace_id"], values[2]["trace_id"]);
        assert_ne!(values[1]["trace_id"], values[3]["trace_id"]);
        assert_eq!(value["kind"], "runtime");
        assert_eq!(value["phase"], "end");
        assert_eq!(value["runtime_stage"], "processing_vertex_retained");
        assert!(value["duration_ns"].is_u64());
        assert_eq!(value["attempt"], 7);
    }

    #[test]
    fn collector_drains_and_rejects_invalid_or_closed_producers() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "qualification-timing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("timing.jsonl");
        let collector = QualificationTiming::start(Config {
            run_id: "qualification-test".into(),
            artifact_sha3_256: "a".repeat(64),
            node_id: "test-node".into(),
            clock_id: "test-process-clock".into(),
            output: path.clone(),
        })
        .unwrap();
        let producer = collector.handle();
        assert!(producer.try_emit(Kind::Runtime, Phase::Start, &"b".repeat(64), None));
        assert!(!producer.try_emit(Kind::Proposal, Phase::QcVerified, &"b".repeat(64), None));
        for reason in [
            Reason::AdmissionClosed,
            Reason::QueueFull,
            Reason::InvalidInput,
            Reason::VerificationFailed,
            Reason::StorageFailed,
            Reason::WorkerFailed,
            Reason::Cancelled,
            Reason::Timeout,
        ] {
            assert!(producer.try_emit_context(
                Kind::Admission,
                Phase::Rejected,
                TraceContext {
                    trace_id: &"c".repeat(64),
                    attempt: 1,
                    target_height: 5,
                    generation: 2,
                    role: Role::Participant,
                    classification: Classification::Recovered
                },
                None,
                Some(reason)
            ));
        }
        assert!(producer.try_emit_context(
            Kind::Runtime,
            Phase::Failed,
            TraceContext {
                trace_id: &"d".repeat(64),
                attempt: 2,
                target_height: 0,
                generation: 0,
                role: Role::Origin,
                classification: Classification::Healthy
            },
            None,
            Some(Reason::Cancelled)
        ));
        #[cfg(feature = "qualification-timing")]
        {
            for attempt in 0..MAX_ONCE_OBSERVATIONS as u64 {
                assert_eq!(
                    reserve_observation(
                        &producer,
                        (
                            trace_id(Kind::Runtime, 0, attempt, 0),
                            Kind::Runtime,
                            Phase::Start
                        )
                    ),
                    Some(true)
                );
            }
            assert_eq!(
                reserve_observation(
                    &producer,
                    (
                        trace_id(Kind::Runtime, 0, 0, 0),
                        Kind::Runtime,
                        Phase::Start
                    )
                ),
                Some(false)
            );
            assert_eq!(
                reserve_observation(
                    &producer,
                    (
                        trace_id(Kind::Runtime, 0, MAX_ONCE_OBSERVATIONS as u64, 0),
                        Kind::Runtime,
                        Phase::Start
                    )
                ),
                None
            );
            assert_eq!(
                producer.metadata.emitted_once.lock().unwrap().len(),
                MAX_ONCE_OBSERVATIONS
            );
        }
        let report = collector.finish();
        assert_eq!(report.written, 10);
        assert_eq!(
            report.failures,
            if cfg!(feature = "qualification-timing") {
                2
            } else {
                1
            }
        );
        assert!(!report.complete());
        assert!(!producer.try_emit(Kind::Runtime, Phase::End, &"b".repeat(64), None));
        let event: serde_json::Value = serde_json::from_str(
            std::fs::read_to_string(&path)
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(event["platform"], std::env::consts::OS);
        assert_ne!(event["clock_id"], "test-process-clock");
        assert_eq!(
            event["clock_basis"],
            if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
                "linux_clock_monotonic"
            } else {
                "process_instant"
            }
        );
        assert_ne!(event["collector_instance_id"], "test-process-clock");
        assert_eq!(event["attempt"], 0);
        assert_eq!(event["isolated"], true);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}

// Fixed-size, one-hour diagnostic retention. Counters never retain payloads or
// protocol state. Only the existing exact-artifact isolated collector can enable it.
const TRANSPORT_WINDOW: Duration = Duration::from_secs(3600);
#[cfg(feature = "qualification-timing")]
const TRANSPORT_SLOW: Duration = Duration::from_millis(250);
const TRANSPORT_SAMPLE_EVERY: u64 = 1024;
const TRANSPORT_MAX_RETAINED: u64 = 8192;
#[derive(Default)]
struct TransportCapture {
    #[cfg(feature = "qualification-timing")]
    started: std::sync::OnceLock<Instant>,
    #[cfg(feature = "qualification-timing")]
    attempts: AtomicU64,
    stages: [AtomicU64; 6],
    retained: AtomicU64,
    omitted_fast: AtomicU64,
    expired: AtomicU64,
    in_flight: AtomicU64,
    slow: AtomicU64,
    failed: AtomicU64,
    #[cfg(feature = "qualification-timing")]
    window_recorded: AtomicBool,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct TransportReport {
    window_seconds: u64,
    sample_every_per_stage: u64,
    max_retained: u64,
    attempts_by_stage: [u64; 6],
    retained: u64,
    omitted_fast: u64,
    expired: u64,
    in_flight: u64,
    slow: u64,
    failed: u64,
    lock_skipped: u64,
    dropped: u64,
    collector_failures: u64,
}
impl TransportReport {
    #[cfg(all(test, feature = "qualification-timing"))]
    pub fn attempted_operations(&self) -> u64 {
        self.attempts_by_stage.iter().sum()
    }
    #[cfg(all(test, feature = "qualification-timing"))]
    pub fn open_operations(&self) -> u64 {
        self.in_flight
    }
}
#[cfg(feature = "qualification-timing")]
impl TransportCapture {
    fn reserve(&self) -> bool {
        self.retained
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < TRANSPORT_MAX_RETAINED).then_some(count + 1)
            })
            .is_ok()
    }
}
impl Metadata {
    fn transport_report(&self) -> TransportReport {
        let c = &self.transport_capture;
        TransportReport {
            window_seconds: TRANSPORT_WINDOW.as_secs(),
            sample_every_per_stage: TRANSPORT_SAMPLE_EVERY,
            max_retained: TRANSPORT_MAX_RETAINED,
            attempts_by_stage: std::array::from_fn(|i| c.stages[i].load(Ordering::Relaxed)),
            retained: c.retained.load(Ordering::Relaxed),
            omitted_fast: c.omitted_fast.load(Ordering::Relaxed),
            expired: c.expired.load(Ordering::Relaxed),
            in_flight: c.in_flight.load(Ordering::Relaxed),
            slow: c.slow.load(Ordering::Relaxed),
            failed: c.failed.load(Ordering::Relaxed),
            lock_skipped: transport_lock_skipped().saturating_sub(self.transport_lock_baseline),
            dropped: self.dropped.load(Ordering::Relaxed),
            collector_failures: self.failures.load(Ordering::Relaxed),
        }
    }
}
#[derive(Serialize)]
struct TransportObservation {
    stage: &'static str,
    peer: String,
    session: u64,
    sequence: u64,
    protocol: u8,
    payload_bytes: usize,
    payload_fingerprint: Option<String>,
    queue_wait_ns: Option<u64>,
    diagnostic_setup_ns: u64,
    sampled_baseline: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    totals: Option<TransportReport>,
}
#[cfg(feature = "qualification-timing")]
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum TransportStage {
    Dispatch,
    Sign,
    Write,
    ReadBody,
    Verify,
    Ingress,
}
#[cfg(feature = "qualification-timing")]
impl TransportStage {
    fn label(self) -> &'static str {
        match self {
            Self::Dispatch => "transport-dispatch",
            Self::Sign => "transport-sign",
            Self::Write => "transport-write",
            Self::ReadBody => "transport-read-body",
            Self::Verify => "transport-verify",
            Self::Ingress => "transport-ingress",
        }
    }
}
#[cfg(feature = "qualification-timing")]
pub struct TransportSpan(Option<(Handle, Instant, u64, TransportObservation, bool)>);
#[cfg(feature = "qualification-timing")]
fn transport_handle(slot: &std::sync::RwLock<Option<Handle>>) -> Option<Handle> {
    // Producers only clone the immutable handle. Shared readers must not discard
    // each other's evidence; registration/clear retain exclusive access.
    match slot.try_read() {
        Ok(slot) => slot.clone(),
        Err(_) => {
            TRANSPORT_LOCK_SKIPPED.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}
/// No collector lock waiting or synchronous file I/O on a protocol thread.
/// End-only records retain failures, >=250ms operation/queue waits, and one
/// baseline per1024 operations of each stage. They are deliberately sparse;
/// no claim of paired starts, complete traffic, or latency quantiles is valid.
#[cfg(feature = "qualification-timing")]
pub fn transport_span(
    stage: TransportStage,
    peer: &str,
    session: u64,
    sequence: u64,
    protocol: u8,
    payload_bytes: usize,
    payload: &[u8],
    queue_wait_ns: Option<u64>,
) -> TransportSpan {
    if !transport_enabled() {
        return TransportSpan(None);
    }
    let setup = Instant::now();
    let Some(handle) = PROCESS_HANDLE.get().and_then(transport_handle) else {
        return TransportSpan(None);
    };
    transport_span_to(
        handle,
        setup,
        stage,
        peer,
        session,
        sequence,
        protocol,
        payload_bytes,
        payload,
        queue_wait_ns,
    )
}
#[cfg(feature = "qualification-timing")]
#[allow(clippy::too_many_arguments)]
fn transport_span_to(
    handle: Handle,
    setup: Instant,
    stage: TransportStage,
    peer: &str,
    session: u64,
    sequence: u64,
    protocol: u8,
    payload_bytes: usize,
    payload: &[u8],
    queue_wait_ns: Option<u64>,
) -> TransportSpan {
    if !handle.metadata.transport_only {
        return TransportSpan(None);
    }
    let c = &handle.metadata.transport_capture;
    if c.started.get_or_init(Instant::now).elapsed() >= TRANSPORT_WINDOW {
        c.expired.fetch_add(1, Ordering::Relaxed);
        if !c.window_recorded.swap(true, Ordering::AcqRel) {
            // One extra bounded snapshot shows expired coverage and any open
            // operations. Slow/error completions begun inside the window can
            // still follow it; their recorded duration remains meaningful.
            let observation = TransportObservation {
                stage: "transport-window-end",
                peer: String::new(),
                session: 0,
                sequence: 0,
                protocol: 0,
                payload_bytes: 0,
                payload_fingerprint: None,
                queue_wait_ns: None,
                diagnostic_setup_ns: 0,
                sampled_baseline: false,
                totals: Some(handle.metadata.transport_report()),
            };
            transport_emit(&handle, u64::MAX, observation, Phase::End, None);
        }
        return TransportSpan(None);
    }
    if peer.len() > 128 || payload.len() > 64 * 1024 * 1024 {
        handle.metadata.failures.fetch_add(1, Ordering::Relaxed);
        return TransportSpan(None);
    }
    let id = c.attempts.fetch_add(1, Ordering::Relaxed);
    let sampled =
        c.stages[stage as usize].fetch_add(1, Ordering::Relaxed) % TRANSPORT_SAMPLE_EVERY == 0;
    c.in_flight.fetch_add(1, Ordering::Relaxed);
    let observation = TransportObservation {
        stage: stage.label(),
        peer: peer.to_owned(),
        session,
        sequence,
        protocol,
        payload_bytes,
        // Unsampled slow/error records join by exact peer/session/sequence;
        // hashing every large frame would itself disturb the measured path.
        payload_fingerprint: (sampled && !payload.is_empty())
            .then(|| synergy_block::hash_block_bytes(payload)),
        queue_wait_ns,
        diagnostic_setup_ns: setup.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        sampled_baseline: sampled,
        totals: None,
    };
    TransportSpan(Some((handle, Instant::now(), id, observation, false)))
}
#[cfg(feature = "qualification-timing")]
fn transport_emit(
    handle: &Handle,
    id: u64,
    observation: TransportObservation,
    phase: Phase,
    duration: Option<u64>,
) {
    let stage = observation.stage;
    let trace = subject_trace_id(Kind::Runtime, 0, id, 0, stage);
    handle.try_emit_context_duration(
        Kind::Runtime,
        phase,
        TraceContext {
            trace_id: &trace,
            attempt: id,
            target_height: 0,
            generation: 0,
            role: Role::Participant,
            classification: Classification::Observed,
        },
        None,
        matches!(phase, Phase::Failed).then_some(Reason::WorkerFailed),
        duration.map(|ns| (stage, ns)),
        None,
        Some(observation),
    );
}
#[cfg(feature = "qualification-timing")]
impl TransportSpan {
    pub fn finish(mut self, success: bool) {
        if let Some((_, _, _, _, outcome)) = self.0.as_mut() {
            *outcome = success;
        }
    }
}
#[cfg(feature = "qualification-timing")]
impl Drop for TransportSpan {
    fn drop(&mut self) {
        let Some((handle, start, id, observation, success)) = self.0.take() else {
            return;
        };
        let duration = start.elapsed();
        let c = &handle.metadata.transport_capture;
        c.in_flight.fetch_sub(1, Ordering::Relaxed);
        let slow = duration >= TRANSPORT_SLOW
            || observation
                .queue_wait_ns
                .is_some_and(|ns| ns >= TRANSPORT_SLOW.as_nanos() as u64);
        if slow {
            c.slow.fetch_add(1, Ordering::Relaxed);
        }
        if !success {
            c.failed.fetch_add(1, Ordering::Relaxed);
        }
        if success && !slow && !observation.sampled_baseline {
            c.omitted_fast.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !c.reserve() {
            handle.metadata.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        transport_emit(
            &handle,
            id,
            observation,
            if success { Phase::End } else { Phase::Failed },
            Some(duration.as_nanos().min(u64::MAX as u128) as u64),
        );
    }
}
#[cfg(feature = "qualification-timing")]
static TRANSPORT_LOCK_SKIPPED: AtomicU64 = AtomicU64::new(0);
fn transport_lock_skipped() -> u64 {
    #[cfg(feature = "qualification-timing")]
    {
        TRANSPORT_LOCK_SKIPPED.load(Ordering::Relaxed)
    }
    #[cfg(not(feature = "qualification-timing"))]
    {
        0
    }
}

#[cfg(all(test, feature = "qualification-timing"))]
mod transport_trace_tests {
    use super::*;
    fn collector(transport_only: bool) -> (QualificationTiming, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "transport-sparse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("timing.jsonl");
        (
            QualificationTiming::start_mode(
                Config {
                    run_id: "transport-sparse-test".into(),
                    artifact_sha3_256: "a".repeat(64),
                    node_id: "test-node".into(),
                    clock_id: "test-clock".into(),
                    output: path.clone(),
                },
                transport_only,
            )
            .unwrap(),
            path,
        )
    }
    fn values(path: PathBuf) -> Vec<serde_json::Value> {
        let result = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
        result
    }
    fn span(handle: &Handle, stage: TransportStage, queue: Option<u64>) -> TransportSpan {
        transport_span_to(
            handle.clone(),
            Instant::now(),
            stage,
            "peer-2",
            11,
            12,
            4,
            42,
            b"public-payload-for-fingerprint",
            queue,
        )
    }
    #[test]
    fn disabled_and_ordinary_mode_do_not_add_transport_work() {
        assert!(!diagnostic_mode(false, false, false));
        assert!(!diagnostic_mode(false, true, true));
        assert!(diagnostic_mode(true, false, false));
        assert!(!diagnostic_mode(true, true, false));
        assert!(diagnostic_mode(true, true, true));
        let (c, p) = collector(false);
        let h = c.handle();
        span(&h, TransportStage::Sign, None).finish(false);
        assert_eq!(
            h.metadata
                .transport_capture
                .attempts
                .load(Ordering::Relaxed),
            0
        );
        let r = c.finish();
        assert!(r.transport.is_none());
        assert_eq!(r.written, 0);
        assert!(values(p).is_empty());
    }
    #[test]
    fn late_slow_queue_and_error_survive_fast_omission_without_hashing_every_frame() {
        let (c, p) = collector(true);
        let h = c.handle();
        let cap = &h.metadata.transport_capture;
        cap.started
            .set(Instant::now() - Duration::from_secs(120))
            .unwrap();
        for a in &cap.stages {
            a.store(1, Ordering::Relaxed);
        }
        span(&h, TransportStage::Dispatch, None).finish(true); // omitted fast baseline gap
        span(&h, TransportStage::Sign, Some(250_000_000)).finish(true); // actual queue age
        let mut blocked = span(&h, TransportStage::Write, None);
        blocked.0.as_mut().unwrap().1 = Instant::now() - Duration::from_secs(43);
        blocked.finish(true); // no wall-clock sleep or network fixture
        drop(span(&h, TransportStage::Ingress, None)); // early return/error
        let r = c.finish();
        let t = r.transport.unwrap();
        assert_eq!(t.omitted_fast, 1);
        assert_eq!(t.slow, 2);
        assert_eq!(t.failed, 1);
        assert_eq!(t.retained, 3);
        assert_eq!(t.in_flight, 0);
        let v = values(p);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0]["transport"]["queue_wait_ns"], 250_000_000u64);
        assert_eq!(v[1]["transport"]["stage"], "transport-write");
        assert!(v[1]["duration_ns"].as_u64().unwrap() >= 43_000_000_000);
        assert_eq!(v[2]["phase"], "failed");
        assert_eq!(v[2]["reason"], "worker_failed");
        assert!(v
            .iter()
            .all(|x| x["transport"]["payload_fingerprint"].is_null()));
        assert!(v.iter().all(|x| x["transport"].get("payload").is_none()));
    }
    #[test]
    fn baseline_sample_is_per_stage_and_keeps_public_fingerprint_only() {
        let (c, p) = collector(true);
        let h = c.handle();
        for stage in [
            TransportStage::Dispatch,
            TransportStage::Sign,
            TransportStage::Write,
            TransportStage::ReadBody,
            TransportStage::Verify,
            TransportStage::Ingress,
        ] {
            h.metadata.transport_capture.stages[stage as usize]
                .store(TRANSPORT_SAMPLE_EVERY, Ordering::Relaxed);
            span(&h, stage, None).finish(true);
        }
        let r = c.finish();
        assert_eq!(r.written, 6);
        assert!(r.complete());
        let v = values(p);
        assert!(v.iter().all(|x| x["transport"]["sampled_baseline"] == true));
        assert!(v.iter().all(|x| x["transport"]["payload_fingerprint"]
            .as_str()
            .unwrap()
            .len()
            == 64));
        assert!(v
            .iter()
            .all(|x| !x.to_string().contains("public-payload-for-fingerprint")));
    }
    #[test]
    fn exact_window_boundary_expires_and_emits_one_bounded_snapshot() {
        let (c, p) = collector(true);
        let h = c.handle();
        h.metadata
            .transport_capture
            .started
            .set(Instant::now() - TRANSPORT_WINDOW)
            .unwrap();
        span(&h, TransportStage::Write, None).finish(true);
        span(&h, TransportStage::Verify, None).finish(true);
        let r = c.finish();
        let t = r.transport.unwrap();
        assert_eq!(t.expired, 2);
        assert_eq!(t.retained, 0);
        let v = values(p);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0]["transport"]["stage"], "transport-window-end");
        assert_eq!(v[0]["transport"]["totals"]["window_seconds"], 3600);
    }
    #[test]
    fn retention_limit_is_exact_and_marks_lost_error_records() {
        let (c, p) = collector(true);
        let h = c.handle();
        let cap = &h.metadata.transport_capture;
        for _ in 0..TRANSPORT_MAX_RETAINED {
            assert!(cap.reserve());
        }
        assert!(!cap.reserve());
        assert_eq!(cap.retained.load(Ordering::Relaxed), TRANSPORT_MAX_RETAINED);
        span(&h, TransportStage::Ingress, None).finish(false);
        let r = c.finish();
        assert_eq!(r.dropped, 1);
        assert!(!r.complete());
        assert!(values(p).is_empty());
    }
    #[test]
    fn full_collector_queue_and_closed_producer_are_visible() {
        let (c, p) = collector(true);
        let h = c.handle();
        let (sender, _receiver) = mpsc::sync_channel(0);
        let full = Handle {
            sender,
            metadata: Arc::clone(&h.metadata),
        };
        span(&full, TransportStage::Dispatch, None).finish(false);
        assert_eq!(h.metadata.dropped.load(Ordering::Relaxed), 1);
        let pending = span(&h, TransportStage::Write, None);
        let r = c.finish();
        assert_eq!(r.transport.unwrap().in_flight, 1);
        pending.finish(false);
        assert_eq!(h.metadata.dropped.load(Ordering::Relaxed), 2);
        assert!(values(p).is_empty());
    }
    #[test]
    fn busy_collector_writer_is_skipped_and_counted_without_waiting() {
        let slot = std::sync::RwLock::new(None);
        let _guard = slot.write().unwrap();
        let before = transport_lock_skipped();
        assert!(transport_handle(&slot).is_none());
        assert_eq!(transport_lock_skipped(), before + 1);
    }
    #[test]
    fn concurrent_collector_readers_preserve_evidence_without_waiting() {
        let (c, p) = collector(true);
        let h = c.handle();
        let slot = std::sync::RwLock::new(Some(h.clone()));
        let before = transport_lock_skipped();
        // Keep one reader alive while another thread clones the handle, exactly
        // the operation previously rejected by the exclusive try_lock path.
        let guard = slot.read().unwrap();
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let cloned =
                        transport_handle(&slot).expect("concurrent reader lost diagnostic handle");
                    span(&cloned, TransportStage::Write, None).finish(false);
                })
                .join()
                .unwrap();
        });
        assert_eq!(transport_lock_skipped(), before);
        drop(guard);
        drop(slot);
        drop(h);
        let r = c.finish();
        assert!(r.complete());
        assert_eq!(r.written, 1);
        assert_eq!(values(p).len(), 1);
    }
    #[test]
    fn unrelated_phases_cannot_spend_transport_only_writer_budget() {
        let (c, p) = collector(true);
        let h = c.handle();
        assert!(h.try_emit(Kind::Runtime, Phase::Start, &"b".repeat(64), None));
        span(&h, TransportStage::ReadBody, None).finish(true);
        let r = c.finish();
        assert_eq!(r.written, 1);
        assert!(r.complete());
        let v = values(p);
        assert_eq!(v.len(), 1);
        assert!(v[0].get("transport").is_some());
    }
}
