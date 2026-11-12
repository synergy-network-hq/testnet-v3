//! Production service qualification over genuine authenticated loopback TCP.
//! This fixture supplies signed Genesis authority and custody, never candidates,
//! QCs, cutoff markers, protected batches or execution material.
//! Loopback is an isolated transport fixture, not a deployable validator
//! configuration: production voting configuration still requires VPN authority.
use super::{authority, etdag, execution, identity, ingress, network, posy, storage, sync};
use aegis_pqvm::pqc::{
    kem::mlkem::mlkem1024,
    signatures::{
        fndsa::fndsa1024,
        mldsa::{mldsa65, mldsa87},
    },
};
use pqrust_traits::{
    kem::SecretKey as _,
    sign::{DetachedSignature as _, PublicKey as _, SecretKey as _},
};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use synergy_aegis::{
    AegisHashEngine, AegisPolicy, AegisSha3_256, AegisSigner, GovernedKeyBindings,
    GovernedNodeKeyBinding, KeyId, PqvmSigner, SignatureAlgorithm, SigningContext,
};
use synergy_config::*;
use synergy_etdag::{
    crypto::{IngressKemKeyRecord, IngressKemKeyRegistry, IngressKemPublicKey},
    EtdagDigest,
};
use synergy_genesis::authority::{
    AuthorityPayload, AuthorityValidator, ProtectedCutoffRelationship, ProtectedEpochPolicy,
    SignedAuthorityBinding, AUTHORITY_SIGNING_DOMAIN,
};
use synergy_identity::PublicNodeIdentity;
use synergy_node_core::{CancellationToken, ManagedService, ServiceHealth};
use synergy_posy::{
    FinalizedBlockRecord, FrozenValidatorRegistry, SimplifiedEpochContext,
    SimplifiedFinalityParent, ValidatorRecord, ValidatorStatus,
};
use synergy_protocol_types::{NodeAddress, NodeRole};

#[path = "socket_qualification_tps.rs"]
mod exploratory_tps;

/// Reservations belong to the complete native fixture, not to an individual
/// service lifetime. A restart receives the identical bound socket, never a
/// released ephemeral port. Exported process fixtures do not use this adapter.
#[derive(Clone)]
struct FixtureListeners {
    network: Arc<Vec<synergy_network::transport::TcpListenerService>>,
    rpc: Arc<TcpListener>,
}
impl FixtureListeners {
    fn bind() -> Self {
        let timeouts = synergy_network::transport::TransportTimeouts {
            connect: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
            read: Duration::from_secs(60),
            write: Duration::from_secs(60),
        };
        Self {
            network: Arc::new(vec![synergy_network::transport::TcpListenerService::bind(
                "127.0.0.1:0",
                timeouts,
            )
            .unwrap()]),
            rpc: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
        }
    }
}

#[test]
fn fixture_listener_reservations_hold_setup_ports_and_multiple_fixtures_cannot_collide() {
    let first = FixtureListeners::bind();
    let second = FixtureListeners::bind();
    let addresses = [
        first.network[0].local_addr().unwrap(),
        first.rpc.local_addr().unwrap(),
        second.network[0].local_addr().unwrap(),
        second.rpc.local_addr().unwrap(),
    ];
    assert_eq!(
        addresses
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4
    );
    let handed_off = first.clone();
    drop(first);
    for address in addresses {
        assert!(TcpListener::bind(address).is_err());
    }
    drop(handed_off);
    assert!(TcpListener::bind(addresses[0]).is_ok());
    assert!(TcpListener::bind(addresses[1]).is_ok());
}

struct Node {
    configuration: NodeConfiguration,
    ingress: ingress::AuthenticatedIngress,
    services: Vec<(&'static str, Box<dyn ManagedService>)>,
    polls: u64,
    _sync_diagnostic_preparation: Option<super::preparation::Pool>,
    wallet_admission: Option<super::protected_admission::AdmissionHandle>,
}
impl Node {
    fn open(configuration: NodeConfiguration, listeners: &FixtureListeners) -> Self {
        Self::open_with_wallet(configuration, None, listeners)
    }
    fn open_with_wallet(
        configuration: NodeConfiguration,
        wallet_admission: Option<super::protected_admission::AdmissionHandle>,
        listeners: &FixtureListeners,
    ) -> Self {
        Self::open_with_wallet_budget(
            configuration,
            wallet_admission,
            listeners,
            synergy_state::world_resources::WorldResourceBudget::new(64 * 1024 * 1024),
            false,
            None,
        )
    }
    fn open_with_wallet_budget(
        mut configuration: NodeConfiguration,
        wallet_admission: Option<super::protected_admission::AdmissionHandle>,
        listeners: &FixtureListeners,
        budget: Arc<synergy_state::world_resources::WorldResourceBudget>,
        threaded: bool,
        held_handoff: Option<(u64, u64)>,
    ) -> Self {
        if configuration.apqe_transport.is_some() {
            configuration.validate().unwrap();
        } else {
            let validation = configuration.validate().unwrap_err().to_string();
            assert!(
                validation.contains("vpn.mode"),
                "unexpected fixture configuration rejection: {validation}"
            );
        }
        let authority = setup_step(
            &format!("{} load signed authority", configuration.node_name),
            || authority::load(&configuration).unwrap().unwrap(),
        );
        let ingress = ingress::AuthenticatedIngress::with_world_budget(budget);
        ingress.hold_processing_handoff(held_handoff).unwrap();
        // Register every owner before starting any: PoSy restores durable VC
        // authority before ETDAG opens its retained collecting targets.
        let identity = setup_step(
            &format!("{} register identity", configuration.node_name),
            || {
                identity::registration(&configuration.public_identity_path, configuration.role)
                    .unwrap()
                    .1
            },
        );
        let storage = setup_step(
            &format!("{} register storage", configuration.node_name),
            || storage::registration(&configuration.storage).unwrap().1,
        );
        let network = setup_step(
            &format!("{} register network", configuration.node_name),
            || {
                network::registration_with_reserved_listeners(
                    &configuration,
                    ingress.clone(),
                    Arc::clone(&listeners.network),
                )
                .unwrap()
                .1
            },
        );
        // Opt-in diagnostics exercise the production background preparation
        // paths. Keep the historical synchronous adapters as fixture defaults.
        let native_consensus_preparation =
            std::env::var_os("POSY_TPS_NATIVE_PREPARATION").is_some_and(|v| v == "1");
        let sync_diagnostic_preparation = (native_consensus_preparation
            || std::env::var_os("SYNERGY_SYNC_DIAGNOSTIC_NATIVE_PREPARATION")
                .is_some_and(|v| v == "1"))
        .then(|| super::preparation::Pool::new().unwrap());
        let sync = setup_step(
            &format!("{} register sync", configuration.node_name),
            || {
                sync::registration_with_preparation(
                    &configuration,
                    Some(Arc::clone(&authority)),
                    authority::AuthorityTransitionSignal::default(),
                    ingress.clone(),
                    sync_diagnostic_preparation
                        .as_ref()
                        .map(|pool| pool.handle()),
                )
                .unwrap()
                .1
            },
        );
        let etdag = setup_step(
            &format!("{} register etdag", configuration.node_name),
            || {
                etdag::registration_with_admission(
                    &configuration,
                    Arc::clone(&authority),
                    ingress.clone(),
                    wallet_admission.clone(),
                )
                .unwrap()
                .1
            },
        );
        let execution = setup_step(
            &format!("{} register execution", configuration.node_name),
            || {
                execution::registration(&configuration, Arc::clone(&authority), ingress.clone())
                    .unwrap()
                    .1
            },
        );
        let posy = setup_step(
            &format!("{} register posy", configuration.node_name),
            || {
                posy::registration_with_preparation(
                    &configuration,
                    authority,
                    ingress.clone(),
                    native_consensus_preparation.then(|| {
                        sync_diagnostic_preparation
                            .as_ref()
                            .expect("created pool")
                            .handle()
                    }),
                )
                .unwrap()
                .1
            },
        );
        let rpc = if let Some(handle) = wallet_admission.clone() {
            let address = listeners.rpc.local_addr().unwrap();
            configuration.rpc.enabled = true;
            configuration.rpc.listen_address = Some(address);
            let runtime = Arc::new(std::sync::RwLock::new(synergy_node_core::RuntimeSnapshot {
                node_name: configuration.node_name.clone(),
                role: "validator".into(),
                chain_id: 1266,
                lifecycle: synergy_node_core::NodeLifecycleState::Starting,
                services: Vec::new(),
            }));
            Some(
                super::rpc::registration_with_reserved_admission_listener(
                    &configuration.rpc,
                    runtime,
                    Arc::new(
                        super::rpc::CanonicalQueryStore::load_with_world_budget(
                            configuration.storage.data_directory.clone(),
                            Arc::clone(ingress.world_budget()),
                        )
                        .unwrap(),
                    ),
                    Arc::new(synergy_ws::server::WsServer::new(16, 16, 1024 * 1024).unwrap()),
                    Some(handle),
                    Arc::clone(&listeners.rpc),
                )
                .unwrap()
                .1,
            )
        } else {
            None
        };
        let mut node = Self {
            configuration,
            ingress,
            polls: 0,
            _sync_diagnostic_preparation: sync_diagnostic_preparation,
            wallet_admission,
            services: vec![
                ("identity", identity),
                ("storage", storage),
                ("network", network),
                ("sync", sync),
                ("etdag", etdag),
                ("execution", execution),
                ("posy", posy),
            ],
        };
        if let Some(rpc) = rpc {
            node.services.push(("rpc", rpc));
        }
        if threaded {
            // Use the actual production owner wrapper for asynchronous timing:
            // expensive cryptography must not stall the fixture's PoSy poll.
            node.services = std::mem::take(&mut node.services)
                .into_iter()
                .map(|(name, service)| {
                    (
                        name,
                        Box::new(super::owned_service::OwnedService::new(service, name))
                            as Box<dyn ManagedService>,
                    )
                })
                .collect();
        }
        let cancellation = CancellationToken::default();
        for (name, service) in &mut node.services {
            setup_step(
                &format!("{} start {name}", node.configuration.node_name),
                || {
                    service
                        .start(&cancellation)
                        .unwrap_or_else(|e| panic!("start {name}: {e}"))
                },
            );
        }
        node
    }
    fn poll(&mut self) {
        self.poll_before_sync(|_| {});
    }
    fn poll_before_sync(&mut self, before_sync: impl FnMut(&ingress::AuthenticatedIngress)) {
        self.poll_selected_owners(before_sync, false);
    }
    fn poll_selected_owners(
        &mut self,
        mut before_sync: impl FnMut(&ingress::AuthenticatedIngress),
        pause_execution: bool,
    ) {
        for (name, service) in &mut self.services {
            if pause_execution && *name == "execution" {
                continue;
            }
            if *name == "sync" {
                before_sync(&self.ingress);
            }
            if self.polls == 0 {
                eprintln!(
                    "socket qualification: {} first poll {name}",
                    self.configuration.node_name
                );
            }
            let started = Instant::now();
            service
                .poll()
                .unwrap_or_else(|e| panic!("{} {name} poll: {e}", self.configuration.node_name));
            if started.elapsed() >= Duration::from_secs(1) {
                eprintln!(
                    "socket qualification: {} poll {name} took {:?}",
                    self.configuration.node_name,
                    started.elapsed()
                );
            }
            assert!(
                !matches!(service.health(), ServiceHealth::Unhealthy { .. }),
                "{} {name}: {:?}",
                self.configuration.node_name,
                service.health()
            );
        }
        self.polls += 1;
    }
    fn stop(&mut self) {
        for (name, service) in self.services.iter_mut().rev() {
            setup_step(
                &format!("{} stop {name}", self.configuration.node_name),
                || {
                    service
                        .stop()
                        .unwrap_or_else(|e| panic!("stop {name}: {e}"))
                },
            );
        }
        self.services.clear();
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Preserve the original assertion/owner failure instead of
            // aborting on the same poisoned owner again during unwinding.
            for (name, service) in self.services.iter_mut().rev() {
                if let Err(error) = service.stop() {
                    eprintln!("socket qualification cleanup {name}: {error}");
                }
            }
            self.services.clear();
            return;
        }
        if !self.services.is_empty() {
            self.stop();
        }
    }
}
struct SocketFleet {
    root: PathBuf,
    nodes: Vec<Option<Node>>,
    ids: Vec<String>,
    listeners: Vec<FixtureListeners>,
}
impl Drop for SocketFleet {
    fn drop(&mut self) {
        let retain = std::thread::panicking()
            && std::env::var_os("SYNERGY_SOCKET_RETAIN_FAILED_FIXTURE").is_some_and(|v| v == "1");
        if retain {
            // Disposable native fixture custody stays under its existing0700
            // root. Save only configuration/path references, never key bytes.
            for (index, node) in self.nodes.iter().enumerate() {
                if let Some(node) = node {
                    let path = self.root.join(format!("diagnostic-node-{index}.json"));
                    if let Err(error) = serde_json::to_vec_pretty(&node.configuration)
                        .map_err(|error| error.to_string())
                        .and_then(|bytes| fs::write(path, bytes).map_err(|error| error.to_string()))
                    {
                        eprintln!("socket diagnostic config preservation failed: {error}");
                    }
                }
            }
        }
        self.nodes.clear();
        if retain {
            eprintln!("SOCKET_FAILED_FIXTURE_RETAINED {} purpose=immediate-terminal-sync-diagnosis cleanup=remove-this-exact-disposable-root-after-diagnosis",self.root.display());
        } else {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}
fn setup_step<T>(label: &str, operation: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    eprintln!("socket qualification: begin {label}");
    let result = operation();
    eprintln!(
        "socket qualification: completed {label} in {:?}",
        started.elapsed()
    );
    result
}
// The provider performs rejection-sampled native key generation. A test-only
// deadline isolates a stuck provider without changing its cryptographic output.
fn bounded_keypair<T: Send + 'static>(
    label: String,
    operation: impl FnOnce() -> T + Send + 'static,
) -> T {
    setup_step(&label, || {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _ = sender.send(operation());
        });
        let result = receiver
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|e| {
                panic!("key generation {label} did not complete within 60 seconds: {e}")
            });
        worker.join().expect("key generation worker panicked");
        result
    })
}
fn operational_fingerprint(public: &[u8]) -> String {
    let length = (public.len() as u64).to_be_bytes();
    AegisSha3_256
        .sha3_256_segments(&[b"SYNERGY_KEY_FINGERPRINT_V1", &length, public])
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn write_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn secret(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn digest(label: &str) -> EtdagDigest {
    EtdagDigest::from_domain_bytes("socket-qualification", label.as_bytes())
}
impl SocketFleet {
    fn new() -> Self {
        Self::with_world_state(synergy_state::WorldState::default())
    }
    fn with_world_state(initial_world_state: synergy_state::WorldState) -> Self {
        Self::with_wallet_world_state(initial_world_state, false)
    }
    fn with_wallet_world_state(
        initial_world_state: synergy_state::WorldState,
        wallet: bool,
    ) -> Self {
        Self::with_wallet_world_state_provider(initial_world_state, wallet, None)
    }
    fn with_wallet_world_state_provider(
        initial_world_state: synergy_state::WorldState,
        wallet: bool,
        provider: Option<synergy_config::ApqeProviderConfiguration>,
    ) -> Self {
        Self::with_wallet_world_state_profile(initial_world_state, wallet, provider, false, None)
    }
    fn with_wallet_world_state_profile(
        initial_world_state: synergy_state::WorldState,
        wallet: bool,
        provider: Option<synergy_config::ApqeProviderConfiguration>,
        processing_profile: bool,
        epoch_end_height: Option<u64>,
    ) -> Self {
        let mut prepared = prepare_socket_fixture_profile_provider(
            initial_world_state,
            None,
            processing_profile,
            epoch_end_height,
            provider.as_ref(),
        );
        for configuration in &mut prepared.configurations {
            configuration.aegis_provider = provider.clone();
        }
        let nodes = prepared
            .configurations
            .into_iter()
            .enumerate()
            .map(|(index, configuration)| {
                Some(Node::open_with_wallet(
                    configuration,
                    wallet.then(super::protected_admission::AdmissionHandle::default),
                    &prepared.listeners[index],
                ))
            })
            .collect();
        let fleet = Self {
            root: prepared.root,
            nodes,
            ids: prepared.ids,
            listeners: prepared.listeners,
        };
        fleet.dial_mesh();
        eprintln!("socket qualification: mesh dial requests queued");
        fleet
    }
    fn dial_mesh(&self) {
        for (i, node) in self.nodes.iter().enumerate() {
            if let Some(node) = node {
                for (j, other) in self.nodes.iter().enumerate() {
                    if j > i {
                        if let Some(other) = other {
                            node.ingress
                                .request_dial(ingress::DialRequest {
                                    peer_id: self.ids[j].clone(),
                                    address: other.configuration.network.listen_addresses[0],
                                })
                                .unwrap();
                        }
                    }
                }
            }
        }
    }
    fn advance(&mut self, height: u64) {
        self.advance_with_peer_redial(height, None);
    }
    fn advance_with_peer_redial(&mut self, height: u64, redial_peer: Option<usize>) {
        let mut next_redial = Instant::now();
        let projection_stages = posy::sync_projection_stages();
        let started = Instant::now();
        let minimum_finalized = |fleet: &Self| {
            fleet
                .nodes
                .iter()
                .flatten()
                .map(|node| {
                    node.ingress
                        .latest_finality()
                        .unwrap()
                        .map(|record| record.height)
                        .unwrap_or(0)
                })
                .min()
                .expect("qualification fleet has no online validators")
        };
        let mut progressed_height = minimum_finalized(self);
        let overall_seconds = height
            .saturating_sub(progressed_height)
            .saturating_mul(15)
            .max(180);
        let deadline = started + Duration::from_secs(overall_seconds);
        let mut last_progress = started;
        let mut next_report = started;
        let mut next_execution_check = started;
        let mut execution_progress = 0;
        eprintln!("socket qualification: advancing to finalized H{height}");
        loop {
            if let Some(index) = redial_peer {
                if Instant::now() >= next_redial {
                    redial_missing_socket_peers(self, index);
                    next_redial = Instant::now() + Duration::from_secs(5);
                }
            }
            for node in self.nodes.iter_mut().flatten() {
                node.poll();
            }
            let minimum = minimum_finalized(self);
            if minimum > progressed_height {
                progressed_height = minimum;
                last_progress = Instant::now();
            }
            assert!(last_progress.elapsed() < Duration::from_secs(60),
                "socket fleet has made no matching finality progress for 60s while advancing to H{height}; slowest online validator finalized H{progressed_height}");
            if Instant::now() >= next_report {
                for node in self.nodes.iter().flatten() {
                    let finalized = node
                        .ingress
                        .latest_finality()
                        .unwrap()
                        .map(|r| r.height)
                        .unwrap_or(0);
                    let vcs = (finalized + 1..=finalized + 3)
                        .map(|h| (h, node.ingress.proposal_validation(h).unwrap().is_some()))
                        .collect::<Vec<_>>();
                    let cuts = (finalized + 3..=finalized + 5)
                        .map(|h| {
                            (
                                h,
                                node.ingress
                                    .protected_cutoff_authority(h)
                                    .unwrap()
                                    .is_some(),
                                node.ingress.protected_commitments(h).unwrap().is_some(),
                            )
                        })
                        .collect::<Vec<_>>();
                    eprintln!("socket qualification: {} elapsed {:?}, finalized H{finalized}, authenticated peers {}, VCs {:?}, cutoff/batch {:?}", node.configuration.node_name, started.elapsed(), node.ingress.authenticated_peers().unwrap().len(), vcs, cuts);
                    for (name, service) in &node.services {
                        if !matches!(service.health(), ServiceHealth::Healthy) {
                            eprintln!(
                                "socket qualification: {} {name} health {:?}",
                                node.configuration.node_name,
                                service.health()
                            );
                        }
                    }
                }
                next_report = Instant::now() + Duration::from_secs(10);
            }
            if minimum >= height && Instant::now() >= next_execution_check {
                let durable_minimum = self
                    .nodes
                    .iter()
                    .flatten()
                    .map(|node| {
                        let layout = synergy_storage::NodeStorageLayout::new(
                            node.configuration.storage.data_directory.clone(),
                        )
                        .unwrap();
                        synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
                            .unwrap()
                            .current()
                            .map(|state| state.finalized_height)
                            .unwrap_or(0)
                    })
                    .min()
                    .unwrap();
                if durable_minimum > execution_progress {
                    execution_progress = durable_minimum;
                    last_progress = Instant::now();
                    eprintln!("socket qualification: safety finality reached H{height}; slowest durable Execution now H{durable_minimum}");
                }
                if durable_minimum >= height {
                    break;
                }
                next_execution_check = Instant::now() + Duration::from_millis(250);
            }
            assert!(
                Instant::now() < deadline,
                "socket finality H{height} exceeded {overall_seconds}s overall bound: {:?}",
                self.nodes
                    .iter()
                    .flatten()
                    .map(|n| (
                        n.configuration.node_name.clone(),
                        n.ingress.latest_finality().unwrap(),
                        n.ingress.authenticated_peers().unwrap()
                    ))
                    .collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let records: Vec<FinalizedBlockRecord> = self
            .nodes
            .iter()
            .flatten()
            .map(|node| node.ingress.finalized_record(height).unwrap().unwrap())
            .collect();
        eprintln!(
            "authenticated socket fleet: matching finalized H{height} across {} online validators",
            records.len()
        );
        eprintln!(
            "authenticated socket fleet: {} full Sync projection stages while advancing to H{height}",
            posy::sync_projection_stages() - projection_stages
        );
        for record in records.iter().skip(1) {
            assert_eq!(record, &records[0], "different finalized record H{height}");
        }
        let mut states = Vec::new();
        for node in self.nodes.iter().flatten() {
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let store =
                synergy_state::FinalizedStateStore::load(layout.state().join("execution")).unwrap();
            let commitment = store
                .history_at(height)
                .unwrap()
                .expect("requested durable finalized commitment absent");
            assert_eq!(commitment.finalized_block_id, records[0].block_id);
            let world = store
                .world_state_at(height)
                .unwrap()
                .expect("requested durable finalized world state absent");
            states.push((commitment, world));
        }
        for state in states.iter().skip(1) {
            assert_eq!(
                state, &states[0],
                "different durable finalized execution state H{height}"
            );
        }
        eprintln!("socket qualification: exact durable Execution commitment and world state match H{height} across {} validators", states.len());
    }
}
#[test]
fn authenticated_socket_protected_finality_and_restart_rejoin() {
    let mut fleet = SocketFleet::new();
    fleet.advance(6);
    fleet.advance(70); // Cross ingress/material/reliable-delivery retention bounds.
    let mut removed = fleet.nodes[4].take().unwrap();
    let configuration = removed.configuration.clone();
    removed.stop();
    drop(removed);
    fleet.advance(74); // Four validators preserve the full governed quorum.
    fleet.nodes[4] = Some(Node::open(configuration, &fleet.listeners[4]));
    // Restarted node initiates its own fresh authenticated connections.
    let restarted = fleet.nodes[4].as_ref().unwrap();
    for i in 0..4 {
        restarted
            .ingress
            .request_dial(ingress::DialRequest {
                peer_id: fleet.ids[i].clone(),
                address: fleet.nodes[i]
                    .as_ref()
                    .unwrap()
                    .configuration
                    .network
                    .listen_addresses[0],
            })
            .unwrap();
    }
    fleet.advance(80);
}

#[test]
fn authenticated_snapshot_is_built_only_on_request_from_durable_restart_state() {
    use synergy_protocol_types::{AuthenticatedPeer, SessionId};
    use synergy_sync::{SnapshotChunkRequest, SyncWireMessage};
    let mut fleet = SocketFleet::new();
    fleet.advance(6);
    let configuration = fleet.nodes[0].as_ref().unwrap().configuration.clone();
    let layout =
        synergy_storage::NodeStorageLayout::new(configuration.storage.data_directory.clone())
            .unwrap();
    let snapshot_root = layout.state().join("snapshots");
    assert!(
        !snapshot_root.join("chunk").exists(),
        "steady-state finality must not produce snapshots"
    );
    let record = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .ingress
        .finalized_record(6)
        .unwrap()
        .unwrap();
    fleet.nodes[0].as_mut().unwrap().stop();
    fleet.nodes[0] = Some(Node::open(configuration.clone(), &fleet.listeners[0]));
    let node = fleet.nodes[0].as_mut().unwrap();
    let peer = AuthenticatedPeer::new(fleet.ids[1].clone(), SessionId(9999), vec![]).unwrap();
    node.ingress
        .admit_session(fleet.ids[1].clone(), peer.session_id)
        .unwrap();
    let authority = authority::load(&configuration).unwrap().unwrap();
    let request = SnapshotChunkRequest {
        epoch: authority.epoch.epoch,
        height: 6,
        finalized_block_id: record.block_id.clone(),
        finality_evidence_id: record.finality_certificate_id.clone(),
        expected_snapshot_root: None,
        index: 0,
    };
    let mut wrong = request.clone();
    wrong.finality_evidence_id = "wrong-finality".into();
    node.ingress
        .submit_snapshot_chunk_request(peer.clone(), wrong)
        .unwrap();
    node.services
        .iter_mut()
        .find(|(name, _)| *name == "sync")
        .unwrap()
        .1
        .poll()
        .unwrap();
    assert!(
        !snapshot_root.join("chunk").exists(),
        "foreign context must not generate a snapshot"
    );
    let pressure = node
        .ingress
        .world_budget()
        .reserve(node.ingress.world_budget().available())
        .unwrap();
    node.ingress
        .submit_snapshot_chunk_request(peer.clone(), request.clone())
        .unwrap();
    node.services
        .iter_mut()
        .find(|(name, _)| *name == "sync")
        .unwrap()
        .1
        .poll()
        .expect("temporary World pressure must defer snapshot serving without failing Sync");
    assert!(
        !snapshot_root.join("chunk").exists(),
        "pressure must not publish a partial snapshot"
    );
    drop(pressure);
    node.ingress
        .submit_snapshot_chunk_request(peer.clone(), request.clone())
        .unwrap();
    let mut received = None;
    for _ in 0..16 {
        node.services
            .iter_mut()
            .find(|(name, _)| *name == "sync")
            .unwrap()
            .1
            .poll()
            .unwrap();
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if let Ok(SyncWireMessage::SnapshotChunkResponse(response)) =
                serde_json::from_slice::<SyncWireMessage>(&frame.payload)
            {
                received = Some(response);
            }
        }
        if received.is_some() {
            break;
        }
    }
    let response = received.expect("exact durable snapshot must remain available after restart");
    assert_eq!(response.request, request);
    synergy_snapshot::verify_snapshot_manifest(authority.as_ref(), &response.manifest).unwrap();
    synergy_snapshot::verify_snapshot(
        &synergy_crypto::AegisSha3_256,
        authority.as_ref(),
        &response.manifest,
        std::slice::from_ref(&response.chunk),
    )
    .unwrap();
    let world: synergy_state::WorldState = serde_json::from_slice(&response.chunk.bytes).unwrap();
    assert_eq!(
        synergy_state::state_root(&world).unwrap(),
        response.manifest.application_state_root
    );
    assert_eq!(response.manifest.finalized_block_id, record.block_id);
    assert!(snapshot_root.join("chunk").exists());
    let fetch = |node: &mut Node, request: &SnapshotChunkRequest| {
        node.ingress
            .submit_snapshot_chunk_request(peer.clone(), request.clone())
            .unwrap();
        node.services
            .iter_mut()
            .find(|(name, _)| *name == "sync")
            .unwrap()
            .1
            .poll()
            .unwrap();
        while let Some(frame) = node.ingress.take_outbound().unwrap() {
            if let Ok(SyncWireMessage::SnapshotChunkResponse(response)) =
                serde_json::from_slice::<SyncWireMessage>(&frame.payload)
            {
                return Some(response);
            }
        }
        None
    };
    let exact_request = |height: u64| {
        let finality = authority::load(&configuration).unwrap().unwrap();
        let record = synergy_posy::persistence::FinalityStore::new(layout.consensus().join("posy"))
            .unwrap()
            .get(height)
            .unwrap()
            .unwrap();
        SnapshotChunkRequest {
            epoch: finality.epoch.epoch,
            height,
            finalized_block_id: record.block_id,
            finality_evidence_id: record.finality_certificate_id,
            expected_snapshot_root: None,
            index: 0,
        }
    };
    for height in 1..=3 {
        let cached = fetch(node, &exact_request(height))
            .expect("retained finalized history must build exact snapshots");
        synergy_snapshot::verify_snapshot(
            &synergy_crypto::AegisSha3_256,
            authority.as_ref(),
            &cached.manifest,
            &[cached.chunk],
        )
        .unwrap();
    }
    let pressured = exact_request(4);
    assert!(
        fetch(node, &pressured).is_none(),
        "live outgoing leases must apply cache backpressure"
    );
    assert_eq!(
        fs::read_dir(snapshot_root.join("manifest-index"))
            .unwrap()
            .count(),
        4
    );
    // Wait for the existing10-second cache leases; product response timeouts stay unchanged.
    std::thread::sleep(Duration::from_secs(11));
    let cached = fetch(node, &pressured).expect("expired cache lease must permit eviction");
    synergy_snapshot::verify_snapshot(
        &synergy_crypto::AegisSha3_256,
        authority.as_ref(),
        &cached.manifest,
        &[cached.chunk],
    )
    .unwrap();
    let rebuilt =
        fetch(node, &request).expect("evicted snapshot must rebuild from verified durable state");
    assert_eq!(rebuilt.chunk, response.chunk);
    assert_eq!(rebuilt.manifest.state_root, response.manifest.state_root);
    assert_eq!(
        rebuilt.manifest.application_state_root,
        response.manifest.application_state_root
    );
    synergy_snapshot::verify_snapshot(
        &synergy_crypto::AegisSha3_256,
        authority.as_ref(),
        &rebuilt.manifest,
        &[rebuilt.chunk],
    )
    .unwrap();
    assert_eq!(
        fs::read_dir(snapshot_root.join("manifest-index"))
            .unwrap()
            .count(),
        4
    );
}

#[test]
fn authenticated_socket_focused_restart_rejoin() {
    let mut fleet = SocketFleet::new();
    fleet.advance(6);
    let mut removed = fleet.nodes[4].take().unwrap();
    let configuration = removed.configuration.clone();
    removed.stop();
    drop(removed);
    fleet.advance(10);
    fleet.nodes[4] = Some(Node::open(configuration, &fleet.listeners[4]));
    let restarted = fleet.nodes[4].as_ref().unwrap();
    for i in 0..4 {
        restarted
            .ingress
            .request_dial(ingress::DialRequest {
                peer_id: fleet.ids[i].clone(),
                address: fleet.nodes[i]
                    .as_ref()
                    .unwrap()
                    .configuration
                    .network
                    .listen_addresses[0],
            })
            .unwrap();
    }
    fleet.advance(16);
}

/// Genuine quorum-subset variants retain the first accepted timeout authority.
#[test]
fn genuine_timeout_quorum_subsets_share_closure_but_differ_in_carry() {
    use synergy_posy::{
        block_vote_signing_bytes, timeout_vote_signing_bytes, BlockVote, CertifiedCandidateSubject,
        ConsensusObjectContext, SimplifiedConsensusStateMachine, SimplifiedQuorumCertificate,
        SimplifiedTimeoutCertificate, TimeoutVote, POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
    };
    let prepared = prepare_socket_fixture(synergy_state::WorldState::default(), None);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let context = ConsensusObjectContext::for_height(&authority.epoch, 1, 0).unwrap();
    let candidate = CertifiedCandidateSubject::new(
        context.clone(),
        "subset-qualified-candidate".into(),
        authority.anchor_parent.block_id().into(),
        authority.anchor_parent.clone(),
        "e".repeat(64),
    )
    .unwrap();
    let reports = (0..5)
        .map(|index| {
            let mut report = TimeoutVote {
                context: context.clone(),
                lease_index: authority.epoch.lease_index(1).unwrap(),
                timed_out_proposer: authority.epoch.authorized_proposer(1, 0).unwrap().into(),
                highest_parent: authority.anchor_parent.clone(),
                previous_tc_id: None,
                last_voted_candidate: (index < 2).then(|| candidate.clone()),
                validator_id: prepared.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: Vec::new(),
            };
            report.signature = fixture_sign(
                &fs::read(prepared.root.join(format!("node-{index}/consensus.key"))).unwrap(),
                SignatureAlgorithm::MlDsa65,
                &report.key_id,
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                Some(1),
                &timeout_vote_signing_bytes(&report).unwrap(),
            );
            report
        })
        .collect::<Vec<_>>();
    let carry = SimplifiedTimeoutCertificate::from_votes(reports[..4].to_vec()).unwrap();
    let no_carry = SimplifiedTimeoutCertificate::from_votes(reports[1..].to_vec()).unwrap();
    for proof in [&carry, &no_carry] {
        proof
            .verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
    }
    assert_eq!(carry.id().unwrap(), no_carry.id().unwrap());
    assert_eq!(
        carry.highest_parent().unwrap(),
        no_carry.highest_parent().unwrap()
    );
    assert_eq!(
        carry.mandatory_carry_candidate().unwrap(),
        Some(candidate.clone())
    );
    assert_eq!(no_carry.mandatory_carry_candidate().unwrap(), None);
    for (first, second) in [(&carry, &no_carry), (&no_carry, &carry)] {
        let mut machine = SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        machine
            .accept_timeout_certificate(first.clone(), authority.as_ref())
            .unwrap();
        let before = (
            machine.active_slot(),
            machine.highest_parent().clone(),
            machine.locked_qc().cloned(),
            machine.last_finalized().cloned(),
            machine.active_mandatory_carry().cloned(),
        );
        let error = machine
            .accept_timeout_certificate(second.clone(), authority.as_ref())
            .unwrap_err();
        if first.mandatory_carry_candidate().unwrap().is_some() {
            assert!(!matches!(&error, synergy_posy::PosyError::Conflict(_)));
            assert!(error.to_string().contains("weaker duplicate timeout proof"));
            assert!(machine
                .accepted_timeout_certificates()
                .next()
                .unwrap()
                .matches_certificate(first)
                .unwrap());
        } else {
            assert!(!matches!(&error, synergy_posy::PosyError::Conflict(_)));
            assert!(error
                .to_string()
                .contains("stronger live duplicate timeout proof"));
        }
        assert_eq!(
            (
                machine.active_slot(),
                machine.highest_parent().clone(),
                machine.locked_qc().cloned(),
                machine.last_finalized().cloned(),
                machine.active_mandatory_carry().cloned(),
            ),
            before
        );
        assert!(machine
            .accepted_timeout_certificates()
            .next()
            .unwrap()
            .matches_certificate(first)
            .unwrap());
    }
    // Exercise every four-of-five subset in both arrival orders. A threshold
    // difference never replaces the first admitted timeout authority.
    let subsets = (0..5)
        .map(|omitted| {
            SimplifiedTimeoutCertificate::from_votes(
                reports
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != omitted)
                    .map(|(_, report)| report.clone())
                    .collect(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    for first in &subsets {
        for second in &subsets {
            let mut machine = SimplifiedConsensusStateMachine::new(
                authority.epoch.clone(),
                authority.registry.clone(),
                authority.anchor_parent.clone(),
            )
            .unwrap();
            machine
                .accept_timeout_certificate(first.clone(), authority.as_ref())
                .unwrap();
            let before = (
                machine.active_slot(),
                machine.highest_parent().clone(),
                machine.locked_qc().cloned(),
                machine.active_mandatory_carry().cloned(),
            );
            let result = machine.accept_timeout_certificate(second.clone(), authority.as_ref());
            if first.mandatory_carry_candidate().unwrap()
                == second.mandatory_carry_candidate().unwrap()
            {
                assert!(result.unwrap().is_empty());
            } else {
                assert!(matches!(result, Err(synergy_posy::PosyError::Invalid(_))));
            }
            assert_eq!(
                (
                    machine.active_slot(),
                    machine.highest_parent().clone(),
                    machine.locked_qc().cloned(),
                    machine.active_mandatory_carry().cloned(),
                ),
                before
            );
            assert!(machine
                .accepted_timeout_certificates()
                .next()
                .unwrap()
                .matches_certificate(first)
                .unwrap());
        }
    }
    // A stronger variant is redundant only after the exact carried subject
    // is independently certified at the now-historical height.
    for first in [&carry, &no_carry] {
        let mut machine = SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        machine
            .accept_timeout_certificate(first.clone(), authority.as_ref())
            .unwrap();
        let votes = (0..4)
            .map(|index| {
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, 1, 1).unwrap(),
                    block_id: candidate.block_id.clone(),
                    parent_block_id: candidate.parent_block_id.clone(),
                    parent: candidate.parent.clone(),
                    takeover_tc_id: Some(first.id().unwrap()),
                    protected_execution_root: candidate.protected_execution_root.clone(),
                    validator_id: prepared.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: Vec::new(),
                };
                vote.signature = fixture_sign(
                    &fs::read(prepared.root.join(format!("node-{index}/consensus.key"))).unwrap(),
                    SignatureAlgorithm::MlDsa65,
                    &vote.key_id,
                    synergy_posy::POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    Some(1),
                    &block_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        assert_eq!(qc.subject().unwrap(), candidate);
        machine
            .accept_quorum_certificate(qc, authority.as_ref())
            .unwrap();
        let before = (
            machine.active_slot(),
            machine.highest_parent().clone(),
            machine.locked_qc().cloned(),
            machine.last_finalized().cloned(),
        );
        if first.mandatory_carry_candidate().unwrap().is_none() {
            assert!(machine
                .accept_timeout_certificate(carry.clone(), authority.as_ref())
                .unwrap()
                .is_empty());
        } else {
            let error = machine
                .accept_timeout_certificate(no_carry.clone(), authority.as_ref())
                .unwrap_err();
            assert!(!matches!(error, synergy_posy::PosyError::Conflict(_)));
        }
        assert_eq!(
            (
                machine.active_slot(),
                machine.highest_parent().clone(),
                machine.locked_qc().cloned(),
                machine.last_finalized().cloned()
            ),
            before
        );
        assert!(machine
            .accepted_timeout_certificates()
            .next()
            .unwrap()
            .matches_certificate(first)
            .unwrap());
    }
    // A shared signer cannot change its authenticated subject under cover of
    // the weaker-subset classification, even when both bundles verify.
    let mut contradictory = no_carry.reports.clone();
    let changed = contradictory
        .iter_mut()
        .find(|r| r.validator_id == prepared.ids[1])
        .unwrap();
    changed.last_voted_candidate = None;
    changed.signature = fixture_sign(
        &fs::read(prepared.root.join("node-1/consensus.key")).unwrap(),
        SignatureAlgorithm::MlDsa65,
        &changed.key_id,
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
        Some(1),
        &timeout_vote_signing_bytes(changed).unwrap(),
    );
    let contradictory = SimplifiedTimeoutCertificate::from_votes(contradictory).unwrap();
    contradictory
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    let mut machine = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    machine
        .accept_timeout_certificate(carry.clone(), authority.as_ref())
        .unwrap();
    let before = machine.active_slot();
    let error = machine
        .accept_timeout_certificate(contradictory, authority.as_ref())
        .unwrap_err();
    assert!(matches!(&error, synergy_posy::PosyError::Conflict(_)));
    assert!(error.to_string().contains("contradictory signed report"));
    assert_eq!(machine.active_slot(), before);
    assert!(machine
        .accepted_timeout_certificates()
        .next()
        .unwrap()
        .matches_certificate(&carry)
        .unwrap());
    fs::remove_dir_all(prepared.root).unwrap();
}

#[test]
fn consensus_signature_cache_preserves_genuine_qc_variants_and_rejects_tampering() {
    use synergy_posy::{
        block_vote_signing_bytes, BlockVote, ConsensusObjectContext, ConsensusSignatureVerifier,
        SimplifiedQuorumCertificate, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
    };
    let fleet = SocketFleet::new();
    let configuration = &fleet.nodes[0].as_ref().unwrap().configuration;
    let authority = authority::load(configuration).unwrap().unwrap();
    let votes = (0..5)
        .map(|index| {
            let mut vote = BlockVote {
                context: ConsensusObjectContext::for_height(&authority.epoch, 1, 0).unwrap(),
                block_id: "cache-qualified-block".into(),
                parent_block_id: authority.anchor_parent.block_id().into(),
                parent: authority.anchor_parent.clone(),
                takeover_tc_id: None,
                protected_execution_root: "e".repeat(64),
                validator_id: fleet.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: Vec::new(),
            };
            vote.signature = fixture_sign(
                &fs::read(fleet.root.join(format!("node-{index}/consensus.key"))).unwrap(),
                SignatureAlgorithm::MlDsa65,
                &vote.key_id,
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                Some(1),
                &block_vote_signing_bytes(&vote).unwrap(),
            );
            vote
        })
        .collect::<Vec<_>>();
    let first = SimplifiedQuorumCertificate::from_votes(votes[..4].to_vec()).unwrap();
    let variant = SimplifiedQuorumCertificate::from_votes(votes[1..].to_vec()).unwrap();
    assert_eq!(first.id().unwrap(), variant.id().unwrap());
    assert_ne!(first.participants, variant.participants);
    first
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    let cached = authority.consensus_signature_cache_stats();
    assert_eq!(cached.0, 4);
    first
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    assert_eq!(authority.consensus_signature_cache_stats(), cached);
    variant
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    let expanded = authority.consensus_signature_cache_stats();
    assert_eq!(expanded.0, 5);
    assert_eq!(expanded.2, cached.2 + 1);
    let mut tampered = first.clone();
    tampered.participants[0].signature[0] ^= 1;
    assert!(tampered
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .is_err());
    assert_eq!(authority.consensus_signature_cache_stats().0, expanded.0);
    let validator = authority
        .registry
        .active_validator(&votes[0].validator_id)
        .unwrap();
    let payload = block_vote_signing_bytes(&votes[0]).unwrap();
    // PQVM signs the supplied canonical payload bytes. SigningContext's
    // domain is validated as metadata, not prepended to those bytes. Changing
    // only that argument must miss this cache and preserve primitive behavior;
    // the certificate's actual chain/protocol/epoch bindings are checked below.
    let fresh_domain = authority.as_ref().clone();
    fresh_domain
        .verify_consensus_signature(
            "different-domain-metadata",
            &payload,
            validator,
            &votes[0].key_id,
            1,
            &votes[0].signature,
        )
        .unwrap();
    assert_eq!(fresh_domain.consensus_signature_cache_stats().2, 1);
    let before_domain = authority.consensus_signature_cache_stats();
    authority
        .verify_consensus_signature(
            "different-domain-metadata",
            &payload,
            validator,
            &votes[0].key_id,
            1,
            &votes[0].signature,
        )
        .unwrap();
    let domain_cached = authority.consensus_signature_cache_stats();
    assert_eq!(domain_cached.0, before_domain.0 + 1);
    assert_eq!(domain_cached.2, before_domain.2 + 1);
    for (domain, key, epoch, message) in [
        ("", votes[0].key_id.as_str(), 1, payload.clone()),
        (
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            "wrong-key",
            1,
            payload.clone(),
        ),
        (
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            votes[0].key_id.as_str(),
            2,
            payload.clone(),
        ),
        (
            POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
            votes[0].key_id.as_str(),
            1,
            b"wrong-payload".to_vec(),
        ),
    ] {
        assert!(authority
            .verify_consensus_signature(
                domain,
                &message,
                validator,
                key,
                epoch,
                &votes[0].signature
            )
            .is_err());
    }
    assert_eq!(
        authority.consensus_signature_cache_stats().0,
        domain_cached.0
    );
    let mut wrong_chain = first.clone();
    wrong_chain.context.chain_id += 1;
    let mut wrong_epoch = first.clone();
    wrong_epoch.context.epoch += 1;
    let mut wrong_protocol = first.clone();
    wrong_protocol.context.protocol_version = "wrong-protocol".into();
    let mut wrong_network = first.clone();
    wrong_network.context.network_id = "wrong-network".into();
    let mut insufficient_quorum = first.clone();
    insufficient_quorum.participants.pop();
    for invalid in [
        wrong_chain,
        wrong_epoch,
        wrong_protocol,
        wrong_network,
        insufficient_quorum,
    ] {
        assert!(invalid
            .verify(&authority.epoch, &authority.registry, authority.as_ref())
            .is_err());
        let uncached = authority.as_ref().clone();
        assert!(invalid
            .verify(&uncached.epoch, &uncached.registry, &uncached)
            .is_err());
    }
    assert_eq!(
        authority.consensus_signature_cache_stats().0,
        domain_cached.0
    );
    let fresh_instance = authority.as_ref().clone();
    assert_eq!(fresh_instance.consensus_signature_cache_stats(), (0, 0, 0));
    first
        .verify(
            &fresh_instance.epoch,
            &fresh_instance.registry,
            &fresh_instance,
        )
        .unwrap();
    assert_eq!(fresh_instance.consensus_signature_cache_stats().2, 4);
    assert!(authority.consensus_signature_cache_stats().1 <= 8 * 1024 * 1024);
}

#[test]
fn authenticated_socket_restart_with_certified_execution_gap_recovers_without_losing_authority() {
    qualify_certified_execution_gap(70, false);
}

#[test]
fn authenticated_socket_outstanding_request_restart_and_reordered_prefetch_recovers() {
    qualify_certified_execution_gap(8, true);
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn authenticated_native_processing_terminal_epoch_replays_seventeen_blocks_after_request_restart() {
    qualify_certified_execution_gap_profile(17, true, true);
}

/// Full secure native boundary qualification: genuine network-produced epoch
/// one, frozen-quorum recovery, activation, all-owner restart and epoch-two work.
#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn authenticated_native_quorum_recovery_restarts_five_owners_and_finalizes_successor_epoch() {
    use super::apqe_transport::{SignedRegistry, REGISTRY_CONTEXT};
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    let provider = trusted_apqe_provider();
    let mut prepared = prepare_socket_fixture_profile_mode_endpoints(
        synergy_state::WorldState::default(),
        None,
        true,
        Some(20),
        Some(&provider),
        true,
        None,
        99999,
    );
    let registry_signer = prepared.registry_signer.take().unwrap();
    // Each real installation owns its authority file. A shared fixture path
    // would let the first activation overwrite the other four predecessors.
    for (index, config) in prepared.configurations.iter_mut().enumerate() {
        let path = prepared.root.join(format!("node-{index}/authority.json"));
        fs::copy(config.consensus.authority_binding.as_ref().unwrap(), &path).unwrap();
        config.consensus.authority_binding = Some(path);
        write_json(
            &prepared.root.join(format!("node-{index}/config.json")),
            config,
        );
    }
    let open = |configuration: NodeConfiguration, listeners: &FixtureListeners| {
        let budget = synergy_state::world_resources::WorldResourceBudget::new(
            configuration.storage.world_memory_budget_bytes,
        );
        Node::open_with_wallet_budget(configuration, None, listeners, budget, false, None)
    };
    let nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(configuration, listeners)| Some(open(configuration, listeners)))
        .collect();
    let mut fleet = SocketFleet {
        root: prepared.root,
        nodes,
        ids: prepared.ids,
        listeners: prepared.listeners,
    };
    fleet.dial_mesh();
    fleet.advance(18);
    let genesis_before = fs::read(fleet.root.join("genesis.sgen")).unwrap();
    let original_root = fs::read(fleet.root.join("trust.pub")).unwrap();
    let transport_root = fs::read(fleet.root.join("registry-root.pub")).unwrap();
    let mut configs = Vec::new();
    for node in &mut fleet.nodes {
        let mut node = node.take().unwrap();
        configs.push(node.configuration.clone());
        node.stop();
    }
    let journal_bytes = configs
        .iter()
        .map(|config| {
            fs::read(
                config
                    .storage
                    .data_directory
                    .join("consensus/posy/sign-once.json"),
            )
            .ok()
        })
        .collect::<Vec<_>>();
    // One real actor lacks only the two certified, unexecuted predecessor-tail
    // payloads. Other four retain them for authenticated successor recovery.
    let missing_layout =
        synergy_storage::NodeStorageLayout::new(configs[4].storage.data_directory.clone()).unwrap();
    let replay = missing_layout
        .blocks()
        .join("processing-proposal-inputs-v1");
    let mut removed_tail = 0;
    for directory in ["inputs", "certified"] {
        let directory = replay.join(directory);
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            if value["inputs"]["context"]["height"]
                .as_u64()
                .is_some_and(|height| (19..=20).contains(&height))
            {
                if directory.file_name().unwrap() == "inputs" {
                    let validation = replay.join("validations").join(path.file_name().unwrap());
                    if validation.exists() {
                        fs::remove_file(validation).unwrap();
                    }
                }
                fs::remove_file(path).unwrap();
                removed_tail += 1;
            }
        }
    }
    for directory in ["certified-ids", "certified-groups"] {
        let directory = replay.join(directory);
        if !directory.exists() {
            continue;
        }
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let bytes: [u8; 8] = fs::read(&path).unwrap().try_into().unwrap();
            if (19..=20).contains(&u64::from_be_bytes(bytes)) {
                fs::remove_file(path).unwrap();
            }
        }
    }
    for height in 19..=20 {
        for directory in ["candidate", "candidate-world"] {
            let path = missing_layout
                .blocks()
                .join("execution-candidates")
                .join(directory)
                .join(format!("{height:020}.json"));
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    }
    assert!(
        removed_tail > 0,
        "fault must remove genuine unexecuted old-epoch replay dependencies"
    );
    authority::recovery::native_activation_tests::activate_real_socket_fixture(&mut configs);
    let successor = authority::load(&configs[0]).unwrap().unwrap();
    let registry_path = fleet.root.join("registry.json");
    let mut registry: SignedRegistry =
        serde_json::from_slice(&fs::read(&registry_path).unwrap()).unwrap();
    let original_payload = serde_json::to_value(&registry.payload).unwrap();
    registry.payload.epoch = 2;
    registry.payload.generation += 1;
    registry.payload.authority_binding_sha256 =
        super::apqe_transport::sha256(successor.binding_bytes());
    let engine = super::apqe_provider::load(&configs[0]).unwrap();
    registry.signature = engine
        .lock()
        .unwrap()
        .sign(
            Algorithm::MlDsa87,
            registry_signer.as_bytes(),
            &super::apqe_transport::signing_bytes(&registry.payload).unwrap(),
            SignOptions::Pure {
                context: REGISTRY_CONTEXT,
            },
        )
        .unwrap();
    write_json(&registry_path, &registry);
    let mut preserved = serde_json::to_value(&registry.payload).unwrap();
    for key in ["epoch", "generation", "authority_binding_sha256"] {
        preserved[key] = original_payload[key].clone();
    }
    assert_eq!(preserved, original_payload);
    for (index, config) in configs.iter().enumerate() {
        assert_eq!(
            fs::read(
                config
                    .storage
                    .data_directory
                    .join("consensus/posy/sign-once.json")
            )
            .ok(),
            journal_bytes[index]
        );
        super::apqe_transport::preflight(config).unwrap();
        write_json(
            &fleet.root.join(format!("node-{index}/config.json")),
            config,
        );
    }
    assert_eq!(
        fs::read(fleet.root.join("genesis.sgen")).unwrap(),
        genesis_before
    );
    assert_eq!(
        fs::read(fleet.root.join("trust.pub")).unwrap(),
        original_root
    );
    assert_eq!(
        fs::read(fleet.root.join("registry-root.pub")).unwrap(),
        transport_root
    );
    for (index, config) in configs.into_iter().enumerate() {
        // Node::open registers every actual production owner before starting:
        // this catches context and namespace gates hidden by authority-only tests.
        fleet.nodes[index] = Some(open(config, &fleet.listeners[index]));
    }
    fleet.dial_mesh();
    fleet.advance_with_peer_redial(23, Some(4));
    for node in fleet.nodes.iter().flatten() {
        assert_eq!(node.ingress.authenticated_peers().unwrap().len(), 4);
        assert_eq!(
            authority::load(&node.configuration)
                .unwrap()
                .unwrap()
                .epoch
                .epoch,
            2
        );
    }
    // Fresh ingress deliberately has no cached finalized publications. Every
    // mixed-tail QC must resolve its signed epoch through the verified lineage.
    let first = fleet.nodes[0].as_ref().unwrap();
    let current = authority::load(&first.configuration).unwrap().unwrap();
    let transition = authority::load_transition_context(&first.configuration, &current)
        .unwrap()
        .unwrap();
    let root = first
        .configuration
        .storage
        .data_directory
        .join("consensus/posy");
    let history = ingress::AuthenticatedIngress::default();
    history
        .install_finality_history_with_transition(root.clone(), current.clone(), Some(transition))
        .unwrap();
    for height in [18, 19, 20] {
        let (record, witness) = history
            .finalized_record_with_witness(height)
            .unwrap()
            .unwrap();
        assert_eq!(record.height, height);
        for (offset, qc) in witness.iter().enumerate() {
            assert_eq!(qc.context.height, height + offset as u64);
        }
    }
    let isolated = ingress::AuthenticatedIngress::default();
    isolated.install_finality_history(root, current).unwrap();
    assert!(
        isolated.finalized_record_with_witness(19).is_err(),
        "old API must not reinterpret predecessor QCs under successor authority"
    );
    eprintln!("secure native epoch recovery: five actual owners restarted, three successor finalized blocks and matching durable worlds verified");
}

/// Export only the genuine retained three-QC head for decoder qualification.
/// No node owner starts and no signed material is synthesized or rewritten.
#[test]
#[ignore = "requires explicitly retained disposable native APQE fixture"]
fn export_retained_authenticated_native_terminal_head_diagnostic() {
    use std::os::unix::fs::PermissionsExt;
    let root = PathBuf::from(
        std::env::var("SYNERGY_SOCKET_RETAINED_FIXTURE")
            .expect("explicit retained fixture root required"),
    );
    assert!(
        root.is_absolute()
            && root.canonicalize().unwrap() == root
            && root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("posy-socket-")
    );
    assert_eq!(root.metadata().unwrap().permissions().mode() & 0o777, 0o700);
    let config: NodeConfiguration =
        serde_json::from_slice(&fs::read(root.join("diagnostic-node-0.json")).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(&config.aegis_provider).unwrap(),
        serde_json::to_value(Some(trusted_apqe_provider())).unwrap()
    );
    let authority = authority::load(&config).unwrap().unwrap();
    assert_eq!(authority.epoch.epoch_end_height, 20);
    let layout =
        synergy_storage::NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
    let store =
        synergy_posy::VerifiedQuorumCertificateStore::new(layout.consensus().join("posy")).unwrap();
    let certificates = (18..=20)
        .map(|height| {
            store
                .get_verified(
                    height,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap()
                .expect("retained genuine terminal QC required")
        })
        .collect::<Vec<_>>();
    let mut chain = synergy_posy::ThreeQcFinality::default();
    for certificate in &certificates {
        chain.accept(certificate.clone()).unwrap();
    }
    let finalized = chain
        .last_finalized()
        .expect("genuine native triple must finalize H18");
    assert_eq!(finalized.height, 18);
    let durable = synergy_posy::persistence::FinalityStore::new(layout.consensus().join("posy"))
        .unwrap()
        .get(18)
        .unwrap()
        .unwrap();
    assert_eq!(finalized, &durable);
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&config.manifest_path).unwrap()).unwrap();
    let identity =
        identity::load_public_identity(&config.public_identity_path, config.role).unwrap();
    let claim = synergy_sync::HeadClaim {
        peer_id: identity.node_address.to_string(),
        chain_id: config.chain_id,
        genesis_hash: manifest["genesis_hash"].as_str().unwrap().to_owned(),
        finalized_height: finalized.height,
        finalized_hash: finalized.block_id.clone(),
        finality_evidence_id: finalized.finality_certificate_id.clone(),
        finality_witness: Some(serde_json::to_vec(&certificates).unwrap()),
    };
    let wire = synergy_sync::SyncWireMessage::<synergy_state::WorldState>::Head(claim);
    let output = root.join("diagnostic-native-head.json");
    write_json(&output, &wire);
    eprintln!(
        "RETAINED_AUTHENTICATED_NATIVE_HEAD {} bytes={}",
        output.display(),
        output.metadata().unwrap().len()
    );
}

/// Immediate diagnosis of one explicitly retained native fixture. Rebind the
/// identical signed loopback endpoints; never manufacture new network inputs.
#[test]
#[ignore = "requires explicitly retained disposable native APQE fixture"]
fn authenticated_native_processing_terminal_epoch_resume_retained_diagnostic() {
    use std::os::unix::fs::PermissionsExt;
    let root = PathBuf::from(
        std::env::var("SYNERGY_SOCKET_RETAINED_FIXTURE")
            .expect("explicit retained fixture root required"),
    );
    assert!(
        root.is_absolute()
            && !root.is_symlink()
            && root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("posy-socket-")
    );
    assert_eq!(root.metadata().unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(root.canonicalize().unwrap(), root);
    let provider = trusted_apqe_provider();
    let mut configurations = Vec::new();
    let mut listeners = Vec::new();
    let mut ids = Vec::new();
    for index in 0..5 {
        let path = root.join(format!("diagnostic-node-{index}.json"));
        assert!(!path.is_symlink());
        let configuration: NodeConfiguration =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&configuration.aegis_provider).unwrap(),
            serde_json::to_value(Some(&provider)).unwrap()
        );
        assert!(configuration.storage.data_directory.starts_with(&root));
        assert_eq!(configuration.network.listen_addresses.len(), 1);
        let address = configuration.network.listen_addresses[0];
        assert!(address.ip().is_loopback() && address.port() != 0);
        listeners.push(FixtureListeners {
            network: Arc::new(vec![synergy_network::transport::TcpListenerService::bind(
                address,
                synergy_network::transport::TransportTimeouts {
                    connect: Duration::from_secs(10),
                    handshake: Duration::from_secs(10),
                    read: Duration::from_secs(60),
                    write: Duration::from_secs(60),
                },
            )
            .unwrap()]),
            rpc: Arc::new(TcpListener::bind("127.0.0.1:0").unwrap()),
        });
        ids.push(
            identity::load_public_identity(&configuration.public_identity_path, configuration.role)
                .unwrap()
                .node_address
                .to_string(),
        );
        let authority = authority::load(&configuration).unwrap().unwrap();
        assert_eq!(authority.epoch.epoch_end_height, 20);
        assert!(authority.processing_profile_enabled());
        configurations.push(configuration);
    }
    let nodes = configurations
        .into_iter()
        .zip(&listeners)
        .map(|(configuration, listener)| Some(Node::open(configuration, listener)))
        .collect();
    let mut fleet = SocketFleet {
        root,
        nodes,
        ids,
        listeners,
    };
    for node in fleet.nodes.iter().flatten() {
        eprintln!(
            "RETAINED_OWNER_BUDGET node={} used={} limit={}",
            node.configuration.node_name,
            node.ingress.world_budget().used(),
            node.ingress.world_budget().limit()
        );
    }
    fleet.dial_mesh();
    fleet.advance_with_peer_redial(18, Some(4));
}

fn qualify_certified_execution_gap(offline_blocks: u64, qualify_prefetch: bool) {
    qualify_certified_execution_gap_profile(offline_blocks, qualify_prefetch, false);
}

fn qualify_certified_execution_gap_profile(
    offline_blocks: u64,
    qualify_prefetch: bool,
    native_terminal: bool,
) {
    let qualification_started = Instant::now();
    // A short, genuinely signed disposable epoch reaches the exact terminal
    // condition without generating ten thousand unrelated qualification blocks.
    // Exported/deployed epoch policy remains unchanged.
    let terminal_height = 18;
    let mut fleet = if native_terminal {
        SocketFleet::with_wallet_world_state_profile(
            synergy_state::WorldState::default(),
            false,
            Some(trusted_apqe_provider()),
            true,
            Some(terminal_height + 2),
        )
    } else {
        SocketFleet::new()
    };
    fleet.advance(if native_terminal {
        terminal_height - offline_blocks
    } else {
        6
    });
    if native_terminal {
        eprintln!(
            "native terminal recovery: warmup complete after {:?}",
            qualification_started.elapsed()
        );
    }
    let mut removed = fleet.nodes[4].take().unwrap();
    let configuration = removed.configuration.clone();
    if native_terminal {
        let layout =
            synergy_storage::NodeStorageLayout::new(configuration.storage.data_directory.clone())
                .unwrap();
        let paused_at = synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .current()
            .unwrap()
            .finalized_height;
        assert_eq!(paused_at + offline_blocks, terminal_height,
            "must pause the actual Execution owner exactly seventeen blocks before terminal finality");
        // The fifth voter deliberately cannot build while Execution is paused.
        // Its genuine proposer slots must close through normal signed timeout
        // quorums. Allow their bounded wall time; never force votes or clocks.
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut observed_slot = None;
        loop {
            for node in fleet.nodes.iter_mut().flatten() {
                node.poll();
            }
            // Every other production owner keeps running over real authenticated
            // sockets. Only this disposable node's Execution consumer is paused.
            removed.poll_selected_owners(|_| {}, true);
            let finalized = removed.ingress.latest_finality().unwrap();
            let observation = removed.ingress.consensus_observation().unwrap();
            let slot = observation
                .as_ref()
                .and_then(|value| Some((value["height"].as_u64()?, value["round"].as_u64()?)));
            if slot != observed_slot {
                observed_slot = slot;
                eprintln!("native terminal recovery: paused Execution phase advanced consensus {slot:?}, finalized {:?}, elapsed {:?}",
                    finalized.as_ref().map(|record| record.height), qualification_started.elapsed());
            }
            if finalized
                .as_ref()
                .is_some_and(|record| record.height == terminal_height)
                && observation
                    .as_ref()
                    .and_then(|slot| slot["height"].as_u64())
                    == Some(terminal_height + 2)
                && removed
                    .ingress
                    .processing_build_request()
                    .unwrap()
                    .is_none()
            {
                eprintln!("native terminal recovery reached exact owner condition: {observation:?}; finalized H{terminal_height}, no live build request, durable Execution H{paused_at}");
                break;
            }
            assert!(Instant::now() < deadline,
                "never reached genuine terminal PoSy with paused Execution: finalized={finalized:?}, observation={observation:?}");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
                .unwrap()
                .current()
                .unwrap()
                .finalized_height,
            paused_at,
            "paused Execution must not receive trusted synthetic commit acknowledgments"
        );
    }
    removed.stop();
    drop(removed);
    let layout =
        synergy_storage::NodeStorageLayout::new(configuration.storage.data_directory.clone())
            .unwrap();
    let state = synergy_state::FinalizedStateStore::load(layout.state().join("execution")).unwrap();
    let committed = state.current().unwrap().clone();
    let gap = committed.finalized_height + 1;
    let authority = authority::load(&configuration).unwrap().unwrap();
    let consensus_root = layout.consensus().join("posy");
    let qcs = synergy_posy::VerifiedQuorumCertificateStore::new(&consensus_root).unwrap();
    let certified = qcs
        .get_verified(
            gap,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap()
        .unwrap();
    let signer_path = consensus_root.join("sign-once.json");
    let signer_before = fs::read(&signer_path).unwrap();
    // Model the real crash boundary: consensus proof is retained, but this
    // not-yet-finalized execution payload has not reached durable storage.
    let missing = layout
        .blocks()
        .join("execution-candidates/candidate")
        .join(format!("{gap:020}.json"));
    assert!(missing.is_file());
    fs::remove_file(&missing).unwrap();
    let missing_world = layout
        .blocks()
        .join("execution-candidates/candidate-world")
        .join(format!("{gap:020}.json"));
    assert!(missing_world.is_file());
    fs::remove_file(&missing_world).unwrap();
    if native_terminal {
        // Model loss of only unexecuted replay dependencies after the crash.
        // Retaining this authenticated archive would correctly allow local
        // regeneration, making a new network request unnecessary. Preserve the
        // signed QCs, signing journals and every executed record/world.
        let replay = layout.blocks().join("processing-proposal-inputs-v1");
        let mut removed_replay = 0;
        for directory in ["inputs", "certified"] {
            let directory = replay.join(directory);
            if !directory.exists() {
                continue;
            }
            for entry in fs::read_dir(&directory).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                let raw = fs::read(&path).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let height = value["inputs"]["context"]["height"].as_u64();
                if height.is_some_and(|h| gap <= h && h <= terminal_height) {
                    if directory.file_name().unwrap() == "inputs" {
                        let validation = replay.join("validations").join(path.file_name().unwrap());
                        if validation.exists() {
                            fs::remove_file(validation).unwrap();
                        }
                    }
                    fs::remove_file(path).unwrap();
                    removed_replay += 1;
                }
            }
        }
        for directory in ["certified-ids", "certified-groups"] {
            let directory = replay.join(directory);
            if !directory.exists() {
                continue;
            }
            for entry in fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().and_then(|v| v.to_str()) != Some("json") {
                    continue;
                }
                let raw: [u8; 8] = fs::read(&path).unwrap().try_into().unwrap();
                let height = u64::from_be_bytes(raw);
                if gap <= height && height <= terminal_height {
                    fs::remove_file(path).unwrap();
                }
            }
        }
        assert!(
            removed_replay > 0,
            "missing-dependency fault must remove actual unexecuted processing inputs"
        );
        assert!(!replay.join(format!("certified/{gap:020}.json")).exists());
        assert!(!replay
            .join(format!("certified-ids/{}.json", certified.block_id))
            .exists());
        eprintln!("native terminal recovery: removed {removed_replay} unexecuted replay dependencies; certified state and signing journals preserved");
    }
    // The long case exceeds the 64-record notification window; the focused
    // case isolates outstanding-request restart and reordered prefetch.
    let catch_up_tip = if native_terminal {
        assert_eq!(authority.epoch.epoch_end_height - 2, terminal_height);
        assert_eq!(
            terminal_height - committed.finalized_height,
            offline_blocks,
            "qualification must create the exact seventeen-block durable execution gap"
        );
        terminal_height
    } else {
        committed.finalized_height + offline_blocks
    };
    fleet.advance(catch_up_tip);
    // Exercise the asynchronous owner boundary with the genuine advancing
    // fleet's verified finality, before the missing execution payload arrives.
    // An absent execution payload must not trigger repeated historical proof
    // loads, even though the queued verified tip is ahead of that exact gap.
    assert!(!missing.is_file());
    let (ahead, witness) = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .ingress
        .latest_finality_with_witness()
        .unwrap()
        .unwrap();
    assert!(ahead.height >= catch_up_tip);
    assert!(ahead.height - committed.finalized_height >= offline_blocks);
    if !qualify_prefetch {
        assert!(ahead.height - committed.finalized_height > 64);
    }
    let certificates: Vec<synergy_posy::SimplifiedQuorumCertificate> =
        serde_json::from_slice(&witness).unwrap();
    assert_eq!(certificates.len(), 3);
    let mut verified_finality = synergy_posy::ThreeQcFinality::default();
    for certificate in certificates {
        certificate
            .verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        verified_finality.accept(certificate).unwrap();
    }
    assert_eq!(verified_finality.last_finalized(), Some(&ahead));
    if !native_terminal {
        let waiting_ingress = ingress::AuthenticatedIngress::default();
        let (_, mut waiting_execution) = execution::registration(
            &configuration,
            Arc::clone(&authority),
            waiting_ingress.clone(),
        )
        .unwrap();
        waiting_ingress
            .submit_finality(ahead.clone(), witness)
            .unwrap();
        waiting_execution
            .start(&CancellationToken::default())
            .unwrap();
        let proof_loads = execution::historical_finality_loads();
        for _ in 0..3 {
            waiting_execution.poll().unwrap();
            assert_eq!(execution::historical_finality_loads(), proof_loads);
            assert_eq!(
                waiting_ingress.pending_finality().unwrap(),
                Some(ahead.clone())
            );
            assert_eq!(
                synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
                    .unwrap()
                    .current(),
                Some(&committed)
            );
        }
        waiting_execution.stop().unwrap();
        drop(waiting_execution);
    }
    if native_terminal {
        eprintln!(
            "native terminal recovery: reopening lagging owner after {:?}",
            qualification_started.elapsed()
        );
    }
    fleet.nodes[4] = Some(Node::open(configuration.clone(), &fleet.listeners[4]));
    if native_terminal {
        eprintln!(
            "native terminal recovery: reopened lagging owner after {:?}",
            qualification_started.elapsed()
        );
    }

    assert_eq!(fs::read(&signer_path).unwrap(), signer_before);
    assert_eq!(
        qcs.get_verified(
            gap,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .unwrap()
        .unwrap(),
        certified
    );
    assert_eq!(
        synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .current(),
        Some(&committed)
    );
    let restarted = fleet.nodes[4].as_ref().unwrap();
    for i in 0..4 {
        restarted
            .ingress
            .request_dial(ingress::DialRequest {
                peer_id: fleet.ids[i].clone(),
                address: fleet.nodes[i]
                    .as_ref()
                    .unwrap()
                    .configuration
                    .network
                    .listen_addresses[0],
            })
            .unwrap();
    }
    if qualify_prefetch {
        // Restart with a real first-gap request still outstanding. No peer response
        // is fabricated, and the durable execution cursor is the resume authority.
        let request_path = layout.metadata().join("sync/active-candidate-request.json");
        let request_deadline = Instant::now() + Duration::from_secs(60);
        let mut next_redial = Instant::now() + Duration::from_secs(5);
        let (outstanding_bytes, restart_cursor) = loop {
            if Instant::now() >= next_redial {
                redial_missing_socket_peers(&fleet, 4);
                next_redial = Instant::now() + Duration::from_secs(5);
            }
            for node in fleet.nodes.iter_mut().flatten() {
                node.poll();
            }
            if let Ok(bytes) = fs::read(&request_path) {
                let persisted: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let cursor =
                    synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
                        .unwrap()
                        .current()
                        .unwrap()
                        .clone();
                if persisted["request"]["height"].as_u64() == Some(cursor.finalized_height + 1) {
                    break (bytes, cursor);
                }
            }
            assert!(
                Instant::now() < request_deadline,
                "no genuine outstanding first-gap Sync request; durable cursor {:?}; persisted request {:?}; authenticated peers {:?}; consensus {:?}; fleet public diagnostics {:?}",
                synergy_state::FinalizedStateStore::load(layout.state().join("execution")).unwrap().current(),
                fs::read(&request_path).ok().map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()),
                fleet.nodes[4].as_ref().unwrap().ingress.authenticated_peers().unwrap(),
                fleet.nodes[4].as_ref().unwrap().ingress.consensus_observation().unwrap(),
                fleet.nodes.iter().flatten().map(|node| serde_json::json!({
                    "node":node.configuration.node_name,
                    "sync":node.ingress.sync_progress_diagnostic().unwrap(),
                    "budget_used":node.ingress.world_budget().used(),
                    "budget_limit":node.ingress.world_budget().limit(),
                    "peer_progress":node.ingress.authenticated_peer_progress().unwrap(),
                    "consensus":node.ingress.consensus_observation().unwrap(),
                    "health":node.services.iter().map(|(name,service)|(*name,format!("{:?}",service.health()))).collect::<Vec<_>>()
                })).collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(2));
        };
        if native_terminal {
            eprintln!("native terminal recovery: genuine outstanding first-gap request reached after {:?}", qualification_started.elapsed());
        }
        let mut outstanding_node = fleet.nodes[4].take().unwrap();
        outstanding_node.stop();
        drop(outstanding_node);
        assert_eq!(fs::read(&request_path).unwrap(), outstanding_bytes);
        fleet.nodes[4] = Some(Node::open(configuration.clone(), &fleet.listeners[4]));
        assert_eq!(fs::read(&request_path).unwrap(), outstanding_bytes);
        assert_eq!(
            synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
                .unwrap()
                .current(),
            Some(&restart_cursor)
        );
        let restarted = fleet.nodes[4].as_ref().unwrap();
        for i in 0..4 {
            restarted
                .ingress
                .request_dial(ingress::DialRequest {
                    peer_id: fleet.ids[i].clone(),
                    address: fleet.nodes[i]
                        .as_ref()
                        .unwrap()
                        .configuration
                        .network
                        .listen_addresses[0],
                })
                .unwrap();
        }
        // Reorder only authentic socket-delivered candidate response frames before
        // the production Sync adapter consumes them. Release a lone response after
        // 1s so initial parent-proof acquisition can open the prefetch window.
        let reorder_deadline = Instant::now() + Duration::from_secs(90);
        let mut held = Vec::new();
        let mut held_since = None;
        let mut reordered_heights = Vec::new();
        let mut observed_response_heights = std::collections::BTreeSet::new();
        let mut next_redial = Instant::now() + Duration::from_secs(5);
        while reordered_heights.is_empty() {
            if Instant::now() >= next_redial {
                redial_missing_socket_peers(&fleet, 4);
                next_redial = Instant::now() + Duration::from_secs(5);
            }
            for node in fleet.nodes[..4].iter_mut().flatten() {
                node.poll();
            }
            fleet.nodes[4]
                .as_mut()
                .unwrap()
                .poll_before_sync(|ingress| {
                    let mut other_frames = Vec::new();
                    while let Some(frame) = ingress
                        .take(synergy_protocol_types::ProtocolKind::Sync)
                        .unwrap()
                    {
                        match serde_json::from_slice::<synergy_sync::SyncWireMessage>(
                            &frame.payload,
                        )
                        .unwrap()
                        {
                            synergy_sync::SyncWireMessage::FinalizedCandidateResponse(response) => {
                                held_since.get_or_insert_with(Instant::now);
                                observed_response_heights.insert(response.request.height);
                                held.push((response.request.height, frame));
                            }
                            synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(chunk) => {
                                observed_response_heights.insert(chunk.request.height);
                                held.push((chunk.request.height, frame));
                            }
                            _ => other_frames.push(frame),
                        }
                    }
                    for frame in other_frames {
                        ingress.publish(frame).unwrap();
                    }
                    let mut complete = std::collections::BTreeSet::new();
                    let mut chunks = std::collections::BTreeMap::<
                        u64,
                        (usize, std::collections::BTreeSet<usize>),
                    >::new();
                    for (height, frame) in &held {
                        match serde_json::from_slice::<synergy_sync::SyncWireMessage>(
                            &frame.payload,
                        )
                        .unwrap()
                        {
                            synergy_sync::SyncWireMessage::FinalizedCandidateResponse(_) => {
                                complete.insert(*height);
                            }
                            synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(chunk) => {
                                let entry = chunks.entry(*height).or_insert_with(|| {
                                    (
                                        chunk
                                            .total_bytes
                                            .div_ceil(synergy_sync::CANDIDATE_CHUNK_BYTES),
                                        std::collections::BTreeSet::new(),
                                    )
                                });
                                entry.1.insert(chunk.offset);
                                if entry.1.len() == entry.0 {
                                    complete.insert(*height);
                                }
                            }
                            _ => unreachable!("only candidate responses are held"),
                        }
                    }
                    if !complete.is_empty() {
                        // Release timing begins at a complete genuine response,
                        // not its first partial chunk. Otherwise a large response
                        // can never be present in the complete-response window.
                        held_since.get_or_insert_with(Instant::now);
                    }
                    if complete.len() >= 2 {
                        // Interleave genuine chunks across prefetched heights; grouping
                        // complete responses would hide a single-assembly owner defect.
                        held.sort_by_key(|(height, frame)| {
                            let offset =
                                match serde_json::from_slice::<synergy_sync::SyncWireMessage>(
                                    &frame.payload,
                                )
                                .unwrap()
                                {
                                    synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(
                                        chunk,
                                    ) => chunk.offset,
                                    _ => 0,
                                };
                            (offset, std::cmp::Reverse(*height))
                        });
                        reordered_heights = held.iter().map(|(height, _)| *height).collect();
                        for (_, frame) in held.drain(..) {
                            ingress.publish(frame).unwrap();
                        }
                    } else if held_since
                        .is_some_and(|started| started.elapsed() >= Duration::from_secs(1))
                    {
                        let mut partial = Vec::new();
                        for (height, frame) in held.drain(..) {
                            if complete.contains(&height) {
                                ingress.publish(frame).unwrap();
                            } else {
                                // Keep other responses' partial chunks together;
                                // releasing them here destroys later completeness.
                                partial.push((height, frame));
                            }
                        }
                        held = partial;
                        held_since = None;
                    }
                });
            assert!(
                Instant::now() < reorder_deadline,
                "Sync never produced concurrent genuine responses for reorder qualification; restart cursor H{}, catch-up tip H{}, observed heights {:?}, held frames {}, authenticated peers: {:?}",
                restart_cursor.finalized_height, catch_up_tip, observed_response_heights, held.len(),
                fleet.nodes[4].as_ref().unwrap().ingress.authenticated_peers().unwrap()
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        if native_terminal {
            eprintln!(
                "native terminal recovery: genuine response burst reached after {:?}",
                qualification_started.elapsed()
            );
        }
        assert!(reordered_heights.windows(2).any(|pair| pair[0] > pair[1]));
        eprintln!("socket qualification: restarted outstanding Sync request and delivered genuine response heights in descending order: {reordered_heights:?}");
    }
    // At the terminal epoch there is no live build request and no successor
    // authority. Only production certified-history replay can commit this gap.
    fleet.advance_with_peer_redial(
        if native_terminal {
            catch_up_tip
        } else {
            catch_up_tip + 8
        },
        Some(4),
    );
    if native_terminal {
        for node in fleet.nodes.iter().flatten() {
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let state =
                synergy_state::FinalizedStateStore::load(layout.state().join("execution")).unwrap();
            assert_eq!(state.current().unwrap().finalized_height, terminal_height);
            assert!(
                node.ingress.processing_build_request().unwrap().is_none(),
                "terminal replay must not depend on an active proposal build request"
            );
        }
    }
}

// The isolated loopback fixture has no VPN service to reschedule dials.
// Production's verified-route scheduler retries after five seconds; preserve
// real admission backoff here and retry only currently missing peers.
fn redial_missing_socket_peers(fleet: &SocketFleet, index: usize) {
    let node = fleet.nodes[index].as_ref().unwrap();
    let connected = node.ingress.authenticated_peers().unwrap();
    for (peer_index, peer) in fleet.nodes.iter().enumerate() {
        if peer_index == index || connected.contains(&fleet.ids[peer_index]) {
            continue;
        }
        if let Some(peer) = peer {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: fleet.ids[peer_index].clone(),
                    address: peer.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn raw_hash(bytes: &[u8]) -> String {
    lower_hex(&AegisSha3_256.sha3_256_segments(&[bytes]).unwrap())
}
fn fixture_sign(
    secret: &[u8],
    algorithm: SignatureAlgorithm,
    key: &str,
    domain: &str,
    epoch: Option<u64>,
    message: &[u8],
) -> Vec<u8> {
    if algorithm == SignatureAlgorithm::MlDsa87 {
        let secret = mldsa87::SecretKey::from_bytes(secret).unwrap();
        return mldsa87::detached_sign(message, &secret).as_bytes().to_vec();
    }
    // Independent PQClean signatures are adversarial/cross-provider fixture
    // inputs. Native runtime signing and verification still require APQE.
    assert_eq!(algorithm, SignatureAlgorithm::MlDsa65);
    KeyId::new(key).unwrap();
    SigningContext {
        domain: domain.into(),
        chain_id: 1266,
        epoch,
        height: None,
    }
    .validate()
    .unwrap();
    let secret = mldsa65::SecretKey::from_bytes(secret).unwrap();
    mldsa65::detached_sign(message, &secret).as_bytes().to_vec()
}

// Genuine wallet-root and independent account-key possession establish the
// signed Genesis authorization. This never derives an address from ML-DSA.
fn funded_transaction_fixture() -> (
    synergy_transaction::SignedTransaction,
    synergy_state::WorldState,
) {
    let (tx, world, _) = funded_transaction_fixture_with_key();
    (tx, world)
}
fn funded_transaction_fixture_with_key() -> (
    synergy_transaction::SignedTransaction,
    synergy_state::WorldState,
    Vec<u8>,
) {
    funded_transaction_fixture_for_network("socket-qualification", 10_000_000)
}
fn funded_transaction_fixture_for_network(
    network_id: &str,
    balance_nwei: u128,
) -> (
    synergy_transaction::SignedTransaction,
    synergy_state::WorldState,
    Vec<u8>,
) {
    funded_transaction_fixture_for_network_provider(network_id, balance_nwei, None)
}
fn funded_transaction_fixture_for_network_provider(
    network_id: &str,
    balance_nwei: u128,
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
) -> (
    synergy_transaction::SignedTransaction,
    synergy_state::WorldState,
    Vec<u8>,
) {
    funded_transaction_fixture_for_network_provider_chain(network_id, balance_nwei, provider, 1266)
}
fn funded_transaction_fixture_for_network_provider_chain(
    network_id: &str,
    balance_nwei: u128,
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
    chain_id: u64,
) -> (
    synergy_transaction::SignedTransaction,
    synergy_state::WorldState,
    Vec<u8>,
) {
    use synergy_identity::authorization::*;
    use synergy_transaction::{
        FeeLimit, NetworkBinding, SignedTransaction, TransactionClass, UnsignedTransaction,
    };
    let (root, root_secret) = bounded_keypair("wallet FN-DSA-1024".into(), fndsa1024::keypair);
    let (account, account_secret) = bounded_keypair("account ML-DSA-87".into(), mldsa87::keypair);
    let sender = synergy_address::derive_key_controlled_address("syna", root.as_bytes()).unwrap();
    let account_hash = raw_hash(account.as_bytes());
    let mut binding: IdentityAuthorizationBinding = serde_json::from_value(serde_json::json!({
        "schema_version":AUTH_BINDING_SCHEMA_VERSION,"binary_encoding":AUTH_BINDING_BINARY_ENCODING,
        "identity_id":"socket-account", "identity_address":sender,
        "identity_root":{"algorithm":"FN-DSA-1024","public_key":lower_hex(root.as_bytes()),"public_key_sha3_256":raw_hash(root.as_bytes())},
        "authorization_policy":{"policy_type":"single-key","threshold":1,"principals":[{
            "principal_id":"account","principal_type":"public-key","algorithm":"ML-DSA-87",
            "public_key":lower_hex(account.as_bytes()),"public_key_sha3_256":account_hash,"status":"active","purposes":["transaction-signing"]}]},
        "authorization_scopes":[{"signature_domain":AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN,
            "chain_id":chain_id,"network_id":network_id,"purpose":"transaction-signing"}],
        "current_auth_key_hash":account_hash,"auth_key_history":[],"supersession_history":[],
        "effective_at":"1970-01-01T00:00:10Z","binding_payload_sha3_256":"",
        "proofs":{"identity_root":{"algorithm":"FN-DSA-1024","signature":""}}
    })).unwrap();
    let payload = canonical_binding_payload(&binding).unwrap();
    binding.binding_payload_sha3_256 = raw_hash(&payload);
    let mut proof_message = AUTH_BINDING_SIGNATURE_DOMAIN.to_vec();
    proof_message.extend_from_slice(&payload);
    binding.proofs.identity_root.signature =
        lower_hex(fndsa1024::detached_sign(&proof_message, &root_secret).as_bytes());
    binding.proofs.authorization_key_possession = vec![AuthorizationKeyPossessionProof {
        principal_id: "account".into(),
        algorithm: "ML-DSA-87".into(),
        signature: lower_hex(mldsa87::detached_sign(&proof_message, &account_secret).as_bytes()),
    }];
    // Fixture keys/proofs are independently generated; native acceptance must
    // still use the explicitly authenticated APQE verifier used by the fleet.
    let identity_verifier = provider.map(|provider| {
        let engine = synergy_aegis::load_authenticated_native_engine(
            &provider.report_path,
            &provider.authenticated_report_sha256,
        )
        .unwrap();
        synergy_aegis::ApqeIdentityVerifier::new(engine).unwrap()
    });
    let commitment = IdentityAuthorizationBindingCommitment::from_verified_binding_with_verifier(
        &binding,
        1_700_000_000,
        identity_verifier
            .as_ref()
            .map(|verifier| verifier as &dyn AuthorizationSignatureVerifier),
    )
    .unwrap();
    let mut world = synergy_state::WorldState::default();
    world.accounts.insert(
        sender.clone(),
        synergy_state::AccountState {
            balance_nwei,
            nonce: 0,
            code_hash: None,
        },
    );
    world.protocol.insert(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        serde_json::to_vec(&std::collections::BTreeMap::from([(
            sender.clone(),
            commitment,
        )]))
        .unwrap(),
    );
    let unsigned = UnsignedTransaction {
        network: NetworkBinding::new(chain_id, network_id).unwrap(),
        class: TransactionClass::User,
        sender,
        receiver: synergy_address::derive_object_address("synq", b"socket-receiver").unwrap(),
        amount_nwei: 7,
        nonce: 0,
        fee_limit: FeeLimit {
            gas_limit: 21000,
            max_fee_per_gas_nwei: 40,
        },
        timestamp_unix: 1_700_000_000,
        payload: vec![],
    };
    let signature = fixture_sign(
        account_secret.as_bytes(),
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &unsigned.signing_bytes().unwrap(),
    );
    (
        SignedTransaction {
            unsigned,
            signer_public_key: account.as_bytes().to_vec(),
            signature,
            signature_algorithm: "ML-DSA-87".into(),
            identity_authorization: Some(IdentityAuthorizationCarrier {
                schema_version: AUTHORIZATION_CARRIER_SCHEMA_VERSION,
                signature_domain: AEGIS_TRANSACTION_AUTHORIZATION_DOMAIN.into(),
                binding,
            }),
        },
        world,
        account_secret.as_bytes().to_vec(),
    )
}

fn fixture_encrypt_protected_payload(
    aad: &impl synergy_etdag::crypto::ProtectedPayloadAad,
    recipients: &[synergy_etdag::IngressKemKeyRecord],
    plaintext: &[u8],
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
) -> synergy_etdag::crypto::ProtectedPayload {
    if let Some(provider) = provider {
        let engine = synergy_aegis::load_authenticated_native_engine(
            &provider.report_path,
            &provider.authenticated_report_sha256,
        )
        .unwrap();
        let kem = synergy_aegis::ApqeKem::mlkem1024(engine).unwrap();
        synergy_etdag::crypto::encrypt_protected_payload_with_kem(
            aad, recipients, 4, plaintext, &kem,
        )
        .unwrap()
    } else {
        synergy_etdag::crypto::encrypt_protected_payload(aad, recipients, 4, plaintext).unwrap()
    }
}

fn processing_wallet_admission_fixture(
    transaction: &synergy_transaction::SignedTransaction,
    context: &synergy_etdag::ProcessingContext,
    authority: &authority::VerifiedAuthority,
    account_secret: &[u8],
) -> synergy_etdag::WalletProcessingAdmission {
    processing_wallet_admission_fixture_provider(
        transaction,
        context,
        authority,
        account_secret,
        None,
    )
}
fn processing_wallet_admission_fixture_provider(
    transaction: &synergy_transaction::SignedTransaction,
    context: &synergy_etdag::ProcessingContext,
    authority: &authority::VerifiedAuthority,
    account_secret: &[u8],
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
) -> synergy_etdag::WalletProcessingAdmission {
    use synergy_etdag::{
        ProcessingAdmissionRequest, ProcessingEnvelope, ProcessingEnvelopeAad,
        WalletProcessingAdmission, PROCESSING_PROFILE_ID,
    };
    let context_root = context.root().unwrap();
    let aad = ProcessingEnvelopeAad {
        profile_id: PROCESSING_PROFILE_ID.into(),
        chain_id: context.authority.chain_id,
        network_id: context.authority.network_id.clone(),
        protocol_version: context.authority.protocol_version.clone(),
        epoch: context.authority.epoch,
        processing_context_root: context_root.clone(),
        authorization_height: context.authority.target_height,
        assigned_cluster_id: context.authority.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: transaction.unsigned.sender.clone(),
        nonce_slot: transaction.unsigned.nonce,
    };
    let mut padded =
        synergy_etdag::crypto::pad_plaintext(&serde_json::to_vec(&transaction).unwrap()).unwrap();
    let payload = fixture_encrypt_protected_payload(
        &aad,
        &authority.protected_ingress_registry().unwrap().records,
        &padded,
        provider,
    );
    padded.fill(0);
    let mut envelope = ProcessingEnvelope {
        envelope_version: 1,
        envelope_id: digest("processing-placeholder"),
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: digest("processing-placeholder"),
        share_capsule_root: digest("processing-placeholder"),
        ciphertext: payload.ciphertext,
        content_blind_order_key: digest("processing-native-order"),
        share_capsules: payload.share_capsules,
    };
    envelope.refresh_capsule_roots().unwrap();
    envelope.envelope_id = envelope.commitment().unwrap();
    let mut request = ProcessingAdmissionRequest {
        request_version: 1,
        context_root,
        sender_wallet: transaction.unsigned.sender.clone(),
        sender_nonce: transaction.unsigned.nonce,
        gas_class_units: transaction.unsigned.fee_limit.gas_limit,
        fee_class: 1,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: transaction.signer_public_key.clone(),
        envelope,
        signature: Vec::new(),
    };
    request.signature = fixture_sign(
        account_secret,
        SignatureAlgorithm::MlDsa87,
        "processing-wallet",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &request.signing_bytes().unwrap(),
    );
    WalletProcessingAdmission {
        request,
        identity_authorization: transaction.identity_authorization.clone().unwrap(),
    }
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn processing_async_native_order_reveal_ready_and_execution_use_existing_posy_proofs() {
    use super::processing_pipeline::*;
    use synergy_etdag::{
        crypto::canonical_signing_bytes, execution::*, AvailabilityCertificate, AvailabilityVote,
        ProcessingContext, PROCESSING_PROFILE_ID,
    };
    use synergy_execution::{
        BlockExecutionScheduler, BudgetedExecutionCandidate, FeeSchedule, NativeTransferDispatcher,
        ProcessingCandidateContext,
    };
    use synergy_posy::{
        block_vote_signing_bytes, BlockVote, CertifiedCandidateSubject, ConsensusObjectContext,
        ProposalDeliveryPhase, ProposalDeliveryStatement, ProposalValidationCertificate,
        SimplifiedFinalityParent, SimplifiedQuorumCertificate, ThreeQcFinality,
        POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, PROPOSAL_ECHO_DOMAIN,
    };
    use synergy_state::world_resources::{BudgetedWorld, WorldResourceBudget};
    let provider = trusted_apqe_provider();
    let (transaction, mut world, mut account_secret) =
        funded_transaction_fixture_for_network_provider(
            "socket-qualification",
            10_000_000,
            Some(&provider),
        );
    // First-use public wallet: funding supplies no pre-enrollment. The full
    // encrypted carrier must survive admission, reveal, recovery and execution.
    world.protocol.insert(
        synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        b"{}".to_vec(),
    );
    let prepared =
        prepare_socket_fixture_profile_provider(world.clone(), None, true, None, Some(&provider));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(prepared.root.clone());
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    assert!(authority.processing_profile_enabled());
    let budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let genesis = BudgetedWorld::try_clone_world(&world, &budget).unwrap();
    let context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 3).unwrap().0,
    };
    let source =
        NativeProcessingContext::verify(&authority, &context, ProcessingSource::Genesis(&genesis))
            .unwrap();
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        &account_secret,
        Some(&provider),
    );
    account_secret.fill(0);
    let admission_handle = super::protected_admission::AdmissionHandle::default();
    assert!(admission_handle
        .enqueue_processing(admission.clone())
        .is_err());
    let publication = |context: &ProcessingContext| {
        serde_json::json!({
            "context": context,
            "ingress_kem_registry": authority.protected_ingress_registry().unwrap(),
        })
    };
    admission_handle
        .publish_processing_context(&authority, Some(publication(&context)))
        .unwrap();
    assert_eq!(
        admission_handle.processing_context().unwrap(),
        publication(&context)
    );
    let queued = admission_handle
        .enqueue_processing(admission.clone())
        .unwrap();
    let queued_bytes = admission_handle.stats().unwrap()["queued_bytes"]
        .as_u64()
        .unwrap();
    assert!(queued_bytes > 0);
    assert_eq!(
        admission_handle
            .enqueue_processing(admission.clone())
            .unwrap(),
        queued
    );
    assert_eq!(
        admission_handle.stats().unwrap()["queued_bytes"],
        queued_bytes
    );
    // A newer published anchor never rewrites or expires an already prepared
    // original envelope. Native source verification still authenticates intake.
    let later_context = ProcessingContext {
        authority: authority.protected_target(None, 4).unwrap().0,
        ..context.clone()
    };
    admission_handle
        .publish_processing_context(&authority, Some(publication(&later_context)))
        .unwrap();
    assert_eq!(
        admission_handle
            .enqueue_processing(admission.clone())
            .unwrap(),
        queued
    );
    let taken = admission_handle.take_processing().unwrap().unwrap();
    assert_eq!(taken.admission, admission);
    assert!(taken.owned_byte_charge() >= queued_bytes as usize);
    admission_handle.return_processing_pending(taken).unwrap();
    assert_eq!(
        admission_handle.stats().unwrap()["queued_bytes"],
        queued_bytes
    );
    let taken = admission_handle.take_processing().unwrap().unwrap();
    admission_handle
        .complete(&taken.id, Err("native test rejection".into()))
        .unwrap();
    assert_eq!(admission_handle.stats().unwrap()["queued_bytes"], 0);
    assert!(admission_handle.take_processing().unwrap().is_none());
    admission_handle
        .publish_processing_context(&authority, None)
        .unwrap();
    assert!(admission_handle.processing_context().is_err());
    assert!(admission_handle
        .enqueue_processing(admission.clone())
        .is_err());
    let sign = |index: usize, domain: &str, bytes: &[u8]| {
        fixture_sign(
            &fs::read(prepared.root.join(format!("node-{index}/consensus.key"))).unwrap(),
            SignatureAlgorithm::MlDsa65,
            &format!("consensus-{index}"),
            domain,
            Some(1),
            bytes,
        )
    };
    let mut vertex = ProcessingVertex {
        vertex_version: 1,
        envelope_ref: synergy_etdag::CertifiedEnvelopeRef {
            tx_commitment: admission.request.envelope.envelope_id.clone(),
            sender_id: admission.request.sender_wallet.clone(),
            nonce_slot: admission.request.sender_nonce,
            certified_dag_round: 0,
            gas_class_units: admission.request.gas_class_units,
            ciphertext_bytes: admission.request.envelope.ciphertext.len() as u64,
            fee_class: admission.request.fee_class,
            protocol_dependencies: vec![],
        },
        admission,
        parents: vec![],
        author_id: prepared.ids[0].clone(),
        key_id: "consensus-0".into(),
        author_signature: vec![],
    };
    vertex.author_signature = sign(
        0,
        "SYNERGY-ETDAG-SIGNATURE-V1",
        &vertex.signing_bytes().unwrap(),
    );
    let vertex_id = vertex.id().unwrap();
    let mut rewritten_authorization = vertex.clone();
    rewritten_authorization.admission.request.signature[0] ^= 1;
    assert_ne!(rewritten_authorization.id().unwrap(), vertex_id);

    let votes = (0..4)
        .map(|index| {
            let mut vote = AvailabilityVote {
                context_root: context.root().unwrap(),
                vertex_id: vertex_id.clone(),
                validator_id: prepared.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: vec![],
            };
            vote.signature = sign(
                index,
                "SYNERGY-ETDAG-SIGNATURE-V1",
                &canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .unwrap(),
            );
            vote
        })
        .collect();
    let availability =
        AvailabilityCertificate::from_votes(context.root().unwrap(), vertex_id, votes, 5).unwrap();
    let verified =
        NativeProcessingVertex::verify(&source, &vertex, &availability, &[], &budget).unwrap();
    // Pending recovery now uses the same authenticated native source instead
    // of a fixture that accepts caller-provided context/time assertions.
    let pending_root = prepared.root.join("native-processing-pending");
    let limits = super::processing_store::ProcessingStoreLimits {
        slots: 1,
        completion_bytes_per_item: 64 * 1024 * 1024,
    };
    let raw = serde_json::to_vec(&vertex.admission).unwrap();
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        processing_namespace(&authority, &budget).unwrap(),
        limits,
        &budget,
        &source,
    )
    .unwrap();
    pending
        .admit(
            &context,
            authority.consensus_timestamp_unix(3).unwrap(),
            &raw,
            &source,
        )
        .unwrap();
    drop(pending);
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        processing_namespace(&authority, &budget).unwrap(),
        limits,
        &budget,
        &source,
    )
    .unwrap();
    let pressure = budget.reserve(budget.available()).unwrap();
    pending
        .with_admission(
            &vertex.envelope_ref.tx_commitment,
            &source,
            |_, _, restored| {
                assert_eq!(restored, &vertex.admission);
                Ok(())
            },
        )
        .unwrap();
    drop(pressure);

    let mut corrupt_availability = availability.clone();
    corrupt_availability.votes[0].signature[0] ^= 1;
    let before = budget.used();
    assert!(
        NativeProcessingVertex::verify(&source, &vertex, &corrupt_availability, &[], &budget)
            .is_err()
    );
    assert_eq!(budget.used(), before);
    let namespace = processing_namespace(&authority, &budget).unwrap();
    let scheduler = BlockExecutionScheduler::new(
        NativeTransferDispatcher,
        super::execution::TransactionPqvmVerifier::from_authority(&authority, 1266),
        FeeSchedule {
            base_fee_per_gas_nwei: 40,
            collector: synergy_address::derive_object_address("synq", b"native-processing-fees")
                .unwrap(),
        },
    )
    .unwrap();
    let make_context = |height, parent_id, group| ProcessingCandidateContext {
        height,
        parent_block_id: parent_id,
        network: &transaction.unsigned.network,
        consensus_timestamp_unix: authority.consensus_timestamp_unix(height).unwrap(),
        namespace_root: &namespace,
        maximum_gas: 30_000_000,
        maximum_bytes: 8 * 1024 * 1024,
        finalized_authorization_state: &world,
        ordered_group: group,
    };
    let certify = |candidate: &BudgetedExecutionCandidate, parent: SimplifiedFinalityParent| {
        let context =
            ConsensusObjectContext::for_height(&authority.epoch, candidate.height, 0).unwrap();
        let subject = CertifiedCandidateSubject::new(
            context.clone(),
            candidate.block_id.clone(),
            candidate.parent_block_id.clone(),
            parent.clone(),
            candidate.protected_execution_root.clone(),
        )
        .unwrap();
        let echoes = (0..4)
            .map(|index| {
                let mut echo = ProposalDeliveryStatement {
                    context: context.clone(),
                    phase: ProposalDeliveryPhase::Echo,
                    candidate: subject.clone(),
                    validator_id: prepared.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: vec![],
                };
                echo.signature = sign(index, PROPOSAL_ECHO_DOMAIN, &echo.signing_bytes().unwrap());
                echo
            })
            .collect();
        let votes = (0..4)
            .map(|index| {
                let mut vote = BlockVote {
                    context: context.clone(),
                    block_id: candidate.block_id.clone(),
                    parent_block_id: candidate.parent_block_id.clone(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: candidate.protected_execution_root.clone(),
                    validator_id: prepared.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: vec![],
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    &block_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let vc = ProposalValidationCertificate {
            context,
            candidate: subject,
            echoes,
        };
        vc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        qc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        (vc, qc)
    };
    let parent = |qc: &SimplifiedQuorumCertificate| SimplifiedFinalityParent::QuorumCertificate {
        height: qc.context.height,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().unwrap(),
    };
    let genesis_parent = NativeProcessingParent::genesis(&genesis, &authority).unwrap();
    assert!(genesis_parent.reveal_permission(&verified).is_err());
    let genesis_pipeline = NativeProcessingPipeline::new(&genesis_parent, &[], &[]).unwrap();
    let first = scheduler
        .execute_processing_candidate(
            make_context(1, authority.anchor_parent.block_id(), None),
            &genesis,
            &[],
            &genesis_pipeline,
            &genesis_pipeline,
        )
        .unwrap();
    let (vc1, qc1) = certify(&first, authority.anchor_parent.clone());
    let authenticated1 = NativeProcessingParent::verify(&first, &vc1, &authority).unwrap();
    let retained_member = verified.retain_member(&budget).unwrap();
    let pipeline1 =
        NativeProcessingPipeline::from_members(&authenticated1, &[&retained_member], &[]).unwrap();
    let mut group1 = ProcessingOrderGroup {
        group_version: 1,
        namespace_root: namespace.clone(),
        group_number: 1,
        previous_group_root: processing_genesis_group_root(&namespace).unwrap(),
        order_seed: digest("placeholder"),
        members: vec![verified.member().clone()],
    };
    group1.order_seed = processing_order_seed(&authority, &group1).unwrap();
    let mut forged_group = group1.clone();
    forged_group.order_seed = digest("forged-order-seed");
    assert!(scheduler
        .execute_processing_candidate(
            make_context(2, &first.block_id, Some(&forged_group)),
            &first.state,
            &[],
            &pipeline1,
            &pipeline1
        )
        .is_err());
    let mut forged_member_group = group1.clone();
    forged_member_group.members[0].envelope.fee_class += 1;
    assert!(scheduler
        .execute_processing_candidate(
            make_context(2, &first.block_id, Some(&forged_member_group)),
            &first.state,
            &[],
            &pipeline1,
            &pipeline1
        )
        .is_err());
    let second = scheduler
        .execute_processing_candidate(
            make_context(2, &first.block_id, Some(&group1)),
            &first.state,
            &[],
            &pipeline1,
            &pipeline1,
        )
        .unwrap();
    let (vc2, qc2) = certify(&second, parent(&qc1));
    // A VC is not a QC. Existing PoSy takeover rules can admit a different
    // candidate at the same height; the runtime must not pin the first VC.
    let alternate = scheduler
        .execute_processing_candidate(
            make_context(2, &first.block_id, None),
            &first.state,
            &[],
            &pipeline1,
            &pipeline1,
        )
        .unwrap();
    let (mut alternate_vc, _) = certify(&alternate, parent(&qc1));
    alternate_vc.context.round = 1;
    for (index, echo) in alternate_vc.echoes.iter_mut().enumerate() {
        echo.context.round = 1;
        echo.signature = sign(index, PROPOSAL_ECHO_DOMAIN, &echo.signing_bytes().unwrap());
    }
    alternate_vc
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    let make_takeover = |carry: bool| {
        let reports = (0..4)
            .map(|index| {
                let mut vote = synergy_posy::TimeoutVote {
                    context: vc2.context.clone(),
                    lease_index: authority.epoch.lease_index(2).unwrap(),
                    timed_out_proposer: authority
                        .epoch
                        .authorized_proposer(2, 0)
                        .unwrap()
                        .to_owned(),
                    previous_tc_id: None,
                    highest_parent: parent(&qc1),
                    last_voted_candidate: carry.then(|| vc2.candidate.clone()),
                    validator_id: prepared.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: vec![],
                };
                vote.signature = sign(
                    index,
                    synergy_posy::POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                    &synergy_posy::timeout_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let tc = synergy_posy::SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(
            reports,
            vec![qc1.clone()],
        )
        .unwrap();
        let mut machine = synergy_posy::SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        machine
            .accept_quorum_certificate(qc1.clone(), authority.as_ref())
            .unwrap();
        machine
            .accept_timeout_certificate(tc, authority.as_ref())
            .unwrap();
        machine
    };
    let machine = make_takeover(false);
    let takeover = machine
        .accepted_timeout_certificate(machine.active_takeover_tc_id().unwrap())
        .unwrap();
    let carry_machine = make_takeover(true);
    let carry = carry_machine
        .accepted_timeout_certificate(carry_machine.active_takeover_tc_id().unwrap())
        .unwrap();
    let validation_root = prepared.root.join("processing-takeover-validation");
    let delivery = synergy_posy::ProposalDelivery::open(
        &validation_root,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    delivery
        .persist_validation(
            &vc2,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    let original_vc_bytes =
        synergy_posy::persistence::ConsensusEvidenceReader::open(&validation_root)
            .unwrap()
            .read_exact("validation-h2.json")
            .unwrap()
            .unwrap();
    let stale_delivery = synergy_posy::ProposalDelivery::open(
        &validation_root,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    stale_delivery
        .stored_validation(2, &authority.epoch, &authority.registry, authority.as_ref())
        .unwrap()
        .unwrap();
    assert!(delivery
        .persist_validation(
            &alternate_vc,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    assert!(delivery
        .persist_processing_validation(
            &alternate_vc,
            None,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    assert!(delivery
        .persist_processing_validation(
            &alternate_vc,
            Some(carry),
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    assert_eq!(
        synergy_posy::persistence::ConsensusEvidenceReader::open(&validation_root)
            .unwrap()
            .read_exact("validation-h2.json")
            .unwrap()
            .unwrap(),
        original_vc_bytes
    );
    let staged_old = Arc::new(
        scheduler
            .execute_processing_candidate(
                make_context(2, &first.block_id, Some(&group1)),
                &first.state,
                &[],
                &pipeline1,
                &pipeline1,
            )
            .unwrap(),
    );
    let alternate = Arc::new(alternate);
    let proposal_root = prepared.root.join("processing-proposal-inputs");
    let mut proposal_store = super::processing_proposals::ProcessingProposalStore::open(
        &proposal_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    let before_handoff = budget.used();
    let validation_ingress = ingress::AuthenticatedIngress::with_world_budget(Arc::clone(&budget));
    validation_ingress
        .initialize_processing_build_requests()
        .unwrap();
    let mut round_zero = synergy_posy::SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    round_zero
        .accept_quorum_certificate(qc1.clone(), authority.as_ref())
        .unwrap();
    validation_ingress
        .publish_processing_build_request(&round_zero)
        .unwrap();
    let obsolete_request = validation_ingress
        .processing_build_request()
        .unwrap()
        .unwrap();
    let obsolete_durable = proposal_store
        .stage(
            Arc::clone(&obsolete_request),
            Arc::clone(&staged_old),
            Some(&group1),
            &[],
        )
        .unwrap();
    let slot_pressure = budget.reserve(budget.available()).unwrap();
    // Native takeover publication uses its prepaid capacity even with unrelated
    // transaction allocations occupying every unreserved byte globally.
    validation_ingress
        .publish_processing_build_request(&machine)
        .unwrap();
    let request = validation_ingress
        .processing_build_request()
        .unwrap()
        .unwrap();
    assert_eq!(
        (request.context.height, request.context.round),
        machine.active_slot()
    );
    assert_eq!(request.parent, *machine.highest_parent());
    assert_eq!(
        request.proposer,
        authority.epoch.authorized_proposer(2, 1).unwrap()
    );
    assert_eq!(request.takeover.as_ref().unwrap().id(), takeover.id());
    validation_ingress
        .publish_processing_build_request(&machine)
        .unwrap();
    assert!(Arc::ptr_eq(
        &request,
        &validation_ingress
            .processing_build_request()
            .unwrap()
            .unwrap()
    ));
    drop(slot_pressure);
    let alternate_durable = proposal_store
        .stage(Arc::clone(&request), Arc::clone(&alternate), None, &[])
        .unwrap();
    let conflicting_durable = proposal_store
        .stage(
            Arc::clone(&request),
            Arc::clone(&staged_old),
            Some(&group1),
            &[],
        )
        .unwrap();
    // Native QC reception may precede this owner's durable ECHO proof under
    // resource pressure. Keep the staged original and retry; never archive or
    // reveal from a missing proof, nor classify an indexed corrupt file as pending.
    let header_before_validation = fs::read(proposal_root.join("proposal-inputs-v1.json")).unwrap();
    assert!(matches!(
        proposal_store.try_with_validation(&staged_old.block_id, |_| Ok(())),
        Err(super::processing_proposals::ProcessingProposalError::AwaitingValidation)
    ));
    assert!(proposal_store
        .try_archive_certified(&qc2, &staged_old)
        .err()
        .unwrap()
        .is_retryable());
    assert_eq!(
        fs::read(proposal_root.join("proposal-inputs-v1.json")).unwrap(),
        header_before_validation
    );
    proposal_store
        .persist_validation(&staged_old.block_id, &vc2)
        .unwrap();
    proposal_store
        .persist_validation(&alternate.block_id, &alternate_vc)
        .unwrap();
    let slot_pressure = budget.reserve(budget.available()).unwrap();
    validation_ingress
        .submit_processing_candidate(obsolete_durable)
        .unwrap();
    assert!(validation_ingress
        .take_processing_candidate()
        .unwrap()
        .is_none());
    validation_ingress
        .submit_processing_candidate(alternate_durable)
        .unwrap();
    let mut stage_candidates = std::collections::BTreeMap::from([(2, Arc::clone(&staged_old))]);
    let mut stage_rounds = std::collections::BTreeMap::from([(2, 0)]);
    super::posy::retain_processing_execution_candidate(
        &mut stage_candidates,
        &mut stage_rounds,
        validation_ingress
            .take_processing_candidate()
            .unwrap()
            .unwrap(),
        &machine,
    )
    .unwrap();
    assert_eq!(stage_candidates[&2].block_id, alternate.block_id);
    validation_ingress
        .submit_processing_candidate(conflicting_durable)
        .unwrap();
    assert!(super::posy::retain_processing_execution_candidate(
        &mut stage_candidates,
        &mut stage_rounds,
        validation_ingress
            .take_processing_candidate()
            .unwrap()
            .unwrap(),
        &machine
    )
    .is_err());
    assert_eq!(stage_candidates[&2].block_id, alternate.block_id);
    drop(stage_candidates);
    drop(obsolete_request);
    validation_ingress
        .clear_processing_build_requests()
        .unwrap();
    // The detached consumer owns the prepaid reservation after owner shutdown.
    assert!(validation_ingress.world_budget().used() > slot_pressure.bytes());
    drop(request);
    assert_eq!(
        validation_ingress.world_budget().used(),
        before_handoff + slot_pressure.bytes()
    );
    drop(slot_pressure);
    proposal_store
        .with_inputs(&staged_old.block_id, |inputs| {
            assert_eq!(inputs.ordered_group.as_ref(), Some(&group1));
            assert_eq!(inputs.context.round, 0); // Later envelope does not rewrite original inputs.
            Ok(())
        })
        .unwrap();
    drop(proposal_store);
    let mut proposal_store = super::processing_proposals::ProcessingProposalStore::open(
        &proposal_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    proposal_store
        .with_inputs(&alternate.block_id, |inputs| {
            assert!(inputs.ordered_group.is_none());
            assert_eq!(inputs.context.round, 1);
            assert_eq!(inputs.takeover_id.as_deref(), Some(takeover.id()));
            let replayed = scheduler
                .replay_processing_candidate(
                    &alternate,
                    ProcessingCandidateContext {
                        height: 2,
                        parent_block_id: &first.block_id,
                        network: &transaction.unsigned.network,
                        consensus_timestamp_unix: authority.consensus_timestamp_unix(2).unwrap(),
                        namespace_root: &namespace,
                        maximum_gas: 30_000_000,
                        maximum_bytes: 8 * 1024 * 1024,
                        finalized_authorization_state: &world,
                        ordered_group: inputs.ordered_group.as_ref(),
                    },
                    &first.state,
                    &inputs.publications,
                    &pipeline1,
                    &pipeline1,
                )
                .unwrap();
            assert_eq!(replayed.block_id, alternate.block_id);
            Ok(())
        })
        .unwrap();
    proposal_store
        .with_validation(&staged_old.block_id, |vc| {
            assert_eq!(vc, &vc2);
            Ok(())
        })
        .unwrap();
    proposal_store
        .with_validation(&alternate.block_id, |vc| {
            assert_eq!(vc, &alternate_vc);
            Ok(())
        })
        .unwrap();
    // Sync transports native replay inputs and the exact ECHO proof, never
    // grants transition authority merely because an incoming World hashes.
    let (sync_bytes, sync_permit) = proposal_store.export_sync(&staged_old.block_id).unwrap();
    // Real Val2 recovery regression: the first local replay envelope was R1,
    // while a delayed native R0 QC certified the exact same stable subject.
    let mut late_inputs: serde_json::Value = serde_json::from_slice(&sync_bytes).unwrap();
    late_inputs[1]["context"]["round"] = serde_json::json!(1);
    late_inputs[1]["takeover_id"] = serde_json::json!(takeover.id());
    let late_bytes = serde_json::to_vec(&late_inputs).unwrap();
    let late_root = prepared.root.join("late-envelope-earlier-qc");
    let mut late_store = super::processing_proposals::ProcessingProposalStore::open(
        &late_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    late_store
        .import_sync(&late_bytes, &staged_old, &qc2)
        .unwrap();
    late_store.try_import_certified(&late_bytes, &qc2).unwrap();
    let mut wrong_subject = late_inputs.clone();
    wrong_subject[1]["protected_execution_root"] =
        serde_json::json!(digest("wrong-certified-root").0);
    assert!(late_store
        .import_sync(
            &serde_json::to_vec(&wrong_subject).unwrap(),
            &staged_old,
            &qc2
        )
        .is_err());
    assert!(late_store
        .try_import_certified(&serde_json::to_vec(&wrong_subject).unwrap(), &qc2)
        .is_err());
    late_store.archive_certified(&qc2, &staged_old).unwrap();
    let archive_path = late_root.join("certified/00000000000000000002.json");
    let immutable_archive = fs::read(&archive_path).unwrap();
    let archive: serde_json::Value = serde_json::from_slice(&immutable_archive).unwrap();
    assert_eq!(archive["inputs"]["context"]["round"], 1);
    assert_eq!(archive["qc"]["context"]["round"], 0);
    drop(late_store);
    let reopened = super::processing_proposals::ProcessingProposalStore::open(
        &late_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    reopened.export_sync(&staged_old.block_id).unwrap();
    assert_eq!(fs::read(&archive_path).unwrap(), immutable_archive);
    drop(reopened);
    // Reproduce the lagging fleet receiver: 32 unreplayed empty proposals
    // occupy every speculative slot while authenticated Sync supplies a
    // different certified transition. Import must preserve every slot and use
    // the certified archive, never turn bounded admission pressure into a fatal.
    let full_root = prepared.root.join("processing-full-sync-inputs");
    let mut full_store = super::processing_proposals::ProcessingProposalStore::open(
        &full_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    let full_ingress = ingress::AuthenticatedIngress::with_world_budget(Arc::clone(&budget));
    full_ingress.initialize_processing_build_requests().unwrap();
    let mut full_machine = synergy_posy::SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    let recovery_qcs = synergy_posy::VerifiedQuorumCertificateStore::new(
        prepared.root.join("processing-stage-recovery-qcs"),
    )
    .unwrap();
    let mut full_state = Arc::new(BudgetedWorld::try_clone_world(&world, &budget).unwrap());
    let mut full_parent = authority.anchor_parent.clone();
    let mut full_vc = None;
    let mut full_candidate: Option<Arc<BudgetedExecutionCandidate>> = None;
    for height in 1..=32 {
        let native_parent = match (&full_candidate, &full_vc) {
            (Some(candidate), Some(vc)) => {
                NativeProcessingParent::verify(candidate, vc, &authority).unwrap()
            }
            _ => NativeProcessingParent::genesis(&full_state, &authority).unwrap(),
        };
        let pipeline = NativeProcessingPipeline::new(&native_parent, &[], &[]).unwrap();
        let candidate = Arc::new(
            scheduler
                .execute_processing_candidate(
                    ProcessingCandidateContext {
                        height,
                        parent_block_id: full_parent.block_id(),
                        network: &transaction.unsigned.network,
                        consensus_timestamp_unix: authority
                            .consensus_timestamp_unix(height)
                            .unwrap(),
                        namespace_root: &namespace,
                        maximum_gas: 30_000_000,
                        maximum_bytes: 8 * 1024 * 1024,
                        finalized_authorization_state: &world,
                        ordered_group: None,
                    },
                    &full_state,
                    &[],
                    &pipeline,
                    &pipeline,
                )
                .unwrap(),
        );
        full_ingress
            .publish_processing_build_request(&full_machine)
            .unwrap();
        full_store
            .stage(
                full_ingress.processing_build_request().unwrap().unwrap(),
                Arc::clone(&candidate),
                None,
                &[],
            )
            .unwrap();
        let (vc, qc) = certify(&candidate, full_parent);
        if height == 3 {
            full_store
                .persist_validation(&candidate.block_id, &vc)
                .unwrap();
            recovery_qcs
                .put_verified(
                    &qc,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
        }
        full_machine
            .accept_quorum_certificate(qc.clone(), authority.as_ref())
            .unwrap();
        drop(pipeline);
        drop(native_parent);
        full_state = Arc::clone(&candidate.state);
        full_parent = parent(&qc);
        full_vc = Some(vc);
        full_candidate = Some(candidate);
    }
    full_ingress
        .publish_processing_build_request(&round_zero)
        .unwrap();
    let recovery_request = full_ingress.processing_build_request().unwrap().unwrap();
    let full_slots = (0..32)
        .map(|slot| fs::read(full_root.join(format!("inputs/{slot:02}.json"))).unwrap())
        .collect::<Vec<_>>();
    let full_header = fs::read(full_root.join("proposal-inputs-v1.json")).unwrap();
    let full_error = full_store
        .try_stage(
            Arc::clone(&recovery_request),
            Arc::clone(&staged_old),
            Some(&group1),
            &[],
        )
        .err()
        .unwrap();
    assert!(matches!(
        full_error,
        super::processing_proposals::ProcessingProposalError::StagingFull
    ));
    assert!(full_error.is_retryable());
    assert_eq!(
        fs::read(full_root.join("proposal-inputs-v1.json")).unwrap(),
        full_header
    );
    assert!(full_store
        .try_import_certified(&serde_json::to_vec(&wrong_subject).unwrap(), &qc2)
        .is_err());
    assert!(!full_root
        .join("certified/00000000000000000002.json")
        .exists());
    full_store.try_import_certified(&sync_bytes, &qc2).unwrap();
    full_store
        .import_sync(&sync_bytes, &staged_old, &qc2)
        .unwrap();
    for (slot, original) in full_slots.iter().enumerate() {
        assert_eq!(
            &fs::read(full_root.join(format!("inputs/{slot:02}.json"))).unwrap(),
            original
        );
    }
    assert_eq!(
        full_store.export_sync(&staged_old.block_id).unwrap().0,
        sync_bytes
    );
    full_store.recover_certified_stages(&recovery_qcs).unwrap();
    assert_eq!(fs::read(full_root.join("inputs/02.json")).unwrap(), b"null");
    assert!(full_root
        .join("certified/00000000000000000003.json")
        .exists());
    // No QC exists for H1, so its safety input remains byte-for-byte intact.
    assert_eq!(
        fs::read(full_root.join("inputs/00.json")).unwrap(),
        full_slots[0]
    );
    drop(full_store);
    let full_store = super::processing_proposals::ProcessingProposalStore::open(
        &full_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    assert_eq!(
        full_store.export_sync(&staged_old.block_id).unwrap().0,
        sync_bytes
    );
    drop(full_store);
    drop(full_candidate);
    drop(full_state);
    drop(full_ingress);
    let sync_root = prepared.root.join("processing-sync-inputs");
    let mut sync_store = super::processing_proposals::ProcessingProposalStore::open(
        &sync_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    sync_store
        .stage(
            Arc::clone(&recovery_request),
            Arc::clone(&staged_old),
            Some(&group1),
            &[],
        )
        .unwrap();
    sync_store
        .persist_validation(&staged_old.block_id, &vc2)
        .unwrap();
    sync_store
        .import_sync(&sync_bytes, &staged_old, &qc2)
        .unwrap();
    let original_header = fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap();
    // Full-pool pressure must remain typed and leave the original candidate,
    // ECHO proof and generation intact. The native fixture supplies real signed
    // ordering/reveal authority; no synthetic certificate stands in for it.
    let retry_ingress = ingress::AuthenticatedIngress::with_world_budget(Arc::clone(&budget));
    retry_ingress
        .initialize_processing_build_requests()
        .unwrap();
    retry_ingress
        .publish_processing_build_request(&machine)
        .unwrap();
    let retry_request = retry_ingress.processing_build_request().unwrap().unwrap();
    let original_inputs = fs::read(sync_root.join("inputs/00.json")).unwrap();
    let original_validation = fs::read(sync_root.join("validations/00.json")).unwrap();
    let pressure = budget.reserve(budget.available()).unwrap();
    // An unfinalized order must remain an allocation-free async wait, including
    // while the original pending work owns the entire shared reservation.
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 1)
        .unwrap()
        .is_empty());
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 2)
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_load_inputs(&staged_old.block_id)
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_group_candidates(&group1.root().unwrap())
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_export_sync(&staged_old.block_id)
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_with_validation(&staged_old.block_id, |_| Ok(()))
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_stage(
            Arc::clone(&retry_request),
            Arc::clone(&staged_old),
            Some(&group1),
            &[]
        )
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_archive_certified(&qc2, &staged_old)
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_import_certified(&sync_bytes, &qc2)
        .err()
        .unwrap()
        .is_capacity());
    assert_eq!(budget.used(), budget.limit());
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        original_header
    );
    assert_eq!(
        fs::read(sync_root.join("inputs/00.json")).unwrap(),
        original_inputs
    );
    assert_eq!(
        fs::read(sync_root.join("validations/00.json")).unwrap(),
        original_validation
    );
    drop(pressure);
    drop(retry_request);
    drop(retry_ingress);
    assert_eq!(
        sync_store.try_export_sync(&staged_old.block_id).unwrap().0,
        sync_bytes
    );
    // Identical semantic retries preserve original records/generation.
    sync_store
        .import_sync(&sync_bytes, &staged_old, &qc2)
        .unwrap();
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        original_header
    );
    let mut corrupt: serde_json::Value = serde_json::from_slice(&sync_bytes).unwrap();
    let byte = corrupt[2]["echoes"][0]["signature"][0].as_u64().unwrap();
    corrupt[2]["echoes"][0]["signature"][0] = serde_json::json!(byte ^ 1);
    assert!(sync_store
        .import_sync(&serde_json::to_vec(&corrupt).unwrap(), &staged_old, &qc2)
        .is_err());
    assert!(!sync_store
        .try_import_certified(&serde_json::to_vec(&corrupt).unwrap(), &qc2)
        .err()
        .unwrap()
        .is_capacity());
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        original_header
    );
    assert!(sync_store
        .import_sync(&sync_bytes, &alternate, &qc2)
        .is_err());
    sync_store.archive_certified(&qc2, &staged_old).unwrap();
    let archived_header = fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap();
    let pressure = budget.reserve(budget.available()).unwrap();
    assert!(sync_store
        .try_archive_certified(&qc2, &staged_old)
        .err()
        .unwrap()
        .is_capacity());
    assert!(sync_store
        .try_compact_certified_stage(&qc2, &Default::default())
        .err()
        .unwrap()
        .is_capacity());
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        archived_header
    );
    assert_eq!(
        fs::read(sync_root.join("inputs/00.json")).unwrap(),
        original_inputs
    );
    assert_eq!(
        fs::read(sync_root.join("validations/00.json")).unwrap(),
        original_validation
    );
    drop(pressure);
    sync_store
        .compact_certified_stage(&qc2, &Default::default())
        .unwrap();
    assert_eq!(fs::read(sync_root.join("inputs/00.json")).unwrap(), b"null");
    let pressure = budget.reserve(budget.available()).unwrap();
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 1)
        .unwrap()
        .is_empty());
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 2)
        .err()
        .unwrap()
        .is_capacity());
    drop(pressure);
    assert_eq!(
        sync_store
            .try_group_candidates_at_or_below(&group1.root().unwrap(), 2)
            .unwrap(),
        vec![(2, staged_old.block_id.clone())]
    );
    // Deferral grants no proof authority. Once eligible, corrupt archived
    // native evidence is rejected by the unchanged full verification path.
    let archive_path = sync_root.join("certified/00000000000000000002.json");
    let original_archive = fs::read(&archive_path).unwrap();
    fs::write(&archive_path, b"{}").unwrap();
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 1)
        .unwrap()
        .is_empty());
    assert!(sync_store
        .try_group_candidates_at_or_below(&group1.root().unwrap(), 2)
        .is_err());
    fs::write(&archive_path, original_archive).unwrap();
    assert_eq!(
        sync_store.export_sync(&staged_old.block_id).unwrap().0,
        sync_bytes
    );
    sync_store
        .with_validation(&staged_old.block_id, |vc| {
            assert_eq!(vc, &vc2);
            Ok(())
        })
        .unwrap();
    drop(sync_store);
    let mut sync_store = super::processing_proposals::ProcessingProposalStore::open(
        &sync_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    assert_eq!(
        sync_store
            .try_group_candidates_at_or_below(&group1.root().unwrap(), 2)
            .unwrap(),
        vec![(2, staged_old.block_id.clone())]
    );
    assert_eq!(
        sync_store.export_sync(&staged_old.block_id).unwrap().0,
        sync_bytes
    );
    sync_store
        .prune_archive(4, 2, &std::collections::BTreeSet::from([2]))
        .unwrap();
    assert!(sync_store.export_sync(&staged_old.block_id).is_ok());
    let retained_header = fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap();
    sync_store
        .prune_archive(4, 2, &std::collections::BTreeSet::from([2]))
        .unwrap();
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        retained_header,
        "unchanged cleanup must not create a durable journal generation"
    );
    sync_store.prune_archive(4, 2, &Default::default()).unwrap();
    assert!(sync_store.export_sync(&staged_old.block_id).is_err());
    let pruned_header = fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap();
    drop(sync_store);
    let mut sync_store = super::processing_proposals::ProcessingProposalStore::open(
        &sync_root,
        namespace.clone(),
        &budget,
        Arc::clone(&authority),
    )
    .unwrap();
    sync_store.prune_archive(4, 2, &Default::default()).unwrap();
    assert_eq!(
        fs::read(sync_root.join("proposal-inputs-v1.json")).unwrap(),
        pruned_header,
        "recovery of caught-up cleanup must preserve the durable generation"
    );
    assert!(sync_store.export_sync(&staged_old.block_id).is_err());
    drop(sync_store);
    drop(sync_permit);
    struct StillReferenced;
    impl super::processing_proposals::ProcessingProposalRetirement for StillReferenced {
        fn verify_retirement(&self, _: u64, _: &str) -> Result<(), String> {
            Err("pending native reveal/recovery still references this candidate".into())
        }
    }
    let before_retirement = fs::read(proposal_root.join("proposal-inputs-v1.json")).unwrap();
    assert!(proposal_store
        .retire(&staged_old.block_id, &StillReferenced)
        .is_err());
    assert_eq!(
        fs::read(proposal_root.join("proposal-inputs-v1.json")).unwrap(),
        before_retirement
    );
    drop(proposal_store);
    validation_ingress
        .submit_proposal_validation(vc2.clone())
        .unwrap();
    assert!(validation_ingress
        .submit_processing_proposal_validation(alternate_vc.clone(), None)
        .is_err());
    assert!(validation_ingress
        .submit_processing_proposal_validation(alternate_vc.clone(), Some(carry))
        .is_err());
    delivery
        .persist_processing_validation(
            &alternate_vc,
            Some(takeover),
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    validation_ingress
        .submit_processing_proposal_validation(alternate_vc.clone(), Some(takeover))
        .unwrap();
    let replacement_bytes =
        synergy_posy::persistence::ConsensusEvidenceReader::open(&validation_root)
            .unwrap()
            .read_exact("validation-h2.json")
            .unwrap()
            .unwrap();
    assert!(stale_delivery
        .persist_processing_validation(
            &alternate_vc,
            Some(takeover),
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    assert_eq!(
        synergy_posy::persistence::ConsensusEvidenceReader::open(&validation_root)
            .unwrap()
            .read_exact("validation-h2.json")
            .unwrap()
            .unwrap(),
        replacement_bytes
    );
    assert_eq!(
        validation_ingress
            .proposal_validation(2)
            .unwrap()
            .unwrap()
            .id()
            .unwrap(),
        alternate_vc.id().unwrap()
    );
    let reopened_delivery = synergy_posy::ProposalDelivery::open(
        &validation_root,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    assert!(reopened_delivery
        .stored_validation_for(
            &vc2.candidate,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .unwrap()
        .is_none());
    assert_eq!(
        reopened_delivery
            .stored_validation_for(
                &alternate_vc.candidate,
                &authority.epoch,
                &authority.registry,
                authority.as_ref()
            )
            .unwrap()
            .unwrap(),
        alternate_vc
    );
    // Native disclosure below continues on the original independently verified
    // fixture branch; the isolated takeover store is not its finality authority.
    drop(alternate);
    drop(staged_old);
    let authenticated2 = NativeProcessingParent::verify(&second, &vc2, &authority).unwrap();
    assert!(authenticated2.reveal_permission(&verified).is_err());
    // A valid native parent proof cannot be reused for another candidate/World.
    assert!(NativeProcessingParent::verify(&second, &vc1, &authority).is_err());
    let mut bad_vc = vc2.clone();
    bad_vc.echoes[0].signature[0] ^= 1;
    assert!(NativeProcessingParent::verify(&second, &bad_vc, &authority).is_err());
    let pipeline2 = NativeProcessingPipeline::new(&authenticated2, &[&verified], &[]).unwrap();
    let mut group2 = ProcessingOrderGroup {
        group_version: 1,
        namespace_root: namespace.clone(),
        group_number: 2,
        previous_group_root: group1.root().unwrap(),
        order_seed: digest("placeholder"),
        members: vec![],
    };
    group2.order_seed = processing_order_seed(&authority, &group2).unwrap();
    let third = scheduler
        .execute_processing_candidate(
            make_context(3, &second.block_id, Some(&group2)),
            &second.state,
            &[],
            &pipeline2,
            &pipeline2,
        )
        .unwrap();
    let (vc3, qc3) = certify(&third, parent(&qc2));
    let authenticated3 = NativeProcessingParent::verify(&third, &vc3, &authority).unwrap();
    let permission = authenticated3.reveal_permission(&verified).unwrap();
    let mut shares = Vec::new();
    let kem = synergy_aegis::ApqeKem::mlkem1024(
        synergy_aegis::load_authenticated_native_engine(
            &provider.report_path,
            &provider.authenticated_report_sha256,
        )
        .unwrap(),
    )
    .unwrap();
    for index in 0..2 {
        let validator = &prepared.ids[index];
        let capsule = vertex
            .admission
            .request
            .envelope
            .share_capsules
            .iter()
            .find(|capsule| &capsule.validator_id == validator)
            .unwrap();
        let key = synergy_etdag::crypto::active_key_for_validator(
            authority.protected_ingress_registry().unwrap(),
            validator,
            context.authority.target_height,
        )
        .unwrap();
        let mut secret = fs::read(prepared.root.join(format!("node-{index}/ingress.key"))).unwrap();
        let share = synergy_etdag::crypto::decrypt_share_capsule_with_kem_diagnostic(
            &vertex.admission.request.envelope,
            capsule,
            key,
            &secret,
            false,
            &kem,
        )
        .unwrap();
        secret.fill(0);
        let mut message = ProcessingDecryptShare {
            share_version: 1,
            permission: permission.clone(),
            validator_id: validator.clone(),
            key_id: format!("consensus-{index}"),
            ingress_kem_key_id: key.key_id.clone(),
            share_index: share.index,
            share_commitment: capsule.share_commitment.clone(),
            share_bytes: share.canonical_bytes().unwrap(),
            signature: vec![],
        };
        message.signature = sign(
            index,
            "SYNERGY-ETDAG-SIGNATURE-V1",
            &message.signing_bytes().unwrap(),
        );
        shares.push(message);
    }
    let before = budget.used();
    assert!(NativeProcessingCompletion::decrypt(&authenticated2, &verified, &shares).is_err());
    assert!(NativeProcessingCompletion::decrypt(&authenticated3, &verified, &shares[..1]).is_err());
    assert!(NativeProcessingCompletion::decrypt(
        &authenticated3,
        &verified,
        &[shares[0].clone(), shares[0].clone()]
    )
    .is_err());
    let mut corrupt_shares = shares.clone();
    corrupt_shares[0].signature[0] ^= 1;
    assert!(
        NativeProcessingCompletion::decrypt(&authenticated3, &verified, &corrupt_shares).is_err()
    );
    assert_eq!(budget.used(), before);
    let full_pressure = budget.reserve(budget.available()).unwrap();
    assert!(NativeProcessingCompletion::decrypt(&authenticated3, &verified, &shares).is_err());
    drop(full_pressure);
    assert_eq!(budget.used(), before);
    // Already accepted work completes from prepaid ownership even while the
    // process-wide pool has no unreserved capacity.
    let full_pressure = budget.reserve(budget.available()).unwrap();
    let completion = pending
        .with_worker(
            &vertex.envelope_ref.tx_commitment,
            &source,
            |_, _, restored, workspace| {
                assert_eq!(restored, &vertex.admission);
                NativeProcessingCompletion::decrypt_in(
                    &authenticated3,
                    &verified,
                    &shares,
                    workspace,
                )
                .map_err(super::processing_store::ProcessingStoreError::Verification)
            },
        )
        .unwrap();
    drop(full_pressure);
    let recovery = NativeProcessingRecovery {
        source: &source,
        reveal_parent: &third,
        dag_parents: &[],
    };
    let evidence = ProcessingCompletionEvidence::from_inputs(
        &vertex,
        &availability,
        &vc3,
        &shares,
        &completion.record,
    );
    let original_pending = fs::read(pending_root.join("slots/0000.json")).unwrap();
    let mut progress = ProcessingProgressEvidence::from_vertex(&vertex);
    let full_pressure = budget.reserve(budget.available()).unwrap();
    pending
        .update_progress(&vertex.envelope_ref.tx_commitment, &progress, &recovery)
        .unwrap();
    progress.availability = Some(availability.clone());
    pending
        .update_progress(&vertex.envelope_ref.tx_commitment, &progress, &recovery)
        .unwrap();
    progress.reveal_validation = Some(vc3.clone());
    progress.shares = shares[..1].to_vec();
    pending
        .update_progress(&vertex.envelope_ref.tx_commitment, &progress, &recovery)
        .unwrap();
    let original_progress = fs::read(pending_root.join("progress/0000.json")).unwrap();
    let progress_header = fs::read(pending_root.join("pending-v1.json")).unwrap();
    let mut corrupt_progress = progress.clone();
    corrupt_progress.shares[0].signature[0] ^= 1;
    assert!(pending
        .update_progress(
            &vertex.envelope_ref.tx_commitment,
            &corrupt_progress,
            &recovery
        )
        .is_err());
    assert!(pending
        .update_progress(
            &vertex.envelope_ref.tx_commitment,
            &ProcessingProgressEvidence::from_vertex(&vertex),
            &recovery
        )
        .is_err());
    assert_eq!(
        fs::read(pending_root.join("progress/0000.json")).unwrap(),
        original_progress
    );
    assert_eq!(
        fs::read(pending_root.join("pending-v1.json")).unwrap(),
        progress_header
    );
    assert_eq!(
        fs::read(pending_root.join("slots/0000.json")).unwrap(),
        original_pending
    );
    drop(full_pressure);
    drop(pending);
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &recovery,
    )
    .unwrap();
    assert!(!pending.has_completion(&vertex.envelope_ref.tx_commitment));
    pending
        .with_progress(
            &vertex.envelope_ref.tx_commitment,
            &recovery,
            |admission, restored, _| {
                assert_eq!(admission, &vertex.admission);
                assert_eq!(restored, Some(&progress));
                Ok(())
            },
        )
        .unwrap();
    let full_pressure = budget.reserve(budget.available()).unwrap();
    pending
        .complete(&vertex.envelope_ref.tx_commitment, &evidence, &recovery)
        .unwrap();
    // Exact retransmission is idempotent, and corrupt proofs cannot overwrite
    // either immutable request or the accepted native completion.
    let durable_completion = fs::read(pending_root.join("completions/0000.json")).unwrap();
    let durable_header = fs::read(pending_root.join("pending-v1.json")).unwrap();
    pending
        .complete(&vertex.envelope_ref.tx_commitment, &evidence, &recovery)
        .unwrap();
    let mut equivalent_evidence = evidence.clone();
    equivalent_evidence.shares.reverse();
    pending
        .complete(
            &vertex.envelope_ref.tx_commitment,
            &equivalent_evidence,
            &recovery,
        )
        .unwrap();
    let mut corrupted_evidence = evidence.clone();
    corrupted_evidence.shares[0].signature[0] ^= 1;
    assert!(pending
        .complete(
            &vertex.envelope_ref.tx_commitment,
            &corrupted_evidence,
            &recovery
        )
        .is_err());
    assert_eq!(
        fs::read(pending_root.join("slots/0000.json")).unwrap(),
        original_pending
    );
    assert_eq!(
        fs::read(pending_root.join("completions/0000.json")).unwrap(),
        durable_completion
    );
    assert_eq!(
        fs::read(pending_root.join("pending-v1.json")).unwrap(),
        durable_header
    );
    drop(full_pressure);
    let pipeline3 =
        NativeProcessingPipeline::new(&authenticated3, &[&verified], &[&completion]).unwrap();
    let fourth = scheduler
        .execute_processing_candidate(
            make_context(4, &third.block_id, None),
            &third.state,
            std::slice::from_ref(&completion.record),
            &pipeline3,
            &pipeline3,
        )
        .unwrap();
    assert!(fourth.transactions.is_empty());
    assert_eq!(fourth.state.accounts, world.accounts);
    let (vc4, qc4) = certify(&fourth, parent(&qc3));
    let authenticated4 = NativeProcessingParent::verify(&fourth, &vc4, &authority).unwrap();
    let pipeline4 =
        NativeProcessingPipeline::new(&authenticated4, &[&verified], &[&completion]).unwrap();
    let fifth = scheduler
        .execute_processing_candidate(
            make_context(5, &fourth.block_id, None),
            &fourth.state,
            &[],
            &pipeline4,
            &pipeline4,
        )
        .unwrap();
    assert!(
        synergy_identity::authorization::canonical_binding_commitment_if_present(
            &fourth.state.protocol,
            &transaction.unsigned.sender,
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        synergy_identity::authorization::canonical_binding_commitment(
            &fifth.state.protocol,
            &transaction.unsigned.sender,
        )
        .unwrap()
        .binding_payload_sha3_256,
        transaction
            .identity_authorization
            .as_ref()
            .unwrap()
            .binding
            .binding_payload_sha3_256
    );
    assert_eq!(fifth.transactions, vec![transaction.clone()]);
    assert_eq!(
        fifth.receipts[0].status,
        synergy_transaction::ReceiptStatus::Applied
    );
    assert_eq!(fifth.state.accounts[&transaction.unsigned.sender].nonce, 1);
    assert_eq!(
        fifth.state.accounts[&transaction.unsigned.receiver].balance_nwei,
        transaction.unsigned.amount_nwei
    );
    assert_eq!(
        scheduler
            .replay_processing_candidate(
                &fifth,
                make_context(5, &fourth.block_id, None),
                &fourth.state,
                &[],
                &pipeline4,
                &pipeline4
            )
            .unwrap(),
        fifth
    );
    let (vc5, qc5) = certify(&fifth, parent(&qc4));
    let authenticated5 = NativeProcessingParent::verify(&fifth, &vc5, &authority).unwrap();
    let pipeline5 = NativeProcessingPipeline::new(&authenticated5, &[], &[]).unwrap();
    let sixth = scheduler
        .execute_processing_candidate(
            make_context(6, &fifth.block_id, None),
            &fifth.state,
            &[],
            &pipeline5,
            &pipeline5,
        )
        .unwrap();
    let (vc6, qc6) = certify(&sixth, parent(&qc5));
    let authenticated6 = NativeProcessingParent::verify(&sixth, &vc6, &authority).unwrap();
    let pipeline6 = NativeProcessingPipeline::new(&authenticated6, &[], &[]).unwrap();
    let seventh = scheduler
        .execute_processing_candidate(
            make_context(7, &sixth.block_id, None),
            &sixth.state,
            &[],
            &pipeline6,
            &pipeline6,
        )
        .unwrap();
    let (vc7, qc7) = certify(&seventh, parent(&qc6));
    // An imported current tip can be valid while the older authorization
    // source candidate and its execution history are both absent.
    {
        use crate::commands::checkpoint::{Action, Request};
        use synergy_posy::persistence::FinalityStore;
        use synergy_posy::{SignOnceJournal, VerifiedQuorumCertificateStore};
        use synergy_state::{FinalizedState, FinalizedStateStore};
        use synergy_storage::NodeStorageLayout;

        let authenticated7 = NativeProcessingParent::verify(&seventh, &vc7, &authority).unwrap();
        let pipeline7 = NativeProcessingPipeline::new(&authenticated7, &[], &[]).unwrap();
        let eighth = scheduler
            .execute_processing_candidate(
                make_context(8, &seventh.block_id, None),
                &seventh.state,
                &[],
                &pipeline7,
                &pipeline7,
            )
            .unwrap();
        let (_, qc8) = certify(&eighth, parent(&qc7));
        checkpoint_recovery::qualify_authorization_bundle(
            &prepared,
            &authority,
            [&fourth, &fifth, &sixth],
            [&qc1, &qc2, &qc3, &qc4, &qc5, &qc6, &qc7, &qc8],
            &vc6,
        );
        let mut target = prepared.configurations[0].clone();
        target.storage.data_directory = prepared.root.join("missing-authorization-source");
        let layout = NodeStorageLayout::new(target.storage.data_directory.clone()).unwrap();
        let posy = layout.consensus().join("posy");
        let qcs = VerifiedQuorumCertificateStore::new(&posy).unwrap();
        let finality = FinalityStore::new(&posy).unwrap();
        let mut chain = ThreeQcFinality::default();
        for qc in [&qc1, &qc2, &qc3, &qc4, &qc5, &qc6, &qc7, &qc8] {
            qcs.put_verified(
                qc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
            let previous = chain.last_finalized().cloned();
            if let Some(record) = chain.accept(qc.clone()).unwrap() {
                finality
                    .commit_exactly_once(&record, previous.as_ref())
                    .unwrap();
            }
        }
        assert_eq!(chain.last_finalized().unwrap().block_id, sixth.block_id);
        let commitment = |candidate: &BudgetedExecutionCandidate| FinalizedState {
            finalized_height: candidate.height,
            finalized_block_id: candidate.block_id.clone(),
            state_root: candidate.state_root.clone(),
        };
        let state_path = layout.state().join("execution");
        let candidate_path = layout.blocks().join("execution-candidates");
        let journal_path = posy.join("sign-once.json");
        let mut journal = SignOnceJournal::load(&journal_path).unwrap();
        journal.advance_finalized_floor(sixth.height).unwrap();
        let original_journal = fs::read(&journal_path).unwrap();
        let mut state =
            FinalizedStateStore::load_budgeted(&state_path, Arc::clone(&budget)).unwrap();
        state
            .commit_verified_snapshot(commitment(&sixth), &sixth.state)
            .unwrap();
        let mut candidates =
            synergy_execution::CandidateStore::new_budgeted(&candidate_path, Arc::clone(&budget))
                .unwrap();
        candidates.put_budgeted(&sixth, &sixth.state).unwrap();
        assert!(candidates.get_budgeted(fifth.height).unwrap().is_none());
        assert!(state.history_at(fifth.height).unwrap().is_none());
        drop((state, candidates));

        let request = Request {
            action: Action::RestoreAuthorizationSource,
            config: prepared.root.join("unused-fixture-config.json"),
            bundle: prepared.root.join("authorization-source.json"),
            from: None,
        };
        let run = || super::checkpoint::fixture_run(&request, &target, None);
        let assert_target = |restored: bool| {
            let state =
                FinalizedStateStore::load_budgeted(&state_path, Arc::clone(&budget)).unwrap();
            assert_eq!(state.current(), Some(&commitment(&sixth)));
            assert_eq!(
                state.history_at(fifth.height).unwrap(),
                restored.then(|| commitment(&fifth))
            );
            let candidates = synergy_execution::CandidateStore::new_budgeted(
                &candidate_path,
                Arc::clone(&budget),
            )
            .unwrap();
            assert_eq!(
                candidates.get_budgeted(fifth.height).unwrap().as_ref(),
                restored.then_some(&fifth)
            );
            assert_eq!(candidates.pinned_descriptors().len(), usize::from(restored));
            assert_eq!(fs::read(&journal_path).unwrap(), original_journal);
        };
        write_json(&request.bundle, &sixth);
        assert!(run()
            .unwrap_err()
            .contains("not the current exact authorization source"));
        assert_target(false);
        let mut substituted = serde_json::to_value(&fifth).unwrap();
        substituted["block_id"] = sixth.block_id.clone().into();
        write_json(&request.bundle, &substituted);
        assert!(run().is_err());
        assert_target(false);
        write_json(&request.bundle, &fifth);
        let restored = run().unwrap();
        assert_eq!(restored["source_height"], fifth.height);
        assert_eq!(restored["finalized_height"], sixth.height);
        assert_target(true);
        assert_eq!(run().unwrap(), restored);
        assert_target(true);
    }
    let witness = [qc5, qc6, qc7];
    let mut finality = ThreeQcFinality::default();
    for qc in &witness {
        finality.accept(qc.clone()).unwrap();
    }
    assert_eq!(finality.last_finalized().unwrap().block_id, fifth.block_id);
    let next_context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority
            .protected_target(
                finality.last_finalized(),
                5 + authority
                    .protected_parameters()
                    .unwrap()
                    .target_height_offset,
            )
            .unwrap()
            .0,
    };
    let _next_source = NativeProcessingContext::verify(
        &authority,
        &next_context,
        ProcessingSource::Finalized {
            candidate: &fifth,
            witness: &witness,
        },
    )
    .unwrap();
    // The same finalized snapshot cannot authorize a different context/root or
    // network. These are native three-QC source checks, not RPC shape checks.
    let mut foreign_network = next_context.clone();
    foreign_network.authority.network_id.push_str("-foreign");
    let mut foreign_chain = next_context.clone();
    foreign_chain.authority.chain_id += 1;
    for changed in [foreign_network, foreign_chain] {
        assert!(NativeProcessingContext::verify(
            &authority,
            &changed,
            ProcessingSource::Finalized {
                candidate: &fifth,
                witness: &witness
            }
        )
        .is_err());
    }
    let mut wrong_root = next_context.clone();
    wrong_root.authority.source_finality_context_root = "0".repeat(64);
    assert!(NativeProcessingContext::verify(
        &authority,
        &wrong_root,
        ProcessingSource::Finalized {
            candidate: &fifth,
            witness: &witness
        }
    )
    .is_err());
    drop(pipeline3);
    drop(pipeline4);
    drop(completion);
    drop(pending);
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &recovery,
    )
    .unwrap();
    let full_pressure = budget.reserve(budget.available()).unwrap();
    pending
        .with_completion(
            &vertex.envelope_ref.tx_commitment,
            &recovery,
            |restored, proof, workspace| {
                recovery
                    .with_completion(restored, proof, workspace, |reconstructed| {
                        assert_eq!(reconstructed.record, evidence.record);
                        Ok(())
                    })
                    .map_err(super::processing_store::ProcessingStoreError::Verification)
            },
        )
        .unwrap();
    drop(full_pressure);
    drop(pending);
    // Shape-valid journal tampering must fail native recovery and preserve the
    // evidence byte-for-byte, with all partially recovered quota rolled back.
    let mut corrupted: serde_json::Value = serde_json::from_slice(&durable_completion).unwrap();
    let original_signature_byte = corrupted["evidence"]["shares"][0]["signature"][0]
        .as_u64()
        .unwrap();
    corrupted["evidence"]["shares"][0]["signature"][0] =
        serde_json::json!(original_signature_byte ^ 1);
    let corrupted_bytes = serde_json::to_vec(&corrupted).unwrap();
    fs::write(pending_root.join("completions/0000.json"), &corrupted_bytes).unwrap();
    let before_recovery = budget.used();
    assert!(super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &recovery,
    )
    .is_err());
    assert_eq!(budget.used(), before_recovery);
    assert_eq!(
        fs::read(pending_root.join("completions/0000.json")).unwrap(),
        corrupted_bytes
    );
    fs::write(
        pending_root.join("completions/0000.json"),
        durable_completion,
    )
    .unwrap();
    let mut durable_candidates = synergy_execution::CandidateStore::new_budgeted(
        prepared.root.join("native-processing-candidates"),
        Arc::clone(&budget),
    )
    .unwrap();
    let mut durable_states = synergy_state::FinalizedStateStore::load_budgeted(
        prepared.root.join("native-processing-state"),
        Arc::clone(&budget),
    )
    .unwrap();
    let durable_finality = synergy_posy::persistence::FinalityStore::new(
        prepared.root.join("native-processing-finality"),
    )
    .unwrap();
    let chain = [&first, &second, &third, &fourth, &fifth, &sixth, &seventh];
    // A retained authorization source can contain another wallet/nonce's
    // transaction after its parent has been pruned. A cold pending-owner scan
    // must not demand that unrelated retirement proof, nor turn its absence
    // into permission to retire a matching pending envelope.
    let sparse_root = prepared.root.join("sparse-retirement-source");
    let mut sparse =
        synergy_execution::CandidateStore::new_budgeted(&sparse_root, Arc::clone(&budget)).unwrap();
    sparse.pin_budgeted(&fifth).unwrap();
    drop(sparse);
    let selected = &fifth.transactions[0].unsigned;
    let matching = super::processing_store::PendingProcessingIdentity {
        envelope_id: vertex.envelope_ref.tx_commitment.clone(),
        context_root: context.root().unwrap(),
        sender_wallet: selected.sender.clone(),
        sender_nonce: selected.nonce,
    };
    let mut unrelated = matching.clone();
    unrelated.sender_nonce += 1;
    assert!(NativeProcessingRetirement::recover_pending(
        &authority,
        fifth.height,
        &fifth.block_id,
        &sparse_root,
        &prepared.root.join("native-processing-state"),
        &prepared.root.join("native-processing-finality"),
        std::iter::once(&unrelated),
        &budget,
    )
    .unwrap()
    .is_none());
    unrelated = matching.clone();
    unrelated.sender_wallet.push_str("-other");
    assert!(NativeProcessingRetirement::recover_pending(
        &authority,
        fifth.height,
        &fifth.block_id,
        &sparse_root,
        &prepared.root.join("native-processing-state"),
        &prepared.root.join("native-processing-finality"),
        std::iter::once(&unrelated),
        &budget,
    )
    .unwrap()
    .is_none());
    assert!(NativeProcessingRetirement::recover_pending(
        &authority,
        fifth.height,
        &fifth.block_id,
        &sparse_root,
        &prepared.root.join("native-processing-state"),
        &prepared.root.join("native-processing-finality"),
        std::iter::once(&matching),
        &budget,
    )
    .err()
    .unwrap()
    .contains("parent is unavailable"));
    let mut previous_world = &genesis;
    for candidate in chain {
        durable_candidates
            .put_budgeted(candidate, previous_world)
            .unwrap();
        previous_world = candidate.state.as_ref();
    }
    let mut finality_chain = ThreeQcFinality::default();
    for qc in [&qc1, &qc2, &qc3, &qc4].into_iter().chain(witness.iter()) {
        let previous = finality_chain.last_finalized().cloned();
        if let Some(record) = finality_chain.accept(qc.clone()).unwrap() {
            durable_finality
                .commit_exactly_once(&record, previous.as_ref())
                .unwrap();
        }
    }
    // A three-QC proof alone never retires an uncommitted execution payload.
    assert!(NativeProcessingRetirement::verify(
        &authority,
        &fifth,
        &fourth,
        &witness,
        &durable_candidates,
        &durable_states,
        &durable_finality,
        0,
        &budget
    )
    .is_err());
    let mut previous_world = &genesis;
    for candidate in &chain[..5] {
        durable_states
            .commit_verified_world_transition(
                synergy_state::FinalizedState {
                    finalized_height: candidate.height,
                    finalized_block_id: candidate.block_id.clone(),
                    state_root: candidate.state_root.clone(),
                },
                previous_world,
                &candidate.state,
            )
            .unwrap();
        previous_world = candidate.state.as_ref();
    }
    assert!(NativeProcessingRetirement::verify(
        &authority,
        &fifth,
        &fourth,
        &witness,
        &durable_candidates,
        &durable_states,
        &durable_finality,
        1,
        &budget
    )
    .is_err());
    let retirement = NativeProcessingRetirement::verify(
        &authority,
        &fifth,
        &fourth,
        &witness,
        &durable_candidates,
        &durable_states,
        &durable_finality,
        0,
        &budget,
    )
    .unwrap();
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &recovery,
    )
    .unwrap();
    use super::processing_store::{
        PendingProcessingIdentity, ProcessingAdmissionAuthenticator, ProcessingRetirementVerifier,
    };
    let full_pressure = budget.reserve(budget.available()).unwrap();
    // Native completion ownership must delay quiescence, without preventing
    // exact finality marking from the existing prepaid worker envelope.
    let cached = pending
        .with_completion(
            &vertex.envelope_ref.tx_commitment,
            &recovery,
            |admission, proof, workspace| {
                recovery
                    .recover(admission, proof, workspace)
                    .map_err(super::processing_store::ProcessingStoreError::Verification)
            },
        )
        .unwrap();
    let before_marker_header = fs::read(pending_root.join("pending-v1.json")).unwrap();
    assert!(pending
        .mark_finalized(
            &vertex.envelope_ref.tx_commitment,
            fifth.height + 1,
            &fifth.block_id,
            &retirement
        )
        .is_err());
    assert!(pending
        .mark_finalized(
            &vertex.envelope_ref.tx_commitment,
            fifth.height,
            &"a".repeat(64),
            &retirement
        )
        .is_err());
    assert_eq!(
        fs::read(pending_root.join("pending-v1.json")).unwrap(),
        before_marker_header
    );
    assert!(!pending_root.join("finalized/0000.json").exists());
    pending
        .mark_finalized(
            &vertex.envelope_ref.tx_commitment,
            fifth.height,
            &fifth.block_id,
            &retirement,
        )
        .unwrap();
    assert_eq!(pending.pending_identities().count(), 0);
    assert_eq!(pending.finalized_identities().count(), 1);
    assert!(pending
        .with_worker(
            &vertex.envelope_ref.tx_commitment,
            &recovery,
            |_, _, _, _| Ok(())
        )
        .is_err());
    assert!(!pending
        .try_quiesce_finalized(&vertex.envelope_ref.tx_commitment)
        .unwrap());
    assert_eq!(cached.record, evidence.record);
    let with_cache = budget.used();
    drop(cached);
    assert!(pending
        .try_quiesce_finalized(&vertex.envelope_ref.tx_commitment)
        .unwrap());
    assert!(budget.used() + 32 * 1024 * 1024 < with_cache);
    let terminal_budget = pending
        .retirement_budget(&vertex.envelope_ref.tx_commitment)
        .unwrap();
    assert!(
        terminal_budget.limit() < original_pending.len() * 16 + 1024 * 1024,
        "terminal byte checks retained the original decoding workspace"
    );
    drop(terminal_budget);
    drop(full_pressure);
    assert_eq!(
        fs::read(pending_root.join("slots/0000.json")).unwrap(),
        original_pending
    );
    let marker_bytes = fs::read(pending_root.join("finalized/0000.json")).unwrap();
    let preserved_completion = fs::read(pending_root.join("completions/0000.json")).unwrap();
    let preserved_progress = fs::read(pending_root.join("progress/0000.json")).unwrap();
    let replay_used = budget.used();
    let replay_header = fs::read(pending_root.join("pending-v1.json")).unwrap();
    assert_eq!(
        pending
            .with_finalized_progress(&vertex.envelope_ref.tx_commitment, |progress, _| Ok(
                progress.shares.len()
            ))
            .unwrap(),
        Some(progress.shares.len())
    );
    assert_eq!(
        budget.used(),
        replay_used,
        "temporary reveal replay charge leaked"
    );
    let pressure = budget.reserve(budget.available()).unwrap();
    assert!(matches!(
        pending.with_finalized_progress(&vertex.envelope_ref.tx_commitment, |_, _| Ok(())),
        Err(super::processing_store::ProcessingStoreError::Resource(_))
    ));
    drop(pressure);
    let mut corrupt_progress = preserved_progress.clone();
    corrupt_progress.push(b' ');
    fs::write(pending_root.join("progress/0000.json"), &corrupt_progress).unwrap();
    assert!(pending
        .with_finalized_progress(&vertex.envelope_ref.tx_commitment, |_, _| Ok(()))
        .is_err());
    assert_eq!(budget.used(), replay_used);
    assert_eq!(
        fs::read(pending_root.join("progress/0000.json")).unwrap(),
        corrupt_progress
    );
    fs::write(pending_root.join("progress/0000.json"), &preserved_progress).unwrap();
    assert_eq!(
        fs::read(pending_root.join("pending-v1.json")).unwrap(),
        replay_header
    );
    drop(pending);
    struct FinalizedAuth<'a, F> {
        source: &'a NativeProcessingContext<'a>,
        finalized: F,
        calls: &'a std::cell::Cell<usize>,
    }
    impl<F> ProcessingAdmissionAuthenticator for FinalizedAuth<'_, F>
    where
        F: Fn(
            &PendingProcessingIdentity,
            u64,
            &str,
            &str,
            &Arc<WorldResourceBudget>,
        ) -> Result<(), String>,
    {
        fn verify(
            &self,
            context: &ProcessingContext,
            timestamp: u64,
            admission: &synergy_etdag::WalletProcessingAdmission,
        ) -> Result<(), String> {
            ProcessingAdmissionAuthenticator::verify(self.source, context, timestamp, admission)
        }
        fn verify_finalized(
            &self,
            identity: &PendingProcessingIdentity,
            height: u64,
            id: &str,
            root: &str,
            budget: &Arc<WorldResourceBudget>,
        ) -> Result<(), String> {
            self.calls.set(self.calls.get() + 1);
            (self.finalized)(identity, height, id, root, budget)
        }
        fn verify_completion(
            &self,
            _: &ProcessingContext,
            _: &synergy_etdag::WalletProcessingAdmission,
            _: &ProcessingCompletionEvidence,
            _: &Arc<WorldResourceBudget>,
        ) -> Result<(), String> {
            panic!("terminal completion must not decrypt on restart")
        }
        fn verify_progress(
            &self,
            _: &ProcessingContext,
            _: &synergy_etdag::WalletProcessingAdmission,
            _: &ProcessingProgressEvidence,
            _: &Arc<WorldResourceBudget>,
        ) -> Result<(), String> {
            panic!("terminal progress must retain exact bytes without replay")
        }
    }
    let finalized_calls = std::cell::Cell::new(0);
    let terminal_auth = FinalizedAuth {
        source: &source,
        calls: &finalized_calls,
        finalized: |identity: &PendingProcessingIdentity,
                    height: u64,
                    id: &str,
                    root: &str,
                    workspace: &Arc<WorldResourceBudget>| {
            let proof = NativeProcessingRetirement::verify(
                &authority,
                &fifth,
                &fourth,
                &witness,
                &durable_candidates,
                &durable_states,
                &durable_finality,
                0,
                workspace,
            )?;
            if proof.finalized_subject() != Some((height, id))
                || proof.finalized_state_root() != Some(root)
            {
                return Err("terminal marker differs from native finalized subject/root".into());
            }
            proof.verify_retirement(identity)
        },
    };
    // Shape-valid marker tampering cannot acquire native finality authority.
    for field in ["block_id", "state_root"] {
        let mut corrupt: serde_json::Value = serde_json::from_slice(&marker_bytes).unwrap();
        corrupt[field] = "f".repeat(64).into();
        let bytes = serde_json::to_vec(&corrupt).unwrap();
        fs::write(pending_root.join("finalized/0000.json"), &bytes).unwrap();
        let before = budget.used();
        assert!(super::processing_store::PendingProcessingStore::open(
            &pending_root,
            namespace.clone(),
            limits,
            &budget,
            &terminal_auth
        )
        .is_err());
        assert_eq!(budget.used(), before);
        assert_eq!(
            fs::read(pending_root.join("finalized/0000.json")).unwrap(),
            bytes
        );
        assert_eq!(
            fs::read(pending_root.join("slots/0000.json")).unwrap(),
            original_pending
        );
    }
    fs::write(pending_root.join("finalized/0000.json"), &marker_bytes).unwrap();
    let mut pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &terminal_auth,
    )
    .unwrap();
    assert!(finalized_calls.get() >= 3);
    assert_eq!(pending.identities().count(), 1);
    assert_eq!(pending.pending_identities().count(), 0);
    assert_eq!(pending.finalized_identities().count(), 1);
    let replay_used = budget.used();
    assert_eq!(
        pending
            .with_finalized_progress(&vertex.envelope_ref.tx_commitment, |progress, _| Ok(
                progress.shares.len()
            ))
            .unwrap(),
        Some(progress.shares.len())
    );
    assert_eq!(budget.used(), replay_used);
    assert!(pending
        .with_completion(
            &vertex.envelope_ref.tx_commitment,
            &terminal_auth,
            |_, _, _| Ok(())
        )
        .is_err());
    assert!(pending
        .retire_finalized(&vertex.envelope_ref.tx_commitment, &durable_states, 1)
        .is_err());
    assert_eq!(
        fs::read(pending_root.join("finalized/0000.json")).unwrap(),
        marker_bytes
    );
    assert_eq!(
        fs::read(pending_root.join("completions/0000.json")).unwrap(),
        preserved_completion
    );
    assert_eq!(
        fs::read(pending_root.join("progress/0000.json")).unwrap(),
        preserved_progress
    );
    durable_states
        .commit_verified_world_transition(
            synergy_state::FinalizedState {
                finalized_height: sixth.height,
                finalized_block_id: sixth.block_id.clone(),
                state_root: sixth.state_root.clone(),
            },
            &fifth.state,
            &sixth.state,
        )
        .unwrap();
    let full_pressure = budget.reserve(budget.available()).unwrap();
    pending
        .retire_finalized(&vertex.envelope_ref.tx_commitment, &durable_states, 1)
        .unwrap();
    for path in [
        "slots/0000.json",
        "completions/0000.json",
        "progress/0000.json",
        "finalized/0000.json",
    ] {
        assert_eq!(fs::read(pending_root.join(path)).unwrap(), b"null");
    }
    drop(full_pressure);
    drop(pending);
    let pending = super::processing_store::PendingProcessingStore::open(
        &pending_root,
        namespace.clone(),
        limits,
        &budget,
        &source,
    )
    .unwrap();
    assert_eq!(pending.identities().count(), 0);
    drop(pending);
    eprintln!("native processing conformance: encrypted DAG 4/5; no reveal before successor; signed 2-share decryption; descendant-only ready execution H5; unchanged three-QC finality H5; pool_used={} pool_limit={}", budget.used(), budget.limit());
    // This exercises native proof/execution boundaries, not live RPC/network,
    // durable worker recovery, resource/RSS qualification or a deployed profile.
}

#[test]
fn processing_async_pending_owner_recovers_native_requests_and_releases_only_on_verified_retirement(
) {
    use super::processing_store::{
        PendingProcessingIdentity, PendingProcessingStore, ProcessingAdmissionAuthenticator,
        ProcessingRetirementVerifier, ProcessingStoreError, ProcessingStoreLimits,
    };
    use synergy_etdag::{ProcessingContext, WalletProcessingAdmission, PROCESSING_PROFILE_ID};
    use synergy_state::world_resources::WorldResourceBudget;

    // Real FN-DSA identity, ML-DSA account authorization and native encrypted
    // carriers. Context/finality ownership and retirement below are explicit
    // fixtures; this is NOT a running async PoSy/order/reveal qualification.
    struct Auth<'a> {
        context: &'a ProcessingContext,
        other: &'a ProcessingContext,
        world: &'a synergy_state::WorldState,
        timestamp: u64,
        revoked: std::cell::Cell<bool>,
    }
    impl ProcessingAdmissionAuthenticator for Auth<'_> {
        fn verify(
            &self,
            context: &ProcessingContext,
            timestamp: u64,
            admission: &WalletProcessingAdmission,
        ) -> Result<(), String> {
            if self.revoked.get() {
                return Err("fixture authorization revoked".into());
            }
            if (context != self.context && context != self.other) || timestamp != self.timestamp {
                return Err("unrecognized fixture authority/time".into());
            }
            super::protected_admission::verify_wallet_processing_admission(
                admission, context, self.world, timestamp,
            )
        }
    }
    struct RetirementFixture(bool);
    impl ProcessingRetirementVerifier for RetirementFixture {
        fn verify_retirement(&self, _: &PendingProcessingIdentity) -> Result<(), String> {
            if self.0 {
                Ok(())
            } else {
                Err("no durable finalized consumption".into())
            }
        }
    }
    let (transaction, world, mut secret) =
        funded_transaction_fixture_for_network("socket-qualification", 10_000_000);
    let prepared = prepare_socket_fixture(world.clone(), None);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 3).unwrap().0,
    };
    let other_context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 4).unwrap().0,
    };
    assert_ne!(context, other_context);
    let timestamp = authority.consensus_timestamp_unix(3).unwrap();
    let auth = Auth {
        context: &context,
        other: &other_context,
        world: &world,
        timestamp,
        revoked: std::cell::Cell::new(false),
    };
    let first = processing_wallet_admission_fixture(&transaction, &context, &authority, &secret);
    let conflict =
        processing_wallet_admission_fixture(&transaction, &other_context, &authority, &secret);
    let mut next_transaction = transaction.clone();
    next_transaction.unsigned.nonce = 1;
    next_transaction.signature = fixture_sign(
        &secret,
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &next_transaction.unsigned.signing_bytes().unwrap(),
    );
    let second =
        processing_wallet_admission_fixture(&next_transaction, &context, &authority, &secret);
    let first_bytes = serde_json::to_vec(&first).unwrap();
    let second_bytes = serde_json::to_vec(&second).unwrap();
    let namespace = digest("processing-pending-owner-native-fixture");
    let limits = ProcessingStoreLimits {
        slots: 2,
        completion_bytes_per_item: 1024 * 1024,
    };
    let budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let root = prepared.root.join("isolated-processing-pending");
    let mut owner =
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth).unwrap();
    let base_used = budget.used();
    let mut stale_owner =
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth).unwrap();
    let first_id = owner
        .admit(&context, timestamp, &first_bytes, &auth)
        .unwrap();
    let original = fs::read(root.join("slots/0000.json")).unwrap();
    assert!(!owner
        .allows_historical_kem_recovery(&first_id.envelope_id)
        .unwrap());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&original).unwrap()["version"],
        2
    );
    // A genuine pre-upgrade on-disk schema remains byte-for-byte recoverable;
    // only it permits the old KEM wrapping. New slots in the same recovered
    // store stay FIPS-only, including after another restart.
    {
        let historical_root = prepared.root.join("historical-kem-pending");
        let mut historical = PendingProcessingStore::open(
            &historical_root,
            namespace.clone(),
            limits,
            &budget,
            &auth,
        )
        .unwrap();
        historical
            .admit(&context, timestamp, &first_bytes, &auth)
            .unwrap();
        drop(historical);
        let mut historical_record: serde_json::Value = serde_json::from_slice(&original).unwrap();
        historical_record["version"] = serde_json::json!(1);
        let historical_bytes = serde_json::to_vec(&historical_record).unwrap();
        fs::write(historical_root.join("slots/0000.json"), &historical_bytes).unwrap();
        let mut historical = PendingProcessingStore::open(
            &historical_root,
            namespace.clone(),
            limits,
            &budget,
            &auth,
        )
        .unwrap();
        assert!(historical
            .allows_historical_kem_recovery(&first_id.envelope_id)
            .unwrap());
        assert_eq!(
            historical
                .admit(&context, timestamp, &first_bytes, &auth)
                .unwrap(),
            first_id
        );
        let second_id = historical
            .admit(&context, timestamp, &second_bytes, &auth)
            .unwrap();
        assert!(!historical
            .allows_historical_kem_recovery(&second_id.envelope_id)
            .unwrap());
        drop(historical);
        let historical = PendingProcessingStore::open(
            &historical_root,
            namespace.clone(),
            limits,
            &budget,
            &auth,
        )
        .unwrap();
        assert!(historical
            .allows_historical_kem_recovery(&first_id.envelope_id)
            .unwrap());
        assert!(!historical
            .allows_historical_kem_recovery(&second_id.envelope_id)
            .unwrap());
        assert_eq!(
            fs::read(historical_root.join("slots/0000.json")).unwrap(),
            historical_bytes
        );
        drop(historical);
        fs::remove_dir_all(historical_root).unwrap();
    }

    let header = fs::read(root.join("pending-v1.json")).unwrap();
    let used = budget.used();
    auth.revoked.set(true);
    assert!(
        owner
            .with_admission(&first_id.envelope_id, &auth, |_, _, _| Ok(()))
            .is_err(),
        "mutable authenticators must reverify even unchanged retained originals"
    );
    assert_eq!(budget.used(), used);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), original);
    assert_eq!(fs::read(root.join("pending-v1.json")).unwrap(), header);
    auth.revoked.set(false);
    assert!(matches!(
        owner.admit(
            &other_context,
            timestamp,
            &serde_json::to_vec(&conflict).unwrap(),
            &auth
        ),
        Err(ProcessingStoreError::NonceClaimed)
    ));
    assert_eq!(budget.used(), used);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), original);
    assert_eq!(fs::read(root.join("pending-v1.json")).unwrap(), header);
    // A second stale process cannot publish the same nonce into another slot.
    assert!(matches!(
        stale_owner.admit(
            &other_context,
            timestamp,
            &serde_json::to_vec(&conflict).unwrap(),
            &auth
        ),
        Err(ProcessingStoreError::Storage(
            synergy_storage::StorageError::ConflictingWrite
        ))
    ));
    assert_eq!(stale_owner.identities().count(), 0);
    drop(stale_owner);
    // Ordinary decode capacity would fit, but new intake must also leave the
    // derived control envelope. Failure precedes decoding or any durable write.
    let exact_second_record_bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "namespace_root": namespace,
        "context": context,
        "authorization_timestamp_unix": timestamp,
        "admission_json": std::str::from_utf8(&second_bytes).unwrap(),
    }))
    .unwrap()
    .len();
    let ordinary_peak = exact_second_record_bytes * 128
        + 128 * 1024
        + limits.completion_bytes_per_item
        + 2 * 16 * 1024;
    let floor = super::processing_store::PROCESSING_INTAKE_HEADROOM_BYTES
        .max(limits.completion_bytes_per_item);
    let free_for_pressure = ordinary_peak + floor - 1;
    assert!(budget.available() > free_for_pressure);
    let pressure = budget
        .reserve(budget.available() - free_for_pressure)
        .unwrap();
    let before_rejection = budget.used();
    assert!(matches!(
        owner.admit(&context, timestamp, &second_bytes, &auth),
        Err(ProcessingStoreError::Resource(
            synergy_state::world_resources::WorldResourceError::Capacity { .. }
        ))
    ));
    assert!(matches!(
        owner.admit(&context, timestamp, &vec![b'"'; second_bytes.len()], &auth),
        Err(ProcessingStoreError::Resource(
            synergy_state::world_resources::WorldResourceError::Capacity { .. }
        ))
    ));
    assert_eq!(owner.identities().count(), 1);
    assert_eq!(budget.used(), before_rejection);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), original);
    assert_eq!(fs::read(root.join("pending-v1.json")).unwrap(), header);
    assert_eq!(
        owner
            .admit(&context, timestamp, &first_bytes, &auth)
            .unwrap(),
        first_id
    );
    drop(pressure);
    let used = budget.used();
    let all_free = budget.reserve(budget.available()).unwrap();
    assert_eq!(
        owner
            .admit(&context, timestamp, &first_bytes, &auth)
            .unwrap(),
        first_id
    );
    owner
        .with_admission(
            &first_id.envelope_id,
            &auth,
            |saved_context, saved_time, saved| {
                assert_eq!(saved_context, &context);
                assert_eq!(saved_time, timestamp);
                assert_eq!(saved, &first);
                Ok(())
            },
        )
        .unwrap();
    assert!(owner
        .admit(&context, timestamp, &second_bytes, &auth)
        .is_err());
    assert!(owner
        .retire(&first_id.envelope_id, &RetirementFixture(false))
        .is_err());
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), original);
    drop(all_free);
    assert_eq!(budget.used(), used);
    // Exactly one more available byte than the rejected boundary admits the
    // same request, retaining the unchanged conservative worker reservation.
    let exact_boundary = budget
        .reserve(budget.available() - ordinary_peak - floor)
        .unwrap();
    let before_exact_admission = budget.used();
    let second_id = owner
        .admit(&context, timestamp, &second_bytes, &auth)
        .unwrap();
    assert_eq!(
        budget.used() - before_exact_admission,
        exact_second_record_bytes * 128 + 128 * 1024 + limits.completion_bytes_per_item
    );
    drop(exact_boundary);
    let second_original = fs::read(root.join("slots/0001.json")).unwrap();
    assert_eq!(second_original.len(), exact_second_record_bytes);
    let populated_used = budget.used();
    eprintln!(
        "processing pending component: pool_limit={} base_reservation={} two_item_reservation={} slot0_bytes={} slot1_bytes={}",
        budget.limit(), base_used, populated_used, original.len(), second_original.len()
    );
    drop(owner);
    assert_eq!(budget.used(), 0);
    // Recovery must reserve the aggregate before decoding the second owner.
    let too_small = WorldResourceBudget::new(populated_used - 1);
    assert!(matches!(
        PendingProcessingStore::open(&root, namespace.clone(), limits, &too_small, &auth),
        Err(ProcessingStoreError::Resource(_))
    ));
    assert_eq!(too_small.used(), 0);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), original);
    let mut owner =
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth).unwrap();
    assert_eq!(budget.used(), populated_used);
    assert_eq!(owner.identities().count(), 2);
    assert_eq!(
        owner
            .admit(&context, timestamp, &first_bytes, &auth)
            .unwrap(),
        first_id
    );
    // Native signature validation on restart catches a shape-valid mutation.
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    let mut changed_request: serde_json::Value =
        serde_json::from_str(changed["admission_json"].as_str().unwrap()).unwrap();
    changed_request["request"]["fee_class"] = serde_json::json!(2);
    changed["admission_json"] = serde_json::json!(serde_json::to_string(&changed_request).unwrap());
    let corrupted = serde_json::to_vec(&changed).unwrap();
    fs::write(root.join("slots/0000.json"), &corrupted).unwrap();
    assert!(owner
        .with_admission(&first_id.envelope_id, &auth, |_, _, _| Ok(()))
        .is_err());
    assert!(owner
        .retire(&first_id.envelope_id, &RetirementFixture(true))
        .is_err());
    drop(owner);
    assert!(
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth).is_err()
    );
    assert_eq!(budget.used(), 0);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), corrupted);
    fs::write(root.join("slots/0000.json"), &original).unwrap();
    // Global claim coherence is re-established during recovery, rather than
    // trusting independent slot headers or accepting half a recovered owner.
    fs::write(root.join("slots/0001.json"), &original).unwrap();
    assert!(matches!(
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth),
        Err(ProcessingStoreError::Invalid(message)) if message.contains("duplicate pending")
    ));
    assert_eq!(budget.used(), 0);
    assert_eq!(fs::read(root.join("slots/0001.json")).unwrap(), original);
    fs::write(root.join("slots/0001.json"), &second_original).unwrap();
    let mut owner =
        PendingProcessingStore::open(&root, namespace.clone(), limits, &budget, &auth).unwrap();
    // A full shared pool does not prevent a held item from completing/retiring.
    let all_free = budget.reserve(budget.available()).unwrap();
    owner
        .retire(&first_id.envelope_id, &RetirementFixture(true))
        .unwrap();
    drop(all_free);
    assert_eq!(fs::read(root.join("slots/0000.json")).unwrap(), b"null");
    assert_eq!(
        fs::read(root.join("slots/0001.json")).unwrap(),
        second_original
    );
    let one_item_used = budget.used();
    for _ in 0..8 {
        // Retirement in this fixture substitutes for authenticated finality.
        // Native execution nonce replay prevention is qualified separately.
        owner
            .admit(&context, timestamp, &first_bytes, &auth)
            .unwrap();
        assert_eq!(
            fs::read(root.join("slots/0001.json")).unwrap(),
            second_original
        );
        owner
            .retire(&first_id.envelope_id, &RetirementFixture(true))
            .unwrap();
        assert_eq!(budget.used(), one_item_used);
    }
    owner
        .retire(&second_id.envelope_id, &RetirementFixture(true))
        .unwrap();
    assert_eq!(budget.used(), base_used);
    drop(owner);
    let recovered = PendingProcessingStore::open(&root, namespace, limits, &budget, &auth).unwrap();
    assert_eq!(recovered.identities().count(), 0);
    assert_eq!(budget.used(), base_used);
    drop(recovered);
    assert_eq!(budget.used(), 0);
    secret.fill(0);
    drop(authority);
    let root = prepared.root.clone();
    drop(prepared);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn processing_async_native_wallet_verifies_governed_carrier_and_context() {
    use synergy_etdag::{ProcessingContext, WalletProcessingAdmission, PROCESSING_PROFILE_ID};
    use synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY;

    let (transaction, world, mut account_secret) =
        funded_transaction_fixture_for_network("socket-qualification", 10_000_000);
    // Prepare signed authority/custody only. No nodes, mesh or consensus polls
    // are started by this focused native verification regression.
    let prepared = prepare_socket_fixture(world.clone(), None);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 3).unwrap().0,
    };
    // Namespace scratch pressure is advisory backpressure, with no changed
    // namespace bytes and no reservation leakage after a failed grow.
    let namespace_budget =
        synergy_state::world_resources::WorldResourceBudget::new(8 * 1024 * 1024);
    let expected_namespace =
        super::processing_pipeline::processing_namespace(&authority, &namespace_budget).unwrap();
    assert_eq!(
        super::processing_pipeline::try_processing_namespace(&authority, &namespace_budget)
            .unwrap(),
        Some(expected_namespace)
    );
    let pressure = namespace_budget
        .reserve(namespace_budget.limit() - 16 * 1024)
        .unwrap();
    assert!(
        super::processing_pipeline::try_processing_namespace(&authority, &namespace_budget)
            .unwrap()
            .is_none()
    );
    assert_eq!(namespace_budget.used(), pressure.bytes());
    drop(pressure);
    assert_eq!(namespace_budget.used(), 0);
    let admission =
        processing_wallet_admission_fixture(&transaction, &context, &authority, &account_secret);
    let timestamp = authority.consensus_timestamp_unix(3).unwrap();
    let verify = |admission: &WalletProcessingAdmission,
                  context: &ProcessingContext,
                  world: &synergy_state::WorldState| {
        super::protected_admission::verify_wallet_processing_admission(
            admission, context, world, timestamp,
        )
    };
    verify(&admission, &context, &world).unwrap();

    let mut wrong_context = context.clone();
    wrong_context.authority.assigned_cluster_id += 1;
    assert!(verify(&admission, &wrong_context, &world).is_err());
    let mut missing_binding = world.clone();
    missing_binding
        .protocol
        .remove(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY);
    assert!(verify(&admission, &context, &missing_binding).is_err());

    // Receiving funds does not require a sponsor. A valid dual-possession
    // carrier authorizes first use; admission itself must leave state unchanged.
    let mut funded_but_unauthorized = world.clone();
    let sender = &transaction.unsigned.sender;
    assert!(funded_but_unauthorized.accounts[sender].balance_nwei > 0);
    let mut bindings: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(
            &funded_but_unauthorized.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY],
        )
        .unwrap();
    assert!(bindings.remove(sender).is_some());
    funded_but_unauthorized.protocol.insert(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        serde_json::to_vec(&bindings).unwrap(),
    );
    verify(&admission, &context, &funded_but_unauthorized).unwrap();
    assert!(
        synergy_identity::authorization::canonical_binding_commitment_if_present(
            &funded_but_unauthorized.protocol,
            sender,
        )
        .unwrap()
        .is_none()
    );
    let mut malformed = funded_but_unauthorized.clone();
    malformed.protocol.insert(
        IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
        b"broken".to_vec(),
    );
    assert!(verify(&admission, &context, &malformed).is_err());
    let mut invalid_proof = admission.clone();
    invalid_proof
        .identity_authorization
        .binding
        .proofs
        .identity_root
        .signature = "00".repeat(1280);
    assert!(verify(&invalid_proof, &context, &funded_but_unauthorized).is_err());
    assert_eq!(
        funded_but_unauthorized.accounts[sender],
        world.accounts[sender]
    );
    verify(&admission, &context, &world).unwrap();

    // Correct cryptographic signature by an unrelated account key does not
    // satisfy the real FN-DSA-root-authorized wallet carrier.
    let (other_public, other_secret) = mldsa87::keypair();
    let mut wrong_key = admission.clone();
    wrong_key.request.signer_public_key = other_public.as_bytes().to_vec();
    wrong_key.request.signature =
        mldsa87::detached_sign(&wrong_key.request.signing_bytes().unwrap(), &other_secret)
            .as_bytes()
            .to_vec();
    assert!(verify(&wrong_key, &context, &world).is_err());
    let mut tampered = admission;
    tampered.request.fee_class += 1;
    assert!(verify(&tampered, &context, &world).is_err());

    account_secret.fill(0);
    drop(authority);
    let root = prepared.root.clone();
    drop(prepared);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn processing_async_actual_parent_rejections_have_receipts_and_do_not_block_next_transfer() {
    use std::collections::BTreeMap;
    use synergy_execution::{BlockExecutionScheduler, FeeSchedule, NativeTransferDispatcher};
    use synergy_state::WorldState;
    use synergy_transaction::{AegisTransactionVerifier, ReceiptStatus};

    struct NativeAccountVerifier;
    impl AegisTransactionVerifier for NativeAccountVerifier {
        type Error = String;
        fn verify_transaction(
            &self,
            message: &[u8],
            public: &[u8],
            signature: &[u8],
            algorithm: &str,
        ) -> Result<bool, String> {
            if algorithm != "ML-DSA-87" {
                return Ok(false);
            }
            let public = mldsa87::PublicKey::from_bytes(public).map_err(|e| e.to_string())?;
            let signature =
                mldsa87::DetachedSignature::from_bytes(signature).map_err(|e| e.to_string())?;
            Ok(mldsa87::verify_detached_signature(&signature, message, &public).is_ok())
        }
    }

    let (original, authorization_world, mut account_secret) =
        funded_transaction_fixture_for_network("processing-async-receipts", 10_000_000);
    let collector =
        synergy_address::derive_object_address("synf", b"processing-fee-collector").unwrap();
    let scheduler = BlockExecutionScheduler::new(
        NativeTransferDispatcher,
        NativeAccountVerifier,
        FeeSchedule {
            base_fee_per_gas_nwei: 40,
            collector: collector.clone(),
        },
    )
    .unwrap();
    // Test both a changed nonce and a transfer whose fee becomes unaffordable
    // after its action. A current-nonce rejection consumes only its nonce; a
    // stale transaction has already consumed that nonce and changes no state.
    for (nonce, balance, next_amount, error_code) in [
        (1, 10_000_000, 7, "async_parent_nonce_stale_v1"),
        (0, 840_001, 1, "async_parent_insufficient_balance_v1"),
    ] {
        let mut parent = authorization_world.clone();
        let sender = &original.unsigned.sender;
        parent.accounts.get_mut(sender).unwrap().nonce = nonce;
        parent.accounts.get_mut(sender).unwrap().balance_nwei = balance;
        let parent_bytes = serde_json::to_vec(&parent).unwrap();
        let mut next = original.clone();
        next.unsigned.nonce = 1;
        next.unsigned.amount_nwei = next_amount;
        next.signature = fixture_sign(
            &account_secret,
            SignatureAlgorithm::MlDsa87,
            "processing-wallet",
            "SYNERGY-TRANSACTION-SIGNING-V1",
            None,
            &next.unsigned.signing_bytes().unwrap(),
        );
        let body = synergy_block::BlockBody {
            transactions: vec![original.clone(), next.clone()],
        };
        let outcome = scheduler
            .execute_async_at(
                &body,
                &original.unsigned.network,
                100,
                1_700_000_100,
                &parent,
                &authorization_world,
            )
            .unwrap();
        assert_eq!(outcome.receipts.len(), 2);
        assert_eq!(outcome.receipts[0].status, ReceiptStatus::Reverted);
        assert_eq!(outcome.receipts[0].error_code.as_deref(), Some(error_code));
        assert_eq!(outcome.receipts[0].gas_used, 0);
        let mut rejected_state = parent.clone();
        rejected_state.accounts.get_mut(sender).unwrap().nonce = 1;
        assert_eq!(
            outcome.receipts[0].state_root_after,
            synergy_state::state_root(&rejected_state).unwrap()
        );
        assert_eq!(rejected_state.accounts[sender].balance_nwei, balance);
        assert_eq!(rejected_state.protocol, parent.protocol);
        assert_eq!(outcome.receipts[1].status, ReceiptStatus::Applied);
        assert!(outcome.receipts.iter().all(|receipt| receipt.validate()));
        assert_eq!(outcome.state.accounts[sender].nonce, 2);
        assert_eq!(
            outcome.state.accounts[sender].balance_nwei,
            balance - next_amount - 840_000
        );
        assert_eq!(
            outcome.state.accounts[&original.unsigned.receiver].balance_nwei,
            next_amount
        );
        assert_eq!(outcome.state.accounts[&collector].balance_nwei, 840_000);
        assert_eq!(outcome.total_gas_used, 21_000);
        assert_eq!(outcome.total_fees_nwei, 840_000);
        assert!(!outcome.may_determine_finality());

        // Restoring funds cannot revive the original signed request. Its nonce
        // is already consumed, with no retained rejected-ID/tombstone state.
        let mut refunded = rejected_state.clone();
        refunded.accounts.get_mut(sender).unwrap().balance_nwei = 10_000_000;
        let replayed = scheduler
            .execute_async_at(
                &synergy_block::BlockBody {
                    transactions: vec![original.clone()],
                },
                &original.unsigned.network,
                101,
                1_700_000_101,
                &refunded,
                &authorization_world,
            )
            .unwrap();
        assert_eq!(replayed.state, refunded);
        assert_eq!(replayed.receipts.len(), 1);
        assert_eq!(replayed.receipts[0].status, ReceiptStatus::Reverted);
        assert_eq!(
            replayed.receipts[0].error_code.as_deref(),
            Some("async_parent_nonce_stale_v1")
        );
        assert_eq!(replayed.receipts[0].gas_used, 0);
        assert_eq!(replayed.total_gas_used, 0);
        assert_eq!(replayed.total_fees_nwei, 0);
        assert_eq!(
            replayed.receipts[0].state_root_after,
            synergy_state::state_root(&refunded).unwrap()
        );

        // Exercise explicit async replay as well as initial execution. This
        // signs a structural execution fixture; it supplies no PoSy authority.
        let mut block = synergy_block::Block {
            header: synergy_block::BlockHeader {
                network: original.unsigned.network.clone(),
                height: 100,
                parent_block_id: "processing-execution-parent-fixture".into(),
                timestamp_unix: 1_700_000_100,
                proposer_id: "execution-replay-fixture".into(),
                transaction_root: body.transaction_root().unwrap(),
                receipt_root: synergy_block::receipt_root(&outcome.receipts).unwrap(),
                state_root: outcome.state_root.clone(),
            },
            body: body.clone(),
            receipts: outcome.receipts.clone(),
            proposer_signature: Vec::new(),
            proposer_signature_algorithm: "ML-DSA-87".into(),
        };
        block.proposer_signature = fixture_sign(
            &account_secret,
            SignatureAlgorithm::MlDsa87,
            "processing-replay-fixture",
            "SYNERGY-BLOCK-SIGNING-V1",
            None,
            &block.header.commitment_bytes().unwrap(),
        );
        let replay = scheduler
            .execute_async_block(&block, &parent, &authorization_world)
            .unwrap();
        assert_eq!(replay.state, outcome.state);
        assert_eq!(replay.receipts, outcome.receipts);
        use synergy_state::world_resources::{
            world_owned_bytes, BudgetedWorld, WorldResourceBudget,
        };
        let owned = world_owned_bytes(&parent).unwrap();
        let budget = WorldResourceBudget::new(owned * 16 + 4 * 1024 * 1024);
        let budgeted_parent =
            BudgetedWorld::from_reserved(parent.clone(), budget.reserve(owned).unwrap()).unwrap();
        let replay = scheduler
            .execute_async_block_budgeted(&block, &budgeted_parent, &authorization_world)
            .unwrap();
        assert_eq!(replay.state.as_ref(), &outcome.state);
        assert_eq!(replay.receipts, outcome.receipts);

        // Exercise candidate/registry composition with genuine native account
        // signatures. Group readiness is an explicit fixture below; this is
        // NOT authenticated ETDAG publication or a running async PoSy profile.
        use synergy_execution::{
            processing_payload_root, ParentProcessingRegistry, ProcessingCandidateContext,
            ProcessingPayloadError, ProcessingPayloadProvider, ProcessingReadinessVerifier,
            ProcessingReadyRecord,
        };
        struct RegistryFixture;
        impl ProcessingReadinessVerifier for RegistryFixture {
            fn verify_ordered_group(
                &self,
                _: &synergy_etdag::execution::ProcessingOrderGroup,
                _: &WorldState,
            ) -> Result<(), String> {
                Ok(())
            }
            fn verify_publication(
                &self,
                _: &ProcessingReadyRecord,
                _: &WorldState,
            ) -> Result<(), String> {
                Ok(())
            }
            fn identity_is_current(
                &self,
                _: &ProcessingReadyRecord,
                _: &WorldState,
            ) -> Result<bool, String> {
                Ok(true)
            }
        }
        struct FixturePayloads(BTreeMap<EtdagDigest, Vec<u8>>);
        impl ProcessingPayloadProvider for FixturePayloads {
            fn plaintext<'a>(
                &'a self,
                record: &ProcessingReadyRecord,
            ) -> Result<&'a [u8], ProcessingPayloadError> {
                self.0
                    .get(&record.item.envelope_id)
                    .map(Vec::as_slice)
                    .ok_or_else(|| {
                        ProcessingPayloadError::Unavailable(record.item.envelope_id.clone())
                    })
            }
        }
        let digest = |label: &str| {
            EtdagDigest::from_domain_bytes("native-processing-candidate-fixture", label.as_bytes())
        };
        let namespace = digest("namespace");
        let original_context = digest("immutable-original-context");
        let mut payloads = FixturePayloads(BTreeMap::new());
        let mut records = Vec::new();
        for (index, transaction) in body.transactions.iter().enumerate() {
            let envelope = digest(&format!("original-envelope-{index}"));
            let plaintext = serde_json::to_vec(transaction).unwrap();
            records.push(ProcessingReadyRecord {
                item: synergy_etdag::execution::ProcessingReadyItem {
                    group_number: index as u64 + 1,
                    group_root: digest(&format!("group-{index}")),
                    order_position: 0,
                    envelope_id: envelope.clone(),
                    payload_root: processing_payload_root(&original_context, &envelope, &plaintext)
                        .unwrap(),
                    readiness_root: digest("fixture-readiness"),
                    gas_class_units: transaction.unsigned.fee_limit.gas_limit,
                    encoded_bytes: plaintext.len() as u64,
                    remaining_dependencies: vec![],
                },
                processing_context_root: original_context.clone(),
                authorization_root: digest("fixture-authority"),
                sender_wallet: transaction.unsigned.sender.clone(),
                sender_nonce: transaction.unsigned.nonce,
            });
            payloads.0.insert(envelope, plaintext);
        }
        // Publish before the competing nonce consumption. Republishing an
        // already-spent nonce would correctly fail instead of creating stale work.
        let mut publication_parent = parent.clone();
        publication_parent.accounts.get_mut(sender).unwrap().nonce = 0;
        // Seed actual canonical assignment/closure records rather than letting
        // the execution fixture bypass processing nonce ownership.
        let mut previous =
            synergy_etdag::execution::processing_genesis_group_root(&namespace).unwrap();
        for index in 0..=records.len() {
            let members = if index < records.len() {
                let record = &records[index];
                vec![synergy_etdag::execution::ProcessingGroupMember {
                    processing_context_root: record.processing_context_root.clone(),
                    authorization_root: record.authorization_root.clone(),
                    envelope: synergy_etdag::CertifiedEnvelopeRef {
                        tx_commitment: record.item.envelope_id.clone(),
                        sender_id: record.sender_wallet.clone(),
                        nonce_slot: record.sender_nonce,
                        certified_dag_round: 0,
                        gas_class_units: record.item.gas_class_units,
                        ciphertext_bytes: record.item.encoded_bytes,
                        fee_class: 1,
                        protocol_dependencies: vec![],
                    },
                }]
            } else {
                vec![]
            };
            let group = synergy_etdag::execution::ProcessingOrderGroup {
                group_version: 1,
                namespace_root: namespace.clone(),
                group_number: index as u64 + 1,
                previous_group_root: previous,
                order_seed: digest("fixture-order-seed"),
                members,
            };
            let root = group.root().unwrap();
            let transition = synergy_execution::processing_group_transition(
                &publication_parent,
                &namespace,
                std::iter::empty(),
                Some(&group),
                &RegistryFixture,
                &budget,
            )
            .unwrap();
            transition.diff().apply(&mut publication_parent).unwrap();
            if index < records.len() {
                records[index].item.group_root = root.clone();
            }
            previous = root;
        }
        let publication_base =
            BudgetedWorld::try_clone_world(&publication_parent, &budget).unwrap();
        let publication_candidate = scheduler
            .execute_processing_candidate(
                ProcessingCandidateContext {
                    ordered_group: None,
                    height: 99,
                    parent_block_id: "processing-publication-fixture-parent",
                    network: &original.unsigned.network,
                    consensus_timestamp_unix: 1_700_000_099,
                    namespace_root: &namespace,
                    maximum_gas: 30_000_000,
                    maximum_bytes: 8 * 1024 * 1024,
                    finalized_authorization_state: &authorization_world,
                },
                &publication_base,
                &records,
                &RegistryFixture,
                &FixturePayloads(BTreeMap::new()),
            )
            .unwrap();
        assert!(publication_candidate.transactions.is_empty());
        assert!(publication_candidate.receipts.is_empty());
        assert_eq!(
            publication_candidate.state.accounts,
            publication_parent.accounts
        );
        let mut ready_parent =
            BudgetedWorld::try_clone_world(publication_candidate.state.as_ref().as_ref(), &budget)
                .unwrap();
        if nonce == 1 {
            ready_parent
                .try_apply(&synergy_state::StateDiff {
                    changes: vec![synergy_state::AccountChange {
                        account: sender.clone(),
                        debit_nwei: 0,
                        credit_nwei: 0,
                        expected_nonce: Some(0),
                        code_hash: None,
                    }],
                    protocol_changes: vec![],
                })
                .unwrap();
        }
        let candidate_context = || ProcessingCandidateContext {
            ordered_group: None,
            height: 100,
            parent_block_id: "native-processing-parent",
            network: &original.unsigned.network,
            consensus_timestamp_unix: 1_700_000_100,
            namespace_root: &namespace,
            maximum_gas: 30_000_000,
            maximum_bytes: 8 * 1024 * 1024,
            finalized_authorization_state: &authorization_world,
        };
        let candidate = scheduler
            .execute_processing_candidate(
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &payloads,
            )
            .unwrap();
        assert_eq!(candidate.state.accounts, outcome.state.accounts);
        assert_eq!(candidate.transactions, body.transactions);
        assert_eq!(
            candidate
                .receipts
                .iter()
                .map(|receipt| &receipt.status)
                .collect::<Vec<_>>(),
            outcome
                .receipts
                .iter()
                .map(|receipt| &receipt.status)
                .collect::<Vec<_>>()
        );
        assert!(candidate.protected_material.as_legacy().is_none());
        let remaining =
            ParentProcessingRegistry::read(candidate.state.as_ref().as_ref(), &namespace, &budget)
                .unwrap();
        assert!(remaining
            .select(&RegistryFixture, 30_000_000, 8 * 1024 * 1024)
            .unwrap()
            .records()
            .next()
            .is_none());
        let replayed = scheduler
            .replay_processing_candidate(
                &candidate,
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &payloads,
            )
            .unwrap();
        assert_eq!(replayed, candidate);
        let retained = budget.used();
        assert!(matches!(
            scheduler.execute_processing_candidate(
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &FixturePayloads(BTreeMap::new())
            ),
            Err(synergy_execution::ProcessingCandidateError::Payload(
                ProcessingPayloadError::Unavailable(_)
            ))
        ));
        assert_eq!(budget.used(), retained);
        let original_ready_bytes = serde_json::to_vec(ready_parent.as_ref()).unwrap();
        let pressure = budget.reserve(budget.available()).unwrap();
        assert!(scheduler
            .execute_processing_candidate(
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &payloads
            )
            .is_err());
        drop(pressure);
        assert_eq!(budget.used(), retained);
        assert_eq!(
            serde_json::to_vec(ready_parent.as_ref()).unwrap(),
            original_ready_bytes
        );
        let mut corrupted_payloads = FixturePayloads(payloads.0.clone());
        *corrupted_payloads
            .0
            .values_mut()
            .next()
            .unwrap()
            .first_mut()
            .unwrap() ^= 1;
        assert!(scheduler
            .execute_processing_candidate(
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &corrupted_payloads
            )
            .is_err());
        assert_eq!(budget.used(), retained);
        let mut forged = candidate;
        forged.receipts[0].error_code = Some("forged-processing-receipt".into());
        forged.block_id = forged.commitment_id().unwrap();
        forged.validate().unwrap();
        assert!(scheduler
            .replay_processing_candidate(
                &forged,
                candidate_context(),
                &ready_parent,
                &[],
                &RegistryFixture,
                &payloads
            )
            .is_err());
        assert!(scheduler.execute_block(&block, &parent).is_err());
        let mut forged_state = block.clone();
        forged_state.header.state_root = "forged-execution-root".into();
        assert!(matches!(
            scheduler.execute_async_block(&forged_state, &parent, &authorization_world),
            Err(synergy_execution::BlockExecutionError::StateRootMismatch { .. })
        ));
        let mut forged_receipt = block;
        forged_receipt.receipts[0].error_code = Some("forged-rejection".into());
        forged_receipt.header.receipt_root =
            synergy_block::receipt_root(&forged_receipt.receipts).unwrap();
        assert!(matches!(
            scheduler.execute_async_block(&forged_receipt, &parent, &authorization_world),
            Err(synergy_execution::BlockExecutionError::ReceiptMismatch)
        ));
        assert!(scheduler
            .execute_at(
                &body,
                &original.unsigned.network,
                100,
                1_700_000_100,
                &parent,
                &authorization_world,
            )
            .is_err());
        assert_eq!(serde_json::to_vec(&parent).unwrap(), parent_bytes);
    }
    // A future nonce must remain pending rather than become a terminal receipt
    // or advance the account. An exhausted nonce cannot wrap or be consumed.
    for (supplied_nonce, parent_nonce, expected_error) in [
        (1, 0, synergy_transaction::TransactionError::NonceNotReady),
        (
            u64::MAX,
            u64::MAX,
            synergy_transaction::TransactionError::NonceOverflow,
        ),
    ] {
        let mut parent = authorization_world.clone();
        parent
            .accounts
            .get_mut(&original.unsigned.sender)
            .unwrap()
            .nonce = parent_nonce;
        let parent_bytes = serde_json::to_vec(&parent).unwrap();
        let mut pending = original.clone();
        pending.unsigned.nonce = supplied_nonce;
        pending.signature = fixture_sign(
            &account_secret,
            SignatureAlgorithm::MlDsa87,
            "processing-wallet",
            "SYNERGY-TRANSACTION-SIGNING-V1",
            None,
            &pending.unsigned.signing_bytes().unwrap(),
        );
        assert!(matches!(
            scheduler.execute_async_at(
                &synergy_block::BlockBody {
                    transactions: vec![pending],
                },
                &original.unsigned.network,
                100,
                1_700_000_100,
                &parent,
                &authorization_world,
            ),
            Err(synergy_execution::BlockExecutionError::Transaction {
                transaction_index: 0,
                source,
            }) if source == expected_error
        ));
        assert_eq!(serde_json::to_vec(&parent).unwrap(), parent_bytes);
    }
    account_secret.fill(0);
}

/// Merge independently verified fixture bindings without replacing prior funding.
fn merge_funded_fixture_world(
    destination: &mut synergy_state::WorldState,
    incoming: synergy_state::WorldState,
) -> Result<(), String> {
    use std::collections::BTreeMap;
    use synergy_identity::authorization::{
        IdentityAuthorizationBindingCommitment, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
    };
    let mut bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> = destination
        .protocol
        .get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
        .map(|bytes| serde_json::from_slice(bytes))
        .transpose()
        .map_err(|e| format!("existing fixture bindings: {e}"))?
        .unwrap_or_default();
    let incoming_bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
        serde_json::from_slice(
            incoming
                .protocol
                .get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
                .ok_or("funded fixture lacks identity bindings")?,
        )
        .map_err(|e| format!("incoming fixture bindings: {e}"))?;
    if incoming
        .accounts
        .keys()
        .any(|address| destination.accounts.contains_key(address))
        || incoming_bindings
            .keys()
            .any(|address| bindings.contains_key(address))
        || incoming
            .accounts
            .keys()
            .any(|address| !incoming_bindings.contains_key(address))
    {
        return Err("duplicate or unbound funded fixture account".into());
    }
    for (key, value) in &incoming.protocol {
        if key != IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY
            && destination
                .protocol
                .get(key)
                .is_some_and(|prior| prior != value)
        {
            return Err("fixture protocol state conflict".into());
        }
    }
    bindings.extend(incoming_bindings);
    let encoded = serde_json::to_vec(&bindings).map_err(|e| e.to_string())?;
    destination.accounts.extend(incoming.accounts);
    destination.protocol.extend(incoming.protocol);
    destination
        .protocol
        .insert(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(), encoded);
    Ok(())
}

#[test]
fn funded_fixture_merge_preserves_independent_authorizations_and_rejects_duplicates() {
    use std::collections::BTreeMap;
    use synergy_identity::authorization::{
        IdentityAuthorizationBindingCommitment, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
    };
    let (first, mut world, mut first_secret) =
        funded_transaction_fixture_for_network("socket-pool-merge", 10);
    let (second, incoming, mut second_secret) =
        funded_transaction_fixture_for_network("socket-pool-merge", 20);
    let duplicate = incoming.clone();
    merge_funded_fixture_world(&mut world, incoming).unwrap();
    let bindings: BTreeMap<String, IdentityAuthorizationBindingCommitment> =
        serde_json::from_slice(&world.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY]).unwrap();
    assert_eq!(bindings.len(), 2);
    for transaction in [&first, &second] {
        let expected = IdentityAuthorizationBindingCommitment::from_verified_binding(
            &transaction.identity_authorization.as_ref().unwrap().binding,
            1_700_000_000,
        )
        .unwrap();
        assert_eq!(bindings[&transaction.unsigned.sender], expected);
    }
    assert_eq!(world.accounts[&first.unsigned.sender].balance_nwei, 10);
    assert_eq!(world.accounts[&second.unsigned.sender].balance_nwei, 20);
    let prior = serde_json::to_vec(&world).unwrap();
    assert!(merge_funded_fixture_world(&mut world, duplicate).is_err());
    assert_eq!(serde_json::to_vec(&world).unwrap(), prior);
    first_secret.fill(0);
    second_secret.fill(0);
}

fn sign_fixture_vertex(fleet: &SocketFleet, vertex: &mut synergy_etdag::TransactionVertex) {
    vertex.vertex_id = synergy_etdag::dag::derive_vertex_id(vertex).unwrap();
    vertex.author_signature = fixture_sign(
        &fs::read(fleet.root.join("node-0/consensus.key")).unwrap(),
        SignatureAlgorithm::MlDsa65,
        "consensus-0",
        "SYNERGY-ETDAG-SIGNATURE-V1",
        Some(1),
        vertex.vertex_id.0.as_bytes(),
    );
    vertex.validate().unwrap();
}
fn protected_transaction_vertex(
    fleet: &SocketFleet,
    tx: &synergy_transaction::SignedTransaction,
) -> synergy_etdag::TransactionVertex {
    protected_transaction_vertex_with_ciphertext_class(fleet, tx, None)
}

fn protected_transaction_vertex_with_ciphertext_class(
    fleet: &SocketFleet,
    tx: &synergy_transaction::SignedTransaction,
    ciphertext_class: Option<usize>,
) -> synergy_etdag::TransactionVertex {
    use synergy_etdag::{
        CertifiedEnvelopeRef, EncryptedTransactionEnvelope, EnvelopeAad, TransactionVertex,
    };
    let authority = authority::load(&fleet.nodes[0].as_ref().unwrap().configuration)
        .unwrap()
        .unwrap();
    let (context, _) = authority.protected_target(None, 3).unwrap();
    let root = context.root().unwrap();
    let aad = EnvelopeAad {
        profile_id: synergy_etdag::ETDAG_PROFILE_ID.into(),
        chain_id: 1266,
        network_id: context.network_id.clone(),
        protocol_version: context.protocol_version.clone(),
        epoch: context.epoch,
        target_height: 3,
        target_context_root: root.clone(),
        assigned_cluster_id: context.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: tx.unsigned.sender.clone(),
        nonce_slot: tx.unsigned.nonce,
    };
    let mut padded =
        synergy_etdag::crypto::pad_plaintext(&serde_json::to_vec(tx).unwrap()).unwrap();
    if let Some(class) = ciphertext_class {
        assert!(synergy_etdag::CIPHERTEXT_SIZE_CLASSES.contains(&class));
        assert!(class >= padded.len() + 16);
        padded.resize(class - 16, 0);
    }
    let payload = fixture_encrypt_protected_payload(
        &aad,
        &authority.protected_ingress_registry().unwrap().records,
        &padded,
        fleet.nodes[0]
            .as_ref()
            .unwrap()
            .configuration
            .aegis_provider
            .as_ref(),
    );
    let mut envelope = EncryptedTransactionEnvelope {
        envelope_version: 2,
        envelope_id: digest("genuine-wallet-transfer"),
        target_context_root: root.clone(),
        target_height: 3,
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: digest("pending"),
        share_capsule_root: digest("pending"),
        ciphertext: payload.ciphertext,
        content_blind_order_key: digest("transfer-order"),
        share_capsules: payload.share_capsules,
    };
    envelope.refresh_capsule_roots().unwrap();
    let reference = CertifiedEnvelopeRef {
        tx_commitment: envelope.envelope_id.clone(),
        sender_id: tx.unsigned.sender.clone(),
        nonce_slot: tx.unsigned.nonce,
        certified_dag_round: 0,
        gas_class_units: 21000,
        ciphertext_bytes: envelope.ciphertext.len() as u64,
        fee_class: 1,
        protocol_dependencies: vec![],
    };
    let mut vertex = TransactionVertex {
        vertex_id: digest("pending"),
        target_context_root: root,
        target_height: 3,
        envelope,
        envelope_ref: reference,
        parents: vec![],
        author_id: fleet.ids[0].clone(),
        author_signature: vec![],

        wallet_admission: None,
    };
    sign_fixture_vertex(fleet, &mut vertex);
    vertex
}

/// Storage qualification with genuine native signatures and maximum ciphertext.
/// This exercises persistence, not fresh wallet admission or chain throughput.
#[test]
fn native_max_ciphertext_collecting_appends_and_restart_preserve_originals() {
    use synergy_etdag::persistence::ProtectedPipeline;
    use synergy_etdag::{AvailabilityCertificate, AvailabilityVote};
    let fleet = SocketFleet::new();
    let authority = authority::load(&fleet.nodes[0].as_ref().unwrap().configuration)
        .unwrap()
        .unwrap();
    let (context, _) = authority.protected_target(None, 3).unwrap();
    let parameters = authority.protected_parameters().unwrap();
    let members = authority
        .registry
        .active()
        .map(|validator| {
            (
                validator.validator_id.clone(),
                (
                    validator.consensus_key_id.clone(),
                    u64::try_from(validator.frozen_voting_weight).unwrap(),
                ),
            )
        })
        .collect::<synergy_etdag::ordering::CutoffMembers>();
    let root = fleet.root.join("native-max-collecting");
    let open = || {
        ProtectedPipeline::open_collecting(
            &root,
            context.clone(),
            parameters.clone(),
            fleet.ids[0].clone(),
            &members,
            authority.as_ref(),
        )
        .unwrap()
    };
    let mut pipeline = open();
    let (transaction, _) = funded_transaction_fixture();
    let journal = root.join("protected-h3.json");
    let length = || fs::metadata(&journal).map(|m| m.len()).unwrap_or(0);
    let mut originals = Vec::new();
    let mut total_original_bytes = 0u64;
    for _ in 0..12 {
        let vertex =
            protected_transaction_vertex_with_ciphertext_class(&fleet, &transaction, Some(131072));
        assert_eq!(vertex.envelope.ciphertext.len(), 131072);
        let encoded = serde_json::to_vec(&vertex).unwrap().len() as u64;
        let before = length();
        assert!(pipeline
            .persist_vertex(vertex.clone(), &members, authority.as_ref())
            .unwrap());
        let appended = length() - before;
        assert!(
            appended <= encoded + 8192,
            "collecting append copied prior graph: item={encoded}, appended={appended}"
        );
        total_original_bytes += encoded;
        originals.push(vertex);
    }
    assert!(length() <= total_original_bytes + 12 * 8192);
    let vertex = originals.last().unwrap();
    let mut votes = Vec::new();
    for index in 0..4 {
        let mut vote = AvailabilityVote {
            context_root: context.root().unwrap(),
            vertex_id: vertex.vertex_id.clone(),
            validator_id: fleet.ids[index].clone(),
            key_id: format!("consensus-{index}"),
            signature: Vec::new(),
        };
        let signing = synergy_etdag::crypto::canonical_signing_bytes(
            "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
            &(
                &vote.context_root,
                &vote.vertex_id,
                &vote.validator_id,
                &vote.key_id,
            ),
        )
        .unwrap();
        vote.signature = fixture_sign(
            &fs::read(fleet.root.join(format!("node-{index}/consensus.key"))).unwrap(),
            SignatureAlgorithm::MlDsa65,
            &vote.key_id,
            "SYNERGY-ETDAG-SIGNATURE-V1",
            Some(1),
            &signing,
        );
        let before = length();
        if index == 0 {
            pipeline
                .persist_local_vote(vote.clone(), &members, authority.as_ref())
                .unwrap();
        } else {
            pipeline
                .persist_vote(vote.clone(), &members, authority.as_ref())
                .unwrap();
        }
        assert!(length() - before <= serde_json::to_vec(&vote).unwrap().len() as u64 + 8192);
        votes.push(vote);
    }
    let certificate = AvailabilityCertificate::from_votes(
        context.root().unwrap(),
        vertex.vertex_id.clone(),
        votes.clone(),
        5,
    )
    .unwrap();
    let before = length();
    pipeline
        .persist_availability(certificate.clone(), &members, authority.as_ref())
        .unwrap();
    assert!(length() - before <= serde_json::to_vec(&certificate).unwrap().len() as u64 + 8192);
    let mut forged =
        protected_transaction_vertex_with_ciphertext_class(&fleet, &transaction, Some(131072));
    forged.author_signature[0] ^= 1;
    let before = length();
    assert!(pipeline
        .persist_vertex(forged, &members, authority.as_ref())
        .is_err());
    assert_eq!(
        length(),
        before,
        "forged native signature wrote journal bytes"
    );
    drop(pipeline);
    let mut recovered = open();
    assert_eq!(recovered.graph().len(), originals.len());
    for original in &originals {
        assert_eq!(recovered.graph().get(&original.vertex_id), Some(original));
    }
    assert_eq!(
        recovered.local_votes().get(&vertex.vertex_id),
        Some(&votes[0])
    );
    assert_eq!(
        recovered.availability().get(&vertex.vertex_id),
        Some(&certificate)
    );
    let before = length();
    for original in originals {
        assert!(!recovered
            .persist_vertex(original, &members, authority.as_ref())
            .unwrap());
    }
    assert_eq!(
        length(),
        before,
        "exact retries rewrote collecting originals"
    );
}

fn poll_before_consensus(fleet: &mut SocketFleet) {
    // Model an admission window before the first proposal; every receipt, VAC
    // and persisted vertex still comes from its genuine production owner.
    for node in fleet.nodes.iter_mut().flatten() {
        for (name, service) in &mut node.services {
            if *name == "posy" {
                continue;
            }
            service
                .poll()
                .unwrap_or_else(|e| panic!("{} {name}: {e}", node.configuration.node_name));
            assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
        }
    }
}
fn await_local_receipt(
    fleet: &mut SocketFleet,
    receipt: std::sync::mpsc::Receiver<Result<(), String>>,
    before_consensus: bool,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if before_consensus {
            poll_before_consensus(fleet);
        } else {
            for node in fleet.nodes.iter_mut().flatten() {
                node.poll();
            }
        }
        match receipt.try_recv() {
            Ok(result) => return result,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("local admission owner disconnected")
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        assert!(
            Instant::now() < deadline,
            "local admission receipt timed out"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn live_source_context_uses_bounded_witness_and_rejects_corruption() {
    let mut fleet = SocketFleet::new();
    fleet.advance(4);
    let node = fleet.nodes[0].as_ref().unwrap();
    let authority = authority::load(&node.configuration).unwrap().unwrap();
    let (record, bytes) = node
        .ingress
        .latest_finality_with_witness()
        .unwrap()
        .unwrap();
    let parameters = authority.protected_parameters().unwrap();
    let context_for = |source: &FinalizedBlockRecord| {
        let height = parameters.protected_target_height(source.height).unwrap();
        let (context, _) = authority.protected_target(Some(source), height).unwrap();
        synergy_etdag::WalletAdmissionContext {
            context,
            parameters: parameters.clone(),
            ingress_keys: fleet
                .ids
                .iter()
                .map(|member| {
                    synergy_etdag::crypto::active_key_for_validator(
                        authority.protected_ingress_registry().unwrap(),
                        member,
                        height,
                    )
                    .unwrap()
                    .clone()
                })
                .collect(),
        }
    };
    let context = context_for(&record);
    let response = |ingress: &ingress::AuthenticatedIngress| {
        super::source_finality_evidence::context_response(&authority, ingress, &context)
    };
    // No history directory is installed: success proves the live path needs
    // neither disk reads nor a second ingress-history authority verification.
    let cached = ingress::AuthenticatedIngress::default();
    cached
        .submit_finality(record.clone(), bytes.clone())
        .unwrap();
    let live = response(&cached).unwrap();
    let durable = response(&node.ingress).unwrap();
    assert_eq!(
        live["source_finality_evidence"],
        durable["source_finality_evidence"]
    );
    let older = node.ingress.finalized_record(1).unwrap().unwrap();
    assert!(older.height < record.height);
    let historical = super::source_finality_evidence::context_response(
        &authority,
        &node.ingress,
        &context_for(&older),
    )
    .unwrap();
    assert_eq!(
        historical["source_finality_evidence"]["record"]["height"],
        1
    );

    let witness: [synergy_posy::SimplifiedQuorumCertificate; 3] =
        serde_json::from_slice(&bytes).unwrap();
    let mut forged = witness.clone();
    forged[0].block_id = digest("forged-live-source-block").0;
    for bad in [
        b"[".to_vec(),
        serde_json::to_vec(&witness[..2]).unwrap(),
        serde_json::to_vec(&forged).unwrap(),
    ] {
        let corrupted = ingress::AuthenticatedIngress::default();
        corrupted.submit_finality(record.clone(), bad).unwrap();
        assert!(response(&corrupted).is_err());
    }
    let mut conflicting = record.clone();
    conflicting.block_id = digest("conflicting-live-source-record").0;
    let corrupted = ingress::AuthenticatedIngress::default();
    corrupted.submit_finality(conflicting, bytes).unwrap();
    assert!(response(&corrupted)
        .unwrap_err()
        .contains("witness and record disagree"));
    assert!(response(&ingress::AuthenticatedIngress::default()).is_err());
}

#[test]
fn authenticated_socket_nonempty_admission_execution_and_closed_cutoff() {
    let (tx, initial) = funded_transaction_fixture();
    let mut fleet = SocketFleet::with_world_state(initial);
    let vertex = protected_transaction_vertex(&fleet, &tx);
    let receipt = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .ingress
        .submit_local_protected_vertex(vertex.clone())
        .unwrap();
    await_local_receipt(&mut fleet, receipt, true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        poll_before_consensus(&mut fleet);
        let mut certified = 0;
        for node in fleet.nodes.iter().flatten() {
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let Some(stored) =
                synergy_etdag::persistence::ProtectedPipeline::read_durable_evidence(
                    layout.etdag().join("protected-pipeline"),
                    3,
                )
                .unwrap()
            else {
                continue;
            };
            let certificate = &stored["collecting"]["certificates"][&vertex.vertex_id.0];
            if !certificate.is_null() {
                let cert: synergy_etdag::AvailabilityCertificate =
                    serde_json::from_value(certificate.clone()).unwrap();
                let authority = authority::load(&node.configuration).unwrap().unwrap();
                synergy_etdag::availability::verify_availability_certificate(
                    &cert,
                    &fleet.ids.iter().cloned().collect(),
                    authority.as_ref(),
                )
                .unwrap();
                assert_eq!(cert.vertex_id, vertex.vertex_id);
                certified += 1;
            }
        }
        if certified == 5 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "genuine VAC propagation timed out ({certified}/5)"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    eprintln!(
        "socket qualification: genuine transfer has verified durable VACs on all five validators"
    );
    let duplicate = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .ingress
        .submit_local_protected_vertex(vertex.clone())
        .unwrap();
    await_local_receipt(&mut fleet, duplicate, true).unwrap();
    fleet.advance(6);
    for node in fleet.nodes.iter().flatten() {
        let layout = synergy_storage::NodeStorageLayout::new(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        let state = synergy_state::FinalizedStateStore::load(layout.state().join("execution"))
            .unwrap()
            .current_world_state()
            .unwrap()
            .unwrap();
        assert_eq!(state.accounts[&tx.unsigned.sender].nonce, 1);
        assert_eq!(state.accounts[&tx.unsigned.receiver].balance_nwei, 7);
    }
    // A different signed vertex remains rejected once VC(1) closed H3. Exact
    // duplicates above were accepted before closure and never execute twice.
    let mut late = vertex;
    late.envelope.envelope_id = digest("fresh-after-cutoff");
    late.envelope_ref.tx_commitment = late.envelope.envelope_id.clone();
    sign_fixture_vertex(&fleet, &mut late);
    let receipt = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .ingress
        .submit_local_protected_vertex(late)
        .unwrap();
    assert!(await_local_receipt(&mut fleet, receipt, false).is_err());
    fleet.advance(8);
}

#[test]
fn authenticated_socket_below_quorum_halt_and_durable_recovery() {
    let mut fleet = SocketFleet::new();
    fleet.advance(6);
    let maximum_verified_qc = |fleet: &SocketFleet, through: u64| {
        let mut maximum = 0;
        for node in fleet.nodes.iter().flatten() {
            let authority = authority::load(&node.configuration).unwrap().unwrap();
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let store = synergy_posy::persistence::VerifiedQuorumCertificateStore::new(
                layout.consensus().join("posy"),
            )
            .unwrap();
            for height in 1..=through {
                if store
                    .get_verified(
                        height,
                        &authority.epoch,
                        &authority.registry,
                        authority.as_ref(),
                    )
                    .unwrap()
                    .is_some()
                {
                    maximum = maximum.max(height);
                }
            }
        }
        maximum
    };
    let before_finality = fleet
        .nodes
        .iter()
        .flatten()
        .map(|node| node.ingress.latest_finality().unwrap().unwrap().height)
        .max()
        .unwrap();
    let before_qc = maximum_verified_qc(&fleet, before_finality + 3);
    assert!(before_qc >= before_finality + 2);
    // The already authenticated pipeline can contain signatures for its next
    // slots. Bound those in-flight slots before removing two genuine signers.
    let inflight_qc_bound = before_qc + 2;
    let inflight_finality_bound = inflight_qc_bound - 2;
    let round_timeout = Duration::from_millis(
        fleet.nodes[0]
            .as_ref()
            .unwrap()
            .configuration
            .consensus
            .round_timeout_ms,
    );
    assert!(round_timeout >= Duration::from_secs(30));
    let mut removed = Vec::new();
    for index in [3, 4] {
        let mut node = fleet.nodes[index].take().unwrap();
        let configuration = node.configuration.clone();
        node.stop();
        drop(node);
        removed.push((index, configuration));
    }
    let halt_started = Instant::now();
    let settle_deadline = halt_started + round_timeout;
    let mut stable_since = halt_started;
    let mut last_tip = before_finality;
    loop {
        for node in fleet.nodes.iter_mut().flatten() {
            node.poll();
        }
        let tip = fleet
            .nodes
            .iter()
            .flatten()
            .map(|node| node.ingress.latest_finality().unwrap().unwrap().height)
            .max()
            .unwrap();
        assert!(
            tip <= inflight_finality_bound,
            "3/5 finalized beyond the genuine pre-outage pipeline"
        );
        if tip != last_tip {
            last_tip = tip;
            stable_since = Instant::now();
        }
        if stable_since.elapsed() >= Duration::from_secs(5) {
            break;
        }
        assert!(
            Instant::now() < settle_deadline,
            "3/5 failed to settle pre-existing certified pipeline"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let settled_qc = maximum_verified_qc(&fleet, inflight_qc_bound + 1);
    assert!(settled_qc <= inflight_qc_bound);
    // Observe an entire configured healthy round timeout after settlement.
    // Timeout votes and authenticated retries still run; three identities
    // cannot manufacture the fourth quorum signature or advance finality.
    let observe_started = Instant::now();
    let mut next_qc_check = observe_started;
    while observe_started.elapsed() < round_timeout + Duration::from_secs(1) {
        for node in fleet.nodes.iter_mut().flatten() {
            node.poll();
        }
        let tip = fleet
            .nodes
            .iter()
            .flatten()
            .map(|node| node.ingress.latest_finality().unwrap().unwrap().height)
            .max()
            .unwrap();
        assert_eq!(
            tip, last_tip,
            "3/5 created additional finality after the certified pipeline settled"
        );
        if Instant::now() >= next_qc_check {
            assert_eq!(
                maximum_verified_qc(&fleet, inflight_qc_bound + 1),
                settled_qc,
                "3/5 created an additional authenticated QC after settlement"
            );
            next_qc_check = Instant::now() + Duration::from_secs(1);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    eprintln!("socket qualification: 3/5 held finality H{last_tip} and QC H{settled_qc} for full {:?} round timeout", round_timeout);
    for (index, configuration) in removed {
        fleet.nodes[index] = Some(Node::open(configuration, &fleet.listeners[index]));
    }
    for index in [3, 4] {
        for peer in 0..5 {
            if peer == index {
                continue;
            }
            fleet.nodes[index]
                .as_ref()
                .unwrap()
                .ingress
                .request_dial(ingress::DialRequest {
                    peer_id: fleet.ids[peer].clone(),
                    address: fleet.nodes[peer]
                        .as_ref()
                        .unwrap()
                        .configuration
                        .network
                        .listen_addresses[0],
                })
                .unwrap();
        }
    }
    fleet.advance(12);
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn genuine_committed_lease_anchor_matches_full_r1_r2_reconstruction() {
    use synergy_posy::persistence::{
        FinalityStore, VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
    };
    use synergy_posy::{
        block_vote_signing_bytes, timeout_vote_signing_bytes, BlockVote, ConsensusObjectContext,
        FinalitySyncWitness, SimplifiedConsensusStateMachine, SimplifiedQuorumCertificate,
        SimplifiedTimeoutCertificate, ThreeQcFinality, TimeoutVote,
        POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN, POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
    };
    let provider = trusted_apqe_provider();
    let prepared = prepare_socket_fixture_profile_mode(
        synergy_state::WorldState::default(),
        None,
        false,
        None,
        Some(&provider),
        false,
    );
    let fleet = SocketFleet {
        root: prepared.root,
        nodes: Vec::new(),
        ids: prepared.ids,
        listeners: prepared.listeners,
    };
    let authority = authority::load(&prepared.configurations[4])
        .unwrap()
        .unwrap();
    let sign = |index: usize, domain: &str, bytes: &[u8]| {
        fixture_sign(
            &fs::read(fleet.root.join(format!("node-{index}/consensus.key"))).unwrap(),
            SignatureAlgorithm::MlDsa65,
            &format!("consensus-{index}"),
            domain,
            Some(1),
            bytes,
        )
    };
    let parent = |qc: &SimplifiedQuorumCertificate| SimplifiedFinalityParent::QuorumCertificate {
        height: qc.context.height,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().unwrap(),
    };
    let qc = |height: u64,
              round: u64,
              parent: SimplifiedFinalityParent,
              takeover: Option<String>| {
        let votes = (0..4)
            .map(|index| {
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, height, round)
                        .unwrap(),
                    block_id: format!("bounded-block-{height}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: takeover.clone(),
                    protected_execution_root: "e".repeat(64),
                    validator_id: fleet.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: Vec::new(),
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    &block_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        SimplifiedQuorumCertificate::from_votes(votes).unwrap()
    };
    let timeout = |height: u64,
                   round: u64,
                   highest: &SimplifiedQuorumCertificate,
                   predecessor: Option<String>,
                   carry: Option<synergy_posy::CertifiedCandidateSubject>| {
        let reports = (0..4)
            .map(|index| {
                let mut vote = TimeoutVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, height, round)
                        .unwrap(),
                    lease_index: authority.epoch.lease_index(height).unwrap(),
                    timed_out_proposer: authority
                        .epoch
                        .authorized_proposer(height, round)
                        .unwrap()
                        .into(),
                    highest_parent: parent(highest),
                    previous_tc_id: predecessor.clone(),
                    last_voted_candidate: carry.clone(),
                    validator_id: fleet.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: Vec::new(),
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                    &timeout_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![highest.clone()])
            .unwrap()
    };
    let root = fleet.root.join("bounded-native-recovery");
    let qcs = VerifiedQuorumCertificateStore::new(&root).unwrap();
    let tcs = VerifiedTimeoutCertificateStore::new(&root).unwrap();
    let durable = FinalityStore::new(&root).unwrap();
    let mut chain = Vec::new();
    let mut finality = ThreeQcFinality::default();
    let mut committed = None;
    let mut canonical = None;
    for height in 1..=12 {
        if height == 3 {
            let tc = timeout(3, 0, &chain[1], None, None);
            tcs.put_verified(
                &tc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
            canonical = Some(tc.id().unwrap());
        }
        let previous = chain
            .last()
            .map(&parent)
            .unwrap_or_else(|| authority.anchor_parent.clone());
        let takeover = (3..=10)
            .contains(&height)
            .then(|| canonical.clone())
            .flatten();
        let proof = qc(height, u64::from(takeover.is_some()), previous, takeover);
        qcs.put_verified(
            &proof,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
        if let Some(record) = finality.accept(proof.clone()).unwrap() {
            durable
                .commit_exactly_once(&record, committed.as_ref())
                .unwrap();
            committed = Some(record);
        }
        chain.push(proof);
    }
    // R1-superseded original evidence remains intact in an older lease.
    let original = timeout(2, 0, &chain[0], None, Some(chain[1].subject().unwrap()));
    tcs.put_verified(
        &original,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    // R2 retains a QC-compatible original timeout at the latest certified tip.
    let carried = timeout(12, 0, &chain[10], None, Some(chain[11].subject().unwrap()));
    tcs.put_verified(
        &carried,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    let outstanding = timeout(13, 1, &chain[11], Some(carried.id().unwrap()), None);
    tcs.put_verified(
        &outstanding,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    let mut safety = synergy_posy::SignOnceJournal::load(root.join("sign-once.json")).unwrap();
    safety
        .advance_finalized_floor(committed.as_ref().unwrap().height)
        .unwrap();
    fn retained_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut paths = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        let mut retained = Vec::new();
        for path in paths {
            if path.is_dir() {
                retained.extend(retained_bytes(&path));
            } else {
                retained.push((path.clone(), fs::read(path).unwrap()));
            }
        }
        retained
    }
    // Complete the timeout store's lazy legacy-index initialization before
    // asserting that replay leaves every retained file byte-for-byte intact.
    tcs.get_slots_for_lease_before(13, 13, &authority.epoch, &authority.registry)
        .unwrap();
    let before = retained_bytes(&root);
    let new = || {
        SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap()
    };
    let mut full = new();
    let mut bounded = new();
    let full_record =
        posy::replay_verified_safety_state(&mut full, authority.as_ref(), &qcs, &tcs, &durable)
            .unwrap();
    let bounded_record = posy::replay_verified_safety_state_from_floor(
        &mut bounded,
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        Some(safety.finalized_floor()),
    )
    .unwrap();
    let equivalent = |a: &SimplifiedConsensusStateMachine, b: &SimplifiedConsensusStateMachine| {
        assert_eq!(a.active_slot(), b.active_slot());
        assert_eq!(a.highest_parent(), b.highest_parent());
        assert_eq!(a.locked_qc(), b.locked_qc());
        assert_eq!(a.active_takeover_tc_id(), b.active_takeover_tc_id());
        assert_eq!(a.last_finalized(), b.last_finalized());
        assert_eq!(
            a.accepted_timeout_certificates()
                .map(|tc| tc.id().to_owned())
                .collect::<Vec<_>>(),
            b.accepted_timeout_certificates()
                .map(|tc| tc.id().to_owned())
                .collect::<Vec<_>>(),
        );
        if let Some(record) = a.last_finalized() {
            assert_eq!(
                a.finality_witness(record.height),
                b.finality_witness(record.height)
            );
        }
    };
    assert_eq!(full_record, bounded_record);
    equivalent(&full, &bounded);
    assert_eq!(bounded.active_slot(), (13, 2));
    assert_eq!(retained_bytes(&root), before);

    let next = qc(13, 2, parent(&chain[11]), Some(outstanding.id().unwrap()));
    let incoming = FinalitySyncWitness {
        quorum_certificates: [chain[10].clone(), chain[11].clone(), next],
        timeout_certificates: vec![carried.clone(), outstanding.clone()],
    };
    let (full_sync, full_events) =
        posy::stage_sync_projection(authority.as_ref(), &qcs, &tcs, &durable, &incoming).unwrap();
    let (bounded_sync, bounded_events) = posy::stage_sync_projection_from_floor(
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        &incoming,
        Some(safety.finalized_floor()),
    )
    .unwrap();
    equivalent(&full_sync, &bounded_sync);
    assert_eq!(full_events, bounded_events);
    assert_eq!(retained_bytes(&root), before);

    // The long-checkpoint adapter must reach the same native state through
    // bounded complete-lease pages, including a carried timeout whose original
    // slot precedes its later certified use. Neither verification page writes.
    let mut prefix = chain.clone();
    prefix.push(incoming.quorum_certificates[2].clone());
    let witnesses = (0..=10)
        .map(|index| {
            FinalitySyncWitness::from_verified_certificates(
                [
                    prefix[index].clone(),
                    prefix[index + 1].clone(),
                    prefix[index + 2].clone(),
                ],
                &tcs,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let initial =
        posy::begin_checkpoint_projection(authority.as_ref(), &qcs, &tcs, &durable, None).unwrap();
    let (paged, mut page_events) = posy::stage_checkpoint_page(
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        &witnesses[..8],
        initial,
        10,
    )
    .unwrap();
    assert_eq!(paged.active_slot().0, 11);
    let (paged, final_events) = posy::stage_checkpoint_page(
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        &witnesses[8..],
        paged,
        13,
    )
    .unwrap();
    page_events.extend(final_events);
    let paged = posy::finish_checkpoint_projection(authority.as_ref(), &tcs, paged).unwrap();
    equivalent(&full_sync, &paged);
    assert_eq!(full_events, page_events);
    assert_eq!(retained_bytes(&root), before);

    // A stopped checkpoint may begin at any of the three already-certified
    // heights at the old lease tail, including the lease's last height.
    for from in 8..=10 {
        let anchor = durable.get(from).unwrap().unwrap();
        let seeded =
            posy::begin_checkpoint_projection(authority.as_ref(), &qcs, &tcs, &durable, Some(from))
                .unwrap();
        assert_eq!(seeded.active_slot().0, 11);
        assert_eq!(seeded.last_finalized().unwrap().height, 8);
        let (covered, events) = posy::stage_offline_checkpoint_page(
            authority.as_ref(),
            &qcs,
            &tcs,
            &durable,
            &witnesses[(from - 1) as usize..10],
            seeded,
            posy::CheckpointPageApplication {
                through: 10,
                initial_anchor: Some(&anchor),
            },
        )
        .unwrap();
        assert_eq!(covered.active_slot().0, 11);
        assert_eq!(covered.last_finalized().unwrap().height, 8);
        assert!(events.is_empty());
        let (finished, _) = posy::stage_checkpoint_page(
            authority.as_ref(),
            &qcs,
            &tcs,
            &durable,
            &witnesses[10..],
            covered,
            13,
        )
        .unwrap();
        let finished =
            posy::finish_checkpoint_projection(authority.as_ref(), &tcs, finished).unwrap();
        equivalent(&full_sync, &finished);
        assert_eq!(retained_bytes(&root), before);
    }

    // An older independently valid witness cannot replace the seeded prefix.
    let older = FinalitySyncWitness::from_verified_certificates(
        [chain[7].clone(), chain[8].clone(), chain[9].clone()],
        &tcs,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    let error = posy::stage_sync_projection_from_floor(
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        &older,
        Some(safety.finalized_floor()),
    )
    .unwrap_err();
    assert!(
        error.contains("ends below the committed recovery anchor"),
        "{error}"
    );
    assert_eq!(retained_bytes(&root), before);

    // Authenticate a complete conflicting fork whose first QC is below the
    // seed boundary. The direct-height guard must reject that omitted height.
    let conflicting_votes = (0..4)
        .map(|index| {
            let mut vote = BlockVote {
                context: chain[8].context.clone(),
                block_id: chain[8].block_id.clone(),
                parent_block_id: chain[8].parent_block_id.clone(),
                parent: chain[8].parent.clone(),
                takeover_tc_id: chain[8].takeover_tc_id.clone(),
                protected_execution_root: "f".repeat(64),
                validator_id: fleet.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: Vec::new(),
            };
            vote.signature = sign(
                index,
                POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                &block_vote_signing_bytes(&vote).unwrap(),
            );
            vote
        })
        .collect();
    let conflicting = SimplifiedQuorumCertificate::from_votes(conflicting_votes).unwrap();
    // End at H11, before the retained H12 carry, so local R1 supersession
    // does not mask the skipped-height QC conflict being tested.
    let child = qc(10, 1, parent(&conflicting), chain[9].takeover_tc_id.clone());
    let grandchild = qc(11, 0, parent(&child), None);
    let fork = FinalitySyncWitness::from_verified_certificates(
        [conflicting, child, grandchild],
        &tcs,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    let error = posy::stage_sync_projection_from_floor(
        authority.as_ref(),
        &qcs,
        &tcs,
        &durable,
        &fork,
        Some(safety.finalized_floor()),
    )
    .unwrap_err();
    // The seeded machine already retains this QC, so the paged projection's
    // staged-overlap guard rejects the fork before its durable-height check.
    assert_eq!(error, "checkpoint page conflicts with staged QC overlap");
    assert_eq!(retained_bytes(&root), before);

    let anchor = FinalitySyncWitness::from_verified_certificates(
        [chain[7].clone(), chain[8].clone(), chain[9].clone()],
        &tcs,
        &authority.epoch,
        &authority.registry,
        authority.as_ref(),
    )
    .unwrap();
    let mut invalid = anchor.clone();
    invalid.quorum_certificates[0].participants[0].signature[0] ^= 1;
    let mut rejected = new();
    assert!(rejected
        .seed_committed_lease_boundary(
            durable.get(8).unwrap().unwrap(),
            invalid,
            authority.as_ref(),
        )
        .is_err());
    assert_eq!(rejected.active_slot(), (1, 0));
    let mut invalid = anchor;
    invalid.timeout_certificates.clear();
    assert!(rejected
        .seed_committed_lease_boundary(
            durable.get(8).unwrap().unwrap(),
            invalid,
            authority.as_ref(),
        )
        .is_err());
    assert_eq!(rejected.active_slot(), (1, 0));
    assert_eq!(retained_bytes(&root), before);
}

#[test]
fn authenticated_r1_timeout_before_older_qc_recovers_certified_path_without_journal_changes() {
    qualify_genuine_r1_recovery(false, false, false);
}

/// Genuine signed evidence must converge despite reversed TC/QC delivery.
#[test]
fn authenticated_live_tc_qc_arrival_order_converges_successor_round() {
    qualify_genuine_r1_recovery(true, false, false);
}

#[test]
fn authenticated_socket_dropped_timeout_retries_converge_successor_round() {
    qualify_genuine_r1_recovery(true, true, false);
}

#[test]
fn authenticated_socket_retained_timeout_retries_after_idle_expiry_and_lease_change() {
    qualify_genuine_r1_recovery(true, true, true);
}

// This focused test polls the real Network and PoSy owners. Its genuine signed
// proof fixture does not supply execution payloads, so executable-chain progress
// remains covered separately by the full service SocketFleet qualifications.
fn qualify_r2_authenticated_delivery(
    mut fleet: SocketFleet,
    qcs: Vec<synergy_posy::SimplifiedQuorumCertificate>,
    timeout: synergy_posy::SimplifiedTimeoutCertificate,
    expire_fifth: bool,
) {
    use synergy_posy::ConsensusEvent;
    use synergy_protocol_types::ProtocolKind;

    fn slots(fleet: &SocketFleet) -> Vec<(u64, u64)> {
        fleet
            .nodes
            .iter()
            .flatten()
            .map(|node| {
                let layout = synergy_storage::NodeStorageLayout::new(
                    node.configuration.storage.data_directory.clone(),
                )
                .unwrap();
                let record: serde_json::Value = serde_json::from_slice(
                    &fs::read(layout.consensus().join("posy/delivery.json")).unwrap(),
                )
                .unwrap();
                (
                    record["slot"][0].as_u64().unwrap(),
                    record["slot"][1].as_u64().unwrap(),
                )
            })
            .collect()
    }
    fn send(
        fleet: &mut SocketFleet,
        event: &ConsensusEvent,
        recipients: &[usize],
        drop_timeout: bool,
        timeout_bytes: &[u8],
        dropped: &mut usize,
    ) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let payload = serde_json::to_vec(event).unwrap();
        let event_kind = std::mem::discriminant(event);
        for &recipient in recipients {
            loop {
                let accepted = fleet.nodes[0]
                    .as_ref()
                    .unwrap()
                    .ingress
                    .try_publish_outbound(ingress::OutboundFrame {
                        peer_id: fleet.ids[recipient].clone(),
                        protocol: ProtocolKind::Posy,
                        payload: payload.clone(),
                    })
                    .unwrap();
                if accepted {
                    break;
                }
                poll(fleet, drop_timeout, timeout_bytes, dropped);
                // The deterministic fixture polls Network before PoSy, whose
                // reliable retries may refill ingress. Give this authored frame
                // the next genuinely drained transport slot before another PoSy
                // poll; retain every queued frame and the production quotas.
                for (name, service) in &mut fleet.nodes[0].as_mut().unwrap().services {
                    if *name == "network" {
                        service.poll().unwrap_or_else(|error| panic!(
                            "fixture sender network drain for {event_kind:?} to {recipient}: {error}"
                        ));
                        assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "fixture outbound queue did not drain for {event_kind:?} to recipient {recipient}"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
    fn poll(
        fleet: &mut SocketFleet,
        drop_timeout: bool,
        timeout_bytes: &[u8],
        dropped: &mut usize,
    ) {
        for (index, node) in fleet.nodes.iter_mut().enumerate() {
            let node = node.as_mut().unwrap();
            for (name, service) in &mut node.services {
                if !matches!(*name, "network" | "posy") {
                    continue;
                }
                if *name == "posy" && index == 4 && drop_timeout {
                    let mut retained = Vec::new();
                    while let Some(frame) = node.ingress.take(ProtocolKind::Posy).unwrap() {
                        assert!(node.ingress.is_current_session(&frame.peer).unwrap());
                        if frame.payload == timeout_bytes {
                            *dropped += 1;
                        } else {
                            retained.push(frame);
                        }
                    }
                    for frame in retained {
                        node.ingress.publish(frame).unwrap();
                    }
                }
                service
                    .poll()
                    .unwrap_or_else(|error| panic!("R2 socket {index} {name}: {error}"));
                assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
            }
        }
    }
    fn wait_for(
        fleet: &mut SocketFleet,
        expected: &[(u64, u64)],
        drop_timeout: bool,
        timeout_bytes: &[u8],
        dropped: &mut usize,
    ) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            poll(fleet, drop_timeout, timeout_bytes, dropped);
            let actual = slots(fleet);
            if actual == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "R2 authenticated slots {actual:?}, expected {expected:?}"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    let timeout_event = ConsensusEvent::TimeoutCertificate(timeout.clone());
    let timeout_bytes = serde_json::to_vec(&timeout_event).unwrap();
    let mut dropped = 0;
    let deadline = Instant::now() + Duration::from_secs(20);
    while fleet
        .nodes
        .iter()
        .flatten()
        .any(|node| node.ingress.authenticated_peers().unwrap().len() != 4)
    {
        poll(&mut fleet, true, &timeout_bytes, &mut dropped);
        assert!(
            Instant::now() < deadline,
            "R2 authenticated mesh did not connect"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    send(
        &mut fleet,
        &ConsensusEvent::QuorumCertificate(qcs[0].clone()),
        &[1, 2, 3, 4],
        true,
        &timeout_bytes,
        &mut dropped,
    );
    wait_for(&mut fleet, &[(2, 0); 5], true, &timeout_bytes, &mut dropped);
    // Seed the valid original TC exactly once through authenticated TCP. All
    // subsequent dissemination comes from the production owner's reliable retry.
    send(
        &mut fleet,
        &timeout_event,
        &[1],
        true,
        &timeout_bytes,
        &mut dropped,
    );
    wait_for(
        &mut fleet,
        &[(2, 1), (2, 1), (2, 1), (2, 1), (2, 0)],
        true,
        &timeout_bytes,
        &mut dropped,
    );
    send(
        &mut fleet,
        &ConsensusEvent::QuorumCertificate(qcs[1].clone()),
        &[1, 2, 3, 4],
        true,
        &timeout_bytes,
        &mut dropped,
    );
    let split = [(3, 1), (3, 1), (3, 1), (3, 1), (3, 0)];
    wait_for(&mut fleet, &split, true, &timeout_bytes, &mut dropped);
    assert!(
        dropped > 0,
        "fixture did not drop an authenticated TC delivery"
    );
    let after_qc_drops = dropped;
    let retry_deadline = Instant::now() + Duration::from_secs(5);
    while dropped == after_qc_drops {
        poll(&mut fleet, true, &timeout_bytes, &mut dropped);
        assert!(
            Instant::now() < retry_deadline,
            "production retry lost original-height TC after QC"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(slots(&fleet), split);
    if expire_fifth {
        let fifth_id = fleet.ids[4].clone();
        let poll_four = |fleet: &mut SocketFleet| {
            for node in fleet.nodes[..4].iter_mut().flatten() {
                for (name, service) in &mut node.services {
                    if matches!(*name, "network" | "posy") {
                        service.poll().unwrap();
                        assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
                    }
                }
            }
        };
        // All progress evidence travels through authenticated sockets. The
        // unavailable owner receives neither manual TC replay nor service polls.
        for qc in &qcs[2..] {
            let bytes = serde_json::to_vec(&ConsensusEvent::QuorumCertificate(qc.clone())).unwrap();
            for recipient in 1..4 {
                let deadline = Instant::now() + Duration::from_secs(20);
                loop {
                    if fleet.nodes[0]
                        .as_ref()
                        .unwrap()
                        .ingress
                        .try_publish_outbound(ingress::OutboundFrame {
                            peer_id: fleet.ids[recipient].clone(),
                            protocol: ProtocolKind::Posy,
                            payload: bytes.clone(),
                        })
                        .unwrap()
                    {
                        break;
                    }
                    poll_four(&mut fleet);
                    // Preserve the genuine queued retries, but admit the
                    // authored fixture QC immediately after actual transport
                    // drain, before a PoSy poll refills the bounded mailbox.
                    for (name, service) in &mut fleet.nodes[0].as_mut().unwrap().services {
                        if *name == "network" {
                            service.poll().unwrap();
                            assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
                        }
                    }
                    assert!(
                        Instant::now() < deadline,
                        "four-owner QC H{} delivery backpressure to recipient {recipient}",
                        qc.context.height
                    );
                }
            }
            let deadline = Instant::now() + Duration::from_secs(20);
            while slots(&fleet)[..4]
                .iter()
                .any(|slot| slot.0 <= qc.context.height)
            {
                poll_four(&mut fleet);
                assert!(
                    Instant::now() < deadline,
                    "four owners failed to cross lease boundary"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let last = qcs.last().unwrap();
        let authority = authority::load(&fleet.nodes[0].as_ref().unwrap().configuration)
            .unwrap()
            .unwrap();
        assert_ne!(
            authority.epoch.lease_index(2).unwrap(),
            authority.epoch.lease_index(last.context.height).unwrap()
        );
        let idle = Duration::from_millis(
            fleet.nodes[0]
                .as_ref()
                .unwrap()
                .configuration
                .network
                .idle_connection_timeout_ms,
        );
        let deadline = Instant::now() + idle + Duration::from_secs(30);
        loop {
            poll_four(&mut fleet);
            if fleet.nodes[..4].iter().flatten().all(|node| {
                !node
                    .ingress
                    .authenticated_peers()
                    .unwrap()
                    .contains(&fifth_id)
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "unpolled fifth session did not actually expire"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        // Discard any original-TC bytes buffered before disconnection until
        // a fresh authenticated mesh exists; only a subsequent retry may pass.
        let reconnect_deadline = Instant::now() + Duration::from_secs(45);
        loop {
            poll(&mut fleet, true, &timeout_bytes, &mut dropped);
            redial_missing_socket_peers(&fleet, 4);
            if fleet
                .nodes
                .iter()
                .flatten()
                .all(|node| node.ingress.authenticated_peers().unwrap().len() == 4)
            {
                break;
            }
            assert!(
                Instant::now() < reconnect_deadline,
                "expired fifth session did not reconnect"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            poll(&mut fleet, false, &timeout_bytes, &mut dropped);
            redial_missing_socket_peers(&fleet, 4);
            let node = fleet.nodes[4].as_ref().unwrap();
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let recovered =
                synergy_posy::VerifiedTimeoutCertificateStore::new(layout.consensus().join("posy"))
                    .unwrap()
                    .get_verified(
                        2,
                        0,
                        &authority.epoch,
                        &authority.registry,
                        authority.as_ref(),
                    )
                    .unwrap();
            if recovered.as_ref() == Some(&timeout) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "retained original TC was not retried after idle expiry and lease change"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        return;
    }
    // No retained frame is injected or manual TC resend performed: removing the
    // drop permits a later production retry to reconcile the QC-first validator.
    wait_for(
        &mut fleet,
        &[(3, 1); 5],
        false,
        &timeout_bytes,
        &mut dropped,
    );
    for node in fleet.nodes.iter().flatten() {
        let authority = authority::load(&node.configuration).unwrap().unwrap();
        let layout = synergy_storage::NodeStorageLayout::new(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        let stored =
            synergy_posy::VerifiedTimeoutCertificateStore::new(layout.consensus().join("posy"))
                .unwrap()
                .get_verified(
                    2,
                    0,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap()
                .unwrap();
        assert_eq!(stored, timeout);
    }
    for qc in &qcs[2..] {
        send(
            &mut fleet,
            &ConsensusEvent::QuorumCertificate(qc.clone()),
            &[1, 2, 3, 4],
            false,
            &timeout_bytes,
            &mut dropped,
        );
        wait_for(
            &mut fleet,
            &[(qc.context.height + 1, 1); 5],
            false,
            &timeout_bytes,
            &mut dropped,
        );
    }
    let records = fleet
        .nodes
        .iter()
        .flatten()
        .map(|node| node.ingress.latest_finality().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records[0].height, 2);
    assert_eq!(records[0].block_id, qcs[1].block_id);
    assert!(records.iter().all(|record| record == &records[0]));
    eprintln!("R2_AUTHENTICATED_RETRY_CONVERGENCE: dropped {dropped} exact TC frames; original-height automatic retry aligned all five at H3/r1 and genuine three-QC finality continued to H2");
}

fn qualify_genuine_r1_recovery(
    reproduce_live_split_only: bool,
    qualify_socket_retry: bool,
    expire_fifth: bool,
) {
    use synergy_posy::persistence::{
        FinalityStore, VerifiedQuorumCertificateStore, VerifiedTimeoutCertificateStore,
    };
    use synergy_posy::{
        block_vote_signing_bytes, timeout_vote_signing_bytes, BlockVote, ConsensusObjectContext,
        SimplifiedConsensusStateMachine, SimplifiedQuorumCertificate, SimplifiedTimeoutCertificate,
        ThreeQcFinality, TimeoutVote, POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
        POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
    };
    let fleet = SocketFleet::new();
    let configuration = &fleet.nodes[4].as_ref().unwrap().configuration;
    let authority = authority::load(configuration).unwrap().unwrap();
    let sign = |index: usize, domain: &str, bytes: &[u8]| {
        fixture_sign(
            &fs::read(fleet.root.join(format!("node-{index}/consensus.key"))).unwrap(),
            SignatureAlgorithm::MlDsa65,
            &format!("consensus-{index}"),
            domain,
            Some(1),
            bytes,
        )
    };
    let qc = |height: u64,
              round: u64,
              parent: SimplifiedFinalityParent,
              takeover: Option<String>| {
        let votes = (0..4)
            .map(|index| {
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, height, round)
                        .unwrap(),
                    block_id: format!("r1-block-{height}"),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: takeover.clone(),
                    protected_execution_root: "e".repeat(64),
                    validator_id: fleet.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: vec![],
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_BLOCK_VOTE_DOMAIN,
                    &block_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        qc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        qc
    };
    let parent = |qc: &SimplifiedQuorumCertificate| SimplifiedFinalityParent::QuorumCertificate {
        height: qc.context.height,
        block_id: qc.block_id.clone(),
        qc_id: qc.id().unwrap(),
    };
    let q1 = qc(1, 0, authority.anchor_parent.clone(), None);
    let q2 = qc(2, 0, parent(&q1), None);
    let timeout = |height: u64,
                   highest: &SimplifiedQuorumCertificate,
                   carry: Option<synergy_posy::CertifiedCandidateSubject>| {
        let reports = (0..4)
            .map(|index| {
                let mut vote = TimeoutVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, height, 0)
                        .unwrap(),
                    lease_index: authority.epoch.lease_index(height).unwrap(),
                    timed_out_proposer: authority
                        .epoch
                        .authorized_proposer(height, 0)
                        .unwrap()
                        .into(),
                    highest_parent: parent(highest),
                    previous_tc_id: None,
                    last_voted_candidate: carry.clone(),
                    validator_id: fleet.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: vec![],
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                    &timeout_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let tc =
            SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![highest.clone()])
                .unwrap();
        tc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        tc
    };
    let local_timeout = timeout(2, &q1, Some(q2.subject().unwrap()));
    if reproduce_live_split_only {
        let new_driver = || {
            SimplifiedConsensusStateMachine::new(
                authority.epoch.clone(),
                authority.registry.clone(),
                authority.anchor_parent.clone(),
            )
            .unwrap()
        };
        let mut timeout_first = new_driver();
        timeout_first
            .accept_quorum_certificate(q1.clone(), authority.as_ref())
            .unwrap();
        timeout_first
            .accept_timeout_certificate(local_timeout.clone(), authority.as_ref())
            .unwrap();
        timeout_first
            .accept_quorum_certificate(q2.clone(), authority.as_ref())
            .unwrap();
        let mut qc_first = new_driver();
        qc_first
            .accept_quorum_certificate(q1.clone(), authority.as_ref())
            .unwrap();
        qc_first
            .accept_quorum_certificate(q2.clone(), authority.as_ref())
            .unwrap();
        assert_eq!(qc_first.active_slot(), (3, 0));
        qc_first
            .accept_timeout_certificate(local_timeout.clone(), authority.as_ref())
            .unwrap();
        assert_eq!(timeout_first.highest_parent(), qc_first.highest_parent());
        assert_eq!(timeout_first.active_slot(), (3, 1));
        assert_eq!(qc_first.active_slot(), timeout_first.active_slot());
        assert_eq!(
            qc_first.active_takeover_tc_id(),
            timeout_first.active_takeover_tc_id()
        );
        assert!(qc_first
            .accept_timeout_certificate(local_timeout.clone(), authority.as_ref())
            .unwrap()
            .is_empty());
        let restart_root = fleet.root.join("r2-retained-restart");
        let restart_qcs = VerifiedQuorumCertificateStore::new(&restart_root).unwrap();
        let restart_tcs = VerifiedTimeoutCertificateStore::new(&restart_root).unwrap();
        let restart_finality = FinalityStore::new(&restart_root).unwrap();
        for certificate in [&q1, &q2] {
            restart_qcs
                .put_verified(
                    certificate,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
        }
        restart_tcs
            .put_verified(
                &local_timeout,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        let original_timeout_bytes =
            synergy_posy::persistence::ConsensusEvidenceReader::open(&restart_root)
                .unwrap()
                .read_exact("verified-timeouts/h2r0.json")
                .unwrap()
                .unwrap();
        let mut restarted = new_driver();
        posy::replay_verified_safety_state(
            &mut restarted,
            authority.as_ref(),
            &restart_qcs,
            &restart_tcs,
            &restart_finality,
        )
        .unwrap();
        assert_eq!(restarted.active_slot(), qc_first.active_slot());
        assert_eq!(
            restarted.active_takeover_tc_id(),
            qc_first.active_takeover_tc_id()
        );
        assert_eq!(
            synergy_posy::persistence::ConsensusEvidenceReader::open(&restart_root)
                .unwrap()
                .read_exact("verified-timeouts/h2r0.json")
                .unwrap()
                .unwrap(),
            original_timeout_bytes
        );
        let takeover = Some(local_timeout.id().unwrap());
        let next = qc(3, 1, parent(&q2), takeover.clone());
        let following = qc(4, 1, parent(&next), takeover);
        for driver in [&mut timeout_first, &mut qc_first, &mut restarted] {
            driver
                .accept_quorum_certificate(next.clone(), authority.as_ref())
                .unwrap();
            driver
                .accept_quorum_certificate(following.clone(), authority.as_ref())
                .unwrap();
        }
        assert_eq!(timeout_first.last_finalized(), qc_first.last_finalized());
        assert_eq!(qc_first.last_finalized().unwrap().height, 2);
        eprintln!("R2_GENUINE_ORDERING_CONVERGENCE: both arrival orders reach identical successor round and continued three-QC finality");
        if qualify_socket_retry {
            let mut qcs = vec![q1, q2, next, following];
            if expire_fifth {
                let first_lease = authority.epoch.lease_index(2).unwrap();
                while authority
                    .epoch
                    .lease_index(qcs.last().unwrap().context.height)
                    .unwrap()
                    == first_lease
                {
                    let previous = qcs.last().unwrap();
                    let height = previous.context.height + 1;
                    let same_lease = authority.epoch.lease_index(height).unwrap() == first_lease;
                    qcs.push(qc(
                        height,
                        u64::from(same_lease),
                        parent(previous),
                        same_lease.then(|| local_timeout.id().unwrap()),
                    ));
                }
            }
            qualify_r2_authenticated_delivery(fleet, qcs, local_timeout, expire_fifth);
        }
        return;
    }
    let canonical_timeout = timeout(3, &q2, None);
    assert_ne!(local_timeout.id().unwrap(), canonical_timeout.id().unwrap());
    let q3 = qc(3, 1, parent(&q2), Some(canonical_timeout.id().unwrap()));
    let q4 = qc(4, 1, parent(&q3), Some(canonical_timeout.id().unwrap()));
    let mut live = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    live.accept_quorum_certificate(q1.clone(), authority.as_ref())
        .unwrap();
    live.accept_timeout_certificate(local_timeout.clone(), authority.as_ref())
        .unwrap();
    live.accept_quorum_certificate(q2.clone(), authority.as_ref())
        .unwrap();
    assert!(
        live.accept_quorum_certificate(q3.clone(), authority.as_ref())
            .is_err(),
        "ordinary live admission must not normalize the alternate timeout path"
    );
    let layout =
        synergy_storage::NodeStorageLayout::new(configuration.storage.data_directory.clone())
            .unwrap();
    let root = layout.consensus().join("posy");
    let certificates = VerifiedQuorumCertificateStore::new(&root).unwrap();
    let timeouts = VerifiedTimeoutCertificateStore::new(&root).unwrap();
    let finality = FinalityStore::new(&root).unwrap();
    timeouts
        .put_verified(
            &local_timeout,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    timeouts
        .put_verified(
            &canonical_timeout,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    let mut chained = ThreeQcFinality::default();
    let mut previous = None;
    for qc in [&q1, &q2, &q3, &q4] {
        certificates
            .put_verified(
                qc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        if let Some(record) = chained.accept(qc.clone()).unwrap() {
            finality
                .commit_exactly_once(&record, previous.as_ref())
                .unwrap();
            previous = Some(record);
        }
    }
    fn journal_bytes(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut entries = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        entries.sort();
        let mut bytes = Vec::new();
        for path in entries {
            if path.is_dir() {
                bytes.extend(journal_bytes(&path));
            } else {
                bytes.push((path.clone(), fs::read(path).unwrap()));
            }
        }
        bytes
    }
    let tip_reports = (0..4)
        .map(|index| {
            let mut vote = TimeoutVote {
                context: ConsensusObjectContext::for_height(&authority.epoch, 5, 1).unwrap(),
                lease_index: authority.epoch.lease_index(5).unwrap(),
                timed_out_proposer: authority.epoch.authorized_proposer(5, 1).unwrap().into(),
                highest_parent: parent(&q4),
                previous_tc_id: Some(canonical_timeout.id().unwrap()),
                last_voted_candidate: None,
                validator_id: fleet.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: vec![],
            };
            vote.signature = sign(
                index,
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                &timeout_vote_signing_bytes(&vote).unwrap(),
            );
            vote
        })
        .collect();
    let tip_timeout =
        SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(tip_reports, vec![q4.clone()])
            .unwrap();
    timeouts
        .put_verified(
            &tip_timeout,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    // Genuine two-TC inherited lease: round-zero closure is a predecessor of
    // the active round-one closure, so successive Syncs must not replay the
    // entire certified prefix merely because those two TC IDs differ.
    let q5_round2 = qc(5, 2, parent(&q4), Some(tip_timeout.id().unwrap()));
    let q6_round2 = qc(6, 2, parent(&q5_round2), Some(tip_timeout.id().unwrap()));
    for chain in [
        [q3.clone(), q4.clone(), q5_round2.clone()],
        [q4.clone(), q5_round2.clone(), q6_round2.clone()],
    ] {
        let multi_tc = synergy_posy::FinalitySyncWitness::from_verified_certificates(
            chain,
            &timeouts,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
        let closure = multi_tc
            .verified_timeout_closure(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        assert_eq!(closure.len(), 2);
        let active = (multi_tc.quorum_certificates[2].context.height + 1, 2);
        assert!(!posy::sync_projection_reference_differs(
            &authority.epoch,
            active,
            Some(tip_timeout.id().unwrap().as_str()),
            &multi_tc,
            &closure,
        )
        .unwrap());
        assert!(posy::sync_projection_reference_differs(
            &authority.epoch,
            active,
            Some(local_timeout.id().unwrap().as_str()),
            &multi_tc,
            &closure,
        )
        .unwrap());
        assert!(posy::sync_projection_reference_differs(
            &authority.epoch,
            (active.0, 1),
            Some(canonical_timeout.id().unwrap().as_str()),
            &multi_tc,
            &closure,
        )
        .unwrap());
    }
    let witness = synergy_posy::FinalitySyncWitness {
        quorum_certificates: [q1.clone(), q2.clone(), q3.clone()],
        timeout_certificates: vec![canonical_timeout.clone()],
    };
    let mut invalid_signature = local_timeout.clone();
    invalid_signature.reports[0].signature[0] ^= 1;
    assert!(witness
        .verify_superseded_timeout(
            &invalid_signature,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    let mut insufficient_quorum = local_timeout.clone();
    insufficient_quorum.reports.pop();
    assert!(witness
        .verify_superseded_timeout(
            &insufficient_quorum,
            &authority.epoch,
            &authority.registry,
            authority.as_ref()
        )
        .is_err());
    let unchanged = journal_bytes(&root);
    // Independently provisioned test namespaces exercise incompatible durable
    // proof inputs without editing or deleting the positive safety history.
    let mut different_candidate = q2.clone();
    different_candidate.block_id = "different-carried-candidate".into();
    let wrong_carry = timeout(2, &q1, Some(different_candidate.subject().unwrap()));
    let no_carry = timeout(2, &q1, None);
    let mut wrong_parent = local_timeout.clone();
    wrong_parent.highest_qc_proofs.clear();
    for report in &mut wrong_parent.reports {
        let index = fleet
            .ids
            .iter()
            .position(|id| id == &report.validator_id)
            .unwrap();
        report.highest_parent = authority.anchor_parent.clone();
        report.signature = sign(
            index,
            POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
            &timeout_vote_signing_bytes(report).unwrap(),
        );
    }
    wrong_parent
        .verify(&authority.epoch, &authority.registry, authority.as_ref())
        .unwrap();
    for (label, local, include_canonical) in [
        ("different-carry", wrong_carry, true),
        ("missing-carry", no_carry, true),
        ("different-parent", wrong_parent, true),
        ("missing-timeout-predecessor", local_timeout.clone(), false),
        ("missing-durable-finality", local_timeout.clone(), true),
        ("conflicting-durable-finality", local_timeout.clone(), true),
    ] {
        let rejected_root = fleet.root.join(format!("r1-rejected-{label}"));
        let rejected_qcs = VerifiedQuorumCertificateStore::new(&rejected_root).unwrap();
        let rejected_tcs = VerifiedTimeoutCertificateStore::new(&rejected_root).unwrap();
        let rejected_finality = FinalityStore::new(&rejected_root).unwrap();
        rejected_tcs
            .put_verified(
                &local,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        if include_canonical {
            rejected_tcs
                .put_verified(
                    &canonical_timeout,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
        }
        let mut proof = ThreeQcFinality::default();
        let mut previous = None;
        for qc in [&q1, &q2, &q3, &q4] {
            rejected_qcs
                .put_verified(
                    qc,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
            if let Some(record) = proof.accept(qc.clone()).unwrap() {
                if label != "missing-durable-finality" {
                    let mut stored = record.clone();
                    if label == "conflicting-durable-finality" {
                        stored.protected_execution_root = "f".repeat(64);
                    }
                    rejected_finality
                        .commit_exactly_once(&stored, previous.as_ref())
                        .unwrap();
                    previous = Some(stored);
                }
            }
        }
        let bytes = journal_bytes(&rejected_root);
        let mut rejected = SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        let initial_slot = rejected.active_slot();
        let initial_parent = rejected.highest_parent().clone();
        assert!(
            posy::replay_verified_safety_state(
                &mut rejected,
                authority.as_ref(),
                &rejected_qcs,
                &rejected_tcs,
                &rejected_finality
            )
            .is_err(),
            "R1 accepted {label}"
        );
        assert_eq!(
            rejected.active_slot(),
            initial_slot,
            "rejected recovery changed active slot for {label}"
        );
        assert_eq!(
            rejected.highest_parent(),
            &initial_parent,
            "rejected recovery changed certified parent for {label}"
        );
        assert!(rejected.active_takeover_tc_id().is_none());
        assert_eq!(
            journal_bytes(&rejected_root),
            bytes,
            "rejected recovery mutated {label} evidence"
        );
    }
    // A delayed older-round QC can legitimately retain the accepted carry TC
    // as the descendant-certified path. It must remain active, not superseded.
    let carried_q3 = qc(3, 1, parent(&q2), Some(local_timeout.id().unwrap()));
    let carried_q4 = qc(4, 1, parent(&carried_q3), Some(local_timeout.id().unwrap()));
    let carried_root = fleet.root.join("r1-referenced-carry-control");
    let carried_qcs = VerifiedQuorumCertificateStore::new(&carried_root).unwrap();
    let carried_tcs = VerifiedTimeoutCertificateStore::new(&carried_root).unwrap();
    let carried_finality = FinalityStore::new(&carried_root).unwrap();
    carried_tcs
        .put_verified(
            &local_timeout,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    let mut carried_chain = ThreeQcFinality::default();
    let mut carried_previous = None;
    for qc in [&q1, &q2, &carried_q3, &carried_q4] {
        carried_qcs
            .put_verified(
                qc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        if let Some(record) = carried_chain.accept(qc.clone()).unwrap() {
            carried_finality
                .commit_exactly_once(&record, carried_previous.as_ref())
                .unwrap();
            carried_previous = Some(record);
        }
    }
    // Exercise the exact staging boundary used by authenticated live Sync,
    // with only q1/q2 durable: incoming q3/q4 must create H1/H2 finality.
    for (label, canonical_tc, third, fourth) in [
        ("alternate-timeout", &canonical_timeout, &q3, &q4),
        ("referenced-carry", &local_timeout, &carried_q3, &carried_q4),
    ] {
        let stage_root = fleet.root.join(format!("r1-live-stage-{label}"));
        let stage_qcs = VerifiedQuorumCertificateStore::new(&stage_root).unwrap();
        let stage_tcs = VerifiedTimeoutCertificateStore::new(&stage_root).unwrap();
        let stage_finality = FinalityStore::new(&stage_root).unwrap();
        for qc in [&q1, &q2] {
            stage_qcs
                .put_verified(
                    qc,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .unwrap();
        }
        stage_tcs
            .put_verified(
                &local_timeout,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        let incoming = synergy_posy::FinalitySyncWitness {
            quorum_certificates: [q2.clone(), third.clone(), fourth.clone()],
            timeout_certificates: vec![canonical_tc.clone()],
        };
        let before = journal_bytes(&stage_root);
        let (staged, transitions) = posy::stage_sync_projection(
            authority.as_ref(),
            &stage_qcs,
            &stage_tcs,
            &stage_finality,
            &incoming,
        )
        .unwrap();
        assert_eq!(staged.active_slot(), (5, 1));
        assert_eq!(
            staged.active_takeover_tc_id(),
            Some(canonical_tc.id().unwrap().as_str())
        );
        assert_eq!(
            transitions
                .iter()
                .map(|(qc, record)| (qc.context.height, record.as_ref().map(|r| r.height)))
                .collect::<Vec<_>>(),
            vec![(3, Some(1)), (4, Some(2))]
        );
        assert_eq!(
            journal_bytes(&stage_root),
            before,
            "live staging mutated {label} journals"
        );
        let mut missing_proof = incoming.clone();
        missing_proof.timeout_certificates.clear();
        assert!(posy::stage_sync_projection(
            authority.as_ref(),
            &stage_qcs,
            &stage_tcs,
            &stage_finality,
            &missing_proof
        )
        .is_err());
        let mut noncontiguous = incoming.clone();
        noncontiguous.quorum_certificates[2] = third.clone();
        assert!(posy::stage_sync_projection(
            authority.as_ref(),
            &stage_qcs,
            &stage_tcs,
            &stage_finality,
            &noncontiguous
        )
        .is_err());
        let gap_root = fleet.root.join(format!("r1-live-gap-{label}"));
        let gap_qcs = VerifiedQuorumCertificateStore::new(&gap_root).unwrap();
        let gap_tcs = VerifiedTimeoutCertificateStore::new(&gap_root).unwrap();
        let gap_finality = FinalityStore::new(&gap_root).unwrap();
        gap_qcs
            .put_verified(
                &q2,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        assert!(posy::stage_sync_projection(
            authority.as_ref(),
            &gap_qcs,
            &gap_tcs,
            &gap_finality,
            &incoming
        )
        .is_err());
        // A conflicting durable finalized record cannot be replaced by the
        // otherwise valid incoming certified history.
        let mut conflict = staged.last_finalized().unwrap().clone();
        conflict.height = 1;
        conflict.block_id = "conflicting-finalized-block".into();
        stage_finality.commit_exactly_once(&conflict, None).unwrap();
        let conflict_bytes = journal_bytes(&stage_root);
        assert!(posy::stage_sync_projection(
            authority.as_ref(),
            &stage_qcs,
            &stage_tcs,
            &stage_finality,
            &incoming
        )
        .is_err());
        assert_eq!(journal_bytes(&stage_root), conflict_bytes);
    }
    // A backward finalized triple ending at the timeout's own certified tip
    // cannot supersede its takeover projection without a descendant QC path.
    let tip_control_root = fleet.root.join("r1-certified-tip-timeout-control");
    let tip_control_qcs = VerifiedQuorumCertificateStore::new(&tip_control_root).unwrap();
    let tip_control_tcs = VerifiedTimeoutCertificateStore::new(&tip_control_root).unwrap();
    let tip_control_finality = FinalityStore::new(&tip_control_root).unwrap();
    let tip_q3 = qc(3, 0, parent(&q2), None);
    let tip_carry = timeout(3, &q2, Some(tip_q3.subject().unwrap()));
    tip_control_tcs
        .put_verified(
            &tip_carry,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    let mut tip_chain = ThreeQcFinality::default();
    for qc in [&q1, &q2, &tip_q3] {
        tip_control_qcs
            .put_verified(
                qc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
        if let Some(record) = tip_chain.accept(qc.clone()).unwrap() {
            tip_control_finality
                .commit_exactly_once(&record, None)
                .unwrap();
        }
    }
    let tip_control_bytes = journal_bytes(&tip_control_root);
    let mut tip_control = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    let tip_record = posy::replay_verified_safety_state(
        &mut tip_control,
        authority.as_ref(),
        &tip_control_qcs,
        &tip_control_tcs,
        &tip_control_finality,
    )
    .unwrap()
    .unwrap();
    assert_eq!(tip_record.height, 1);
    assert_eq!(tip_control.active_slot(), (4, 1));
    assert_eq!(
        tip_control.active_takeover_tc_id(),
        Some(tip_carry.id().unwrap().as_str())
    );
    assert_eq!(
        journal_bytes(&tip_control_root),
        tip_control_bytes,
        "certified-tip timeout recovery altered original records"
    );
    let early_root = fleet.root.join("r1-early-no-three-qc-control");
    let early_qcs = VerifiedQuorumCertificateStore::new(&early_root).unwrap();
    let early_tcs = VerifiedTimeoutCertificateStore::new(&early_root).unwrap();
    let early_finality = FinalityStore::new(&early_root).unwrap();
    let early_reports = (0..4)
        .map(|index| {
            let mut vote = TimeoutVote {
                context: ConsensusObjectContext::for_height(&authority.epoch, 1, 0).unwrap(),
                lease_index: authority.epoch.lease_index(1).unwrap(),
                timed_out_proposer: authority.epoch.authorized_proposer(1, 0).unwrap().into(),
                highest_parent: authority.anchor_parent.clone(),
                previous_tc_id: None,
                last_voted_candidate: Some(q1.subject().unwrap()),
                validator_id: fleet.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: vec![],
            };
            vote.signature = sign(
                index,
                POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                &timeout_vote_signing_bytes(&vote).unwrap(),
            );
            vote
        })
        .collect();
    let early_timeout = SimplifiedTimeoutCertificate::from_votes(early_reports).unwrap();
    early_tcs
        .put_verified(
            &early_timeout,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    early_qcs
        .put_verified(
            &q1,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .unwrap();
    let early_bytes = journal_bytes(&early_root);
    let mut early = SimplifiedConsensusStateMachine::new(
        authority.epoch.clone(),
        authority.registry.clone(),
        authority.anchor_parent.clone(),
    )
    .unwrap();
    assert!(posy::replay_verified_safety_state(
        &mut early,
        authority.as_ref(),
        &early_qcs,
        &early_tcs,
        &early_finality
    )
    .unwrap()
    .is_none());
    assert_eq!(early.active_slot(), (2, 1));
    assert_eq!(
        early.active_takeover_tc_id(),
        Some(early_timeout.id().unwrap().as_str())
    );
    assert_eq!(
        journal_bytes(&early_root),
        early_bytes,
        "early TC-first restart altered original records"
    );
    let carried_bytes = journal_bytes(&carried_root);
    // A real long timeout predecessor closure exceeds one transport frame.
    // Chunk integrity is not consensus authority: the reconstructed bytes must
    // still pass the same production PoSy projection and signature checks.
    let mut long_timeouts = Vec::new();
    let mut predecessor = None;
    for round in 0..46 {
        let reports = (0..4)
            .map(|index| {
                let mut vote = TimeoutVote {
                    context: ConsensusObjectContext::for_height(&authority.epoch, 3, round)
                        .unwrap(),
                    lease_index: authority.epoch.lease_index(3).unwrap(),
                    timed_out_proposer: authority
                        .epoch
                        .authorized_proposer(3, round)
                        .unwrap()
                        .into(),
                    highest_parent: parent(&q2),
                    previous_tc_id: predecessor.clone(),
                    last_voted_candidate: None,
                    validator_id: fleet.ids[index].clone(),
                    key_id: format!("consensus-{index}"),
                    signature: Vec::new(),
                };
                vote.signature = sign(
                    index,
                    POSY_SIMPLIFIED_TIMEOUT_VOTE_DOMAIN,
                    &timeout_vote_signing_bytes(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let tc = SimplifiedTimeoutCertificate::from_votes_with_qc_proofs(reports, vec![q2.clone()])
            .unwrap();
        tc.verify(&authority.epoch, &authority.registry, authority.as_ref())
            .unwrap();
        predecessor = Some(tc.id().unwrap());
        long_timeouts.push(tc);
    }
    let long_q3 = qc(3, 46, parent(&q2), predecessor.clone());
    let long_q4 = qc(4, 46, parent(&long_q3), predecessor);
    let long_witness = synergy_posy::FinalitySyncWitness {
        quorum_certificates: [q2.clone(), long_q3, long_q4],
        timeout_certificates: long_timeouts,
    };
    let chunk_roundtrip = |witness: &synergy_posy::FinalitySyncWitness| {
        let bytes = serde_json::to_vec(witness).unwrap();
        assert!(
            bytes.len() > 1024 * 1024,
            "genuine timeout witness must exceed legacy frame bound"
        );
        assert!(bytes.len() <= synergy_sync::MAX_CANDIDATE_WITNESS_BYTES);
        let request = synergy_sync::FinalizedCandidateRequest {
            height: 2,
            expected_parent_id: q1.block_id.clone(),
        };
        let digest = synergy_sync::candidate_response_digest(&bytes);
        let mut chunks = bytes
            .chunks(synergy_sync::CANDIDATE_CHUNK_BYTES)
            .enumerate()
            .map(|(index, part)| synergy_sync::CandidateResponseChunk {
                request: request.clone(),
                total_bytes: bytes.len(),
                digest,
                offset: index * synergy_sync::CANDIDATE_CHUNK_BYTES,
                bytes: part.to_vec(),
            })
            .collect::<Vec<_>>();
        let mut assembly = synergy_sync::CandidateResponseAssembly::new(&chunks[0]).unwrap();
        chunks.reverse();
        for chunk in chunks {
            let wire = serde_json::to_vec(&synergy_sync::SyncWireMessage::<
                synergy_state::WorldState,
            >::FinalizedCandidateChunk(chunk))
            .unwrap();
            assert!(wire.len() < 1024 * 1024);
            let synergy_sync::SyncWireMessage::<synergy_state::WorldState>::FinalizedCandidateChunk(
                decoded,
            ) = serde_json::from_slice(&wire).unwrap()
            else {
                unreachable!()
            };
            assembly.push(decoded).unwrap();
        }
        assert!(assembly.is_complete());
        let reconstructed = assembly.finish().unwrap();
        assert_eq!(reconstructed, bytes);
        serde_json::from_slice::<synergy_posy::FinalitySyncWitness>(&reconstructed).unwrap()
    };
    let oversized_root = fleet.root.join("r1-oversized-timeout-proof");
    let oversized_qcs = VerifiedQuorumCertificateStore::new(&oversized_root).unwrap();
    let oversized_tcs = VerifiedTimeoutCertificateStore::new(&oversized_root).unwrap();
    let oversized_finality = FinalityStore::new(&oversized_root).unwrap();
    for certificate in [&q1, &q2] {
        oversized_qcs
            .put_verified(
                certificate,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .unwrap();
    }
    let oversized_before = journal_bytes(&oversized_root);
    let reconstructed = chunk_roundtrip(&long_witness);
    let (projected, transitions) = posy::stage_sync_projection(
        authority.as_ref(),
        &oversized_qcs,
        &oversized_tcs,
        &oversized_finality,
        &reconstructed,
    )
    .unwrap();
    assert_eq!(projected.active_slot(), (5, 46));
    assert_eq!(
        transitions
            .iter()
            .filter_map(|(_, record)| record.as_ref().map(|record| record.height))
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(journal_bytes(&oversized_root), oversized_before);
    let mut corrupt = long_witness;
    corrupt.timeout_certificates[23].reports[0].signature[0] ^= 1;
    // Recompute a valid transport digest around an invalid consensus proof.
    let corrupt = chunk_roundtrip(&corrupt);
    assert!(posy::stage_sync_projection(
        authority.as_ref(),
        &oversized_qcs,
        &oversized_tcs,
        &oversized_finality,
        &corrupt
    )
    .is_err());
    assert_eq!(journal_bytes(&oversized_root), oversized_before);

    for _ in 0..2 {
        let mut recovered = SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        let record = posy::replay_verified_safety_state(
            &mut recovered,
            authority.as_ref(),
            &carried_qcs,
            &carried_tcs,
            &carried_finality,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record, carried_previous.clone().unwrap());
        assert_eq!(recovered.active_slot(), (5, 1));
        assert_eq!(
            recovered.active_takeover_tc_id(),
            Some(local_timeout.id().unwrap().as_str())
        );
        assert_eq!(
            journal_bytes(&carried_root),
            carried_bytes,
            "referenced carry recovery altered original records"
        );
    }
    for _ in 0..2 {
        let mut recovered = SimplifiedConsensusStateMachine::new(
            authority.epoch.clone(),
            authority.registry.clone(),
            authority.anchor_parent.clone(),
        )
        .unwrap();
        let record = posy::replay_verified_safety_state(
            &mut recovered,
            authority.as_ref(),
            &certificates,
            &timeouts,
            &finality,
        )
        .unwrap()
        .unwrap();
        assert_eq!(record.height, 2);
        assert_eq!(record, previous.clone().unwrap());
        assert_eq!(recovered.active_slot(), (5, 2));
        assert_eq!(
            recovered.active_takeover_tc_id(),
            Some(tip_timeout.id().unwrap().as_str())
        );
        assert_eq!(
            journal_bytes(&root),
            unchanged,
            "recovery changed original safety/signing journals"
        );
    }
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn authenticated_socket_apqe_wallet_admission_finalizes_real_transfer() {
    qualify_wallet_admission_finality_provider(None, Some(trusted_apqe_provider()));
}
fn trusted_apqe_provider() -> synergy_config::ApqeProviderConfiguration {
    synergy_config::ApqeProviderConfiguration {
        report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT")
            .expect("explicit trusted report")
            .into(),
        authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256")
            .expect("explicit authenticated digest"),
    }
}

#[test]
fn authenticated_socket_wallet_admission_finalizes_real_transfer() {
    qualify_wallet_admission_finality(None);
}

#[test]
fn authenticated_socket_oversized_wallet_vertex_rejected_before_durable_admission() {
    qualify_wallet_admission_finality(Some(131072));
}

#[test]
fn authenticated_socket_large_frame_compatible_wallet_admission_finalizes_real_transfer() {
    qualify_wallet_admission_finality(Some(65536));
}

#[test]
fn authenticated_socket_four_wallets_share_target_and_finalize_under_resource_budget() {
    let mut initial = synergy_state::WorldState::default();
    let mut wallets = Vec::new();
    for _ in 0..4 {
        let (tx, world, secret) = funded_transaction_fixture_with_key();
        merge_funded_fixture_world(&mut initial, world).unwrap();
        wallets.push((tx, secret));
    }
    let mut fleet = SocketFleet::with_wallet_world_state(initial, true);
    let handle = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .wallet_admission
        .clone()
        .unwrap();
    let mut receipts = Vec::new();
    let mut transactions = Vec::new();
    for (tx, mut secret) in wallets {
        let mut vertex =
            protected_transaction_vertex_with_ciphertext_class(&fleet, &tx, Some(65536));
        vertex.envelope.envelope_id = synergy_etdag::envelope_commitment(&vertex.envelope).unwrap();
        let mut request = synergy_etdag::AdmissionRequest {
            request_version: synergy_etdag::ADMISSION_REQUEST_VERSION,
            chain_id: 1266,
            network_id: tx.unsigned.network.network_id.clone(),
            context_root: vertex.target_context_root,
            target_height: 3,
            sender_wallet: tx.unsigned.sender.clone(),
            sender_nonce: 0,
            gas_class_units: 21000,
            fee_class: 1,
            signature_algorithm: "ML-DSA-87".into(),
            signer_public_key: tx.signer_public_key.clone(),
            envelope: vertex.envelope,
            signature: vec![],
        };
        request.signature = fixture_sign(
            &secret,
            SignatureAlgorithm::MlDsa87,
            "transaction-presented-key",
            "SYNERGY-TRANSACTION-SIGNING-V1",
            None,
            &request.signing_bytes().unwrap(),
        );
        secret.fill(0);
        let admission = synergy_etdag::WalletAdmission {
            request,
            identity_authorization: tx.identity_authorization.clone().unwrap(),
        };
        let queued = wallet_rpc(
            &mut fleet,
            synergy_rpc::methods::PROTECTED_TRANSACTION_SUBMIT,
            serde_json::to_value(admission).unwrap(),
        );
        assert_eq!(queued["status"], "queued");
        receipts.push(queued["receipt_id"].as_str().unwrap().to_owned());
        transactions.push(tx);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        poll_before_consensus(&mut fleet);
        let observations: Vec<_> = receipts
            .iter()
            .map(|id| handle.receipt(id).unwrap())
            .collect();
        assert!(
            observations.iter().all(|r| r["status"] != "rejected"),
            "four-wallet rejection: {observations:?}"
        );
        if observations
            .iter()
            .all(|r| r["lifecycle_status"] == "certified")
        {
            let all_certified = fleet.nodes.iter().flatten().all(|node| {
                synergy_etdag::persistence::ProtectedPipeline::read_durable_evidence(
                    node.configuration
                        .storage
                        .data_directory
                        .join("etdag/protected-pipeline"),
                    3,
                )
                .unwrap()
                .is_some_and(|stored| {
                    observations.iter().all(|receipt| {
                        let vertex = receipt["evidence"]["vertex_id"].as_str().unwrap();
                        !stored["collecting"]["certificates"][vertex].is_null()
                    })
                })
            });
            if all_certified {
                eprintln!(
                    "socket qualification: all four wallets certified on all five validators"
                );
                break;
            }
        }
        let health: Vec<_> = fleet
            .nodes
            .iter()
            .flatten()
            .flat_map(|node| {
                node.services
                    .iter()
                    .filter(|(name, _)| *name == "etdag")
                    .map(|(_, service)| service.health())
            })
            .collect();
        assert!(
            health
                .iter()
                .all(|h| *h == synergy_node_core::ServiceHealth::Healthy),
            "four-wallet intake must fit without global health degradation: {health:?}"
        );
        assert!(
            Instant::now() < deadline,
            "four-wallet certification deadline: {observations:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    fleet.advance(6);
    for node in fleet.nodes.iter().flatten() {
        let store = synergy_state::FinalizedStateStore::load(
            node.configuration
                .storage
                .data_directory
                .join("state/execution"),
        )
        .unwrap();
        let world = store.current_world_state().unwrap().unwrap();
        assert_eq!(
            world.accounts[&transactions[0].unsigned.receiver].balance_nwei,
            28
        );
        let query = super::rpc::CanonicalQueryStore::load(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        use synergy_rpc::provider::CanonicalReadProvider;
        for tx in &transactions {
            assert_eq!(world.accounts[&tx.unsigned.sender].nonce, 1);
            let applied = query
                .transaction(&synergy_rpc::methods::TransactionQuery {
                    transaction_id: tx.id().unwrap().0,
                })
                .unwrap()
                .unwrap();
            assert_eq!(applied.status, "applied");
        }
    }
}

fn qualify_wallet_admission_finality(ciphertext_class: Option<usize>) {
    qualify_wallet_admission_finality_provider(ciphertext_class, None);
}
fn qualify_wallet_admission_finality_provider(
    ciphertext_class: Option<usize>,
    provider: Option<synergy_config::ApqeProviderConfiguration>,
) {
    let (tx, initial, mut account_secret) = funded_transaction_fixture_for_network_provider(
        "socket-qualification",
        10_000_000,
        provider.as_ref(),
    );
    let mut fleet = SocketFleet::with_wallet_world_state_provider(initial, true, provider);
    let handle = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .wallet_admission
        .clone()
        .unwrap();
    let exported: synergy_etdag::WalletAdmissionContext = serde_json::from_value(wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_ADMISSION_CONTEXT,
        serde_json::json!({}),
    ))
    .unwrap();
    assert_eq!(exported.context.target_height, 5);
    // H3 is another actually open Genesis target. The envelope helper below
    // encrypts with genuine assigned ingress keys and quorum.
    let mut vertex =
        protected_transaction_vertex_with_ciphertext_class(&fleet, &tx, ciphertext_class);
    if let Some(class) = ciphertext_class {
        assert_eq!(vertex.envelope.ciphertext.len(), class);
    }
    vertex.envelope.envelope_id = synergy_etdag::envelope_commitment(&vertex.envelope).unwrap();
    let mut request = synergy_etdag::AdmissionRequest {
        request_version: synergy_etdag::ADMISSION_REQUEST_VERSION,
        chain_id: 1266,
        network_id: tx.unsigned.network.network_id.clone(),
        context_root: vertex.target_context_root,
        target_height: 3,
        sender_wallet: tx.unsigned.sender.clone(),
        sender_nonce: 0,
        gas_class_units: 21000,
        fee_class: 1,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: tx.signer_public_key.clone(),
        envelope: vertex.envelope,
        signature: vec![],
    };
    request.signature = fixture_sign(
        &account_secret,
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &request.signing_bytes().unwrap(),
    );
    account_secret.fill(0);
    let admission = synergy_etdag::WalletAdmission {
        request,
        identity_authorization: tx.identity_authorization.clone().unwrap(),
    };
    let mut forged = admission.clone();
    forged.request.fee_class += 1;
    let rejected = wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_TRANSACTION_SUBMIT,
        serde_json::to_value(forged).unwrap(),
    )["receipt_id"]
        .as_str()
        .unwrap()
        .to_string();
    let accepted = wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_TRANSACTION_SUBMIT,
        serde_json::to_value(&admission).unwrap(),
    );
    assert_eq!(accepted["status"], "queued");
    assert_eq!(accepted["admitted"], false);
    let id = accepted["receipt_id"].as_str().unwrap().to_string();
    assert_eq!(
        wallet_rpc(
            &mut fleet,
            synergy_rpc::methods::PROTECTED_TRANSACTION_SUBMIT,
            serde_json::to_value(admission).unwrap()
        ),
        accepted
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        poll_before_consensus(&mut fleet);
        let receipt = handle.receipt(&id).unwrap();
        if ciphertext_class == Some(131072) && receipt["status"] == "rejected" {
            assert_eq!(
                receipt["reason"],
                "signed local vertex exceeds authenticated frame bound"
            );
            for node in fleet.nodes.iter().flatten() {
                let stored = synergy_etdag::persistence::ProtectedPipeline::read_durable_evidence(
                    node.configuration
                        .storage
                        .data_directory
                        .join("etdag/protected-pipeline"),
                    3,
                )
                .unwrap();
                if let Some(stored) = stored {
                    assert!(stored["collecting"]["graph"]["vertices"]
                        .as_object()
                        .unwrap()
                        .is_empty());
                }
            }
            return;
        }
        if receipt["status"] == "accepted" {
            eprintln!(
                "socket qualification: wallet authored ciphertext_class={ciphertext_class:?}"
            );
            break;
        }
        if receipt["status"] == "rejected" || Instant::now() >= deadline {
            let health: Vec<_> = fleet
                .nodes
                .iter()
                .flatten()
                .flat_map(|node| {
                    node.services.iter().map(|(name, service)| {
                        (
                            node.configuration.node_name.clone(),
                            *name,
                            service.health(),
                        )
                    })
                })
                .collect();
            panic!("wallet authoring did not complete: receipt={receipt}, health={health:?}");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        wallet_rpc(
            &mut fleet,
            synergy_rpc::methods::PROTECTED_ADMISSION_RECEIPT,
            serde_json::json!({"receipt_id":rejected})
        )["status"],
        "rejected"
    );
    let stats = wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_ADMISSION_STATS,
        serde_json::json!({}),
    );
    assert_eq!(stats["accepted_total"], 1);
    assert_eq!(stats["rejected_total"], 1);
    assert_eq!(handle.receipt(&id).unwrap()["evidence"]["finalized"], false);
    // Allow real authenticated VAC propagation before closing the first cut.
    let vertex_id = handle.receipt(&id).unwrap()["evidence"]["vertex_id"]
        .as_str()
        .unwrap()
        .to_string();
    loop {
        poll_before_consensus(&mut fleet);
        let all = fleet.nodes.iter().flatten().all(|node| {
            synergy_etdag::persistence::ProtectedPipeline::read_durable_evidence(
                node.configuration
                    .storage
                    .data_directory
                    .join("etdag/protected-pipeline"),
                3,
            )
            .unwrap()
            .is_some_and(|stored| !stored["collecting"]["certificates"][&vertex_id].is_null())
        });
        if all {
            eprintln!("socket qualification: wallet VAC present on all validators ciphertext_class={ciphertext_class:?}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "wallet VAC propagation did not complete"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    fleet.advance(6);
    for node in fleet.nodes.iter().flatten() {
        assert_eq!(
            node.wallet_admission.as_ref().unwrap().stats().unwrap()["etdag_ordered_total"],
            1
        );
        let store = synergy_state::FinalizedStateStore::load(
            node.configuration
                .storage
                .data_directory
                .join("state/execution"),
        )
        .unwrap();
        let world = store.current_world_state().unwrap().unwrap();
        assert_eq!(world.accounts[&tx.unsigned.sender].nonce, 1);
        assert_eq!(world.accounts[&tx.unsigned.receiver].balance_nwei, 7);
        let query = super::rpc::CanonicalQueryStore::load(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        use synergy_rpc::provider::CanonicalReadProvider;
        let result = query
            .transaction(&synergy_rpc::methods::TransactionQuery {
                transaction_id: tx.id().unwrap().0,
            })
            .unwrap()
            .unwrap();
        assert_eq!(result.status, "applied");
    }
}

fn wallet_rpc(
    fleet: &mut SocketFleet,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    wallet_rpc_node(fleet.nodes[0].as_mut().unwrap(), method, params)
}
fn wallet_rpc_node(node: &mut Node, method: &str, params: serde_json::Value) -> serde_json::Value {
    use std::io::{Read, Write};
    let address = node.configuration.rpc.listen_address.unwrap();
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let body = serde_json::to_vec(
        &serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}),
    )
    .unwrap();
    let mut request = format!("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    request.extend_from_slice(&body);
    socket.set_nonblocking(true).unwrap();
    let mut sent = 0;
    let mut response = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if sent < request.len() {
            match socket.write(&request[sent..]) {
                Ok(0) => panic!("RPC request socket closed before complete write"),
                Ok(count) => sent += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("RPC request write: {error}"),
            }
        }
        node.services
            .iter_mut()
            .find(|(name, _)| *name == "rpc")
            .unwrap()
            .1
            .poll()
            .unwrap();
        let mut buffer = [0u8; 4096];
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("RPC response read: {error}"),
        }
        assert!(Instant::now() < deadline, "RPC response deadline exceeded");
    }
    let start = response.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
    let response: serde_json::Value = serde_json::from_slice(&response[start..]).unwrap();
    assert!(
        response.get("error").is_none(),
        "RPC admission error: {response}"
    );
    response["result"].clone()
}

/// Delay genuine authenticated traffic immediately before its production owner
/// consumes it. Network/session verification remains active throughout.
// Explicit packet-hold controls keep this test fixture's failure phases visible.
#[allow(clippy::too_many_arguments)]
fn r3_poll_delayed(
    fleet: &mut SocketFleet,
    participating_validators: usize,
    hold_posy_from_height: Option<u64>,
    allow_timeout_traffic: bool,
    hold_availability: bool,
    held_posy: &mut Vec<(usize, synergy_network::protocol::InboundFrame)>,
    held_etdag: &mut Vec<(usize, synergy_network::protocol::InboundFrame)>,
    target_root: Option<&EtdagDigest>,
) {
    use synergy_etdag::{AuthenticatedEtdagMessage, EtdagNetworkMessage};
    use synergy_protocol_types::ProtocolKind;
    assert!(participating_validators <= fleet.nodes.len());
    for (index, node) in fleet
        .nodes
        .iter_mut()
        .take(participating_validators)
        .enumerate()
    {
        let node = node.as_mut().unwrap();
        for (name, service) in &mut node.services {
            let protocol = match *name {
                "posy" if hold_posy_from_height.is_some() => Some(ProtocolKind::Posy),
                "etdag" if hold_availability && index < 3 => Some(ProtocolKind::Etdag),
                _ => None,
            };
            if let Some(protocol) = protocol {
                let mut deliver = Vec::new();
                while let Some(frame) = node.ingress.take(protocol).unwrap() {
                    assert!(node.ingress.is_current_session(&frame.peer).unwrap());
                    let delay = if protocol == ProtocolKind::Posy {
                        let event: serde_json::Value =
                            serde_json::from_slice(&frame.payload).unwrap();
                        let events = event.as_object().unwrap();
                        let (kind, body) = events.iter().next().unwrap();
                        let is_timeout =
                            matches!(kind.as_str(), "TimeoutVote" | "TimeoutCertificate");
                        let held_height = body
                            .get("context")
                            .or_else(|| body.get("statement").and_then(|v| v.get("context")))
                            .and_then(|v| v.get("height"))
                            .and_then(|v| v.as_u64());
                        held_height.is_some_and(|height| {
                            height >= hold_posy_from_height.unwrap()
                                && !(allow_timeout_traffic && is_timeout)
                        })
                    } else {
                        let message: AuthenticatedEtdagMessage =
                            serde_json::from_slice(&frame.payload).unwrap();
                        match &message.message {
                            EtdagNetworkMessage::AvailabilityVote(v) => {
                                Some(&v.context_root) == target_root
                            }
                            EtdagNetworkMessage::AvailabilityCertificate(c) => {
                                Some(&c.context_root) == target_root
                            }
                            _ => false,
                        }
                    };
                    if delay {
                        let held = if protocol == ProtocolKind::Posy {
                            &mut *held_posy
                        } else {
                            &mut *held_etdag
                        };
                        if !held
                            .iter()
                            .any(|(i, existing)| *i == index && existing.payload == frame.payload)
                        {
                            assert!(
                                held.len() < 256,
                                "R3 packet fixture exceeded its bounded retention"
                            );
                            held.push((index, frame));
                        }
                    } else {
                        deliver.push(frame);
                    }
                }
                for frame in deliver {
                    node.ingress.publish(frame).unwrap();
                }
            }
            // Hold authenticated H50+ block progress while timeout traffic continues. PoSy must keep polling:
            // its candidate/sync/deferred-QC work projects already-certified
            // finality into execution while the H49 quorum remains withheld.
            service
                .poll()
                .unwrap_or_else(|e| panic!("R3 {index} {name}: {e}"));
            assert!(!matches!(service.health(), ServiceHealth::Unhealthy { .. }));
        }
    }
}

fn r3_target_record(node: &Node) -> Option<serde_json::Value> {
    synergy_etdag::persistence::ProtectedPipeline::read_durable_evidence(
        node.configuration
            .storage
            .data_directory
            .join("etdag/protected-pipeline"),
        51,
    )
    .expect("read checksum-checked canonical R3 target evidence")
}

#[test]
fn authenticated_socket_r3_h51_late_vac_split_recovers_real_wallet_and_restart() {
    use synergy_etdag::{
        AdmissionRequest, AuthenticatedEtdagMessage, EncryptedTransactionEnvelope, EnvelopeAad,
        EtdagNetworkMessage, WalletAdmission, WalletAdmissionContext,
    };
    let (tx, initial, mut account_secret) = funded_transaction_fixture_with_key();
    let mut fleet = SocketFleet::with_wallet_world_state(initial, true);
    let mut held_posy = Vec::new();
    let mut held_etdag = Vec::new();
    let prepare_deadline = Instant::now() + Duration::from_secs(900);
    let mut prepare_progress_at = Instant::now();
    let mut prepare_report_at = Instant::now();
    let mut previous_prepare_state = Vec::new();
    loop {
        r3_poll_delayed(
            &mut fleet,
            5,
            Some(49),
            false,
            false,
            &mut held_posy,
            &mut held_etdag,
            None,
        );
        let prepare_state: Vec<_> = fleet
            .nodes
            .iter()
            .flatten()
            .map(|node| {
                let finalized = node
                    .ingress
                    .latest_finality()
                    .unwrap()
                    .map(|record| record.height)
                    .unwrap_or(0);
                let executed = synergy_state::FinalizedStateStore::load(
                    node.configuration
                        .storage
                        .data_directory
                        .join("state/execution"),
                )
                .unwrap()
                .current()
                .map(|state| state.finalized_height)
                .unwrap_or(0);
                // An empty collecting target need not have a durable record yet.
                // The owner-published governed admission context proves it is open.
                let open = node
                    .wallet_admission
                    .as_ref()
                    .and_then(|handle| handle.context().ok())
                    .map(|value| {
                        serde_json::from_value::<WalletAdmissionContext>(value)
                            .expect("R3 governed admission context must decode")
                    })
                    .is_some_and(|context| {
                        context.context.target_height == 51
                            && context.context.source_finalized_height == 46
                    });
                (finalized, executed, open)
            })
            .collect();
        if prepare_state != previous_prepare_state {
            prepare_progress_at = Instant::now();
            previous_prepare_state = prepare_state.clone();
        }
        if prepare_state
            .iter()
            .all(|&(finalized, executed, open)| finalized == 46 && executed == 46 && open)
        {
            break;
        }
        if prepare_report_at.elapsed() >= Duration::from_secs(20) {
            eprintln!("R3 setup (finality, execution, H51 governed open): {prepare_state:?}; held PoSy={}, ETDAG={}; unchanged {:?}",
                held_posy.len(), held_etdag.len(), prepare_progress_at.elapsed());
            prepare_report_at = Instant::now();
        }
        assert!(
            prepare_progress_at.elapsed() < Duration::from_secs(60)
                && Instant::now() < prepare_deadline,
            "R3 did not establish open H51 at executed F46: (finality, execution, H51 governed open)={prepare_state:?}; held PoSy={}, ETDAG={}; unchanged {:?}",
            held_posy.len(), held_etdag.len(), prepare_progress_at.elapsed()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let exported: WalletAdmissionContext = serde_json::from_value(wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_ADMISSION_CONTEXT,
        serde_json::json!({}),
    ))
    .unwrap();
    assert_eq!(exported.context.target_height, 51);
    assert_eq!(exported.context.source_finalized_height, 46);
    let root = exported.context.root().unwrap();
    let aad = EnvelopeAad {
        profile_id: exported.parameters.profile_id.clone(),
        chain_id: 1266,
        network_id: exported.context.network_id.clone(),
        protocol_version: exported.context.protocol_version.clone(),
        epoch: exported.context.epoch,
        target_height: 51,
        target_context_root: root.clone(),
        assigned_cluster_id: exported.context.assigned_cluster_id,
        lane_id: "ordinary-user".into(),
        sender_id: tx.unsigned.sender.clone(),
        nonce_slot: 0,
    };
    let padded = synergy_etdag::crypto::pad_plaintext(&serde_json::to_vec(&tx).unwrap()).unwrap();
    let payload =
        synergy_etdag::crypto::encrypt_protected_payload(&aad, &exported.ingress_keys, 4, &padded)
            .unwrap();
    let mut envelope = EncryptedTransactionEnvelope {
        envelope_version: 2,
        envelope_id: digest("pending"),
        target_context_root: root.clone(),
        target_height: 51,
        aad,
        aead_nonce: payload.aead_nonce,
        key_commitment: payload.key_commitment,
        share_commitment_root: digest("pending"),
        share_capsule_root: digest("pending"),
        ciphertext: payload.ciphertext,
        content_blind_order_key: digest("R3-real-transfer"),
        share_capsules: payload.share_capsules,
    };
    envelope.refresh_capsule_roots().unwrap();
    envelope.envelope_id = synergy_etdag::envelope_commitment(&envelope).unwrap();
    let mut request = AdmissionRequest {
        request_version: synergy_etdag::ADMISSION_REQUEST_VERSION,
        chain_id: 1266,
        network_id: tx.unsigned.network.network_id.clone(),
        context_root: root.clone(),
        target_height: 51,
        sender_wallet: tx.unsigned.sender.clone(),
        sender_nonce: 0,
        gas_class_units: 21000,
        fee_class: 1,
        signature_algorithm: "ML-DSA-87".into(),
        signer_public_key: tx.signer_public_key.clone(),
        envelope,
        signature: vec![],
    };
    request.signature = fixture_sign(
        &account_secret,
        SignatureAlgorithm::MlDsa87,
        "transaction-presented-key",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &request.signing_bytes().unwrap(),
    );
    account_secret.fill(0);
    let admission = WalletAdmission {
        request,
        identity_authorization: tx.identity_authorization.clone().unwrap(),
    };
    let queued = wallet_rpc(
        &mut fleet,
        synergy_rpc::methods::PROTECTED_TRANSACTION_SUBMIT,
        serde_json::to_value(admission).unwrap(),
    );
    assert_eq!(queued["status"], "queued");
    let receipt = queued["receipt_id"].as_str().unwrap().to_string();
    let handle = fleet.nodes[0]
        .as_ref()
        .unwrap()
        .wallet_admission
        .clone()
        .unwrap();
    let availability_deadline = Instant::now() + Duration::from_secs(90);
    let vertex_id = loop {
        r3_poll_delayed(
            &mut fleet,
            5,
            Some(49),
            false,
            true,
            &mut held_posy,
            &mut held_etdag,
            Some(&root),
        );
        let receipt = handle.receipt(&receipt).unwrap();
        if receipt["status"] == "accepted" {
            let id = receipt["evidence"]["vertex_id"].as_str().unwrap();
            let right = fleet.nodes[3..].iter().flatten().all(|n| {
                r3_target_record(n).is_some_and(|s| !s["collecting"]["certificates"][id].is_null())
            });
            let left = fleet.nodes[..3].iter().flatten().all(|n| {
                r3_target_record(n).is_some_and(|s| s["collecting"]["certificates"][id].is_null())
            });
            if right && left {
                break id.to_string();
            }
        }
        assert!(
            Instant::now() < availability_deadline,
            "R3 fixture failed to induce actual 3/2 VAC arrival split"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    assert!(!held_etdag.is_empty());
    for (index, frame) in held_posy.drain(..) {
        let node = fleet.nodes[index].as_ref().unwrap();
        if node.ingress.is_current_session(&frame.peer).unwrap() {
            node.ingress.publish(frame).unwrap();
        }
    }
    let marker_deadline = Instant::now() + Duration::from_secs(90);
    let original_markers = loop {
        r3_poll_delayed(
            &mut fleet,
            5,
            None,
            false,
            true,
            &mut held_posy,
            &mut held_etdag,
            Some(&root),
        );
        let records = fleet
            .nodes
            .iter()
            .flatten()
            .map(r3_target_record)
            .collect::<Option<Vec<_>>>();
        if let Some(records) = records {
            if records.iter().all(|s| !s["local_marker"].is_null()) {
                let markers = records
                    .iter()
                    .map(|s| {
                        serde_json::from_value::<synergy_etdag::ordering::ProtectedCutMarker>(
                            s["local_marker"].clone(),
                        )
                        .unwrap()
                    })
                    .collect::<Vec<_>>();
                assert!(records.iter().all(|s| s["cut_recovery_generations"]
                    .as_array()
                    .is_none_or(|g| g.is_empty())));
                assert!(markers[..3].iter().all(|m| m.frontier.is_empty()));
                assert!(markers[3..]
                    .iter()
                    .all(|m| m.frontier == vec![EtdagDigest(vertex_id.clone())]));
                assert!(markers
                    .iter()
                    .all(|m| m.cutoff_context_root == markers[0].cutoff_context_root));
                for (node, marker) in fleet.nodes.iter().flatten().zip(&markers) {
                    let authority = authority::load(&node.configuration).unwrap().unwrap();
                    synergy_etdag::crypto::SignatureVerifier::verify(
                        authority.as_ref(),
                        &marker.validator_id,
                        &marker.key_id,
                        &marker.signing_bytes().unwrap(),
                        &marker.signature,
                    )
                    .unwrap();
                }
                break markers;
            }
        }
        assert!(
            Instant::now() < marker_deadline,
            "R3 did not durably preserve 3-empty/2-wallet H51 marker split"
        );
        std::thread::sleep(Duration::from_millis(2));
    };
    // Two arrival orders in one genuine mesh: node0 certificate first, node1
    // votes first. No frame contents or production records are rewritten.
    held_etdag.sort_by_key(|(index, frame)| {
        let message: AuthenticatedEtdagMessage = serde_json::from_slice(&frame.payload).unwrap();
        let certificate = matches!(
            message.message,
            EtdagNetworkMessage::AvailabilityCertificate(_)
        );
        (
            *index,
            if *index == 1 {
                certificate as u8
            } else {
                (!certificate) as u8
            },
        )
    });
    // Deliver the genuine retained evidence while only three validators poll
    // their owners. They must retain the original marker split without
    // authorizing H51 recovery or committing the target. Pre-cutoff PoSy
    // finality may continue to advance during this bounded observation.
    for (index, frame) in held_etdag.drain(..) {
        if index < 3 {
            let node = fleet.nodes[index].as_ref().unwrap();
            if node.ingress.is_current_session(&frame.peer).unwrap() {
                node.ingress.publish(frame).unwrap();
            }
        }
    }
    // Keep the R3 fail-closed phase open for one complete governed round
    // timeout. Three real signers may emit genuine timeout votes, but cannot
    // form the four-validator certificate needed to authorize recovery.
    let below_quorum_observation = Duration::from_millis(
        fleet.nodes[0]
            .as_ref()
            .unwrap()
            .configuration
            .consensus
            .round_timeout_ms,
    )
    .saturating_add(Duration::from_secs(1));
    assert!(below_quorum_observation > Duration::from_secs(1));
    let below_quorum_deadline = Instant::now() + below_quorum_observation;
    while Instant::now() < below_quorum_deadline {
        r3_poll_delayed(
            &mut fleet,
            3,
            Some(50),
            true,
            false,
            &mut held_posy,
            &mut held_etdag,
            Some(&root),
        );
        for (index, original) in original_markers.iter().enumerate().take(3) {
            let node = fleet.nodes[index].as_ref().unwrap();
            let stored = r3_target_record(node).unwrap();
            assert_eq!(
                stored["local_marker"],
                serde_json::to_value(original).unwrap()
            );
            assert!(stored["cut_recovery_generations"]
                .as_array()
                .is_none_or(|generations| generations.is_empty()));
            assert!(stored["committed"].is_null());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // Four participating validators preserve the governed 4/5 quorum. Require
    // their real owners to recover and commit the same H51 target before the
    // fifth validator resumes polling.
    let recovery_deadline = Instant::now() + Duration::from_secs(180);
    loop {
        r3_poll_delayed(
            &mut fleet,
            4,
            Some(51),
            true,
            false,
            &mut held_posy,
            &mut held_etdag,
            Some(&root),
        );
        let four_recovered =
            fleet.nodes[..4]
                .iter()
                .zip(&original_markers)
                .all(|(node, original)| {
                    node.as_ref().is_some_and(|node| {
                        r3_target_record(node).is_some_and(|stored| {
                            let history = stored["retained_markers"].as_array().unwrap();
                            !stored["cut_recovery_generations"]
                                .as_array()
                                .is_none_or(|generations| generations.is_empty())
                                && history.iter().any(|entry| {
                                    entry["marker"] == serde_json::to_value(original).unwrap()
                                })
                                && !stored["committed"].is_null()
                        })
                    })
                });
        if four_recovered {
            break;
        }
        let diagnostics = fleet.nodes[..4]
            .iter()
            .enumerate()
            .map(|(index, node)| {
                let node = node.as_ref().unwrap();
                let finalized = node
                    .ingress
                    .latest_finality()
                    .unwrap()
                    .map(|record| record.height);
                let stored = r3_target_record(node).unwrap_or(serde_json::Value::Null);
                serde_json::json!({
                    "validator_index": index,
                    "finalized_height": finalized,
                    "local_marker": stored["local_marker"]["cutoff_context_root"],
                    "generation_count": stored["cut_recovery_generations"].as_array().map_or(0, Vec::len),
                    "committed": !stored["committed"].is_null(),
                })
            })
            .collect::<Vec<_>>();
        assert!(
            Instant::now() < recovery_deadline,
            "four participating validators did not recover and commit the H51 cut; diagnostics={diagnostics:?}"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(fleet.nodes[4].as_ref().is_some_and(
        |node| r3_target_record(node).is_some_and(|stored| stored["committed"].is_null())
    ));
    // Restart an actual recovered owner before H51 is finalized. Native
    // reopen must verify and preserve the complete durable recovery record.
    let recovered_before = r3_target_record(fleet.nodes[0].as_ref().unwrap()).unwrap();
    assert!(
        fleet.nodes[0]
            .as_ref()
            .unwrap()
            .ingress
            .latest_finality()
            .unwrap()
            .unwrap()
            .height
            < 51
    );
    let mut recovered_owner = fleet.nodes[0].take().unwrap();
    let recovered_config = recovered_owner.configuration.clone();
    recovered_owner.stop();
    drop(recovered_owner);
    fleet.nodes[0] = Some(Node::open_with_wallet(
        recovered_config,
        Some(super::protected_admission::AdmissionHandle::default()),
        &fleet.listeners[0],
    ));
    let recovered_after = r3_target_record(fleet.nodes[0].as_ref().unwrap()).unwrap();
    for field in ["cut_recovery_generations", "retained_markers", "committed"] {
        assert_eq!(
            recovered_before[field], recovered_after[field],
            "recovered owner restart changed {field}"
        );
    }
    // Prove the quorum can finalize and execute the recovered wallet batch
    // while the fifth owner remains offline, rather than merely agreeing a cut.
    let mut fifth_held = Vec::new();
    for (index, frame) in held_posy.drain(..) {
        if index >= 4 {
            fifth_held.push((index, frame));
            continue;
        }
        let node = fleet.nodes[index].as_ref().unwrap();
        if node.ingress.is_current_session(&frame.peer).unwrap() {
            node.ingress.publish(frame).unwrap();
        }
    }
    held_posy = fifth_held;
    let four_finality_deadline = Instant::now() + Duration::from_secs(180);
    let mut next_owner_redial = Instant::now();
    loop {
        if Instant::now() >= next_owner_redial {
            redial_missing_socket_peers(&fleet, 0);
            next_owner_redial = Instant::now() + Duration::from_secs(5);
        }
        r3_poll_delayed(
            &mut fleet,
            4,
            None,
            false,
            false,
            &mut held_posy,
            &mut held_etdag,
            Some(&root),
        );
        let mut h54_states = Vec::new();
        let four_applied = fleet.nodes[..4].iter().all(|node| {
            let node = node.as_ref().unwrap();
            if !node
                .ingress
                .latest_finality()
                .unwrap()
                .is_some_and(|record| record.height >= 54)
            {
                return false;
            }
            let store = synergy_state::FinalizedStateStore::load(
                node.configuration
                    .storage
                    .data_directory
                    .join("state/execution"),
            )
            .unwrap();
            if !store
                .current()
                .is_some_and(|state| state.finalized_height >= 54)
            {
                return false;
            }
            let Some(state) = store.history_at(54).unwrap() else {
                return false;
            };
            h54_states.push(state);
            let world = store.world_state_at(54).unwrap().unwrap();
            assert_eq!(world.accounts[&tx.unsigned.sender].nonce, 1);
            assert_eq!(world.accounts[&tx.unsigned.receiver].balance_nwei, 7);
            let stored = r3_target_record(node).unwrap();
            let index = h54_states.len() - 1;
            assert!(stored["retained_markers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| {
                    entry["marker"] == serde_json::to_value(&original_markers[index]).unwrap()
                }));
            let query = super::rpc::CanonicalQueryStore::load(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            use synergy_rpc::provider::CanonicalReadProvider;
            query
                .transaction(&synergy_rpc::methods::TransactionQuery {
                    transaction_id: tx.id().unwrap().0,
                })
                .unwrap()
                .is_some_and(|receipt| receipt.status == "applied")
        });
        if four_applied {
            assert!(
                h54_states.windows(2).all(|pair| pair[0] == pair[1]),
                "four-validator recovery finalized conflicting H54 execution commitments"
            );
            break;
        }
        assert!(Instant::now() < four_finality_deadline,
            "four-validator recovery did not finalize and apply the wallet transfer through H54 before fifth rejoin");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(fleet.nodes[4]
        .as_ref()
        .unwrap()
        .ingress
        .latest_finality()
        .unwrap()
        .is_some_and(|record| record.height < 51));
    // The lagging fifth follows verified historical Sync after the four-owner
    // quorum has finalized; it need not author another historical generation.
    for (index, frame) in held_etdag.drain(..).chain(held_posy.drain(..)) {
        let node = fleet.nodes[index].as_ref().unwrap();
        if node.ingress.is_current_session(&frame.peer).unwrap() {
            node.ingress.publish(frame).unwrap();
        }
    }
    fleet.advance_with_peer_redial(54, Some(4));
    let load_state = |index: usize| {
        synergy_state::FinalizedStateStore::load(
            fleet.nodes[index]
                .as_ref()
                .unwrap()
                .configuration
                .storage
                .data_directory
                .join("state/execution"),
        )
        .unwrap()
    };
    let anchor = load_state(0).history_at(54).unwrap().unwrap();
    assert_eq!(load_state(4).history_at(54).unwrap().unwrap(), anchor);
    let world = load_state(4).world_state_at(54).unwrap().unwrap();
    assert_eq!(world.accounts[&tx.unsigned.sender].nonce, 1);
    assert_eq!(world.accounts[&tx.unsigned.receiver].balance_nwei, 7);
    let fifth_before = r3_target_record(fleet.nodes[4].as_ref().unwrap()).unwrap();
    assert!(fifth_before["retained_markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["marker"] == serde_json::to_value(&original_markers[4]).unwrap()),
        "fifth original marker missing from retained history: local_marker={} retained_markers={} cut_recovery_generations={}",
        fifth_before["local_marker"], fifth_before["retained_markers"], fifth_before["cut_recovery_generations"]);
    {
        use synergy_rpc::provider::CanonicalReadProvider;
        let query = super::rpc::CanonicalQueryStore::load(
            fleet.nodes[4]
                .as_ref()
                .unwrap()
                .configuration
                .storage
                .data_directory
                .clone(),
        )
        .unwrap();
        assert_eq!(
            query
                .transaction(&synergy_rpc::methods::TransactionQuery {
                    transaction_id: tx.id().unwrap().0
                })
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
    }
    let mut removed = fleet.nodes[4].take().unwrap();
    let configuration = removed.configuration.clone();
    removed.stop();
    drop(removed);
    fleet.nodes[4] = Some(Node::open_with_wallet(
        configuration,
        Some(super::protected_admission::AdmissionHandle::default()),
        &fleet.listeners[4],
    ));
    assert_eq!(
        r3_target_record(fleet.nodes[4].as_ref().unwrap()).unwrap()["retained_markers"],
        fifth_before["retained_markers"]
    );
    fleet.dial_mesh();
    fleet.advance_with_peer_redial(54, Some(4));
    fleet.advance_with_peer_redial(58, Some(4));
    for (node, original) in fleet.nodes.iter().flatten().zip(&original_markers) {
        let stored = r3_target_record(node).unwrap();
        assert!(stored["retained_markers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["marker"] == serde_json::to_value(original).unwrap()));
        let world = synergy_state::FinalizedStateStore::load(
            node.configuration
                .storage
                .data_directory
                .join("state/execution"),
        )
        .unwrap()
        .current_world_state()
        .unwrap()
        .unwrap();
        assert_eq!(world.accounts[&tx.unsigned.sender].nonce, 1);
        assert_eq!(world.accounts[&tx.unsigned.receiver].balance_nwei, 7);
        let query = super::rpc::CanonicalQueryStore::load(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        use synergy_rpc::provider::CanonicalReadProvider;
        assert_eq!(
            query
                .transaction(&synergy_rpc::methods::TransactionQuery {
                    transaction_id: tx.id().unwrap().0
                })
                .unwrap()
                .unwrap()
                .status,
            "applied"
        );
    }
}

fn fixture_world_memory_budget(secure: bool, processing_profile: bool) -> usize {
    if secure && processing_profile {
        512 * 1024 * 1024
    } else if secure {
        128 * 1024 * 1024
    } else {
        default_world_memory_budget_bytes()
    }
}

#[test]
fn secure_processing_fixture_budget_supports_native_pending_intake() {
    let capacity = fixture_world_memory_budget(true, true);
    super::processing_store::validate_processing_world_capacity(capacity).unwrap();
    // Pending-store retention charges exact encoded admission bytes at 128x
    // plus 64 MiB completion capacity, in addition to native frame headroom.
    // Include doubled JSON escaping/framing for one maximum-size request.
    let budget = synergy_state::world_resources::WorldResourceBudget::new(capacity);
    let maximum_pending =
        (2 * 1024 * 1024 + 16 * 1024 + 1024) * 128 + 128 * 1024 + 64 * 1024 * 1024;
    let retained = budget
        .reserve_with_headroom(
            maximum_pending,
            super::processing_store::PROCESSING_INTAKE_HEADROOM_BYTES,
        )
        .unwrap();
    drop(retained);
    assert!(
        synergy_state::world_resources::WorldResourceBudget::new(128 * 1024 * 1024)
            .reserve_with_headroom(
                maximum_pending,
                super::processing_store::PROCESSING_INTAKE_HEADROOM_BYTES
            )
            .is_err()
    );
    assert_eq!(fixture_world_memory_budget(true, false), 128 * 1024 * 1024);
    assert_eq!(
        fixture_world_memory_budget(false, true),
        default_world_memory_budget_bytes()
    );
}

// Shared signed fixture input for poll-boundary regressions; no owners started.
pub(super) fn sync_poll_test_configuration() -> (PathBuf, NodeConfiguration) {
    let fixture = prepare_socket_fixture_profile(synergy_state::WorldState::default(), None, true);
    (fixture.root, fixture.configurations[0].clone())
}

// Same signed fixture, with mandatory authenticated native provisioning.
pub(super) fn sync_poll_native_test_configuration() -> (PathBuf, NodeConfiguration) {
    let provider = trusted_apqe_provider();
    let fixture = prepare_socket_fixture_profile_provider(
        synergy_state::WorldState::default(),
        None,
        true,
        None,
        Some(&provider),
    );
    (fixture.root, fixture.configurations[0].clone())
}

struct PreparedSocketFixture {
    registry_signer: Option<synergy_address_engine::apqe::SecretBytes>,
    root: PathBuf,
    configurations: Vec<NodeConfiguration>,
    ids: Vec<String>,
    listeners: Vec<FixtureListeners>,
}
struct IsolatedFixtureExport {
    root: PathBuf,
    network_id: String,
    attestation_public_key: String,
    provider_plan_sha256: String,
    target_height_offset: u64,
    epoch_end_height: u64,
}
fn prepare_socket_fixture(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
) -> PreparedSocketFixture {
    prepare_socket_fixture_profile(initial_world_state, export, false)
}
fn prepare_socket_fixture_profile(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
    processing_profile: bool,
) -> PreparedSocketFixture {
    prepare_socket_fixture_profile_with_epoch(initial_world_state, export, processing_profile, None)
}

// Only opt-in long disposable tests supply a larger authenticated epoch. The
// ordinary fixtures and exported installation architecture retain their defaults.
fn prepare_socket_fixture_profile_with_epoch(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
    processing_profile: bool,
    epoch_end_override: Option<u64>,
) -> PreparedSocketFixture {
    prepare_socket_fixture_profile_provider(
        initial_world_state,
        export,
        processing_profile,
        epoch_end_override,
        None,
    )
}
fn prepare_socket_fixture_profile_provider(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
    processing_profile: bool,
    epoch_end_override: Option<u64>,
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
) -> PreparedSocketFixture {
    prepare_socket_fixture_profile_mode(
        initial_world_state,
        export,
        processing_profile,
        epoch_end_override,
        provider,
        false,
    )
}
fn prepare_socket_fixture_profile_mode(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
    processing_profile: bool,
    epoch_end_override: Option<u64>,
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
    secure: bool,
) -> PreparedSocketFixture {
    prepare_socket_fixture_profile_mode_endpoints(
        initial_world_state,
        export,
        processing_profile,
        epoch_end_override,
        provider,
        secure,
        None,
        1266,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_socket_fixture_profile_mode_endpoints(
    initial_world_state: synergy_state::WorldState,
    export: Option<&IsolatedFixtureExport>,
    processing_profile: bool,
    epoch_end_override: Option<u64>,
    provider: Option<&synergy_config::ApqeProviderConfiguration>,
    secure: bool,
    registry_endpoints: Option<&[std::net::SocketAddr; 5]>,
    chain_id: u64,
) -> PreparedSocketFixture {
    assert!(export.is_none() || epoch_end_override.is_none());
    assert!(epoch_end_override
        .is_none_or(|height| height == 20 || (10_000..=10_000_000).contains(&height)));
    let default_root = std::env::temp_dir().join(format!(
        "posy-socket-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let root = export.map(|e| e.root.clone()).unwrap_or(default_root);
    assert!(!root.exists(), "fresh fixture root required");
    assert!(root.is_absolute());
    if export.is_some() {
        assert!(!root
            .components()
            .any(|c| c == std::path::Component::ParentDir));
        for ancestor in root.ancestors().skip(1) {
            assert!(!ancestor.is_symlink(), "fixture root ancestor is a symlink");
        }
    }
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    // Preparation may fail before its caller can install the ordinary fixture
    // cleanup owner. Remove only this freshly created synthetic fixture on unwind.
    struct PreparationCleanup(Option<PathBuf>);
    impl Drop for PreparationCleanup {
        fn drop(&mut self) {
            if let Some(root) = &self.0 {
                let _ = fs::remove_dir_all(root);
            }
        }
    }
    let mut preparation_cleanup = PreparationCleanup(Some(root.clone()));

    // macOS temporary-directory aliases may include /var -> /private/var.
    // Materialize once, then derive every fixture custody/storage/journal path
    // from its canonical directory. Production path checks stay strict.
    let root = fs::canonicalize(&root).unwrap();
    let secure_network = format!("posy-apqe-canary-process-{}", std::process::id());
    let network_id = if secure {
        secure_network.as_str()
    } else {
        export
            .map(|e| e.network_id.as_str())
            .unwrap_or("socket-qualification")
    };
    let secure_engine = if secure {
        let p = provider.expect("authenticated provider required");
        Some(
            synergy_aegis::load_authenticated_native_engine(
                &p.report_path,
                &p.authenticated_report_sha256,
            )
            .unwrap(),
        )
    } else {
        None
    };
    let mut staged = Vec::new();
    eprintln!("socket qualification: starting five-validator setup");
    let mut validators = Vec::new();
    let mut transports = Vec::new();
    let mut ids = Vec::new();
    let mut kem_records = Vec::new();
    let mut addresses = Vec::new();
    let mut listeners = Vec::new();
    for index in 0..5 {
        let dir = root.join(format!("node-{index}"));
        fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let (identity_public, _identity_secret) = bounded_keypair(
            format!("node-{index} FN-DSA-1024 identity key"),
            fndsa1024::keypair,
        );
        let (public, key) = bounded_keypair(
            format!("node-{index} ML-DSA-65 consensus key"),
            mldsa65::keypair,
        );
        let address = NodeAddress::parse(
            synergy_address::generate_class_based_address(identity_public.as_bytes(), 1).unwrap(),
        )
        .unwrap();
        let staged_keys = secure_engine.as_ref().map(|engine| {
            synergy_address_engine::validator_provisioning::prepare(
                &engine.lock().unwrap(),
                synergy_address_engine::types::AddressType::NodeClass1,
            )
            .unwrap()
        });
        let staged_public = staged_keys.as_ref().map(|keys| keys.public_identity());
        let address = staged_public
            .as_ref()
            .map(|p| NodeAddress::parse(p.address.clone()).unwrap())
            .unwrap_or(address);
        let consensus_public = staged_public
            .as_ref()
            .map(|p| hex_decode(&p.consensus_key.public_key))
            .unwrap_or_else(|| public.as_bytes().to_vec());
        ids.push(address.to_string());
        validators.push(AuthorityValidator {
            record: ValidatorRecord {
                validator_id: address.to_string(),
                consensus_key_id: format!("consensus-{index}"),
                frozen_voting_weight: 1,
                status: ValidatorStatus::Active,
            },
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key: consensus_public,
        });
        if !secure {
            secret(&dir.join("consensus.key"), key.as_bytes());
        }
        // Distinct key purposes, including independent P2P custody.
        let (transport_public, transport_key) = bounded_keypair(
            format!("node-{index} ML-DSA-65 transport key"),
            mldsa65::keypair,
        );
        let transport_public_bytes = staged_public
            .as_ref()
            .map(|p| hex_decode(&p.node_identity_key.public_key))
            .unwrap_or_else(|| transport_public.as_bytes().to_vec());
        let identity_fingerprint = operational_fingerprint(&transport_public_bytes);
        if !secure {
            secret(&dir.join("transport.key"), transport_key.as_bytes());
        }
        transports.push(GovernedNodeKeyBinding {
            node_address: address.clone(),
            key_id: KeyId::new(format!("transport-{index}")).unwrap(),
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key: transport_public_bytes,
            capabilities: vec![],
        });
        write_json(
            &dir.join("identity.json"),
            &PublicNodeIdentity::new(address, identity_fingerprint),
        );
        let (kem_public, kem_secret) = bounded_keypair(
            format!("node-{index} ML-KEM-1024 ingress key"),
            mlkem1024::keypair,
        );
        let ingress_public = staged_keys
            .as_ref()
            .map(|keys| hex_decode(&keys.ingress_public_key().public_key))
            .unwrap_or_else(|| pqrust_traits::kem::PublicKey::as_bytes(&kem_public).to_vec());
        if !secure {
            secret(&dir.join("ingress.key"), kem_secret.as_bytes());
        }
        if let Some(keys) = staged_keys {
            staged.push(keys);
        }
        kem_records.push(IngressKemKeyRecord {
            key_id: format!("ingress-{index}"),
            validator_id: ids[index].clone(),
            public_key: IngressKemPublicKey {
                algorithm: "ML-KEM-1024".into(),
                public_key: ingress_public,
            },
            activation_height: 3,
            retirement_height: None,
        });
        if export.is_some() {
            addresses.push(format!("10.69.10.{}:5622", index + 2).parse().unwrap());
        } else {
            let reserved = FixtureListeners::bind();
            addresses.push(reserved.network[0].local_addr().unwrap());
            listeners.push(reserved);
        }
    }
    let registry =
        FrozenValidatorRegistry::new(1, validators.iter().map(|v| v.record.clone()).collect())
            .unwrap();
    let epoch_end_height =
        epoch_end_override.unwrap_or_else(|| export.map_or(10_000, |value| value.epoch_end_height));
    let preliminary = SimplifiedEpochContext::from_frozen_registry(
        chain_id,
        network_id.into(),
        1,
        1,
        epoch_end_height,
        "a".repeat(64),
        "b".repeat(64),
        &registry,
    )
    .unwrap();
    let target_height_offset = export.map_or(5, |e| e.target_height_offset);
    let mut parameters = synergy_etdag::EtdagParameters::default();
    if target_height_offset != 5 {
        parameters.profile_id = synergy_etdag::ETDAG_EXPERIMENTAL_PROFILE_ID.into();
        parameters.target_height_offset = target_height_offset;
    }
    parameters
        .validate()
        .expect("bounded isolated governed lookahead");
    let protected = ProtectedEpochPolicy {
        version: if processing_profile { 2 } else { 1 },
        cutoff_relationship: if processing_profile {
            ProtectedCutoffRelationship::ProcessingGroupsV1
        } else {
            ProtectedCutoffRelationship::VcEventContextV1
        },
        epoch_start_timestamp_ms: 1_700_000_000_000,
        target_block_time_ms: if secure { 2_000 } else { 1_000 },
        parameters,
        initial_world_state,
        cryptographic_profile_root: "a".repeat(64),
        ingress_kem_registry: IngressKemKeyRegistry {
            context_root: digest("key-registry-context"),
            records: kem_records,
        },
        cluster_schedule_version: "socket-qualification-v1".into(),
        assigned_height_schedule_root: "e".repeat(64),
        cluster_map_root: "f".repeat(64),
        assigned_cluster_id: 0,
        assigned_cluster_membership_root: preliminary.active_validator_set_root,
    };
    let mut payload = AuthorityPayload {
        version: 1,
        chain_id,
        network_id: network_id.into(),
        epoch: 1,
        epoch_start_height: 1,
        epoch_end_height,
        finalized_epoch_seed_root: "a".repeat(64),
        consensus_parameter_root: protected.commitment().unwrap(),
        validators,
        anchor_parent: SimplifiedFinalityParent::Genesis {
            genesis_hash: "c".repeat(64),
            block_id: "socket-qualification-genesis".into(),
            reference_id: "d".repeat(64),
        },
        protected: Some(protected),
    };
    payload.validate().unwrap();
    let (trust_public, trust_secret) =
        bounded_keypair("ML-DSA-65 authority root".into(), mldsa65::keypair);
    fs::write(root.join("trust.pub"), trust_public.as_bytes()).unwrap();
    let key_id = KeyId::new("socket-qualification-root").unwrap();
    let signing_policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: 1024 * 1024,
        maximum_signature_bytes: 16 * 1024,
    };
    let signer = if let Some(provider) = provider {
        let engine = synergy_aegis::load_authenticated_native_engine(
            &provider.report_path,
            &provider.authenticated_report_sha256,
        )
        .unwrap();
        PqvmSigner::with_apqe(
            signing_policy,
            key_id.clone(),
            trust_public.as_bytes(),
            trust_secret.as_bytes().to_vec(),
            engine,
        )
    } else {
        PqvmSigner::from_secret_key_bytes(
            signing_policy,
            key_id.clone(),
            trust_secret.as_bytes().to_vec(),
        )
    }
    .unwrap();
    let fixture_genesis_hash = if export.is_some() || secure {
        let policy = payload.protected.as_ref().unwrap();
        let unsigned = synergy_genesis::builder::UnsignedGenesis {
            format_version: if secure { 2 } else { 1 },
            network: synergy_genesis::network::GenesisNetwork {
                chain_id: payload.chain_id,
                network_id: payload.network_id.clone(),
                protocol_version: preliminary.protocol_version.clone(),
                activation_unix: policy.epoch_start_timestamp_ms / 1000,
            },
            validators: payload
                .validators
                .iter()
                .map(|v| synergy_genesis::validator_set::GenesisValidator {
                    record: v.record.clone(),
                    algorithm: v.algorithm,
                    public_key: v.public_key.clone(),
                })
                .collect(),
            etdag: synergy_genesis::etdag::GenesisEtdag {
                parameters: policy.parameters.clone(),
                cryptographic_profile_root: policy.cryptographic_profile_root.clone(),
                ingress_kem_registry_root: policy.ingress_kem_registry.root().unwrap(),
            },
            initial_state_root: synergy_genesis::state_root(&policy.initial_world_state).unwrap(),
            authority_trust_key_id: key_id.as_str().into(),
        };
        let signed = synergy_genesis::signing::sign(unsigned, &signer, key_id.clone()).unwrap();
        if let Some(engine) = &secure_engine {
            let verifier = synergy_aegis::PqvmVerifier::with_apqe(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 16 * 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                engine.clone(),
            )
            .unwrap();
            synergy_genesis::signing::verify(&signed, &verifier, trust_public.as_bytes()).unwrap();
        } else {
            synergy_genesis::verify::verify_signed_genesis(&signed, trust_public.as_bytes())
                .unwrap();
        }
        let hash = signed.genesis_hash.clone();
        payload.anchor_parent = SimplifiedFinalityParent::Genesis {
            genesis_hash: hash.clone(),
            block_id: hash.clone(),
            reference_id: synergy_posy::canonical_hash(
                "SYNERGY_FRESH_GENESIS_REFERENCE_V1",
                &(
                    payload.chain_id,
                    &payload.network_id,
                    payload.epoch,
                    &hash,
                    &signed.unsigned.initial_state_root,
                ),
            )
            .unwrap(),
        };
        payload.finalized_epoch_seed_root = synergy_posy::canonical_hash(
            "SYNERGY_FRESH_GENESIS_EPOCH_SEED_V1",
            &(payload.chain_id, &payload.network_id, payload.epoch, &hash),
        )
        .unwrap();
        write_json(&root.join("genesis.sgen"), &signed);
        payload.validate().unwrap();
        hash
    } else {
        "c".repeat(64)
    };
    let signature = signer
        .sign(
            &key_id,
            &SigningContext {
                domain: AUTHORITY_SIGNING_DOMAIN.into(),
                chain_id,
                epoch: Some(1),
                height: None,
            },
            &payload.signing_bytes().unwrap(),
        )
        .unwrap()
        .bytes;
    let signed_binding = SignedAuthorityBinding {
        payload,
        signer_key_id: key_id.as_str().to_owned(),
        signature,
    };
    if export.is_some() || secure {
        let signed: synergy_genesis::signing::SignedGenesis =
            serde_json::from_slice(&fs::read(root.join("genesis.sgen")).unwrap()).unwrap();
        if let Some(engine) = &secure_engine {
            let verifier = synergy_aegis::PqvmVerifier::with_apqe(
                AegisPolicy {
                    allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                    maximum_message_bytes: 16 * 1024 * 1024,
                    maximum_signature_bytes: 16 * 1024,
                },
                engine.clone(),
            )
            .unwrap();
            synergy_genesis::verify_binding_with_verifier(
                &signed,
                trust_public.as_bytes(),
                &signed_binding,
                &verifier,
            )
            .unwrap();
        } else {
            synergy_genesis::verify_binding(&signed, trust_public.as_bytes(), &signed_binding)
                .unwrap();
        }
    }
    write_json(&root.join("authority.json"), &signed_binding);
    write_json(
        &root.join("bindings.json"),
        &GovernedKeyBindings::new(transports).unwrap(),
    );
    let manifest = synergy_manifest::NetworkManifest {
        chain_id,
        network_id: network_id.into(),
        genesis_hash: fixture_genesis_hash,
        protocol_version: preliminary.protocol_version,
        manifest_hash: "a".repeat(64),
    };
    write_json(&root.join("manifest.json"), &manifest);
    let mut configurations = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let dir = root.join(format!("node-{index}"));
        let configuration = NodeConfiguration {
            aegis_provider: provider.cloned(),
            apqe_transport: None,
            schema_version: CONFIG_SCHEMA_VERSION,
            node_name: format!("socket-{index}"),
            role: NodeRole::Validator,
            chain_id,
            network_id: network_id.into(),
            manifest_path: root.join("manifest.json"),
            genesis_path: secure.then(|| root.join("genesis.sgen")),
            public_identity_path: dir.join("identity.json"),
            aegis_key_bindings_path: Some(root.join("bindings.json")),
            aegis_signing_key_path: Some(dir.join("transport.key")),
            admin_socket_path: dir.join("admin.sock"),
            network: NetworkConfiguration {
                listen_addresses: vec![*address],
                advertised_addresses: vec![*address],
                dial_timeout_ms: 10_000,
                idle_connection_timeout_ms: 60_000,
            },
            p2p: P2pConfiguration {
                max_authenticated_peers: 8,
                max_pending_handshakes: 8,
                ..P2pConfiguration::default()
            },
            consensus: ConsensusConfiguration {
                mode: ConsensusMode::ValidateAndVote,
                authority_binding: Some(root.join("authority.json")),
                authority_trust_key_path: Some(root.join("trust.pub")),
                signing_key_path: Some(dir.join("consensus.key")),
                round_timeout_ms: 30_000,
                ..ConsensusConfiguration::default()
            },
            etdag: EtdagConfiguration {
                enabled: true,
                protected_lookahead: target_height_offset,
                ingress_kem_secret_key_path: Some(dir.join("ingress.key")),
                ..EtdagConfiguration::default()
            },
            storage: StorageConfiguration {
                data_directory: dir.join("data"),
                wal_sync: WalSyncPolicy::EveryCommit,
                max_open_files: 128,
                world_memory_budget_bytes: fixture_world_memory_budget(secure, processing_profile),
                minimum_free_bytes: 1024 * 1024,
                prune_finalized_history_after_blocks: None,
            },
            rpc: if export.is_some() || secure {
                RpcConfiguration {
                    enabled: true,
                    listen_address: Some(if secure {
                        listeners[index].rpc.local_addr().unwrap()
                    } else {
                        format!("127.0.0.1:{}", 8545 + index).parse().unwrap()
                    }),
                    ..RpcConfiguration::default()
                }
            } else {
                RpcConfiguration::default()
            },
            telemetry: TelemetryConfiguration::default(),
            update: UpdateConfiguration::default(),
            vpn: if let Some(export) = export {
                VpnConfiguration {
                    transport_context: Some(synergy_config::TransportContext {
                        network: "synergy-testnet-v3-validator-transport-v1".into(),
                        registry_id: "synergy-testnet-v3-block-zero-transport-v1".into(),
                        release_id: "testnet-v3".into(),
                        protocol_version: "posy/3.0".into(),
                    }),
                    mode: VpnMode::Required,
                    interface_name: Some("wt0".into()),
                    signed_registry_path: Some(root.join("transport-signed.json")),
                    attestation_public_key: Some(export.attestation_public_key.clone()),
                    provider_plan_sha256: Some(export.provider_plan_sha256.clone()),
                }
            } else {
                VpnConfiguration::default()
            },
        };
        if export.is_some() {
            configuration.validate().unwrap();
            write_json(
                &root.join(format!("node-{index}/config.json")),
                &configuration,
            );
        }
        configurations.push(configuration);
    }

    if let Some(export) = export {
        let transports = ids.iter().zip(&addresses).map(|(identity,address)|
            serde_json::json!({"validator_address":identity,"dial_address":address.to_string()})).collect::<Vec<_>>();
        let unsigned = serde_json::json!({"version":2,
            "network":"synergy-testnet-v3-validator-transport-v1",
            "registry_id":"synergy-testnet-v3-block-zero-transport-v1",
            "chain_id":chain_id,"network_id":"testnet","release_id":"testnet-v3",
            "protocol_version":"posy/3.0","provider_plan_sha256":export.provider_plan_sha256,
            "configuration_version":1,"transports":transports});
        write_json(&root.join("transport-unsigned.json"), &unsigned);
        write_json(
            &root.join("export-status.json"),
            &serde_json::json!({
            "fixture_kind":"posy-isolated-synthetic-v1","network_id":network_id,
            "synthetic_keys_only":true,"pending_transport_attestation":true,"pending_native_attestation_verification":true,
            "provider_simulated":true,"transport_domain":"legacyfixedtestnet-v3-labels",
            "GateE_qualified":false,"GateD_qualified":false,"diagnostic_only":true,"full_signed_genesis":true,"services_started":false,
            "isolated_network":"10.69.10.0/24"}),
        );
    }
    let registry_signer = if secure {
        Some(finalize_secure_fixture(
            &root,
            &mut configurations,
            staged,
            secure_engine.as_ref().unwrap(),
            registry_endpoints,
        ))
    } else {
        None
    };
    preparation_cleanup.0 = None;
    PreparedSocketFixture {
        registry_signer,
        root,
        configurations,
        ids,
        listeners,
    }
}

#[test]
#[ignore = "explicit synthetic fixture export; creates fresh keys, starts no services"]
fn export_isolated_posy_process_fixture() {
    let root = PathBuf::from(
        std::env::var("SYNERGY_POSY_ISOLATED_FIXTURE_ROOT").expect("new private root required"),
    );
    let network_id = format!(
        "posy-isolated-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let export = IsolatedFixtureExport {
        root,
        network_id,
        attestation_public_key: std::env::var("SYNERGY_POSY_ISOLATED_ATTESTATION_PUBLIC_KEY")
            .expect("fresh public attestation pin required"),
        provider_plan_sha256: std::env::var("SYNERGY_POSY_ISOLATED_PROVIDER_SHA256")
            .expect("synthetic provider digest required"),
        target_height_offset: std::env::var("SYNERGY_POSY_ISOLATED_LOOKAHEAD")
            .map(|s| s.parse().expect("integer isolated lookahead required"))
            .unwrap_or(5),
        epoch_end_height: std::env::var("SYNERGY_POSY_ISOLATED_EPOCH_END_HEIGHT")
            .map(|s| s.parse().expect("integer isolated epoch end required"))
            .unwrap_or(10_000),
    };
    assert!(
        (10_000..=10_000_000).contains(&export.epoch_end_height),
        "bounded signed isolated epoch horizon required"
    );
    assert!(
        (5..=16).contains(&export.target_height_offset),
        "bounded approved isolated lookahead required"
    );
    synergy_transport_registry::SnapshotTrust::from_encoded(
        &export.attestation_public_key,
        export.provider_plan_sha256.clone(),
        synergy_transport_registry::SnapshotContext {
            network: "synergy-testnet-v3-validator-transport-v1".into(),
            registry_id: "synergy-testnet-v3-block-zero-transport-v1".into(),
            chain_id: 1266,
            network_id: "testnet".into(),
            release_id: "testnet-v3".into(),
            protocol_version: "posy/3.0".into(),
        },
    )
    .unwrap();
    let canonical_target = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target");
    let leaf = export
        .root
        .file_name()
        .and_then(|s| s.to_str())
        .expect("fixture leaf required");
    assert!(leaf.starts_with("posy-isolated-") && leaf.len() <= 128);
    assert!(
        export.root.parent() == Some(Path::new("/tmp"))
            || export.root.parent() == Some(Path::new("/var/tmp"))
            || export.root.parent() == Some(canonical_target.as_path()),
        "fixture root must be dedicated /tmp or /var/tmp posy-isolated-* or canonical target/posy-isolated-*"
    );
    let pool_size: usize = std::env::var("SYNERGY_POSY_ISOLATED_WALLET_POOL_SIZE")
        .map(|value| value.parse().expect("integer wallet pool size required"))
        .unwrap_or(1);
    assert!(
        (1..=64).contains(&pool_size),
        "synthetic wallet pool must be bounded 1..=64"
    );
    let mut initial_world = synergy_state::WorldState::default();
    let mut wallets = Vec::with_capacity(pool_size);
    for _ in 0..pool_size {
        let (wallet, world, secret) =
            funded_transaction_fixture_for_network(&export.network_id, 1_000_000_000);
        merge_funded_fixture_world(&mut initial_world, world).unwrap();
        wallets.push((wallet, secret));
    }
    // Explicit fresh-fixture activation only; historical exporters keep their
    // governed legacy profile unless the caller selects the approved async one.
    let processing = match std::env::var("SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(profile) if profile == synergy_etdag::PROCESSING_PROFILE_ID => true,
        _ => panic!("unknown isolated processing profile"),
    };
    let commitments: Vec<_> = wallets
        .iter()
        .map(|(wallet, _)| {
            synergy_identity::authorization::canonical_binding_commitment(
                &initial_world.protocol,
                &wallet.unsigned.sender,
            )
            .expect("exported wallet must have an actual Genesis authorization commitment")
        })
        .collect();
    let prepared = prepare_socket_fixture_profile(initial_world, Some(&export), processing);
    let chain_id = prepared.configurations[0].chain_id;
    assert!(prepared
        .configurations
        .iter()
        .all(|c| c.chain_id == chain_id));
    use std::os::unix::fs::DirBuilderExt;
    let mut registry = Vec::with_capacity(pool_size);
    for (index, ((wallet, mut wallet_secret), commitment)) in
        wallets.into_iter().zip(commitments).enumerate()
    {
        // Retain the historical first wallet's sole custody path; no key copies.
        let wallet_dir = prepared.root.join(if index == 0 {
            "wallet".into()
        } else {
            format!("wallet-{index}")
        });
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&wallet_dir)
            .unwrap();
        let secret_path = wallet_dir.join("transaction-signing.secret.bin");
        let public_path = wallet_dir.join("wallet.public.json");
        secret(&secret_path, &wallet_secret);
        wallet_secret.fill(0);
        write_json(
            &public_path,
            &serde_json::json!({
            "sender":wallet.unsigned.sender,
            "genesis_binding_commitment":commitment,
            "identity_authorization":wallet.identity_authorization.as_ref().unwrap()}),
        );
        write_json(
            &wallet_dir.join("metadata.json"),
            &serde_json::json!({
            "synthetic":true,"network_id":export.network_id,"sender":wallet.unsigned.sender,
            "receiver":wallet.unsigned.receiver,"initial_balance_nwei":1_000_000_000u64,
            "consensus_epoch_timestamp_unix":1_700_000_000u64,"pool_size":pool_size,
            "capacity_baseline_qualified":false,"admission_authored":false}),
        );
        registry.push(serde_json::json!({"wallet_id":format!("wallet-{index}"),
            "wallet_public_path":public_path,"transaction_secret_path":secret_path}));
    }
    write_json(
        &prepared.root.join("wallet-pool.json"),
        &serde_json::json!({
        "session_version":1,"fixture_root":prepared.root,"synthetic":true,"network_id":export.network_id,"chain_id":chain_id,
        "authority_binding_path":prepared.root.join("authority.json"),
        "authority_trust_key_path":prepared.root.join("trust.pub"),
        "authority_key_id":"socket-qualification-root","wallets":registry}),
    );

    assert_eq!(prepared.configurations.len(), 5);
    for config in &prepared.configurations {
        assert_eq!(config.vpn.mode, VpnMode::Required);
        assert!(!config.storage.data_directory.exists());
        assert!(!config.admin_socket_path.exists());
        assert!(authority::load(config).unwrap().is_some());
    }
    assert!(!prepared.root.join("transport-signed.json").exists());
    eprintln!("isolated fixture exported: services_started=false pending_transport_attestation=true GateE_qualified=false");
}

/// Live owners supply every candidate and proof. No fixture-created World,
/// validation certificate or QC is injected into the running services.
#[test]
fn processing_async_live_native_owners_finalize_empty_blocks_over_authenticated_sockets() {
    let prepared = prepare_socket_fixture_profile(synergy_state::WorldState::default(), None, true);
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(configuration, listeners)| Node::open(configuration, listeners))
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    let started = Instant::now();
    let mut last_progress = started;
    let mut previous = 0;
    loop {
        for node in &mut nodes {
            node.poll();
        }
        let records = nodes
            .iter()
            .map(|node| node.ingress.latest_finality().unwrap())
            .collect::<Vec<_>>();
        if records
            .iter()
            .all(|record| record.as_ref().is_some_and(|record| record.height >= 2))
        {
            break;
        }
        let minimum = records
            .iter()
            .map(|r| r.as_ref().map_or(0, |r| r.height))
            .min()
            .unwrap();
        if minimum > previous {
            previous = minimum;
            last_progress = Instant::now();
            eprintln!(
                "async live minimum finality H{minimum} after {:?}",
                started.elapsed()
            );
        }
        // Existing empty-chain socket criteria: 60s without progress, 180s
        // overall. This is not the separate 30s encrypted admission contract.
        assert!(
            last_progress.elapsed() < Duration::from_secs(60) && started.elapsed() < Duration::from_secs(180),
            "native async empty-chain finality stalled under established socket criteria: {records:?}; evidence {}; observations {:?}",
            prepared.root.display(), nodes.iter().map(|node| node.ingress.consensus_observation().unwrap()).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // Compare the same independently finalized height, not racing tip heights.
    let commitments = nodes
        .iter()
        .map(|node| {
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let store = synergy_state::FinalizedStateStore::load_budgeted(
                layout.state().join("execution"),
                Arc::clone(node.ingress.world_budget()),
            )
            .unwrap();
            store.current().cloned()
        })
        .collect::<Vec<_>>();
    assert!(
        commitments.iter().all(|record| record
            .as_ref()
            .is_some_and(|record| record.finalized_height >= 1)),
        "native finality must reach durable execution: {commitments:?}"
    );
    // A legitimately retired historical candidate must not let an authenticated
    // lagging peer terminate the serving execution owner. Corruption remains
    // fatal; here only the absent metadata record models normal retirement.
    let first = &mut nodes[0];
    let (peer_id, (session_id, _)) = first
        .ingress
        .authenticated_peer_progress()
        .unwrap()
        .into_iter()
        .next()
        .expect("authenticated socket peer");
    let missing = first
        .configuration
        .storage
        .data_directory
        .join("blocks/execution-candidates/candidate/00000000000000000001.json");
    fs::remove_file(missing).unwrap();
    first
        .ingress
        .submit_sync_candidate_request_version(
            synergy_protocol_types::AuthenticatedPeer::new(peer_id, session_id, vec![]).unwrap(),
            synergy_sync::FinalizedCandidateRequest {
                height: 1,
                expected_parent_id: "retired-history-request".into(),
            },
            true,
        )
        .unwrap();
    // Node::poll asserts every native owner remains healthy.
    first.poll();
    for node in &mut nodes {
        node.stop();
    }
    fs::remove_dir_all(prepared.root).unwrap();
}

/// Real network/PoSy/ETDAG/execution owners; the fault holds only transaction
/// workers. It neither injects proofs nor changes any governed timing policy.
fn processing_retry_fixture_relay(
    prepared: &PreparedSocketFixture,
    nodes: &[Node],
    relay: usize,
    destination: usize,
    vertex: synergy_etdag::execution::ProcessingVertex,
) {
    use synergy_etdag::{
        crypto::canonical_signing_bytes, AuthenticatedEtdagMessage, EtdagNetworkMessage,
    };
    let message = EtdagNetworkMessage::ProcessingVertexV1(vertex);
    let sender = &prepared.ids[relay];
    let key = format!("consensus-{relay}");
    let message_id = EtdagDigest::from_canonical(
        "SYNERGY_ETDAG_NETWORK_MESSAGE_V1",
        &(1u32, sender.as_str(), key.as_str(), &message),
    )
    .unwrap();
    let bytes = canonical_signing_bytes(
        "SYNERGY_ETDAG_NETWORK_MESSAGE_SIGNATURE_V1",
        &(1u32, &message_id, sender, key.as_str(), &message),
    )
    .unwrap();
    let mut secret = fs::read(prepared.root.join(format!("node-{relay}/consensus.key"))).unwrap();
    let signature = fixture_sign(
        &secret,
        SignatureAlgorithm::MlDsa65,
        &key,
        "SYNERGY-ETDAG-SIGNATURE-V1",
        Some(1),
        &bytes,
    );
    secret.fill(0);
    let message = AuthenticatedEtdagMessage {
        message_version: 1,
        message_id,
        sender_id: sender.clone(),
        key_id: key,
        message,
        signature,
    };
    message.validate_shape().unwrap();
    assert!(
        nodes[relay]
            .ingress
            .authenticated_peers()
            .unwrap()
            .contains(&prepared.ids[destination]),
        "retry qualification requires a genuine current authenticated relay session"
    );
    nodes[relay]
        .ingress
        .publish_outbound(ingress::OutboundFrame {
            peer_id: prepared.ids[destination].clone(),
            protocol: synergy_protocol_types::ProtocolKind::Etdag,
            payload: serde_json::to_vec(&message).unwrap(),
        })
        .unwrap();
}

#[test]
fn processing_async_live_encrypted_pending_spans_blocks_then_finalizes_wallet_effects() {
    qualify_async_pending_with_apqe(None);
}
#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn processing_async_apqe_encrypted_pending_spans_blocks_then_finalizes_wallet_effects() {
    qualify_async_pending_with_apqe(Some(trusted_apqe_provider()));
}
fn qualify_async_pending_with_apqe(provider: Option<synergy_config::ApqeProviderConfiguration>) {
    // Optional exact-test-artifact diagnostic activation; the original fixture,
    // cryptography, resource budget, transfer and restart assertions are unchanged.
    #[cfg(feature = "qualification-timing")]
    let transport_diagnostics = std::env::var_os("POSY_TRANSPORT_NATIVE_CONFIG").map(|path| {
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(path)
            .unwrap()
            .take(4097)
            .read_to_end(&mut bytes)
            .unwrap();
        assert!(bytes.len() <= 4096);
        let config = serde_json::from_slice(&bytes).unwrap();
        super::qualification_timing::start_native_transport_fixture(config).unwrap()
    });
    use synergy_state::world_resources::WorldResourceBudget;
    let (transaction, world, mut account_secret) = funded_transaction_fixture_for_network_provider(
        "socket-qualification",
        10_000_000,
        provider.as_ref(),
    );
    let receiver = transaction.unsigned.receiver.clone();
    let sender = transaction.unsigned.sender.clone();
    let amount = transaction.unsigned.amount_nwei;
    let mut prepared =
        prepare_socket_fixture_profile_provider(world.clone(), None, true, None, provider.as_ref());
    for configuration in &mut prepared.configurations {
        configuration.aegis_provider = provider.clone();
    }
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(prepared.root.clone());
    eprintln!("async live encrypted evidence: {}", prepared.root.display());
    // This fault holds one transaction worker through the other four wallets'
    // finalization. Choose a late-lease participant before admission: holding a
    // proposer for the active ten-block lease can validly produce empty blocks
    // while lacking the held completion, making random fixture keys decide the
    // test's outcome. PoSy's schedule, deadlines and all assertions stay intact.
    let fixture_authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let lagging_id = fixture_authority.epoch.leader_ring.last().unwrap();
    let lagging = prepared.ids.iter().position(|id| id == lagging_id).unwrap();
    let peers = (0..prepared.ids.len())
        .filter(|index| *index != lagging)
        .collect::<Vec<_>>();
    eprintln!(
        "async recovery fixture roles: lagging physical node{lagging}, governed leader ring {:?}",
        fixture_authority
            .epoch
            .leader_ring
            .iter()
            .map(|id| prepared.ids.iter().position(|v| v == id).unwrap())
            .collect::<Vec<_>>()
    );
    // Existing declared integrated envelope: five validators share 1 GiB.
    // This local fixture does not constitute actual-host RSS/OOM evidence.
    let budget = WorldResourceBudget::new(1024 * 1024 * 1024);
    let genesis =
        synergy_state::world_resources::BudgetedWorld::try_clone_world(&world, &budget).unwrap();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(configuration, listeners)| {
            Node::open_with_wallet_budget(
                configuration,
                Some(super::protected_admission::AdmissionHandle::default()),
                listeners,
                budget.clone(),
                true,
                Some((1, 0)),
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    for node in &nodes {
        node.ingress.hold_processing_work(true).unwrap();
    }
    let response = wallet_rpc_node(
        &mut nodes[lagging],
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    );
    let context = serde_json::from_value(response["context"].clone()).unwrap();
    let authority = authority::load(&prepared.configurations[lagging])
        .unwrap()
        .unwrap();
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        &account_secret,
        provider.as_ref(),
    );
    account_secret.fill(0);
    let envelope = admission.request.envelope.envelope_id.clone();
    let receipt = wallet_rpc_node(
        &mut nodes[lagging],
        "synergy_submitProcessingTransactionV1",
        serde_json::to_value(&admission).unwrap(),
    );
    let receipt_id = receipt["receipt_id"].as_str().unwrap().to_owned();
    let started = Instant::now();
    let mut hold = true;
    let mut released = None;
    let mut held_finalized = 0;
    let mut last_progress = started;
    let mut prior_height = 0;
    let mut last_wallet_check = Instant::now();
    let mut next_redial = Instant::now();
    let mut original_vertex = None;
    let mut reveal_finality_observed = std::collections::BTreeSet::new();
    // Bounded first-observation diagnostics only; no fixture scheduling changes.
    let mut first_completion = std::collections::BTreeMap::new();
    let mut first_finalized_publication = std::collections::BTreeMap::new();
    let mut first_wallet_effect = std::collections::BTreeMap::new();
    let ready_record_key = format!("etdag-processing-ready-v1/item/{}", envelope.0);
    let mut awaiting_retired_share_replay = false;
    let mut delayed_reveal_worker = false;
    let mut retired_share_recovery_exercised = false;
    loop {
        for node in &mut nodes {
            node.poll();
        }
        if !hold && Instant::now() >= next_redial {
            let connected = nodes[lagging].ingress.authenticated_peers().unwrap();
            for (index, other) in nodes
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != lagging)
            {
                if !connected.contains(&prepared.ids[index]) {
                    nodes[lagging]
                        .ingress
                        .request_dial(ingress::DialRequest {
                            peer_id: prepared.ids[index].clone(),
                            address: other.configuration.network.listen_addresses[0],
                        })
                        .unwrap();
                }
            }
            next_redial = Instant::now() + Duration::from_secs(5);
        }
        let records = nodes
            .iter()
            .map(|n| n.ingress.latest_finality().unwrap())
            .collect::<Vec<_>>();
        let minimum = records
            .iter()
            .map(|r| r.as_ref().map_or(0, |r| r.height))
            .min()
            .unwrap();
        if minimum > prior_height {
            prior_height = minimum;
            last_progress = Instant::now();
        }
        if hold && minimum >= 2 {
            let receipt = nodes[lagging]
                .wallet_admission
                .as_ref()
                .unwrap()
                .receipt(&receipt_id)
                .unwrap();
            assert_eq!(
                receipt["admitted"], true,
                "durable pending admission: {receipt}"
            );
            for node in &nodes {
                let snapshot = node.ingress.processing_snapshot().unwrap().unwrap();
                assert!(
                    snapshot.completions.is_empty(),
                    "held encrypted work completed unexpectedly"
                );
            }
            held_finalized = minimum;
            assert!(nodes.iter().map(|node| node.ingress.stale_processing_handoffs().unwrap()).sum::<usize>() > 0,
                "native takeover must discard obsolete candidate handoffs while retaining pending work");
            // A different authenticated relay produces a fresh outer message,
            // bypassing the exact-frame cache while preserving the native
            // original. Held workers make these journal comparisons quiescent.
            let pending = nodes[lagging]
                .configuration
                .storage
                .data_directory
                .join("etdag/protected-pipeline/processing-v1");
            let paths = [
                pending.join("slots/0000.json"),
                pending.join("progress/0000.json"),
                pending.join("pending-v1.json"),
            ];
            let before = paths
                .iter()
                .map(|p| fs::read(p).unwrap())
                .collect::<Vec<_>>();
            let progress: serde_json::Value = serde_json::from_slice(&before[1]).unwrap();
            let evidence: super::processing_pipeline::ProcessingProgressEvidence =
                serde_json::from_value(progress["evidence"].clone()).unwrap();
            let vertex = synergy_etdag::execution::ProcessingVertex {
                vertex_version: evidence.vertex_version,
                admission: admission.clone(),
                envelope_ref: evidence.envelope_ref,
                parents: evidence.parents,
                author_id: evidence.author_id,
                key_id: evidence.key_id,
                author_signature: evidence.author_signature,
            };
            let source = super::processing_pipeline::NativeProcessingContext::verify(
                &authority,
                &context,
                super::processing_pipeline::ProcessingSource::Genesis(&genesis),
            )
            .unwrap();
            super::processing_pipeline::NativeProcessingVertex::verify_for_availability(
                &source,
                &vertex,
                &[],
                &budget,
            )
            .unwrap();
            let mut changed_signature = vertex.clone();
            changed_signature.author_signature[0] ^= 1;
            assert_eq!(
                changed_signature.id().unwrap(),
                vertex.id().unwrap(),
                "native ID deliberately excludes separately verified author signature"
            );
            let mut changed_admission = vertex.clone();
            changed_admission.admission.request.signature[0] ^= 1;
            assert_ne!(changed_admission.id().unwrap(), vertex.id().unwrap());
            let mut changed_parents = vertex.clone();
            changed_parents
                .parents
                .push(digest("unavailable-processing-parent"));
            changed_parents.envelope_ref.certified_dag_round = 1;
            assert_ne!(changed_parents.id().unwrap(), vertex.id().unwrap());
            for changed in [&changed_signature, &changed_admission, &changed_parents] {
                assert!(
                    super::processing_pipeline::NativeProcessingVertex::verify_for_availability(
                        &source,
                        changed,
                        &[],
                        &budget
                    )
                    .is_err(),
                    "changed native proof was accepted"
                );
            }
            for retry in [
                vertex.clone(),
                changed_signature,
                changed_admission,
                changed_parents,
            ] {
                processing_retry_fixture_relay(&prepared, &nodes, peers[0], lagging, retry);
            }
            let observe = Instant::now();
            while observe.elapsed() < Duration::from_secs(2) {
                for node in &mut nodes {
                    node.poll();
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(paths.iter().map(|p| fs::read(p).unwrap()).collect::<Vec<_>>(), before,
                "exact retries and rejected changed proofs must preserve original/progress/generation");
            assert!(!pending.join("completions/0000.json").exists());
            eprintln!("async retry qualification: exact original plus changed signature/admission/parents relayed; immutable slot/progress/generation preserved");
            original_vertex = Some(vertex);
            // Reopen the admitting validator from its actual durable journals
            // while its encrypted request is unfinished. No records are edited.
            nodes[lagging].stop();
            nodes[lagging] = Node::open_with_wallet_budget(
                prepared.configurations[lagging].clone(),
                Some(super::protected_admission::AdmissionHandle::default()),
                &prepared.listeners[lagging],
                budget.clone(),
                true,
                None,
            );
            for (index, other) in nodes
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != lagging)
            {
                nodes[lagging]
                    .ingress
                    .request_dial(ingress::DialRequest {
                        peer_id: prepared.ids[index].clone(),
                        address: other.configuration.network.listen_addresses[0],
                    })
                    .unwrap();
            }
            for node in &nodes {
                node.ingress.hold_processing_work(false).unwrap();
            }
            // First let the recovered original reach all peers. Only then hold
            // this worker behind reveal while the other four finalize/quiesce.
            awaiting_retired_share_replay = true;
            hold = false;
            released = Some(Instant::now());
            eprintln!("async encrypted {envelope:?} remained unfinished through finalized H{minimum}; release after {:?}; reserved={}", started.elapsed(), budget.used());
        }
        if !hold && last_wallet_check.elapsed() >= Duration::from_millis(250) {
            last_wallet_check = Instant::now();
            for (index, node) in nodes.iter().enumerate() {
                if reveal_finality_observed.contains(&index) {
                    continue;
                }
                let path = node
                    .configuration
                    .storage
                    .data_directory
                    .join("etdag/protected-pipeline/processing-v1/progress/0000.json");
                let Ok(bytes) = fs::read(path) else { continue };
                let progress: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                let Some(evidence) = progress.get("evidence") else {
                    continue;
                };
                let evidence: super::processing_pipeline::ProcessingProgressEvidence =
                    serde_json::from_value(evidence.clone()).unwrap();
                let Some(vc) = evidence.reveal_validation else {
                    assert!(
                        evidence.shares.is_empty(),
                        "shares preceded finalized order authorization"
                    );
                    continue;
                };
                let finalized = node
                    .ingress
                    .finalized_record(vc.context.height)
                    .unwrap()
                    .expect("reveal authorization preceded ordinary three-QC order finality");
                assert_eq!(finalized.block_id, vc.candidate.block_id);
                assert_eq!(
                    finalized.protected_execution_root,
                    vc.candidate.protected_execution_root
                );
                if !evidence.shares.is_empty() {
                    eprintln!("async reveal finality fence: validator{index} order H{} is finalized before retained reveal shares", finalized.height);
                    reveal_finality_observed.insert(index);
                }
            }
            for (index, node) in nodes.iter().enumerate() {
                if !first_completion.contains_key(&index)
                    && node
                        .ingress
                        .processing_snapshot()
                        .unwrap()
                        .is_some_and(|snapshot| {
                            snapshot
                                .completions
                                .iter()
                                .any(|completion| completion.record.item.envelope_id == envelope)
                        })
                {
                    let build = node.ingress.processing_build_request().unwrap();
                    let observed = (
                        started.elapsed().as_millis(),
                        minimum,
                        build.as_ref().map(|request| request.context.height),
                    );
                    eprintln!("async first verified completion: validator{index} elapsed_ms={} minimum_finalized={} build_height={:?}", observed.0, observed.1, observed.2);
                    first_completion.insert(index, observed);
                }
            }
            let effects = nodes
                .iter()
                .enumerate()
                .map(|(index, node)| {
                    let layout = synergy_storage::NodeStorageLayout::new(
                        node.configuration.storage.data_directory.clone(),
                    )
                    .unwrap();
                    let store = synergy_state::FinalizedStateStore::load_budgeted(
                        layout.state().join("execution"),
                        budget.clone(),
                    )
                    .unwrap();
                    store
                        .current_world_state_budgeted(&budget)
                        .unwrap()
                        .map(|world| {
                            let height = store.current().unwrap().finalized_height;
                            if world.protocol.contains_key(&ready_record_key)
                                && !first_finalized_publication.contains_key(&index)
                            {
                                let observed = (started.elapsed().as_millis(), height);
                                eprintln!("async first finalized ready publication: validator{index} elapsed_ms={} finalized_height={height}", observed.0);
                                first_finalized_publication.insert(index, observed);
                            }
                            let effect = (
                                world.accounts.get(&sender).map_or(0, |a| a.nonce),
                                world.accounts.get(&receiver).map_or(0, |a| a.balance_nwei),
                            );
                            if effect == (1, amount) && !first_wallet_effect.contains_key(&index) {
                                let observed = (started.elapsed().as_millis(), height);
                                eprintln!("async first finalized wallet effect: validator{index} elapsed_ms={} finalized_height={height}", observed.0);
                                first_wallet_effect.insert(index, observed);
                            }
                            effect
                        })
                })
                .collect::<Vec<_>>();
            if awaiting_retired_share_replay
                && !delayed_reveal_worker
                && peers.iter().map(|index| &nodes[*index]).all(|node| {
                    let path = node
                        .configuration
                        .storage
                        .data_directory
                        .join("etdag/protected-pipeline/processing-v1/slots/0000.json");
                    fs::read(path).is_ok_and(|bytes| bytes != b"null")
                })
            {
                let path = nodes[lagging]
                    .configuration
                    .storage
                    .data_directory
                    .join("etdag/protected-pipeline/processing-v1/progress/0000.json");
                let progress: serde_json::Value =
                    serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                assert!(
                    progress["evidence"]["reveal_validation"].is_null(),
                    "lagging reveal fixture must hold before its own reveal authorization"
                );
                nodes[lagging].ingress.hold_processing_work(true).unwrap();
                delayed_reveal_worker = true;
                eprintln!("async retained reveal recovery: original replicated before restarted worker hold");
            }
            if awaiting_retired_share_replay
                && delayed_reveal_worker
                && peers
                    .iter()
                    .map(|index| &effects[*index])
                    .all(|effect| *effect == Some((1, amount)))
                && peers.iter().map(|index| &nodes[*index]).all(|node| {
                    let path = node
                        .configuration
                        .storage
                        .data_directory
                        .join("etdag/protected-pipeline/processing-v1/finalized/0000.json");
                    fs::read(path).is_ok_and(|bytes| bytes != b"null")
                })
            {
                nodes[lagging].ingress.hold_processing_work(false).unwrap();
                awaiting_retired_share_replay = false;
                retired_share_recovery_exercised = true;
                eprintln!("async retained reveal recovery: four validators finalized and quiesced before restarted worker release");
            }
            if effects.iter().all(|effect| *effect == Some((1, amount))) {
                eprintln!("async live wallet finalized on all five: held H{held_finalized}, finality H{minimum}, elapsed {:?}, released {:?}, reserved={}", started.elapsed(), released.unwrap().elapsed(), budget.used());
                break;
            }
        }
        if last_progress.elapsed() >= Duration::from_secs(60)
            || started.elapsed() >= Duration::from_secs(180)
        {
            let diagnostic = nodes.iter().enumerate().map(|(index, node)| {
                let pending = node.configuration.storage.data_directory.join("etdag/protected-pipeline/processing-v1");
                let progress = fs::read(pending.join("progress/0000.json")).ok().and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
                let evidence = progress.as_ref().and_then(|p| p.get("evidence"));
                let snapshot = node.ingress.processing_snapshot().unwrap();
                let build = node.ingress.processing_build_request().unwrap();
                serde_json::json!({
                    "validator": index,
                    "held": node.ingress.processing_work_held().unwrap(),
                    "durable_original": pending.join("slots/0000.json").exists(),
                    "availability": evidence.is_some_and(|e| !e["availability"].is_null()),
                    "reveal_height": evidence.and_then(|e| e["reveal_validation"]["context"]["height"].as_u64()),
                    "shares": evidence.and_then(|e| e["shares"].as_array()).map(|s| s.len()),
                    "durable_completion": pending.join("completions/0000.json").exists(),
                    "durable_finalized": pending.join("finalized/0000.json").exists(),
                    "published_members": snapshot.as_ref().map(|s| s.members.len()),
                    "published_completions": snapshot.as_ref().map(|s| s.completions.len()),
                    "build_height": build.as_ref().map(|b| b.context.height),
                    "build_round": build.as_ref().map(|b| b.context.round),
                    "proposer": build.as_ref().map(|b| &b.proposer),
                    "sync": node.ingress.sync_progress_diagnostic().unwrap(),
                })
            }).collect::<Vec<_>>();
            eprintln!("async first-observation summary: completion={first_completion:?} finalized_publication={first_finalized_publication:?} wallet_effect={first_wallet_effect:?}");
            eprintln!("async failure diagnostic: elapsed={:?} progress_age={:?} released={:?} retired_replay_wait={} retired_replay_exercised={} reserved={} stages={}", started.elapsed(), last_progress.elapsed(), released.map(|time| time.elapsed()), awaiting_retired_share_replay, retired_share_recovery_exercised, budget.used(), serde_json::to_string(&diagnostic).unwrap());
        }
        assert!(last_progress.elapsed() < Duration::from_secs(60) && started.elapsed() < Duration::from_secs(180),
            "live async encrypted fixture stalled; held={hold}, finality={records:?}, evidence={}, observations={:?}",
            prepared.root.display(), nodes.iter().map(|n| n.ingress.consensus_observation().unwrap()).collect::<Vec<_>>());
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(held_finalized >= 2);
    assert!(retired_share_recovery_exercised);
    assert_eq!(
        reveal_finality_observed.len(),
        5,
        "each live validator must reveal only a finalized exact order"
    );
    // A new relay identity avoids the successful pre-finality frame cache.
    // The live finalized nonce fence must prevent resurrection of this work;
    // the existing restart/rejoin checks below verify no duplicate execution.
    processing_retry_fixture_relay(
        &prepared,
        &nodes,
        peers[1],
        lagging,
        original_vertex.unwrap(),
    );
    let observe = Instant::now();
    while observe.elapsed() < Duration::from_secs(2) {
        for node in &mut nodes {
            node.poll();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let before_restart = nodes
        .iter()
        .map(|node| node.ingress.latest_finality().unwrap().unwrap().height)
        .min()
        .unwrap();
    nodes[lagging].stop();
    nodes[lagging] = Node::open_with_wallet_budget(
        prepared.configurations[lagging].clone(),
        Some(super::protected_admission::AdmissionHandle::default()),
        &prepared.listeners[lagging],
        budget.clone(),
        true,
        None,
    );
    for (index, other) in nodes
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != lagging)
    {
        nodes[lagging]
            .ingress
            .request_dial(ingress::DialRequest {
                peer_id: prepared.ids[index].clone(),
                address: other.configuration.network.listen_addresses[0],
            })
            .unwrap();
    }
    let restart = Instant::now();
    let mut last_progress = restart;
    let mut previous = before_restart;
    let mut next_redial = restart;
    loop {
        for node in &mut nodes {
            node.poll();
        }
        if Instant::now() >= next_redial {
            let connected = nodes[lagging].ingress.authenticated_peers().unwrap();
            for (index, other) in nodes
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != lagging)
            {
                if !connected.contains(&prepared.ids[index]) {
                    nodes[lagging]
                        .ingress
                        .request_dial(ingress::DialRequest {
                            peer_id: prepared.ids[index].clone(),
                            address: other.configuration.network.listen_addresses[0],
                        })
                        .unwrap();
                }
            }
            next_redial = Instant::now() + Duration::from_secs(5);
        }
        let minimum = nodes
            .iter()
            .map(|node| {
                node.ingress
                    .latest_finality()
                    .unwrap()
                    .map_or(0, |r| r.height)
            })
            .min()
            .unwrap();
        if minimum > previous {
            previous = minimum;
            last_progress = Instant::now();
        }
        if minimum >= before_restart + 2 {
            for node in &nodes {
                let layout = synergy_storage::NodeStorageLayout::new(
                    node.configuration.storage.data_directory.clone(),
                )
                .unwrap();
                let store = synergy_state::FinalizedStateStore::load_budgeted(
                    layout.state().join("execution"),
                    budget.clone(),
                )
                .unwrap();
                let world = store
                    .current_world_state_budgeted(&budget)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    world.accounts[&sender].nonce, 1,
                    "restart duplicated execution"
                );
                assert_eq!(
                    world.accounts[&receiver].balance_nwei, amount,
                    "restart changed finalized wallet effects"
                );
            }
            eprintln!("async finalized restart/rejoin: all five progressed H{before_restart} to H{minimum}, wallet effects preserved, elapsed {:?}", restart.elapsed());
            break;
        }
        assert!(
            last_progress.elapsed() < Duration::from_secs(60)
                && restart.elapsed() < Duration::from_secs(180),
            "async finalized restart stalled at H{minimum}; evidence={}",
            prepared.root.display()
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    for node in &mut nodes {
        node.stop();
    }
    #[cfg(feature = "qualification-timing")]
    if let Some(diagnostics) = transport_diagnostics {
        super::qualification_timing::clear_process_handle();
        let report = diagnostics.finish();
        eprintln!("sparse transport diagnostic collector: {report:?}");
        assert!(
            report.complete(),
            "diagnostic collector lost retained evidence"
        );
        let transport = report.transport.as_ref().unwrap();
        assert!(
            transport.attempted_operations() > 0,
            "native transport hooks not exercised"
        );
        assert_eq!(
            transport.open_operations(),
            0,
            "socket cleanup left diagnostic operations open"
        );
    }
    // Diagnostic fixture is removed on success, failure and cancellation unwind.
}

#[test]
fn processing_async_native_registration_finalizes_then_new_wallet_transfers_over_five_sockets() {
    use synergy_identity::authorization::{
        canonical_binding_commitment, IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY,
    };
    use synergy_state::world_resources::WorldResourceBudget;
    let (mut registration, mut world, mut sponsor_secret) =
        funded_transaction_fixture_for_network("socket-qualification", 100_000_000);
    let (transfer, target_world, mut target_secret) =
        funded_transaction_fixture_for_network("socket-qualification", 10_000_000);
    let (other_target, other_target_world, mut other_target_secret) =
        funded_transaction_fixture_for_network("socket-qualification", 10_000_000);
    // Target is genuinely funded but absent from finalized authorization.
    world.accounts.extend(target_world.accounts);
    world.accounts.extend(other_target_world.accounts);
    assert!(canonical_binding_commitment(&world.protocol, &transfer.unsigned.sender).is_err());
    registration.unsigned.amount_nwei = 0;
    registration.unsigned.fee_limit.gas_limit = 200_000;
    registration.unsigned.payload = synergy_transaction::TransactionAction::Native {
        module: "identity".into(),
        method: "register_authorization".into(),
        input: serde_json::to_vec(transfer.identity_authorization.as_ref().unwrap()).unwrap(),
    }
    .encode()
    .unwrap();
    registration.signature = fixture_sign(
        &sponsor_secret,
        SignatureAlgorithm::MlDsa87,
        "registration-sponsor",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &registration.unsigned.signing_bytes().unwrap(),
    );
    let mut second_transfer = transfer.clone();
    second_transfer.unsigned.nonce = 1;
    second_transfer.signature = fixture_sign(
        &target_secret,
        SignatureAlgorithm::MlDsa87,
        "registration-target-second",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &second_transfer.unsigned.signing_bytes().unwrap(),
    );
    // An older frozen source must remain usable while its future nonce waits
    // across a finalized registration/source refresh. Fill nonce1 only later.
    let mut older_pending = registration.clone();
    older_pending.unsigned.payload.clear();
    older_pending.unsigned.amount_nwei = 7;
    older_pending.unsigned.fee_limit.gas_limit = 21_000;
    older_pending.unsigned.nonce = 2;
    older_pending.signature = fixture_sign(
        &sponsor_secret,
        SignatureAlgorithm::MlDsa87,
        "older-processing-source",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &older_pending.unsigned.signing_bytes().unwrap(),
    );
    let mut fill_gap = older_pending.clone();
    fill_gap.unsigned.nonce = 1;
    fill_gap.unsigned.amount_nwei = 0;
    fill_gap.unsigned.fee_limit.gas_limit = 200_000;
    fill_gap.unsigned.payload = synergy_transaction::TransactionAction::Native {
        module: "identity".into(),
        method: "register_authorization".into(),
        input: serde_json::to_vec(other_target.identity_authorization.as_ref().unwrap()).unwrap(),
    }
    .encode()
    .unwrap();
    fill_gap.signature = fixture_sign(
        &sponsor_secret,
        SignatureAlgorithm::MlDsa87,
        "fill-processing-nonce-gap",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &fill_gap.unsigned.signing_bytes().unwrap(),
    );
    // A failed marker CAS must leave both authorization and sponsor nonce
    // untouched; the native operation stages them in one ordinary atomic diff.
    let mut atomic_probe = world.clone();
    let replacement = synergy_identity::registration::register_authorization(
        &world.protocol,
        &registration.unsigned.sender,
        transfer.identity_authorization.as_ref().unwrap(),
        registration.unsigned.network.chain_id,
        &registration.unsigned.network.network_id,
        registration.unsigned.timestamp_unix,
    )
    .unwrap();
    let conflict = synergy_state::StateDiff {
        changes: vec![synergy_state::AccountChange {
            account: registration.unsigned.sender.clone(),
            debit_nwei: 0,
            credit_nwei: 0,
            expected_nonce: Some(0),
            code_hash: None,
        }],
        protocol_changes: vec![
            synergy_state::ProtocolChange {
                key: IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY.into(),
                expected_value: world
                    .protocol
                    .get(IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
                    .cloned(),
                value: Some(replacement),
            },
            synergy_state::ProtocolChange {
                key: synergy_identity::registration::AUTHORIZATION_UPDATED_HEIGHT_STATE_KEY.into(),
                expected_value: Some(b"999".to_vec()),
                value: Some(b"7".to_vec()),
            },
        ],
    };
    assert!(
        synergy_state::StateDiff::apply_ordered_atomic(&[&conflict], &mut atomic_probe).is_err()
    );
    assert_eq!(atomic_probe, world);
    let prepared = prepare_socket_fixture_profile(world.clone(), None, true);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(config, listeners)| {
            Node::open_with_wallet_budget(
                config,
                Some(super::protected_admission::AdmissionHandle::default()),
                listeners,
                WorldResourceBudget::new(1024 * 1024 * 1024),
                true,
                None,
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    let original_table = world.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY].clone();
    let mut registration_gas = 0;
    let mut registration_height = 0;
    let mut second_registration_height = 0;
    let mut second_registration_gas = 0;
    let mut older_receipt = serde_json::Value::Null;
    for (phase, (transaction, secret)) in [
        (&registration, &sponsor_secret),
        (&transfer, &target_secret),
        (&second_transfer, &target_secret),
        (&fill_gap, &sponsor_secret),
    ]
    .into_iter()
    .enumerate()
    {
        let phase_start = Instant::now();
        let context_start = Instant::now();
        let exported = loop {
            let exported = wallet_rpc_node(
                &mut nodes[0],
                "synergy_getProcessingContextV1",
                serde_json::json!({}),
            );
            if phase == 0
                || exported["context"]["authority"]["source_finalized_height"]
                    .as_u64()
                    .unwrap()
                    >= registration_height
            {
                break exported;
            }
            assert!(
                context_start.elapsed() < Duration::from_secs(30),
                "finalized registration source was not advertised"
            );
            for node in &mut nodes {
                node.poll();
            }
        };
        let context = serde_json::from_value(exported["context"].clone()).unwrap();
        if phase == 1 {
            let receipt_start = Instant::now();
            loop {
                let receipt = wallet_rpc_node(
                    &mut nodes[0],
                    "synergy_getProtectedAdmissionReceipt",
                    serde_json::json!({"receipt_id":older_receipt["receipt_id"]}),
                );
                if receipt["admitted"] == true {
                    break;
                }
                assert!(
                    receipt_start.elapsed() < Duration::from_secs(30),
                    "older source intake did not become durable: {receipt}"
                );
                for node in &mut nodes {
                    node.poll();
                }
            }
            assert!(wallet_rpc_node(
                &mut nodes[0],
                "synergy_getTransaction",
                serde_json::json!({"transaction_id":older_pending.id().unwrap().0})
            )
            .is_null());
        }
        let admission =
            processing_wallet_admission_fixture(transaction, &context, &authority, secret);
        if phase == 0 {
            let first_use = processing_wallet_admission_fixture(
                &transfer,
                &context,
                &authority,
                &target_secret,
            );
            assert!(
                super::protected_admission::verify_wallet_processing_admission(
                    &first_use,
                    &context,
                    &world,
                    authority
                        .consensus_timestamp_unix(context.authority.target_height)
                        .unwrap()
                )
                .is_ok()
            );
        }
        let queued = wallet_rpc_node(
            &mut nodes[0],
            "synergy_submitProcessingTransactionV1",
            serde_json::to_value(admission).unwrap(),
        );
        assert_eq!(queued["status"], "queued");
        if phase == 0 {
            let old_admission = processing_wallet_admission_fixture(
                &older_pending,
                &context,
                &authority,
                &sponsor_secret,
            );
            assert_eq!(old_admission.request.envelope.aad.authorization_height, 3);
            older_receipt = wallet_rpc_node(
                &mut nodes[0],
                "synergy_submitProcessingTransactionV1",
                serde_json::to_value(old_admission).unwrap(),
            );
            assert_eq!(older_receipt["status"], "queued");
        }
        let txid = transaction.id().unwrap().0;
        let start = Instant::now();
        let mut checked = Instant::now() - Duration::from_secs(1);
        loop {
            for node in &mut nodes {
                node.poll();
            }
            if checked.elapsed() >= Duration::from_millis(50) {
                checked = Instant::now();
                let views = nodes
                    .iter_mut()
                    .map(|n| {
                        wallet_rpc_node(
                            n,
                            "synergy_getTransaction",
                            serde_json::json!({"transaction_id":txid}),
                        )
                    })
                    .collect::<Vec<_>>();
                if views.iter().all(|v| !v.is_null()) {
                    let first = &views[0];
                    for view in &views {
                        assert_eq!(view["status"], "applied", "{view}");
                        assert_eq!(view["block_height"], first["block_height"]);
                        assert_eq!(view["block_hash"], first["block_hash"]);
                        assert_eq!(
                            view["finality_certificate_id"],
                            first["finality_certificate_id"]
                        );
                        assert_eq!(view["receipt"], first["receipt"]);
                    }
                    if phase == 0 {
                        registration_gas = first["receipt"]["gas_used"].as_u64().unwrap();
                        registration_height = first["block_height"].as_u64().unwrap();
                    } else if phase == 3 {
                        second_registration_height = first["block_height"].as_u64().unwrap();
                        second_registration_gas = first["receipt"]["gas_used"].as_u64().unwrap();
                        assert!(second_registration_height > registration_height);
                    }
                    eprintln!("registration fixture phase {phase} finalized at {} context_to_all_five_effects_ms={}",
                        first["block_height"], phase_start.elapsed().as_millis());
                    assert!(
                        phase_start.elapsed() <= Duration::from_secs(30),
                        "current-nonce phase exceeded unchanged30s finality contract"
                    );
                    break;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "encrypted registration/transfer phase {phase} stalled: {}",
                prepared.root.display()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        if phase == 3 {
            let old_start = Instant::now();
            loop {
                for node in &mut nodes {
                    node.poll();
                }
                let views = nodes
                    .iter_mut()
                    .map(|node| {
                        wallet_rpc_node(
                            node,
                            "synergy_getTransaction",
                            serde_json::json!({"transaction_id":older_pending.id().unwrap().0}),
                        )
                    })
                    .collect::<Vec<_>>();
                if views.iter().all(|view| !view.is_null()) {
                    for view in &views {
                        assert_eq!(view["status"], "applied");
                        assert_eq!(view["block_hash"], views[0]["block_hash"]);
                        assert_eq!(
                            view["finality_certificate_id"],
                            views[0]["finality_certificate_id"]
                        );
                        assert_eq!(view["receipt"], views[0]["receipt"]);
                    }
                    eprintln!(
                        "older frozen pending source finalized after context refresh at {}",
                        views[0]["block_height"]
                    );
                    break;
                }
                assert!(
                    old_start.elapsed() < Duration::from_secs(30),
                    "older source did not finalize after filling nonce gap"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // Read the actual durable finalized world, not an admission counter.
        let mut roots = std::collections::BTreeSet::new();
        let heights = nodes
            .iter()
            .map(|n| n.ingress.latest_finality().unwrap().unwrap().height)
            .collect::<Vec<_>>();
        let height = *heights.iter().min().unwrap();
        for node in &mut nodes {
            let telemetry = wallet_rpc_node(
                node,
                "synergy_chainTelemetry",
                serde_json::json!({"at_height":height}),
            );
            roots.insert(
                telemetry["common_finalized_commitment"]["state_root"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            );
            let sender = wallet_rpc_node(
                node,
                "synergy_getAccount",
                serde_json::json!({"address":transaction.unsigned.sender,"at_height":height}),
            );
            assert_eq!(
                sender["nonce"],
                match phase {
                    0 => 1,
                    3 => 3,
                    _ => phase,
                }
            );
            let expected = if phase == 0 {
                100_000_000 - u128::from(registration_gas) * 40
            } else if phase < 3 {
                10_000_000 - phase as u128 * (transfer.unsigned.amount_nwei + 840_000)
            } else {
                100_000_000
                    - u128::from(registration_gas + second_registration_gas) * 40
                    - (7 + 840_000)
            };
            assert_eq!(sender["balance_nwei"], expected.to_string());
            if phase > 0 {
                let receiver = wallet_rpc_node(
                    node,
                    "synergy_getAccount",
                    serde_json::json!({"address":transfer.unsigned.receiver,"at_height":height}),
                );
                assert_eq!(
                    receiver["balance_nwei"],
                    ((if phase == 3 { 3 } else { phase }) as u128 * transfer.unsigned.amount_nwei)
                        .to_string()
                );
            }
        }
        assert_eq!(roots.len(), 1);
    }
    assert_eq!(
        world.protocol[IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY],
        original_table
    );
    let source_start = Instant::now();
    let retained_context: synergy_etdag::ProcessingContext = loop {
        let contexts = nodes
            .iter_mut()
            .map(|node| {
                serde_json::from_value::<synergy_etdag::ProcessingContext>(
                    wallet_rpc_node(
                        node,
                        "synergy_getProcessingContextV1",
                        serde_json::json!({}),
                    )["context"]
                        .clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        if contexts
            .iter()
            .all(|context| context.authority.source_finalized_height == second_registration_height)
        {
            assert!(contexts.iter().all(|context| context == &contexts[0]));
            break contexts[0].clone();
        }
        assert!(
            source_start.elapsed() < Duration::from_secs(30),
            "second canonical registration source was not advertised consistently"
        );
        for node in &mut nodes {
            node.poll();
        }
    };
    for node in &mut nodes {
        node.stop();
    }
    // Only stopped disposable fixture stores are pruned here. Reopen after
    // pruning past the source to prove the same bounded sparse pin preserves
    // authenticated original World ownership, without a full-World cache.
    for node in &nodes {
        let height = retained_context.authority.source_finalized_height;
        let layout = synergy_storage::NodeStorageLayout::new(
            node.configuration.storage.data_directory.clone(),
        )
        .unwrap();
        let root = layout.blocks().join("execution-candidates");
        let budget = node.ingress.world_budget();
        let tip = node.ingress.latest_finality().unwrap().unwrap().height;
        // retain1 prunes through tip-1; the source need only precede the tip.
        assert!(tip > height);
        let store =
            synergy_execution::BudgetedCandidateStore::new_budgeted(&root, budget.clone()).unwrap();
        assert!(store
            .pinned_descriptors()
            .iter()
            .any(|pin| pin.height == height));
        store.prune_finalized_history(tip, 1).unwrap();
        drop(store);
        let store =
            synergy_execution::BudgetedCandidateStore::new_budgeted(&root, budget.clone()).unwrap();
        let candidate = store.get_budgeted(height).unwrap().unwrap();
        let (_, witness) = node
            .ingress
            .finalized_record_with_witness(height)
            .unwrap()
            .unwrap();
        for (kind, mut changed) in [
            retained_context.clone(),
            retained_context.clone(),
            retained_context.clone(),
        ]
        .into_iter()
        .enumerate()
        {
            match kind {
                0 => changed.authority.network_id.push_str("-foreign"),
                1 => changed.authority.chain_id += 1,
                _ => changed.authority.source_finality_context_root = "0".repeat(64),
            }
            assert!(super::processing_pipeline::NativeProcessingContext::verify(
                &authority,
                &changed,
                super::processing_pipeline::ProcessingSource::Finalized {
                    candidate: &candidate,
                    witness: &witness
                }
            )
            .is_err());
        }
        super::processing_pipeline::NativeProcessingContext::verify_owned_finalized(
            &authority,
            &retained_context,
            candidate,
            &witness,
            budget,
        )
        .unwrap();
    }
    // Restart a stopped disposable node from the pruned native chain. Its RPC
    // may be unavailable while reconciling sources, but may never advertise a
    // Genesis fallback after registration. Retain the original5s readiness gate.
    let restart_started = Instant::now();
    let mut reopened = Node::open_with_wallet_budget(
        prepared.configurations[0].clone(),
        Some(super::protected_admission::AdmissionHandle::default()),
        &prepared.listeners[0],
        WorldResourceBudget::new(1024 * 1024 * 1024),
        true,
        None,
    );
    loop {
        reopened.poll();
        if let Ok(published) = reopened
            .wallet_admission
            .as_ref()
            .unwrap()
            .processing_context()
        {
            let context: synergy_etdag::ProcessingContext =
                serde_json::from_value(published["context"].clone()).unwrap();
            assert_ne!(
                context.authority.source_finalized_height, 0,
                "recovered node advertised Genesis after registration"
            );
            assert_eq!(context, retained_context);
            assert!(
                restart_started.elapsed() <= Duration::from_secs(5),
                "recovered registration source missed original5s readiness gate"
            );
            eprintln!(
                "registered native source restart ready_ms={}",
                restart_started.elapsed().as_millis()
            );
            break;
        }
        assert!(
            restart_started.elapsed() < Duration::from_secs(5),
            "recovered registration source stayed unavailable beyond original5s readiness gate"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    reopened.stop();
    drop(reopened);
    sponsor_secret.fill(0);
    target_secret.fill(0);
    other_target_secret.fill(0);
    let root = prepared.root.clone();
    drop(nodes);
    drop(authority);
    drop(prepared);
    fs::remove_dir_all(root).unwrap();
}

#[path = "socket_checkpoint_qualification.rs"]
mod checkpoint_recovery;

#[test]
fn encrypted_wallet_synid_finalizes_with_identical_ownership_on_five_sockets() {
    use synergy_state::world_resources::WorldResourceBudget;
    let (mut transaction, world, mut secret) =
        funded_transaction_fixture_for_network("socket-qualification", 100_000_000);
    transaction.unsigned.amount_nwei = 0;
    transaction.unsigned.fee_limit.gas_limit =
        50_000 + synergy_naming::MAX_WALLET_NAMING_BYTES as u64;
    transaction.unsigned.payload = synergy_transaction::TransactionAction::Native {
        module: "naming".into(),
        method: "register_wallet".into(),
        input: serde_json::to_vec(&serde_json::json!({"syn_id":"alice.syn"})).unwrap(),
    }
    .encode()
    .unwrap();
    transaction.signature = fixture_sign(
        &secret,
        SignatureAlgorithm::MlDsa87,
        "wallet-naming",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &transaction.unsigned.signing_bytes().unwrap(),
    );
    let prepared = prepare_socket_fixture_profile(world, None, true);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .map(|(config, listeners)| {
            Node::open_with_wallet_budget(
                config,
                Some(super::protected_admission::AdmissionHandle::default()),
                listeners,
                WorldResourceBudget::new(1024 * 1024 * 1024),
                true,
                None,
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    assert!(wallet_rpc_node(
        &mut nodes[0],
        "synergy_resolveSynID",
        serde_json::json!({"value":"alice.syn"})
    )
    .is_null());
    let exported = wallet_rpc_node(
        &mut nodes[0],
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    );
    assert_eq!(exported["fee_policy"]["base_fee_per_gas_nwei"], 40);
    let context = serde_json::from_value(exported["context"].clone()).unwrap();
    let admission =
        processing_wallet_admission_fixture(&transaction, &context, &authority, &secret);
    assert_eq!(
        wallet_rpc_node(
            &mut nodes[0],
            "synergy_submitProcessingTransactionV1",
            serde_json::to_value(admission).unwrap()
        )["status"],
        "queued"
    );
    let start = Instant::now();
    let views = loop {
        for node in &mut nodes {
            node.poll();
        }
        let views = nodes
            .iter_mut()
            .map(|node| {
                wallet_rpc_node(
                    node,
                    "synergy_getTransaction",
                    serde_json::json!({"transaction_id":transaction.id().unwrap().0}),
                )
            })
            .collect::<Vec<_>>();
        if views.iter().all(|view| !view.is_null()) {
            break views;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "encrypted wallet naming stalled: {}",
            wallet_rpc_node(
                &mut nodes[0],
                "synergy_chainTelemetry",
                serde_json::json!({})
            )
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    for (node, view) in nodes.iter_mut().zip(&views) {
        assert_eq!(view["status"], "applied", "{view}");
        assert_eq!(view["block_hash"], views[0]["block_hash"]);
        let record = wallet_rpc_node(
            node,
            "synergy_resolveSynID",
            serde_json::json!({"value":"alice.syn"}),
        );
        assert_eq!(record["address"], transaction.unsigned.sender);
        assert_eq!(record["registered_height"], view["block_height"]);
        assert!(!record["finality_certificate_id"].is_null());
        let reverse = wallet_rpc_node(
            node,
            "synergy_reverseResolveSynID",
            serde_json::json!({"value":transaction.unsigned.sender}),
        );
        assert_eq!(reverse[0]["synId"], "alice.syn");
    }
    drop(nodes);
    secret.fill(0);
    std::fs::remove_dir_all(prepared.root).unwrap();
}

#[test]
fn wallet_naming_native_dispatch_is_owner_bound_atomic_and_fee_capped() {
    let (mut tx, mut world, mut secret) =
        funded_transaction_fixture_for_network("socket-qualification", 100_000_000);
    tx.unsigned.amount_nwei = 0;
    tx.unsigned.fee_limit.gas_limit = 200_000;
    let prepared = prepare_socket_fixture_profile(world.clone(), None, true);
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let original = world.clone();
    assert!(super::execution::wallet_naming_execution_fixture(
        Arc::clone(&authority),
        &tx,
        br#"{"syn_id":"alice.syn","address":"attacker"}"#,
        &world
    )
    .is_err());
    assert_eq!(world, original);
    let dispatch = super::execution::wallet_naming_execution_fixture(
        Arc::clone(&authority),
        &tx,
        br#"{"syn_id":"alice.syn"}"#,
        &world,
    )
    .unwrap();
    let fees = synergy_execution::FeeSchedule {
        base_fee_per_gas_nwei: 40,
        collector: "fee-collector".into(),
    };
    tx.unsigned.fee_limit.max_fee_per_gas_nwei = 1;
    assert!(matches!(
        fees.settle(&tx, dispatch.gas_used, 0),
        Err(synergy_execution::BlockExecutionError::FeeCapTooLow { .. })
    ));
    assert_eq!(world, original);
    tx.unsigned.fee_limit.max_fee_per_gas_nwei = 40;
    let (fee, charge) = fees.settle(&tx, dispatch.gas_used, 0).unwrap();
    assert_eq!(fee.fee_nwei, u128::from(dispatch.gas_used) * 40);
    synergy_state::StateDiff::apply_ordered_atomic(&[&dispatch.state_diff, &charge], &mut world)
        .unwrap();
    let registry = synergy_naming::WalletSynIdRegistry::decode(Some(
        &world.protocol[synergy_naming::WALLET_PROTOCOL_STATE_KEY],
    ))
    .unwrap();
    assert_eq!(
        registry.resolve("alice.syn").unwrap().unwrap().address,
        tx.unsigned.sender
    );
    secret.fill(0);
    drop(authority);
    let root = prepared.root.clone();
    drop(prepared);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn processing_bad_capsule_preserves_pending_and_empty_finality_across_restart() {
    use synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY as BINDINGS;
    let (bad_tx, mut world, mut bad_secret) = funded_transaction_fixture_with_key();
    let (good_tx, good_world, mut good_secret) = funded_transaction_fixture_with_key();
    world.accounts.extend(good_world.accounts);
    let mut bindings: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&world.protocol[BINDINGS]).unwrap();
    let extra: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&good_world.protocol[BINDINGS]).unwrap();
    bindings.extend(extra);
    world
        .protocol
        .insert(BINDINGS.into(), serde_json::to_vec(&bindings).unwrap());
    let prepared = prepare_socket_fixture_profile(world, None, true);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(prepared.root.clone());
    // Match the real five-host resource policy: each independent validator owns
    // its original 1GiB allocation pool, rather than sharing one pool fleetwide.
    let budgets = (0..prepared.configurations.len())
        .map(|_| synergy_state::world_resources::WorldResourceBudget::new(1024 * 1024 * 1024))
        .collect::<Vec<_>>();
    let mut nodes = prepared
        .configurations
        .iter()
        .cloned()
        .zip(&prepared.listeners)
        .enumerate()
        .map(|(index, (configuration, listeners))| {
            Node::open_with_wallet_budget(
                configuration,
                Some(super::protected_admission::AdmissionHandle::default()),
                listeners,
                budgets[index].clone(),
                true,
                None,
            )
        })
        .collect::<Vec<_>>();
    for (i, node) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate().skip(i + 1) {
            node.ingress
                .request_dial(ingress::DialRequest {
                    peer_id: prepared.ids[j].clone(),
                    address: other.configuration.network.listen_addresses[0],
                })
                .unwrap();
        }
    }
    let response = wallet_rpc_node(
        &mut nodes[0],
        "synergy_getProcessingContextV1",
        serde_json::json!({}),
    );
    let context = serde_json::from_value(response["context"].clone()).unwrap();
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let mut bad = processing_wallet_admission_fixture(&bad_tx, &context, &authority, &bad_secret);
    for capsule in &mut bad.request.envelope.share_capsules {
        capsule.encrypted_share[0] ^= 1;
    }
    bad.request.envelope.refresh_capsule_roots().unwrap();
    bad.request.envelope.envelope_id = bad.request.envelope.commitment().unwrap();
    bad.request.signature = fixture_sign(
        &bad_secret,
        SignatureAlgorithm::MlDsa87,
        "processing-wallet",
        "SYNERGY-TRANSACTION-SIGNING-V1",
        None,
        &bad.request.signing_bytes().unwrap(),
    );
    bad_secret.fill(0);
    let good = processing_wallet_admission_fixture(&good_tx, &context, &authority, &good_secret);
    good_secret.fill(0);
    for admission in [&bad, &good] {
        let receipt = wallet_rpc_node(
            &mut nodes[0],
            "synergy_submitProcessingTransactionV1",
            serde_json::to_value(admission).unwrap(),
        );
        assert!(receipt["receipt_id"].is_string(), "{receipt}");
    }
    let mut originals = Vec::new();
    let start = Instant::now();
    let mut restart_height = None;
    let mut restarted = false;
    let mut next_redial = start;
    loop {
        for node in &mut nodes {
            node.poll();
        }
        if Instant::now() >= next_redial {
            for (i, node) in nodes.iter().enumerate() {
                let peers = node.ingress.authenticated_peers().unwrap();
                for (j, other) in nodes.iter().enumerate().filter(|(j, _)| *j != i) {
                    if !peers.contains(&prepared.ids[j]) {
                        node.ingress
                            .request_dial(ingress::DialRequest {
                                peer_id: prepared.ids[j].clone(),
                                address: other.configuration.network.listen_addresses[0],
                            })
                            .unwrap();
                    }
                }
            }
            next_redial = Instant::now() + Duration::from_secs(5);
        }
        let mut all_ready = true;
        let mut minimum = u64::MAX;
        for node in &nodes {
            let height = node
                .ingress
                .latest_finality()
                .unwrap()
                .map_or(0, |r| r.height);
            minimum = minimum.min(height);
            let root = node
                .configuration
                .storage
                .data_directory
                .join("etdag/protected-pipeline/processing-v1");
            let mut found = None;
            let Ok(slots) = fs::read_dir(root.join("slots")) else {
                all_ready = false;
                continue;
            };
            for path in slots {
                let path = path.unwrap().path();
                let bytes = fs::read(&path).unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if let Some(admission) = value.get("admission_json").and_then(|a| a.as_str()) {
                    let admission: synergy_etdag::WalletProcessingAdmission =
                        serde_json::from_str(admission).unwrap();
                    if admission.request.envelope.envelope_id == bad.request.envelope.envelope_id {
                        found = Some((path, bytes));
                        break;
                    }
                }
            }
            let Some((path, bytes)) = found else {
                all_ready = false;
                continue;
            };
            if originals.len() < nodes.len() && !originals.iter().any(|(p, _)| p == &path) {
                originals.push((path.clone(), bytes.clone()));
            }
            let progress = root.join("progress").join(path.file_name().unwrap());
            let Ok(progress_bytes) = fs::read(progress) else {
                all_ready = false;
                continue;
            };
            let evidence: serde_json::Value = serde_json::from_slice(&progress_bytes).unwrap();
            let reveal = evidence["evidence"]["reveal_validation"]["context"]["height"].as_u64();
            if reveal.is_none_or(|r| height <= r + 2) {
                all_ready = false;
            }
            assert!(evidence["evidence"]["shares"]
                .as_array()
                .unwrap()
                .is_empty());
            let layout = synergy_storage::NodeStorageLayout::new(
                node.configuration.storage.data_directory.clone(),
            )
            .unwrap();
            let budget = node.ingress.world_budget().clone();
            let store = synergy_state::FinalizedStateStore::load_budgeted(
                layout.state().join("execution"),
                budget.clone(),
            )
            .unwrap();
            let Some(world) = store.current_world_state_budgeted(&budget).unwrap() else {
                all_ready = false;
                continue;
            };
            assert_eq!(world.accounts[&bad_tx.unsigned.sender].nonce, 0);
            if world.accounts[&good_tx.unsigned.sender].nonce != 1 {
                all_ready = false;
            } else {
                assert_eq!(
                    world.accounts[&good_tx.unsigned.receiver].balance_nwei,
                    good_tx.unsigned.amount_nwei
                );
            }
        }
        if all_ready && !restarted {
            assert_eq!(originals.len(), nodes.len());
            for (path, bytes) in &originals {
                assert_eq!(&fs::read(path).unwrap(), bytes);
            }
            nodes[0].stop();
            nodes[0] = Node::open_with_wallet_budget(
                prepared.configurations[0].clone(),
                Some(super::protected_admission::AdmissionHandle::default()),
                &prepared.listeners[0],
                budgets[0].clone(),
                true,
                None,
            );
            restarted = true;
            restart_height = Some(minimum);
            next_redial = Instant::now();
        } else if all_ready && restart_height.is_some_and(|r| minimum >= r + 2) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "bad capsule isolation/restart did not complete at H{minimum}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    for (path, bytes) in &originals {
        assert_eq!(&fs::read(path).unwrap(), bytes);
    }
    for node in &mut nodes {
        node.stop();
    }
}

#[test]
#[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
fn processing_apqe_progress_verifies_certified_original_once_and_rejects_invalid_proofs() {
    use super::processing_pipeline::*;
    use super::processing_store::ProcessingAdmissionAuthenticator;
    use synergy_etdag::{
        crypto::canonical_signing_bytes, execution::*, AvailabilityCertificate, AvailabilityVote,
        ProcessingContext, PROCESSING_PROFILE_ID,
    };
    use synergy_state::world_resources::{BudgetedWorld, WorldResourceBudget};
    let provider = trusted_apqe_provider();
    let (transaction, world, mut account_secret) = funded_transaction_fixture_for_network_provider(
        "socket-qualification",
        10_000_000,
        Some(&provider),
    );
    let prepared =
        prepare_socket_fixture_profile_provider(world.clone(), None, true, None, Some(&provider));
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(prepared.root.clone());
    let authority = authority::load(&prepared.configurations[0])
        .unwrap()
        .unwrap();
    let budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let genesis = BudgetedWorld::try_clone_world(&world, &budget).unwrap();
    let context = ProcessingContext {
        context_version: 1,
        profile_id: PROCESSING_PROFILE_ID.into(),
        authority: authority.protected_target(None, 3).unwrap().0,
    };
    let source =
        NativeProcessingContext::verify(&authority, &context, ProcessingSource::Genesis(&genesis))
            .unwrap();
    let admission = processing_wallet_admission_fixture_provider(
        &transaction,
        &context,
        &authority,
        &account_secret,
        Some(&provider),
    );
    account_secret.fill(0);
    let sign = |index: usize, domain: &str, bytes: &[u8]| {
        fixture_sign(
            &fs::read(prepared.root.join(format!("node-{index}/consensus.key"))).unwrap(),
            SignatureAlgorithm::MlDsa65,
            &format!("consensus-{index}"),
            domain,
            Some(1),
            bytes,
        )
    };
    let mut vertex = ProcessingVertex {
        vertex_version: 1,
        envelope_ref: synergy_etdag::CertifiedEnvelopeRef {
            tx_commitment: admission.request.envelope.envelope_id.clone(),
            sender_id: admission.request.sender_wallet.clone(),
            nonce_slot: admission.request.sender_nonce,
            certified_dag_round: 0,
            gas_class_units: admission.request.gas_class_units,
            ciphertext_bytes: admission.request.envelope.ciphertext.len() as u64,
            fee_class: admission.request.fee_class,
            protocol_dependencies: vec![],
        },
        admission,
        parents: vec![],
        author_id: prepared.ids[0].clone(),
        key_id: "consensus-0".into(),
        author_signature: vec![],
    };
    vertex.author_signature = sign(
        0,
        "SYNERGY-ETDAG-SIGNATURE-V1",
        &vertex.signing_bytes().unwrap(),
    );
    let vertex_id = vertex.id().unwrap();
    let mut rewritten_authorization = vertex.clone();
    rewritten_authorization.admission.request.signature[0] ^= 1;
    assert_ne!(rewritten_authorization.id().unwrap(), vertex_id);

    let votes = (0..4)
        .map(|index| {
            let mut vote = AvailabilityVote {
                context_root: context.root().unwrap(),
                vertex_id: vertex_id.clone(),
                validator_id: prepared.ids[index].clone(),
                key_id: format!("consensus-{index}"),
                signature: vec![],
            };
            vote.signature = sign(
                index,
                "SYNERGY-ETDAG-SIGNATURE-V1",
                &canonical_signing_bytes(
                    "SYNERGY_ETDAG_AVAILABILITY_VOTE_V1",
                    &(
                        &vote.context_root,
                        &vote.vertex_id,
                        &vote.validator_id,
                        &vote.key_id,
                    ),
                )
                .unwrap(),
            );
            vote
        })
        .collect();
    let availability =
        AvailabilityCertificate::from_votes(context.root().unwrap(), vertex_id, votes, 5).unwrap();

    let recovery = NativeProcessingProgressRecovery {
        source: &source,
        reveal_parent: None,
        dag_parents: &[],
    };
    let mut progress = ProcessingProgressEvidence::from_vertex(&vertex);
    recovery
        .verify_progress(&context, &vertex.admission, &progress, &budget)
        .unwrap();
    progress.availability = Some(availability);
    recovery
        .verify_progress(&context, &vertex.admission, &progress, &budget)
        .unwrap();
    let mut wrong_wallet = vertex.admission.clone();
    wrong_wallet.request.signature[0] ^= 1;
    assert!(recovery
        .verify_progress(&context, &wrong_wallet, &progress, &budget)
        .is_err());
    let mut wrong_author = progress.clone();
    wrong_author.author_signature[0] ^= 1;
    assert!(recovery
        .verify_progress(&context, &vertex.admission, &wrong_author, &budget)
        .is_err());
    let mut missing = progress.clone();
    missing.availability = None;
    missing.shares.push(ProcessingDecryptShare {
        share_version: 1,
        permission: ProcessingRevealPermission {
            namespace_root: digest("namespace"),
            group_number: 1,
            group_root: digest("group"),
            successor_root: digest("successor"),
            processing_context_root: context.root().unwrap(),
            envelope_id: vertex.admission.request.envelope.envelope_id.clone(),
            parent_block_id: "a".repeat(64),
            validation_id: "b".repeat(64),
        },
        validator_id: prepared.ids[0].clone(),
        key_id: "consensus-0".into(),
        ingress_kem_key_id: "ingress-0".into(),
        share_index: 1,
        share_commitment: digest("share"),
        share_bytes: vec![1],
        signature: vec![1],
    });
    assert_eq!(
        recovery
            .verify_progress(&context, &vertex.admission, &missing, &budget)
            .unwrap_err(),
        "processing reveal lacks native availability"
    );
    missing.shares.clear();
    let vc_context =
        synergy_posy::ConsensusObjectContext::for_height(&authority.epoch, 1, 0).unwrap();
    missing.reveal_validation = Some(synergy_posy::ProposalValidationCertificate {
        context: vc_context.clone(),
        candidate: synergy_posy::CertifiedCandidateSubject {
            context: vc_context,
            block_id: "a".repeat(64),
            parent_block_id: "b".repeat(64),
            parent: authority.anchor_parent.clone(),
            protected_execution_root: "c".repeat(64),
        },
        echoes: vec![],
    });
    assert_eq!(
        recovery
            .verify_progress(&context, &vertex.admission, &missing, &budget)
            .unwrap_err(),
        "processing reveal lacks native availability"
    );
    // Exercise the production ready-identity eligibility boundary independently
    // of group selection; these record fields supply no completion capability.
    let parent = NativeProcessingParent::genesis(&genesis, &authority).unwrap();
    let carrier = transaction.identity_authorization.as_ref().unwrap();
    let binding = synergy_identity::authorization::canonical_binding_commitment_if_present(
        &world.protocol,
        &transaction.unsigned.sender,
    )
    .unwrap()
    .unwrap();
    let ready = synergy_execution::ProcessingReadyRecord {
        item: synergy_etdag::execution::ProcessingReadyItem {
            group_number: 1,
            group_root: digest("group"),
            order_position: 0,
            envelope_id: vertex.admission.request.envelope.envelope_id.clone(),
            payload_root: digest("payload"),
            readiness_root: digest("readiness"),
            gas_class_units: 21000,
            encoded_bytes: 1,
            remaining_dependencies: vec![],
        },
        processing_context_root: context.root().unwrap(),
        authorization_root: digest("authorization"),
        sender_wallet: transaction.unsigned.sender.clone(),
        sender_nonce: 0,
    };
    let eligible =
        |record: &synergy_execution::ProcessingReadyRecord,
         commitment: &synergy_identity::authorization::IdentityAuthorizationBindingCommitment,
         identity: &synergy_identity::authorization::IdentityAuthorizationCarrier,
         network: &str| {
            parent
                .identity_is_current(
                    record,
                    commitment,
                    identity,
                    1266,
                    network,
                    &transaction.signer_public_key,
                )
                .unwrap()
        };
    assert!(
        eligible(&ready, &binding, carrier, "socket-qualification"),
        "authenticated APQE identity must remain eligible after ready publication"
    );
    assert!(!eligible(&ready, &binding, carrier, "foreign-network"));
    let mut wrong_address = ready.clone();
    wrong_address.sender_wallet = transaction.unsigned.receiver.clone();
    assert!(!eligible(
        &wrong_address,
        &binding,
        carrier,
        "socket-qualification"
    ));
    let mut stale = binding.clone();
    stale.binding_payload_sha3_256 = "0".repeat(64);
    assert!(!eligible(&ready, &stale, carrier, "socket-qualification"));
    let mut altered = carrier.clone();
    let original = altered.binding.proofs.identity_root.signature.as_bytes()[0];
    altered
        .binding
        .proofs
        .identity_root
        .signature
        .replace_range(..1, if original == b'0' { "1" } else { "0" });
    assert!(!eligible(
        &ready,
        &binding,
        &altered,
        "socket-qualification"
    ));
    let mut revoked = carrier.clone();
    revoked.binding.authorization_policy.principals[0].status =
        synergy_identity::authorization::BindingStatus::Retired;
    assert!(!eligible(
        &ready,
        &binding,
        &revoked,
        "socket-qualification"
    ));
}

#[path = "socket_qualification_secure.rs"]
mod secure_process_canary;
use secure_process_canary::{finalize_secure_fixture, hex_decode};
