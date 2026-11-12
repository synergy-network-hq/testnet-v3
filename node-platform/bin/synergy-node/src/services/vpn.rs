use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use synergy_config::{NodeConfiguration, VpnMode};
use synergy_identity::{NodeAddress, PublicNodeIdentity};
use synergy_storage::NodeStorageLayout;
use synergy_transport_registry::{
    verify_snapshot, SignedTransportSnapshot, SnapshotAcceptance, SnapshotTrust,
    TransportSnapshotCache, MAX_SNAPSHOT_BYTES,
};

use super::authority::VerifiedAuthority;
use super::ingress::{AuthenticatedIngress, DialRequest};
use synergy_node_core::{
    CancellationToken, Criticality, ManagedService, RestartPolicy, ServiceHealth, ServiceId,
    ServiceReadiness, ServiceSpec,
};
use synergy_vpn::netbird::{CommandNetbirdDaemon, NetbirdDaemon};
use synergy_vpn::{evaluate_readiness, NetbirdStatus, VpnReadiness, VpnState};

const NETBIRD_BINARY_ENV: &str = "SYNERGY_NETBIRD_BINARY";
const MAX_PUBLIC_IDENTITY_BYTES: u64 = 64 * 1024;
const DIAL_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const OBSERVATION_INTERVAL: Duration = Duration::from_secs(1);

/// Owns health observation of an already provisioned NetBird overlay. Setup
/// credentials are intentionally never read by the node process.
pub fn registration(
    node: &NodeConfiguration,
    authority: Option<Arc<VerifiedAuthority>>,
    ingress: AuthenticatedIngress,
) -> Result<(ServiceSpec, Box<dyn ManagedService>), String> {
    let configuration = &node.vpn;
    if configuration.mode == VpnMode::Disabled {
        return Err("VPN service cannot be registered when VPN mode is disabled".into());
    }
    let interface = configuration
        .interface_name
        .clone()
        .ok_or_else(|| "VPN mode requires a configured interface name".to_string())?;
    if interface.trim().is_empty() {
        return Err("VPN interface name is empty".into());
    }
    let registry = configuration
        .signed_registry_path
        .clone()
        .ok_or_else(|| "VPN mode requires a signed transport registry path".to_string())?;
    let context = configuration
        .transport_context
        .as_ref()
        .ok_or("VPN mode requires an explicit selected transport context")?;
    let trust = SnapshotTrust::from_encoded_with_provider(
        configuration
            .attestation_public_key
            .as_deref()
            .ok_or("VPN mode requires a pinned transport attestation public key")?,
        configuration
            .provider_plan_sha256
            .clone()
            .ok_or("VPN mode requires a pinned transport provider-plan hash")?,
        synergy_transport_registry::SnapshotContext {
            network: context.network.clone(),
            registry_id: context.registry_id.clone(),
            chain_id: node.chain_id,
            network_id: node.network_id.clone(),
            release_id: context.release_id.clone(),
            protocol_version: context.protocol_version.clone(),
        },
        super::apqe_provider::load(node)?,
    )
    .map_err(|error| format!("construct pinned transport trust: {error}"))?;
    let identity_bytes = read_regular_bounded(
        &node.public_identity_path,
        MAX_PUBLIC_IDENTITY_BYTES,
        "public node identity",
    )?;
    let local_node_address = serde_json::from_slice::<PublicNodeIdentity>(&identity_bytes)
        .map_err(|error| format!("decode public node identity for VPN: {error}"))?
        .validate()
        .map_err(|error| format!("validate public node identity for VPN: {error:?}"))?
        .node_address;
    let active_identities = authority.map(|authority| {
        authority
            .registry
            .active()
            .map(|record| record.validator_id.clone())
            .collect::<Vec<_>>()
    });
    let layout = NodeStorageLayout::new(node.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let cache =
        TransportSnapshotCache::new(layout.peers().join("transport-registry-accepted.json"))
            .map_err(|error| format!("open transport generation cache: {error}"))?;
    Ok((
        ServiceSpec {
            id: ServiceId::new("vpn")?,
            dependencies: vec![ServiceId::new("identity")?, ServiceId::new("network")?],
            criticality: Criticality::Required,
            restart_policy: RestartPolicy::OnFailure { max_attempts: 3 },
        },
        Box::new(VpnService {
            mode: configuration.mode,
            interface,
            registry,
            trust,
            cache,
            acceptance: SnapshotAcceptance::default(),
            active_identities,
            local_node_address,
            ingress,
            last_dial: BTreeMap::new(),
            daemon: None,
            last_observation: None,
            state: VpnState::Disconnected,
            status: None,
            failure: None,
        }),
    ))
}

struct VpnService {
    mode: VpnMode,
    interface: String,
    registry: std::path::PathBuf,
    trust: SnapshotTrust,
    cache: TransportSnapshotCache,
    acceptance: SnapshotAcceptance,
    active_identities: Option<Vec<String>>,
    local_node_address: NodeAddress,
    ingress: AuthenticatedIngress,
    last_dial: BTreeMap<String, Instant>,
    daemon: Option<CommandNetbirdDaemon>,
    last_observation: Option<Instant>,
    state: VpnState,
    status: Option<NetbirdStatus>,
    failure: Option<String>,
}

fn read_regular_bounded(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
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
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{label} changed shape while loading"));
    }
    Ok(bytes)
}

// Registry signatures/generations and daemon health are fully rechecked on
// every observation. Dial retry scheduling remains independent on each tick.
fn observe_when_due(
    last: &mut Option<Instant>,
    now: Instant,
    observe: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    if last.is_some_and(|previous| now.duration_since(previous) < OBSERVATION_INTERVAL) {
        return Ok(());
    }
    observe()?;
    *last = Some(Instant::now());
    Ok(())
}

impl VpnService {
    fn coverage_for(&self, signed: &synergy_transport_registry::VerifiedSnapshot) -> Vec<String> {
        self.active_identities.clone().unwrap_or_else(|| {
            signed
                .registry()
                .routes()
                .map(|route| route.identity.clone())
                .collect()
        })
    }

    fn refresh_registry(&mut self) -> Result<(), String> {
        let bytes = read_regular_bounded(
            &self.registry,
            MAX_SNAPSHOT_BYTES as u64,
            "signed transport registry",
        )?;
        let signed: SignedTransportSnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode signed transport registry: {error}"))?;
        let verified = verify_snapshot(&signed, &self.trust)
            .map_err(|error| format!("verify signed transport registry: {error}"))?;
        let coverage = self.coverage_for(&verified);
        let installed = self
            .acceptance
            .install(verified, &coverage)
            .map_err(|error| format!("admit signed transport registry: {error}"))?;
        if installed.changed {
            self.cache
                .store(&signed)
                .map_err(|error| format!("persist accepted transport generation: {error}"))?;
            self.last_dial.clear();
        }
        let current = self
            .acceptance
            .current()
            .ok_or("accepted transport snapshot is missing")?
            .clone();
        self.ingress.install_verified_overlay(current)?;
        Ok(())
    }

    fn schedule_verified_dials(&mut self) -> Result<(), String> {
        let registry = self
            .acceptance
            .current()
            .ok_or("VPN has no verified transport registry")?
            .registry();
        let authenticated = self
            .ingress
            .authenticated_peers()?
            .into_iter()
            .collect::<BTreeSet<_>>();
        for route in registry.routes() {
            if route.identity == self.local_node_address.as_str()
                || authenticated.contains(&route.identity)
                || self
                    .active_identities
                    .as_ref()
                    .is_some_and(|active| !active.contains(&route.identity))
            {
                continue;
            }
            let now = Instant::now();
            if self
                .last_dial
                .get(&route.identity)
                .is_some_and(|last| now.duration_since(*last) < DIAL_RETRY_INTERVAL)
            {
                continue;
            }
            let address: SocketAddr = route
                .dial_address
                .parse()
                .map_err(|error| format!("invalid verified transport dial address: {error}"))?;
            self.ingress.request_dial(DialRequest {
                peer_id: route.identity.clone(),
                address,
            })?;
            self.last_dial.insert(route.identity.clone(), now);
        }
        Ok(())
    }

    fn refresh(&mut self) -> Result<(), String> {
        let daemon = self
            .daemon
            .as_ref()
            .ok_or_else(|| "NetBird daemon is not configured".to_string())?;
        let status = daemon.status()?;
        self.state = if status.connected {
            VpnState::Connected
        } else if status.management_connected || status.signal_connected {
            VpnState::Degraded
        } else {
            VpnState::Disconnected
        };
        self.status = Some(status);
        self.failure = None;
        Ok(())
    }

    fn required(&self) -> bool {
        self.mode == VpnMode::Required
    }
}

impl ManagedService for VpnService {
    fn start(&mut self, cancellation: &CancellationToken) -> Result<(), String> {
        if cancellation.is_cancelled() {
            return Err("VPN service start was cancelled".into());
        }
        if let Some(cached) = self
            .cache
            .load()
            .map_err(|error| format!("load accepted transport generation: {error}"))?
        {
            let verified = verify_snapshot(&cached, &self.trust)
                .map_err(|error| format!("verify cached transport generation: {error}"))?;
            let coverage = self.coverage_for(&verified);
            self.acceptance
                .install(verified, &coverage)
                .map_err(|error| format!("admit cached transport generation: {error}"))?;
        }
        self.refresh_registry()?;
        let binary = env::var(NETBIRD_BINARY_ENV)
            .map_err(|_| format!("{NETBIRD_BINARY_ENV} must name an absolute NetBird binary"))?;
        self.daemon = Some(CommandNetbirdDaemon::new(binary)?);
        if let Err(error) = self.refresh() {
            self.failure = Some(error.clone());
            if self.required() {
                return Err(error);
            }
        }
        self.last_observation = Some(Instant::now());
        if self.failure.is_none() && self.state == VpnState::Connected {
            self.schedule_verified_dials()?;
        }
        Ok(())
    }

    fn poll(&mut self) -> Result<(), String> {
        let mut last = self.last_observation;
        let result = observe_when_due(&mut last, Instant::now(), || {
            self.refresh_registry()?;
            self.refresh()
        });
        self.last_observation = last;
        if let Err(error) = result {
            self.failure = Some(error.clone());
            if self.required() {
                return Err(error);
            }
        }
        if self.failure.is_none() && self.state == VpnState::Connected {
            self.schedule_verified_dials()?;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), String> {
        self.last_observation = None;
        self.daemon = None;
        self.last_dial.clear();
        self.status = None;
        self.state = VpnState::Disconnected;
        Ok(())
    }

    fn health(&self) -> ServiceHealth {
        if self.acceptance.current().is_none() {
            return ServiceHealth::Unhealthy {
                reason: "signed validator transport registry is not verified".into(),
            };
        }
        if let Some(reason) = &self.failure {
            return if self.required() {
                ServiceHealth::Unhealthy {
                    reason: reason.clone(),
                }
            } else {
                ServiceHealth::Degraded {
                    reason: reason.clone(),
                }
            };
        }
        match evaluate_readiness(self.required(), self.state, self.status.as_ref()) {
            VpnReadiness::Ready => ServiceHealth::Healthy,
            VpnReadiness::Pending(reason) => ServiceHealth::Degraded { reason },
            VpnReadiness::Blocked(reason) => ServiceHealth::Unhealthy { reason },
        }
    }

    fn readiness(&self) -> ServiceReadiness {
        if let Some(reason) = &self.failure {
            return if self.required() {
                ServiceReadiness::Blocked {
                    reason: reason.clone(),
                }
            } else {
                ServiceReadiness::Pending {
                    reason: reason.clone(),
                }
            };
        }
        let mut readiness = evaluate_readiness(self.required(), self.state, self.status.as_ref());
        if !matches!(readiness, VpnReadiness::Ready) && self.interface.trim().is_empty() {
            readiness = VpnReadiness::Blocked("VPN interface name is empty".into());
        }
        match readiness {
            VpnReadiness::Ready => ServiceReadiness::Ready,
            VpnReadiness::Pending(reason) => ServiceReadiness::Pending { reason },
            VpnReadiness::Blocked(reason) => ServiceReadiness::Blocked { reason },
        }
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    #[test]
    fn runtime_ticks_do_not_repeat_status_process_and_due_failure_is_not_cached() {
        let mut last = None;
        let mut processes = 0;
        {
            let mut observe = || {
                let result = std::process::Command::new("/bin/sh")
                    .args(["-c", "exit 0"])
                    .status()
                    .map_err(|e| e.to_string())?;
                assert!(result.success());
                processes += 1;
                Ok(())
            };
            observe_when_due(&mut last, Instant::now(), &mut observe).unwrap();
            let initial = last.unwrap();
            for tick in 1..20 {
                observe_when_due(
                    &mut last,
                    initial + Duration::from_millis(tick * 50),
                    &mut observe,
                )
                .unwrap();
            }
            observe_when_due(&mut last, initial + OBSERVATION_INTERVAL, &mut observe).unwrap();
        }
        assert_eq!(processes, 2);
        let committed = last;
        let error = observe_when_due(&mut last, committed.unwrap() + OBSERVATION_INTERVAL, || {
            Err("fresh signed registry or NetBird status failed".into())
        })
        .unwrap_err();
        assert!(error.contains("failed"));
        assert_eq!(
            last, committed,
            "failed observation must not cache a success"
        );
    }
}
