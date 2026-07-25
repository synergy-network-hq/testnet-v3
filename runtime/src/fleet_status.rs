use crate::cluster::{fault_tolerance_f, quorum_threshold};
use crate::synergy_types::{SYNERGY_TESTNET_V3_CHAIN_ID, SYNERGY_TESTNET_V3_NETWORK_ID};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FleetStatusSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetStatusFinding {
    pub code: String,
    pub severity: FleetStatusSeverity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetStatusSnapshot {
    pub chain_id: Option<u64>,
    pub network_id: Option<String>,
    #[serde(default)]
    pub validators: Vec<FleetValidatorSnapshot>,
    #[serde(default)]
    pub public_rpc_backends: Vec<FleetBackendSnapshot>,
    pub atlas: Option<FleetBackendSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetValidatorSnapshot {
    pub validator_id: String,
    #[serde(default)]
    pub cluster_id: u64,
    pub status: String,
    pub height: Option<u64>,
    pub block_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetBackendSnapshot {
    pub name: String,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub cluster_id: Option<u64>,
    #[serde(default = "default_available")]
    pub available: bool,
    pub height: Option<u64>,
    pub block_hash: Option<String>,
    #[serde(default)]
    pub latest_finalized_height: Option<u64>,
    #[serde(default)]
    pub latest_finalized_hash: Option<String>,
    #[serde(default)]
    pub latest_observed_height: Option<u64>,
    #[serde(default)]
    pub latest_observed_hash: Option<String>,
    #[serde(default)]
    pub config_digest: Option<String>,
    #[serde(default)]
    pub validator_set_digest: Option<String>,
    #[serde(default)]
    pub binary_digest: Option<String>,
    #[serde(default)]
    pub lifecycle_state: Option<String>,
    #[serde(default)]
    pub qrpc_status: Option<String>,
    #[serde(default)]
    pub timed_out: bool,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub archive_contained: bool,
    #[serde(default)]
    pub minority_fork: bool,
    #[serde(default)]
    pub synthetic_height: bool,
    #[serde(default)]
    pub lag_tolerance_blocks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetClusterStatus {
    pub cluster_id: u64,
    pub validator_count: usize,
    pub active_validator_count: usize,
    pub fault_tolerance_f: usize,
    pub quorum_threshold: usize,
    pub can_finalize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetBackendConfidenceReport {
    pub backend_id: String,
    pub backend_role: String,
    pub cluster_id: Option<u64>,
    pub latest_finalized_height: Option<u64>,
    pub latest_finalized_hash: Option<String>,
    pub latest_observed_height: Option<u64>,
    pub latest_observed_hash: Option<String>,
    pub config_digest: Option<String>,
    pub validator_set_digest: Option<String>,
    pub binary_digest: Option<String>,
    pub lifecycle_state: Option<String>,
    pub qrpc_status: Option<String>,
    pub lag_blocks: Option<u64>,
    pub hash_agreement_status: String,
    pub canonical_confidence: String,
    pub trusted_for_public_reads: bool,
    pub trusted_for_repair: bool,
    pub stale_reason: Option<String>,
    pub minority_reason: Option<String>,
    pub quarantined_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetPublicSurfaceSummary {
    pub cluster_count: usize,
    pub validator_count: usize,
    pub active_validator_count: usize,
    pub clusters: Vec<FleetClusterStatus>,
    pub trusted_public_read_backend_count: usize,
    pub trusted_repair_backend_count: usize,
    pub ambiguous_public_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FleetStatusReport {
    pub ok: bool,
    pub decision: String,
    pub strict: bool,
    pub canonical_height: Option<u64>,
    pub canonical_hash: Option<String>,
    pub validator_count: usize,
    pub active_validator_count: usize,
    pub cluster_count: usize,
    pub clusters: Vec<FleetClusterStatus>,
    pub backend_confidence: Vec<FleetBackendConfidenceReport>,
    pub public_surface_summary: FleetPublicSurfaceSummary,
    pub findings: Vec<FleetStatusFinding>,
}

pub fn evaluate_fleet_status(snapshot: &FleetStatusSnapshot, strict: bool) -> FleetStatusReport {
    let mut findings = Vec::new();

    if snapshot.chain_id != Some(SYNERGY_TESTNET_V3_CHAIN_ID) {
        findings.push(error(
            "chain_id_mismatch",
            format!(
                "expected chain_id {} but snapshot has {:?}",
                SYNERGY_TESTNET_V3_CHAIN_ID, snapshot.chain_id
            ),
        ));
    }
    if snapshot.network_id.as_deref() != Some(SYNERGY_TESTNET_V3_NETWORK_ID) {
        findings.push(error(
            "network_id_mismatch",
            format!(
                "expected network_id {} but snapshot has {:?}",
                SYNERGY_TESTNET_V3_NETWORK_ID, snapshot.network_id
            ),
        ));
    }
    if snapshot.validators.is_empty() {
        findings.push(error(
            "validators_empty",
            "fleet snapshot has no validators",
        ));
    }

    let mut clusters = BTreeMap::<u64, Vec<&FleetValidatorSnapshot>>::new();
    for validator in &snapshot.validators {
        clusters
            .entry(validator.cluster_id)
            .or_default()
            .push(validator);
    }

    let mut cluster_reports = Vec::new();
    for (cluster_id, validators) in clusters {
        let validator_count = validators.len();
        let active_validator_count = validators
            .iter()
            .filter(|validator| validator_is_active(&validator.status))
            .count();
        let quorum = quorum_threshold(validator_count);
        let can_finalize = active_validator_count >= quorum && validator_count > 0;
        if !can_finalize {
            findings.push(error(
                "cluster_quorum_unavailable",
                format!(
                    "cluster {cluster_id} has {active_validator_count}/{validator_count} active validators; quorum requires {quorum}"
                ),
            ));
        }
        if strict && active_validator_count != validator_count {
            findings.push(error(
                "strict_validator_inactive",
                format!(
                    "cluster {cluster_id} strict mode requires all {validator_count} validators active"
                ),
            ));
        }
        cluster_reports.push(FleetClusterStatus {
            cluster_id,
            validator_count,
            active_validator_count,
            fault_tolerance_f: fault_tolerance_f(validator_count),
            quorum_threshold: quorum,
            can_finalize,
        });
    }

    let canonical = canonical_validator_head(&snapshot.validators, strict, &mut findings);
    let canonical_quorum_proven =
        canonical_validator_quorum_proven(&snapshot.validators, canonical.as_ref());
    validate_backends(
        &snapshot.public_rpc_backends,
        canonical.as_ref(),
        strict,
        &mut findings,
    );
    if let Some(atlas) = snapshot.atlas.as_ref() {
        validate_backend(atlas, canonical.as_ref(), strict, &mut findings);
    } else if strict {
        findings.push(error(
            "atlas_missing",
            "strict mode requires Atlas backend evidence",
        ));
    }
    let public_response_ambiguous = detect_public_backend_ambiguity(
        snapshot,
        canonical.as_ref(),
        canonical_quorum_proven,
        &mut findings,
    );
    let backend_confidence =
        backend_confidence_reports(snapshot, canonical.as_ref(), canonical_quorum_proven);

    let errors = findings
        .iter()
        .any(|finding| finding.severity == FleetStatusSeverity::Error);
    let active_validator_count = snapshot
        .validators
        .iter()
        .filter(|validator| validator_is_active(&validator.status))
        .count();
    FleetStatusReport {
        ok: !errors,
        decision: if errors { "NO_GO" } else { "GO" }.to_string(),
        strict,
        canonical_height: canonical.as_ref().map(|head| head.0),
        canonical_hash: canonical.as_ref().map(|head| head.1.clone()),
        validator_count: snapshot.validators.len(),
        active_validator_count,
        cluster_count: cluster_reports.len(),
        clusters: cluster_reports.clone(),
        public_surface_summary: FleetPublicSurfaceSummary {
            cluster_count: cluster_reports.len(),
            validator_count: snapshot.validators.len(),
            active_validator_count,
            clusters: cluster_reports,
            trusted_public_read_backend_count: backend_confidence
                .iter()
                .filter(|backend| backend.trusted_for_public_reads)
                .count(),
            trusted_repair_backend_count: backend_confidence
                .iter()
                .filter(|backend| backend.trusted_for_repair)
                .count(),
            ambiguous_public_response: public_response_ambiguous,
        },
        backend_confidence,
        findings,
    }
}

fn canonical_validator_head(
    validators: &[FleetValidatorSnapshot],
    strict: bool,
    findings: &mut Vec<FleetStatusFinding>,
) -> Option<(u64, String)> {
    let mut heads = BTreeMap::<(u64, String), usize>::new();
    for validator in validators
        .iter()
        .filter(|validator| validator_is_active(&validator.status))
    {
        let Some(height) = validator.height else {
            findings.push(error(
                "active_validator_missing_height",
                format!("active validator {} has no height", validator.validator_id),
            ));
            continue;
        };
        let Some(hash) = validator
            .block_hash
            .as_ref()
            .filter(|hash| !hash.is_empty())
        else {
            findings.push(error(
                "active_validator_missing_hash",
                format!(
                    "active validator {} has no block hash",
                    validator.validator_id
                ),
            ));
            continue;
        };
        *heads.entry((height, hash.clone())).or_default() += 1;
    }
    let canonical = heads
        .iter()
        .max_by_key(|((_height, _hash), count)| *count)
        .map(|(head, _count)| head.clone());
    if strict && heads.len() > 1 {
        findings.push(error(
            "strict_validator_head_mismatch",
            format!("strict mode found {} active validator heads", heads.len()),
        ));
    }
    canonical
}

fn canonical_validator_quorum_proven(
    validators: &[FleetValidatorSnapshot],
    canonical: Option<&(u64, String)>,
) -> bool {
    let Some((height, hash)) = canonical else {
        return false;
    };
    let mut clusters = BTreeMap::<u64, (usize, usize)>::new();
    for validator in validators {
        let entry = clusters.entry(validator.cluster_id).or_default();
        entry.0 += 1;
        if validator_is_active(&validator.status)
            && validator.height == Some(*height)
            && validator.block_hash.as_deref() == Some(hash.as_str())
        {
            entry.1 += 1;
        }
    }
    !clusters.is_empty()
        && clusters.values().all(|(validator_count, matching_count)| {
            *matching_count >= quorum_threshold(*validator_count)
        })
}

fn validate_backends(
    backends: &[FleetBackendSnapshot],
    canonical: Option<&(u64, String)>,
    strict: bool,
    findings: &mut Vec<FleetStatusFinding>,
) {
    if strict && backends.is_empty() {
        findings.push(error(
            "public_rpc_backends_missing",
            "strict mode requires at least one public RPC backend",
        ));
    }
    for backend in backends {
        validate_backend(backend, canonical, strict, findings);
    }
}

fn validate_backend(
    backend: &FleetBackendSnapshot,
    canonical: Option<&(u64, String)>,
    strict: bool,
    findings: &mut Vec<FleetStatusFinding>,
) {
    if backend.timed_out {
        findings.push(warning(
            "backend_timeout_surface_jitter",
            format!(
                "{} timed out; excluding it from public-read confidence without treating it as chain failure",
                backend.name
            ),
        ));
        return;
    }
    if !backend.available {
        findings.push(error(
            "backend_unavailable",
            format!("{} is unavailable", backend.name),
        ));
        return;
    }
    if backend.quarantined {
        findings.push(error(
            "backend_quarantined",
            format!("{} is quarantined and cannot be trusted", backend.name),
        ));
    }
    if backend.minority_fork {
        findings.push(error(
            "backend_minority_fork",
            format!("{} is marked as minority-fork evidence", backend.name),
        ));
    }
    if backend.synthetic_height {
        findings.push(error(
            "backend_synthetic_height",
            format!("{} reported a synthetic height", backend.name),
        ));
    }
    let Some((canonical_height, canonical_hash)) = canonical else {
        findings.push(error(
            "canonical_head_unavailable",
            format!(
                "cannot verify {} without canonical validator head",
                backend.name
            ),
        ));
        return;
    };
    let Some(height) = backend_finalized_height(backend) else {
        findings.push(error(
            "backend_missing_height",
            format!("{} has no height", backend.name),
        ));
        return;
    };
    let Some(hash) = backend_finalized_hash(backend) else {
        findings.push(error(
            "backend_missing_hash",
            format!("{} has no block hash", backend.name),
        ));
        return;
    };
    let lag = canonical_height.saturating_sub(height);
    if height > *canonical_height {
        findings.push(error(
            "backend_ahead_of_canonical",
            format!(
                "{} reports h{} above canonical validator height h{}",
                backend.name, height, canonical_height
            ),
        ));
    } else if strict && lag > backend.lag_tolerance_blocks {
        findings.push(error(
            "backend_lag_exceeds_tolerance",
            format!(
                "{} lags canonical validator height by {lag} blocks; tolerance is {}",
                backend.name, backend.lag_tolerance_blocks
            ),
        ));
    }
    if height == *canonical_height && hash != canonical_hash {
        findings.push(error(
            "backend_hash_mismatch",
            format!(
                "{} hash {} at h{} does not match canonical hash {}",
                backend.name, hash, height, canonical_hash
            ),
        ));
    }
}

fn detect_public_backend_ambiguity(
    snapshot: &FleetStatusSnapshot,
    canonical: Option<&(u64, String)>,
    canonical_quorum_proven: bool,
    findings: &mut Vec<FleetStatusFinding>,
) -> bool {
    let mut heads = BTreeMap::<u64, BTreeMap<String, Vec<String>>>::new();
    for surface in public_surface_backends(snapshot) {
        let backend = surface.backend;
        if !backend.available
            || backend.timed_out
            || backend.synthetic_height
            || backend.quarantined
            || backend.minority_fork
        {
            continue;
        }
        let Some(height) = backend_finalized_height(backend) else {
            continue;
        };
        let Some(hash) = backend_finalized_hash(backend) else {
            continue;
        };
        heads
            .entry(height)
            .or_default()
            .entry(hash.clone())
            .or_default()
            .push(backend_identity(backend));
    }

    let mut ambiguous = false;
    for (height, hashes) in heads {
        if hashes.len() <= 1 {
            continue;
        }
        ambiguous = true;
        if canonical.is_none() || !canonical_quorum_proven {
            findings.push(error(
                "public_backend_ambiguous_without_quorum_proof",
                format!(
                    "public backends report {} hashes at h{} without validator quorum proof",
                    hashes.len(),
                    height
                ),
            ));
        } else {
            findings.push(warning(
                "public_backend_ambiguous_with_quorum_proof",
                format!(
                    "public backends report {} hashes at h{}; validator quorum proof selects the canonical head",
                    hashes.len(),
                    height
                ),
            ));
        }
    }
    ambiguous
}

fn backend_confidence_reports(
    snapshot: &FleetStatusSnapshot,
    canonical: Option<&(u64, String)>,
    canonical_quorum_proven: bool,
) -> Vec<FleetBackendConfidenceReport> {
    public_surface_backends(snapshot)
        .into_iter()
        .map(|surface| {
            backend_confidence_report(
                surface.backend,
                surface.default_role,
                canonical,
                canonical_quorum_proven,
            )
        })
        .collect()
}

fn backend_confidence_report(
    backend: &FleetBackendSnapshot,
    default_role: &'static str,
    canonical: Option<&(u64, String)>,
    canonical_quorum_proven: bool,
) -> FleetBackendConfidenceReport {
    let role = backend_role(backend, default_role);
    let finalized_height = backend_finalized_height(backend);
    let finalized_hash = backend_finalized_hash(backend).cloned();
    let observed_height = backend.latest_observed_height.or(finalized_height);
    let observed_hash = backend
        .latest_observed_hash
        .as_ref()
        .filter(|hash| !hash.is_empty())
        .cloned()
        .or_else(|| finalized_hash.clone());
    let lag_blocks = canonical.and_then(|(canonical_height, _hash)| {
        finalized_height.map(|height| canonical_height.saturating_sub(height))
    });

    let mut stale_reason = None;
    let mut minority_reason = None;
    let mut quarantined_reason = None;
    let (hash_agreement_status, canonical_confidence) = backend_confidence_status(
        backend,
        canonical,
        canonical_quorum_proven,
        finalized_height,
        finalized_hash.as_deref(),
        lag_blocks,
        &mut stale_reason,
        &mut minority_reason,
        &mut quarantined_reason,
    );
    let trusted_candidate = matches!(hash_agreement_status.as_str(), "matches_canonical")
        && canonical_quorum_proven
        && !backend.timed_out
        && backend.available
        && !backend.synthetic_height
        && !backend.quarantined
        && !backend.archive_contained
        && !backend.minority_fork;
    let public_role = matches!(role.as_str(), "public_rpc" | "atlas" | "rpc_gateway");
    let repair_role = matches!(
        role.as_str(),
        "validator" | "validator_peer" | "canonical_validator"
    );

    FleetBackendConfidenceReport {
        backend_id: backend_identity(backend),
        backend_role: role,
        cluster_id: backend.cluster_id,
        latest_finalized_height: finalized_height,
        latest_finalized_hash: finalized_hash,
        latest_observed_height: observed_height,
        latest_observed_hash: observed_hash,
        config_digest: backend.config_digest.clone(),
        validator_set_digest: backend.validator_set_digest.clone(),
        binary_digest: backend.binary_digest.clone(),
        lifecycle_state: backend.lifecycle_state.clone(),
        qrpc_status: backend
            .qrpc_status
            .clone()
            .or_else(|| backend.timed_out.then(|| "timeout".to_string())),
        lag_blocks,
        hash_agreement_status,
        canonical_confidence,
        trusted_for_public_reads: public_role && trusted_candidate,
        trusted_for_repair: repair_role
            && trusted_candidate
            && backend.config_digest.is_some()
            && backend.validator_set_digest.is_some()
            && backend.binary_digest.is_some(),
        stale_reason,
        minority_reason,
        quarantined_reason,
    }
}

#[allow(clippy::too_many_arguments)]
fn backend_confidence_status(
    backend: &FleetBackendSnapshot,
    canonical: Option<&(u64, String)>,
    canonical_quorum_proven: bool,
    finalized_height: Option<u64>,
    finalized_hash: Option<&str>,
    lag_blocks: Option<u64>,
    stale_reason: &mut Option<String>,
    minority_reason: &mut Option<String>,
    quarantined_reason: &mut Option<String>,
) -> (String, String) {
    if backend.timed_out {
        return (
            "timeout".to_string(),
            "excluded_timeout_surface_jitter".to_string(),
        );
    }
    if !backend.available {
        return (
            "unavailable".to_string(),
            "excluded_unavailable".to_string(),
        );
    }
    if backend.quarantined {
        *quarantined_reason = Some("backend is quarantined".to_string());
        return (
            "quarantined".to_string(),
            "excluded_quarantined".to_string(),
        );
    }
    if backend.archive_contained {
        *quarantined_reason = Some("backend is archive-contained".to_string());
        return (
            "archive_contained".to_string(),
            "excluded_archive_contained".to_string(),
        );
    }
    if backend.minority_fork {
        *minority_reason = Some("backend is marked as minority-fork evidence".to_string());
        return ("minority_fork".to_string(), "excluded_minority".to_string());
    }
    if backend.synthetic_height {
        return (
            "synthetic_height".to_string(),
            "excluded_synthetic_height".to_string(),
        );
    }
    let Some((canonical_height, canonical_hash)) = canonical else {
        return (
            "unverified".to_string(),
            "ambiguous_no_quorum_proof".to_string(),
        );
    };
    if !canonical_quorum_proven {
        return (
            "unverified".to_string(),
            "ambiguous_no_quorum_proof".to_string(),
        );
    }
    let Some(height) = finalized_height else {
        return (
            "missing_height".to_string(),
            "excluded_missing_evidence".to_string(),
        );
    };
    let Some(hash) = finalized_hash else {
        return (
            "missing_hash".to_string(),
            "excluded_missing_evidence".to_string(),
        );
    };
    if height > *canonical_height {
        *minority_reason = Some(format!(
            "backend reports h{} ahead of canonical h{}",
            height, canonical_height
        ));
        return (
            "ahead_of_canonical".to_string(),
            "excluded_minority".to_string(),
        );
    }
    if height < *canonical_height {
        let lag = lag_blocks.unwrap_or_else(|| canonical_height.saturating_sub(height));
        if lag > backend.lag_tolerance_blocks {
            *stale_reason = Some(format!(
                "backend lags canonical h{} by {lag} blocks; tolerance is {}",
                canonical_height, backend.lag_tolerance_blocks
            ));
            return ("stale".to_string(), "excluded_stale".to_string());
        }
        return (
            "lagging_within_tolerance".to_string(),
            "low_confidence_lagging".to_string(),
        );
    }
    if hash != canonical_hash {
        *minority_reason = Some(format!(
            "backend hash {} at h{} does not match canonical hash {}",
            hash, height, canonical_hash
        ));
        return ("hash_mismatch".to_string(), "excluded_minority".to_string());
    }
    (
        "matches_canonical".to_string(),
        "canonical_quorum_proven".to_string(),
    )
}

#[derive(Debug, Clone, Copy)]
struct FleetSurfaceBackend<'a> {
    backend: &'a FleetBackendSnapshot,
    default_role: &'static str,
}

fn public_surface_backends(snapshot: &FleetStatusSnapshot) -> Vec<FleetSurfaceBackend<'_>> {
    let mut backends = Vec::new();
    backends.extend(
        snapshot
            .public_rpc_backends
            .iter()
            .map(|backend| FleetSurfaceBackend {
                backend,
                default_role: "public_rpc",
            }),
    );
    if let Some(atlas) = snapshot.atlas.as_ref() {
        backends.push(FleetSurfaceBackend {
            backend: atlas,
            default_role: "atlas",
        });
    }
    backends
}

fn backend_identity(backend: &FleetBackendSnapshot) -> String {
    backend
        .backend_id
        .as_ref()
        .filter(|backend_id| !backend_id.is_empty())
        .cloned()
        .unwrap_or_else(|| backend.name.clone())
}

fn backend_role(backend: &FleetBackendSnapshot, default_role: &'static str) -> String {
    let role = backend.role.trim();
    if role.is_empty() {
        default_role.to_string()
    } else {
        role.to_ascii_lowercase()
    }
}

fn backend_finalized_height(backend: &FleetBackendSnapshot) -> Option<u64> {
    backend.latest_finalized_height.or(backend.height)
}

fn backend_finalized_hash(backend: &FleetBackendSnapshot) -> Option<&String> {
    backend
        .latest_finalized_hash
        .as_ref()
        .filter(|hash| !hash.is_empty())
        .or_else(|| backend.block_hash.as_ref().filter(|hash| !hash.is_empty()))
}

fn validator_is_active(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "active" | "validatorstatus::active"
    )
}

fn default_available() -> bool {
    true
}

fn error(code: impl Into<String>, detail: impl Into<String>) -> FleetStatusFinding {
    FleetStatusFinding {
        code: code.into(),
        severity: FleetStatusSeverity::Error,
        detail: detail.into(),
    }
}

fn warning(code: impl Into<String>, detail: impl Into<String>) -> FleetStatusFinding {
    FleetStatusFinding {
        code: code.into(),
        severity: FleetStatusSeverity::Warning,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator(id: &str, cluster_id: u64, height: u64, hash: &str) -> FleetValidatorSnapshot {
        FleetValidatorSnapshot {
            validator_id: id.to_string(),
            cluster_id,
            status: "active".to_string(),
            height: Some(height),
            block_hash: Some(hash.to_string()),
        }
    }

    fn backend(name: &str, height: u64, hash: &str) -> FleetBackendSnapshot {
        FleetBackendSnapshot {
            name: name.to_string(),
            backend_id: Some(name.to_string()),
            role: "public_rpc".to_string(),
            cluster_id: Some(0),
            available: true,
            height: Some(height),
            block_hash: Some(hash.to_string()),
            latest_finalized_height: None,
            latest_finalized_hash: None,
            latest_observed_height: None,
            latest_observed_hash: None,
            config_digest: Some("config-digest".to_string()),
            validator_set_digest: Some("validator-set-digest".to_string()),
            binary_digest: Some("binary-digest".to_string()),
            lifecycle_state: Some("active".to_string()),
            qrpc_status: Some("healthy".to_string()),
            timed_out: false,
            quarantined: false,
            archive_contained: false,
            minority_fork: false,
            synthetic_height: false,
            lag_tolerance_blocks: 0,
        }
    }

    fn valid_snapshot() -> FleetStatusSnapshot {
        FleetStatusSnapshot {
            chain_id: Some(SYNERGY_TESTNET_V3_CHAIN_ID),
            network_id: Some(SYNERGY_TESTNET_V3_NETWORK_ID.to_string()),
            validators: vec![
                validator("validator-1", 0, 100, "hash-100"),
                validator("validator-2", 0, 100, "hash-100"),
                validator("validator-3", 0, 100, "hash-100"),
                validator("validator-4", 0, 100, "hash-100"),
            ],
            public_rpc_backends: vec![backend("public-rpc", 100, "hash-100")],
            atlas: Some(backend("atlas", 100, "hash-100")),
        }
    }

    fn finding_codes(report: &FleetStatusReport) -> Vec<String> {
        report
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect()
    }

    #[test]
    fn strict_fleet_status_accepts_dynamic_four_validator_cluster() {
        let report = evaluate_fleet_status(&valid_snapshot(), true);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.validator_count, 4);
        assert_eq!(report.clusters[0].quorum_threshold, 3);
        assert_eq!(report.canonical_height, Some(100));
        assert_eq!(report.backend_confidence.len(), 2);
        assert_eq!(report.public_surface_summary.cluster_count, 1);
        assert_eq!(
            report
                .public_surface_summary
                .trusted_public_read_backend_count,
            2
        );
    }

    #[test]
    fn strict_fleet_status_rejects_backend_hash_mismatch() {
        let mut snapshot = valid_snapshot();
        snapshot.atlas = Some(backend("atlas", 100, "different-hash"));
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"backend_hash_mismatch".to_string()));
    }

    #[test]
    fn strict_fleet_status_rejects_synthetic_public_rpc_height() {
        let mut snapshot = valid_snapshot();
        snapshot.public_rpc_backends[0].synthetic_height = true;
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"backend_synthetic_height".to_string()));
    }

    #[test]
    fn strict_fleet_status_rejects_inactive_validator_even_when_quorum_exists() {
        let mut snapshot = valid_snapshot();
        snapshot.validators.push(FleetValidatorSnapshot {
            validator_id: "validator-5".to_string(),
            cluster_id: 0,
            status: "inactive".to_string(),
            height: Some(100),
            block_hash: Some("hash-100".to_string()),
        });
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"strict_validator_inactive".to_string()));
    }

    #[test]
    fn strict_fleet_status_rejects_multicluster_liveness_failure() {
        let mut snapshot = valid_snapshot();
        snapshot.validators.extend(vec![
            validator("validator-a", 1, 100, "hash-100"),
            FleetValidatorSnapshot {
                validator_id: "validator-b".to_string(),
                cluster_id: 1,
                status: "inactive".to_string(),
                height: Some(100),
                block_hash: Some("hash-100".to_string()),
            },
            FleetValidatorSnapshot {
                validator_id: "validator-c".to_string(),
                cluster_id: 1,
                status: "inactive".to_string(),
                height: Some(100),
                block_hash: Some("hash-100".to_string()),
            },
        ]);
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"cluster_quorum_unavailable".to_string()));
    }

    #[test]
    fn strict_fleet_status_excludes_stale_backend_confidence() {
        let mut snapshot = valid_snapshot();
        snapshot.public_rpc_backends[0] = backend("public-rpc", 98, "hash-98");
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"backend_lag_exceeds_tolerance".to_string()));
        let rpc = report
            .backend_confidence
            .iter()
            .find(|backend| backend.backend_id == "public-rpc")
            .expect("public-rpc confidence");
        assert_eq!(rpc.hash_agreement_status, "stale");
        assert!(!rpc.trusted_for_public_reads);
        assert!(rpc.stale_reason.is_some());
    }

    #[test]
    fn strict_fleet_status_excludes_minority_fork_backend() {
        let mut snapshot = valid_snapshot();
        snapshot.public_rpc_backends[0] = backend("public-rpc", 100, "minority-hash");
        snapshot.public_rpc_backends[0].minority_fork = true;
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(!report.ok);
        assert!(finding_codes(&report).contains(&"backend_minority_fork".to_string()));
        let rpc = report
            .backend_confidence
            .iter()
            .find(|backend| backend.backend_id == "public-rpc")
            .expect("public-rpc confidence");
        assert_eq!(rpc.hash_agreement_status, "minority_fork");
        assert!(!rpc.trusted_for_public_reads);
        assert!(rpc.minority_reason.is_some());
    }

    #[test]
    fn fleet_status_records_public_rpc_timeout_as_surface_jitter() {
        let mut snapshot = valid_snapshot();
        snapshot.public_rpc_backends[0].available = false;
        snapshot.public_rpc_backends[0].timed_out = true;
        snapshot.public_rpc_backends[0].height = None;
        snapshot.public_rpc_backends[0].block_hash = None;
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(report.ok, "{:?}", report.findings);
        assert!(finding_codes(&report).contains(&"backend_timeout_surface_jitter".to_string()));
        let rpc = report
            .backend_confidence
            .iter()
            .find(|backend| backend.backend_id == "public-rpc")
            .expect("public-rpc confidence");
        assert_eq!(rpc.hash_agreement_status, "timeout");
        assert_eq!(rpc.qrpc_status.as_deref(), Some("healthy"));
        assert!(!rpc.trusted_for_public_reads);
        assert_eq!(
            report
                .public_surface_summary
                .trusted_public_read_backend_count,
            1
        );
    }

    #[test]
    fn fleet_status_rejects_public_backend_ambiguity_without_quorum_proof() {
        let mut snapshot = valid_snapshot();
        snapshot.validators[0].block_hash = Some("validator-minority".to_string());
        snapshot.validators[1].block_hash = Some("validator-minority".to_string());
        snapshot.public_rpc_backends = vec![
            backend("public-rpc-a", 100, "hash-100"),
            backend("public-rpc-b", 100, "other-hash"),
        ];
        snapshot.atlas = None;
        let report = evaluate_fleet_status(&snapshot, false);
        assert!(!report.ok);
        assert!(report.public_surface_summary.ambiguous_public_response);
        assert!(finding_codes(&report)
            .contains(&"public_backend_ambiguous_without_quorum_proof".to_string()));
    }

    #[test]
    fn fleet_status_reports_two_clusters_independently() {
        let mut snapshot = valid_snapshot();
        snapshot.validators.extend(vec![
            validator("validator-a", 1, 100, "hash-100"),
            validator("validator-b", 1, 100, "hash-100"),
            validator("validator-c", 1, 100, "hash-100"),
            validator("validator-d", 1, 100, "hash-100"),
        ]);
        snapshot.public_rpc_backends[0].cluster_id = Some(0);
        let mut cluster_one_rpc = backend("public-rpc-cluster-1", 100, "hash-100");
        cluster_one_rpc.cluster_id = Some(1);
        snapshot.public_rpc_backends.push(cluster_one_rpc);
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(report.ok, "{:?}", report.findings);
        assert_eq!(report.cluster_count, 2);
        assert_eq!(report.public_surface_summary.cluster_count, 2);
        assert_eq!(report.public_surface_summary.clusters.len(), 2);
        assert!(report
            .backend_confidence
            .iter()
            .any(|backend| backend.cluster_id == Some(1)));
    }

    #[test]
    fn fleet_status_never_trusts_archive_contained_backend_for_repair() {
        let mut snapshot = valid_snapshot();
        let mut archive = backend("archive-contained", 100, "hash-100");
        archive.role = "archive".to_string();
        archive.archive_contained = true;
        snapshot.public_rpc_backends.push(archive);
        let report = evaluate_fleet_status(&snapshot, true);
        assert!(report.ok, "{:?}", report.findings);
        let archive = report
            .backend_confidence
            .iter()
            .find(|backend| backend.backend_id == "archive-contained")
            .expect("archive confidence");
        assert_eq!(archive.hash_agreement_status, "archive_contained");
        assert!(!archive.trusted_for_public_reads);
        assert!(!archive.trusted_for_repair);
        assert!(archive.quarantined_reason.is_some());
    }
}
