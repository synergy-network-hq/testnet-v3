//! Proof-backed new-node synchronization. Public imports never authorize a vote.
use super::{
    apqe_transport::read,
    authority::{self, VerifiedAuthority},
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use synergy_config::NodeConfiguration;
use synergy_genesis::validator_admission::{
    MembershipAdmissionEvidence, VerifiedShadowValidatorAdmissions,
};
use synergy_posy::{FinalitySyncWitness, FinalizedBlockRecord};
const SOURCE: &str = "shadow-admission.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub version: u8,
    pub finalized: FinalizedBlockRecord,
    pub witness: FinalitySyncWitness,
    pub evidence: MembershipAdmissionEvidence,
}
fn root(config: &NodeConfiguration) -> Result<PathBuf, String> {
    Ok(
        synergy_storage::NodeStorageLayout::new(config.storage.data_directory.clone())
            .map_err(|e| e.to_string())?
            .consensus()
            .join("autonomous-epochs"),
    )
}
fn local(config: &NodeConfiguration) -> Result<String, String> {
    Ok(
        super::identity::load_public_identity(&config.public_identity_path, config.role)?
            .node_address
            .to_string(),
    )
}
fn verify(
    config: &NodeConfiguration,
    authority: &Arc<VerifiedAuthority>,
    source: &Source,
) -> Result<Arc<VerifiedAuthority>, String> {
    verify_source(config, authority, source, false)
}
fn verify_source(
    config: &NodeConfiguration,
    authority: &Arc<VerifiedAuthority>,
    source: &Source,
    certified_activation: bool,
) -> Result<Arc<VerifiedAuthority>, String> {
    if source.version != 1 {
        return Err("unsupported shadow source".into());
    }
    let mut current = authority.as_ref().clone();
    // This publishes no global cache: independently check the complete old-authority
    // World before using its governed policy and bonded synchronization record.
    let world = synergy_genesis::validator_admission::VerifiedValidatorAdmissionWorld::verify(
        &current.epoch,
        &current.registry,
        &source.finalized,
        &source.witness,
        &source.evidence,
        &current,
    )?;
    current.membership_retirement = Arc::new(std::sync::Mutex::new(None));
    current.validator_admissions = Arc::new(std::sync::Mutex::new(None));
    super::membership_retirement::refresh_finalized(
        &current,
        source.finalized.height,
        world.world(),
    )?;
    let retirement = current.pending_membership_retirement()?;
    let earned = VerifiedShadowValidatorAdmissions::verify(
        &current.epoch,
        &current.registry,
        current
            .protected_policy()
            .ok_or("shadow processing policy missing")?,
        current.authenticated_genesis_hash()?,
        &source.finalized,
        &source.witness,
        &source.evidence,
        retirement.as_deref(),
        &current,
    )?;
    let identity = local(config)?;
    let record = earned
        .records()
        .iter()
        .find(|r| r.validator_id == identity)
        .ok_or("local node lacks a finalized bonded shadow admission")?;
    let boundary = source
        .finalized
        .height
        .checked_add(3)
        .ok_or("shadow source height overflow")?;
    if source.finalized.height < record.eligible_finalized_height
        || (!certified_activation
            && (!current.epoch.contains_height(boundary)
                || (boundary - current.epoch.epoch_start_height)
                    % current.epoch.leader_lease_blocks
                    != 0))
        || (certified_activation
            && source.finalized.height != current.epoch.epoch_end_height.saturating_sub(2))
    {
        return Err(
            "shadow synchronization source must be an eligible certified lease-boundary snapshot"
                .into(),
        );
    }
    let selected = config
        .apqe_transport
        .as_ref()
        .ok_or("native shadow transport required")?;
    let enrollment = read(&selected.enrollment_path, 128 * 1024, false)?;
    let request: synergy_address_engine::validator_provisioning::EnrollmentRequest =
        serde_json::from_slice(&enrollment).map_err(|_| "invalid local enrollment")?;
    let bytes = |text: &str| -> Result<Vec<u8>, String> {
        if text.len() % 2 != 0 {
            return Err("invalid enrollment public bytes".into());
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|v| {
                u8::from_str_radix(
                    std::str::from_utf8(v).map_err(|_| "invalid public encoding")?,
                    16,
                )
                .map_err(|_| "invalid public encoding".into())
            })
            .collect()
    };
    if super::apqe_transport::sha256(&enrollment) != record.enrollment_sha256
        || request.payload.identity.address != identity
        || bytes(&request.payload.identity.consensus_key.public_key)? != record.consensus_public_key
        || bytes(&request.payload.identity.node_identity_key.public_key)?
            != record.transport_public_key
        || bytes(&request.payload.ingress_key.public_key)? != record.ingress_kem_public_key
    {
        return Err("shadow admission does not bind this local custody's public keys".into());
    }
    *current
        .validator_admissions
        .lock()
        .map_err(|_| "shadow admission cache poisoned")? =
        Some(Arc::new(earned.native_projection().clone()));
    Ok(Arc::new(current))
}
pub(super) fn attach(
    config: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
) -> Result<Arc<VerifiedAuthority>, String> {
    if authority.registry.active_validator(&local(config)?).is_ok() {
        return Ok(authority);
    }
    let path = root(config)?.join(SOURCE);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(authority);
    }
    let source: Source = serde_json::from_slice(&read(&path, 4 * 1024 * 1024, false)?)
        .map_err(|_| "invalid persisted shadow source")?;
    verify(config, &authority, &source)
}
/// The original admitted synchronization World remains an authenticated
/// bootstrap anchor after activation. It never becomes a fictitious E-height
/// finalized state merely because the current epoch's parent QC is at E.
pub(super) fn bootstrap_source(
    config: &NodeConfiguration,
    tip: &Arc<VerifiedAuthority>,
) -> Result<Option<(Arc<VerifiedAuthority>, Source)>, String> {
    let id = local(config)?;
    if tip.registry.active_validator(&id).is_ok()
        && tip
            .autonomous_processing_origin()
            .registry
            .active_validator(&id)
            .is_err()
    {
        let mut cursor = tip.clone();
        while cursor.epoch.epoch > 1 {
            let predecessor = cursor
                .authenticated_history_at(cursor.epoch.epoch_start_height.saturating_sub(1))
                .ok_or("bootstrap predecessor unavailable")?
                .clone();
            if predecessor.registry.active_validator(&id).is_err() {
                let path = root(config)?.join(format!("epoch-{:020}.json", cursor.epoch.epoch));
                let bytes = read(&path, 4 * 1024 * 1024, false)?;
                let earned = super::authority::recovery::successor::verify_next_derived_bytes(
                    predecessor.clone(),
                    &bytes,
                )?;
                if earned.epoch.root().map_err(|e| e.to_string())?
                    != cursor.epoch.root().map_err(|e| e.to_string())?
                {
                    return Err("bootstrap proof differs from certified history".into());
                }
                let proof: super::authority::recovery::successor::DerivedEpochProof =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                let source = Source {
                    version: 1,
                    finalized: proof.finalized,
                    witness: proof.witness,
                    evidence: proof
                        .membership_admissions
                        .ok_or("new active node lacks authenticated admission World")?,
                };
                let selected = verify_source(config, &predecessor, &source, true)?;
                let records = selected
                    .pending_validator_admissions()?
                    .ok_or("bootstrap admission projection missing")?;
                let record = records
                    .records()
                    .iter()
                    .find(|r| r.validator_id == id)
                    .ok_or("bootstrap local admission missing")?;
                if cursor
                    .registry
                    .active_validator(&id)
                    .map_err(|e| e.to_string())?
                    .consensus_key_id
                    != record.consensus_key_id
                {
                    return Err("bootstrap earned key differs from activated registry".into());
                }
                return Ok(Some((selected, source)));
            }
            cursor = predecessor;
        }
    }
    let path = root(config)?.join(SOURCE);
    if !path.try_exists().map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let source: Source = serde_json::from_slice(&read(&path, 4 * 1024 * 1024, false)?)
        .map_err(|_| "invalid retained bootstrap source")?;
    let original = tip
        .authenticated_history_at(source.finalized.height)
        .ok_or("bootstrap source lacks original authenticated epoch")?;
    let selected = verify(config, original, &source)?;
    Ok(Some((selected, source)))
}
pub(crate) fn is_local(
    config: &NodeConfiguration,
    authority: &VerifiedAuthority,
) -> Result<bool, String> {
    let id = local(config)?;
    if authority.registry.active_validator(&id).is_ok() {
        return Ok(false);
    }
    Ok(authority
        .pending_validator_admissions()?
        .is_some_and(|a| a.records().iter().any(|r| r.validator_id == id)))
}
pub(super) fn source(
    config: &NodeConfiguration,
    authority: &Arc<VerifiedAuthority>,
) -> Result<Option<Source>, String> {
    if !is_local(config, authority)? {
        return Ok(None);
    }
    let source: Source =
        serde_json::from_slice(&read(&root(config)?.join(SOURCE), 4 * 1024 * 1024, false)?)
            .map_err(|_| "invalid persisted shadow source")?;
    verify(config, authority, &source)?;
    Ok(Some(source))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chain {
    version: u32,
    origin_context_root: String,
    transitions: Vec<super::authority::recovery::successor::DerivedEpochProof>,
}
pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let mut args = args;
    let operation = args
        .next()
        .ok_or("validator-admission requires an exact closed operation")?;
    if matches!(operation.as_str(), "bootstrap" | "inspect-bootstrap") {
        return bootstrap(args, operation == "inspect-bootstrap");
    }
    let mut config = None;
    let mut proof = None;
    let mut owner = None;
    let mut platform_root = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(args.next().ok_or("missing config")?)),
            "--proof" => proof = Some(PathBuf::from(args.next().ok_or("missing public proof")?)),
            "--owner-wallet" => owner = Some(args.next().ok_or("missing owner wallet")?),
            "--root" => {
                platform_root = Some(PathBuf::from(args.next().ok_or("missing platform root")?))
            }
            _ => return Err("validator-admission accepts only --config and --proof".into()),
        }
    }
    let path = config.ok_or("installed configuration required")?;
    let proof = proof.ok_or("bounded public proof required")?;
    let _exclusive = if matches!(operation.as_str(), "status" | "import-status") {
        None
    } else {
        Some(super::checkpoint::lock_configuration(&path)?)
    };
    let config = synergy_config::load(&path).map_err(|e| e.to_string())?;
    if !matches!(operation.as_str(), "status" | "import-status") {
        super::checkpoint::require_stopped(&path, &config.admin_socket_path)?;
    }
    let mut authority =
        authority::load(&config)?.ok_or("original signed Genesis authority required")?;
    let raw = if proof == std::path::Path::new("-") {
        use std::io::Read;
        let mut bytes = vec![];
        std::io::stdin()
            .lock()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
            return Err("bounded public proof stdin required".into());
        }
        bytes
    } else {
        read(&proof, 4 * 1024 * 1024, false)?
    };
    if matches!(operation.as_str(), "prepare" | "status") {
        return prepare(
            &config,
            authority,
            &raw,
            owner.as_deref().ok_or("bond owner wallet required")?,
            &platform_root.ok_or("installed platform root required")?,
            operation == "status",
        );
    }
    if owner.is_some() || platform_root.is_some() {
        return Err("import operation does not accept authoring fields".into());
    }
    if operation == "import-status" {
        let value: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|_| "invalid exact public import input")?;
        let (kind, applied) = if value.get("transitions").is_some() {
            let chain: Chain =
                serde_json::from_slice(&raw).map_err(|_| "invalid original epoch page")?;
            let first = chain
                .transitions
                .first()
                .ok_or("empty original epoch page")?;
            let mut selected = authority
                .authenticated_history_at(first.authorization.finalized_height)
                .cloned()
                .ok_or("original epoch page lacks authenticated history")?;
            if chain.version != 1
                || chain.transitions.len() > 16
                || selected.epoch.root().map_err(|e| e.to_string())? != chain.origin_context_root
            {
                return Err("original page context mismatch".into());
            }
            let mut applied = true;
            for transition in chain.transitions {
                let epoch = transition.authorization.next_epoch;
                let bytes = serde_json::to_vec(&transition).map_err(|e| e.to_string())?;
                selected = super::authority::recovery::successor::verify_next_derived_bytes(
                    selected, &bytes,
                )?;
                let path = root(&config)?.join(format!("epoch-{epoch:020}.json"));
                if !path.try_exists().map_err(|e| e.to_string())?
                    || read(&path, 4 * 1024 * 1024, false)? != bytes
                {
                    applied = false;
                }
            }
            ("chain", applied)
        } else {
            let source: Source =
                serde_json::from_slice(&raw).map_err(|_| "invalid original shadow source")?;
            let selected = authority
                .authenticated_history_at(source.finalized.height)
                .cloned()
                .ok_or("original shadow source lacks history")?;
            verify(&config, &selected, &source)?;
            let path = root(&config)?.join(SOURCE);
            (
                "shadow",
                path.try_exists().map_err(|e| e.to_string())?
                    && read(&path, 4 * 1024 * 1024, false)?
                        == serde_json::to_vec(&source).map_err(|e| e.to_string())?,
            )
        };
        println!(
            "{}",
            serde_json::json!({"schema":"synergy-validator-admission-import-status-v1","kind":kind,"input_sha256":super::apqe_transport::sha256(&raw),"applied":applied,"mutation_performed":false,"consensus_started":false})
        );
        return Ok(());
    }
    let store = synergy_storage::AtomicStore::new(root(&config)?, 4 * 1024 * 1024)
        .map_err(|e| e.to_string())?;
    match operation.as_str() {
        "import-chain" => {
            let chain: Chain =
                serde_json::from_slice(&raw).map_err(|_| "invalid native epoch proof page")?;
            if chain.version != 1 || chain.transitions.is_empty() || chain.transitions.len() > 16 {
                return Err(
                    "epoch page differs from exact authenticated cursor or bounded page".into(),
                );
            }
            if chain.origin_context_root != authority.epoch.root().map_err(|e| e.to_string())? {
                let first = chain.transitions.first().unwrap();
                authority = authority
                    .authenticated_history_at(first.authorization.finalized_height)
                    .cloned()
                    .ok_or("original import page is not in retained authenticated history")?;
                if chain.origin_context_root != authority.epoch.root().map_err(|e| e.to_string())? {
                    return Err("original import page has another context root".into());
                }
                let mut writes = vec![];
                for transition in chain.transitions {
                    let epoch = transition.authorization.next_epoch;
                    let bytes = serde_json::to_vec(&transition).map_err(|e| e.to_string())?;
                    authority = super::authority::recovery::successor::verify_next_derived_bytes(
                        authority, &bytes,
                    )?;
                    if read(
                        &root(&config)?.join(format!("epoch-{epoch:020}.json")),
                        4 * 1024 * 1024,
                        false,
                    )? != bytes
                    {
                        return Err("original page is not exactly fully retained; reconcile read-only before retry".into());
                    }
                    writes.push(bytes);
                }
                println!(
                    "{}",
                    serde_json::json!({"schema":"synergy-validator-admission-epoch-import-v1","epoch":authority.epoch.epoch,"context_root":authority.epoch.root().map_err(|e|e.to_string())?,"proofs_imported":writes.len(),"consensus_started":false})
                );
                return Ok(());
            }
            if authority.has_historical_validator(&local(&config)?) {
                return Err("new-node proof import cannot replace an existing validator's history or safety state".into());
            }
            let mut writes = vec![];
            let mut anchors = vec![];
            for transition in chain.transitions {
                let bytes = serde_json::to_vec(&transition).map_err(|e| e.to_string())?;
                let epoch = transition.authorization.next_epoch;
                anchors.push((
                    authority.clone(),
                    transition.finalized.clone(),
                    transition.witness.clone(),
                ));
                authority = super::authority::recovery::successor::verify_next_derived_bytes(
                    authority, &bytes,
                )?;
                writes.push(synergy_storage::StorageWrite {
                    relative_path: format!("epoch-{epoch:020}.json").into(),
                    bytes,
                });
            }
            let layout =
                synergy_storage::NodeStorageLayout::new(config.storage.data_directory.clone())
                    .map_err(|e| e.to_string())?;
            let posy_root = layout.consensus().join("posy");
            let transitions =
                synergy_posy::persistence::AtomicConsensusTransitionStore::new(&posy_root)
                    .map_err(|e| e.to_string())?;
            let timeouts =
                synergy_posy::persistence::VerifiedTimeoutCertificateStore::new(&posy_root)
                    .map_err(|e| e.to_string())?;
            for (old, finalized, witness) in &anchors {
                for tc in &witness.timeout_certificates {
                    timeouts
                        .put_verified(tc, &old.epoch, &old.registry, old.as_ref())
                        .map_err(|e| e.to_string())?;
                }
                transitions
                    .commit_verified_snapshot_anchor(
                        finalized,
                        witness,
                        &old.epoch,
                        &old.registry,
                        old.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
            }
            store.put_once_atomic(&writes).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({"schema":"synergy-validator-admission-epoch-import-v1","epoch":authority.epoch.epoch,"context_root":authority.epoch.root().map_err(|e|e.to_string())?,"proofs_imported":writes.len(),"consensus_started":false})
            );
        }
        "import-shadow" => {
            let source: Source = serde_json::from_slice(&raw)
                .map_err(|_| "invalid native finalized shadow proof")?;
            let original = authority
                .authenticated_history_at(source.finalized.height)
                .cloned()
                .ok_or("shadow source has no authenticated preceding epoch")?;
            let selected = verify(&config, &original, &source)?;
            if !is_local(&config, &selected)? {
                return Err("local identity is not a newly admitted shadow".into());
            }
            // The exact source is retained only until its activation/expiry; it is the
            // current synchronization root, not a historical diagnostics archive.
            store
                .put_once_atomic(&[synergy_storage::StorageWrite {
                    relative_path: SOURCE.into(),
                    bytes: serde_json::to_vec(&source).map_err(|e| e.to_string())?,
                }])
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::json!({"schema":"synergy-validator-shadow-import-v1","validator_id":local(&config)?,"frozen_epoch":selected.epoch.epoch,"effective_epoch":selected.epoch.epoch+1,"source_finalized_height":source.finalized.height,"source_finalized_block_id":source.finalized.block_id,"consensus_authorized":false,"consensus_started":false})
            );
        }
        _ => return Err("unknown closed validator admission operation".into()),
    }
    Ok(())
}

/// Registers only the synchronization responsibility for a proof-earned new
/// identity. It cannot sign availability, processing or consensus messages.
pub(super) fn registration(
    config: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    ingress: super::ingress::AuthenticatedIngress,
) -> Result<
    (
        synergy_node_core::ServiceSpec,
        Box<dyn synergy_node_core::ManagedService>,
    ),
    String,
> {
    let source = source(config, &authority)?.ok_or("proof-earned shadow source unavailable")?;
    let service = ShadowSync {
        authority,
        source,
        ingress,
        running: false,
    };
    Ok((
        synergy_node_core::ServiceSpec {
            id: synergy_node_core::ServiceId::new("etdag")?,
            dependencies: vec![
                synergy_node_core::ServiceId::new("network")?,
                synergy_node_core::ServiceId::new("storage")?,
            ],
            criticality: synergy_node_core::Criticality::Critical,
            restart_policy: synergy_node_core::RestartPolicy::OnFailure { max_attempts: 3 },
        },
        super::owned_service::production(Box::new(service), "etdag"),
    ))
}
struct ShadowSync {
    authority: Arc<VerifiedAuthority>,
    source: Source,
    ingress: super::ingress::AuthenticatedIngress,
    running: bool,
}
impl synergy_node_core::ManagedService for ShadowSync {
    fn start(&mut self, cancel: &synergy_node_core::CancellationToken) -> Result<(), String> {
        if cancel.is_cancelled() {
            return Err("shadow synchronization canceled".into());
        }
        let verified =
            synergy_genesis::validator_admission::VerifiedValidatorAdmissionWorld::verify(
                &self.authority.epoch,
                &self.authority.registry,
                &self.source.finalized,
                &self.source.witness,
                &self.source.evidence,
                self.authority.as_ref(),
            )?;
        let world = Arc::new(
            synergy_state::world_resources::BudgetedWorld::try_clone_world(
                verified.world(),
                self.ingress.world_budget(),
            )
            .map_err(|e| format!("{e:?}"))?,
        );
        self.ingress
            .submit_snapshot_restore_handoff(super::ingress::SnapshotRestoreHandoff {
                epoch: self.authority.epoch.epoch,
                finalized_height: self.source.finalized.height,
                finalized_block_id: self.source.finalized.block_id.clone(),
                finality_evidence_id: self.source.finalized.finality_certificate_id.clone(),
                application_state_root: synergy_state::state_root(&world)
                    .map_err(|e| format!("{e:?}"))?,
                state: world,
            })?;
        self.running = true;
        Ok(())
    }
    fn poll(&mut self) -> Result<(), String> {
        for _ in 0..64 {
            if self
                .ingress
                .take(synergy_protocol_types::ProtocolKind::Etdag)?
                .is_none()
            {
                break;
            }
        }
        for _ in 0..16 {
            let Some(request) = self.ingress.take_local_protected_vertex()? else {
                break;
            };
            let _ = request.response.send(Err(
                "shadow validator has no pre-activation processing authority".into(),
            ));
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<(), String> {
        self.running = false;
        Ok(())
    }
    fn health(&self) -> synergy_node_core::ServiceHealth {
        if self.running {
            synergy_node_core::ServiceHealth::Healthy
        } else {
            synergy_node_core::ServiceHealth::Unhealthy {
                reason: "shadow synchronization is stopped".into(),
            }
        }
    }
    fn readiness(&self) -> synergy_node_core::ServiceReadiness {
        if self.running {
            synergy_node_core::ServiceReadiness::Ready
        } else {
            synergy_node_core::ServiceReadiness::Pending {
                reason: "shadow synchronization not started".into(),
            }
        }
    }
}

fn prepare(
    config: &NodeConfiguration,
    authority: Arc<VerifiedAuthority>,
    raw: &[u8],
    owner: &str,
    platform_root: &std::path::Path,
    read_only: bool,
) -> Result<(), String> {
    use synergy_governance::{ValidatorAdmissionRequest, ValidatorAdmissionSpec};
    let journal_root = config
        .storage
        .data_directory
        .join("metadata/validator-admission-authoring");
    let journal_path = journal_root.join("current.json");
    let source_request_sha256 = super::apqe_transport::sha256(
        &serde_json::to_vec(&(owner, super::apqe_transport::sha256(raw)))
            .map_err(|e| e.to_string())?,
    );
    if journal_path.try_exists().map_err(|e| e.to_string())? {
        let journal: serde_json::Value =
            serde_json::from_slice(&read(&journal_path, 512 * 1024, false)?)
                .map_err(|_| "invalid native node-admission authoring journal")?;
        if journal["source_request_sha256"] == source_request_sha256 {
            let request: synergy_governance::ValidatorAdmissionRequest =
                serde_json::from_value(journal["reply"]["request"].clone())
                    .map_err(|_| "invalid cached node-admission request")?;
            let encoded = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            if journal["reply"]["request_sha256"] != super::apqe_transport::sha256(&encoded)
                || request.spec.validator_id != local(config)?
                || request.spec.owner_wallet != owner
            {
                return Err("cached admission request differs from exact local owner scope".into());
            }
            let source: Source = serde_json::from_slice(raw)
                .map_err(|_| "invalid original public authoring source")?;
            let original = authority
                .authenticated_history_at(source.finalized.height)
                .ok_or("cached authoring source has no authenticated epoch history")?;
            synergy_genesis::validator_admission::VerifiedValidatorAdmissionWorld::verify(
                &original.epoch,
                &original.registry,
                &source.finalized,
                &source.witness,
                &source.evidence,
                original.as_ref(),
            )?;
            let verifier = original
                .native_identity_verifier()
                .ok_or("cached authoring native verifier unavailable")?;
            synergy_genesis::validator_admission::verify_validator_admission_possession(
                &request,
                original.epoch.chain_id,
                original.authenticated_genesis_hash()?,
                original.epoch.epoch,
                &original.epoch.root().map_err(|e| e.to_string())?,
                owner,
                verifier,
            )
            .map_err(|e| e.to_string())?;
            if journal["reply"]["request_json"]
                != std::str::from_utf8(&encoded).map_err(|_| "invalid original request UTF8")?
            {
                return Err("cached exact request JSON changed".into());
            }
            println!("{}", journal["reply"]);
            return Ok(());
        }
    }
    if read_only {
        println!(
            "{}",
            serde_json::json!({"schema":"synergy-validator-admission-authoring-status-v1","prepared":false,"mutation_performed":false,"source_request_sha256":source_request_sha256})
        );
        return Ok(());
    }
    let source: Source = serde_json::from_slice(raw)
        .map_err(|_| "invalid independently finalized admission source")?;
    let verified = synergy_genesis::validator_admission::VerifiedValidatorAdmissionWorld::verify(
        &authority.epoch,
        &authority.registry,
        &source.finalized,
        &source.witness,
        &source.evidence,
        authority.as_ref(),
    )?;
    let mut selected = authority.as_ref().clone();
    selected.membership_retirement = Arc::new(std::sync::Mutex::new(None));
    super::membership_retirement::refresh_finalized(
        &selected,
        source.finalized.height,
        verified.world(),
    )?;
    let policy = selected
        .automatic_admission_policy()?
        .ok_or("network has no finalized automatic admission policy")?;
    if !synergy_address::is_spendable_user_address(owner)
        || !verified.world().accounts.get(owner).is_some_and(|a| {
            a.balance_nwei >= policy.bond_nwei().unwrap_or(u128::MAX) && a.code_hash.is_none()
        })
    {
        return Err("bond owner is not an authenticated funded native account".into());
    }
    let root = platform_root.canonicalize().map_err(|e| e.to_string())?;
    for path in [
        &config.public_identity_path,
        &config.manifest_path,
        &config.storage.data_directory,
    ] {
        if !path
            .canonicalize()
            .map_err(|e| e.to_string())?
            .starts_with(&root)
        {
            return Err("admission authoring escaped its installed platform root".into());
        }
    }
    let (endpoint, _binding) = super::transport_endpoint::managed_endpoint(config, &root)?;
    let transport = config
        .apqe_transport
        .as_ref()
        .ok_or("native validator custody required")?;
    let enrollment = read(&transport.enrollment_path, 128 * 1024, false)?;
    let request: synergy_address_engine::validator_provisioning::EnrollmentRequest =
        serde_json::from_slice(&enrollment).map_err(|_| "invalid target enrollment")?;
    if serde_json::to_vec(&request).map_err(|e| e.to_string())? != enrollment {
        return Err("admission requires exact canonical local enrollment bytes".into());
    }
    let decode = |text: &str| -> Result<Vec<u8>, String> {
        if text.len() % 2 != 0 {
            return Err("invalid public key encoding".into());
        }
        text.as_bytes()
            .chunks_exact(2)
            .map(|b| {
                u8::from_str_radix(
                    std::str::from_utf8(b).map_err(|_| "invalid public encoding")?,
                    16,
                )
                .map_err(|_| "invalid public encoding".into())
            })
            .collect()
    };
    let id = local(config)?;
    if id != request.payload.identity.address || selected.has_historical_validator(&id) {
        return Err("admission is restricted to an independently provisioned new identity".into());
    }
    let public = &request.payload.identity;
    let key_domain = &super::apqe_transport::sha256(id.as_bytes())[..32];
    let spec = ValidatorAdmissionSpec {
        schema_version: 1,
        chain_id: config.chain_id,
        network_id: config.network_id.clone(),
        genesis_hash: selected.authenticated_genesis_hash()?.into(),
        frozen_epoch: selected.epoch.epoch,
        frozen_epoch_context_root: selected.epoch.root().map_err(|e| e.to_string())?,
        effective_epoch: selected
            .epoch
            .epoch
            .checked_add(1)
            .ok_or("admission epoch overflow")?,
        owner_wallet: owner.into(),
        validator_id: id,
        identity_root_public_key: decode(&public.public_key)?,
        consensus_key_id: format!("admitted-consensus-{key_domain}"),
        consensus_public_key: decode(&public.consensus_key.public_key)?,
        transport_key_id: format!("admitted-transport-{key_domain}"),
        transport_public_key: decode(&public.node_identity_key.public_key)?,
        ingress_kem_key_id: format!("admitted-ingress-{key_domain}"),
        ingress_kem_public_key: decode(&request.payload.ingress_key.public_key)?,
        sync_finalized_height: source.finalized.height,
        sync_finalized_block_id: source.finalized.block_id.clone(),
        dial_address: endpoint.to_string(),
        enrollment_sha256: super::apqe_transport::sha256(&enrollment),
    };
    let envelope: synergy_address_engine::encrypt::EncryptedEnvelope =
        serde_json::from_slice(&read(&transport.custody_path, 256 * 1024, true)?)
            .map_err(|_| "invalid sealed validator custody")?;
    let pass = synergy_address_engine::apqe::SecretBytes::from_bytes(read(
        &transport.custody_unlock_path,
        4096,
        true,
    )?);
    let pass = std::str::from_utf8(pass.as_bytes())
        .map_err(|_| "invalid native custody unlock encoding")?;
    let (_, network) = crate::commands::selected_network::verify_with_custody_binding(config)?;
    let engine = super::apqe_provider::load(config)?;
    let guard = engine
        .try_lock()
        .map_err(|_| "native admission provider busy")?;
    let proofs =
        synergy_address_engine::validator_provisioning::sign_validator_admission_possession(
            &guard,
            &request,
            &network,
            &envelope,
            pass,
            &spec.signing_bytes()?,
        )?;
    let admission = ValidatorAdmissionRequest {
        spec,
        identity_root_signature: proofs.identity_root_signature,
        consensus_possession_signature: proofs.consensus_possession_signature,
        transport_possession_signature: proofs.transport_possession_signature,
        sync_finality_document:
            synergy_genesis::validator_admission::encode_validator_admission_sync(
                &source.finalized,
                &source.witness,
            )?,
    };
    let input = serde_json::to_vec(&admission).map_err(|e| e.to_string())?;
    if input.len() > 128 * 1024 {
        return Err("native admission exceeds exact bounded carrier".into());
    }
    let reply = serde_json::json!({"schema":"synergy-validator-admission-authoring-v1","request_sha256":super::apqe_transport::sha256(&input),"request":admission,"request_json":std::str::from_utf8(&input).map_err(|_|"invalid canonical request UTF8")?,"owner_wallet":owner,"bond_nwei":policy.minimum_bond_nwei,"gas_limit":75000+input.len(),"source_finalized_height":source.finalized.height,"source_finalized_block_id":source.finalized.block_id,"source_owner_nonce":verified.world().accounts[owner].nonce,"financial_signature_required":true,"consensus_authorized":false,"consensus_started":false});
    let journal = serde_json::json!({"schema_version":1,"source_request_sha256":source_request_sha256,"reply":reply});
    synergy_storage::AtomicStore::new(journal_root, 512 * 1024)
        .map_err(|e| e.to_string())?
        .write_atomic(
            "current.json",
            &serde_json::to_vec(&journal).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    println!("{reply}");
    Ok(())
}

fn bootstrap(mut args: impl Iterator<Item = String>, final_inputs: bool) -> Result<(), String> {
    let mut root = None;
    let mut genesis_pin = None;
    let mut transport_pin = None;
    let mut provider_pin = None;
    let mut stdin = false;
    while let Some(arg) = args.next() {
        let value = args.next().ok_or("bootstrap argument requires value")?;
        match arg.as_str() {
            "--root" => root = Some(PathBuf::from(value)),
            "--genesis-trust-key-sha256" => genesis_pin = Some(value),
            "--transport-trust-key-sha256" => transport_pin = Some(value),
            "--provider-report-sha256" => provider_pin = Some(value),
            "--proof" if value == "-" => stdin = true,
            _ => return Err("unknown closed admission bootstrap argument".into()),
        }
    }
    if !stdin {
        return Err("bootstrap master template must arrive on bounded stdin".into());
    }
    let root = root
        .ok_or("platform root required")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let genesis_pin = genesis_pin.ok_or("independently pinned original Genesis root required")?;
    let transport_pin =
        transport_pin.ok_or("independently pinned original transport root required")?;
    let provider_pin =
        provider_pin.ok_or("independently pinned native provider report required")?;
    if [&genesis_pin, &transport_pin, &provider_pin]
        .iter()
        .any(|h| !synergy_posy::is_hash(h))
    {
        return Err("exact SHA256 pins required".into());
    }
    use std::io::Read;
    let mut bytes = vec![];
    std::io::stdin()
        .lock()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err("bounded typed master configuration required".into());
    }
    let mut c: NodeConfiguration = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid public master configuration template")?;
    if c.role != synergy_protocol_types::NodeRole::Validator
        || c.aegis_signing_key_path.is_some()
        || c.consensus.signing_key_path.is_some()
        || c.etdag.ingress_kem_secret_key_path.is_some()
        || c.consensus.authority_recovery_certificate_path.is_some()
        || c.consensus.autonomous_epoch_activation.is_some()
        || c.update.enabled
        || c.rpc.listen_address.is_some_and(|a| !a.ip().is_loopback())
    {
        return Err("new-node bootstrap forbids existing safety state, raw signing keys, recovery, public RPC and automatic updates".into());
    }
    let pending = if final_inputs {
        root.join("keys/apqe")
    } else {
        root.join("tmp/pending-validator-custody")
    };
    let network = if final_inputs {
        root.join("network")
    } else {
        root.join("tmp/identity-network")
    };
    let approved = if final_inputs {
        root.join("network")
    } else {
        root.join("tmp/admission-bootstrap/network")
    };
    let node_public = if final_inputs {
        pending.join("validator.pub.json")
    } else {
        pending.join("node-identity.json")
    };
    let enrollment_path = if final_inputs {
        pending.join("enrollment.json")
    } else {
        pending.join("bundle/enrollment-request.json")
    };
    let custody_path = if final_inputs {
        pending.join("custody.json")
    } else {
        pending.join("bundle/validator.enc.json")
    };
    c.manifest_path = approved.join("network-manifest.json");
    c.genesis_path = Some(network.join("genesis.json"));
    c.public_identity_path = node_public.clone();
    c.admin_socket_path = root.join("run/admin.sock");
    c.consensus.authority_binding = Some(network.join("authority.json"));
    c.consensus.authority_trust_key_path = Some(network.join("authority-root.pub"));
    c.consensus.mode = synergy_config::ConsensusMode::ValidateAndVote;
    c.aegis_key_bindings_path = None;
    c.aegis_provider = Some(synergy_config::ApqeProviderConfiguration {
        report_path: root.join("lib/apqe/build-report.json"),
        authenticated_report_sha256: provider_pin,
    });
    c.apqe_transport = Some(synergy_config::ApqeTransportConfiguration {
        profile: synergy_config::ApqeTransportProfile::EngineeringCanaryPqVsessionV1,
        registry_path: approved.join("transport-registry.json"),
        registry_trust_key_path: approved.join("transport-root.pub"),
        registry_trust_key_sha256: transport_pin.clone(),
        genesis_trust_key_sha256: genesis_pin.clone(),
        enrollment_path,
        custody_path,
        custody_unlock_path: pending.join("unlock"),
    });
    c.etdag.enabled = true;
    c.storage.data_directory = root.join("data");
    c.vpn = Default::default();
    let genesis: synergy_genesis::signing::SignedGenesis = serde_json::from_slice(&read(
        c.genesis_path.as_ref().unwrap(),
        16 * 1024 * 1024,
        false,
    )?)
    .map_err(|_| "invalid original signed Genesis")?;
    c.chain_id = genesis.unsigned.network.chain_id;
    c.network_id = genesis.unsigned.network.network_id.clone();
    let (endpoint, _) = super::transport_endpoint::managed_endpoint(&c, &root)?;
    c.network.listen_addresses = vec![endpoint];
    c.network.advertised_addresses = vec![endpoint];
    c.validate().map_err(|e| e.to_string())?;
    let original = super::apqe_transport::Snapshot::load_origin(&c, &[transport_pin, genesis_pin])?;
    let selected = c.apqe_transport.as_ref().unwrap();
    let request_raw = read(&selected.enrollment_path, 128 * 1024, false)?;
    let request: synergy_address_engine::validator_provisioning::EnrollmentRequest =
        serde_json::from_slice(&request_raw).map_err(|_| "invalid pending target enrollment")?;
    let envelope: synergy_address_engine::encrypt::EncryptedEnvelope =
        serde_json::from_slice(&read(&selected.custody_path, 256 * 1024, true)?)
            .map_err(|_| "invalid pending encrypted target custody")?;
    let pass = synergy_address_engine::apqe::SecretBytes::from_bytes(read(
        &selected.custody_unlock_path,
        4096,
        true,
    )?);
    let pass = std::str::from_utf8(pass.as_bytes())
        .map_err(|_| "invalid pending custody unlock encoding")?;
    let engine = super::apqe_provider::load(&c)?;
    let guard = engine
        .try_lock()
        .map_err(|_| "native bootstrap provider busy")?;
    synergy_address_engine::validator_provisioning::verify_custody(
        &guard,
        &request,
        &original.network,
        &envelope,
        pass,
    )?;
    let id = synergy_protocol_types::NodeAddress::parse(&request.payload.identity.address)
        .map_err(|e| e.to_string())?;
    if original
        .entries
        .iter()
        .any(|e| e.node_address == id.as_str())
    {
        return Err(
            "admission bootstrap cannot re-provision an original validator identity".into(),
        );
    }
    let existing = super::identity::load_public_identity(&node_public, c.role)?;
    if existing.node_address != id {
        return Err("pending native identity differs from sealed enrollment".into());
    }
    let public_json = String::from_utf8(read(&node_public, 65536, false)?)
        .map_err(|_| "invalid original public identity UTF8")?;
    let enrollment_json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    c.manifest_path = root.join("network/network-manifest.json");
    c.genesis_path = Some(root.join("network/genesis.json"));
    c.public_identity_path = root.join("keys/apqe/validator.pub.json");
    c.consensus.authority_binding = Some(root.join("network/authority.json"));
    c.consensus.authority_trust_key_path = Some(root.join("network/authority-root.pub"));
    let selected = c.apqe_transport.as_mut().unwrap();
    selected.registry_path = root.join("network/transport-registry.json");
    selected.registry_trust_key_path = root.join("network/transport-root.pub");
    selected.enrollment_path = root.join("keys/apqe/enrollment.json");
    selected.custody_path = root.join("keys/apqe/custody.json");
    selected.custody_unlock_path = root.join("keys/apqe/unlock");
    let configuration_json = serde_json::to_string(&c).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({"schema":"synergy-validator-admission-bootstrap-v1","configuration_sha256":super::apqe_transport::sha256(configuration_json.as_bytes()),"configuration_json":configuration_json,"public_identity_sha256":super::apqe_transport::sha256(public_json.as_bytes()),"public_identity_json":public_json,"enrollment_sha256":super::apqe_transport::sha256(enrollment_json.as_bytes()),"enrollment_json":enrollment_json,"chain_id":c.chain_id,"network_id":c.network_id,"genesis_hash":genesis.genesis_hash,"validator_id":id,"custody_verified":true,"consensus_authorized":false,"consensus_started":false,"mutation_performed":false})
    );
    Ok(())
}

pub(crate) fn membership_status(
    config: &NodeConfiguration,
    authority: Option<&Arc<VerifiedAuthority>>,
) -> Result<serde_json::Value, String> {
    let Some(authority) = authority else {
        return Ok(
            serde_json::json!({"validator_shadow_verified":false,"validator_admission_verified":false}),
        );
    };
    let id = local(config)?;
    let records = authority.earned_transport_records()?;
    let record = records.iter().find(|r| r.validator_id == id);
    let shadow = is_local(config, authority)?;
    let active = authority.registry.active_validator(&id).is_ok();
    Ok(
        serde_json::json!({"validator_shadow_verified":shadow,"validator_admission_verified":record.is_some()&&(shadow||active),"validator_admission_effective_epoch":record.map(|r|r.effective_epoch),"validator_id":id,"consensus_authorized":active}),
    )
}
