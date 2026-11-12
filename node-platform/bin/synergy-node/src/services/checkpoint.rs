//! Stopped-only checkpoint recovery through canonical PoSy and execution stores.
//! The bundle contains public certified facts, never provider custody/journals.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use synergy_execution::{BudgetedExecutionCandidate, CandidateStore};
use synergy_posy::persistence::{AtomicConsensusTransitionStore, FinalityStore, SignOnceJournal};
use synergy_posy::{
    FinalitySyncWitness, FinalizedBlockRecord, SimplifiedQuorumCertificate,
    SimplifiedTimeoutCertificate, ThreeQcFinality, VerifiedQuorumCertificateStore,
    VerifiedTimeoutCertificateStore,
};
use synergy_state::world_resources::WorldResourceBudget;
use synergy_state::{FinalizedState, FinalizedStateStore};
use synergy_storage::NodeStorageLayout;

use super::{authority::VerifiedAuthority, posy, processing_pipeline, processing_proposals};
use crate::commands::checkpoint::{Action, Request};

// These are offline allocation/frame capacities, never consensus rules. History
// length is streamed in complete leader-lease pages; it is not a memory limit.
const MAX_PROOF_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CANDIDATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PAGES: u64 = 65536;
const AUTHORIZATION_SOURCE: &str = "authorization-source.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    chain_id: u64,
    network_id: String,
    epoch_context_root: String,
    anchor: FinalizedBlockRecord,
    checkpoint: FinalizedBlockRecord,
    pages: u64,
    prefix_chain: String,
    files: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    first_height: u64,
    last_height: u64,
    apply_through: u64,
    certificates: Vec<SimplifiedQuorumCertificate>,
    timeouts: Vec<SimplifiedTimeoutCertificate>,
}

fn chain_start() -> String {
    synergy_block::hash_block_bytes(b"SYNERGY-OFFLINE-CHECKPOINT-PREFIX-V2")
}
fn chain_next(previous: &str, frame: &str) -> String {
    let mut bytes = Vec::with_capacity(previous.len() + frame.len());
    bytes.extend_from_slice(previous.as_bytes());
    bytes.extend_from_slice(frame.as_bytes());
    synergy_block::hash_block_bytes(&bytes)
}

/// Configuration inode is the shared start/recovery exclusion boundary. The
/// returned file must remain alive until start or offline recovery completes.
pub(crate) fn lock_configuration(path: &Path) -> Result<File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !path.is_absolute() || !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("checkpoint/start requires a regular absolute configuration".into());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|e| format!("configuration is owned by a running node/recovery: {e}"))?;
    Ok(file)
}

pub(crate) fn require_stopped(config: &Path, socket: &Path) -> Result<(), String> {
    #[cfg(unix)]
    if std::os::unix::net::UnixStream::connect(socket).is_ok() {
        return Err("offline checkpoint requires the node to be stopped".into());
    }
    // Also exclude older native binaries that predate the configuration lock.
    // Match a complete argv configuration, not a substring or this command's
    // parent shell/sudo argv. The current command is checkpoint, never start.
    let output = std::process::Command::new("ps")
        .args(["-axo", "pid=,args="])
        .output()
        .map_err(|e| format!("inspect stopped process ownership: {e}"))?;
    if !output.status.success() || output.stdout.len() > 8 * 1024 * 1024 {
        return Err("cannot establish stopped process ownership".into());
    }
    let path = config.to_str().ok_or("configuration path is not UTF-8")?;
    for line in std::str::from_utf8(&output.stdout)
        .map_err(|e| e.to_string())?
        .lines()
    {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let Some(pid) = fields.first().and_then(|v| v.parse::<u32>().ok()) else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        if fields.get(1).is_some_and(|v| {
            Path::new(v)
                .file_name()
                .is_some_and(|v| v.to_string_lossy().starts_with("synergy-node"))
        }) && fields.get(2) == Some(&"start")
            && fields.windows(2).any(|v| v == ["--config", path])
        {
            return Err("offline checkpoint refuses a running native node".into());
        }
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > maximum {
        return Err(format!(
            "checkpoint file is not bounded/regular: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err("checkpoint file grew beyond bound".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

fn witness_record(
    witness: &FinalitySyncWitness,
    authority: &VerifiedAuthority,
) -> Result<FinalizedBlockRecord, String> {
    witness
        .verified_timeout_closure(&authority.epoch, &authority.registry, authority)
        .map_err(|e| e.to_string())?;
    let mut finality = ThreeQcFinality::default();
    for qc in &witness.quorum_certificates {
        qc.verify(&authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?;
        finality.accept(qc.clone()).map_err(|e| e.to_string())?;
    }
    finality
        .last_finalized()
        .cloned()
        .ok_or("checkpoint lacks exact three-QC finality".into())
}

pub(crate) fn run(request: &Request) -> Result<serde_json::Value, String> {
    let _exclusive = lock_configuration(&request.config)?;
    crate::commands::start::preflight(&request.config)?;
    let configuration = synergy_config::load(&request.config).map_err(|e| e.to_string())?;
    require_stopped(&request.config, &configuration.admin_socket_path)?;
    let authority = super::authority::load(&configuration)?
        .ok_or("checkpoint requires authenticated PoSy authority")?;
    if authority.epoch.epoch != 1 || !authority.processing_profile_enabled() {
        return Err(
            "checkpoint currently requires the native initial-epoch processing profile".into(),
        );
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    let bundle_parent = request
        .bundle
        .parent()
        .ok_or("checkpoint bundle has no parent")?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let data = layout.root().canonicalize().map_err(|e| e.to_string())?;
    if bundle_parent.starts_with(&data) {
        return Err("checkpoint bundle must be outside application data".into());
    }
    let budget = WorldResourceBudget::new(configuration.storage.world_memory_budget_bytes);
    match request.action {
        Action::Import => import(request, &authority, &layout, &budget),
        Action::Export => export(request, &authority, &layout, &budget),
        Action::RestoreAuthorizationSource => {
            restore_authorization_source(request, &authority, &layout, &budget)
        }
    }
}

fn restore_authorization_source(
    request: &Request,
    authority: &VerifiedAuthority,
    layout: &NodeStorageLayout,
    budget: &Arc<WorldResourceBudget>,
) -> Result<serde_json::Value, String> {
    let mut state =
        FinalizedStateStore::load_budgeted(layout.state().join("execution"), budget.clone())
            .map_err(|e| format!("load checkpoint execution: {e:?}"))?;
    let tip = state
        .current()
        .ok_or("authorization source restore requires an existing finalized tip")?
        .clone();
    let mut candidates =
        CandidateStore::new_budgeted(layout.blocks().join("execution-candidates"), budget.clone())?;
    let posy = layout.consensus().join("posy");
    let qcs = VerifiedQuorumCertificateStore::new(&posy).map_err(|e| e.to_string())?;
    let tcs = VerifiedTimeoutCertificateStore::new(&posy).map_err(|e| e.to_string())?;
    let finality = FinalityStore::new(&posy).map_err(|e| e.to_string())?;
    let tip_candidate = candidates
        .get_budgeted(tip.finalized_height)
        .map_err(|e| e.to_string())?
        .ok_or("authorization source restore lacks current finalized candidate")?;
    verify_durable_candidate(&tip_candidate, authority, &qcs, &tcs, &finality)?;
    if tip_candidate.block_id != tip.finalized_block_id
        || tip_candidate.state_root != tip.state_root
    {
        return Err(
            "authorization source restore tip disagrees with current durable execution".into(),
        );
    }
    if authorization_source_height(&tip_candidate)? == 0 {
        return Err("current finalized tip has no eligible authorization source".into());
    }
    let bytes = read_bounded(&request.bundle, MAX_CANDIDATE_BYTES)?;
    let source =
        synergy_execution::decode_budgeted_candidate(&bytes, budget).map_err(|e| e.to_string())?;
    drop(bytes);
    verify_authorization_source(&tip_candidate, &source)?;
    drop(tip_candidate);
    verify_durable_candidate(&source, authority, &qcs, &tcs, &finality)?;
    let commitment = install_authorization_source(&source, &mut candidates, &mut state)?;
    if state.current() != Some(&tip) {
        return Err("authorization source restore changed the finalized tip".into());
    }
    Ok(
        serde_json::json!({"restored_authorization_source": true, "source_height": source.height,
        "source_block_id": source.block_id, "source_state_root": commitment.state_root,
        "finalized_height": tip.finalized_height, "finalized_block_id": tip.finalized_block_id,
        "state_root": tip.state_root, "signing": false}),
    )
}

fn authorization_source_height(candidate: &BudgetedExecutionCandidate) -> Result<u64, String> {
    let height =
        synergy_identity::registration::authorization_update_height(&candidate.state.protocol)?;
    if height > candidate.height {
        return Err("authorization source is above its finalized checkpoint".into());
    }
    Ok(height)
}

fn verify_authorization_source(
    tip: &BudgetedExecutionCandidate,
    source: &BudgetedExecutionCandidate,
) -> Result<(), String> {
    let height = authorization_source_height(tip)?;
    let key = synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY;
    if height == 0
        || source.height != height
        || authorization_source_height(source)? != height
        || !source.state.protocol.contains_key(key)
        || source.state.protocol.get(key) != tip.state.protocol.get(key)
    {
        return Err("supplied candidate is not the current exact authorization source".into());
    }
    Ok(())
}

fn verify_durable_candidate(
    candidate: &BudgetedExecutionCandidate,
    authority: &VerifiedAuthority,
    qcs: &VerifiedQuorumCertificateStore,
    tcs: &VerifiedTimeoutCertificateStore,
    finality: &FinalityStore,
) -> Result<(), String> {
    let height = candidate.height;
    let end = height
        .checked_add(2)
        .ok_or("authorization source witness height overflow")?;
    let record = finality
        .get(height)
        .map_err(|e| e.to_string())?
        .ok_or("authorization source restore lacks local finalized record")?;
    let [a, b, c] = [height, end - 1, end].map(|height| {
        qcs.get_verified(height, &authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?
            .ok_or("authorization source restore lacks local verified QC".to_string())
    });
    let witness = FinalitySyncWitness::from_verified_certificates(
        [a?, b?, c?],
        tcs,
        &authority.epoch,
        &authority.registry,
        authority,
    )
    .map_err(|e| e.to_string())?;
    if witness_record(&witness, authority)? != record {
        return Err("authorization source disagrees with local native finality".into());
    }
    verify_candidate(candidate, &record)
}

fn install_authorization_source(
    source: &BudgetedExecutionCandidate,
    candidates: &mut synergy_execution::BudgetedCandidateStore,
    state: &mut FinalizedStateStore,
) -> Result<FinalizedState, String> {
    if candidates
        .get_budgeted(source.height)
        .map_err(|e| e.to_string())?
        .is_some_and(|existing| &existing != source)
    {
        return Err("authorization source conflicts with existing execution candidate".into());
    }
    let commitment = FinalizedState {
        finalized_height: source.height,
        finalized_block_id: source.block_id.clone(),
        state_root: source.state_root.clone(),
    };
    // Write the commitment first. The candidate descriptor is the readiness
    // signal used by ETDAG; an interrupted attempt cannot advertise a partial
    // repair, and retries compare the same immutable artifacts.
    state
        .pin_verified_processing_history(&commitment)
        .map_err(|e| format!("restore authorization history pin: {e:?}"))?;
    candidates.pin_budgeted(source).map_err(|e| e.to_string())?;
    if state
        .history_at(source.height)
        .map_err(|e| format!("read authorization history pin: {e:?}"))?
        .as_ref()
        != Some(&commitment)
        || !candidates
            .pinned_descriptors()
            .iter()
            .any(|pin| pin.height == source.height && pin.block_id == source.block_id)
    {
        return Err("authorization source pin readback mismatch".into());
    }
    Ok(commitment)
}

fn export(
    request: &Request,
    authority: &Arc<VerifiedAuthority>,
    layout: &NodeStorageLayout,
    budget: &Arc<WorldResourceBudget>,
) -> Result<serde_json::Value, String> {
    let state =
        FinalizedStateStore::load_budgeted(layout.state().join("execution"), Arc::clone(budget))
            .map_err(|e| format!("{e:?}"))?;
    let current = state
        .current()
        .ok_or("checkpoint exporter has no finalized execution state")?;
    let (from, block) = request
        .from
        .as_ref()
        .ok_or("checkpoint export lacks anchor")?;
    if *from > current.finalized_height {
        return Err("checkpoint anchor is above provider finalized execution".into());
    }
    let root = layout.consensus().join("posy");
    let qcs = VerifiedQuorumCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let tcs = VerifiedTimeoutCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let finality = FinalityStore::new(&root).map_err(|e| e.to_string())?;
    let anchor = finality
        .get(*from)
        .map_err(|e| e.to_string())?
        .ok_or("export anchor finality is absent")?;
    if anchor.block_id != *block {
        return Err("export anchor differs from requested local block".into());
    }
    let checkpoint = finality
        .get(current.finalized_height)
        .map_err(|e| e.to_string())?
        .ok_or("export checkpoint lacks finality")?;
    let candidates = CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        Arc::clone(budget),
    )?;
    let candidate = candidates
        .get_budgeted(current.finalized_height)
        .map_err(|e| e.to_string())?
        .ok_or("export checkpoint candidate unavailable")?;
    candidate.validate()?;
    if candidate.block_id != current.finalized_block_id
        || candidate.state_root != current.state_root
    {
        return Err("export candidate differs from finalized state".into());
    }
    let namespace = processing_pipeline::processing_namespace(authority, budget)?;
    let processing = processing_proposals::ProcessingProposalStore::open(
        &super::processing_proposals::epoch_store_path(&layout.blocks(), authority.epoch.epoch),
        namespace.clone(),
        budget,
        Arc::clone(authority),
    )?;
    let (replay, _replay_permit) = processing.export_sync(&candidate.block_id)?;
    let qc = qcs
        .get_verified(
            candidate.height,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .map_err(|e| e.to_string())?
        .ok_or("export candidate lacks QC")?;
    processing_proposals::verify_checkpoint_replay(
        &replay, &candidate, &qc, authority, &namespace,
    )?;
    let source_height = authorization_source_height(&candidate)?;
    let authorization = if source_height > 0 && source_height != candidate.height {
        let source = candidates
            .get_budgeted(source_height)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                format!("checkpoint missing required authorization source at H{source_height}")
            })?;
        verify_authorization_source(&candidate, &source)?;
        verify_durable_candidate(&source, authority, &qcs, &tcs, &finality)?;
        Some(serde_json::to_vec(&source).map_err(|e| e.to_string())?)
    } else {
        None
    };
    fs::create_dir(&request.bundle).map_err(|e| e.to_string())?;
    let result = (|| {
        let mut manifest = Manifest {
            version: 2,
            chain_id: authority.epoch.chain_id,
            network_id: authority.epoch.network_id.clone(),
            epoch_context_root: authority.epoch.root().map_err(|e| e.to_string())?,
            anchor,
            checkpoint,
            pages: 0,
            prefix_chain: chain_start(),
            files: BTreeMap::new(),
        };
        let mut stream = new_file(&request.bundle.join("prefix.bin"))?;
        let mut bytes_written = 0u64;
        let mut first = *from;
        while first <= current.finalized_height {
            let end = lease_end(first, authority)?.min(current.finalized_height);
            let through = if end == current.finalized_height {
                end.checked_add(2).ok_or("checkpoint height overflow")?
            } else {
                end
            };
            let mut certificates = BTreeMap::new();
            let mut timeouts = BTreeMap::new();
            for height in first..=end {
                let mut chain = Vec::new();
                for h in height..=height.checked_add(2).ok_or("checkpoint height overflow")? {
                    chain.push(
                        qcs.get_verified(
                            h,
                            &authority.epoch,
                            &authority.registry,
                            authority.as_ref(),
                        )
                        .map_err(|e| e.to_string())?
                        .ok_or("export certified prefix has a gap")?,
                    );
                }
                let witness = FinalitySyncWitness::from_verified_certificates(
                    chain.try_into().map_err(|_| "checkpoint QC triple")?,
                    &tcs,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .map_err(|e| e.to_string())?;
                let record = witness_record(&witness, authority)?;
                if finality.get(height).map_err(|e| e.to_string())?.as_ref() != Some(&record) {
                    return Err("export finality differs from native witness".into());
                }
                for qc in witness.quorum_certificates {
                    certificates.insert(qc.context.height, qc);
                }
                for tc in witness.timeout_certificates {
                    timeouts.insert((tc.context.height, tc.context.round), tc);
                }
            }
            let page = Page {
                first_height: first,
                last_height: end,
                apply_through: through,
                certificates: certificates.into_values().collect(),
                timeouts: timeouts.into_values().collect(),
            };
            let bytes = serde_json::to_vec(&page).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_PROOF_BYTES {
                return Err("checkpoint lease page exceeds offline frame capacity".into());
            }
            stream
                .write_all(&(bytes.len() as u64).to_le_bytes())
                .and_then(|()| stream.write_all(&bytes))
                .map_err(|e| e.to_string())?;
            bytes_written = bytes_written
                .checked_add(bytes.len() as u64 + 8)
                .ok_or("checkpoint byte overflow")?;
            manifest.prefix_chain = chain_next(
                &manifest.prefix_chain,
                &synergy_block::hash_block_bytes(&bytes),
            );
            manifest.pages += 1;
            if manifest.pages > MAX_PAGES {
                return Err("checkpoint page catalog exceeds offline capacity".into());
            }
            first = end.checked_add(1).ok_or("checkpoint height overflow")?;
        }
        stream.sync_all().map_err(|e| e.to_string())?;
        let mut files = vec![
            (
                "candidate.json",
                serde_json::to_vec(&candidate).map_err(|e| e.to_string())?,
                MAX_CANDIDATE_BYTES,
            ),
            ("processing-replay.json", replay, MAX_PROOF_BYTES),
        ];
        if let Some(bytes) = authorization {
            files.push((AUTHORIZATION_SOURCE, bytes, MAX_CANDIDATE_BYTES));
        }
        for (name, bytes, bound) in files {
            if bytes.len() as u64 > bound {
                return Err("checkpoint payload exceeds importer capacity".into());
            }
            bytes_written = bytes_written
                .checked_add(bytes.len() as u64)
                .ok_or("checkpoint byte overflow")?;
            manifest
                .files
                .insert(name.into(), synergy_block::hash_block_bytes(&bytes));
            write_new(&request.bundle.join(name), &bytes)?;
        }
        write_new(
            &request.bundle.join("manifest.json"),
            &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
        )?;
        File::open(&request.bundle)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        File::open(request.bundle.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        Ok(
            serde_json::json!({"exported": true, "from_height": from, "checkpoint_height": current.finalized_height, "pages": manifest.pages, "bytes": bytes_written, "signing": false}),
        )
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&request.bundle);
    }
    result
}

fn new_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| e.to_string())
}

fn lease_end(height: u64, authority: &VerifiedAuthority) -> Result<u64, String> {
    authority
        .epoch
        .epoch_start_height
        .checked_add(
            authority
                .epoch
                .lease_index(height)
                .map_err(|e| e.to_string())?
                .checked_add(1)
                .and_then(|n| n.checked_mul(authority.epoch.leader_lease_blocks))
                .ok_or("checkpoint lease overflow")?,
        )
        .and_then(|h| h.checked_sub(1))
        .ok_or("checkpoint lease overflow".into())
}

fn read_page(
    file: &mut File,
    budget: &Arc<WorldResourceBudget>,
) -> Result<
    (
        Page,
        String,
        synergy_state::world_resources::WorldResourcePermit,
    ),
    String,
> {
    let mut length = [0u8; 8];
    file.read_exact(&mut length)
        .map_err(|e| format!("checkpoint frame length: {e}"))?;
    let length = u64::from_le_bytes(length);
    if length == 0 || length > MAX_PROOF_BYTES {
        return Err("checkpoint frame exceeds bounded capacity".into());
    }
    // Includes serialized frame, decoded unique facts, overlapping witnesses,
    // staging maps, returned transitions and signature-verification scratch.
    let permit = budget
        .reserve(
            (length as usize)
                .checked_mul(12)
                .and_then(|n| n.checked_add(64 * 1024))
                .ok_or("checkpoint page charge overflow")?,
        )
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![0; length as usize];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("checkpoint frame: {e}"))?;
    let hash = synergy_block::hash_block_bytes(&bytes);
    let page = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    Ok((page, hash, permit))
}

fn page_witnesses(
    page: &Page,
    next: u64,
    head: u64,
    authority: &VerifiedAuthority,
) -> Result<Vec<FinalitySyncWitness>, String> {
    let end = lease_end(next, authority)?.min(head);
    let apply = if end == head {
        end.checked_add(2).ok_or("checkpoint height overflow")?
    } else {
        end
    };
    if page.first_height != next
        || page.last_height != end
        || page.apply_through != apply
        || page.certificates.len() as u64 != end - next + 3
    {
        return Err("checkpoint lease page is not contiguous/canonical".into());
    }
    let mut qcs = BTreeMap::new();
    let mut tcs = BTreeMap::new();
    for qc in &page.certificates {
        if qc.context.height < next
            || qc.context.height > end + 2
            || qcs.insert(qc.context.height, qc).is_some()
        {
            return Err("checkpoint repeats/outscopes QC".into());
        }
        qc.verify(&authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?;
    }
    for tc in &page.timeouts {
        tc.verify(&authority.epoch, &authority.registry, authority)
            .map_err(|e| e.to_string())?;
        if tcs
            .insert(tc.id().map_err(|e| e.to_string())?, tc)
            .is_some()
        {
            return Err("checkpoint repeats timeout".into());
        }
    }
    let mut witnesses = Vec::new();
    let mut used = BTreeSet::new();
    for height in next..=end {
        let chain: Vec<_> = (height..=height + 2)
            .map(|h| {
                qcs.get(&h)
                    .map(|v| (*v).clone())
                    .ok_or("checkpoint certified prefix has a gap")
            })
            .collect::<Result<_, _>>()?;
        let mut closure = BTreeMap::new();
        for qc in &chain {
            if qc.context.round > tcs.len() as u64 {
                return Err("checkpoint omits timeout closure".into());
            }
            let mut expected = qc.takeover_tc_id.clone();
            for _ in 0..qc.context.round {
                let id = expected
                    .as_ref()
                    .ok_or("checkpoint timeout predecessor missing")?;
                let tc = tcs
                    .get(id)
                    .ok_or("checkpoint timeout predecessor unavailable")?;
                used.insert(id.clone());
                closure.insert((tc.context.height, tc.context.round), (*tc).clone());
                expected = tc.previous_tc_id.clone();
            }
            if expected.is_some() {
                return Err("checkpoint timeout closure does not end at round zero".into());
            }
        }
        let witness = FinalitySyncWitness {
            quorum_certificates: chain.try_into().map_err(|_| "checkpoint QC triple")?,
            timeout_certificates: closure.into_values().collect(),
        };
        witness_record(&witness, authority)?;
        witnesses.push(witness);
    }
    if used.len() != tcs.len() {
        return Err("checkpoint contains unreferenced timeouts".into());
    }
    Ok(witnesses)
}

fn verify_preview(preview: &[SimplifiedQuorumCertificate], page: &Page) -> Result<(), String> {
    if !preview.is_empty() && page.certificates.get(..2) != Some(preview) {
        return Err("checkpoint page QC lookahead conflicts".into());
    }
    Ok(())
}
fn import(
    request: &Request,
    authority: &Arc<VerifiedAuthority>,
    layout: &NodeStorageLayout,
    budget: &Arc<WorldResourceBudget>,
) -> Result<serde_json::Value, String> {
    let metadata = fs::symlink_metadata(&request.bundle).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("checkpoint bundle is not a canonical directory".into());
    }
    let manifest: Manifest = serde_json::from_slice(&read_bounded(
        &request.bundle.join("manifest.json"),
        64 * 1024,
    )?)
    .map_err(|e| e.to_string())?;
    let from = manifest.anchor.height;
    let height = manifest.checkpoint.height;
    if manifest.version != 2
        || manifest.chain_id != authority.epoch.chain_id
        || manifest.network_id != authority.epoch.network_id
        || manifest.epoch_context_root != authority.epoch.root().map_err(|e| e.to_string())?
        || from == 0
        || height < from
        || manifest.pages == 0
        || manifest.pages > MAX_PAGES
        || !(2..=3).contains(&manifest.files.len())
        || !authority.epoch.contains_height(from)
        || !authority
            .epoch
            .contains_height(height.checked_add(2).ok_or("checkpoint height overflow")?)
    {
        return Err("checkpoint manifest scope/range differs from authenticated authority".into());
    }
    for name in manifest.files.keys() {
        if !matches!(
            name.as_str(),
            "candidate.json" | "processing-replay.json" | AUTHORIZATION_SOURCE
        ) {
            return Err("unexpected checkpoint file path".into());
        }
    }
    let read = |name: &str, max: u64| -> Result<Vec<u8>, String> {
        let expected = manifest
            .files
            .get(name)
            .ok_or("checkpoint file is not committed by manifest")?;
        let bytes = read_bounded(&request.bundle.join(name), max)?;
        if synergy_block::hash_block_bytes(&bytes) != *expected {
            return Err("checkpoint file hash mismatch".into());
        }
        Ok(bytes)
    };
    let candidate_bytes = read("candidate.json", MAX_CANDIDATE_BYTES)?;
    let candidate = synergy_execution::decode_budgeted_candidate(&candidate_bytes, budget)
        .map_err(|e| e.to_string())?;
    drop(candidate_bytes);
    verify_candidate(&candidate, &manifest.checkpoint)?;
    let replay = read("processing-replay.json", MAX_PROOF_BYTES)?;
    let namespace = processing_pipeline::processing_namespace(authority, budget)?;
    let _replay_decode = budget
        .reserve(
            replay
                .len()
                .checked_mul(4)
                .and_then(|n| n.checked_add(64 * 1024))
                .ok_or("checkpoint replay charge overflow")?,
        )
        .map_err(|e| e.to_string())?;
    let root = layout.consensus().join("posy");
    let qcs = VerifiedQuorumCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let tcs = VerifiedTimeoutCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let finality = FinalityStore::new(&root).map_err(|e| e.to_string())?;
    if finality.get(from).map_err(|e| e.to_string())?.as_ref() != Some(&manifest.anchor) {
        return Err("checkpoint does not extend local finalized anchor".into());
    }
    let mut state =
        FinalizedStateStore::load_budgeted(layout.state().join("execution"), Arc::clone(budget))
            .map_err(|e| format!("{e:?}"))?;
    let current = state
        .current()
        .ok_or("checkpoint import requires existing execution state")?;
    if !((current.finalized_height == from
        && current.finalized_block_id == manifest.anchor.block_id)
        || (current.finalized_height == height
            && current.finalized_block_id == candidate.block_id
            && current.state_root == candidate.state_root))
    {
        return Err("checkpoint import cannot replace a different execution anchor".into());
    }
    let mut candidates = CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        Arc::clone(budget),
    )?;
    let source_height = authorization_source_height(&candidate)?;
    let mut source_verified = false;
    let source = if source_height > 0 && source_height != height {
        let stored = candidates
            .get_budgeted(source_height)
            .map_err(|e| e.to_string())?;
        let source = if manifest.files.contains_key(AUTHORIZATION_SOURCE) {
            let bytes = read(AUTHORIZATION_SOURCE, MAX_CANDIDATE_BYTES)?;
            let source = synergy_execution::decode_budgeted_candidate(&bytes, budget)
                .map_err(|e| e.to_string())?;
            if stored.as_ref().is_some_and(|existing| existing != &source) {
                return Err(
                    "checkpoint authorization source conflicts with durable candidate".into(),
                );
            }
            source
        } else {
            stored.ok_or_else(|| {
                format!("checkpoint missing required authorization source at H{source_height}")
            })?
        };
        verify_authorization_source(&candidate, &source)?;
        if source_height < from {
            verify_durable_candidate(&source, authority, &qcs, &tcs, &finality)?;
            source_verified = true;
        }
        Some(source)
    } else {
        if manifest.files.contains_key(AUTHORIZATION_SOURCE) {
            return Err("checkpoint includes an unreferenced authorization source".into());
        }
        None
    };
    // Refuse to synthesize a missing journal. Its floor advances only after
    // all authenticated commits and the complete checkpoint are durable.
    read_bounded(&root.join("sign-once.json"), 16 * 1024 * 1024)?;
    let mut journal =
        SignOnceJournal::load(root.join("sign-once.json")).map_err(|e| format!("{e:?}"))?;
    if journal.finalized_floor() > height {
        return Err("checkpoint would regress signing floor".into());
    }
    let proof_budget = WorldResourceBudget::new(256 * 1024 * 1024);
    let _catalog = proof_budget
        .reserve(
            (manifest.pages as usize)
                .checked_mul(128)
                .ok_or("checkpoint catalog overflow")?,
        )
        .map_err(|e| e.to_string())?;
    let prefix = request.bundle.join("prefix.bin");
    let metadata = fs::symlink_metadata(&prefix).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("checkpoint prefix must be regular".into());
    }
    let mut stream = File::open(&prefix).map_err(|e| e.to_string())?;
    let mut hashes = Vec::with_capacity(manifest.pages as usize);
    let mut chain = chain_start();
    let mut next = from;
    let mut staged =
        posy::begin_checkpoint_projection(authority, &qcs, &tcs, &finality, Some(from))?;
    let mut head_qc = None;
    let _preview_charge = proof_budget
        .reserve(2 * MAX_PROOF_BYTES as usize)
        .map_err(|e| e.to_string())?;
    let mut preview = Vec::new();
    // First pass validates the ENTIRE streamed prefix and every local safety
    // conflict before writing any consensus, candidate, replay, or world fact.
    for _ in 0..manifest.pages {
        let (page, hash, _permit) = read_page(&mut stream, &proof_budget)?;
        verify_preview(&preview, &page)?;
        preview = page
            .certificates
            .iter()
            .rev()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        preview.reverse();
        let witnesses = page_witnesses(&page, next, height, authority)?;
        if next == from && witness_record(&witnesses[0], authority)? != manifest.anchor {
            return Err("checkpoint prefix anchor mismatch".into());
        }
        if let Some(source) = source
            .as_ref()
            .filter(|source| (next..=page.last_height).contains(&source.height))
        {
            let witness = &witnesses[(source.height - next) as usize];
            verify_candidate(source, &witness_record(witness, authority)?)?;
            source_verified = true;
        }
        if page.last_height == height {
            let last = witnesses.last().ok_or("checkpoint empty final page")?;
            if witness_record(last, authority)? != manifest.checkpoint {
                return Err("checkpoint prefix finality mismatch".into());
            }
            processing_proposals::verify_checkpoint_replay(
                &replay,
                &candidate,
                &last.quorum_certificates[0],
                authority,
                &namespace,
            )?;
            head_qc = Some(last.quorum_certificates[0].clone());
        }
        let (machine, _transitions) = posy::stage_offline_checkpoint_page(
            authority,
            &qcs,
            &tcs,
            &finality,
            &witnesses,
            staged,
            posy::CheckpointPageApplication {
                through: page.apply_through,
                initial_anchor: (next == from && page.last_height < height)
                    .then_some(&manifest.anchor),
            },
        )?;
        staged = machine;
        next = page
            .last_height
            .checked_add(1)
            .ok_or("checkpoint height overflow")?;
        chain = chain_next(&chain, &hash);
        hashes.push(hash);
    }
    let mut trailing = [0];
    if stream.read(&mut trailing).map_err(|e| e.to_string())? != 0
        || next != height + 1
        || chain != manifest.prefix_chain
    {
        return Err("checkpoint prefix length/hash mismatch".into());
    }
    staged = posy::finish_checkpoint_projection(authority, &tcs, staged)?;
    if staged.last_finalized() != Some(&manifest.checkpoint) {
        return Err("checkpoint staged consensus head mismatch".into());
    }
    drop(staged);
    if source.is_some() && !source_verified {
        return Err("checkpoint authorization source lacks finalized proof".into());
    }
    let head_qc = head_qc.ok_or("checkpoint lacks head QC")?;
    if let Some(old) = candidates.get_budgeted(height).map_err(|e| e.to_string())? {
        if old != candidate {
            return Err("checkpoint conflicts with existing durable candidate".into());
        }
    }
    let mut processing = processing_proposals::ProcessingProposalStore::open(
        &super::processing_proposals::epoch_store_path(&layout.blocks(), authority.epoch.epoch),
        namespace,
        budget,
        Arc::clone(authority),
    )?;
    let atomic = AtomicConsensusTransitionStore::new(&root).map_err(|e| e.to_string())?;
    // Re-read the SAME open inode, checking each frame against its first-pass
    // hash before a commit. A changed bundle can never introduce an unverified
    // later page after earlier pages have been acknowledged.
    stream.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut staged =
        posy::begin_checkpoint_projection(authority, &qcs, &tcs, &finality, Some(from))?;
    next = from;
    preview.clear();
    for expected in &hashes {
        let (page, hash, _permit) = read_page(&mut stream, &proof_budget)?;
        if &hash != expected {
            return Err("checkpoint changed after full verification".into());
        }
        verify_preview(&preview, &page)?;
        preview = page
            .certificates
            .iter()
            .rev()
            .take(2)
            .cloned()
            .collect::<Vec<_>>();
        preview.reverse();
        let witnesses = page_witnesses(&page, next, height, authority)?;
        let covered = page.apply_through < staged.active_slot().0;
        let (machine, transitions) = posy::stage_offline_checkpoint_page(
            authority,
            &qcs,
            &tcs,
            &finality,
            &witnesses,
            staged,
            posy::CheckpointPageApplication {
                through: page.apply_through,
                initial_anchor: (next == from && page.last_height < height)
                    .then_some(&manifest.anchor),
            },
        )?;
        staged = machine;
        next = page.last_height + 1;
        if covered {
            continue;
        }
        for tc in &page.timeouts {
            tcs.put_verified(
                tc,
                &authority.epoch,
                &authority.registry,
                authority.as_ref(),
            )
            .map_err(|e| e.to_string())?;
        }
        for (qc, record) in &transitions {
            if let Some(record) = record {
                let previous = record
                    .height
                    .checked_sub(1)
                    .filter(|h| *h > 0)
                    .map(|h| finality.get(h).map_err(|e| e.to_string()))
                    .transpose()?
                    .flatten();
                atomic
                    .commit_verified_qc_and_finality(
                        qc,
                        record,
                        previous.as_ref(),
                        &authority.epoch,
                        &authority.registry,
                        authority.as_ref(),
                    )
                    .map_err(|e| e.to_string())?;
            } else {
                qcs.put_verified(
                    qc,
                    &authority.epoch,
                    &authority.registry,
                    authority.as_ref(),
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    let staged = posy::finish_checkpoint_projection(authority, &tcs, staged)?;
    if staged.last_finalized() != Some(&manifest.checkpoint)
        || finality.get(height).map_err(|e| e.to_string())?.as_ref() != Some(&manifest.checkpoint)
    {
        return Err("checkpoint durable finality readback mismatch".into());
    }
    #[cfg(test)]
    failpoint("consensus")?;
    candidates
        .put_budgeted(&candidate, candidate.state.as_ref().as_ref())
        .map_err(|e| e.to_string())?;
    processing.import_checkpoint(&replay, &candidate, &head_qc)?;
    #[cfg(test)]
    failpoint("candidate")?;
    state
        .commit_verified_snapshot(
            FinalizedState {
                finalized_height: height,
                finalized_block_id: candidate.block_id.clone(),
                state_root: candidate.state_root.clone(),
            },
            candidate.state.as_ref().as_ref(),
        )
        .map_err(|e| format!("{e:?}"))?;
    if let Some(source) = &source {
        install_authorization_source(source, &mut candidates, &mut state)?;
    } else if source_height == height {
        install_authorization_source(&candidate, &mut candidates, &mut state)?;
    }
    #[cfg(test)]
    failpoint("world")?;
    // This is the same verified-finality journal advancement used by the PoSy
    // owner, after every checkpoint dependency is durable. No signature is made
    // and reservations above the finalized checkpoint remain authoritative.
    journal
        .advance_finalized_floor(height)
        .map_err(|e| format!("{e:?}"))?;
    Ok(
        serde_json::json!({"imported": true, "from_height": from, "checkpoint_height": height, "pages": manifest.pages,
        "block_id": candidate.block_id, "state_root": candidate.state_root, "signing": false,
        "authorization_source_height": source_height,
        "signing_floor_advanced_after_verified_commit": true, "skipped_transitions_locally_reexecuted": false}),
    )
}

fn verify_candidate(
    candidate: &BudgetedExecutionCandidate,
    record: &FinalizedBlockRecord,
) -> Result<(), String> {
    candidate.validate()?;
    if candidate.height != record.height
        || candidate.block_id != record.block_id
        || candidate.protected_execution_root != record.protected_execution_root
    {
        return Err("checkpoint candidate differs from exact native finality".into());
    }
    Ok(())
}

#[cfg(test)]
thread_local! { static STOP_AFTER: std::cell::RefCell<Option<&'static str>> = const { std::cell::RefCell::new(None) }; }
#[cfg(test)]
fn failpoint(stage: &'static str) -> Result<(), String> {
    STOP_AFTER.with(|v| {
        if *v.borrow() == Some(stage) {
            Err(format!("checkpoint interrupted after {stage}"))
        } else {
            Ok(())
        }
    })
}
#[cfg(test)]
pub(super) fn fixture_run(
    request: &Request,
    configuration: &synergy_config::NodeConfiguration,
    stop: Option<&'static str>,
) -> Result<serde_json::Value, String> {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            STOP_AFTER.with(|v| *v.borrow_mut() = None);
        }
    }
    let _reset = Reset;
    STOP_AFTER.with(|v| *v.borrow_mut() = stop);
    let authority = super::authority::load(configuration)?.ok_or("fixture missing authority")?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    let budget = WorldResourceBudget::new(configuration.storage.world_memory_budget_bytes);
    match request.action {
        Action::Import => import(request, &authority, &layout, &budget),
        Action::Export => export(request, &authority, &layout, &budget),
        Action::RestoreAuthorizationSource => {
            restore_authorization_source(request, &authority, &layout, &budget)
        }
    }
}
