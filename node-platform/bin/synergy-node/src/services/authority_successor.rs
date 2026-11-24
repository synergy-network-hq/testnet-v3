//! Offline ordinary continuation under the root authenticated by the existing
//! lost-root recovery certificate. This does not replace that certificate or
//! grant authority from local state, mutable configuration, or a new key.
use super::*;
use crate::services::{
    apqe_rpc::Admission,
    apqe_transport::{self, Snapshot, Stamp},
    processing_pipeline::{processing_namespace, NativeProcessingParent},
    processing_proposals::{epoch_store_path, ProcessingProposalStore},
};
use std::path::PathBuf;
use synergy_genesis::authority::VerifiedWalletDispatchRelease;
use synergy_posy::persistence::{FinalityStore, VerifiedQuorumCertificateStore};

#[cfg(test)]
#[path = "authority_wallet_dispatch_tests.rs"]
mod wallet_dispatch_tests;
#[cfg(test)]
pub(crate) use wallet_dispatch_tests::stage_process_wallet_release;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    version: u32,
    previous_authority_binding: Vec<u8>,
    witness: Witness,
    successor_authority_binding: Vec<u8>,
}

/// Compact public inputs for offline proof qualification. Decoding this
/// structure never activates a successor or authorizes peer membership.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedEpochProof {
    authorization: EpochTransitionAuthorization,
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
    closing_material: synergy_etdag::execution::CandidateProtectedMaterial,
    next_validators: Vec<ValidatorRecord>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedEpochProofChain {
    version: u32,
    origin_context_root: String,
    transitions: Vec<DerivedEpochProof>,
}

struct VerifiedDerivedEpoch {
    context: SimplifiedEpochContext,
    parent: SimplifiedFinalityParent,
    registry: FrozenValidatorRegistry,
    policy: ProtectedEpochPolicy,
}

/// A one-time protocol activation on an already certified chain. Its exact
/// bytes are pinned by the activated configuration; the legacy candidate is
/// not rewritten to pretend it committed a POSY-00E subject.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomousBootstrap {
    version: u32,
    genesis_hash: String,
    previous_binding_sha256: String,
    authorization: EpochTransitionAuthorization,
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
}

fn native_autonomous_authority(
    previous: Arc<VerifiedAuthority>,
    verified: VerifiedDerivedEpoch,
    closure: VerifiedAutonomousClosure,
) -> Arc<VerifiedAuthority> {
    let mut native = previous.as_ref().clone();
    native.registry = verified.registry;
    native.epoch = verified.context;
    native.anchor_parent = verified.parent;
    native.protected = Some(Arc::new(verified.policy));
    native.timeout_predecessor = Some(previous);
    native.autonomous_closure = Some(Arc::new(closure));
    Arc::new(native)
}

pub(crate) fn load_autonomous(
    configuration: &NodeConfiguration,
    activation: &synergy_config::AutonomousEpochActivation,
    origin: Arc<VerifiedAuthority>,
) -> Result<Arc<VerifiedAuthority>, String> {
    let bytes = apqe_transport::read(&activation.path, 4 * 1024 * 1024, false)?;
    let authority = attach_public_proof(
        verify_pinned_bootstrap_bytes(configuration, origin, &activation.sha256, &bytes)?,
        AutonomousProofFile {
            path: activation.path.clone(),
            sha256: activation.sha256.clone(),
            kind: "bootstrap-v1",
        },
    )?;

    load_fresh_autonomous(configuration, authority)
}

/// Replay only sequential native closures from an authenticated autonomous
/// origin (fresh signed Genesis or the historical pinned activation).
pub(crate) fn load_fresh_autonomous(
    configuration: &NodeConfiguration,
    mut authority: Arc<VerifiedAuthority>,
) -> Result<Arc<VerifiedAuthority>, String> {
    if !authority.autonomous_epochs_enabled() {
        return Err("autonomous history lacks authenticated origin".into());
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    let root = layout.consensus().join("autonomous-epochs");
    loop {
        let epoch = authority
            .epoch
            .epoch
            .checked_add(1)
            .ok_or("autonomous epoch overflow")?;
        let path = root.join(format!("epoch-{epoch:020}.json"));
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("read autonomous successor metadata: {error}")),
            Ok(_) => {}
        }
        authority = load_next_autonomous(authority, path)?;
    }
    Ok(authority)
}

fn attach_public_proof(
    mut authority: Arc<VerifiedAuthority>,
    proof: AutonomousProofFile,
) -> Result<Arc<VerifiedAuthority>, String> {
    let closure = Arc::get_mut(&mut authority)
        .and_then(|authority| authority.autonomous_closure.as_mut())
        .and_then(Arc::get_mut)
        .ok_or("new authority must privately own its verified proof before publication")?;
    closure.public = Some(proof);
    Ok(authority)
}

fn load_next_autonomous(
    previous: Arc<VerifiedAuthority>,
    path: std::path::PathBuf,
) -> Result<Arc<VerifiedAuthority>, String> {
    let bytes = apqe_transport::read(&path, 4 * 1024 * 1024, false)?;
    let verified = verify_next_derived_bytes(previous, &bytes)?;
    attach_public_proof(
        verified,
        AutonomousProofFile {
            path,
            sha256: apqe_transport::sha256(&bytes),
            kind: "derived-v1",
        },
    )
}

pub(crate) fn load_next_runtime_autonomous(
    configuration: &NodeConfiguration,
    previous: Arc<VerifiedAuthority>,
    epoch: u64,
) -> Result<Arc<VerifiedAuthority>, String> {
    if !previous.autonomous_epochs_enabled() || previous.epoch.epoch.checked_add(1) != Some(epoch) {
        return Err("cannot rebind to a nonsequential autonomous successor".into());
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|e| e.to_string())?;
    load_next_autonomous(
        previous,
        layout
            .consensus()
            .join("autonomous-epochs")
            .join(format!("epoch-{epoch:020}.json")),
    )
}

/// Authenticate exact public bootstrap bytes without publishing or activating them.
pub(crate) fn verify_pinned_bootstrap_bytes(
    configuration: &NodeConfiguration,
    origin: Arc<VerifiedAuthority>,
    expected_sha256: &str,
    bytes: &[u8],
) -> Result<Arc<VerifiedAuthority>, String> {
    if bytes.is_empty()
        || bytes.len() > 4 * 1024 * 1024
        || apqe_transport::sha256(bytes) != expected_sha256
    {
        return Err(
            "autonomous activation differs from its approved SHA-256 pin or size bound".into(),
        );
    }
    let activation =
        serde_json::from_slice(bytes).map_err(|e| format!("decode autonomous activation: {e}"))?;
    verify_autonomous_bootstrap(configuration, origin, activation)
}

/// Verify one bounded public successor against its already authenticated predecessor.
pub(crate) fn verify_next_derived_bytes(
    previous: Arc<VerifiedAuthority>,
    bytes: &[u8],
) -> Result<Arc<VerifiedAuthority>, String> {
    verify_next_derived_with_wallet_release(previous, bytes, None)
}

/// The same proof verifier accepts an independently authenticated release
/// capability when the platform's managed release owner supplies it. Proof
/// bytes alone and ordinary startup cannot nominate the release.
pub(super) fn verify_next_derived_with_wallet_release(
    previous: Arc<VerifiedAuthority>,
    bytes: &[u8],
    release: Option<&VerifiedWalletDispatchRelease>,
) -> Result<Arc<VerifiedAuthority>, String> {
    if !previous.autonomous_epochs_enabled() || bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err(
            "derived proof lacks an autonomous predecessor or exceeds its size bound".into(),
        );
    }
    let proof =
        serde_json::from_slice(bytes).map_err(|e| format!("decode successor proof: {e}"))?;
    verify_native_successor(previous, proof, release)
}

fn verify_autonomous_bootstrap(
    configuration: &NodeConfiguration,
    origin: Arc<VerifiedAuthority>,
    activation: AutonomousBootstrap,
) -> Result<Arc<VerifiedAuthority>, String> {
    if activation.version != 1
        || activation.genesis_hash != crate::commands::selected_network::verify(configuration)?
        || activation.previous_binding_sha256 != apqe_transport::sha256(origin.binding_bytes())
        || !origin.processing_profile_enabled()
    {
        return Err("autonomous activation differs from the authenticated chain or origin".into());
    }
    let policy = origin
        .protected
        .as_ref()
        .ok_or("origin processing policy missing")?;
    let (subject, policy) = unchanged_successor_subject(&origin.epoch, &origin.registry, policy)?;
    if subject != activation.authorization {
        return Err("activation is not the exact unchanged-governance successor".into());
    }
    let registry = FrozenValidatorRegistry::new(
        subject.next_epoch,
        origin.registry.active().cloned().collect(),
    )
    .map_err(|e| e.to_string())?;
    let subject_root = subject.subject_root_v2().map_err(|e| e.to_string())?;
    let (context, parent) = subject
        .derive_from_finalized_subject(
            &origin.epoch,
            &origin.registry,
            &registry,
            &activation.finalized,
            &activation.witness,
            &subject_root,
            origin.as_ref(),
        )
        .map_err(|e| format!("authenticate pinned activation against original quorum: {e}"))?;
    Ok(native_autonomous_authority(
        origin,
        VerifiedDerivedEpoch {
            context,
            parent,
            registry,
            policy,
        },
        VerifiedAutonomousClosure {
            authorization: subject,
            finalized: activation.finalized,
            witness: activation.witness,
            subject_root,
            public: None,
        },
    ))
}

fn verify_native_successor(
    previous: Arc<VerifiedAuthority>,
    proof: DerivedEpochProof,
    wallet_release: Option<&VerifiedWalletDispatchRelease>,
) -> Result<Arc<VerifiedAuthority>, String> {
    let wallet_release = wallet_release.or_else(|| previous.pending_wallet_release(&previous.epoch));
    if let Some(release) = wallet_release {
        let SimplifiedFinalityParent::Genesis { genesis_hash, .. } =
            &previous.autonomous_processing_origin().anchor_parent
        else {
            return Err("Wallet release requires the authenticated original Genesis".into());
        };
        if release.policy().genesis_hash != *genesis_hash {
            return Err("Wallet release does not select the successor's original Genesis".into());
        }
    }
    let policy = previous
        .protected
        .as_ref()
        .ok_or("predecessor processing policy missing")?;
    let verified = verify_derived_epoch_in_scope(
        &previous.epoch,
        &previous.registry,
        policy,
        previous.as_ref(),
        &proof,
        wallet_release,
    )?;
    let subject_root = proof
        .authorization
        .subject_root_v2()
        .map_err(|e| e.to_string())?;
    Ok(native_autonomous_authority(
        previous,
        verified,
        VerifiedAutonomousClosure {
            authorization: proof.authorization,
            finalized: proof.finalized,
            witness: proof.witness,
            subject_root,
            public: None,
        },
    ))
}

pub(crate) fn persist_native_successor(
    root: &Path,
    current: &Arc<VerifiedAuthority>,
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
    candidate: &synergy_execution::BudgetedExecutionCandidate,
) -> Result<u64, String> {
    if !current.autonomous_epochs_enabled() {
        return Err("native successor lacks an authenticated autonomous origin".into());
    }
    current.verify_processing_candidate(candidate)?;
    if candidate.height != finalized.height
        || candidate.block_id != finalized.block_id
        || candidate.protected_execution_root != finalized.protected_execution_root
    {
        return Err("durable epoch-close candidate differs from finality".into());
    }
    let policy = current
        .protected
        .as_ref()
        .ok_or("active processing policy missing")?;
    let (authorization, _) = governed_successor_subject(
        &current.epoch, &current.registry, policy, current.pending_wallet_release(&current.epoch),
    )?;
    let epoch = authorization.next_epoch;
    let proof = DerivedEpochProof {
        authorization,
        finalized,
        witness,
        closing_material: candidate.protected_material.clone(),
        next_validators: current.registry.active().cloned().collect(),
    };
    let bytes = serde_json::to_vec(&proof).map_err(|e| e.to_string())?;
    let expected = verify_native_successor(Arc::clone(current), proof, None)?;
    let store = AtomicStore::new(root, 4 * 1024 * 1024).map_err(|e| e.to_string())?;
    let name = format!("epoch-{epoch:020}.json");
    if store.exists(&name).map_err(|e| e.to_string())? {
        let stored = store.read_bounded(&name).map_err(|e| e.to_string())?;
        let decoded = serde_json::from_slice(&stored).map_err(|e| e.to_string())?;
        let existing = verify_native_successor(Arc::clone(current), decoded, None)?;
        if existing.epoch != expected.epoch || existing.anchor_parent != expected.anchor_parent {
            return Err("durable autonomous successor conflicts with the current closure".into());
        }
    } else {
        store
            .write_atomic(&name, &bytes)
            .map_err(|e| e.to_string())?;
    }
    Ok(epoch)
}

/// Read-only proof cursor. It cannot return a live authority binding, peer
/// registry or signing capability. Only a verified closure can advance it.
struct DerivedEpochVerifier<'a> {
    origin: &'a VerifiedAuthority,
    context: SimplifiedEpochContext,
    registry: FrozenValidatorRegistry,
    policy: Arc<ProtectedEpochPolicy>,
}

impl<'a> DerivedEpochVerifier<'a> {
    fn new(origin: &'a VerifiedAuthority) -> Result<Self, String> {
        Ok(Self {
            origin,
            context: origin.epoch.clone(),
            registry: origin.registry.clone(),
            policy: origin
                .protected
                .clone()
                .ok_or("previous authority lacks ETDAG policy")?,
        })
    }

    fn advance(&mut self, proof: &DerivedEpochProof) -> Result<SimplifiedFinalityParent, String> {
        let verified = verify_derived_epoch_in_scope(
            &self.context,
            &self.registry,
            &self.policy,
            self,
            proof,
            self.origin.pending_wallet_release(&self.context),
        )?;
        self.context = verified.context;
        self.registry = verified.registry;
        self.policy = Arc::new(verified.policy);
        Ok(verified.parent)
    }
}

impl ConsensusSignatureVerifier for DerivedEpochVerifier<'_> {
    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()> {
        self.origin.verify_consensus_signature_in_epoch(
            domain,
            payload,
            validator,
            key_id,
            self.context.epoch,
            epoch,
            signature,
        )
    }

    fn verify_timeout_boundary_parent(
        &self,
        successor: &SimplifiedEpochContext,
        proof: &SimplifiedQuorumCertificate,
    ) -> PosyResult<()> {
        // Closing proofs for derived 1,000-block epochs are confined to the
        // last lease. They cannot include a first-lease boundary parent.
        if self.context != self.origin.epoch || successor != &self.context {
            return Err(PosyError::invalid(
                "closing proof references another epoch's boundary",
            ));
        }
        self.origin.verify_timeout_boundary_parent(successor, proof)
    }
}

#[cfg(test)]
fn verify_derived_epoch(
    previous: &VerifiedAuthority,
    proof: &DerivedEpochProof,
) -> Result<(SimplifiedEpochContext, SimplifiedFinalityParent), String> {
    let mut cursor = DerivedEpochVerifier::new(previous)?;
    let parent = cursor.advance(proof)?;
    Ok((cursor.context, parent))
}

fn verify_derived_epoch_in_scope(
    previous: &SimplifiedEpochContext,
    previous_registry: &FrozenValidatorRegistry,
    policy: &ProtectedEpochPolicy,
    verifier: &impl ConsensusSignatureVerifier,
    proof: &DerivedEpochProof,
    wallet_release: Option<&VerifiedWalletDispatchRelease>,
) -> Result<VerifiedDerivedEpoch, String> {
    if proof
        .next_validators
        .iter()
        .any(|validator| !validator.may_sign_consensus())
    {
        return Err("derived epoch proof includes a validator outside the active set".into());
    }
    let next_registry = FrozenValidatorRegistry::new(
        proof.authorization.next_epoch,
        proof.next_validators.clone(),
    )
    .map_err(|e| e.to_string())?;
    let (expected, next_policy) =
        governed_successor_subject(previous, previous_registry, policy, wallet_release)?;
    if proof.authorization != expected {
        return Err("epoch subject differs from independently derived rollover policy".into());
    }
    let subject = proof
        .closing_material
        .epoch_subject_from_commitment(
            proof.finalized.height,
            &proof.finalized.protected_execution_root,
            synergy_block::hash_block_bytes,
        )
        .map_err(|e| {
            format!("epoch closure lacks its exact protected transition subject: {e:?}")
        })?;
    let (context, parent) = proof
        .authorization
        .derive_from_finalized_subject(
            previous,
            previous_registry,
            &next_registry,
            &proof.finalized,
            &proof.witness,
            subject,
            verifier,
        )
        .map_err(|e| format!("authenticate consensus-derived epoch: {e}"))?;
    Ok(VerifiedDerivedEpoch {
        context,
        parent,
        registry: next_registry,
        policy: next_policy,
    })
}

fn verify(
    config: &NodeConfiguration,
    proposal: &Proposal,
) -> Result<(Arc<VerifiedAuthority>, Arc<VerifiedAuthority>), String> {
    if proposal.version != 1 {
        return Err("unsupported authority successor proposal".into());
    }
    let (_, recovery) = configured_certificate(config)?;
    let previous = verify_binding_bytes(config, proposal.previous_authority_binding.clone())?;
    if previous.epoch.epoch < recovery.next.epoch.epoch {
        return Err("successor predecessor predates authenticated replacement root".into());
    }
    // The predecessor itself must have a durable, authenticated origin here,
    // including on a non-signing relay.
    let predecessor_proof = transition_witness_path(config, &previous)?
        .ok_or("successor predecessor lacks its verified transition")?;
    let stored = apqe_transport::read(&predecessor_proof, 4 * 1024 * 1024, false)?;
    verify_stored_transition(config, &previous, &stored)?;
    if config.chain_id != 99999 {
        return Err("offline successor is scoped to Canary 99999".into());
    }
    let next = verify_binding_bytes(config, proposal.successor_authority_binding.clone())?;
    let [_, _, boundary] = verify_transition_witness(
        &previous,
        &proposal.witness.finalized,
        &serde_json::to_vec(&proposal.witness.certificates).map_err(|e| e.to_string())?,
    )?;
    if next.anchor_parent.quorum_certificate_reference()
        != Some(boundary.reference().map_err(|e| e.to_string())?)
    {
        return Err("successor anchor differs from certified boundary QC".into());
    }
    let established: SignedAuthorityBinding =
        serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
    let proposed: SignedAuthorityBinding =
        serde_json::from_slice(next.binding_bytes()).map_err(|e| e.to_string())?;
    if established.signer_key_id != proposed.signer_key_id
        || serde_json::to_vec(&successor_payload(established.payload, &boundary)?)
            .map_err(|e| e.to_string())?
            != serde_json::to_vec(&proposed.payload).map_err(|e| e.to_string())?
    {
        return Err("binding differs from exact authorized 1,000-block continuation".into());
    }
    EpochTransitionAuthorization {
        previous_epoch: previous.epoch.epoch,
        previous_epoch_context_root: previous.epoch.root().map_err(|e| e.to_string())?,
        finalized_height: proposal.witness.finalized.height,
        next_epoch: next.epoch.epoch,
        next_epoch_start_height: next.epoch.epoch_start_height,
        next_epoch_end_height: next.epoch.epoch_end_height,
        next_consensus_parameter_root: next.epoch.consensus_parameter_root.clone(),
        next_active_validator_set_root: next.epoch.active_validator_set_root.clone(),
        next_validator_consensus_key_root: next.epoch.validator_consensus_key_root.clone(),
        next_frozen_voting_weight_root: next.epoch.frozen_voting_weight_root.clone(),
    }
    .validate(&previous.epoch, &next.epoch, &next.registry)
    .map_err(|e| e.to_string())?;
    let current = load(config)?.ok_or("current authority is missing")?;
    if current.binding_bytes() != previous.binding_bytes()
        && current.binding_bytes() != next.binding_bytes()
    {
        return Err("installed authority is not an exact endpoint of this successor".into());
    }
    Ok((previous, next))
}

const CANARY_EPOCH_BLOCKS: u64 = 1_000;

fn governed_successor_subject(
    previous: &SimplifiedEpochContext,
    previous_registry: &FrozenValidatorRegistry,
    policy: &ProtectedEpochPolicy,
    wallet_release: Option<&VerifiedWalletDispatchRelease>,
) -> Result<(EpochTransitionAuthorization, ProtectedEpochPolicy), String> {
    match wallet_release {
        Some(release) => release.prepare_successor(previous, policy, previous_registry),
        None => unchanged_successor_subject(previous, previous_registry, policy),
    }
}

fn unchanged_successor_subject(
    previous: &SimplifiedEpochContext,
    previous_registry: &FrozenValidatorRegistry,
    policy: &ProtectedEpochPolicy,
) -> Result<(EpochTransitionAuthorization, ProtectedEpochPolicy), String> {
    let next_epoch = previous.epoch.checked_add(1).ok_or("epoch overflow")?;
    let next_policy = policy.successor_clock(previous.epoch_start_height, previous.epoch_end_height)?;
    let registry =
        FrozenValidatorRegistry::new(next_epoch, previous_registry.active().cloned().collect())
            .map_err(|e| e.to_string())?;
    let subject = EpochTransitionAuthorization::for_governed_successor(
        previous,
        &registry,
        next_policy.commitment()?,
    )
    .map_err(|e| e.to_string())?;
    Ok((subject, next_policy))
}

impl VerifiedAuthority {
    pub(crate) fn epoch_close_subject_at(&self, height: u64) -> Result<Option<String>, String> {
        if !self.autonomous_epochs_enabled()
            || height.checked_add(2) != Some(self.epoch.epoch_end_height)
        {
            return Ok(None);
        }
        let policy = self
            .protected
            .as_ref()
            .ok_or("active processing policy missing")?;
        let (subject, _) = governed_successor_subject(
            &self.epoch, &self.registry, policy, self.pending_wallet_release(&self.epoch),
        )?;
        subject
            .subject_root_v2()
            .map(Some)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn verify_processing_candidate(
        &self,
        candidate: &synergy_execution::BudgetedExecutionCandidate,
    ) -> Result<(), String> {
        if !self.epoch.contains_height(candidate.height) {
            return Err("candidate lies outside its authenticated epoch".into());
        }
        match self.epoch_close_subject_at(candidate.height)? {
            None => candidate.validate(),
            Some(root) => candidate.validate_epoch_close(candidate.height, &root),
        }
    }
}

// A spending client may use a retained immutable processing snapshot. Select its
// exact authenticated autonomous owner, never substitute the latest epoch or
// treat the RPC response itself as governance/finality evidence.
fn treasury_processing_scope(
    tip: &VerifiedAuthority,
    response: &serde_json::Value,
) -> Result<synergy_etdag::ProcessingContext, String> {
    if !tip.autonomous_processing_origin().genesis_autonomous {
        return Err("treasury lineage requires the authenticated fresh Genesis origin".into());
    }
    let context: synergy_etdag::ProcessingContext = serde_json::from_value(response["context"].clone())
        .map_err(|_| "invalid treasury processing context")?;
    context.validate().map_err(|_| "invalid treasury processing context")?;
    let c = &context.authority;
    let selected = tip.autonomous_authority_at(c.target_height)
        .ok_or("treasury processing anchor lacks authenticated autonomous history")?;
    let epoch = &selected.epoch;
    let policy = selected.protected.as_ref().ok_or("treasury processing policy missing")?;
    c.validate_with_parameters(&policy.parameters).map_err(|_| "invalid treasury source mapping")?;
    let registry: synergy_etdag::crypto::IngressKemKeyRegistry =
        serde_json::from_value(response["ingress_kem_registry"].clone())
            .map_err(|_| "invalid treasury ingress registry")?;
    registry.validate_protected_profile().map_err(|_| "invalid treasury ingress registry")?;
    if !selected.processing_profile_enabled()
        || response["profile_id"] != synergy_etdag::PROCESSING_PROFILE_ID
        || c.chain_id != epoch.chain_id || c.network_id != epoch.network_id
        || c.protocol_version != epoch.protocol_version || c.epoch != epoch.epoch
        || c.active_validator_set_root != epoch.active_validator_set_root
        || c.validator_consensus_key_root != epoch.validator_consensus_key_root
        || c.frozen_voting_weight_root != epoch.frozen_voting_weight_root
        || c.finalized_epoch_seed_root != epoch.finalized_epoch_seed_root
        || c.consensus_parameter_root != epoch.consensus_parameter_root
        || c.cluster_schedule_version != policy.cluster_schedule_version
        || c.assigned_height_schedule_root != policy.assigned_height_schedule_root
        || c.cluster_map_root != policy.cluster_map_root
        || c.assigned_cluster_id != policy.assigned_cluster_id
        || c.assigned_cluster_membership_root != policy.assigned_cluster_membership_root
        || c.cryptographic_profile_root != policy.cryptographic_profile_root
        || c.assigned_cluster_validator_count != selected.registry.active_count() as u64
        || u128::from(c.assigned_cluster_total_voting_weight) != selected.registry.active_weight().map_err(|e| e.to_string())?
        || registry != policy.ingress_kem_registry
        || registry.root().map_err(|_| "invalid treasury ingress root")? != c.ingress_kem_registry_root
        || (c.source_finalized_height == 0 && c.source_finality_context_root != selected.anchor_parent.reference_id())
    {
        return Err("treasury processing context differs from its authenticated epoch and registry".into());
    }
    Ok(context)
}

fn check_treasury_processing_context(config: &NodeConfiguration, request_path: &Path) -> Result<serde_json::Value, String> {
    let genesis_path = config.genesis_path.as_ref().ok_or("treasury Genesis absent")?;
    let root_path = config.consensus.authority_trust_key_path.as_ref().ok_or("treasury authority root absent")?;
    let binding_path = config.consensus.authority_binding.as_ref().ok_or("treasury signed authority absent")?;
    let stamps = [Stamp::capture(genesis_path)?, Stamp::capture(root_path)?, Stamp::capture(binding_path)?];
    let raw = apqe_transport::read(request_path, 2 * 1024 * 1024, false)?;
    let request: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| "invalid treasury request")?;
    let p = &request["parameters"];
    let text = p["processing_context_json"].as_str().ok_or("treasury processing bytes missing")?;
    if request["version"] != 1 || request["operation"] != "treasury_send_prepare"
        || text.is_empty() || text.len() > 1024 * 1024
        || p["processing_context_sha256"] != apqe_transport::sha256(text.as_bytes())
    {
        return Err("treasury request or exact processing digest differs".into());
    }
    // load() authenticates signed Genesis and every retained three-QC closure;
    // it reads only public authority files, never opens a FinalityStore writer.
    let tip = load(config)?.ok_or("authenticated treasury authority unavailable")?;
    let response = serde_json::from_str(text).map_err(|_| "invalid treasury processing response")?;
    let context = treasury_processing_scope(&tip, &response)?;
    let origin = tip.autonomous_processing_origin();
    let genesis = apqe_transport::read(genesis_path, 4 * 1024 * 1024, false)?;
    let genesis_sha = apqe_transport::sha256(&genesis);
    if p["genesis_sha256"] != genesis_sha {
        return Err("treasury request differs from the authenticated Genesis bytes".into());
    }
    let root = apqe_transport::read(root_path, 8192, false)?;
    if !stamps.iter().all(Stamp::unchanged) {
        return Err("treasury origin changed during native verification".into());
    }
    let selected = tip.autonomous_authority_at(context.authority.target_height).ok_or("treasury epoch disappeared")?;
    Ok(serde_json::json!({"schema":"nodenetwork-verified-treasury-context-v1",
        "request_sha256":apqe_transport::sha256(&raw),"genesis_sha256":genesis_sha,
        "authority_sha256":apqe_transport::sha256(origin.binding_bytes()),"authority_root_sha256":apqe_transport::sha256(&root),
        "processing_context_sha256":apqe_transport::sha256(text.as_bytes()),
        "processing_context_root":context.root().map_err(|_| "invalid treasury context root")?,
        "epoch_context_root":selected.epoch.root().map_err(|e| e.to_string())?,
        "epoch":selected.epoch.epoch,"chain_id":selected.epoch.chain_id,"network_id":selected.epoch.network_id}))
}

fn canary_successor_range(
    chain: u64,
    epoch: u64,
    first: u64,
    last: u64,
) -> Option<(u64, u64, u64)> {
    if chain != 99999 {
        return None;
    }
    let expected_first = if epoch == 2 {
        10_001
    } else {
        epoch
            .checked_sub(3)?
            .checked_mul(CANARY_EPOCH_BLOCKS)?
            .checked_add(20_001)?
    };
    let expected_last = if epoch == 2 {
        20_000
    } else {
        expected_first.checked_add(CANARY_EPOCH_BLOCKS - 1)?
    };
    if (first, last) != (expected_first, expected_last) {
        return None;
    }
    Some((
        epoch.checked_add(1)?,
        last.checked_add(1)?,
        last.checked_add(CANARY_EPOCH_BLOCKS)?,
    ))
}

fn successor_payload(
    mut payload: AuthorityPayload,
    boundary: &SimplifiedQuorumCertificate,
) -> Result<AuthorityPayload, String> {
    let (epoch, first, last) = canary_successor_range(
        payload.chain_id,
        payload.epoch,
        payload.epoch_start_height,
        payload.epoch_end_height,
    )
    .ok_or("predecessor is outside the established 1,000-block Canary continuation schedule")?;
    if boundary.context.height != payload.epoch_end_height {
        return Err("successor requires the certified last height of the predecessor".into());
    }
    let policy = payload
        .protected
        .as_ref()
        .ok_or("predecessor lacks ETDAG policy")?;
    let next_policy = policy.successor_clock(payload.epoch_start_height, payload.epoch_end_height)?;
    payload.consensus_parameter_root = next_policy.commitment()?;
    payload.protected = Some(next_policy);
    payload.epoch = epoch;
    payload.epoch_start_height = first;
    payload.epoch_end_height = last;
    payload.anchor_parent = SimplifiedFinalityParent::QuorumCertificate {
        height: boundary.context.height,
        block_id: boundary.block_id.clone(),
        qc_id: boundary.id().map_err(|e| e.to_string())?,
    };
    payload.validate()?;
    Ok(payload)
}

#[cfg(test)]
#[test]
fn canary_schedule_preserves_the_signed_bridge_and_continues_in_exact_windows() {
    assert_eq!(
        canary_successor_range(99999, 2, 10001, 20000),
        Some((3, 20001, 21000))
    );
    assert_eq!(
        canary_successor_range(99999, 3, 20001, 21000),
        Some((4, 21001, 22000))
    );
    assert_eq!(
        canary_successor_range(99999, 4, 21001, 22000),
        Some((5, 22001, 23000))
    );
    assert_eq!(canary_successor_range(99999, 3, 20002, 21001), None);
    assert_eq!(canary_successor_range(99999, 3, 20001, 22000), None);
    assert_eq!(canary_successor_range(1266, 3, 20001, 21000), None);
    assert_eq!(canary_successor_range(99999, 1, 1, 10000), None);
    assert_eq!(canary_successor_range(99999, u64::MAX, 20001, 21000), None);
}

fn stored_transition(
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&StoredEpochTransition {
        version: 1,
        next_epoch: next.epoch.epoch,
        previous_authority_binding: previous.binding_bytes().to_vec(),
        finalized: witness.finalized.clone(),
        finality_witness: serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
    })
    .map_err(|e| e.to_string())
}

fn verify_processing_boundary(
    config: &NodeConfiguration,
    previous: &Arc<VerifiedAuthority>,
    next: &VerifiedAuthority,
    witness: &Witness,
) -> Result<(), String> {
    if !previous.processing_profile_enabled() || !next.processing_profile_enabled() {
        return Err("Canary successor requires the existing processing profile".into());
    }
    let layout =
        NodeStorageLayout::new(config.storage.data_directory.clone()).map_err(|e| e.to_string())?;
    let budget = synergy_state::world_resources::WorldResourceBudget::new(
        config.storage.world_memory_budget_bytes,
    );
    let boundary = &witness.certificates[2];
    let candidates = synergy_execution::CandidateStore::new_budgeted(
        layout.blocks().join("execution-candidates"),
        budget.clone(),
    )?;
    let candidate = candidates
        .get_budgeted(boundary.context.height)
        .map_err(|e| e.to_string())?
        .ok_or("certified terminal execution candidate is unavailable")?;
    let transition =
        verify_stored_transition(config, next, &stored_transition(previous, next, witness)?)?;
    verify_terminal_processing_parent(config, next, &transition, candidate, &budget)
}

fn verify_terminal_processing_parent(
    config: &NodeConfiguration,
    next: &VerifiedAuthority,
    transition: &VerifiedTransitionContext,
    candidate: synergy_execution::BudgetedExecutionCandidate,
    budget: &Arc<synergy_state::world_resources::WorldResourceBudget>,
) -> Result<(), String> {
    let previous = transition.previous_authority();
    let layout =
        NodeStorageLayout::new(config.storage.data_directory.clone()).map_err(|e| e.to_string())?;
    let path = epoch_store_path(&layout.blocks(), previous.epoch.epoch);
    if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
        return Err("certified terminal proposal journal is unavailable".into());
    }
    let store = ProcessingProposalStore::open(
        &path,
        processing_namespace(previous, budget)?,
        budget,
        previous.clone(),
    )?;
    store.with_validation(&candidate.block_id, |certificate| {
        NativeProcessingParent::verify_transition(
            &candidate,
            certificate,
            previous,
            next,
            transition,
        )
        .map(|_| ())
    })
}

fn export_boundary(config: &NodeConfiguration, output: &Path) -> Result<(), String> {
    let authority = load(config)?.ok_or("missing installed authenticated authority")?;
    let root = NodeStorageLayout::new(config.storage.data_directory.clone())
        .map_err(|e| e.to_string())?
        .consensus()
        .join("posy");
    let end = authority.epoch.epoch_end_height;
    let height = end
        .checked_sub(2)
        .filter(|height| *height != 0)
        .ok_or("invalid epoch end")?;
    let finality = FinalityStore::new(&root).map_err(|e| e.to_string())?;
    let finalized = finality
        .get(height)
        .map_err(|e| e.to_string())?
        .ok_or("certified terminal finality record is not yet durable")?;
    let qcs = VerifiedQuorumCertificateStore::new(&root).map_err(|e| e.to_string())?;
    let [a, b, c] = [height, end - 1, end].map(|height| {
        qcs.get_verified(
            height,
            &authority.epoch,
            &authority.registry,
            authority.as_ref(),
        )
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("terminal QC H{height} is not durable"))
    });
    let certificates = [a?, b?, c?];
    verify_transition_witness(
        &authority,
        &finalized,
        &serde_json::to_vec(&certificates).map_err(|e| e.to_string())?,
    )?;
    write_public(
        output,
        &serde_json::to_vec(&Witness {
            finalized,
            certificates,
        })
        .map_err(|e| e.to_string())?,
    )
}

// A single offline execution owner, with no signer, network service, or node
// process. Input is an explicitly supplied scratch copy of a certified
// boundary (public authority, Worlds, replay inputs and validation proofs).
#[cfg(test)]
#[test]
#[ignore = "requires an authenticated Canary boundary export and scratch storage"]
fn native_terminal_replay_checks_exact_successor_on_existing_canary_evidence() {
    use crate::services::{execution, ingress::AuthenticatedIngress};
    use synergy_node_core::CancellationToken;

    let path = |key| PathBuf::from(std::env::var_os(key).expect(key));
    let config = synergy_config::load(&path("SYNERGY_TEST_TERMINAL_CONFIG")).unwrap();
    let decode = |file: &Path| fs::read(file).unwrap();
    let proposal: Proposal =
        serde_json::from_slice(&decode(&path("SYNERGY_TEST_TERMINAL_PROPOSAL"))).unwrap();
    let preceding: Witness =
        serde_json::from_slice(&decode(&path("SYNERGY_TEST_TERMINAL_PRECEDING"))).unwrap();
    let expected = &proposal.witness;
    let (previous, next) = verify(&config, &proposal).unwrap();
    let mut prior_finality = synergy_posy::ThreeQcFinality::default();
    for qc in preceding.certificates {
        qc.verify(&previous.epoch, &previous.registry, previous.as_ref())
            .unwrap();
        prior_finality.accept(qc).unwrap();
    }
    assert_eq!(prior_finality.last_finalized(), Some(&preceding.finalized));
    let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
    let root = layout.consensus().join("posy");
    let certificates = VerifiedQuorumCertificateStore::new(&root).unwrap();
    for qc in &expected.certificates {
        certificates
            .put_verified(qc, &previous.epoch, &previous.registry, previous.as_ref())
            .unwrap();
    }
    let finality = FinalityStore::new(&root).unwrap();
    finality
        .commit_exactly_once(&expected.finalized, Some(&preceding.finalized))
        .unwrap();
    require_validator_boundary(&config, expected).unwrap();
    assert_eq!(
        verify_processing_boundary(&config, &previous, &next, expected).unwrap_err(),
        "certified terminal execution candidate is unavailable"
    );
    let ingress = AuthenticatedIngress::with_world_budget(
        synergy_state::world_resources::WorldResourceBudget::new(
            config.storage.world_memory_budget_bytes,
        ),
    );
    let (_, mut owner) =
        execution::registration(&config, previous.clone(), ingress.clone()).unwrap();
    ingress
        .submit_finality(
            expected.finalized.clone(),
            serde_json::to_vec(&expected.certificates).unwrap(),
        )
        .unwrap();
    owner.start(&CancellationToken::default()).unwrap();
    owner.poll().unwrap();
    owner.stop().unwrap();
    require_validator_boundary(&config, expected).unwrap();
    verify_processing_boundary(&config, &previous, &next, expected).unwrap();
    assert_eq!(
        finality.get(expected.finalized.height).unwrap().as_ref(),
        Some(&expected.finalized)
    );
    assert!(finality
        .get(expected.finalized.height + 1)
        .unwrap()
        .is_none());
    assert!(finality
        .get(expected.finalized.height + 2)
        .unwrap()
        .is_none());
    assert!(!root.join("sign-once.json").exists());
}

fn write_public(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("public successor output must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error.to_string());
    }
    File::open(path.parent().ok_or("public output parent required")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| e.to_string())
}

fn with_staged_network<T>(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
    registry: &Path,
    workspace: &Path,
    f: impl FnOnce(&NodeConfiguration, &[String; 2]) -> Result<T, String>,
) -> Result<T, String> {
    if !workspace.is_absolute() {
        return Err("staged public verification workspace must be absolute".into());
    }
    fs::create_dir(workspace).map_err(|e| e.to_string())?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(workspace.to_owned());
    let mut staged = config.clone();
    let authority_path = workspace.join("authority.json");
    write_public(&authority_path, next.binding_bytes())?;
    staged.consensus.authority_binding = Some(authority_path);
    staged.storage.data_directory = workspace.join("data");
    let path = transition_witness_path(&staged, next)?
        .ok_or("staged successor requires its exact witness")?;
    fs::create_dir_all(path.parent().ok_or("staged transition parent missing")?)
        .map_err(|e| e.to_string())?;
    write_public(&path, &stored_transition(previous, next, witness)?)?;
    let transport = staged
        .apqe_transport
        .as_mut()
        .ok_or("missing APQE transport")?;
    transport.registry_path = registry.to_owned();
    let anchors = [
        transport.registry_trust_key_sha256.clone(),
        transport.genesis_trust_key_sha256.clone(),
    ];
    f(&staged, &anchors)
}

fn check_staged_network(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    next: &VerifiedAuthority,
    witness: &Witness,
    registry: &Path,
    admission: Option<&Path>,
    workspace: &Path,
) -> Result<serde_json::Value, String> {
    with_staged_network(
        config,
        previous,
        next,
        witness,
        registry,
        workspace,
        |staged, anchors| {
            let (registry_sha256, admission_sha256) = if let Some(path) = admission {
                let before = Stamp::capture(path)?;
                let admission = Admission::load(staged, path)?;
                let digest = sha256(&apqe_transport::read(path, 128 * 1024, false)?);
                if !before.unchanged() {
                    return Err("staged RPC admission changed".into());
                }
                (sha256(&admission.base.registry_bytes), Some(digest))
            } else {
                (
                    sha256(&Snapshot::load(staged, anchors)?.registry_bytes),
                    None,
                )
            };
            Ok(serde_json::json!({
                "status":"successor-network-verified",
                "registry_sha256":registry_sha256,
                "admission_sha256":admission_sha256,
            }))
        },
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AutonomousBoundary {
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum AutonomousBoundaryInput {
    Complete(AutonomousBoundary),
    CertificatesOnly(Witness),
}

impl AutonomousBoundaryInput {
    fn into_boundary(self) -> AutonomousBoundary {
        match self {
            Self::Complete(boundary) => boundary,
            Self::CertificatesOnly(boundary) => AutonomousBoundary {
                finalized: boundary.finalized,
                witness: synergy_posy::FinalitySyncWitness {
                    quorum_certificates: boundary.certificates,
                    timeout_certificates: Vec::new(),
                },
            },
        }
    }
}

fn autonomous_bootstrap_cli(
    configuration: &NodeConfiguration,
    config_path: &Path,
    input: &Path,
    output: Option<&Path>,
    local: bool,
) -> Result<(), String> {
    if output.is_some()
        && configuration
            .consensus
            .autonomous_epoch_activation
            .is_some()
    {
        return Err(
            "use the authenticated signed epoch-5 origin configuration, before activation".into(),
        );
    }
    let binding_path = configuration
        .consensus
        .authority_binding
        .as_deref()
        .ok_or("missing signed origin binding path")?;
    let stamps = [
        Stamp::capture(config_path)?,
        Stamp::capture(input)?,
        Stamp::capture(binding_path)?,
    ];
    // The terminal proof authenticates E5 directly against the signed origin.
    // Do not require or open an earlier local runtime transition journal here.
    let origin = verify_binding_bytes(
        configuration,
        apqe_transport::read(binding_path, MAX_AUTHORITY_BYTES, false)?,
    )?;
    if (
        origin.epoch.chain_id,
        origin.epoch.epoch,
        origin.epoch.epoch_start_height,
        origin.epoch.epoch_end_height,
    ) != (99999, 5, 22001, 23000)
    {
        return Err(
            "autonomous Canary bootstrap requires signed chain 99999 epoch 5 (H22001–H23000)"
                .into(),
        );
    }
    // Load only exported public evidence, never open a writable consensus store.
    let input_bytes = apqe_transport::read(input, 4 * 1024 * 1024, false)?;
    if let Some(configured) = &configuration.consensus.autonomous_epoch_activation {
        if sha256(&input_bytes) != configured.sha256 {
            return Err("candidate activation differs from the committed configuration pin".into());
        }
    }
    let bytes = if output.is_some() {
        let boundary = serde_json::from_slice::<AutonomousBoundaryInput>(&input_bytes)
            .map_err(|e| format!("decode exported autonomous boundary: {e}"))?
            .into_boundary();
        let policy = origin
            .protected
            .as_ref()
            .ok_or("origin processing policy missing")?;
        let (authorization, _) =
            unchanged_successor_subject(&origin.epoch, &origin.registry, policy)?;
        serde_json::to_vec(&AutonomousBootstrap {
            version: 1,
            genesis_hash: crate::commands::selected_network::verify(configuration)?,
            previous_binding_sha256: sha256(origin.binding_bytes()),
            authorization,
            finalized: boundary.finalized,
            witness: boundary.witness,
        })
        .map_err(|e| e.to_string())?
    } else {
        input_bytes
    };
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("autonomous bootstrap exceeds its runtime size limit".into());
    }
    let activation: AutonomousBootstrap =
        serde_json::from_slice(&bytes).map_err(|e| format!("decode autonomous bootstrap: {e}"))?;
    let finalized = activation.finalized.clone();
    let genesis_hash = activation.genesis_hash.clone();
    let previous_binding_sha256 = activation.previous_binding_sha256.clone();
    let next = verify_autonomous_bootstrap(configuration, origin, activation)?;
    if local {
        let transition = load_transition_context(configuration, &next)?
            .ok_or("autonomous boundary lacks its authenticated predecessor")?;
        require_validator_boundary(
            configuration,
            &Witness {
                finalized: finalized.clone(),
                certificates: transition.certificates().clone(),
            },
        )?;
        let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
            .map_err(|e| e.to_string())?;
        let budget = synergy_state::world_resources::WorldResourceBudget::new(
            configuration.storage.world_memory_budget_bytes,
        );
        let candidates = synergy_execution::BudgetedCandidateStore::new_budgeted(
            layout.blocks().join("execution-candidates"),
            budget.clone(),
        )?;
        let candidate = candidates
            .get_budgeted(next.anchor_parent.height())
            .map_err(|e| e.to_string())?
            .ok_or("autonomous boundary lacks the exact certified tail in durable execution")?;
        let previous = transition.previous_authority();
        let qcs = VerifiedQuorumCertificateStore::new(&layout.consensus().join("posy"))
            .map_err(|e| e.to_string())?;
        for expected in transition.certificates() {
            let height = expected.context.height;
            let local = qcs
                .get_verified(
                    height,
                    &previous.epoch,
                    &previous.registry,
                    previous.as_ref(),
                )
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("autonomous boundary lacks durable QC H{height}"))?;
            if local.reference().map_err(|e| e.to_string())?
                != expected.reference().map_err(|e| e.to_string())?
            {
                return Err(format!(
                    "durable QC H{height} differs from the autonomous boundary"
                ));
            }
        }
        let path = epoch_store_path(&layout.blocks(), previous.epoch.epoch);
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
            return Err("certified terminal proposal journal is unavailable".into());
        }
        let store = ProcessingProposalStore::open(
            &path,
            processing_namespace(previous, &budget)?,
            &budget,
            previous.clone(),
        )?;
        for qc in &transition.certificates()[1..] {
            let inputs = store
                .try_load_inputs(&qc.block_id)
                .map_err(|e| format!("certified proposal inputs H{}: {e}", qc.context.height))?;
            drop(inputs);
            store.with_validation(&qc.block_id, |vc| {
                if vc.context != qc.context
                    || vc.candidate.block_id != qc.block_id
                    || vc.candidate.parent_block_id != qc.parent_block_id
                    || vc.candidate.protected_execution_root != qc.protected_execution_root
                {
                    return Err(format!(
                        "durable proposal H{} differs from its boundary QC",
                        qc.context.height
                    ));
                }
                if qc.context.height == candidate.height {
                    NativeProcessingParent::verify_transition(
                        &candidate,
                        vc,
                        previous,
                        &next,
                        &transition,
                    )?;
                }
                Ok(())
            })?;
        }
    }
    if !stamps.iter().all(Stamp::unchanged) {
        return Err("autonomous bootstrap input changed during verification".into());
    }
    let result = serde_json::json!({
        "status": if local { "autonomous-bootstrap-local-boundary-verified" } else if output.is_some() { "autonomous-bootstrap-prepared" } else { "autonomous-bootstrap-verified" },
        "autonomous_bootstrap_sha256": sha256(&bytes),
        "genesis_hash": genesis_hash,
        "previous_authority_sha256": previous_binding_sha256,
        "finalized": finalized,
        "epoch": next.epoch.epoch,
        "epoch_start_height": next.epoch.epoch_start_height,
        "epoch_end_height": next.epoch.epoch_end_height,
        "context_root": next.epoch.root().map_err(|e| e.to_string())?,
        "certified_parent": next.anchor_parent,
        "finalized_seed_qc_id": next.epoch.finalized_epoch_seed_root,
        "activated": false,
    });
    if let Some(output) = output {
        write_public(output, &bytes)?;
    }
    println!("{}", crate::output::json::render(&result)?);
    Ok(())
}

pub(crate) fn cli(args: impl Iterator<Item = String>) -> Result<(), String> {
    let args: Vec<_> = args.take(10).collect();
    let [command, config, proposal_path, extra @ ..] = args.as_slice() else {
        return Err("usage: authority-successor check|activate|activate-observer CONFIG PROPOSAL; check-derived|check-derived-chain CONFIG PROOF; check-processing-context CONFIG SEND_REQUEST; prepare-autonomous CONFIG WITNESS OUTPUT; check-autonomous|check-autonomous-local CONFIG ARTIFACT; export-boundary CONFIG WITNESS; prepare-payload CONFIG WITNESS OUTPUT; bundle CONFIG WITNESS SIGNED_AUTHORITY OUTPUT; check-local CONFIG PROPOSAL; registry CONFIG PROPOSAL CUSTODY OUTPUT; check-network CONFIG PROPOSAL REGISTRY WORKSPACE [ADMISSION]; issue-admission CONFIG PROPOSAL REGISTRY WORKSPACE ENROLLMENT CUSTODY UNLOCK OUTPUT".into());
    };
    let config = Path::new(config);
    if !config.is_absolute() {
        return Err("successor configuration path must be absolute".into());
    }
    let lock = matches!(
        command.as_str(),
        "activate"
            | "activate-observer"
            | "export-boundary"
            | "check-local"
            | "check-autonomous-local"
    )
    .then(|| crate::services::checkpoint::lock_configuration(config))
    .transpose()?;
    let configuration = synergy_config::load(config).map_err(|e| e.to_string())?;
    if command == "check-processing-context" && extra.is_empty() {
        println!("{}", check_treasury_processing_context(&configuration, Path::new(proposal_path))?);
        return Ok(());
    }
    if configuration
        .consensus
        .autonomous_epoch_activation
        .is_some()
        && matches!(command.as_str(), "activate" | "activate-observer")
    {
        return Err("signed successor cannot replace the configured autonomous origin".into());
    }
    if matches!(command.as_str(), "activate" | "activate-observer")
        && load_signed(&configuration)?.is_some_and(|origin| origin.genesis_autonomous)
    {
        return Err("signed successor cannot replace the signed Genesis autonomous origin".into());
    }
    if lock.is_some() {
        crate::services::checkpoint::require_stopped(config, &configuration.admin_socket_path)?;
    }
    match (command.as_str(), extra) {
        ("prepare-autonomous", [output]) => {
            return autonomous_bootstrap_cli(
                &configuration,
                config,
                Path::new(proposal_path),
                Some(Path::new(output)),
                false,
            )
        }
        ("check-autonomous" | "check-autonomous-local", []) => {
            return autonomous_bootstrap_cli(
                &configuration,
                config,
                Path::new(proposal_path),
                None,
                command == "check-autonomous-local",
            )
        }
        ("prepare-autonomous" | "check-autonomous", _) => {
            return Err("invalid autonomous bootstrap arguments".into());
        }
        _ => {}
    }
    if command == "export-boundary" && extra.is_empty() {
        return export_boundary(&configuration, Path::new(proposal_path));
    }
    if matches!(command.as_str(), "check-derived" | "check-derived-chain") && extra.is_empty() {
        let previous = load(&configuration)?.ok_or("missing authenticated predecessor")?;
        let bytes = apqe_transport::read(Path::new(proposal_path), 4 * 1024 * 1024, false)?;
        let mut cursor = DerivedEpochVerifier::new(&previous)?;
        let proofs = if command == "check-derived-chain" {
            let chain: DerivedEpochProofChain = serde_json::from_slice(&bytes)
                .map_err(|e| format!("decode derived epoch proof chain: {e}"))?;
            if chain.version != 1
                || chain.origin_context_root != cursor.context.root().map_err(|e| e.to_string())?
                || !(1..=16).contains(&chain.transitions.len())
            {
                return Err("invalid proof-chain version, origin or length".into());
            }
            chain.transitions
        } else {
            vec![serde_json::from_slice(&bytes)
                .map_err(|e| format!("decode derived epoch proof: {e}"))?]
        };
        let mut certified_parent = None;
        for proof in &proofs {
            certified_parent = Some(cursor.advance(proof)?);
        }
        println!(
            "{}",
            serde_json::json!({
                "status": "consensus-derived-context-verified",
                "context_root": cursor.context.root().map_err(|e| e.to_string())?,
                "context": cursor.context,
                "certified_parent": certified_parent,
                "verified_transitions": proofs.len(),
                "activated": false,
            })
        );
        return Ok(());
    }
    if command == "prepare-payload" && extra.len() == 1 {
        let previous = load(&configuration)?.ok_or("missing installed predecessor")?;
        let bytes = apqe_transport::read(
            Path::new(proposal_path),
            MAX_CONSENSUS_MESSAGE_BYTES as u64,
            false,
        )?;
        let witness: Witness = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let [_, _, boundary] = verify_transition_witness(
            &previous,
            &witness.finalized,
            &serde_json::to_vec(&witness.certificates).map_err(|e| e.to_string())?,
        )?;
        let binding: SignedAuthorityBinding =
            serde_json::from_slice(previous.binding_bytes()).map_err(|e| e.to_string())?;
        return write_public(
            Path::new(&extra[0]),
            &serde_json::to_vec(&successor_payload(binding.payload, &boundary)?)
                .map_err(|e| e.to_string())?,
        );
    }
    if command == "bundle" && extra.len() == 2 {
        let previous = load(&configuration)?.ok_or("missing installed predecessor")?;
        let witness: Witness = serde_json::from_slice(&apqe_transport::read(
            Path::new(proposal_path),
            MAX_CONSENSUS_MESSAGE_BYTES as u64,
            false,
        )?)
        .map_err(|e| e.to_string())?;
        let proposal = Proposal {
            version: 1,
            previous_authority_binding: previous.binding_bytes().to_vec(),
            witness,
            successor_authority_binding: apqe_transport::read(
                Path::new(&extra[0]),
                MAX_AUTHORITY_BYTES,
                false,
            )?,
        };
        verify(&configuration, &proposal)?;
        return write_public(
            Path::new(&extra[1]),
            &serde_json::to_vec(&proposal).map_err(|e| e.to_string())?,
        );
    }
    let stamp = Stamp::capture(Path::new(proposal_path))?;
    let bytes = apqe_transport::read(Path::new(proposal_path), 8 * 1024 * 1024, false)?;
    let proposal: Proposal = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let (previous, next) = verify(&configuration, &proposal)?;
    if !stamp.unchanged() {
        return Err("successor proposal changed during verification".into());
    }
    let result = match (command.as_str(), extra) {
        ("check", []) => serde_json::json!({
            "status":"successor-proof-verified",
            "successor_proposal_sha256": sha256(&bytes),
            "previous_authority_sha256": sha256(previous.binding_bytes()),
            "successor_authority_sha256": sha256(next.binding_bytes()),
            "epoch": next.epoch.epoch,
            "finalized_height": proposal.witness.finalized.height,
            "genesis_trust_pin_preserved": true,
        }),
        ("check-local", []) => {
            require_validator_boundary(&configuration, &proposal.witness)?;
            verify_processing_boundary(&configuration, &previous, &next, &proposal.witness)?;
            serde_json::json!({
                "status":"successor-local-boundary-verified",
                "successor_proposal_sha256":sha256(&bytes),
            })
        }
        ("activate" | "activate-observer", []) => {
            if command == "activate" {
                require_validator_boundary(&configuration, &proposal.witness)?;
                verify_processing_boundary(&configuration, &previous, &next, &proposal.witness)?;
            }
            activate_verified(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                command == "activate-observer",
            )?
        }
        ("check-network", [registry, workspace] | [registry, workspace, _]) => {
            let mut result = check_staged_network(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                Path::new(registry),
                extra.get(2).map(Path::new),
                Path::new(workspace),
            )?;
            result["successor_proposal_sha256"] = sha256(&bytes).into();
            result
        }
        ("issue-admission", [registry, workspace, enrollment, custody, unlock, output]) => {
            return with_staged_network(
                &configuration,
                &previous,
                &next,
                &proposal.witness,
                Path::new(registry),
                Path::new(workspace),
                |staged, _| {
                    crate::services::apqe_rpc::issue(
                        staged,
                        Path::new(enrollment),
                        Path::new(custody),
                        Path::new(unlock),
                        Path::new(output),
                    )
                },
            );
        }
        ("registry", [custody, output]) => {
            return registry::issue_successor(
                config,
                custody,
                output,
                Path::new(proposal_path),
                &previous,
                &next,
            );
        }
        _ => return Err("invalid authority-successor arguments".into()),
    };
    println!("{}", crate::output::json::render(&result)?);
    Ok(())
}

#[cfg(test)]
fn signed_derived_test_proof(
    previous: &SimplifiedEpochContext,
    authorization: EpochTransitionAuthorization,
    next_validators: Vec<ValidatorRecord>,
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
    ingress: Option<&crate::services::ingress::AuthenticatedIngress>,
) -> (
    DerivedEpochProof,
    Option<synergy_execution::BudgetedExecutionCandidate>,
) {
    use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
    use synergy_posy::{block_vote_signing_bytes, BlockVote, ConsensusObjectContext};
    let root = synergy_etdag::EtdagDigest::from_domain_bytes("epoch-closure-test", b"namespace");
    let (closing_material, commitment) = synergy_etdag::execution::ProcessingProposalMaterial {
        material_version: 1,
        profile_id: synergy_etdag::PROCESSING_PROFILE_ID.into(),
        height: authorization.finalized_height,
        namespace_root: root.clone(),
        selection: synergy_etdag::execution::ProcessingReadyView {
            namespace_root: root.clone(),
            items: Vec::new(),
        }
        .select(21_000, 128 * 1024)
        .unwrap(),
        transition_root: root,
        ordered_group: None,
        epoch_transition_subject_root: None,
    }
    .with_epoch_close_subject(authorization.subject_root_v2().unwrap())
    .unwrap();
    let protected_root = synergy_block::hash_block_bytes(&commitment);
    let mut parent = SimplifiedFinalityParent::QuorumCertificate {
        height: authorization.finalized_height - 1,
        block_id: "d".repeat(64),
        qc_id: "e".repeat(64),
    };
    let closing_candidate = ingress.map(|ingress| {
        let world = synergy_state::WorldState::default();
        let mut candidate = synergy_execution::BudgetedExecutionCandidate {
            height: authorization.finalized_height,
            block_id: String::new(),
            parent_block_id: parent.block_id().into(),
            protected_execution_root: protected_root.clone(),
            protected_material: closing_material.clone().into(),
            state_root: synergy_state::state_root(&world).unwrap(),
            transactions: Vec::new(),
            receipts: Vec::new(),
            state: Arc::new(
                synergy_state::world_resources::BudgetedWorld::try_clone_world(
                    &world,
                    ingress.world_budget(),
                )
                .unwrap(),
            ),
            resource_permit: None,
        };
        candidate.block_id = candidate.commitment_id().unwrap();
        candidate
    });
    let mut finality = ThreeQcFinality::default();
    let mut certificates = Vec::new();
    for height in authorization.finalized_height..=previous.epoch_end_height {
        let votes = keys
            .iter()
            .take(4)
            .enumerate()
            .map(|(index, key)| {
                let record = &next_validators[index];
                let mut vote = BlockVote {
                    context: ConsensusObjectContext::for_height(previous, height, 0).unwrap(),
                    block_id: closing_candidate
                        .as_ref()
                        .filter(|candidate| candidate.height == height)
                        .map_or_else(
                            || format!("{height:064x}"),
                            |candidate| candidate.block_id.clone(),
                        ),
                    parent_block_id: parent.block_id().into(),
                    parent: parent.clone(),
                    takeover_tc_id: None,
                    protected_execution_root: if height == authorization.finalized_height {
                        protected_root.clone()
                    } else {
                        "f".repeat(64)
                    },
                    validator_id: record.validator_id.clone(),
                    key_id: record.consensus_key_id.clone(),
                    signature: vec![],
                };
                vote.signature = engine
                    .lock()
                    .unwrap()
                    .sign(
                        Algorithm::MlDsa65,
                        key.private_key.as_bytes(),
                        &block_vote_signing_bytes(&vote).unwrap(),
                        SignOptions::default(),
                    )
                    .unwrap();
                vote
            })
            .collect();
        let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
        finality.accept(qc.clone()).unwrap();
        parent = SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id: qc.block_id.clone(),
            qc_id: qc.id().unwrap(),
        };
        certificates.push(qc);
    }
    (
        DerivedEpochProof {
            authorization,
            finalized: finality.last_finalized().unwrap().clone(),
            witness: synergy_posy::FinalitySyncWitness {
                quorum_certificates: certificates.try_into().unwrap(),
                timeout_certificates: Vec::new(),
            },
            closing_material: closing_material.into(),
            next_validators,
        },
        closing_candidate,
    )
}

#[cfg(test)]
pub(super) fn qualify_offline_successor(
    config: &NodeConfiguration,
    previous: &VerifiedAuthority,
    signed_previous: &SignedAuthorityBinding,
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    signer: &synergy_aegis::PqvmSigner,
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
) {
    use synergy_aegis::AegisSigner;
    // The old validator keys certify each closing subject; no successor
    // authority signature is used for this consecutive-epoch verification.
    let mut cursor = DerivedEpochVerifier::new(previous).unwrap();
    let validators = signed_previous
        .payload
        .validators
        .iter()
        .map(|validator| validator.record.clone())
        .collect::<Vec<_>>();
    let next_subject = |cursor: &DerivedEpochVerifier<'_>| {
        unchanged_successor_subject(&cursor.context, &cursor.registry, &cursor.policy)
            .unwrap()
            .0
    };
    let (mut derived, _) = signed_derived_test_proof(
        &cursor.context,
        next_subject(&cursor),
        validators.clone(),
        keys,
        engine,
        None,
    );
    cursor.advance(&derived).unwrap();
    let ingress = crate::services::ingress::AuthenticatedIngress::default();
    let (second, closing_candidate) = signed_derived_test_proof(
        &cursor.context,
        next_subject(&cursor),
        validators,
        keys,
        engine,
        Some(&ingress),
    );
    let active = verify_native_successor(
        Arc::new(previous.clone()),
        serde_json::from_slice(&serde_json::to_vec(&derived).unwrap()).unwrap(),
        None,
    )
    .unwrap();
    crate::services::rpc::proofs::qualify_first_epoch_timeout(
        Arc::clone(&active), &derived.witness.quorum_certificates[2],
        &signed_previous.payload.validators.iter().map(|v|v.record.clone()).collect::<Vec<_>>(),
        keys, engine,
    );
    let closing_candidate = Arc::new(closing_candidate.unwrap());
    let qc = &second.witness.quorum_certificates[0];
    assert!(closing_candidate.validate().is_err());
    assert!(ingress
        .verify_sync_candidate_integrity(&closing_candidate)
        .is_err());
    ingress
        .install_finality_history(config.storage.data_directory.clone(), Arc::clone(&active))
        .unwrap();
    let mut malformed = synergy_execution::BudgetedExecutionCandidate {
        height: closing_candidate.height,
        block_id: closing_candidate.block_id.clone(),
        parent_block_id: closing_candidate.parent_block_id.clone(),
        protected_execution_root: closing_candidate.protected_execution_root.clone(),
        protected_material: closing_candidate.protected_material.clone(),
        state_root: closing_candidate.state_root.clone(),
        transactions: Vec::new(),
        receipts: Vec::new(),
        state: Arc::clone(&closing_candidate.state),
        resource_permit: None,
    };
    let synergy_etdag::execution::CandidateProtectedMaterial::Processing(material) =
        &mut malformed.protected_material
    else {
        panic!("closing candidate requires processing material");
    };
    material.epoch_transition_subject_root = Some("a".repeat(64));
    assert!(ingress.verify_sync_candidate_integrity(&malformed).is_err());
    assert!(active.verify_processing_candidate(&malformed).is_err());
    let synergy_etdag::execution::CandidateProtectedMaterial::Processing(material) =
        &mut malformed.protected_material
    else {
        unreachable!();
    };
    material.material_version = 1;
    material.epoch_transition_subject_root = None;
    malformed.protected_execution_root =
        synergy_block::hash_block_bytes(&material.commitment_bytes().unwrap());
    malformed.block_id = malformed.commitment_id().unwrap();
    malformed.validate().unwrap();
    assert!(ingress.verify_sync_candidate_integrity(&malformed).is_err());
    assert!(active.verify_processing_candidate(&malformed).is_err());
    ingress
        .publish_processing_certified_parent(Arc::clone(&closing_candidate), qc, &active)
        .unwrap();
    assert_eq!(
        ingress
            .processing_certified_parent()
            .unwrap()
            .unwrap()
            .block_id,
        closing_candidate.block_id
    );
    assert!(ingress
        .try_submit_verified_sync_candidate(
            Arc::clone(&closing_candidate),
            second.finalized.clone()
        )
        .unwrap());
    assert_eq!(
        ingress
            .take_verified_sync_candidate()
            .unwrap()
            .unwrap()
            .0
            .block_id,
        closing_candidate.block_id
    );

    assert!(verify_derived_epoch(previous, &second).is_err());
    cursor.advance(&second).unwrap();
    assert_eq!(cursor.context.epoch_start_height, 21001);
    let final_root = cursor.context.root().unwrap();
    assert!(cursor.advance(&derived).is_err());
    assert_eq!(cursor.context.root().unwrap(), final_root);

    let certificates = derived.witness.quorum_certificates.clone();
    let finalized = derived.finalized.clone();
    let (next_context, parent) = verify_derived_epoch(previous, &derived).unwrap();
    assert_ne!(
        next_context.consensus_parameter_root,
        previous.epoch.consensus_parameter_root
    );
    assert_eq!(
        next_context.finalized_epoch_seed_root,
        certificates[0].id().unwrap()
    );
    assert_eq!(
        parent.quorum_certificate_reference().unwrap(),
        certificates[2].reference().unwrap()
    );

    let closing_material = derived.closing_material.clone();
    let synergy_etdag::execution::CandidateProtectedMaterial::Processing(foreign_material) =
        &mut derived.closing_material
    else {
        panic!("derived fixture requires processing material");
    };
    foreign_material.epoch_transition_subject_root = Some("a".repeat(64));
    assert!(verify_derived_epoch(previous, &derived)
        .unwrap_err()
        .contains("protected transition subject"));
    derived.closing_material = closing_material;
    derived.next_validators[0].frozen_voting_weight += 1;
    assert!(verify_derived_epoch(previous, &derived).is_err());
    derived.next_validators[0].frozen_voting_weight -= 1;

    let saved_root = derived.authorization.next_consensus_parameter_root.clone();
    derived.authorization.next_consensus_parameter_root =
        previous.epoch.consensus_parameter_root.clone();
    assert!(verify_derived_epoch(previous, &derived)
        .unwrap_err()
        .contains("independently derived rollover policy"));
    derived.authorization.next_consensus_parameter_root = saved_root;

    // Change a signature without changing the QC subject/ID.
    derived.witness.quorum_certificates[2].participants[0].signature[0] ^= 1;
    assert!(verify_derived_epoch(previous, &derived).is_err());

    let mut candidate = signed_previous.clone();
    candidate.payload =
        successor_payload(signed_previous.payload.clone(), &certificates[2]).unwrap();
    assert_eq!(
        candidate.payload.consensus_parameter_root,
        next_context.consensus_parameter_root
    );
    let sign = |payload: &AuthorityPayload| {
        signer
            .sign(
                &KeyId::new(candidate.signer_key_id.clone()).unwrap(),
                &SigningContext {
                    domain: synergy_genesis::authority::AUTHORITY_SIGNING_DOMAIN.into(),
                    chain_id: config.chain_id,
                    epoch: Some(3),
                    height: None,
                },
                &payload.signing_bytes().unwrap(),
            )
            .unwrap()
            .bytes
    };
    candidate.signature = sign(&candidate.payload);
    let mut proposal = Proposal {
        version: 1,
        previous_authority_binding: previous.binding_bytes().to_vec(),
        witness: Witness {
            finalized,
            certificates,
        },
        successor_authority_binding: serde_json::to_vec(&candidate).unwrap(),
    };
    let (_, next) = verify(config, &proposal).unwrap();
    assert_eq!(
        (next.epoch.epoch_start_height, next.epoch.epoch_end_height),
        (20001, 21000)
    );
    let correct = proposal.successor_authority_binding.clone();
    candidate.payload.epoch_end_height += 1;
    candidate.signature = sign(&candidate.payload);
    proposal.successor_authority_binding = serde_json::to_vec(&candidate).unwrap();
    assert!(verify(config, &proposal)
        .err()
        .unwrap()
        .contains("1,000-block"));
    proposal.successor_authority_binding = correct;
    proposal.witness.certificates[2].participants[0].signature[0] ^= 1;
    assert!(verify(config, &proposal)
        .err()
        .unwrap()
        .contains("verify authority transition QC"));
}


#[cfg(test)]
pub(super) fn qualify_fresh_genesis_autonomous(
    config: &NodeConfiguration,
    origin: Arc<VerifiedAuthority>,
    keys: &[synergy_address_engine::apqe::crypto_engine::EncodedKeyPair],
    engine: &Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>,
    origin_signer: &impl synergy_aegis::AegisSigner,
) {
    assert!(origin.genesis_autonomous);
    assert!(origin.autonomous_closure.is_none()); // E1 has no fabricated prior QC.
    assert_eq!((origin.epoch.epoch_start_height, origin.epoch.epoch_end_height), (1, 1000));
    assert!(origin.epoch_close_subject_at(997).unwrap().is_none());
    assert!(origin.epoch_close_subject_at(998).unwrap().is_some());
    let mut legacy = origin.as_ref().clone();
    legacy.genesis_autonomous = false;
    assert!(legacy.epoch_close_subject_at(998).unwrap().is_none());
    assert!(verify_next_derived_bytes(Arc::new(legacy), b"{}").is_err());
    let original_bytes = fs::read(config.genesis_path.as_ref().unwrap()).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
    tampered["unsigned"]["network"]["autonomous_epoch_protocol"] = "unknown-profile".into();
    fs::write(config.genesis_path.as_ref().unwrap(), serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(load(config).is_err());
    tampered["unsigned"]["network"].as_object_mut().unwrap().remove("autonomous_epoch_protocol");
    fs::write(config.genesis_path.as_ref().unwrap(), serde_json::to_vec(&tampered).unwrap()).unwrap();
    assert!(load(config).is_err()); // Dropping an approved marker breaks the signed bytes.
    fs::write(config.genesis_path.as_ref().unwrap(), original_bytes).unwrap();
    let layout = NodeStorageLayout::new(config.storage.data_directory.clone()).unwrap();
    let proof_root = layout.consensus().join("autonomous-epochs");
    let ingress = crate::services::ingress::AuthenticatedIngress::default();
    let binding: SignedAuthorityBinding = serde_json::from_slice(origin.binding_bytes()).unwrap();
    // Match the fixture's independently generated key array, not BTree iteration order.
    let validators = binding.payload.validators.iter().map(|v| v.record.clone()).collect::<Vec<_>>();
    wallet_dispatch_tests::qualify_signed_release(config, &origin, &validators, keys, engine, origin_signer);
    let mut current = origin.clone();
    for expected_epoch in [2, 3] {
        let (subject, _) = unchanged_successor_subject(&current.epoch, &current.registry, current.protected.as_ref().unwrap()).unwrap();
        let (proof, candidate) = signed_derived_test_proof(&current.epoch, subject,
            validators.clone(), keys, engine, Some(&ingress));
        let candidate = candidate.unwrap();
        let encoded = serde_json::to_vec(&proof).unwrap();
        let verified = verify_next_derived_bytes(current.clone(), &encoded).unwrap();
        crate::services::apqe_rpc_service::qualify_fresh_gateway_successor(config, current.clone(), verified.clone(), &encoded);
        assert_eq!(verified.epoch.epoch, expected_epoch);
        assert_eq!(verified.epoch.epoch_start_height, (expected_epoch-1)*1000+1);
        assert_eq!(verified.epoch.epoch_end_height, expected_epoch*1000);
        assert_eq!(verified.epoch.finalized_epoch_seed_root, proof.witness.quorum_certificates[0].id().unwrap());
        assert!(verify_next_derived_bytes(verified.clone(), &encoded).is_err());
        let mut bad: DerivedEpochProof = serde_json::from_slice(&encoded).unwrap();
        bad.witness.quorum_certificates[2].participants[0].signature[0] ^= 1;
        assert!(verify_next_derived_bytes(current.clone(), &serde_json::to_vec(&bad).unwrap()).is_err());
        let mut bad: DerivedEpochProof = serde_json::from_slice(&encoded).unwrap();
        bad.next_validators[0].frozen_voting_weight += 1;
        assert!(verify_next_derived_bytes(current.clone(), &serde_json::to_vec(&bad).unwrap()).is_err());
        assert_eq!(persist_native_successor(&proof_root, &current, proof.finalized.clone(), proof.witness.clone(), &candidate).unwrap(), expected_epoch);
        assert_eq!(persist_native_successor(&proof_root, &current, proof.finalized.clone(), proof.witness.clone(), &candidate).unwrap(), expected_epoch);
        current = load(config).unwrap().unwrap(); // exact signed-origin + disk proof replay
        assert_eq!(current.epoch, verified.epoch);
        assert_eq!(current.anchor_parent, verified.anchor_parent);
        // Reuse the real signed-Genesis/three-QC fixture, not a second authority
        // algorithm or a simulated running cohort, for spending-context trust.
        let target = proof.finalized.height + current.protected.as_ref().unwrap().parameters.target_height_offset;
        let context = synergy_etdag::ProcessingContext { context_version:1,
            profile_id:synergy_etdag::PROCESSING_PROFILE_ID.into(),
            authority:current.protected_target(Some(&proof.finalized), target).unwrap().0 };
        let response = serde_json::json!({"profile_id":synergy_etdag::PROCESSING_PROFILE_ID,
            "context":context,"ingress_kem_registry":current.protected_ingress_registry().unwrap()});
        assert_eq!(treasury_processing_scope(&current, &response).unwrap(), context);
        assert!(treasury_processing_scope(&origin, &response).is_err()); // No skipped missing history.
        for (field,value) in [("epoch",serde_json::json!(expected_epoch+1)),
            ("network_id",serde_json::json!("foreign")),("finalized_epoch_seed_root",serde_json::json!("0".repeat(64))),
            ("assigned_cluster_total_voting_weight",serde_json::json!(999)),("source_finalized_height",serde_json::json!(0))] {
            let mut bad=response.clone();bad["context"]["authority"][field]=value;
            assert!(treasury_processing_scope(&current,&bad).is_err());
        }
        let mut bad=response.clone();bad["ingress_kem_registry"]["records"][0]["public_key"]["public_key"][0]=serde_json::json!(99);
        assert!(treasury_processing_scope(&current,&bad).is_err());
        let text=response.to_string();
        let request=serde_json::json!({"version":1,"operation":"treasury_send_prepare","parameters":{
            "genesis_sha256":apqe_transport::sha256(&fs::read(config.genesis_path.as_ref().unwrap()).unwrap()),
            "processing_context_json":text,"processing_context_sha256":apqe_transport::sha256(text.as_bytes())}});
        let request_path=proof_root.join("treasury-context-request.json");
        fs::write(&request_path,serde_json::to_vec(&request).unwrap()).unwrap();
        let descriptor=check_treasury_processing_context(config,&request_path).unwrap();
        assert_eq!(descriptor["epoch"],expected_epoch);
        assert_eq!(descriptor["request_sha256"],apqe_transport::sha256(&fs::read(&request_path).unwrap()));
        let mut bad=request.clone();bad["parameters"]["genesis_sha256"]=serde_json::json!("0".repeat(64));
        fs::write(&request_path,serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(check_treasury_processing_context(config,&request_path).is_err());
        fs::remove_file(&request_path).unwrap();
        assert!(load_next_runtime_autonomous(config, origin.clone(), expected_epoch+1).is_err());
        let path = proof_root.join(format!("epoch-{expected_epoch:020}.json"));
        let mut broken: DerivedEpochProof = serde_json::from_slice(&encoded).unwrap();
        broken.authorization.next_epoch += 1;
        fs::write(&path, serde_json::to_vec(&broken).unwrap()).unwrap();
        assert!(load(config).is_err());
        let broken_bytes = fs::read(&path).unwrap();
        assert!(persist_native_successor(&proof_root, current.timeout_predecessor.as_ref().unwrap(),
            proof.finalized.clone(), proof.witness.clone(), &candidate).is_err());
        assert_eq!(fs::read(&path).unwrap(), broken_bytes);
        fs::write(&path, &encoded).unwrap();
    }
    // Missing predecessor cannot be skipped by loading a later stored epoch.
    let first = proof_root.join("epoch-00000000000000000002.json");
    let saved = fs::read(&first).unwrap();
    fs::remove_file(&first).unwrap();
    let replayed = load(config).unwrap().unwrap();
    assert_eq!(replayed.epoch.epoch, 1);
    assert!(load_next_runtime_autonomous(config, replayed, 3).is_err());
    fs::write(first, saved).unwrap();
    assert_eq!(load(config).unwrap().unwrap().epoch.epoch, 3);
}
