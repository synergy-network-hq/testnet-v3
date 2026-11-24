//! Verified frozen PoSy/ETDAG authority shared by protocol owners.
use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use synergy_aegis::{
    AegisPolicy, AegisVerifier, KeyId, PqvmVerifier, Signature, SignatureAlgorithm, SigningContext,
};
use synergy_config::NodeConfiguration;
use synergy_data_availability::ProofVerifier;
use synergy_etdag::crypto::SignatureVerifier as EtdagSignatureVerifier;
use synergy_etdag::EtdagError;
use synergy_governance::{GovernanceVote, VoteVerifier};
use synergy_posy::{
    ConsensusSignatureVerifier, EpochTransitionAuthorization, FinalizedBlockRecord,
    FrozenValidatorRegistry, PosyError, PosyResult, SimplifiedEpochContext,
    SimplifiedFinalityParent, SimplifiedQuorumCertificate, ThreeQcFinality, ValidatorRecord,
};
use synergy_storage::{AtomicStore, NodeStorageLayout};
use synergy_sxcp::{SxcpExecutionAuthorizationVerifier, SxcpRelayExecution};

const MAX_AUTHORITY_BYTES: u64 = 1024 * 1024;
const MAX_TRUST_KEY_BYTES: u64 = 8 * 1024;
const MAX_CONSENSUS_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_SIGNATURE_CACHE_ENTRIES: usize = 1024;
const MAX_SIGNATURE_CACHE_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNATURE_CACHE_ENTRY_BYTES: usize = 64 * 1024;
use synergy_genesis::authority::{ProtectedEpochPolicy, SignedAuthorityBinding};

#[path = "authority_managed_wallet_release.rs"]
pub(super) mod managed_wallet;
#[path = "authority_wallet_release_artifacts.rs"]
mod wallet_release_artifacts;

pub(super) fn processing_finality_root(
    record: &FinalizedBlockRecord,
) -> Result<synergy_etdag::EtdagDigest, String> {
    synergy_etdag::EtdagDigest::from_canonical("SYNERGY_ETDAG_FINALIZED_SOURCE_V1", record)
        .map_err(|error| format!("finalized source: {error:?}"))
}

/// Exact successful primitive verification, scoped to this immutable authority.
/// Certificate structure, quorum, ancestry and durable bindings are never cached.
#[derive(Debug, PartialEq)]
struct VerifiedConsensusSignature {
    domain: String,
    chain_id: u64,
    epoch: u64,
    height: Option<u64>,
    validator_id: String,
    key_id: String,
    payload: Vec<u8>,
    signature: Vec<u8>,
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
}

impl VerifiedConsensusSignature {
    fn byte_len(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.domain.len()
            + self.validator_id.len()
            + self.key_id.len()
            + self.payload.len()
            + self.signature.len()
            + self.public_key.len()
    }
}

#[derive(Debug, Default)]
struct ConsensusSignatureCache {
    entries: VecDeque<VerifiedConsensusSignature>,
    bytes: usize,
    #[cfg(test)]
    primitive_verifications: usize,
}

impl ConsensusSignatureCache {
    fn insert(&mut self, entry: VerifiedConsensusSignature) {
        let bytes = entry.byte_len();
        if bytes > MAX_SIGNATURE_CACHE_ENTRY_BYTES {
            return;
        }
        while self.entries.len() >= MAX_SIGNATURE_CACHE_ENTRIES
            || self.bytes + bytes > MAX_SIGNATURE_CACHE_BYTES
        {
            let Some(oldest) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= oldest.byte_len();
        }
        self.bytes += bytes;
        self.entries.push_back(entry);
    }
}

#[cfg(test)]
pub(crate) fn qualification_authority(
    entries: Vec<(ValidatorRecord, Vec<u8>)>,
) -> Arc<VerifiedAuthority> {
    qualification_authority_with_provider(entries, None)
}
#[cfg(test)]
pub(crate) fn qualification_authority_with_provider(
    entries: Vec<(ValidatorRecord, Vec<u8>)>,
    engine: Option<Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>>,
) -> Arc<VerifiedAuthority> {
    qualification_authority_for_network(entries, engine, 1266, "qualification")
}

#[cfg(test)]
pub(crate) fn qualification_authority_for_network(
    entries: Vec<(ValidatorRecord, Vec<u8>)>,
    engine: Option<Arc<Mutex<synergy_address_engine::apqe::crypto_engine::CryptoEngine>>>,
    chain_id: u64,
    network_id: &str,
) -> Arc<VerifiedAuthority> {
    let verifier = |policy| {
        match &engine {
            Some(engine) => PqvmVerifier::with_apqe(policy, engine.clone()),
            None => PqvmVerifier::new(policy),
        }
        .unwrap()
    };
    let registry =
        FrozenValidatorRegistry::new(1, entries.iter().map(|(r, _)| r.clone()).collect()).unwrap();
    let epoch = SimplifiedEpochContext::from_frozen_registry(
        chain_id,
        network_id.into(),
        1,
        1,
        10_000,
        "a".repeat(64),
        "b".repeat(64),
        &registry,
    )
    .unwrap();
    Arc::new(VerifiedAuthority {
        registry,
        epoch,
        timeout_predecessor: None,
        autonomous_closure: None,
        genesis_autonomous: false,
        ethereum_genesis: None,
        ethereum_activation_cache:Arc::new(Mutex::new(None)),
        managed_wallet_release: None,
        anchor_parent: SimplifiedFinalityParent::Genesis {
            genesis_hash: "c".repeat(64),
            block_id: "qualification-genesis".into(),
            reference_id: "d".repeat(64),
        },
        verifier: verifier(AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
            maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
            maximum_signature_bytes: 16 * 1024,
        }),
        wallet_verifier: verifier(AegisPolicy {
            allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
            maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
            maximum_signature_bytes: 16 * 1024,
        }),
        identity_verifier: None,
        provider_configuration: None,
        keys: entries
            .into_iter()
            .map(|(validator, public_key)| {
                (
                    validator.validator_id.clone(),
                    ConsensusKey {
                        validator,
                        public_key,
                        algorithm: SignatureAlgorithm::MlDsa65,
                    },
                )
            })
            .collect(),
        chain_id,
        binding_bytes: Arc::new(Vec::new()),
        protected: None,
        signature_cache: Arc::new(Mutex::new(ConsensusSignatureCache::default())),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEpochTransition {
    version: u32,
    next_epoch: u64,
    previous_authority_binding: Vec<u8>,
    finalized: FinalizedBlockRecord,
    finality_witness: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ConsensusKey {
    validator: ValidatorRecord,
    algorithm: SignatureAlgorithm,
    public_key: Vec<u8>,
}

#[derive(Debug)]
pub struct VerifiedAuthority {
    pub registry: FrozenValidatorRegistry,
    pub epoch: SimplifiedEpochContext,
    pub anchor_parent: SimplifiedFinalityParent,
    // Only a verified, sequential transition can attach the previous epoch.
    timeout_predecessor: Option<Arc<VerifiedAuthority>>,
    autonomous_closure: Option<Arc<VerifiedAutonomousClosure>>,
    // Derived only from authenticated signed Genesis, never deserialized authority/config.
    genesis_autonomous: bool,
    ethereum_genesis: Option<EthereumGenesisAuthority>,
    pub(super) ethereum_activation_cache:Arc<Mutex<Option<super::ethereum_activation::CachedActivation>>>,
    managed_wallet_release: Option<Arc<managed_wallet::ManagedWalletRelease>>,
    verifier: PqvmVerifier,
    wallet_verifier: PqvmVerifier,
    identity_verifier: Option<synergy_aegis::ApqeIdentityVerifier>,
    provider_configuration: Option<synergy_config::ApqeProviderConfiguration>,
    keys: BTreeMap<String, ConsensusKey>,
    chain_id: u64,
    binding_bytes: Arc<Vec<u8>>,
    protected: Option<Arc<ProtectedEpochPolicy>>,
    signature_cache: Arc<Mutex<ConsensusSignatureCache>>,
}

#[derive(Clone,Debug)]
pub(super) struct EthereumGenesisAuthority {
    pub descriptor:synergy_genesis::network::GenesisEthereumCompatibility,
    pub genesis_hash:String,
    pub activation_unix:u64,
    pub activation_height:u64,
    pub chain_id:u64,
}

thread_local! {
    static WORKER_AUTHORITY: std::cell::RefCell<Option<(std::sync::Weak<VerifiedAuthority>, Arc<VerifiedAuthority>)>> = const { std::cell::RefCell::new(None) };
}
impl VerifiedAuthority {
    pub(super) fn ethereum_genesis(&self)->Option<&EthereumGenesisAuthority> {self.ethereum_genesis.as_ref()}
    pub(super) fn authenticated_genesis_hash(&self)->Result<&str,String>{
        let mut origin=self;while let Some(previous)=origin.timeout_predecessor.as_deref(){origin=previous;}
        match &origin.anchor_parent {SimplifiedFinalityParent::Genesis{genesis_hash,..}=>Ok(genesis_hash),
            _=>Err("authenticated Genesis lineage is unavailable".into())}
    }
    pub(super) fn ethereum_activation(&self,world:&synergy_state::WorldState,budget:Option<&Arc<synergy_state::world_resources::WorldResourceBudget>>)
        ->Result<Option<EthereumGenesisAuthority>,String>{
        super::ethereum_activation::resolve(self,world,budget)
    }
    // Translation is not admission authority: the native owner independently
    // verifies finalized source policy and activation before its durable ACK.
    pub(super) fn ethereum_submission_authority(&self)->Result<EthereumGenesisAuthority,String>{
        if let Some(genesis)=&self.ethereum_genesis{return Ok(genesis.clone());}
        self.ethereum_activation_cache.lock().map_err(|_|"EVM activation cache poisoned")?.as_ref()
            .map(super::ethereum_activation::cached_authority).ok_or_else(||"authenticated EVM activation is unavailable".into())
    }
    pub(super) fn ethereum_ingress_kem(&self)->Result<synergy_aegis::ApqeKem,String>{
        self.ethereum_submission_authority()?;
        let selected=self.provider_configuration.as_ref().ok_or("Ethereum ingress requires an explicitly authenticated APQE provider")?;
        synergy_aegis::ApqeKem::mlkem1024(super::apqe_provider::load_selected(selected)?).map_err(|error|format!("{error:?}"))
    }

    pub(crate) fn autonomous_epochs_enabled(&self) -> bool {
        self.genesis_autonomous || self.autonomous_closure.is_some()
    }
    /// Includes verified signed predecessors as well as derived successors.
    /// This selects historical certificate authority, never a live processing
    /// namespace or spending policy.
    pub(super) fn authenticated_history_at(self: &Arc<Self>, height: u64) -> Option<&Arc<Self>> {
        let mut selected = self;
        loop {
            if selected.epoch.contains_height(height) {
                return Some(selected);
            }
            selected = selected.timeout_predecessor.as_ref()?;
        }
    }
    pub(super) fn authenticated_history_ref_at(&self, height: u64) -> Option<&Self> {
        let mut selected = self;
        loop {
            if selected.epoch.contains_height(height) {
                return Some(selected);
            }
            selected = selected.timeout_predecessor.as_deref()?;
        }
    }
    /// Runtime-only descent through authenticated autonomous closures. Never
    /// treat an unrelated signed authority as part of this processing lineage.
    pub(super) fn autonomous_processing_origin(&self) -> &Self {
        let mut authority = self;
        while authority.autonomous_closure.is_some() {
            authority = authority
                .timeout_predecessor
                .as_deref()
                .expect("verified autonomous closure has a predecessor");
        }
        authority
    }

    pub(super) fn autonomous_authority_at(&self, height: u64) -> Option<&Self> {
        self.autonomous_authority_ref_at(height)
    }

    fn autonomous_authority_ref_at(&self, height: u64) -> Option<&Self> {
        let mut authority = self;
        loop {
            if authority.epoch.contains_height(height) {
                return Some(authority);
            }
            if authority.autonomous_closure.is_none() {
                return None;
            }
            authority = authority.timeout_predecessor.as_deref()?;
        }
    }

    pub(super) fn autonomous_authority_arc_at(self: &Arc<Self>, height: u64) -> Option<&Arc<Self>> {
        let mut authority = self;
        loop {
            if authority.epoch.contains_height(height) {
                return Some(authority);
            }
            if authority.autonomous_closure.is_none() {
                return None;
            }
            authority = authority.timeout_predecessor.as_ref()?;
        }
    }

    /// Advertise the earliest still-needed certified boundary to a peer that
    /// cannot verify the current head yet. It derives the successor itself.
    pub(super) fn next_autonomous_sync_boundary(
        &self,
        known_height: Option<u64>,
    ) -> Option<(&FinalizedBlockRecord, &[SimplifiedQuorumCertificate; 3])> {
        let mut authority = self;
        let mut needed = None;
        while let Some(closure) = authority.autonomous_closure.as_ref() {
            if known_height.is_some_and(|height| height >= closure.finalized.height) {
                break;
            }
            needed = Some((&closure.finalized, &closure.witness.quorum_certificates));
            authority = authority.timeout_predecessor.as_deref()?;
        }
        needed
    }

    /// A client must verify this artifact from its independently trusted
    /// origin. Do not expose proof files that were not authenticated on load.
    pub(super) fn public_autonomous_proof(
        &self,
        epoch: u64,
    ) -> Result<Option<serde_json::Value>, String> {
        let mut authority = self;
        while let Some(closure) = authority.autonomous_closure.as_ref() {
            if authority.epoch.epoch == epoch {
                let public = closure
                    .public
                    .as_ref()
                    .ok_or("authenticated epoch proof is not published")?;
                let bytes = super::apqe_transport::read(&public.path, 4 * 1024 * 1024, false)?;
                if super::apqe_transport::sha256(&bytes) != public.sha256 {
                    return Err("published epoch proof changed after authentication".into());
                }
                let artifact = String::from_utf8(bytes).map_err(|e| e.to_string())?;
                return Ok(Some(serde_json::json!({
                    "chain_id":authority.epoch.chain_id,
                    "network_id":authority.epoch.network_id,
                    "epoch":epoch,
                    "epoch_context_root":authority.epoch.root().map_err(|e| e.to_string())?,
                    "kind":public.kind,
                    "sha256":public.sha256,
                    "artifact_json":artifact,
                })));
            }
            authority = authority
                .timeout_predecessor
                .as_deref()
                .ok_or("authenticated epoch lineage lacks a predecessor")?;
        }
        Ok(None)
    }

    /// Independent engines for one long-lived consuming owner. This is
    /// intentionally uncached: registrations run on the same supervisor thread.
    pub(super) fn owner_context(source: &Arc<Self>) -> Result<Arc<Self>, String> {
        let Some(selected) = source.provider_configuration.as_ref() else {
            #[cfg(test)]
            return Ok(Arc::clone(source));
            #[cfg(not(test))]
            return Err("owner requires explicit APQE provider configuration".into());
        };
        let mut context = source.as_ref().clone();
        context.verifier = PqvmVerifier::with_apqe(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
                maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
            super::apqe_provider::load_selected(selected)?,
        )
        .map_err(|e| e.to_string())?;
        context.wallet_verifier = PqvmVerifier::with_apqe(
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
            super::apqe_provider::load_selected(selected)?,
        )
        .map_err(|e| e.to_string())?;
        context.identity_verifier = Some(synergy_aegis::ApqeIdentityVerifier::new(
            super::apqe_provider::load_selected(selected)?,
        )?);
        Ok(Arc::new(context))
    }

    /// Invoke inside a bounded preparation worker. Each worker owns independent
    /// native engines; main-loop engines remain nonblocking. A single cached
    /// context is replaced on source/epoch change and drops at worker shutdown.
    pub(super) fn worker_context(source: &Arc<Self>) -> Result<Arc<Self>, String> {
        if source.provider_configuration.is_none() {
            #[cfg(test)]
            return Ok(Arc::clone(source));
            #[cfg(not(test))]
            return Err("worker requires explicit APQE provider configuration".into());
        }
        WORKER_AUTHORITY.with(|slot| {
            let mut slot = slot.borrow_mut();
            if let Some((base, context)) = slot.as_ref() {
                if base
                    .upgrade()
                    .is_some_and(|base| Arc::ptr_eq(&base, source))
                {
                    return Ok(Arc::clone(context));
                }
            }
            let context = Self::owner_context(source)?;
            *slot = Some((Arc::downgrade(source), Arc::clone(&context)));
            Ok(context)
        })
    }
}

impl Clone for VerifiedAuthority {
    fn clone(&self) -> Self {
        Self {
            registry: self.registry.clone(),
            epoch: self.epoch.clone(),
            anchor_parent: self.anchor_parent.clone(),
            timeout_predecessor: self.timeout_predecessor.clone(),
            autonomous_closure: self.autonomous_closure.clone(),
            genesis_autonomous: self.genesis_autonomous,
            ethereum_genesis:self.ethereum_genesis.clone(),
            ethereum_activation_cache:self.ethereum_activation_cache.clone(),
            managed_wallet_release: self.managed_wallet_release.clone(),
            verifier: self.verifier.clone(),
            wallet_verifier: self.wallet_verifier.clone(),
            identity_verifier: self.identity_verifier.clone(),
            provider_configuration: self.provider_configuration.clone(),
            keys: self.keys.clone(),
            chain_id: self.chain_id,
            binding_bytes: self.binding_bytes.clone(),
            protected: self.protected.clone(),
            signature_cache: Arc::new(Mutex::new(ConsensusSignatureCache::default())),
        }
    }
}

impl VerifiedAuthority {
    #[cfg(test)]
    pub(super) fn qualification_verifier(&mut self, verifier: PqvmVerifier) {
        self.verifier = verifier;
    }

    #[cfg(test)]
    pub(super) fn consensus_signature_cache_stats(&self) -> (usize, usize, usize) {
        let cache = self.signature_cache.lock().unwrap();
        (
            cache.entries.len(),
            cache.bytes,
            cache.primitive_verifications,
        )
    }
    #[cfg(test)]
    pub(super) fn qualification_with_ingress(
        &self,
        registry: synergy_etdag::IngressKemKeyRegistry,
    ) -> Self {
        let mut authority = self.clone();
        // This extends the existing unsigned qualification authority fixture.
        // Production must load and validate the complete signed policy instead.
        authority.protected = Some(Arc::new(ProtectedEpochPolicy {
            version: 1,
            cutoff_relationship:
                synergy_genesis::authority::ProtectedCutoffRelationship::VcEventContextV1,
            epoch_start_timestamp_ms: 1_000_000,
            target_block_time_ms: 1_000,
            parameters: synergy_etdag::EtdagParameters::default(),
            initial_world_state: synergy_state::WorldState::default(),
            cryptographic_profile_root: "a".repeat(64),
            ingress_kem_registry: registry,
            cluster_schedule_version: "qualification".into(),
            assigned_height_schedule_root: "e".repeat(64),
            cluster_map_root: "f".repeat(64),
            assigned_cluster_id: 0,
            assigned_cluster_membership_root: self.epoch.active_validator_set_root.clone(),
            wallet_dispatch: None,
        }));
        authority
    }

    #[cfg(test)]
    pub(super) fn qualification_with_processing_ingress(
        &self,
        registry: synergy_etdag::IngressKemKeyRegistry,
        genesis_hash: String,
    ) -> Self {
        let mut authority = self.qualification_with_ingress(registry);
        let policy = Arc::make_mut(authority.protected.as_mut().expect("fixture policy"));
        policy.version = 2;
        policy.cutoff_relationship =
            synergy_genesis::authority::ProtectedCutoffRelationship::ProcessingGroupsV1;
        let SimplifiedFinalityParent::Genesis {
            genesis_hash: hash, ..
        } = &mut authority.anchor_parent
        else {
            panic!("qualification authority lacks Genesis");
        };
        *hash = genesis_hash;
        authority
    }

    /// Exact deterministic time bound by signed policy, never a transaction or wall clock.
    pub fn consensus_timestamp_unix(&self, height: u64) -> Result<u64, String> {
        self.protected
            .as_ref()
            .ok_or("signed protected time policy is absent")?
            .timestamp_for_height_ms(
                self.epoch.epoch_start_height,
                self.epoch.epoch_end_height,
                height,
            )
            .map(|timestamp_ms| timestamp_ms / 1_000)
    }

    pub fn consensus_binding(&self, validator_id: &str) -> Result<(&str, &[u8]), String> {
        let key = self
            .keys
            .get(validator_id)
            .ok_or_else(|| format!("validator {validator_id} has no frozen consensus key"))?;
        if key.algorithm != SignatureAlgorithm::MlDsa65 || !key.validator.may_sign_consensus() {
            return Err(format!(
                "validator {validator_id} has no active ML-DSA-65 authority"
            ));
        }
        Ok((
            key.validator.consensus_key_id.as_str(),
            key.public_key.as_slice(),
        ))
    }

    pub fn protected_parameters(&self) -> Result<synergy_etdag::EtdagParameters, String> {
        self.protected
            .as_ref()
            .map(|policy| policy.parameters.clone())
            .ok_or_else(|| "signed authority lacks complete protected policy".into())
    }

    /// Activation comes solely from the complete pinned-root signed policy.
    /// Runtime configuration or decoded candidate material cannot select it.
    pub fn processing_profile_enabled(&self) -> bool {
        self.protected.as_ref().is_some_and(|policy| {
            policy.version == 2
                && policy.cutoff_relationship
                    == synergy_genesis::authority::ProtectedCutoffRelationship::ProcessingGroupsV1
        })
    }

    /// Read the exact signed Wallet dispatch policy. A launcher or request
    /// cannot supply this component from a mutable runtime setting.
    pub(super) fn wallet_dispatch_policy(
        &self,
    ) -> Option<&synergy_genesis::authority::ProtectedWalletDispatchPolicy> {
        self.protected.as_ref()?.wallet_dispatch.as_ref()
    }

    pub(super) fn matches_wallet_dispatch_release(
        &self,
        release: &synergy_genesis::authority::VerifiedWalletDispatchRelease,
    ) -> Result<(), String> {
        let policy = release.policy();
        let activation = self.autonomous_authority_at(policy.activation_finalized_height)
            .filter(|authority| authority.epoch.epoch_start_height == policy.activation_finalized_height)
            .ok_or("Wallet release lacks its authenticated activation epoch")?;
        let predecessor = activation.timeout_predecessor.as_deref()
            .ok_or("Wallet release activation has no authenticated predecessor")?;
        if activation.autonomous_closure.is_none()
            || activation.wallet_dispatch_policy() != Some(policy)
            || predecessor.epoch.root().map_err(|error| error.to_string())?
                != release.predecessor_context_root()
        {
            return Err("Wallet release differs from the certified authority transition".into());
        }
        Ok(())
    }

    pub fn protected_ingress_registry(
        &self,
    ) -> Result<&synergy_etdag::crypto::IngressKemKeyRegistry, String> {
        self.protected
            .as_ref()
            .map(|policy| &policy.ingress_kem_registry)
            .ok_or_else(|| "signed authority lacks governed ingress KEM registry".into())
    }

    pub(super) fn initial_world_state_root(&self) -> Result<String, String> {
        synergy_state::state_root(
            &self
                .protected
                .as_ref()
                .ok_or("signed protected initial World absent")?
                .initial_world_state,
        )
        .map_err(|e| format!("root governed initial World: {e:?}"))
    }

    pub fn initial_world_state_budgeted(
        &self,
        budget: &Arc<synergy_state::world_resources::WorldResourceBudget>,
    ) -> Result<synergy_state::world_resources::BudgetedWorld, String> {
        let world = &self
            .protected
            .as_ref()
            .ok_or("signed authority lacks governed initial world state")?
            .initial_world_state;
        synergy_state::world_resources::BudgetedWorld::try_clone_world(world, budget)
            .map_err(|error| format!("reserve initial world state: {error}"))
    }

    /// Names the approved future close boundary; never grants cutoff or reveal.
    pub fn protected_cutoff_boundary(
        &self,
        source: Option<&FinalizedBlockRecord>,
        proposal_height: u64,
    ) -> Result<synergy_etdag::EtdagDigest, String> {
        let policy = self
            .protected
            .as_ref()
            .ok_or("signed protected policy is absent")?;
        if policy.cutoff_relationship
            != synergy_genesis::authority::ProtectedCutoffRelationship::VcEventContextV1
        {
            return Err("unsupported governed cutoff relationship".into());
        }
        let target = proposal_height
            .checked_add(2)
            .ok_or("cutoff target height overflow")?;
        let (context, _) = self.protected_target(source, target)?;
        synergy_etdag::EtdagDigest::from_canonical(
            "SYNERGY_POSY_CUTOFF_BOUNDARY_V1",
            &(
                "vc_event_context_v1",
                self.epoch.chain_id,
                &self.epoch.network_id,
                self.epoch.epoch,
                proposal_height,
                target,
                context
                    .root()
                    .map_err(|e| format!("cutoff boundary context: {e:?}"))?,
                &self.epoch.consensus_parameter_root,
            ),
        )
        .map_err(|e| format!("governed cutoff boundary: {e:?}"))
    }

    pub fn protected_bootstrap_execution(
        &self,
        height: u64,
    ) -> Result<synergy_etdag::EtdagDigest, String> {
        self.bootstrap_commitment("SYNERGY_POSY_BOOTSTRAP_EXECUTION_V1", height)
    }

    pub fn protected_bootstrap_next_batch(
        &self,
        height: u64,
    ) -> Result<synergy_etdag::EtdagDigest, String> {
        self.bootstrap_commitment("SYNERGY_POSY_BOOTSTRAP_NEXT_BATCH_V1", height)
    }

    fn bootstrap_commitment(
        &self,
        domain: &str,
        height: u64,
    ) -> Result<synergy_etdag::EtdagDigest, String> {
        if !(1..=2).contains(&height) || self.anchor_parent.height() != 0 {
            return Err("bootstrap commitment is confined to fresh Genesis H1/H2".into());
        }
        let policy = self
            .protected
            .as_ref()
            .ok_or("signed protected policy is absent")?;
        let state_root = synergy_state::state_root(&policy.initial_world_state)
            .map_err(|e| format!("bootstrap state root: {e:?}"))?;
        synergy_etdag::EtdagDigest::from_canonical(
            domain,
            &(
                self.epoch.chain_id,
                &self.epoch.network_id,
                self.epoch.epoch,
                height,
                &self.anchor_parent,
                &self.epoch.consensus_parameter_root,
                policy.commitment()?,
                state_root,
            ),
        )
        .map_err(|e| format!("governed bootstrap commitment: {e:?}"))
    }

    pub fn protected_target(
        &self,
        source: Option<&FinalizedBlockRecord>,
        target: u64,
    ) -> Result<
        (
            synergy_etdag::TargetAdmissionContextV3,
            synergy_etdag::EtdagDigest,
        ),
        String,
    > {
        let policy = self
            .protected
            .as_ref()
            .ok_or("signed protected policy is absent")?;
        let (source_height, source_root) = match source {
            Some(record) => (record.height, processing_finality_root(record)?.0),
            None if self.anchor_parent.height() == 0 => {
                (0, self.anchor_parent.reference_id().to_owned())
            }
            None => return Err("protected target needs verified finalized source".into()),
        };
        let parameters = self.protected_parameters()?;
        parameters
            .validate_target_height(source_height, target)
            .map_err(|e| format!("governed protected source/target mapping: {e:?}"))?;
        let context = synergy_etdag::TargetAdmissionContextV3 {
            context_version: 1,
            chain_id: self.epoch.chain_id,
            network_id: self.epoch.network_id.clone(),
            protocol_version: self.epoch.protocol_version.clone(),
            epoch: self.epoch.epoch,
            target_height: target,
            target_height_offset: parameters.target_height_offset,
            source_finalized_height: source_height,
            source_finality_context_root: source_root,
            active_validator_set_root: self.epoch.active_validator_set_root.clone(),
            validator_consensus_key_root: self.epoch.validator_consensus_key_root.clone(),
            frozen_voting_weight_root: self.epoch.frozen_voting_weight_root.clone(),
            cluster_schedule_version: policy.cluster_schedule_version.clone(),
            finalized_epoch_seed_root: self.epoch.finalized_epoch_seed_root.clone(),
            assigned_height_schedule_root: policy.assigned_height_schedule_root.clone(),
            cluster_map_root: policy.cluster_map_root.clone(),
            assigned_cluster_id: policy.assigned_cluster_id,
            assigned_cluster_membership_root: policy.assigned_cluster_membership_root.clone(),
            assigned_cluster_validator_count: self.registry.active_count() as u64,
            assigned_cluster_total_voting_weight: u64::try_from(
                self.registry.active_weight().map_err(|e| e.to_string())?,
            )
            .map_err(|_| "protected cluster weight exceeds capacity")?,
            consensus_parameter_root: self.epoch.consensus_parameter_root.clone(),
            cryptographic_profile_root: policy.cryptographic_profile_root.clone(),
            ingress_kem_registry_root: policy
                .ingress_kem_registry
                .root()
                .map_err(|e| format!("KEM root: {e:?}"))?,
        };
        context
            .validate_with_parameters(&parameters)
            .map_err(|e| format!("governed protected context: {e:?}"))?;
        let root = context
            .root()
            .map_err(|e| format!("target context root: {e:?}"))?;
        // This return value identifies admission authority only. Actual close
        // authority is the independently verified VC at target-2.
        Ok((context, root))
    }

    /// Derives the sole source mapping from the verified signed ETDAG policy.
    pub fn protected_source_height(&self, target: u64) -> Result<u64, String> {
        self.protected_parameters()?
            .source_finalized_height(target)
            .map_err(|e| format!("governed protected source height: {e:?}"))
    }

    pub fn binding_bytes(&self) -> &[u8] {
        &self.binding_bytes
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthorityTransitionSignal {
    pending_epoch: Arc<Mutex<Option<u64>>>,
}

impl AuthorityTransitionSignal {
    pub fn stage(&self, epoch: u64) -> Result<(), String> {
        let mut pending = self
            .pending_epoch
            .lock()
            .map_err(|_| "authority transition signal lock is poisoned")?;
        match *pending {
            Some(existing) if existing != epoch => {
                Err("a different authority transition is already pending".into())
            }
            _ => {
                *pending = Some(epoch);
                Ok(())
            }
        }
    }

    pub fn take(&self) -> Result<Option<u64>, String> {
        self.pending_epoch
            .lock()
            .map(|mut pending| pending.take())
            .map_err(|_| "authority transition signal lock is poisoned".into())
    }
}

impl AegisVerifier for VerifiedAuthority {
    fn verify(
        &self,
        context: &SigningContext,
        message: &[u8],
        signature: &Signature,
        public_key: &[u8],
    ) -> Result<(), synergy_aegis::VerificationError> {
        if context.chain_id != self.chain_id {
            return Err(synergy_aegis::VerificationError::InvalidContext);
        }
        self.verifier
            .verify(context, message, signature, public_key)
    }
}

impl ProofVerifier for VerifiedAuthority {
    fn governed_public_key(&self, key_id: &KeyId) -> Result<Vec<u8>, String> {
        self.keys
            .values()
            .find(|key| {
                key.validator.consensus_key_id == key_id.as_str()
                    && key.algorithm == SignatureAlgorithm::MlDsa65
                    && key.validator.may_sign_consensus()
            })
            .map(|key| key.public_key.clone())
            .ok_or_else(|| {
                format!(
                    "key {} is not governed active validator authority",
                    key_id.as_str()
                )
            })
    }
}

fn read_bounded(path: &std::path::Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
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
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| file.take(maximum + 1).read_to_end(&mut bytes))
        .map_err(|error| format!("read {label} {}: {error}", path.display()))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{label} changed size while loading"));
    }
    Ok(bytes)
}

pub fn load(configuration: &NodeConfiguration) -> Result<Option<Arc<VerifiedAuthority>>, String> {
    let origin = load_managed_origin(configuration)?;
    if origin.as_ref().is_some_and(|authority| authority.genesis_autonomous)
        && configuration.consensus.autonomous_epoch_activation.is_some()
    {
        return Err("fresh autonomous Genesis cannot be mixed with a historical bootstrap".into());
    }
    match configuration.consensus.autonomous_epoch_activation.as_ref() {
        None => match origin {
            Some(origin) if origin.genesis_autonomous => recovery::successor::load_fresh_autonomous(configuration, origin).map(Some),
            other => Ok(other),
        },
        Some(activation) => recovery::successor::load_autonomous(
            configuration,
            activation,
            origin.ok_or("autonomous epochs require their authenticated signed origin")?,
        )
        .map(Some),
    }
}

/// The observer starts its independent proof cursor at signed Genesis. A
/// locally selected release may authenticate a future certified successor,
/// while the origin remains E1 and carries no activated Wallet policy.
pub(super) fn load_managed_origin(configuration: &NodeConfiguration) -> Result<Option<Arc<VerifiedAuthority>>, String> {
    let mut origin = load_signed(configuration)?;
    if let Some(pins) = &configuration.consensus.managed_wallet_dispatch_release {
        let verified = origin.as_mut().filter(|authority| authority.genesis_autonomous)
            .ok_or("managed Wallet release requires current signed autonomous Genesis")?;
        let release = managed_wallet::ManagedWalletRelease::load(configuration, verified, pins)?;
        Arc::make_mut(verified).managed_wallet_release = Some(Arc::new(release));
    }
    Ok(origin)
}

/// Authenticate the original transport trust document independently of the
/// current PoSy epoch. It never supplies derived consensus authority.
pub(super) fn load_signed(
    configuration: &NodeConfiguration,
) -> Result<Option<Arc<VerifiedAuthority>>, String> {
    let Some(binding_path) = configuration.consensus.authority_binding.as_ref() else {
        return Ok(None);
    };
    if configuration.consensus.authority_trust_key_path.is_none() {
        return Ok(None);
    }
    let bytes = read_bounded(binding_path, MAX_AUTHORITY_BYTES, "PoSy authority binding")?;
    let mut authority = verify_binding_bytes(configuration, bytes)?;
    if configuration.genesis_path.is_some() {
        let genesis = crate::commands::selected_network::verified_genesis(configuration)?;
        if authority.protected.as_ref().is_some_and(|policy|
            policy.initial_world_state.protocol.contains_key(super::ethereum_activation::RECORD_KEY)
            || policy.initial_world_state.protocol.contains_key(super::ethereum_activation::ACTIVE_KEY)) {
            return Err("Genesis cannot preinstall a governed EVM amendment or activation marker".into());
        }
        if genesis.unsigned.network.autonomous_epoch_protocol.is_some() || genesis.unsigned.network.ethereum_compatibility.is_some() {
            let binding: SignedAuthorityBinding = serde_json::from_slice(authority.binding_bytes())
                .map_err(|e| e.to_string())?;
            let trust = read_bounded(configuration.consensus.authority_trust_key_path.as_ref()
                .ok_or("fresh autonomous Genesis requires its pinned trust root")?,
                MAX_TRUST_KEY_BYTES, "fresh Genesis trust key")?;
            // Authenticate the exact authority bytes loaded above, not a second
            // file read observed by selected-network verification.
            synergy_genesis::verify_binding_with_verifier(&genesis, &trust, &binding, &authority.verifier)?;
            let enabled = synergy_genesis::validate_autonomous_origin(&genesis.unsigned, &binding.payload)?;
            Arc::make_mut(&mut authority).genesis_autonomous = enabled;
            if let Some(descriptor)=&genesis.unsigned.network.ethereum_compatibility {
                descriptor.validate()?;
                let world=&authority.protected.as_ref().ok_or("signed Ethereum Genesis requires canonical processing World")?.initial_world_state;
                let policy=synergy_aivm::ethereum_execution::EvmCompatibilityPolicy::load(world).map_err(|error|error.to_string())?;
                if world.protocol.keys().any(|key|key.starts_with("aivm/ethereum/v1/transaction/")
                    || key.starts_with("aivm/ethereum/v1/block/")||key.starts_with("aivm/ethereum/v1/native-parent/")
                    || key.starts_with("aivm/ethereum/v1/consumption/")) {
                    return Err("initial EVM World cannot claim transaction, receipt or native block history".into());
                }

                let bytes=world.protocol.get(synergy_aivm::ethereum_execution::EVM_POLICY_KEY).ok_or("initial EVM policy is missing")?;
                let expected=synergy_posy::parse_hash_bytes(&descriptor.policy_sha256).map_err(|error|error.to_string())?;
                if policy.chain_id!=genesis.unsigned.network.chain_id || synergy_aegis::AegisProtectedPrimitives.sha256(bytes)!=expected {
                    return Err("initial native EVM policy differs from independently signed Genesis commitment".into());
                }
                Arc::make_mut(&mut authority).ethereum_genesis=Some(EthereumGenesisAuthority{
                    descriptor:descriptor.clone(),genesis_hash:genesis.genesis_hash.clone(),activation_unix:genesis.unsigned.network.activation_unix,
                    activation_height:0,chain_id:genesis.unsigned.network.chain_id,
                });
            }
        }
    }

    let mut lineage = Vec::new();
    while let Some(path) = transition_witness_path(configuration, &authority)? {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(format!("inspect signed authority history: {error}")),
            Ok(_) => {}
        }
        // Read the immutable published witness without claiming its writer lock.
        let bytes = read_bounded(&path, 4 * 1024 * 1024, "authority transition witness")?;
        let transition = verify_stored_transition(configuration, &authority, &bytes)?;
        lineage.push(authority);
        authority = transition.previous;
    }
    for mut current in lineage.into_iter().rev() {
        Arc::make_mut(&mut current).timeout_predecessor = Some(authority);
        authority = current;
    }
    Ok(Some(authority))
}

pub fn verify_binding_bytes(
    configuration: &NodeConfiguration,
    bytes: Vec<u8>,
) -> Result<Arc<VerifiedAuthority>, String> {
    let trust_path = configuration
        .consensus
        .authority_trust_key_path
        .as_ref()
        .ok_or("PoSy authority verification requires authority_trust_key_path")?;
    let trust_key = read_bounded(trust_path, MAX_TRUST_KEY_BYTES, "authority trust key")?;
    let binding: SignedAuthorityBinding = serde_json::from_slice(&bytes)
        .map_err(|e| format!("decode authority for trust selection: {e}"))?;
    if binding.payload.epoch > 1
        && configuration
            .consensus
            .authority_recovery_certificate_path
            .is_some()
    {
        return recovery::verify_recovered_binding(configuration, bytes);
    }
    verify_binding_with_explicit_key(configuration, bytes, &trust_key)
}

// Kept private to the service. The normal runtime always uses the Genesis pin;
// the offline recovery verifier can inspect a candidate under a separate key.
fn verify_binding_with_explicit_key(
    configuration: &NodeConfiguration,
    bytes: Vec<u8>,
    trust_key: &[u8],
) -> Result<Arc<VerifiedAuthority>, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_AUTHORITY_BYTES {
        return Err("PoSy authority binding exceeds its canonical bound".into());
    }
    let binding: SignedAuthorityBinding = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode PoSy authority binding: {error}"))?;
    if binding.payload.version != 1
        || binding.payload.chain_id != configuration.chain_id
        || binding.payload.network_id != configuration.network_id
        || binding.signature.is_empty()
        || binding.signature.len() > 16 * 1024
    {
        return Err("PoSy authority binding is incompatible or malformed".into());
    }
    let signer_key_id = KeyId::new(binding.signer_key_id.clone())
        .map_err(|error| format!("invalid authority signer key id: {error}"))?;
    let policy = AegisPolicy {
        allowed_algorithms: vec![SignatureAlgorithm::MlDsa65],
        maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
        maximum_signature_bytes: 16 * 1024,
    };
    let verifier = super::apqe_provider::verifier(configuration, policy)?;
    let signing_bytes = binding.payload.signing_bytes()?;
    verifier
        .verify(
            &SigningContext {
                domain: "SYNERGY-POSY-AUTHORITY-BINDING-V1".into(),
                chain_id: configuration.chain_id,
                epoch: Some(binding.payload.epoch),
                height: None,
            },
            &signing_bytes,
            &Signature {
                algorithm: SignatureAlgorithm::MlDsa65,
                key_id: signer_key_id,
                bytes: binding.signature,
            },
            trust_key,
        )
        .map_err(|error| format!("verify PoSy authority binding: {error}"))?;

    let mut records = Vec::with_capacity(binding.payload.validators.len());
    let mut keys = BTreeMap::new();
    for authority in binding.payload.validators {
        authority
            .record
            .validate()
            .map_err(|error| error.to_string())?;
        if authority.algorithm != SignatureAlgorithm::MlDsa65 || authority.public_key.is_empty() {
            return Err("authority binding contains an unsupported consensus key".into());
        }
        if keys
            .insert(
                authority.record.validator_id.clone(),
                ConsensusKey {
                    validator: authority.record.clone(),
                    algorithm: authority.algorithm,
                    public_key: authority.public_key,
                },
            )
            .is_some()
        {
            return Err("authority binding contains a duplicate validator".into());
        }
        records.push(authority.record);
    }
    let registry = FrozenValidatorRegistry::new(binding.payload.epoch, records)
        .map_err(|error| error.to_string())?;
    let epoch = SimplifiedEpochContext::from_frozen_registry(
        binding.payload.chain_id,
        binding.payload.network_id,
        binding.payload.epoch,
        binding.payload.epoch_start_height,
        binding.payload.epoch_end_height,
        binding.payload.finalized_epoch_seed_root,
        binding.payload.consensus_parameter_root,
        &registry,
    )
    .map_err(|error| error.to_string())?;
    binding
        .payload
        .anchor_parent
        .validate_for_child_height(epoch.epoch_start_height)
        .map_err(|error| error.to_string())?;
    if let Some(policy) = &binding.payload.protected {
        policy.validate(&registry, &epoch)?;
    }
    Ok(Arc::new(VerifiedAuthority {
        registry,
        epoch,
        timeout_predecessor: None,
        autonomous_closure: None,
        genesis_autonomous: false,
        ethereum_genesis: None,
        ethereum_activation_cache:Arc::new(Mutex::new(None)),
        managed_wallet_release: None,
        anchor_parent: binding.payload.anchor_parent,
        verifier,
        wallet_verifier: super::apqe_provider::verifier(
            configuration,
            AegisPolicy {
                allowed_algorithms: vec![SignatureAlgorithm::MlDsa87],
                maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
                maximum_signature_bytes: 16 * 1024,
            },
        )?,
        identity_verifier: super::apqe_provider::identity_verifier(configuration)?,
        provider_configuration: configuration.aegis_provider.clone(),
        keys,
        chain_id: configuration.chain_id,
        binding_bytes: Arc::new(bytes),
        protected: binding.payload.protected.map(Arc::new),
        signature_cache: Arc::new(Mutex::new(ConsensusSignatureCache::default())),
    }))
}

pub(super) fn verify_transition_witness(
    previous: &VerifiedAuthority,
    finalized: &FinalizedBlockRecord,
    finality_witness: &[u8],
) -> Result<[SimplifiedQuorumCertificate; 3], String> {
    if finalized.height.checked_add(2) != Some(previous.epoch.epoch_end_height) {
        return Err(
            "authority transition requires finality closed by the epoch-boundary QC".into(),
        );
    }
    if finality_witness.is_empty() || finality_witness.len() > MAX_CONSENSUS_MESSAGE_BYTES {
        return Err("authority transition finality witness is missing or oversized".into());
    }
    let certificates: [SimplifiedQuorumCertificate; 3] =
        serde_json::from_slice(finality_witness)
            .map_err(|error| format!("decode authority transition finality witness: {error}"))?;
    let mut finality = ThreeQcFinality::default();
    for certificate in &certificates {
        certificate
            .verify(&previous.epoch, &previous.registry, previous)
            .map_err(|error| format!("verify authority transition QC: {error}"))?;
        finality
            .accept(certificate.clone())
            .map_err(|error| format!("verify authority transition ancestry: {error}"))?;
    }
    if finality.last_finalized() != Some(finalized) {
        return Err("authority transition witness differs from local finalized record".into());
    }
    Ok(certificates)
}

#[path = "authority_recovery.rs"]
pub(crate) mod recovery;

/// Previous-epoch evidence authenticated against this exact successor anchor.
/// Construction stays inside the transition verifier; consumers cannot promote
/// an arbitrary historical authority into native recovery authority.
#[derive(Clone)]
pub(super) struct VerifiedTransitionContext {
    previous: Arc<VerifiedAuthority>,
    finalized: FinalizedBlockRecord,
    certificates: [SimplifiedQuorumCertificate; 3],
    current_epoch_root: String,
    autonomous_closure: Option<Arc<VerifiedAutonomousClosure>>,
}

#[derive(Debug)]
struct VerifiedAutonomousClosure {
    authorization: EpochTransitionAuthorization,
    finalized: FinalizedBlockRecord,
    witness: synergy_posy::FinalitySyncWitness,
    subject_root: String,
    public: Option<AutonomousProofFile>,
}

#[derive(Debug)]
struct AutonomousProofFile {
    path: std::path::PathBuf,
    sha256: String,
    kind: &'static str,
}

impl VerifiedTransitionContext {
    pub(super) fn is_autonomous(&self) -> bool {
        self.autonomous_closure.is_some()
    }

    pub(super) fn previous_authority(&self) -> &Arc<VerifiedAuthority> {
        &self.previous
    }
    pub(super) fn finalized(&self) -> &FinalizedBlockRecord {
        &self.finalized
    }
    pub(super) fn certificates(&self) -> &[SimplifiedQuorumCertificate; 3] {
        &self.certificates
    }
    /// Initialize the single PoSy projection from an authenticated predecessor.
    /// Signed continuation and future consensus-derived authority share this
    /// carryover path; neither is allowed to inject a raw three-QC prefix.
    pub(super) fn seed_successor(
        &self,
        current: &VerifiedAuthority,
        machine: &mut synergy_posy::SimplifiedConsensusStateMachine,
    ) -> Result<(), String> {
        self.verify_current(current)?;
        let previous = self.previous_authority();
        if let Some(closure) = &self.autonomous_closure {
            return machine
                .restore_derived_epoch_transition(
                    &closure.authorization,
                    &previous.epoch,
                    &previous.registry,
                    closure.finalized.clone(),
                    closure.witness.clone(),
                    &closure.subject_root,
                    previous.as_ref(),
                )
                .map_err(|e| format!("restore autonomous epoch finality: {e}"));
        }
        let authorization = EpochTransitionAuthorization {
            previous_epoch: previous.epoch.epoch,
            previous_epoch_context_root: previous.epoch.root().map_err(|e| e.to_string())?,
            finalized_height: self.finalized.height,
            next_epoch: current.epoch.epoch,
            next_epoch_start_height: current.epoch.epoch_start_height,
            next_epoch_end_height: current.epoch.epoch_end_height,
            next_consensus_parameter_root: current.epoch.consensus_parameter_root.clone(),
            next_active_validator_set_root: current.epoch.active_validator_set_root.clone(),
            next_validator_consensus_key_root: current.epoch.validator_consensus_key_root.clone(),
            next_frozen_voting_weight_root: current.epoch.frozen_voting_weight_root.clone(),
        };
        machine
            .seed_verified_epoch_transition(
                &authorization,
                &previous.epoch,
                &previous.registry,
                self.finalized.clone(),
                self.certificates.clone(),
                previous.as_ref(),
            )
            .map_err(|e| format!("seed successor epoch finality: {e}"))
    }

    pub(super) fn verify_current(&self, current: &VerifiedAuthority) -> Result<(), String> {
        if current.epoch.root().map_err(|e| e.to_string())? != self.current_epoch_root {
            return Err("verified transition belongs to a different successor authority".into());
        }
        Ok(())
    }
}

pub fn load_transition_finality_prefix(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
) -> Result<Option<(FinalizedBlockRecord, [SimplifiedQuorumCertificate; 3])>, String> {
    Ok(load_transition_context(configuration, current)?
        .map(|context| (context.finalized, context.certificates)))
}

pub(super) fn load_transition_context(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
) -> Result<Option<VerifiedTransitionContext>, String> {
    if let Some(closure) = &current.autonomous_closure {
        return Ok(Some(VerifiedTransitionContext {
            previous: current
                .timeout_predecessor
                .clone()
                .ok_or("derived predecessor missing")?,
            finalized: closure.finalized.clone(),
            certificates: closure.witness.quorum_certificates.clone(),
            current_epoch_root: current.epoch.root().map_err(|e| e.to_string())?,
            autonomous_closure: Some(Arc::clone(closure)),
        }));
    }
    if current.epoch.epoch <= 1 {
        return Ok(None);
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let store = AtomicStore::new(
        layout.consensus().join("authority-transitions"),
        4 * 1024 * 1024,
    )
    .map_err(|error| format!("open authority transition store: {error}"))?;
    let path = format!("epoch-{:020}.json", current.epoch.epoch);
    if !store.exists(&path).map_err(|error| error.to_string())? {
        return Err(format!(
            "successor epoch {} lacks its verified transition witness",
            current.epoch.epoch
        ));
    }
    let bytes = store
        .read_bounded(&path)
        .map_err(|error| format!("read authority transition witness: {error}"))?;
    verify_stored_transition(configuration, current, &bytes).map(Some)
}

pub(super) fn transition_witness_path(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
) -> Result<Option<std::path::PathBuf>, String> {
    if current.epoch.epoch <= 1 {
        return Ok(None);
    }
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    Ok(Some(
        layout
            .consensus()
            .join("authority-transitions")
            .join(format!("epoch-{:020}.json", current.epoch.epoch)),
    ))
}

/// The transition owner publishes this single immutable witness with
/// write_atomic before switching authority. Transport observers authenticate
/// the published file; journal recovery remains with the storage owner.
pub(super) fn verify_stored_transition(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
    bytes: &[u8],
) -> Result<VerifiedTransitionContext, String> {
    let stored: StoredEpochTransition = serde_json::from_slice(bytes)
        .map_err(|error| format!("decode authority transition witness: {error}"))?;
    if stored.version != 1 || stored.next_epoch != current.epoch.epoch {
        return Err("stored authority transition identifies a different epoch".into());
    }
    let previous = verify_binding_bytes(configuration, stored.previous_authority_binding)?;
    if previous.epoch.epoch.checked_add(1) != Some(current.epoch.epoch)
        || previous.epoch.epoch_end_height.checked_add(1) != Some(current.epoch.epoch_start_height)
    {
        return Err("stored authority transition is not sequential".into());
    }
    let certificates = verify_transition_witness(
        previous.as_ref(),
        &stored.finalized,
        &stored.finality_witness,
    )?;
    let boundary = certificates
        .last()
        .ok_or("stored authority transition has no boundary QC")?;
    let boundary_reference = boundary.reference().map_err(|error| error.to_string())?;
    if current
        .anchor_parent
        .quorum_certificate_reference()
        .as_ref()
        != Some(&boundary_reference)
    {
        return Err("stored authority transition differs from current anchor".into());
    }
    Ok(VerifiedTransitionContext {
        previous,
        finalized: stored.finalized,
        certificates,
        current_epoch_root: current.epoch.root().map_err(|e| e.to_string())?,
        autonomous_closure: None,
    })
}

pub fn verify_and_persist_transition(
    configuration: &NodeConfiguration,
    current: &VerifiedAuthority,
    finalized: &FinalizedBlockRecord,
    finality_witness: &[u8],
    next_binding_bytes: Vec<u8>,
    signal: &AuthorityTransitionSignal,
) -> Result<Arc<VerifiedAuthority>, String> {
    if current.autonomous_epochs_enabled()
        || configuration.consensus.autonomous_epoch_activation.is_some()
    {
        return Err("signed successor cannot replace the autonomous trust origin".into());
    }
    let certificates = verify_transition_witness(current, finalized, finality_witness)?;
    let boundary = certificates
        .last()
        .ok_or("authority transition witness has no boundary QC")?;
    let boundary_qc_id = boundary.id().map_err(|error| error.to_string())?;
    let next = verify_binding_bytes(configuration, next_binding_bytes.clone())?;
    match &next.anchor_parent {
        SimplifiedFinalityParent::QuorumCertificate {
            height,
            block_id,
            qc_id,
        } if *height == boundary.context.height
            && block_id == &boundary.block_id
            && qc_id == &boundary_qc_id => {}
        _ => {
            return Err(
                "next authority anchor does not match the verified epoch-boundary QC".into(),
            )
        }
    }
    let authorization = EpochTransitionAuthorization {
        previous_epoch: current.epoch.epoch,
        previous_epoch_context_root: current.epoch.root().map_err(|error| error.to_string())?,
        finalized_height: finalized.height,
        next_epoch: next.epoch.epoch,
        next_epoch_start_height: next.epoch.epoch_start_height,
        next_epoch_end_height: next.epoch.epoch_end_height,
        next_consensus_parameter_root: next.epoch.consensus_parameter_root.clone(),
        next_active_validator_set_root: next.epoch.active_validator_set_root.clone(),
        next_validator_consensus_key_root: next.epoch.validator_consensus_key_root.clone(),
        next_frozen_voting_weight_root: next.epoch.frozen_voting_weight_root.clone(),
    };
    authorization
        .validate(&current.epoch, &next.epoch, &next.registry)
        .map_err(|error| format!("validate finalized authority transition: {error}"))?;
    let layout = NodeStorageLayout::new(configuration.storage.data_directory.clone())
        .map_err(|error| format!("construct canonical storage layout: {error}"))?;
    let transition_store = AtomicStore::new(
        layout.consensus().join("authority-transitions"),
        4 * 1024 * 1024,
    )
    .map_err(|error| format!("open authority transition store: {error}"))?;
    let transition = StoredEpochTransition {
        version: 1,
        next_epoch: next.epoch.epoch,
        previous_authority_binding: current.binding_bytes.as_ref().clone(),
        finalized: finalized.clone(),
        finality_witness: finality_witness.to_vec(),
    };
    let transition_path = format!("epoch-{:020}.json", next.epoch.epoch);
    let transition_bytes = serde_json::to_vec(&transition)
        .map_err(|error| format!("encode authority transition witness: {error}"))?;
    if transition_store
        .exists(&transition_path)
        .map_err(|e| e.to_string())?
    {
        if transition_store
            .read_bounded(&transition_path)
            .map_err(|e| e.to_string())?
            != transition_bytes
        {
            return Err("existing authority transition witness conflicts with activation".into());
        }
    } else {
        transition_store
            .write_atomic(&transition_path, &transition_bytes)
            .map_err(|error| format!("persist authority transition witness: {error}"))?;
    }
    persist_binding(configuration, &next_binding_bytes, next.epoch.epoch)?;
    signal.stage(next.epoch.epoch)?;
    Ok(next)
}

fn persist_binding(
    configuration: &NodeConfiguration,
    bytes: &[u8],
    next_epoch: u64,
) -> Result<(), String> {
    let path = configuration
        .consensus
        .authority_binding
        .as_ref()
        .ok_or("authority transition requires authority_binding path")?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect current authority binding: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("authority binding target must be a regular non-symlink file".into());
    }
    let parent = path
        .parent()
        .ok_or("authority binding path has no parent directory")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect authority binding directory: {error}"))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("authority binding parent must be a regular directory".into());
    }
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("authority binding file name is invalid")?;
    let staging = parent.join(format!(
        ".{file_name}.epoch-{next_epoch}.{}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .map_err(|error| format!("create authority transition staging file: {error}"))?;
    let write_result = file
        .write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("persist authority transition staging file: {error}"));
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&staging);
        return Err(error);
    }
    if let Err(error) = fs::rename(&staging, path) {
        let _ = fs::remove_file(&staging);
        return Err(format!("commit authority transition binding: {error}"));
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync authority transition directory: {error}"))
}

impl SxcpExecutionAuthorizationVerifier for VerifiedAuthority {
    fn verify_execution_authorization(&self, execution: &SxcpRelayExecution) -> Result<(), String> {
        let transcript = execution.signing_bytes()?;
        let mut signers = Vec::with_capacity(execution.signatures.len());
        let mut seen = std::collections::BTreeSet::new();
        for signature in &execution.signatures {
            if !seen.insert(signature.validator_id.as_str()) {
                return Err("SXCP authorization repeats a validator".into());
            }
            let key = self
                .keys
                .get(&signature.validator_id)
                .ok_or("SXCP authorization signer is not frozen authority")?;
            if key.validator.consensus_key_id != signature.key_id
                || key.algorithm != SignatureAlgorithm::MlDsa65
                || !key.validator.may_sign_consensus()
            {
                return Err("SXCP authorization uses a non-authoritative key".into());
            }
            let key_id = KeyId::new(signature.key_id.clone()).map_err(|error| error.to_string())?;
            self.verifier
                .verify(
                    &SigningContext {
                        domain: "SYNERGY-SXCP-RELAY-AUTHORIZATION-V1".into(),
                        chain_id: self.chain_id,
                        epoch: Some(self.epoch.epoch),
                        height: None,
                    },
                    &transcript,
                    &Signature {
                        algorithm: SignatureAlgorithm::MlDsa65,
                        key_id,
                        bytes: signature.signature.clone(),
                    },
                    &key.public_key,
                )
                .map_err(|error| format!("verify Aegis SXCP authorization: {error}"))?;
            signers.push(signature.validator_id.clone());
        }
        synergy_posy::verify_strict_dual_quorum(&self.registry.quorum_validators(), &signers)
            .map_err(|error| format!("SXCP authorization lacks frozen dual quorum: {error:?}"))
    }
}

impl VoteVerifier for VerifiedAuthority {
    fn verify(&self, vote: &GovernanceVote) -> Result<(), String> {
        vote.validate_shape()?;
        let key = self
            .keys
            .get(&vote.authority_id)
            .ok_or("governance voter is not in frozen authority")?;
        if key.validator.consensus_key_id != vote.key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || !key.validator.may_sign_consensus()
        {
            return Err("governance vote key is not active frozen authority".into());
        }
        let key_id = KeyId::new(vote.key_id.clone()).map_err(|error| error.to_string())?;
        self.verifier
            .verify(
                &SigningContext {
                    domain: "SYNERGY-GOVERNANCE-VOTE-V1".into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch.epoch),
                    height: None,
                },
                &vote.signing_bytes()?,
                &Signature {
                    algorithm: SignatureAlgorithm::MlDsa65,
                    key_id,
                    bytes: vote.signature.clone(),
                },
                &key.public_key,
            )
            .map_err(|error| format!("verify Aegis governance vote: {error}"))
    }
}

impl ConsensusSignatureVerifier for VerifiedAuthority {
    fn verify_timeout_boundary_parent(
        &self,
        successor: &SimplifiedEpochContext,
        proof: &SimplifiedQuorumCertificate,
    ) -> PosyResult<()> {
        let previous = self.timeout_predecessor.as_ref().ok_or_else(|| {
            PosyError::invalid("timeout boundary requires an authenticated predecessor")
        })?;
        if successor != &self.epoch
            || proof.context.height != previous.epoch.epoch_end_height
            || proof.context.height.checked_add(1) != Some(successor.epoch_start_height)
            || previous.epoch.epoch.checked_add(1) != Some(successor.epoch)
            || self.anchor_parent.quorum_certificate_reference().as_ref()
                != Some(&proof.reference()?)
        {
            return Err(PosyError::invalid(
                "timeout parent differs from authenticated epoch anchor",
            ));
        }
        // The stable QC ID does not commit to signatures. Verify the complete
        // supplied QC, including its actual quorum, using the previous roster.
        proof.verify(&previous.epoch, &previous.registry, previous.as_ref())
    }

    fn verify_consensus_signature(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()> {
        self.verify_consensus_signature_in_epoch(
            domain,
            payload,
            validator,
            key_id,
            self.epoch.epoch,
            epoch,
            signature,
        )
    }
}

impl VerifiedAuthority {
    // The ordinary verifier pins self.epoch. An offline successor proof
    // consumer can advance its expected scope only after it has verified the
    // finalized transition and independently proven that the key set is
    // unchanged. Both use this same APQE implementation and cache.
    #[allow(clippy::too_many_arguments)]
    fn verify_consensus_signature_in_epoch(
        &self,
        domain: &str,
        payload: &[u8],
        validator: &ValidatorRecord,
        key_id: &str,
        expected_epoch: u64,
        epoch: u64,
        signature: &[u8],
    ) -> PosyResult<()> {
        let key = self
            .keys
            .get(&validator.validator_id)
            .ok_or_else(|| PosyError::UnknownValidator(validator.validator_id.clone()))?;
        if &key.validator != validator
            || key.validator.consensus_key_id != key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || epoch != expected_epoch
        {
            return Err(PosyError::invalid(
                "consensus signature authority binding mismatch",
            ));
        }
        let key_id = KeyId::new(key_id.to_string())
            .map_err(|error| PosyError::invalid(error.to_string()))?;
        let cache_bytes = domain
            .len()
            .saturating_add(std::mem::size_of::<VerifiedConsensusSignature>())
            .saturating_add(validator.validator_id.len())
            .saturating_add(key_id.as_str().len())
            .saturating_add(payload.len())
            .saturating_add(signature.len())
            .saturating_add(key.public_key.len());
        let cached =
            (cache_bytes <= MAX_SIGNATURE_CACHE_ENTRY_BYTES).then(|| VerifiedConsensusSignature {
                domain: domain.to_string(),
                chain_id: self.chain_id,
                epoch,
                height: None,
                validator_id: validator.validator_id.clone(),
                key_id: key_id.as_str().to_string(),
                payload: payload.to_vec(),
                signature: signature.to_vec(),
                algorithm: key.algorithm,
                public_key: key.public_key.clone(),
            });
        if let Some(entry) = cached.as_ref() {
            let cache = self
                .signature_cache
                .lock()
                .map_err(|_| PosyError::invalid("consensus signature cache poisoned"))?;
            if cache.entries.contains(entry) {
                return Ok(());
            }
        }
        #[cfg(test)]
        {
            self.signature_cache.lock().unwrap().primitive_verifications += 1;
        }
        self.verifier
            .verify(
                &SigningContext {
                    domain: domain.to_string(),
                    chain_id: self.chain_id,
                    epoch: Some(epoch),
                    height: None,
                },
                payload,
                &Signature {
                    algorithm: key.algorithm,
                    key_id,
                    bytes: signature.to_vec(),
                },
                &key.public_key,
            )
            .map_err(|error| PosyError::invalid(format!("Aegis consensus signature: {error}")))?;
        if let Some(entry) = cached {
            self.signature_cache
                .lock()
                .map_err(|_| PosyError::invalid("consensus signature cache poisoned"))?
                .insert(entry);
        }
        Ok(())
    }
}

impl EtdagSignatureVerifier for VerifiedAuthority {
    fn verify(
        &self,
        validator_id: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EtdagError> {
        let key = self
            .keys
            .get(validator_id)
            .ok_or_else(|| EtdagError::UnauthorizedValidator(validator_id.into()))?;
        if key.validator.consensus_key_id != key_id
            || key.algorithm != SignatureAlgorithm::MlDsa65
            || !key.validator.may_sign_consensus()
        {
            return Err(EtdagError::UnauthorizedValidator(validator_id.into()));
        }
        let key_id = KeyId::new(key_id.to_string()).map_err(|_| EtdagError::InvalidSignature)?;
        // Cache only the exact successful primitive under frozen authority.
        // Certificate quorum, context and structure remain checked by callers.
        let domain = "SYNERGY-ETDAG-SIGNATURE-V1";
        let cache_bytes = domain
            .len()
            .saturating_add(std::mem::size_of::<VerifiedConsensusSignature>())
            .saturating_add(validator_id.len())
            .saturating_add(key_id.as_str().len())
            .saturating_add(message.len())
            .saturating_add(signature.len())
            .saturating_add(key.public_key.len());
        let cached =
            (cache_bytes <= MAX_SIGNATURE_CACHE_ENTRY_BYTES).then(|| VerifiedConsensusSignature {
                domain: domain.to_string(),
                chain_id: self.chain_id,
                epoch: self.epoch.epoch,
                height: None,
                validator_id: validator_id.to_string(),
                key_id: key_id.as_str().to_string(),
                payload: message.to_vec(),
                signature: signature.to_vec(),
                algorithm: key.algorithm,
                public_key: key.public_key.clone(),
            });
        if let Some(entry) = cached.as_ref() {
            let cache = self.signature_cache.lock().map_err(|_| {
                EtdagError::CryptoProvider("consensus signature cache poisoned".into())
            })?;
            if cache.entries.contains(entry) {
                return Ok(());
            }
        }
        #[cfg(test)]
        {
            self.signature_cache.lock().unwrap().primitive_verifications += 1;
        }
        self.verifier
            .verify(
                &SigningContext {
                    domain: domain.into(),
                    chain_id: self.chain_id,
                    epoch: Some(self.epoch.epoch),
                    height: None,
                },
                message,
                &Signature {
                    algorithm: key.algorithm,
                    key_id,
                    bytes: signature.to_vec(),
                },
                &key.public_key,
            )
            .map_err(|error| match error {
                synergy_aegis::VerificationError::InvalidSignature
                | synergy_aegis::VerificationError::InvalidPublicKey => {
                    EtdagError::InvalidSignature
                }
                error => EtdagError::CryptoProvider(error.to_string()),
            })?;
        if let Some(entry) = cached {
            self.signature_cache
                .lock()
                .map_err(|_| {
                    EtdagError::CryptoProvider("consensus signature cache poisoned".into())
                })?
                .insert(entry);
        }
        Ok(())
    }
}

impl synergy_etdag::reveal::RevealAuthorizationVerifier for VerifiedAuthority {
    fn verify_parent_commitment(
        &self,
        authorization: &synergy_etdag::ProtectedRevealAuthorization,
        evidence: &synergy_etdag::execution::ParentProposalRevealEvidence,
    ) -> Result<(), EtdagError> {
        // The existing ECHO quorum proves validation of the exact parent.
        // It adds no ETDAG vote, leader, timeout or finality engine.
        let certificate: synergy_posy::ProposalValidationCertificate =
            serde_json::from_slice(&evidence.validation_proof)
                .map_err(|_| EtdagError::UnauthorizedReveal)?;
        certificate
            .verify(&self.epoch, &self.registry, self)
            .map_err(|_| EtdagError::UnauthorizedReveal)?;
        let material_root = synergy_block::hash_block_bytes(&evidence.material.commitment_bytes()?);
        if certificate.context.height != evidence.material.height
            || certificate.context.height.checked_add(1) != Some(authorization.target_height)
            || certificate.candidate.protected_execution_root != material_root
            || evidence.material.next_batch_root != authorization.protected_batch_root
            || evidence.next_batch.context_root != authorization.context_root
            || evidence.next_batch.target_height != authorization.target_height
            || evidence.next_batch.protected_batch_root != authorization.protected_batch_root
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        let id = certificate
            .id()
            .map_err(|_| EtdagError::UnauthorizedReveal)?;
        if synergy_etdag::reveal::parent_reveal_reference(
            &certificate.candidate.block_id,
            &id,
            authorization,
        )? != authorization.finality_reference
        {
            return Err(EtdagError::UnauthorizedReveal);
        }
        Ok(())
    }
}

// Durable plaintext is accepted only after replaying the authenticated threshold
// evidence against the same frozen authority that opened the target.
impl synergy_etdag::persistence::ProtectedRecoveryVerifier for VerifiedAuthority {
    fn verify_nonempty_prepared(
        &self,
        context: &synergy_etdag::TargetAdmissionContextV3,
        prepared: &synergy_etdag::execution::PreparedProtectedBatch,
        transcripts: &BTreeMap<synergy_etdag::EtdagDigest, synergy_etdag::reveal::RevealTranscript>,
        envelopes: &BTreeMap<
            synergy_etdag::EtdagDigest,
            synergy_etdag::EncryptedTransactionEnvelope,
        >,
    ) -> Result<(), EtdagError> {
        use synergy_etdag::reveal::{
            decrypt_authorized_envelope, verify_decrypt_share, VerifiedRevealAuthorization,
            VerifiedShareCollector,
        };
        prepared.validate()?;
        if &prepared.context != context
            || prepared.transactions.is_empty()
            || transcripts.len() != prepared.transactions.len()
            || envelopes.len() != prepared.transactions.len()
        {
            return Err(EtdagError::InvalidExecutionInput);
        }
        let registry = self
            .protected_ingress_registry()
            .map_err(EtdagError::Governance)?;
        registry.validate_protected_profile()?;
        let members = self
            .registry
            .active()
            .map(|v| v.validator_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        if context.assigned_cluster_validator_count != members.len() as u64
            || registry.root()? != context.ingress_kem_registry_root
        {
            return Err(EtdagError::ContextMismatch);
        }
        let count_quorum = synergy_etdag::certificate_quorum(members.len())?;
        let decryptor =
            synergy_etdag::crypto::GovernedThresholdDecryptor::new(members.len(), count_quorum)?;
        let verified = VerifiedRevealAuthorization::verify(
            prepared.reveal_authorization.clone(),
            &prepared.parent_evidence,
            self,
        )?;
        let mut revealed_transactions = Vec::with_capacity(prepared.transactions.len());
        let mut vertex_envelopes = BTreeMap::new();
        for transaction in &prepared.transactions {
            let envelope = envelopes
                .get(&transaction.envelope_id)
                .ok_or_else(|| EtdagError::MissingArtifact(transaction.envelope_id.0.clone()))?;
            let transcript = transcripts
                .get(&transaction.envelope_id)
                .ok_or_else(|| EtdagError::MissingArtifact(transaction.envelope_id.0.clone()))?;
            if transcript.authorization != prepared.reveal_authorization {
                return Err(EtdagError::UnauthorizedReveal);
            }
            let mut collector = VerifiedShareCollector::new(
                verified.clone(),
                transaction.envelope_id.clone(),
                count_quorum,
                members.len(),
            )?;
            for share in &transcript.shares {
                collector.insert(verify_decrypt_share(
                    share,
                    &prepared.reveal_authorization,
                    &members,
                    envelope,
                    registry,
                    context,
                    self,
                )?)?;
            }
            let shares = collector.into_threshold_shares()?;
            if transcript.root(synergy_etdag::crypto::governed_reveal_threshold(
                members.len(),
                count_quorum,
            )?)? != shares.transcript_root()?
            {
                return Err(EtdagError::InvalidExecutionInput);
            }
            let revealed = decrypt_authorized_envelope(envelope, &shares, &decryptor)?;
            if revealed.plaintext() != transaction.plaintext
                || revealed.envelope_id() != &transaction.envelope_id
            {
                return Err(EtdagError::InvalidExecutionInput);
            }
            vertex_envelopes.insert(
                transaction.vertex_id.clone(),
                transaction.envelope_id.clone(),
            );
            revealed_transactions.push(revealed);
        }
        let mut roots = revealed_transactions
            .iter()
            .map(|tx| (tx.envelope_id().clone(), tx.transcript_root().clone()))
            .collect::<Vec<_>>();
        roots.sort();
        let transcript_root = synergy_etdag::EtdagDigest::from_canonical(
            "SYNERGY_ETDAG_BATCH_REVEAL_TRANSCRIPTS_V1",
            &roots,
        )?;
        let input = synergy_etdag::DeterministicProtectedExecutionInput::from_batch(
            &prepared.parent_evidence.next_batch,
            &vertex_envelopes,
            transcript_root,
        )?;
        let rebuilt = synergy_etdag::execution::prepare_deterministic_batch(
            context.clone(),
            &input,
            &vertex_envelopes,
            &revealed_transactions,
            &verified,
            prepared.parent_evidence.clone(),
        )?;
        if &rebuilt != prepared {
            return Err(EtdagError::InvalidExecutionInput);
        }
        Ok(())
    }
}

impl VerifiedAuthority {
    pub(crate) fn apqe_identity_verifier(&self) -> Option<synergy_aegis::ApqeIdentityVerifier> {
        self.identity_verifier.clone()
    }
    pub(crate) fn wallet_verifier(&self) -> &PqvmVerifier {
        &self.wallet_verifier
    }
    pub(crate) fn identity_verifier(
        &self,
    ) -> Option<&dyn synergy_identity::authorization::AuthorizationSignatureVerifier> {
        self.identity_verifier
            .as_ref()
            .map(|v| v as &dyn synergy_identity::authorization::AuthorizationSignatureVerifier)
    }
    pub(super) fn native_identity_verifier(&self)->Option<&synergy_aegis::ApqeIdentityVerifier>{
        self.identity_verifier.as_ref()
    }
}

#[cfg(test)]
mod signature_cache_storage_tests {
    use super::*;

    #[test]
    fn etdag_signature_cache_reuses_only_exact_successful_frozen_authority() {
        use aegis_pqvm::pqc::signatures::mldsa::mldsa65;
        use pqrust_traits::sign::{DetachedSignature as _, PublicKey as _};
        use synergy_posy::ValidatorStatus;

        let (public, secret) = mldsa65::keypair();
        let validator = ValidatorRecord {
            validator_id: "etdag-cache-validator".into(),
            consensus_key_id: "etdag-cache-key".into(),
            frozen_voting_weight: 1,
            status: ValidatorStatus::Active,
        };
        let mut validators = vec![(validator.clone(), public.as_bytes().to_vec())];
        // The primitive fixture retains the governed minimum validator set.
        for index in 1..synergy_posy::POSY_MIN_VALIDATOR_COUNT {
            let mut peer = validator.clone();
            peer.validator_id = format!("etdag-cache-peer-{index}");
            peer.consensus_key_id = format!("etdag-cache-peer-key-{index}");
            validators.push((peer, public.as_bytes().to_vec()));
        }
        let mut authority = qualification_authority(validators);
        let message = b"genuine ETDAG cache primitive";
        let signature = mldsa65::detached_sign(message, &secret);
        let verify = |authority: &VerifiedAuthority, message: &[u8], signature: &[u8]| {
            EtdagSignatureVerifier::verify(
                authority,
                "etdag-cache-validator",
                "etdag-cache-key",
                message,
                signature,
            )
        };
        verify(&authority, message, signature.as_bytes()).unwrap();
        let warmed = authority.consensus_signature_cache_stats();
        assert_eq!(warmed.0, 1);
        assert_eq!(warmed.2, 1);
        verify(&authority, message, signature.as_bytes()).unwrap();
        assert_eq!(authority.consensus_signature_cache_stats(), warmed);

        let mut bad_signature = signature.as_bytes().to_vec();
        bad_signature[0] ^= 1;
        for _ in 0..2 {
            assert!(verify(&authority, message, &bad_signature).is_err());
        }
        assert!(verify(&authority, b"altered message", signature.as_bytes()).is_err());
        assert_eq!(authority.consensus_signature_cache_stats().0, warmed.0);
        assert_eq!(authority.consensus_signature_cache_stats().2, warmed.2 + 3);
        for (validator_id, key_id) in [
            ("unknown-validator", "etdag-cache-key"),
            ("etdag-cache-validator", "wrong-key"),
        ] {
            assert!(EtdagSignatureVerifier::verify(
                &*authority,
                validator_id,
                key_id,
                message,
                signature.as_bytes()
            )
            .is_err());
        }
        assert_eq!(authority.consensus_signature_cache_stats().2, warmed.2 + 3);

        // Test-only mutation exercises authority checks against a warmed cache;
        // production authority is immutable and epoch replacements start empty.
        let key = Arc::get_mut(&mut authority)
            .unwrap()
            .keys
            .get_mut("etdag-cache-validator")
            .unwrap();
        key.validator.status = ValidatorStatus::Jailed;
        assert!(verify(&authority, message, signature.as_bytes()).is_err());
        let key = Arc::get_mut(&mut authority)
            .unwrap()
            .keys
            .get_mut("etdag-cache-validator")
            .unwrap();
        key.validator.status = ValidatorStatus::Active;
        key.public_key[0] ^= 1;
        assert!(verify(&authority, message, signature.as_bytes()).is_err());
        assert_eq!(authority.consensus_signature_cache_stats().0, warmed.0);
        let key = Arc::get_mut(&mut authority)
            .unwrap()
            .keys
            .get_mut("etdag-cache-validator")
            .unwrap();
        key.public_key[0] ^= 1;
        verify(&authority, message, signature.as_bytes()).unwrap();
        let fresh = authority.as_ref().clone();
        assert_eq!(fresh.consensus_signature_cache_stats(), (0, 0, 0));
        verify(&fresh, message, signature.as_bytes()).unwrap();
        assert_eq!(fresh.consensus_signature_cache_stats().2, 1);

        // Oversized entries retain native validation without consuming cache.
        let large = vec![7; MAX_SIGNATURE_CACHE_ENTRY_BYTES];
        let large_signature = mldsa65::detached_sign(&large, &secret);
        let before = authority.consensus_signature_cache_stats();
        for _ in 0..2 {
            verify(&authority, &large, large_signature.as_bytes()).unwrap();
        }
        let after = authority.consensus_signature_cache_stats();
        assert_eq!((after.0, after.1), (before.0, before.1));
        assert_eq!(after.2, before.2 + 2);
    }

    // Storage-only entries exercise eviction independently of cryptography;
    // genuine signed QC admission and rejection live in socket qualification.
    fn entry(index: usize, payload_bytes: usize) -> VerifiedConsensusSignature {
        VerifiedConsensusSignature {
            domain: "bounded-cache-storage".into(),
            chain_id: 1266,
            epoch: 1,
            height: None,
            validator_id: "storage-test".into(),
            key_id: index.to_string(),
            payload: vec![0; payload_bytes],
            signature: Vec::new(),
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key: Vec::new(),
        }
    }

    #[test]
    fn consensus_signature_cache_evicts_at_both_memory_and_entry_bounds() {
        let mut by_count = ConsensusSignatureCache::default();
        for index in 0..=MAX_SIGNATURE_CACHE_ENTRIES {
            by_count.insert(entry(index, 0));
        }
        assert_eq!(by_count.entries.len(), MAX_SIGNATURE_CACHE_ENTRIES);
        assert!(!by_count.entries.contains(&entry(0, 0)));
        assert!(by_count
            .entries
            .contains(&entry(MAX_SIGNATURE_CACHE_ENTRIES, 0)));

        let mut by_bytes = ConsensusSignatureCache::default();
        for index in 0..1024 {
            by_bytes.insert(entry(index, 32 * 1024));
            assert!(by_bytes.bytes <= MAX_SIGNATURE_CACHE_BYTES);
            assert!(by_bytes.entries.len() <= MAX_SIGNATURE_CACHE_ENTRIES);
        }
        assert!(!by_bytes.entries.contains(&entry(0, 32 * 1024)));
        assert!(by_bytes.entries.contains(&entry(1023, 32 * 1024)));
        assert_eq!(
            by_bytes.bytes,
            by_bytes
                .entries
                .iter()
                .map(VerifiedConsensusSignature::byte_len)
                .sum::<usize>()
        );
    }
}

#[cfg(test)]
mod native_worker_isolation_tests {
    use super::*;
    use synergy_posy::ValidatorStatus;
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn historical_lookup_crosses_multiple_signed_predecessors_without_relabeling_processing() {
        let provider = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::apqe_provider::load_selected(&provider).unwrap();
        let records = (0..5)
            .map(|index| {
                (
                    ValidatorRecord {
                        validator_id: format!("history-{index}"),
                        consensus_key_id: format!("history-key-{index}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    vec![1; 32],
                )
            })
            .collect();
        let oldest = qualification_authority_with_provider(records, Some(engine));
        let mut middle = oldest.as_ref().clone();
        middle.epoch.epoch = 2;
        middle.epoch.epoch_start_height = 10001;
        middle.epoch.epoch_end_height = 11000;
        middle.timeout_predecessor = Some(oldest.clone());
        let middle = Arc::new(middle);
        let mut current = middle.as_ref().clone();
        current.epoch.epoch = 3;
        current.epoch.epoch_start_height = 11001;
        current.epoch.epoch_end_height = 12000;
        current.timeout_predecessor = Some(middle);
        let current = Arc::new(current);
        assert_eq!(
            current.authenticated_history_at(9999).unwrap().epoch.epoch,
            1
        );
        assert_eq!(
            current
                .authenticated_history_ref_at(10000)
                .unwrap()
                .epoch
                .epoch,
            1
        );
        assert_eq!(
            current
                .authenticated_history_ref_at(10001)
                .unwrap()
                .epoch
                .epoch,
            2
        );
        assert_eq!(
            current
                .authenticated_history_ref_at(11001)
                .unwrap()
                .epoch
                .epoch,
            3
        );
        assert!(current.authenticated_history_at(0).is_none());
        assert!(current.authenticated_history_at(12001).is_none());
        assert!(current.autonomous_authority_at(9999).is_none());
        assert_eq!(current.autonomous_processing_origin().epoch.epoch, 3);
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_execution_sync_and_ingress_history_verify_with_parent_provider_held() {
        use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
        use synergy_posy::{
            block_vote_signing_bytes, BlockVote, ConsensusObjectContext,
            SimplifiedQuorumCertificate, ThreeQcFinality, VerifiedQuorumCertificateStore,
        };
        let selected = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::apqe_provider::load_selected(&selected).unwrap();
        let pair = engine
            .lock()
            .unwrap()
            .generate_keypair(Algorithm::MlDsa65)
            .unwrap();
        let entries = (0..5)
            .map(|index| {
                (
                    ValidatorRecord {
                        validator_id: format!("history-validator-{index}"),
                        consensus_key_id: format!("history-key-{index}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    pair.public_key.clone(),
                )
            })
            .collect();
        let mut parent = qualification_authority_with_provider(entries, Some(engine.clone()))
            .as_ref()
            .clone();
        parent.provider_configuration = Some(selected);
        let parent = Arc::new(parent);
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let cleanup = Cleanup(std::env::temp_dir().join(
            format!("apqe-native-history-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()),
        ));
        std::fs::create_dir(&cleanup.0).unwrap();
        let store = VerifiedQuorumCertificateStore::new(&cleanup.0).unwrap();
        let mut finality = ThreeQcFinality::default();
        let mut previous = parent.anchor_parent.clone();
        let mut certificates = Vec::new();
        for height in 1..=3 {
            let votes = (0..4)
                .map(|index| {
                    let mut vote = BlockVote {
                        context: ConsensusObjectContext::for_height(&parent.epoch, height, 0)
                            .unwrap(),
                        block_id: format!("history-block-{height}"),
                        parent_block_id: previous.block_id().into(),
                        parent: previous.clone(),
                        takeover_tc_id: None,
                        protected_execution_root: "e".repeat(64),
                        validator_id: format!("history-validator-{index}"),
                        key_id: format!("history-key-{index}"),
                        signature: Vec::new(),
                    };
                    vote.signature = engine
                        .lock()
                        .unwrap()
                        .sign(
                            Algorithm::MlDsa65,
                            pair.private_key.as_bytes(),
                            &block_vote_signing_bytes(&vote).unwrap(),
                            SignOptions::default(),
                        )
                        .unwrap();
                    vote
                })
                .collect();
            let qc = SimplifiedQuorumCertificate::from_votes(votes).unwrap();
            store
                .put_verified(&qc, &parent.epoch, &parent.registry, parent.as_ref())
                .unwrap();
            previous = SimplifiedFinalityParent::QuorumCertificate {
                height,
                block_id: qc.block_id.clone(),
                qc_id: qc.id().unwrap(),
            };
            finality.accept(qc.clone()).unwrap();
            certificates.push(qc);
        }
        let expected = finality.last_finalized().unwrap().clone();
        synergy_posy::persistence::FinalityStore::new(&cleanup.0)
            .unwrap()
            .commit_exactly_once(&expected, None)
            .unwrap();
        // Fresh authority cache proves success cannot come from cached parent verification.
        let parent = Arc::new(parent.as_ref().clone());
        let ingress = super::super::ingress::AuthenticatedIngress::default();
        ingress
            .install_finality_history(cleanup.0.clone(), parent.clone())
            .unwrap();
        let held = engine.lock().unwrap();
        assert!(certificates[0]
            .verify(&parent.epoch, &parent.registry, parent.as_ref())
            .unwrap_err()
            .to_string()
            .contains("provider busy"));
        let timeout_store = synergy_posy::VerifiedTimeoutCertificateStore::new(&cleanup.0).unwrap();
        let worker = std::thread::spawn(move || {
            let sync =
                super::super::execution::load_sync_witness(&parent, &store, &timeout_store, 1)
                    .unwrap();
            assert_eq!(sync.quorum_certificates.as_slice(), certificates.as_slice());
            assert!(sync.timeout_certificates.is_empty());
            assert_eq!(ingress.finalized_record(1).unwrap(), Some(expected.clone()));
            let (record, witness) = ingress.finalized_record_with_witness(1).unwrap().unwrap();
            assert_eq!(record, expected);
            assert_eq!(witness.as_slice(), certificates.as_slice());
        });
        worker.join().unwrap();
        drop(held);
    }
    #[test]
    #[ignore = "requires explicitly authenticated immutable APQE native artifacts"]
    fn native_worker_crypto_context_is_independent_of_held_parent_provider() {
        use synergy_address_engine::{apqe::provider::SignOptions, types::Algorithm};
        let selected = synergy_config::ApqeProviderConfiguration {
            report_path: std::env::var("APQE_TRUSTED_NATIVE_REPORT").unwrap().into(),
            authenticated_report_sha256: std::env::var("APQE_AUTHENTICATED_REPORT_SHA256").unwrap(),
        };
        let engine = super::super::apqe_provider::load_selected(&selected).unwrap();
        let message = b"unchanged worker verification preimage";
        let mut proofs = Vec::new();
        {
            let engine = engine.lock().unwrap();
            for algorithm in [Algorithm::MlDsa65, Algorithm::MlDsa87, Algorithm::FnDsa1024] {
                let pair = engine.generate_keypair(algorithm).unwrap();
                let signature = engine
                    .sign(
                        algorithm,
                        pair.private_key.as_bytes(),
                        message,
                        SignOptions::default(),
                    )
                    .unwrap();
                proofs.push((pair.public_key, signature));
            }
        }
        let entries = (0..5)
            .map(|index| {
                (
                    ValidatorRecord {
                        validator_id: format!("worker-isolation-{index}"),
                        consensus_key_id: format!("worker-key-{index}"),
                        frozen_voting_weight: 1,
                        status: ValidatorStatus::Active,
                    },
                    proofs[0].0.clone(),
                )
            })
            .collect();
        let mut parent = qualification_authority_with_provider(entries, Some(engine.clone()))
            .as_ref()
            .clone();
        let policy = |algorithm| AegisPolicy {
            allowed_algorithms: vec![algorithm],
            maximum_message_bytes: MAX_CONSENSUS_MESSAGE_BYTES,
            maximum_signature_bytes: 16 * 1024,
        };
        parent.verifier =
            PqvmVerifier::with_apqe(policy(SignatureAlgorithm::MlDsa65), engine.clone()).unwrap();
        parent.wallet_verifier =
            PqvmVerifier::with_apqe(policy(SignatureAlgorithm::MlDsa87), engine.clone()).unwrap();
        parent.identity_verifier =
            Some(synergy_aegis::ApqeIdentityVerifier::new(engine.clone()).unwrap());
        parent.provider_configuration = Some(selected);
        let parent = Arc::new(parent);
        let held = engine.lock().unwrap();
        assert!(
            matches!(
                EtdagSignatureVerifier::verify(
                    parent.as_ref(),
                    "worker-isolation-0",
                    "worker-key-0",
                    message,
                    &proofs[0].1
                ),
                Err(EtdagError::CryptoProvider(_))
            ),
            "busy parent provider is operational failure, never invalid authority"
        );
        // Registrations share a supervisor thread: uncached owners must still
        // differ from one another and the preparation-thread cache.
        let owners = (0..3)
            .map(|_| VerifiedAuthority::owner_context(&parent).unwrap())
            .collect::<Vec<_>>();
        for (i, owner) in owners.iter().enumerate() {
            assert!(!Arc::ptr_eq(owner, &parent));
            for sibling in owners.iter().skip(i + 1) {
                assert!(!Arc::ptr_eq(owner, sibling));
            }
        }
        std::thread::scope(|scope| {
            for owner in &owners {
                let proofs = &proofs;
                scope.spawn(move || {
                    let context = SigningContext {
                        domain: "owner-isolation".into(),
                        chain_id: 1266,
                        epoch: None,
                        height: None,
                    };
                    for _ in 0..16 {
                        EtdagSignatureVerifier::verify(
                            owner.as_ref(),
                            "worker-isolation-0",
                            "worker-key-0",
                            message,
                            &proofs[0].1,
                        )
                        .unwrap();
                        owner
                            .wallet_verifier()
                            .verify(
                                &context,
                                message,
                                &Signature {
                                    algorithm: SignatureAlgorithm::MlDsa87,
                                    key_id: KeyId::new("owner-key").unwrap(),
                                    bytes: proofs[1].1.clone(),
                                },
                                &proofs[1].0,
                            )
                            .unwrap();
                        owner
                            .identity_verifier()
                            .unwrap()
                            .verify("FN-DSA-1024", &proofs[2].0, message, &proofs[2].1)
                            .unwrap();
                    }
                });
            }
        });
        let worker = std::thread::spawn(move || {
            let worker = VerifiedAuthority::worker_context(&parent).unwrap();
            // This is the same per-owner context used before ETDAG startup.
            EtdagSignatureVerifier::verify(
                worker.as_ref(),
                "worker-isolation-0",
                "worker-key-0",
                message,
                &proofs[0].1,
            )
            .unwrap();
            let mut altered = proofs[0].1.clone();
            altered[0] ^= 1;
            assert_eq!(
                EtdagSignatureVerifier::verify(
                    worker.as_ref(),
                    "worker-isolation-0",
                    "worker-key-0",
                    message,
                    &altered
                ),
                Err(EtdagError::InvalidSignature)
            );
            assert_eq!(
                worker.consensus_signature_cache_stats().0,
                1,
                "only the successful exact primitive may enter the cache"
            );
            assert!(!Arc::ptr_eq(&worker, &parent));
            assert!(Arc::ptr_eq(
                &worker,
                &VerifiedAuthority::worker_context(&parent).unwrap()
            ));
            let context = SigningContext {
                domain: "worker-isolation".into(),
                chain_id: 1266,
                epoch: None,
                height: None,
            };
            for (algorithm, (public, signature)) in
                [SignatureAlgorithm::MlDsa65, SignatureAlgorithm::MlDsa87]
                    .into_iter()
                    .zip(&proofs)
            {
                let signature = Signature {
                    algorithm,
                    key_id: KeyId::new("presented-worker-key").unwrap(),
                    bytes: signature.clone(),
                };
                if algorithm == SignatureAlgorithm::MlDsa65 {
                    AegisVerifier::verify(worker.as_ref(), &context, message, &signature, public)
                        .unwrap();
                } else {
                    worker
                        .wallet_verifier()
                        .verify(&context, message, &signature, public)
                        .unwrap();
                }
            }
            worker
                .identity_verifier()
                .unwrap()
                .verify("FN-DSA-1024", &proofs[2].0, message, &proofs[2].1)
                .unwrap();
            let old_context = Arc::downgrade(&worker);
            let old_source = Arc::downgrade(&parent);
            let replacement = Arc::new(parent.as_ref().clone());
            let replaced = VerifiedAuthority::worker_context(&replacement).unwrap();
            assert!(!Arc::ptr_eq(&worker, &replaced));
            drop(worker);
            assert!(
                old_context.upgrade().is_none(),
                "cache retained obsolete worker context"
            );
            drop(parent);
            assert!(
                old_source.upgrade().is_none(),
                "worker cache retained parent authority"
            );
        });
        worker.join().unwrap();
        drop(held);
    }
}
