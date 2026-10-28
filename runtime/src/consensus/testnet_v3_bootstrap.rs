//! Canonical Testnet-v3 Genesis bindings for the typed PoSy coordinator.
//!
//! This module is intentionally a read-only adapter.  It never creates an
//! identity, key, validator, cluster, or lifecycle record.  Instead it turns
//! the integrity-checked Genesis public records into the exact typed inputs
//! consumed by PoSy and Aegis PQVM.  A missing or malformed binding prevents
//! coordinator startup.

use crate::consensus::posy::LocalConsensusContext;
use crate::crypto::aegis_pqvm::{
    AegisPqKeyLifecycleRecord, AegisPqvmKeyRegistry, AegisPqvmVerifier,
};
use crate::crypto::pqc::{PQCAlgorithm, PQCPublicKey};
use crate::etdag::{
    protected_reveal_transcript_root, DeterministicProtectedBatch,
    DeterministicProtectedExecutionInput, EtdagDigest, NextProtectedBatchCommitment,
    ProtectedBatchSource, ProtectedExecutionTargetContext, ProtectedRevealShareMessage,
    DOMAIN_PROTECTED_ORDER_ROOT, ETDAG_PROFILE_ID, PROTECTED_PIPELINE_VERSION,
};
use crate::genesis::GenesisDocument;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, ClusterId, ClusterMap, Epoch, Hash, Height,
    HeightConsensusContext, HeightConsensusContextSpec, ProtocolConfig, Round, UmaId, ValidatorId,
    ValidatorRecord, ValidatorSet, ValidatorStatus, POSY_PROTOCOL_VERSION,
    TESTNET_V3_CLUSTER_SCHEDULE_VERSION, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const GENESIS_EPOCH_SEED_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_EPOCH_SEED_V1";
const GENESIS_TRANSITION_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_TRANSITION_ROOT_V1";
const GENESIS_CRYPTO_PROFILE_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_CRYPTO_PROFILE_V1";
const GENESIS_HEIGHT_SCHEDULE_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_HEIGHT_SCHEDULE_V1";
const TRANSITION_HEIGHT_SCHEDULE_DOMAIN: &str =
    "SYNERGY_TESTNET_V3_FINALIZED_TRANSITION_HEIGHT_SCHEDULE_V1";
const GENESIS_EMPTY_PROTECTED_CUT_DOMAIN: &str =
    "PoSy/ProtectedPipeline/GenesisBootstrap/EmptyCut/v1";
const GENESIS_EMPTY_ELIGIBLE_SET_DOMAIN: &str =
    "PoSy/ProtectedPipeline/GenesisBootstrap/EligibleSet/v1";
const GENESIS_EMPTY_ORDER_SEED_DOMAIN: &str =
    "PoSy/ProtectedPipeline/GenesisBootstrap/OrderSeed/v1";
const GENESIS_BOOTSTRAP_H2_PRIOR_AUTHORITY_DOMAIN: &str =
    "PoSy/ProtectedPipeline/GenesisBootstrap/H2PriorAuthority/v1";
pub const PROTECTED_PIPELINE_LOOKAHEAD_HEIGHTS: u64 = 3;
pub const GENESIS_BOOTSTRAP_FIRST_HEIGHT: Height = Height(1);
pub const GENESIS_BOOTSTRAP_LAST_HEIGHT: Height = Height(2);
pub const FIRST_NORMAL_ETDAG_HEIGHT: Height = Height(3);
pub const FIRST_STEADY_STATE_ETDAG_HEIGHT: Height = Height(4);
const INITIAL_ACTIVE_VALIDATOR_IDS: [&str; 5] = [
    "validator-02",
    "validator-03",
    "validator-04",
    "validator-05",
    "validator-06",
];

/// Fully public, integrity-bound starting inputs for the typed PoSy runtime.
#[derive(Debug, Clone)]
pub struct TestnetV3GenesisBootstrap {
    /// Includes the five active Genesis validators and the sixteen explicitly
    /// preconfigured-but-pending validators.  Pending records cannot vote or
    /// join a cluster until an authenticated activation transition changes
    /// their status.
    pub validator_set: ValidatorSet,
    /// The deterministic epoch-zero assignment for the five active validators.
    pub cluster_map: ClusterMap,
    /// Verification-only Aegis registry for the active consensus keys.
    pub verifier: AegisPqvmVerifier,
    pub finalized_epoch_seed_root: Hash,
    pub genesis_transition_root: Hash,
    pub cryptographic_profile_root: Hash,
}

/// Deterministic candidate topology for an authenticated epoch transition.
///
/// This type deliberately contains no signature or authority claim.  The
/// typed coordinator must first verify the transition with the current active
/// validators' `EpochTransition` keys, then bind these exact roots into the
/// next height context before installing it.
#[derive(Debug, Clone)]
pub struct TestnetV3ActivationPlan {
    pub validator_set: ValidatorSet,
    pub cluster_map: ClusterMap,
}

/// Canonical protected material for the minimal pre-window bootstrap. Both
/// values are derived together so a caller cannot accidentally commit a batch
/// assembled from different Genesis or protocol bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisBootstrapProtectedMaterial {
    pub source: ProtectedBatchSource,
    pub protected_batch: DeterministicProtectedBatch,
    pub next_commitment: NextProtectedBatchCommitment,
    pub execution_input: DeterministicProtectedExecutionInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GenesisEmptyProtectedBindings {
    binding_version: u32,
    genesis_anchor: Hash,
    genesis_transition_root: Hash,
    cryptographic_profile_root: Hash,
    chain_id: crate::synergy_types::ChainId,
    network_id: crate::synergy_types::NetworkId,
    protocol_version: String,
    protected_pipeline_version: u32,
    etdag_profile_id: String,
    epoch: Epoch,
    target_height: Height,
    cluster_id: ClusterId,
    target_context_root: Hash,
    validator_set_commitment: Hash,
    parameter_root: crate::consensus_parameters::ConsensusParameterRoot,
}

/// Returns the only protected-batch source permitted at a target height.
/// Height zero is Genesis itself and therefore has no protected batch.
pub fn protected_batch_source_for_height(
    target_height: Height,
) -> Result<ProtectedBatchSource, String> {
    match target_height {
        GENESIS_BOOTSTRAP_FIRST_HEIGHT | GENESIS_BOOTSTRAP_LAST_HEIGHT => {
            Ok(ProtectedBatchSource::GenesisBootstrap)
        }
        FIRST_NORMAL_ETDAG_HEIGHT => Ok(ProtectedBatchSource::NormalEtdag),
        height if height.0 >= FIRST_STEADY_STATE_ETDAG_HEIGHT.0 => {
            Ok(ProtectedBatchSource::NormalEtdagSteadyState)
        }
        _ => Err("Genesis height zero has no protected batch source".to_string()),
    }
}

/// Enforces the protocol's exact, rather than minimum, protected-pipeline
/// look-ahead. A runtime configured for H+2 or H+4 is a different protocol and
/// must fail closed.
pub fn require_exact_protected_pipeline_lookahead(lookahead: u64) -> Result<(), String> {
    if lookahead == PROTECTED_PIPELINE_LOOKAHEAD_HEIGHTS {
        Ok(())
    } else {
        Err(format!(
            "protected pipeline look-ahead must be exactly H+{}; found H+{}",
            PROTECTED_PIPELINE_LOOKAHEAD_HEIGHTS, lookahead
        ))
    }
}

/// Maps a finalized source boundary H to the normal ETDAG target H+3.
pub fn normal_etdag_target_height(source_finalized_height: Height) -> Result<Height, String> {
    let target = source_finalized_height
        .0
        .checked_add(PROTECTED_PIPELINE_LOOKAHEAD_HEIGHTS)
        .ok_or_else(|| "protected pipeline H+3 target height overflow".to_string())?;
    Ok(Height(target))
}

/// Returns the finalized source boundary for a normal ETDAG target. H1 and H2
/// deliberately have no pre-Genesis source boundary and must use bootstrap.
pub fn normal_etdag_source_finalized_height(target_height: Height) -> Result<Height, String> {
    if target_height.0 < FIRST_NORMAL_ETDAG_HEIGHT.0 {
        return Err(format!(
            "target H{} is Genesis bootstrap and has no H-3 finalized source boundary",
            target_height.0
        ));
    }
    Ok(Height(
        target_height.0 - PROTECTED_PIPELINE_LOOKAHEAD_HEIGHTS,
    ))
}

impl TestnetV3GenesisBootstrap {
    /// Derives the canonical immutable H1/H2 context used by the Genesis
    /// protected pipeline. Neither height waits for a live PoSy QC: H1 is
    /// bound to the finalized Genesis transition, while H2 uses a distinct
    /// deterministic authority derived from that same Genesis anchor.
    pub fn derive_genesis_bootstrap_height_context(
        &self,
        protocol_config: &ProtocolConfig,
        genesis_anchor: Hash,
        height: Height,
    ) -> Result<HeightConsensusContext, String> {
        self.derive_genesis_bootstrap_height_context_from_parameter_root(
            protocol_config.hash()?,
            genesis_anchor,
            height,
        )
    }

    /// Production bootstrap variant: the immutable parameter root is read
    /// from verified Genesis, rather than reconstructed through a mutable
    /// runtime configuration.  The resulting H1/H2 context is otherwise
    /// byte-for-byte the same derivation as the test/config path above.
    pub fn derive_genesis_bootstrap_height_context_from_parameter_root(
        &self,
        consensus_parameter_root: crate::consensus_parameters::ConsensusParameterRoot,
        genesis_anchor: Hash,
        height: Height,
    ) -> Result<HeightConsensusContext, String> {
        if genesis_anchor.is_zero() {
            return Err("Genesis bootstrap height context requires final Genesis anchor".into());
        }
        if protected_batch_source_for_height(height)? != ProtectedBatchSource::GenesisBootstrap {
            return Err(format!(
                "Genesis bootstrap context is forbidden at H{}; H3+ requires normal ETDAG",
                height.0
            ));
        }
        let prior_finalized_qc_or_transition_root = match height {
            GENESIS_BOOTSTRAP_FIRST_HEIGHT => self.genesis_transition_root,
            GENESIS_BOOTSTRAP_LAST_HEIGHT => Hash::from_domain_bytes(
                GENESIS_BOOTSTRAP_H2_PRIOR_AUTHORITY_DOMAIN,
                &genesis_anchor.0,
            ),
            _ => unreachable!("bootstrap source check already restricts H1/H2"),
        };
        HeightConsensusContext::derive_from_finalized_parameter_root(
            HeightConsensusContextSpec {
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height,
                epoch: Epoch(0),
                assigned_cluster_id: ClusterId(0),
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: self.finalized_epoch_seed_root,
                assigned_height_schedule_root: self.assigned_height_schedule_root(height.0),
                cryptographic_profile_root: self.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root,
            },
            &self.validator_set,
            &self.cluster_map,
            consensus_parameter_root,
        )
    }

    /// Returns a distinct schedule root for a height derived solely from the
    /// finalized Genesis commitment.  It is not an imported snapshot.
    pub fn assigned_height_schedule_root(&self, height: u64) -> Hash {
        let mut material = Vec::with_capacity(40);
        material.extend_from_slice(&self.genesis_transition_root.0);
        material.extend_from_slice(&height.to_be_bytes());
        Hash::from_domain_bytes(GENESIS_HEIGHT_SCHEDULE_DOMAIN, &material)
    }

    /// Returns the unique height schedule commitment after a verified epoch
    /// transition.  Genesis keeps its historical domain separation; every
    /// later epoch binds its height schedule to the signed transition root so
    /// a peer cannot reuse a Genesis schedule under a changed topology.
    pub fn assigned_height_schedule_root_from_transition(
        &self,
        transition_root: Hash,
        height: u64,
    ) -> Result<Hash, String> {
        if transition_root.is_zero() {
            return Err("verified epoch transition root is missing".to_string());
        }
        if height == 0 {
            return Err("height schedule cannot target genesis height zero".to_string());
        }
        let mut material = Vec::with_capacity(40);
        material.extend_from_slice(&transition_root.0);
        material.extend_from_slice(&height.to_be_bytes());
        Ok(Hash::from_domain_bytes(
            TRANSITION_HEIGHT_SCHEDULE_DOMAIN,
            &material,
        ))
    }

    /// Derives the protocol-defined empty protected batch and the exact parent
    /// commitment for H1 or H2. No cutoff, DCC, BVC, BOC, pre-Genesis traffic,
    /// or locally selected fallback participates in this derivation.
    ///
    /// The result is bound to the deployed Genesis anchor, the immutable
    /// Genesis transition and cryptographic profile, the complete target
    /// context, the active validator set, and the frozen parameter root. H3 and
    /// every later height are rejected: absence of normal ETDAG material there
    /// is a hard not-ready condition.
    pub fn derive_genesis_bootstrap_protected_material(
        &self,
        protocol_config: &ProtocolConfig,
        genesis_anchor: Hash,
        target_context: &HeightConsensusContext,
    ) -> Result<GenesisBootstrapProtectedMaterial, String> {
        if genesis_anchor.is_zero() {
            return Err("Genesis bootstrap protected batch requires final Genesis anchor".into());
        }
        target_context.validate_against(&self.validator_set, &self.cluster_map, protocol_config)?;
        if target_context.epoch != Epoch(0) {
            return Err("Genesis bootstrap protected batch requires epoch zero".to_string());
        }
        let source = protected_batch_source_for_height(target_context.height)?;
        if source != ProtectedBatchSource::GenesisBootstrap {
            return Err(format!(
                "Genesis bootstrap protected batch is forbidden at H{}; H3+ requires normal ETDAG",
                target_context.height.0
            ));
        }

        let target_context_root = target_context.root()?;
        let bindings = GenesisEmptyProtectedBindings {
            binding_version: 1,
            genesis_anchor,
            genesis_transition_root: self.genesis_transition_root,
            cryptographic_profile_root: self.cryptographic_profile_root,
            chain_id: target_context.chain_id,
            network_id: target_context.network_id.clone(),
            protocol_version: target_context.protocol_version.clone(),
            protected_pipeline_version: PROTECTED_PIPELINE_VERSION,
            etdag_profile_id: ETDAG_PROFILE_ID.to_string(),
            epoch: target_context.epoch,
            target_height: target_context.height,
            cluster_id: target_context.assigned_cluster_id,
            target_context_root,
            validator_set_commitment: target_context.active_validator_set_root,
            parameter_root: target_context.consensus_parameter_root,
        };

        let cut_root = EtdagDigest::from_canonical(GENESIS_EMPTY_PROTECTED_CUT_DOMAIN, &bindings)?;
        let eligible_set_root =
            EtdagDigest::from_canonical(GENESIS_EMPTY_ELIGIBLE_SET_DOMAIN, &bindings)?;
        let order_seed = EtdagDigest::from_canonical(GENESIS_EMPTY_ORDER_SEED_DOMAIN, &bindings)?;
        let ordered_transaction_ids = Vec::<EtdagDigest>::new();
        let order_root =
            EtdagDigest::from_canonical(DOMAIN_PROTECTED_ORDER_ROOT, &ordered_transaction_ids)?;

        let mut protected_batch = DeterministicProtectedBatch {
            batch_version: PROTECTED_PIPELINE_VERSION,
            chain_id: target_context.chain_id,
            network_id: target_context.network_id.clone(),
            protocol_version: target_context.protocol_version.clone(),
            profile_id: ETDAG_PROFILE_ID.to_string(),
            epoch: target_context.epoch,
            target_height: target_context.height,
            cluster_id: target_context.assigned_cluster_id,
            target_context_root,
            validator_set_commitment: target_context.active_validator_set_root,
            parameter_root: target_context.consensus_parameter_root,
            cut_root: cut_root.clone(),
            eligible_set_root: eligible_set_root.clone(),
            order_seed: order_seed.clone(),
            ordered_transaction_ids,
            order_root: order_root.clone(),
            protected_count: 0,
            protected_gas: 0,
            protected_bytes: 0,
            protected_batch_root: EtdagDigest::zero(),
        };
        protected_batch.protected_batch_root = protected_batch.semantic_root()?;
        protected_batch.validate_declared_roots()?;

        let next_commitment = NextProtectedBatchCommitment {
            commitment_version: PROTECTED_PIPELINE_VERSION,
            chain_id: target_context.chain_id,
            network_id: target_context.network_id.clone(),
            protocol_version: target_context.protocol_version.clone(),
            epoch: target_context.epoch,
            target_height: target_context.height,
            cluster_id: target_context.assigned_cluster_id,
            target_context_root,
            validator_set_commitment: target_context.active_validator_set_root,
            parameter_root: target_context.consensus_parameter_root,
            cut_root,
            eligible_set_root,
            order_seed,
            order_root,
            protected_batch_root: protected_batch.protected_batch_root.clone(),
            protected_count: 0,
            protected_gas: 0,
            protected_bytes: 0,
        };
        // Force canonical serialization now; consumers receive no material
        // whose commitment cannot itself be rooted.
        next_commitment.root()?;

        let execution_input = DeterministicProtectedExecutionInput {
            material_version: PROTECTED_PIPELINE_VERSION,
            source,
            target_context: ProtectedExecutionTargetContext::GenesisBootstrap {
                height_context: target_context.clone(),
            },
            cut_proof: None,
            protected_batch: protected_batch.clone(),
            next_commitment: next_commitment.clone(),
            reveal_authorization: None,
            envelopes: Default::default(),
            reveal_shares: Default::default(),
            ordered_transactions: Vec::new(),
            reveal_transcript_root: protected_reveal_transcript_root(
                &std::collections::BTreeMap::<EtdagDigest, Vec<ProtectedRevealShareMessage>>::new(),
            )?,
        };
        execution_input.digest()?;

        Ok(GenesisBootstrapProtectedMaterial {
            source,
            protected_batch,
            next_commitment,
            execution_input,
        })
    }

    /// Derives the only valid immutable consensus authority for height one of
    /// a fresh Testnet-v3 chain. Callers supply the final deployed Genesis
    /// state root rather than using artifact-preparation state: a candidate
    /// deployment may never start validator signing.
    pub fn initial_local_consensus_context(
        &self,
        protocol_config: &ProtocolConfig,
        genesis_anchor: Hash,
        deployed_genesis_state_root: Hash,
    ) -> Result<LocalConsensusContext, String> {
        if genesis_anchor.is_zero() || deployed_genesis_state_root.is_zero() {
            return Err(
                "typed PoSy height-one startup requires final Genesis anchor and deployed state root"
                    .to_string(),
            );
        }
        let height_context = HeightConsensusContext::derive(
            HeightConsensusContextSpec {
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height: Height(1),
                epoch: Epoch(0),
                assigned_cluster_id: ClusterId(0),
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: self.finalized_epoch_seed_root,
                assigned_height_schedule_root: self.assigned_height_schedule_root(1),
                cryptographic_profile_root: self.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: self.genesis_transition_root,
            },
            &self.validator_set,
            &self.cluster_map,
            protocol_config,
        )?;
        Ok(LocalConsensusContext {
            height_context,
            latest_finalized_height: Height(0),
            latest_finalized_block_hash: genesis_anchor,
            latest_finalized_state_root: deployed_genesis_state_root,
            latest_finalized_timestamp_ms: 0,
            round: Round(0),
            evidence_root: self.genesis_transition_root,
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        })
    }

    /// Derives the only permissible Testnet-v3 topology after activating a
    /// non-empty subset of the 16 Genesis-preconfigured pending validators.
    /// It cannot add new identities, reactivate an already-active validator,
    /// or alter any public key or voting weight. In particular, activating
    /// five pending validators yields ten active validators and therefore two
    /// dynamically derived clusters.
    pub fn derive_activation_plan(
        &self,
        validator_ids: &[ValidatorId],
        to_epoch: Epoch,
        finalized_epoch_seed_root: Hash,
    ) -> Result<TestnetV3ActivationPlan, String> {
        if to_epoch.0 != self.validator_set.epoch.0.saturating_add(1) {
            return Err("validator activation must advance exactly one epoch".to_string());
        }
        if finalized_epoch_seed_root.is_zero() {
            return Err("validator activation transition epoch seed is missing".to_string());
        }
        if validator_ids.is_empty() {
            return Err(
                "validator activation transition must activate at least one validator".to_string(),
            );
        }
        let requested = validator_ids.iter().cloned().collect::<BTreeSet<_>>();
        if requested.len() != validator_ids.len() {
            return Err(
                "validator activation transition contains duplicate validator IDs".to_string(),
            );
        }

        let mut validators = self.validator_set.validators.clone();
        for validator_id in &requested {
            let validator = validators
                .iter_mut()
                .find(|validator| validator.validator_id == *validator_id)
                .ok_or_else(|| {
                    format!(
                        "validator activation transition references unknown Genesis validator {}",
                        validator_id.0
                    )
                })?;
            if validator.status != ValidatorStatus::PendingActivation {
                return Err(format!(
                    "validator {} is not pending Genesis activation",
                    validator_id.0
                ));
            }
            validator.status = ValidatorStatus::Active;
            validator.activation_epoch = to_epoch;
        }
        let active_set = ValidatorSet {
            epoch: to_epoch,
            validators: validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .cloned()
                .collect(),
        };
        active_set.validate_unique_validator_and_key_ids()?;
        if active_set.validators.len() < 5 {
            return Err(
                "Testnet-v3 activation would violate the five-validator minimum".to_string(),
            );
        }
        let cluster_map =
            ClusterMap::derive_from_finalized_epoch_seed(&active_set, finalized_epoch_seed_root)?;
        for validator in &mut validators {
            if let Some(assignment) = cluster_map
                .assignments
                .iter()
                .find(|assignment| assignment.validator_id == validator.validator_id)
            {
                validator.cluster_id = assignment.cluster_id;
            }
        }
        let validator_set = ValidatorSet {
            epoch: to_epoch,
            validators,
        };
        validator_set.validate_unique_validator_and_key_ids()?;
        let updated_active_set = validator_set.active_for_epoch(to_epoch);
        cluster_map.validate_complete_balanced_assignment(&updated_active_set)?;
        Ok(TestnetV3ActivationPlan {
            validator_set,
            cluster_map,
        })
    }
}

/// Authenticates a typed PoSy transport peer against the finalized validator
/// records.  A valid generic P2P signature is not enough: the peer must prove
/// possession of the exact ML-DSA-65 consensus key assigned to an active
/// validator's operator address.  This function accepts public material only.
pub fn authenticate_active_typed_consensus_peer(
    bootstrap: &TestnetV3GenesisBootstrap,
    validator_operator_address: &str,
    advertised_key_id: &str,
    advertised_algorithm: &str,
    advertised_public_key: &[u8],
) -> Result<ValidatorRecord, String> {
    if !matches!(
        advertised_algorithm.trim(),
        "ML-DSA-65" | "ml-dsa-65" | "mldsa65"
    ) {
        return Err("typed PoSy peer handshake key algorithm must be ML-DSA-65".to_string());
    }
    let operator = validator_operator_address.trim();
    if operator.is_empty() {
        return Err("typed PoSy peer handshake omits validator operator address".to_string());
    }
    let validator = bootstrap
        .validator_set
        .validators
        .iter()
        .find(|validator| validator.validator_uma_id.0 == operator)
        .ok_or_else(|| "typed PoSy peer is not in the finalized validator set".to_string())?;
    if validator.status != ValidatorStatus::Active || validator.activation_epoch != Epoch(0) {
        return Err("typed PoSy peer is not active for the current finalized epoch".to_string());
    }
    if validator.consensus_public_key.key_id.0 != advertised_key_id.trim()
        || validator.consensus_public_key.key_bytes != advertised_public_key
    {
        return Err(
            "typed PoSy peer handshake key does not match the finalized validator consensus key"
                .to_string(),
        );
    }
    Ok(validator.clone())
}

/// The single canonical key-ID derivation used by both the legacy validator
/// private-key loader and the typed PoSy registry.  Keeping this derivation
/// tied to the Genesis operator address avoids mutable, locally generated key
/// identifiers.
pub fn consensus_key_id_for_operator(operator_address: &str) -> Result<AegisPqKeyId, String> {
    let operator_address = operator_address.trim();
    if operator_address.is_empty() {
        return Err("Genesis validator operator_address is empty".to_string());
    }
    Ok(AegisPqKeyId(format!(
        "validator-consensus:{operator_address}"
    )))
}

#[derive(Clone, Copy)]
enum GenesisBootstrapConsensusMode {
    PosyV2_2,
    CoordinatedRoundRobinV1,
    CoordinatedRoundRobinActivationV1,
}

/// Builds the typed-PoSy validator and verifier state directly from the
/// canonical Testnet-v3 Genesis document.
pub fn load_testnet_v3_genesis_bootstrap(
    genesis: &GenesisDocument,
) -> Result<TestnetV3GenesisBootstrap, String> {
    load_genesis_bootstrap(genesis, GenesisBootstrapConsensusMode::PosyV2_2)
}

/// Builds the P1 verifier state from a Genesis binding that explicitly
/// authorizes coordinated round robin. It registers only the proposer role;
/// the P1 verifier has no vote, QC, VC, TC, aggregation, or epoch-transition
/// authority.
pub fn load_coordinated_round_robin_genesis_bootstrap(
    genesis: &GenesisDocument,
) -> Result<TestnetV3GenesisBootstrap, String> {
    load_genesis_bootstrap(
        genesis,
        GenesisBootstrapConsensusMode::CoordinatedRoundRobinV1,
    )
}

/// Builds the P1 verifier from the immutable canonical PoSy Genesis after a
/// separate signed consensus-activation manifest has been verified by the
/// caller. This helper cannot itself authorize a mode switch.
pub fn load_coordinated_round_robin_activation_bootstrap(
    genesis: &GenesisDocument,
) -> Result<TestnetV3GenesisBootstrap, String> {
    load_genesis_bootstrap(
        genesis,
        GenesisBootstrapConsensusMode::CoordinatedRoundRobinActivationV1,
    )
}

fn load_genesis_bootstrap(
    genesis: &GenesisDocument,
    mode: GenesisBootstrapConsensusMode,
) -> Result<TestnetV3GenesisBootstrap, String> {
    if genesis.chain_id() != 1266 {
        return Err(format!(
            "Testnet-v3 Genesis has chain_id {}; expected 1266",
            genesis.chain_id()
        ));
    }
    if genesis.network_id() != 1266 {
        return Err("Testnet-v3 Genesis network binding is invalid".to_string());
    }
    match mode {
        GenesisBootstrapConsensusMode::PosyV2_2
            if genesis.consensus_version() != POSY_PROTOCOL_VERSION =>
        {
            return Err("typed PoSy Genesis consensus binding is invalid".to_string());
        }
        GenesisBootstrapConsensusMode::CoordinatedRoundRobinV1 => {
            let parameters = genesis.consensus_parameters().ok_or_else(|| {
                "coordinated P1 Genesis has no finalized consensus parameter binding".to_string()
            })?;
            parameters.require_coordinated_round_robin_manifest()?;
            if genesis.consensus_version()
                != crate::consensus_parameters::COORDINATED_ROUND_ROBIN_V1_PROTOCOL_VERSION
            {
                return Err("coordinated P1 Genesis consensus binding is invalid".to_string());
            }
        }
        GenesisBootstrapConsensusMode::CoordinatedRoundRobinActivationV1 => {
            if genesis.consensus_version() != POSY_PROTOCOL_VERSION {
                return Err(
                    "coordinated P1 activation requires the immutable canonical PoSy Genesis"
                        .to_string(),
                );
            }
        }
        GenesisBootstrapConsensusMode::PosyV2_2 => {}
    }

    let records = genesis
        .value()
        .get("preconfigured_validators")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "Genesis preconfigured_validators is missing".to_string())?;
    if records.len() != 21 {
        return Err(format!(
            "Testnet-v3 Genesis must contain exactly 21 preconfigured validator records; found {}",
            records.len()
        ));
    }

    let mut validators = records
        .iter()
        .map(parse_genesis_validator_record)
        .collect::<Result<Vec<_>, _>>()?;
    let validator_ids = validators
        .iter()
        .map(|validator| validator.validator_id.0.clone())
        .collect::<BTreeSet<_>>();
    let expected_validator_ids = (1..=21)
        .map(|ordinal| format!("validator-{ordinal:02}"))
        .collect::<BTreeSet<_>>();
    if validator_ids != expected_validator_ids {
        return Err(
            "Testnet-v3 Genesis validator IDs must be exactly validator-01 through validator-21"
                .to_string(),
        );
    }
    let active_validator_ids = validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .map(|validator| validator.validator_id.0.as_str())
        .collect::<BTreeSet<_>>();
    let expected_active_validator_ids = INITIAL_ACTIVE_VALIDATOR_IDS
        .into_iter()
        .collect::<BTreeSet<_>>();
    if active_validator_ids != expected_active_validator_ids {
        return Err(
            "Testnet-v3 Genesis active validator IDs must be exactly validator-02 through validator-06"
                .to_string(),
        );
    }
    let active_count = validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .count();
    if active_count != 5 {
        return Err(format!(
            "Testnet-v3 Genesis must activate exactly five validators; found {active_count}"
        ));
    }
    if validators.len().saturating_sub(active_count) != 16 {
        return Err("Testnet-v3 Genesis must retain sixteen pending validator records".to_string());
    }

    let epoch = Epoch(0);
    let finalized_epoch_seed_root =
        Hash::from_domain_bytes(GENESIS_EPOCH_SEED_DOMAIN, genesis.hash().as_bytes());
    let active_set = ValidatorSet {
        epoch,
        validators: validators
            .iter()
            .filter(|validator| validator.status == ValidatorStatus::Active)
            .cloned()
            .collect(),
    };
    let cluster_map =
        ClusterMap::derive_from_finalized_epoch_seed(&active_set, finalized_epoch_seed_root)?;
    if cluster_map.assignments.len() != 5
        || cluster_map
            .assignments
            .iter()
            .any(|assignment| assignment.cluster_id != ClusterId(0))
    {
        return Err(
            "five-validator Testnet-v3 Genesis must derive exactly one cluster (cluster 0)"
                .to_string(),
        );
    }
    for validator in &mut validators {
        if let Some(assignment) = cluster_map
            .assignments
            .iter()
            .find(|assignment| assignment.validator_id == validator.validator_id)
        {
            validator.cluster_id = assignment.cluster_id;
        }
    }
    let validator_set = ValidatorSet { epoch, validators };
    validator_set.validate_unique_validator_and_key_ids()?;
    cluster_map.validate_complete_balanced_assignment(&active_set)?;

    let mut registry = AegisPqvmKeyRegistry::default();
    for validator in validator_set
        .validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
    {
        let consensus = &validator.consensus_public_key;
        registry
            .register_public_key_with_lifecycle(
                PQCPublicKey {
                    algorithm: PQCAlgorithm::MLDSA65,
                    key_data: consensus.key_bytes.clone(),
                    key_id: consensus.key_id.0.clone(),
                    created_at: 0,
                },
                AegisPqKeyLifecycleRecord {
                    uma_id: validator.validator_uma_id.0.clone(),
                    key_id: consensus.key_id.clone(),
                    roles: match mode {
                        GenesisBootstrapConsensusMode::PosyV2_2 => vec![
                            AegisPqKeyRole::ConsensusProposer,
                            AegisPqKeyRole::ConsensusVote,
                            AegisPqKeyRole::EpochTransition,
                        ],
                        GenesisBootstrapConsensusMode::CoordinatedRoundRobinV1
                        | GenesisBootstrapConsensusMode::CoordinatedRoundRobinActivationV1 => {
                            vec![AegisPqKeyRole::ConsensusProposer]
                        }
                    },
                    active_from_epoch: epoch,
                    active_until_epoch: None,
                    revoked_from_epoch: None,
                },
            )
            .map_err(|error| format!("register Genesis Aegis consensus key: {error}"))?;
    }
    let verifier = AegisPqvmVerifier::initialize_required(registry)
        .map_err(|error| format!("initialize Genesis Aegis verifier: {error}"))?;

    Ok(TestnetV3GenesisBootstrap {
        validator_set,
        cluster_map,
        verifier,
        finalized_epoch_seed_root,
        genesis_transition_root: Hash::from_domain_bytes(
            GENESIS_TRANSITION_DOMAIN,
            genesis.hash().as_bytes(),
        ),
        cryptographic_profile_root: Hash::from_domain_bytes(
            GENESIS_CRYPTO_PROFILE_DOMAIN,
            genesis.hash().as_bytes(),
        ),
    })
}

fn parse_genesis_validator_record(value: &serde_json::Value) -> Result<ValidatorRecord, String> {
    let validator_id = required_string(value, "validator_id")?;
    let operator_address = required_string(value, "operator_address")?;
    let consensus_algorithm = required_string(value, "consensus_key_type")?;
    if !matches!(
        consensus_algorithm.as_str(),
        "ML-DSA-65" | "ml-dsa-65" | "mldsa65"
    ) {
        return Err(format!(
            "Genesis validator {validator_id} consensus_key_type must be ML-DSA-65"
        ));
    }
    let consensus_key = decode_public_key(
        &validator_id,
        "consensus_public_key",
        required_string(value, "consensus_public_key")?,
    )?;
    if consensus_key.len() != TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES {
        return Err(format!(
            "Genesis validator {validator_id} consensus key has {} bytes; expected {}",
            consensus_key.len(),
            TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES
        ));
    }
    let account_key = decode_public_key(
        &validator_id,
        "account_public_key",
        required_string(value, "account_public_key")?,
    )?;
    let node_key = decode_public_key(
        &validator_id,
        "node_identity_key",
        required_string(value, "node_identity_key")?,
    )?;
    let status = match required_string(value, "status")?.as_str() {
        "active_at_genesis" => ValidatorStatus::Active,
        "preconfigured_pending_activation" => ValidatorStatus::PendingActivation,
        other => {
            return Err(format!(
                "Genesis validator {validator_id} has unsupported startup status {other}"
            ))
        }
    };
    let activation_height = value
        .get("activation_height")
        .and_then(serde_json::Value::as_u64);
    if status == ValidatorStatus::Active && activation_height != Some(0) {
        return Err(format!(
            "Genesis active validator {validator_id} must have activation_height 0"
        ));
    }
    if status == ValidatorStatus::PendingActivation && activation_height.is_some() {
        return Err(format!(
            "Genesis pending validator {validator_id} must not have an activation height"
        ));
    }
    let voting_weight = value
        .get("voting_power")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("Genesis validator {validator_id} voting_power is missing"))?;
    if voting_weight == 0 {
        return Err(format!(
            "Genesis validator {validator_id} has zero voting_power"
        ));
    }
    let consensus_key_id = consensus_key_id_for_operator(&operator_address)?;
    Ok(ValidatorRecord {
        validator_id: ValidatorId(validator_id.clone()),
        validator_uma_id: UmaId(operator_address),
        consensus_public_key: AegisPqPublicKey {
            key_id: consensus_key_id,
            algorithm: "mldsa65".to_string(),
            key_bytes: consensus_key,
        },
        peer_public_key: AegisPqPublicKey {
            key_id: AegisPqKeyId(format!(
                "validator-peer:{}",
                required_string(value, "peer_id")?
            )),
            algorithm: canonical_non_consensus_algorithm(required_string(
                value,
                "node_identity_key_type",
            )?)?,
            key_bytes: node_key,
        },
        operator_public_key: AegisPqPublicKey {
            key_id: AegisPqKeyId(format!("validator-operator:{validator_id}")),
            algorithm: canonical_non_consensus_algorithm(required_string(
                value,
                "account_key_type",
            )?)?,
            key_bytes: account_key,
        },
        voting_weight,
        status,
        cluster_id: ClusterId(0),
        activation_epoch: Epoch(0),
    })
}

fn required_string(value: &serde_json::Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .filter(|field| !field.trim().is_empty())
        .ok_or_else(|| format!("Genesis validator field {field} is missing or empty"))
}

fn decode_public_key(validator_id: &str, field: &str, encoded: String) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|error| {
            format!("Genesis validator {validator_id} field {field} is not valid base64: {error}")
        })
}

fn canonical_non_consensus_algorithm(value: String) -> Result<String, String> {
    match value.as_str() {
        "FN-DSA-1024" | "FN-DSA" | "fndsa" => Ok("fndsa".to_string()),
        "ML-DSA-65" | "ml-dsa-65" | "mldsa65" => Ok("mldsa65".to_string()),
        "ML-DSA-87" | "ml-dsa-87" | "mldsa87" => Ok("mldsa87".to_string()),
        "Ed25519" | "ed25519" => Ok("ed25519".to_string()),
        other => Err(format!(
            "Genesis non-consensus Aegis key algorithm {other} is unsupported"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::canonical_genesis;

    fn protected_bootstrap_fixture() -> (TestnetV3GenesisBootstrap, ProtocolConfig, Hash) {
        let genesis = canonical_genesis().expect("load complete fresh P3 test Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("typed Genesis bootstrap");
        let genesis_anchor = Hash::from_hex(genesis.hash()).expect("Genesis anchor");
        (bootstrap, ProtocolConfig::testnet_v3(), genesis_anchor)
    }

    fn target_context(
        bootstrap: &TestnetV3GenesisBootstrap,
        protocol: &ProtocolConfig,
        height: Height,
    ) -> HeightConsensusContext {
        let prior_root = if height == Height(1) {
            bootstrap.genesis_transition_root
        } else {
            Hash::from_domain_bytes(
                "SYNERGY_TESTNET_V3_BOOTSTRAP_TEST_PRIOR_QC",
                &height.0.saturating_sub(1).to_be_bytes(),
            )
        };
        HeightConsensusContext::derive(
            HeightConsensusContextSpec {
                protocol_version: POSY_PROTOCOL_VERSION.to_string(),
                height,
                epoch: Epoch(0),
                assigned_cluster_id: ClusterId(0),
                cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
                finalized_epoch_seed_root: bootstrap.finalized_epoch_seed_root,
                assigned_height_schedule_root: bootstrap.assigned_height_schedule_root(height.0),
                cryptographic_profile_root: bootstrap.cryptographic_profile_root,
                prior_finalized_qc_or_transition_root: prior_root,
            },
            &bootstrap.validator_set,
            &bootstrap.cluster_map,
            protocol,
        )
        .expect("target height context")
    }

    #[test]
    fn identity_assigned_genesis_derives_five_active_validators_one_cluster_and_aegis_registry() {
        let genesis = canonical_genesis().expect("load complete fresh P3 test Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("typed Genesis bootstrap");
        assert_eq!(bootstrap.validator_set.validators.len(), 21);
        assert_eq!(
            bootstrap
                .validator_set
                .validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count(),
            5
        );
        assert_eq!(
            bootstrap
                .validator_set
                .validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .map(|validator| validator.validator_id.0.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(INITIAL_ACTIVE_VALIDATOR_IDS)
        );
        assert_eq!(bootstrap.cluster_map.assignments.len(), 5);
        assert!(bootstrap
            .cluster_map
            .assignments
            .iter()
            .all(|assignment| assignment.cluster_id == ClusterId(0)));
        assert_eq!(bootstrap.verifier.registry.lifecycle.records.len(), 5);
        assert!(bootstrap
            .verifier
            .registry
            .lifecycle
            .records
            .iter()
            .all(|record| { record.roles.contains(&AegisPqKeyRole::EpochTransition) }));
        assert_ne!(bootstrap.assigned_height_schedule_root(1), Hash::zero());
    }

    #[test]
    fn activating_five_pending_validators_derives_the_second_dynamic_cluster() {
        let genesis = canonical_genesis().expect("load complete fresh P3 test Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("typed Genesis bootstrap");
        let activated = bootstrap
            .validator_set
            .validators
            .iter()
            .filter(|validator| validator.status == ValidatorStatus::PendingActivation)
            .take(5)
            .map(|validator| validator.validator_id.clone())
            .collect::<Vec<_>>();
        let plan = bootstrap
            .derive_activation_plan(
                &activated,
                Epoch(1),
                Hash::from_domain_bytes("SYNERGY_TESTNET_V3_TEST_EPOCH_SEED", b"epoch-1"),
            )
            .expect("activation plan");
        assert_eq!(
            plan.validator_set
                .validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count(),
            10
        );
        assert_eq!(plan.cluster_map.assignments.len(), 10);
        assert_eq!(
            plan.cluster_map
                .assignments
                .iter()
                .map(|assignment| assignment.cluster_id)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([ClusterId(0), ClusterId(1)])
        );
    }

    #[test]
    fn active_typed_peer_must_prove_the_exact_genesis_consensus_key() {
        let genesis = canonical_genesis().expect("load complete fresh P3 test Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("typed Genesis bootstrap");
        let active = bootstrap
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.status == ValidatorStatus::Active)
            .expect("active Genesis validator");
        let authenticated = authenticate_active_typed_consensus_peer(
            &bootstrap,
            &active.validator_uma_id.0,
            &active.consensus_public_key.key_id.0,
            "ML-DSA-65",
            &active.consensus_public_key.key_bytes,
        )
        .expect("exact active consensus key must authenticate");
        assert_eq!(authenticated.validator_id, active.validator_id);

        let error = authenticate_active_typed_consensus_peer(
            &bootstrap,
            &active.validator_uma_id.0,
            "other-key",
            "ML-DSA-65",
            &active.consensus_public_key.key_bytes,
        )
        .expect_err("substituted key identity must fail");
        assert!(error.contains("does not match"));
        let pending = bootstrap
            .validator_set
            .validators
            .iter()
            .find(|validator| validator.status == ValidatorStatus::PendingActivation)
            .expect("pending Genesis validator");
        assert!(authenticate_active_typed_consensus_peer(
            &bootstrap,
            &pending.validator_uma_id.0,
            &pending.consensus_public_key.key_id.0,
            "mldsa65",
            &pending.consensus_public_key.key_bytes,
        )
        .is_err());
    }

    #[test]
    fn height_one_context_requires_final_genesis_anchor_and_deployed_state() {
        let genesis = canonical_genesis().expect("load complete fresh P3 test Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(genesis).expect("typed Genesis bootstrap");
        let protocol = ProtocolConfig::testnet_v3();
        let anchor = Hash::from_hex(genesis.hash()).expect("candidate genesis hash");
        let deployed_state = Hash::from_domain_bytes(
            "SYNERGY_TESTNET_V3_TEST_DEPLOYED_GENESIS_STATE",
            b"fully-deployed-test-state",
        );
        let context = bootstrap
            .initial_local_consensus_context(&protocol, anchor, deployed_state)
            .expect("final inputs must derive height one context");
        assert_eq!(context.height_context.height, Height(1));
        assert_eq!(context.height_context.epoch, Epoch(0));
        assert_eq!(context.latest_finalized_height, Height(0));
        assert_eq!(context.latest_finalized_block_hash, anchor);
        assert_eq!(context.latest_finalized_state_root, deployed_state);
        assert_eq!(context.height_context.assigned_cluster_id, ClusterId(0));
        assert_eq!(context.height_context.assigned_cluster_validator_count, 5);
        assert!(bootstrap
            .initial_local_consensus_context(&protocol, Hash::zero(), deployed_state)
            .is_err());
    }

    #[test]
    fn h1_and_h2_empty_material_is_deterministic_bound_and_distinct() {
        let (bootstrap, protocol, genesis_anchor) = protected_bootstrap_fixture();
        let h1_context = target_context(&bootstrap, &protocol, Height(1));
        let h2_context = target_context(&bootstrap, &protocol, Height(2));

        let h1 = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &h1_context)
            .expect("H1 Genesis empty protected material");
        let h1_again = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &h1_context)
            .expect("repeat H1 Genesis empty protected material");
        let h2 = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &h2_context)
            .expect("H2 Genesis empty protected material");

        assert_eq!(h1, h1_again);
        for (height, material) in [(Height(1), &h1), (Height(2), &h2)] {
            assert_eq!(material.source, ProtectedBatchSource::GenesisBootstrap);
            assert_eq!(material.protected_batch.target_height, height);
            assert_eq!(
                material.protected_batch.protocol_version,
                POSY_PROTOCOL_VERSION
            );
            assert_eq!(
                material.protected_batch.batch_version,
                PROTECTED_PIPELINE_VERSION
            );
            assert_eq!(material.protected_batch.protected_count, 0);
            assert_eq!(material.protected_batch.protected_gas, 0);
            assert_eq!(material.protected_batch.protected_bytes, 0);
            assert!(material.protected_batch.ordered_transaction_ids.is_empty());
            material
                .protected_batch
                .validate_declared_roots()
                .expect("canonical empty protected batch roots");
            assert_eq!(material.next_commitment.target_height, height);
            assert_eq!(material.next_commitment.protected_count, 0);
            assert_eq!(material.next_commitment.protected_gas, 0);
            assert_eq!(material.next_commitment.protected_bytes, 0);
            assert_eq!(
                material.next_commitment.protected_batch_root,
                material.protected_batch.protected_batch_root
            );
            assert_eq!(
                material.next_commitment.validator_set_commitment,
                material.protected_batch.validator_set_commitment
            );
            assert_eq!(
                material.next_commitment.parameter_root,
                material.protected_batch.parameter_root
            );
            material
                .next_commitment
                .root()
                .expect("canonical next protected batch commitment");
            assert!(material
                .execution_input
                .verify_and_extract_transactions(
                    &bootstrap.verifier,
                    &bootstrap.validator_set,
                    &bootstrap.cluster_map,
                    &crate::etdag::EtdagParameters::default(),
                )
                .expect("canonical H1/H2 protected execution input")
                .is_empty());
        }
        assert_ne!(
            h1.protected_batch.protected_batch_root,
            h2.protected_batch.protected_batch_root
        );
        assert_ne!(
            h1.next_commitment.root().expect("H1 commitment root"),
            h2.next_commitment.root().expect("H2 commitment root")
        );

        let other_anchor = Hash::from_domain_bytes(
            "SYNERGY_TESTNET_V3_OTHER_GENESIS_ANCHOR",
            b"different-genesis",
        );
        let other_genesis = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, other_anchor, &h1_context)
            .expect("same context under a distinct Genesis anchor");
        assert_ne!(
            h1.protected_batch.protected_batch_root,
            other_genesis.protected_batch.protected_batch_root
        );
        assert_ne!(
            h1.next_commitment.root().expect("H1 commitment root"),
            other_genesis
                .next_commitment
                .root()
                .expect("other-Genesis commitment root")
        );
    }

    #[test]
    fn genesis_bootstrap_context_accepts_the_finalized_parameter_root_directly() {
        let (bootstrap, protocol, genesis_anchor) = protected_bootstrap_fixture();
        let through_config = bootstrap
            .derive_genesis_bootstrap_height_context(&protocol, genesis_anchor, Height(1))
            .expect("derive H1 through finalized protocol configuration");
        let through_root = bootstrap
            .derive_genesis_bootstrap_height_context_from_parameter_root(
                protocol.hash().expect("finalized parameter root"),
                genesis_anchor,
                Height(1),
            )
            .expect("derive H1 directly through finalized parameter root");
        assert_eq!(through_root, through_config);
    }

    #[test]
    fn bootstrap_material_binds_parameters_and_validator_set() {
        let (bootstrap, protocol, genesis_anchor) = protected_bootstrap_fixture();
        let context = target_context(&bootstrap, &protocol, Height(1));
        let canonical = bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &context)
            .expect("canonical H1 material");

        let mut changed_protocol = protocol.clone();
        changed_protocol.consensus_parameter_root =
            crate::consensus_parameters::ConsensusParameterRoot::from_canonical_manifest_bytes(
                b"SYNERGY_TESTNET_V3_CHANGED_BOOTSTRAP_PARAMETERS",
            );
        changed_protocol
            .seal_runtime_binding()
            .expect("seal changed test parameters");
        let changed_parameter_context = target_context(&bootstrap, &changed_protocol, Height(1));
        let changed_parameter = bootstrap
            .derive_genesis_bootstrap_protected_material(
                &changed_protocol,
                genesis_anchor,
                &changed_parameter_context,
            )
            .expect("parameter-bound H1 material");
        assert_ne!(
            canonical.protected_batch.protected_batch_root,
            changed_parameter.protected_batch.protected_batch_root
        );

        let mut changed_validator_bootstrap = bootstrap.clone();
        let active = changed_validator_bootstrap
            .validator_set
            .validators
            .iter_mut()
            .find(|validator| validator.status == ValidatorStatus::Active)
            .expect("active Genesis validator");
        active.voting_weight = active.voting_weight.checked_add(1).expect("test weight");
        let changed_validator_context =
            target_context(&changed_validator_bootstrap, &protocol, Height(1));
        let changed_validator = changed_validator_bootstrap
            .derive_genesis_bootstrap_protected_material(
                &protocol,
                genesis_anchor,
                &changed_validator_context,
            )
            .expect("validator-set-bound H1 material");
        assert_ne!(
            canonical.protected_batch.validator_set_commitment,
            changed_validator.protected_batch.validator_set_commitment
        );
        assert_ne!(
            canonical.protected_batch.protected_batch_root,
            changed_validator.protected_batch.protected_batch_root
        );

        assert!(bootstrap
            .derive_genesis_bootstrap_protected_material(
                &changed_protocol,
                genesis_anchor,
                &context,
            )
            .expect_err("mismatched frozen parameter context must fail")
            .contains("parameter"));
        assert!(changed_validator_bootstrap
            .derive_genesis_bootstrap_protected_material(&protocol, genesis_anchor, &context,)
            .expect_err("mismatched validator-set context must fail")
            .contains("validator"));
    }

    #[test]
    fn h1_h2_h3_h4_boundary_and_exact_h_plus_three_are_explicit() {
        let (bootstrap, protocol, genesis_anchor) = protected_bootstrap_fixture();
        let h1 = bootstrap
            .derive_genesis_bootstrap_protected_material(
                &protocol,
                genesis_anchor,
                &target_context(&bootstrap, &protocol, Height(1)),
            )
            .expect("H1 bootstrap");
        let h2 = bootstrap
            .derive_genesis_bootstrap_protected_material(
                &protocol,
                genesis_anchor,
                &target_context(&bootstrap, &protocol, Height(2)),
            )
            .expect("H2 bootstrap");

        assert_eq!(
            protected_batch_source_for_height(Height(1)).expect("H1 source"),
            ProtectedBatchSource::GenesisBootstrap
        );
        assert_eq!(
            protected_batch_source_for_height(Height(2)).expect("H2 source"),
            ProtectedBatchSource::GenesisBootstrap
        );
        assert_eq!(
            protected_batch_source_for_height(Height(3)).expect("H3 source"),
            ProtectedBatchSource::NormalEtdag
        );
        assert_eq!(
            protected_batch_source_for_height(Height(4)).expect("H4 source"),
            ProtectedBatchSource::NormalEtdagSteadyState
        );
        assert!(protected_batch_source_for_height(Height(0)).is_err());

        require_exact_protected_pipeline_lookahead(3).expect("exact H+3 look-ahead");
        assert!(require_exact_protected_pipeline_lookahead(2).is_err());
        assert!(require_exact_protected_pipeline_lookahead(4).is_err());
        assert_eq!(
            normal_etdag_target_height(Height(0)).expect("Genesis -> H3"),
            Height(3)
        );
        assert_eq!(
            normal_etdag_target_height(Height(1)).expect("H1 -> H4"),
            Height(4)
        );
        assert_eq!(
            normal_etdag_source_finalized_height(Height(3)).expect("H3 source"),
            Height(0)
        );
        assert_eq!(
            normal_etdag_source_finalized_height(Height(4)).expect("H4 source"),
            Height(1)
        );
        assert!(normal_etdag_source_finalized_height(Height(1)).is_err());
        assert!(normal_etdag_source_finalized_height(Height(2)).is_err());

        for height in [Height(3), Height(4)] {
            let error = bootstrap
                .derive_genesis_bootstrap_protected_material(
                    &protocol,
                    genesis_anchor,
                    &target_context(&bootstrap, &protocol, height),
                )
                .expect_err("bootstrap must end before H3");
            assert!(error.contains("forbidden"));
            assert!(error.contains("normal ETDAG"));
        }

        println!(
            "H1:\nsource=GENESIS_BOOTSTRAP\nprotected_batch={}\nordinary_user_count=0\nbootstrap_allowed=yes",
            h1.protected_batch.protected_batch_root.0
        );
        println!(
            "H2:\nsource=GENESIS_BOOTSTRAP\nprotected_batch={}\nordinary_user_count=0\nbootstrap_allowed=yes",
            h2.protected_batch.protected_batch_root.0
        );
        println!(
            "H3:\nsource=NORMAL_ETDAG\nsource_finalized_height=H0\nlookahead=H+3\nbootstrap_allowed=no"
        );
        println!(
            "H4:\nsource=NORMAL_ETDAG_STEADY_STATE\nsource_finalized_height=H1\nlookahead=H+3\nbootstrap_allowed=no"
        );
    }
}
