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
use crate::genesis::GenesisDocument;
use crate::synergy_types::{
    AegisPqKeyId, AegisPqKeyRole, AegisPqPublicKey, ClusterId, ClusterMap, Epoch, Hash, Height,
    HeightConsensusContext, HeightConsensusContextSpec, ProtocolConfig, Round, UmaId, ValidatorId,
    ValidatorRecord, ValidatorSet, ValidatorStatus, POSY_PROTOCOL_VERSION,
    TESTNET_V3_CLUSTER_SCHEDULE_VERSION, TESTNET_V3_MLDSA65_PUBLIC_KEY_BYTES,
};
use base64::{engine::general_purpose, Engine as _};
use std::collections::BTreeSet;

const GENESIS_EPOCH_SEED_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_EPOCH_SEED_V1";
const GENESIS_TRANSITION_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_TRANSITION_ROOT_V1";
const GENESIS_CRYPTO_PROFILE_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_CRYPTO_PROFILE_V1";
const GENESIS_HEIGHT_SCHEDULE_DOMAIN: &str = "SYNERGY_TESTNET_V3_GENESIS_HEIGHT_SCHEDULE_V1";

/// Fully public, integrity-bound starting inputs for the typed PoSy runtime.
#[derive(Debug, Clone)]
pub struct TestnetV3GenesisBootstrap {
    /// Includes the six active Genesis validators and the fifteen explicitly
    /// preconfigured-but-pending validators.  Pending records cannot vote or
    /// join a cluster until an authenticated activation transition changes
    /// their status.
    pub validator_set: ValidatorSet,
    /// The deterministic epoch-zero assignment for the six active validators.
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

impl TestnetV3GenesisBootstrap {
    /// Returns a distinct schedule root for a height derived solely from the
    /// finalized Genesis commitment.  It is not an imported snapshot.
    pub fn assigned_height_schedule_root(&self, height: u64) -> Hash {
        let mut material = Vec::with_capacity(40);
        material.extend_from_slice(&self.genesis_transition_root.0);
        material.extend_from_slice(&height.to_be_bytes());
        Hash::from_domain_bytes(GENESIS_HEIGHT_SCHEDULE_DOMAIN, &material)
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
            round: Round(0),
            evidence_root: self.genesis_transition_root,
            app_version: 1,
            execution_version: 1,
            dag_version: 1,
            aegis_pqvm_version: "aegis-pqvm".to_string(),
        })
    }

    /// Derives the only permissible Testnet-v3 topology after activating a
    /// non-empty subset of the 15 Genesis-preconfigured pending validators.
    /// It cannot add new identities, reactivate an already-active validator,
    /// or alter any public key or voting weight.  In particular, activating
    /// validators 7 through 10 yields ten active validators and therefore two
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
        if active_set.validators.len() < 6 {
            return Err(
                "Testnet-v3 activation would violate the six-validator minimum".to_string(),
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

/// Builds the typed validator and verifier state directly from the canonical
/// Testnet-v3 Genesis document.
pub fn load_testnet_v3_genesis_bootstrap(
    genesis: &GenesisDocument,
) -> Result<TestnetV3GenesisBootstrap, String> {
    if genesis.chain_id() != 1266 {
        return Err(format!(
            "typed PoSy Genesis has chain_id {}; expected 1266",
            genesis.chain_id()
        ));
    }
    if genesis.network_id() != 1266 || genesis.consensus_version() != "posy/2.2" {
        return Err("typed PoSy Genesis network/consensus binding is invalid".to_string());
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
    let active_count = validators
        .iter()
        .filter(|validator| validator.status == ValidatorStatus::Active)
        .count();
    if active_count != 6 {
        return Err(format!(
            "Testnet-v3 Genesis must activate exactly six validators; found {active_count}"
        ));
    }
    if validators.len().saturating_sub(active_count) != 15 {
        return Err("Testnet-v3 Genesis must retain fifteen pending validator records".to_string());
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
    if cluster_map.assignments.len() != 6
        || cluster_map
            .assignments
            .iter()
            .any(|assignment| assignment.cluster_id != ClusterId(0))
    {
        return Err(
            "six-validator Testnet-v3 Genesis must derive exactly one cluster (cluster 0)"
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
                    roles: vec![
                        AegisPqKeyRole::ConsensusProposer,
                        AegisPqKeyRole::ConsensusVote,
                        // The already-active Genesis validators, and only
                        // those validators, may authorize an epoch transition
                        // that activates one of the preconfigured records.
                        // Pending validators are deliberately absent from this
                        // verifier lifecycle until that transition succeeds.
                        AegisPqKeyRole::EpochTransition,
                    ],
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
    use crate::genesis::load_genesis_from_path_for_test;
    use std::path::PathBuf;

    #[test]
    fn identity_assigned_genesis_derives_six_active_validators_one_cluster_and_aegis_registry() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("genesis.testnet-v3.identity-assigned.json");
        let genesis =
            load_genesis_from_path_for_test(path).expect("load identity-assigned Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(&genesis).expect("typed Genesis bootstrap");
        assert_eq!(bootstrap.validator_set.validators.len(), 21);
        assert_eq!(
            bootstrap
                .validator_set
                .validators
                .iter()
                .filter(|validator| validator.status == ValidatorStatus::Active)
                .count(),
            6
        );
        assert_eq!(bootstrap.cluster_map.assignments.len(), 6);
        assert!(bootstrap
            .cluster_map
            .assignments
            .iter()
            .all(|assignment| assignment.cluster_id == ClusterId(0)));
        assert_eq!(bootstrap.verifier.registry.lifecycle.records.len(), 6);
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
    fn activating_the_tenth_validator_derives_the_second_dynamic_cluster() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("genesis.testnet-v3.identity-assigned.json");
        let genesis =
            load_genesis_from_path_for_test(path).expect("load identity-assigned Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(&genesis).expect("typed Genesis bootstrap");
        let activated = bootstrap
            .validator_set
            .validators
            .iter()
            .filter(|validator| validator.status == ValidatorStatus::PendingActivation)
            .take(4)
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("genesis.testnet-v3.identity-assigned.json");
        let genesis =
            load_genesis_from_path_for_test(path).expect("load identity-assigned Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(&genesis).expect("typed Genesis bootstrap");
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
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("genesis.testnet-v3.identity-assigned.json");
        let genesis =
            load_genesis_from_path_for_test(path).expect("load identity-assigned Genesis");
        let bootstrap =
            load_testnet_v3_genesis_bootstrap(&genesis).expect("typed Genesis bootstrap");
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
        assert_eq!(context.height_context.assigned_cluster_validator_count, 6);
        assert!(bootstrap
            .initial_local_consensus_context(&protocol, Hash::zero(), deployed_state)
            .is_err());
    }
}
