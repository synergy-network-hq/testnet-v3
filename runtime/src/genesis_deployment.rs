//! Atomic Testnet-v3 genesis system deployment.
//!
//! There is exactly one deployment algorithm on this chain and this module does
//! not add a second. Every cryptographic and state-mutating step below is the
//! production path: `pqsynq` builds and verifies the deploy/call envelopes,
//! `synq_admission` applies the chain admission and manifest/ABI security
//! policy, `synq_execution` derives the contract address and drives AIVM
//! execution. What genesis adds is orchestration only — a fixed plan, fixed
//! nonces, no mempool, no fee requirement, an all-or-nothing overlay, and a
//! deployer that is retired in protocol state when it is done.

use crate::execution::{compute_state_root_after, ExecutionState};
use crate::synergy_types::{
    AegisPqKeyId, AegisPqSignature, ChainId, Epoch, Hash, Height, NetworkId, Transaction, TxId,
    UmaId, SYNERGY_TESTNET_V3_CHAIN_ID,
};
use crate::synq_admission::{
    build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_constructor_args_and_identity_authorization,
    encode_synq_admission_carrier, verify_synq_call_for_chain_admission_at_current_binding,
    verify_synq_deploy_for_chain_admission_at_current_binding, SynQAdmissionEnvelope,
    SynQAdmissionKind, SYNQ_ADMISSION_VERSION, SYNQ_CALL_AUTHORIZATION_PURPOSE,
    SYNQ_CANONICAL_TESTNET_NETWORK_ID, SYNQ_DEPLOY_AUTHORIZATION_PURPOSE,
};
use crate::synq_execution::{
    execute_synq_transaction_at, SynQAivmReceiptSummary, SynQContractArtifact, SynQExecutionContext,
};
use aivm_core::state::StateKey;
use pqsynq::{
    canonicalize_signing_payload, derive_synq_address, hash_contract_call_body,
    hash_contract_deploy_body, AlgorithmId, ChainId as SynQChainId, ContractCallEnvelope,
    ContractDeployEnvelope, DomainTag, NetworkId as SynQNetworkId, Sign, SignaturePurpose,
    SynQAddress, SynQPublicKey, SynQSignature, SynQSigningPayload,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Reserved AIVM namespace recording the genesis deployment authority
/// lifecycle. Retirement is enforced here, in protocol state that is covered by
/// the AIVM state root — never by deleting a key, which is unverifiable.
pub const GENESIS_DEPLOYMENT_NAMESPACE: &[u8] = b"__synergy_genesis_deployment_v1";
const LIFECYCLE_KEY: &[u8] = b"authority_lifecycle";
const MANIFEST_KEY: &[u8] = b"deployment_manifest_hash";

/// Genesis executes at height 0 with no fee and no mempool.
const GENESIS_BLOCK_HEIGHT: u64 = 0;
/// Fixed genesis validity anchor. Deployment addresses are time-independent —
/// `not_before_unix` / `expiration_unix` feed neither the payload hash nor the
/// address — but admission still evaluates the window, so it must be fixed for
/// reproducibility rather than read from the wall clock.
pub const GENESIS_NOW_UNIX: u64 = 1_800_000_000;
const GENESIS_EXPIRATION_UNIX: u64 = 4_102_444_800;
const GENESIS_PROTOCOL_VERSION: u16 = 1;

/// The nine Testnet-v3 native contracts, in approved nonce order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GenesisContract {
    Identity,
    ValidatorRegistry,
    Staking,
    Governance,
    Treasury,
    Slashing,
    RewardDistributor,
    SynergyOracle,
    TeamVesting,
}

impl GenesisContract {
    pub const APPROVED_ORDER: [GenesisContract; 9] = [
        GenesisContract::Identity,
        GenesisContract::ValidatorRegistry,
        GenesisContract::Staking,
        GenesisContract::Governance,
        GenesisContract::Treasury,
        GenesisContract::Slashing,
        GenesisContract::RewardDistributor,
        GenesisContract::SynergyOracle,
        GenesisContract::TeamVesting,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::ValidatorRegistry => "ValidatorRegistry",
            Self::Staking => "Staking",
            Self::Governance => "Governance",
            Self::Treasury => "Treasury",
            Self::Slashing => "Slashing",
            Self::RewardDistributor => "RewardDistributor",
            Self::SynergyOracle => "SynergyOracle",
            Self::TeamVesting => "TeamVesting",
        }
    }

    /// Deployed-contract dependencies, i.e. constructor arguments that resolve
    /// to another native contract's deployed address. Account authorities are
    /// deliberately not edges: `Slashing.initialSlashingAuthority` is an account
    /// authority under the operator ruling, not a contract.
    pub fn contract_dependencies(self) -> &'static [GenesisContract] {
        match self {
            Self::Staking => &[GenesisContract::ValidatorRegistry],
            Self::Governance => &[GenesisContract::Staking],
            Self::Treasury => &[GenesisContract::Governance],
            Self::Slashing => &[GenesisContract::ValidatorRegistry, GenesisContract::Staking],
            _ => &[],
        }
    }
}

/// Deployment authority lifecycle. Monotonic and one-way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenesisDeployerLifecycle {
    Uninitialized,
    AuthorizedForGenesis,
    Executing,
    Completed,
    PermanentlyRetired,
}

impl GenesisDeployerLifecycle {
    fn code(self) -> u8 {
        match self {
            Self::Uninitialized => 0,
            Self::AuthorizedForGenesis => 1,
            Self::Executing => 2,
            Self::Completed => 3,
            Self::PermanentlyRetired => 4,
        }
    }

    fn from_code(code: u8) -> Result<Self, String> {
        Ok(match code {
            0 => Self::Uninitialized,
            1 => Self::AuthorizedForGenesis,
            2 => Self::Executing,
            3 => Self::Completed,
            4 => Self::PermanentlyRetired,
            other => return Err(format!("unknown genesis deployer lifecycle code {other}")),
        })
    }
}

/// An ML-DSA-87 signing identity used by the genesis orchestrator.
#[derive(Debug, Clone)]
pub struct GenesisSigner {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub identity_authorization: Option<crate::identity_auth::IdentityAuthorizationCarrier>,
}

impl GenesisSigner {
    /// Canonical public identity: `syna…` Standard Account address. Fails
    /// closed (rather than deriving a substitute identity) when the public
    /// key material cannot produce a canonical address.
    pub fn account_address(&self) -> Result<String, String> {
        let carrier = self.identity_authorization.as_ref().ok_or_else(|| {
            "genesis signer is missing its identity authorization carrier".to_string()
        })?;
        carrier
            .identity_address_for_key_in_context_at(
                crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
                crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
                "ML-DSA-87",
                &self.public_key,
                "genesis-signing",
                GENESIS_NOW_UNIX,
            )
            .map_err(|error| format!("genesis signer authorization failed: {error}"))
    }

    fn synq_identity_authorization(
        &self,
        required_purpose: &str,
    ) -> Result<crate::identity_auth::IdentityAuthorizationCarrier, String> {
        let carrier = self.identity_authorization.as_ref().ok_or_else(|| {
            "genesis signer is missing its identity authorization carrier".to_string()
        })?;
        if required_purpose != SYNQ_DEPLOY_AUTHORIZATION_PURPOSE
            && required_purpose != SYNQ_CALL_AUTHORIZATION_PURPOSE
        {
            return Err(format!(
                "unsupported Genesis SynQ authorization purpose '{required_purpose}'"
            ));
        }
        carrier.verify_context_at(
            crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
            GENESIS_NOW_UNIX,
        )?;
        // The domain switch below is only a wire-routing label. Authority is
        // established first from the binding's root- and key-possession-signed
        // exact (domain, chain, network, purpose) scope. Re-labelling a binding
        // that lacks this exact signed scope therefore cannot grant authority.
        crate::identity_auth::identity_address_for_authorization_key_in_context_at(
            &carrier.binding,
            "ML-DSA-87",
            &self.public_key,
            crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
            crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
            required_purpose,
            GENESIS_NOW_UNIX,
        )
        .map_err(|error| {
            format!(
                "genesis binding does not explicitly authorize SynQ purpose '{required_purpose}': {error}"
            )
        })?;
        let synq_carrier = crate::identity_auth::IdentityAuthorizationCarrier {
            schema_version: crate::identity_auth::AUTHORIZATION_CARRIER_SCHEMA_VERSION,
            signature_domain: crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN.to_string(),
            binding: carrier.binding.clone(),
        };
        synq_carrier.verify_context_at(
            crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
            GENESIS_NOW_UNIX,
        )?;
        Ok(synq_carrier)
    }

    /// Resolves this ML-DSA-87 signer through a dual-possession SNTS v1.3
    /// binding instead of treating the operational key as an address root.
    pub fn account_address_from_binding(
        &self,
        binding: &crate::identity_auth::IdentityAuthorizationBinding,
        required_purpose: &str,
    ) -> Result<String, String> {
        crate::identity_auth::identity_address_for_authorization_key_in_context_at(
            binding,
            "ML-DSA-87",
            &self.public_key,
            crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
            crate::synergy_types::SYNERGY_TESTNET_V3_CHAIN_ID,
            crate::synergy_types::SYNERGY_TESTNET_V3_NETWORK_ID,
            required_purpose,
            GENESIS_NOW_UNIX,
        )
        .map_err(|error| format!("genesis signer authorization binding failed: {error}"))
    }

    /// Internal signed-payload binding. Never surfaced as an address.
    pub fn synq_address(&self) -> Result<SynQAddress, String> {
        derive_synq_address(
            &SynQPublicKey::new(self.public_key.clone()),
            AlgorithmId::MlDsa87,
            &SynQNetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
        )
        .map_err(|error| format!("derive genesis signer address: {error}"))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        Sign::mldsa87()
            .detached_sign(message, &self.private_key)
            .map_err(|error| format!("ML-DSA-87 sign failed: {error:?}"))
    }

    pub fn hex_public_key(&self) -> String {
        format!("0x{}", hex::encode(&self.public_key))
    }
}

/// The authorities genesis needs. During development every one of these is a
/// frozen test-only fixture; production public identities are substituted after
/// the custody ceremonies, and only the deployer and governance authority need
/// private keys at genesis-execution time.
#[derive(Debug, Clone)]
pub struct GenesisAuthorities {
    pub genesis_deployer: GenesisSigner,
    pub governance: GenesisSigner,
    pub emergency_slashing_authority: String,
    pub validator_registry_authority: String,
    pub validator_registry_authority_key: GenesisSigner,
    pub reward_distributor_authority: String,
    pub identity_fee_collector: String,
    pub team_vesting_admin: String,
    pub oracle_publisher: String,
}

fn validate_genesis_signer_authorizations(authorities: &GenesisAuthorities) -> Result<(), String> {
    authorities.genesis_deployer.account_address()?;
    authorities
        .genesis_deployer
        .synq_identity_authorization(SYNQ_DEPLOY_AUTHORIZATION_PURPOSE)?;

    authorities.governance.account_address()?;
    authorities
        .governance
        .synq_identity_authorization(SYNQ_CALL_AUTHORIZATION_PURPOSE)?;

    let registry_authority = authorities
        .validator_registry_authority_key
        .account_address()?;
    if registry_authority != authorities.validator_registry_authority {
        return Err(format!(
            "validator registry authority identity mismatch: configured {}, signed binding resolves to {registry_authority}",
            authorities.validator_registry_authority
        ));
    }
    authorities
        .validator_registry_authority_key
        .synq_identity_authorization(SYNQ_CALL_AUTHORIZATION_PURPOSE)?;
    Ok(())
}

/// Genesis configuration values that are not authorities. Sourced from the
/// genesis document's `init_params` after the approved unit conversions.
#[derive(Debug, Clone)]
pub struct GenesisParameters {
    pub identity_registration_fee_nwei: String,
    pub identity_reserved_names: Vec<String>,
    pub validator_max_count: String,
    pub validator_min_count: String,
    pub validator_min_self_stake_nwei: String,
    pub validators: Vec<GenesisValidator>,
    pub staking_min_stake_nwei: String,
    pub staking_max_stake_nwei: String,
    pub staking_unbonding_blocks: String,
    pub governance_quorum_bps: String,
    pub governance_approval_bps: String,
    pub governance_veto_bps: String,
    pub governance_min_deposit_nwei: String,
    pub governance_voting_blocks: String,
    pub governance_timelock_blocks: String,
    pub treasury_required_signers: String,
    pub treasury_signers: Vec<String>,
    pub slashing_double_sign_bps: String,
    pub slashing_downtime_bps: String,
    pub slashing_invalid_block_bps: String,
    pub slashing_missed_blocks_threshold: String,
    pub slashing_jail_blocks: String,
    pub oracle_quorum_threshold: String,
    pub oracle_replay_protection: bool,
    pub oracle_source_domains: Vec<String>,
    pub team_vesting_start_time: String,
    pub team_allocation_nwei: String,
    pub support_allocation_nwei: String,
    pub team_count: String,
    pub support_count: String,
}

#[derive(Debug, Clone)]
pub struct GenesisValidator {
    pub id_hash: String,
    pub operator_address: String,
    pub reward_address: String,
    pub voting_power: String,
    pub self_stake_nwei: String,
    pub metadata_hash: String,
    pub key_bundle_hash: String,
    pub activation_height: String,
}

/// One planned deployment: fixed nonce, fixed contract, fixed artifact.
#[derive(Debug, Clone)]
pub struct GenesisPlanEntry {
    pub nonce: u64,
    pub contract: GenesisContract,
    pub artifact: SynQContractArtifact,
}

#[derive(Debug, Clone)]
pub struct GenesisDeploymentPlan {
    pub entries: Vec<GenesisPlanEntry>,
}

impl GenesisDeploymentPlan {
    pub fn new(
        artifacts: &BTreeMap<GenesisContract, SynQContractArtifact>,
    ) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (nonce, contract) in GenesisContract::APPROVED_ORDER.iter().enumerate() {
            let artifact = artifacts
                .get(contract)
                .ok_or_else(|| format!("genesis plan is missing artifact for {}", contract.name()))?
                .clone();
            entries.push(GenesisPlanEntry {
                nonce: nonce as u64,
                contract: *contract,
                artifact,
            });
        }
        Ok(Self { entries })
    }

    /// Machine-enforced ordering. Runs before any state is touched: a plan that
    /// violates the dependency graph, repeats a nonce, or is not exactly the
    /// nine approved contracts fails here, not halfway through execution.
    pub fn validate(&self) -> Result<(), String> {
        if self.entries.len() != GenesisContract::APPROVED_ORDER.len() {
            return Err(format!(
                "genesis plan must contain exactly {} deployments, found {}",
                GenesisContract::APPROVED_ORDER.len(),
                self.entries.len()
            ));
        }
        let mut seen_nonces = std::collections::BTreeSet::new();
        let mut position: BTreeMap<GenesisContract, u64> = BTreeMap::new();
        for entry in &self.entries {
            if !seen_nonces.insert(entry.nonce) {
                return Err(format!("genesis plan repeats nonce {}", entry.nonce));
            }
            if position.insert(entry.contract, entry.nonce).is_some() {
                return Err(format!(
                    "genesis plan repeats contract {}",
                    entry.contract.name()
                ));
            }
        }
        for expected in 0..self.entries.len() as u64 {
            if !seen_nonces.contains(&expected) {
                return Err(format!("genesis plan is missing nonce {expected}"));
            }
        }
        for entry in &self.entries {
            for dependency in entry.contract.contract_dependencies() {
                let dependency_nonce = position.get(dependency).ok_or_else(|| {
                    format!(
                        "genesis plan omits {}, required by {}",
                        dependency.name(),
                        entry.contract.name()
                    )
                })?;
                if *dependency_nonce >= entry.nonce {
                    return Err(format!(
                        "genesis plan violates the dependency graph: {} (nonce {}) must deploy after {} (nonce {})",
                        entry.contract.name(),
                        entry.nonce,
                        dependency.name(),
                        dependency_nonce
                    ));
                }
            }
        }
        Ok(())
    }
}

/// What a completed genesis deployment produced.
#[derive(Debug, Clone)]
pub struct GenesisDeploymentOutcome {
    pub addresses: BTreeMap<GenesisContract, String>,
    pub deployment_receipts: Vec<SynQAivmReceiptSummary>,
    pub initialization_receipts: Vec<SynQAivmReceiptSummary>,
    pub post_deployment_state_root: Hash,
    pub receipt_root: Hash,
    pub deployment_manifest_hash: Hash,
    pub lifecycle: GenesisDeployerLifecycle,
}

/// Deterministic genesis transaction identifier.
///
/// Deliberately not the hash of the signed transaction bytes: ML-DSA signatures
/// are randomized, and the identifier is recorded in the deployment record and
/// therefore in the state root.
fn genesis_tx_id(kind: &str, label: &str, ordinal: u64, payload_hash: &[u8; 32]) -> TxId {
    let mut material = Vec::new();
    material.extend_from_slice(b"SYNERGY_GENESIS_TX_ID_V1");
    material.extend_from_slice(kind.as_bytes());
    material.extend_from_slice(label.as_bytes());
    material.extend_from_slice(&ordinal.to_be_bytes());
    material.extend_from_slice(payload_hash);
    TxId(Hash::from_domain_bytes("SYNERGY_GENESIS_TX_ID_V1", &material).to_hex())
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

fn json_args(values: &[serde_json::Value]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::Value::Array(values.to_vec()))
        .expect("constructor/call argument arrays are always serializable")
}

fn signing_payload(
    domain_tag: DomainTag,
    signature_purpose: SignaturePurpose,
    signer_address: SynQAddress,
    payload_hash: [u8; 32],
    nonce: u64,
) -> SynQSigningPayload {
    SynQSigningPayload {
        domain_tag,
        chain_id: SynQChainId(SYNERGY_TESTNET_V3_CHAIN_ID),
        network_id: SynQNetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
        protocol_version: GENESIS_PROTOCOL_VERSION,
        algorithm_id: AlgorithmId::MlDsa87,
        signature_purpose,
        nonce,
        not_before_unix: 0,
        expiration_unix: GENESIS_EXPIRATION_UNIX,
        signer_address,
        payload_hash,
    }
}

/// A genesis carrier transaction. Genesis policy exempts fees and there is no
/// public mempool, so this is a deterministic wrapper around an already-signed
/// SynQ envelope rather than a user transaction.
fn genesis_transaction(sender: &str, payload: Vec<u8>, sequence: u64) -> Transaction {
    Transaction {
        version: 1,
        chain_id: ChainId(SYNERGY_TESTNET_V3_CHAIN_ID),
        network_id: NetworkId(SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string()),
        epoch: Epoch(0),
        sender_uma_or_account: sender.to_string(),
        receiver_uma_or_account: String::new(),
        account_nonce_or_sequence: sequence,
        amount_nwei: 0,
        gas_limit: 12_000_000,
        max_fee_nwei: 0,
        ttl_height: Height(0),
        explicit_dependencies: Vec::new(),
        read_set_hint: Vec::new(),
        write_set_hint: Vec::new(),
        payload,
        // Genesis carriers are not user transactions: authorization lives in
        // the enclosed SynQ envelope, which is signed by the Genesis Deployer.
        signer_uma_id: UmaId(String::new()),
        aegis_pq_key_id: AegisPqKeyId(String::new()),
        aegis_pq_signature: AegisPqSignature {
            algorithm: String::new(),
            signature_bytes: Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// Deployment authority lifecycle, held in protocol state
// ---------------------------------------------------------------------------

fn lifecycle_key(key: &[u8]) -> StateKey {
    StateKey::new(GENESIS_DEPLOYMENT_NAMESPACE, key)
}

pub fn read_deployer_lifecycle(state: &ExecutionState) -> Result<GenesisDeployerLifecycle, String> {
    match state.synq_aivm_state.get(&lifecycle_key(LIFECYCLE_KEY)) {
        None => Ok(GenesisDeployerLifecycle::Uninitialized),
        Some(bytes) if bytes.len() == 1 => GenesisDeployerLifecycle::from_code(bytes[0]),
        Some(_) => Err("stored genesis deployer lifecycle is malformed".to_string()),
    }
}

fn write_lifecycle(
    state: &mut ExecutionState,
    lifecycle: GenesisDeployerLifecycle,
) -> Result<(), String> {
    let mut overlay = aivm_core::state::StateOverlay::default();
    overlay.write(lifecycle_key(LIFECYCLE_KEY), vec![lifecycle.code()]);
    overlay.commit(&mut state.synq_aivm_state);
    Ok(())
}

fn write_manifest_hash(state: &mut ExecutionState, manifest_hash: &Hash) {
    let mut overlay = aivm_core::state::StateOverlay::default();
    overlay.write(lifecycle_key(MANIFEST_KEY), manifest_hash.0.to_vec());
    overlay.commit(&mut state.synq_aivm_state);
}

pub fn read_deployment_manifest_hash(state: &ExecutionState) -> Option<Hash> {
    state
        .synq_aivm_state
        .get(&lifecycle_key(MANIFEST_KEY))
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(Hash)
}

/// Canonical hash over the whole signed deployment plan. Binds the deployer,
/// every nonce, and every artifact triple, so replaying a manifest against a
/// changed plan — or the same plan twice — is detectable.
pub fn deployment_manifest_hash(
    deployer: &SynQAddress,
    plan: &GenesisDeploymentPlan,
) -> Result<Hash, String> {
    let mut material = Vec::new();
    material.extend_from_slice(b"SYNERGY_GENESIS_DEPLOYMENT_MANIFEST_V1");
    material.extend_from_slice(deployer.as_bytes());
    material.extend_from_slice(&(plan.entries.len() as u64).to_be_bytes());
    for entry in &plan.entries {
        material.extend_from_slice(&entry.nonce.to_be_bytes());
        material.extend_from_slice(entry.contract.name().as_bytes());
        let key = entry.artifact.key();
        material.extend_from_slice(&key.bytecode_hash);
        material.extend_from_slice(&key.manifest_hash);
        material.extend_from_slice(&key.abi_hash);
    }
    Ok(Hash::from_domain_bytes(
        "SYNERGY_GENESIS_DEPLOYMENT_MANIFEST_V1",
        &material,
    ))
}

// ---------------------------------------------------------------------------
// Constructor arguments
// ---------------------------------------------------------------------------

/// Canonical typed constructor arguments, resolved dependency-first.
///
/// Dependencies are read from `resolved`, which only ever contains contracts
/// already deployed earlier in the plan. A placeholder is never substituted:
/// the constructor-args hash feeds the contract's own address, so a placeholder
/// would permanently bind the address to a value the contract never used.
pub fn constructor_arguments(
    contract: GenesisContract,
    authorities: &GenesisAuthorities,
    parameters: &GenesisParameters,
    resolved: &BTreeMap<GenesisContract, String>,
) -> Result<Vec<u8>, String> {
    let dependency = |needed: GenesisContract| -> Result<String, String> {
        resolved.get(&needed).cloned().ok_or_else(|| {
            format!(
                "{} constructor requires {} which is not yet deployed",
                contract.name(),
                needed.name()
            )
        })
    };
    let gov = serde_json::Value::String(authorities.governance.hex_public_key());
    let s = |v: &str| serde_json::Value::String(v.to_string());

    let values: Vec<serde_json::Value> = match contract {
        GenesisContract::Identity => vec![
            gov,
            s(&authorities.identity_fee_collector),
            s(&parameters.identity_registration_fee_nwei),
        ],
        GenesisContract::ValidatorRegistry => vec![
            gov,
            s(&authorities.validator_registry_authority),
            s(&parameters.validator_max_count),
            s(&parameters.validator_min_count),
            s(&parameters.validator_min_self_stake_nwei),
        ],
        GenesisContract::Staking => vec![
            gov,
            s(&dependency(GenesisContract::ValidatorRegistry)?),
            s(&parameters.staking_min_stake_nwei),
            s(&parameters.staking_max_stake_nwei),
            // Delegation disabled at genesis: false / 0 / 0 is the only
            // combination the amended constructor accepts while disabled.
            serde_json::Value::Bool(false),
            s("0"),
            s("0"),
            s(&parameters.staking_unbonding_blocks),
        ],
        GenesisContract::Governance => vec![
            gov,
            s(&dependency(GenesisContract::Staking)?),
            s(&parameters.governance_quorum_bps),
            s(&parameters.governance_approval_bps),
            s(&parameters.governance_veto_bps),
            s(&parameters.governance_min_deposit_nwei),
            s(&parameters.governance_voting_blocks),
            s(&parameters.governance_timelock_blocks),
        ],
        GenesisContract::Treasury => vec![
            gov,
            s(&dependency(GenesisContract::Governance)?),
            s(&parameters.treasury_required_signers),
        ],
        GenesisContract::Slashing => vec![
            gov,
            s(&dependency(GenesisContract::ValidatorRegistry)?),
            s(&dependency(GenesisContract::Staking)?),
            s(&authorities.emergency_slashing_authority),
            s(&parameters.slashing_double_sign_bps),
            s(&parameters.slashing_downtime_bps),
            s(&parameters.slashing_invalid_block_bps),
            s(&parameters.slashing_missed_blocks_threshold),
            s(&parameters.slashing_jail_blocks),
        ],
        GenesisContract::RewardDistributor => {
            vec![gov, s(&authorities.reward_distributor_authority)]
        }
        GenesisContract::SynergyOracle => vec![
            gov,
            s(&parameters.oracle_quorum_threshold),
            serde_json::Value::Bool(parameters.oracle_replay_protection),
        ],
        // TeamVesting takes no governance key — only an address administrator.
        GenesisContract::TeamVesting => vec![
            s(&authorities.team_vesting_admin),
            s(&parameters.team_vesting_start_time),
            s(&parameters.team_allocation_nwei),
            s(&parameters.support_allocation_nwei),
            s(&parameters.team_count),
            s(&parameters.support_count),
        ],
    };
    Ok(json_args(&values))
}

// ---------------------------------------------------------------------------
// Deployment and call execution over the canonical path
// ---------------------------------------------------------------------------

fn deploy_one(
    state: &mut ExecutionState,
    entry: &GenesisPlanEntry,
    deployer: &GenesisSigner,
    constructor_args: Vec<u8>,
) -> Result<(String, SynQAddress, SynQAivmReceiptSummary), String> {
    let deployer_address = deployer.synq_address()?;
    let key = entry.artifact.key();
    let constructor_args_hash = sha256_array(&constructor_args);
    let payload_hash = hash_contract_deploy_body(
        &key.bytecode_hash,
        &key.manifest_hash,
        &key.abi_hash,
        deployer_address.as_bytes(),
        &constructor_args_hash,
    );
    let payload = signing_payload(
        DomainTag::SynqContractDeployV1,
        SignaturePurpose::ContractDeploy,
        deployer_address,
        payload_hash,
        // SynQ admission refuses a zero envelope nonce (`require_nonce`), so the
        // envelope nonce is the deployment ordinal + 1. The approved ordinals
        // stay 0..=8; the envelope disambiguator is 1..=9, fixed and derived
        // from the ordinal alone so addresses remain reproducible.
        entry.nonce + 1,
    );
    let canonical = canonicalize_signing_payload(&payload)
        .map_err(|error| format!("canonicalize genesis deploy payload: {error}"))?;
    let deploy = ContractDeployEnvelope {
        signing_payload: payload,
        public_key: SynQPublicKey::new(deployer.public_key.clone()),
        signature: SynQSignature::new(deployer.sign(&canonical)?),
        bytecode_hash: key.bytecode_hash,
        manifest_hash: key.manifest_hash,
        abi_hash: key.abi_hash,
        constructor_args_hash,
    };

    // The address is derived from the same envelope the runtime admits and
    // executes — never chosen, never assigned.
    let deployer_identity_address = deployer.account_address()?;
    let synq_contract_address =
        crate::synq_execution::derive_synq_contract_address_from_deploy_with_identity_address(
            &deploy,
            &deployer_identity_address,
        )?;
    let contract_address =
        crate::synq_execution::derive_synergy_contract_address_from_deploy_with_identity_address(
            &deploy,
            &deployer_identity_address,
        )?;

    let encoded = serde_json::to_vec(&deploy)
        .map_err(|error| format!("encode genesis deploy envelope: {error}"))?;
    let envelope =
        build_deploy_admission_envelope_from_pqsynq_bytes_with_artifacts_constructor_args_and_identity_authorization(
            SYNERGY_TESTNET_V3_CHAIN_ID,
            SYNQ_CANONICAL_TESTNET_NETWORK_ID,
            &encoded,
            entry.artifact.bytecode.clone(),
            entry.artifact.abi_json.clone(),
            entry.artifact.manifest_json.clone(),
            constructor_args,
            deployer.synq_identity_authorization(SYNQ_DEPLOY_AUTHORIZATION_PURPOSE)?,
            SYNQ_DEPLOY_AUTHORIZATION_PURPOSE,
            GENESIS_NOW_UNIX,
        )
        .map_err(|error| {
            format!(
                "{} genesis deploy admission failed: {error}",
                entry.contract.name()
            )
        })?;
    let canonical_binding = state
        .current_identity_authorization_binding_hash(&envelope.signer)
        .ok_or_else(|| {
            format!(
                "Genesis deployer {} has no canonical identity binding",
                envelope.signer
            )
        })?;
    let verification = verify_synq_deploy_for_chain_admission_at_current_binding(
        &envelope,
        GENESIS_NOW_UNIX,
        canonical_binding,
    )
    .map_err(|error| {
        format!(
            "{} genesis deploy verification failed: {error}",
            entry.contract.name()
        )
    })?;
    let carrier = encode_synq_admission_carrier(&envelope)
        .map_err(|error| format!("encode genesis deploy carrier: {error}"))?;

    let tx = genesis_transaction(&verification.signer, carrier, entry.nonce);
    // ML-DSA signing is hedged, so the signature bytes differ every run. The
    // deployment record stores the tx id, which feeds the state root, so the
    // genesis tx id is derived from *what is being deployed* rather than from
    // the signed bytes. Addresses were already signature-independent; this makes
    // the state root reproducible too.
    let tx_id = genesis_tx_id("deploy", entry.contract.name(), entry.nonce, &payload_hash);
    let summary = execute_synq_transaction_at(
        &tx_id,
        &tx,
        &verification,
        &mut state.synq_aivm_state,
        &mut state.synq_artifacts,
        &mut state.synq_contracts,
        SynQExecutionContext {
            runtime_block_height: GENESIS_BLOCK_HEIGHT,
            runtime_block_timestamp_unix: GENESIS_NOW_UNIX,
            sts_host: None,
            applied_fee_market: None,
        },
    )?
    .ok_or_else(|| {
        format!(
            "{} genesis deploy produced no receipt",
            entry.contract.name()
        )
    })?;

    if summary.status != "succeeded" {
        return Err(format!(
            "{} genesis deployment failed: {} {}",
            entry.contract.name(),
            summary.error_code.clone().unwrap_or_default(),
            summary.error_message.clone().unwrap_or_default()
        ));
    }
    if summary.contract_address != contract_address {
        return Err(format!(
            "{} deployed at {} but derivation produced {}",
            entry.contract.name(),
            summary.contract_address,
            contract_address
        ));
    }
    state.synq_verifications.insert(tx_id, verification);
    Ok((contract_address, synq_contract_address, summary))
}

/// Selector for a method, read from the contract's own compiled ABI.
fn selector(artifact: &SynQContractArtifact, method: &str) -> Result<[u8; 4], String> {
    let abi: serde_json::Value =
        serde_json::from_str(&artifact.abi_json).map_err(|error| format!("parse ABI: {error}"))?;
    let raw = abi["methods"]
        .as_array()
        .ok_or_else(|| "ABI has no methods array".to_string())?
        .iter()
        .find(|m| m["name"] == method)
        .ok_or_else(|| format!("ABI has no method {method}"))?["selector"]
        .as_str()
        .ok_or_else(|| format!("method {method} has no selector"))?
        .trim_start_matches("0x")
        .to_string();
    let bytes = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("decode selector for {method}: {error}"))?;
    <[u8; 4]>::try_from(bytes.as_slice())
        .map_err(|_| format!("selector for {method} is not 4 bytes"))
}

/// One initialization call, executed by the deployer through the canonical
/// call path. Governed calls carry a Session-13J authorization envelope built
/// over the exact contract, method, arguments and nonce.
#[allow(clippy::too_many_arguments)]
fn call_one(
    state: &mut ExecutionState,
    artifact: &SynQContractArtifact,
    contract_address: &str,
    synq_contract_address: SynQAddress,
    method: &str,
    args: Vec<serde_json::Value>,
    caller: &GenesisSigner,
    call_nonce: u64,
) -> Result<SynQAivmReceiptSummary, String> {
    let caller_address = caller.synq_address()?;
    let method_selector = selector(artifact, method)?;
    let encoded_args = json_args(&args);
    let encoded_args_hash = sha256_array(&encoded_args);

    if !state.synq_contracts.contains_key(contract_address) {
        return Err(format!("{contract_address} is not deployed"));
    }

    let payload_hash = hash_contract_call_body(
        synq_contract_address.as_bytes(),
        &method_selector,
        &encoded_args_hash,
        caller_address.as_bytes(),
    );
    let payload = signing_payload(
        DomainTag::SynqContractCallV1,
        SignaturePurpose::ContractCall,
        caller_address,
        payload_hash,
        // Same `require_nonce` rule as the deploy domain.
        call_nonce + 1,
    );
    let canonical = canonicalize_signing_payload(&payload)
        .map_err(|error| format!("canonicalize genesis call payload: {error}"))?;
    let call = ContractCallEnvelope {
        signing_payload: payload,
        public_key: SynQPublicKey::new(caller.public_key.clone()),
        signature: SynQSignature::new(caller.sign(&canonical)?),
        contract_address: synq_contract_address,
        method_selector,
        encoded_args_hash,
    };
    let encoded = serde_json::to_vec(&call)
        .map_err(|error| format!("encode genesis call envelope: {error}"))?;
    // Built directly rather than through
    // `build_call_admission_envelope_from_pqsynq_bytes_with_args`, which runs a
    // first verification pass before attaching the arguments and therefore
    // hashes an empty argument list. The envelope below is the same shape and
    // is verified once, with the arguments present.
    let envelope = SynQAdmissionEnvelope {
        version: SYNQ_ADMISSION_VERSION,
        kind: SynQAdmissionKind::Call,
        chain_id: SYNERGY_TESTNET_V3_CHAIN_ID,
        network_id: SYNQ_CANONICAL_TESTNET_NETWORK_ID.to_string(),
        signer: caller.account_address()?,
        identity_authorization: Some(
            caller.synq_identity_authorization(SYNQ_CALL_AUTHORIZATION_PURPOSE)?,
        ),
        authorization_purpose: SYNQ_CALL_AUTHORIZATION_PURPOSE.to_string(),
        payload_hash: call.signing_payload.payload_hash,
        bytecode_hash: None,
        manifest_hash: None,
        abi_hash: None,
        encoded_pqsynq_envelope: encoded,
        bytecode: None,
        abi_json: None,
        manifest_json: None,
        constructor_args: None,
        encoded_args: Some(encoded_args),
        sts9_verification_json: None,
    };
    let canonical_binding = state
        .current_identity_authorization_binding_hash(&envelope.signer)
        .ok_or_else(|| {
            format!(
                "Genesis caller {} has no canonical identity binding",
                envelope.signer
            )
        })?;
    let verification = verify_synq_call_for_chain_admission_at_current_binding(
        &envelope,
        GENESIS_NOW_UNIX,
        canonical_binding,
    )
    .map_err(|error| format!("genesis {method} call verification failed: {error}"))?;
    let carrier = encode_synq_admission_carrier(&envelope)
        .map_err(|error| format!("encode genesis call carrier: {error}"))?;

    let tx = genesis_transaction(&verification.signer, carrier, call_nonce);
    let tx_id = genesis_tx_id("call", method, call_nonce, &payload_hash);
    let summary = execute_synq_transaction_at(
        &tx_id,
        &tx,
        &verification,
        &mut state.synq_aivm_state,
        &mut state.synq_artifacts,
        &mut state.synq_contracts,
        SynQExecutionContext {
            runtime_block_height: GENESIS_BLOCK_HEIGHT,
            runtime_block_timestamp_unix: GENESIS_NOW_UNIX,
            sts_host: None,
            applied_fee_market: None,
        },
    )?
    .ok_or_else(|| format!("genesis {method} call produced no receipt"))?;

    if summary.status != "succeeded" {
        return Err(format!(
            "genesis {method} call failed: {} {}",
            summary.error_code.clone().unwrap_or_default(),
            summary.error_message.clone().unwrap_or_default()
        ));
    }
    state.synq_verifications.insert(tx_id, verification);
    Ok(summary)
}

/// Builds the Session-13J governance authorization tail for a governed call.
///
/// The host reconstructs this exact payload from the invocation, so the
/// orchestrator signs the real contract, the real method and the real
/// arguments. There is no arbitrary message anywhere in this path.
fn governance_tail(
    governance: &GenesisSigner,
    artifact: &SynQContractArtifact,
    contract_address: &str,
    method: &str,
    action_args: &[serde_json::Value],
    governance_nonce: u128,
) -> Result<Vec<serde_json::Value>, String> {
    let payload = aivm_core::stateful_synq::governance_action_signing_payload(
        SYNERGY_TESTNET_V3_CHAIN_ID,
        SYNQ_CANONICAL_TESTNET_NETWORK_ID,
        contract_address.as_bytes(),
        method,
        &sha256_array(&governance_action_arguments(artifact, method, action_args)?),
        governance_nonce,
        0,
        &aivm_core::stateful_synq::governance_key_fingerprint(&governance.public_key),
    );
    let signature = governance.sign(&payload)?;
    let mut tail = action_args.to_vec();
    tail.push(serde_json::Value::String(governance_nonce.to_string()));
    tail.push(serde_json::Value::String("0".to_string()));
    tail.push(serde_json::Value::String(format!(
        "0x{}",
        hex::encode(signature)
    )));
    Ok(tail)
}

/// Mirrors the host's typed, length-prefixed argument encoding.
///
/// The host tags each value by the parameter's **declared SynQ type**, so the
/// tag cannot be inferred from the JSON shape alone — `String`, `Bytes` and
/// `Address` are all JSON strings but encode as 0x04, 0x05 and 0x06. Types are
/// therefore read from the contract's own compiled ABI.
fn governance_action_arguments(
    artifact: &SynQContractArtifact,
    method: &str,
    values: &[serde_json::Value],
) -> Result<Vec<u8>, String> {
    fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(value);
    }
    fn hex_bytes(text: &str) -> Vec<u8> {
        let raw = text.strip_prefix("0x").unwrap_or(text);
        if !raw.is_empty() && raw.len() % 2 == 0 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            (0..raw.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap_or(0))
                .collect()
        } else {
            text.as_bytes().to_vec()
        }
    }

    let abi: serde_json::Value =
        serde_json::from_str(&artifact.abi_json).map_err(|error| format!("parse ABI: {error}"))?;
    let inputs = abi["methods"]
        .as_array()
        .ok_or_else(|| "ABI has no methods array".to_string())?
        .iter()
        .find(|m| m["name"] == method)
        .ok_or_else(|| format!("ABI has no method {method}"))?["params"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for (index, value) in values.iter().enumerate() {
        let declared = inputs
            .get(index)
            .and_then(|input| input["type"].as_str())
            .ok_or_else(|| format!("{method} argument {index} has no declared ABI type"))?;
        match declared {
            "bool" => {
                let flag = value
                    .as_bool()
                    .ok_or_else(|| format!("{method} argument {index} must be a bool"))?;
                out.push(0x03);
                out.push(u8::from(flag));
            }
            "string" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{method} argument {index} must be a string"))?;
                out.push(0x04);
                push_bytes(&mut out, text.as_bytes());
            }
            "address" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{method} argument {index} must be an address"))?;
                out.push(0x06);
                push_bytes(&mut out, text.as_bytes());
            }
            other if other.starts_with('u') || other.starts_with('i') => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{method} argument {index} must be a decimal string"))?;
                let parsed: u128 = text
                    .parse()
                    .map_err(|_| format!("{method} argument {index} is not an integer"))?;
                out.push(0x01);
                out.extend_from_slice(&parsed.to_be_bytes());
            }
            // bytes, ml-dsa-signature, ml-dsa-public-key and friends
            _ => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{method} argument {index} must be hex bytes"))?;
                out.push(0x05);
                push_bytes(&mut out, &hex_bytes(text));
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Atomic genesis deployment
// ---------------------------------------------------------------------------

/// Deploys the nine native contracts, runs every launch-critical initialization
/// call, and retires the Genesis Deployer — all or nothing.
///
/// Atomicity is structural rather than best-effort: the whole plan executes
/// against a **clone** of `ExecutionState`, and the caller's state is only
/// overwritten once every step has succeeded. Any error at any point returns
/// early, the clone is dropped, and the original is byte-identical — no
/// contracts, no constructor storage, no Treasury signers, no reserved names,
/// no validator records, no oracle records, no authority assignments, no
/// receipts, no roots, no lifecycle change.
pub fn execute_genesis_deployment(
    state: &mut ExecutionState,
    plan: &GenesisDeploymentPlan,
    authorities: &GenesisAuthorities,
    parameters: &GenesisParameters,
) -> Result<GenesisDeploymentOutcome, String> {
    plan.validate()?;

    let lifecycle = read_deployer_lifecycle(state)?;
    if lifecycle != GenesisDeployerLifecycle::Uninitialized {
        return Err(format!(
            "genesis deployment already ran: deployer lifecycle is {lifecycle:?}"
        ));
    }

    // Fail before constructing the overlay unless every signer has the exact
    // root-signed scope it will exercise. Genesis does not infer deploy
    // authority from call authority, or vice versa.
    validate_genesis_signer_authorizations(authorities)?;

    let deployer_address = authorities.genesis_deployer.synq_address()?;
    let manifest_hash = deployment_manifest_hash(&deployer_address, plan)?;

    // Everything below mutates the working clone only.
    let mut working = state.clone();
    for signer in [
        &authorities.genesis_deployer,
        &authorities.governance,
        &authorities.validator_registry_authority_key,
    ] {
        let carrier = signer.identity_authorization.as_ref().ok_or_else(|| {
            "Genesis signer is missing its canonical identity authorization binding".to_string()
        })?;
        working.install_genesis_identity_authorization_binding(&carrier.binding)?;
    }
    write_lifecycle(&mut working, GenesisDeployerLifecycle::AuthorizedForGenesis)?;
    write_lifecycle(&mut working, GenesisDeployerLifecycle::Executing)?;

    let mut addresses: BTreeMap<GenesisContract, String> = BTreeMap::new();
    let mut synq_addresses: BTreeMap<GenesisContract, SynQAddress> = BTreeMap::new();
    let mut deployment_receipts = Vec::new();

    for entry in &plan.entries {
        let constructor_args =
            constructor_arguments(entry.contract, authorities, parameters, &addresses)?;
        let (address, synq_address, receipt) = deploy_one(
            &mut working,
            entry,
            &authorities.genesis_deployer,
            constructor_args,
        )?;
        addresses.insert(entry.contract, address);
        synq_addresses.insert(entry.contract, synq_address);
        deployment_receipts.push(receipt);
    }

    let initialization_receipts = run_initialization_sequence(
        &mut working,
        plan,
        &addresses,
        &synq_addresses,
        authorities,
        parameters,
    )?;

    normalize_genesis_deployment_records(&mut working, &addresses)?;
    verify_initialization_state(&working, &addresses, parameters)?;

    // Retirement is the last state transition and is itself inside the
    // transaction: if it fails, the entire deployment is discarded.
    write_lifecycle(&mut working, GenesisDeployerLifecycle::Completed)?;
    write_lifecycle(&mut working, GenesisDeployerLifecycle::PermanentlyRetired)?;
    write_manifest_hash(&mut working, &manifest_hash);
    if read_deployer_lifecycle(&working)? != GenesisDeployerLifecycle::PermanentlyRetired {
        return Err("genesis deployer retirement did not persist".to_string());
    }

    let post_deployment_state_root = compute_state_root_after(&working)?;
    let receipt_root =
        compute_genesis_receipt_root(&deployment_receipts, &initialization_receipts)?;

    // Single commit point.
    *state = working;

    Ok(GenesisDeploymentOutcome {
        addresses,
        deployment_receipts,
        initialization_receipts,
        post_deployment_state_root,
        receipt_root,
        deployment_manifest_hash: manifest_hash,
        lifecycle: GenesisDeployerLifecycle::PermanentlyRetired,
    })
}

/// Replaces each deployment record's receipt hash with a value derived only
/// from genesis inputs.
///
/// `SynQDeploymentRecord` is part of the state root, and its `deploy_receipt_hash`
/// is the AIVM receipt hash, which embeds the signed transaction bytes. ML-DSA
/// signing is hedged, so that value differs on every run. At genesis there is no
/// mempool transaction whose identity is meaningful, so the record is bound to
/// the deployed address, the artifact and the deployment ordinal instead — all
/// of which are fixed by the signed deployment manifest.
fn normalize_genesis_deployment_records(
    working: &mut ExecutionState,
    addresses: &BTreeMap<GenesisContract, String>,
) -> Result<(), String> {
    for (ordinal, contract) in GenesisContract::APPROVED_ORDER.iter().enumerate() {
        let address = addresses
            .get(contract)
            .ok_or_else(|| format!("{} was not deployed", contract.name()))?;
        let record = working
            .synq_contracts
            .get_mut(address)
            .ok_or_else(|| format!("{} has no deployment record", contract.name()))?;
        let mut material = Vec::new();
        material.extend_from_slice(b"SYNERGY_GENESIS_DEPLOY_RECEIPT_V1");
        material.extend_from_slice(address.as_bytes());
        material.extend_from_slice(&record.artifact_key.bytecode_hash);
        material.extend_from_slice(&record.artifact_key.manifest_hash);
        material.extend_from_slice(&record.artifact_key.abi_hash);
        material.extend_from_slice(&(ordinal as u64).to_be_bytes());
        record.deploy_receipt_hash =
            Hash::from_domain_bytes("SYNERGY_GENESIS_DEPLOY_RECEIPT_V1", &material).to_hex();
    }
    Ok(())
}

/// Recomputes the deterministic combined receipt root emitted by the genesis
/// orchestrator. Release tooling uses this to reject edited, reordered, or
/// mismatched ceremony receipt files before binding them into Genesis.
pub fn compute_genesis_receipt_root(
    deployments: &[SynQAivmReceiptSummary],
    initializations: &[SynQAivmReceiptSummary],
) -> Result<Hash, String> {
    // `receipt_hash` embeds the AIVM execution context's tx hash, which is
    // taken over the signed transaction bytes and is therefore hedged-signature
    // dependent. The genesis receipt root commits to the deterministic content
    // of each receipt instead: what ran, where, whether it succeeded, and the
    // storage transition it produced.
    let mut material = Vec::new();
    material.extend_from_slice(b"SYNERGY_GENESIS_RECEIPT_ROOT_V1");
    for receipt in deployments.iter().chain(initializations.iter()) {
        material.extend_from_slice(receipt.operation.as_bytes());
        material.extend_from_slice(receipt.contract_address.as_bytes());
        material.extend_from_slice(receipt.status.as_bytes());
        material.extend_from_slice(receipt.return_data_hex.as_bytes());
        material.extend_from_slice(receipt.pre_state_root.as_bytes());
        material.extend_from_slice(receipt.post_state_root.as_bytes());
        for log in &receipt.logs {
            material.extend_from_slice(log.as_bytes());
        }
    }
    Ok(Hash::from_domain_bytes(
        "SYNERGY_GENESIS_RECEIPT_ROOT_V1",
        &material,
    ))
}

/// Every launch-critical initialization call, in a fixed order.
///
/// These run inside the same overlay as the deployments because each one is
/// load-bearing: Treasury is inert until its five signers exist, and any
/// reserved name not seeded before the network opens is claimable by the first
/// registrant.
fn run_initialization_sequence(
    working: &mut ExecutionState,
    plan: &GenesisDeploymentPlan,
    addresses: &BTreeMap<GenesisContract, String>,
    synq_addresses: &BTreeMap<GenesisContract, SynQAddress>,
    authorities: &GenesisAuthorities,
    parameters: &GenesisParameters,
) -> Result<Vec<SynQAivmReceiptSummary>, String> {
    let artifact_for = |contract: GenesisContract| -> Result<SynQContractArtifact, String> {
        plan.entries
            .iter()
            .find(|entry| entry.contract == contract)
            .map(|entry| entry.artifact.clone())
            .ok_or_else(|| format!("plan has no artifact for {}", contract.name()))
    };
    let address_for = |contract: GenesisContract| -> Result<String, String> {
        addresses
            .get(&contract)
            .cloned()
            .ok_or_else(|| format!("{} was not deployed", contract.name()))
    };
    let synq_for = |contract: GenesisContract| -> Result<SynQAddress, String> {
        synq_addresses
            .get(&contract)
            .copied()
            .ok_or_else(|| format!("{} has no SynQ address", contract.name()))
    };

    let mut receipts = Vec::new();
    // Call-envelope nonces are per-signer and must never repeat. Deployments
    // consumed 0..=8 under the deployer, so initialization continues from there.
    let mut deployer_call_nonce: u64 = plan.entries.len() as u64;
    let mut governance_call_nonce: u64 = 0;
    // Per-contract governance nonces, matching the protocol-owned counters.
    let mut governance_nonces: BTreeMap<GenesisContract, u128> = BTreeMap::new();

    // --- Treasury: five signers -------------------------------------------
    let treasury_artifact = artifact_for(GenesisContract::Treasury)?;
    let treasury_address = address_for(GenesisContract::Treasury)?;
    let treasury_synq = synq_for(GenesisContract::Treasury)?;
    if parameters.treasury_signers.len() != 5 {
        return Err(format!(
            "Treasury genesis initialization requires exactly five signers, found {}",
            parameters.treasury_signers.len()
        ));
    }
    let mut unique_signers = std::collections::BTreeSet::new();
    for signer in &parameters.treasury_signers {
        if !unique_signers.insert(signer.clone()) {
            return Err(format!("Treasury signer {signer} is duplicated"));
        }
    }
    if parameters.treasury_required_signers != "4" {
        return Err(format!(
            "Treasury threshold must be 4, found {}",
            parameters.treasury_required_signers
        ));
    }
    for signer in &parameters.treasury_signers {
        let nonce = governance_nonces
            .entry(GenesisContract::Treasury)
            .or_insert(0);
        let args = governance_tail(
            &authorities.governance,
            &treasury_artifact,
            &treasury_address,
            "setSigner",
            &[
                serde_json::Value::String(signer.clone()),
                serde_json::Value::Bool(true),
            ],
            *nonce,
        )?;
        receipts.push(call_one(
            working,
            &treasury_artifact,
            &treasury_address,
            treasury_synq,
            "setSigner",
            args,
            &authorities.governance,
            governance_call_nonce,
        )?);
        *nonce += 1;
        governance_call_nonce += 1;
    }

    // --- Identity: six reserved names -------------------------------------
    let identity_artifact = artifact_for(GenesisContract::Identity)?;
    let identity_address = address_for(GenesisContract::Identity)?;
    let identity_synq = synq_for(GenesisContract::Identity)?;
    if parameters.identity_reserved_names.len() != 6 {
        return Err(format!(
            "Identity genesis initialization requires exactly six reserved names, found {}",
            parameters.identity_reserved_names.len()
        ));
    }
    for name in &parameters.identity_reserved_names {
        let nonce = governance_nonces
            .entry(GenesisContract::Identity)
            .or_insert(0);
        let canonical_hash = synid_name_hash(name);
        let args = governance_tail(
            &authorities.governance,
            &identity_artifact,
            &identity_address,
            "setReservedName",
            &[
                serde_json::Value::String(name.clone()),
                serde_json::Value::String(canonical_hash),
                serde_json::Value::Bool(true),
            ],
            *nonce,
        )?;
        receipts.push(call_one(
            working,
            &identity_artifact,
            &identity_address,
            identity_synq,
            "setReservedName",
            args,
            &authorities.governance,
            governance_call_nonce,
        )?);
        *nonce += 1;
        governance_call_nonce += 1;
    }

    // --- ValidatorRegistry: register and activate the five Genesis validators
    // These are authority-gated (`msg.sender == authority`), not
    // governance-signed, so they are issued by the dedicated registry authority.
    let registry_artifact = artifact_for(GenesisContract::ValidatorRegistry)?;
    let registry_address = address_for(GenesisContract::ValidatorRegistry)?;
    let registry_synq = synq_for(GenesisContract::ValidatorRegistry)?;
    let registry_authority = GenesisSigner {
        public_key: authorities
            .validator_registry_authority_key
            .public_key
            .clone(),
        private_key: authorities
            .validator_registry_authority_key
            .private_key
            .clone(),
        identity_authorization: authorities
            .validator_registry_authority_key
            .identity_authorization
            .clone(),
    };
    let mut registry_call_nonce: u64 = 0;
    for validator in &parameters.validators {
        receipts.push(call_one(
            working,
            &registry_artifact,
            &registry_address,
            registry_synq,
            "registerValidator",
            vec![
                serde_json::Value::String(validator.id_hash.clone()),
                serde_json::Value::String(validator.operator_address.clone()),
                serde_json::Value::String(validator.reward_address.clone()),
                serde_json::Value::String(validator.voting_power.clone()),
                serde_json::Value::String(validator.self_stake_nwei.clone()),
                serde_json::Value::String(validator.metadata_hash.clone()),
                serde_json::Value::String(validator.key_bundle_hash.clone()),
            ],
            &registry_authority,
            registry_call_nonce,
        )?);
        registry_call_nonce += 1;
    }
    for validator in &parameters.validators {
        receipts.push(call_one(
            working,
            &registry_artifact,
            &registry_address,
            registry_synq,
            "activateValidator",
            vec![
                serde_json::Value::String(validator.operator_address.clone()),
                serde_json::Value::String(validator.activation_height.clone()),
            ],
            &registry_authority,
            registry_call_nonce,
        )?);
        registry_call_nonce += 1;
    }

    // --- SynergyOracle: publisher and accepted source domains -------------
    let oracle_artifact = artifact_for(GenesisContract::SynergyOracle)?;
    let oracle_address = address_for(GenesisContract::SynergyOracle)?;
    let oracle_synq = synq_for(GenesisContract::SynergyOracle)?;
    {
        let nonce = governance_nonces
            .entry(GenesisContract::SynergyOracle)
            .or_insert(0);
        let args = governance_tail(
            &authorities.governance,
            &oracle_artifact,
            &oracle_address,
            "setOracle",
            &[
                serde_json::Value::String(authorities.oracle_publisher.clone()),
                serde_json::Value::Bool(true),
            ],
            *nonce,
        )?;
        receipts.push(call_one(
            working,
            &oracle_artifact,
            &oracle_address,
            oracle_synq,
            "setOracle",
            args,
            &authorities.governance,
            governance_call_nonce,
        )?);
        *nonce += 1;
        governance_call_nonce += 1;
    }
    for domain in &parameters.oracle_source_domains {
        let nonce = governance_nonces
            .entry(GenesisContract::SynergyOracle)
            .or_insert(0);
        let args = governance_tail(
            &authorities.governance,
            &oracle_artifact,
            &oracle_address,
            "setSourceDomain",
            &[
                serde_json::Value::String(domain.clone()),
                serde_json::Value::Bool(true),
            ],
            *nonce,
        )?;
        receipts.push(call_one(
            working,
            &oracle_artifact,
            &oracle_address,
            oracle_synq,
            "setSourceDomain",
            args,
            &authorities.governance,
            governance_call_nonce,
        )?);
        *nonce += 1;
        governance_call_nonce += 1;
    }

    let _ = deployer_call_nonce;
    deployer_call_nonce += 1;
    let _ = deployer_call_nonce;

    Ok(receipts)
}

/// SynID canonical name hash, matching the `synidNameHash` host function.
fn synid_name_hash(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"SYNERGY_SYNID_NAME_V1");
    hasher.update(name.to_ascii_lowercase().as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Reads back the contract state the initialization calls were supposed to
/// produce. A deployment that "succeeded" but left Treasury unusable or the
/// name space unprotected must not commit.
fn verify_initialization_state(
    working: &ExecutionState,
    addresses: &BTreeMap<GenesisContract, String>,
    parameters: &GenesisParameters,
) -> Result<(), String> {
    let treasury = addresses
        .get(&GenesisContract::Treasury)
        .ok_or_else(|| "Treasury was not deployed".to_string())?;
    let signer_count = read_contract_uint(working, treasury, "signerCount")?;
    if signer_count != 5 {
        return Err(format!(
            "Treasury genesis initialization left signerCount = {signer_count}, expected 5"
        ));
    }
    let required = read_contract_uint(working, treasury, "requiredSigners")?;
    if required != 4 {
        return Err(format!("Treasury requiredSigners = {required}, expected 4"));
    }

    let registry = addresses
        .get(&GenesisContract::ValidatorRegistry)
        .ok_or_else(|| "ValidatorRegistry was not deployed".to_string())?;
    let validator_count = read_contract_uint(working, registry, "validatorCount")?;
    if validator_count != parameters.validators.len() as u128 {
        return Err(format!(
            "ValidatorRegistry validatorCount = {validator_count}, expected {}",
            parameters.validators.len()
        ));
    }
    Ok(())
}

/// Reads a public scalar from a deployed contract's AIVM storage.
fn read_contract_uint(
    state: &ExecutionState,
    contract_address: &str,
    field: &str,
) -> Result<u128, String> {
    // The AIVM keys contract storage by (contract_id, "synq-v2:<field>").
    let key = StateKey::new(
        contract_address.as_bytes().to_vec(),
        format!("synq-v2:{field}").into_bytes(),
    );
    let raw = state
        .synq_aivm_state
        .get(&key)
        .ok_or_else(|| format!("{contract_address}.{field} is not present in AIVM state"))?;
    let value: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|error| format!("decode {contract_address}.{field}: {error}"))?;
    value
        .get("value")
        .and_then(|inner| inner.as_u64())
        .map(u128::from)
        .or_else(|| value.as_u64().map(u128::from))
        .ok_or_else(|| format!("{contract_address}.{field} is not an unsigned integer: {value}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn staged_artifact(contract: GenesisContract) -> SynQContractArtifact {
        let dir = repo_root().join("genesis-contracts/contracts");
        let name = contract.name();
        let read = |ext: &str| {
            let path = dir.join(format!("{name}.{ext}"));
            assert!(
                path.is_file(),
                "approved test artifact triple is missing {}",
                path.display()
            );
            std::fs::read(&path)
                .unwrap_or_else(|e| panic!("read approved test artifact {}: {e}", path.display()))
        };
        SynQContractArtifact::new(
            read("compiled.synq"),
            String::from_utf8(read("abi.json")).unwrap(),
            String::from_utf8(read("manifest.json")).unwrap(),
        )
    }

    pub(crate) fn staged_plan() -> GenesisDeploymentPlan {
        let artifacts = GenesisContract::APPROVED_ORDER
            .iter()
            .map(|contract| (*contract, staged_artifact(*contract)))
            .collect();
        GenesisDeploymentPlan::new(&artifacts).expect("staged plan")
    }

    /// Frozen test-only authorities. Generated once and checked in precisely so
    /// that addresses, receipts and roots reproduce across runs and machines.
    fn test_signer_with_scopes(
        role: &str,
        authorization_scopes: &[crate::identity_auth::AuthorizationScope],
    ) -> GenesisSigner {
        let path = repo_root().join("runtime/fixtures/genesis-deployment-test-authorities.json");
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read authority fixture"))
                .expect("parse authority fixture");
        assert_eq!(doc["fixture"], "TEST_FIXTURE_NOT_FOR_PRODUCTION");
        let entry = doc["authorities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["role"] == role)
            .unwrap_or_else(|| panic!("fixture has no role {role}"));
        let public_key = hex::decode(entry["public_key_hex"].as_str().unwrap()).unwrap();
        let private_key = hex::decode(entry["private_key_hex"].as_str().unwrap()).unwrap();
        let mut manager = crate::crypto::pqc::PQCManager::new();
        let (identity_public, identity_private) = manager
            .generate_keypair(crate::crypto::pqc::PQCAlgorithm::FNDSA)
            .expect("test identity keypair");
        let authorization_public = crate::crypto::pqc::PQCPublicKey {
            algorithm: crate::crypto::pqc::PQCAlgorithm::MLDSA87,
            key_data: public_key.clone(),
            key_id: format!("test-genesis-{role}"),
            created_at: 0,
        };
        let authorization_private = crate::crypto::pqc::PQCPrivateKey {
            algorithm: crate::crypto::pqc::PQCAlgorithm::MLDSA87,
            key_data: private_key.clone(),
            public_key_id: authorization_public.key_id.clone(),
            created_at: 0,
        };
        let binding = crate::identity_auth::create_single_key_binding_with_scopes(
            role,
            "syna",
            &identity_public,
            &identity_private,
            "genesis-key",
            &authorization_public,
            &authorization_private,
            authorization_scopes,
            "2026-08-22T00:00:00Z",
        )
        .expect("test genesis identity binding");
        GenesisSigner {
            public_key,
            private_key,
            identity_authorization: Some(
                crate::identity_auth::IdentityAuthorizationCarrier::new(
                    crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                    binding,
                )
                .expect("test genesis identity carrier"),
            ),
        }
    }

    fn test_signer(role: &str) -> GenesisSigner {
        test_signer_with_scopes(
            role,
            &[crate::identity_auth::AuthorizationScope::testnet(
                crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                "genesis-signing",
            )],
        )
    }

    fn test_deploy_signer(role: &str) -> GenesisSigner {
        test_signer_with_scopes(
            role,
            &[
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                    "genesis-signing",
                ),
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
                    SYNQ_DEPLOY_AUTHORIZATION_PURPOSE,
                ),
            ],
        )
    }

    fn test_call_signer(role: &str) -> GenesisSigner {
        test_signer_with_scopes(
            role,
            &[
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                    "genesis-signing",
                ),
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
                    SYNQ_CALL_AUTHORIZATION_PURPOSE,
                ),
            ],
        )
    }

    pub(crate) fn test_authorities() -> GenesisAuthorities {
        let registry = test_call_signer("validator_registry_authority");
        let registry_address = registry
            .account_address()
            .expect("test fixture signer produces a valid canonical address");
        GenesisAuthorities {
            genesis_deployer: test_deploy_signer("genesis_deployer"),
            governance: test_call_signer("governance_authority"),
            emergency_slashing_authority: test_signer("emergency_slashing_authority")
                .account_address()
                .expect("test fixture signer produces a valid canonical address"),
            validator_registry_authority: registry_address,
            validator_registry_authority_key: registry,
            reward_distributor_authority: test_signer("reward_distributor_authority")
                .account_address()
                .expect("test fixture signer produces a valid canonical address"),
            identity_fee_collector: "synf1genesisfeecollectortestfixture".to_string(),
            team_vesting_admin: "synu1teamvestingadmintestfixture".to_string(),
            oracle_publisher: test_signer("oracle_publisher")
                .account_address()
                .expect("test fixture signer produces a valid canonical address"),
        }
    }

    fn test_validator(index: usize) -> GenesisValidator {
        GenesisValidator {
            id_hash: format!("0x{:064x}", index + 1),
            operator_address: format!("synv1testvalidator{index}"),
            reward_address: format!("synv1testvalidator{index}"),
            voting_power: "100".to_string(),
            self_stake_nwei: "50000000000000".to_string(),
            metadata_hash: format!("0x{:064x}", 0x1000 + index),
            key_bundle_hash: format!("0x{:064x}", 0x2000 + index),
            activation_height: "0".to_string(),
        }
    }

    /// Genesis values after the approved unit conversions.
    pub(crate) fn test_parameters() -> GenesisParameters {
        GenesisParameters {
            identity_registration_fee_nwei: "1000000".to_string(),
            identity_reserved_names: vec![
                "synergy".into(),
                "snrg".into(),
                "treasury".into(),
                "foundation".into(),
                "validator".into(),
                "oracle".into(),
            ],
            validator_max_count: "100".to_string(),
            validator_min_count: "4".to_string(),
            validator_min_self_stake_nwei: "50000000000000".to_string(),
            validators: (0..5).map(test_validator).collect(),
            staking_min_stake_nwei: "50000000000000".to_string(),
            staking_max_stake_nwei: "5000000000000000000".to_string(),
            staking_unbonding_blocks: "302400".to_string(),
            governance_quorum_bps: "6000".to_string(),
            governance_approval_bps: "5000".to_string(),
            governance_veto_bps: "3300".to_string(),
            governance_min_deposit_nwei: "1000000000000".to_string(),
            governance_voting_blocks: "302400".to_string(),
            governance_timelock_blocks: "43200".to_string(),
            treasury_required_signers: "4".to_string(),
            treasury_signers: vec![
                "synw1vtax0twlhhmcscut087zj8tum57rw02uvn7f".into(),
                "synw1zg0jxs9x6gc64x3y27uy8gww20jr2zjpp4lz".into(),
                "synw1764khnddfl7ld3cgrxgay9l3pd68uk9sartr".into(),
                "synw1s7caj8vx9r3qgddhuyljqlfuapkswjufjkzy".into(),
                "synw13qxuegekghf55s3tqjhktcvmyx8rxvhhj6rk".into(),
            ],
            slashing_double_sign_bps: "500".to_string(),
            slashing_downtime_bps: "100".to_string(),
            slashing_invalid_block_bps: "500".to_string(),
            slashing_missed_blocks_threshold: "50".to_string(),
            slashing_jail_blocks: "43200".to_string(),
            oracle_quorum_threshold: "1".to_string(),
            oracle_replay_protection: true,
            oracle_source_domains: vec![
                "ethereum-sepolia".into(),
                "solana-testnet".into(),
                "synergy-testbeta".into(),
            ],
            team_vesting_start_time: "1775044800".to_string(),
            team_allocation_nwei: "60000000000000000".to_string(),
            support_allocation_nwei: "10000000000000000".to_string(),
            team_count: "5".to_string(),
            support_count: "4".to_string(),
        }
    }

    #[test]
    fn approved_nonce_order_satisfies_the_dependency_graph() {
        staged_plan()
            .validate()
            .expect("approved order is topological");
    }

    #[test]
    fn a_plan_that_violates_the_dependency_graph_is_rejected_before_execution() {
        let mut plan = staged_plan();
        // Give Governance an earlier nonce than Staking, breaking
        // Governance -> Staking. Nonces stay a complete 0..=8 set, so this is
        // rejected by the dependency check specifically.
        let staking = plan.entries[2].contract;
        let governance = plan.entries[3].contract;
        plan.entries[2].contract = governance;
        plan.entries[3].contract = staking;
        let staking_artifact = plan.entries[2].artifact.clone();
        plan.entries[2].artifact = plan.entries[3].artifact.clone();
        plan.entries[3].artifact = staking_artifact;
        let error = plan.validate().expect_err("must reject");
        assert!(
            error.contains("dependency graph"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn genesis_deployment_succeeds_and_reproduces_addresses_and_state_root() {
        let plan = staged_plan();
        let authorities = test_authorities();
        let parameters = test_parameters();

        let mut first = ExecutionState::new();
        let a = execute_genesis_deployment(&mut first, &plan, &authorities, &parameters)
            .expect("first genesis deployment");

        let mut second = ExecutionState::new();
        let b = execute_genesis_deployment(&mut second, &plan, &authorities, &parameters)
            .expect("second genesis deployment");

        assert_eq!(a.addresses.len(), 9, "nine contracts deployed");
        assert_eq!(a.addresses, b.addresses, "addresses reproduce");
        assert_eq!(
            a.post_deployment_state_root, b.post_deployment_state_root,
            "post-deployment AIVM state root reproduces"
        );
        assert_eq!(a.receipt_root, b.receipt_root, "receipt root reproduces");
        assert_eq!(
            a.deployment_manifest_hash, b.deployment_manifest_hash,
            "deployment manifest hash reproduces"
        );
        let snapshot = crate::execution::GenesisExecutionSnapshot::capture_testnet_v3(&first)
            .expect("capture deployed Genesis execution state");
        let snapshot_bytes =
            serde_json::to_vec(&snapshot).expect("deployed Genesis snapshot is valid JSON");
        let restored: crate::execution::GenesisExecutionSnapshot =
            serde_json::from_slice(&snapshot_bytes).expect("decode deployed Genesis snapshot");
        assert_eq!(
            compute_state_root_after(
                &restored
                    .restore_testnet_v3()
                    .expect("restore deployed Genesis execution state")
            )
            .expect("restored deployed state root"),
            a.post_deployment_state_root
        );

        // Every address is distinct.
        let unique: std::collections::BTreeSet<_> = a.addresses.values().collect();
        assert_eq!(unique.len(), 9, "no two contracts share an address");

        // 9 deployments; 5 treasury signers + 6 reserved names + 12 validator
        // calls + 1 oracle + 3 source domains = 25 initialization calls.
        assert_eq!(a.deployment_receipts.len(), 9);
        assert_eq!(a.initialization_receipts.len(), 25);
        assert_eq!(a.lifecycle, GenesisDeployerLifecycle::PermanentlyRetired);

        let genesis_signers = [
            &authorities.genesis_deployer,
            &authorities.governance,
            &authorities.validator_registry_authority_key,
        ];
        assert_eq!(
            first.identity_authorization_bindings.len(),
            genesis_signers.len(),
            "every GenesisSigner binding is part of root-bearing execution state"
        );
        for signer in genesis_signers {
            let binding = &signer
                .identity_authorization
                .as_ref()
                .expect("test Genesis signer identity authorization")
                .binding;
            assert_eq!(
                first.current_identity_authorization_binding_hash(&binding.identity_address),
                Some(binding.binding_payload_sha3_256.as_str()),
                "Genesis snapshot must commit the signer's exact binding"
            );
        }

        for (contract, address) in &a.addresses {
            assert!(
                first.synq_contracts.contains_key(address),
                "{} missing from deployment records",
                contract.name()
            );
        }
    }

    #[test]
    fn zero_validator_maximum_is_unbounded_and_allows_a_post_genesis_admission() {
        let plan = staged_plan();
        let authorities = test_authorities();
        let mut parameters = test_parameters();
        // ABI zero is the canonical representation of the public Genesis
        // policy `max_validator_count: null`: a dynamic, uncapped set.
        parameters.validator_max_count = "0".to_string();

        let mut state = ExecutionState::new();
        let outcome = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect("unbounded registry accepts the five canonical Genesis validators");
        let registry_address = outcome.addresses[&GenesisContract::ValidatorRegistry].clone();
        assert_eq!(
            read_contract_uint(&state, &registry_address, "maxValidatorCount").unwrap(),
            0,
            "Genesis preserves the zero/unbounded ABI sentinel"
        );
        assert_eq!(
            read_contract_uint(&state, &registry_address, "validatorCount").unwrap(),
            5,
            "the canonical Genesis contains exactly validators 02 through 06"
        );

        let derived = derive_genesis_addresses(
            &plan,
            &authorities.genesis_deployer.public_key,
            &authorities,
            &parameters,
        )
        .expect("derive Genesis contract addresses");
        let registry_synq: SynQAddress = serde_json::from_value(serde_json::Value::String(
            derived
                .iter()
                .find(|entry| entry.contract == "ValidatorRegistry")
                .expect("registry address")
                .synq_contract_address
                .clone(),
        ))
        .expect("decode registry SynQ address");
        let later = test_validator(5);
        call_one(
            &mut state,
            &staged_artifact(GenesisContract::ValidatorRegistry),
            &registry_address,
            registry_synq,
            "registerValidator",
            vec![
                serde_json::Value::String(later.id_hash),
                serde_json::Value::String(later.operator_address),
                serde_json::Value::String(later.reward_address),
                serde_json::Value::String(later.voting_power),
                serde_json::Value::String(later.self_stake_nwei),
                serde_json::Value::String(later.metadata_hash),
                serde_json::Value::String(later.key_bundle_hash),
            ],
            &authorities.validator_registry_authority_key,
            50,
        )
        .expect("a sixth validator is admitted under the unbounded policy");
        assert_eq!(
            read_contract_uint(&state, &registry_address, "validatorCount").unwrap(),
            6
        );
    }

    #[test]
    fn nonzero_validator_maximum_remains_a_hard_membership_limit() {
        let plan = staged_plan();
        let authorities = test_authorities();
        let mut parameters = test_parameters();
        parameters.validator_max_count = "5".to_string();
        parameters.validators.push(test_validator(5));

        let mut state = ExecutionState::new();
        let error = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect_err("a sixth validator must exceed a nonzero maximum");
        assert!(error.contains("Validator limit reached"), "unexpected error: {error}");
        assert!(state.synq_contracts.is_empty(), "failed Genesis remains atomic");
    }

    #[test]
    fn genesis_rejects_conflicting_preexisting_identity_binding_without_committing() {
        let plan = staged_plan();
        let authorities = test_authorities();
        let parameters = test_parameters();
        let binding = &authorities
            .genesis_deployer
            .identity_authorization
            .as_ref()
            .expect("deployer carrier")
            .binding;

        let mut state = ExecutionState::new();
        state.identity_authorization_bindings.insert(
            binding.identity_address.clone(),
            crate::execution::IdentityAuthorizationBindingCommitment {
                binding_payload_sha3_256: "00".repeat(32),
                identity_root_public_key_sha3_256: binding
                    .identity_root
                    .public_key_sha3_256
                    .clone(),
                effective_at_unix: 0,
            },
        );
        let baseline = state.clone();

        let error = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect_err("conflicting Genesis binding must fail closed");
        assert!(
            error.contains("conflicting identity authorization bindings"),
            "unexpected error: {error}"
        );
        assert_eq!(
            state, baseline,
            "the conflicting deployment must not commit"
        );
    }

    #[test]
    fn genesis_synq_requires_the_exact_root_signed_scope() {
        let call_only = test_signer_with_scopes(
            "genesis_deployer",
            &[
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::GENESIS_CEREMONY_AUTHORIZATION_DOMAIN,
                    "genesis-signing",
                ),
                crate::identity_auth::AuthorizationScope::testnet(
                    crate::identity_auth::SYNQ_ADMISSION_AUTHORIZATION_DOMAIN,
                    SYNQ_CALL_AUTHORIZATION_PURPOSE,
                ),
            ],
        );

        call_only
            .synq_identity_authorization(SYNQ_CALL_AUTHORIZATION_PURPOSE)
            .expect("the separately signed call scope is accepted");
        let error = call_only
            .synq_identity_authorization(SYNQ_DEPLOY_AUTHORIZATION_PURPOSE)
            .expect_err("an absent deploy scope must not be synthesized by carrier relabelling");
        assert!(
            error.contains("does not explicitly authorize SynQ purpose 'synq-contract-deploy'")
                && (error.contains("does not grant signed scope")
                    || error.contains("is not actively bound for purpose")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_failure_rolls_back_every_deployment_and_initialization() {
        let plan = staged_plan();
        let authorities = test_authorities();

        // Treasury requires exactly five signers. Six fails validation *after*
        // all nine contracts have deployed and Identity/Treasury work has begun.
        let mut parameters = test_parameters();
        parameters
            .treasury_signers
            .push("synw1extrasignerbreakstheinvariant".to_string());

        let baseline = ExecutionState::new();
        let baseline_root = compute_state_root_after(&baseline).expect("baseline root");

        let mut state = baseline.clone();
        let error = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect_err("must fail");
        assert!(error.contains("five signers"), "unexpected error: {error}");

        // Nothing committed: no contracts, no artifacts, no lifecycle change,
        // and the state root is byte-identical to the original.
        assert!(state.synq_contracts.is_empty(), "no contracts committed");
        assert!(state.synq_artifacts.is_empty(), "no artifacts committed");
        assert!(
            state.synq_verifications.is_empty(),
            "no verifications committed"
        );
        assert_eq!(
            read_deployer_lifecycle(&state).unwrap(),
            GenesisDeployerLifecycle::Uninitialized,
            "deployer lifecycle unchanged"
        );
        assert_eq!(
            compute_state_root_after(&state).expect("rolled back root"),
            baseline_root,
            "state root is byte-identical after rollback"
        );
    }

    #[test]
    fn the_genesis_deployer_is_retired_and_cannot_deploy_again() {
        let plan = staged_plan();
        let authorities = test_authorities();
        let parameters = test_parameters();

        let mut state = ExecutionState::new();
        let outcome = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect("genesis deployment");
        assert_eq!(
            outcome.lifecycle,
            GenesisDeployerLifecycle::PermanentlyRetired
        );
        assert_eq!(
            read_deployer_lifecycle(&state).unwrap(),
            GenesisDeployerLifecycle::PermanentlyRetired
        );
        assert_eq!(
            read_deployment_manifest_hash(&state),
            Some(outcome.deployment_manifest_hash),
            "the executed manifest is recorded in protocol state"
        );

        // Running genesis again — same plan, same manifest, same deployer —
        // is refused by protocol state, not by key custody.
        let replay = execute_genesis_deployment(&mut state, &plan, &authorities, &parameters)
            .expect_err("replay must fail");
        assert!(
            replay.contains("already ran") && replay.contains("PermanentlyRetired"),
            "unexpected replay error: {replay}"
        );

        // A tenth deployment is refused for the same reason, and the plan
        // validator refuses it structurally as well.
        let mut tenth = plan.clone();
        tenth.entries.push(GenesisPlanEntry {
            nonce: 9,
            contract: GenesisContract::Identity,
            artifact: staged_artifact(GenesisContract::Identity),
        });
        assert!(tenth.validate().is_err(), "a tenth deployment is rejected");
    }
}

#[cfg(test)]
mod evidence {
    use super::tests_support::run_reference_deployment;

    /// Prints the derived test-fixture addresses and roots. Not an assertion —
    /// it exists so the values can be captured for the handoff record.
    #[test]
    fn print_genesis_deployment_evidence() {
        let (outcome, _state) = run_reference_deployment();
        println!("=== NINE TEST-DERIVED CONTRACT ADDRESSES ===");
        for (contract, address) in &outcome.addresses {
            println!("{:<20} {}", contract.name(), address);
        }
        println!("=== ROOTS ===");
        println!(
            "post_deployment_state_root  {}",
            outcome.post_deployment_state_root.to_hex()
        );
        println!(
            "receipt_root                {}",
            outcome.receipt_root.to_hex()
        );
        println!(
            "deployment_manifest_hash    {}",
            outcome.deployment_manifest_hash.to_hex()
        );
        println!(
            "deployment_receipts         {}",
            outcome.deployment_receipts.len()
        );
        println!(
            "initialization_receipts     {}",
            outcome.initialization_receipts.len()
        );
        println!("lifecycle                   {:?}", outcome.lifecycle);
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;

    pub fn run_reference_deployment() -> (GenesisDeploymentOutcome, ExecutionState) {
        let mut state = ExecutionState::new();
        let outcome = execute_genesis_deployment(
            &mut state,
            &super::tests::staged_plan(),
            &super::tests::test_authorities(),
            &super::tests::test_parameters(),
        )
        .expect("reference genesis deployment");
        (outcome, state)
    }
}

// ---------------------------------------------------------------------------
// Address derivation from public inputs only
// ---------------------------------------------------------------------------

/// The published derivation record for one contract.
#[derive(Debug, Clone, Serialize)]
pub struct DerivedContractAddress {
    pub nonce: u64,
    pub contract: String,
    pub deployer_address: String,
    pub payload_hash: String,
    pub constructor_args_hash: String,
    pub bytecode_hash: String,
    pub abi_hash: String,
    pub manifest_hash: String,
    pub contract_address: String,
    pub synq_contract_address: String,
}

/// Derives all nine contract addresses dependency-first **without any private
/// key**. A deploy address is a function of public inputs only — the signature
/// authorizes execution, it does not feed the address — so the full set can be
/// published and independently reproduced before any custody ceremony signs.
pub fn derive_genesis_addresses(
    plan: &GenesisDeploymentPlan,
    deployer_public_key: &[u8],
    authorities: &GenesisAuthorities,
    parameters: &GenesisParameters,
) -> Result<Vec<DerivedContractAddress>, String> {
    plan.validate()?;
    let deployer_signer = GenesisSigner {
        public_key: deployer_public_key.to_vec(),
        private_key: Vec::new(),
        identity_authorization: authorities.genesis_deployer.identity_authorization.clone(),
    };
    let deployer_address = deployer_signer.synq_address()?;
    let deployer_account = deployer_signer.account_address()?;
    let mut resolved: BTreeMap<GenesisContract, String> = BTreeMap::new();
    let mut out = Vec::new();

    for entry in &plan.entries {
        let constructor_args =
            constructor_arguments(entry.contract, authorities, parameters, &resolved)?;
        let constructor_args_hash = sha256_array(&constructor_args);
        let key = entry.artifact.key();
        let payload_hash = hash_contract_deploy_body(
            &key.bytecode_hash,
            &key.manifest_hash,
            &key.abi_hash,
            deployer_address.as_bytes(),
            &constructor_args_hash,
        );
        // Derivation reads only the signing payload and the artifact hashes.
        let envelope = ContractDeployEnvelope {
            signing_payload: signing_payload(
                DomainTag::SynqContractDeployV1,
                SignaturePurpose::ContractDeploy,
                deployer_address,
                payload_hash,
                entry.nonce + 1,
            ),
            public_key: SynQPublicKey::new(deployer_public_key.to_vec()),
            signature: SynQSignature::new(Vec::new()),
            bytecode_hash: key.bytecode_hash,
            manifest_hash: key.manifest_hash,
            abi_hash: key.abi_hash,
            constructor_args_hash,
        };
        let synq_address =
            crate::synq_execution::derive_synq_contract_address_from_deploy_with_identity_address(
                &envelope,
                &deployer_account,
            )?;
        let contract_address =
            crate::synq_execution::derive_synergy_contract_address_from_deploy_with_identity_address(
                &envelope,
                &deployer_account,
            )?;

        resolved.insert(entry.contract, contract_address.clone());
        out.push(DerivedContractAddress {
            nonce: entry.nonce,
            contract: entry.contract.name().to_string(),
            deployer_address: deployer_account.to_string(),
            payload_hash: hex::encode(payload_hash),
            constructor_args_hash: hex::encode(constructor_args_hash),
            bytecode_hash: hex::encode(key.bytecode_hash),
            abi_hash: hex::encode(key.abi_hash),
            manifest_hash: hex::encode(key.manifest_hash),
            contract_address,
            synq_contract_address: hex::encode(synq_address.as_bytes()),
        });
    }
    Ok(out)
}
