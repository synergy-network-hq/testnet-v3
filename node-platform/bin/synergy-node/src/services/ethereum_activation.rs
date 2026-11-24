//! Same-Genesis activation through the existing native governance executor.
//! Supplied constitutions never select the actual PoSy signer/weight threshold.
use super::authority::{EthereumGenesisAuthority, VerifiedAuthority};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use synergy_aivm::ethereum_execution::{EvmCompatibilityPolicy, EVM_POLICY_KEY};
use synergy_governance::{GovernanceExecution, VoteChoice, VoteVerifier};
use synergy_state::{world_resources::WorldResourceBudget, ProtocolChange, StateDiff, WorldState};

pub(super) use synergy_governance::{
    EthereumActivationSpec, ETHEREUM_ACTIVATION_ACTION_V1 as ACTION,
    ETHEREUM_ACTIVATION_HISTORY_WARMUP_BLOCKS as HISTORY_WARMUP_BLOCKS,
    ETHEREUM_ACTIVATION_RECORD_KEY_V1 as RECORD_KEY, ETHEREUM_ACTIVATION_TARGET_V1 as TARGET,
};
pub(super) const ACTIVE_KEY: &str = "aivm/ethereum/v1/activation";
const MAX_RECORD: usize = 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernedRecord {
    schema_version: u32,
    included_height: u64,
    execution: GovernanceExecution,
}
#[derive(Debug, Clone)]
pub(super) struct CachedActivation {
    record_sha256: [u8; 32],
    authority: EthereumGenesisAuthority,
}

pub(super) fn genesis_hash(authority: &VerifiedAuthority) -> Result<&str, String> {
    authority.authenticated_genesis_hash()
}
pub(super) fn cached_authority(cached: &CachedActivation) -> EthereumGenesisAuthority {
    cached.authority.clone()
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    synergy_aegis::AegisProtectedPrimitives.sha256(bytes)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify_execution(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
    height: u64,
) -> Result<EthereumActivationSpec, String> {
    if execution.mutation.action_kind != ACTION
        || execution.mutation.target != TARGET
        || execution.mutation.expected_value.is_some()
        || execution.proposal.actions.len() != 1
        || execution.mutation.value.len() > 32768
    {
        return Err("EVM installation must be one exact unused canonical governance action".into());
    }
    let spec: EthereumActivationSpec =
        serde_json::from_slice(&execution.mutation.value).map_err(|error| error.to_string())?;
    if spec.canonical_bytes()? != execution.mutation.value
        || spec.schema_version != 1
        || spec.profile_id != synergy_genesis::network::ETHEREUM_COMPATIBILITY_PROFILE_V1
        || spec.chain_id != authority.epoch.chain_id
        || spec.network_id != authority.epoch.network_id
        || spec.genesis_hash != genesis_hash(authority)?
        || spec.install_height > height
        || height > execution.proposal.expires_at_height
        || !authority.epoch.contains_height(spec.install_height)
        || execution.proposal.expires_at_height > authority.epoch.epoch_end_height
        || spec.frozen_epoch != authority.epoch.epoch
        || spec.frozen_epoch_context_root
            != authority.epoch.root().map_err(|error| error.to_string())?
        || spec.policy_bytes.is_empty()
        || spec.policy_bytes.len() > 16384
        || spec.activation_height
            < execution
                .proposal
                .expires_at_height
                .checked_add(HISTORY_WARMUP_BLOCKS)
                .ok_or("EVM activation height overflow")?
    {
        return Err("EVM installation differs from frozen chain/Genesis/epoch/height or required history warmup".into());
    }
    if !authority.autonomous_epochs_enabled() {
        return Err(
            "EVM installation requires the authenticated autonomous processing architecture".into(),
        );
    }
    let policy: EvmCompatibilityPolicy =
        serde_json::from_slice(&spec.policy_bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&policy).map_err(|error| error.to_string())? != spec.policy_bytes
        || policy.chain_id != spec.chain_id
        || hex(&digest(&spec.policy_bytes)) != spec.policy_sha256
    {
        return Err("EVM installation policy bytes/digest/chain differ".into());
    }
    let mut policy_world = WorldState::default();
    policy_world
        .protocol
        .insert(EVM_POLICY_KEY.into(), spec.policy_bytes.clone());
    EvmCompatibilityPolicy::load(&policy_world).map_err(|error| error.to_string())?;
    if execution.votes.len() > authority.registry.quorum_validators().len() {
        return Err("EVM governance vote count exceeds frozen membership".into());
    }
    // This checks signatures and the existing proposal/payload/height contract.
    // Its caller-supplied Constitution is not the independent quorum authority.
    if execution.verify(
        authority,
        &execution.authorization_root,
        spec.install_height,
    )? != RECORD_KEY
    {
        return Err("EVM governance key differs".into());
    }
    let mut signers = Vec::with_capacity(execution.votes.len());
    for vote in &execution.votes {
        if vote.choice != VoteChoice::Approve {
            return Err("EVM governance requires approvals".into());
        }
        authority.verify(vote)?;
        signers.push(vote.authority_id.clone());
    }
    synergy_posy::verify_strict_dual_quorum(&authority.registry.quorum_validators(), &signers)
        .map_err(|error| {
            format!("EVM governance lacks actual frozen distinct/weighted dual quorum: {error:?}")
        })?;
    Ok(spec)
}

pub(super) fn install(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
    height: u64,
    world: &WorldState,
) -> Result<StateDiff, String> {
    if authority.ethereum_genesis().is_some()
        || world.protocol.contains_key(RECORD_KEY)
        || world.protocol.contains_key(EVM_POLICY_KEY)
        || world.protocol.contains_key(ACTIVE_KEY)
    {
        return Err(
            "EVM policy already exists; initial installation cannot replace or replay it".into(),
        );
    }
    let request = authorize_request(authority, execution)?;
    let frozen = authority
        .authenticated_history_ref_at(request.install_height)
        .ok_or("EVM frozen authority unavailable")?;
    let spec = verify_execution(frozen, execution, height)?;
    let bytes = serde_json::to_vec(&GovernedRecord {
        schema_version: 1,
        included_height: height,
        execution: execution.clone(),
    })
    .map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RECORD {
        return Err("EVM governance record exceeds bound".into());
    }
    Ok(StateDiff {
        changes: Vec::new(),
        protocol_changes: vec![
            ProtocolChange {
                key: RECORD_KEY.into(),
                expected_value: None,
                value: Some(bytes),
            },
            ProtocolChange {
                key: EVM_POLICY_KEY.into(),
                expected_value: None,
                value: Some(spec.policy_bytes),
            },
        ],
    })
}

/// Only an already authenticated canonical World may enter this boundary.
/// Cold verification is prepaid; cached authority never grants record presence.
pub(super) fn resolve(
    authority: &VerifiedAuthority,
    world: &WorldState,
    budget: Option<&Arc<WorldResourceBudget>>,
) -> Result<Option<EthereumGenesisAuthority>, String> {
    let Some(bytes) = world.protocol.get(RECORD_KEY) else {
        return Ok(authority.ethereum_genesis().cloned());
    };
    if authority.ethereum_genesis().is_some() || bytes.len() > MAX_RECORD {
        return Err("conflicting or oversized EVM activation authority".into());
    }
    let hash = digest(bytes);
    if let Some(cached) = authority
        .ethereum_activation_cache
        .lock()
        .map_err(|_| "EVM activation cache poisoned")?
        .as_ref()
        .filter(|cached| cached.record_sha256 == hash)
        .cloned()
    {
        validate_policy(&cached.authority, world, authority)?;
        return Ok(Some(cached.authority));
    }
    let budget = budget.ok_or("EVM activation requires budgeted cold authority verification")?;
    let _scratch = budget
        .reserve(bytes.len() * 16 + 65536)
        .map_err(|error| error.to_string())?;
    let record: GovernedRecord =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if record.schema_version != 1
        || serde_json::to_vec(&record).map_err(|error| error.to_string())? != *bytes
    {
        return Err("EVM activation record is not canonical".into());
    }
    let install_height = record.included_height;
    let frozen = authority
        .authenticated_history_ref_at(install_height)
        .ok_or("EVM installation frozen authority is unavailable")?;
    let spec = verify_execution(frozen, &record.execution, install_height)?;
    let selected = EthereumGenesisAuthority {
        descriptor: synergy_genesis::network::GenesisEthereumCompatibility {
            profile_id: spec.profile_id,
            policy_sha256: spec.policy_sha256,
        },
        genesis_hash: spec.genesis_hash,
        activation_unix: frozen.consensus_timestamp_unix(install_height)?,
        activation_height: spec.activation_height,
        chain_id: spec.chain_id,
    };
    validate_policy(&selected, world, authority)?;
    *authority
        .ethereum_activation_cache
        .lock()
        .map_err(|_| "EVM activation cache poisoned")? = Some(CachedActivation {
        record_sha256: hash,
        authority: selected.clone(),
    });
    Ok(Some(selected))
}

pub(super) fn authorize_request(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
) -> Result<EthereumActivationSpec, String> {
    let height = match execution.activation.point {
        synergy_governance::ActivationPoint::FinalizedHeight { height } => height,
        _ => return Err("EVM governance requires a signed installation window".into()),
    };
    let frozen = authority
        .authenticated_history_ref_at(height)
        .ok_or("EVM governance frozen authority unavailable")?;
    verify_execution(frozen, execution, height)
}
pub(super) fn processing_transaction(
    authority: &VerifiedAuthority,
    transaction: &synergy_transaction::SignedTransaction,
) -> Result<Option<u64>, String> {
    if transaction.unsigned.class == synergy_transaction::TransactionClass::User {
        return Ok(None);
    }
    let synergy_transaction::TransactionAction::Governance {
        authorization_id,
        operation,
    } = transaction
        .unsigned
        .action()
        .map_err(|error| error.to_string())?
    else {
        return Err("only independently authorized EVM governance may use the native system processing class".into());
    };
    let execution: GovernanceExecution =
        serde_json::from_slice(&operation).map_err(|error| error.to_string())?;
    if authorization_id != execution.authorization_root {
        return Err("EVM governance authorization identity differs".into());
    }
    Ok(Some(
        authorize_request(authority, &execution)?.install_height,
    ))
}
pub(super) fn dispatch(
    authority: &VerifiedAuthority,
    execution: &GovernanceExecution,
    height: u64,
    world: &WorldState,
) -> Result<StateDiff, String> {
    let spec = authorize_request(authority, execution)?;
    if height < spec.install_height {
        return Err("EVM installation precedes signed window".into());
    }
    let outcome = if height > execution.proposal.expires_at_height {
        "expired"
    } else if authority.ethereum_genesis().is_some()
        || world.protocol.contains_key(RECORD_KEY)
        || world.protocol.contains_key(EVM_POLICY_KEY)
    {
        "already-installed"
    } else {
        return install(authority, execution, height, world);
    };
    let key = format!(
        "governance/aivm-ethereum-outcome-v1/{}",
        execution.proposal.proposal_root
    );
    if world.protocol.contains_key(&key) {
        return Ok(StateDiff::default());
    }
    let value = serde_json::to_vec(&(
        1u32,
        &spec.genesis_hash,
        &execution.authorization_root,
        height,
        outcome,
    ))
    .map_err(|error| error.to_string())?;
    Ok(StateDiff {
        changes: Vec::new(),
        protocol_changes: vec![ProtocolChange {
            key,
            expected_value: None,
            value: Some(value),
        }],
    })
}
fn validate_policy(
    selected: &EthereumGenesisAuthority,
    world: &WorldState,
    authority: &VerifiedAuthority,
) -> Result<(), String> {
    if selected.genesis_hash != genesis_hash(authority)?
        || selected.chain_id != authority.epoch.chain_id
        || world
            .protocol
            .get(EVM_POLICY_KEY)
            .is_none_or(|bytes| hex(&digest(bytes)) != selected.descriptor.policy_sha256)
    {
        return Err("EVM policy differs from authenticated governed authority".into());
    }
    Ok(())
}
pub(super) fn active_marker(selected: &EthereumGenesisAuthority) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        1u32,
        selected.chain_id,
        &selected.genesis_hash,
        selected.activation_height,
        &selected.descriptor.policy_sha256,
    ))
    .map_err(|error| error.to_string())
}
pub(super) fn is_active(
    selected: &EthereumGenesisAuthority,
    world: &WorldState,
) -> Result<bool, String> {
    if selected.activation_height == 0 {
        return Ok(true);
    }
    let expected = active_marker(selected)?;
    Ok(world.protocol.get(ACTIVE_KEY) == Some(&expected))
}
pub(super) fn authorization_root(world: &WorldState) -> String {
    let binding = world
        .protocol
        .get(synergy_identity::authorization::IDENTITY_AUTHORIZATION_BINDINGS_STATE_KEY)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let legacy = synergy_block::hash_block_bytes(binding);
    if !world.protocol.contains_key(RECORD_KEY) && !world.protocol.contains_key(ACTIVE_KEY) {
        return legacy;
    }
    let mut bytes = b"SYNERGY_NATIVE_EVM_AUTHORIZATION_ANCHOR_V1".to_vec();
    bytes.extend_from_slice(legacy.as_bytes());
    for key in [RECORD_KEY, ACTIVE_KEY] {
        match world.protocol.get(key) {
            Some(value) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest(value));
            }
            None => bytes.push(0),
        }
    }
    synergy_block::hash_block_bytes(&bytes)
}

/// Index only for an already authenticated canonical World. This does not
/// authenticate a policy or a quorum; resolve() owns that boundary. Both
/// installation and maturation change the frozen admission authorization root.
pub(super) fn authorization_update_height(world: &WorldState) -> Result<u64, String> {
    let mut height = synergy_identity::registration::authorization_update_height(&world.protocol)?;
    let mut installed = 0;
    if let Some(bytes) = world.protocol.get(RECORD_KEY) {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Index {
            schema_version: u32,
            included_height: u64,
            execution: serde::de::IgnoredAny,
        }
        if bytes.len() > MAX_RECORD {
            return Err("EVM authorization index exceeds bound".into());
        }
        let index: Index = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        let _ignored = index.execution;
        if index.schema_version != 1 || index.included_height == 0 {
            return Err("invalid EVM authorization installation index".into());
        }
        installed = index.included_height;
        height = height.max(installed);
    }
    if let Some(bytes) = world.protocol.get(ACTIVE_KEY) {
        if !world.protocol.contains_key(RECORD_KEY) || bytes.len() > 1024 {
            return Err("EVM activation index lacks bounded governed authority".into());
        }
        let (version, _chain, _genesis, effective, _policy): (u32, u64, String, u64, String) =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if version != 1 || effective == 0 || effective < installed {
            return Err("invalid EVM authorization effective-height index".into());
        }
        height = height.max(effective);
    }
    Ok(height)
}
