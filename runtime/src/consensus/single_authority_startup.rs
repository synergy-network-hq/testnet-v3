//! Verified consensus startup resolution for Chain 1266.
//!
//! The active consensus protocol is decided by the ML-DSA-87 signed
//! `DesiredStateV2` activation, and by nothing else. Local configuration, an
//! environment variable, an old V1 desired-state file, and the presence or
//! absence of P2P can all be wrong; none of them may select or deselect a
//! driver.
//!
//! Order is fixed:
//!   1. verify Genesis identity
//!   2. verify the canonical form of the desired state
//!   3. verify the ML-DSA-87 start authorization over the canonical payload
//!   4. verify release / chain / incarnation / namespace / authority binding
//!   5. branch by the signed consensus binding
//!   6. only then apply protocol-specific preflight
//!
//! `single_authority_v1` has no peers, so its branch requires no P2P network,
//! no discovery, no endpoint refresh, no peer or quorum readiness, no relayer,
//! and no second validator. The coordinated and PoSy branches keep their
//! existing preflight unchanged.

use super::single_authority_finality_store::{
    SingleAuthorityChainBinding, SingleAuthorityFinalityStore,
};
use super::single_authority_signing_journal::SingleAuthoritySigningJournal;
use crate::crypto::pqc::{PQCAlgorithm, PQCManager, PQCPublicKey, PQCSignature};
use crate::desired_state_v2::{
    canonical_signing_payload, sha256_hex, ConsensusBindingV2, ExpectedStartBinding,
    SignedDesiredStateV2, MLDSA87_PUBLIC_KEY_LEN,
};
use crate::desired_state_v2_canonical::verify_canonical_and_signature;
use base64::{engine::general_purpose, Engine as _};
use std::path::{Path, PathBuf};

/// Launch constants this release will start. They are asserted, never derived
/// from local configuration.
pub const LAUNCH_CHAIN_ID: u64 = 1266;
pub const LAUNCH_CHAIN_INCARNATION: u64 = 5;
pub const LAUNCH_NETWORK_ID: &str = "synergy-testnet-v3";
pub const LAUNCH_AUTHORITY_ID: &str = "authority-node-01";
pub const LAUNCH_TARGET_BLOCK_TIME_MS: u64 = 1_000;

/// The fully verified single-authority startup decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleAuthorityStartupPlan {
    pub chain_id: u64,
    pub chain_incarnation: u64,
    pub network_id: String,
    pub release_id: String,
    pub directory_namespace: String,
    pub genesis_hash: String,
    pub authority_id: String,
    pub authority_public_key_fingerprint: String,
    pub target_block_time_ms: u64,
    pub authority_start_height: u64,
}

/// What the signed activation selected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedConsensusStartup {
    SingleAuthority(Box<SingleAuthorityStartupPlan>),
    CoordinatedRoundRobin,
}

/// What the runtime independently believes, from Genesis and the release, and
/// must agree with the signed activation on.
#[derive(Debug, Clone)]
pub struct StartupExpectation {
    /// From the canonical Genesis document.
    pub genesis_chain_id: u64,
    pub genesis_chain_incarnation: u64,
    pub genesis_network_id: String,
    pub genesis_hash: String,
    pub genesis_directory_namespace: String,
    /// From the release identity.
    pub release_id: String,
    /// From the locally held authority key material.
    pub authority_id: String,
    pub authority_public_key_fingerprint: String,
    pub authority_key_algorithm: PQCAlgorithm,
}

/// Durable single-authority surfaces that must all carry the same incarnation.
#[derive(Debug, Clone)]
pub struct SingleAuthorityDurablePaths {
    pub finality_log_path: PathBuf,
    pub finality_head_path: PathBuf,
    pub signing_journal_path: PathBuf,
    pub committed_block_log_path: PathBuf,
    pub execution_state_path: PathBuf,
    pub receipt_log_path: PathBuf,
}

/// Full verified startup resolution. This is the only function permitted to
/// decide which consensus driver runs.
pub fn resolve_verified_consensus_startup(
    supplied_desired_state_bytes: &[u8],
    signed: &SignedDesiredStateV2,
    expectation: &StartupExpectation,
) -> Result<VerifiedConsensusStartup, String> {
    // 1. Genesis identity, before anything else is trusted.
    verify_genesis_identity(expectation)?;

    // 2-3. Canonical form, then the real ML-DSA-87 signature over the canonical
    //      domain-separated payload. A V1 signature cannot reach this far: the
    //      domain and the canonical payload are both structurally different.
    let start_authority_public_key = decode_start_authority_public_key(signed)?;
    let signature_bytes = general_purpose::STANDARD
        .decode(&signed.signature_base64)
        .map_err(|error| format!("decode start authorization signature: {error}"))?;
    if signature_bytes.is_empty() {
        return Err("start authorization signature is empty".to_string());
    }
    let desired_state = verify_canonical_and_signature(
        supplied_desired_state_bytes,
        signed,
        |payload, signature| verify_mldsa87(&start_authority_public_key, payload, signature),
        &signature_bytes,
    )?;

    // The signature must cover exactly the canonical payload of this state.
    let payload = canonical_signing_payload(&desired_state)?;
    if !verify_mldsa87(&start_authority_public_key, &payload, &signature_bytes)? {
        return Err(
            "ML-DSA-87 start authorization does not cover the canonical payload".to_string(),
        );
    }

    // 4. Release / chain / incarnation / namespace / authority binding.
    crate::desired_state_v2::verify_signed_desired_state_v2(
        signed,
        &ExpectedStartBinding {
            chain_id: expectation.genesis_chain_id,
            chain_incarnation: expectation.genesis_chain_incarnation,
            release_id: expectation.release_id.clone(),
            genesis_hash: expectation.genesis_hash.clone(),
            authority_public_key_fingerprint: expectation.authority_public_key_fingerprint.clone(),
        },
    )?;
    if desired_state.network_id != expectation.genesis_network_id {
        return Err(format!(
            "desired state network id {} disagrees with Genesis network {}",
            desired_state.network_id, expectation.genesis_network_id
        ));
    }
    if desired_state.directory_namespace != expectation.genesis_directory_namespace {
        return Err(format!(
            "desired state namespace {} disagrees with the Genesis namespace {}",
            desired_state.directory_namespace, expectation.genesis_directory_namespace
        ));
    }

    // 5. Branch by the SIGNED binding.
    match &desired_state.consensus_binding {
        ConsensusBindingV2::CoordinatedRoundRobin { .. } => {
            Ok(VerifiedConsensusStartup::CoordinatedRoundRobin)
        }
        ConsensusBindingV2::SingleAuthority {
            authority_id,
            authority_public_key_fingerprint,
            target_block_time_ms,
            authority_start_height,
            authority_end_height,
            pending_consensus_transition,
        } => {
            if expectation.authority_key_algorithm != PQCAlgorithm::MLDSA65 {
                return Err(format!(
                    "single-authority block signing requires ML-DSA-65, found {:?}",
                    expectation.authority_key_algorithm
                ));
            }
            if desired_state.chain_id != LAUNCH_CHAIN_ID {
                return Err(format!(
                    "single-authority launch requires chain {LAUNCH_CHAIN_ID}, found {}",
                    desired_state.chain_id
                ));
            }
            if desired_state.chain_incarnation != LAUNCH_CHAIN_INCARNATION {
                return Err(format!(
                    "single-authority launch requires incarnation {LAUNCH_CHAIN_INCARNATION}, found {}",
                    desired_state.chain_incarnation
                ));
            }
            if desired_state.network_id != LAUNCH_NETWORK_ID {
                return Err(format!(
                    "single-authority launch requires network {LAUNCH_NETWORK_ID}, found {}",
                    desired_state.network_id
                ));
            }
            let expected_namespace =
                format!("chain-{LAUNCH_CHAIN_ID}/incarnation-{LAUNCH_CHAIN_INCARNATION}");
            if desired_state.directory_namespace != expected_namespace {
                return Err(format!(
                    "single-authority launch requires namespace {expected_namespace}, found {}",
                    desired_state.directory_namespace
                ));
            }
            if authority_id != LAUNCH_AUTHORITY_ID {
                return Err(format!(
                    "single-authority launch requires authority {LAUNCH_AUTHORITY_ID}, found {authority_id}"
                ));
            }
            if authority_id != &expectation.authority_id {
                return Err(format!(
                    "signed authority {authority_id} disagrees with the local authority {}",
                    expectation.authority_id
                ));
            }
            if authority_public_key_fingerprint != &expectation.authority_public_key_fingerprint {
                return Err(
                    "signed authority key fingerprint disagrees with the local authority key"
                        .to_string(),
                );
            }
            if *target_block_time_ms != LAUNCH_TARGET_BLOCK_TIME_MS {
                return Err(format!(
                    "single-authority launch requires a {LAUNCH_TARGET_BLOCK_TIME_MS}ms block time, found {target_block_time_ms}"
                ));
            }
            if *authority_start_height != 1 {
                return Err(format!(
                    "single-authority launch must start at height 1, found {authority_start_height}"
                ));
            }
            if authority_end_height.is_some() {
                return Err("single-authority launch must not bind an end height".to_string());
            }
            if pending_consensus_transition.is_some() {
                return Err(
                    "single-authority launch must have a null pending consensus transition"
                        .to_string(),
                );
            }
            Ok(VerifiedConsensusStartup::SingleAuthority(Box::new(
                SingleAuthorityStartupPlan {
                    chain_id: desired_state.chain_id,
                    chain_incarnation: desired_state.chain_incarnation,
                    network_id: desired_state.network_id.clone(),
                    release_id: desired_state.release_id.clone(),
                    directory_namespace: desired_state.directory_namespace.clone(),
                    genesis_hash: desired_state.genesis_hash.clone(),
                    authority_id: authority_id.clone(),
                    authority_public_key_fingerprint: authority_public_key_fingerprint.clone(),
                    target_block_time_ms: *target_block_time_ms,
                    authority_start_height: *authority_start_height,
                },
            )))
        }
    }
}

/// Genesis must already agree with the launch chain identity. A Genesis still
/// bound to incarnation 4 can never start an incarnation-5 runtime.
pub fn verify_genesis_identity(expectation: &StartupExpectation) -> Result<(), String> {
    if expectation.genesis_chain_id != LAUNCH_CHAIN_ID {
        return Err(format!(
            "Genesis chain {} is not the launch chain {LAUNCH_CHAIN_ID}",
            expectation.genesis_chain_id
        ));
    }
    if expectation.genesis_chain_incarnation != LAUNCH_CHAIN_INCARNATION {
        return Err(format!(
            "Genesis incarnation {} is not the launch incarnation {LAUNCH_CHAIN_INCARNATION}; \
             refusing to start a runtime bound to a different incarnation",
            expectation.genesis_chain_incarnation
        ));
    }
    let expected_namespace =
        format!("chain-{LAUNCH_CHAIN_ID}/incarnation-{LAUNCH_CHAIN_INCARNATION}");
    if expectation.genesis_directory_namespace != expected_namespace {
        return Err(format!(
            "Genesis namespace {} is not {expected_namespace}",
            expectation.genesis_directory_namespace
        ));
    }
    if expectation.genesis_network_id != LAUNCH_NETWORK_ID {
        return Err(format!(
            "Genesis network {} is not {LAUNCH_NETWORK_ID}",
            expectation.genesis_network_id
        ));
    }
    if expectation.genesis_hash.trim().is_empty() {
        return Err("Genesis hash is missing".to_string());
    }
    Ok(())
}

/// Every durable single-authority surface must already carry this exact
/// incarnation binding, or startup fails closed.
pub fn require_durable_binding_agreement(
    plan: &SingleAuthorityStartupPlan,
    paths: &SingleAuthorityDurablePaths,
) -> Result<(), String> {
    let binding = SingleAuthorityChainBinding {
        first_authority_height: plan.authority_start_height,
        chain_id: plan.chain_id,
        chain_incarnation: plan.chain_incarnation,
        authority_id: plan.authority_id.clone(),
        authority_public_key_fingerprint: plan.authority_public_key_fingerprint.clone(),
    };
    let store = SingleAuthorityFinalityStore::at_paths(
        paths.finality_log_path.clone(),
        paths.finality_head_path.clone(),
        binding,
    )?;
    // A log or head written under a different incarnation cannot be recovered
    // under this binding, so this is the incarnation gate for finality.
    let recovery = store.recover()?;
    if let Some(head) = store.load_head()? {
        if head.chain_incarnation != plan.chain_incarnation || head.chain_id != plan.chain_id {
            return Err(
                "durable finalized head is bound to a different chain incarnation".to_string(),
            );
        }
        match recovery.latest() {
            Some(latest)
                if latest.height == head.height && latest.block_hash == head.block_hash => {}
            Some(latest) => {
                return Err(format!(
                    "durable head {} does not match the last finality record {}",
                    head.height, latest.height
                ));
            }
            None => {
                return Err("durable head exists with no finality records".to_string());
            }
        }
    }
    for record in &recovery.records {
        if record.chain_incarnation != plan.chain_incarnation || record.chain_id != plan.chain_id {
            return Err(
                "durable finality record is bound to a different chain incarnation".to_string(),
            );
        }
        if record.release_id != plan.release_id {
            return Err("durable finality record is bound to a different release".to_string());
        }
    }

    // Bind and compact the signing journal only after the finality log/head
    // have recovered.  This preserves the historical V1 journal as an audit
    // archive while making every normal startup and block write bounded.
    let journal = SingleAuthoritySigningJournal::at_path(paths.signing_journal_path.clone());
    let namespace = super::single_authority_signing_journal::SingleAuthorityHaltNamespace {
        chain_id: plan.chain_id,
        chain_incarnation: plan.chain_incarnation,
        consensus_protocol:
            super::single_authority_finality_store::SINGLE_AUTHORITY_CONSENSUS_PROTOCOL.to_string(),
        authority_id: plan.authority_id.clone(),
        release_id: plan.release_id.clone(),
    };
    let finalized_tip = recovery
        .latest()
        .map(|record| (record.height, record.block_hash));
    journal.reconcile_finalized_head(
        &namespace,
        finalized_tip.map(|(height, _)| height).unwrap_or(0),
        finalized_tip.as_ref().map(|(_, hash)| hash),
    )?;
    journal.require_signing_allowed(&namespace)?;
    for entry in journal.entries()? {
        if entry.subject.chain_incarnation != plan.chain_incarnation
            || entry.subject.chain_id != plan.chain_id
        {
            return Err(
                "signing journal contains an entry bound to a different chain incarnation"
                    .to_string(),
            );
        }
    }

    // The execution, receipt, and committed-body surfaces must live under the
    // signed namespace directory, so a stale incarnation cannot be read.
    let namespace_component = plan.directory_namespace.replace('/', "-");
    for path in [
        &paths.committed_block_log_path,
        &paths.execution_state_path,
        &paths.receipt_log_path,
    ] {
        require_namespaced_path(path, &namespace_component)?;
    }
    Ok(())
}

fn require_namespaced_path(path: &Path, namespace_component: &str) -> Result<(), String> {
    let rendered = path.to_string_lossy();
    if rendered.contains(namespace_component) {
        return Ok(());
    }
    Err(format!(
        "durable path {rendered} is not inside the signed namespace {namespace_component}"
    ))
}

fn decode_start_authority_public_key(
    signed: &SignedDesiredStateV2,
) -> Result<PQCPublicKey, String> {
    let key_data = general_purpose::STANDARD
        .decode(&signed.start_authority_public_key_base64)
        .map_err(|error| format!("decode start authority public key: {error}"))?;
    if key_data.len() != MLDSA87_PUBLIC_KEY_LEN {
        return Err(format!(
            "start authority public key must be {MLDSA87_PUBLIC_KEY_LEN} bytes, found {}",
            key_data.len()
        ));
    }
    let fingerprint = format!("sha256:{}", sha256_hex(&key_data));
    if fingerprint != signed.start_authority_fingerprint {
        return Err("start authority fingerprint does not match its public key".to_string());
    }
    Ok(PQCPublicKey {
        algorithm: PQCAlgorithm::MLDSA87,
        key_data,
        key_id: signed.start_authority_fingerprint.clone(),
        created_at: 0,
    })
}

fn verify_mldsa87(
    public_key: &PQCPublicKey,
    payload: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, String> {
    let signature = PQCSignature {
        algorithm: PQCAlgorithm::MLDSA87,
        signature_data: signature_bytes.to_vec(),
        message_hash: Vec::new(),
        public_key_id: public_key.key_id.clone(),
        created_at: 0,
    };
    PQCManager::new()
        .verify(public_key, &signature, payload)
        .map_err(|error| format!("verify ML-DSA-87 start authorization: {error}"))
}
