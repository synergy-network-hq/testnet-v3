//! Emits the exact canonical Testnet-v3 consensus-parameter manifest.
//!
//! This tool does not create a governance signature. It requires an explicit
//! operator-assigned Testnet release Decision ID and verifies that the supplied
//! decision record contains that exact identifier.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use synergy_testnet::consensus_parameters::{
    ConsensusParameterManifest, HealthyNetworkPerformanceTargets,
    CONSENSUS_PARAMETER_ACTIVATION_BOUNDARY, CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS,
    CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID, CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION,
};
use synergy_testnet::synergy_types::{
    ChainId, NetworkId, POSY_PROTOCOL_VERSION, TESTNET_V3_CLUSTER_SCHEDULE_VERSION,
    TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM,
};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("error: {}", message.as_ref());
    std::process::exit(1);
}

fn parse_args() -> (PathBuf, String, PathBuf) {
    let mut decision_file = None;
    let mut decision_id = None;
    let mut output = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--decision-file" => {
                decision_file = args.next().map(PathBuf::from);
            }
            "--decision-id" => {
                decision_id = args.next();
            }
            "--output" => {
                output = args.next().map(PathBuf::from);
            }
            "--help" | "-h" => {
                println!(
                    "usage: emit-testnet-v3-consensus-parameters \\\n+  --decision-file launch/TESTNET_V3_CONSENSUS_PARAMETER_RELEASE_DECISION.md \\\n+  --decision-id TV3-POSY-PARAMS-2026-07-28-01 \\\n+  --output launch/TESTNET_V3_CONSENSUS_PARAMETERS.json"
                );
                std::process::exit(0);
            }
            _ => fail(format!("unknown argument {argument}")),
        }
    }
    (
        decision_file.unwrap_or_else(|| fail("--decision-file is required")),
        decision_id.unwrap_or_else(|| fail("--decision-id is required")),
        output.unwrap_or_else(|| fail("--output is required")),
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn release_manifest(approval_id: String) -> ConsensusParameterManifest {
    ConsensusParameterManifest {
        schema_version: CONSENSUS_PARAMETER_MANIFEST_SCHEMA_VERSION,
        release_id: CONSENSUS_PARAMETER_MANIFEST_RELEASE_ID.to_string(),
        status: CONSENSUS_PARAMETER_MANIFEST_FINALIZED_STATUS.to_string(),
        governance_approval_id: approval_id,
        chain_id: ChainId::synergy_testnet_v3(),
        network_id: NetworkId::synergy_testnet_v3(),
        protocol_version: POSY_PROTOCOL_VERSION.to_string(),
        activation_boundary: CONSENSUS_PARAMETER_ACTIVATION_BOUNDARY.to_string(),
        epoch_length_slots: Some(1_000),
        target_block_time_ms: 2_000,
        count_quorum_rule: "strict_more_than_two_thirds".to_string(),
        weight_quorum_rule: "strict_more_than_two_thirds".to_string(),
        cluster_schedule_version: TESTNET_V3_CLUSTER_SCHEDULE_VERSION.to_string(),
        consensus_signature_algorithm: TESTNET_V3_CONSENSUS_SIGNATURE_ALGORITHM.to_string(),
        ingress_kem_algorithm: "mlkem1024".to_string(),
        payload_encryption_algorithm: "aes256gcm".to_string(),
        encrypted_transaction_target_offset: 3,
        initial_cluster_validator_count: 6,
        initial_availability_quorum: 5,
        initial_decryption_threshold: 2,
        shadow_epochs_required: 1,
        activation_delay_epochs: 1,
        minimum_shadow_blocks: 100,
        max_finalized_lag_blocks: 2,
        required_vote_match_rate_ppm: 995_000,
        required_validator_stake_nwei: 50_000_000_000_000,
        allow_over_staking: true,
        anti_divergence_enabled: true,
        auto_reconciliation_enabled: true,
        self_quarantine_on_local_divergence: true,
        peer_quarantine_on_invalid_finality_claim: true,
        require_quorum_peer_confirmation_for_reconciliation: true,
        min_canonical_sync_peers: 4,
        max_rejoin_lag_blocks: 0,
        rejoin_only_at_round_boundary: true,
        allow_quorum_reduction: false,
        proposal_timeout_ms: 1_500,
        prevote_timeout_ms: 1_500,
        precommit_timeout_ms: 1_500,
        max_round_timeout_ms: 10_000,
        healthy_network_performance_targets: HealthyNetworkPerformanceTargets {
            healthy_proposal_target_ms: 450,
            healthy_qc_target_ms: 1_850,
            healthy_commit_target_ms: 2_250,
            finality_p95_target_ms: 2_500,
            finality_p99_target_ms: 3_000,
        },
        // The applied schema-v2 Genesis manifest deliberately leaves ETDAG
        // deferred.  Its future activation requires a new schema-v3 manifest
        // at a declared epoch boundary.
        etdag_activation: None,
    }
}

fn write_exact(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Ok(existing) = fs::read(path) {
        if existing == bytes {
            return Ok(());
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path).map_err(|error| format!("publish {}: {error}", path.display()))
}

fn main() {
    let (decision_file, decision_id, output) = parse_args();
    let decision_bytes = fs::read(&decision_file)
        .unwrap_or_else(|error| fail(format!("read {}: {error}", decision_file.display())));
    if decision_bytes.is_empty() {
        fail("release decision record is empty");
    }
    let decision_marker = format!("Decision ID: `{decision_id}`");
    if !decision_bytes
        .windows(decision_marker.len())
        .any(|window| window == decision_marker.as_bytes())
    {
        fail(format!(
            "release decision record does not contain exact marker {decision_marker}"
        ));
    }
    let decision_sha256 = sha256(&decision_bytes);
    let manifest = release_manifest(decision_id.clone());
    let canonical_bytes = manifest
        .canonical_bytes()
        .unwrap_or_else(|error| fail(format!("validate release manifest: {error}")));
    write_exact(&output, &canonical_bytes).unwrap_or_else(|error| fail(error));
    println!("manifest path       : {}", output.display());
    println!("manifest sha256     : {}", sha256(&canonical_bytes));
    println!(
        "parameter root      : {}",
        manifest
            .root()
            .unwrap_or_else(|error| fail(format!("compute parameter root: {error}")))
            .to_hex()
    );
    println!("release decision id : {decision_id}");
    println!("decision sha256      : {decision_sha256}");
}
