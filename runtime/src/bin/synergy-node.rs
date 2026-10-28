use std::collections::BTreeMap;
use std::fs;
use synergy_testnet::aegis_tx_tool::{
    build_fixture_report, sign_aegis_transaction_sequence_with_new_key,
    sign_with_new_aegis_transaction_key, AegisSignedTxReport, AegisTxBuildOptions,
};
use synergy_testnet::gas::GasSchedule;
use synergy_testnet::synergy_types::{ChainId, Hash, NetworkId};

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-node failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "--version" | "version" => print_version(),
        "release-binding" => print_testnet_v3_release_binding(),
        "tx" => run_tx_command(&args)?,
        "dag" => run_dag_command(&args)?,
        "synq" => run_synq_command(&args)?,
        "recovery" => run_recovery_command(&args)?,
        "validator" => run_validator_command(&args)?,
        "fleet" => run_fleet_command(&args)?,
        "archive" => run_archive_command(&args)?,
        "chaos" => run_chaos_command(&args)?,
        "diagnose-sync-target" => {
            require_testnet_args(&args)?;
            let rpc_url = arg_value(&args, "--rpc-url")
                .unwrap_or_else(|| "https://testnet-core-rpc.synergy-network.io".to_string());
            let expected_genesis_hash = arg_value(&args, "--expected-genesis-hash");
            let report = diagnose_sync_target(&rpc_url, expected_genesis_hash.as_deref())?;
            println!("{report}");
        }
        "diagnose-consensus-stall" => {
            require_testnet_args(&args)?;
            print_json(
                synergy_testnet::consensus::diagnostics::diagnose_consensus_stall(
                    &synergy_testnet::rpc::rpc_server::SHARED_CHAIN,
                ),
            )?;
        }
        "diagnose-vote-locks" => {
            require_testnet_args(&args)?;
            let finalized_height = optional_u64_arg(&args, "--finalized-height")?;
            print_json(
                synergy_testnet::consensus::diagnostics::diagnose_vote_locks(finalized_height),
            )?;
        }
        "divergence-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::divergence_status(
                &synergy_testnet::rpc::rpc_server::SHARED_CHAIN,
            ))?;
        }
        "quarantine-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::quarantine_status())?;
        }
        "self-heal-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::self_heal_status())?;
        }
        "self-heal" => {
            require_testnet_args(&args)?;
            match synergy_testnet::consensus::diagnostics::start_self_heal() {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "recover-transient-vote-locks" => {
            require_testnet_args(&args)?;
            let finalized_height = optional_u64_arg(&args, "--finalized-height")?;
            let min_age_secs = optional_u64_arg(&args, "--min-age-secs")?.unwrap_or(0);
            let reason = arg_value(&args, "--reason")
                .unwrap_or_else(|| "operator_cli_recover_transient_vote_locks".to_string());
            let report = synergy_testnet::consensus::diagnostics::recover_transient_vote_locks(
                finalized_height,
                min_age_secs,
                &reason,
            )?;
            print_json(report)?;
        }
        "sync-from-canonical-peer" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::SyncFromCanonicalPeerOptions {
                canonical_height: optional_u64_arg(&args, "--canonical-height")?,
                canonical_hash: arg_value(&args, "--canonical-hash"),
                source_peer: arg_value(&args, "--source-peer"),
                source_qc_aegis_pqc_verified: arg_flag(&args, "--source-qc-aegis-pqc-verified"),
                parent_continuity_verified: arg_flag(&args, "--parent-continuity-verified"),
                state_root_matches: arg_flag(&args, "--state-root-matches"),
                source_peer_quarantined: !arg_flag(&args, "--source-peer-not-quarantined"),
            };
            match synergy_testnet::consensus::diagnostics::sync_from_canonical_peer_with_options(
                options,
            ) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "create-snapshot" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::CreateSnapshotOptions {
                source_node_majority_branch_proven: arg_flag(
                    &args,
                    "--source-node-majority-branch-proven",
                ),
                source_role: arg_value(&args, "--source-role"),
                conflict_height_hash: arg_value(&args, "--conflict-height-hash"),
                snapshot_class: arg_value(&args, "--snapshot-class"),
                allowed_restore_roles: arg_values(&args, "--allowed-role"),
            };
            match synergy_testnet::consensus::diagnostics::create_snapshot_with_options(options) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "list-snapshots" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::list_snapshots())?;
        }
        "verify-snapshot" => {
            require_testnet_args(&args)?;
            let manifest = arg_value(&args, "--manifest")
                .or_else(|| arg_value(&args, "--manifest-path"))
                .ok_or_else(|| "verify-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(&args, "--snapshot-root");
            let report = synergy_testnet::consensus::diagnostics::verify_snapshot_with_options(
                &manifest,
                snapshot_root.as_deref(),
                synergy_testnet::consensus::diagnostics::VerifySnapshotOptions {
                    snapshot_class: arg_value(&args, "--snapshot-class"),
                    target_role: arg_value(&args, "--target-role"),
                },
            )?;
            print_json(report)?;
        }
        "self-heal-from-snapshot" => {
            require_testnet_args(&args)?;
            let manifest = arg_value(&args, "--manifest")
                .or_else(|| arg_value(&args, "--manifest-path"))
                .ok_or_else(|| "self-heal-from-snapshot requires --manifest <path>".to_string())?;
            let snapshot_root = arg_value(&args, "--snapshot-root");
            let report = synergy_testnet::consensus::diagnostics::self_heal_from_snapshot(
                &manifest,
                snapshot_root.as_deref(),
            )?;
            print_json(report)?;
        }
        "quarantine-stopped-validator" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::OperatorQuarantineOptions {
                reason: arg_value(&args, "--reason"),
                target_stopped: arg_flag(&args, "--target-stopped"),
                operator_approved_containment: arg_flag(&args, "--operator-approved-containment"),
                quorum_majority_height: optional_u64_arg(&args, "--quorum-majority-height")?,
                quorum_majority_hash: arg_value(&args, "--quorum-majority-hash"),
                local_conflicting_height: optional_u64_arg(&args, "--local-conflicting-height")?,
                local_conflicting_hash: arg_value(&args, "--local-conflicting-hash"),
            };
            let report =
                synergy_testnet::consensus::diagnostics::quarantine_stopped_validator_with_options(
                    options,
                )?;
            print_json(report)?;
        }
        "start-shadow-observe" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::StartShadowObserveOptions {
                required_blocks: optional_u64_arg(&args, "--required-blocks")?,
            };
            match synergy_testnet::consensus::diagnostics::start_shadow_observe_with_options(
                options,
            ) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "shadow-status" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::shadow_status())?;
        }
        "rejoin-eligibility" => {
            require_testnet_args(&args)?;
            print_json(synergy_testnet::consensus::diagnostics::rejoin_eligibility())?;
        }
        "request-rejoin" => {
            require_testnet_args(&args)?;
            let options = synergy_testnet::consensus::diagnostics::RejoinRequestOptions {
                common_height: optional_u64_arg(&args, "--common-height")?,
                common_hash: arg_value(&args, "--common-hash"),
                exact_common_height_match: arg_flag(&args, "--exact-common-height-match"),
                latest_finalized_qc_aegis_pqc_verified: arg_flag(
                    &args,
                    "--latest-finalized-qc-aegis-pqc-verified",
                ),
                state_root_matches: arg_flag(&args, "--state-root-matches"),
                rejoin_at_finalized_safe_boundary: arg_flag(
                    &args,
                    "--rejoin-at-finalized-safe-boundary",
                ),
                cluster_marks_pending_reactivation: arg_flag(
                    &args,
                    "--cluster-marks-pending-reactivation",
                ),
                operator_approved_reactivation: arg_flag(&args, "--operator-approved-reactivation"),
                operator_approved_emergency_leader_stall_recovery: arg_flag(
                    &args,
                    "--operator-approved-emergency-leader-stall-recovery",
                ),
            };
            match synergy_testnet::consensus::diagnostics::request_rejoin_with_options(options) {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "promote-vote-only-to-active" => {
            require_testnet_args(&args)?;
            match synergy_testnet::consensus::diagnostics::promote_vote_only_to_active() {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "emergency-promote-leader-stall-to-active" => {
            require_testnet_args(&args)?;
            let options =
                synergy_testnet::consensus::diagnostics::EmergencyLeaderStallPromotionOptions {
                    common_height: optional_u64_arg(&args, "--common-height")?,
                    common_hash: arg_value(&args, "--common-hash"),
                    exact_common_height_match: arg_flag(&args, "--exact-common-height-match"),
                    latest_finalized_qc_aegis_pqc_verified: arg_flag(
                        &args,
                        "--latest-finalized-qc-aegis-pqc-verified",
                    ),
                    state_root_matches: arg_flag(&args, "--state-root-matches"),
                    rejoin_at_finalized_safe_boundary: arg_flag(
                        &args,
                        "--rejoin-at-finalized-safe-boundary",
                    ),
                    cluster_marks_pending_reactivation: arg_flag(
                        &args,
                        "--cluster-marks-pending-reactivation",
                    ),
                    operator_approved_emergency_leader_stall_recovery: arg_flag(
                        &args,
                        "--operator-approved-emergency-leader-stall-recovery",
                    ),
                };
            match synergy_testnet::consensus::diagnostics::
                emergency_promote_leader_stall_to_active_with_options(options)
            {
                Ok(report) => print_json(report)?,
                Err(error) => return Err(error),
            }
        }
        "sync-from-archive" | "self-heal-from-archive" => {
            require_testnet_args(&args)?;
            let archive_url = arg_value(&args, "--archive-url")
                .ok_or_else(|| format!("{command} requires --archive-url <url>"))?;
            let expected_genesis_hash = arg_value(&args, "--expected-genesis-hash")
                .ok_or_else(|| format!("{command} requires --expected-genesis-hash <hash>"))?;
            if command == "self-heal-from-archive" {
                arg_value(&args, "--divergence-height").ok_or_else(|| {
                    "self-heal-from-archive requires --divergence-height <height>".to_string()
                })?;
            }
            return Err(format!(
                "{command} is not yet wired to install archive state. Refusing to mutate local chain data from {archive_url} with expected_genesis_hash={expected_genesis_hash} until catalog, manifest, content root, state root, chunks, and every QC are verified through aegis-pqvm."
            ));
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node tx create-aegis --chain-id 1266 --network-id synergy-testnet-v3 [tx options]");
            println!("  synergy-node tx sign-aegis --chain-id 1266 --network-id synergy-testnet-v3 [tx options]");
            println!("  synergy-node tx submit-aegis --chain-id 1266 --network-id synergy-testnet-v3 [tx options]");
            println!("  synergy-node synq replay-flow --chain-id 1266 --network-id synergy-testnet-v3 --synq-deploy-envelope <ContractDeployEnvelope.json> --synq-bytecode <Counter.compiled.synq> --synq-manifest <Counter.manifest.json> --synq-abi <Counter.abi.json> [--synq-call-envelope <ContractCallEnvelope.json> ...]");
            println!("  synergy-node dag submit-test-fixture --real-aegis-pqvm --chain-id 1266 --network-id synergy-testnet-v3");
            println!(
                "  synergy-node recovery status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!("  synergy-node recovery inspect-divergence --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery build-plan --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --source-node <validator-id>... --evidence-path <dir> --rollback-path <dir> --output <plan.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery verify-plan --plan <plan.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery apply-plan --plan <plan.json> --confirm-target-stopped --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator inspect-state --state-root <runtime-root-or-data-dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-state --state-root <runtime-root-or-data-dir> [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-live-state --state-root <runtime-root-or-data-dir> [--expected-height <height> --expected-hash <hash>] [--max-expected-lag <blocks>] [--max-qc-ahead <blocks>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator repair-missing-qc --state-root <runtime-root-or-data-dir> --expected-height <height> --expected-qc-sha256 <sha256> --source-qc <qc.json> --source-node <validator> --source-qc <qc.json> --source-node <validator> --block <block.json> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator adopt-compacted-checkpoint --state-root <runtime-root-or-data-dir> --source-validator <source-validator> --source-bundle-path <path> --source-bundle-sha256 <sha256> --source-state-dir <path> --operator-approval-id <id> --recovery-reason <text> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator migrate-state --state-root <runtime-root-or-data-dir> --dry-run|--force [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator rebuild-derived-indexes --state-root <runtime-root-or-data-dir> [--dry-run] [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync-plan --request <request.json> --source-proof <proof.json> --transfer-proof <transfer.json> [--state-root <runtime-root-or-data-dir>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator classify-supervisor-state --evidence <evidence.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-transition --evidence <evidence.json> [--previous-state <state.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-preflight --input <candidate.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-bundle --input <bundle-input.json> [--output <manifest.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-dry-run-join --input <join-input.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator enrollment-token verify --input <token.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator package verify --manifest <package.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator identity-bundle verify --input <identity.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator cluster-assignment preview --input <assignment.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator activation-eligibility --input <activation.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator export-compat-json --state-root <runtime-root-or-data-dir> [--output <state.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node fleet status --snapshot <fleet-status.json> [--strict] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive verify-canonical --manifest <signed-manifest.json> --snapshot-root <dir> --expected-height <height> --expected-block-hash <hash> --expected-snapshot-class <class> --source-canonical [--allow-validator-pruned-support-snapshot] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive reseed --dry-run --plan <plan.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive publish-snapshot --dry-run --manifest <signed-manifest.json> --snapshot-root <dir> --snapshot-api-disabled --snapshot-worker-disabled --source-canonical [--unsafe-snapshot] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive list-unsafe-snapshots [--inventory <inventory.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive mark-unsafe-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive quarantine-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node chaos run --input <scenario.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node diagnose-sync-target --rpc-url <url> --chain-id 1266 --network-id synergy-testnet-v3 [--expected-genesis-hash <hash>]");
            println!("  synergy-node diagnose-consensus-stall --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node diagnose-vote-locks --chain-id 1266 --network-id synergy-testnet-v3 [--finalized-height <height>]");
            println!(
                "  synergy-node divergence-status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!(
                "  synergy-node quarantine-status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!(
                "  synergy-node self-heal-status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!("  synergy-node recover-transient-vote-locks --chain-id 1266 --network-id synergy-testnet-v3 [--finalized-height <height>] [--min-age-secs <seconds>]");
            println!("  synergy-node self-heal --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node sync-from-canonical-peer --chain-id 1266 --network-id synergy-testnet-v3 --canonical-height <height> --canonical-hash <hash> --source-qc-aegis-pqc-verified --parent-continuity-verified --state-root-matches --source-peer-not-quarantined [--source-peer <id>]");
            println!("  synergy-node create-snapshot --chain-id 1266 --network-id synergy-testnet-v3 --source-node-majority-branch-proven [--source-role VALIDATOR] [--snapshot-class validator-pruned|support-relayer|support-rpc|support-observer|indexer-replay|indexer-full|archive-full|archive-bootstrap] [--allowed-role <role> ...] [--conflict-height-hash <hash>]");
            println!(
                "  synergy-node list-snapshots --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!("  synergy-node verify-snapshot --manifest <path> --chain-id 1266 --network-id synergy-testnet-v3 [--snapshot-root <dir>] [--snapshot-class <class>] [--target-role <role>]");
            println!("  synergy-node self-heal-from-snapshot --manifest <path> --chain-id 1266 --network-id synergy-testnet-v3 [--snapshot-root <dir>]");
            println!("  synergy-node quarantine-stopped-validator --chain-id 1266 --network-id synergy-testnet-v3 --target-stopped --operator-approved-containment --quorum-majority-height <height> --quorum-majority-hash <hash> [--local-conflicting-height <height>] [--local-conflicting-hash <hash>]");
            println!("  synergy-node start-shadow-observe --chain-id 1266 --network-id synergy-testnet-v3 [--required-blocks <blocks>]");
            println!(
                "  synergy-node shadow-status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!(
                "  synergy-node rejoin-eligibility --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!(
                "  synergy-node request-rejoin --chain-id 1266 --network-id synergy-testnet-v3 --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation [--operator-approved-emergency-leader-stall-recovery]"
            );
            println!("  synergy-node promote-vote-only-to-active --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node emergency-promote-leader-stall-to-active --chain-id 1266 --network-id synergy-testnet-v3 --common-height <height> --common-hash <hash> --exact-common-height-match --latest-finalized-qc-aegis-pqc-verified --state-root-matches --rejoin-at-finalized-safe-boundary --cluster-marks-pending-reactivation --operator-approved-emergency-leader-stall-recovery");
            println!("  synergy-node sync-from-archive --archive-url <url> --chain-id 1266 --network-id synergy-testnet-v3 --expected-genesis-hash <hash>");
            println!("  synergy-node self-heal-from-archive --archive-url <url> --divergence-height <height> --chain-id 1266 --network-id synergy-testnet-v3 --expected-genesis-hash <hash>");
        }
    }
    Ok(())
}

fn run_validator_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    if wants_help(args) {
        print_validator_command_help(args);
        return Ok(());
    }
    match subcommand {
        "inspect-state" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::inspect_state(&state_root);
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize validator state report: {error}"))?,
            )?;
        }
        "verify-state" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::verify_state_with_options(
                &state_root,
                synergy_testnet::consensus_state::ConsensusStateVerificationOptions {
                    allow_testnet_recovery_checkpoint: arg_flag(
                        args,
                        "--allow-testnet-recovery-checkpoint",
                    ),
                },
            );
            let ok = report.ok;
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize validator state verification: {error}"))?,
            )?;
            if !ok {
                return Err("validator state verification failed closed".to_string());
            }
        }
        "verify-live-state" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::verify_live_state_with_options(
                &state_root,
                synergy_testnet::consensus_state::LiveStateVerificationOptions {
                    expected_height: optional_u64_arg(args, "--expected-height")?,
                    expected_hash: arg_value(args, "--expected-hash"),
                    max_expected_lag: optional_u64_arg(args, "--max-expected-lag")?.unwrap_or(32),
                    max_qc_ahead: optional_u64_arg(args, "--max-qc-ahead")?.unwrap_or(128),
                },
            );
            let ok = report.ok;
            print_json(serde_json::to_value(report).map_err(|error| {
                format!("serialize live validator state verification: {error}")
            })?)?;
            if !ok {
                return Err("validator live state verification failed closed".to_string());
            }
        }
        "repair-missing-qc" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let expected_height =
                optional_u64_arg(args, "--expected-height")?.ok_or_else(|| {
                    "validator repair-missing-qc requires --expected-height <height>".to_string()
                })?;
            let expected_qc_sha256 = arg_value(args, "--expected-qc-sha256").ok_or_else(|| {
                "validator repair-missing-qc requires --expected-qc-sha256 <sha256>".to_string()
            })?;
            let source_qc_paths = arg_values(args, "--source-qc")
                .into_iter()
                .map(std::path::PathBuf::from)
                .collect();
            let source_nodes = arg_values(args, "--source-node");
            let block_path = arg_value(args, "--block")
                .map(std::path::PathBuf::from)
                .ok_or_else(|| {
                    "validator repair-missing-qc requires --block <block.json>".to_string()
                })?;
            let report = synergy_testnet::recovery::repair_missing_committed_qc(
                synergy_testnet::recovery::MissingQcRepairOptions {
                    state_root,
                    expected_height,
                    expected_qc_sha256,
                    source_qc_paths,
                    source_nodes,
                    block_path,
                    dry_run: arg_flag(args, "--dry-run"),
                    apply: arg_flag(args, "--apply"),
                },
            )?;
            let ok = report.ok;
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize missing QC repair report: {error}"))?,
            )?;
            if !ok {
                return Err("validator missing QC repair failed closed".to_string());
            }
        }
        "adopt-compacted-checkpoint" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::adopt_compacted_recovery_checkpoint(
                &state_root,
                synergy_testnet::consensus_state::CompactedRecoveryCheckpointOptions {
                    dry_run: arg_flag(args, "--dry-run"),
                    apply: arg_flag(args, "--apply"),
                    force: arg_flag(args, "--force"),
                    source_validator: arg_value(args, "--source-validator").ok_or_else(|| {
                        "validator adopt-compacted-checkpoint requires --source-validator <name>"
                            .to_string()
                    })?,
                    source_bundle_path: arg_value(args, "--source-bundle-path").ok_or_else(|| {
                        "validator adopt-compacted-checkpoint requires --source-bundle-path <path>"
                            .to_string()
                    })?,
                    source_bundle_sha256: arg_value(args, "--source-bundle-sha256")
                        .ok_or_else(|| {
                            "validator adopt-compacted-checkpoint requires --source-bundle-sha256 <sha256>"
                                .to_string()
                        })?,
                    source_state_dir: arg_value(args, "--source-state-dir").ok_or_else(|| {
                        "validator adopt-compacted-checkpoint requires --source-state-dir <path>"
                            .to_string()
                    })?,
                    operator_approval_id: arg_value(args, "--operator-approval-id").ok_or_else(
                        || {
                            "validator adopt-compacted-checkpoint requires --operator-approval-id <id>"
                                .to_string()
                        },
                    )?,
                    recovery_reason: arg_value(args, "--recovery-reason").ok_or_else(|| {
                        "validator adopt-compacted-checkpoint requires --recovery-reason <text>"
                            .to_string()
                    })?,
                },
            )?;
            let ok = report.ok;
            print_json(serde_json::to_value(report).map_err(|error| {
                format!("serialize compacted recovery checkpoint adoption: {error}")
            })?)?;
            if !ok {
                return Err(
                    "validator compacted recovery checkpoint adoption failed closed".to_string(),
                );
            }
        }
        "export-compat-json" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let export = synergy_testnet::consensus_state::export_compat_json(&state_root)?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&export)
                    .map_err(|error| format!("serialize compat export: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write compat export {output}: {error}"))?;
                print_json(serde_json::json!({
                    "command": "validator export-compat-json",
                    "output": output,
                    "state_root": state_root.display().to_string(),
                    "wrote": true,
                    "fail_closed": true,
                }))?;
            } else {
                print_json(export)?;
            }
        }
        "migrate-state" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::migrate_state_with_verification_options(
                &state_root,
                synergy_testnet::consensus_state::ConsensusStateMigrationOptions {
                    dry_run: arg_flag(args, "--dry-run"),
                    force: arg_flag(args, "--force"),
                },
                synergy_testnet::consensus_state::ConsensusStateVerificationOptions {
                    allow_testnet_recovery_checkpoint: arg_flag(
                        args,
                        "--allow-testnet-recovery-checkpoint",
                    ),
                },
            )?;
            let ok = report.ok;
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize validator state migration: {error}"))?,
            )?;
            if !ok {
                return Err("validator state migration failed closed".to_string());
            }
        }
        "rebuild-derived-indexes" => {
            require_testnet_args(args)?;
            let state_root = validator_state_root_from_args(args);
            let report = synergy_testnet::consensus_state::rebuild_derived_indexes_with_verification_options(
                &state_root,
                synergy_testnet::consensus_state::DerivedIndexRebuildOptions {
                    dry_run: arg_flag(args, "--dry-run"),
                },
                synergy_testnet::consensus_state::ConsensusStateVerificationOptions {
                    allow_testnet_recovery_checkpoint: arg_flag(
                        args,
                        "--allow-testnet-recovery-checkpoint",
                    ),
                },
            )?;
            let ok = report.ok;
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize derived-index rebuild: {error}"))?,
            )?;
            if !ok {
                return Err("validator derived-index rebuild failed closed".to_string());
            }
        }
        "state-sync-plan" => {
            require_testnet_args(args)?;
            let request_path = arg_value(args, "--request")
                .ok_or_else(|| "validator state-sync-plan requires --request <json>".to_string())?;
            let source_path = arg_value(args, "--source-proof").ok_or_else(|| {
                "validator state-sync-plan requires --source-proof <json>".to_string()
            })?;
            let transfer_path = arg_value(args, "--transfer-proof").ok_or_else(|| {
                "validator state-sync-plan requires --transfer-proof <json>".to_string()
            })?;
            let request: synergy_testnet::sync::state_sync::StateSyncRequest =
                read_json_file(&request_path)?;
            let source: synergy_testnet::sync::state_sync::StateSyncSourceProof =
                read_json_file(&source_path)?;
            let transfer: synergy_testnet::sync::state_sync::StateSyncTransferProof =
                read_json_file(&transfer_path)?;
            let local_state = if arg_value(args, "--state-root").is_some()
                || arg_value(args, "--data-dir").is_some()
            {
                Some(synergy_testnet::consensus_state::verify_state(
                    &validator_state_root_from_args(args),
                ))
            } else {
                None
            };
            let plan = synergy_testnet::sync::state_sync::build_state_sync_repair_plan(
                &request,
                &source,
                &transfer,
                local_state.as_ref(),
            );
            let ok = plan.ok;
            let value = serde_json::to_value(&plan)
                .map_err(|error| format!("serialize state-sync plan: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize state-sync plan output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write state-sync plan {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator state-sync plan failed closed".to_string());
            }
        }
        "state-sync" => {
            require_testnet_args(args)?;
            let nested = args.get(2).map(String::as_str).unwrap_or("help");
            match nested {
                "repair" => {
                    let plan_path = arg_value(args, "--plan").ok_or_else(|| {
                        "validator state-sync repair requires --plan <json>".to_string()
                    })?;
                    let workspace = arg_value(args, "--workspace").ok_or_else(|| {
                        "validator state-sync repair requires --workspace <path>".to_string()
                    })?;
                    let plan: synergy_testnet::sync::state_sync::StateSyncRepairPlan =
                        read_json_file(&plan_path)?;
                    let report = synergy_testnet::sync::state_sync::apply_state_sync_repair(
                        &plan,
                        &std::path::PathBuf::from(&workspace),
                        synergy_testnet::sync::state_sync::StateSyncRepairApplyOptions {
                            dry_run: arg_flag(args, "--dry-run"),
                            apply: arg_flag(args, "--apply"),
                        },
                    )?;
                    let ok = report.ok;
                    print_json(serde_json::to_value(report).map_err(|error| {
                        format!("serialize state-sync repair report: {error}")
                    })?)?;
                    if !ok {
                        return Err("validator state-sync repair failed closed".to_string());
                    }
                }
                _ => {
                    println!("Validator state-sync commands:");
                    println!("  synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
                }
            }
        }
        "classify-supervisor-state" => {
            require_testnet_args(args)?;
            let evidence_path = arg_value(args, "--evidence").ok_or_else(|| {
                "validator classify-supervisor-state requires --evidence <json>".to_string()
            })?;
            let evidence: synergy_testnet::validator_lifecycle::ValidatorSupervisorEvidence =
                read_json_file(&evidence_path)?;
            let decision =
                synergy_testnet::validator_lifecycle::classify_validator_supervisor_state(
                    &evidence,
                );
            let fail_closed = decision.fail_closed;
            print_json(
                serde_json::to_value(&decision)
                    .map_err(|error| format!("serialize validator supervisor decision: {error}"))?,
            )?;
            if fail_closed {
                return Err("validator supervisor classified fail-closed".to_string());
            }
        }
        "supervisor-transition" => {
            require_testnet_args(args)?;
            let evidence_path = arg_value(args, "--evidence").ok_or_else(|| {
                "validator supervisor-transition requires --evidence <json>".to_string()
            })?;
            let evidence: synergy_testnet::validator_lifecycle::ValidatorSupervisorEvidence =
                read_json_file(&evidence_path)?;
            let previous = arg_value(args, "--previous-state")
                .or_else(|| arg_value(args, "--previous"))
                .map(|path| {
                    read_json_file::<
                        synergy_testnet::validator_lifecycle::ValidatorSupervisorPersistentState,
                    >(&path)
                })
                .transpose()?;
            let mut report =
                synergy_testnet::validator_lifecycle::plan_validator_supervisor_transition(
                    &synergy_testnet::validator_lifecycle::ValidatorSupervisorTransitionInput {
                        previous,
                        evidence,
                    },
                );
            report.persistent_state.evidence_path = Some(evidence_path.clone());
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize validator supervisor transition: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize validator supervisor transition output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write validator supervisor transition {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator supervisor transition failed closed".to_string());
            }
        }
        "supervisor-write" => {
            require_testnet_args(args)?;
            let transition_path = arg_value(args, "--transition").ok_or_else(|| {
                "validator supervisor-write requires --transition <json>".to_string()
            })?;
            let workspace = arg_value(args, "--workspace").ok_or_else(|| {
                "validator supervisor-write requires --workspace <path>".to_string()
            })?;
            let transition: synergy_testnet::validator_lifecycle::ValidatorSupervisorTransitionReport =
                read_json_file(&transition_path)?;
            let report = synergy_testnet::validator_lifecycle::write_validator_supervisor_state(
                &transition,
                &std::path::PathBuf::from(&workspace),
                synergy_testnet::validator_lifecycle::ValidatorSupervisorWriteOptions {
                    dry_run: arg_flag(args, "--dry-run"),
                    apply: arg_flag(args, "--apply"),
                },
            )?;
            let ok = report.ok;
            print_json(serde_json::to_value(report).map_err(|error| {
                format!("serialize validator supervisor write report: {error}")
            })?)?;
            if !ok {
                return Err("validator supervisor write failed closed".to_string());
            }
        }
        "onboarding-preflight" => {
            require_testnet_args(args)?;
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator onboarding-preflight requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityValidatorPreflightInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::evaluate_community_validator_preflight(
                    &input,
                );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize onboarding preflight report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize onboarding preflight report output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write onboarding preflight report {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator onboarding preflight failed closed".to_string());
            }
        }
        "onboarding-bundle" => {
            require_testnet_args(args)?;
            let input_path = arg_value(args, "--input")
                .ok_or_else(|| "validator onboarding-bundle requires --input <json>".to_string())?;
            let input: synergy_testnet::community_onboarding::CommunityValidatorBundleInput =
                read_json_file(&input_path)?;
            let manifest =
                synergy_testnet::community_onboarding::build_community_validator_bundle_manifest(
                    &input,
                );
            let ok = manifest.ok;
            let value = serde_json::to_value(&manifest)
                .map_err(|error| format!("serialize onboarding bundle manifest: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize onboarding bundle manifest output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write onboarding bundle manifest {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator onboarding bundle failed closed".to_string());
            }
        }
        "onboarding-dry-run-join" => {
            require_testnet_args(args)?;
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator onboarding-dry-run-join requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityValidatorDryRunJoinInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::evaluate_community_validator_dry_run_join(
                    &input,
                );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize onboarding dry-run join report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize onboarding dry-run join report output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write onboarding dry-run join report {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator onboarding dry-run join failed closed".to_string());
            }
        }
        "enrollment-token" => {
            require_testnet_args(args)?;
            if args.get(2).map(String::as_str) != Some("verify") {
                return Err("validator enrollment-token requires verify --input <json>".to_string());
            }
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator enrollment-token verify requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityEnrollmentTokenInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::verify_community_enrollment_token(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize enrollment token report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize enrollment token report output: {error}")
                })?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write enrollment token report {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator enrollment token verification failed closed".to_string());
            }
        }
        "package" => {
            require_testnet_args(args)?;
            if args.get(2).map(String::as_str) != Some("verify") {
                return Err("validator package requires verify --manifest <json>".to_string());
            }
            let manifest_path = arg_value(args, "--manifest")
                .ok_or_else(|| "validator package verify requires --manifest <json>".to_string())?;
            let input: synergy_testnet::community_onboarding::CommunityPackageCompatibilityManifest =
                read_json_file(&manifest_path)?;
            let report =
                synergy_testnet::community_onboarding::verify_community_package_manifest(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize package verification report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize package verification report output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write package verification report {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator package verification failed closed".to_string());
            }
        }
        "identity-bundle" => {
            require_testnet_args(args)?;
            if args.get(2).map(String::as_str) != Some("verify") {
                return Err("validator identity-bundle requires verify --input <json>".to_string());
            }
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator identity-bundle verify requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityIdentityBundleInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::verify_community_identity_bundle(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize identity bundle report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize identity bundle report output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write identity bundle report {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator identity bundle verification failed closed".to_string());
            }
        }
        "cluster-assignment" => {
            require_testnet_args(args)?;
            if args.get(2).map(String::as_str) != Some("preview") {
                return Err(
                    "validator cluster-assignment requires preview --input <json>".to_string(),
                );
            }
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator cluster-assignment preview requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityClusterAssignmentPreviewInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::preview_community_cluster_assignment(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize cluster assignment preview: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize cluster assignment preview output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write cluster assignment preview {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator cluster assignment preview failed closed".to_string());
            }
        }
        "activation-eligibility" => {
            require_testnet_args(args)?;
            let input_path = arg_value(args, "--input").ok_or_else(|| {
                "validator activation-eligibility requires --input <json>".to_string()
            })?;
            let input: synergy_testnet::community_onboarding::CommunityActivationEligibilityInput =
                read_json_file(&input_path)?;
            let report =
                synergy_testnet::community_onboarding::evaluate_community_activation_eligibility(
                    &input,
                );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize activation eligibility report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize activation eligibility report output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write activation eligibility report {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("validator activation eligibility failed closed".to_string());
            }
        }
        _ => {
            println!("Validator commands:");
            println!("  synergy-node validator inspect-state --state-root <runtime-root-or-data-dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-state --state-root <runtime-root-or-data-dir> [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-live-state --state-root <runtime-root-or-data-dir> [--expected-height <height> --expected-hash <hash>] [--max-expected-lag <blocks>] [--max-qc-ahead <blocks>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator repair-missing-qc --state-root <runtime-root-or-data-dir> --expected-height <height> --expected-qc-sha256 <sha256> --source-qc <qc.json> --source-node <validator> --source-qc <qc.json> --source-node <validator> --block <block.json> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator adopt-compacted-checkpoint --state-root <runtime-root-or-data-dir> --source-validator <source-validator> --source-bundle-path <path> --source-bundle-sha256 <sha256> --source-state-dir <path> --operator-approval-id <id> --recovery-reason <text> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator migrate-state --state-root <runtime-root-or-data-dir> --dry-run|--force [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator rebuild-derived-indexes --state-root <runtime-root-or-data-dir> [--dry-run] [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync-plan --request <request.json> --source-proof <proof.json> --transfer-proof <transfer.json> [--state-root <runtime-root-or-data-dir>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator classify-supervisor-state --evidence <evidence.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-transition --evidence <evidence.json> [--previous-state <state.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-preflight --input <candidate.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-bundle --input <bundle-input.json> [--output <manifest.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator onboarding-dry-run-join --input <join-input.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator enrollment-token verify --input <token.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator package verify --manifest <package.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator identity-bundle verify --input <identity.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator cluster-assignment preview --input <assignment.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator activation-eligibility --input <activation.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator export-compat-json --state-root <runtime-root-or-data-dir> [--output <state.json>] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
    Ok(())
}

fn validator_state_root_from_args(args: &[String]) -> std::path::PathBuf {
    arg_value(args, "--state-root")
        .or_else(|| arg_value(args, "--data-dir"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
}

fn run_fleet_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    if wants_help(args) {
        print_fleet_command_help(subcommand);
        return Ok(());
    }
    match subcommand {
        "status" => {
            require_testnet_args(args)?;
            let snapshot_path = arg_value(args, "--snapshot")
                .ok_or_else(|| "fleet status requires --snapshot <json>".to_string())?;
            let snapshot: synergy_testnet::fleet_status::FleetStatusSnapshot =
                read_json_file(&snapshot_path)?;
            let report = synergy_testnet::fleet_status::evaluate_fleet_status(
                &snapshot,
                arg_flag(args, "--strict"),
            );
            let ok = report.ok;
            print_json(
                serde_json::to_value(report)
                    .map_err(|error| format!("serialize fleet status report: {error}"))?,
            )?;
            if !ok {
                return Err("fleet status failed closed".to_string());
            }
        }
        _ => {
            println!("Fleet commands:");
            println!("  synergy-node fleet status --snapshot <fleet-status.json> [--strict] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
    Ok(())
}

fn run_archive_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    if wants_help(args) {
        print_archive_command_help(subcommand);
        return Ok(());
    }
    match subcommand {
        "status" => {
            require_testnet_args(args)?;
            let report = synergy_testnet::archive_validator::archive_status(
                &synergy_testnet::archive_validator::ArchiveStatusInput {
                    archive_services_disabled: arg_flag(args, "--archive-services-disabled"),
                    snapshot_api_disabled: arg_flag(args, "--snapshot-api-disabled"),
                    snapshot_worker_disabled: arg_flag(args, "--snapshot-worker-disabled"),
                    archive_publication_disabled: arg_flag(args, "--archive-publication-disabled"),
                    unsafe_inventory_reviewed: arg_flag(args, "--unsafe-inventory-reviewed"),
                },
            );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive status: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize archive status output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write archive status {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive status failed closed".to_string());
            }
        }
        "verify-canonical" => {
            require_testnet_args(args)?;
            let manifest_path = arg_value(args, "--manifest")
                .ok_or_else(|| "archive verify-canonical requires --manifest <json>".to_string())?;
            let signed_manifest: synergy_testnet::consensus::self_realign::SignedSnapshotManifest =
                read_json_file(&manifest_path)?;
            let expected_height =
                optional_u64_arg(args, "--expected-height")?.ok_or_else(|| {
                    "archive verify-canonical requires --expected-height <height>".to_string()
                })?;
            let expected_block_hash =
                arg_value(args, "--expected-block-hash").ok_or_else(|| {
                    "archive verify-canonical requires --expected-block-hash <hash>".to_string()
                })?;
            let expected_snapshot_class =
                arg_value(args, "--expected-snapshot-class").ok_or_else(|| {
                    "archive verify-canonical requires --expected-snapshot-class <class>"
                        .to_string()
                })?;
            let report = synergy_testnet::archive_validator::verify_archive_canonical_snapshot(
                &synergy_testnet::archive_validator::ArchiveCanonicalVerificationInput {
                    signed_manifest,
                    snapshot_root: arg_value(args, "--snapshot-root").map(std::path::PathBuf::from),
                    expected_height,
                    expected_block_hash,
                    expected_snapshot_class,
                    source_canonical: arg_flag(args, "--source-canonical"),
                    allow_validator_pruned_support_snapshot: arg_flag(
                        args,
                        "--allow-validator-pruned-support-snapshot",
                    ),
                    current_finalized_height: optional_u64_arg(args, "--current-finalized-height")?,
                },
            );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive canonical verification: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize archive canonical verification output: {error}")
                })?;
                fs::write(&output, bytes).map_err(|error| {
                    format!("write archive canonical verification {output}: {error}")
                })?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive canonical verification failed closed".to_string());
            }
        }
        "reseed-plan" => {
            require_testnet_args(args)?;
            let manifest_path = arg_value(args, "--manifest")
                .ok_or_else(|| "archive reseed-plan requires --manifest <json>".to_string())?;
            let signed_manifest: synergy_testnet::consensus::self_realign::SignedSnapshotManifest =
                read_json_file(&manifest_path)?;
            let input = synergy_testnet::archive_validator::ArchiveReseedPlanInput {
                signed_manifest,
                snapshot_root: arg_value(args, "--snapshot-root").map(std::path::PathBuf::from),
                archive_services_disabled: arg_flag(args, "--archive-services-disabled"),
                archive_publication_disabled: arg_flag(args, "--archive-publication-disabled"),
                unsafe_inventory_reviewed: arg_flag(args, "--unsafe-inventory-reviewed"),
                current_finalized_height: optional_u64_arg(args, "--current-finalized-height")?,
            };
            let report = synergy_testnet::archive_validator::build_archive_reseed_plan(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive reseed plan: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize archive reseed plan output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write archive reseed plan {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive reseed plan failed closed".to_string());
            }
        }
        "reseed" => {
            require_testnet_args(args)?;
            let plan_path = arg_value(args, "--plan")
                .ok_or_else(|| "archive reseed requires --plan <json>".to_string())?;
            let plan: synergy_testnet::archive_validator::ArchiveReseedPlanReport =
                read_json_file(&plan_path)?;
            let report = synergy_testnet::archive_validator::dry_run_archive_reseed(
                &synergy_testnet::archive_validator::ArchiveReseedDryRunInput {
                    plan,
                    dry_run: arg_flag(args, "--dry-run"),
                },
            );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive reseed dry-run: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize archive reseed dry-run output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write archive reseed dry-run {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive reseed dry-run failed closed".to_string());
            }
        }
        "publish-snapshot" => {
            require_testnet_args(args)?;
            let manifest_path = arg_value(args, "--manifest")
                .ok_or_else(|| "archive publish-snapshot requires --manifest <json>".to_string())?;
            let signed_manifest: synergy_testnet::consensus::self_realign::SignedSnapshotManifest =
                read_json_file(&manifest_path)?;
            let report = synergy_testnet::archive_validator::dry_run_publish_snapshot(
                &synergy_testnet::archive_validator::ArchivePublishSnapshotInput {
                    signed_manifest,
                    snapshot_root: arg_value(args, "--snapshot-root").map(std::path::PathBuf::from),
                    dry_run: arg_flag(args, "--dry-run"),
                    snapshot_api_disabled: arg_flag(args, "--snapshot-api-disabled"),
                    snapshot_worker_disabled: arg_flag(args, "--snapshot-worker-disabled"),
                    source_canonical: arg_flag(args, "--source-canonical"),
                    unsafe_snapshot: arg_flag(args, "--unsafe-snapshot"),
                    current_finalized_height: optional_u64_arg(args, "--current-finalized-height")?,
                },
            );
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive publish dry-run: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize archive publish dry-run output: {error}")
                })?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write archive publish dry-run {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive publish dry-run failed closed".to_string());
            }
        }
        "list-unsafe-snapshots" => {
            require_testnet_args(args)?;
            let inventory = if let Some(path) = arg_value(args, "--inventory") {
                read_json_file::<synergy_testnet::archive_validator::ArchiveUnsafeSnapshotInventory>(
                    &path,
                )?
            } else {
                synergy_testnet::archive_validator::ArchiveUnsafeSnapshotInventory {
                    snapshots: Vec::new(),
                }
            };
            let report = synergy_testnet::archive_validator::list_unsafe_snapshots(&inventory);
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize unsafe snapshot list: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize unsafe snapshot list output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write unsafe snapshot list {output}: {error}"))?;
            }
            print_json(value)?;
        }
        "mark-unsafe-snapshot" | "quarantine-snapshot" => {
            require_testnet_args(args)?;
            let snapshot = archive_snapshot_record_from_args(args)?;
            let report = if subcommand == "mark-unsafe-snapshot" {
                synergy_testnet::archive_validator::mark_unsafe_snapshot(snapshot)
            } else {
                synergy_testnet::archive_validator::quarantine_snapshot(snapshot)
            };
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize archive snapshot marker: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value).map_err(|error| {
                    format!("serialize archive snapshot marker output: {error}")
                })?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write archive snapshot marker {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("archive snapshot marker failed closed".to_string());
            }
        }
        _ => {
            println!("Archive commands:");
            println!("  synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive verify-canonical --manifest <signed-manifest.json> --snapshot-root <dir> --expected-height <height> --expected-block-hash <hash> --expected-snapshot-class <class> --source-canonical [--allow-validator-pruned-support-snapshot] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed [--current-finalized-height <height>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive reseed --dry-run --plan <plan.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive publish-snapshot --dry-run --manifest <signed-manifest.json> --snapshot-root <dir> --snapshot-api-disabled --snapshot-worker-disabled --source-canonical [--unsafe-snapshot] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive list-unsafe-snapshots [--inventory <inventory.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive mark-unsafe-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive quarantine-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
    Ok(())
}

fn archive_snapshot_record_from_args(
    args: &[String],
) -> Result<synergy_testnet::archive_validator::ArchiveUnsafeSnapshotRecord, String> {
    let snapshot_id = arg_value(args, "--snapshot-id")
        .or_else(|| arg_value(args, "--snapshot"))
        .ok_or_else(|| "archive snapshot marker requires --snapshot-id <id>".to_string())?;
    let height = optional_u64_arg(args, "--height")?
        .ok_or_else(|| "archive snapshot marker requires --height <height>".to_string())?;
    let snapshot_class = arg_value(args, "--snapshot-class")
        .ok_or_else(|| "archive snapshot marker requires --snapshot-class <class>".to_string())?;
    let block_hash = arg_value(args, "--block-hash")
        .ok_or_else(|| "archive snapshot marker requires --block-hash <hash>".to_string())?;
    Ok(
        synergy_testnet::archive_validator::ArchiveUnsafeSnapshotRecord {
            snapshot_id,
            height,
            snapshot_class,
            block_hash,
            canonical_verified: arg_flag(args, "--canonical-verified"),
            unsafe_marked: arg_flag(args, "--unsafe-marked"),
            quarantined: arg_flag(args, "--quarantined"),
            reason: arg_value(args, "--reason"),
        },
    )
}

fn run_chaos_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "run" => {
            require_testnet_args(args)?;
            let input_path = arg_value(args, "--input")
                .ok_or_else(|| "chaos run requires --input <scenario.json>".to_string())?;
            let input: synergy_testnet::chaos_harness::ChaosHarnessInput =
                read_json_file(&input_path)?;
            let report = synergy_testnet::chaos_harness::run_chaos_harness(&input);
            let ok = report.ok;
            let value = serde_json::to_value(&report)
                .map_err(|error| format!("serialize chaos report: {error}"))?;
            if let Some(output) = arg_value(args, "--output") {
                let bytes = serde_json::to_vec_pretty(&value)
                    .map_err(|error| format!("serialize chaos report output: {error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("write chaos report {output}: {error}"))?;
            }
            print_json(value)?;
            if !ok {
                return Err("chaos harness failed closed".to_string());
            }
        }
        _ => {
            println!("Chaos commands:");
            println!("  synergy-node chaos run --input <scenario.json> [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
    Ok(())
}

fn run_recovery_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "status" => {
            require_testnet_args(args)?;
            print_json(synergy_testnet::recovery::status())?;
        }
        "inspect-divergence" => {
            require_testnet_args(args)?;
            let input = recovery_build_input_from_args(args)?;
            print_json(synergy_testnet::recovery::inspect_divergence(&input))?;
        }
        "build-plan" => {
            require_testnet_args(args)?;
            let input = recovery_build_input_from_args(args)?;
            let plan = synergy_testnet::recovery::build_plan(input);
            if let Some(output) = arg_value(args, "--output") {
                synergy_testnet::recovery::write_plan(&plan, std::path::Path::new(&output))?;
            }
            print_json(
                serde_json::to_value(&plan)
                    .map_err(|error| format!("serialize recovery plan: {error}"))?,
            )?;
        }
        "verify-plan" => {
            require_testnet_args(args)?;
            let plan_path = arg_value(args, "--plan")
                .ok_or_else(|| "recovery verify-plan requires --plan <plan.json>".to_string())?;
            let content = std::fs::read_to_string(&plan_path)
                .map_err(|error| format!("read recovery plan {plan_path}: {error}"))?;
            let plan: synergy_testnet::recovery::RecoveryPlan = serde_json::from_str(&content)
                .map_err(|error| format!("parse recovery plan {plan_path}: {error}"))?;
            let verification = synergy_testnet::recovery::verify_plan(&plan);
            print_json(
                serde_json::to_value(&verification)
                    .map_err(|error| format!("serialize recovery verification: {error}"))?,
            )?;
            if !verification.valid_for_apply {
                return Err("recovery plan is not valid for apply".to_string());
            }
        }
        "apply-plan" => {
            require_testnet_args(args)?;
            let plan_path = arg_value(args, "--plan")
                .ok_or_else(|| "recovery apply-plan requires --plan <plan.json>".to_string())?;
            let result =
                synergy_testnet::recovery::apply_plan(synergy_testnet::recovery::ApplyPlanInput {
                    plan_path: std::path::PathBuf::from(plan_path),
                    confirm_target_stopped: args.iter().any(|arg| {
                        arg == "--confirm-target-stopped" || arg == "--confirm-target-quarantined"
                    }),
                })?;
            print_json(
                serde_json::to_value(&result)
                    .map_err(|error| format!("serialize recovery apply result: {error}"))?,
            )?;
        }
        _ => {
            println!("Recovery commands:");
            println!(
                "  synergy-node recovery status --chain-id 1266 --network-id synergy-testnet-v3"
            );
            println!("  synergy-node recovery inspect-divergence --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery build-plan --target-node-id <id> --target-role validator|relayer|rpc|archive --target-data-dir <dir> --source-state-dir <dir> --source-node <validator-id>... --evidence-path <dir> --rollback-path <dir> --output <plan.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery verify-plan --plan <plan.json> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node recovery apply-plan --plan <plan.json> --confirm-target-stopped --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
    Ok(())
}

fn recovery_build_input_from_args(
    args: &[String],
) -> Result<synergy_testnet::recovery::BuildPlanInput, String> {
    let target_node_id = arg_value(args, "--target-node-id")
        .ok_or_else(|| "missing --target-node-id <id>".to_string())?;
    let target_role = parse_recovery_target_role(
        &arg_value(args, "--target-role")
            .ok_or_else(|| "missing --target-role validator|relayer|rpc|archive".to_string())?,
    )?;
    let chain_id = arg_value(args, "--chain-id")
        .ok_or_else(|| "missing --chain-id 1266".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    let network_id = arg_value(args, "--network-id")
        .ok_or_else(|| "missing --network-id synergy-testnet-v3".to_string())?;
    let target_data_dir = std::path::PathBuf::from(
        arg_value(args, "--target-data-dir").unwrap_or_else(|| "data".to_string()),
    );
    let source_state_dir = arg_value(args, "--source-state-dir").map(std::path::PathBuf::from);
    let source_evidence_dirs = arg_values(args, "--source-evidence-dir")
        .into_iter()
        .map(std::path::PathBuf::from)
        .collect();
    let evidence_path =
        std::path::PathBuf::from(arg_value(args, "--evidence-path").unwrap_or_else(|| {
            format!(
                "data/recovery-evidence/{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
            )
        }));
    let rollback_path =
        std::path::PathBuf::from(arg_value(args, "--rollback-path").unwrap_or_else(|| {
            format!(
                "data/recovery-rollback/{}",
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ")
            )
        }));
    Ok(synergy_testnet::recovery::BuildPlanInput {
        target_node_id,
        target_role,
        chain_id,
        network_id,
        genesis_hash: arg_value(args, "--expected-genesis-hash")
            .unwrap_or_else(synergy_testnet::recovery::expected_genesis_hash),
        target_data_dir,
        source_state_dir,
        source_evidence_dirs,
        source_nodes_used: arg_values(args, "--source-node"),
        source_common_height: optional_u64_arg(args, "--source-common-height")?,
        source_common_hash: arg_value(args, "--source-common-hash"),
        source_canonical_lock_height: optional_u64_arg(args, "--source-canonical-lock-height")?,
        source_canonical_lock_hash: arg_value(args, "--source-canonical-lock-hash"),
        target_runtime_sha256: arg_value(args, "--target-runtime-sha256").unwrap_or_default(),
        evidence_path,
        rollback_path,
        recovery_type: arg_value(args, "--recovery-type")
            .map(|value| parse_recovery_type(&value))
            .transpose()?,
        conflict_height: optional_u64_arg(args, "--conflict-height")?,
        expected_target_conflict_hash: arg_value(args, "--expected-target-conflict-hash"),
        expected_source_conflict_hash: arg_value(args, "--expected-source-conflict-hash"),
        target_stopped_or_quarantined: args.iter().any(|arg| {
            arg == "--target-stopped-or-quarantined"
                || arg == "--target-stopped"
                || arg == "--target-quarantined"
        }),
    })
}

fn parse_recovery_target_role(
    value: &str,
) -> Result<synergy_testnet::recovery::TargetRole, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "validator" => Ok(synergy_testnet::recovery::TargetRole::Validator),
        "relayer" => Ok(synergy_testnet::recovery::TargetRole::Relayer),
        "rpc" | "rpc-gateway" | "rpc_gateway" => Ok(synergy_testnet::recovery::TargetRole::Rpc),
        "archive" => Ok(synergy_testnet::recovery::TargetRole::Archive),
        other => Err(format!("unsupported --target-role {other}")),
    }
}

fn parse_recovery_type(value: &str) -> Result<synergy_testnet::recovery::RecoveryType, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "no_action" | "no-action" => Ok(synergy_testnet::recovery::RecoveryType::NoAction),
        "transient_cache_prune" | "transient-cache-prune" => {
            Ok(synergy_testnet::recovery::RecoveryType::TransientCachePrune)
        }
        "canonical_state_reconcile" | "canonical-state-reconcile" => {
            Ok(synergy_testnet::recovery::RecoveryType::CanonicalStateReconcile)
        }
        "support_chain_fast_sync" | "support-chain-fast-sync" => {
            Ok(synergy_testnet::recovery::RecoveryType::SupportChainFastSync)
        }
        "archive_snapshot_restore" | "archive-snapshot-restore" => {
            Ok(synergy_testnet::recovery::RecoveryType::ArchiveSnapshotRestore)
        }
        "unsafe_requires_operator_approval" | "unsafe-requires-operator-approval" => {
            Ok(synergy_testnet::recovery::RecoveryType::UnsafeRequiresOperatorApproval)
        }
        other => Err(format!("unsupported --recovery-type {other}")),
    }
}

fn run_tx_command(args: &[String]) -> Result<(), String> {
    require_testnet_args(args)?;
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "create-aegis" | "sign-aegis" => {
            let report = sign_with_new_aegis_transaction_key(tx_options_from_args(args)?)?;
            let mut output = signed_tx_summary(subcommand, &report);
            if args.iter().any(|arg| arg == "--include-signed-transaction") {
                output["signed_transaction"] = serde_json::to_value(&report.transaction)
                    .map_err(|error| format!("failed to serialize signed transaction: {error}"))?;
                output["canonical_tx_bytes_hex"] =
                    serde_json::Value::String(report.canonical_tx_bytes_hex);
            }
            print_json(output)?;
        }
        "submit-aegis" => {
            return Err(
                "ERR_PLAINTEXT_USER_TX_DISABLED: submit-aegis cannot transmit a plaintext transaction after ETDAG activation; use tx submit-etdag with a wallet-sealed envelope"
                    .to_string(),
            );
        }
        "submit-etdag" => {
            let rpc_url = arg_value(args, "--rpc-url")
                .ok_or_else(|| "tx submit-etdag requires --rpc-url <url>".to_string())?;
            let envelope_path = arg_value(args, "--sealed-envelope")
                .or_else(|| arg_value(args, "--sealed-envelope-file"))
                .ok_or_else(|| {
                    "tx submit-etdag requires --sealed-envelope <EtdagSubmissionEnvelope.json>"
                        .to_string()
                })?;
            let envelope: synergy_testnet::etdag::EtdagSubmissionEnvelope =
                read_json_file(&envelope_path)?;
            let response = submit_etdag_transaction(&rpc_url, &envelope)?;
            print_json(serde_json::json!({
                "command": subcommand,
                "live_submission_status": "submitted_sealed_etdag_envelope",
                "plaintext_transmitted": false,
                "automatic_plaintext_fallback": false,
                "rpc_url": rpc_url,
                "sealed_envelope": envelope_path,
                "rpc_response": response,
            }))?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node tx create-aegis --chain-id 1266 --network-id synergy-testnet-v3 [--sender <uma>] [--receiver <uma>] [--nonce <n>] [--amount-nwei <n>] [--gas-limit <n>] [--max-fee-nwei <n>] [--ttl-height <h>] [--read <key>] [--write <key>] [--dependency <tx_id>] [--payload <text> | --synq-deploy-envelope <ContractDeployEnvelope.json> [--synq-bytecode <Counter.compiled.synq> --synq-manifest <Counter.manifest.json> --synq-abi <Counter.abi.json>] | --synq-call-envelope <ContractCallEnvelope.json>]");
            println!("  synergy-node tx sign-aegis --chain-id 1266 --network-id synergy-testnet-v3 [same options]");
            println!("  synergy-node tx submit-etdag --chain-id 1266 --network-id synergy-testnet-v3 --rpc-url <url> --sealed-envelope <EtdagSubmissionEnvelope.json>");
        }
    }
    Ok(())
}

fn run_dag_command(args: &[String]) -> Result<(), String> {
    require_testnet_args(args)?;
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "submit-test-fixture" => {
            if !args.iter().any(|arg| arg == "--real-aegis-pqvm") {
                return Err(
                    "dag submit-test-fixture requires --real-aegis-pqvm; wallet CLI and demo data paths are refused"
                        .to_string(),
                );
            }
            let report = build_fixture_report()?;
            let rpc_url = arg_value(args, "--rpc-url");
            if rpc_url.is_some() {
                return Err(
                    "ERR_PLAINTEXT_USER_TX_DISABLED: DAG test fixtures are local-only and cannot be submitted to Testnet-v3 RPC"
                        .to_string(),
                );
            }
            let rpc_submissions: Vec<serde_json::Value> = Vec::new();
            print_json(serde_json::json!({
                "command": subcommand,
                "aegis_pqvm_path": "synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner",
                "wallet_cli_used": false,
                "demo_data_used": false,
                "chain_id": report.chain_id,
                "network_id": report.network_id,
                "key_id": report.key_id,
                "key_role": report.key_role,
                "transactions": report.transactions.iter().map(|tx| {
                    serde_json::json!({
                        "tx_id": tx.tx_id,
                        "key_id": tx.key_id,
                        "key_role": tx.key_role,
                        "signature_verification_result": tx.signature_verification_result,
                        "dag_node_id": tx.dag_node_id,
                        "admission_result": tx.admission_result,
                        "signature_bytes_len": tx.transaction.aegis_pq_signature.signature_bytes.len(),
                    })
                }).collect::<Vec<_>>(),
                "ready_frontier": report.ready_frontier,
                "selected_ancestor_closed_set": report.selected_ancestor_closed_set,
                "tx_order_root": report.tx_order_root,
                "dag_frontier_root": report.dag_frontier_root,
                "live_submission_status": "local_fixture_only",
                "rpc_url": rpc_url,
                "rpc_submissions": rpc_submissions,
                "atlas_ingestion_status": if rpc_submissions.is_empty() { report.atlas_ingestion_status } else { "submitted_to_rpc: verify finalized block inclusion and Atlas DAG API from canonical chain data".to_string() },
            }))?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node dag submit-test-fixture --real-aegis-pqvm --chain-id 1266 --network-id synergy-testnet-v3 [--rpc-url <url>]");
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct SynqReplayStep {
    label: String,
    report: AegisSignedTxReport,
}

#[derive(Debug, Clone)]
struct SynqReplayRun {
    steps: Vec<serde_json::Value>,
    receipt_hashes: Vec<String>,
    post_state_roots: Vec<String>,
    statuses: Vec<String>,
    final_state_root: String,
}

fn run_synq_command(args: &[String]) -> Result<(), String> {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    match subcommand {
        "replay-flow" => {
            require_testnet_args(args)?;
            print_json(synq_replay_flow_report(args)?)?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-node synq replay-flow --chain-id 1266 --network-id synergy-testnet-v3 --synq-deploy-envelope <ContractDeployEnvelope.json> --synq-bytecode <Counter.compiled.synq> --synq-manifest <Counter.manifest.json> --synq-abi <Counter.abi.json> [--synq-call-envelope <ContractCallEnvelope.json> ...] [--base-nonce <n>]");
        }
    }
    Ok(())
}

fn synq_replay_flow_report(args: &[String]) -> Result<serde_json::Value, String> {
    let base_nonce = optional_u64_arg(args, "--base-nonce")?.unwrap_or(0);
    let mut labels = Vec::new();
    let mut options = Vec::new();
    let schedule = GasSchedule::default();

    let deploy_payload = synq_deploy_payload_from_args(args)?;
    let deploy_write_hint = synq_write_hint("deploy", &deploy_payload);
    labels.push("deploy".to_string());
    options.push(AegisTxBuildOptions {
        nonce: base_nonce,
        payload: deploy_payload,
        gas_limit: schedule.synq_contract_deploy_base_gas,
        write_set_hint: vec![deploy_write_hint],
        ..AegisTxBuildOptions::default()
    });

    for (index, path) in arg_values(args, "--synq-call-envelope")
        .into_iter()
        .enumerate()
    {
        let payload = synq_call_payload_from_path(&path)?;
        let write_hint = synq_write_hint("call", &payload);
        labels.push(format!("call:{}", path));
        options.push(AegisTxBuildOptions {
            nonce: base_nonce + index as u64 + 1,
            payload,
            gas_limit: schedule.synq_contract_call_base_gas,
            write_set_hint: vec![write_hint],
            ..AegisTxBuildOptions::default()
        });
    }

    let reports = sign_aegis_transaction_sequence_with_new_key(options, true)?;
    let steps = labels
        .into_iter()
        .zip(reports)
        .map(|(label, report)| SynqReplayStep { label, report })
        .collect::<Vec<_>>();
    let first = execute_synq_replay_once(&steps)?;
    let second = execute_synq_replay_once(&steps)?;
    let receipt_hashes_match = first.receipt_hashes == second.receipt_hashes;
    let post_state_roots_match = first.post_state_roots == second.post_state_roots;
    let final_state_root_match = first.final_state_root == second.final_state_root;
    let replay_matches = receipt_hashes_match && post_state_roots_match && final_state_root_match;

    Ok(serde_json::json!({
        "command": "synq replay-flow",
        "chain_id": 1266,
        "network_id": "synergy-testnet-v3",
        "normalized_synq_network_id": "synergy-testnet",
        "aegis_pqsynq_path": "synergy_testnet::synq_admission",
        "aegis_pqvm_path": "synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner",
        "aivm_path": "synergy_testnet::synq_execution -> aivm_core::synq_runtime",
        "executor": "synq-bytecode-v1 through current QuantumVM-backed AIVM runtime",
        "steps": first.steps,
        "receipt_hashes": first.receipt_hashes,
        "post_state_roots": first.post_state_roots,
        "final_state_root": first.final_state_root,
        "all_receipts_succeeded": first.statuses.iter().all(|status| status == "succeeded"),
        "replay": {
            "enabled": true,
            "matches": replay_matches,
            "receipt_hashes_match": receipt_hashes_match,
            "post_state_roots_match": post_state_roots_match,
            "final_state_root_match": final_state_root_match,
            "receipt_hashes": second.receipt_hashes,
            "post_state_roots": second.post_state_roots,
            "final_state_root": second.final_state_root,
        }
    }))
}

fn execute_synq_replay_once(steps: &[SynqReplayStep]) -> Result<SynqReplayRun, String> {
    let mut aivm_state = aivm_core::state::ContractState::default();
    let mut artifacts = BTreeMap::new();
    let mut deployments = BTreeMap::new();
    let mut step_values = Vec::new();
    let mut receipt_hashes = Vec::new();
    let mut post_state_roots = Vec::new();
    let mut statuses = Vec::new();

    for step in steps {
        let verification =
            step.report.synq_verification.as_ref().ok_or_else(|| {
                format!("{} did not carry a SynQ verification summary", step.label)
            })?;
        let receipt = synergy_testnet::synq_execution::execute_synq_transaction_at(
            &step.report.tx_id,
            &step.report.transaction,
            verification,
            &mut aivm_state,
            &mut artifacts,
            &mut deployments,
            synergy_testnet::synq_execution::SynQExecutionContext {
                runtime_block_height:
                    aivm_core::synq_runtime::GENERIC_SYNQ_RUNTIME_ACTIVATION_HEIGHT,
                runtime_block_timestamp_unix: 0,
                sts_host: None,
                applied_fee_market: None,
            },
        )?
        .ok_or_else(|| format!("{} did not execute as a SynQ transaction", step.label))?;
        let receipt_json = serde_json::to_value(&receipt)
            .map_err(|error| format!("serialize SynQ AIVM receipt: {error}"))?;
        receipt_hashes.push(receipt.receipt_hash.clone());
        post_state_roots.push(receipt.post_state_root.clone());
        statuses.push(receipt.status.clone());
        step_values.push(serde_json::json!({
            "label": step.label,
            "tx_id": step.report.tx_id.0,
            "dag_node_id": step.report.dag_node_id.0,
            "admission_ready": step.report.admission_result.ready,
            "missing_dependencies": step.report.admission_result.missing_dependencies,
            "explicit_dependencies": step.report.transaction.explicit_dependencies.iter().map(|dependency| dependency.tx_id.0.clone()).collect::<Vec<_>>(),
            "outer_signature_verification": step.report.signature_verification_result,
            "synq_contract_address": synq_contract_address_from_payload(&step.report.transaction.payload),
            "synq_verification": verification,
            "aivm_receipt": receipt_json,
        }));
    }

    Ok(SynqReplayRun {
        steps: step_values,
        receipt_hashes,
        post_state_roots,
        statuses,
        final_state_root: hex::encode(aivm_state.state_root()),
    })
}

fn synq_deploy_payload_from_args(args: &[String]) -> Result<Vec<u8>, String> {
    let deploy_path = arg_value(args, "--synq-deploy-envelope")
        .ok_or_else(|| "synq replay-flow requires --synq-deploy-envelope <path>".to_string())?;
    let bytecode_path = arg_value(args, "--synq-bytecode")
        .ok_or_else(|| "synq replay-flow requires --synq-bytecode <path>".to_string())?;
    let manifest_path = arg_value(args, "--synq-manifest")
        .ok_or_else(|| "synq replay-flow requires --synq-manifest <path>".to_string())?;
    let abi_path = arg_value(args, "--synq-abi")
        .ok_or_else(|| "synq replay-flow requires --synq-abi <path>".to_string())?;
    let pqsynq_bytes =
        fs::read(&deploy_path).map_err(|error| format!("failed to read {deploy_path}: {error}"))?;
    let bytecode = fs::read(&bytecode_path)
        .map_err(|error| format!("failed to read {bytecode_path}: {error}"))?;
    let manifest_json = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("failed to read {manifest_path}: {error}"))?;
    let abi_json = fs::read_to_string(&abi_path)
        .map_err(|error| format!("failed to read {abi_path}: {error}"))?;
    synergy_testnet::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
        ChainId::synergy_testnet_v3().0,
        &NetworkId::synergy_testnet_v3().0,
        &pqsynq_bytes,
        bytecode,
        abi_json,
        manifest_json,
        current_timestamp(),
    )
    .map_err(|error| {
        format!(
            "SynQ executable deploy admission carrier rejected [{}]: {error}",
            error.code()
        )
    })
}

fn synq_call_payload_from_path(path: &str) -> Result<Vec<u8>, String> {
    let pqsynq_bytes = fs::read(path).map_err(|error| format!("failed to read {path}: {error}"))?;
    synergy_testnet::synq_admission::build_call_admission_carrier_from_pqsynq_bytes(
        ChainId::synergy_testnet_v3().0,
        &NetworkId::synergy_testnet_v3().0,
        &pqsynq_bytes,
        current_timestamp(),
    )
    .map_err(|error| {
        format!(
            "SynQ call admission carrier rejected [{}]: {error}",
            error.code()
        )
    })
}

fn signed_tx_summary(
    command: &str,
    report: &synergy_testnet::aegis_tx_tool::AegisSignedTxReport,
) -> serde_json::Value {
    let synq_contract_address = synq_contract_address_from_payload(&report.transaction.payload);
    serde_json::json!({
        "command": command,
        "aegis_pqvm_path": "synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner",
        "wallet_cli_used": false,
        "tx_id": report.tx_id,
        "key_id": report.key_id,
        "key_role": report.key_role,
        "signature_verification_result": report.signature_verification_result,
        "dag_node_id": report.dag_node_id,
        "admission_result": report.admission_result,
        "signature_bytes_len": report.transaction.aegis_pq_signature.signature_bytes.len(),
        "chain_id": report.transaction.chain_id.0,
        "network_id": report.transaction.network_id.0,
        "sender": report.transaction.sender_uma_or_account,
        "receiver": report.transaction.receiver_uma_or_account,
        "aegis_public_key": report.public_key,
        "key_lifecycle_record": report.lifecycle_record,
        "rpc_transaction": report.rpc_transaction,
        "synq_verification": report.synq_verification,
        "synq_contract_address": synq_contract_address,
    })
}

fn synq_contract_address_from_payload(payload: &[u8]) -> Option<String> {
    let envelope = synergy_testnet::synq_admission::decode_synq_admission_carrier(payload)
        .ok()
        .flatten()?;
    match envelope.kind {
        synergy_testnet::synq_admission::SynQAdmissionKind::Deploy => {
            let deploy =
                synergy_testnet::synq_execution::deploy_envelope_from_carrier(&envelope).ok()?;
            synergy_testnet::synq_execution::derive_synergy_contract_address_from_deploy(&deploy)
                .ok()
        }
        synergy_testnet::synq_admission::SynQAdmissionKind::Call => {
            let call: pqsynq::ContractCallEnvelope =
                serde_json::from_slice(&envelope.encoded_pqsynq_envelope).ok()?;
            synergy_testnet::synq_execution::synergy_contract_address_from_pqsynq_address(
                &call.contract_address,
            )
            .ok()
        }
    }
}

fn print_json(value: serde_json::Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value)
            .map_err(|error| format!("failed to serialize JSON report: {error}"))?
    );
    Ok(())
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let content = fs::read_to_string(path).map_err(|error| format!("read {path}: {error}"))?;
    serde_json::from_str(&content).map_err(|error| format!("parse {path}: {error}"))
}

fn submit_etdag_transaction(
    rpc_url: &str,
    envelope: &synergy_testnet::etdag::EtdagSubmissionEnvelope,
) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| format!("failed to initialize encrypted RPC client: {error}"))?;
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "synergy_submitEncryptedTransaction",
        "params": [envelope],
    });
    let response = client
        .post(rpc_url)
        .json(&request)
        .send()
        .map_err(|error| format!("failed to submit sealed ETDAG envelope to {rpc_url}: {error}"))?;
    let status = response.status();
    let value = response
        .json::<serde_json::Value>()
        .map_err(|error| format!("failed to parse encrypted RPC response: {error}"))?;
    if !status.is_success() {
        return Err(format!("encrypted RPC returned HTTP {status}: {value}"));
    }
    if let Some(error) = value.get("error") {
        if !error.is_null() {
            return Err(format!("encrypted RPC returned JSON-RPC error: {error}"));
        }
    }
    Ok(value)
}

fn tx_options_from_args(args: &[String]) -> Result<AegisTxBuildOptions, String> {
    let mut options = AegisTxBuildOptions::default();
    let gas_limit_was_explicit = arg_value(args, "--gas-limit").is_some();
    if let Some(sender) = arg_value(args, "--sender") {
        options.sender = sender.clone();
        options.signer_uma_id = sender;
    }
    if let Some(signer_uma_id) = arg_value(args, "--signer-uma-id") {
        options.signer_uma_id = signer_uma_id;
    }
    if let Some(receiver) = arg_value(args, "--receiver") {
        options.receiver = receiver;
    }
    if let Some(nonce) = arg_value(args, "--nonce") {
        options.nonce = nonce
            .parse::<u64>()
            .map_err(|error| format!("invalid --nonce: {error}"))?;
    }
    if let Some(amount) = arg_value(args, "--amount-nwei") {
        options.amount_nwei = amount
            .parse::<u128>()
            .map_err(|error| format!("invalid --amount-nwei: {error}"))?;
    }
    if let Some(gas_limit) = arg_value(args, "--gas-limit") {
        options.gas_limit = gas_limit
            .parse::<u64>()
            .map_err(|error| format!("invalid --gas-limit: {error}"))?;
    }
    if let Some(max_fee) = arg_value(args, "--max-fee-nwei") {
        options.max_fee_nwei = max_fee
            .parse::<u128>()
            .map_err(|error| format!("invalid --max-fee-nwei: {error}"))?;
    }
    if let Some(ttl) = arg_value(args, "--ttl-height") {
        options.ttl_height = ttl
            .parse::<u64>()
            .map_err(|error| format!("invalid --ttl-height: {error}"))?;
    }
    if let Some(epoch) = arg_value(args, "--epoch") {
        options.epoch = epoch
            .parse::<u64>()
            .map_err(|error| format!("invalid --epoch: {error}"))?;
    }
    let synq_write_hint = apply_payload_args(args, &mut options, gas_limit_was_explicit)?;
    options.read_set_hint = arg_values(args, "--read");
    let writes = arg_values(args, "--write");
    if !writes.is_empty() {
        options.write_set_hint = writes;
    } else if let Some(write_hint) = synq_write_hint {
        options.write_set_hint = vec![write_hint];
    }
    options.explicit_dependencies = arg_values(args, "--dependency");
    Ok(options)
}

fn apply_payload_args(
    args: &[String],
    options: &mut AegisTxBuildOptions,
    gas_limit_was_explicit: bool,
) -> Result<Option<String>, String> {
    let raw_payload = arg_value(args, "--payload");
    let deploy_envelope = arg_value(args, "--synq-deploy-envelope");
    let call_envelope = arg_value(args, "--synq-call-envelope");
    let synq_bytecode = arg_value(args, "--synq-bytecode");
    let synq_manifest = arg_value(args, "--synq-manifest");
    let synq_abi = arg_value(args, "--synq-abi");
    let payload_source_count = raw_payload.is_some() as u8
        + deploy_envelope.is_some() as u8
        + call_envelope.is_some() as u8;
    if payload_source_count > 1 {
        return Err(
            "choose only one of --payload, --synq-deploy-envelope, or --synq-call-envelope"
                .to_string(),
        );
    }
    if deploy_envelope.is_none()
        && (synq_bytecode.is_some() || synq_manifest.is_some() || synq_abi.is_some())
    {
        return Err(
            "--synq-bytecode, --synq-manifest, and --synq-abi are only valid with --synq-deploy-envelope"
                .to_string(),
        );
    }

    if let Some(payload) = raw_payload {
        options.payload = payload.into_bytes();
        return Ok(None);
    }

    let schedule = GasSchedule::default();
    if let Some(path) = deploy_envelope {
        let pqsynq_bytes =
            fs::read(&path).map_err(|error| format!("failed to read {path}: {error}"))?;
        let artifact_arg_count = synq_bytecode.is_some() as u8
            + synq_manifest.is_some() as u8
            + synq_abi.is_some() as u8;
        options.payload = if artifact_arg_count == 0 {
            synergy_testnet::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes(
                ChainId::synergy_testnet_v3().0,
                &NetworkId::synergy_testnet_v3().0,
                &pqsynq_bytes,
                current_timestamp(),
            )
            .map_err(|error| {
                format!(
                    "SynQ deploy admission carrier rejected [{}]: {error}",
                    error.code()
                )
            })?
        } else if artifact_arg_count == 3 {
            let bytecode_path = synq_bytecode.expect("checked artifact_arg_count");
            let manifest_path = synq_manifest.expect("checked artifact_arg_count");
            let abi_path = synq_abi.expect("checked artifact_arg_count");
            let bytecode = fs::read(&bytecode_path)
                .map_err(|error| format!("failed to read {bytecode_path}: {error}"))?;
            let manifest_json = fs::read_to_string(&manifest_path)
                .map_err(|error| format!("failed to read {manifest_path}: {error}"))?;
            let abi_json = fs::read_to_string(&abi_path)
                .map_err(|error| format!("failed to read {abi_path}: {error}"))?;
            synergy_testnet::synq_admission::build_deploy_admission_carrier_from_pqsynq_bytes_with_artifacts(
                ChainId::synergy_testnet_v3().0,
                &NetworkId::synergy_testnet_v3().0,
                &pqsynq_bytes,
                bytecode,
                abi_json,
                manifest_json,
                current_timestamp(),
            )
            .map_err(|error| {
                format!(
                    "SynQ executable deploy admission carrier rejected [{}]: {error}",
                    error.code()
                )
            })?
        } else {
            return Err(
                "--synq-bytecode, --synq-manifest, and --synq-abi must be supplied together with --synq-deploy-envelope"
                    .to_string(),
            );
        };
        if !gas_limit_was_explicit {
            options.gas_limit = schedule.synq_contract_deploy_base_gas;
        }
        return Ok(Some(synq_write_hint("deploy", &options.payload)));
    }

    if let Some(path) = call_envelope {
        let pqsynq_bytes =
            fs::read(&path).map_err(|error| format!("failed to read {path}: {error}"))?;
        options.payload =
            synergy_testnet::synq_admission::build_call_admission_carrier_from_pqsynq_bytes(
                ChainId::synergy_testnet_v3().0,
                &NetworkId::synergy_testnet_v3().0,
                &pqsynq_bytes,
                current_timestamp(),
            )
            .map_err(|error| {
                format!(
                    "SynQ call admission carrier rejected [{}]: {error}",
                    error.code()
                )
            })?;
        if !gas_limit_was_explicit {
            options.gas_limit = schedule.synq_contract_call_base_gas;
        }
        return Ok(Some(synq_write_hint("call", &options.payload)));
    }

    Ok(None)
}

fn synq_write_hint(kind: &str, carrier: &[u8]) -> String {
    let hash = Hash::from_domain_bytes("SYNERGY_SYNQ_ADMISSION_WRITE_HINT_V1", carrier).to_hex();
    format!("synq-{kind}:{}", &hash[..16])
}

fn diagnose_sync_target(
    rpc_url: &str,
    expected_genesis_hash: Option<&str>,
) -> Result<String, String> {
    let chain_id_result = rpc_call(rpc_url, "synergy_getChainId", serde_json::json!([]));
    let node_info_result = rpc_call(rpc_url, "synergy_nodeInfo", serde_json::json!([]));
    let latest_block_result = rpc_call(rpc_url, "synergy_getLatestBlock", serde_json::json!([]));
    let genesis_block_result =
        rpc_call(rpc_url, "synergy_getBlockByNumber", serde_json::json!([0]));
    let height_result = rpc_call(rpc_url, "synergy_blockNumber", serde_json::json!([]))
        .or_else(|_| rpc_call(rpc_url, "synergy_getBlockNumber", serde_json::json!([])));

    let chain_id = chain_id_result
        .as_ref()
        .ok()
        .and_then(parse_u64ish)
        .or_else(|| {
            node_info_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("chainId")
                        .or_else(|| value.get("chain_id"))
                        .cloned()
                })
                .and_then(|value| parse_u64ish(&value))
        });
    let reported_network_id = node_info_result
        .as_ref()
        .ok()
        .and_then(|value| {
            value
                .get("networkId")
                .or_else(|| value.get("network_id"))
                .cloned()
        })
        .and_then(|value| {
            value
                .as_str()
                .map(str::to_string)
                .or_else(|| Some(value.to_string()))
        });
    let latest_height = height_result
        .as_ref()
        .ok()
        .and_then(parse_u64ish)
        .or_else(|| {
            latest_block_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("block_index")
                        .or_else(|| value.get("height"))
                        .cloned()
                })
                .and_then(|value| parse_u64ish(&value))
        });
    let latest_hash = latest_block_result
        .as_ref()
        .ok()
        .and_then(|value| value.get("hash").and_then(serde_json::Value::as_str))
        .map(str::to_string);
    let genesis_hash = genesis_block_result
        .as_ref()
        .ok()
        .and_then(block_hash_from_value)
        .or_else(|| {
            latest_block_result
                .as_ref()
                .ok()
                .and_then(|value| {
                    value
                        .get("genesis_hash")
                        .or_else(|| value.get("genesisHash"))
                        .and_then(serde_json::Value::as_str)
                })
                .map(str::to_string)
        });
    let genesis_verified = match (expected_genesis_hash, genesis_hash.as_deref()) {
        (Some(expected), Some(actual)) => actual.eq_ignore_ascii_case(expected),
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => false,
    };
    let canonical_network_id = genesis_verified.then(|| "synergy-testnet-v3".to_string());
    let usable = chain_id == Some(1266)
        && canonical_network_id.as_deref() == Some("synergy-testnet-v3")
        && latest_height.is_some()
        && genesis_verified;

    Ok(serde_json::json!({
        "source": "rpc",
        "source_url": rpc_url,
        "chain_id": chain_id,
        "network_id": canonical_network_id,
        "reported_network_id": reported_network_id,
        "genesis_hash": genesis_hash,
        "expected_genesis_hash": expected_genesis_hash,
        "genesis_verified": genesis_verified,
        "latest_height": latest_height,
        "latest_hash": latest_hash,
        "latest_qc_hash": latest_block_result
            .as_ref()
            .ok()
            .and_then(|value| value.get("qc_hash").or_else(|| value.get("latest_qc_hash")).cloned()),
        "verification_result": if usable { "accepted" } else { "rejected" },
        "usable_for_sync_target": usable,
        "errors": {
            "chain_id": chain_id_result.err(),
            "node_info": node_info_result.err(),
            "genesis_block": genesis_block_result.err(),
            "latest_block": latest_block_result.err(),
            "height": height_result.err()
        }
    })
    .to_string())
}

fn rpc_call(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()
        .map_err(|error| format!("failed to build HTTP client: {error}"))?;
    let payload = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
        .send()
        .map_err(|error| format!("{method} request failed: {error}"))?
        .json::<serde_json::Value>()
        .map_err(|error| format!("{method} response parse failed: {error}"))?;
    if let Some(error) = payload.get("error") {
        return Err(format!("{method} returned error: {error}"));
    }
    payload
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{method} response did not include result"))
}

fn block_hash_from_value(value: &serde_json::Value) -> Option<String> {
    value
        .get("hash")
        .or_else(|| value.get("block_hash"))
        .or_else(|| value.get("blockHash"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn parse_u64ish(value: &serde_json::Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

fn print_version() {
    println!("synergy-node {}", env!("CARGO_PKG_VERSION"));
}

/// Prints the immutable Testnet-v3 release binding embedded at compile time.
/// It intentionally contains no keys or mutable node configuration. Release
/// tooling compares this exact payload to the executed canonical Genesis.
fn print_testnet_v3_release_binding() {
    print!(
        "{}",
        include_str!("../../../launch/TESTNET_V3_RUNTIME_BINDING.json")
    );
}

fn wants_help(args: &[String]) -> bool {
    arg_flag(args, "--help")
        || arg_flag(args, "-h")
        || matches!(args.get(1).map(String::as_str), Some("help"))
}

fn print_validator_command_help(args: &[String]) {
    let subcommand = args.get(1).map(String::as_str).unwrap_or("help");
    let nested = args.get(2).map(String::as_str).unwrap_or("");
    match (subcommand, nested) {
        ("inspect-state", _) => {
            println!("Usage: synergy-node validator inspect-state --state-root <runtime-root-or-data-dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Read-only validator state inventory and digest report.");
        }
        ("verify-state", _) => {
            println!("Usage: synergy-node validator verify-state --state-root <runtime-root-or-data-dir> [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!(
                "Read-only validator state verifier. Exits nonzero when safety checks fail closed."
            );
        }
        ("verify-live-state", _) => {
            println!("Usage: synergy-node validator verify-live-state --state-root <runtime-root-or-data-dir> [--expected-height <height> --expected-hash <hash>] [--max-expected-lag <blocks>] [--max-qc-ahead <blocks>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!(
                "Read-only bounded-edge validator state verifier for live restart preflight. Exits nonzero when durable state is too stale or inconsistent."
            );
        }
        ("repair-missing-qc", _) => {
            println!("Usage: synergy-node validator repair-missing-qc --state-root <runtime-root-or-data-dir> --expected-height <height> --expected-qc-sha256 <sha256> --source-qc <qc.json> --source-node <validator> --source-qc <qc.json> --source-node <validator> --block <block.json> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Repair one exact internal committed-QC gap using independently collected, byte-identical quorum evidence. Requires a stopped-validator marker and performs full Aegis, block-continuity, atomic-backup, and post-repair state verification.");
        }
        ("migrate-state", _) => {
            println!("Usage: synergy-node validator migrate-state --state-root <runtime-root-or-data-dir> --dry-run|--force [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Verify and migrate consensus state into the durable store. Compact testnet state is accepted only with the explicit recovery flag.");
        }
        ("rebuild-derived-indexes", _) => {
            println!("Usage: synergy-node validator rebuild-derived-indexes --state-root <runtime-root-or-data-dir> [--dry-run] [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Verify consensus state and rebuild derived indexes. Compact testnet state is accepted only with the explicit recovery flag.");
        }
        ("state-sync-plan", _) => {
            println!("Usage: synergy-node validator state-sync-plan --request <request.json> --source-proof <proof.json> --transfer-proof <transfer.json> [--state-root <runtime-root-or-data-dir>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Build a protocol-native state-sync repair plan from verified request, source, and transfer proofs.");
        }
        ("state-sync", "repair") => {
            println!("Usage: synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!(
                "Apply a verified state-sync repair plan to a marker-gated offline workspace."
            );
        }
        ("supervisor-transition", _) => {
            println!("Usage: synergy-node validator supervisor-transition --evidence <evidence.json> [--previous-state <state.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Plan the next validator supervisor state from explicit evidence without writing it.");
        }
        ("supervisor-write", _) => {
            println!("Usage: synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!(
                "Write a validated supervisor transition into a marker-gated offline workspace."
            );
        }
        _ => {
            println!("Validator commands:");
            println!("  synergy-node validator inspect-state --state-root <runtime-root-or-data-dir> --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-state --state-root <runtime-root-or-data-dir> [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator verify-live-state --state-root <runtime-root-or-data-dir> [--expected-height <height> --expected-hash <hash>] [--max-expected-lag <blocks>] [--max-qc-ahead <blocks>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator repair-missing-qc --state-root <runtime-root-or-data-dir> --expected-height <height> --expected-qc-sha256 <sha256> --source-qc <qc.json> --source-node <validator> --source-qc <qc.json> --source-node <validator> --block <block.json> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator migrate-state --state-root <runtime-root-or-data-dir> --dry-run|--force [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator rebuild-derived-indexes --state-root <runtime-root-or-data-dir> [--dry-run] [--allow-testnet-recovery-checkpoint] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync-plan --request <request.json> --source-proof <proof.json> --transfer-proof <transfer.json> [--state-root <runtime-root-or-data-dir>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator state-sync repair --plan <plan.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-transition --evidence <evidence.json> [--previous-state <state.json>] [--output <report.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node validator supervisor-write --transition <transition.json> --workspace <offline-workspace> --dry-run|--apply --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
}

fn print_fleet_command_help(subcommand: &str) {
    match subcommand {
        "status" => {
            println!("Usage: synergy-node fleet status --snapshot <fleet-status.json> [--strict] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Evaluate validator, public RPC, and Atlas evidence. Strict mode fails closed on stale, minority, synthetic, or mismatched surfaces.");
        }
        _ => {
            println!("Fleet commands:");
            println!("  synergy-node fleet status --snapshot <fleet-status.json> [--strict] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
}

fn print_archive_command_help(subcommand: &str) {
    match subcommand {
        "reseed-plan" => {
            println!("Usage: synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed [--current-finalized-height <height>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
            println!("Build a dry-run canonical archive reseed plan from a signed, verified archive-bootstrap or archive-full manifest.");
        }
        "status" => {
            println!("Usage: synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1266 --network-id synergy-testnet-v3");
        }
        _ => {
            println!("Archive commands:");
            println!("  synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1266 --network-id synergy-testnet-v3");
            println!("  synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed [--current-finalized-height <height>] [--output <plan.json>] --chain-id 1266 --network-id synergy-testnet-v3");
        }
    }
}

fn require_testnet_args(args: &[String]) -> Result<(), String> {
    let chain_id = arg_value(args, "--chain-id")
        .ok_or_else(|| "missing --chain-id 1266".to_string())?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    ChainId(chain_id).require_testnet_v3()?;
    let network_id = arg_value(args, "--network-id")
        .ok_or_else(|| "missing --network-id synergy-testnet-v3".to_string())?;
    NetworkId(network_id).require_testnet_v3()?;
    Ok(())
}

fn optional_u64_arg(args: &[String], name: &str) -> Result<Option<u64>, String> {
    arg_value(args, name)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid {name}: {error}"))
        })
        .transpose()
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn arg_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn arg_values(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}
