use synergy_node_control_panel::app_context::AppContext;
use synergy_node_control_panel::event_bus::EventBus;
use synergy_node_control_panel::testnet::{
    testnet_align_validator_vpn_config, testnet_apply_validator_snapshot,
    testnet_apply_validator_vpn_snapshot, testnet_backup_keys, testnet_diagnose_onboarding_sync,
    testnet_discover_validator_snapshot, testnet_download_validator_snapshot,
    testnet_enroll_validator_vpn, testnet_get_device_profile, testnet_get_state,
    testnet_record_innernet_enrollment, testnet_record_validator_funding,
    testnet_restore_validator_snapshot, testnet_reuse_innernet_enrollment,
    testnet_run_validator_onboarding, testnet_set_validator_owner, testnet_setup_node,
    testnet_stake_validator, testnet_start_validator_normal_sync, testnet_sync_catch_up_rejoin,
    testnet_validator_vpn_status, testnet_verify_validator_eligibility,
    testnet_verify_validator_snapshot, TestnetFilesystemTargetInput,
    TestnetInnernetEnrollmentInput, TestnetSetValidatorOwnerInput, TestnetSetupInput,
    TestnetSnapshotRestoreInput, TestnetValidatorCatchUpInput, TestnetValidatorEligibilityInput,
    TestnetValidatorFundingInput, TestnetValidatorOnboardingInput,
    TestnetValidatorSnapshotApplyInput, TestnetValidatorSnapshotDownloadInput,
    TestnetValidatorSnapshotVerifyInput, TestnetValidatorStakeInput, TestnetValidatorVpnInput,
};
use synergy_node_control_panel::validator_vpn::{
    import_validator_vpn_bootstrap_nodes, validator_vpn_status, ValidatorVpnBootstrapImportRequest,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("synergy-control failed closed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("help");
    match command {
        "diagnose-onboarding-sync" => {
            let node_id = arg_value(&args, "--node-id");
            let payload = testnet_diagnose_onboarding_sync(node_id).await?;
            let rendered = serde_json::to_string_pretty(&payload)
                .map_err(|error| format!("failed to render diagnostic JSON: {error}"))?;
            println!("{rendered}");
        }
        "prove-onboarding" => {
            let node_id = arg_value(&args, "--node-id")
                .ok_or_else(|| "prove-onboarding requires --node-id <node-id>".to_string())?;
            let payload = testnet_run_validator_onboarding(
                &AppContext::from_env(),
                TestnetValidatorOnboardingInput {
                    node_id,
                    dry_run: Some(true),
                    auto_start: Some(false),
                    auto_resync_time: Some(false),
                    auto_stake: Some(false),
                    auto_activate: Some(false),
                    sync_mode: None,
                },
            )
            .await?;
            let rendered = serde_json::to_string_pretty(&payload)
                .map_err(|error| format!("failed to render onboarding proof JSON: {error}"))?;
            println!("{rendered}");
        }
        "validator-vpn-status" => {
            let payload = validator_vpn_status(&AppContext::from_env())?;
            print_json(&payload)?;
        }
        "testnet-state" => {
            let payload = testnet_get_state()?;
            print_json(&payload)?;
        }
        "device-check" => {
            let payload = testnet_get_device_profile()?;
            print_json(&payload)?;
        }
        "discover-validator-snapshot" => {
            let payload = testnet_discover_validator_snapshot().await?;
            print_json(&payload)?;
        }
        "setup-node" => {
            let input: TestnetSetupInput = input_json(&args, "setup-node")?;
            let payload = testnet_setup_node(input).await?;
            print_json(&payload)?;
        }
        "backup-keys" => {
            let input: TestnetFilesystemTargetInput = input_json(&args, "backup-keys")?;
            let payload = testnet_backup_keys(input)?;
            print_json(&payload)?;
        }
        "restore-validator-snapshot" => {
            let input: TestnetSnapshotRestoreInput =
                input_json(&args, "restore-validator-snapshot")?;
            let payload = testnet_restore_validator_snapshot(
                &AppContext::from_env(),
                EventBus::new(32),
                input,
            )
            .await?;
            print_json(&payload)?;
        }
        "download-validator-snapshot" => {
            let input: TestnetValidatorSnapshotDownloadInput =
                input_json(&args, "download-validator-snapshot")?;
            let payload = testnet_download_validator_snapshot(input).await?;
            print_json(&payload)?;
        }
        "verify-validator-snapshot" => {
            let input: TestnetValidatorSnapshotVerifyInput =
                input_json(&args, "verify-validator-snapshot")?;
            let payload = testnet_verify_validator_snapshot(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        "apply-validator-snapshot" => {
            let input: TestnetValidatorSnapshotApplyInput =
                input_json(&args, "apply-validator-snapshot")?;
            let payload =
                testnet_apply_validator_snapshot(&AppContext::from_env(), EventBus::new(32), input)
                    .await?;
            print_json(&payload)?;
        }
        "validator-onboarding" => {
            let input: TestnetValidatorOnboardingInput = input_json(&args, "validator-onboarding")?;
            let payload = testnet_run_validator_onboarding(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        "set-validator-owner" => {
            let input: TestnetSetValidatorOwnerInput = input_json(&args, "set-validator-owner")?;
            let payload = testnet_set_validator_owner(input)?;
            print_json(&payload)?;
        }
        "record-validator-funding" => {
            let input: TestnetValidatorFundingInput =
                input_json(&args, "record-validator-funding")?;
            let payload = testnet_record_validator_funding(input).await?;
            print_json(&payload)?;
        }
        "stake-validator" => {
            let input: TestnetValidatorStakeInput = input_json(&args, "stake-validator")?;
            let payload = testnet_stake_validator(input).await?;
            print_json(&payload)?;
        }
        "verify-validator-eligibility" => {
            let input: TestnetValidatorEligibilityInput =
                input_json(&args, "verify-validator-eligibility")?;
            let payload = testnet_verify_validator_eligibility(input).await?;
            print_json(&payload)?;
        }
        "validator-vpn-import-bootstrap" => {
            let path = arg_value(&args, "--file").ok_or_else(|| {
                "validator-vpn-import-bootstrap requires --file <public-key-artifact.json>"
                    .to_string()
            })?;
            let raw = std::fs::read_to_string(&path)
                .map_err(|error| format!("failed to read {path}: {error}"))?;
            let mut request: ValidatorVpnBootstrapImportRequest = serde_json::from_str(&raw)
                .map_err(|error| format!("failed to parse {path}: {error}"))?;
            if arg_flag(&args, "--no-regenerate-snapshot") {
                request.regenerate_snapshot = Some(false);
            }
            let payload = import_validator_vpn_bootstrap_nodes(&AppContext::from_env(), request)?;
            print_json(&payload)?;
        }
        "validator-vpn-enroll" => {
            let input = input_or_node_id::<TestnetValidatorVpnInput>(
                &args,
                "validator-vpn-enroll",
                |node_id| TestnetValidatorVpnInput {
                    node_id,
                    auto_apply: Some(!arg_flag(&args, "--no-auto-apply")),
                },
            )?;
            let payload = testnet_enroll_validator_vpn(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        "record-innernet-enrollment" => {
            let input: TestnetInnernetEnrollmentInput =
                input_json(&args, "record-innernet-enrollment")?;
            let payload =
                testnet_record_innernet_enrollment(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        "reuse-innernet-enrollment" => {
            let input = input_or_node_id::<TestnetValidatorVpnInput>(
                &args,
                "reuse-innernet-enrollment",
                |node_id| TestnetValidatorVpnInput {
                    node_id,
                    auto_apply: None,
                },
            )?;
            let payload = testnet_reuse_innernet_enrollment(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        "validator-vpn-apply" => {
            let node_id = arg_value(&args, "--node-id")
                .ok_or_else(|| "validator-vpn-apply requires --node-id <node-id>".to_string())?;
            let payload = testnet_apply_validator_vpn_snapshot(
                &AppContext::from_env(),
                TestnetValidatorVpnInput {
                    node_id,
                    auto_apply: Some(true),
                },
            )
            .await?;
            print_json(&payload)?;
        }
        "validator-vpn-align-config" => {
            let node_id = arg_value(&args, "--node-id").ok_or_else(|| {
                "validator-vpn-align-config requires --node-id <node-id>".to_string()
            })?;
            let payload = testnet_align_validator_vpn_config(
                &AppContext::from_env(),
                TestnetValidatorVpnInput {
                    node_id,
                    auto_apply: None,
                },
            )
            .await?;
            print_json(&payload)?;
        }
        "validator-vpn-agent-status" => {
            let node_id = arg_value(&args, "--node-id").ok_or_else(|| {
                "validator-vpn-agent-status requires --node-id <node-id>".to_string()
            })?;
            let payload = testnet_validator_vpn_status(
                &AppContext::from_env(),
                TestnetValidatorVpnInput {
                    node_id,
                    auto_apply: None,
                },
            )
            .await?;
            print_json(&payload)?;
        }
        "validator-sync-catch-up" => {
            let input = input_or_node_id::<TestnetValidatorCatchUpInput>(
                &args,
                "validator-sync-catch-up",
                |node_id| TestnetValidatorCatchUpInput {
                    node_id,
                    auto_activate: Some(!arg_flag(&args, "--no-auto-activate")),
                },
            )?;
            let payload =
                testnet_sync_catch_up_rejoin(&AppContext::from_env(), None, input).await?;
            print_json(&payload)?;
        }
        "validator-normal-sync" => {
            let input: TestnetValidatorCatchUpInput = input_json(&args, "validator-normal-sync")?;
            let payload =
                testnet_start_validator_normal_sync(&AppContext::from_env(), input).await?;
            print_json(&payload)?;
        }
        _ => {
            println!("Commands:");
            println!("  synergy-control diagnose-onboarding-sync [--node-id <node-id>]");
            println!("  synergy-control prove-onboarding --node-id <node-id>");
            println!("  synergy-control testnet-state");
            println!("  synergy-control device-check");
            println!("  synergy-control setup-node --input <json-file>");
            println!("  synergy-control backup-keys --input <json-file>");
            println!("  synergy-control restore-validator-snapshot --input <json-file>");
            println!("  synergy-control download-validator-snapshot --input <json-file>");
            println!("  synergy-control verify-validator-snapshot --input <json-file>");
            println!("  synergy-control apply-validator-snapshot --input <json-file>");
            println!("  synergy-control validator-onboarding --input <json-file>");
            println!("  synergy-control set-validator-owner --input <json-file>");
            println!("  synergy-control record-validator-funding --input <json-file>");
            println!("  synergy-control stake-validator --input <json-file>");
            println!("  synergy-control verify-validator-eligibility --input <json-file>");
            println!("  synergy-control validator-vpn-status");
            println!(
                "  synergy-control validator-vpn-import-bootstrap --file <public-key-artifact.json>"
            );
            println!(
                "  synergy-control validator-vpn-enroll --node-id <node-id> [--no-auto-apply]"
            );
            println!("  synergy-control record-innernet-enrollment --input <json-file>");
            println!("  synergy-control reuse-innernet-enrollment --node-id <node-id>");
            println!("  synergy-control validator-vpn-apply --node-id <node-id>");
            println!("  synergy-control validator-vpn-align-config --node-id <node-id>");
            println!("  synergy-control validator-vpn-agent-status --node-id <node-id>");
            println!(
                "  synergy-control validator-sync-catch-up --node-id <node-id> [--no-auto-activate]"
            );
            println!("  synergy-control validator-normal-sync --input <json-file>");
        }
    }
    Ok(())
}

fn input_json<T: serde::de::DeserializeOwned>(args: &[String], command: &str) -> Result<T, String> {
    let path = arg_value(args, "--input")
        .ok_or_else(|| format!("{command} requires --input <json-file>."))?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read input file {path}: {error}"))?;
    serde_json::from_str(&raw)
        .map_err(|error| format!("failed to parse input file {path}: {error}"))
}

fn input_or_node_id<T>(
    args: &[String],
    command: &str,
    from_node_id: impl FnOnce(String) -> T,
) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    if arg_value(args, "--input").is_some() {
        return input_json(args, command);
    }
    let node_id = arg_value(args, "--node-id")
        .ok_or_else(|| format!("{command} requires --node-id <node-id> or --input <json-file>."))?;
    Ok(from_node_id(node_id))
}

fn print_json<T: serde::Serialize>(payload: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(payload)
        .map_err(|error| format!("failed to render JSON: {error}"))?;
    println!("{rendered}");
    Ok(())
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn arg_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}
