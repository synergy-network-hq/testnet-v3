use serde_json::Value;
use std::env;
use std::fs;
use std::path::PathBuf;
use synergy_node_control_panel::archive_snapshot::{
    create_and_publish, import_and_publish, ArchiveSnapshotCreateRequest,
};

fn argument(name: &str) -> Result<String, String> {
    let args = env::args().collect::<Vec<_>>();
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing required argument {name}"))
}

fn optional_argument(name: &str) -> Option<String> {
    env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].trim().to_string())
        .filter(|value| !value.is_empty())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-archive-publisher: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let chain_id = argument("--chain-id")?
        .parse::<u64>()
        .map_err(|error| format!("invalid --chain-id: {error}"))?;
    let consensus_fork_path = PathBuf::from(argument("--consensus-fork")?);
    let consensus_fork: Value =
        serde_json::from_str(&fs::read_to_string(&consensus_fork_path).map_err(|error| {
            format!(
                "failed to read consensus fork {}: {error}",
                consensus_fork_path.display()
            )
        })?)
        .map_err(|error| {
            format!(
                "failed to parse consensus fork {}: {error}",
                consensus_fork_path.display()
            )
        })?;

    let request = ArchiveSnapshotCreateRequest {
        workspace: PathBuf::from(argument("--workspace")?),
        publish_root: PathBuf::from(argument("--publish-root")?),
        source_node_id: argument("--source-node-id")?,
        chain_id,
        network_id: argument("--network-id")?,
        genesis_hash: argument("--genesis-hash")?,
        consensus_fork,
        majority_proof_marker: PathBuf::from(argument("--majority-proof-marker")?),
    };
    let import_root = optional_argument("--import-snapshot-root");
    let runtime_report = optional_argument("--runtime-report");
    if import_root.is_some() != runtime_report.is_some() {
        return Err(
            "--import-snapshot-root and --runtime-report must be supplied together; refusing partial import mode."
                .to_string(),
        );
    }
    let publication = match (import_root, runtime_report) {
        (Some(snapshot_root), Some(runtime_report)) => import_and_publish(
            request,
            PathBuf::from(snapshot_root),
            PathBuf::from(runtime_report),
        )?,
        (None, None) => create_and_publish(request)?,
        _ => unreachable!("validated import mode arguments"),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&publication)
            .map_err(|error| format!("failed to serialize publication result: {error}"))?
    );
    Ok(())
}
