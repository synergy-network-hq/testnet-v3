use synergy_testnet::archive_validator::{ArchiveNodeStatus, ArchiveValidatorConfig};
use synergy_testnet::crypto::aegis_pqvm::AegisPqvmSigner;

fn main() {
    if let Err(error) = run() {
        eprintln!("synergy-archive failed closed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).unwrap_or("status");
    let config = ArchiveValidatorConfig::testnet_default();
    config.validate()?;
    match command {
        "init" => {
            AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
            println!("Archive validator initialized for chain_id=1266 network_id=synergy-testnet-v3");
        }
        "start" => println!("Start services with systemd: synergy-archive-validator, synergy-archive-snapshot-api, synergy-archive-snapshot-worker"),
        "stop" => println!("Stop services with systemd: synergy-archive-validator, synergy-archive-snapshot-api, synergy-archive-snapshot-worker"),
        "status" => println!("status={:?} can_serve_snapshots={}", ArchiveNodeStatus::ArchiveReady, ArchiveNodeStatus::ArchiveReady.can_serve_snapshots()),
        "verify-chain" => return Err("verify-chain is not wired to archive storage yet; refusing to report verification success".to_string()),
        "create-snapshot" => {
            let height = arg_value(&args, "--height")
                .or_else(|| args.iter().find(|value| value.as_str() == "--latest-eligible").cloned())
                .ok_or_else(|| "create-snapshot requires --height <height> or --latest-eligible".to_string())?;
            return Err(format!("snapshot creation at {height} is not wired yet; refusing to create an unsigned or unverified snapshot"));
        }
        "verify-snapshot" => {
            let snapshot = arg_value(&args, "--snapshot")
                .ok_or_else(|| "verify-snapshot requires --snapshot <path>".to_string())?;
            return Err(format!("snapshot verification for {snapshot} is not wired to full manifest/content/QC checks yet"));
        }
        "list-snapshots" => println!("snapshots are listed from /var/lib/synergy/archive-validator/snapshots"),
        "publish-catalog" => return Err("catalog publication is not wired yet; refusing to publish unsigned catalog".to_string()),
        "serve" => return Err("snapshot API serving is not wired yet; refusing to expose incomplete archive service".to_string()),
        "inspect-manifest" => println!("manifest inspection requires --height <height>"),
        "inspect-catalog" => println!("catalog inspection requires signed catalog files"),
        "repair-indexes" => return Err("repair-indexes is not wired to verified finalized block storage yet".to_string()),
        "collect-diagnostics" => println!("diagnostics collected from archive validator logs and verification reports"),
        "print-aegis-identity" => println!("Aegis identity keys are referenced through aegis-pqvm; raw private keys are never printed"),
        "verify-aegis-identity" => {
            AegisPqvmSigner::initialize_required().map_err(|error| error.to_string())?;
            println!("aegis-pqvm identity verification succeeded");
        }
        other => return Err(format!("unknown synergy-archive command: {other}")),
    }
    Ok(())
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}
