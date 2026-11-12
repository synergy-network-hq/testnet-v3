mod admin_client;
mod cli;
mod commands;
mod output;
mod services;

use cli::{Cli, Command, OutputFormat, HELP};
use serde_json::json;

fn main() {
    if let Err(error) = run(std::env::args().skip(1)) {
        eprintln!("synergy-node failed closed: {error}");
        std::process::exit(1);
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut args = args.into_iter().peekable();
    if args.peek().is_some_and(|arg| arg == "canary-rpc-relay") {
        args.next();
        return services::apqe_rpc_service::cli(args);
    }
    if args.peek().is_some_and(|arg| arg == "authority-recovery") {
        args.next();
        return services::authority::recovery::cli(args);
    }
    let cli = Cli::parse(args)?;
    match &cli.command {
        Command::Help => println!("{HELP}"),
        Command::Version => {
            let report = commands::version::report();
            println!(
                "synergy-node {} management-schema={} config-schema={}",
                report.software, report.management_schema, report.config_schema
            );
        }
        Command::Start(config_path) => {
            let _exclusive = services::checkpoint::lock_configuration(config_path)?;
            commands::start::run(config_path).map_err(|error| format!("start refused: {error}"))?
        }
        Command::Checkpoint(request) => {
            println!(
                "{}",
                output::json::render(&services::checkpoint::run(request)?)?
            );
        }
        Command::Preflight(config_path) => {
            let report = commands::start::preflight(config_path)?;
            println!("{}", output::json::render(&report)?);
        }
        Command::Init(request) => {
            let initialized = commands::init::initialize(request)?;
            let rendered = output::json::render(&initialized)?;
            println!("{rendered}");
        }
        Command::Join(request) => {
            for (label, path) in [
                ("configuration", &request.configuration_path),
                ("signed manifest", &request.signed_manifest_path),
            ] {
                if !path.is_file() {
                    return Err(format!("{label} is not a regular file: {}", path.display()));
                }
            }
            let configuration =
                synergy_config::load(&request.configuration_path).map_err(|e| e.to_string())?;
            if configuration.manifest_path != request.signed_manifest_path {
                return Err("join manifest differs from selected configuration".into());
            }
            commands::start::preflight(&request.configuration_path)?;
            let rendered = output::json::render(request)?;
            println!("{rendered}");
        }
        Command::Manifest(request) => match request {
            commands::manifest::ManifestRequest::Inspect { path } => {
                let bytes = std::fs::read(path)
                    .map_err(|error| format!("read manifest {}: {error}", path.display()))?;
                let manifest: synergy_manifest::NetworkManifest = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("decode manifest {}: {error}", path.display()))?;
                manifest
                    .validate_against(&manifest)
                    .map_err(|error| format!("validate manifest {}: {error:?}", path.display()))?;
                let rendered = output::json::render(&manifest)?;
                println!("{rendered}");
            }
            commands::manifest::ManifestRequest::Verify { path, public_key } => {
                if !path.is_file() || !public_key.is_file() {
                    return Err(
                        "manifest verification requires regular manifest and public-key files"
                            .into(),
                    );
                }
                return Err(
                    "manifest signature verification requires a governed Aegis verifier and is unavailable in the offline CLI"
                        .into(),
                );
            }
        },
        Command::Admin(operation) => {
            let socket_path = cli.admin_socket.as_deref().ok_or_else(|| {
                "admin command reached execution without an explicit socket".to_string()
            })?;
            let request = cli.admin_request(operation.clone())?;
            let response = admin_client::request(socket_path, &request)
                .map_err(|error| format!("{}: {}", error.code, error.message))?;
            match response.result {
                Ok(result) => {
                    let value = json!({
                        "schema_version": response.schema_version,
                        "request_id": response.request_id,
                        "ok": true,
                        "result": result,
                    });
                    let rendered = match cli.output_format {
                        OutputFormat::Json => output::json::render(&value)?,
                        OutputFormat::Human => output::human::render(&value),
                    };
                    println!("{rendered}");
                }
                Err(error) => return Err(format!("{}: {}", error.code, error.message)),
            }
        }
    }
    Ok(())
}
