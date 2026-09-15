mod admin_client;
mod cli;
mod commands;
mod output;
mod services;

use cli::{Cli, Command, HELP};
use serde_json::json;

fn main() {
    if let Err(error) = run(std::env::args().skip(1)) {
        eprintln!("synergy-node failed closed: {error}");
        std::process::exit(1);
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<(), String> {
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
            commands::start::run(config_path).map_err(|error| format!("start refused: {error}"))?
        }
        Command::Admin(operation) => {
            let socket_path = cli.admin_socket.as_deref().ok_or_else(|| {
                "admin command reached execution without an explicit socket".to_string()
            })?;
            let request = cli.admin_request(operation.clone())?;
            let response = admin_client::request(socket_path, &request)
                .map_err(|error| format!("{}: {}", error.code, error.message))?;
            match response.result {
                Ok(result) => println!(
                    "{}",
                    output::json::render(&json!({
                        "schema_version": response.schema_version,
                        "request_id": response.request_id,
                        "ok": true,
                        "result": result,
                    }))?
                ),
                Err(error) => return Err(format!("{}: {}", error.code, error.message)),
            }
        }
    }
    Ok(())
}
