use clap::{Arg, Command};
use std::process;
use std::path::PathBuf;
use log::{info, error, LevelFilter};

mod node;
mod network;
mod consensus;
mod rpc;
mod storage;
mod crypto;

use node::Node;
use network::NetworkService;
use crypto::CryptoService;
use consensus::ConsensusService;
use rpc::RpcService;
use storage::StorageService;

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    let matches = Command::new("synergy-node")
        .version("1.0.0")
        .author("Synergy Network")
        .about("Synergy Network Node Implementation")
        .subcommand(
            Command::new("start")
                .about("Start a node")
                .arg(Arg::new("type")
                    .long("type")
                    .value_name("TYPE")
                    .help("Node type (validator, relayer, etc.)")
                    .required(true))
                .arg(Arg::new("id")
                    .long("id")
                    .value_name("ID")
                    .help("Node ID")
                    .required(true))
                .arg(Arg::new("network")
                    .long("network")
                    .value_name("NETWORK_ID")
                    .help("Network ID")
                    .required(true))
                .arg(Arg::new("p2p")
                    .long("p2p")
                    .value_name("PORT")
                    .help("P2P port")
                    .required(true))
                .arg(Arg::new("rpc")
                    .long("rpc")
                    .value_name("PORT")
                    .help("RPC port")
                    .required(true))
                .arg(Arg::new("data")
                    .long("data")
                    .value_name("DIR")
                    .help("Data directory")
                    .required(true))
                .arg(Arg::new("bootstrap")
                    .long("bootstrap")
                    .value_name("NODE")
                    .help("Bootstrap node")
                    .action(clap::ArgAction::Append))
        )
        .subcommand(
            Command::new("stop")
                .about("Stop a running node")
        )
        .subcommand(
            Command::new("status")
                .about("Get node status")
        )
        .get_matches();

    match matches.subcommand() {
        Some(("start", sub_matches)) => {
            let node_type = sub_matches.get_one::<String>("type").unwrap();
            let node_id = sub_matches.get_one::<String>("id").unwrap();
            let network_id = sub_matches.get_one::<String>("network").unwrap().parse::<u64>().unwrap();
            let p2p_port = sub_matches.get_one::<String>("p2p").unwrap().parse::<u16>().unwrap();
            let rpc_port = sub_matches.get_one::<String>("rpc").unwrap().parse::<u16>().unwrap();
            let data_dir = PathBuf::from(sub_matches.get_one::<String>("data").unwrap());

            let bootstrap_nodes: Vec<String> = sub_matches.get_many::<String>("bootstrap")
                .map(|v| v.map(|s| s.to_string()).collect())
                .unwrap_or_default();

            // Initialize and start the node
            if let Err(e) = start_node(
                node_type.clone(),
                node_id.clone(),
                network_id,
                p2p_port,
                rpc_port,
                data_dir,
                bootstrap_nodes
            ).await {
                error!("Failed to start node: {}", e);
                process::exit(1);
            }
        },
        Some(("stop", _)) => {
            info!("Stop command received");
            // In a real implementation, this would stop the node
        },
        Some(("status", _)) => {
            info!("Status command received");
            // In a real implementation, this would show status
        },
        _ => {
            eprintln!("No subcommand provided");
            process::exit(1);
        }
    }
}

async fn start_node(
    node_type: String,
    node_id: String,
    network_id: u64,
    p2p_port: u16,
    rpc_port: u16,
    data_dir: PathBuf,
    bootstrap_nodes: Vec<String>
) -> Result<(), String> {
    info!("Starting Synergy node: {} (type: {})", node_id, node_type);

    // Initialize crypto service
    let crypto_service = CryptoService::new()?;

    // Initialize network service
    let network_service = NetworkService::new(
        node_id.clone(),
        p2p_port,
        bootstrap_nodes,
    );

    // Initialize node
    let mut node = Node::new(
        node_id.clone(),
        node_type.clone(),
        network_id,
        p2p_port,
        rpc_port,
        data_dir.clone(),
        network_service,
        crypto_service
    ).await?;

    // Start the node
    node.start().await?;

    info!("Node {} started successfully", node_id);

    // Keep the node running until Ctrl+C
    tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
    node.stop().await?;

    info!("Node {} stopped", node_id);
    Ok(())
}