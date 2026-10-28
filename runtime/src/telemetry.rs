use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{NodeConfig, ResolvedConsensusMode};
use crate::gas::constants::BLOCK_GAS_LIMIT;
use crate::info;
use crate::rpc::rpc_server::{SHARED_CHAIN, SYNC_MANAGER, TX_POOL};
use crate::sync::SyncState;
use crate::validator::{ValidatorStatus, VALIDATOR_MANAGER};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

type ChainMetricsSnapshot = (u64, u64, u64, u64, u64, u64, u64, u64, f64, f64, f64);

/// A process-local view of the signed P1 coordinator lifecycle.  It carries
/// only public finality/assignment identities; no signing material, proposal
/// body, or mempool data is ever exposed through metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoordinatedConsensusTelemetrySnapshot {
    pub active: bool,
    pub finalized_height: u64,
    pub finalized_block_id: String,
    pub finalized_producer_id: String,
    pub finalized_producer_round: u64,
    pub assigned_height: u64,
    pub assigned_producer_round: u64,
    pub assigned_producer_id: String,
    pub missed_turns_total: u64,
}

lazy_static::lazy_static! {
    static ref LAST_CHAIN_METRICS_SNAPSHOT: Mutex<Option<ChainMetricsSnapshot>> = Mutex::new(None);
    static ref COORDINATED_CONSENSUS_TELEMETRY: Mutex<CoordinatedConsensusTelemetrySnapshot> =
        Mutex::new(CoordinatedConsensusTelemetrySnapshot::default());
}

/// Publishes the P1 validator worker's durable state after every lifecycle
/// transition.  The role runtime owns the source state; this module only
/// renders a read-only copy for qualification and monitoring.
pub fn publish_coordinated_consensus_telemetry(snapshot: CoordinatedConsensusTelemetrySnapshot) {
    if let Ok(mut telemetry) = COORDINATED_CONSENSUS_TELEMETRY.lock() {
        *telemetry = snapshot;
    }
}

/// Clears P1 worker telemetry during a controlled worker shutdown so a later
/// non-P1 startup in the same process cannot inherit stale consensus state.
pub fn clear_coordinated_consensus_telemetry() {
    if let Ok(mut telemetry) = COORDINATED_CONSENSUS_TELEMETRY.lock() {
        *telemetry = CoordinatedConsensusTelemetrySnapshot::default();
    }
}

fn coordinated_consensus_telemetry_snapshot() -> CoordinatedConsensusTelemetrySnapshot {
    COORDINATED_CONSENSUS_TELEMETRY
        .lock()
        .map(|telemetry| telemetry.clone())
        .unwrap_or_default()
}

pub fn start_metrics_server(bind_address: &str, config: NodeConfig, start_time: SystemTime) {
    let listener = match TcpListener::bind(bind_address) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!(
                "Warning: failed to bind metrics listener on {}: {}",
                bind_address, err
            );
            return;
        }
    };

    info!(
        "telemetry",
        "Metrics listener bound",
        "bind_address" => bind_address.to_string()
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = config.clone();
                thread::spawn(move || handle_connection(stream, config, start_time));
            }
            Err(err) => {
                eprintln!("Warning: metrics listener accept failed: {}", err);
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream, config: NodeConfig, start_time: SystemTime) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));

    let mut buffer = [0_u8; 2048];
    let read = match stream.read(&mut buffer) {
        Ok(read) => read,
        Err(_) => return,
    };

    if read == 0 {
        return;
    }

    let request = String::from_utf8_lossy(&buffer[..read]);
    let mut request_line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = request_line.next().unwrap_or_default();
    let path = request_line.next().unwrap_or("/");

    if method != "GET" {
        let _ = write_response(
            &mut stream,
            "HTTP/1.1 405 Method Not Allowed",
            "method not allowed\n",
            "text/plain; charset=utf-8",
        );
        return;
    }

    match path {
        "/metrics" => {
            let body = render_metrics(&config, start_time);
            let _ = write_response(
                &mut stream,
                "HTTP/1.1 200 OK",
                &body,
                PROMETHEUS_CONTENT_TYPE,
            );
        }
        "/healthz" | "/" => {
            let _ = write_response(
                &mut stream,
                "HTTP/1.1 200 OK",
                "ok\n",
                "text/plain; charset=utf-8",
            );
        }
        _ => {
            let _ = write_response(
                &mut stream,
                "HTTP/1.1 404 Not Found",
                "not found\n",
                "text/plain; charset=utf-8",
            );
        }
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    body: &str,
    content_type: &str,
) -> std::io::Result<()> {
    let response = format!(
        "{status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

fn empty_chain_metrics_snapshot() -> ChainMetricsSnapshot {
    (0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0)
}

fn cached_chain_metrics_snapshot() -> ChainMetricsSnapshot {
    LAST_CHAIN_METRICS_SNAPSHOT
        .lock()
        .ok()
        .and_then(|snapshot| *snapshot)
        .unwrap_or_else(empty_chain_metrics_snapshot)
}

fn update_cached_chain_metrics_snapshot(snapshot: ChainMetricsSnapshot) {
    if snapshot.0 == 0 {
        return;
    }
    if let Ok(mut cached) = LAST_CHAIN_METRICS_SNAPSHOT.lock() {
        *cached = Some(snapshot);
    }
}

fn collect_chain_metrics_snapshot() -> ChainMetricsSnapshot {
    match SHARED_CHAIN.try_lock() {
        Ok(chain) => {
            let height = chain.last().map(|block| block.block_index).unwrap_or(0);
            let block_count = chain.chain.len() as u64;
            let last_timestamp = chain.last().map(|block| block.timestamp).unwrap_or(0);
            let latest_transactions = chain
                .last()
                .map(|block| block.transactions.len() as u64)
                .unwrap_or(0);
            let latest_gas = chain
                .last()
                .map(|block| {
                    block
                        .transactions
                        .iter()
                        .map(|transaction| transaction.get_fee())
                        .sum::<u64>()
                })
                .unwrap_or(0);
            let latest_interval = chain
                .chain
                .iter()
                .rev()
                .take(2)
                .map(|block| block.timestamp)
                .collect::<Vec<_>>();
            let latest_interval = if latest_interval.len() == 2 {
                latest_interval[0].saturating_sub(latest_interval[1])
            } else {
                0
            };
            let total_transactions = chain
                .chain
                .iter()
                .map(|block| block.transactions.len() as u64)
                .sum::<u64>();
            let recent_blocks = chain.chain.iter().rev().take(100).collect::<Vec<_>>();
            let recent_transactions = recent_blocks
                .iter()
                .map(|block| block.transactions.len() as u64)
                .sum::<u64>();
            let recent_gas = recent_blocks
                .iter()
                .map(|block| {
                    block
                        .transactions
                        .iter()
                        .map(|transaction| transaction.get_fee())
                        .sum::<u64>()
                })
                .sum::<u64>();
            let recent_avg_txs = if recent_blocks.is_empty() {
                0.0
            } else {
                recent_transactions as f64 / recent_blocks.len() as f64
            };
            let mut intervals = Vec::new();
            for pair in recent_blocks.windows(2) {
                intervals.push(pair[0].timestamp.saturating_sub(pair[1].timestamp));
            }
            let recent_avg_block_time = if intervals.is_empty() {
                0.0
            } else {
                intervals.iter().sum::<u64>() as f64 / intervals.len() as f64
            };
            let recent_avg_gas = if recent_blocks.is_empty() {
                0.0
            } else {
                recent_gas as f64 / recent_blocks.len() as f64
            };
            let snapshot = (
                height,
                block_count,
                last_timestamp,
                latest_transactions,
                latest_gas,
                latest_interval,
                total_transactions,
                recent_transactions,
                recent_avg_block_time,
                recent_avg_txs,
                recent_avg_gas,
            );
            update_cached_chain_metrics_snapshot(snapshot);
            snapshot
        }
        Err(_) => cached_chain_metrics_snapshot(),
    }
}

fn render_metrics(config: &NodeConfig, start_time: SystemTime) -> String {
    let start_time_seconds = start_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime_seconds = now_seconds.saturating_sub(start_time_seconds);

    let (
        chain_height,
        chain_blocks_total,
        last_block_timestamp_seconds,
        latest_block_transactions,
        latest_block_gas_nwei,
        latest_block_interval_seconds,
        chain_transactions_total,
        recent_transactions_total,
        recent_avg_block_time_seconds,
        recent_avg_txs_per_block,
        recent_avg_gas_nwei,
    ) = collect_chain_metrics_snapshot();
    let last_block_age_seconds = if last_block_timestamp_seconds == 0 {
        0
    } else {
        now_seconds.saturating_sub(last_block_timestamp_seconds)
    };

    let (
        mempool_pending_total,
        mempool_gas_limit_total,
        mempool_fee_nwei_total,
        mempool_min_gas_price_nwei,
        mempool_avg_gas_price_nwei,
        mempool_max_gas_price_nwei,
    ) = match TX_POOL.try_lock() {
        Ok(pool) => {
            let pending = pool.len() as u64;
            let gas_limit_total = pool.iter().map(|tx| tx.gas_limit).sum::<u64>();
            let fee_total = pool.iter().map(|tx| tx.get_fee()).sum::<u64>();
            let min_gas_price = pool.iter().map(|tx| tx.gas_price).min().unwrap_or(0);
            let max_gas_price = pool.iter().map(|tx| tx.gas_price).max().unwrap_or(0);
            let avg_gas_price = if pending == 0 {
                0.0
            } else {
                pool.iter().map(|tx| tx.gas_price).sum::<u64>() as f64 / pending as f64
            };
            (
                pending,
                gas_limit_total,
                fee_total,
                min_gas_price,
                avg_gas_price,
                max_gas_price,
            )
        }
        Err(_) => (0, 0, 0, 0, 0.0, 0),
    };

    let (
        sync_state_label,
        sync_in_progress,
        sync_highest_block,
        sync_starting_block,
        sync_progress_percent,
    ) = match SYNC_MANAGER.try_lock() {
        Ok(manager) => {
            let state = manager.get_state();
            let highest = manager.get_network_height();
            let starting = manager.get_sync_start_height();
            (
                sync_state_name(state).to_string(),
                !matches!(state, SyncState::Synced | SyncState::Idle),
                highest,
                starting,
                manager.get_progress_percentage(),
            )
        }
        Err(_) => ("unknown".to_string(), false, 0, 0, 0.0),
    };

    let (
        p2p_peer_total,
        p2p_status_ready_validators,
        p2p_best_validator_peer_height,
        peer_metric_lines,
    ) = match crate::p2p::get_p2p_network() {
        Some(network) => {
            let snapshots = network.collect_peer_snapshots();
            let mut lines = String::new();
            for peer in &snapshots {
                let peer_label = escape_label_value(&peer.address);
                let direction = escape_label_value(&peer.direction);
                let node_id = escape_label_value(peer.node_id.as_deref().unwrap_or(""));
                let validator_address =
                    escape_label_value(peer.validator_address.as_deref().unwrap_or(""));
                lines.push_str(&format!(
                    "synergy_p2p_peer_info{{peer=\"{peer_label}\",direction=\"{direction}\",node_id=\"{node_id}\",validator_address=\"{validator_address}\"}} 1\n"
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_height{{peer=\"{peer_label}\"}} {}\n",
                    peer.block_height
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_last_seen_age_seconds{{peer=\"{peer_label}\"}} {}\n",
                    now_seconds.saturating_sub(peer.last_seen)
                ));
                let status_age = peer
                    .status_received_at
                    .map(|timestamp| now_seconds.saturating_sub(timestamp))
                    .unwrap_or(0);
                lines.push_str(&format!(
                    "synergy_p2p_peer_status_age_seconds{{peer=\"{peer_label}\"}} {status_age}\n"
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_blocks_sent_total{{peer=\"{peer_label}\"}} {}\n",
                    peer.blocks_sent
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_blocks_received_total{{peer=\"{peer_label}\"}} {}\n",
                    peer.blocks_received
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_txs_sent_total{{peer=\"{peer_label}\"}} {}\n",
                    peer.txs_sent
                ));
                lines.push_str(&format!(
                    "synergy_p2p_peer_txs_received_total{{peer=\"{peer_label}\"}} {}\n",
                    peer.txs_received
                ));
            }
            (
                snapshots.len() as u64,
                network.get_status_ready_validator_count() as u64,
                network.get_best_validator_peer_height(),
                lines,
            )
        }
        None => (0, 0, 0, String::new()),
    };

    let sync_gap_blocks = observed_sync_gap_blocks(
        chain_height,
        sync_highest_block,
        p2p_best_validator_peer_height,
    );

    let (
        validators_total,
        validator_pending_total,
        validator_active_total,
        validator_inactive_total,
        validator_jailed_total,
        validator_slashed_total,
        clusters_total,
    ) = match VALIDATOR_MANAGER.registry.try_lock() {
        Ok(registry) => {
            let mut active = 0_u64;
            let mut inactive = 0_u64;
            let mut jailed = 0_u64;
            let mut slashed = 0_u64;
            for validator in registry.validators.values() {
                match validator.status {
                    ValidatorStatus::Active => active += 1,
                    ValidatorStatus::Inactive => inactive += 1,
                    ValidatorStatus::Jailed => jailed += 1,
                    ValidatorStatus::Slashed => slashed += 1,
                    ValidatorStatus::Pending => {}
                    ValidatorStatus::Shadow => {}
                }
            }
            (
                registry.validators.len() as u64,
                registry.pending_registrations.len() as u64,
                active,
                inactive,
                jailed,
                slashed,
                registry.clusters.len() as u64,
            )
        }
        Err(_) => (0, 0, 0, 0, 0, 0, 0),
    };

    let configured_peer_targets = (config.network.bootnodes.len()
        + config.network.seed_servers.len()
        + config.network.bootstrap_dns_records.len()
        + config.network.additional_dial_targets.len()
        + config.network.persistent_peers.len()) as u64;
    let consensus_runtime_metrics =
        crate::consensus::dual_quorum::DualQuorumConsensus::consensus_runtime_metrics_snapshot();
    let proposal_cache_discard_total =
        crate::consensus::consensus_algorithm::ProofOfSynergy::proposal_cache_discard_count();
    let expired_transaction_drop_total = crate::consensus::consensus_algorithm::ProofOfSynergy::
        expired_proposal_transaction_drop_count();
    let qrpc_fallback_total = crate::rpc::rpc_server::qrpc_fallback_count();

    let mut body = String::new();
    push_metric_header(
        &mut body,
        "synergy_node_info",
        "Static identity and role labels for this Synergy node.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_node_info{{network=\"{}\",role=\"{}\",node_id=\"{}\",node_name=\"{}\",validator_address=\"{}\"}} 1\n",
        escape_label_value(&config.network.name),
        escape_label_value(&config.identity.role),
        escape_label_value(&config.identity.node_id),
        escape_label_value(&config.p2p.node_name),
        escape_label_value(&config.node.validator_address),
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_height",
        "Latest block height in the shared chain state.",
        "gauge",
    );
    body.push_str(&format!("synergy_chain_height {chain_height}\n"));

    push_metric_header(
        &mut body,
        "synergy_chain_blocks_total",
        "Number of blocks currently held in memory.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_blocks_total {chain_blocks_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_last_block_timestamp_seconds",
        "Unix timestamp for the latest block in the shared chain state.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_last_block_timestamp_seconds {last_block_timestamp_seconds}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_last_block_age_seconds",
        "Age of the latest local block, in seconds.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_last_block_age_seconds {last_block_age_seconds}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_latest_block_transactions",
        "Number of transactions included in the latest local block.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_latest_block_transactions {latest_block_transactions}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_latest_block_gas_nwei",
        "Total transaction fee units in the latest local block, measured in nWei.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_latest_block_gas_nwei {latest_block_gas_nwei}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_latest_block_interval_seconds",
        "Seconds between the latest block and its local parent.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_latest_block_interval_seconds {latest_block_interval_seconds}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_transactions_total",
        "Total number of transactions currently held in local chain state.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_transactions_total {chain_transactions_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_recent_transactions_total",
        "Transactions included in the latest 100 local blocks.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_recent_transactions_total {recent_transactions_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_recent_avg_block_time_seconds",
        "Average block interval across the latest 100 local blocks.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_recent_avg_block_time_seconds {recent_avg_block_time_seconds:.3}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_recent_avg_transactions_per_block",
        "Average transaction count per block across the latest 100 local blocks.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_recent_avg_transactions_per_block {recent_avg_txs_per_block:.3}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_recent_avg_gas_nwei_per_block",
        "Average transaction fee units per block across the latest 100 local blocks, measured in nWei.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_recent_avg_gas_nwei_per_block {recent_avg_gas_nwei:.3}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_block_gas_limit",
        "Configured maximum gas per block.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_block_gas_limit {BLOCK_GAS_LIMIT}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_chain_recent_gas_utilization_ratio",
        "Average recent block gas divided by the configured block gas limit.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_chain_recent_gas_utilization_ratio {:.6}\n",
        recent_avg_gas_nwei / BLOCK_GAS_LIMIT as f64
    ));

    push_metric_header(
        &mut body,
        "synergy_validator_registry_total",
        "Number of validators tracked in the local registry.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_validator_registry_total {validators_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_validator_pending_total",
        "Number of validator registrations still pending approval.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_validator_pending_total {validator_pending_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_validator_status_total",
        "Number of validators in each status bucket.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_validator_status_total{{status=\"active\"}} {validator_active_total}\n"
    ));
    body.push_str(&format!(
        "synergy_validator_status_total{{status=\"inactive\"}} {validator_inactive_total}\n"
    ));
    body.push_str(&format!(
        "synergy_validator_status_total{{status=\"jailed\"}} {validator_jailed_total}\n"
    ));
    body.push_str(&format!(
        "synergy_validator_status_total{{status=\"slashed\"}} {validator_slashed_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_validator_clusters_total",
        "Number of validator clusters in the local registry.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_validator_clusters_total {clusters_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_configured_peer_targets_total",
        "Total configured peer bootstrap targets for this node.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_configured_peer_targets_total {configured_peer_targets}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_live_validator_count",
        "Validators currently observed as live over the P2P status path.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_live_validator_count {p2p_status_ready_validators}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_active_validator_count",
        "Validators currently eligible for consensus from live P2P status evidence.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_active_validator_count {p2p_status_ready_validators}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_registry_active_validator_count",
        "Validators marked active in the local validator registry.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_registry_active_validator_count {validator_active_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_current_consensus_height",
        "Most recent consensus height observed by the local round runner.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_current_consensus_height {}\n",
        consensus_runtime_metrics.current_height
    ));

    push_metric_header(
        &mut body,
        "synergy_current_consensus_round",
        "Most recent consensus round observed by the local round runner.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_current_consensus_round {}\n",
        consensus_runtime_metrics.current_round
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_timeout_mode",
        "Current consensus timeout mode, labelled as fast or recovery.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_timeout_mode{{mode=\"{}\"}} 1\n",
        escape_label_value(&consensus_runtime_metrics.timeout_mode)
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_effective_vote_timeout_seconds",
        "Effective vote timeout used for the current consensus round.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_effective_vote_timeout_seconds {}\n",
        consensus_runtime_metrics.effective_vote_timeout_secs
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_votes_collected",
        "Votes collected in the most recently observed consensus round.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_votes_collected {}\n",
        consensus_runtime_metrics.votes_collected
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_votes_required",
        "Votes required for quorum in the most recently observed consensus round.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_votes_required {}\n",
        consensus_runtime_metrics.votes_required
    ));

    push_metric_header(
        &mut body,
        "synergy_consensus_leader_info",
        "Leader identity for the most recently observed consensus round.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_leader_info{{leader=\"{}\",reason=\"{}\"}} 1\n",
        escape_label_value(&consensus_runtime_metrics.leader),
        escape_label_value(&consensus_runtime_metrics.retry_reason)
    ));

    push_metric_header(
        &mut body,
        "synergy_proposal_cache_discard_total",
        "Cached block proposals discarded because they were unsafe to reuse.",
        "counter",
    );
    body.push_str(&format!(
        "synergy_proposal_cache_discard_total {proposal_cache_discard_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_expired_transaction_drop_total",
        "Expired transactions dropped before block proposal construction.",
        "counter",
    );
    body.push_str(&format!(
        "synergy_expired_transaction_drop_total {expired_transaction_drop_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_qrpc_fallback_total",
        "qRPC read requests served from last-known-good or fallback state.",
        "counter",
    );
    body.push_str(&format!(
        "synergy_qrpc_fallback_total {qrpc_fallback_total}\n"
    ));

    // These series are sourced directly from the operational typed PoSy
    // coordinator. Observer/indexing timestamps are deliberately excluded:
    // Atlas and release monitoring must not infer consensus health from
    // database insertion time.
    let typed = crate::consensus::typed_coordinator::typed_consensus_telemetry_snapshot();
    let pqc = crate::crypto::aegis_pqvm::pqc_verification_metrics_snapshot();
    let p2p_handshakes = crate::p2p::networking::p2p_handshake_metrics_snapshot();
    push_metric_header(
        &mut body,
        "p2p_verified_handshakes_total",
        "P2P handshakes successfully verified with the real post-quantum implementation.",
        "counter",
    );
    body.push_str(&format!(
        "p2p_verified_handshakes_total{{algorithm=\"ML-DSA-65\"}} {}\n",
        p2p_handshakes.mldsa65_verified
    ));
    body.push_str(&format!(
        "p2p_verified_handshakes_total{{algorithm=\"FN-DSA-1024\"}} {}\n",
        p2p_handshakes.fndsa_verified
    ));
    push_metric_header(
        &mut body,
        "consensus_finalized_height",
        "Latest height finalized by the typed validator coordinator.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_finalized_height {}\n",
        typed.finalized_height
    ));
    push_metric_header(
        &mut body,
        "consensus_finalized_block_id",
        "Identity of the latest block finalized directly by typed consensus.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_finalized_block_id{{block_id=\"{}\"}} 1\n",
        escape_label_value(&typed.finalized_block_id)
    ));
    push_metric_header(
        &mut body,
        "consensus_finalized_round",
        "Round that finalized the latest typed block.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_finalized_round {}\n",
        typed.finalized_round
    ));
    push_metric_header(
        &mut body,
        "consensus_finality_interval_seconds",
        "Wall-clock interval between the latest two local typed finality commits.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_finality_interval_seconds {:.6}\n",
        typed.finality_interval_millis as f64 / 1_000.0
    ));
    let mut finality_intervals = typed
        .finality_intervals_millis
        .iter()
        .copied()
        .collect::<Vec<_>>();
    finality_intervals.sort_unstable();
    let finality_sample_count = finality_intervals.len();
    let finality_mean_millis = if finality_sample_count == 0 {
        0.0
    } else {
        finality_intervals
            .iter()
            .map(|value| *value as f64)
            .sum::<f64>()
            / finality_sample_count as f64
    };
    let percentile_millis = |percentile: usize| -> u64 {
        if finality_intervals.is_empty() {
            return 0;
        }
        let rank = (percentile * finality_intervals.len()).div_ceil(100);
        finality_intervals[rank.saturating_sub(1).min(finality_intervals.len() - 1)]
    };
    for (name, help, value) in [
        (
            "consensus_finality_interval_mean_seconds",
            "Mean typed finality interval over the latest 10,000 finalized-block intervals.",
            finality_mean_millis / 1_000.0,
        ),
        (
            "consensus_finality_interval_median_seconds",
            "Median typed finality interval over the latest 10,000 finalized-block intervals.",
            percentile_millis(50) as f64 / 1_000.0,
        ),
        (
            "consensus_finality_interval_p95_seconds",
            "P95 typed finality interval over the latest 10,000 finalized-block intervals.",
            percentile_millis(95) as f64 / 1_000.0,
        ),
        (
            "consensus_finality_interval_sample_count",
            "Number of typed finality intervals retained for direct health qualification.",
            finality_sample_count as f64,
        ),
    ] {
        push_metric_header(&mut body, name, help, "gauge");
        body.push_str(&format!("{name} {value:.6}\n"));
    }
    push_metric_header(
        &mut body,
        "consensus_phase_duration_seconds",
        "Most recently completed typed consensus phase duration.",
        "gauge",
    );
    for (phase, millis) in &typed.phase_duration_millis {
        body.push_str(&format!(
            "consensus_phase_duration_seconds{{phase=\"{}\"}} {:.6}\n",
            escape_label_value(phase),
            *millis as f64 / 1_000.0
        ));
    }
    let round_zero_ratio = if typed.finalized_blocks == 0 {
        0.0
    } else {
        typed.round_zero_finalized_blocks as f64 / typed.finalized_blocks as f64
    };
    let startup_phase = if typed.startup_phase.is_empty() {
        "UNINITIALIZED"
    } else {
        typed.startup_phase.as_str()
    };
    push_metric_header(
        &mut body,
        "consensus_startup_phase_info",
        "Current typed-consensus startup/readiness phase.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_startup_phase_info{{phase=\"{}\"}} 1\n",
        escape_label_value(startup_phase)
    ));
    push_metric_header(
        &mut body,
        "consensus_ready",
        "One only after recovery, mailbox, peer readiness, and release barrier complete.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_ready {}\n",
        u8::from(startup_phase == "RUNNING")
    ));
    for (name, help, value) in [
        (
            "consensus_round_zero_ratio",
            "Fraction of locally finalized typed blocks committed in round zero.",
            round_zero_ratio,
        ),
        (
            "consensus_current_height",
            "Current typed consensus height.",
            typed.current_height as f64,
        ),
        (
            "consensus_current_round",
            "Current typed consensus round.",
            typed.current_round as f64,
        ),
        (
            "consensus_prepared_height",
            "Height of the current durable prepared certificate.",
            typed.prepared_height as f64,
        ),
        (
            "consensus_prepared_round",
            "Round of the current durable prepared certificate.",
            typed.prepared_round as f64,
        ),
        (
            "consensus_mailbox_depth",
            "Messages in the typed startup buffer and bounded coordinator mailbox quotas.",
            typed.mailbox_depth as f64,
        ),
    ] {
        push_metric_header(&mut body, name, help, "gauge");
        body.push_str(&format!("{name} {value}\n"));
    }
    push_metric_header(
        &mut body,
        "consensus_prepared_candidate",
        "Candidate identity held by the latest durable prepared certificate.",
        "gauge",
    );
    body.push_str(&format!(
        "consensus_prepared_candidate{{candidate_id=\"{}\"}} 1\n",
        escape_label_value(&typed.prepared_candidate)
    ));
    for (name, help, value) in [
        (
            "consensus_highest_qc_height",
            "Height of the highest durable typed finality quorum certificate.",
            typed.highest_qc_height,
        ),
        (
            "consensus_highest_tc_round",
            "Next round authorized by the highest durable timeout certificate.",
            typed.highest_tc_round,
        ),
    ] {
        push_metric_header(&mut body, name, help, "gauge");
        body.push_str(&format!("{name} {value}\n"));
    }
    for (name, help, label, value) in [
        (
            "consensus_highest_qc_block_id",
            "Candidate bound by the highest durable finality QC.",
            "block_id",
            typed.highest_qc_block_id.as_str(),
        ),
        (
            "consensus_highest_qc_root",
            "Canonical root of the highest durable finality QC.",
            "root",
            typed.highest_qc_root.as_str(),
        ),
        (
            "consensus_highest_tc_root",
            "Canonical root of the highest durable timeout certificate.",
            "root",
            typed.highest_tc_root.as_str(),
        ),
    ] {
        push_metric_header(&mut body, name, help, "gauge");
        body.push_str(&format!(
            "{name}{{{label}=\"{}\"}} 1\n",
            escape_label_value(value)
        ));
    }
    if let Some(identity) = crate::desired_state::verified_desired_state_identity() {
        push_metric_header(
            &mut body,
            "chain1266_desired_state_info",
            "Exact verified release, source, artifact, config, Genesis, and state identity.",
            "gauge",
        );
        body.push_str(&format!(
            concat!(
                "chain1266_desired_state_info{{release_id=\"{}\",node_id=\"{}\",role_profile=\"{}\",",
                "chain_id=\"{}\",chain_incarnation=\"{}\",genesis_hash=\"{}\",validator_set_root=\"{}\",",
                "consensus_state_schema_version=\"{}\",state_namespace=\"{}\",testnet_v3_revision=\"{}\",",
                "synq_revision=\"{}\",aegis_revision=\"{}\",binary_sha256=\"{}\",configuration_sha256=\"{}\",",
                "desired_state_sha256=\"{}\",desired_state_signature_sha256=\"{}\",state_root=\"{}\"}} 1\n"
            ),
            escape_label_value(&identity.release_id),
            escape_label_value(&identity.node_id),
            escape_label_value(&identity.role_profile),
            identity.chain_id,
            identity.chain_incarnation,
            escape_label_value(&identity.genesis_hash),
            escape_label_value(&identity.validator_set_root),
            identity.consensus_state_schema_version,
            escape_label_value(&identity.directory_namespace),
            escape_label_value(&identity.testnet_v3_revision),
            escape_label_value(&identity.synq_revision),
            escape_label_value(&identity.aegis_revision),
            escape_label_value(&identity.binary_sha256),
            escape_label_value(&identity.configuration_sha256),
            escape_label_value(&identity.desired_state_sha256),
            escape_label_value(&identity.desired_state_signature_sha256),
            escape_label_value(&identity.state_root),
        ));
    }
    for (name, help, values) in [
        (
            "consensus_messages_received_total",
            "Typed consensus messages received by type.",
            &typed.messages_received,
        ),
        (
            "consensus_messages_deduplicated_total",
            "Typed consensus messages suppressed as exact replays by type.",
            &typed.messages_deduplicated,
        ),
        (
            "consensus_messages_rejected_precrypto_total",
            "Typed messages rejected before PQ verification by reason.",
            &typed.messages_rejected_precrypto,
        ),
        (
            "consensus_rebroadcast_total",
            "Typed consensus rebroadcasts by message type.",
            &typed.rebroadcasts,
        ),
    ] {
        push_metric_header(&mut body, name, help, "counter");
        let label_name = if name == "consensus_messages_rejected_precrypto_total" {
            "reason"
        } else {
            "type"
        };
        for (label, value) in values {
            body.push_str(&format!(
                "{name}{{{label_name}=\"{}\"}} {value}\n",
                escape_label_value(label)
            ));
        }
    }
    for (name, help, value, metric_type) in [
        (
            "pqc_verification_requests_total",
            "Uncached PQ verification jobs submitted to the bounded worker pool.",
            pqc.requests as f64,
            "counter",
        ),
        (
            "pqc_verification_cache_hits_total",
            "Positive PQ verification cache hits.",
            pqc.cache_hits as f64,
            "counter",
        ),
        (
            "pqc_verification_cache_misses_total",
            "Positive PQ verification cache misses.",
            pqc.cache_misses as f64,
            "counter",
        ),
        (
            "pqc_verification_duration_seconds",
            "Cumulative worker time spent performing uncached PQ verification.",
            pqc.verification_duration_micros as f64 / 1_000_000.0,
            "counter",
        ),
        (
            "pqc_verification_queue_depth",
            "Current bounded PQ verification queue depth.",
            pqc.queue_depth as f64,
            "gauge",
        ),
        (
            "pqc_verification_cache_evictions",
            "Positive PQ verification cache evictions.",
            pqc.cache_evictions as f64,
            "counter",
        ),
        (
            "pqc_verification_queue_rejections",
            "PQ verification jobs rejected by bounded backpressure.",
            pqc.queue_rejections as f64,
            "counter",
        ),
        (
            "consensus_restarts_total",
            "Typed coordinator restarts durably observed after the first successful start.",
            typed.restarts as f64,
            "counter",
        ),
    ] {
        push_metric_header(&mut body, name, help, metric_type);
        body.push_str(&format!("{name} {value}\n"));
    }

    for (name, help, value) in [
        (
            "consensus_message_deduplications",
            "Total exact typed-consensus envelope deduplications.",
            typed.messages_deduplicated.values().copied().sum::<u64>() as f64,
        ),
        (
            "consensus_precrypto_rejections",
            "Total typed messages rejected before PQ verification.",
            typed
                .messages_rejected_precrypto
                .values()
                .copied()
                .sum::<u64>() as f64,
        ),
        (
            "consensus_rebroadcasts",
            "Total typed consensus rebroadcasts.",
            typed.rebroadcasts.values().copied().sum::<u64>() as f64,
        ),
        (
            "consensus_restart_count",
            "Durable typed-coordinator restart count.",
            typed.restarts as f64,
        ),
        (
            "pqc_verification_requests",
            "Uncached PQ verification requests.",
            pqc.requests as f64,
        ),
        (
            "pqc_verification_cache_hits",
            "Positive PQ verification cache hits.",
            pqc.cache_hits as f64,
        ),
        (
            "pqc_verification_cache_misses",
            "Positive PQ verification cache misses.",
            pqc.cache_misses as f64,
        ),
        (
            "pqc_verification_duration",
            "Cumulative PQ verification worker duration in seconds.",
            pqc.verification_duration_micros as f64 / 1_000_000.0,
        ),
    ] {
        push_metric_header(&mut body, name, help, "counter");
        body.push_str(&format!("{name} {value}\n"));
    }

    push_metric_header(
        &mut body,
        "synergy_mempool_pending_transactions",
        "Transactions waiting in the local node transaction pool.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_mempool_pending_transactions {mempool_pending_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_mempool_gas_limit_total",
        "Sum of gas limits for transactions waiting in the local transaction pool.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_mempool_gas_limit_total {mempool_gas_limit_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_mempool_fee_nwei_total",
        "Total fee units for transactions waiting in the local transaction pool, measured in nWei.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_mempool_fee_nwei_total {mempool_fee_nwei_total}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_mempool_gas_price_nwei",
        "Gas price distribution for transactions waiting in the local transaction pool.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_mempool_gas_price_nwei{{stat=\"min\"}} {mempool_min_gas_price_nwei}\n"
    ));
    body.push_str(&format!(
        "synergy_mempool_gas_price_nwei{{stat=\"avg\"}} {mempool_avg_gas_price_nwei:.3}\n"
    ));
    body.push_str(&format!(
        "synergy_mempool_gas_price_nwei{{stat=\"max\"}} {mempool_max_gas_price_nwei}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_sync_info",
        "Current sync state label for this node.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_sync_info{{state=\"{}\"}} 1\n",
        escape_label_value(&sync_state_label)
    ));

    push_metric_header(
        &mut body,
        "synergy_sync_in_progress",
        "Whether this node is currently syncing, represented as 0 or 1.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_sync_in_progress {}\n",
        if sync_in_progress { 1 } else { 0 }
    ));

    push_metric_header(
        &mut body,
        "synergy_sync_highest_block",
        "Highest block height observed by the sync manager.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_sync_highest_block {sync_highest_block}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_sync_starting_block",
        "Block height where the current sync run started.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_sync_starting_block {sync_starting_block}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_sync_gap_blocks",
        "Difference between the highest observed sync height and this node's local height.",
        "gauge",
    );
    body.push_str(&format!("synergy_sync_gap_blocks {sync_gap_blocks}\n"));

    push_metric_header(
        &mut body,
        "synergy_sync_progress_percent",
        "Current sync progress percentage reported by the sync manager.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_sync_progress_percent {sync_progress_percent:.3}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_p2p_peers_connected",
        "Connected P2P peers visible to this node.",
        "gauge",
    );
    body.push_str(&format!("synergy_p2p_peers_connected {p2p_peer_total}\n"));

    push_metric_header(
        &mut body,
        "synergy_p2p_status_ready_validators",
        "Connected validators with status data ready for consensus membership checks.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_p2p_status_ready_validators {p2p_status_ready_validators}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_p2p_best_validator_peer_height",
        "Best block height reported by connected validator peers.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_p2p_best_validator_peer_height {p2p_best_validator_peer_height}\n"
    ));

    push_metric_header(
        &mut body,
        "synergy_p2p_peer_info",
        "Static peer labels for currently connected peers.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_height",
        "Last block height reported by each connected peer.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_last_seen_age_seconds",
        "Seconds since each connected peer was last seen.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_status_age_seconds",
        "Seconds since each connected peer last sent status data.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_blocks_sent_total",
        "Blocks sent to each connected peer by this process.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_blocks_received_total",
        "Blocks received from each connected peer by this process.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_txs_sent_total",
        "Transactions sent to each connected peer by this process.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_p2p_peer_txs_received_total",
        "Transactions received from each connected peer by this process.",
        "counter",
    );
    body.push_str(&peer_metric_lines);

    push_metric_header(
        &mut body,
        "synergy_consensus_config",
        "Consensus timing and quorum configuration values.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"block_time_secs\"}} {}\n",
        config.consensus.block_time_secs
    ));
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"vote_timeout_secs\"}} {}\n",
        config.consensus.vote_timeout_secs
    ));
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"block_timeout_secs\"}} {}\n",
        config.consensus.block_timeout_secs
    ));
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"leader_timeout_secs\"}} {}\n",
        config.consensus.leader_timeout_secs
    ));
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"validator_vote_threshold\"}} {}\n",
        config.consensus.validator_vote_threshold
    ));
    body.push_str(&format!(
        "synergy_consensus_config{{setting=\"min_validators\"}} {}\n",
        config.consensus.min_validators
    ));

    push_metric_header(
        &mut body,
        "synergy_validator_blocks_produced_total",
        "Blocks produced by each validator according to the local registry.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_transactions_validated_total",
        "Transactions validated by each validator according to the local registry.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_missed_blocks_total",
        "Missed blocks recorded for each validator according to the local registry.",
        "counter",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_average_block_time_seconds",
        "Average block time recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_uptime_percent",
        "Uptime percentage recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_synergy_score",
        "Synergy score recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_stake_nwei",
        "Stake amount recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_consecutive_missed_votes",
        "Consecutive missed votes recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_missed_vote_window",
        "Rolling missed-vote window recorded for each validator according to the local registry.",
        "gauge",
    );
    push_metric_header(
        &mut body,
        "synergy_validator_equivocation_evidence_total",
        "Equivocation evidence count recorded for each validator according to the local registry.",
        "counter",
    );
    if let Ok(registry) = VALIDATOR_MANAGER.registry.try_lock() {
        for validator in registry.validators.values() {
            let address = escape_label_value(&validator.address);
            let name = escape_label_value(&validator.name);
            let status = escape_label_value(validator_status_name(&validator.status));
            let labels = format!("validator=\"{address}\",name=\"{name}\",status=\"{status}\"");
            body.push_str(&format!(
                "synergy_validator_blocks_produced_total{{{labels}}} {}\n",
                validator.total_blocks_produced
            ));
            body.push_str(&format!(
                "synergy_validator_transactions_validated_total{{{labels}}} {}\n",
                validator.total_transactions_validated
            ));
            body.push_str(&format!(
                "synergy_validator_missed_blocks_total{{{labels}}} {}\n",
                validator.missed_blocks
            ));
            body.push_str(&format!(
                "synergy_validator_average_block_time_seconds{{{labels}}} {:.3}\n",
                validator.average_block_time
            ));
            body.push_str(&format!(
                "synergy_validator_uptime_percent{{{labels}}} {:.3}\n",
                validator.uptime_percentage
            ));
            body.push_str(&format!(
                "synergy_validator_synergy_score{{{labels}}} {:.6}\n",
                validator.synergy_score
            ));
            body.push_str(&format!(
                "synergy_validator_stake_nwei{{{labels}}} {}\n",
                validator.stake_amount
            ));
            body.push_str(&format!(
                "synergy_validator_consecutive_missed_votes{{{labels}}} {}\n",
                validator.consecutive_missed_votes
            ));
            body.push_str(&format!(
                "synergy_validator_missed_vote_window{{{labels}}} {}\n",
                validator.missed_vote_window
            ));
            body.push_str(&format!(
                "synergy_validator_equivocation_evidence_total{{{labels}}} {}\n",
                validator.equivocation_evidence_count
            ));
        }
    }

    push_metric_header(
        &mut body,
        "synergy_node_uptime_seconds",
        "Process uptime in seconds.",
        "counter",
    );
    body.push_str(&format!("synergy_node_uptime_seconds {uptime_seconds}\n"));

    push_metric_header(
        &mut body,
        "synergy_process_start_time_seconds",
        "Unix timestamp for the current process start time.",
        "gauge",
    );
    body.push_str(&format!(
        "synergy_process_start_time_seconds {start_time_seconds}\n"
    ));

    render_coordinated_consensus_metrics(&mut body, config);

    body
}

/// Renders P1-only finality and turn-state evidence.  The legacy typed-PoSy
/// series above remain backward-compatible operational diagnostics, but are
/// never used as evidence for a coordinated release.  These series appear
/// only when the loaded config resolves to the explicit P1 mode.
fn render_coordinated_consensus_metrics(body: &mut String, config: &NodeConfig) {
    let Ok(ResolvedConsensusMode::CoordinatedRoundRobinV1(coordinated_config)) = config
        .consensus
        .resolve_mode(config.blockchain.chain_id, &config.network.network_id)
    else {
        return;
    };

    let validator = coordinated_consensus_telemetry_snapshot();
    let observer = crate::consensus::coordinated_finality_observer::coordinated_finality_observer_telemetry_tip();
    let (
        source,
        active,
        finalized_height,
        finalized_block_id,
        finalized_producer_id,
        finalized_producer_round,
        assigned_height,
        assigned_producer_round,
        assigned_producer_id,
        missed_turns_total,
    ) = if validator.active {
        (
            "validator",
            1_u8,
            validator.finalized_height,
            validator.finalized_block_id,
            validator.finalized_producer_id,
            validator.finalized_producer_round,
            validator.assigned_height,
            validator.assigned_producer_round,
            validator.assigned_producer_id,
            validator.missed_turns_total,
        )
    } else if let Some(observer) = observer {
        (
            "observer",
            1_u8,
            observer.finalized_height,
            observer.finalized_block_id,
            observer.finalized_producer_id,
            observer.finalized_producer_round,
            0,
            0,
            String::new(),
            0,
        )
    } else {
        (
            "uninitialized",
            0_u8,
            0,
            String::new(),
            String::new(),
            0,
            0,
            0,
            String::new(),
            0,
        )
    };

    push_metric_header(
        body,
        "coordinated_consensus_mode_info",
        "Configured coordinated-round-robin P1 mode and source of its independently verified finality.",
        "gauge",
    );
    body.push_str(&format!(
        "coordinated_consensus_mode_info{{mode=\"{}\",coordinator_id=\"{}\",source=\"{source}\"}} 1\n",
        escape_label_value(&coordinated_config.consensus_version),
        escape_label_value(&coordinated_config.coordinator_id),
    ));
    push_metric_header(
        body,
        "coordinated_consensus_active",
        "One only after the P1 validator worker or non-signing finality observer is installed.",
        "gauge",
    );
    body.push_str(&format!(
        "coordinated_consensus_active{{source=\"{source}\"}} {active}\n"
    ));
    push_metric_header(
        body,
        "coordinated_consensus_finalized_height",
        "Latest independently verified P1 finalized height; observer values are replicated finality, not database insertion height.",
        "gauge",
    );
    body.push_str(&format!(
        "coordinated_consensus_finalized_height{{source=\"{source}\"}} {finalized_height}\n"
    ));
    push_metric_header(
        body,
        "coordinated_consensus_finalized_block_id",
        "Digest of the latest independently verified P1 finalized block.",
        "gauge",
    );
    body.push_str(&format!(
        "coordinated_consensus_finalized_block_id{{source=\"{source}\",block_id=\"{}\"}} 1\n",
        escape_label_value(&finalized_block_id)
    ));
    push_metric_header(
        body,
        "coordinated_consensus_finalized_producer_info",
        "Producer and producer round bound by the latest signed P1 coordinator commit.",
        "gauge",
    );
    body.push_str(&format!(
        "coordinated_consensus_finalized_producer_info{{source=\"{source}\",producer_id=\"{}\",producer_round=\"{finalized_producer_round}\"}} 1\n",
        escape_label_value(&finalized_producer_id)
    ));
    if source == "validator" {
        push_metric_header(
            body,
            "coordinated_consensus_assignment_info",
            "Current signed P1 assignment, or the next deterministic producer turn when no assignment is pending.",
            "gauge",
        );
        body.push_str(&format!(
            "coordinated_consensus_assignment_info{{height=\"{assigned_height}\",producer_round=\"{assigned_producer_round}\",producer_id=\"{}\"}} 1\n",
            escape_label_value(&assigned_producer_id)
        ));
        push_metric_header(
            body,
            "coordinated_consensus_missed_turns_total",
            "Durably evidenced P1 producer turns skipped without advancing block height.",
            "counter",
        );
        body.push_str(&format!(
            "coordinated_consensus_missed_turns_total {missed_turns_total}\n"
        ));
    }
}

fn push_metric_header(body: &mut String, name: &str, help: &str, metric_type: &str) {
    body.push_str(&format!("# HELP {name} {help}\n"));
    body.push_str(&format!("# TYPE {name} {metric_type}\n"));
}

fn escape_label_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn sync_state_name(state: SyncState) -> &'static str {
    match state {
        SyncState::Idle => "idle",
        SyncState::Discovering => "discovering",
        SyncState::Downloading => "downloading",
        SyncState::Validating => "validating",
        SyncState::Applying => "applying",
        SyncState::Synced => "synced",
    }
}

fn observed_sync_gap_blocks(
    chain_height: u64,
    sync_manager_highest_block: u64,
    p2p_best_validator_peer_height: u64,
) -> u64 {
    sync_manager_highest_block
        .max(p2p_best_validator_peer_height)
        .saturating_sub(chain_height)
}

fn validator_status_name(status: &ValidatorStatus) -> &'static str {
    match status {
        ValidatorStatus::Active => "active",
        ValidatorStatus::Inactive => "inactive",
        ValidatorStatus::Jailed => "jailed",
        ValidatorStatus::Slashed => "slashed",
        ValidatorStatus::Pending => "pending",
        ValidatorStatus::Shadow => "shadow",
    }
}

#[cfg(test)]
mod tests {
    use super::render_metrics;
    use crate::block::{Block, BlockChain};
    use crate::config::NodeConfig;
    use crate::rpc::rpc_server::SHARED_CHAIN;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{Duration, SystemTime};

    struct TestRuntimeGuard {
        _lock: MutexGuard<'static, ()>,
        previous: PathBuf,
        previous_genesis_file: Option<String>,
        runtime_dir: PathBuf,
    }

    impl TestRuntimeGuard {
        fn set(repo_root: &Path) -> Self {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            let previous = env::current_dir().expect("current dir should resolve");
            let previous_genesis_file = env::var("SYNERGY_GENESIS_FILE").ok();
            let runtime_dir = crate::utils::test_temp_root(format!(
                "synergy-telemetry-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system clock should be after epoch")
                    .as_nanos()
            ));
            fs::create_dir_all(runtime_dir.join("data")).expect("runtime data dir should exist");
            env::set_var(
                "SYNERGY_GENESIS_FILE",
                repo_root.join("config/genesis.json"),
            );
            env::set_current_dir(&runtime_dir).expect("current dir should update");
            Self {
                _lock: lock,
                previous,
                previous_genesis_file,
                runtime_dir,
            }
        }
    }

    impl Drop for TestRuntimeGuard {
        fn drop(&mut self) {
            env::set_current_dir(&self.previous).expect("current dir should restore");
            match &self.previous_genesis_file {
                Some(value) => env::set_var("SYNERGY_GENESIS_FILE", value),
                None => env::remove_var("SYNERGY_GENESIS_FILE"),
            }
            let _ = fs::remove_dir_all(&self.runtime_dir);
        }
    }

    #[test]
    fn render_metrics_includes_identity_labels() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate manifest should live under repo root");
        let _runtime = TestRuntimeGuard::set(repo_root);

        let mut config = NodeConfig::default();
        config.network.name = "synergy-testnet".to_string();
        config.identity.role = "validator".to_string();
        config.identity.node_id = "GenVal-01".to_string();
        config.p2p.node_name = "genesisval1".to_string();
        config.node.validator_address = "synv1test".to_string();

        let body = render_metrics(&config, SystemTime::now() - Duration::from_secs(5));

        assert!(body.contains("synergy_node_info"));
        assert!(body.contains("role=\"validator\""));
        assert!(body.contains("node_id=\"GenVal-01\""));
        assert!(body.contains("validator_address=\"synv1test\""));
        for metric in [
            "consensus_finalized_height",
            "consensus_finalized_round",
            "consensus_finality_interval_seconds",
            "consensus_finality_interval_mean_seconds",
            "consensus_finality_interval_median_seconds",
            "consensus_finality_interval_p95_seconds",
            "consensus_finality_interval_sample_count",
            "consensus_phase_duration_seconds",
            "consensus_round_zero_ratio",
            "consensus_current_round",
            "consensus_prepared_height",
            "consensus_prepared_round",
            "consensus_mailbox_depth",
            "consensus_messages_received_total",
            "consensus_messages_deduplicated_total",
            "consensus_messages_rejected_precrypto_total",
            "pqc_verification_requests_total",
            "pqc_verification_cache_hits_total",
            "pqc_verification_cache_misses_total",
            "pqc_verification_duration_seconds",
            "pqc_verification_queue_depth",
            "consensus_rebroadcast_total",
            "consensus_restarts_total",
            "consensus_startup_phase_info",
            "consensus_ready",
        ] {
            assert!(
                body.contains(&format!("# HELP {metric} ")),
                "missing release-gate metric {metric}"
            );
        }
    }

    #[test]
    fn render_metrics_exposes_signed_p1_finality_without_typed_relabeling() {
        let mut config = NodeConfig::default();
        config.blockchain.chain_id = 1266;
        config.network.network_id = "synergy-testnet-v3".to_string();
        config.consensus.mode =
            crate::consensus::coordinated_round_robin::COORDINATED_ROUND_ROBIN_V1.to_string();
        config.consensus.coordinator_id = "validator-1".to_string();
        config.consensus.producer_ids = (2..=6).map(|index| format!("validator-{index}")).collect();

        super::publish_coordinated_consensus_telemetry(
            super::CoordinatedConsensusTelemetrySnapshot {
                active: true,
                finalized_height: 73,
                finalized_block_id: "p1-finalized-block".to_string(),
                finalized_producer_id: "validator-4".to_string(),
                finalized_producer_round: 2,
                assigned_height: 74,
                assigned_producer_round: 0,
                assigned_producer_id: "validator-5".to_string(),
                missed_turns_total: 3,
            },
        );
        let mut body = String::new();
        super::render_coordinated_consensus_metrics(&mut body, &config);
        super::clear_coordinated_consensus_telemetry();

        assert!(body.contains(
            "coordinated_consensus_mode_info{mode=\"coordinated_round_robin_v1\",coordinator_id=\"validator-1\",source=\"validator\"} 1"
        ));
        assert!(body.contains("coordinated_consensus_finalized_height{source=\"validator\"} 73"));
        assert!(body.contains(
            "coordinated_consensus_finalized_block_id{source=\"validator\",block_id=\"p1-finalized-block\"} 1"
        ));
        assert!(body.contains(
            "coordinated_consensus_assignment_info{height=\"74\",producer_round=\"0\",producer_id=\"validator-5\"} 1"
        ));
        assert!(body.contains("coordinated_consensus_missed_turns_total 3"));
    }

    #[test]
    fn non_p1_config_does_not_emit_coordinated_consensus_metrics() {
        super::publish_coordinated_consensus_telemetry(
            super::CoordinatedConsensusTelemetrySnapshot {
                active: true,
                ..Default::default()
            },
        );
        let mut body = String::new();
        super::render_coordinated_consensus_metrics(&mut body, &NodeConfig::default());
        super::clear_coordinated_consensus_telemetry();
        assert!(!body.contains("coordinated_consensus_mode_info"));
    }

    #[test]
    fn sync_gap_uses_p2p_validator_height_when_sync_manager_is_idle() {
        assert_eq!(super::observed_sync_gap_blocks(303_717, 0, 303_725), 8);
        assert_eq!(
            super::observed_sync_gap_blocks(303_717, 303_720, 303_725),
            8
        );
        assert_eq!(
            super::observed_sync_gap_blocks(303_725, 303_720, 303_717),
            0
        );
    }

    #[test]
    fn render_metrics_includes_chain_mempool_sync_p2p_and_validator_series() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate manifest should live under repo root");
        let _runtime = TestRuntimeGuard::set(repo_root);

        let body = render_metrics(&NodeConfig::default(), SystemTime::now());

        assert!(body.contains("synergy_chain_last_block_age_seconds"));
        assert!(body.contains("synergy_chain_recent_avg_block_time_seconds"));
        assert!(body.contains("synergy_mempool_pending_transactions"));
        assert!(body.contains("synergy_sync_info"));
        assert!(body.contains("synergy_p2p_peers_connected"));
        assert!(body.contains("synergy_consensus_config"));
        assert!(body.contains("synergy_consensus_timeout_mode"));
        assert!(body.contains("synergy_proposal_cache_discard_total"));
        assert!(body.contains("synergy_qrpc_fallback_total"));
        assert!(body.contains("synergy_validator_blocks_produced_total"));
    }

    #[test]
    fn render_metrics_reuses_last_chain_height_when_chain_lock_is_busy() {
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate manifest should live under repo root");
        let _runtime = TestRuntimeGuard::set(repo_root);
        let previous_chain = {
            let mut chain = SHARED_CHAIN
                .lock()
                .expect("shared chain lock should succeed");
            let previous = chain.clone();
            let genesis = Block::new_with_timestamp(
                0,
                Vec::new(),
                "genesis-parent".to_string(),
                "validator-1".to_string(),
                0,
                1_700_000_000,
            );
            let child = Block::new_with_timestamp(
                1,
                Vec::new(),
                genesis.hash.clone(),
                "validator-2".to_string(),
                1,
                1_700_000_004,
            );
            *chain = BlockChain {
                chain: vec![genesis, child],
            };
            previous
        };

        let body = render_metrics(&NodeConfig::default(), SystemTime::now());
        assert!(body.contains("synergy_chain_height 1\n"));

        let chain_guard = SHARED_CHAIN
            .lock()
            .expect("shared chain lock should succeed");
        let contended_body = render_metrics(&NodeConfig::default(), SystemTime::now());
        drop(chain_guard);

        assert!(contended_body.contains("synergy_chain_height 1\n"));

        let mut chain = SHARED_CHAIN
            .lock()
            .expect("shared chain lock should succeed");
        *chain = previous_chain;
    }
}
