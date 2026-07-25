use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::NodeConfig;
use crate::gas::constants::BLOCK_GAS_LIMIT;
use crate::info;
use crate::rpc::rpc_server::{SHARED_CHAIN, SYNC_MANAGER, TX_POOL};
use crate::sync::SyncState;
use crate::validator::{ValidatorStatus, VALIDATOR_MANAGER};

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

type ChainMetricsSnapshot = (u64, u64, u64, u64, u64, u64, u64, u64, f64, f64, f64);

lazy_static::lazy_static! {
    static ref LAST_CHAIN_METRICS_SNAPSHOT: Mutex<Option<ChainMetricsSnapshot>> = Mutex::new(None);
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

    body
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
            let runtime_dir = env::temp_dir().join(format!(
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
