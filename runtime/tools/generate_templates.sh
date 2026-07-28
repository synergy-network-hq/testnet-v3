#!/bin/bash
set -euo pipefail

TEMPLATES_DIR="templates"
BOOTNODE_TARGETS='["snr://bootstrap@bootnode1.synergy-network.io:5620", "snr://bootstrap@bootnode2.synergy-network.io:5620", "snr://bootstrap@bootnode3.synergy-network.io:5620"]'
SEED_SERVER_TARGETS='["http://seed1.synergy-network.io:5621", "http://seed2.synergy-network.io:5621", "http://seed3.synergy-network.io:5621"]'
BOOTSTRAP_DNS_RECORDS='["_dnsaddr.bootstrap.synergy-network.io"]'
SENTRY1_TARGETS='["relay1.synergy-network.io:5622"]'
SENTRY2_TARGETS='["relay2.synergy-network.io:5622"]'
SENTRY_EDGE_TARGETS='["relay1.synergy-network.io:5622", "relay2.synergy-network.io:5622"]'
VALIDATOR_MESH_TARGETS='[]'
RELAYER_SUPPORT_TARGETS='["relay1.synergynode.xyz:5622", "relay2.synergynode.xyz:5622", "relay3.synergynode.xyz:5622"]'
ALLOWED_VALIDATOR_ADDRESSES='["synv11yc4cjehqjm6fp0ey4ppjptv0p3cwdy6r79t", "synv11k0vlmkt5gyp3czlgvlfm5yqkxu5nyvp4ekk", "synv11jk9pprkz7faykn4ez7hzaj2q7lg04l2fjgj", "synv11s7hag82s6d9f8urrv5cl40lyeamxelthpeg", "synv11cl92kxcx4jyzusecqydrxc8aj3hsgscrvtu", "synv1129lck2uvz73f59wd3yame0w04qnrdpmmmfc"]'

generate_template() {
    local node_type=$1
    local role_id=$2
    local compiled_profile=$3
    local node_name=$4
    local p2p_port=$5
    local rpc_port=$6
    local ws_port=$7
    local discovery_port=$8
    local metrics_port=$9
    local log_file=${10}
    local enable_pruning=${11:-false}
    local vrf_enabled=${12:-true}
    local bootstrap_mode=${13:-public-bootstrap}

    local bootnodes="$BOOTNODE_TARGETS"
    local seed_servers="$SEED_SERVER_TARGETS"
    local bootstrap_dns_records="$BOOTSTRAP_DNS_RECORDS"
    local additional_dial_targets="[]"
    local persistent_peers="[]"
    local enable_discovery="true"
    local enable_peer_exchange="true"
    local public_address="replace-with-public-host:$p2p_port"
    local discovery_public_address="replace-with-public-host:$discovery_port"
    local validator_vpn_transports=""
    local bootstrap_refresh_secs="60"
    local cors_enabled="false"
    local cors_origins="[]"
    local metrics_bind="127.0.0.1:${metrics_port}"
    local strict_allowlist="false"
    local snapshots_enabled="false"
    local snapshot_interval_blocks="5000"
    if [[ "$compiled_profile" == "validator_node" ]]; then
        strict_allowlist="true"
        validator_vpn_transports="validator_vpn_transports = []"
    fi
    if [[ "$role_id" == "archive_validator" ]]; then
        snapshots_enabled="true"
        snapshot_interval_blocks="15000"
    fi

    case "$bootstrap_mode" in
        validator-mesh)
            bootnodes="[]"
            seed_servers="[]"
            bootstrap_dns_records="[]"
            additional_dial_targets="$VALIDATOR_MESH_TARGETS"
            persistent_peers="$VALIDATOR_MESH_TARGETS"
            enable_discovery="false"
            enable_peer_exchange="false"
            public_address=""
            discovery_public_address=""
            bootstrap_refresh_secs="3600"
            if [[ "$role_id" == "relayer" ]]; then
                additional_dial_targets="$RELAYER_SUPPORT_TARGETS"
                persistent_peers="$RELAYER_SUPPORT_TARGETS"
            fi
            ;;
        sentry-edge)
            bootnodes="[]"
            seed_servers="[]"
            bootstrap_dns_records="[]"
            additional_dial_targets="$SENTRY_EDGE_TARGETS"
            persistent_peers="$SENTRY_EDGE_TARGETS"
            enable_discovery="false"
            bootstrap_refresh_secs="3600"
            ;;
        sentry1-only)
            bootnodes="[]"
            seed_servers="[]"
            bootstrap_dns_records="[]"
            additional_dial_targets="$SENTRY1_TARGETS"
            persistent_peers="$SENTRY1_TARGETS"
            enable_discovery="false"
            bootstrap_refresh_secs="3600"
            ;;
        sentry2-only)
            bootnodes="[]"
            seed_servers="[]"
            bootstrap_dns_records="[]"
            additional_dial_targets="$SENTRY2_TARGETS"
            persistent_peers="$SENTRY2_TARGETS"
            enable_discovery="false"
            bootstrap_refresh_secs="3600"
            ;;
    esac

    cat > "$TEMPLATES_DIR/$node_type.toml" <<EOF
[identity]
node_id = "$node_name"
role = "$role_id"
role_display = "$node_type"
address = ""
label = "$node_name"

[role]
compiled_profile = "$compiled_profile"
services = []

[network]
id = 1264
name = "synergy-testnet"
p2p_port = $p2p_port
rpc_port = $rpc_port
ws_port = $ws_port
max_peers = 100
bootnodes = $bootnodes
seed_servers = $seed_servers
bootstrap_dns_records = $bootstrap_dns_records
additional_dial_targets = $additional_dial_targets
persistent_peers = $persistent_peers
$validator_vpn_transports

[blockchain]
block_time = 2
max_gas_limit = "0x2fefd8"
chain_id = 1264

[consensus]
algorithm = "Proof of Synergy"
block_time_secs = 2
epoch_length = 1000
emergency_stable_committee_mode = true
freeze_validator_set = true
freeze_score_weighted_proposer_order = true
vote_only_rejoin_enabled = true
vote_only_probation_blocks = 1000
min_validators = 4
validator_cluster_size = 6
validator_vote_threshold = 0
max_validators = 0
status_ready_gate_enabled = true
status_ready_min_validators = 4
status_ready_genesis_grace_secs = 0
allow_genesis_status_bypass = false
mesh_settle_secs = 15
leader_timeout_secs = 15
vote_timeout_secs = 8
block_timeout_secs = 30
penalization_enabled = false
synergy_score_decay_rate = 0.05
vrf_enabled = $vrf_enabled
vrf_seed_epoch_interval = 1000
max_synergy_points_per_epoch = 100
max_tasks_per_validator = 10

[consensus.reward_weighting]
task_accuracy = 0.5
uptime = 0.3
collaboration = 0.2

[logging]
log_level = "debug"
log_file = "$log_file"
enable_console = true
max_file_size = 10485760
max_files = 5

[rpc]
bind_address = "127.0.0.1:$rpc_port"
enable_http = true
http_port = $rpc_port
enable_ws = true
ws_port = $ws_port
enable_grpc = true
grpc_port = $rpc_port
cors_enabled = $cors_enabled
cors_origins = $cors_origins

[p2p]
listen_address = "0.0.0.0:$p2p_port"
public_address = "$public_address"
node_name = "$node_name"
enable_discovery = $enable_discovery
enable_peer_exchange = $enable_peer_exchange
discovery_port = $discovery_port
discovery_listen_address = "0.0.0.0:$discovery_port"
discovery_public_address = "$discovery_public_address"
heartbeat_interval = 10
bootstrap_refresh_secs = $bootstrap_refresh_secs

[storage]
database = "rocksdb"
path = "data/chain"
enable_pruning = $enable_pruning
pruning_interval = 86400

[snapshots]
enabled = $snapshots_enabled
interval_blocks = $snapshot_interval_blocks

[node]
bootstrap_only = false
auto_register_validator = false
validator_address = ""
strict_validator_allowlist = $strict_allowlist
allowed_validator_addresses = $ALLOWED_VALIDATOR_ADDRESSES

[telemetry]
enabled = true
metrics_bind = "$metrics_bind"
structured_logs = true
log_level = "debug"
EOF

    echo "Generated: $node_type.toml"
}

mkdir -p "$TEMPLATES_DIR"

echo "Generating node configuration templates..."
echo

generate_template "validator" "validator" "validator_node" "validator-node-01" 5622 5640 5660 5680 6030 "data/logs/validator.log" false true "validator-mesh"
generate_template "archive-validator" "archive_validator" "archive_validator_node" "archive-validator-01" 5622 5640 5660 5680 6030 "data/logs/archive-validator.log" false true "public-bootstrap"
generate_template "audit-validator" "audit_validator" "audit_validator_node" "audit-validator-01" 5622 5640 5660 5680 6030 "data/logs/audit-validator.log" false true "public-bootstrap"
generate_template "committee" "committee" "committee_node" "committee-node-01" 5622 5640 5660 5680 6030 "data/logs/committee.log" false true "public-bootstrap"
generate_template "governance-auditor" "governance_auditor" "governance_auditor_node" "governance-auditor-01" 5622 5640 5660 5680 6030 "data/logs/governance-auditor.log" false true "public-bootstrap"
generate_template "security-council" "security_council" "security_council_node" "security-council-01" 5622 5640 5660 5680 6030 "data/logs/security-council.log" false true "public-bootstrap"
generate_template "treasury-controller" "treasury_controller" "treasury_controller_node" "treasury-controller-01" 5622 5640 5660 5680 6030 "data/logs/treasury-controller.log" false true "public-bootstrap"

generate_template "oracle" "oracle" "oracle_node" "oracle-node-01" 5622 5640 5660 5680 6030 "data/logs/oracle.log" true false "public-bootstrap"
generate_template "observer" "observer" "observer_light_node" "observer-node-01" 5622 5640 5660 5680 6030 "data/logs/observer.log" true false "sentry-edge"
generate_template "indexer" "indexer" "indexer_and_explorer_node" "indexer-node-01" 5622 5640 5660 5680 6030 "data/logs/indexer.log" false false "sentry-edge"
generate_template "data-availability" "data_availability" "data_availability_node" "data-availability-01" 5622 5640 5660 5680 6030 "data/logs/data-availability.log" false false "public-bootstrap"
generate_template "cross-chain-verifier" "cross_chain_verifier" "cross_chain_verifier_node" "cross-chain-verifier-01" 5622 5640 5660 5680 6030 "data/logs/cross-chain-verifier.log" true false "public-bootstrap"
generate_template "relayer" "relayer" "relayer_node" "relayer-node-01" 5622 5640 5660 5680 6030 "data/logs/relayer.log" true false "validator-mesh"
generate_template "rpc" "rpc_gateway" "rpc_gateway_node" "rpc-node-01" 5623 5641 5661 5681 6031 "data/logs/rpc.log" true false "sentry-edge"
generate_template "rpc-gateway" "rpc_gateway" "rpc_gateway_node" "rpc-gateway-01" 5623 5641 5661 5681 6031 "data/logs/rpc-gateway.log" true false "sentry-edge"
generate_template "witness" "witness" "witness_node" "witness-node-01" 5622 5640 5660 5680 6030 "data/logs/witness.log" true false "public-bootstrap"

generate_template "ai-inference" "ai_inference" "analytics_simulation_node" "ai-inference-01" 5622 5640 5660 5680 6030 "data/logs/ai-inference.log" true false "public-bootstrap"
generate_template "compute" "compute" "compute_node" "compute-node-01" 5622 5640 5660 5680 6030 "data/logs/compute.log" true false "public-bootstrap"
generate_template "pqc-crypto" "pqc_crypto" "pqc_crypto_node" "pqc-crypto-01" 5622 5640 5660 5680 6030 "data/logs/pqc-crypto.log" true false "public-bootstrap"
generate_template "uma-coordinator" "uma_coordinator" "uma_coordinator_node" "uma-coordinator-01" 5622 5640 5660 5680 6030 "data/logs/uma-coordinator.log" true false "public-bootstrap"

echo
echo "✓ All node templates generated successfully!"
echo "Templates location: $TEMPLATES_DIR/"
