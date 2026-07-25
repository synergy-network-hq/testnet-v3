#!/usr/bin/env python3
import json
import pathlib


DATASOURCE = {"type": "prometheus", "uid": "prometheus"}
SCHEMA_VERSION = 39
CANONICAL_JOBS = "synergy-observer|synergy-validators|synergy-archive|synergy-rpc-gateway|synergy-explorer-indexer|node_exporter|node_exporter_public|synergy-qrpc-probes|synergy-http-probes|synergy-bootstrap-probes"
ONBOARDING_JOBS = CANONICAL_JOBS


def templating(active_jobs=CANONICAL_JOBS):
    return {
        "list": [
            {
                "name": "environment",
                "label": "Environment",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": "query_result(max by (environment) (synergy_inventory_node_info))",
                "query": "query_result(max by (environment) (synergy_inventory_node_info))",
                "regex": "/environment=\"([^\"]+)\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "network",
                "label": "Network",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": "query_result(max by (network) (synergy_inventory_node_info))",
                "query": "query_result(max by (network) (synergy_inventory_node_info))",
                "regex": "/network=\"([^\"]+)\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "chain_id",
                "label": "Chain ID",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": "query_result(max by (chain_id) (synergy_inventory_node_info))",
                "query": "query_result(max by (chain_id) (synergy_inventory_node_info))",
                "regex": "/chain_id=\"([^\"]+)\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "node_type",
                "label": "Node Type",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": f"query_result(sort(max by (node_type) (up{{job=~\"{active_jobs}\",node_type!=\"\"}})))",
                "query": f"query_result(sort(max by (node_type) (up{{job=~\"{active_jobs}\",node_type!=\"\"}})))",
                "regex": "/node_type=\\\"([^\\\"]+)\\\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "node",
                "label": "Node",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": f"query_result(sort(max by (node) (up{{job=~\"{active_jobs}\",node!=\"\"}})))",
                "query": f"query_result(sort(max by (node) (up{{job=~\"{active_jobs}\",node!=\"\"}})))",
                "regex": "/node=\\\"([^\\\"]+)\\\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "job",
                "label": "Job",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": f"query_result(sort(max by (job) (up{{job=~\"{active_jobs}\"}})))",
                "query": f"query_result(sort(max by (job) (up{{job=~\"{active_jobs}\"}})))",
                "regex": "/job=\"([^\"]+)\"/",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
            {
                "name": "runtime_sha",
                "label": "Runtime SHA",
                "type": "query",
                "datasource": DATASOURCE,
                "definition": "label_values(synergy_build_info, runtime_sha)",
                "query": "label_values(synergy_build_info, runtime_sha)",
                "refresh": 1,
                "multi": True,
                "includeAll": True,
                "current": {"selected": True, "text": "All", "value": "$__all"},
            },
        ]
    }


def dashboard(uid, title, panels, active_jobs=CANONICAL_JOBS):
    return {
        "id": None,
        "uid": uid,
        "title": title,
        "tags": ["synergy", "observability", "testnet"],
        "style": "dark",
        "timezone": "browser",
        "editable": True,
        "graphTooltip": 1,
        "schemaVersion": SCHEMA_VERSION,
        "version": 1,
        "refresh": "30s",
        "time": {"from": "now-6h", "to": "now"},
        "templating": templating(active_jobs),
        "annotations": {"list": []},
        "panels": panels,
    }


def default_field(unit="none"):
    return {
        "defaults": {
            "unit": unit,
            "thresholds": {
                "mode": "absolute",
                "steps": [
                    {"color": "red", "value": None},
                    {"color": "orange", "value": 1},
                    {"color": "green", "value": 2},
                ],
            },
        },
        "overrides": [],
    }


def stat_panel(pid, title, expr, x, y, w=6, h=4, unit="none", desc="", legend="{{node}}"):
    return {
        "id": pid,
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": DATASOURCE,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [{"refId": "A", "expr": expr, "instant": True, "legendFormat": legend}],
        "options": {
            "colorMode": "background",
            "graphMode": "area",
            "justifyMode": "auto",
            "orientation": "auto",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto",
        },
        "fieldConfig": default_field(unit),
    }


def ts_panel(pid, title, expr, x, y, w=12, h=8, unit="short", desc="", legend="{{node}}"):
    return {
        "id": pid,
        "type": "timeseries",
        "title": title,
        "description": desc,
        "datasource": DATASOURCE,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [{"refId": "A", "expr": expr, "legendFormat": legend}],
        "options": {"legend": {"displayMode": "table", "placement": "bottom"}},
        "fieldConfig": default_field(unit),
    }


def text_panel(pid, title, content, x, y, w=24, h=4):
    return {
        "id": pid,
        "type": "text",
        "title": title,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "options": {"mode": "markdown", "content": content},
    }


def table_panel(pid, title, expr, x, y, w=24, h=8, desc="", legend="{{node}}"):
    return {
        "id": pid,
        "type": "table",
        "title": title,
        "description": desc,
        "datasource": DATASOURCE,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [{"refId": "A", "expr": expr, "instant": True, "legendFormat": legend}],
        "options": {"showHeader": True},
        "fieldConfig": default_field("none"),
    }


def network_overview():
    return dashboard(
        "synergy-network-overview-v3",
        "Synergy Network Overview",
        [
            stat_panel(1, "Network Majority Height", "max(synergy_canonical_network_majority_height)", 0, 0, unit="none"),
            stat_panel(2, "Finalized Height", "max(synergy_canonical_finalized_height)", 6, 0, unit="none"),
            stat_panel(3, "Avg Block Time", "max(synergy_canonical_average_block_time_seconds)", 12, 0, unit="s"),
            stat_panel(4, "Age Since Last Block", "max(synergy_canonical_latest_block_age_seconds)", 18, 0, unit="s"),
            stat_panel(5, "Active Validators", "max(synergy_canonical_active_validator_count)", 0, 4),
            stat_panel(6, "Expected Validators", "max(synergy_canonical_expected_validator_count)", 6, 4),
            stat_panel(7, "Ready Validators", "max(synergy_canonical_status_ready_validators)", 12, 4),
            stat_panel(8, "Operational Clusters", "max(synergy_operational_cluster_count)", 18, 4),
            ts_panel(9, "Canonical Height by Node", "synergy_node_chain_height{instance!=\"\"}", 0, 8, 12, 8, "none"),
            ts_panel(10, "Height Gap by Node", "synergy_node_height_gap{instance!=\"\"}", 12, 8, 12, 8, "none"),
            ts_panel(11, "Latest Block Age by Node", "synergy_canonical_latest_block_age_seconds{instance!=\"\"}", 0, 16, 12, 8, "s"),
            ts_panel(12, "P2P Peers by Node", "synergy_node_peer_count", 12, 16, 12, 8, "none"),
        ],
    )


def validator_health():
    return dashboard(
        "synergy-validator-health-v2",
        "Synergy Validator Health",
        [
            ts_panel(1, "Validator Local Height", "synergy_node_chain_height{instance!=\"\",role=\"validator\"}", 0, 0, 12, 8, "none"),
            ts_panel(2, "Validator Height Gap", "synergy_node_height_gap{instance!=\"\",role=\"validator\"}", 12, 0, 12, 8, "none"),
            ts_panel(3, "Validator Latest Block Age", "synergy_canonical_latest_block_age_seconds{instance!=\"\",role=\"validator\"}", 0, 8, 12, 8, "s"),
            ts_panel(4, "Validator Peer Count", "synergy_node_peer_count{role=\"validator\"}", 12, 8, 12, 8, "none"),
            ts_panel(5, "Validator Metrics Scrape Up", "synergy_node_metrics_up{instance!=\"\",role=\"validator\"}", 0, 16, 8, 8, "none"),
            ts_panel(6, "Validator qRPC Up", "synergy_node_qrpc_up{target!=\"\",role=\"validator\"}", 8, 16, 8, 8, "none"),
            ts_panel(7, "Validator CPU Usage", "(1 - avg by (node) (rate(node_cpu_seconds_total{job=~\"node_exporter|node_exporter_public\",role=\"validator\",mode=\"idle\"}[5m]))) * 100", 16, 16, 8, 8, "percent"),
            ts_panel(8, "Validator Memory Usage", "max by (node) ((1 - node_memory_MemAvailable_bytes{job=~\"node_exporter|node_exporter_public\",role=\"validator\"} / node_memory_MemTotal_bytes{job=~\"node_exporter|node_exporter_public\",role=\"validator\"}) * 100)", 0, 24, 12, 8, "percent"),
            ts_panel(9, "Validator Disk Usage", "max by (node) (100 - (node_filesystem_avail_bytes{job=~\"node_exporter|node_exporter_public\",role=\"validator\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"} / node_filesystem_size_bytes{job=~\"node_exporter|node_exporter_public\",role=\"validator\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"}) * 100)", 12, 24, 12, 8, "percent"),
        ],
    )


def validator_onboarding():
    return dashboard(
        "synergy-validator-onboarding-v2",
        "Synergy Validator Activation and Health",
        [
            stat_panel(1, "Active Validators", "max(synergy_canonical_active_validator_count)", 0, 0),
            stat_panel(2, "Expected Validators", "max(synergy_canonical_expected_validator_count)", 6, 0),
            stat_panel(3, "Ready Validators", "max(synergy_canonical_status_ready_validators)", 12, 0),
            stat_panel(4, "Validator Metrics Up", "count(synergy_node_metrics_up{instance!=\"\",role=\"validator\"} == 1)", 18, 0),
            ts_panel(5, "Validator Status Buckets", "max by (status) (synergy_validator_status_total{job=~\"synergy-validators|synergy-observer|synergy-rpc-gateway\"})", 0, 4, 12, 8, "none"),
            ts_panel(6, "Validator qRPC Up", "synergy_node_qrpc_up{target!=\"\",role=\"validator\"}", 12, 4, 12, 8, "none"),
            ts_panel(7, "Validator Host Up", "synergy_node_host_up{instance!=\"\",role=\"validator\"}", 0, 12, 12, 8, "none"),
            ts_panel(8, "Validator Chain Height", "synergy_node_chain_height{instance!=\"\",role=\"validator\"}", 12, 12, 12, 8, "none"),
            ts_panel(9, "Validator Height Gap", "synergy_node_height_gap{instance!=\"\",role=\"validator\"}", 0, 20, 12, 8, "none"),
            ts_panel(10, "Validator Latest Block Age", "synergy_canonical_latest_block_age_seconds{instance!=\"\",role=\"validator\"}", 12, 20, 12, 8, "s"),
            ts_panel(11, "Validator Peer Count", "synergy_node_peer_count{role=\"validator\"}", 0, 28, 12, 8, "none"),
            ts_panel(12, "Validator Blocks Produced / 5m", "sum by (name,validator,status) (increase(synergy_validator_blocks_produced_total{job=~\"synergy-validators|synergy-observer|synergy-rpc-gateway\"}[5m]))", 12, 28, 12, 8, "none", legend="{{name}} {{status}}"),
            ts_panel(13, "Validator Missed Vote Window", "max by (name,validator,status) (synergy_validator_missed_vote_window{job=~\"synergy-validators|synergy-observer|synergy-rpc-gateway\"})", 0, 36, 12, 8, "none", legend="{{name}} {{status}}"),
            table_panel(14, "Consensus Timing Config by Node", "max by (node,job,setting) (synergy_consensus_config{job=~\"synergy-validators|synergy-rpc-gateway|synergy-observer\"})", 12, 36, 12, 8, legend="{{node}} {{setting}}"),
        ],
    )


def archive_health():
    return dashboard(
        "synergy-archive-validator-health-v2",
        "Synergy Archive Validator and Snapshot Health",
        [
            stat_panel(1, "Archive Metrics Up", "max(synergy_node_metrics_up{instance!=\"\",node=\"archive\"})", 0, 0),
            stat_panel(2, "Archive qRPC Probe Up", "max(synergy_node_qrpc_up{target!=\"\",node=\"archive\"})", 6, 0),
            stat_panel(3, "Archive Host Metrics Up", "max(synergy_node_host_up{instance!=\"\",node=\"archive\"})", 12, 0),
            stat_panel(4, "Archive Height", "max(synergy_node_chain_height{instance!=\"\",node=\"archive\"})", 18, 0, unit="none"),
            ts_panel(5, "Archive Latest Block Age", "synergy_canonical_latest_block_age_seconds{instance!=\"\",node=\"archive\"}", 0, 4, 12, 8, "s"),
            ts_panel(6, "Archive Height Gap", "synergy_node_height_gap{instance!=\"\",node=\"archive\"}", 12, 4, 12, 8, "none"),
            text_panel(
                7,
                "Snapshot Metrics TODO",
                "Snapshot creation status, snapshot freshness, snapshot export path, snapshot size, and restore-test metrics are not yet exposed by the archive runtime. They must be added in application code before this dashboard can show them truthfully.",
                0,
                12,
                24,
                4,
            ),
        ],
    )


def consensus_finality():
    return dashboard(
        "synergy-consensus-finality-v2",
        "Synergy Testnet Consensus and Chain",
        [
            stat_panel(1, "Majority Height", "max(synergy_canonical_network_majority_height)", 0, 0, unit="none"),
            stat_panel(2, "Avg Block Time", "max(synergy_canonical_average_block_time_seconds)", 6, 0, unit="s"),
            stat_panel(3, "Latest Block Age", "max(synergy_canonical_latest_block_age_seconds)", 12, 0, unit="s"),
            stat_panel(4, "View Changes / 5m", "sum(increase(synergy_view_change_total[5m])) or vector(0)", 18, 0),
            ts_panel(5, "Chain Height by Consensus Role", "synergy_node_chain_height{instance!=\"\",role=~\"validator|observer|rpc_gateway|archive\"}", 0, 4, 12, 8, "none"),
            ts_panel(6, "Height Gap by Consensus Role", "synergy_node_height_gap{instance!=\"\",role=~\"validator|observer|rpc_gateway|archive\"}", 12, 4, 12, 8, "none"),
            ts_panel(7, "Average Block Time by Node", "synergy_canonical_average_block_time_seconds", 0, 12, 12, 8, "s"),
            ts_panel(8, "Sync Progress", "100 * synergy_node_chain_height{instance!=\"\"} / scalar(max(synergy_node_chain_height{instance!=\"\",role=~\"validator|observer|rpc_gateway|archive|explorer_indexer\"}))", 12, 12, 12, 8, "percent"),
            ts_panel(9, "Validator Blocks Produced / 5m", "sum by (name,validator,status) (increase(synergy_validator_blocks_produced_total{job=~\"synergy-validators|synergy-observer|synergy-rpc-gateway\"}[5m]))", 0, 20, 12, 8, "none", legend="{{name}} {{status}}"),
            ts_panel(10, "Validator Missed Vote Window", "max by (name,validator,status) (synergy_validator_missed_vote_window{job=~\"synergy-validators|synergy-observer|synergy-rpc-gateway\"})", 12, 20, 12, 8, "none", legend="{{name}} {{status}}"),
            table_panel(11, "Consensus Timing Config by Node", "max by (node,job,setting) (synergy_consensus_config{job=~\"synergy-validators|synergy-rpc-gateway|synergy-observer\"})", 0, 28, 24, 8, legend="{{node}} {{setting}}"),
        ],
    )


def p2p_network():
    return dashboard(
        "synergy-p2p-network-v2",
        "Synergy P2P Network",
        [
            stat_panel(1, "Bootstrap TCP Targets Up", "count(synergy_bootstrap_probe_up == 1)", 0, 0),
            stat_panel(2, "Validator qRPC TCP Targets Up", "count(synergy_node_qrpc_up{target!=\"\",role=\"validator\"} == 1)", 6, 0),
            stat_panel(3, "Public HTTPS Targets Up", "count(synergy_public_health_probe_up == 1)", 12, 0),
            stat_panel(4, "Average Peer Count", "avg(synergy_node_peer_count)", 18, 0),
            ts_panel(5, "Peers Connected by Node", "synergy_node_peer_count", 0, 4, 12, 8, "none"),
            ts_panel(6, "Best Peer Height by Node", "synergy_p2p_best_validator_peer_height", 12, 4, 12, 8, "none"),
            ts_panel(7, "Per-Peer Heights", "max by (node, peer_id) (synergy_p2p_peer_height)", 0, 12, 12, 8, "none", legend="{{node}} {{peer_id}}"),
            ts_panel(8, "Per-Peer Last Seen Age", "max by (node, peer_id) (synergy_p2p_peer_last_seen_age_seconds)", 12, 12, 12, 8, "s", legend="{{node}} {{peer_id}}"),
        ],
    )


def rpc_gateway_health():
    return dashboard(
        "synergy-rpc-gateway-health-v2",
        "Synergy RPC Gateway Health",
        [
            stat_panel(1, "RPC Metrics Up", "max(synergy_node_metrics_up{instance!=\"\",role=\"rpc_gateway\"})", 0, 0),
            stat_panel(2, "RPC HTTPS Health", "max(synergy_public_health_probe_up{telemetry_path!=\"\",role=\"rpc_gateway\"})", 6, 0),
            stat_panel(3, "RPC Height", "max(synergy_node_chain_height{instance!=\"\",role=\"rpc_gateway\"})", 12, 0, unit="none"),
            stat_panel(4, "RPC Latest Block Age", "max(synergy_canonical_latest_block_age_seconds{instance!=\"\",role=\"rpc_gateway\"})", 18, 0, unit="s"),
            ts_panel(5, "RPC Height", "synergy_node_chain_height{instance!=\"\",role=\"rpc_gateway\"}", 0, 4, 12, 8, "none"),
            ts_panel(6, "RPC Peer Count", "synergy_node_peer_count{role=\"rpc_gateway\"}", 12, 4, 12, 8, "none"),
            ts_panel(7, "RPC Height Gap", "synergy_node_height_gap{instance!=\"\",role=\"rpc_gateway\"}", 0, 12, 12, 8, "none"),
            ts_panel(8, "RPC Latest Block Age", "synergy_canonical_latest_block_age_seconds{instance!=\"\",role=\"rpc_gateway\"}", 12, 12, 12, 8, "s"),
        ],
    )


def relayer_health():
    return dashboard(
        "synergy-relayer-health-v2",
        "Synergy Relayer Health",
        [
            ts_panel(1, "Relayer Host Metrics Up", "synergy_node_host_up{instance!=\"\",role=\"relayer\"}", 0, 0, 12, 8, "none"),
            ts_panel(2, "Relayer qRPC Up", "synergy_node_qrpc_up{target!=\"\",role=\"relayer\"}", 12, 0, 12, 8, "none"),
            ts_panel(3, "Relayer CPU Usage", "(1 - avg by (node) (rate(node_cpu_seconds_total{job=\"node_exporter\",role=\"relayer\",mode=\"idle\"}[5m]))) * 100", 0, 8, 12, 8, "percent"),
            ts_panel(4, "Relayer Memory Usage", "max by (node) ((1 - node_memory_MemAvailable_bytes{job=\"node_exporter\",role=\"relayer\"} / node_memory_MemTotal_bytes{job=\"node_exporter\",role=\"relayer\"}) * 100)", 12, 8, 12, 8, "percent"),
            ts_panel(5, "Relayer Disk Usage", "max by (node) (100 - (node_filesystem_avail_bytes{job=\"node_exporter\",role=\"relayer\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"} / node_filesystem_size_bytes{job=\"node_exporter\",role=\"relayer\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"}) * 100)", 0, 16, 12, 8, "percent"),
            ts_panel(6, "Relayer Network Receive Bytes/s", "sum by (node) (rate(node_network_receive_bytes_total{job=\"node_exporter\",role=\"relayer\",device!~\"lo\"}[5m]))", 12, 16, 12, 8, "Bps"),
            ts_panel(6, "Relayer CPU Usage", "(1 - avg by (node) (rate(node_cpu_seconds_total{job=~\"node_exporter|node_exporter_public\",role=\"relayer\",mode=\"idle\"}[5m]))) * 100", 12, 16, 12, 8, "percent"),
        ],
    )


def explorer_health():
    return dashboard(
        "synergy-explorer-indexer-health-v2",
        "Synergy Explorer Health",
        [
            stat_panel(1, "Explorer Metrics Up", "max(synergy_node_metrics_up{instance!=\"\",role=\"explorer_indexer\"})", 0, 0),
            stat_panel(2, "Explorer HTTPS Health", "max(synergy_public_health_probe_up{telemetry_path!=\"\",role=\"explorer_indexer\"})", 6, 0),
            stat_panel(3, "Explorer Height", "max(synergy_node_chain_height{instance!=\"\",role=\"explorer_indexer\"})", 12, 0, unit="none"),
            stat_panel(4, "Explorer Height Gap", "max(synergy_node_height_gap{instance!=\"\",role=\"explorer_indexer\"})", 18, 0, unit="none"),
            text_panel(
                5,
                "Current Explorer Gap",
                "The Explorer/indexer panel reflects the public metrics and health routes defined in TARGET_INVENTORY.md. Route failures remain visible instead of being masked by a fallback series.",
                0,
                4,
                24,
                4,
            ),
            ts_panel(6, "Explorer Metrics Target Up", "synergy_node_metrics_up{instance!=\"\",role=\"explorer_indexer\"}", 0, 8, 12, 8, "none"),
            ts_panel(7, "Explorer Public Health", "synergy_public_health_probe_up{telemetry_path!=\"\",role=\"explorer_indexer\"}", 12, 8, 12, 8, "none"),
        ],
    )


def node_resource_usage():
    return dashboard(
        "synergy-node-resource-usage-v2",
            "Synergy Node Resource Usage",
        [
            ts_panel(1, "CPU Usage", "(1 - avg by (node) (rate(node_cpu_seconds_total{job=~\"node_exporter|node_exporter_public\",mode=\"idle\"}[5m]))) * 100", 0, 0, 12, 8, "percent"),
            ts_panel(2, "Memory Usage", "max by (node) ((1 - node_memory_MemAvailable_bytes{job=~\"node_exporter|node_exporter_public\"} / node_memory_MemTotal_bytes{job=~\"node_exporter|node_exporter_public\"}) * 100)", 12, 0, 12, 8, "percent"),
            ts_panel(3, "Disk Usage", "max by (node) (100 - (node_filesystem_avail_bytes{job=~\"node_exporter|node_exporter_public\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"} / node_filesystem_size_bytes{job=~\"node_exporter|node_exporter_public\",mountpoint=\"/\",fstype!~\"tmpfs|overlay|squashfs\"}) * 100)", 0, 8, 12, 8, "percent"),
            ts_panel(4, "Open File Descriptor Usage", "max by (node) ((node_filefd_allocated{job=~\"node_exporter|node_exporter_public\"} / node_filefd_maximum{job=~\"node_exporter|node_exporter_public\"}) * 100)", 12, 8, 12, 8, "percent"),
            ts_panel(5, "Network Receive Bytes/s", "sum by (node) (rate(node_network_receive_bytes_total{job=~\"node_exporter|node_exporter_public\",device!~\"lo\"}[5m]))", 0, 16, 12, 8, "Bps"),
            ts_panel(6, "Network Transmit Bytes/s", "sum by (node) (rate(node_network_transmit_bytes_total{job=~\"node_exporter|node_exporter_public\",device!~\"lo\"}[5m]))", 12, 16, 12, 8, "Bps"),
        ],
    )


def incident_recovery():
    return dashboard(
        "synergy-incident-recovery-v2",
        "Synergy Incident and Recovery Dashboard",
        [
            stat_panel(1, "Down Metrics Targets", "count(synergy_node_metrics_up{instance!=\"\"} == 0)", 0, 0),
            stat_panel(2, "Down qRPC Probes", "count(synergy_node_qrpc_up{target!=\"\"} == 0)", 6, 0),
            stat_panel(3, "Nodes with Height Gap > 5", "count(synergy_node_height_gap{instance!=\"\"} > 5)", 12, 0),
            stat_panel(4, "View Changes / 5m", "sum(increase(synergy_view_change_total[5m]))", 18, 0),
            ts_panel(5, "Metrics Target Availability", "synergy_node_metrics_up{instance!=\"\"}", 0, 4, 12, 8, "none"),
            ts_panel(6, "qRPC Probe Availability", "synergy_node_qrpc_up{target!=\"\"}", 12, 4, 12, 8, "none"),
            ts_panel(7, "Height Gap During Incidents", "synergy_node_height_gap{instance!=\"\"}", 0, 12, 12, 8, "none"),
            ts_panel(8, "Latest Block Age During Incidents", "synergy_canonical_latest_block_age_seconds{instance!=\"\"}", 12, 12, 12, 8, "s"),
        ],
    )


def write_dashboard(output_dir: pathlib.Path, filename: str, data: dict):
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def main():
    root = pathlib.Path(__file__).resolve().parents[1] / "live-config-after/observer/dashboards"
    dashboards = {
        "synergy-network-overview-v3.json": network_overview(),
        "synergy-validator-health-v2.json": validator_health(),
        "synergy-validator-onboarding-and-activation-v2.json": validator_onboarding(),
        "synergy-archive-validator-and-snapshot-health-v2.json": archive_health(),
        "synergy-consensus-and-finality-v2.json": consensus_finality(),
        "synergy-p2p-network-v2.json": p2p_network(),
        "synergy-rpc-gateway-health-v2.json": rpc_gateway_health(),
        "synergy-relayer-health-v2.json": relayer_health(),
        "synergy-explorer-indexer-health-v2.json": explorer_health(),
        "synergy-node-resource-usage-v2.json": node_resource_usage(),
        "synergy-incident-and-recovery-dashboard-v2.json": incident_recovery(),
    }
    for name, data in dashboards.items():
        write_dashboard(root, name, data)


if __name__ == "__main__":
    main()
