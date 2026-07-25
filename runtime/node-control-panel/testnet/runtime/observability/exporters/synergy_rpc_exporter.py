#!/usr/bin/env python3
import csv
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

INVENTORY_FILE = os.environ.get(
    "SYNERGY_INVENTORY_FILE", "/config/node-inventory.csv"
)
EXPORTER_HOST = os.environ.get("SYNERGY_EXPORTER_HOST", "0.0.0.0")
EXPORTER_PORT = int(os.environ.get("SYNERGY_EXPORTER_PORT", "9168"))
RPC_TIMEOUT_SECONDS = float(os.environ.get("SYNERGY_RPC_TIMEOUT_SECONDS", "3.0"))


def parse_bool(raw: str) -> bool:
    value = (raw or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def load_targets():
    env_targets = os.environ.get("SYNERGY_RPC_TARGETS", "").strip()
    if env_targets:
        targets = []
        for part in env_targets.split(","):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                name, url = part.split("=", 1)
                targets.append((name.strip(), url.strip()))
            else:
                targets.append((f"node-{len(targets)+1}", part.strip()))
        if targets:
            return targets

    targets = []
    if not os.path.isfile(INVENTORY_FILE):
        return targets

    with open(INVENTORY_FILE, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            node_slot_id = row.get("node_slot_id", "").strip()
            management_host = row.get("management_host", "").strip()
            host = row.get("host", "").strip()
            rpc_port = row.get("rpc_port", "").strip()
            endpoint_host = management_host or host
            if not node_slot_id or not endpoint_host or not rpc_port:
                continue
            targets.append((node_slot_id, f"http://{endpoint_host}:{rpc_port}"))
    return targets


def rpc_call(url, method, params=None):
    if params is None:
        params = []
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.time()
    with urllib.request.urlopen(req, timeout=RPC_TIMEOUT_SECONDS) as response:
        body = response.read()
    latency_ms = (time.time() - started) * 1000.0
    data = json.loads(body.decode("utf-8"))
    return data.get("result"), latency_ms


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def quote_label(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def collect_metrics():
    targets = load_targets()
    lines = []

    lines.append("# HELP synergy_node_up 1 when JSON-RPC checks succeed for node.")
    lines.append("# TYPE synergy_node_up gauge")

    lines.append("# HELP synergy_block_height Latest block height.")
    lines.append("# TYPE synergy_block_height gauge")

    lines.append("# HELP synergy_peer_count Connected peer count.")
    lines.append("# TYPE synergy_peer_count gauge")

    lines.append("# HELP synergy_avg_block_time_seconds Average block time in seconds.")
    lines.append("# TYPE synergy_avg_block_time_seconds gauge")

    lines.append("# HELP synergy_txpool_size Pending transaction pool size.")
    lines.append("# TYPE synergy_txpool_size gauge")

    lines.append("# HELP synergy_latest_block_tx_count Transactions in latest block.")
    lines.append("# TYPE synergy_latest_block_tx_count gauge")

    lines.append("# HELP synergy_estimated_tps Estimated TPS from latest block tx count / avg block time.")
    lines.append("# TYPE synergy_estimated_tps gauge")

    lines.append("# HELP synergy_active_validators Active validator count.")
    lines.append("# TYPE synergy_active_validators gauge")

    lines.append("# HELP synergy_rpc_latency_ms RPC method latency in milliseconds.")
    lines.append("# TYPE synergy_rpc_latency_ms gauge")

    lines.append("# HELP synergy_validator_uptime_percent Validator uptime percentage.")
    lines.append("# TYPE synergy_validator_uptime_percent gauge")

    lines.append("# HELP synergy_determinism_match 1 if node state_root matches reference node.")
    lines.append("# TYPE synergy_determinism_match gauge")

    lines.append("# HELP synergy_fork_events 1 if deterministic digest diverges from reference node.")
    lines.append("# TYPE synergy_fork_events gauge")

    lines.append("# HELP synergy_gossip_latency_proxy_ms Proxy latency metric derived from peer-info RPC.")
    lines.append("# TYPE synergy_gossip_latency_proxy_ms gauge")

    digest_by_node = {}

    for node_name, url in targets:
        node_label = quote_label(node_name)
        up = 0
        block_height = 0
        peer_count = 0
        avg_block_time = 0.0
        txpool_size = 0
        latest_block_tx_count = 0
        est_tps = 0.0
        active_validators = 0
        gossip_latency_ms = 0.0

        try:
            node_status, latency = rpc_call(url, "synergy_getNodeStatus", [])
            up = 1
            block_height = safe_int((node_status or {}).get("last_block", 0))
            peer_count = safe_int((node_status or {}).get("peer_count", 0))
            avg_block_time = safe_float((node_status or {}).get("avg_block_time", 0.0))
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getNodeStatus\"}} {latency:.3f}"
            )

            tx_pool, txpool_latency = rpc_call(url, "synergy_getTransactionPool", [])
            if isinstance(tx_pool, list):
                txpool_size = len(tx_pool)
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getTransactionPool\"}} {txpool_latency:.3f}"
            )

            latest_block, latest_block_latency = rpc_call(url, "synergy_getLatestBlock", [])
            if isinstance(latest_block, dict):
                latest_block_tx_count = len(latest_block.get("transactions", []))
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getLatestBlock\"}} {latest_block_latency:.3f}"
            )

            network_stats, network_stats_latency = rpc_call(url, "synergy_getNetworkStats", [])
            active_validators = safe_int((network_stats or {}).get("active_validators", 0))
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getNetworkStats\"}} {network_stats_latency:.3f}"
            )

            peer_info, peer_info_latency = rpc_call(url, "synergy_getPeerInfo", [])
            _ = peer_info
            gossip_latency_ms = peer_info_latency
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getPeerInfo\"}} {peer_info_latency:.3f}"
            )

            validator_activity, validator_activity_latency = rpc_call(
                url, "synergy_getValidatorActivity", []
            )
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getValidatorActivity\"}} {validator_activity_latency:.3f}"
            )
            validators = (validator_activity or {}).get("validators", [])
            for validator in validators:
                validator_address = str(validator.get("address", "unknown"))
                uptime_raw = str(validator.get("uptime", "0")).rstrip("%")
                uptime_value = safe_float(uptime_raw)
                lines.append(
                    "synergy_validator_uptime_percent"
                    + "{"
                    + f"node={node_label},validator={quote_label(validator_address)}"
                    + "} "
                    + f"{uptime_value:.3f}"
                )

            digest, digest_latency = rpc_call(url, "synergy_getDeterminismDigest", [])
            lines.append(
                f"synergy_rpc_latency_ms{{node={node_label},method=\"synergy_getDeterminismDigest\"}} {digest_latency:.3f}"
            )
            if isinstance(digest, dict):
                digest_by_node[node_name] = digest.get("state_root")

        except Exception:
            up = 0

        if avg_block_time > 0:
            est_tps = latest_block_tx_count / avg_block_time

        lines.append(f"synergy_node_up{{node={node_label}}} {up}")
        lines.append(f"synergy_block_height{{node={node_label}}} {block_height}")
        lines.append(f"synergy_peer_count{{node={node_label}}} {peer_count}")
        lines.append(f"synergy_avg_block_time_seconds{{node={node_label}}} {avg_block_time:.6f}")
        lines.append(f"synergy_txpool_size{{node={node_label}}} {txpool_size}")
        lines.append(
            f"synergy_latest_block_tx_count{{node={node_label}}} {latest_block_tx_count}"
        )
        lines.append(f"synergy_estimated_tps{{node={node_label}}} {est_tps:.6f}")
        lines.append(f"synergy_active_validators{{node={node_label}}} {active_validators}")
        lines.append(
            f"synergy_gossip_latency_proxy_ms{{node={node_label}}} {gossip_latency_ms:.3f}"
        )

    reference_root = None
    for node_name, state_root in digest_by_node.items():
        if state_root:
            reference_root = state_root
            break

    for node_name, _ in targets:
        node_label = quote_label(node_name)
        state_root = digest_by_node.get(node_name)
        if not reference_root or not state_root:
            match = 0
        else:
            match = 1 if state_root == reference_root else 0
        fork_events = 0 if match == 1 else 1
        lines.append(f"synergy_determinism_match{{node={node_label}}} {match}")
        lines.append(f"synergy_fork_events{{node={node_label}}} {fork_events}")

    return "\n".join(lines) + "\n"


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/metrics", "/metrics/"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return

        payload = collect_metrics().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    server = ThreadedHTTPServer((EXPORTER_HOST, EXPORTER_PORT), Handler)
    print(f"synergy_rpc_exporter listening on {EXPORTER_HOST}:{EXPORTER_PORT}")
    server.serve_forever()
