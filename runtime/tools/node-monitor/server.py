#!/usr/bin/env python3
"""Synergy Testnet 15-node monitor server.

Serves a browser dashboard and a local API that probes all nodes from node-inventory.
"""

from __future__ import annotations

import argparse
import csv
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def machine_env_key(machine_id: str) -> str:
    return machine_id.upper().replace("-", "_") + "_HOST"


def parse_hosts_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip()
    return env


def parse_int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def parse_block_number(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s.startswith("0x"):
            try:
                return int(s, 16)
            except Exception:
                return None
        try:
            return int(s)
        except Exception:
            return None
    return None


def load_nodes(inventory_file: Path, hosts_env_file: Path) -> list[dict[str, Any]]:
    host_overrides = parse_hosts_env(hosts_env_file)
    nodes: list[dict[str, Any]] = []

    with inventory_file.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            machine_id = row.get("machine_id", "").strip()
            if not machine_id:
                continue

            default_host = row.get("host", "").strip()
            host = host_overrides.get(machine_env_key(machine_id), default_host)
            rpc_port = parse_int(row.get("rpc_port", "0"), 0)

            node = {
                "machine_id": machine_id,
                "node_id": row.get("node_id", "").strip(),
                "role_group": row.get("role_group", "").strip(),
                "role": row.get("role", "").strip(),
                "node_type": row.get("node_type", "").strip(),
                "host": host,
                "rpc_port": rpc_port,
                "rpc_url": f"http://{host}:{rpc_port}",
                "p2p_port": parse_int(row.get("p2p_port", "0"), 0),
                "ws_port": parse_int(row.get("ws_port", "0"), 0),
                "grpc_port": parse_int(row.get("grpc_port", "0"), 0),
                "discovery_port": parse_int(row.get("discovery_port", "0"), 0),
                "address_class": row.get("address_class", "").strip(),
            }
            nodes.append(node)

    return nodes


def rpc_call(rpc_url: str, method: str, params: list[Any] | None, timeout_sec: float) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or [],
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        latency_ms = round((time.perf_counter() - start) * 1000, 1)

        if isinstance(body, dict) and "error" in body:
            return {
                "ok": False,
                "error": body.get("error"),
                "latency_ms": latency_ms,
                "method": method,
            }

        return {
            "ok": True,
            "result": body.get("result") if isinstance(body, dict) else body,
            "latency_ms": latency_ms,
            "method": method,
        }
    except urllib.error.URLError as e:
        return {"ok": False, "error": str(e.reason), "method": method}
    except Exception as e:
        return {"ok": False, "error": str(e), "method": method}


def probe_node(node: dict[str, Any], timeout_sec: float) -> dict[str, Any]:
    rpc_url = node["rpc_url"]

    node_info = rpc_call(rpc_url, "synergy_nodeInfo", [], timeout_sec)
    block_number = rpc_call(rpc_url, "synergy_blockNumber", [], timeout_sec)
    latest_block = rpc_call(rpc_url, "synergy_getLatestBlock", [], timeout_sec)
    peer_count = rpc_call(rpc_url, "synergy_peerCount", [], timeout_sec)
    syncing = rpc_call(rpc_url, "synergy_syncing", [], timeout_sec)

    height = None
    if block_number.get("ok"):
        height = parse_block_number(block_number.get("result"))
    if height is None and latest_block.get("ok"):
        lb = latest_block.get("result")
        if isinstance(lb, dict):
            height = parse_block_number(lb.get("block_index") or lb.get("index") or lb.get("height"))

    peers = None
    if peer_count.get("ok"):
        peers = parse_block_number(peer_count.get("result"))

    sync_state = None
    if syncing.get("ok"):
        sync_state = syncing.get("result")

    calls = [node_info, block_number, latest_block, peer_count, syncing]
    ok_calls = [c for c in calls if c.get("ok")]
    latency_values = [c.get("latency_ms") for c in ok_calls if c.get("latency_ms") is not None]

    healthy = len(ok_calls) > 0
    primary_error = None
    if not healthy:
        for c in calls:
            if c.get("error"):
                primary_error = f"{c.get('method')}: {c.get('error')}"
                break

    return {
        **node,
        "healthy": healthy,
        "latest_block": height,
        "peer_count": peers,
        "syncing": sync_state,
        "latency_ms": min(latency_values) if latency_values else None,
        "primary_error": primary_error,
        "last_checked_unix": int(time.time()),
    }


def collect_status(nodes: list[dict[str, Any]], timeout_sec: float) -> list[dict[str, Any]]:
    if not nodes:
        return []

    results: list[dict[str, Any]] = []
    workers = max(1, min(16, len(nodes)))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {pool.submit(probe_node, node, timeout_sec): node for node in nodes}
        for future in as_completed(future_map):
            node = future_map[future]
            try:
                results.append(future.result())
            except Exception as e:
                results.append(
                    {
                        **node,
                        "healthy": False,
                        "latest_block": None,
                        "peer_count": None,
                        "syncing": None,
                        "latency_ms": None,
                        "primary_error": f"internal probe error: {e}",
                        "last_checked_unix": int(time.time()),
                    }
                )

    results.sort(key=lambda x: x.get("machine_id", ""))
    return results


@dataclass
class AppState:
    static_dir: Path
    nodes: list[dict[str, Any]]
    timeout_sec: float


class MonitorHandler(SimpleHTTPRequestHandler):
    state: AppState

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(self.state.static_dir), **kwargs)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)

        if parsed.path == "/":
            self.path = "/dashboard.html"
            return super().do_GET()

        if parsed.path == "/api/health":
            return self._send_json({"ok": True, "timestamp_unix": int(time.time())})

        if parsed.path == "/api/nodes":
            return self._send_json({"nodes": self.state.nodes})

        if parsed.path == "/api/status":
            statuses = collect_status(self.state.nodes, self.state.timeout_sec)
            online = sum(1 for s in statuses if s.get("healthy"))
            offline = len(statuses) - online
            max_height = max((s["latest_block"] for s in statuses if s.get("latest_block") is not None), default=None)
            return self._send_json(
                {
                    "summary": {
                        "total": len(statuses),
                        "online": online,
                        "offline": offline,
                        "max_latest_block": max_height,
                        "generated_at_unix": int(time.time()),
                    },
                    "nodes": statuses,
                }
            )

        return super().do_GET()

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent

    parser = argparse.ArgumentParser(description="Synergy Testnet node monitor GUI server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=7080, help="Bind port (default: 7080)")
    parser.add_argument(
        "--inventory",
        type=Path,
        default=repo_root / "testnet/runtime/node-inventory.csv",
        help="Path to node-inventory.csv",
    )
    parser.add_argument(
        "--hosts-env",
        type=Path,
        default=repo_root / "testnet/runtime/hosts.env",
        help="Optional hosts.env for IP overrides",
    )
    parser.add_argument(
        "--rpc-timeout",
        type=float,
        default=2.5,
        help="Per-RPC timeout in seconds (default: 2.5)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.inventory.exists():
        raise SystemExit(f"Inventory file not found: {args.inventory}")

    nodes = load_nodes(args.inventory, args.hosts_env)
    state = AppState(static_dir=Path(__file__).resolve().parent, nodes=nodes, timeout_sec=args.rpc_timeout)

    MonitorHandler.state = state
    server = ThreadingHTTPServer((args.host, args.port), MonitorHandler)

    print(f"Synergy Testnet Monitor GUI listening on http://{args.host}:{args.port}")
    print(f"Inventory: {args.inventory}")
    if args.hosts_env.exists():
        print(f"Hosts overrides: {args.hosts_env}")
    else:
        print("Hosts overrides: (none; using host values from inventory)")
    print(f"Loaded nodes: {len(nodes)}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down monitor server...")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
