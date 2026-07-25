#!/usr/bin/env python3
"""
posy_exporter — Synergy Network Prometheus exporter (polling sidecar).

Polls the local Synergy node's JSON-RPC and exposes Synergy-specific
metrics on an HTTP endpoint (default: 0.0.0.0:6030/metrics).

Design:
  - Runs one thread that loops every --interval seconds.
  - Each loop makes a small batch of synergy_* RPC calls.
  - Failures set synergy_up = 0 and increment synergy_rpc_call_errors_total.
  - Metrics are re-computed each poll so stale values time-expire naturally.

Covers the 14 PromQL templates in grafana_promql_query_reference.md §12
plus an additional ~20 node-health, mempool, and SXCP metrics.

No third-party deps beyond `prometheus_client` and `requests`.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
import time
from typing import Any, Optional

import requests
from prometheus_client import (
    start_http_server, Counter, Gauge, Histogram, Info, CollectorRegistry,
    REGISTRY,
)


LOG = logging.getLogger("posy_exporter")


# --------------------------------------------------------------------------
# Metrics catalogue
# --------------------------------------------------------------------------
# Every metric below is on the shared default Prometheus registry.
# Labels are kept low-cardinality (address, cluster, method, category).
# --------------------------------------------------------------------------

M_UP = Gauge("synergy_up", "1 if the local Synergy RPC responded in the last poll, 0 otherwise")
M_NODE_RPC_UP = Gauge("synergy_node_rpc_up", "1 if the local Synergy RPC exposed authoritative chain data in the last poll, 0 otherwise")
M_POLL_DURATION = Histogram(
    "synergy_poll_duration_seconds",
    "Wallclock duration of a full poll cycle of the exporter",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# --- Node / chain ---
M_BLOCK_HEIGHT = Gauge("synergy_block_height", "Latest finalized block height reported by this node")
M_CHAIN_HEIGHT = Gauge("synergy_chain_height", "Canonical local chain height reported by this node")
M_CHAIN_ID = Gauge("synergy_chain_id", "Chain ID reported by this node")
M_CHAIN_LAST_BLOCK_TIMESTAMP = Gauge(
    "synergy_chain_last_block_timestamp_seconds",
    "Unix timestamp for the latest block reported by this node",
)
M_CHAIN_LAST_BLOCK_AGE = Gauge(
    "synergy_chain_last_block_age_seconds",
    "Age of the latest local block reported by this node, in seconds",
)
M_CHAIN_LATEST_BLOCK_INTERVAL = Gauge(
    "synergy_chain_latest_block_interval_seconds",
    "Seconds between the latest block and its parent, when available",
)
M_CHAIN_RECENT_AVG_BLOCK_TIME = Gauge(
    "synergy_chain_recent_avg_block_time_seconds",
    "Recent average block time reported by this node",
)
M_EPOCH = Gauge("synergy_epoch", "Current epoch number")
M_SYNC_IN_PROGRESS = Gauge("synergy_sync_in_progress", "1 if the node is currently syncing, else 0")
M_SYNC_HIGHEST_BLOCK = Gauge("synergy_sync_highest_block", "Highest block height observed by the sync manager")
M_SYNC_STARTING_BLOCK = Gauge("synergy_sync_starting_block", "Block height where the current sync run started")
M_SYNC_GAP_BLOCKS = Gauge("synergy_sync_gap_blocks", "Difference between the best known height and the local height")
M_SYNC_PROGRESS_PERCENT = Gauge("synergy_sync_progress_percent", "Current sync progress percentage")
M_BEST_PEER_HEIGHT_DELTA = Gauge(
    "synergy_best_peer_height_delta",
    "max(peer.height) - local.height; positive means we're behind",
)
M_BUILD_INFO = Info("synergy_build", "Build / identity info for this node")
M_NODE_INFO = Gauge(
    "synergy_node_info",
    "Static identity and role labels for this Synergy node.",
    ["network", "role", "node_id", "node_name", "validator_address"],
)
M_NODE_UPTIME_SECONDS = Gauge("synergy_node_uptime_seconds", "Process uptime in seconds.")
M_PROCESS_START_TIME_SECONDS = Gauge(
    "synergy_process_start_time_seconds",
    "Unix timestamp for the current process start time.",
)

# --- Peers ---
M_PEER_COUNT = Gauge("synergy_peer_count", "Active peer count")
M_VALIDATOR_PEER_COUNT = Gauge("synergy_validator_peer_count", "Alias of synergy_peer_count kept for the §12 template")
M_PEER_INBOUND = Gauge("synergy_peer_inbound_count", "Inbound peer count")
M_PEER_OUTBOUND = Gauge("synergy_peer_outbound_count", "Outbound peer count")
M_P2P_PEERS_CONNECTED = Gauge("synergy_p2p_peers_connected", "Connected P2P peers visible to this node.")
M_P2P_STATUS_READY_VALIDATORS = Gauge(
    "synergy_p2p_status_ready_validators",
    "Connected validators with status data ready for consensus membership checks.",
)
M_P2P_BEST_VALIDATOR_PEER_HEIGHT = Gauge(
    "synergy_p2p_best_validator_peer_height",
    "Best block height reported by connected validator peers.",
)

# --- Validators ---
M_VALIDATORS_TOTAL = Gauge("synergy_validators_total", "Total validators known to this node")
M_LIVE_VALIDATORS = Gauge("synergy_live_validators", "Validators currently marked active")
M_STATUS_READY_VALIDATORS = Gauge(
    "synergy_status_ready_validators",
    "Validators this node considers ready to produce / finalize",
)
M_VALIDATOR_ACTIVE = Gauge("synergy_validator_active", "1 if this validator is active", ["address", "label"])
M_VALIDATOR_JAILED = Gauge("synergy_validator_jailed", "1 if this validator is jailed", ["address", "label"])
M_VALIDATOR_STAKED = Gauge("synergy_validator_staked_balance", "Staked balance in nwei", ["address", "label"])
M_VALIDATOR_UPTIME = Gauge("synergy_validator_uptime_ratio", "Reported uptime ratio 0..1", ["address", "label"])
M_VALIDATOR_SCORE = Gauge("synergy_validator_score", "PoSy Score", ["address", "label"])
M_VALIDATOR_SCORE_CATEGORY = Gauge(
    "synergy_validator_score_category",
    "PoSy Score broken down by category",
    ["address", "label", "category"],
)

# --- Clusters ---
M_CLUSTER_MEMBER = Gauge(
    "synergy_validator_cluster_member",
    "1 if the validator is a member of the cluster",
    ["cluster", "address"],
)
M_CLUSTER_QUORUM_READY = Gauge(
    "synergy_cluster_quorum_ready",
    "1 if the cluster currently has quorum",
    ["cluster"],
)
M_CLUSTER_BLOCKS = Counter("synergy_cluster_blocks_total", "Blocks produced by this cluster", ["cluster"])
M_CLUSTER_SHUFFLE = Counter("synergy_cluster_shuffle_total", "Cluster shuffles / rebalances observed")

# --- Consensus timing (approximations derived from observed RPC deltas) ---
M_VIEW_CHANGE_TOTAL = Counter("synergy_view_change_total", "Observed view-change events")
M_BLOCK_FINALIZATION = Histogram(
    "synergy_block_finalization_seconds",
    "Wallclock seconds between finalized blocks as observed by the exporter",
    buckets=(0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 6.0, 10.0, 30.0),
)
M_VOTE_REQUEST_LATENCY = Histogram(
    "synergy_vote_request_latency_seconds",
    "Latency of a probe vote-request RPC",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)

# --- Mempool / DAG ---
M_MEMPOOL_SIZE = Gauge("synergy_mempool_size", "Transactions in mempool")
M_DAG_PENDING_TX = Gauge("synergy_dag_pending_transactions", "Transactions awaiting DAG inclusion")
M_GAS_PRICE = Gauge("synergy_gas_price_nwei", "Current gas price (nwei/gas)")

# --- SXCP (cross-chain) ---
M_SXCP_RELAYER_COUNT = Gauge("synergy_sxcp_relayer_count", "Active SXCP relayers")
M_SXCP_HEALTHY_RELAYERS = Gauge("synergy_sxcp_healthy_relayers", "Healthy SXCP relayers")
M_SXCP_ATTESTATIONS = Counter("synergy_sxcp_attestations_total", "Cross-chain attestations observed")

# --- RPC observability (self-metrics) ---
M_RPC_CALL_DURATION = Histogram(
    "synergy_rpc_call_duration_seconds",
    "Exporter-observed RPC call duration",
    ["method"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
M_RPC_CALL_ERRORS = Counter(
    "synergy_rpc_call_errors_total", "Exporter-observed RPC call errors", ["method", "kind"]
)


# --------------------------------------------------------------------------
# RPC client
# --------------------------------------------------------------------------

class RpcClient:
    def __init__(self, url: str, timeout: float = 3.0):
        self.url = url
        self.timeout = timeout
        self._id = 0
        self._s = requests.Session()

    def call(self, method: str, params: Optional[list] = None) -> Any:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}
        t0 = time.monotonic()
        try:
            r = self._s.post(self.url, json=body, timeout=self.timeout)
            dt = time.monotonic() - t0
            M_RPC_CALL_DURATION.labels(method=method).observe(dt)
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                M_RPC_CALL_ERRORS.labels(method=method, kind="rpc_error").inc()
                raise RuntimeError(f"{method}: {data['error']}")
            return data.get("result")
        except requests.Timeout:
            M_RPC_CALL_ERRORS.labels(method=method, kind="timeout").inc()
            raise
        except requests.ConnectionError:
            M_RPC_CALL_ERRORS.labels(method=method, kind="connection").inc()
            raise
        except requests.HTTPError:
            M_RPC_CALL_ERRORS.labels(method=method, kind="http").inc()
            raise
        except json.JSONDecodeError:
            M_RPC_CALL_ERRORS.labels(method=method, kind="json_decode").inc()
            raise


# --------------------------------------------------------------------------
# Poll loop
# --------------------------------------------------------------------------

def _int_like(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    try:
        if isinstance(v, str):
            return int(v, 16) if v.lower().startswith("0x") else int(v)
        if isinstance(v, bool):
            return 1 if v else 0
        return int(v)
    except (TypeError, ValueError):
        return default


def _float_like(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        if isinstance(v, str) and v.lower().startswith("0x"):
            return float(int(v, 16))
        return float(v)
    except (TypeError, ValueError):
        return default


def _extract_label_addr(v: dict) -> tuple[str, str]:
    addr = v.get("address") or v.get("validator") or v.get("validator_address") or ""
    label = v.get("label") or v.get("name") or v.get("moniker") or addr[:12]
    return (str(addr).lower(), str(label))


class Poller:
    def __init__(self, rpc: RpcClient, interval: float, role_label: str):
        self.rpc = rpc
        self.interval = interval
        self.role_label = role_label
        self._stop = threading.Event()
        self._prev_block_time: Optional[float] = None
        self._prev_block_height: Optional[int] = None

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        LOG.info("poller starting (rpc=%s interval=%ss role=%s)", self.rpc.url, self.interval, self.role_label)
        while not self._stop.is_set():
            start = time.monotonic()
            try:
                self.poll_once()
                M_UP.set(1)
                M_NODE_RPC_UP.set(1)
            except Exception as e:  # noqa: BLE001
                LOG.warning("poll failed: %s", e)
                self._mark_rpc_unavailable()
                M_UP.set(0)
                M_NODE_RPC_UP.set(0)
            M_POLL_DURATION.observe(time.monotonic() - start)
            self._stop.wait(self.interval)

    # -- One poll cycle ------------------------------------------------------

    def poll_once(self) -> None:
        # 1. Fetch the authoritative RPC views first. A successful scrape must
        # be able to prove local height from at least one of these sources.
        ni = self._try("synergy_nodeInfo") or {}
        if not isinstance(ni, dict):
            ni = {}
        status = self._try("synergy_getNodeStatus") or {}
        if not isinstance(status, dict):
            status = {}
        latest_block = self._try("synergy_getLatestBlock") or {}
        if not isinstance(latest_block, dict):
            latest_block = {}
        h = self._try("synergy_blockNumber")

        chain_id = (
            ni.get("chain_id")
            or ni.get("chainId")
            or ni.get("network_id")
            or ni.get("networkId")
        )
        if chain_id is not None:
            M_CHAIN_ID.set(_int_like(chain_id))
        version = str(
            ni.get("version")
            or ni.get("node_version")
            or status.get("version")
            or ""
        )
        node_id = str(
            ni.get("node_id")
            or ni.get("nodeId")
            or status.get("node_id")
            or ""
        )
        role = str(ni.get("role") or self.role_label)
        M_BUILD_INFO.info({"version": version, "node_id": node_id, "role": role})
        node_name = str(ni.get("name") or status.get("name") or node_id or self.role_label)
        network_name = str(
            ni.get("network")
            or status.get("network")
            or "synergy-testnet"
        )
        validator_address = str(
            ni.get("validator_address")
            or ni.get("validatorAddress")
            or status.get("validator_address")
            or ""
        )
        _reset_labeled(M_NODE_INFO)
        M_NODE_INFO.labels(
            network=network_name,
            role=role,
            node_id=node_id,
            node_name=node_name,
            validator_address=validator_address,
        ).set(1)

        height_candidates = [
            status.get("last_block"),
            status.get("highest_block"),
            latest_block.get("block_index"),
            latest_block.get("height"),
            latest_block.get("nonce"),
            ni.get("currentBlock"),
            h,
        ]
        height = next(
            (_int_like(value) for value in height_candidates if value not in (None, "")),
            0,
        )
        if height <= 0:
            raise RuntimeError("authoritative height unavailable from RPC")

        now = time.monotonic()
        M_BLOCK_HEIGHT.set(height)
        M_CHAIN_HEIGHT.set(height)
        if self._prev_block_height is not None and height > self._prev_block_height and self._prev_block_time is not None:
            dt = now - self._prev_block_time
            if (height - self._prev_block_height) == 1 and dt < 60:
                M_BLOCK_FINALIZATION.observe(dt)
        if self._prev_block_height is None or height != self._prev_block_height:
            self._prev_block_time = now
            self._prev_block_height = height

        last_block_timestamp = _int_like(
            latest_block.get("timestamp")
            or status.get("timestamp")
            or ni.get("timestamp")
        )
        if last_block_timestamp > 0:
            M_CHAIN_LAST_BLOCK_TIMESTAMP.set(last_block_timestamp)
            M_CHAIN_LAST_BLOCK_AGE.set(max(0, time.time() - last_block_timestamp))
        else:
            M_CHAIN_LAST_BLOCK_TIMESTAMP.set(0)
            M_CHAIN_LAST_BLOCK_AGE.set(0)
        avg_block_time = _float_like(
            status.get("avg_block_time")
            or status.get("average_block_time")
        )
        if avg_block_time:
            M_CHAIN_RECENT_AVG_BLOCK_TIME.set(avg_block_time)
            M_CHAIN_LATEST_BLOCK_INTERVAL.set(avg_block_time)
        else:
            M_CHAIN_RECENT_AVG_BLOCK_TIME.set(0)
            M_CHAIN_LATEST_BLOCK_INTERVAL.set(0)
        uptime_seconds = _int_like(status.get("uptime_seconds"))
        if uptime_seconds > 0:
            M_NODE_UPTIME_SECONDS.set(uptime_seconds)
            M_PROCESS_START_TIME_SECONDS.set(max(0, time.time() - uptime_seconds))
        else:
            M_NODE_UPTIME_SECONDS.set(0)
            M_PROCESS_START_TIME_SECONDS.set(0)

        # 2. sync status
        sync = self._try("synergy_getSyncStatus") or {}
        if not isinstance(sync, dict):
            sync = {}
        in_progress = sync.get("syncing") if "syncing" in sync else sync.get("in_progress", False)
        M_SYNC_IN_PROGRESS.set(1 if in_progress else 0)
        best_peer = _int_like(sync.get("highest_block") or sync.get("best_peer_height"))
        M_SYNC_HIGHEST_BLOCK.set(best_peer)
        M_SYNC_STARTING_BLOCK.set(_int_like(sync.get("starting_block")))
        M_SYNC_PROGRESS_PERCENT.set(_float_like(sync.get("sync_percentage")))
        M_SYNC_GAP_BLOCKS.set(max(0, best_peer - height))

        # 3. peers
        peers = self._try("synergy_getPeerInfo") or []
        if isinstance(peers, dict):
            peers = peers.get("peers", [])
        if not isinstance(peers, list):
            peers = []
        # keep only dict-shaped peer records; the RPC occasionally returns
        # string IDs or error strings we do not want to treat as peer objects
        peers = [p for p in peers if isinstance(p, dict)]
        peer_count = len(peers)
        M_PEER_COUNT.set(peer_count)
        M_VALIDATOR_PEER_COUNT.set(peer_count)
        M_P2P_PEERS_CONNECTED.set(peer_count)
        inbound = sum(1 for p in peers if p.get("direction") == "inbound" or p.get("inbound") is True)
        outbound = peer_count - inbound
        M_PEER_INBOUND.set(inbound)
        M_PEER_OUTBOUND.set(outbound)
        peer_heights = [_int_like(p.get("height") or p.get("block_height")) for p in peers]
        peer_heights = [peer_height for peer_height in peer_heights if peer_height > 0]
        if peer_heights:
            best_peer = max(best_peer, max(peer_heights))
        M_P2P_BEST_VALIDATOR_PEER_HEIGHT.set(best_peer)
        M_BEST_PEER_HEIGHT_DELTA.set(max(0, best_peer - height))

        # 4. validators
        validators = self._try("synergy_getValidators") or []
        if isinstance(validators, dict):
            validators = validators.get("validators", [])
        if not isinstance(validators, list):
            validators = []
        validators = [v for v in validators if isinstance(v, dict)]
        M_VALIDATORS_TOTAL.set(len(validators))
        live = 0
        ready = 0
        # clear per-address gauges so departed validators disappear
        _reset_labeled(M_VALIDATOR_ACTIVE); _reset_labeled(M_VALIDATOR_JAILED)
        _reset_labeled(M_VALIDATOR_STAKED);  _reset_labeled(M_VALIDATOR_UPTIME)
        _reset_labeled(M_VALIDATOR_SCORE);   _reset_labeled(M_VALIDATOR_SCORE_CATEGORY)
        _reset_labeled(M_CLUSTER_MEMBER)
        for v in validators:
            addr, label = _extract_label_addr(v)
            status = str(v.get("status") or v.get("state") or "").lower()
            is_active = 1 if status in ("active", "live", "ready", "online") else 0
            is_jailed = 1 if (v.get("jailed") or status in ("jailed", "slashed")) else 0
            if is_active: live += 1
            if status in ("active", "ready"): ready += 1
            M_VALIDATOR_ACTIVE.labels(address=addr, label=label).set(is_active)
            M_VALIDATOR_JAILED.labels(address=addr, label=label).set(is_jailed)
            M_VALIDATOR_STAKED.labels(address=addr, label=label).set(
                _float_like(v.get("staked") or v.get("stake") or v.get("balance"))
            )
            M_VALIDATOR_UPTIME.labels(address=addr, label=label).set(
                _float_like(v.get("uptime") or v.get("uptime_ratio"))
            )
            M_VALIDATOR_SCORE.labels(address=addr, label=label).set(
                _float_like(v.get("score") or v.get("synergy_score"))
            )
            # Per-validator score breakdown
            if addr:
                try:
                    bd = self.rpc.call("synergy_getSynergyScoreBreakdown", [addr]) or {}
                    for cat, val in (bd.items() if isinstance(bd, dict) else []):
                        M_VALIDATOR_SCORE_CATEGORY.labels(address=addr, label=label, category=str(cat)).set(_float_like(val))
                except Exception:
                    pass
            # Cluster membership (best-effort; real cluster key is in v.cluster / v.cluster_id)
            cluster = str(v.get("cluster") or v.get("cluster_id") or "")
            if cluster and addr:
                M_CLUSTER_MEMBER.labels(cluster=cluster, address=addr).set(1)
        M_LIVE_VALIDATORS.set(live)
        M_STATUS_READY_VALIDATORS.set(ready)
        M_P2P_STATUS_READY_VALIDATORS.set(ready)

        # 5. cluster quorum (derived)
        if validators:
            clusters: dict[str, int] = {}
            clusters_active: dict[str, int] = {}
            for v in validators:
                cl = str(v.get("cluster") or v.get("cluster_id") or "")
                if not cl: continue
                clusters[cl] = clusters.get(cl, 0) + 1
                st = str(v.get("status") or "").lower()
                if st in ("active", "ready", "live"):
                    clusters_active[cl] = clusters_active.get(cl, 0) + 1
            _reset_labeled(M_CLUSTER_QUORUM_READY)
            for cl, total in clusters.items():
                act = clusters_active.get(cl, 0)
                # quorum threshold = ceil(2/3 * total)
                threshold = (2 * total + 2) // 3
                M_CLUSTER_QUORUM_READY.labels(cluster=cl).set(1 if act >= threshold else 0)

        # 6. mempool / gas
        pool = self._try("synergy_getTransactionPool") or self._try("synergy_getPendingTransactions") or []
        if isinstance(pool, dict):
            pool = pool.get("pending") or pool.get("transactions") or []
        if isinstance(pool, list):
            size = len(pool)
        elif isinstance(pool, (int, float)):
            size = int(pool)
        else:
            size = 0
        M_MEMPOOL_SIZE.set(size)
        M_DAG_PENDING_TX.set(size)
        gp = self._try("synergy_gasPrice")
        if gp is not None:
            M_GAS_PRICE.set(_float_like(gp))

        # 7. SXCP
        relayers = self._try("synergy_getRelayerSet") or []
        if isinstance(relayers, dict):
            relayers = relayers.get("relayers", [])
        if not isinstance(relayers, list):
            relayers = []
        M_SXCP_RELAYER_COUNT.set(len(relayers))
        health = self._try("synergy_getRelayerHealth") or {}
        if isinstance(health, dict):
            healthy = sum(1 for v in health.values() if v is True or (isinstance(v, dict) and v.get("healthy")))
            M_SXCP_HEALTHY_RELAYERS.set(healthy)

        # 8. epoch
        consensus_status = self._try("synergy_status") or {}
        if not isinstance(consensus_status, dict):
            consensus_status = {}
        ep = consensus_status.get("epoch") or consensus_status.get("current_epoch")
        if ep is not None:
            M_EPOCH.set(_int_like(ep))

        # 9. probe vote-request latency if the method exists
        t0 = time.monotonic()
        try:
            self.rpc.call("synergy_getValidators", [])
            M_VOTE_REQUEST_LATENCY.observe(time.monotonic() - t0)
        except Exception:
            pass

    def _mark_rpc_unavailable(self) -> None:
        # Clear the canonical chain gauges so Grafana does not display stale
        # heights for validators whose RPC surface has disappeared.
        for metric in (
            M_BLOCK_HEIGHT,
            M_CHAIN_HEIGHT,
            M_CHAIN_LAST_BLOCK_TIMESTAMP,
            M_CHAIN_LAST_BLOCK_AGE,
            M_CHAIN_LATEST_BLOCK_INTERVAL,
            M_CHAIN_RECENT_AVG_BLOCK_TIME,
            M_SYNC_IN_PROGRESS,
            M_SYNC_HIGHEST_BLOCK,
            M_SYNC_STARTING_BLOCK,
            M_SYNC_GAP_BLOCKS,
            M_SYNC_PROGRESS_PERCENT,
            M_BEST_PEER_HEIGHT_DELTA,
            M_PEER_COUNT,
            M_VALIDATOR_PEER_COUNT,
            M_PEER_INBOUND,
            M_PEER_OUTBOUND,
            M_P2P_PEERS_CONNECTED,
            M_P2P_STATUS_READY_VALIDATORS,
            M_P2P_BEST_VALIDATOR_PEER_HEIGHT,
            M_NODE_UPTIME_SECONDS,
            M_PROCESS_START_TIME_SECONDS,
        ):
            metric.set(0)

    def _try(self, method: str, params: Optional[list] = None):
        try:
            return self.rpc.call(method, params)
        except Exception:
            return None


def _reset_labeled(m) -> None:
    """Drop all labeled children of a prometheus_client collector."""
    try:
        m._metrics.clear()  # type: ignore[attr-defined]
    except Exception:
        pass


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Synergy Prometheus exporter (polling sidecar)")
    ap.add_argument("--rpc-url", default=os.environ.get("POSY_RPC_URL", "http://127.0.0.1:5640"),
                    help="Base URL of the local Synergy JSON-RPC")
    ap.add_argument("--listen", default=os.environ.get("POSY_LISTEN", "0.0.0.0"),
                    help="Interface to listen on for /metrics")
    ap.add_argument("--port", type=int, default=int(os.environ.get("POSY_PORT", 6030)),
                    help="Port to listen on for /metrics")
    ap.add_argument("--interval", type=float, default=float(os.environ.get("POSY_INTERVAL", 5.0)),
                    help="Poll interval in seconds")
    ap.add_argument("--role", default=os.environ.get("POSY_ROLE", "unknown"),
                    help="Role label recorded in synergy_build info")
    ap.add_argument("--log-level", default=os.environ.get("POSY_LOG_LEVEL", "INFO"))
    args = ap.parse_args()

    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(message)s")

    rpc = RpcClient(args.rpc_url)
    poller = Poller(rpc, args.interval, args.role)

    def handle_sig(signum, frame):
        LOG.info("signal %d received, shutting down", signum)
        poller.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    LOG.info("serving /metrics on %s:%d", args.listen, args.port)
    start_http_server(args.port, addr=args.listen)
    poller.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
