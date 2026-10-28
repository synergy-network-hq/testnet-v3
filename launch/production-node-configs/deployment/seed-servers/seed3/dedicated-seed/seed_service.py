#!/usr/bin/env python3
"""HTTP seed service for Synergy testnet public peer discovery."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

ALLOWED_ROLES = {
    "bootnode",
    "validator",
    "relayer",
    "observer",
    "rpc_gateway",
    "archive_validator",
    "explorer_indexer",
}

PRIVATE_HOSTNAMES = {"localhost"}

CANONICAL_PUBLIC_RELAYER_RECOMMENDATIONS = [
    "relay1.synergynode.xyz:5622",
    "relay2.synergynode.xyz:5622",
    "relay3.synergynode.xyz:5622",
]


@dataclass
class EndpointParts:
    host: str
    port: int
    endpoint: str


def utc_now() -> float:
    return time.time()


def isoformat(timestamp: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(utc_now() if timestamp is None else timestamp))


def normalize_role(value: Any) -> str:
    role = str(value or "").strip().lower().replace("-", "_")
    if role == "rpc":
        return "rpc_gateway"
    if role == "archive":
        return "archive_validator"
    if role == "indexer":
        return "explorer_indexer"
    return role


def normalize_dial(value: str) -> str | None:
    parts = parse_endpoint(value)
    return parts.endpoint if parts else None


def parse_endpoint(value: str) -> EndpointParts | None:
    raw = (value or "").strip()
    if not raw:
        return None

    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        if not parsed.hostname or parsed.port is None:
            return None
        return normalize_endpoint_parts(parsed.hostname, parsed.port)

    if raw.startswith("snr://"):
        raw = raw.split("://", 1)[1]
    if raw.startswith("dnsaddr="):
        raw = raw.split("=", 1)[1]
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]
    raw = raw.split("/", 1)[0].strip()
    if not raw:
        return None

    host = ""
    port = ""
    if raw.startswith("["):
        end = raw.find("]")
        if end < 0 or len(raw) <= end + 2 or raw[end + 1] != ":":
            return None
        host = raw[1:end]
        port = raw[end + 2 :]
    elif ":" in raw:
        host, port = raw.rsplit(":", 1)
    else:
        return None

    host = host.strip().strip("[]")
    try:
        port_num = int(port)
    except ValueError:
        return None
    return normalize_endpoint_parts(host, port_num)


def normalize_endpoint_parts(host: str, port: int) -> EndpointParts | None:
    clean_host = (host or "").strip().strip("[]").lower().rstrip(".")
    if not clean_host or port <= 0 or port > 65535:
        return None
    try:
        ipaddress.ip_address(clean_host)
        endpoint = f"[{clean_host}]:{port}" if ":" in clean_host else f"{clean_host}:{port}"
    except ValueError:
        endpoint = f"{clean_host}:{port}"
    return EndpointParts(host=clean_host, port=port, endpoint=endpoint)


def is_netbird_validator_endpoint(endpoint: str) -> bool:
    parts = parse_endpoint(endpoint)
    if not parts or parts.port != 5622:
        return False
    try:
        address = ipaddress.ip_address(parts.host)
    except ValueError:
        return False
    return isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("10.69.0.0/16")


def endpoint_rejection_reason(endpoint: str, *, allow_netbird_validator: bool = False) -> str | None:
    parts = parse_endpoint(endpoint)
    if not parts:
        return "missing or invalid public_endpoint"

    host = parts.host.lower().rstrip(".")
    if host in PRIVATE_HOSTNAMES:
        return "private hostname is not allowed"
    if host == "0.0.0.0":
        return "unspecified address is not allowed"

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None

    if allow_netbird_validator and is_netbird_validator_endpoint(endpoint):
        return None

    if ip.is_unspecified:
        return "unspecified address is not allowed"
    if ip.is_loopback:
        return "loopback address is not allowed"
    if ip.is_link_local:
        return "link-local address is not allowed"
    if ip.is_multicast:
        return "multicast address is not allowed"
    if ip.is_private:
        return "private address is not allowed"
    if isinstance(ip, ipaddress.IPv4Address) and str(ip).startswith("10.69."):
        return "10.69.x VPN endpoint is not allowed"
    return None


def to_dnsaddr(dial: str) -> str | None:
    parts = parse_endpoint(dial)
    if not parts:
        return None
    try:
        ip = ipaddress.ip_address(parts.host)
    except ValueError:
        return f"dnsaddr=/dns4/{parts.host}/tcp/{parts.port}"
    family = "ip6" if ip.version == 6 else "ip4"
    return f"dnsaddr=/{family}/{parts.host}/tcp/{parts.port}"


def int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class SeedConfig:
    label: str
    seed_id: str
    chain_id: str = "synergy-testnet"
    listen_host: str = "0.0.0.0"
    port: int = 5621
    admin_token_env: str = "SEED_ADMIN_TOKEN"
    allow_dynamic_registration: bool = False
    state_file: str = ""
    default_ttl_seconds: int = 900
    max_ttl_seconds: int = 3600
    dialback_timeout_seconds: float = 1.5
    static_dialback_on_start: bool = True
    replication_timeout_seconds: float = 1.0
    bootnodes: list[dict[str, Any]] = field(default_factory=list)
    static_peers: list[str] = field(default_factory=list)
    static_registry: list[dict[str, Any]] = field(default_factory=list)
    dnsaddr_bootstrap: list[str] = field(default_factory=list)
    replication_peers: list[str] = field(default_factory=list)
    public_bootstrap_roles: list[str] = field(default_factory=lambda: ["relayer"])


class SeedState:
    def __init__(self, config: SeedConfig) -> None:
        self.config = config
        self.dynamic_peers: dict[str, dict[str, Any]] = {}
        self.static_peers: dict[str, dict[str, Any]] = {}
        self.state_path = Path(config.state_file).expanduser() if config.state_file else None
        self.expired_total = 0
        self._load_static_registry()
        self._load()
        self._purge_expired(save=False)

    def _load_static_registry(self) -> None:
        now = utc_now()
        entries: list[dict[str, Any]] = []
        for bootnode in self.config.bootnodes:
            hostname = str(bootnode.get("hostname", "")).strip()
            port = int_or_none(bootnode.get("port")) or 5620
            if hostname:
                entries.append(
                    {
                        "chain_id": self.config.chain_id,
                        "role": "bootnode",
                        "node_name": bootnode.get("node_name") or hostname.split(".", 1)[0],
                        "public_endpoint": f"{hostname}:{port}",
                        "listen_port": port,
                        "protocol_version": bootnode.get("protocol_version", "synergy-p2p/1"),
                        "app_version": bootnode.get("app_version", "static"),
                    }
                )
        for peer in self.config.static_peers:
            endpoint = normalize_dial(str(peer))
            if endpoint:
                entries.append({"chain_id": self.config.chain_id, "role": "bootnode", "public_endpoint": endpoint})
        entries.extend(self.config.static_registry)

        for entry in entries:
            record = self._build_record(entry, observed_remote_ip="", now=now, static=True)
            if not record:
                continue
            endpoint = record["public_endpoint"]
            if endpoint_rejection_reason(
                endpoint,
                allow_netbird_validator=record.get("role") == "validator",
            ):
                continue
            if self.config.static_dialback_on_start or entry.get("require_dialback"):
                self._refresh_dialback(record, now)
            elif not record.get("dialback_status"):
                record["dialback_status"] = "pending"
                record["health_status"] = "pending"
            self.static_peers[endpoint] = record

    def _load(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return
        peers = payload.get("dynamic_peers", [])
        now = utc_now()
        for entry in peers:
            record = self._build_record(entry, observed_remote_ip=str(entry.get("observed_remote_ip", "")), now=now)
            if record:
                record.update({k: v for k, v in entry.items() if k in self._persisted_keys()})
                endpoint = normalize_dial(str(record.get("public_endpoint", "")))
                if endpoint:
                    record["public_endpoint"] = endpoint
                    self.dynamic_peers[endpoint] = record

    def _persisted_keys(self) -> set[str]:
        return {
            "chain_id",
            "role",
            "node_name",
            "validator_address",
            "peer_id",
            "node_public_key",
            "public_endpoint",
            "observed_remote_ip",
            "listen_port",
            "protocol_version",
            "app_version",
            "current_height",
            "highest_known_height",
            "sync_gap",
            "last_seen",
            "ttl_seconds",
            "health_status",
            "signature",
            "source_seed",
            "dialback_status",
            "dialback_last_success",
            "dialback_last_failure",
            "failure_count",
            "score",
            "expires_at",
        }

    def _save(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "seed_id": self.config.seed_id,
            "chain_id": self.config.chain_id,
            "saved_at": isoformat(),
            "dynamic_peers": sorted(
                (self._public_record(record, include_internal=True) for record in self.dynamic_peers.values()),
                key=lambda item: item["public_endpoint"],
            ),
        }
        self.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _build_record(
        self,
        payload: dict[str, Any],
        *,
        observed_remote_ip: str,
        now: float,
        static: bool = False,
    ) -> dict[str, Any] | None:
        endpoint = normalize_dial(str(payload.get("public_endpoint") or payload.get("dial") or ""))
        if not endpoint:
            return None
        parts = parse_endpoint(endpoint)
        if not parts:
            return None
        role = normalize_role(payload.get("role") or payload.get("role_id") or ("bootnode" if static else ""))
        if role not in ALLOWED_ROLES:
            return None
        ttl = int_or_none(payload.get("ttl_seconds"))
        if ttl is None:
            ttl = 0 if static else self.config.default_ttl_seconds
        if not static:
            ttl = max(30, min(ttl, self.config.max_ttl_seconds))
        source_seed = str(payload.get("source_seed") or self.config.seed_id).strip() or self.config.seed_id
        current_height = int_or_none(payload.get("current_height"))
        highest_known_height = int_or_none(payload.get("highest_known_height"))
        sync_gap = int_or_none(payload.get("sync_gap"))
        if sync_gap is None and current_height is not None and highest_known_height is not None:
            sync_gap = max(0, highest_known_height - current_height)
        last_seen = str(payload.get("last_seen") or payload.get("timestamp") or isoformat(now)).strip()
        record = {
            "chain_id": str(payload.get("chain_id") or self.config.chain_id).strip() or self.config.chain_id,
            "role": role,
            "node_name": str(payload.get("node_name") or payload.get("node_id") or "").strip(),
            "validator_address": str(payload.get("validator_address") or "").strip(),
            "peer_id": str(payload.get("peer_id") or payload.get("node_id") or "").strip(),
            "node_public_key": str(payload.get("node_public_key") or payload.get("public_key") or "").strip(),
            "public_endpoint": endpoint,
            "observed_remote_ip": observed_remote_ip,
            "listen_port": int_or_none(payload.get("listen_port")) or parts.port,
            "protocol_version": str(payload.get("protocol_version") or "").strip(),
            "app_version": str(payload.get("app_version") or "").strip(),
            "current_height": current_height,
            "highest_known_height": highest_known_height,
            "sync_gap": sync_gap,
            "last_seen": last_seen,
            "ttl_seconds": ttl,
            "health_status": str(payload.get("health_status") or "pending").strip() or "pending",
            "signature": str(payload.get("signature") or "").strip(),
            "source_seed": source_seed,
            "dialback_status": str(payload.get("dialback_status") or "pending").strip() or "pending",
            "dialback_last_success": str(payload.get("dialback_last_success") or "").strip(),
            "dialback_last_failure": str(payload.get("dialback_last_failure") or "").strip(),
            "failure_count": int_or_none(payload.get("failure_count")) or 0,
            "score": int_or_none(payload.get("score")) or 0,
            "expires_at": None if static else now + ttl,
            "static": static,
        }
        return record

    def _refresh_dialback(self, record: dict[str, Any], now: float) -> None:
        ok, reason = self._dialback(record["public_endpoint"])
        if ok:
            record["dialback_status"] = "success"
            record["dialback_last_success"] = isoformat(now)
            record["health_status"] = "healthy"
            record["score"] = self._score(record)
            return
        record["dialback_status"] = "failed"
        record["dialback_last_failure"] = f"{isoformat(now)} {reason}"
        record["failure_count"] = int(record.get("failure_count") or 0) + 1
        record["health_status"] = "unhealthy"
        record["score"] = self._score(record)

    def _dialback(self, endpoint: str) -> tuple[bool, str | None]:
        parts = parse_endpoint(endpoint)
        if not parts:
            return False, "invalid endpoint"
        reason = endpoint_rejection_reason(parts.endpoint)
        if reason:
            return False, reason
        try:
            with socket.create_connection((parts.host, parts.port), timeout=self.config.dialback_timeout_seconds):
                return True, None
        except OSError as exc:
            return False, str(exc)

    def _score(self, record: dict[str, Any]) -> int:
        if record.get("dialback_status") != "success":
            return max(0, 25 - int(record.get("failure_count") or 0) * 5)
        sync_gap = int(record.get("sync_gap") or 0)
        failure_count = int(record.get("failure_count") or 0)
        return max(1, min(100, 100 - min(sync_gap, 50) - failure_count * 5))

    def _purge_expired(self, *, save: bool = True) -> None:
        now = utc_now()
        expired = [
            endpoint
            for endpoint, record in self.dynamic_peers.items()
            if record.get("expires_at") is not None and float(record.get("expires_at") or 0) <= now
        ]
        for endpoint in expired:
            self.dynamic_peers.pop(endpoint, None)
        if expired:
            self.expired_total += len(expired)
            if save:
                self._save()

    def active_records(self, role: str | None = None) -> list[dict[str, Any]]:
        self._purge_expired()
        records = [*self.static_peers.values(), *self.dynamic_peers.values()]
        out = []
        for record in records:
            if role and record.get("role") != role:
                continue
            endpoint = str(record.get("public_endpoint") or "")
            if endpoint_rejection_reason(
                endpoint,
                allow_netbird_validator=record.get("role") == "validator",
            ):
                continue
            if not record.get("static") and (
                record.get("dialback_status") not in {"success", "transport_candidate"}
                or record.get("health_status") != "healthy"
            ):
                continue
            out.append(record)
        return sorted(out, key=lambda item: (str(item.get("role", "")), str(item.get("public_endpoint", ""))))

    def peer_list_payload(self) -> dict[str, Any]:
        records = self.public_bootstrap_records()
        endpoints = sorted({str(record["public_endpoint"]) for record in records})
        dns_records: list[str] = []
        for endpoint in endpoints:
            record = to_dnsaddr(endpoint)
            if record and record not in dns_records:
                dns_records.append(record)
        return {
            "ok": True,
            "label": self.config.label,
            "seed_id": self.config.seed_id,
            "chain_id": self.config.chain_id,
            "generated_at": isoformat(),
            "bootnodes": [],
            "dnsaddr_bootstrap": dns_records,
            "peers": endpoints,
            "registry": [self._public_record(record) for record in records],
        }

    def peers_payload(self, role: str | None = None) -> dict[str, Any]:
        records = self.public_bootstrap_records(role)
        return {
            "ok": True,
            "seed_id": self.config.seed_id,
            "chain_id": self.config.chain_id,
            "role": role,
            "endpoints": [str(record["public_endpoint"]) for record in records],
            "peers": [self._public_record(record) for record in records],
        }

    def public_bootstrap_records(self, role: str | None = None) -> list[dict[str, Any]]:
        allowed_roles = {
            normalized
            for configured in self.config.public_bootstrap_roles
            if (normalized := normalize_role(configured)) in ALLOWED_ROLES
        }
        if not allowed_roles:
            return []
        requested_role = normalize_role(role) if role else None
        if requested_role and requested_role not in allowed_roles:
            return []
        return [
            record
            for record in self.active_records(requested_role)
            if record.get("role") in allowed_roles
        ]

    def health_payload(self) -> dict[str, Any]:
        self._purge_expired()
        active = self.active_records()
        return {
            "ok": True,
            "status": "healthy",
            "seed_id": self.config.seed_id,
            "chain_id": self.config.chain_id,
            "active_public_peers": len(active),
            "dynamic_peers": len(self.dynamic_peers),
            "static_peers": len(self.static_peers),
            "expired_total": self.expired_total,
            "generated_at": isoformat(),
        }

    def metrics_payload(self) -> str:
        self._purge_expired()
        records = [*self.static_peers.values(), *self.dynamic_peers.values()]
        lines = [
            "# HELP synergy_seed_registry_records Seed registry records by role, health, and dialback status.",
            "# TYPE synergy_seed_registry_records gauge",
        ]
        grouped: dict[tuple[str, str, str], int] = {}
        for record in records:
            key = (
                str(record.get("role") or "unknown"),
                str(record.get("health_status") or "unknown"),
                str(record.get("dialback_status") or "unknown"),
            )
            grouped[key] = grouped.get(key, 0) + 1
        for (role, health, dialback), count in sorted(grouped.items()):
            lines.append(
                'synergy_seed_registry_records{seed_id="%s",role="%s",health_status="%s",dialback_status="%s"} %d'
                % (self.config.seed_id, role, health, dialback, count)
            )
        lines.extend(
            [
                "# HELP synergy_seed_registry_public_peers Advertisable public peers with successful dialback.",
                "# TYPE synergy_seed_registry_public_peers gauge",
                f'synergy_seed_registry_public_peers{{seed_id="{self.config.seed_id}"}} {len(self.active_records())}',
                "# HELP synergy_seed_registry_expired_total Dynamic peer records expired since service start.",
                "# TYPE synergy_seed_registry_expired_total counter",
                f'synergy_seed_registry_expired_total{{seed_id="{self.config.seed_id}"}} {self.expired_total}',
            ]
        )
        return "\n".join(lines) + "\n"

    def register(self, payload: dict[str, Any], *, observed_remote_ip: str, replicate: bool) -> tuple[HTTPStatus, dict[str, Any]]:
        return self._upsert(payload, observed_remote_ip=observed_remote_ip, replicate=replicate, heartbeat=False)

    def heartbeat(self, payload: dict[str, Any], *, observed_remote_ip: str, replicate: bool) -> tuple[HTTPStatus, dict[str, Any]]:
        return self._upsert(payload, observed_remote_ip=observed_remote_ip, replicate=replicate, heartbeat=True)

    def _upsert(
        self,
        payload: dict[str, Any],
        *,
        observed_remote_ip: str,
        replicate: bool,
        heartbeat: bool,
    ) -> tuple[HTTPStatus, dict[str, Any]]:
        if not self.config.allow_dynamic_registration:
            return HTTPStatus.OK, {
                "ok": True,
                "accepted": False,
                "reason": "dynamic registration disabled",
                "seed_id": self.config.seed_id,
            }
        now = utc_now()
        record = self._build_record(payload, observed_remote_ip=observed_remote_ip, now=now)
        if not record:
            return HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "accepted": False,
                "reason": "missing or invalid registry fields",
                "seed_id": self.config.seed_id,
            }
        if record["chain_id"] != self.config.chain_id:
            return HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "accepted": False,
                "reason": "chain_id mismatch",
                "seed_id": self.config.seed_id,
            }
        endpoint = record["public_endpoint"]
        reason = endpoint_rejection_reason(
            endpoint,
            allow_netbird_validator=record.get("role") == "validator",
        )
        if reason:
            return HTTPStatus.BAD_REQUEST, {
                "ok": False,
                "accepted": False,
                "reason": reason,
                "seed_id": self.config.seed_id,
                "public_endpoint": endpoint,
            }
        existing = self.dynamic_peers.get(endpoint, {})
        if heartbeat and not existing:
            record["health_status"] = "pending"
        record["failure_count"] = int(existing.get("failure_count") or record.get("failure_count") or 0)
        record["dialback_last_success"] = str(existing.get("dialback_last_success") or record.get("dialback_last_success") or "")
        if is_netbird_validator_endpoint(endpoint) and record["role"] == "validator":
            # Seed registration supplies only a transport candidate.  NetBird
            # validator routes are private to the coordinator and cannot be
            # public-dialed by this service; the validator runtime performs
            # the required synv, chain, and protocol authentication.
            record["dialback_status"] = "transport_candidate"
            record["health_status"] = "healthy"
        else:
            self._refresh_dialback(record, now)
        self.dynamic_peers[endpoint] = record
        self._save()
        if replicate:
            self._replicate("/heartbeat" if heartbeat else "/register", self._public_record(record, include_internal=True))
        registered_until = isoformat(record["expires_at"]) if record.get("expires_at") else None
        dialback_status = str(record.get("dialback_status") or "pending")
        return HTTPStatus.OK, {
            "ok": True,
            "accepted": True,
            "dialback_status": dialback_status,
            "reason": None if dialback_status == "success" else record.get("dialback_last_failure") or "dialback pending",
            "registered_until": registered_until,
            "seed_id": self.config.seed_id,
            "public_endpoint": endpoint,
            "health_status": record.get("health_status"),
            "recommended_peers": self.recommended_peers(exclude=endpoint),
        }

    def _replicate(self, path: str, payload: dict[str, Any]) -> None:
        if not self.config.replication_peers:
            return
        body = json.dumps(payload).encode("utf-8")
        for base_url in self.config.replication_peers:
            url = f"{base_url.rstrip('/')}{path}"
            request = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "X-Seed-Replication": "1"},
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=self.config.replication_timeout_seconds).close()
            except (OSError, urllib.error.URLError, urllib.error.HTTPError):
                continue

    def recommended_peers(self, *, exclude: str = "") -> list[str]:
        active = {str(record["public_endpoint"]) for record in self.public_bootstrap_records()}
        active.update(CANONICAL_PUBLIC_RELAYER_RECOMMENDATIONS)
        active.discard(exclude)
        return sorted(endpoint for endpoint in active if not endpoint_rejection_reason(endpoint))

    def clear(self) -> None:
        self.dynamic_peers.clear()
        self._save()

    def _public_record(self, record: dict[str, Any], *, include_internal: bool = False) -> dict[str, Any]:
        keys = [
            "chain_id",
            "role",
            "node_name",
            "validator_address",
            "peer_id",
            "node_public_key",
            "public_endpoint",
            "observed_remote_ip",
            "listen_port",
            "protocol_version",
            "app_version",
            "current_height",
            "highest_known_height",
            "sync_gap",
            "last_seen",
            "ttl_seconds",
            "health_status",
            "signature",
            "source_seed",
            "dialback_status",
            "dialback_last_success",
            "dialback_last_failure",
            "failure_count",
            "score",
        ]
        if include_internal:
            keys.append("expires_at")
        return {key: record.get(key) for key in keys if record.get(key) not in (None, "")}


class SeedHandler(BaseHTTPRequestHandler):
    server_version = "SynergySeed/2.0"

    @property
    def state(self) -> SeedState:
        return self.server.seed_state  # type: ignore[attr-defined]

    def _write_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_text(self, status: HTTPStatus, body: str, *, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _is_admin(self) -> bool:
        token_name = self.state.config.admin_token_env
        expected = os.environ.get(token_name, "").strip()
        supplied = self.headers.get("X-Seed-Admin-Token", "").strip()
        if expected and supplied == expected:
            return True
        host = self.client_address[0]
        return host in {"127.0.0.1", "::1"}

    def _is_replication(self) -> bool:
        return self.headers.get("X-Seed-Replication", "").strip() == "1"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if path == "/":
            self._write_json(HTTPStatus.OK, self.state.health_payload())
            return
        if path == "/health":
            self._write_json(HTTPStatus.OK, self.state.health_payload())
            return
        if path == "/healthz":
            self._write_text(HTTPStatus.OK, "ok\n")
            return
        if path == "/metrics":
            self._write_text(HTTPStatus.OK, self.state.metrics_payload(), content_type="text/plain; version=0.0.4")
            return
        if path == "/peer-list.json":
            self._write_json(HTTPStatus.OK, self.state.peer_list_payload())
            return
        if path == "/dns/bootstrap.txt":
            payload = self.state.peer_list_payload()
            body = "\n".join(payload["dnsaddr_bootstrap"]) + "\n"
            self._write_text(HTTPStatus.OK, body)
            return
        if path == "/peers":
            role = normalize_role(query.get("role", [""])[0]) if query.get("role") else None
            if role and role not in ALLOWED_ROLES:
                self._write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid role"})
                return
            self._write_json(HTTPStatus.OK, self.state.peers_payload(role))
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path not in {"/register", "/heartbeat", "/peers/register"}:
            self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            return
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._write_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON"})
            return
        observed_remote_ip = self.client_address[0]
        replicate = not self._is_replication()
        if parsed.path == "/heartbeat":
            status, response = self.state.heartbeat(payload, observed_remote_ip=observed_remote_ip, replicate=replicate)
        else:
            status, response = self.state.register(payload, observed_remote_ip=observed_remote_ip, replicate=replicate)
        self._write_json(status, response)

    def do_DELETE(self) -> None:  # noqa: N802
        if urlparse(self.path).path != "/peers":
            self._write_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found"})
            return
        if not self._is_admin():
            self._write_json(HTTPStatus.FORBIDDEN, {"ok": False, "error": "Admin token required"})
            return
        self.state.clear()
        self._write_json(HTTPStatus.OK, {"ok": True, "cleared": True})


def load_config(path: Path) -> SeedConfig:
    payload = json.loads(path.read_text(encoding="utf-8"))
    label = str(payload.get("label", path.stem)).strip() or path.stem
    return SeedConfig(
        label=label,
        seed_id=str(payload.get("seed_id", label)).strip() or label,
        chain_id=str(payload.get("chain_id", "synergy-testnet")).strip() or "synergy-testnet",
        listen_host=str(payload.get("listen_host", "0.0.0.0")).strip() or "0.0.0.0",
        port=int(payload.get("port", 5621)),
        admin_token_env=str(payload.get("admin_token_env", "SEED_ADMIN_TOKEN")).strip() or "SEED_ADMIN_TOKEN",
        allow_dynamic_registration=bool(payload.get("allow_dynamic_registration", False)),
        state_file=str(payload.get("state_file", "")).strip(),
        default_ttl_seconds=int(payload.get("default_ttl_seconds", 900)),
        max_ttl_seconds=int(payload.get("max_ttl_seconds", 3600)),
        dialback_timeout_seconds=float(payload.get("dialback_timeout_seconds", 1.5)),
        static_dialback_on_start=bool(payload.get("static_dialback_on_start", True)),
        replication_timeout_seconds=float(payload.get("replication_timeout_seconds", 1.0)),
        bootnodes=list(payload.get("bootnodes", [])),
        static_peers=list(payload.get("static_peers", [])),
        static_registry=list(payload.get("static_registry", [])),
        dnsaddr_bootstrap=list(payload.get("dnsaddr_bootstrap", [])),
        replication_peers=list(payload.get("replication_peers", [])),
        public_bootstrap_roles=list(payload.get("public_bootstrap_roles", ["relayer"])),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Synergy testnet seed service.")
    parser.add_argument("--config", required=True, help="Path to the seed service JSON config")
    args = parser.parse_args()

    config = load_config(Path(args.config).expanduser())
    state = SeedState(config)
    server = ThreadingHTTPServer((config.listen_host, config.port), SeedHandler)
    server.daemon_threads = True
    server.seed_state = state  # type: ignore[attr-defined]
    print(f"Seed service '{config.label}' listening on {config.listen_host}:{config.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
