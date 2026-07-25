#!/usr/bin/env python3
"""Health-aware JSON-RPC router for the public Synergy testnet gateway.

Primary upstreams are supplied at runtime and must be the relayer RPC URLs.
The router deliberately has no validator endpoints or credentials built in.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen


DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 5655
DEFAULT_LOCAL_FALLBACK_URL = "http://127.0.0.1:5641"
DEFAULT_TIMEOUT_SECONDS = 4.0
DEFAULT_WRITE_TIMEOUT_SECONDS = 90.0
MAX_TIMEOUT_SECONDS = 30.0
MAX_WRITE_TIMEOUT_SECONDS = 90.0
DEFAULT_RELAYER_RPC_PORT = 5640
DEFAULT_MAX_REQUEST_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_SYNID_REGISTRY_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_SYNID_RECORDS = 10_000
DEFAULT_CACHE_TTL_SECONDS = 5.0
DEFAULT_CACHE_ENTRIES = 512
DEFAULT_CACHE_MAX_BYTES = 8 * 1024 * 1024
DEFAULT_CACHE_ENTRY_MAX_BYTES = 256 * 1024
DEFAULT_PARSE_RESPONSE_MAX_BYTES = 256 * 1024
DEFAULT_MAX_CONCURRENT_REQUESTS = 4
DEFAULT_MAX_BATCH_REQUESTS = 32
DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS = 30.0
RESPONSE_READ_CHUNK_BYTES = 64 * 1024
DEFAULT_FAILURE_THRESHOLD = 1
DEFAULT_COOLDOWN_SECONDS = 60.0

LOCAL_SYNID_METHODS = frozenset(
    {
        "synergy_resolveSynID",
        "synergy_reverseResolveSynID",
        "synergy_getAddressBook",
        "synergy_registerSynID",
    }
)
# Kept under the live router's established name for deployment and QA tooling.
LOCAL_READ_METHODS = LOCAL_SYNID_METHODS

# Consensus membership must come from one canonical registry. Relayer-local
# snapshots can legitimately differ during rollout and must not be mixed by
# the public read pool.
CANONICAL_LOCAL_METHODS = frozenset({"synergy_getValidatorSetSnapshot"})

# Block ranges are the router's largest routine response. Preserve them as
# serialized JSON end-to-end so Python never expands the block graph in heap
# and never retains it in the cache.
PASSTHROUGH_READ_METHODS = frozenset({"synergy_getBlockRange"})

WRITE_METHODS = frozenset(
    {
        "eth_sendRawTransaction",
        "eth_sendTransaction",
        "personal_sendTransaction",
        "synergy_simulateTransaction",
        "synergy_sendTransaction",
        "synergy_submitAegisTransaction",
        "synergy_submitAegisTransactionBatch",
        "synergy_submitAegisDagTransaction",
        "synergy_submitAegisDagTransactionBatch",
        "synergy_estimateTransactionFee",
        "synergy_estimateFee",
        "synergy_feeQuote",
        "synergy_estimateGas",
        "synergy_createApproval",
        "synergy_revokeAllApprovals",
        "synergy_createWallet",
        "synergy_createWalletFromKeypair",
        "synergy_registerRelayer",
        "synergy_unregisterRelayer",
        "synergy_relayerHeartbeat",
        "synergy_submitAttestation",
        "synergy_slashRelayer",
        "synergy_setSxcpHeartbeatTimeout",
    }
)


class RouterConfigError(ValueError):
    """Raised when production routing configuration is incomplete."""


class UpstreamError(RuntimeError):
    """Raised for transport, HTTP, size, or malformed-response failures."""


def _positive_float(value: str, name: str, maximum: float | None = None) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise RouterConfigError(f"{name} must be a number") from exc
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        limit = f" and <= {maximum:g}" if maximum is not None else ""
        raise RouterConfigError(f"{name} must be > 0{limit}")
    return parsed


def _positive_int(value: str, name: str, maximum: int | None = None) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RouterConfigError(f"{name} must be an integer") from exc
    if parsed <= 0 or (maximum is not None and parsed > maximum):
        limit = f" and <= {maximum}" if maximum is not None else ""
        raise RouterConfigError(f"{name} must be > 0{limit}")
    return parsed


def _split_urls(value: str | None, name: str, minimum: int = 1) -> tuple[str, ...]:
    urls = tuple(item.strip() for item in (value or "").split(",") if item.strip())
    if len(urls) < minimum:
        raise RouterConfigError(f"{name} must contain at least {minimum} URL(s)")
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RouterConfigError(f"{name} contains an invalid HTTP URL")
        if parsed.username or parsed.password:
            raise RouterConfigError(f"{name} must not contain URL credentials")
    return urls


def _is_loopback_hostname(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_read_upstream_ports(urls: tuple[str, ...], expected_port: int) -> None:
    for url in urls:
        parsed = urlparse(url)
        if _is_loopback_hostname(parsed.hostname):
            continue
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port != expected_port:
            raise RouterConfigError(
                "SYNERGY_RPC_READ_UPSTREAMS must use relayer JSON-RPC port "
                f"{expected_port}; {url} uses {port}"
            )


def _env_first(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return None


@dataclass(frozen=True)
class RouterConfig:
    bind_host: str
    bind_port: int
    read_upstreams: tuple[str, ...]
    write_upstreams: tuple[str, ...]
    local_fallback_url: str | None
    synid_local_source: str | None
    timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int
    cache_ttl_seconds: float
    cache_entries: int
    failure_threshold: int
    cooldown_seconds: float
    cache_max_bytes: int = DEFAULT_CACHE_MAX_BYTES
    cache_entry_max_bytes: int = DEFAULT_CACHE_ENTRY_MAX_BYTES
    parse_response_max_bytes: int = DEFAULT_PARSE_RESPONSE_MAX_BYTES
    max_concurrent_requests: int = DEFAULT_MAX_CONCURRENT_REQUESTS
    max_batch_requests: int = DEFAULT_MAX_BATCH_REQUESTS
    client_socket_timeout_seconds: float = DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS
    write_methods: frozenset[str] = field(default_factory=lambda: WRITE_METHODS)
    write_timeout_seconds: float = DEFAULT_WRITE_TIMEOUT_SECONDS
    max_synid_registry_bytes: int = DEFAULT_MAX_SYNID_REGISTRY_BYTES
    max_synid_records: int = DEFAULT_MAX_SYNID_RECORDS

    @classmethod
    def from_env(cls) -> "RouterConfig":
        read = _split_urls(
            _env_first("SYNERGY_RPC_READ_UPSTREAMS", "SYNERGY_RPC_READ_URLS"),
            "SYNERGY_RPC_READ_UPSTREAMS",
            minimum=3,
        )
        if len(read) != 3:
            raise RouterConfigError("SYNERGY_RPC_READ_UPSTREAMS must contain exactly three relayer URLs")
        if len(set(read)) != len(read):
            raise RouterConfigError("SYNERGY_RPC_READ_UPSTREAMS must contain three distinct relayer URLs")
        relayer_rpc_port = _positive_int(
            os.environ.get("SYNERGY_RPC_RELAYER_RPC_PORT", str(DEFAULT_RELAYER_RPC_PORT)),
            "SYNERGY_RPC_RELAYER_RPC_PORT",
            maximum=65535,
        )
        _validate_read_upstream_ports(read, relayer_rpc_port)
        write = _split_urls(
            _env_first("SYNERGY_RPC_WRITE_UPSTREAMS", "SYNERGY_RPC_WRITE_URLS"),
            "SYNERGY_RPC_WRITE_UPSTREAMS",
        )
        local_fallback = _env_first(
            "SYNERGY_RPC_LOCAL_FALLBACK_URL", "SYNERGY_RPC_LOCAL_STATEFUL_GATEWAY"
        ) or DEFAULT_LOCAL_FALLBACK_URL
        _split_urls(local_fallback, "SYNERGY_RPC_LOCAL_FALLBACK_URL")
        local_fallback = local_fallback.strip()
        synid_source = _env_first(
            "SYNERGY_RPC_SYNID_LOCAL_SOURCE", "SYNERGY_SYNID_REGISTRY_PATH"
        ) or local_fallback
        synid_parsed = urlparse(synid_source)
        if synid_parsed.scheme not in {"", "file", "http", "https"}:
            raise RouterConfigError("SYNERGY_RPC_SYNID_LOCAL_SOURCE must be a path, file URL, or HTTP URL")
        if synid_parsed.username or synid_parsed.password:
            raise RouterConfigError("SYNERGY_RPC_SYNID_LOCAL_SOURCE must not contain URL credentials")
        methods = set(WRITE_METHODS)
        methods.update(
            item.strip()
            for item in os.environ.get("SYNERGY_RPC_WRITE_METHODS", "").split(",")
            if item.strip()
        )
        config = cls(
            bind_host=os.environ.get("SYNERGY_RPC_BIND_HOST", DEFAULT_BIND_HOST),
            bind_port=_positive_int(
                os.environ.get("SYNERGY_RPC_BIND_PORT", str(DEFAULT_BIND_PORT)),
                "SYNERGY_RPC_BIND_PORT",
                maximum=65535,
            ),
            read_upstreams=read,
            write_upstreams=write,
            local_fallback_url=local_fallback,
            synid_local_source=synid_source,
            timeout_seconds=_positive_float(
                os.environ.get("SYNERGY_RPC_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)),
                "SYNERGY_RPC_TIMEOUT_SECONDS",
                maximum=MAX_TIMEOUT_SECONDS,
            ),
            write_timeout_seconds=_positive_float(
                os.environ.get(
                    "SYNERGY_RPC_WRITE_TIMEOUT_SECONDS", str(DEFAULT_WRITE_TIMEOUT_SECONDS)
                ),
                "SYNERGY_RPC_WRITE_TIMEOUT_SECONDS",
                maximum=MAX_WRITE_TIMEOUT_SECONDS,
            ),
            max_request_bytes=_positive_int(
                os.environ.get("SYNERGY_RPC_MAX_REQUEST_BYTES", str(DEFAULT_MAX_REQUEST_BYTES)),
                "SYNERGY_RPC_MAX_REQUEST_BYTES",
            ),
            max_response_bytes=_positive_int(
                os.environ.get("SYNERGY_RPC_MAX_RESPONSE_BYTES", str(DEFAULT_MAX_RESPONSE_BYTES)),
                "SYNERGY_RPC_MAX_RESPONSE_BYTES",
            ),
            cache_ttl_seconds=_positive_float(
                os.environ.get("SYNERGY_RPC_CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS)),
                "SYNERGY_RPC_CACHE_TTL_SECONDS",
            ),
            cache_entries=_positive_int(
                os.environ.get("SYNERGY_RPC_CACHE_ENTRIES", str(DEFAULT_CACHE_ENTRIES)),
                "SYNERGY_RPC_CACHE_ENTRIES",
            ),
            cache_max_bytes=_positive_int(
                os.environ.get("SYNERGY_RPC_CACHE_MAX_BYTES", str(DEFAULT_CACHE_MAX_BYTES)),
                "SYNERGY_RPC_CACHE_MAX_BYTES",
                maximum=512 * 1024 * 1024,
            ),
            cache_entry_max_bytes=_positive_int(
                os.environ.get(
                    "SYNERGY_RPC_CACHE_ENTRY_MAX_BYTES",
                    str(DEFAULT_CACHE_ENTRY_MAX_BYTES),
                ),
                "SYNERGY_RPC_CACHE_ENTRY_MAX_BYTES",
                maximum=64 * 1024 * 1024,
            ),
            parse_response_max_bytes=_positive_int(
                os.environ.get(
                    "SYNERGY_RPC_PARSE_RESPONSE_MAX_BYTES",
                    str(DEFAULT_PARSE_RESPONSE_MAX_BYTES),
                ),
                "SYNERGY_RPC_PARSE_RESPONSE_MAX_BYTES",
                maximum=64 * 1024 * 1024,
            ),
            max_concurrent_requests=_positive_int(
                os.environ.get(
                    "SYNERGY_RPC_MAX_CONCURRENT_REQUESTS",
                    str(DEFAULT_MAX_CONCURRENT_REQUESTS),
                ),
                "SYNERGY_RPC_MAX_CONCURRENT_REQUESTS",
                maximum=1024,
            ),
            max_batch_requests=_positive_int(
                os.environ.get(
                    "SYNERGY_RPC_MAX_BATCH_REQUESTS",
                    str(DEFAULT_MAX_BATCH_REQUESTS),
                ),
                "SYNERGY_RPC_MAX_BATCH_REQUESTS",
                maximum=1024,
            ),
            client_socket_timeout_seconds=_positive_float(
                os.environ.get(
                    "SYNERGY_RPC_CLIENT_SOCKET_TIMEOUT_SECONDS",
                    str(DEFAULT_CLIENT_SOCKET_TIMEOUT_SECONDS),
                ),
                "SYNERGY_RPC_CLIENT_SOCKET_TIMEOUT_SECONDS",
                maximum=MAX_WRITE_TIMEOUT_SECONDS,
            ),
            failure_threshold=_positive_int(
                os.environ.get("SYNERGY_RPC_FAILURE_THRESHOLD", str(DEFAULT_FAILURE_THRESHOLD)),
                "SYNERGY_RPC_FAILURE_THRESHOLD",
            ),
            cooldown_seconds=_positive_float(
                os.environ.get("SYNERGY_RPC_COOLDOWN_SECONDS", str(DEFAULT_COOLDOWN_SECONDS)),
                "SYNERGY_RPC_COOLDOWN_SECONDS",
            ),
            write_methods=frozenset(methods),
            max_synid_registry_bytes=_positive_int(
                os.environ.get(
                    "SYNERGY_RPC_MAX_SYNID_REGISTRY_BYTES", str(DEFAULT_MAX_SYNID_REGISTRY_BYTES)
                ),
                "SYNERGY_RPC_MAX_SYNID_REGISTRY_BYTES",
            ),
            max_synid_records=_positive_int(
                os.environ.get("SYNERGY_RPC_MAX_SYNID_RECORDS", str(DEFAULT_MAX_SYNID_RECORDS)),
                "SYNERGY_RPC_MAX_SYNID_RECORDS",
            ),
        )
        if config.parse_response_max_bytes > config.max_response_bytes:
            raise RouterConfigError(
                "SYNERGY_RPC_PARSE_RESPONSE_MAX_BYTES must be <= SYNERGY_RPC_MAX_RESPONSE_BYTES"
            )
        return config


@dataclass
class EndpointState:
    name: str
    url: str
    consecutive_failures: int = 0
    open_until: float = 0.0
    requests: int = 0
    successes: int = 0
    failures: int = 0

    def available(self, now: float) -> bool:
        return self.open_until <= now


@dataclass
class CacheEntry:
    response_body: bytes
    expires_at: float
    size_bytes: int


@dataclass(frozen=True)
class RawRpcResponse:
    """A validated large JSON-RPC object kept in serialized form."""

    body: bytes | bytearray


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {
            "rpc_requests_total": 0,
            "rpc_request_failures_total": 0,
            "rpc_cache_hits_total": 0,
            "rpc_cache_expired_total": 0,
            "rpc_cache_evictions_total": 0,
            "rpc_cache_oversize_skips_total": 0,
            "rpc_local_fallback_total": 0,
            "rpc_upstream_failures_total": 0,
            "rpc_overload_rejections_total": 0,
            "rpc_large_response_passthrough_total": 0,
        }

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _request_id(request: dict[str, Any]) -> Any:
    return request.get("id")


def _cache_key(request: dict[str, Any]) -> bytes:
    return json.dumps(
        {"method": request.get("method"), "params": request.get("params", [])},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _response_is_success(response: Any) -> bool:
    return isinstance(response, dict) and "error" not in response and (
        "result" in response or response.get("jsonrpc") == "2.0"
    )


FAIL_CLOSED_READ_MARKERS = (
    "busy",
    "lock contention",
    "lock-contention",
    "fail-closed",
    "failed closed",
    "temporarily unavailable",
    "try again later",
)


def _response_is_fail_closed_read(response: dict[str, Any]) -> bool:
    error = response.get("error")
    if not error:
        return False
    if isinstance(error, dict):
        haystack = " ".join(
            str(error.get(key, "")) for key in ("code", "message", "data")
        ).lower()
    else:
        haystack = str(error).lower()
    return any(marker in haystack for marker in FAIL_CLOSED_READ_MARKERS)


def _copy_with_id(
    response: dict[str, Any] | RawRpcResponse, request_id: Any
) -> dict[str, Any] | RawRpcResponse:
    if isinstance(response, RawRpcResponse):
        # The exact client request body is forwarded upstream, including its id.
        return response
    copied = dict(response)
    copied["id"] = request_id
    return copied


def _synid_normalize(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("SynID is required")
    cleaned = value.strip().lstrip("@").lower()
    if not cleaned:
        raise ValueError("SynID is required")
    normalized = cleaned if cleaned.endswith(".syn") else f"{cleaned}.syn"
    label = normalized[:-4]
    if not 3 <= len(label) <= 32:
        raise ValueError("SynID must be 3-32 characters before .syn")
    if not (label[0].islower() or label[0].isdigit()) or not all(
        char.islower() or char.isdigit() or char == "-" for char in label
    ):
        raise ValueError("SynID may only contain lowercase letters, numbers, and hyphens")
    return normalized


_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3
_NETWORK_BURN_ADDRESS = "syn00000000000000000000000000000000000000"


def _bech32_polymod(values: Iterable[int]) -> int:
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for bit, generator in enumerate(generators):
            if (top >> bit) & 1:
                checksum ^= generator
    return checksum


def _is_valid_synergy_address(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == _NETWORK_BURN_ADDRESS:
        return True
    if len(value) != 41 or not value.startswith("syn") or not value.isascii():
        return False
    separator = value.rfind("1")
    if separator < 1 or separator + 7 > len(value):
        return False
    if any(char not in _BECH32_CHARSET for char in value[separator + 1 :]):
        return False
    hrp = value[:separator]
    expanded = [ord(char) >> 5 for char in hrp]
    expanded.append(0)
    expanded.extend(ord(char) & 31 for char in hrp)
    expanded.extend(_BECH32_CHARSET.index(char) for char in value[separator + 1 :])
    return _bech32_polymod(expanded) == _BECH32M_CONST


def _display_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned[:80] if cleaned else None


def _record_from_json(value: Any, fallback_syn_id: Any = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("invalid SynID record")
    syn_id = _synid_normalize(value.get("syn_id") or value.get("synId") or fallback_syn_id)
    address = value.get("address")
    if not isinstance(address, str) or not _is_valid_synergy_address(address.strip()):
        raise ValueError("Wallet address is not a valid Synergy address")
    created_at = value.get("created_at") or value.get("createdAt", 0)
    updated_at = value.get("updated_at") or value.get("updatedAt", 0)
    return {
        "syn_id": syn_id,
        "address": address.strip(),
        "display_name": _display_name(value.get("display_name") or value.get("displayName")),
        "created_at": created_at if isinstance(created_at, int) and created_at >= 0 else 0,
        "updated_at": updated_at if isinstance(updated_at, int) and updated_at >= 0 else 0,
    }


class LocalSynIDStore:
    def __init__(self, source: str, max_bytes: int, max_records: int) -> None:
        self.source = source
        self.max_bytes = max_bytes
        self.max_records = max_records
        self._lock = threading.Lock()

    def _path(self) -> Path:
        parsed = urlparse(self.source)
        if parsed.scheme == "file":
            return Path(unquote(parsed.path))
        if parsed.scheme:
            raise ValueError("SynID source is not a local file")
        return Path(self.source).expanduser()

    def _load(self) -> dict[str, dict[str, Any]]:
        path = self._path()
        if not path.exists():
            return {}
        with path.open("rb") as handle:
            raw_bytes = handle.read(self.max_bytes + 1)
        if len(raw_bytes) > self.max_bytes:
            raise ValueError("SynID registry exceeds configured size limit")
        raw = json.loads(raw_bytes.decode("utf-8"))
        records = raw.get("records", raw) if isinstance(raw, dict) else {}
        if not isinstance(records, dict):
            raise ValueError("SynID registry records must be an object")
        if len(records) > self.max_records:
            raise ValueError("SynID registry exceeds configured record limit")
        loaded: dict[str, dict[str, Any]] = {}
        for key, value in records.items():
            record = _record_from_json(value, key)
            syn_id = record["syn_id"]
            if syn_id in loaded and loaded[syn_id] != record:
                raise ValueError(f"duplicate SynID record: {syn_id}")
            record["syn_id"] = syn_id
            loaded[syn_id] = record
        return loaded

    def _save(self, records: dict[str, dict[str, Any]]) -> None:
        if len(records) > self.max_records:
            raise ValueError("SynID registry exceeds configured record limit")
        path = self._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp")
        body = (json.dumps({"records": records}, indent=2, sort_keys=True) + "\n").encode("utf-8")
        if len(body) > self.max_bytes:
            raise ValueError("SynID registry exceeds configured size limit")
        temporary.write_bytes(body)
        temporary.replace(path)

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request["method"]
        params = request.get("params", [])
        with self._lock:
            records = self._load()
            if method == "synergy_getAddressBook":
                return {"success": True, "records": [records[key] for key in sorted(records)]}
            if method == "synergy_resolveSynID":
                value = params[0] if isinstance(params, list) and params else None
                try:
                    record = records.get(_synid_normalize(value))
                except ValueError as exc:
                    return {"success": False, "error": str(exc)}
                if record is None:
                    return None
                return {
                    "success": True,
                    "synId": record["syn_id"],
                    "address": record["address"],
                    "displayName": record["display_name"],
                    "createdAt": record["created_at"],
                    "updatedAt": record["updated_at"],
                }
            if method == "synergy_reverseResolveSynID":
                address = params[0].strip() if isinstance(params, list) and params and isinstance(params[0], str) else ""
                if not address:
                    return {"success": False, "error": "Wallet address is not a valid Synergy address"}
                return {"success": True, "address": address, "records": [record for record in records.values() if record["address"] == address]}
            if method == "synergy_registerSynID":
                obj = params[0] if isinstance(params, list) and params and isinstance(params[0], dict) else {}
                syn_id_value = obj.get("synId", obj.get("syn_id")) or (params[0] if isinstance(params, list) and params else None)
                address = obj.get("address", obj.get("walletAddress")) or (params[1] if isinstance(params, list) and len(params) > 1 else None)
                display_name = obj.get("displayName", obj.get("name")) or (params[2] if isinstance(params, list) and len(params) > 2 else None)
                if not isinstance(address, str) or not address.strip():
                    return {"success": False, "error": "Missing required parameters: synId, address"}
                address = address.strip()
                if not _is_valid_synergy_address(address):
                    return {"success": False, "error": "Wallet address is not a valid Synergy address"}
                try:
                    syn_id = _synid_normalize(syn_id_value)
                except ValueError as exc:
                    return {"success": False, "error": str(exc)}
                existing = records.get(syn_id)
                if existing and existing["address"] != address:
                    return {"success": False, "error": f"SynID {syn_id} is already registered to a different address"}
                now = int(time.time())
                if existing:
                    existing["display_name"] = _display_name(display_name) or existing["display_name"]
                    existing["updated_at"] = now
                    record = existing
                else:
                    record = {
                        "syn_id": syn_id,
                        "address": address,
                        "display_name": _display_name(display_name),
                        "created_at": now,
                        "updated_at": now,
                    }
                    records[syn_id] = record
                self._save(records)
                return {
                    "success": True,
                    "synId": record["syn_id"],
                    "address": record["address"],
                    "displayName": record["display_name"],
                    "createdAt": record["created_at"],
                    "updatedAt": record["updated_at"],
                }
        raise ValueError(f"unsupported local SynID method: {method}")


def _read_bounded_response(response: Any, max_bytes: int) -> bytearray:
    payload = bytearray()
    while len(payload) <= max_bytes:
        remaining = max_bytes + 1 - len(payload)
        chunk = response.read(min(RESPONSE_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > max_bytes:
        raise UpstreamError("response exceeded configured size limit")
    return payload


def _decode_or_passthrough_response(
    payload: bytes | bytearray,
    parse_max_bytes: int,
    force_passthrough: bool = False,
) -> dict[str, Any] | RawRpcResponse:
    if force_passthrough or len(payload) > parse_max_bytes:
        stripped = payload.strip()
        prefix = stripped[:4096]
        if b'"error"' in prefix and b'"result"' not in prefix:
            force_passthrough = False
        elif (
            stripped.startswith(b"{")
            and stripped.endswith(b"}")
            and b'"jsonrpc"' in prefix
            and b'"result"' in prefix
        ):
            return RawRpcResponse(payload)
        else:
            raise UpstreamError("large upstream response is not a JSON-RPC result object")
    if force_passthrough:
        raise UpstreamError("upstream passthrough response was not a JSON-RPC result object")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise UpstreamError("upstream returned invalid JSON") from None
    if not isinstance(decoded, dict):
        raise UpstreamError("upstream returned a non-object JSON-RPC response")
    return decoded


def _read_json_response(
    url: str,
    body: bytes,
    timeout: float,
    max_bytes: int,
    parse_max_bytes: int,
    force_passthrough: bool = False,
) -> dict[str, Any] | RawRpcResponse:
    request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise UpstreamError(f"HTTP status {response.status}")
            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError:
                    declared_length = -1
                if declared_length > max_bytes:
                    raise UpstreamError("response exceeded configured size limit")
            payload = _read_bounded_response(response, max_bytes)
    except HTTPError as exc:
        raise UpstreamError(f"HTTP status {exc.code}") from None
    except (URLError, TimeoutError, OSError):
        raise UpstreamError("transport failure") from None
    return _decode_or_passthrough_response(
        payload, parse_max_bytes, force_passthrough=force_passthrough
    )


class Router:
    def __init__(self, config: RouterConfig, clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config
        self.clock = clock
        self.metrics = Metrics()
        self._lock = threading.RLock()
        self._cursor = {"read": 0, "write": 0}
        self._states = {
            "read": [EndpointState(f"relayer-{index + 1}", url) for index, url in enumerate(config.read_upstreams)],
            "write": [EndpointState(f"relayer-write-{index + 1}", url) for index, url in enumerate(config.write_upstreams)],
        }
        self._cache: OrderedDict[bytes, CacheEntry] = OrderedDict()
        self._cache_bytes = 0
        self.local_synid = (
            LocalSynIDStore(
                config.synid_local_source,
                config.max_synid_registry_bytes,
                config.max_synid_records,
            )
            if config.synid_local_source and urlparse(config.synid_local_source).scheme in {"", "file"}
            else None
        )

    def _ordered_states(self, kind: str) -> list[EndpointState]:
        with self._lock:
            states = self._states[kind]
            now = self.clock()
            eligible = [state for state in states if state.available(now)]
            if not eligible:
                return []
            start = self._cursor[kind] % len(eligible)
            self._cursor[kind] += 1
            return eligible[start:] + eligible[:start]

    def _mark_success(self, state: EndpointState) -> None:
        with self._lock:
            state.successes += 1
            state.consecutive_failures = 0
            state.open_until = 0.0

    def _mark_failure(self, state: EndpointState) -> None:
        with self._lock:
            state.failures += 1
            state.consecutive_failures += 1
            self.metrics.inc("rpc_upstream_failures_total")
            if state.consecutive_failures >= self.config.failure_threshold:
                state.open_until = self.clock() + self.config.cooldown_seconds

    def _forward(
        self, request: dict[str, Any], kind: str
    ) -> tuple[dict[str, Any] | RawRpcResponse, str]:
        body = _json_bytes(request)
        had_error = False
        timeout = self.config.write_timeout_seconds if kind == "write" else self.config.timeout_seconds
        states = self._ordered_states(kind)
        # A transport error is ambiguous for a state-changing request: retrying
        # on another relayer could submit the same operation twice.
        if kind == "write":
            states = states[:1]
        for state in states:
            with self._lock:
                state.requests += 1
            try:
                response = _read_json_response(
                    state.url,
                    body,
                    timeout,
                    self.config.max_response_bytes,
                    self.config.parse_response_max_bytes,
                    force_passthrough=(
                        kind == "read" and request["method"] in PASSTHROUGH_READ_METHODS
                    ),
                )
                if (
                    kind == "read"
                    and isinstance(response, dict)
                    and _response_is_fail_closed_read(response)
                ):
                    raise UpstreamError("fail-closed read response")
            except UpstreamError as exc:
                del exc
                had_error = True
                self._mark_failure(state)
                continue
            self._mark_success(state)
            if isinstance(response, RawRpcResponse):
                self.metrics.inc("rpc_large_response_passthrough_total")
            return response, state.name
        if had_error:
            raise UpstreamError("all configured upstreams unavailable")
        raise UpstreamError("all configured upstream circuits are open")

    def _forward_local_url(
        self, request: dict[str, Any], url: str
    ) -> dict[str, Any] | RawRpcResponse:
        return _read_json_response(
            url,
            _json_bytes(request),
            self.config.timeout_seconds,
            self.config.max_response_bytes,
            self.config.parse_response_max_bytes,
            force_passthrough=(request["method"] in PASSTHROUGH_READ_METHODS),
        )

    def _cache_get(self, request: dict[str, Any]) -> dict[str, Any] | None:
        key = _cache_key(request)
        with self._lock:
            self._prune_expired_cache_locked(self.clock())
            entry = self._cache.get(key)
            if entry is None:
                return None
            self._cache.move_to_end(key)
            self.metrics.inc("rpc_cache_hits_total")
            response_body = entry.response_body
        try:
            decoded = json.loads(response_body)
        except json.JSONDecodeError:
            return None
        if not isinstance(decoded, dict):
            return None
        return _copy_with_id(decoded, _request_id(request))

    def _prune_expired_cache_locked(self, now: float) -> None:
        expired_keys = [
            key for key, entry in self._cache.items() if entry.expires_at <= now
        ]
        for key in expired_keys:
            expired = self._cache.pop(key)
            self._cache_bytes -= expired.size_bytes
            self.metrics.inc("rpc_cache_expired_total")

    def _cache_put(
        self, request: dict[str, Any], response: dict[str, Any] | RawRpcResponse
    ) -> None:
        if isinstance(response, RawRpcResponse):
            self.metrics.inc("rpc_cache_oversize_skips_total")
            return
        if not _response_is_success(response):
            return
        key = _cache_key(request)
        response_body = _json_bytes(response)
        response_size = len(key) + len(response_body)
        if (
            response_size > self.config.cache_entry_max_bytes
            or response_size > self.config.cache_max_bytes
        ):
            self.metrics.inc("rpc_cache_oversize_skips_total")
            return
        with self._lock:
            self._prune_expired_cache_locked(self.clock())
            previous = self._cache.pop(key, None)
            if previous is not None:
                self._cache_bytes -= previous.size_bytes
            self._cache[key] = CacheEntry(
                response_body,
                self.clock() + self.config.cache_ttl_seconds,
                response_size,
            )
            self._cache_bytes += response_size
            self._cache.move_to_end(key)
            while (
                len(self._cache) > self.config.cache_entries
                or self._cache_bytes > self.config.cache_max_bytes
            ):
                _, evicted = self._cache.popitem(last=False)
                self._cache_bytes -= evicted.size_bytes
                self.metrics.inc("rpc_cache_evictions_total")

    def _local_synid_response(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if self.local_synid is not None:
            return {"jsonrpc": "2.0", "id": _request_id(request), "result": self.local_synid.handle(request)}
        if self.config.synid_local_source:
            return self._forward_local_url(request, self.config.synid_local_source)
        return None

    def route_one(
        self, request: dict[str, Any]
    ) -> dict[str, Any] | RawRpcResponse:
        method = request["method"]
        self.metrics.inc("rpc_requests_total")
        is_synid = method in LOCAL_SYNID_METHODS
        is_write = method in self.config.write_methods

        if method in CANONICAL_LOCAL_METHODS:
            if not self.config.local_fallback_url:
                self.metrics.inc("rpc_request_failures_total")
                return _rpc_error(
                    _request_id(request),
                    -32003,
                    "canonical validator-set source unavailable",
                )
            try:
                response = self._forward_local_url(request, self.config.local_fallback_url)
                return _copy_with_id(response, _request_id(request))
            except (OSError, ValueError, UpstreamError, json.JSONDecodeError):
                self.metrics.inc("rpc_request_failures_total")
                return _rpc_error(
                    _request_id(request),
                    -32003,
                    "canonical validator-set source unavailable",
                )

        if is_synid and self.config.synid_local_source:
            try:
                local_response = self._local_synid_response(request)
                if local_response is not None:
                    return local_response
            except (OSError, ValueError, UpstreamError, json.JSONDecodeError):
                if method == "synergy_registerSynID":
                    self.metrics.inc("rpc_request_failures_total")
                    return _rpc_error(_request_id(request), -32002, "local SynID source unavailable")

        try:
            response, _ = self._forward(request, "write" if is_write else "read")
            if not is_write and not is_synid:
                self._cache_put(request, response)
            return _copy_with_id(response, _request_id(request))
        except UpstreamError:
            if not is_write:
                if self.config.local_fallback_url:
                    try:
                        response = self._forward_local_url(request, self.config.local_fallback_url)
                        self.metrics.inc("rpc_local_fallback_total")
                        self._cache_put(request, response)
                        return _copy_with_id(response, _request_id(request))
                    except UpstreamError:
                        pass
                cached = self._cache_get(request)
                if cached is not None:
                    return cached
            self.metrics.inc("rpc_request_failures_total")
            return _rpc_error(_request_id(request), -32001, "RPC upstream unavailable")

    def route(self, payload: Any) -> Any:
        if isinstance(payload, dict):
            return self.route_one(payload)
        if len(payload) > self.config.max_batch_requests:
            return _rpc_error(None, -32600, "JSON-RPC batch exceeds configured item limit")
        responses: list[dict[str, Any]] = []
        serialized_parts: list[bytes | bytearray] | None = None
        serialized_size = 2
        for item in payload:
            response = self.route_one(item)
            if serialized_parts is None and isinstance(response, dict):
                responses.append(response)
                continue
            if serialized_parts is None:
                serialized_parts = [_json_bytes(previous) for previous in responses]
                serialized_size += sum(len(part) for part in serialized_parts)
                serialized_size += max(0, len(serialized_parts) - 1)
                responses.clear()
            part = response.body if isinstance(response, RawRpcResponse) else _json_bytes(response)
            projected_size = serialized_size + len(part) + (1 if serialized_parts else 0)
            if projected_size > self.config.max_response_bytes:
                return _rpc_error(None, -32003, "response exceeds configured size limit")
            serialized_parts.append(part)
            serialized_size = projected_size
        if serialized_parts is None:
            return responses
        return RawRpcResponse(b"[" + b",".join(serialized_parts) + b"]")

    def health(self) -> tuple[bool, dict[str, Any]]:
        now = self.clock()
        with self._lock:
            read_ready = any(state.available(now) for state in self._states["read"])
            write_ready = any(state.available(now) for state in self._states["write"])
            ready = read_ready and write_ready
            status = "ok" if ready else "degraded" if read_ready or write_ready else "unavailable"
            return ready, {
                "status": status,
                "read_upstreams_ready": read_ready,
                "write_upstreams_ready": write_ready,
                "local_fallback_configured": bool(self.config.local_fallback_url),
                "synid_local_source_configured": bool(self.config.synid_local_source),
            }

    def metrics_text(self) -> str:
        lines = [
            "# TYPE synergy_rpc_router_info gauge",
            'synergy_rpc_router_info{version="1"} 1',
        ]
        for name, value in sorted(self.metrics.snapshot().items()):
            lines.extend([f"# TYPE {name} counter", f"{name} {value}"])
        with self._lock:
            lines.append(f"synergy_rpc_cache_entries {len(self._cache)}")
            lines.append(f"synergy_rpc_cache_bytes {self._cache_bytes}")
            for kind, states in self._states.items():
                for state in states:
                    open_value = 1 if state.open_until > self.clock() else 0
                    lines.append(f'synergy_rpc_upstream_circuit_open{{kind="{kind}",upstream="{state.name}"}} {open_value}')
                    lines.append(f'synergy_rpc_upstream_requests_total{{kind="{kind}",upstream="{state.name}"}} {state.requests}')
                    lines.append(f'synergy_rpc_upstream_successes_total{{kind="{kind}",upstream="{state.name}"}} {state.successes}')
                    lines.append(f'synergy_rpc_upstream_failures_by_endpoint_total{{kind="{kind}",upstream="{state.name}"}} {state.failures}')
        return "\n".join(lines) + "\n"


def _validate_payload(payload: Any, max_batch_requests: int) -> str | None:
    if isinstance(payload, dict):
        requests: Iterable[Any] = (payload,)
    elif isinstance(payload, list) and payload:
        if len(payload) > max_batch_requests:
            return "JSON-RPC batch exceeds configured item limit"
        requests = payload
    else:
        return "Invalid JSON-RPC request"
    for request in requests:
        if not isinstance(request, dict) or not isinstance(request.get("method"), str) or not request["method"]:
            return "Invalid JSON-RPC request"
    return None


class RouterHTTPHandler(BaseHTTPRequestHandler):
    server: "RouterHTTPServer"

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (
            BrokenPipeError,
            ConnectionAbortedError,
            ConnectionResetError,
            TimeoutError,
        ):
            return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            ready, details = self.server.router.health()
            if ready:
                self._send(HTTPStatus.OK, b"ok\n", "text/plain")
            else:
                self._send(HTTPStatus.SERVICE_UNAVAILABLE, _json_bytes(details))
            return
        if self.path in {"/metrics", "/metrics/"}:
            self._send(HTTPStatus.OK, self.server.router.metrics_text().encode("utf-8"), "text/plain; version=0.0.4")
            return
        self._send(HTTPStatus.NOT_FOUND, b'{"error":"not found"}')

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(HTTPStatus.NO_CONTENT, b"", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/":
            self._send(HTTPStatus.NOT_FOUND, b'{"error":"not found"}')
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        limit = self.server.router.config.max_request_bytes
        if length < 0:
            self._send(HTTPStatus.LENGTH_REQUIRED, b'{"error":"content length required"}')
            return
        if length > limit:
            self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b'{"error":"request exceeds configured size limit"}')
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._send(HTTPStatus.BAD_REQUEST, b'{"error":"incomplete request"}')
            return
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send(HTTPStatus.BAD_REQUEST, _json_bytes(_rpc_error(None, -32700, "Parse error")))
            return
        validation_error = _validate_payload(
            payload, self.server.router.config.max_batch_requests
        )
        if validation_error:
            self._send(HTTPStatus.BAD_REQUEST, _json_bytes(_rpc_error(None, -32600, validation_error)))
            return
        response = self.server.router.route(payload)
        body = response.body if isinstance(response, RawRpcResponse) else _json_bytes(response)
        if len(body) > self.server.router.config.max_response_bytes:
            self._send(HTTPStatus.INTERNAL_SERVER_ERROR, _json_bytes(_rpc_error(None, -32003, "response exceeds configured size limit")))
            return
        self._send(HTTPStatus.OK, body)

    def log_message(self, format: str, *args: Any) -> None:
        return


class RouterHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], router: Router) -> None:
        self.router = router
        self._request_slots = threading.BoundedSemaphore(
            router.config.max_concurrent_requests
        )
        self._request_executor = ThreadPoolExecutor(
            max_workers=router.config.max_concurrent_requests,
            thread_name_prefix="rpc-router",
        )
        super().__init__(address, RouterHTTPHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.router.metrics.inc("rpc_overload_rejections_total")
            body = b'{"error":"router concurrency limit reached"}'
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Connection: close\r\n"
                b"Content-Type: application/json\r\n"
                b"Retry-After: 1\r\n"
                b"Content-Length: "
                + str(len(body)).encode("ascii")
                + b"\r\n\r\n"
                + body
            )
            try:
                request.sendall(response)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            request.settimeout(
                self.router.config.client_socket_timeout_seconds
            )
            self._request_executor.submit(
                self.process_request_thread, request, client_address
            )
        except BaseException:
            self._request_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    def server_close(self) -> None:
        self._request_executor.shutdown(wait=True, cancel_futures=True)
        super().server_close()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true", help="validate environment and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        config = RouterConfig.from_env()
    except RouterConfigError as exc:
        print(f"configuration error: {exc}", file=os.sys.stderr)
        return 2
    if args.check_config:
        print("configuration ok")
        return 0
    server = RouterHTTPServer((config.bind_host, config.bind_port), Router(config))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
