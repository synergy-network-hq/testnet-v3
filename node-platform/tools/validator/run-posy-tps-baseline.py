#!/usr/bin/env python3
"""Run a bounded genuine-transaction baseline against the current PoSy RPC.

Dry-run is the default. This tool uses the current protected admission API and
delegates signing/encryption to the canonical synergy-keytool wallet command;
it never reads private key bytes itself. A live run requires --execute and an
explicit dedicated signer directory.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import resource
import selectors
import select
import threading
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


VALIDATORS = ("val2", "val3", "val4", "val5", "val6")
MAX_DURATION = 120
MAX_RATE = 5.0
MAX_TX = 600
MAX_IN_FLIGHT = 4
MAX_FINALIZED_LAG = 2
EXPERIMENTAL_LOOKAHEAD_PROFILE = "etdag-protected-lookahead-experimental-v1"
RPC_TIMEOUT = 5
POLL_SECONDS = 1.0
FINALITY_STALL_SECONDS = 6.0
DEFAULT_NETWORK_ID = "synergy-posy-baseline-20261010"
RPC_TOKEN = None
RPC_VPN_PEERS = frozenset()


def configure_rpc_transport(token_file=None, vpn_peers=()):
    """Explicit run-scoped relay access over the existing authenticated VPN."""
    global RPC_TOKEN, RPC_VPN_PEERS
    peers = frozenset(str(ipaddress.ip_address(peer)) for peer in vpn_peers)
    token = None
    if token_file is not None:
        path = Path(token_file)
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077
                or metadata.st_uid != os.geteuid() or metadata.st_size > 256):
            raise BaselineError("RPC token must be a private, owned regular file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r") as stream:
            token = stream.read(257).strip()
        if not token or not all(c.isascii() and (c.isalnum() or c in "-_") for c in token):
            raise BaselineError("RPC token has invalid encoding")
    if peers and token is None:
        raise BaselineError("VPN relay peers require a private run token")
    RPC_TOKEN, RPC_VPN_PEERS = token, peers


class NoRpcRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, *args, **kwargs):
        raise BaselineError("authenticated RPC redirects are forbidden")


class BaselineError(RuntimeError):
    pass


class RpcResponseError(BaselineError):
    """An explicit JSON-RPC response, distinct from ambiguous transport failure."""
    def __init__(self, method, code, message):
        self.method, self.code, self.message = method, code, str(message)[:300]
        super().__init__(f"{method} RPC returned an error: {str(message)[:300]}")


class TransientSampleError(BaselineError):
    """Only recognized progressing-finality readiness/context transitions."""
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def parse_validator_rpc(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected val2=URL through val6=URL")
    name, url = value.split("=", 1)
    if name not in VALIDATORS:
        raise argparse.ArgumentTypeError(f"validator must be one of {', '.join(VALIDATORS)}")
    # Effective transport policy is validated after all CLI options are parsed.
    return name, url


def validate_rpc_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ("https", "http") or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment):
        raise BaselineError("RPC URL must be HTTPS, or loopback HTTP, without embedded credentials")
    if (parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1", "localhost")
            and parsed.hostname not in RPC_VPN_PEERS):
        raise BaselineError("unencrypted HTTP is allowed only for loopback RPC")
    return url


def rpc(url: str, method: str, params: Any, *, timeout: float = RPC_TIMEOUT) -> Any:
    validate_rpc_url(url)
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                      separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if RPC_TOKEN is not None:
        headers["Authorization"] = "Bearer " + RPC_TOKEN
    request = urllib.request.Request(url, data=body, headers=headers)
    try:
        opener = urllib.request.build_opener(NoRpcRedirect()).open if RPC_TOKEN else urllib.request.urlopen
        with opener(request, timeout=timeout) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise BaselineError(f"{method} RPC response exceeds the 4 MiB bound")
        payload = json.loads(raw)
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        host = urllib.parse.urlsplit(url).hostname
        code = getattr(error, "code", None)
        reason = type(getattr(error, "reason", None)).__name__
        raise BaselineError(f"{method} RPC failed at {host}: {type(error).__name__}; HTTP={code}; reason={reason}") from error
    if payload.get("error"):
        error = payload["error"]
        if (method in {"synergy_getProtectedAdmissionContext", "synergy_getProtectedAdmissionContextV2"}
                and isinstance(error, dict)
                and error.get("code") == -32000
                and error.get("message") in {"protected admission context unavailable",
                                             "fresh local protected admission is closed"}):
            raise TransientSampleError(str(error["message"]))
        detail = error.get("message", "unspecified") if isinstance(error, dict) else "invalid error"
        raise RpcResponseError(method, error.get("code") if isinstance(error, dict) else None, detail)
    if "result" not in payload:
        raise BaselineError(f"{method} RPC response has no result")
    return payload["result"]


def validate_chain_id(chain_id: int, expected: int | None = None) -> int:
    if type(chain_id) is not int or not 0 < chain_id < 2**64:
        raise BaselineError("chain_id must be a positive u64")
    if expected is not None and chain_id != validate_chain_id(expected):
        raise BaselineError("node/context is on the wrong chain")
    return chain_id


def canonical_unsigned_signing_bytes(network_id: str, sender: str, receiver: str,
                                     amount_nwei: int, nonce: int, gas_limit: int,
                                     max_fee_per_gas_nwei: int, timestamp_unix: int, *, chain_id: int) -> bytes:
    def sized(data: bytes) -> bytes:
        return len(data).to_bytes(8, "big") + data

    return (b"SYNERGY_TRANSACTION_SIGNING_V1"
            + validate_chain_id(chain_id).to_bytes(8, "big") + sized(network_id.encode()) + b"\x00"
            + sized(sender.encode()) + sized(receiver.encode())
            + amount_nwei.to_bytes(16, "big") + nonce.to_bytes(8, "big")
            + gas_limit.to_bytes(8, "big") + max_fee_per_gas_nwei.to_bytes(8, "big")
            + timestamp_unix.to_bytes(8, "big") + (0).to_bytes(8, "big"))


def transaction_id(network_id: str, sender: str, receiver: str, amount_nwei: int,
                   nonce: int, gas_limit: int, max_fee_per_gas_nwei: int,
                   timestamp_unix: int, *, chain_id: int) -> str:
    signing = canonical_unsigned_signing_bytes(network_id, sender, receiver, amount_nwei,
                                                nonce, gas_limit, max_fee_per_gas_nwei,
                                                timestamp_unix, chain_id=chain_id)
    return hashlib.sha3_256(b"SYNERGY_TRANSACTION_ID_V1" + len(signing).to_bytes(8, "big")
                            + signing).hexdigest()


def order_key() -> str:
    data = os.urandom(32)
    domain = b"POSY_TPS_BASELINE_ORDER_KEY_V1"
    return hashlib.sha3_512(len(domain).to_bytes(8, "big") + domain
                            + len(data).to_bytes(8, "big") + data).hexdigest()


def percentile95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def fresh_admission_context(url: str) -> dict[str, Any]:
    deadline = time.monotonic() + FINALITY_STALL_SECONDS
    previous_target = None
    while time.monotonic() < deadline:
        try:
            context = rpc(url, "synergy_getProtectedAdmissionContext", {})
            target = context.get("context", {}).get("target_height")
            if type(target) is not int:
                raise BaselineError("invalid admission target")
            if previous_target is None:
                previous_target = target
            elif target > previous_target:
                return context
        except TransientSampleError:
            pass
        time.sleep(0.05)
    raise BaselineError("no fresh admission window opened within six seconds")



REMOTE_KEYTOOL = "/usr/local/libexec/synergy/posy-stability/synergy-keytool-wallet-admission"
REMOTE_SIGNER = r"""
import json,os,stat,subprocess,sys,tempfile
from pathlib import Path
custody=Path(sys.argv[1]); mode=sys.argv[2]
if not custody.is_absolute() or '..' in custody.parts: raise SystemExit(1)
for part in [custody,*custody.parents]:
 if part.is_symlink(): raise SystemExit(1)
if not custody.is_dir() or stat.S_IMODE(custody.stat().st_mode)!=0o700: raise SystemExit(1)
public=custody/'wallet.public.json'; secret=custody/'transaction.secret.key'
for p in [public,secret]:
 m=p.lstat()
 if not stat.S_ISREG(m.st_mode) or not 0<m.st_size<=1048576: raise SystemExit(1)
if stat.S_IMODE(secret.stat().st_mode)!=0o600: raise SystemExit(1)
binding=json.loads(public.read_text())
if mode=='public':
 print(json.dumps(binding)); raise SystemExit(0)
tool=Path('/usr/local/libexec/synergy/posy-stability/synergy-keytool-wallet-admission')
if tool.is_symlink() or not tool.is_file() or not os.access(tool,os.X_OK): raise SystemExit(1)
request=json.loads(sys.stdin.buffer.read(1048577))
with tempfile.TemporaryDirectory(prefix='posy-tps-') as name:
 os.chmod(name,0o700); directory=Path(name)
 context=directory/'context.json'; inputs=directory/'input.json'; output=directory/'admission.json'
 context.write_text(json.dumps(request.pop('context'))); os.chmod(context,0o600)
 request.update(wallet_public_path=str(public),transaction_secret_path=str(secret),admission_context_path=str(context))
 inputs.write_text(json.dumps(request)); os.chmod(inputs,0o600)
 result=subprocess.run([str(tool),'prepare-wallet-admission',str(inputs),str(output)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 if result.returncode or output.is_symlink() or not output.is_file() or output.stat().st_size>1048576: raise SystemExit(1)
 admission=json.loads(output.read_text())
 if not isinstance(admission,dict): raise SystemExit(1)
 print(json.dumps(admission))
"""


def remote_owner():
    spec = importlib.util.spec_from_file_location("posy_provision_owner", Path(__file__).with_name("provision-stability-hosts.py"))
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner


def owner_remote(host: str, argv: list[str], data: bytes | None = None) -> bytes:
    """Use one already-open, configured master; never create an SSH connection."""
    owner = remote_owner()
    socket = owner.configured_master_socket(host)
    return owner.remote(host, socket, argv, data=data)


def remote_signer_call(custody: Path, mode: str, request: dict | None = None) -> dict:
    if not custody.is_absolute() or ".." in custody.parts:
        raise BaselineError("remote custody must be an absolute path without traversal")
    try:
        result = owner_remote("synergy-val2",
            ["python3", "-c", REMOTE_SIGNER, str(custody), mode],
            data=None if request is None else json.dumps(request).encode())
        parsed = json.loads(result)
        if not isinstance(parsed, dict): raise ValueError("shape")
        return parsed
    except Exception:
        raise BaselineError("remote native wallet authoring failed; no request sent") from None


def read_remote_wallet(custody: Path) -> tuple[str, Path, Path]:
    public = remote_signer_call(custody, "public")
    sender = public.get("sender")
    if not isinstance(sender, str) or sender != public.get("identity_authorization", {}).get("binding", {}).get("identity_address"):
        raise BaselineError("remote wallet public identity binding mismatch")
    return sender, custody / "wallet.public.json", custody / "transaction.secret.key"


def read_wallet_public(signer_dir: Path) -> tuple[str, Path, Path]:
    if not signer_dir.is_absolute() or signer_dir.is_symlink() or not signer_dir.is_dir():
        raise BaselineError("signer directory must be an absolute, existing non-symlink directory")
    if stat.S_IMODE(signer_dir.stat().st_mode) & 0o077:
        raise BaselineError("dedicated signer directory must be private (mode 0700)")
    public_path = signer_dir / "wallet.public.json"
    secret_path = signer_dir / "transaction.secret.key"
    for path, label in ((public_path, "wallet public binding"), (secret_path, "transaction signer")):
        if path.is_symlink() or not path.is_file():
            raise BaselineError(f"{label} must be a regular non-symlink file")
    if stat.S_IMODE(secret_path.stat().st_mode) & 0o077:
        raise BaselineError("transaction signer file must be private (mode 0600)")
    try:
        public = json.loads(public_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineError("wallet public binding is unreadable or invalid JSON") from error
    sender = public.get("sender")
    binding = public.get("identity_authorization", {}).get("binding", {})
    if not isinstance(sender, str) or sender != binding.get("identity_address"):
        raise BaselineError("wallet address does not match its public identity binding")
    return sender, public_path, secret_path


def endpoint_state(name: str, url: str, require_admission: bool = True, expected_network: str | None = None, expected_chain_id: int | None = None) -> dict[str, Any]:
    if not require_admission:
        status = rpc(url, "synergy_nodeStatus", {})
        if not isinstance(status, dict) or type(status.get("ready")) is not bool:
            raise BaselineError(f"{name} invalid finalized peer chain/readiness")
        validate_chain_id(status.get("chain_id"), expected_chain_id)
        pointer = finalized_peer_pointer(name)
        if pointer["network_id"] != expected_network:
            raise BaselineError(f"{name} finalized peer is on the wrong network")
        block = rpc(url, "synergy_getBlock", {"height": pointer["state"]["finalized_height"], "hash": None})
        if not isinstance(block, dict) or type(block.get("height")) is not int or not all(block.get(k) for k in ["block_hash", "state_root", "finality_certificate_id"]):
            raise BaselineError(f"{name} lacks canonical finalized peer evidence")
        if (block["block_hash"],block["state_root"]) != (pointer["state"]["finalized_block_id"],pointer["state"]["state_root"]):
            raise BaselineError(f"{name} finalized peer durable/RPC disagreement")
        return {"name":name,"height":block["height"],"target_height":None,"network_id":expected_network,
                "status":status,"context":None,"stats":rpc(url,"synergy_getProtectedAdmissionStats",{}),
                "network_binding":"matching finalized block with submitting validator"}
    deadline = time.monotonic() + RPC_TIMEOUT
    while True:
        def bounded_rpc(method: str) -> Any:
            # Each distinct request retains its original transport deadline.
            # The retry window must not shrink a later stats request to a few
            # milliseconds after readiness/context consumed most of it.
            return rpc(url, method, {}, timeout=RPC_TIMEOUT)
        try:
            return endpoint_state_once(name, bounded_rpc, expected_chain_id)
        except TransientSampleError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BaselineError(f"{name} readiness/context unavailable for 5 seconds")
            time.sleep(min(0.1, remaining))


def finalized_peer_pointer(name: str) -> dict[str, Any]:
    # Reuse the same retained-state observation boundary used by live Atlas.
    code = '''import json,os,stat\nfrom pathlib import Path\ndef read(p):\n fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)\n with os.fdopen(fd,'rb') as f:\n  s=os.fstat(f.fileno());assert stat.S_ISREG(s.st_mode) and s.st_size<=1048576\n  return json.loads(f.read(1048577))\nc=read('/etc/synergy/posy-stability/node.json');r=Path(c['storage']['data_directory']);assert r.is_absolute() and str(r).startswith('/var/lib/synergy/posy-stability/')\nprint(json.dumps({'network_id':c['network_id'],'state':read(r/'state/execution/finalized-state.json')['state']}))\n'''
    return json.loads(owner_remote(f"synergy-{name}",['python3','-c',code]))



def validate_context_target(context):
    inner = context.get("context") if isinstance(context, dict) else None
    parameters = context.get("parameters") if isinstance(context, dict) else None
    if not isinstance(inner, dict) or not isinstance(parameters, dict):
        raise BaselineError("admission context requires returned governed parameters")
    offset = parameters.get("target_height_offset")
    profile = parameters.get("profile_id")
    if not (type(offset) is int and
            ((profile == "POSY-ETDAG-v3.0" and offset == 5) or
             (profile == EXPERIMENTAL_LOOKAHEAD_PROFILE and 6 <= offset <= 16))):
        raise BaselineError("unsupported governed admission profile/offset")
    context_offset = inner.get("target_height_offset", 5)
    if type(context_offset) is not int or context_offset != offset:
        raise BaselineError("context offset differs from returned governed parameters")
    source, target = inner.get("source_finalized_height"), inner.get("target_height")
    if type(source) is not int or source < 0 or type(target) is not int or target >= 2**64 or source >= 2**64:
        raise BaselineError("invalid admission source/target height")
    if not ((source == 0 and 3 <= target <= offset) or (source > 0 and target == source + offset)):
        raise BaselineError("admission target differs from governed source mapping")
    return offset


def endpoint_state_once(name: str, read_rpc, expected_chain_id: int | None = None) -> dict[str, Any]:
    status = read_rpc("synergy_nodeStatus")
    validate_chain_id(status.get("chain_id"), expected_chain_id)
    if status.get("ready") is False:
        raise TransientSampleError(f"{name} node is temporarily not ready")
    if status.get("ready") is not True:
        raise BaselineError(f"{name} node has invalid readiness")
    context = read_rpc("synergy_getProtectedAdmissionContext")
    inner = context.get("context") if isinstance(context, dict) else None
    if not isinstance(inner, dict):
        raise BaselineError(f"{name} has no governed protected-admission context")
    height = inner.get("source_finalized_height")
    target = inner.get("target_height")
    network_id = inner.get("network_id")
    validate_context_target(context)
    validate_chain_id(inner.get("chain_id"), status["chain_id"])
    stats = read_rpc("synergy_getProtectedAdmissionStats")
    return {"name": name, "height": height, "target_height": target,
            "network_id": network_id, "status": status,
            "context": context, "stats": stats}


def validate_live_services(name: str, value: dict) -> None:
    services = value.get("services")
    required = {"identity", "storage", "network", "sync", "etdag", "execution", "posy", "rpc"}
    if (value.get("lifecycle") != "active" or not isinstance(services, list)
            or any(not isinstance(item, dict) for item in services)
            or not required.issubset({item.get("id") for item in services})):
        raise BaselineError(f"{name} lacks live service health")
    for service in services:
        readiness = service.get("readiness", {})
        normal_sync = (service.get("id") == "sync" and readiness.get("status") == "pending"
                       and readiness.get("reason") == "verified synchronization remains in progress")
        if (service.get("state") != "running" or service.get("health") != "healthy"
                or not (readiness.get("status") == "ready" or normal_sync)):
            raise BaselineError(f"{name} live service is unhealthy or blocked: {service.get('id')}")


def native_endpoint_state(name: str, url: str, expected_network: str, expected_chain_id: int | None = None, *, live_progress: bool = False) -> dict[str, Any]:
    """Observe service readiness and first native finality within one budget."""
    started = time.monotonic()
    deadline = started + RPC_TIMEOUT
    null_samples = 0
    details = {}
    observed_epoch = None

    def public_field(value: dict, field: str) -> dict:
        raw = value.get(field)
        shown = raw if type(raw) in (int, bool, type(None)) else raw[:64] if isinstance(raw, str) else "non-scalar"
        return {"present": field in value, "type": type(raw).__name__, "value": shown}

    def expired() -> BaselineError:
        return BaselineError(f"{name} native readiness/finality unavailable within 5 seconds; observations="
                             + json.dumps({"null_height_samples": null_samples, "last_fields": details}, sort_keys=True))

    def query(method: str):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise expired()
        return rpc(url, method, {}, timeout=min(RPC_TIMEOUT, remaining))

    for _ in range(51):
        status = query("synergy_nodeStatus")
        if (not isinstance(status, dict) or type(status.get("chain_id")) is not int
                or not 0 < status["chain_id"] < 2**64 or type(status.get("ready")) is not bool):
            fields = {field: public_field(status, field) for field in ("chain_id", "ready")} if isinstance(status, dict) else {"response_type": type(status).__name__}
            raise BaselineError(f"{name} invalid native chain/readiness; fields=" + json.dumps(fields, sort_keys=True))
        validate_chain_id(status["chain_id"], expected_chain_id)
        if status["ready"] or live_progress:
            break
        if time.monotonic() >= deadline:
            raise expired()
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    else:
        raise BaselineError(f"{name} native readiness observation bound exceeded")

    for _ in range(51):
        native = query("synergy_chainTelemetry")
        details = ({field: public_field(native, field) for field in ("chain_id", "epoch", "finalized_height")}
                   | {"network_identity_matches": native.get("network_identity") == expected_network}
                   if isinstance(native, dict) else {"response_type": type(native).__name__})
        if (not isinstance(native, dict) or type(native.get("chain_id")) is not int or native["chain_id"] != status["chain_id"]
                or native.get("network_identity") != expected_network
                or type(native.get("epoch")) is not int or native["epoch"] < 0
                or observed_epoch is not None and native["epoch"] != observed_epoch
                or "finalized_height" not in native):
            raise BaselineError(f"{name} invalid native identity/epoch/height; fields=" + json.dumps(details, sort_keys=True))
        observed_epoch = native["epoch"]
        height = native["finalized_height"]
        if height is None:
            # The native query store explicitly returns null until its first
            # durable finalized block; service readiness does not promise one.
            null_samples += 1
            if time.monotonic() >= deadline:
                raise expired()
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            continue
        if type(height) is not int or height < 0:
            raise BaselineError(f"{name} invalid native identity/epoch/height; fields=" + json.dumps(details, sort_keys=True))
        if live_progress:
            validate_live_services(name, native)
            if type(native.get("process_id")) is not int or native["process_id"] < 1:
                raise BaselineError(f"{name} missing native process identity")
        stats = query("synergy_getProtectedAdmissionStats")
        if time.monotonic() >= deadline:
            raise expired()
        return {"name": name, "height": height, "native_epoch": native["epoch"],
                "network_id": expected_network, "status": status, "context": None, "target_height": None,
                "stats": stats, "native_progress_gate": live_progress,
                "native_process_id": native.get("process_id"), "readiness_rechecked": not live_progress,
                "native_finality_warmup": {"null_height_samples": null_samples,
                    "elapsed_seconds": time.monotonic() - started}}
    raise expired()


def pool_admission_context(url: str, expected_network: str, expected_epoch: int,
                           cancellation: threading.Event, *,
                           operation_deadline: float | None = None, expected_chain_id: int | None = None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Observe target advancement before signing; never retry signed work."""
    start = time.monotonic()
    deadline = start + RPC_TIMEOUT
    if operation_deadline is not None:
        deadline = min(deadline, operation_deadline)
    observations = []
    previous_target = None
    for _ in range(51):
        guard_pool_workload(cancellation, operation_deadline, "context retrieval")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            envelope = rpc(url, "synergy_getProtectedAdmissionContextV2", {}, timeout=min(RPC_TIMEOUT, remaining))
        except TransientSampleError as error:
            observations.append({"elapsed_seconds": time.monotonic() - start, "error": str(error)})
        else:
            guard_pool_workload(cancellation, operation_deadline, "context return")
            context = envelope.get("signing_context") if isinstance(envelope, dict) else None
            validate_context_target(context)
            inner = context["context"]
            validate_chain_id(inner.get("chain_id"), expected_chain_id)
            if inner.get("network_id") != expected_network or type(inner.get("epoch")) is not int or inner["epoch"] != expected_epoch:
                raise BaselineError("V2 signing context differs from native network/epoch")
            observations.append({"elapsed_seconds": time.monotonic() - start,
                                 "source_height": inner["source_finalized_height"],
                                 "target_height": inner["target_height"], "epoch": inner["epoch"]})
            if previous_target is None:
                previous_target = inner["target_height"]
            elif inner["target_height"] > previous_target:
                return envelope, observations
            elif inner["target_height"] < previous_target:
                raise BaselineError("V2 admission target regressed during observation")
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    raise BaselineError("V2 admission window unavailable within bounded read-only observation; observations="
                        + json.dumps(observations, sort_keys=True))


def submit_pool_admission(url: str, admission: dict, record: dict) -> None:
    """Submit once; retain explicit rejection versus transport uncertainty."""
    try:
        response = rpc(url, "synergy_submitProtectedTransaction", admission)
    except RpcResponseError as error:
        record["submission_rejection"] = {"code": error.code, "message": error.message}
        raise BaselineError("explicit protected submission rejection: " + str(error)) from error
    except BaselineError as error:
        record["ambiguous_response"] = True
        record["submission_error"] = str(error)
    else:
        if not isinstance(response, dict) or response.get("receipt_id") != record["receipt_id"]:
            record["submission_failure"] = "submission receipt identity mismatch"
            raise BaselineError(record["submission_failure"])
        record["submission_response"] = {"status": response.get("status"), "receipt_id": response["receipt_id"]}


def observe_pool_receipt(url: str, record: dict) -> dict | None:
    try:
        receipt = rpc(url, "synergy_getProtectedAdmissionReceipt", {"receipt_id": record["receipt_id"]})
    except RpcResponseError as error:
        if error.code != -32000 or error.message != "admission receipt unavailable; verify finalized transaction before retry":
            raise
        record["receipt_observation"] = {"status": "unavailable", "code": error.code, "message": error.message}
        return None
    if (not isinstance(receipt, dict) or receipt.get("receipt_id") != record["receipt_id"]
            or receipt.get("status") not in {"queued", "accepted", "rejected"}):
        raise BaselineError("invalid admission receipt observation")
    record["receipt_observation"] = receipt
    return receipt


def observe_pool_finality(endpoints: dict[str, str], submit_validator: str, record: dict):
    receipt = observe_pool_receipt(endpoints[submit_validator], record)
    if receipt is not None and receipt.get("status") == "rejected":
        raise BaselineError("durable admission rejection: " + str(receipt.get("reason_code", receipt.get("reason"))))
    final = all_finalized(endpoints, record["transaction_id"], record["target_height"], include_views=True)
    return receipt, final


def native_fleet_observation(endpoints: dict[str, str], expected_network: str,
                             states: dict[str, dict[str, Any]], expected_chain_id: int | None = None) -> dict[str, dict[str, Any]]:
    """Align live tips separately from older protected-authoring snapshots.

    Only read-only native tip observations may repeat within the five-second
    window. Identity, epoch, regression and pinned commitment conflicts fail
    immediately; this function never authors or submits a transaction.
    """
    chain_ids = {validate_chain_id(states[name]["status"]["chain_id"], expected_chain_id) for name in VALIDATORS}
    if len(chain_ids) != 1:
        raise BaselineError("validator chain identities disagree")
    chain_id = next(iter(chain_ids))
    epochs = [states[name]["native_epoch"] if states[name].get("context") is None
              else states[name]["context"]["context"].get("epoch") for name in VALIDATORS]
    if any(type(epoch) is not int or epoch < 0 for epoch in epochs) or len(set(epochs)) != 1:
        raise BaselineError("validator protected authority epochs disagree or are invalid")
    deadline = time.monotonic() + RPC_TIMEOUT
    readings = []
    def query(name, params):
        started = time.monotonic()
        value = rpc(endpoints[name], "synergy_chainTelemetry", params,
                    timeout=max(0.1, min(RPC_TIMEOUT, deadline - started)))
        if not isinstance(value, dict) or type(value.get("chain_id")) is not int or value["chain_id"] != chain_id:
            raise BaselineError(f"{name} invalid native chain identity")
        expected_epoch = epochs[VALIDATORS.index(name)]
        if (value.get("network_identity") != expected_network
                or type(expected_epoch) is not int or expected_epoch < 0
                or type(value.get("epoch")) is not int or value["epoch"] != expected_epoch):
            raise BaselineError(f"{name} native network/epoch differs from protected authority")
        if states[name].get("readiness_rechecked") is False:
            validate_live_services(name, value)
            if states[name].get("native_process_id") is not None and value.get("process_id") != states[name]["native_process_id"]:
                raise BaselineError(f"{name} native process changed during live qualification")
        height = value.get("finalized_height")
        if type(height) is not int or height < states[name]["height"]:
            raise BaselineError(f"{name} native finalized height regressed or is invalid")
        return {"started": started, "finished": time.monotonic(), "native": value}
    for _ in range(51):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            pointers = dict(zip(VALIDATORS, pool.map(lambda name: query(name, {}), VALIDATORS)))
        heights = {name: item["native"]["finalized_height"] for name, item in pointers.items()}
        readings.append({"heights": heights,
                         "query_span_seconds": max(p["finished"] for p in pointers.values()) - min(p["started"] for p in pointers.values())})
        if max(heights.values()) - min(heights.values()) <= MAX_FINALIZED_LAG:
            break
        if time.monotonic() >= deadline:
            raise BaselineError(f"native validator finalized-height spread exceeds {MAX_FINALIZED_LAG} blocks for 5 seconds; observations=" + json.dumps(readings, sort_keys=True))
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))
    else:
        raise BaselineError("native finalized-height observation retry bound exceeded")
    common = min(heights.values())
    # Pin exact native commitments after aligned tip observations. The live tip
    # may advance while querying; the comparison height never changes mid-sample.
    deadline = time.monotonic() + RPC_TIMEOUT
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        pinned = dict(zip(VALIDATORS, pool.map(lambda name: query(name, {"at_height": common}), VALIDATORS)))
    blocks = {}
    for name, item in pinned.items():
        commitment = item["native"].get("common_finalized_commitment")
        if (item["native"]["finalized_height"] < heights[name]
                or not isinstance(commitment, dict) or commitment.get("height") != common
                or not all(isinstance(commitment.get(key), str) and commitment[key]
                           for key in ("block_id", "state_root", "finality_certificate_id", "protected_execution_root"))):
            raise BaselineError(f"{name} lacks the pinned native finalized commitment")
        blocks[name] = {"height": common, "block_hash": commitment["block_id"],
                        "state_root": commitment["state_root"],
                        "finality_certificate_id": commitment["finality_certificate_id"],
                        "protected_execution_root": commitment["protected_execution_root"]}
        if states[name].get("context") is not None:
            states[name]["admission_source_height"] = states[name]["height"]
        states[name]["height"] = heights[name]
        states[name]["native_tip_observations"] = readings
        states[name]["native_epoch"] = item["native"]["epoch"]
    if len({block["protected_execution_root"] for block in blocks.values()}) != 1:
        raise BaselineError("validators disagree on the pinned native protected execution root")
    return blocks


def sample_fleet(endpoints: dict[str, str], expected_network: str, submit_validator: str | None = None, *, native_tips: bool = False, expected_chain_id: int | None = None, native_prior_state: dict | None = None, live_progress: bool = False) -> dict[str, dict[str, Any]]:
    if native_prior_state is not None:
        if not native_tips or submit_validator is not None or set(native_prior_state) != set(VALIDATORS):
            raise BaselineError("native progress requires the complete preceding startup-gated fleet")
        states = {name: dict(state) for name, state in native_prior_state.items()}
        for state in states.values():
            if (state.get("context") is not None or not (state.get("status", {}).get("ready") is True or state.get("native_progress_gate") is True)
                    or not isinstance(state.get("native_finality_warmup"), dict)):
                raise BaselineError("native progress lacks the initial readiness/finality gate")
            # This is historical startup readiness, not a fresh Ready claim.
            # Live Sync can receive a newer verified head during normal finality.
            state["readiness_rechecked"] = False
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            if native_tips:
                if submit_validator is not None:
                    raise BaselineError("native tip observation requires the all-five local pool view")
                futures = {pool.submit(native_endpoint_state, name, url, expected_network, expected_chain_id, **({"live_progress": True} if live_progress else {})): name for name, url in endpoints.items()}
            else:
                futures = {pool.submit(endpoint_state, name, url, submit_validator is None or name == submit_validator, expected_network, expected_chain_id): name for name, url in endpoints.items()}
            states = {futures[f]: f.result() for f in concurrent.futures.as_completed(futures)}
    if set(states) != set(VALIDATORS):
        raise BaselineError("exactly one RPC endpoint for each of Val2–Val6 is required")
    chain_ids = {validate_chain_id(s["status"]["chain_id"], expected_chain_id) for s in states.values()}
    if len(chain_ids) != 1:
        raise BaselineError("validator chain identities disagree")
    if any(s["network_id"] != expected_network for s in states.values()):
        raise BaselineError("validator RPCs do not all report the expected fresh-chain network")
    if submit_validator is not None:
        # Align height observations after variable-duration RPC calls. A fresh
        # admission context is an authoring snapshot, not a live tip oracle.
        snapshot_deadline = time.monotonic() + RPC_TIMEOUT
        while True:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                pointers = dict(zip(VALIDATORS, pool.map(finalized_peer_pointer, VALIDATORS)))
            heights = [p["state"]["finalized_height"] for p in pointers.values()]
            if max(heights) - min(heights) <= MAX_FINALIZED_LAG:
                break
            if time.monotonic() >= snapshot_deadline:
                raise BaselineError(f"validator finalized-height spread exceeds {MAX_FINALIZED_LAG} blocks for 5 seconds")
            time.sleep(0.1)
        for name, pointer in pointers.items():
            if pointer["network_id"] != expected_network:
                raise BaselineError(f"{name} durable network differs")
            height = pointer["state"]["finalized_height"]
            if type(height) is not int or height < states[name]["height"]:
                raise BaselineError(f"{name} finalized height regressed")
            states[name]["height"] = height
    # RPCs are sampled sequentially across hosts. Their reported live tips can
    # advance between calls, so compare commitments at a common finalized height
    # instead of requiring coincidentally identical live-tip samples.
    common_height = min(s["height"] for s in states.values())
    blocks: dict[str, dict[str, Any]] = {}
    if native_tips:
        if submit_validator is not None:
            raise BaselineError("native tip observation requires the all-five local pool view")
        blocks = native_fleet_observation(endpoints, expected_network, states, expected_chain_id)
        common_height = min(s["height"] for s in states.values())
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(rpc, endpoints[name], "synergy_getBlock",
                                   {"height": common_height, "hash": None}): name
                       for name in VALIDATORS}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                block = future.result()
                if (not isinstance(block, dict) or block.get("height") != common_height
                        or not block.get("block_hash") or not block.get("state_root") or not block.get("finality_certificate_id")):
                    raise BaselineError(f"{name} lacks the common finalized block commitment")
                blocks[name] = block
    commitments = {(b["block_hash"], b["state_root"], b["finality_certificate_id"]) for b in blocks.values()}
    if len(commitments) != 1:
        raise BaselineError("validators disagree on the common finalized block/state")
    if submit_validator is not None:
        for name, pointer in pointers.items():
            durable = pointer["state"]
            if durable["finalized_height"] == common_height and (durable["finalized_block_id"],durable["state_root"]) != (blocks[name]["block_hash"],blocks[name]["state_root"]):
                raise BaselineError(f"{name} common durable/RPC disagreement")
    max_height = max(s["height"] for s in states.values())
    lag = max_height - common_height
    if lag > MAX_FINALIZED_LAG:
        raise BaselineError(f"validator finalized-height spread exceeds {MAX_FINALIZED_LAG} blocks")
    for name, state in states.items():
        state["common_height"] = common_height
        state["block_hash"], state["state_root"], state["finality_certificate_id"] = next(iter(commitments))
        state["lag_blocks"] = max_height - state["height"]
        state["distance_above_common"] = state["height"] - common_height
    return states


def require_progressing_preflight(endpoints: dict[str, str], expected_network: str,
                                  stable_seconds: int, measure_outside_target: bool = False, submit_validator: str | None = None, maximum_gap_seconds: float = FINALITY_STALL_SECONDS) -> tuple[dict[str, Any], dict[str, Any]]:
    first = sample_fleet(endpoints, expected_network, submit_validator)
    first_time = time.monotonic()
    prev = first
    last_advance = first_time
    last_advance_height = first["val2"]["common_height"]
    while time.monotonic() - first_time < stable_seconds:
        time.sleep(POLL_SECONDS)
        current = sample_fleet(endpoints, expected_network, submit_validator, expected_chain_id=first["val2"]["status"]["chain_id"])
        now = time.monotonic()
        current_height = current["val2"]["common_height"]
        if current_height > last_advance_height:
            last_advance = now
            last_advance_height = current_height
        elif now - last_advance > maximum_gap_seconds:
            raise BaselineError("finalized tip stalled during the all-five preflight")
        prev = current
    elapsed = max(0.001, time.monotonic() - first_time)
    advanced = prev["val2"]["common_height"] - first["val2"]["common_height"]
    if advanced <= 0:
        raise BaselineError("five-validator tip did not advance during the preflight window")
    avg_block_time = elapsed / advanced
    prev["val2"]["preflight_average_block_time_seconds"] = avg_block_time
    if not 0.5 <= avg_block_time <= 1.5 and not measure_outside_target:
        raise BaselineError("average finalized block cadence over the full preflight window is outside 0.5–1.5 seconds")
    return first, prev


def make_admission(keytool: Path, public_path: Path, secret_path: Path,
                   context: dict[str, Any], output_dir: Path, sender: str, receiver: str,
                   amount: int, nonce: int, gas_limit: int, max_fee: int,
                   gas_units: int, fee_class: int, timestamp: int,
                   remote: bool = False) -> tuple[dict[str, Any], str]:
    if remote:
        request = {"context": context, "sender": sender, "receiver": receiver,
                   "amount_nwei": amount, "nonce": nonce, "timestamp_unix": timestamp,
                   "gas_limit": gas_limit, "max_fee_per_gas_nwei": max_fee,
                   "gas_class_units": gas_units, "fee_class": fee_class,
                   "content_blind_order_key": order_key()}
        admission = remote_signer_call(public_path.parent, "admission", request)
        txid = transaction_id(context["context"]["network_id"], sender, receiver, amount,
                              nonce, gas_limit, max_fee, timestamp, chain_id=context["context"]["chain_id"])
        return admission, txid
    context_path = output_dir / "context.json"
    input_path = output_dir / "input.json"
    admission_path = output_dir / "admission.json"
    context_path.write_text(json.dumps(context, separators=(",", ":")), encoding="utf-8")
    os.chmod(context_path, 0o600)
    input_obj = {"wallet_public_path": str(public_path),
                 "transaction_secret_path": str(secret_path),
                 "admission_context_path": str(context_path),
                 "sender": sender, "receiver": receiver, "amount_nwei": amount,
                 "nonce": nonce, "timestamp_unix": timestamp,
                 "gas_limit": gas_limit, "max_fee_per_gas_nwei": max_fee,
                 "gas_class_units": gas_units, "fee_class": fee_class,
                 "content_blind_order_key": order_key()}
    input_path.write_text(json.dumps(input_obj, separators=(",", ":")), encoding="utf-8")
    os.chmod(input_path, 0o600)
    result = subprocess.run([str(keytool), "prepare-wallet-admission", str(input_path), str(admission_path)],
                            check=False, capture_output=True, text=True, timeout=30)
    if result.returncode != 0 or not admission_path.is_file():
        raise BaselineError("canonical wallet signer rejected admission authoring; no request sent")
    os.chmod(admission_path, 0o600)
    try:
        admission = json.loads(admission_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise BaselineError("canonical wallet signer produced invalid admission JSON") from error
    txid = transaction_id(context["context"]["network_id"], sender, receiver, amount, nonce,
                          gas_limit, max_fee, timestamp, chain_id=context["context"]["chain_id"])
    return admission, txid


def all_finalized(endpoints: dict[str, str], txid: str, target_height: int,
                  *, include_views: bool = False) -> dict[str, Any] | None:
    """Read one signed target block from every validator, never historical receipt scans.

    A protected-admission context binds each submitted transaction to one target
    height.  Once that target is finalized, the canonical finalized block view
    contains the transaction and its execution receipt.  Looking only there
    makes a missing result an honest "not finalized at its signed target" state
    and bounds each reconciliation pass to five direct block reads.
    """
    if type(target_height) is not int or not 0 <= target_height < 2**64:
        raise BaselineError("invalid signed transaction target height")

    def lookup(name_url: tuple[str, str]) -> tuple[str, Any]:
        name, url = name_url
        return name, rpc(url, "synergy_getBlock", {"height": target_height, "hash": None})

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        blocks = dict(pool.map(lookup, endpoints.items()))
    if any(block is None for block in blocks.values()):
        return None

    found: dict[str, dict[str, Any]] = {}
    for name, block in blocks.items():
        if not isinstance(block, dict) or block.get("height") != target_height:
            raise BaselineError(f"{name} lacks the signed target finalized block")
        transactions, receipts = block.get("transactions"), block.get("receipts")
        if not isinstance(transactions, list) or not isinstance(receipts, list) or len(transactions) != len(receipts):
            raise BaselineError(f"{name} signed target block has invalid execution contents")
        matches = [index for index, receipt in enumerate(receipts)
                   if isinstance(receipt, dict) and receipt.get("transaction_id") == txid]
        if not matches:
            return None
        if len(matches) != 1:
            raise BaselineError(f"{name} signed target block contains duplicate transaction receipts")
        index = matches[0]
        if not isinstance(transactions[index], dict):
            raise BaselineError(f"{name} signed target block has invalid transaction entry")
        if not all(isinstance(block.get(field), str) and block[field]
                   for field in ("block_hash", "finality_certificate_id")):
            raise BaselineError(f"{name} signed target block lacks finality evidence")
        receipt = receipts[index]
        status = receipt.get("status")
        if not isinstance(status, str):
            raise BaselineError(f"{name} signed target receipt has invalid status")
        found[name] = {
            "transaction_id": txid,
            "block_height": target_height,
            "block_hash": block["block_hash"],
            "finality_certificate_id": block["finality_certificate_id"],
            "status": status,
            "transaction": transactions[index],
            "receipt": receipt,
        }
    fingerprints = {json.dumps({k:v.get(k) for k in ("block_height","block_hash","finality_certificate_id","status","transaction","receipt")},sort_keys=True,separators=(",",":")) for v in found.values()}
    if len(fingerprints) != 1:
        raise BaselineError("validators disagree on finalized transaction receipt")
    result = next(iter(found.values()))
    if result.get("status") != "applied":
        raise BaselineError("finalized transaction receipt is not applied")
    return {**result,"validator_views":found} if include_views else result


def verify_context_source_block(context: dict[str, Any], states: dict[str, dict[str, Any]],
                                endpoints: dict[str, str], submit_name: str) -> None:
    """Bind fresh protected context to a canonical finalized block view.

    Query the context's own source height from the submitting validator and all
    other validators whose sampled finalized tip has reached that height. Their
    commitments must agree. Ahead validators may legitimately be beyond the
    fleet's minimum common height, up to MAX_FINALIZED_LAG.
    """
    inner = context.get("context") if isinstance(context, dict) else None
    if not isinstance(inner, dict):
        raise BaselineError("submit endpoint returned no protected-admission context")
    source_height = inner.get("source_finalized_height")
    target_height = inner.get("target_height")
    validate_context_target(context)
    if (not isinstance(inner.get("source_finality_context_root"), str)
            or not inner["source_finality_context_root"]):
        raise BaselineError("submit endpoint protected context is not a complete governed F+5 context")
    if (inner.get("network_id") != states[submit_name]["network_id"]
            or source_height > states[submit_name]["height"]):
        raise BaselineError("submit context source is outside the submitting validator's sampled finalized tip")
    eligible = [name for name, state in states.items() if state["height"] >= source_height]
    if submit_name not in eligible:
        raise BaselineError("submit validator has not finalized the admission context source height")
    blocks: dict[str, dict[str, Any]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(eligible)) as pool:
        futures = {pool.submit(rpc, endpoints[name], "synergy_getBlock",
                               {"height": source_height, "hash": None}): name
                   for name in eligible}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            block = future.result()
            if (not isinstance(block, dict) or block.get("height") != source_height
                    or not block.get("block_hash") or not block.get("state_root")
                    or not block.get("finality_certificate_id")):
                raise BaselineError(f"{name} lacks the protected context source finalized-block view")
            blocks[name] = block
    commitments = {(b["block_hash"], b["state_root"], b["finality_certificate_id"])
                   for b in blocks.values()}
    if len(commitments) != 1:
        raise BaselineError("validators disagree on the protected context source finalized block")


def sample_resource() -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {"scope": "load-generator-host-only", "user_cpu_seconds": usage.ru_utime,
            "system_cpu_seconds": usage.ru_stime, "max_rss_platform_units": usage.ru_maxrss}


def operational_drain_deadline(args, offered_end):
    """Optional run-control bound, never a transaction latency requirement."""
    seconds = getattr(args, "drain_timeout_seconds", None)
    if seconds is not None and (type(seconds) not in (int, float)
            or not math.isfinite(seconds) or not 0 < seconds <= 86400):
        raise BaselineError("drain timeout must be finite, positive and at most 86400 seconds")
    return None if seconds is None else offered_end + seconds


def run(args: argparse.Namespace) -> dict[str, Any]:
    if getattr(args, "wallet_registry", None):
        return run_wallet_pool(args)
    if getattr(args, "workload_mode", "offered-rate") != "offered-rate":
        raise BaselineError("closed-loop-memory requires the explicit funded wallet pool")
    if getattr(args,"operator_wallet_registry",False):
        raise BaselineError("--operator-wallet-registry requires an explicit registry")
    operational_drain_deadline(args, 0)
    partial: dict[str, Any] = {"status": "running", "network_id": args.network_id,
                               "execute": bool(args.execute), "transactions": []}
    args._partial_report = partial
    endpoints = dict(args.validator_rpc)
    if len(endpoints) != 5 or set(endpoints) != set(VALIDATORS):
        raise BaselineError("provide exactly one --validator-rpc for each of Val2–Val6")
    if not math.isfinite(args.maximum_gap_seconds) or not 0 < args.maximum_gap_seconds <= 600:
        raise BaselineError("finite positive block stall budget at most 600 seconds required")
    if args.duration_seconds <= 0 or args.duration_seconds > MAX_DURATION:
        raise BaselineError(f"duration must be in 1..{MAX_DURATION} seconds")
    if not math.isfinite(args.rate_tps) or args.rate_tps <= 0 or args.rate_tps > MAX_RATE:
        raise BaselineError(f"rate must be in 0..{MAX_RATE:g} TPS")
    if args.max_tx <= 0 or args.max_tx > MAX_TX:
        raise BaselineError(f"transaction cap must be in 1..{MAX_TX}")
    if args.stability_seconds < 10 or args.stability_seconds > 120:
        raise BaselineError("stability window must be in 10..120 seconds")
    if args.execute and any(v is None for v in (args.gas_limit, args.max_fee_per_gas_nwei, args.gas_class_units)):
        raise BaselineError("--execute requires explicit governed --gas-limit, --max-fee-per-gas-nwei, and --gas-class-units")
    configured = (args.amount_nwei, args.gas_limit, args.max_fee_per_gas_nwei, args.gas_class_units)
    if any(v is not None and v <= 0 for v in configured):
        raise BaselineError("amount and governed gas/fee values must be positive")
    keytool = args.keytool
    if getattr(args, "remote_signer", False):
        keytool = Path(REMOTE_KEYTOOL)
    elif args.execute:
        keytool = keytool.resolve(strict=True)
        if not keytool.is_file() or not os.access(keytool, os.X_OK):
            raise BaselineError("--keytool must name an executable canonical synergy-keytool binary")
    if args.signer_dir is None:
        if args.execute:
            raise BaselineError("--execute requires an explicit dedicated --signer-dir")
        signer = None
        sender = None
        public_path = secret_path = None
    else:
        signer = args.signer_dir
        if getattr(args, "remote_signer", False):
            sender, public_path, secret_path = read_remote_wallet(signer)
        else:
            sender, public_path, secret_path = read_wallet_public(signer)
    if args.receiver:
        receiver = args.receiver
    elif args.execute:
        raise BaselineError("--execute requires an explicit --receiver")
    else:
        receiver = "<required-for-execution>"

    first, stable_tip = require_progressing_preflight(endpoints, args.network_id, args.stability_seconds,
                                                     getattr(args, "measure_outside_cadence_target", False), args.submit_validator, args.maximum_gap_seconds)
    chain_id = first["val2"]["status"]["chain_id"]
    partial["chain_id"] = chain_id
    partial.update({"preflight_start_tip": tip_record(first),
                    "preflight_end_tip": tip_record(stable_tip),
                    "preflight_complete": True,
                    "preflight_average_block_time_seconds": stable_tip["val2"]["preflight_average_block_time_seconds"]})
    if not args.execute:
        return {"status": "dry_run_ready", "execute": False, "network_id": args.network_id, "chain_id": chain_id,
                "start_tip": tip_record(first), "preflight_end_tip": tip_record(stable_tip),
                "planned_rate_tps": args.rate_tps, "planned_duration_seconds": args.duration_seconds,
                "planned_max_tx": args.max_tx, "signer_present": signer is not None,
                "sender_address": sender, "receiver_address": receiver,
                "note": "No signer bytes were read and no transaction was submitted."}
    assert signer is not None and sender is not None and public_path is not None and secret_path is not None
    submit_name = args.submit_validator
    submit_url = endpoints[submit_name]
    account_views = {name: rpc(url, "synergy_getAccount", {"address": sender, "at_height": None})
                     for name, url in endpoints.items()}
    if any(not isinstance(view, dict) for view in account_views.values()):
        raise BaselineError("dedicated test wallet is not funded in the finalized state on all five")
    nonces = {v.get("nonce") for v in account_views.values()}
    balances = {int(v.get("balance_nwei", "0")) for v in account_views.values()}
    if len(nonces) != 1 or None in nonces or len(balances) != 1:
        raise BaselineError("wallet nonce/balance differ across the five finalized views")
    nonce = next(iter(nonces))
    max_cost = args.max_tx * (args.amount_nwei + args.gas_limit * args.max_fee_per_gas_nwei)
    if next(iter(balances)) < max_cost:
        raise BaselineError("dedicated test wallet balance is below the configured maximum spend bound")

    # Refresh immediately before timing begins so setup and account-view calls
    # are excluded from measured admission-counter deltas.
    load_start_states = sample_fleet(endpoints, args.network_id, args.submit_validator, expected_chain_id=chain_id)
    start = tip_record(load_start_states)
    counters_start = {n: s["stats"] for n, s in load_start_states.items()}
    resource_start = sample_resource()
    started_mono = time.monotonic()
    started_utc = utc_now()
    partial.update({"start_utc": started_utc, "start_tip": start,
                    "start_counters": counters_start,
                    "resource_start": resource_start})
    next_submit = started_mono
    pending: dict[str, dict[str, Any]] = {}
    finalized_latencies: list[float] = []
    submissions: list[dict[str, Any]] = []
    last_progress = started_mono
    previous_height = load_start_states["val2"]["common_height"]
    observed_block_times: list[float] = []
    failure: str | None = None
    counters_end: dict[str, Any] | None = None
    end: dict[str, Any] | None = None
    load_end_mono = started_mono
    with tempfile.TemporaryDirectory(prefix="posy-tps-", dir=args.temp_dir) as temp_name:
        temp_path = Path(temp_name)
        os.chmod(temp_path, 0o700)
        deadline = started_mono + args.duration_seconds
        while time.monotonic() < deadline and len(submissions) < args.max_tx:
            states = sample_fleet(endpoints, args.network_id, args.submit_validator, expected_chain_id=chain_id)
            height = states["val2"]["common_height"]
            if height > previous_height:
                previous_height = height
                last_progress = time.monotonic()
            elif time.monotonic() - last_progress > args.maximum_gap_seconds:
                failure = "finalized tip stalled during the load window"
                break
            if len(pending) < MAX_IN_FLIGHT and time.monotonic() >= next_submit:
                # Keep the context and finalized-height sample from one fleet view.
                # Admission still enforces the live cutoff when this is submitted.
                ctx = fresh_admission_context(submit_url)
                ci = ctx.get("context", {})
                validate_context_target(ctx)
                validate_chain_id(ci.get("chain_id"), chain_id)
                if ci.get("network_id") != args.network_id:
                    failure = "submit endpoint admission context is on the wrong network"
                    break
                source = rpc(submit_url, "synergy_getBlock", {"height":ci["source_finalized_height"],"hash":None})
                if not isinstance(source,dict) or source.get("height") != ci["source_finalized_height"] or not all(source.get(k) for k in ["block_hash","state_root","finality_certificate_id"]):
                    raise BaselineError("submit context lacks canonical source finality")
                timestamp = int(time.time())
                admission, txid = make_admission(keytool, public_path, secret_path,
                    ctx, temp_path, sender, receiver, args.amount_nwei, nonce,
                    args.gas_limit, args.max_fee_per_gas_nwei, args.gas_class_units,
                    args.fee_class, timestamp, remote=getattr(args, "remote_signer", False))
                before = time.monotonic()
                queued = rpc(submit_url, "synergy_submitProtectedTransaction", admission)
                receipt_id = queued.get("receipt_id") if isinstance(queued, dict) else None
                if queued.get("status") != "queued" or not isinstance(receipt_id, str):
                    failure = "protected admission was not queued; stopping without retry"
                    break
                transaction_record = {"transaction_id": txid, "nonce": nonce,
                                      "receipt_id": receipt_id, "target_height":ci["target_height"],
                                      "submitted_at": utc_now(), "submitted_mono": before}
                pending[txid] = {"nonce": nonce, "receipt_id": receipt_id,
                                 "target_height": ci["target_height"],
                                 "context": ctx,
                                 "submitted_mono": before, "submitted_utc": utc_now(),
                                 "accepted": False, "transaction_record": transaction_record}
                submissions.append(transaction_record)
                partial["transactions"] = submissions
                nonce += 1
                next_submit = before + 1.0 / args.rate_tps

            for txid, record in list(pending.items()):
                receipt = rpc(submit_url, "synergy_getProtectedAdmissionReceipt",
                              {"receipt_id": record["receipt_id"]})
                if receipt.get("status") == "rejected":
                    record["transaction_record"]["admission_rejection"] = receipt.get("reason")
                    failure = "protected admission was rejected; stopping load: " + str(receipt.get("reason"))
                    break
                if receipt.get("status") == "accepted" and not record["accepted"]:
                    record["accepted"] = True
                    record["accepted_utc"] = utc_now()
                    record["transaction_record"]["accepted_at"] = record["accepted_utc"]
                if record["accepted"] and height >= record["target_height"]:
                    final = all_finalized(endpoints, txid, record["target_height"])
                    if final:
                        verify_context_source_block(record["context"], states, endpoints, submit_name)
                        record["finalized"] = final
                        record["finalized_mono"] = time.monotonic()
                        record["transaction_record"]["finalized_mono"] = record["finalized_mono"]
                        record["transaction_record"]["finalized_at"] = utc_now()
                        finalized_latencies.append(record["finalized_mono"] - record["submitted_mono"])
                        del pending[txid]
                        continue
            if failure:
                break
            time.sleep(max(0.05, min(POLL_SECONDS, next_submit - time.monotonic()))
                       if len(pending) < MAX_IN_FLIGHT else POLL_SECONDS)
        load_end_mono = time.monotonic()
        try:
            load_end_states = sample_fleet(endpoints, args.network_id, args.submit_validator, expected_chain_id=chain_id)
            end = tip_record(load_end_states)
            counters_end = {n: s["stats"] for n, s in load_end_states.items()}
            advanced_blocks = end["common_finalized_height"] - start["common_finalized_height"]
            if advanced_blocks > 0:
                average_block_time = (load_end_mono - started_mono) / advanced_blocks
                observed_block_times.append(average_block_time)
                if not 0.5 <= average_block_time <= 1.5 and not getattr(args, "measure_outside_cadence_target", False):
                    failure = failure or "average finalized block cadence over the full load window left the required 0.5–1.5 second range"
            partial.update({"load_end_tip": end, "load_end_counters": counters_end,
                            "load_window_seconds": load_end_mono - started_mono})
        except (BaselineError, OSError, KeyError, ValueError) as error:
            failure = failure or f"load-end snapshot failed: {type(error).__name__}"
        # Continue block safety checks independently while original requests drain.
        # Only an explicit operator deadline bounds healthy pending transactions.
        drain_deadline = operational_drain_deadline(args, deadline)
        while pending and failure is None:
            if drain_deadline is not None and time.monotonic() >= drain_deadline:
                failure = "explicit operational drain deadline reached; reconcile original requests before any further authoring"
                break
            drain_states = sample_fleet(endpoints, args.network_id, args.submit_validator, expected_chain_id=chain_id)
            height = drain_states["val2"]["common_height"]
            if height < previous_height:
                raise BaselineError("finalized height regressed while draining")
            if height > previous_height:
                previous_height = height
                last_progress = time.monotonic()
            elif time.monotonic() - last_progress > args.maximum_gap_seconds:
                raise BaselineError("finalized tip stalled while original transactions drain")
            for txid, record in list(pending.items()):
                receipt = rpc(submit_url, "synergy_getProtectedAdmissionReceipt",
                              {"receipt_id": record["receipt_id"]})
                if receipt.get("status") == "rejected":
                    failure = "protected admission was rejected while draining"
                    break
                if receipt.get("status") == "accepted":
                    record["accepted"] = True
                    record["transaction_record"]["accepted_at"] = record.get("accepted_utc", utc_now())
                    if drain_states["val2"]["common_height"] < record["target_height"]:
                        continue
                    final = all_finalized(endpoints, txid, record["target_height"])
                    if final:
                        verify_context_source_block(record["context"], drain_states, endpoints, submit_name)
                        record["finalized"] = final
                        record["finalized_mono"] = time.monotonic()
                        record["transaction_record"]["finalized_mono"] = record["finalized_mono"]
                        record["transaction_record"]["finalized_at"] = utc_now()
                        finalized_latencies.append(record["finalized_mono"] - record["submitted_mono"])
                        del pending[txid]
            if pending and failure is None:
                time.sleep(POLL_SECONDS)
        if pending and failure is None:
            failure = "one or more accepted transactions did not reach matching five-validator finality"
        final_states = sample_fleet(endpoints, args.network_id, args.submit_validator, expected_chain_id=chain_id)
    elapsed = time.monotonic() - started_mono
    load_window = max(0.0, load_end_mono - started_mono)
    ended_utc = utc_now()
    end = tip_record(final_states)
    if counters_end is None:
        counters_end = {n: s["stats"] for n, s in final_states.items()}
    accepted_tps = counter_rates(counters_start, counters_end, "accepted_total", load_window)
    ordered_tps = counter_rates(counters_start, counters_end, "etdag_ordered_total", load_window)
    if any(value is None for value in accepted_tps.values()) or any(
            value is None for value in ordered_tps.values()):
        failure = failure or "validator admission counters reset or became unavailable during the run"
    finalized_in_load = sum(1 for record in submissions
                            if record.get("finalized_mono", float("inf")) <= load_end_mono)
    finalized_count = sum(1 for record in submissions if record.get("finalized_mono") is not None)
    finalized_tps = finalized_in_load / load_window if load_window > 0 else 0.0
    result = {"status": "failed" if failure else "completed", "failure": failure,
            "network_id": args.network_id, "submit_validator": submit_name,
            "start_utc": started_utc, "end_utc": ended_utc,
            "load_window_seconds": load_window, "verification_seconds_including_drain": elapsed,
            "start_tip": start, "end_tip": end,
            "offered_rate_tps": args.rate_tps, "submitted_transactions": len(submissions),
            "observed_block_time_seconds": observed_block_times,
            "cadence_target_met": bool(observed_block_times) and all(0.5 <= v <= 1.5 for v in observed_block_times) and 0.5 <= stable_tip["val2"]["preflight_average_block_time_seconds"] <= 1.5,
            "measured_outside_cadence_target": getattr(args, "measure_outside_cadence_target", False),
            "accepted_tps_by_validator": accepted_tps,
            "etdag_ordered_tps_by_validator": ordered_tps,
            "finalized_tps": finalized_tps,
            "finalized_tps_cohort": "transactions finalized before load window ended",
            "end_to_end_finalized_tps": finalized_count / elapsed if elapsed > 0 else 0.0,
            "finalized_transactions": finalized_count,
            "p95_finality_latency_seconds": percentile95(finalized_latencies),
            "backlog": {"remaining_in_flight": len(pending),
                        "queued_requests_by_validator": {n: s["stats"].get("queued_requests") for n, s in final_states.items()},
                        "queued_bytes_by_validator": {n: s["stats"].get("queued_bytes") for n, s in final_states.items()}},
            "resource_start": resource_start, "resource_end": sample_resource(),
            "validator_os_resources": "unavailable: current PoSy JSON-RPC has no host CPU/memory/disk/network metric",
            "transactions": submissions}
    partial.update(result)
    return result


def tip_record(states: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"common_finalized_height": states["val2"]["common_height"],
            "block_hash": states["val2"]["block_hash"],
            "state_root": states["val2"]["state_root"],
            "finality_certificate_id": states["val2"]["finality_certificate_id"],
            "validators": {name: {"live_finalized_height": state["height"],
                                   "lag_blocks": state["lag_blocks"],
                                   "distance_above_common": state["distance_above_common"],
                                   "target_height": state["target_height"], "admission_ready": state["status"].get("ready"),
                                   "common_height":state["common_height"],"block_hash":state["block_hash"],
                                   "state_root":state["state_root"],"finality_certificate_id":state["finality_certificate_id"]}
                           for name, state in states.items()}}


def counter_rates(start: dict[str, Any], end: dict[str, Any], key: str,
                  elapsed: float) -> dict[str, float | None]:
    rates: dict[str, float | None] = {}
    for name in VALIDATORS:
        before = start[name].get(key)
        after = end[name].get(key)
        if type(before) is not int or type(after) is not int or after < before:
            rates[name] = None
        else:
            rates[name] = (after - before) / elapsed if elapsed > 0 else None
    return rates


def self_test() -> None:
    # Mock only the owner transport: remote metadata/admission contracts and
    # canonical transaction identity remain exercised without host access.
    from unittest.mock import patch
    good_context = {"parameters":{"profile_id":"POSY-ETDAG-v3.0","target_height_offset":5},"context": {"chain_id":1266,"source_finalized_height": 10, "target_height": 15, "network_id": "test"}}
    for transient in ["ready", "context"]:
        seen = [0]
        def mock_rpc(url, method, params, *, timeout):
            assert 0 < timeout <= RPC_TIMEOUT
            if method == "synergy_nodeStatus":
                seen[0] += 1
                return {"chain_id":1266,"ready": not (transient == "ready" and seen[0] == 1)}
            if method == "synergy_getProtectedAdmissionContext":
                if transient == "context" and seen[0] == 1:raise TransientSampleError("protected admission context unavailable")
                return good_context
            return {}
        with patch(__name__ + ".rpc", side_effect=mock_rpc):
            assert endpoint_state("val2", "unused")["target_height"] == 15 and seen[0] == 2
    for status, expected_calls in [({"chain_id":999,"ready":False},1), ({"chain_id":1266,"ready":False},2)]:
        ticks = iter([0.0,0.5,5.0])
        with patch(__name__ + ".rpc", return_value=status) as mocked, patch(__name__ + ".time.monotonic", side_effect=lambda:next(ticks)), patch(__name__ + ".time.sleep"):
            try:endpoint_state("val2","unused", expected_chain_id=1266)
            except BaselineError:pass
            else:raise AssertionError("persistent unavailable/wrong-chain accepted")
            assert mocked.call_count == expected_calls
    sampled_context = {"parameters":{"profile_id":"POSY-ETDAG-v3.0","target_height_offset":5},"context": {"source_finalized_height":10,"target_height":15,"network_id":"test","source_finality_context_root":"source"}}
    sampled = {name:{"height":10,"network_id":"test","context":sampled_context} for name in VALIDATORS}
    block = {"height":10,"block_hash":"block","state_root":"state","finality_certificate_id":"qc"}
    with patch(__name__ + ".rpc", return_value=block) as mocked:
        verify_context_source_block(sampled["val2"]["context"],sampled,{name:"unused" for name in VALIDATORS},"val2")
        assert mocked.call_count == 5
        assert all(call.args[1] == "synergy_getBlock" and call.args[2]["height"] == 10 for call in mocked.call_args_list)
    for field,value in [("source_finalized_height",11),("target_height",16)]:
        newer = {"parameters":sampled_context["parameters"],"context":dict(sampled_context["context"])}
        newer["context"][field] = value
        if field == "source_finalized_height":newer["context"]["target_height"] = 16
        with patch(__name__ + ".rpc") as mocked:
            try:verify_context_source_block(newer,sampled,{name:"unused" for name in VALIDATORS},"val2")
            except BaselineError:pass
            else:raise AssertionError("ahead source or invalid F+5 accepted")
            assert not mocked.called
    calls = []
    class MockOwner:
        def configured_master_socket(self, host):
            assert host == "synergy-val2"
            return "/tmp/existing-master"
        def remote(self, host, socket, argv, data=None):
            assert host == "synergy-val2" and socket == "/tmp/existing-master"
            calls.append((argv, data))
            value = ({"sender": "wallet", "identity_authorization": {"binding": {"identity_address": "wallet"}}}
                     if argv[-1] == "public" else {"ciphertext": "opaque"})
            return json.dumps(value).encode()
    original_owner = globals()["remote_owner"]
    try:
        globals()["remote_owner"] = lambda: MockOwner()
        custody = Path("/var/lib/synergy/test-wallet")
        assert read_remote_wallet(custody)[0] == "wallet"
        context = {"context": {"network_id": "test", "chain_id":1266}}
        admission, txid = make_admission(Path(REMOTE_KEYTOOL), custody / "wallet.public.json",
            custody / "transaction.secret.key", context, Path("/tmp"),
            "wallet", "receiver", 1, 2, 3, 4, 5, 1, 123, remote=True)
        assert admission == {"ciphertext": "opaque"}
        assert txid == transaction_id("test", "wallet", "receiver", 1, 2, 3, 4, 123, chain_id=1266)
        assert "transaction_secret_path" not in json.loads(calls[-1][1])
        try:
            remote_signer_call(Path("/var/../secret"), "public")
        except BaselineError:
            pass
        else:
            raise AssertionError("remote custody traversal accepted")
        compile(REMOTE_SIGNER, "remote-signer", "exec")
    finally:
        globals()["remote_owner"] = original_owner
    assert parse_validator_rpc("val2=https://127.0.0.1:8545")[0] == "val2"
    try:
        validate_rpc_url("http://192.0.2.1:8545")
    except BaselineError:
        pass
    else:
        raise AssertionError("remote plaintext RPC must be rejected")
    assert transaction_id("net", "s", "r", 1, 2, 3, 4, 5, chain_id=1266) == transaction_id("net", "s", "r", 1, 2, 3, 4, 5, chain_id=1266)
    assert transaction_id("net", "s", "r", 1, 2, 3, 4, 5, chain_id=1266) != transaction_id("net", "s", "r", 1, 2, 3, 4, 6, chain_id=1266)
    assert percentile95([1.0, 2.0, 3.0, 4.0]) == 4.0



class RawProofStream:
    """One create-new canonical public evidence stream, bounded frames and disk budget."""
    def __init__(self, path: Path, budget: int = 16 * 1024**3):
        self.path=Path(path)
        if not self.path.is_absolute() or ".." in self.path.parts or not self.path.parent.is_dir():
            raise BaselineError("raw proof stream requires absolute new path in existing directory")
        for ancestor in [self.path,*self.path.parents]:
            if ancestor.is_symlink(): raise BaselineError("symlink raw proof stream rejected")
        if type(budget) is not int or not 4*1024*1024<=budget<=64*1024**3:
            raise BaselineError("raw proof budget must be 4 MiB..64 GiB")
        self.reserve=1024**3
        volume=os.statvfs(self.path.parent)
        available=volume.f_bavail*volume.f_frsize
        if available<self.reserve+4*1024*1024:
            raise BaselineError("raw proof filesystem lacks free space above the 1 GiB reserve")
        self.requested_budget=budget
        self.budget=min(budget,available-self.reserve)
        self.file=os.fdopen(os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),"wb")
        self.digest=hashlib.sha3_256();self.length=0;self.records=0;self.closed=False;self.generation=0
    def append(self, value: dict) -> dict:
        encoded=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
        volume=os.statvfs(self.path.parent)
        if (len(encoded)>4*1024*1024 or self.length+len(encoded)>self.budget
                or len(encoded)>volume.f_bavail*volume.f_frsize-self.reserve):
            raise BaselineError("generator raw evidence budget or filesystem reserve reached; chain capacity unknown")
        offset=self.length
        self.file.write(encoded)
        self.digest.update(encoded);self.length+=len(encoded);self.records+=1
        return {"offset":offset,"length":len(encoded),"generation":self.generation,"sha3_256":hashlib.sha3_256(encoded).hexdigest()}
    def compact(self, value: dict) -> dict:
        """Atomically replace consumed observations with the active intent ledger.

        Caller owns its publication/proof locks. Never truncate the old ledger
        before the replacement is durable and ready to become the same path.
        """
        if self.closed:
            raise BaselineError("cannot compact closed proof stream")
        encoded=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
        volume=os.statvfs(self.path.parent)
        if (len(encoded)>4*1024*1024 or len(encoded)>self.budget
                or len(encoded)>volume.f_bavail*volume.f_frsize-self.reserve):
            raise BaselineError("active intent ledger exceeds bounded proof budget; original retained")
        self.file.flush();os.fsync(self.file.fileno())
        fd, name=tempfile.mkstemp(prefix="."+self.path.name+"-",dir=self.path.parent)
        temporary=Path(name);replacement=None
        try:
            replacement=os.fdopen(fd,"wb")
            replacement.write(encoded);replacement.flush();os.fsync(replacement.fileno())
            os.replace(temporary,self.path)
            old=self.file;self.file=replacement;replacement=None
            self.digest=hashlib.sha3_256(encoded);self.length=len(encoded);self.records=1
            self.generation+=1
            old.close()
            directory=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(directory)
            finally:os.close(directory)
            return {"offset":0,"length":len(encoded),"generation":self.generation,
                    "sha3_256":self.digest.hexdigest()}
        finally:
            if replacement is not None:replacement.close()
            temporary.unlink(missing_ok=True)

    def metadata(self) -> dict:
        return {"schema_version":1,"path":str(self.path),"length":self.length,"records":self.records,"generation":self.generation,
                "sha3_256":self.digest.hexdigest(),"budget_bytes":self.budget,
                "requested_budget_bytes":self.requested_budget,"filesystem_reserve_bytes":self.reserve,
                "complete":self.closed,"encoding":"canonical JSONL; per-line SHA3 includes trailing newline"}
    def close(self):
        if not self.closed:
            self.file.flush();os.fsync(self.file.fileno());self.file.close();self.closed=True


class PersistentNativeSigner:
    """One serial custody process, bounded frames; never reads private bytes in Python."""
    def __init__(self, keytool: Path, registry: Path, operator: bool = False, cancellation=None):
        self.lock = threading.Lock()
        self.request_id = 0
        self.failure = False
        self.buffer = bytearray()
        self.cancellation = cancellation or threading.Event()
        command = "prepare-wallet-admission-session-operator" if operator else "prepare-wallet-admission-session"
        self.process = subprocess.Popen([str(keytool), command, str(registry)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        os.set_blocking(self.process.stdin.fileno(),False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)

    def _write_frame(self, frame: bytes, deadline: float):
        written=0
        fd=self.process.stdin.fileno()
        while written<len(frame):
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([], [fd], [], remaining)[1]:
                raise BaselineError("native signer input deadline exceeded")
            try:written+=os.write(fd,frame[written:written+65536])
            except BlockingIOError:continue

    def sign(self, wallet_id: str, context_response: dict, transfer: dict, *,
             operation_deadline: float | None = None) -> dict:
        with self.lock:
            if operation_deadline is not None:
                guard_pool_workload(self.cancellation, operation_deadline, "native signing after session lock")
            if self.cancellation.is_set(): raise BaselineError("native signing cancelled; no subsequent authoring")
            if self.failure:raise BaselineError("native signer failure latched; no subsequent signing")
            try:
                if operation_deadline is None:
                    return self._sign_locked(wallet_id,context_response,transfer)
                return self._sign_locked(wallet_id,context_response,transfer,operation_deadline=operation_deadline)
            except Exception:
                self.failure=True
                self.cancellation.set()
                self.process.terminate()
                raise

    def _sign_locked(self, wallet_id: str, context_response: dict, transfer: dict, *,
                     operation_deadline: float | None = None) -> dict:
        self.request_id += 1
        frame = json.dumps({"session_version":1,"request_id":self.request_id,
            "wallet_id":wallet_id,"context_response":context_response,"transfer":transfer},
            separators=(",",":")).encode()+b"\n"
        if len(frame)>1024*1024:
            raise BaselineError("native signer input frame exceeds 1 MiB")
        deadline=time.monotonic()+30
        if operation_deadline is not None:
            guard_pool_workload(self.cancellation,operation_deadline,"native signer request write")
            deadline=min(deadline,operation_deadline)
        self._write_frame(frame,deadline)
        while b"\n" not in self.buffer:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not self.selector.select(remaining):
                raise BaselineError("native signer deadline exceeded; no submission")
            chunk=os.read(self.process.stdout.fileno(), min(65536,1024*1024+1-len(self.buffer)))
            if not chunk:
                raise BaselineError("native signer closed; no submission")
            self.buffer.extend(chunk)
            if len(self.buffer)>1024*1024:
                raise BaselineError("native signer output frame exceeds 1 MiB")
        line, _, tail=self.buffer.partition(b"\n")
        self.buffer=bytearray(tail)
        result=json.loads(line)
        if result.get("request_id")!=self.request_id or result.get("session_version")!=1 or result.get("status")!="signed":
            raise BaselineError("native signer rejected verified source/context authoring")
        rid=result.get("receipt_id")
        if not isinstance(rid,str) or len(rid)!=128 or any(c not in "0123456789abcdef" for c in rid):
            raise BaselineError("native signer lacks deterministic receipt identity")
        return result

    def close(self):
        if self.process.stdin:
            try:self.process.stdin.close()
            except OSError:pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill();self.process.wait(timeout=5)
        self.selector.close()
        if self.process.stdout:self.process.stdout.close()


def wallet_pool_public(registry_path: Path, network: str, operator: bool = False) -> list[dict]:
    if not registry_path.is_absolute() or ".." in registry_path.parts:
        raise BaselineError("absolute isolated wallet registry required")
    for ancestor in [registry_path,*registry_path.parents]:
        if ancestor.is_symlink():raise BaselineError("symlink wallet registry rejected")
    if not registry_path.is_file() or registry_path.stat().st_size>1024*1024:
        raise BaselineError("wallet registry exceeds input bound")
    registry=json.loads(registry_path.read_text())
    selected = (registry.get("synthetic") is False and not network.startswith("posy-isolated-")
                and registry.get("custody_kind")=="operator-wallet-allowlist-v1"
                and isinstance(registry.get("genesis_path"),str)) if operator else (
                registry.get("synthetic") is True and network.startswith("posy-isolated-"))
    if registry.get("session_version")!=1 or registry.get("network_id")!=network or not selected:
        raise BaselineError("registry does not match explicit native custody mode")
    entries=registry.get("wallets")
    if not isinstance(entries,list) or not 1<=len(entries)<=64:
        raise BaselineError("wallet pool must contain 1..64 independent funded wallets")
    wallets=[]; ids=set();senders=set()
    root=Path(registry["fixture_root"])
    if operator and (stat.S_IMODE(root.stat().st_mode)!=0o700
                     or stat.S_IMODE(registry_path.stat().st_mode)!=0o600):
        raise BaselineError("operator custody registry requires a private dedicated wallet allowlist root")
    if root not in registry_path.parents:raise BaselineError("registry outside its isolated fixture")
    for entry in entries:
        wallet_id=entry.get("wallet_id")
        public=Path(entry["wallet_public_path"])
        if not isinstance(wallet_id,str) or wallet_id in ids or root not in public.parents:
            raise BaselineError("invalid wallet registry entry")
        for ancestor in [public,*public.parents]:
            if ancestor.is_symlink():raise BaselineError("symlink public wallet rejected")
        if not public.is_file() or not 0<public.stat().st_size<=1024*1024:
            raise BaselineError("public wallet exceeds bound")
        data=json.loads(public.read_text());sender=data.get("sender")
        if not isinstance(sender,str) or sender in senders or sender!=data.get("identity_authorization",{}).get("binding",{}).get("identity_address"):
            raise BaselineError("independent wallet identity binding invalid")
        ids.add(wallet_id);senders.add(sender)
        wallets.append({"wallet_id":wallet_id,"sender":sender})
    return wallets


def pool_account(endpoints: dict, address: str, height: int, *, include_views: bool = False) -> dict:
    # Independent reads of the same finalized state need no serial dependency.
    # Keep all-five comparison and proof completion inside the timing budget.
    def read(item):
        name,url=item
        return name,rpc(url,"synergy_getAccount",{"address":address,"at_height":height})
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(endpoints)) as readers:
        views=dict(readers.map(read,endpoints.items()))
    values=list(views.values())
    fingerprints={json.dumps(v,sort_keys=True,separators=(",",":")) for v in values}
    if len(fingerprints)!=1:raise BaselineError("wallet state disagreement at common finalized height")
    value=values[0]
    if value is None:return {"balance_nwei":0,"nonce":0,**({"validator_views":views} if include_views else {})}
    if not isinstance(value,dict) or type(value.get("nonce")) is not int:
        raise BaselineError("invalid wallet state")
    return {"balance_nwei":int(value["balance_nwei"]),"nonce":value["nonce"],**({"validator_views":views} if include_views else {})}


def cancellation_guard(cancellation, callback, *args):
    """Latch a worker failure before another queued authoring job can proceed."""
    if cancellation.is_set():
        raise BaselineError("load cancelled before worker start")
    try:
        return callback(*args)
    except Exception:
        cancellation.set()
        raise


def validate_pool_workload(args: argparse.Namespace, wallet_count: int) -> bool:
    """An explicit resource qualification profile, never an offered-rate claim."""
    mode = getattr(args, "workload_mode", "offered-rate")
    if mode not in {"offered-rate", "closed-loop-memory"}:
        raise BaselineError("unknown wallet-pool workload mode")
    closed = mode == "closed-loop-memory"
    if closed and (args.max_tx != 30 or args.duration_seconds != 300
                   or not 1 <= wallet_count <= 4 or not 1 <= args.max_in_flight <= 4):
        raise BaselineError("closed-loop-memory requires exactly 30 transactions, a 300-second count deadline, and at most four wallets/in-flight jobs")
    return closed


def guard_pool_workload(cancellation: threading.Event, deadline: float | None, phase: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        cancellation.set()
        raise BaselineError("closed-loop memory count deadline exceeded before " + phase)
    if cancellation.is_set():
        raise BaselineError("load cancelled before " + phase)


def pool_offer_slot(closed: bool, now: float, next_slot: float | None,
                    rate_tps: float) -> tuple[float, float | None, int]:
    if closed:
        return now, None, 0
    due = int((now - next_slot) * rate_tps) + 1
    return next_slot + (due - 1) / rate_tps, next_slot + due / rate_tps, max(0, due - 1)


def closed_loop_deadline_met(attempted: int, transactions: list[dict], remaining: int,
                             deadline: float, effects_verified_at: float) -> bool:
    return (attempted == 30 and len(transactions) == 30 and remaining == 0
            and effects_verified_at < deadline
            and all(type(record.get("finalized_mono")) in (int, float)
                    and math.isfinite(record["finalized_mono"])
                    and record["finalized_mono"] < deadline
                    and record.get("submission_started",True)
                    and bool(record.get("raw_proof_ref")) for record in transactions))


def run_wallet_pool(args: argparse.Namespace) -> dict:
    """Explicitly authorized native load source; generator caps are never chain capacity."""
    endpoints=dict(args.validator_rpc)
    report={"status":"running","execute":bool(args.execute),"network_id":args.network_id,"transactions":[],
            "workload_mode":getattr(args,"workload_mode","offered-rate"),"capacity_result":False,"TPS_qualified":False}
    args._partial_report=report
    if set(endpoints)!=set(VALIDATORS) or len(args.validator_rpc)!=5:
        raise BaselineError("exactly five distinct validator endpoints required")
    if getattr(args,"remote_signer",False) or args.signer_dir:
        raise BaselineError("pool mode runs on the authorized isolated custody host; no legacy signer flags")
    if not 1<=args.duration_seconds<=86400 or not 1<=args.max_tx<=100000:
        raise BaselineError("pool generator duration 1..86400s and transaction cap 1..100000 required")
    if getattr(args,"workload_mode","offered-rate")=="offered-rate" and (not math.isfinite(args.rate_tps) or not 0<args.rate_tps<=4096):
        raise BaselineError("pool generator offered-rate bound is 4096 TPS; this is not network capacity")
    if not 10<=args.stability_seconds<=120:
        raise BaselineError("preflight duration must be 10..120 seconds")
    if not 1<=args.max_in_flight<=64 or not math.isfinite(args.maximum_gap_seconds) or not 0<args.maximum_gap_seconds<=600:
        raise BaselineError("bounded in-flight and declared block stall budget required")
    operational_drain_deadline(args, 0)
    wallets=wallet_pool_public(args.wallet_registry,args.network_id,getattr(args,"operator_wallet_registry",False))
    closed_loop=validate_pool_workload(args,len(wallets))
    if closed_loop:
        report.update(requested_transactions=30,workload_deadline_seconds=300,workload_deadline_met=False,
                      peak_in_flight=0,offered_rate_tps=None,generator_missed_offered_slots=None,
                      generator_limited=None,measured_submitted_tps=None,finalized_tps=None)
    if args.max_in_flight>len(wallets):raise BaselineError("in-flight cap exceeds independent funded wallet count")
    if args.receiver in {w["sender"] for w in wallets}:raise BaselineError("receiver must be independent of generator senders")
    if args.execute and (not args.receiver or any(type(v) is not int or v<=0 for v in [args.amount_nwei,args.gas_limit,args.max_fee_per_gas_nwei,args.gas_class_units])):
        raise BaselineError("funded receiver and explicit positive governed transfer gas/fee values required")
    # The reviewed profile supplies a gap budget; no historical hardcoded 0.5..1.5s gate.
    first=sample_fleet(endpoints,args.network_id,native_tips=True)
    chain_id=first["val2"]["status"]["chain_id"]
    report["chain_id"]=chain_id
    preflight_start=time.monotonic(); last_height=first["val2"]["common_height"]; last_advance=preflight_start
    while time.monotonic()-preflight_start<args.stability_seconds:
        time.sleep(POLL_SECONDS)
        state=sample_fleet(endpoints,args.network_id,native_tips=True, expected_chain_id=chain_id);height=state["val2"]["common_height"]
        if height>last_height:last_height=height;last_advance=time.monotonic()
        elif time.monotonic()-last_advance>args.maximum_gap_seconds:raise BaselineError("preflight finality stalled")
    if last_height<=first["val2"]["common_height"]:raise BaselineError("no preflight finalized progression")
    report.update(preflight_complete=True,preflight_end_tip=tip_record(state),generator_limits={"offered_rate_cap_tps":None if closed_loop else 4096,"wallet_count":len(wallets),"in_flight_cap":args.max_in_flight,"native_signer":"one persistent serial custody process"},capacity_result=False)
    if not args.execute:
        report.update(status="dry_run_ready",note="No signer process started and no transaction submitted.")
        return report
    keytool=args.keytool.resolve(strict=True)
    if not keytool.is_file() or not os.access(keytool,os.X_OK):raise BaselineError("canonical native signer executable required")
    common=state["val2"]["common_height"]
    for wallet in wallets:
        initial_account=pool_account(endpoints,wallet["sender"],common,include_views=True)
        wallet["initial_views"]=initial_account.pop("validator_views")
        wallet.update(initial_account)
        wallet["initial_nonce"]=wallet["nonce"];wallet["initial_balance"]=wallet["balance_nwei"];wallet["spent"]=0
        # One transaction worst-case reserve; each subsequent transfer is checked again.
        if wallet["balance_nwei"]<args.amount_nwei+args.gas_limit*args.max_fee_per_gas_nwei:
            raise BaselineError("pool wallet is not independently funded on all five")
    receiver_initial=pool_account(endpoints,args.receiver,common,include_views=True)
    effects_before_height=common
    state_at_load_start=sample_fleet(endpoints,args.network_id,native_tips=True, expected_chain_id=chain_id)
    cancellation=threading.Event()
    signer=PersistentNativeSigner(keytool,args.wallet_registry,getattr(args,"operator_wallet_registry",False),cancellation)
    proof_path=getattr(args,"raw_proof_stream",None)
    if proof_path is None and getattr(args,"output",None):
        proof_path=args.output.with_suffix(".proof.jsonl")
    if proof_path is not None and getattr(args,"output",None) and proof_path.absolute()==args.output.absolute():
        signer.close()
        raise BaselineError("raw evidence stream and summary must have distinct canonical paths")
    if proof_path is None:
        signer.close()
        raise BaselineError("pool execution requires --raw-proof-stream or --output for canonical raw evidence")
    try:
        proof=RawProofStream(proof_path,getattr(args,"raw_proof_budget_bytes",16*1024**3))
    except Exception:
        cancellation.set();signer.close();raise
    report["raw_proof_stream"]=proof.metadata()
    start=time.monotonic();deadline=start+args.duration_seconds;next_slot=None if closed_loop else start
    workload_deadline=deadline if closed_loop else None
    readonly_drain_deadline=deadline+30.0
    drain_deadline=operational_drain_deadline(args,deadline)
    peak_inflight=0
    available=list(wallets); pending={}; jobs={};transactions=report["transactions"]
    submitted_records={}; submitted_lock=threading.Lock()
    skipped=0;attempted=0; finalities=[]; stop_reason=None; highest=common;last_progress=start
    last_snapshot=start;load_end=deadline;raw_proof_bytes=0
    report.update(start_utc=utc_now(),start_tip=tip_record(state_at_load_start),transaction_latency_limit_seconds=None,drain_timeout_seconds=getattr(args,"drain_timeout_seconds",None),maximum_gap_seconds=args.maximum_gap_seconds)
    if closed_loop:
        report.update(workload_start_mono=start,workload_deadline_mono=deadline)

    def offer(wallet, scheduled):
        guard_pool_workload(cancellation,workload_deadline,"context retrieval")
        context_start=time.monotonic()
        envelope, context_observations = pool_admission_context(
            endpoints[args.submit_validator], args.network_id,
            state_at_load_start[args.submit_validator]["native_epoch"], cancellation,
            operation_deadline=workload_deadline, expected_chain_id=chain_id)
        context=envelope.get("signing_context",{});validate_context_target(context)
        if context.get("context",{}).get("network_id")!=args.network_id:raise BaselineError("wrong signing network")
        context_received=time.monotonic()
        timestamp=int(time.time())
        transfer={"sender":wallet["sender"],"receiver":args.receiver,"amount_nwei":args.amount_nwei,
            "nonce":wallet["nonce"],"timestamp_unix":timestamp,"gas_limit":args.gas_limit,
            "max_fee_per_gas_nwei":args.max_fee_per_gas_nwei,"gas_class_units":args.gas_class_units,
            "fee_class":args.fee_class,"content_blind_order_key":order_key()}
        guard_pool_workload(cancellation,workload_deadline,"native signing")
        signed=(signer.sign(wallet["wallet_id"],envelope,transfer,operation_deadline=workload_deadline)
                if closed_loop else signer.sign(wallet["wallet_id"],envelope,transfer))
        signed_at=time.monotonic()
        txid=transaction_id(args.network_id,wallet["sender"],args.receiver,args.amount_nwei,wallet["nonce"],args.gas_limit,args.max_fee_per_gas_nwei,timestamp, chain_id=chain_id)
        before=time.monotonic(); ambiguous=False
        guard_pool_workload(cancellation,workload_deadline,"submission")
        record={"transaction_id":txid,"receipt_id":signed["receipt_id"],"sender":wallet["sender"],
            "nonce":wallet["nonce"],"target_height":context["context"]["target_height"],
            "submitted_mono":before,"submitted_at":utc_now(),"context_started_mono":context_start,
            "scheduled_mono":scheduled,"ambiguous_response":ambiguous,"accepted":False,"wallet":wallet,
            "context_retrieval_seconds":context_received-context_start,
            "context_observations":context_observations,
            "native_signing_and_session_queue_seconds":signed_at-context_received,
            "submission_transport_seconds":0.0,"submission_started":False}
        # Publish immutable reconciliation identity before initiating transport.
        # Even a mismatched/ambiguous response cannot lose a submitted nonce.
        with submitted_lock: submitted_records[txid]=record
        try:
            guard_pool_workload(cancellation,workload_deadline,"submission transport")
            record["submission_started"]=True
            submit_pool_admission(endpoints[args.submit_validator], signed["admission"], record)
        finally:
            record["submission_transport_seconds"]=time.monotonic()-before
        return record

    def reconcile(record):
        nonlocal raw_proof_bytes
        receipt, final = observe_pool_finality(endpoints, args.submit_validator, record)
        if isinstance(receipt,dict) and (receipt.get("status")=="accepted" or receipt.get("lifecycle_status") in {"durably_admitted","certified","ordered","finalized"}):
            record["accepted"]=True
        if isinstance(receipt,dict):record["observed_admission_lifecycle"]=receipt.get("lifecycle_status")
        if final is None:return False

        unsigned=final.get("transaction",{}).get("unsigned",{})
        if unsigned.get("sender")!=record["sender"] or unsigned.get("nonce")!=record["nonce"] or unsigned.get("receiver")!=args.receiver or int(unsigned.get("amount_nwei",-1))!=args.amount_nwei:
            raise BaselineError("finalized transaction differs from signed transfer")
        wallet=record["wallet"];gas=final.get("receipt",{}).get("gas_used")
        if type(gas) is not int or gas>args.gas_limit:raise BaselineError("invalid finalized gas receipt")
        finalized_account=pool_account(endpoints,wallet["sender"],final["block_height"],include_views=True)

        debit=wallet["balance_nwei"]-finalized_account["balance_nwei"]
        if finalized_account["nonce"]!=wallet["nonce"]+1 or not args.amount_nwei<=debit<=args.amount_nwei+gas*args.max_fee_per_gas_nwei:
            raise BaselineError("finalized sender nonce/debit differs from exactly-once transfer and signed fee bound")
        record["raw_proof_ref"]=proof.append({"kind":"finalized_transfer","transaction_id":record["transaction_id"],
            "finalized_transaction_views":final["validator_views"],
            "finalized_sender_account_views":finalized_account["validator_views"]})
        wallet["spent"]+=debit
        wallet["nonce"]+=1;wallet["balance_nwei"]=finalized_account["balance_nwei"]
        record["observed_fee_nwei"]=debit-args.amount_nwei
        record.update(finalized_mono=time.monotonic(),finalized_at=utc_now(),block_height=final["block_height"],accepted=True)
        finalities.append(record["finalized_mono"]-record["context_started_mono"])
        raw_proof_bytes=proof.length
        report["raw_proof_stream"]=proof.metadata()
        return True

    try:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.max_in_flight)
        try:
            while (time.monotonic()<deadline and attempted<args.max_tx) or jobs or pending:
                now=time.monotonic()
                if closed_loop and now>=deadline:
                    stop_reason=stop_reason or "closed-loop memory count deadline exceeded"
                    cancellation.set()
                    if now>=readonly_drain_deadline:
                        raise BaselineError(stop_reason+"; bounded read-only reconciliation ended")
                if stop_reason is None and now<deadline and attempted<args.max_tx and (closed_loop or now>=next_slot):
                    # Closed-loop work consumes available wallet slots without an
                    # offered clock. Offered-rate mode still drops missed slots.
                    scheduled,next_slot,missed=pool_offer_slot(closed_loop,now,next_slot,args.rate_tps)
                    skipped+=missed
                    if available and len(jobs)+len(pending)<args.max_in_flight:
                        wallet=available.pop(0)
                        if wallet["balance_nwei"]<args.amount_nwei+args.gas_limit*args.max_fee_per_gas_nwei:
                            stop_reason="funded generator budget exhausted";cancellation.set()
                        else:
                            jobs[pool.submit(cancellation_guard,cancellation,offer,wallet,scheduled)]=wallet;attempted+=1
                            peak_inflight=max(peak_inflight,len(jobs)+len(pending))
                            if closed_loop:report["peak_in_flight"]=peak_inflight
                    elif not closed_loop:skipped+=1
                for future in list(jobs):
                    if future.done():
                        wallet=jobs.pop(future)
                        try:record=future.result()
                        except Exception as error:
                            stop_reason=stop_reason or "generator/signing/submission boundary failed: "+str(error);cancellation.set()
                            with submitted_lock:
                                recovered=[r for r in submitted_records.values() if r["wallet"] is wallet]
                            for record in recovered:
                                if record not in transactions:transactions.append(record)
                                if "finalized_mono" not in record and record.get("submission_started",True) and not record.get("submission_rejection"):pending[record["transaction_id"]]=record
                            continue
                        pending[record["transaction_id"]]=record;transactions.append(record)
                if now-last_snapshot>=POLL_SECONDS:
                    state=sample_fleet(endpoints,args.network_id,native_tips=True, expected_chain_id=chain_id);height=state["val2"]["common_height"]
                    if height<highest:raise BaselineError("finalized height regressed")
                    if height>highest:highest=height;last_progress=time.monotonic()
                    elif now-last_progress>args.maximum_gap_seconds:raise BaselineError("unresolved finality stall; load stopped")
                    for txid,record in list(pending.items()):
                        if reconcile(record):
                            available.append(record["wallet"]);del pending[txid]
                    last_snapshot=time.monotonic()
                if stop_reason and not jobs and not pending:break
                if stop_reason and not closed_loop:
                    raise BaselineError(stop_reason+"; stop and reconcile original requests before further authoring")
                if drain_deadline is not None and time.monotonic()>=drain_deadline:
                    raise BaselineError("explicit operational drain deadline reached; original requests remain unresolved")
                time.sleep(0.02 if closed_loop else min(0.02,max(0.001,next_slot-time.monotonic())) if time.monotonic()<deadline else 0.05)
            load_end=min(time.monotonic(),deadline)
        finally:
            if sys.exc_info()[0] is not None or stop_reason:
                cancellation.set()
                for future in jobs: future.cancel()
            pool.shutdown(wait=True, cancel_futures=True)
            # Shutdown joins in-progress submissions. Retain their identities even
            # when a safety/stall exception prevented the normal future harvest.
            known={record["transaction_id"] for record in transactions}
            with submitted_lock:
                for txid,record in submitted_records.items():
                    if txid not in known:transactions.append(record);known.add(txid)
                    if "finalized_mono" not in record and record.get("submission_started",True) and not record.get("submission_rejection"):pending[txid]=record
            if closed_loop:
                report.update(attempted_transactions=attempted,submitted_transactions=sum(record.get("submission_started",True) for record in transactions),
                              finalized_transactions=sum(record.get("finalized_mono") is not None for record in transactions),
                              remaining_in_flight=len(pending),peak_in_flight=peak_inflight)
            if sys.exc_info()[0] is not None:
                report["cancelled_load"]=True
                report["remaining_in_flight"]=len(pending)
                # One bounded receipt observation per submitted unresolved request.
                # No retry, re-signing, nonce reuse or passing qualification claim.
                reconcile_deadline=time.monotonic()+30.0
                for record in pending.values():
                    if time.monotonic()>=reconcile_deadline:
                        record["reconciliation_status"]="unresolved_after_cancel";continue
                    try:
                        record["cancelled_receipt_observation"]=rpc(endpoints[args.submit_validator],
                            "synergy_getProtectedAdmissionReceipt",{"receipt_id":record["receipt_id"]},
                            timeout=min(RPC_TIMEOUT,max(0.1,reconcile_deadline-time.monotonic())))
                        record["reconciliation_status"]="receipt_observed_after_cancel_finality_unverified"
                    except Exception as error:
                        record["reconciliation_status"]="unresolved_after_cancel"
                        record["reconciliation_error"]=str(error)
        end_state=sample_fleet(endpoints,args.network_id,native_tips=True, expected_chain_id=chain_id);common=end_state["val2"]["common_height"]
        observation_elapsed=time.monotonic()-start
        sender_effects=[]
        for wallet in wallets:
            view=pool_account(endpoints,wallet["sender"],common,include_views=True)
            sender_effects.append({"sender":wallet["sender"],"initial_by_validator":wallet["initial_views"],"final_by_validator":view["validator_views"],
                "initial_nonce":wallet["initial_nonce"],"final_nonce":wallet["nonce"],"observed_total_debit_nwei":wallet["spent"]})
            if view["nonce"]!=wallet["nonce"] or view["balance_nwei"]!=wallet["initial_balance"]-wallet["spent"]:
                raise BaselineError("funded wallet effects differ from exactly-once execution")
        receiver_end=pool_account(endpoints,args.receiver,common,include_views=True)
        finalized=sum(1 for record in transactions if record.get("finalized_mono") is not None)
        if receiver_end["balance_nwei"]!=receiver_initial["balance_nwei"]+finalized*args.amount_nwei:
            raise BaselineError("receiver credit differs from exactly-once finalized transfer count")
        if closed_loop:
            effects_verified_at=time.monotonic()
            deadline_met=closed_loop_deadline_met(attempted,transactions,len(pending)+len(jobs),deadline,effects_verified_at)
            report.update(all_five_effects_verified_mono=effects_verified_at,
                          workload_elapsed_seconds=effects_verified_at-start)
            report["workload_deadline_met"]=deadline_met
            if not deadline_met:
                stop_reason=stop_reason or "closed-loop memory cohort requires all 30 exact proofs and all-five wallet effects before the count deadline"
        else:
            if attempted<args.max_tx and args.max_tx<=math.ceil(args.rate_tps*args.duration_seconds):
                stop_reason=stop_reason or "generator failed to deliver requested cohort"
            expected_cohort=min(args.max_tx,math.ceil(args.rate_tps*args.duration_seconds))
            if skipped or attempted!=expected_cohort:
                stop_reason=stop_reason or "generator did not deliver the complete offered-rate cohort; chain capacity unknown"
        observed_start_counters={name:value["stats"] for name,value in state_at_load_start.items()}
        observed_end_counters={name:value["stats"] for name,value in end_state.items()}
        def latency_distribution(values):
            ordered=sorted(values)
            if not ordered:return {"count":0,"p50":None,"p95":None,"p99":None,"maximum":None}
            return {"count":len(ordered),**{f"p{percent}":ordered[max(0,math.ceil(percent*len(ordered)/100)-1)] for percent in (50,95,99)},"maximum":ordered[-1]}
        report.update(status="failed" if stop_reason else "completed",failure=stop_reason,end_utc=utc_now(),end_tip=tip_record(end_state),
            observed_client_latency_seconds={"context_to_finality":latency_distribution(finalities),
                **{field:latency_distribution([record[field] for record in transactions]) for field in ("context_retrieval_seconds","native_signing_and_session_queue_seconds","submission_transport_seconds")}},
            latency_observation_basis="client clock and polling; native signing queue combined; RPC receipt arrival is not durable admission timestamp",
            offered_rate_tps=None if closed_loop else args.rate_tps,attempted_transactions=attempted,submitted_transactions=sum(record.get("submission_started",True) for record in transactions) if closed_loop else len(transactions),finalized_transactions=finalized,
            generator_missed_offered_slots=None if closed_loop else skipped,generator_limited=None if closed_loop else skipped>0,
            raw_proof_bytes=raw_proof_bytes,raw_proof_budget_bytes=proof.budget,
            raw_proof_stream=proof.metadata(),
            wallet_effects_evidence={"before_height":effects_before_height,"after_height":common,"senders":sender_effects,
                "receiver":{"address":args.receiver,"initial_by_validator":receiver_initial["validator_views"],"final_by_validator":receiver_end["validator_views"],"credited_nwei":finalized*args.amount_nwei}},
            common_height_snapshots={"preflight":tip_record(first),"load_start":tip_record(state_at_load_start),"end":tip_record(end_state)},
            measured_submitted_tps=None if closed_loop else len(transactions)/max(0.001,load_end-start),
            finalized_tps=None if closed_loop else sum(1 for record in transactions if record.get("finalized_mono",float("inf"))<=load_end)/max(0.001,load_end-start),
            end_to_end_finalized_tps=finalized/max(0.001,observation_elapsed),
            drain={"offered_window_end_mono":deadline,"drained_at_mono":time.monotonic(),
                   "seconds_after_offered_window":max(0,time.monotonic()-deadline),
                   "unresolved":len(pending)+len(jobs)},
            accepted_tps_by_validator=None if closed_loop else counter_rates(observed_start_counters,observed_end_counters,"accepted_total",observation_elapsed),
            etdag_ordered_tps_by_validator=None if closed_loop else counter_rates(observed_start_counters,observed_end_counters,"etdag_ordered_total",observation_elapsed),
            diagnostic_achieved_finalized_rate=finalized/max(0.001,observation_elapsed) if closed_loop else None,
            native_counter_observation_seconds=observation_elapsed,native_counter_window="closed-loop memory workload; diagnostic only" if closed_loop else "load and drain; independent from offered window",
            executed_and_finalized_cohort_transactions=finalized,
            p95_context_to_finality_seconds=percentile95(finalities),remaining_in_flight=len(pending)+len(jobs),wallet_effects_verified_all_five=True,
            capacity_result=False,TPS_qualified=False,note="Count-based resource qualification only; no offered-rate or TPS/capacity claim." if closed_loop else "One load step only. Generator limits and missed slots are reported separately; capacity requires highest clean ten-minute step and explicit overload/drain qualification.")
        return report
    finally:
        cancellation.set()
        try:
            signer.close()
        finally:
            try:
                proof.close()
                report["raw_proof_stream"]=proof.metadata()
            finally:
                for record in transactions:record.pop("wallet",None)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validator-rpc", action="append", type=parse_validator_rpc, default=[], metavar="VAL=URL")
    parser.add_argument("--rpc-token-file", type=Path, help="private run token for qualification-only VPN relays")
    parser.add_argument("--rpc-vpn-peer", action="append", default=[], help="exact authenticated VPN peer IP allowed for HTTP relay; requires token file")
    parser.add_argument("--network-id", default=DEFAULT_NETWORK_ID)
    parser.add_argument("--submit-validator", choices=VALIDATORS, default="val2")
    parser.add_argument("--keytool", type=Path, default=Path(__file__).resolve().parents[2] / "target/release/synergy-keytool")
    parser.add_argument("--remote-signer", action="store_true", help="author on Val2 through its existing canonical SSH master; custody stays remote")
    parser.add_argument("--signer-dir", type=Path, help="dedicated funded wallet custody directory; never validator custody")
    parser.add_argument("--operator-wallet-registry", action="store_true", help="explicit existing-wallet operator custody mode; exact signed Genesis and authority remain required; does not activate a protocol")
    parser.add_argument("--installation-root", type=Path, help="operator qualification: canonical installed Synergy root")
    parser.add_argument("--release-manifest", type=Path, help="operator qualification: independently reviewed canonical package.json")
    parser.add_argument("--raw-proof-budget-bytes", type=int, default=16*1024**3, help="raw public evidence disk bound: 4 MiB..64 GiB, default16GiB, retaining1GiBfilesystemreserve")
    parser.add_argument("--raw-proof-stream", type=Path, help="create one bounded canonical raw JSONL evidence stream; otherwise derived from --output")
    parser.add_argument("--wallet-registry", type=Path, help="isolated funded wallet-pool registry; persistent native signing on this authorized custody host")
    parser.add_argument("--wallet-id", action="append", default=[], help="explicit existing registry wallet IDs for this workload; all selected wallets still require native custody and all-five finalized authorization")
    parser.add_argument("--max-in-flight", type=int, default=32, help="bounded total pool generator concurrency")
    parser.add_argument("--author-workers", type=int, default=8, help="bounded native signing/RPC worker count, independent of outstanding transaction capacity")
    parser.add_argument("--max-in-flight-per-wallet", type=int, default=1,
                        help="async processing generator nonce window per wallet, 1..256; does not change legacy governed admission limits")
    parser.add_argument("--drain-timeout-seconds", type=float, help="optional operational deadline after offered window; default drains while block safety remains healthy; never a transaction latency gate")
    parser.add_argument("--maximum-gap-seconds", type=float, default=30.0, help="reviewed isolated profile stall budget")
    parser.add_argument("--receiver")
    parser.add_argument("--amount-nwei", type=int, default=1)
    parser.add_argument("--gas-limit", type=int)
    parser.add_argument("--max-fee-per-gas-nwei", type=int)
    parser.add_argument("--gas-class-units", type=int)
    parser.add_argument("--fee-class", type=int, default=1)
    parser.add_argument("--workload-mode", choices=("offered-rate","closed-loop-memory"), default="offered-rate",
                        help="closed-loop-memory: wallet-pool-only 30-count/300-second memory qualification; no TPS claim")
    parser.add_argument("--rate-tps", type=float, default=1.0)
    parser.add_argument("--duration-seconds", type=int, default=30)
    parser.add_argument("--max-tx", type=int, default=30)
    parser.add_argument("--stability-seconds", type=int, default=30)
    parser.add_argument("--measure-outside-cadence-target", action="store_true", help="measure performance even when cadence misses its target; quorum, stall and finality checks remain strict")
    parser.add_argument("--temp-dir", type=Path)
    parser.add_argument("--output", type=Path, help="create-new JSON report path; default stdout")
    parser.add_argument("--execute", action="store_true", help="submit bounded real transactions")
    parser.add_argument("--self-test", action="store_true", help="run offline helper checks")
    parser.add_argument("--async-processing", action="store_true", help="explicit native async processing RPC workload; isolated wallet-pool custody, no inclusion-height deadline")
    parser.add_argument("--exploratory-async-fixture", type=Path, metavar="TEST_BINARY",
                        help="measure the optimized native five-validator async fixture, with independent process sampling")
    parser.add_argument("--fixture-per-validator-budgets", action="store_true",
                        help="local async fixture only: independent unchanged 1GiB pool per validator; never changes RPC validators")
    parser.add_argument("--fixture-native-preparation", action="store_true",
                        help="local async fixture only: use existing production PoSy/Sync preparation workers")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        configure_rpc_transport(args.rpc_token_file, args.rpc_vpn_peer)
        for _, url in args.validator_rpc:
            validate_rpc_url(url)
    except (OSError, ValueError, BaselineError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if args.self_test:
        self_test()
        print("TPS harness offline checks passed")
        return 0
    if args.output:
        output_path = args.output.expanduser()
        if not output_path.is_absolute() or not output_path.parent.is_dir() or output_path.exists():
            print("--output must be an absolute new path in an existing directory", file=sys.stderr)
            return 2
        args.output = output_path
    try:
        if args.async_processing:
            if args.exploratory_async_fixture:
                raise BaselineError("choose one explicit async measurement mode")
            from posy_async_rpc_baseline import run_async
            report = run_async(args, sys.modules[__name__])
        elif args.exploratory_async_fixture:
            from posy_async_fixture_baseline import run_fixture
            report = run_fixture(args)
        else:
            report = run(args)
    except (BaselineError, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        report = getattr(args, "_partial_report", {"status": "running"})
        report.update({"status": "failed", "failure": str(error), "observed_at": utc_now()})
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(args.output, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(encoded)
    else:
        print(encoded, end="")
    return 1 if report.get("status") == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
