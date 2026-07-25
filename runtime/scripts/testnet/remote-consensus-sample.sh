#!/usr/bin/env bash
set -uo pipefail

python3 - <<'PY'
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path


def find_workspace() -> str:
    explicit = os.environ.get("SYNERGY_WORKSPACE")
    if explicit:
        return explicit
    home = Path.home()
    for candidate in [
        home / ".synergy/testnet/nodes/validator-workspace",
        home / ".synergy/testnet/nodes/relayer-workspace",
        Path("/opt/synergy/testnet/relayer"),
        Path("/opt/synergy/testnet/observer"),
        Path("/opt/synergy/Node-RPC"),
        Path("/opt/synergy/Node-EXP"),
    ]:
        if candidate.exists():
            return str(candidate)
    return str(Path.cwd())


def rpc(port: str, method: str, params=None, timeout=8, attempts=3):
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                value = json.loads(response.read().decode())
                if isinstance(value, dict):
                    value["_attempt"] = attempt
                return value
        except Exception as exc:
            last_error = {"error": type(exc).__name__, "message": str(exc), "attempt": attempt}
    return last_error or {"error": "unknown"}


def unwrap_result(value):
    if isinstance(value, dict) and "result" in value:
        return value["result"]
    return None


def block_summary(block):
    if not isinstance(block, dict):
        return None
    return {
        "height": block.get("height") or block.get("number") or block.get("block_number") or block.get("block_index"),
        "hash": block.get("hash") or block.get("block_hash"),
        "parent_hash": block.get("parent_hash") or block.get("parentHash"),
        "timestamp": block.get("timestamp"),
    }


def lock_summary(lock):
    if not isinstance(lock, dict):
        return None
    return {
        "height": lock.get("height") or lock.get("block_height"),
        "hash": lock.get("hash") or lock.get("block_hash"),
        "round": lock.get("round"),
        "epoch": lock.get("epoch"),
    }


def sha256_file(path: Path):
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def last_json_line(path: Path):
    if not path.exists():
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 1024 * 1024))
            lines = handle.read().splitlines()
        for raw in reversed(lines):
            raw = raw.strip()
            if not raw:
                continue
            try:
                return json.loads(raw.decode())
            except Exception:
                continue
    except Exception:
        return None
    return None


def qc_summary(qc):
    if not isinstance(qc, dict):
        return None
    nested = qc.get("qc") if isinstance(qc.get("qc"), dict) else qc
    signatures = (
        nested.get("signatures")
        or nested.get("votes")
        or nested.get("validator_signatures")
        or nested.get("participants")
        or []
    )
    vote_count = nested.get("vote_count")
    if vote_count is None and isinstance(signatures, list):
        vote_count = len(signatures)
    return {
        "height": nested.get("height") or nested.get("block_height"),
        "hash": nested.get("block_hash") or nested.get("hash"),
        "round": nested.get("round"),
        "epoch": nested.get("epoch"),
        "vote_count": vote_count,
        "cumulative_weight": nested.get("cumulative_weight"),
        "participant_bitmap": nested.get("participant_bitmap"),
    }


def count_vote_locks_above(path: Path, finalized_height):
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except Exception:
        return "unreadable"
    try:
        finalized = int(finalized_height)
    except Exception:
        return "unknown_finalized_height"
    count = 0

    def walk(value):
        nonlocal count
        if isinstance(value, dict):
            height = value.get("height") or value.get("block_height")
            if height is not None:
                try:
                    if int(height) > finalized:
                        count += 1
                except Exception:
                    pass
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(data)
    return count


def process_state():
    entries = []
    deleted = False
    for proc in Path("/proc").glob("[0-9]*"):
        pid = proc.name
        try:
            raw_cmd = (proc / "cmdline").read_bytes()
        except Exception:
            continue
        if not raw_cmd:
            continue
        parts = [part.decode("utf-8", errors="replace") for part in raw_cmd.split(b"\0") if part]
        if not parts:
            continue
        cmd = " ".join(parts)
        if " start --config " not in f" {cmd} ":
            continue
        if not any(
            name in parts[0]
            for name in (
                "synergy-testnet-linux-amd64",
                "synergy-rpc-gateway-node-linux-amd64",
            )
        ):
            continue
        exe = ""
        try:
            exe = os.readlink(proc / "exe")
            deleted = deleted or "(deleted)" in exe
        except Exception:
            pass
        rss_kb = None
        try:
            with (proc / "status").open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        rss_kb = int(line.split()[1])
                        break
        except Exception:
            pass
        entries.append({"pid": pid, "cmd": cmd, "exe": exe, "rss_kb": rss_kb})
    return entries, deleted


def listener_ports_for_node(workspace: Path, qrpc_port: str):
    explicit = os.environ.get("SYNERGY_LISTENER_PORTS")
    if explicit:
        ports = []
        for part in explicit.replace(",", " ").split():
            try:
                ports.append(int(part))
            except Exception:
                pass
        return ports
    try:
        qrpc = int(qrpc_port)
    except Exception:
        return []
    if os.environ.get("SYNERGY_NODE") == "RPC Gateway" or workspace.name == "Node-RPC":
        return [5623, qrpc, 5661]
    return [qrpc - 18, qrpc, qrpc + 20]


def listener_process_state(ports):
    if not ports:
        return {"ports": {}, "owner_pids": [], "raw": [], "error": "no_ports"}
    wanted = {str(port) for port in ports}
    owners = {str(port): [] for port in ports}
    raw = []
    try:
        output = subprocess.check_output(
            ["ss", "-ltnp"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=4,
        )
    except Exception as exc:
        return {"ports": owners, "owner_pids": [], "raw": [], "error": str(exc)}
    for line in output.splitlines():
        matched = False
        for port in wanted:
            if re.search(rf":{re.escape(port)}\b", line):
                owners[port] = sorted(set(re.findall(r"pid=(\d+)", line)))
                matched = True
        if matched:
            raw.append(line)
    owner_pids = sorted({pid for values in owners.values() for pid in values}, key=int)
    return {"ports": owners, "owner_pids": owner_pids, "raw": raw}


workspace = Path(find_workspace())
data_dir = workspace / "data"
port = os.environ.get("SYNERGY_QRPC_PORT", "5640")
latest = unwrap_result(rpc(port, "synergy_getLatestBlock"))
canonical_rpc = rpc(port, "synergy_getCanonicalLock")
canonical = unwrap_result(canonical_rpc)
peer_info = unwrap_result(rpc(port, "synergy_getPeerInfo"))
node_status = unwrap_result(rpc(port, "synergy_getNodeStatus"))
block = block_summary(latest)
lock = lock_summary(canonical)
qc_from_file = qc_summary(last_json_line(data_dir / "committed_qcs.jsonl"))
processes, deleted_inode = process_state()
listener_state = listener_process_state(listener_ports_for_node(workspace, port))
listener_owner_pids = listener_state.get("owner_pids")
binary_candidates = []
if os.environ.get("SYNERGY_NODE") == "RPC Gateway" or workspace.name == "Node-RPC":
    binary_candidates.append(workspace / "bin/synergy-rpc-gateway-node-linux-amd64")
binary_candidates.extend(
    [
        workspace / "bin/synergy-testnet-linux-amd64",
    ]
)
binary = next((candidate for candidate in binary_candidates if candidate.exists()), binary_candidates[0])

result = {
    "spreadsheet_row_used": True,
    "row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
    "node": os.environ.get("SYNERGY_NODE"),
    "host": os.uname().nodename,
    "date_utc": subprocess.check_output(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], text=True).strip(),
    "workspace": str(workspace),
    "qrpc_port": port,
    "latest_block": block,
    "canonical_lock": lock,
    "canonical_lock_rpc_error": canonical_rpc if lock is None and isinstance(canonical_rpc, dict) else None,
    "committed_qc_file_tail": qc_from_file,
    "peer_count": len(peer_info) if isinstance(peer_info, list) else None,
    "peer_info_sample": peer_info[:5] if isinstance(peer_info, list) else peer_info,
    "node_status": node_status,
    "vote_locks_above_canonical": count_vote_locks_above(
        data_dir / "consensus_vote_locks.json",
        lock.get("height") if lock else None,
    ),
    "quarantine_marker": (data_dir / "validator_quarantine.json").exists(),
    "runtime_sha256": sha256_file(binary),
    "process_count": len(processes),
    "deleted_inode_process": deleted_inode,
    "processes": processes[:4],
    "listener_process_count": len(listener_owner_pids) if isinstance(listener_owner_pids, list) else None,
    "listener_owner_pids": listener_owner_pids,
    "listener_ports": listener_state.get("ports"),
    "listener_probe_error": listener_state.get("error"),
    "listener_raw": (listener_state.get("raw") or [])[:8],
}
print(json.dumps(result, sort_keys=True))
PY
