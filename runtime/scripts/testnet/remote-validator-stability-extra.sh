#!/usr/bin/env bash
set -uo pipefail

python3 - <<'PY'
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path


def workspace() -> Path:
    explicit = os.environ.get("SYNERGY_WORKSPACE")
    if explicit:
        return Path(explicit)
    candidate = Path.home() / ".synergy/testnet/nodes/validator-workspace"
    return candidate if candidate.exists() else Path.cwd()


def rpc(port: str, method: str):
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": [], "id": 1}).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            value = json.loads(response.read().decode())
        return value.get("result"), round((time.monotonic() - started) * 1000, 3), None
    except Exception as error:
        return None, round((time.monotonic() - started) * 1000, 3), f"{type(error).__name__}: {error}"


def runtime_pids() -> list[str]:
    matches = []
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            parts = [
                value.decode("utf-8", errors="replace")
                for value in (proc / "cmdline").read_bytes().split(b"\0")
                if value
            ]
        except Exception:
            continue
        if not parts:
            continue
        command = " ".join(parts)
        if "synergy-testnet-linux-amd64" in Path(parts[0]).name and " start --config " in f" {command} ":
            matches.append(proc.name)
    return sorted(matches, key=int)


def count_close_wait() -> int | None:
    try:
        output = subprocess.check_output(
            ["ss", "-tan", "state", "close-wait"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return max(0, len([line for line in output.splitlines() if line.strip()]) - 1)
    except Exception:
        return None


def recent_error_scan(root: Path) -> dict:
    patterns = {
        "same_height_conflict": re.compile(r"same[-_ ]height.*(?:conflict|supersede|different block)", re.I),
        "duplicate_vote": re.compile(r"duplicate[-_ ]vote|duplicate vote", re.I),
        "already_locally_voted": re.compile(r"already[-_ ]locally[-_ ]voted|already locally voted", re.I),
        "chain_lock_busy": re.compile(r"chain_lock_busy|chain lock busy", re.I),
        "committed_qc_conflict": re.compile(r"committed[-_ ]qc[-_ ]conflict|committed qc conflict", re.I),
        "h175518_resurrection": re.compile(r"\b175518\b"),
    }
    counts = {name: 0 for name in patterns}
    samples = []
    files = []
    cutoff = time.time() - 15 * 60
    for directory in [root / "logs", root / "data/logs"]:
        if directory.is_dir():
            files.extend(
                path for path in directory.glob("*")
                if path.is_file() and path.stat().st_mtime >= cutoff
            )
    for path in sorted(files, key=lambda value: value.stat().st_mtime)[-12:]:
        try:
            lines = subprocess.check_output(
                ["tail", "-n", "2000", str(path)],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).splitlines()
        except Exception:
            continue
        for line in lines:
            matched = []
            for name, pattern in patterns.items():
                if pattern.search(line):
                    counts[name] += 1
                    matched.append(name)
            if matched:
                samples.append({"file": path.name, "kinds": matched, "line": line[-500:]})
    return {"counts": counts, "samples": samples[-30:], "files_scanned": len(files)}


root = workspace()
port = os.environ.get("SYNERGY_QRPC_PORT", "5640")
pids = runtime_pids()
fd_counts = {}
for pid in pids:
    try:
        fd_counts[pid] = len(list((Path("/proc") / pid / "fd").iterdir()))
    except Exception:
        fd_counts[pid] = None
status, qrpc_ms, qrpc_error = rpc(port, "synergy_getNodeStatus")
peers, _, peer_error = rpc(port, "synergy_getPeerInfo")
peer_count = None
if isinstance(peers, list):
    peer_count = len(peers)
elif isinstance(peers, dict):
    peer_count = peers.get("peer_count")
print(json.dumps({
    "spreadsheet_row_used": True,
    "row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
    "node": os.environ.get("SYNERGY_NODE"),
    "workspace": str(root),
    "process_count": len(pids),
    "runtime_pids": pids,
    "fd_counts": fd_counts,
    "close_wait_count": count_close_wait(),
    "qrpc_responsive": qrpc_error is None,
    "qrpc_latency_ms": qrpc_ms,
    "qrpc_error": qrpc_error,
    "peer_count": peer_count,
    "peer_error": peer_error,
    "node_status": status,
    "recent_consensus_error_scan": recent_error_scan(root),
}, sort_keys=True))
PY
