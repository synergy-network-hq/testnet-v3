#!/usr/bin/env bash
set -uo pipefail

python3 - <<'PY'
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path


def sh(command: str, timeout: int = 5) -> str:
    try:
        return subprocess.check_output(
            ["bash", "-lc", command],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"


def rpc(port: str, method: str, params=None, timeout=5):
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}
    ).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except Exception as exc:
        return {"error": type(exc).__name__, "message": str(exc)}


def result(payload):
    return payload.get("result") if isinstance(payload, dict) else None


def find_workspace() -> Path:
    explicit = os.environ.get("SYNERGY_WORKSPACE")
    if explicit:
        return Path(explicit)
    home = Path.home()
    candidates = [
        home / ".synergy/testnet/nodes/validator-workspace",
        home / ".synergy/testnet/nodes/relayer-workspace",
        Path("/opt/synergy/testnet/relayer"),
        Path("/opt/synergy/testnet/observer"),
        Path("/opt/synergy/Node-RPC"),
        Path("/opt/synergy/Node-EXP"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return Path.cwd()


def sha256_file(path: Path):
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def tail_jsonl(path: Path, max_bytes: int = 2 * 1024 * 1024):
    if not path.exists():
        return None
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            lines = handle.read().splitlines()
        for raw in reversed(lines):
            if not raw.strip():
                continue
            try:
                parsed = json.loads(raw.decode())
                return parsed
            except Exception:
                continue
    except Exception:
        return None
    return None


def summarize_block(block):
    if not isinstance(block, dict):
        return None
    return {
        "height": block.get("height") or block.get("number") or block.get("block_number"),
        "hash": block.get("hash") or block.get("block_hash"),
        "parent_hash": block.get("parent_hash") or block.get("parentHash"),
        "timestamp": block.get("timestamp"),
        "transactions": len(block.get("transactions") or []),
    }


def summarize_lock(lock):
    if not isinstance(lock, dict):
        return None
    nested = lock.get("lock") if isinstance(lock.get("lock"), dict) else lock
    return {
        "height": nested.get("height") or nested.get("block_height"),
        "hash": nested.get("hash") or nested.get("block_hash"),
        "qc_hash": nested.get("qc_hash") or nested.get("quorum_certificate_hash"),
        "round": nested.get("round"),
        "epoch": nested.get("epoch"),
    }


def summarize_qc(qc):
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
    signature_count = len(signatures) if isinstance(signatures, list) else None
    return {
        "height": nested.get("height") or nested.get("block_height"),
        "hash": nested.get("block_hash") or nested.get("hash"),
        "round": nested.get("round"),
        "epoch": nested.get("epoch"),
        "vote_count": vote_count,
        "signature_count": signature_count,
        "cumulative_weight": nested.get("cumulative_weight"),
        "participant_bitmap": nested.get("participant_bitmap"),
    }


def summarize_vote_locks(path: Path, finalized_height):
    payload = read_json(path)
    if payload is None:
        return {"exists": path.exists()}
    heights = {}
    hashes_by_height = {}
    above = 0
    try:
        finalized = int(finalized_height)
    except Exception:
        finalized = None

    def walk(value):
        nonlocal above
        if isinstance(value, dict):
            height = value.get("height") or value.get("block_height")
            block_hash = value.get("hash") or value.get("block_hash") or value.get("locked_hash")
            if height is not None:
                key = str(height)
                heights[key] = heights.get(key, 0) + 1
                if block_hash:
                    hashes_by_height.setdefault(key, set()).add(str(block_hash))
                if finalized is not None:
                    try:
                        if int(height) > finalized:
                            above += 1
                    except Exception:
                        pass
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(payload)
    conflicting_heights = {
        height: sorted(list(hashes))
        for height, hashes in hashes_by_height.items()
        if len(hashes) > 1
    }
    return {
        "exists": True,
        "entries_by_height": heights,
        "locks_above_finalized": above,
        "conflicting_heights": conflicting_heights,
    }


def proposal_summary(path: Path):
    if not path.exists():
        return {"exists": False}
    files = []
    try:
        for item in sorted(path.rglob("*"))[:200]:
            if item.is_file():
                files.append({"path": str(item.relative_to(path)), "size": item.stat().st_size})
    except Exception as exc:
        return {"exists": True, "error": str(exc)}
    return {"exists": True, "file_count_sample": len(files), "files": files[:20]}


def process_state():
    output = sh(
        "ps -eo pid=,args= | grep -E '/bin/synergy-test(net|beta)-linux-amd64 start --config|Node-RPC|Node-EXP|synergy-testnet-relayer' | grep -v grep || true"
    )
    entries = []
    deleted = False
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=1)
        if not parts or not parts[0].isdigit():
            continue
        pid = parts[0]
        exe = ""
        cwd = ""
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
            cwd = os.readlink(f"/proc/{pid}/cwd")
            deleted = deleted or "(deleted)" in exe
        except Exception:
            pass
        entries.append({"pid": pid, "cmd": parts[1] if len(parts) > 1 else "", "exe": exe, "cwd": cwd})
    return entries, deleted


def log_tail(workspace: Path, max_lines: int = 120):
    lines = []
    log_dir = workspace / "logs"
    if log_dir.exists():
        for path in sorted(log_dir.glob("*"))[:6]:
            if path.is_file():
                lines.append(f"== {path.name} ==")
                lines.extend(sh(f"tail -{max_lines} {str(path)!r}", timeout=5).splitlines()[-max_lines:])
    if not lines:
        lines = sh("journalctl -n 180 --no-pager 2>/dev/null | tail -180 || true", timeout=6).splitlines()
    selected = []
    pattern = re.compile(r"(QC|quorum|vote|lock|stall|proposal|proposer|round|height|Aegis|invalid|quarantine)", re.I)
    for line in lines[-800:]:
        if pattern.search(line):
            selected.append(line[-500:])
    return selected[-160:]


workspace = find_workspace()
data_dir = workspace / "data"
port = os.environ.get("SYNERGY_QRPC_PORT", "5640")
latest_rpc = rpc(port, "synergy_getLatestBlock")
latest_block = summarize_block(result(latest_rpc))
latest_height = latest_block.get("height") if latest_block else None
canonical_rpc = rpc(port, "synergy_getCanonicalLock")
canonical_lock = summarize_lock(result(canonical_rpc))
committed_qc_rpc = rpc(port, "synergy_getCommittedQC")
committed_qc = summarize_qc(result(committed_qc_rpc)) or summarize_qc(tail_jsonl(data_dir / "committed_qcs.jsonl"))
genesis = summarize_block(result(rpc(port, "synergy_getBlockByNumber", [0])))
current_height_block = summarize_block(result(rpc(port, "synergy_getBlockByNumber", [latest_height]))) if latest_height is not None else None
legacy_split_37335 = summarize_block(result(rpc(port, "synergy_getBlockByNumber", [37335])))
legacy_split_37440 = summarize_block(result(rpc(port, "synergy_getBlockByNumber", [37440])))
peer_info = result(rpc(port, "synergy_getPeerInfo"))
node_status = result(rpc(port, "synergy_getNodeStatus"))
methods = {}
for method in [
    "synergy_getDivergenceStatus",
    "synergy_getQuarantineStatus",
    "synergy_diagnoseConsensusStall",
    "synergy_diagnoseVoteLocks",
]:
    methods[method] = rpc(port, method)

binary = workspace / "bin/synergy-testnet-linux-amd64"
processes, deleted_inode = process_state()
listeners = sh(f"ss -ltnp 2>/dev/null | grep -E ':({port}|{os.environ.get('SYNERGY_WS_PORT', '5660')}|{os.environ.get('SYNERGY_METRICS_PORT', '6030')})\\b' || true")
package_version = sh("dpkg-query -W -f='${Package} ${Version}\\n' 'synergy*' 2>/dev/null || true").strip().splitlines()[:20]
service_status = sh("systemctl --no-pager --plain is-active synergy-testnet.service synergy-testnet-relayer.service synergy-node-control-panel.service 2>/dev/null || true").strip().splitlines()

output = {
    "spreadsheet_row_used": True,
    "row": os.environ.get("SYNERGY_SPREADSHEET_ROW"),
    "node": os.environ.get("SYNERGY_NODE"),
    "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": os.uname().nodename,
    "workspace": str(workspace),
    "qrpc_port": port,
    "latest_block": latest_block,
    "current_height_block": current_height_block,
    "block_37335": legacy_split_37335,
    "block_37440": legacy_split_37440,
    "genesis_block": genesis,
    "runtime_sha256": sha256_file(binary),
    "package_version": package_version,
    "process_count": len(processes),
    "deleted_inode_process": deleted_inode,
    "processes": processes[:8],
    "listeners": listeners.splitlines()[:20],
    "node_status": node_status,
    "peer_count": len(peer_info) if isinstance(peer_info, list) else None,
    "peer_info_sample": peer_info[:5] if isinstance(peer_info, list) else peer_info,
    "canonical_lock": canonical_lock,
    "committed_qc": committed_qc,
    "vote_locks": summarize_vote_locks(
        data_dir / "consensus_vote_locks.json",
        canonical_lock.get("height") if canonical_lock else None,
    ),
    "proposal_cache": proposal_summary(data_dir / "consensus_proposals"),
    "quarantine_marker": (data_dir / "validator_quarantine.json").exists(),
    "quarantine": read_json(data_dir / "validator_quarantine.json"),
    "diagnostic_methods": methods,
    "service_status": service_status,
    "log_signals_tail": log_tail(workspace),
}
print(json.dumps(output, sort_keys=True))
PY
