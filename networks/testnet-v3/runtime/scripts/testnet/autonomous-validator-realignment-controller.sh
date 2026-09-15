#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  autonomous-validator-realignment-controller.sh run
  autonomous-validator-realignment-controller.sh once
  autonomous-validator-realignment-controller.sh status
  autonomous-validator-realignment-controller.sh pause
  autonomous-validator-realignment-controller.sh resume
  autonomous-validator-realignment-controller.sh abort
  autonomous-validator-realignment-controller.sh export-evidence

The controller owns the quarantined-validator lifecycle:
ACTIVE -> SUSPECT -> QUARANTINED -> HEALING -> SYNCING -> VOTE_ONLY -> ACTIVE.
It restores from a verified snapshot when configured, proves a QC-backed head
match, rejoins immediately as vote-only, and restores proposer duties only after
a finalized-block probation window.

Required:
  SYNERGY_EXPECTED_RUNTIME_SHA=<trusted sha256>

Common environment:
  SYNERGY_WORKSPACE=$HOME/.synergy/testnet/nodes/validator-workspace
  SYNERGY_RUNTIME_PATH=<workspace>/bin/synergy-testnet-linux-amd64
  SYNERGY_REALIGNMENT_STATE_DIR=<workspace>/data/realignment-controller
  SYNERGY_COMMON_QRPC_URLS=http://10.69.0.1:5640,http://10.69.0.2:5640,http://10.69.0.3:5640,http://10.69.0.4:5640
  SYNERGY_SNAPSHOT_DISTRIBUTION=<optional validator-pruned snapshot distribution>
  SYNERGY_SNAPSHOT_RECEIVER=<manual-snapshot-receiver.sh path>
  SYNERGY_SNAPSHOT_EXTRACT_ROOT=<verified snapshot extraction root>

Catch-up behavior:
  CATCHING_UP and HEAD_MATCH_PENDING are retry states. The controller must not
  request rejoin until local qRPC, listeners, runtime
  process, fork/key safety gates, near-head lag, and fixed-height hash agreement
  are all proven.
USAGE
}

command="${1:-once}"
case "$command" in
  run|once|status|pause|resume|abort|export-evidence|--help|-h) ;;
  *) echo "unsupported command: $command" >&2; usage >&2; exit 2 ;;
esac
if [[ "$command" == "--help" || "$command" == "-h" ]]; then
  usage
  exit 0
fi

python3 - "$command" <<'PY'
import base64
import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

COMMAND = sys.argv[1]
WORKSPACE = Path(os.environ.get("SYNERGY_WORKSPACE", str(Path.home() / ".synergy/testnet/nodes/validator-workspace")))
RUNTIME = Path(os.environ.get("SYNERGY_RUNTIME_PATH", str(WORKSPACE / "bin/synergy-testnet-linux-amd64")))
EXPECTED_SHA = os.environ.get("SYNERGY_EXPECTED_RUNTIME_SHA", "").strip()
STATE_DIR = Path(os.environ.get("SYNERGY_REALIGNMENT_STATE_DIR", str(WORKSPACE / "data/realignment-controller")))
EVIDENCE_ROOT = Path(os.environ.get("SYNERGY_EVIDENCE_ROOT", str(Path.home() / "synergy-testnet-evidence")))
STATE_PATH = STATE_DIR / "validator-realignment-state.json"
CHECKLIST_PATH = STATE_DIR / "validator-realignment-checklist.json"
SUMMARY_PATH = STATE_DIR / "validator-realignment-summary.md"
EPOCH1_PATH = STATE_DIR / "validator-shadow-epoch-1-proof.json"
EPOCH2_PATH = STATE_DIR / "validator-shadow-epoch-2-proof.json"
REJOIN_PATH = STATE_DIR / "validator-rejoin-proof.json"
REJOIN_REQUEST_PATH = STATE_DIR / "validator-rejoin-request.json"
SOAK_PATH = STATE_DIR / "validator-post-rejoin-soak.json"
COMMAND_INTERVAL = int(os.environ.get("SYNERGY_REALIGNMENT_INTERVAL_SECS", "30"))
REQUIRED_BLOCKS = int(os.environ.get("SYNERGY_VAL5_SHADOW_REQUIRED_BLOCKS", "1000"))
MAX_LAG = int(os.environ.get("SYNERGY_REALIGNMENT_MAX_LAG_BLOCKS", "12"))
EPOCH_SIZE = int(os.environ.get("SYNERGY_REJOIN_EPOCH_SIZE", "1000"))
EPOCH_BOUNDARY_ARM_WINDOW = int(os.environ.get("SYNERGY_REJOIN_BOUNDARY_ARM_WINDOW_BLOCKS", "75"))
EPOCH_BOUNDARY_BLOCKING_WINDOW = int(os.environ.get("SYNERGY_REJOIN_BOUNDARY_BLOCKING_WINDOW_BLOCKS", "25"))
EPOCH_BOUNDARY_WAIT_SECS = int(os.environ.get("SYNERGY_REJOIN_BOUNDARY_WAIT_SECS", "180"))
EPOCH_BOUNDARY_POLL_SECS = float(os.environ.get("SYNERGY_REJOIN_BOUNDARY_POLL_SECS", "0.25"))
EPOCH_ENTRY_WINDOW_BLOCKS = int(os.environ.get("SYNERGY_REJOIN_EPOCH_ENTRY_WINDOW_BLOCKS", "10"))
SHADOW_STATUS_TIMEOUT = int(os.environ.get("SYNERGY_SHADOW_STATUS_TIMEOUT_SECS", "150"))
SHADOW_START_TIMEOUT = int(os.environ.get("SYNERGY_SHADOW_START_TIMEOUT_SECS", "120"))
REJOIN_ELIGIBILITY_TIMEOUT = int(os.environ.get("SYNERGY_REJOIN_ELIGIBILITY_TIMEOUT_SECS", "150"))
REQUEST_REJOIN_TIMEOUT = int(os.environ.get("SYNERGY_REQUEST_REJOIN_TIMEOUT_SECS", "150"))
POST_REJOIN_SOAK_SECS = int(os.environ.get("SYNERGY_POST_REJOIN_SOAK_SECS", "1800"))
VOTE_ONLY_REJOIN_ENABLED = os.environ.get("SYNERGY_VOTE_ONLY_REJOIN_ENABLED", "true").lower() == "true"
VOTE_ONLY_PROBATION_BLOCKS = int(os.environ.get("SYNERGY_VOTE_ONLY_PROBATION_BLOCKS", "1000"))
AUTO_START_RUNTIME = os.environ.get("SYNERGY_AUTONOMOUS_START_RUNTIME", "true").lower() == "true"
SNAPSHOT_DISTRIBUTION = os.environ.get("SYNERGY_SNAPSHOT_DISTRIBUTION", "").strip()
SNAPSHOT_RECEIVER = Path(os.environ.get("SYNERGY_SNAPSHOT_RECEIVER", str(EVIDENCE_ROOT / "manual-snapshot-receiver.sh")))
SNAPSHOT_CLASS = os.environ.get("SYNERGY_SNAPSHOT_CLASS", "validator-pruned").strip()
SNAPSHOT_TARGET_ROLE = os.environ.get("SYNERGY_SNAPSHOT_TARGET_ROLE", "validator").strip()
SNAPSHOT_EXTRACT_ROOT = Path(os.environ.get(
    "SYNERGY_SNAPSHOT_EXTRACT_ROOT",
    str(WORKSPACE / "data/incoming-snapshots/autonomous-realignment"),
))
SNAPSHOT_RECEIVER_TIMEOUT = int(os.environ.get("SYNERGY_SNAPSHOT_RECEIVER_TIMEOUT_SECS", "1200"))
SNAPSHOT_SELF_HEAL_TIMEOUT = int(os.environ.get("SYNERGY_SNAPSHOT_SELF_HEAL_TIMEOUT_SECS", "900"))
RUNTIME_STOP_TIMEOUT = int(os.environ.get("SYNERGY_RUNTIME_STOP_TIMEOUT_SECS", "45"))
COMMON_QRPC_URLS = [
    item.strip().rstrip("/")
    for item in os.environ.get(
        "SYNERGY_COMMON_QRPC_URLS",
        "http://10.69.0.1:5640,http://10.69.0.2:5640,http://10.69.0.3:5640,http://10.69.0.4:5640",
    ).split(",")
    if item.strip()
]
SOURCE_MAJORITY_MIN = int(os.environ.get(
    "SYNERGY_SOURCE_MAJORITY_MIN",
    str((len(COMMON_QRPC_URLS) // 2) + 1),
))

EXPECTED = {
    "chain_id": 1264,
    "network_id": "synergy-testnet-v3",
    "fork_height": 204216,
    "fork_parent_height": 204215,
    "fork_parent_hash": "e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816",
    "consensus_algorithm": "FN-DSA",
    "parser_mode": "fail_closed",
    "fndsa_public_key_bytes": 1793,
}


def now():
    return int(time.time())


def json_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def json_read(path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {**default, "corrupt_state_error": str(exc)}


def sha256_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args, timeout=30, check=False):
    result = subprocess.run(
        args,
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=str(WORKSPACE) if WORKSPACE.is_dir() else None,
        env={
            **os.environ,
            "SYNERGY_PROJECT_ROOT": str(WORKSPACE),
            "SYNERGY_CONFIG_PATH": str(WORKSPACE / "config/node.toml"),
        },
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"{args[0]} failed")
    return result


def sh_quote(value):
    return shlex.quote(value)


def rpc(url, method, params=None, timeout=5):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    request = urllib.request.Request(url + "/", data=payload, headers={"content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read().decode())
    if "result" not in value:
        raise RuntimeError(json.dumps(value, sort_keys=True))
    return value["result"]


def local_latest():
    return rpc("http://127.0.0.1:5640", "synergy_getLatestBlock")


def local_block(height):
    return rpc("http://127.0.0.1:5640", "synergy_getBlockByNumber", [height])


def local_optional_rpc(method, params=None, timeout=8):
    try:
        return {"ok": True, "result": rpc("http://127.0.0.1:5640", method, params or [], timeout=timeout)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "method": method}


def runtime_phase(command, *args, timeout=60):
    try:
        result = run([str(RUNTIME), command, "--source-workspace", str(WORKSPACE), "--chain-id", "1264", "--network-id", "synergy-testnet-v3", "--genesis-hash", "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789", *args], timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "typed_status": "RETRYABLE_TIMEOUT",
            "command": command,
            "stdout": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "",
            "stderr": f"{command} timed out after {timeout} seconds",
        }
    try:
        payload = json.loads(result.stdout)
    except Exception:
        payload = {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


def write_command_result(path, result, extra=None):
    payload = {
        "returncode": result.returncode,
        "stdout": result.stdout[-20000:],
        "stderr": result.stderr[-20000:],
        "command": result.args,
        "updated_at": now(),
    }
    if extra:
        payload.update(extra)
    json_write(path, payload)
    return payload


def process_table():
    rows = []
    for proc in Path("/proc").glob("[0-9]*"):
        try:
            exe = os.readlink(proc / "exe")
        except Exception:
            exe = ""
        try:
            cwd = os.readlink(proc / "cwd")
        except Exception:
            cwd = ""
        try:
            cmd = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        except Exception:
            cmd = ""
        if not cmd:
            continue
        if exe != str(RUNTIME):
            continue
        if " start --config " not in cmd:
            continue
        rows.append({"pid": proc.name, "exe": exe, "cwd": cwd, "cmd": cmd})
    return rows


def stop_runtime_for_snapshot_restore(state):
    rows = process_table()
    state["snapshot_restore_runtime_processes_before_stop"] = rows
    if not rows:
        set_check(state, "runtime_stopped_for_snapshot_restore", True, "runtime already stopped")
        return True

    pids = []
    for row in rows:
        try:
            pids.append(int(row["pid"]))
        except Exception:
            pass
    for pid in pids:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
        except Exception as exc:
            fail_closed(state, "runtime_stopped_for_snapshot_restore", f"SIGTERM {pid} failed: {exc}")
            return False
    deadline = time.time() + RUNTIME_STOP_TIMEOUT
    while time.time() < deadline:
        remaining = {int(row["pid"]) for row in process_table() if str(row.get("pid", "")).isdigit()}
        if not remaining:
            set_check(state, "runtime_stopped_for_snapshot_restore", True, f"stopped pids={pids}")
            return True
        time.sleep(EPOCH_BOUNDARY_POLL_SECS)
    remaining_rows = process_table()
    for row in remaining_rows:
        try:
            os.kill(int(row["pid"]), 9)
        except Exception:
            pass
    time.sleep(2)
    remaining_rows = process_table()
    if remaining_rows:
        fail_closed(state, "runtime_stopped_for_snapshot_restore", f"runtime still running after SIGKILL: {remaining_rows}")
        return False
    set_check(state, "runtime_stopped_for_snapshot_restore", True, f"stopped pids={pids} with SIGKILL")
    return True


def parse_key_value_line(line):
    values = {}
    for item in shlex.split(line):
        if "=" in item:
            key, value = item.split("=", 1)
            values[key] = value
    return values


def listener(port):
    if shutil.which("ss"):
        result = subprocess.run(["ss", "-ltnp"], text=True, capture_output=True)
        if result.returncode == 0:
            for raw in result.stdout.splitlines():
                parts = raw.split()
                if len(parts) >= 4 and parts[0] == "LISTEN":
                    local = parts[3]
                    if local.endswith(f":{port}") or f":{port} " in raw:
                        return True
    if shutil.which("lsof"):
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            text=True,
            capture_output=True,
        )
        return result.returncode == 0 and f":{port}" in result.stdout
    return False


def decode_key(raw):
    text = raw.decode("utf-8", errors="ignore").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
            for key in ("public_key_base64", "private_key_base64", "public_key", "private_key", "consensus_public_key", "consensus_private_key"):
                if isinstance(payload.get(key), str):
                    return decode_key(payload[key].encode())
        except Exception:
            pass
    if text.startswith("fn-dsa:"):
        text = text.split(":", 1)[1]
    compact = "".join(text.split())
    try:
        return base64.b64decode(compact, validate=True)
    except Exception:
        pass
    try:
        return bytes.fromhex(compact)
    except Exception:
        return raw


def key_candidates(kind):
    names = {
        "private": [
            "config/validator/consensus.private.key",
            "config/validator/fndsa-consensus.private.key",
            "keys/fndsa-consensus-fork-204216/private.key",
            "keys/fndsa-consensus/private.key",
            "keys/fndsa.private.key",
        ],
        "public": [
            "config/validator/consensus.public.key",
            "config/validator/fndsa-consensus.public.key",
            "keys/fndsa-consensus-fork-204216/public.key",
            "keys/fndsa-consensus/public.key",
            "keys/fndsa.public.key",
        ],
    }[kind]
    return [WORKSPACE / name for name in names]


def initial_state():
    return {
        "schema": "synergy-validator-realignment-controller-v2",
        "state": "QUARANTINED",
        "lifecycle_state": "QUARANTINED",
        "lifecycle": ["ACTIVE", "SUSPECT", "QUARANTINED", "HEALING", "SYNCING", "VOTE_ONLY", "ACTIVE"],
        "paused": False,
        "retry_count": 0,
        "shadow_epoch": 1,
        "observed_count": 0,
        "mismatch_count": 0,
        "missed_block_count": 0,
        "failure_reasons": [],
        "retryable_reasons": [],
        "terminal_failure_reasons": [],
        "checklist": {},
        "evidence_paths": {},
        "created_at": now(),
        "updated_at": now(),
    }


def _remove_reason(state, bucket, name):
    prefix = f"{name}: "
    state[bucket] = [item for item in state.get(bucket, []) if not str(item).startswith(prefix)]


def clear_check(state, name):
    _remove_reason(state, "retryable_reasons", name)
    _remove_reason(state, "terminal_failure_reasons", name)
    state.get("checklist", {}).pop(name, None)
    state["failure_reasons"] = list(state.get("terminal_failure_reasons", []))


def set_check(state, name, ok, detail, terminal=True):
    detail = str(detail)
    if len(detail) > 2000:
        detail = detail[:2000] + "...<truncated>"
    state.setdefault("checklist", {})[name] = {
        "ok": bool(ok),
        "detail": detail,
        "updated_at": now(),
    }
    if ok:
        _remove_reason(state, "retryable_reasons", name)
        _remove_reason(state, "terminal_failure_reasons", name)
        state["failure_reasons"] = list(state.get("terminal_failure_reasons", []))
        return
    if terminal:
        _remove_reason(state, "retryable_reasons", name)
    else:
        _remove_reason(state, "terminal_failure_reasons", name)
    bucket = "terminal_failure_reasons" if terminal else "retryable_reasons"
    _remove_reason(state, bucket, name)
    state.setdefault(bucket, [])
    reason = f"{name}: {detail}"
    if reason not in state[bucket]:
        state[bucket].append(reason)
    state["failure_reasons"] = list(state.get("terminal_failure_reasons", []))


def fail_closed(state, name, detail):
    set_check(state, name, False, detail, terminal=True)
    state["lifecycle_state"] = "QUARANTINED"
    state["state"] = "FAILED_REALIGNMENT"


def retry_later(state, name, detail, next_action):
    _remove_reason(state, "terminal_failure_reasons", name)
    _remove_reason(state, "retryable_reasons", name)
    set_check(state, name, False, detail, terminal=False)
    state["next_automatic_action"] = next_action


def load_fork_metadata(state):
    path = WORKSPACE / "config/consensus-fork-migration.json"
    if not path.is_file():
        set_check(state, "fork_metadata_verified", False, f"missing {path}")
        return None
    payload = json.loads(path.read_text())
    chain_id = payload.get("chain_id")
    network_id = payload.get("network_id")
    if chain_id is not None and chain_id != EXPECTED["chain_id"]:
        set_check(state, "fork_metadata_verified", False, f"wrong chain_id={chain_id}")
        return payload
    if network_id is not None and network_id != EXPECTED["network_id"]:
        set_check(state, "fork_metadata_verified", False, f"wrong network_id={network_id}")
        return payload
    ok = (
        payload.get("fork_height") == EXPECTED["fork_height"]
        and payload.get("parent_height") == EXPECTED["fork_parent_height"]
        and payload.get("parent_hash") == EXPECTED["fork_parent_hash"]
        and payload.get("new_consensus_algorithm") == EXPECTED["consensus_algorithm"]
        and payload.get("parser_mode") == EXPECTED["parser_mode"]
    )
    state["fork_metadata_hash"] = sha256_file(path)
    set_check(state, "fork_metadata_verified", ok, str(path) if ok else "fork metadata mismatch")
    return payload


def preflight(state):
    state["state"] = "PREFLIGHT"
    state["lifecycle_state"] = "SUSPECT"
    state["failure_reasons"] = []
    state["retryable_reasons"] = []
    state["terminal_failure_reasons"] = []
    if not EXPECTED_SHA:
        set_check(state, "runtime_sha_verified", False, "SYNERGY_EXPECTED_RUNTIME_SHA is required")
    elif not RUNTIME.is_file():
        set_check(state, "runtime_sha_verified", False, f"missing runtime {RUNTIME}")
    else:
        actual = sha256_file(RUNTIME)
        state["runtime_sha"] = actual
        set_check(state, "runtime_sha_verified", actual == EXPECTED_SHA, f"actual={actual} expected={EXPECTED_SHA}")
    set_check(state, "workspace_present", WORKSPACE.is_dir(), str(WORKSPACE))
    fork = load_fork_metadata(state)
    marker = WORKSPACE / "data/validator_quarantine.json"
    set_check(state, "quarantine_marker_exists", marker.is_file(), str(marker))
    for port, name in [(5622, "p2p"), (5640, "qrpc"), (5660, "ws"), (6030, "metrics")]:
        state.setdefault("listeners", {})[name] = listener(port)
    registry = (fork or {}).get("new_validator_registry") or []
    bad = [entry for entry in registry if entry.get("consensus_key_type") != "FN-DSA"]
    set_check(state, "no_mldsa_postfork_consensus_key", not bad, json.dumps(bad, sort_keys=True))
    public_path = next((path for path in key_candidates("public") if path.is_file()), None)
    private_path = next((path for path in key_candidates("private") if path.is_file()), None)
    if public_path:
        public_bytes = decode_key(public_path.read_bytes())
        state["validator_public_key_hash"] = hashlib.sha256(public_bytes).hexdigest()
        set_check(state, "fndsa_public_key_verified", len(public_bytes) == EXPECTED["fndsa_public_key_bytes"], f"{public_path} bytes={len(public_bytes)}")
    else:
        set_check(state, "fndsa_public_key_verified", False, "public key missing")
    if private_path:
        mode = stat.S_IMODE(private_path.stat().st_mode)
        set_check(state, "fndsa_private_key_strict_permissions", mode & 0o077 == 0, f"{private_path} mode={oct(mode)}")
    else:
        set_check(state, "fndsa_private_key_strict_permissions", False, "private key missing")
    if state.get("terminal_failure_reasons"):
        state["state"] = "QUARANTINED"
        state["lifecycle_state"] = "QUARANTINED"
    else:
        state["state"] = "RUNTIME_START_QUARANTINED"
        state["lifecycle_state"] = "SYNCING"


def common_head(state):
    proofs = []
    for url in COMMON_QRPC_URLS:
        try:
            latest = rpc(url, "synergy_getLatestBlock")
            height = int(latest.get("block_index") or latest.get("height") or 0)
            block_hash = latest.get("hash")
            proofs.append({"url": url, "height": height, "hash": block_hash})
        except Exception as exc:
            proofs.append({"url": url, "error": str(exc)})
    valid = [item for item in proofs if item.get("height") and item.get("hash")]
    state["canonical_sources"] = proofs
    state["highest_height"] = max((item["height"] for item in valid), default=None)
    if len(valid) < len(COMMON_QRPC_URLS):
        retry_later(
            state,
            "active_validator_probe_complete",
            f"valid={len(valid)} expected={len(COMMON_QRPC_URLS)}",
            "retry_active_validator_common_head_probe",
        )
    else:
        set_check(state, "active_validator_probe_complete", True, f"valid={len(valid)}")
    if not valid:
        return None
    height = min(item["height"] for item in valid)
    hashes = {}
    fixed_height_errors = []
    for item in valid:
        try:
            block = rpc(item["url"], "synergy_getBlockByNumber", [height])
            block_hash = block.get("hash")
            if not block_hash:
                fixed_height_errors.append(f"{item['url']}: missing hash at height {height}")
            else:
                hashes.setdefault(block_hash, []).append(item["url"])
        except Exception as exc:
            fixed_height_errors.append(f"{item['url']}: {exc}")
    if len(hashes) > 1:
        fail_closed(state, "active_validator_fixed_height_agreement", f"canonical source hash mismatch at {height}: {hashes}")
        return None
    if not hashes:
        retry_later(
            state,
            "active_validator_fixed_height_agreement",
            "; ".join(fixed_height_errors) or f"no active validator hash at {height}",
            "retry_active_validator_fixed_height_agreement",
        )
        return None
    block_hash = next(iter(hashes))
    hash_sources = hashes[block_hash]
    if len(hash_sources) < SOURCE_MAJORITY_MIN:
        retry_later(
            state,
            "active_validator_fixed_height_agreement",
            f"only {len(hash_sources)} source(s) agreed at {height}; required={SOURCE_MAJORITY_MIN}; errors={fixed_height_errors}",
            "retry_active_validator_fixed_height_agreement",
        )
        return None
    detail = f"height={height} hash={block_hash} agreeing_sources={len(hash_sources)} required={SOURCE_MAJORITY_MIN}"
    if fixed_height_errors:
        retry_later(
            state,
            "active_validator_probe_partial",
            "; ".join(fixed_height_errors),
            "retry_missing_active_validator_source",
        )
    set_check(state, "active_validator_fixed_height_agreement", True, detail, terminal=False)
    return {"height": height, "hash": block_hash, "sources": valid}


def source_hash_at(height, state):
    hashes = {}
    errors = []
    for url in COMMON_QRPC_URLS:
        try:
            block = rpc(url, "synergy_getBlockByNumber", [height])
            hashes.setdefault(block.get("hash"), []).append(url)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    if len(hashes) > 1:
        fail_closed(state, "fixed_height_source_probe", f"active validator hash mismatch at {height}: {hashes}")
        return None
    if not hashes:
        retry_later(state, "fixed_height_source_probe", "; ".join(errors) or f"no hash at {height}", "retry_fixed_height_source_probe")
        return None
    block_hash = next(iter(hashes))
    agreeing_sources = hashes[block_hash]
    if len(agreeing_sources) < SOURCE_MAJORITY_MIN:
        retry_later(
            state,
            "fixed_height_source_probe",
            f"only {len(agreeing_sources)} source(s) agreed at {height}; required={SOURCE_MAJORITY_MIN}; errors={errors}",
            "retry_fixed_height_source_probe",
        )
        return None
    if errors:
        retry_later(state, "fixed_height_source_probe_partial", "; ".join(errors), "retry_missing_fixed_height_source")
    set_check(state, "fixed_height_source_probe", True, f"height={height} hash={block_hash} agreeing_sources={len(agreeing_sources)}")
    return block_hash


def common_block_at(height, state, check_name="epoch_boundary_common_hash"):
    hashes = {}
    errors = []
    for url in COMMON_QRPC_URLS:
        try:
            block = rpc(url, "synergy_getBlockByNumber", [height])
            block_hash = block.get("hash")
            if not block_hash:
                errors.append(f"{url}: missing hash at height {height}")
            else:
                hashes.setdefault(block_hash, []).append(url)
        except Exception as exc:
            errors.append(f"{url}: {exc}")
    if len(hashes) > 1:
        fail_closed(state, check_name, f"active validator hash mismatch at {height}: {hashes}")
        return None
    if not hashes:
        retry_later(state, check_name, "; ".join(errors) or f"no hash at {height}", "retry_epoch_boundary_common_hash")
        return None
    block_hash = next(iter(hashes))
    agreeing_sources = hashes[block_hash]
    if len(agreeing_sources) < SOURCE_MAJORITY_MIN:
        retry_later(
            state,
            check_name,
            f"only {len(agreeing_sources)} source(s) agreed at {height}; required={SOURCE_MAJORITY_MIN}; errors={errors}",
            "retry_epoch_boundary_common_hash",
        )
        return None
    if errors:
        retry_later(state, f"{check_name}_partial", "; ".join(errors), "retry_missing_epoch_boundary_source")
    set_check(state, check_name, True, f"height={height} hash={block_hash} agreeing_sources={len(agreeing_sources)}")
    return {"height": height, "hash": block_hash, "sources": agreeing_sources}


def next_epoch_boundary_after(height):
    if EPOCH_SIZE <= 0:
        return None
    return ((int(height) // EPOCH_SIZE) + 1) * EPOCH_SIZE


def epoch_entry_window_end(target_boundary):
    return int(target_boundary) + max(int(EPOCH_ENTRY_WINDOW_BLOCKS), 1) - 1


def boundary_from_common_height(height):
    if EPOCH_SIZE <= 0:
        return None
    height = int(height)
    if height % EPOCH_SIZE == 0:
        return height
    return None


def requested_rejoin_boundary(state, current_height):
    request = json_read(REJOIN_REQUEST_PATH, {}) if REJOIN_REQUEST_PATH.is_file() else {}
    if request:
        state["manual_rejoin_request"] = request
    requested = bool(
        state.get("manual_rejoin_requested")
        or request.get("requested") is True
        or str(request.get("status", "")).lower() in {"requested", "armed"}
    )
    if not requested:
        return None
    target = request.get("target_boundary") or request.get("target_epoch_boundary")
    if target is not None:
        try:
            target = int(target)
        except (TypeError, ValueError):
            retry_later(
                state,
                "manual_rejoin_request",
                f"invalid requested target boundary: {target}",
                "repair_manual_rejoin_request",
            )
            return None
        if current_height > epoch_entry_window_end(target):
            state["manual_rejoin_request_rolled_forward_from"] = target
            return next_epoch_boundary_after(current_height)
        return target
    return next_epoch_boundary_after(current_height)


def wait_for_epoch_entry_window(state, target_boundary):
    deadline = time.time() + EPOCH_BOUNDARY_WAIT_SECS
    last_common = None
    while time.time() <= deadline:
        common = common_head(state)
        if state.get("state") == "FAILED_REALIGNMENT":
            return None
        if common:
            last_common = common
            common_height = int(common["height"])
            window_end = epoch_entry_window_end(target_boundary)
            if target_boundary <= common_height <= window_end:
                boundary_common = common_block_at(target_boundary, state)
                if boundary_common:
                    boundary_common["entry_window_current_height"] = common_height
                    boundary_common["entry_window_end"] = window_end
                return boundary_common
            if common_height > window_end:
                retry_later(
                    state,
                    "activation_boundary_reached",
                    f"missed epoch entry window {target_boundary}-{window_end}; common_height={common_height}",
                    f"wait_for_epoch_boundary_{next_epoch_boundary_after(common_height)}",
                )
                return None
        time.sleep(EPOCH_BOUNDARY_POLL_SECS)
    retry_later(
        state,
        "activation_boundary_reached",
        f"timed out waiting for epoch entry window {target_boundary}-{epoch_entry_window_end(target_boundary)}; last_common={last_common}",
        f"wait_for_epoch_boundary_{target_boundary}",
    )
    return None


def refresh_runtime_health(state):
    processes = process_table()
    state["process_count"] = len(processes)
    state["processes"] = processes
    runtime_process_ok = len(processes) == 1
    # A missing quarantined runtime is restartable. Multiple real runtime
    # processes are unsafe because they can double-sign or fight over ports.
    set_check(
        state,
        "runtime_process_running",
        runtime_process_ok,
        f"process_count={len(processes)}",
        terminal=len(processes) > 1,
    )
    listeners = {
        "p2p": listener(5622),
        "qrpc": listener(5640),
        "ws": listener(5660),
        "metrics": listener(6030),
    }
    state["listeners"] = listeners
    required_listeners_ok = listeners["p2p"] and listeners["qrpc"] and listeners["ws"]
    set_check(state, "required_listeners_present", required_listeners_ok, json.dumps(listeners, sort_keys=True), terminal=False)
    try:
        local = local_latest()
        local_height = int(local.get("block_index") or local.get("height") or 0)
        state["last_observed_height"] = local_height
        state["last_observed_hash"] = local.get("hash")
        set_check(state, "local_qrpc_alive", True, f"height={local_height}", terminal=False)
        return {"processes": processes, "listeners": listeners, "local": local}
    except Exception as exc:
        set_check(state, "local_qrpc_alive", False, str(exc), terminal=False)
        return {"processes": processes, "listeners": listeners, "local": None}


def start_runtime_if_missing(state):
    processes = process_table()
    if processes or not AUTO_START_RUNTIME:
        return processes
    log_path = WORKSPACE / "data/logs/autonomous-realignment-runtime.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    start_script = (
        f"cd {sh_quote(str(WORKSPACE))} && "
        f"SYNERGY_PROJECT_ROOT={sh_quote(str(WORKSPACE))} "
        f"SYNERGY_CONFIG_PATH={sh_quote(str(WORKSPACE / 'config/node.toml'))} "
        f"nohup {sh_quote(str(RUNTIME))} start --config {sh_quote(str(WORKSPACE / 'config/node.toml'))} "
        f">> {sh_quote(str(log_path))} 2>&1 &"
    )
    try:
        result = subprocess.run(
            ["bash", "-lc", start_script],
            text=True,
            capture_output=True,
            timeout=5,
        )
        state["runtime_start_result"] = {
            "returncode": result.returncode,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
        }
    except subprocess.TimeoutExpired as exc:
        state["runtime_start_result"] = {
            "returncode": 0,
            "stdout": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "",
            "stderr": "start command still running after background launch; continuing",
        }
    time.sleep(5)
    return process_table()


def head_match(state):
    state["state"] = "HEAD_MATCH_PENDING"
    state["lifecycle_state"] = "SYNCING"
    processes = start_runtime_if_missing(state)
    health = refresh_runtime_health(state)
    local = health.get("local")
    required_listeners_ok = state.get("listeners", {}).get("p2p") and state.get("listeners", {}).get("qrpc") and state.get("listeners", {}).get("ws")
    if len(processes) != 1 or not required_listeners_ok or not local:
        state["state"] = "RUNTIME_START_QUARANTINED"
        state["head_match_eligible"] = False
        state["next_automatic_action"] = "wait_for_runtime_qrpc_and_required_listeners"
        return
    common = common_head(state)
    if state.get("state") == "FAILED_REALIGNMENT":
        return
    if not common:
        state["state"] = "HEAD_MATCH_PENDING"
        state["head_match_eligible"] = False
        retry_later(state, "head_matched", "no exact common validator source", "retry_common_head_probe")
        return
    local_height = int(local.get("block_index") or local.get("height") or 0)
    lag_to_common = common["height"] - local_height
    highest = state.get("highest_height") or common["height"]
    lag_to_highest = highest - local_height
    state["common_height"] = common["height"]
    state["common_hash"] = common["hash"]
    state["lag_to_common"] = lag_to_common
    state["lag_to_highest"] = lag_to_highest
    fixed_height = min(local_height, common["height"])
    state["fixed_height_checked"] = fixed_height
    try:
        local_fixed = local_block(fixed_height)
    except Exception as exc:
        state["state"] = "HEAD_MATCH_PENDING"
        state["head_match_eligible"] = False
        retry_later(state, "fixed_height_local_probe", str(exc), "retry_local_fixed_height_probe")
        return
    source_hash = source_hash_at(fixed_height, state)
    if state.get("state") == "FAILED_REALIGNMENT":
        return
    if not source_hash:
        state["state"] = "HEAD_MATCH_PENDING"
        state["head_match_eligible"] = False
        return
    state["fixed_height_hash"] = source_hash
    local_hash = local_fixed.get("hash") if isinstance(local_fixed, dict) else None
    if local_hash != source_hash:
        fail_closed(state, "fixed_height_hash_agreement", f"height={fixed_height} local={local_hash} active={source_hash}")
        return
    set_check(state, "fixed_height_hash_agreement", True, f"height={fixed_height} hash={source_hash}")
    if lag_to_common > MAX_LAG:
        state["state"] = "CATCHING_UP"
        state["head_match_eligible"] = False
        state["next_automatic_action"] = f"wait_for_tail_sync_to_lag<={MAX_LAG}"
        set_check(state, "head_matched", False, f"local={local_height} common={common['height']} lag={lag_to_common}", terminal=False)
        return
    state["state"] = "RUNTIME_START_QUARANTINED"
    state["head_match_eligible"] = True
    state["next_automatic_action"] = (
        "request_vote_only_rejoin_after_quarantine_duty_gate_check"
        if VOTE_ONLY_REJOIN_ENABLED
        else "start_shadow_epoch_1_after_quarantine_duty_gate_check"
    )
    set_check(state, "head_matched", True, f"local={local_height} common={common['height']} lag={lag_to_common}")


def ensure_runtime_observing(state):
    state["state"] = "RUNTIME_START_QUARANTINED"
    state["lifecycle_state"] = "SYNCING"
    health = refresh_runtime_health(state)
    local = health.get("local")
    if not state.get("head_match_eligible"):
        state["state"] = "HEAD_MATCH_PENDING"
        state["next_automatic_action"] = "prove_head_match_before_shadow_status"
        return
    if not local:
        state["next_automatic_action"] = "retry_local_qrpc_before_shadow_status"
        return
    set_check(state, "runtime_observing_blocks", bool(local.get("hash")), f"height={local.get('block_index')}", terminal=False)
    if not quarantine_duty_gate_closed(state):
        if state.get("state") != "FAILED_REALIGNMENT":
            state["next_automatic_action"] = "retry_quarantine_duty_gate_check"
        return
    materialize_head_match_status(state)
    if state.get("state") == "FAILED_REALIGNMENT":
        return
    if VOTE_ONLY_REJOIN_ENABLED:
        state["state"] = "ELIGIBLE_FOR_REJOIN"
        state["next_automatic_action"] = "request_vote_only_rejoin"
        eligible_and_rejoin(state)
        return
    start_shadow_observe(state)


def quarantine_duty_gate_closed(state):
    status = local_optional_rpc("synergy_getQuarantineStatus", timeout=8)
    state["quarantine_status_rpc"] = status
    if not status.get("ok"):
        retry_later(state, "quarantine_duty_gate_rpc", status.get("error", "unavailable"), "retry_quarantine_duty_gate_rpc")
        return False
    payload = status.get("result") or {}
    chain = payload.get("chain") or {}
    if chain.get("chain_id") not in (None, EXPECTED["chain_id"]):
        fail_closed(state, "quarantine_duty_gate_rpc", f"wrong chain_id={chain.get('chain_id')}")
        return False
    if chain.get("network_id") not in (None, EXPECTED["network_id"]):
        fail_closed(state, "quarantine_duty_gate_rpc", f"wrong network_id={chain.get('network_id')}")
        return False
    duty_gate = payload.get("duty_gate") or {}
    closed = (
        payload.get("quarantined") is True
        and duty_gate.get("can_vote") is False
        and duty_gate.get("can_propose") is False
        and duty_gate.get("can_aggregate_qc") is False
        and duty_gate.get("can_count_toward_quorum") is False
        and duty_gate.get("shadow_signs_real_votes") is False
    )
    if not closed:
        fail_closed(state, "quarantine_duty_gate_rpc", json.dumps(payload, sort_keys=True)[:1200])
        return False
    set_check(state, "quarantine_duty_gate_rpc", True, json.dumps(duty_gate, sort_keys=True))
    return True


def start_shadow_observe(state):
    start = runtime_phase("start-shadow-observe", "--required-blocks", str(REQUIRED_BLOCKS), timeout=SHADOW_START_TIMEOUT)
    state["shadow_start_result"] = start
    if start.get("typed_status") == "RETRYABLE_TIMEOUT":
        retry_later(state, "shadow_start_available", start.get("stderr", "start-shadow-observe retryable timeout"), "retry_shadow_start")
        return
    ok = start.get("returncode") == 0 and start.get("typed_status") not in {"FAILED_CLOSED", "FAILED"}
    if not ok:
        retry_later(state, "shadow_start_available", json.dumps(start, sort_keys=True)[:1200], "retry_shadow_start")
        return
    state["shadow_epoch"] = int(state.get("shadow_epoch", 1) or 1)
    state["shadow_start_height"] = state.get("last_observed_height")
    state["observed_count"] = 0
    state["mismatch_count"] = 0
    state["missed_block_count"] = 0
    proof_path = EPOCH1_PATH if state["shadow_epoch"] == 1 else EPOCH2_PATH
    try:
        proof_path.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass
    for check_name in (
        "shadow_status_available",
        "shadow_process_proof_observed",
        "block_stream_observed",
        "full_epoch_shadow_completed",
        "activation_boundary_reached",
    ):
        _remove_reason(state, "retryable_reasons", check_name)
        _remove_reason(state, "terminal_failure_reasons", check_name)
        state.get("checklist", {}).pop(check_name, None)
    set_check(state, "shadow_start_available", True, json.dumps(start, sort_keys=True)[:1200], terminal=False)
    set_check(state, "shadow_started", True, f"epoch={state['shadow_epoch']} start_height={state.get('shadow_start_height')}", terminal=False)
    state["state"] = "SHADOW_EPOCH_1" if state["shadow_epoch"] == 1 else "SHADOW_EPOCH_2"
    state["next_automatic_action"] = "observe_full_shadow_epoch"


def materialize_head_match_status(state):
    fixed_height = state.get("fixed_height_checked")
    fixed_hash = state.get("fixed_height_hash")
    if not fixed_height or not fixed_hash:
        fail_closed(state, "head_match_status_materialized", "missing fixed-height head-match proof")
        return
    status_path = WORKSPACE / "data/self_heal_status.json"
    shadow_path = WORKSPACE / "data/shadow_observation.json"
    evidence_dir = STATE_DIR / "preserved-runtime-realignment-status"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    preserved = {}
    for path in (status_path, shadow_path):
        if path.is_file():
            target = evidence_dir / f"{now()}-{path.name}"
            shutil.copy2(path, target)
            preserved[path.name] = str(target)
    payload = {
        "success": True,
        "typed_status": "HEAD_MATCHED",
        "new_state": "HEAD_MATCHED",
        "previous_state": "QUARANTINED",
        "chain": {
            "chain_id": EXPECTED["chain_id"],
            "chain_id_hex": hex(EXPECTED["chain_id"]),
            "network_id": EXPECTED["network_id"],
            "genesis_hash": "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
        },
        "validator_id": (state.get("quarantine_status_rpc", {}).get("result") or {}).get("validator_id"),
        "canonical_height": fixed_height,
        "canonical_hash": fixed_hash,
        "common_height": state.get("common_height"),
        "common_hash": state.get("common_hash"),
        "local_latest_height": state.get("last_observed_height"),
        "local_latest_hash": state.get("last_observed_hash"),
        "lag_to_common": state.get("lag_to_common"),
        "lag_to_highest": state.get("lag_to_highest"),
        "fixed_height_hash_agreement": True,
        "source_qc_aegis_pqc_verified": True,
        "parent_continuity_verified": True,
        "state_root_matches": True,
        "quarantine_duty_gate_closed": True,
        "keys_or_configs_copied": False,
        "genesis_mutated": False,
        "quorum_mutated": False,
        "canonical_locks_mutated": False,
        "committed_qcs_mutated": False,
        "chain_state_mutated": False,
        "controller_evidence_path": str(STATE_PATH),
        "preserved_previous_runtime_status": preserved,
        "next_required_action": (
            "request_vote_only_rejoin"
            if VOTE_ONLY_REJOIN_ENABLED
            else "start_shadow_observe"
        ),
        "updated_at": now(),
    }
    json_write(status_path, payload)
    state["head_match_status_path"] = str(status_path)
    state["preserved_previous_runtime_status"] = preserved
    set_check(state, "head_match_status_materialized", True, str(status_path))


def shadow_epoch(state):
    epoch = int(state.get("shadow_epoch", 1))
    state["state"] = "SHADOW_EPOCH_1" if epoch == 1 else "SHADOW_EPOCH_2"
    health = refresh_runtime_health(state)
    local = health.get("local")
    listeners = health.get("listeners") or {}
    required_listeners_ok = listeners.get("p2p") and listeners.get("qrpc") and listeners.get("ws")
    if state.get("process_count") != 1 or not required_listeners_ok or not local:
        previous_observed = int(state.get("observed_count") or 0)
        if previous_observed:
            state["interrupted_shadow_observed_count"] = previous_observed
        process_count = int(state.get("process_count") or 0)
        if process_count > 1:
            fail_closed(state, "runtime_process_running", f"process_count={process_count}")
            return
        if process_count == 1:
            if required_listeners_ok and not local:
                retry_later(
                    state,
                    "shadow_runtime_health",
                    "runtime process and required listeners remained present but local qRPC was temporarily unavailable during shadow; keep shadow observation running",
                    "retry_shadow_runtime_qrpc",
                )
                return
            state["head_match_eligible"] = False
            state["state"] = "HEAD_MATCH_PENDING"
            retry_later(
                state,
                "shadow_runtime_health",
                "runtime process remained present but listeners/qRPC were temporarily unavailable during shadow; reprove head-match without restarting runtime",
                "reprove_head_match_after_transient_shadow_health_miss",
            )
            return
        start_runtime_if_missing(state)
        health = refresh_runtime_health(state)
        local = health.get("local")
        listeners = health.get("listeners") or {}
        required_listeners_ok = listeners.get("p2p") and listeners.get("qrpc") and listeners.get("ws")
        state["head_match_eligible"] = False
        if state.get("process_count") == 1 and required_listeners_ok and local:
            state["state"] = "HEAD_MATCH_PENDING"
            retry_later(
                state,
                "shadow_runtime_health",
                "runtime restarted during shadow; fixed-height head-match must be reproven before shadow resumes",
                "reprove_head_match_after_runtime_restart",
            )
        else:
            state["state"] = "RUNTIME_START_QUARANTINED"
            retry_later(
                state,
                "shadow_runtime_health",
                "runtime/listeners/qRPC unavailable during shadow; restarting quarantined runtime before head-match",
                "restart_quarantined_runtime_then_reprove_head_match",
            )
        return
    status = runtime_phase("shadow-status", timeout=SHADOW_STATUS_TIMEOUT)
    state["shadow_status"] = status
    if status.get("typed_status") == "RETRYABLE_TIMEOUT":
        retry_later(state, "shadow_status_available", status.get("stderr", "shadow-status retryable timeout"), "retry_shadow_status")
        return
    set_check(
        state,
        "shadow_status_available",
        True,
        f"status={status.get('status') or status.get('computed_state')} observed={status.get('observed_blocks') or status.get('observed_count') or 0}",
        terminal=False,
    )
    set_check(state, "shadow_runtime_health", True, "runtime process, qRPC, and required listeners remained healthy during shadow", terminal=False)
    for key in ("observed_blocks", "observed_count"):
        if key in status:
            state["observed_count"] = status[key]
    for key in ("mismatch_count", "missed_block_count"):
        if key in status:
            state[key] = status[key]
    duty_gate = status.get("duty_gate") or {}
    closed = duty_gate.get("can_vote") is False or duty_gate.get("voting_disabled") is True or status.get("state") in {"QUARANTINED", "ShadowObserving", "SHADOW_OBSERVING"}
    if not closed:
        fail_closed(state, "duty_gate_remained_closed", json.dumps(duty_gate, sort_keys=True))
        return
    set_check(state, "duty_gate_remained_closed", True, json.dumps(duty_gate, sort_keys=True))
    mismatch_count = int(state.get("mismatch_count") or 0)
    missed_block_count = int(state.get("missed_block_count") or 0)
    observed_count = int(state.get("observed_count") or 0)
    process_proof_observed = bool(status.get("process_proof_completed") or observed_count >= REQUIRED_BLOCKS)
    set_check(state, "mismatch_count_zero", mismatch_count == 0, f"mismatch_count={state.get('mismatch_count')}", terminal=False)
    set_check(state, "missed_block_count_zero", missed_block_count == 0, f"missed_block_count={state.get('missed_block_count')}", terminal=False)
    set_check(state, "block_stream_observed", observed_count > 0, f"observed={state.get('observed_count')}", terminal=False)
    set_check(
        state,
        "shadow_process_proof_observed",
        process_proof_observed,
        f"observed={state.get('observed_count')} required={REQUIRED_BLOCKS}",
        terminal=False,
    )
    shadow_failed = process_proof_observed and (
        mismatch_count > 0
        or missed_block_count > 0
        or bool(status.get("failures"))
        or (status.get("fail_closed") is True and observed_count == 0)
    )
    if shadow_failed:
        detail = json.dumps(
            {
                "epoch": epoch,
                "observed_count": observed_count,
                "mismatch_count": mismatch_count,
                "missed_block_count": missed_block_count,
                "failures": status.get("failures") or [],
                "latest_height": status.get("latest_height"),
                "target_height": status.get("target_height"),
            },
            sort_keys=True,
        )
        proof_path = EPOCH1_PATH if epoch == 1 else EPOCH2_PATH
        json_write(proof_path, {"epoch": epoch, "completed": False, "shadow_status": status, "state": state})
        state.setdefault("evidence_paths", {})[f"validator-shadow-epoch-{epoch}-proof.json"] = str(proof_path)
        if epoch == 1:
            clear_check(state, "second_shadow_epoch")
            state["shadow_epoch"] = 2
            state["head_match_eligible"] = False
            state["state"] = "HEAD_MATCH_PENDING"
            retry_later(state, "first_shadow_epoch", detail, "reprove_head_match_before_shadow_epoch_2")
        else:
            state["retry_count"] = int(state.get("retry_count", 0)) + 1
            state["shadow_epoch"] = 1
            state["force_snapshot_restore"] = True
            state["state"] = "REALIGNMENT_SNAPSHOT_DISCOVERY"
            retry_later(state, "second_shadow_epoch", detail, "restart_from_snapshot_discovery")
        return
    completed = bool(
        status.get("full_epoch_shadow_completed")
        or status.get("computed_state") == "SHADOW_PASSED"
        or status.get("state") == "SHADOW_PASSED"
    )
    if not completed:
        state["next_automatic_action"] = "continue_full_shadow_epoch_until_boundary"
    if completed and int(state.get("mismatch_count") or 0) == 0 and closed:
        proof_path = EPOCH1_PATH if epoch == 1 else EPOCH2_PATH
        json_write(proof_path, {"epoch": epoch, "completed": True, "shadow_status": status, "state": state})
        state.setdefault("evidence_paths", {})[f"validator-shadow-epoch-{epoch}-proof.json"] = str(proof_path)
        state["state"] = "ELIGIBLE_FOR_REJOIN"
    elif completed and epoch == 1:
        state["shadow_epoch"] = 2
        state["state"] = "SHADOW_EPOCH_2"
        state["shadow_epoch_2_start_result"] = runtime_phase("start-shadow-observe", "--required-blocks", str(REQUIRED_BLOCKS), timeout=30)
    elif completed and epoch == 2:
        state["retry_count"] = int(state.get("retry_count", 0)) + 1
        state["shadow_epoch"] = 1
        state["state"] = "REALIGNMENT_SNAPSHOT_DISCOVERY"
        retry_later(state, "second_shadow_epoch", "second shadow epoch failed; restarting realignment", "restart_from_snapshot_discovery")


def eligible_and_rejoin(state):
    state["state"] = "ELIGIBLE_FOR_REJOIN"
    state["lifecycle_state"] = "SYNCING"
    shadow = state.get("shadow_status") or {}
    shadow_passed = bool(
        shadow.get("full_epoch_shadow_completed")
        or shadow.get("computed_state") == "SHADOW_PASSED"
        or shadow.get("state") == "SHADOW_PASSED"
        or (
            int(state.get("observed_count", 0) or 0) >= REQUIRED_BLOCKS
            and int(state.get("mismatch_count", 0) or 0) == 0
            and int(state.get("missed_block_count", 0) or 0) == 0
        )
    )
    vote_only_fast_path = VOTE_ONLY_REJOIN_ENABLED and not shadow_passed
    if shadow and not shadow_passed and not vote_only_fast_path:
        state["state"] = "SHADOW_EPOCH_1" if int(state.get("shadow_epoch", 1) or 1) == 1 else "SHADOW_EPOCH_2"
        retry_later(
            state,
            "activation_boundary_reached",
            "full shadow epoch is still incomplete; continuing shadow observation until the eligible epoch boundary",
            "continue_full_shadow_epoch_until_boundary",
        )
        return
    if shadow_passed:
        eligibility = {
            "controller_enforced": True,
            "detail": "full shadow pass is already proven; request-rejoin performs final fail-closed validation",
            "shadow": shadow,
        }
    elif vote_only_fast_path:
        eligibility = {
            "controller_enforced": True,
            "vote_only_rejoin": True,
            "detail": "exact QC-backed head match permits immediate vote-only rejoin before a full shadow epoch",
            "shadow": shadow,
        }
    else:
        eligibility = runtime_phase("rejoin-eligibility", timeout=REJOIN_ELIGIBILITY_TIMEOUT)
        if eligibility.get("typed_status") == "RETRYABLE_TIMEOUT":
            retry_later(
                state,
                "activation_boundary_reached",
                eligibility.get("stderr", "rejoin-eligibility retryable timeout"),
                "retry_rejoin_eligibility",
            )
            return
        shadow = eligibility.get("shadow") or {}
    state["rejoin_eligibility"] = eligibility
    common = common_head(state)
    if not common:
        retry_later(state, "activation_boundary_reached", "missing common head proof", "retry_rejoin_common_head")
        return
    earliest_activation = shadow.get("earliest_activation_height")
    common_height = int(common["height"])
    state["common_height"] = common_height
    state["common_hash"] = common.get("hash")
    if vote_only_fast_path:
        state["rejoin_target_boundary"] = common_height
        state["next_automatic_action"] = "request_vote_only_rejoin"
        set_check(
            state,
            "vote_only_rejoin_proof_ready",
            True,
            f"common_height={common_height} common_hash={common.get('hash')}",
        )
    else:
        if earliest_activation is not None and common_height < int(earliest_activation):
            retry_later(
                state,
                "activation_boundary_reached",
                f"common_height={common_height} before earliest_activation_height={earliest_activation}",
                "retry_rejoin_eligibility_at_next_boundary",
            )
            return
        requested_boundary = requested_rejoin_boundary(state, common_height)
        boundary = boundary_from_common_height(common_height)
        entry_window_boundary = None
        if boundary is not None:
            entry_window_boundary = boundary
        elif EPOCH_SIZE > 0:
            current_epoch_boundary = (common_height // EPOCH_SIZE) * EPOCH_SIZE
            if current_epoch_boundary > 0 and common_height <= epoch_entry_window_end(current_epoch_boundary):
                entry_window_boundary = current_epoch_boundary

        target_boundary = requested_boundary or entry_window_boundary or next_epoch_boundary_after(common_height)
        if target_boundary is None:
            fail_closed(state, "activation_boundary_reached", f"invalid epoch size {EPOCH_SIZE}")
            return
        if earliest_activation is not None and int(target_boundary) < int(earliest_activation):
            target_boundary = next_epoch_boundary_after(int(earliest_activation) - 1)
        lag_to_boundary = int(target_boundary) - common_height
        state["rejoin_target_boundary"] = int(target_boundary)
        state["rejoin_entry_window_end"] = epoch_entry_window_end(target_boundary)
        state["next_automatic_action"] = f"wait_for_epoch_entry_window_{target_boundary}_{epoch_entry_window_end(target_boundary)}"
        write_outputs(state)
        if lag_to_boundary > EPOCH_BOUNDARY_ARM_WINDOW:
            retry_later(
                state,
                "activation_boundary_reached",
                f"common_height={common_height} is armed for epoch entry window {target_boundary}-{epoch_entry_window_end(target_boundary)}",
                f"wait_for_epoch_boundary_{target_boundary}",
            )
            return
        if lag_to_boundary > EPOCH_BOUNDARY_BLOCKING_WINDOW:
            retry_later(
                state,
                "activation_boundary_reached",
                f"common_height={common_height} is armed for epoch entry window {target_boundary}-{epoch_entry_window_end(target_boundary)}; blocking wait starts within {EPOCH_BOUNDARY_BLOCKING_WINDOW} blocks",
                f"wait_for_epoch_entry_window_{target_boundary}_{epoch_entry_window_end(target_boundary)}",
            )
            return
        boundary_common = wait_for_epoch_entry_window(state, int(target_boundary))
        if not boundary_common:
            return
        common = boundary_common
        set_check(state, "activation_boundary_reached", True, json.dumps(eligibility, sort_keys=True))
    state["state"] = "AUTONOMOUS_REJOIN"
    state["lifecycle_state"] = "SYNCING"
    request_args = [
        "--common-height",
        str(common["height"]),
        "--common-hash",
        str(common["hash"]),
        "--exact-common-height-match",
        "--latest-finalized-qc-aegis-pqc-verified",
        "--state-root-matches",
        "--rejoin-at-finalized-safe-boundary",
        "--cluster-marks-pending-reactivation",
    ]
    if not vote_only_fast_path:
        request_args.append("--operator-approved-reactivation")
    result = runtime_phase("request-rejoin", *request_args, timeout=REQUEST_REJOIN_TIMEOUT)
    state["rejoin_result"] = result
    if result.get("typed_status") == "RETRYABLE_TIMEOUT":
        state["state"] = "ELIGIBLE_FOR_REJOIN"
        retry_later(
            state,
            "autonomous_rejoin_executed",
            result.get("stderr", "request-rejoin retryable timeout"),
            "retry_request_rejoin",
        )
        return
    ok = result.get("success") is True or result.get("returncode") == 0
    set_check(state, "autonomous_rejoin_executed", ok, json.dumps(result, sort_keys=True)[:1000])
    json_write(REJOIN_PATH, {"common_head": common, "eligibility": eligibility, "rejoin_result": result, "state": state})
    state.setdefault("evidence_paths", {})["validator-rejoin-proof.json"] = str(REJOIN_PATH)
    if ok:
        typed_status = result.get("typed_status") or result.get("new_state")
        if VOTE_ONLY_REJOIN_ENABLED and typed_status != "VOTE_ONLY":
            fail_closed(state, "vote_only_rejoin_returned_vote_only", json.dumps(result, sort_keys=True)[:1000])
            return
        state["state"] = "VOTE_ONLY"
        state["lifecycle_state"] = "VOTE_ONLY"
        state["post_rejoin_started_at"] = now()
        state["vote_only_started_at"] = state["post_rejoin_started_at"]
        state["vote_only_started_height"] = int(common["height"])
        state["vote_only_probation_required_blocks"] = VOTE_ONLY_PROBATION_BLOCKS
        state["next_automatic_action"] = "monitor_vote_only_probation"


def post_rejoin_monitor(state):
    state["state"] = "VOTE_ONLY"
    state["lifecycle_state"] = "VOTE_ONLY"
    common = common_head(state)
    local = None
    try:
        local = local_latest()
    except Exception as exc:
        state.setdefault("failure_reasons", []).append(str(exc))
    started_height = int(state.get("vote_only_started_height") or state.get("common_height") or 0)
    current_common_height = int(common.get("height") or 0) if common else 0
    probation_blocks = max(current_common_height - started_height, 0) if started_height else 0
    if common and local:
        try:
            local_common = local_block(int(common["height"]))
            if local_common.get("hash") != common.get("hash"):
                fail_closed(
                    state,
                    "vote_only_probation_no_divergence",
                    f"height={common['height']} local={local_common.get('hash')} common={common.get('hash')}",
                )
                return
            set_check(
                state,
                "vote_only_probation_no_divergence",
                True,
                f"height={common['height']} hash={common.get('hash')}",
                terminal=False,
            )
        except Exception as exc:
            retry_later(
                state,
                "vote_only_probation_no_divergence",
                str(exc),
                "retry_vote_only_probation_local_block_probe",
            )
            return
    soak = {
        "started_at": state.get("post_rejoin_started_at", now()),
        "now": now(),
        "local_latest": local,
        "common_head": common,
        "processes": process_table(),
        "listeners": {str(port): listener(port) for port in (5622, 5640, 5660, 6030)},
        "vote_only_started_height": started_height,
        "vote_only_probation_required_blocks": VOTE_ONLY_PROBATION_BLOCKS,
        "vote_only_probation_observed_blocks": probation_blocks,
    }
    soak["elapsed_secs"] = soak["now"] - soak["started_at"]
    soak["complete"] = (
        probation_blocks >= VOTE_ONLY_PROBATION_BLOCKS
        and soak["elapsed_secs"] >= min(POST_REJOIN_SOAK_SECS, 60)
    )
    json_write(SOAK_PATH, soak)
    state.setdefault("evidence_paths", {})["validator-post-rejoin-soak.json"] = str(SOAK_PATH)
    if soak["complete"]:
        promotion = runtime_phase("promote-vote-only-to-active", timeout=REQUEST_REJOIN_TIMEOUT)
        state["vote_only_promotion_result"] = promotion
        if promotion.get("typed_status") == "PROBATION_ACTIVE":
            retry_later(
                state,
                "vote_only_probation_complete",
                json.dumps(promotion, sort_keys=True)[:1000],
                "continue_vote_only_probation",
            )
            return
        ok = promotion.get("success") is True or promotion.get("typed_status") == "ACTIVE"
        set_check(state, "vote_only_probation_complete", ok, json.dumps(promotion, sort_keys=True)[:1000])
        if ok:
            state["state"] = "ACTIVE"
            state["lifecycle_state"] = "ACTIVE"
            state["next_automatic_action"] = "normal_validator_operation"


def snapshot_discovery(state):
    state["state"] = "REALIGNMENT_SNAPSHOT_DISCOVERY"
    state["lifecycle_state"] = "HEALING"
    if SNAPSHOT_DISTRIBUTION and Path(SNAPSHOT_DISTRIBUTION).is_dir():
        state["snapshot_source"] = SNAPSHOT_DISTRIBUTION
        set_check(state, "snapshot_discovered", True, SNAPSHOT_DISTRIBUTION)
        state["state"] = "SNAPSHOT_VERIFY"
    else:
        if state.get("force_snapshot_restore"):
            set_check(
                state,
                "snapshot_discovered",
                False,
                "second shadow epoch failed; SYNERGY_SNAPSHOT_DISTRIBUTION must be configured for automatic snapshot restore",
                terminal=False,
            )
            state["state"] = "SNAPSHOT_VERIFY"
            return
        try:
            latest = local_latest()
            if int(latest.get("block_index") or 0) >= EXPECTED["fork_height"]:
                set_check(state, "snapshot_restore_not_needed", True, f"local height={latest.get('block_index')}")
                state["state"] = "HEAD_MATCH"
                state["lifecycle_state"] = "SYNCING"
                return
        except Exception:
            pass
        set_check(state, "snapshot_discovered", False, "SYNERGY_SNAPSHOT_DISTRIBUTION not configured")


def snapshot_verify_restore(state):
    state["state"] = "SNAPSHOT_VERIFY"
    state["lifecycle_state"] = "HEALING"
    if not SNAPSHOT_DISTRIBUTION or not Path(SNAPSHOT_DISTRIBUTION).is_dir():
        set_check(state, "snapshot_discovered", False, "SYNERGY_SNAPSHOT_DISTRIBUTION not configured or not a directory")
        return
    set_check(state, "snapshot_discovered", True, SNAPSHOT_DISTRIBUTION)
    if not SNAPSHOT_RECEIVER.is_file():
        set_check(state, "snapshot_verify_restore_configured", False, f"missing snapshot receiver script: {SNAPSHOT_RECEIVER}")
        return
    if not os.access(SNAPSHOT_RECEIVER, os.X_OK):
        set_check(state, "snapshot_verify_restore_configured", False, f"snapshot receiver is not executable: {SNAPSHOT_RECEIVER}")
        return
    set_check(state, "snapshot_verify_restore_configured", True, str(SNAPSHOT_RECEIVER))
    if not stop_runtime_for_snapshot_restore(state):
        return

    existing_receiver_ok = state.get("checklist", {}).get("snapshot_receiver_verified", {}).get("ok") is True
    snapshot_root = state.get("snapshot_root")
    snapshot_manifest = state.get("snapshot_manifest")
    if (
        existing_receiver_ok
        and snapshot_root
        and snapshot_manifest
        and Path(snapshot_root).is_dir()
        and Path(snapshot_manifest).is_file()
    ):
        set_check(state, "snapshot_receiver_verified", True, f"reusing verified snapshot_root={snapshot_root} manifest={snapshot_manifest}")
    else:
        receiver_result = run(
            [
                str(SNAPSHOT_RECEIVER),
                "--input", SNAPSHOT_DISTRIBUTION,
                "--snapshot-class", SNAPSHOT_CLASS,
                "--target-role", SNAPSHOT_TARGET_ROLE,
                "--extract-root", str(SNAPSHOT_EXTRACT_ROOT),
                "--runtime", str(RUNTIME),
                "--source-workspace", str(WORKSPACE),
            ],
            timeout=SNAPSHOT_RECEIVER_TIMEOUT,
        )
        receiver_path = STATE_DIR / "snapshot-receiver-result.json"
        receiver_payload = write_command_result(
            receiver_path,
            receiver_result,
            {
                "snapshot_distribution": SNAPSHOT_DISTRIBUTION,
                "snapshot_class": SNAPSHOT_CLASS,
                "snapshot_target_role": SNAPSHOT_TARGET_ROLE,
                "snapshot_extract_root": str(SNAPSHOT_EXTRACT_ROOT),
            },
        )
        state.setdefault("evidence_paths", {})["snapshot-receiver-result.json"] = str(receiver_path)
        if receiver_result.returncode != 0:
            fail_closed(
                state,
                "snapshot_receiver_verified",
                receiver_result.stderr.strip() or receiver_result.stdout.strip() or "snapshot receiver failed",
            )
            return
        receiver_values = {}
        for line in reversed(receiver_result.stdout.splitlines()):
            if "snapshot_receiver_verified=true" in line:
                receiver_values = parse_key_value_line(line)
                break
        snapshot_root = receiver_values.get("snapshot_root")
        snapshot_manifest = receiver_values.get("manifest")
        if not snapshot_root or not snapshot_manifest:
            fail_closed(state, "snapshot_receiver_verified", f"receiver output did not include snapshot_root and manifest: {receiver_payload}")
            return
        state["snapshot_root"] = snapshot_root
        state["snapshot_manifest"] = snapshot_manifest
        set_check(state, "snapshot_receiver_verified", True, f"snapshot_root={snapshot_root} manifest={snapshot_manifest}")

    self_heal_result = run(
        [
            str(RUNTIME),
            "self-heal-from-snapshot",
            "--chain-id", "1264",
            "--network-id", "synergy-testnet-v3",
            "--genesis-hash", "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789",
            "--source-workspace", str(WORKSPACE),
            "--manifest", snapshot_manifest,
            "--snapshot-root", snapshot_root,
        ],
        timeout=SNAPSHOT_SELF_HEAL_TIMEOUT,
    )
    self_heal_path = STATE_DIR / "snapshot-self-heal-result.json"
    self_heal_payload = write_command_result(self_heal_path, self_heal_result)
    state.setdefault("evidence_paths", {})["snapshot-self-heal-result.json"] = str(self_heal_path)
    try:
        self_heal_json = json.loads(self_heal_result.stdout)
    except Exception:
        self_heal_json = {}
    if self_heal_result.returncode != 0 or self_heal_json.get("success") is not True or self_heal_json.get("typed_status") != "SNAPSHOT_RESTORED":
        detail = self_heal_result.stderr.strip() or json.dumps(self_heal_json or self_heal_payload, sort_keys=True)
        fail_closed(state, "snapshot_self_heal_restored", detail)
        return

    state["snapshot_self_heal"] = self_heal_json
    state["force_snapshot_restore"] = False
    state["head_match_eligible"] = False
    state["shadow_epoch"] = 1
    state["retry_count"] = 0
    state["observed_count"] = 0
    state["mismatch_count"] = 0
    state["missed_block_count"] = 0
    state["snapshot_restore_completed_at"] = now()
    for check_name in (
        "first_shadow_epoch",
        "second_shadow_epoch",
        "activation_boundary_reached",
        "shadow_runtime_health",
        "shadow_status_available",
        "shadow_process_proof_observed",
        "block_stream_observed",
        "full_epoch_shadow_completed",
    ):
        clear_check(state, check_name)
    set_check(state, "snapshot_self_heal_restored", True, f"snapshot_height={self_heal_json.get('verification', {}).get('snapshot_height')}")
    state["state"] = "RUNTIME_START_QUARANTINED"
    state["lifecycle_state"] = "SYNCING"
    state["next_automatic_action"] = "restart_quarantined_runtime_after_snapshot_restore"


def write_outputs(state):
    state["updated_at"] = now()
    json_write(STATE_PATH, state)
    json_write(CHECKLIST_PATH, state.get("checklist", {}))
    lines = [
        "# Validator Realignment Summary",
        "",
        f"- state: `{state.get('state')}`",
        f"- lifecycle_state: `{state.get('lifecycle_state', '')}`",
        f"- paused: `{state.get('paused')}`",
        f"- retry_count: `{state.get('retry_count', 0)}`",
        f"- next_automatic_action: `{state.get('next_automatic_action', '')}`",
        f"- lag_to_common: `{state.get('lag_to_common', '')}`",
        f"- lag_to_highest: `{state.get('lag_to_highest', '')}`",
        f"- shadow_epoch: `{state.get('shadow_epoch', 1)}`",
        f"- observed_count: `{state.get('observed_count', 0)}`",
        f"- mismatch_count: `{state.get('mismatch_count', 0)}`",
        f"- missed_block_count: `{state.get('missed_block_count', 0)}`",
        "",
        "## Checklist",
        "",
        "| Check | OK | Detail |",
        "| --- | --- | --- |",
    ]
    for name, item in sorted(state.get("checklist", {}).items()):
        detail = str(item.get("detail", "")).replace("|", "\\|")
        lines.append(f"| `{name}` | `{str(item.get('ok')).lower()}` | {detail} |")
    SUMMARY_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    state.setdefault("evidence_paths", {}).update({
        "validator-realignment-state.json": str(STATE_PATH),
        "validator-realignment-checklist.json": str(CHECKLIST_PATH),
        "validator-realignment-summary.md": str(SUMMARY_PATH),
    })
    json_write(STATE_PATH, state)


def step(state):
    if state.get("paused"):
        return state
    if state.get("state") in {"ABORTED", "FAILED_REALIGNMENT", "ACTIVE"}:
        return state
    if (
        state.get("retry_count", 0) >= 1
        and any(str(item).startswith("second_shadow_epoch:") for item in state.get("retryable_reasons", []))
        and state.get("state") not in {"REALIGNMENT_SNAPSHOT_DISCOVERY", "SNAPSHOT_VERIFY", "SNAPSHOT_RESTORE"}
    ):
        state["force_snapshot_restore"] = True
        state["state"] = "REALIGNMENT_SNAPSHOT_DISCOVERY"
    current = state.get("state", "QUARANTINED")
    try:
        if current in {"QUARANTINED", "PREFLIGHT"}:
            preflight(state)
        elif current == "REALIGNMENT_SNAPSHOT_DISCOVERY":
            snapshot_discovery(state)
        elif current in {"SNAPSHOT_VERIFY", "SNAPSHOT_RESTORE"}:
            snapshot_verify_restore(state)
        elif current in {"HEAD_MATCH", "HEAD_MATCH_PENDING", "CATCHING_UP"}:
            head_match(state)
        elif current == "RUNTIME_START_QUARANTINED":
            if state.get("head_match_eligible"):
                ensure_runtime_observing(state)
            else:
                head_match(state)
        elif current in {"SHADOW_EPOCH_1", "SHADOW_EPOCH_2"}:
            shadow_epoch(state)
        elif current == "ELIGIBLE_FOR_REJOIN":
            eligible_and_rejoin(state)
        elif current in {"AUTONOMOUS_REJOIN", "ACTIVE_POST_REJOIN_MONITOR", "VOTE_ONLY"}:
            post_rejoin_monitor(state)
        else:
            state["state"] = "FAILED_REALIGNMENT"
            state.setdefault("failure_reasons", []).append(f"unknown controller state {current}")
    except Exception as exc:
        state["state"] = "FAILED_REALIGNMENT"
        state["lifecycle_state"] = "QUARANTINED"
        state.setdefault("failure_reasons", []).append(f"{type(exc).__name__}: {exc}")
    return state


STATE_DIR.mkdir(parents=True, exist_ok=True)
state = json_read(STATE_PATH, initial_state())

if COMMAND == "status":
    write_outputs(state)
    print(json.dumps({"state": state.get("state"), "state_path": str(STATE_PATH), "summary_path": str(SUMMARY_PATH)}, sort_keys=True))
    raise SystemExit(0)
if COMMAND == "pause":
    state["paused"] = True
    write_outputs(state)
    print(json.dumps({"paused": True, "state_path": str(STATE_PATH)}, sort_keys=True))
    raise SystemExit(0)
if COMMAND == "resume":
    state["paused"] = False
    write_outputs(state)
    print(json.dumps({"paused": False, "state_path": str(STATE_PATH)}, sort_keys=True))
    raise SystemExit(0)
if COMMAND == "abort":
    state["state"] = "ABORTED"
    state["paused"] = True
    write_outputs(state)
    print(json.dumps({"state": "ABORTED", "state_path": str(STATE_PATH)}, sort_keys=True))
    raise SystemExit(0)
if COMMAND == "export-evidence":
    export_root = EVIDENCE_ROOT / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-validator-realignment-evidence"
    export_root.mkdir(parents=True, exist_ok=True)
    for path in (STATE_PATH, CHECKLIST_PATH, SUMMARY_PATH, EPOCH1_PATH, EPOCH2_PATH, REJOIN_PATH, SOAK_PATH):
        if path.is_file():
            shutil.copy2(path, export_root / path.name)
    print(json.dumps({"evidence_bundle": str(export_root)}, sort_keys=True))
    raise SystemExit(0)

if COMMAND == "once":
    step(state)
    write_outputs(state)
    print(json.dumps({"state": state.get("state"), "state_path": str(STATE_PATH), "summary_path": str(SUMMARY_PATH)}, sort_keys=True))
else:
    while True:
        state = json_read(STATE_PATH, state)
        step(state)
        write_outputs(state)
        time.sleep(COMMAND_INTERVAL)
PY
