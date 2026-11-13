#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  val5-fndsa-rejoin-workflow.sh [--phase preflight|shadow-start|eligibility|request-rejoin|post-rejoin-proof]

Default phase:
  preflight

Required for every phase:
  SYNERGY_EXPECTED_RUNTIME_SHA=<trusted release sha256>

Common environment:
  SYNERGY_WORKSPACE=$HOME/.synergy/testnet/nodes/validator-workspace
  SYNERGY_BINARY_NAME=synergy-testnet-linux-amd64
  SYNERGY_VAL5_VALIDATOR_ADDRESS=synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f
  SYNERGY_CONSENSUS_FORK_METADATA=<workspace>/config/consensus-fork-migration.json
  SYNERGY_VAL5_FNDSA_PRIVATE_KEY_FILE=<workspace>/config/validator/consensus.private.key
  SYNERGY_VAL5_FNDSA_PUBLIC_KEY_FILE=<workspace>/config/validator/consensus.public.key

Mutation guards:
  --phase shadow-start requires --operator-approved-shadow-start and --execute.
  --phase request-rejoin requires --operator-approved-rejoin, --execute,
  --common-height <height>, and --common-hash <hash>.

Output:
  Writes val5-rejoin-proof.json, val5-rejoin-proof.md, command transcript,
  preflight table, activation command, and phase-specific JSON under
  $SYNERGY_EVIDENCE_ROOT/<timestamp>-Val5-fndsa-rejoin-<phase>.
USAGE
}

phase="preflight"
execute=false
operator_approved_shadow_start=false
operator_approved_rejoin=false
common_height=""
common_hash=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      phase="${2:?--phase requires a value}"
      shift 2
      ;;
    --execute)
      execute=true
      shift
      ;;
    --dry-run)
      execute=false
      shift
      ;;
    --operator-approved-shadow-start)
      operator_approved_shadow_start=true
      shift
      ;;
    --operator-approved-rejoin)
      operator_approved_rejoin=true
      shift
      ;;
    --common-height)
      common_height="${2:?--common-height requires a value}"
      shift 2
      ;;
    --common-hash)
      common_hash="${2:?--common-hash requires a value}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$phase" in
  preflight|shadow-start|eligibility|request-rejoin|post-rejoin-proof) ;;
  *)
    echo "unsupported phase: $phase" >&2
    usage >&2
    exit 2
    ;;
esac

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
binary_name="${SYNERGY_BINARY_NAME:-synergy-testnet-linux-amd64}"
runtime_path="${SYNERGY_RUNTIME_PATH:-$workspace/bin/$binary_name}"
expected_runtime_sha="${SYNERGY_EXPECTED_RUNTIME_SHA:-}"
evidence_root="${SYNERGY_EVIDENCE_ROOT:-$HOME/synergy-testnet-evidence}"
python_bin="${PYTHON_BIN:-python3}"
chain_id="${SYNERGY_CHAIN_ID:-1264}"
network_id="${SYNERGY_NETWORK_ID:-synergy-testnet-v3}"
genesis_hash="${SYNERGY_GENESIS_HASH:-f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789}"
fork_height="${SYNERGY_FORK_HEIGHT:-204216}"
fork_parent_height="${SYNERGY_FORK_PARENT_HEIGHT:-204215}"
fork_parent_hash="${SYNERGY_FORK_PARENT_HASH:-e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816}"
old_consensus_algorithm="${SYNERGY_OLD_CONSENSUS_ALGORITHM:-FN-DSA}"
new_consensus_algorithm="${SYNERGY_NEW_CONSENSUS_ALGORITHM:-FN-DSA}"
expected_public_key_bytes="${SYNERGY_EXPECTED_FNDSA_PUBLIC_KEY_BYTES:-1793}"
expected_private_key_bytes="${SYNERGY_EXPECTED_FNDSA_PRIVATE_KEY_BYTES:-2305}"
val5_address="${SYNERGY_VAL5_VALIDATOR_ADDRESS:-synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f}"
fork_metadata="${SYNERGY_CONSENSUS_FORK_METADATA:-$workspace/config/consensus-fork-migration.json}"
private_key_file="${SYNERGY_VAL5_FNDSA_PRIVATE_KEY_FILE:-}"
public_key_file="${SYNERGY_VAL5_FNDSA_PUBLIC_KEY_FILE:-}"
qrpc_port="${SYNERGY_QRPC_PORT:-5640}"
ws_port="${SYNERGY_WS_PORT:-5660}"
p2p_port="${SYNERGY_P2P_PORT:-5622}"
metrics_port="${SYNERGY_METRICS_PORT:-6030}"
discovery_port="${SYNERGY_DISCOVERY_PORT:-5680}"
shadow_required_blocks="${SYNERGY_VAL5_SHADOW_REQUIRED_BLOCKS:-500}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
evidence="$evidence_root/${timestamp}-Val5-fndsa-rejoin-$phase"

mkdir -p "$evidence"
transcript="$evidence/command-transcript.txt"
gates_tsv="$evidence/preflight-table.tsv"
runtime_phase_json="$evidence/runtime-phase-output.json"
health_json="$evidence/local-health.json"
fork_json="$evidence/fork-metadata-validation.json"
key_json="$evidence/fndsa-key-validation.json"
activation_command="$evidence/activation-command.txt"
post_rejoin_table="$evidence/post-rejoin-health-table.tsv"

exec > >(tee -a "$transcript") 2>&1

printf 'gate\tstatus\tdetail\n' > "$gates_tsv"
printf 'check\tstatus\tdetail\n' > "$post_rejoin_table"

record_gate() {
  local gate="$1"
  local status="$2"
  local detail="$3"
  printf '%s\t%s\t%s\n' "$gate" "$status" "$detail" >> "$gates_tsv"
  printf '%s=%s %s\n' "$gate" "$status" "$detail"
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  else
    shasum -a 256 "$path" | awk '{print $1}'
  fi
}

runtime_processes() {
  local proc pid exe cwd cmd
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    pid="${proc##*/}"
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    [[ -n "$cmd" ]] || continue
    if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" || "$cmd" == *"$workspace"* ]]; then
      if [[ "$cmd" == *" start --config "* || "$exe" == "$runtime_path" ]]; then
        printf '%s\t%s\t%s\t%s\n' "$pid" "$exe" "$cwd" "$cmd"
      fi
    fi
  done
}

listener_present() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit found ? 0 : 1}'
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 1
  fi
}

qrpc_latest_block() {
  curl -fsS --max-time 5 \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}' \
    "http://127.0.0.1:${qrpc_port}"
}

append_json_gates() {
  local path="$1"
  "$python_bin" - "$path" "$gates_tsv" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
table = Path(sys.argv[2])
with table.open("a", encoding="utf-8") as handle:
    for check in payload.get("checks", []):
        handle.write(
            f"{check.get('gate','unknown')}\t{check.get('status','FAIL')}\t{check.get('detail','')}\n"
        )
PY
}

validate_basic_layout() {
  if [[ -n "$expected_runtime_sha" ]]; then
    record_gate "trusted_runtime_sha_input" "PASS" "trusted runtime sha supplied"
  else
    record_gate "trusted_runtime_sha_input" "FAIL" "SYNERGY_EXPECTED_RUNTIME_SHA is required"
  fi

  if [[ -d "$workspace" ]]; then
    record_gate "workspace_exists" "PASS" "$workspace"
  else
    record_gate "workspace_exists" "FAIL" "missing workspace $workspace"
  fi

  if [[ -d "$workspace/config" && -d "$workspace/data" ]]; then
    record_gate "workspace_structure" "PASS" "config and data directories exist"
  else
    record_gate "workspace_structure" "FAIL" "workspace must contain config and data directories"
  fi

  if [[ -f "$runtime_path" ]]; then
    local actual
    actual="$(sha256_file "$runtime_path")"
    if [[ "$actual" == "$expected_runtime_sha" ]]; then
      record_gate "runtime_sha" "PASS" "$actual"
    else
      record_gate "runtime_sha" "FAIL" "actual=$actual expected=$expected_runtime_sha"
    fi
    if [[ -x "$runtime_path" ]]; then
      record_gate "runtime_executable" "PASS" "$runtime_path"
    else
      record_gate "runtime_executable" "FAIL" "runtime is not executable: $runtime_path"
    fi
  else
    record_gate "runtime_exists" "FAIL" "missing runtime $runtime_path"
  fi
}

capture_stopped_state() {
  local process_file="$evidence/processes.tsv"
  runtime_processes > "$process_file" || true
  local process_count
  process_count="$(wc -l < "$process_file" | tr -d ' ')"
  if [[ "$process_count" == "0" ]]; then
    record_gate "val5_process_stopped" "PASS" "process_count=0"
  else
    record_gate "val5_process_stopped" "FAIL" "process_count=$process_count process_file=$process_file"
  fi

  local failed_listener=false
  local port label
  for label in p2p qrpc ws discovery metrics; do
    case "$label" in
      p2p) port="$p2p_port" ;;
      qrpc) port="$qrpc_port" ;;
      ws) port="$ws_port" ;;
      discovery) port="$discovery_port" ;;
      metrics) port="$metrics_port" ;;
    esac
    if listener_present "$port"; then
      record_gate "listener_absent_$label" "FAIL" "port=$port has a listener"
      failed_listener=true
    else
      record_gate "listener_absent_$label" "PASS" "port=$port"
    fi
  done
  if [[ "$failed_listener" == "true" ]]; then
    return 1
  fi
}

capture_running_health() {
  "$python_bin" - "$workspace" "$runtime_path" "$health_json" "$qrpc_port" "$p2p_port" "$ws_port" "$metrics_port" <<'PY'
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

workspace, runtime_path, out_path, qrpc_port, p2p_port, ws_port, metrics_port = sys.argv[1:8]

def run(command):
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=8)
    except Exception as exc:
        return exc

def listener(port):
    proc = run(["bash", "-lc", f"ss -ltn 2>/dev/null | awk '$4 ~ /:{port}$/ {{found=1}} END {{exit found ? 0 : 1}}'"])
    return getattr(proc, "returncode", 1) == 0

def qrpc():
    data = json.dumps({"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{qrpc_port}", data=data, headers={"content-type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return {"ok": True, "payload": json.loads(response.read().decode())}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

processes = []
for proc in Path("/proc").glob("[0-9]*"):
    try:
        pid = proc.name
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
    if cmd and (exe.startswith(str(Path(workspace) / "bin")) or cwd == workspace or workspace in cmd):
        if " start --config " in cmd or exe == runtime_path:
            processes.append({"pid": pid, "exe": exe, "cwd": cwd, "cmd": cmd})

payload = {
    "process_count": len(processes),
    "processes": processes,
    "listeners": {
        "p2p": listener(p2p_port),
        "qrpc": listener(qrpc_port),
        "ws": listener(ws_port),
        "metrics": listener(metrics_port),
    },
    "qrpc_latest_block": qrpc(),
}
Path(out_path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
  append_json_gates "$("$python_bin" - "$health_json" <<'PY'
import json
import sys
from pathlib import Path
payload = json.loads(Path(sys.argv[1]).read_text())
checks = []
checks.append({
    "gate": "post_rejoin_process_running",
    "status": "PASS" if payload.get("process_count", 0) > 0 else "FAIL",
    "detail": f"process_count={payload.get('process_count')}",
})
for name, present in payload.get("listeners", {}).items():
    checks.append({
        "gate": f"post_rejoin_listener_{name}",
        "status": "PASS" if present else "FAIL",
        "detail": f"listener_present={present}",
    })
qrpc = payload.get("qrpc_latest_block", {})
checks.append({
    "gate": "post_rejoin_qrpc_latest_block",
    "status": "PASS" if qrpc.get("ok") else "FAIL",
    "detail": "qRPC latest block returned" if qrpc.get("ok") else qrpc.get("error", "qRPC failed"),
})
tmp = Path(sys.argv[1]).with_suffix(".checks.json")
tmp.write_text(json.dumps({"checks": checks}, indent=2, sort_keys=True) + "\n")
print(tmp)
PY
)"
}

validate_quarantine() {
  local marker="$workspace/data/validator_quarantine.json"
  if [[ -f "$marker" ]]; then
    record_gate "quarantine_marker" "PASS" "$marker"
  else
    record_gate "quarantine_marker" "FAIL" "missing $marker"
  fi
}

validate_fork_metadata() {
  "$python_bin" - \
    "$fork_metadata" \
    "$fork_json" \
    "$fork_height" \
    "$fork_parent_height" \
    "$fork_parent_hash" \
    "$old_consensus_algorithm" \
    "$new_consensus_algorithm" \
    "$val5_address" \
    "$expected_public_key_bytes" <<'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

metadata_path = Path(sys.argv[1])
out_path = Path(sys.argv[2])
expected_fork_height = int(sys.argv[3])
expected_parent_height = int(sys.argv[4])
expected_parent_hash = sys.argv[5]
expected_old = sys.argv[6]
expected_new = sys.argv[7]
val5_address = sys.argv[8]
expected_public_key_bytes = int(sys.argv[9])

checks = []

def add(gate, ok, detail):
    checks.append({"gate": gate, "status": "PASS" if ok else "FAIL", "detail": detail})

if not metadata_path.is_file():
    add("fork_metadata_file", False, f"missing {metadata_path}")
    payload = {"ok": False, "checks": checks}
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    raise SystemExit(0)

payload = json.loads(metadata_path.read_text())
add("fork_metadata_file", True, str(metadata_path))
add("fork_height", payload.get("fork_height") == expected_fork_height, str(payload.get("fork_height")))
add("fork_parent_height", payload.get("parent_height") == expected_parent_height, str(payload.get("parent_height")))
add("fork_parent_hash", payload.get("parent_hash") == expected_parent_hash, str(payload.get("parent_hash")))
add("fork_chain_continuity_state_root", bool(payload.get("state_root")), "state_root present")
add("fork_old_consensus_algorithm", payload.get("old_consensus_algorithm") == expected_old, str(payload.get("old_consensus_algorithm")))
add("fork_new_consensus_algorithm", payload.get("new_consensus_algorithm") == expected_new, str(payload.get("new_consensus_algorithm")))
add("fork_parser_mode", payload.get("parser_mode") == "fail_closed", str(payload.get("parser_mode")))
registry = payload.get("new_validator_registry")
add("fork_registry_shape", isinstance(registry, list) and len(registry) >= 5, f"entries={len(registry) if isinstance(registry, list) else 'not-list'}")
val5 = None
bad_algorithms = []
ambiguous = {"pqc", "aegis", "auto", "default", "unknown", "", None}
for entry in registry or []:
    address = entry.get("validator_address") or entry.get("address")
    key_type = entry.get("consensus_key_type")
    if address == val5_address:
        val5 = entry
    if key_type != expected_new:
        bad_algorithms.append({"validator_address": address, "consensus_key_type": key_type})
    if isinstance(key_type, str) and key_type.lower() in ambiguous:
        bad_algorithms.append({"validator_address": address, "consensus_key_type": key_type})
add("fork_registry_all_fndsa", not bad_algorithms, json.dumps(bad_algorithms, sort_keys=True))
add("fork_registry_val5_entry", val5 is not None, val5_address)
expected_public = None
if val5:
    expected_public = val5.get("consensus_public_key") or ""
    if expected_public.startswith("fn-dsa:"):
        expected_public = expected_public.split(":", 1)[1]
    try:
        decoded = base64.b64decode(expected_public, validate=True)
    except Exception as exc:
        decoded = b""
        add("fork_registry_val5_public_key_base64", False, str(exc))
    else:
        add("fork_registry_val5_public_key_base64", True, "base64")
        add("fork_registry_val5_public_key_bytes", len(decoded) == expected_public_key_bytes, str(len(decoded)))
        payload["val5_registry_public_key_sha256"] = hashlib.sha256(decoded).hexdigest()
        payload["val5_registry_public_key_bytes"] = len(decoded)
payload["checks"] = checks
payload["metadata_path"] = str(metadata_path)
payload["ok"] = all(check["status"] == "PASS" for check in checks)
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
  append_json_gates "$fork_json"
}

validate_fndsa_key_material() {
  "$python_bin" - \
    "$workspace" \
    "$key_json" \
    "$fork_json" \
    "$private_key_file" \
    "$public_key_file" \
    "$expected_public_key_bytes" \
    "$expected_private_key_bytes" <<'PY'
import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

workspace = Path(sys.argv[1])
out_path = Path(sys.argv[2])
fork_path = Path(sys.argv[3])
private_arg = sys.argv[4].strip()
public_arg = sys.argv[5].strip()
expected_public_len = int(sys.argv[6])
expected_private_len = int(sys.argv[7])

checks = []

def add(gate, ok, detail):
    checks.append({"gate": gate, "status": "PASS" if ok else "FAIL", "detail": detail})

def candidates(kind):
    if kind == "private":
        names = [
            "config/validator/consensus.private.key",
            "config/validator/fndsa-consensus.private.key",
            "config/validator/fndsa.private.key",
            "keys/validator/consensus.private.key",
            "keys/fndsa-consensus/private.key",
            "keys/fndsa.private.key",
            "keys/fndsa_private.key",
        ]
    else:
        names = [
            "config/validator/consensus.public.key",
            "config/validator/public.key",
            "config/validator/fndsa-consensus.public.key",
            "config/validator/fndsa.public.key",
            "keys/validator/consensus.public.key",
            "keys/fndsa-consensus/public.key",
            "keys/fndsa.public.key",
            "keys/fndsa_public.key",
        ]
    return [workspace / name for name in names]

def resolve(path_arg, kind):
    paths = []
    if path_arg:
        paths.append(Path(path_arg))
    paths.extend(candidates(kind))
    for path in paths:
        if path.is_file():
            return path
    return None

def decode_value(raw):
    text = raw.decode("utf-8", errors="ignore").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            for key in (
                "public_key_base64",
                "private_key_base64",
                "public_key",
                "private_key",
                "consensus_public_key",
                "consensus_private_key",
            ):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return decode_value(value.strip().encode())
    if text.startswith("fn-dsa:"):
        text = text.split(":", 1)[1]
    compact = "".join(text.split())
    if compact:
        try:
            return base64.b64decode(compact, validate=True), "base64"
        except Exception:
            pass
        try:
            return bytes.fromhex(compact), "hex"
        except Exception:
            pass
    return raw, "raw"

fork = json.loads(fork_path.read_text()) if fork_path.is_file() else {}
expected_public_sha = fork.get("val5_registry_public_key_sha256")
private_path = resolve(private_arg, "private")
public_path = resolve(public_arg, "public")

private_info = None
if private_path is None:
    add("fndsa_private_key_file", False, "missing private key file")
else:
    raw = private_path.read_bytes()
    decoded, encoding = decode_value(raw)
    mode = stat.S_IMODE(private_path.stat().st_mode)
    private_info = {
        "path": str(private_path),
        "encoding": encoding,
        "decoded_bytes": len(decoded),
        "sha256": hashlib.sha256(decoded).hexdigest(),
        "file_mode_octal": oct(mode),
    }
    add("fndsa_private_key_file", True, str(private_path))
    add("fndsa_private_key_bytes", len(decoded) == expected_private_len, str(len(decoded)))
    add("fndsa_private_key_permissions", mode & 0o077 == 0, oct(mode))

public_info = None
if public_path is None:
    add("fndsa_public_key_file", False, "missing public key mirror for fork-registry match")
else:
    raw = public_path.read_bytes()
    decoded, encoding = decode_value(raw)
    public_sha = hashlib.sha256(decoded).hexdigest()
    public_info = {
        "path": str(public_path),
        "encoding": encoding,
        "decoded_bytes": len(decoded),
        "sha256": public_sha,
    }
    add("fndsa_public_key_file", True, str(public_path))
    add("fndsa_public_key_bytes", len(decoded) == expected_public_len, str(len(decoded)))
    add(
        "fndsa_public_key_matches_fork_registry",
        bool(expected_public_sha) and public_sha == expected_public_sha,
        f"public_sha={public_sha} registry_sha={expected_public_sha}",
    )

payload = {
    "ok": all(check["status"] == "PASS" for check in checks),
    "checks": checks,
    "private_key": private_info,
    "public_key": public_info,
    "private_key_material_redacted": True,
}
out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
PY
  append_json_gates "$key_json"
}

runtime_command_base() {
  printf '%q ' \
    "$runtime_path" \
    "$1" \
    --source-workspace "$workspace" \
    --chain-id "$chain_id" \
    --network-id "$network_id" \
    --genesis-hash "$genesis_hash"
}

write_activation_command() {
  {
    echo "# Val5 dry-run/preflight completed here. Do not execute until the operator approves the phase."
    echo "# Start shadow observe after restore/head-match proof:"
    runtime_command_base start-shadow-observe
    printf '%q %q\n' --required-blocks "$shadow_required_blocks"
    echo
    echo "# Request rejoin only at the eligible epoch boundary with fresh exact common-height proof:"
    runtime_command_base request-rejoin
    printf '%q %q %q %q %q %q %q %q %q %q %q %q %q\n' \
      --common-height "<height>" \
      --common-hash "<hash>" \
      --exact-common-height-match \
      --latest-finalized-qc-aegis-pqc-verified \
      --state-root-matches \
      --rejoin-at-finalized-safe-boundary \
      --cluster-marks-pending-reactivation \
      --operator-approved-reactivation
  } > "$activation_command"
}

run_runtime_phase() {
  local command="$1"
  shift
  if [[ ! -x "$runtime_path" ]]; then
    echo '{"success":false,"typed_status":"FAILED_CLOSED","blocked_reasons":["runtime missing or not executable"]}' > "$runtime_phase_json"
    record_gate "runtime_phase_$command" "FAIL" "runtime missing or not executable"
    return 1
  fi
  (
    cd "$workspace"
    SYNERGY_PROJECT_ROOT="$workspace" \
    SYNERGY_CONFIG_PATH="$workspace/config/node.toml" \
    "$runtime_path" "$command" \
      --source-workspace "$workspace" \
      --chain-id "$chain_id" \
      --network-id "$network_id" \
      --genesis-hash "$genesis_hash" \
      "$@"
  ) > "$runtime_phase_json"
  record_gate "runtime_phase_$command" "PASS" "output=$runtime_phase_json"
}

write_reports() {
  "$python_bin" - \
    "$phase" \
    "$execute" \
    "$workspace" \
    "$runtime_path" \
    "$expected_runtime_sha" \
    "$gates_tsv" \
    "$evidence/val5-rejoin-proof.json" \
    "$evidence/val5-rejoin-proof.md" \
    "$fork_json" \
    "$key_json" \
    "$health_json" \
    "$runtime_phase_json" \
    "$activation_command" \
    "$transcript" <<'PY'
import csv
import json
import sys
from pathlib import Path

(
    phase,
    execute,
    workspace,
    runtime_path,
    expected_runtime_sha,
    gates_path,
    json_path,
    md_path,
    fork_path,
    key_path,
    health_path,
    runtime_phase_path,
    activation_command_path,
    transcript_path,
) = sys.argv[1:15]

gates = []
with Path(gates_path).open("r", encoding="utf-8") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        gates.append(row)

def read_json(path):
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text())
    except Exception as exc:
        return {"parse_error": str(exc), "path": str(p)}

failures = [gate for gate in gates if gate.get("status") == "FAIL"]
warnings = [gate for gate in gates if gate.get("status") == "WARN"]
proof = {
    "schema": "synergy-val5-fndsa-rejoin-proof-v1",
    "phase": phase,
    "execute": execute == "true",
    "workspace": workspace,
    "runtime_path": runtime_path,
    "expected_runtime_sha256": expected_runtime_sha,
    "all_gates_passed": not failures,
    "failure_count": len(failures),
    "warning_count": len(warnings),
    "gates": gates,
    "fork_metadata": read_json(fork_path),
    "fndsa_key_validation": read_json(key_path),
    "local_health": read_json(health_path),
    "runtime_phase_output": read_json(runtime_phase_path),
    "activation_command_path": activation_command_path,
    "transcript_path": transcript_path,
    "private_key_material_redacted": True,
}
Path(json_path).write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")

lines = [
    "# Val5 FN-DSA Rejoin Proof",
    "",
    f"- phase: `{phase}`",
    f"- execute: `{execute}`",
    f"- workspace: `{workspace}`",
    f"- runtime: `{runtime_path}`",
    f"- expected runtime sha256: `{expected_runtime_sha or 'MISSING'}`",
    f"- all gates passed: `{str(not failures).lower()}`",
    f"- failure count: `{len(failures)}`",
    f"- private key material: `redacted`",
    "",
    "## Gate Table",
    "",
    "| Gate | Status | Detail |",
    "| --- | --- | --- |",
]
for gate in gates:
    detail = gate.get("detail", "").replace("|", "\\|")
    lines.append(f"| `{gate.get('gate')}` | `{gate.get('status')}` | {detail} |")
lines.extend([
    "",
    "## Evidence",
    "",
    f"- JSON proof: `{json_path}`",
    f"- transcript: `{transcript_path}`",
    f"- activation command: `{activation_command_path}`",
])
Path(md_path).write_text("\n".join(lines) + "\n")
print(json.dumps({"all_gates_passed": not failures, "failure_count": len(failures), "proof_json": json_path, "proof_md": md_path}, sort_keys=True))
PY
}

finish() {
  write_activation_command
  local result
  result="$(write_reports)"
  echo "$result"
  local failures
  failures="$("$python_bin" - "$evidence/val5-rejoin-proof.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))["failure_count"])
PY
)"
  if [[ "$failures" != "0" ]]; then
    exit 1
  fi
}

echo "phase=$phase"
echo "execute=$execute"
echo "workspace=$workspace"
echo "runtime_path=$runtime_path"
echo "evidence_path=$evidence"
echo "val5_validator_address=$val5_address"
echo "chain_id=$chain_id"
echo "network_id=$network_id"

validate_basic_layout

case "$phase" in
  preflight)
    capture_stopped_state || true
    validate_quarantine
    validate_fork_metadata
    validate_fndsa_key_material
    ;;
  shadow-start)
    capture_stopped_state || true
    validate_quarantine
    validate_fork_metadata
    validate_fndsa_key_material
    if [[ "$operator_approved_shadow_start" != "true" ]]; then
      record_gate "shadow_start_operator_approval" "FAIL" "--operator-approved-shadow-start is required"
    elif [[ "$execute" != "true" ]]; then
      record_gate "shadow_start_execute_guard" "FAIL" "--execute is required for mutation phase"
    else
      run_runtime_phase start-shadow-observe --required-blocks "$shadow_required_blocks"
    fi
    ;;
  eligibility)
    validate_quarantine
    validate_fork_metadata
    validate_fndsa_key_material
    run_runtime_phase shadow-status || true
    cp "$runtime_phase_json" "$evidence/shadow-status.json" 2>/dev/null || true
    run_runtime_phase rejoin-eligibility || true
    cp "$runtime_phase_json" "$evidence/rejoin-eligibility.json" 2>/dev/null || true
    ;;
  request-rejoin)
    validate_quarantine
    validate_fork_metadata
    validate_fndsa_key_material
    if [[ -z "$common_height" || -z "$common_hash" ]]; then
      record_gate "request_rejoin_common_height_hash" "FAIL" "--common-height and --common-hash are required"
    else
      record_gate "request_rejoin_common_height_hash" "PASS" "height=$common_height hash=$common_hash"
    fi
    if [[ "$operator_approved_rejoin" != "true" ]]; then
      record_gate "request_rejoin_operator_approval" "FAIL" "--operator-approved-rejoin is required"
    elif [[ "$execute" != "true" ]]; then
      record_gate "request_rejoin_execute_guard" "FAIL" "--execute is required for mutation phase"
    else
      run_runtime_phase request-rejoin \
        --common-height "$common_height" \
        --common-hash "$common_hash" \
        --exact-common-height-match \
        --latest-finalized-qc-aegis-pqc-verified \
        --state-root-matches \
        --rejoin-at-finalized-safe-boundary \
        --cluster-marks-pending-reactivation \
        --operator-approved-reactivation
    fi
    ;;
  post-rejoin-proof)
    validate_fork_metadata
    validate_fndsa_key_material
    capture_running_health
    ;;
esac

finish
