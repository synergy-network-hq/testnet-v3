#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OLD_BINARY=""
NEW_BINARY=""
WORKDIR=""
TIMEOUT_SECS="${TIMEOUT_SECS:-240}"
POLL_INTERVAL_SECS="${POLL_INTERVAL_SECS:-2}"
OLD_MIN_HEIGHT="${OLD_MIN_HEIGHT:-6}"
FOUR_VALIDATOR_ADVANCE="${FOUR_VALIDATOR_ADVANCE:-20}"
MIXED_RUNTIME_ADVANCE="${MIXED_RUNTIME_ADVANCE:-100}"
START_HEIGHT=""
POST_STOP_HEIGHT=""
INSERTION_HEIGHT=""
TARGET_HEIGHT=""
FINAL_HEIGHT=""
FINAL_HASH=""

RPC_PORTS=(5740 5741 5742 5743 5744)
VALIDATOR_ADDRESSES=(
  "synv11qen9x0g9p0f2pqznpqzfrwkrgnsussdwmvs"
  "synv11s4wc6l4kg4jr0k5meg42cyzxa03cf863srt"
  "synv11e3ephsarcw6mey0fx5xtnygg2ewegnum4re"
  "synv11mka64uz049aekwhdvfrq6dvh75d0k7kmdp5"
  "synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f"
)
P2P_PORTS=(5722 5723 5724 5725 5726)
WS_PORTS=(5760 5761 5762 5763 5764)

usage() {
  cat <<USAGE
Usage: $0 --old-binary PATH --new-binary PATH [--workdir PATH] [--timeout SECONDS]

Reproduces the live mixed-runtime rollout class locally:
  1. start five validators on the old runtime;
  2. stop validator 5 and prove four-validator finality;
  3. replace validator 3 with the new runtime;
  4. monitor for finality, same-height lock churn, and proposal timeout symptoms.

The workdir is always preserved as evidence. No live hosts are touched.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old-binary)
      OLD_BINARY="$2"
      shift 2
      ;;
    --new-binary)
      NEW_BINARY="$2"
      shift 2
      ;;
    --workdir)
      WORKDIR="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$OLD_BINARY" || -z "$NEW_BINARY" ]]; then
  usage >&2
  exit 1
fi

if [[ ! -x "$OLD_BINARY" ]]; then
  echo "old runtime binary is not executable: $OLD_BINARY" >&2
  exit 1
fi
if [[ ! -x "$NEW_BINARY" ]]; then
  echo "new runtime binary is not executable: $NEW_BINARY" >&2
  exit 1
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/synergy-mixed-runtime-repro.XXXXXX")"
else
  mkdir -p "$WORKDIR"
fi

sha256_for_file() {
  local file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    sha256sum "$file" | awk '{print $1}'
  fi
}

rpc_call() {
  local port="$1"
  local method="$2"
  local params="${3:-[]}"
  python3 - "$port" "$method" "$params" <<'PY'
import json
import sys
import urllib.request

port = int(sys.argv[1])
method = sys.argv[2]
params = json.loads(sys.argv[3])
payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params, "id": 1}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=2) as response:
        body = json.loads(response.read().decode())
except Exception as error:
    print(json.dumps({"rpc_error": str(error)}))
    raise SystemExit(1)
print(json.dumps(body.get("result")))
PY
}

rpc_height() {
  local port="$1"
  if ! rpc_call "$port" "synergy_blockNumber" "[]" 2>/dev/null | python3 -c 'import json,sys; print(int(json.load(sys.stdin)))' 2>/dev/null; then
    echo -1
  fi
}

rpc_latest_hash() {
  local port="$1"
  if ! rpc_call "$port" "synergy_getLatestBlock" "[]" 2>/dev/null | python3 -c 'import json,sys; v=json.load(sys.stdin) or {}; print(v.get("hash",""))' 2>/dev/null; then
    echo ""
  fi
}

rpc_block_hash_at_height() {
  local port="$1"
  local height="$2"
  if ! rpc_call "$port" "synergy_getBlockByNumber" "[$height]" 2>/dev/null | python3 -c 'import json,sys; v=json.load(sys.stdin) or {}; print(v.get("hash",""))' 2>/dev/null; then
    echo ""
  fi
}

min_height_for_indices() {
  local min=999999999
  local index
  for index in "$@"; do
    local height
    height="$(rpc_height "${RPC_PORTS[$((index - 1))]}")"
    if [[ "$height" -lt "$min" ]]; then
      min="$height"
    fi
  done
  echo "$min"
}

common_hash_at_height() {
  local height="$1"
  shift
  local expected=""
  local index
  for index in "$@"; do
    local hash
    hash="$(rpc_block_hash_at_height "${RPC_PORTS[$((index - 1))]}" "$height")"
    if [[ -z "$hash" ]]; then
      echo ""
      return 1
    fi
    if [[ -z "$expected" ]]; then
      expected="$hash"
    elif [[ "$hash" != "$expected" ]]; then
      echo ""
      return 1
    fi
  done
  echo "$expected"
}

height_table() {
  local index
  for index in 1 2 3 4 5; do
    local port="${RPC_PORTS[$((index - 1))]}"
    printf 'validator-%s height=%s hash=%s\n' "$index" "$(rpc_height "$port")" "$(rpc_latest_hash "$port")"
  done
}

latest_qc_summary() {
  local workspace="$1"
  python3 - "$workspace/data/committed_qcs.jsonl" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("missing_committed_qcs")
    raise SystemExit(0)
last = None
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if line:
        last = line
if last is None:
    print("empty_committed_qcs")
    raise SystemExit(0)
try:
    value = json.loads(last)
except Exception as error:
    print(f"invalid_committed_qc:{error}")
    raise SystemExit(0)
qc = value.get("qc") if isinstance(value.get("qc"), dict) else value
votes = qc.get("votes") if isinstance(qc.get("votes"), list) else []
signers = [
    vote.get("validator_address")
    for vote in votes
    if isinstance(vote, dict) and vote.get("validator_address")
]
print(json.dumps({
    "height": value.get("height") or value.get("block_height") or (votes[0].get("block_index") if votes and isinstance(votes[0], dict) else None),
    "block_hash": value.get("block_hash") or qc.get("block_hash") or value.get("hash"),
    "vote_count": value.get("vote_count") or qc.get("vote_count") or len(votes) or None,
    "signature_count": value.get("signature_count") or qc.get("signature_count") or len(votes) or None,
    "signers": value.get("signers") or value.get("validator_signers") or value.get("validators") or signers,
}, sort_keys=True))
PY
}

stop_validator() {
  local index="$1"
  local pid_file="$WORKDIR/validator-${index}/node.pid"
  local rpc_port="${RPC_PORTS[$((index - 1))]}"
  if [[ -f "$pid_file" ]]; then
    local pid
    pid="$(cat "$pid_file")"
    pkill -TERM -P "$pid" 2>/dev/null || true
    kill "$pid" 2>/dev/null || true
    for _ in {1..10}; do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    pkill -KILL -P "$pid" 2>/dev/null || true
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$pid_file"
  fi
  local listener_pids
  listener_pids="$(lsof -tiTCP:"$rpc_port" -sTCP:LISTEN 2>/dev/null || true)"
  if [[ -n "$listener_pids" ]]; then
    kill $listener_pids 2>/dev/null || true
    sleep 1
    kill -9 $listener_pids 2>/dev/null || true
  fi
}

start_validator_with_binary() {
  local index="$1"
  local binary="$2"
  local runtime_sha="$3"
  local workspace="$WORKDIR/validator-${index}"
  local config_path="$workspace/config/node.toml"
  local node_name="validator-${index}"
  local validator_address="${VALIDATOR_ADDRESSES[$((index - 1))]}"
  local stdout_path="$workspace/logs/mixed-runtime-start.stdout.log"
  local stderr_path="$workspace/logs/mixed-runtime-start.stderr.log"
  (
    cd "$workspace"
    SYNERGY_PROJECT_ROOT="$workspace" \
    SYNERGY_CONFIG_PATH="$config_path" \
    SYNERGY_GENESIS_FILE="$workspace/config/genesis.json" \
    SYNERGY_VALIDATOR_CONSENSUS_PRIVATE_KEY_FILE="$workspace/config/validator/consensus.private.key" \
    SYNERGY_RUNTIME_SHA256="$runtime_sha" \
    SYNERGY_TIMING_TRACE_NODE_ROLE="validator" \
    SYNERGY_TIMING_TRACE_NODE_NAME="$node_name" \
    SYNERGY_TIMING_TRACE_VALIDATOR="$validator_address" \
    SYNERGY_CONSENSUS_TIMING_TRACE_PATH="$workspace/data/consensus_timing_trace.jsonl" \
    exec "$binary" start --config "$config_path" >"$stdout_path" 2>"$stderr_path"
  ) &
  echo "$!" > "$workspace/node.pid"
}

wait_for_advance() {
  local required_advance="$1"
  shift
  local indices=("$@")
  local start_height
  local deadline=$(( $(date +%s) + TIMEOUT_SECS ))
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    start_height="$(min_height_for_indices "${indices[@]}")"
    if [[ "$start_height" -ge 0 ]]; then
      break
    fi
    sleep "$POLL_INTERVAL_SECS"
  done
  if [[ "${start_height:-"-1"}" -lt 0 ]]; then
    echo "advance_failed start_height_unavailable indices=${indices[*]}" >&2
    return 1
  fi
  local target=$((start_height + required_advance))
  wait_until_height "$target" "${indices[@]}"
}

wait_until_height() {
  local target="$1"
  shift
  local indices=("$@")
  local deadline=$(( $(date +%s) + TIMEOUT_SECS ))
  local display_start
  display_start="$(min_height_for_indices "${indices[@]}")"
  echo "wait_for_advance indices=${indices[*]} start_height=${display_start} target=${target}"
  while [[ "$(date +%s)" -lt "$deadline" ]]; do
    local current
    current="$(min_height_for_indices "${indices[@]}")"
    if [[ "$current" -ge "$target" ]]; then
      echo "advance_ok current=${current} target=${target}"
      return 0
    fi
    sleep "$POLL_INTERVAL_SECS"
  done
  echo "advance_failed current=$(min_height_for_indices "${indices[@]}") target=${target}" >&2
  return 1
}

write_markdown_report() {
  local report="$WORKDIR/local-mixed-runtime-evidence-report.md"
  {
    echo "# Local Mixed-Runtime Evidence Report"
    echo
    echo "launch_status=NOT_READY"
    echo "live_hosts_touched=false"
    echo "workdir=$WORKDIR"
    echo
    echo "## Runtime Inputs"
    echo
    echo "old_binary=$OLD_BINARY"
    echo "old_sha=$(sha256_for_file "$OLD_BINARY")"
    echo "new_binary=$NEW_BINARY"
    echo "new_sha=$(sha256_for_file "$NEW_BINARY")"
    echo "stopped_validator=validator-5"
    echo "mixed_validator=validator-3"
    echo
    echo "## Heights"
    echo
    echo "start_height=$START_HEIGHT"
    echo "post_stop_height=$POST_STOP_HEIGHT"
    echo "insertion_height=$INSERTION_HEIGHT"
    echo "target_height=$TARGET_HEIGHT"
    echo "final_height=$FINAL_HEIGHT"
    echo "final_common_hash=$FINAL_HASH"
    echo
    echo "## QC Summary"
    echo
    for index in 1 2 3 4 5; do
      echo "validator-${index} qc=$(latest_qc_summary "$WORKDIR/validator-${index}")"
    done
    echo
    echo "## Conclusion"
    echo
    if [[ "${FINAL_HEIGHT:-0}" -ge "${TARGET_HEIGHT:-1}" && -n "$FINAL_HASH" ]]; then
      echo "The clean local mixed-runtime reproduction did not reproduce the live v13.0.23 stall."
      echo "Validators 1-4 finalized through the target with validator-5 stopped and validator-3 running the candidate runtime."
    else
      echo "The local mixed-runtime reproduction did not reach the requested target. Treat this as failed evidence, not a launch pass."
    fi
  } > "$report"
  echo "report_path=$report"
}

collect_evidence() {
  local evidence="$WORKDIR/mixed-runtime-evidence.txt"
  {
    echo "workdir=$WORKDIR"
    echo "old_binary=$OLD_BINARY"
    echo "old_sha=$(sha256_for_file "$OLD_BINARY")"
    echo "new_binary=$NEW_BINARY"
    echo "new_sha=$(sha256_for_file "$NEW_BINARY")"
    echo
    height_table
    echo
    for index in 1 2 3 4 5; do
      echo "validator-${index} qc=$(latest_qc_summary "$WORKDIR/validator-${index}")"
    done
    echo
    for index in 1 2 3 4 5; do
      local log="$WORKDIR/validator-${index}/logs/synergy-testnet.log"
      echo "--- validator-${index} key log lines ---"
      if [[ -f "$log" ]]; then
        grep -Ei 'leader|proposal timeout|same-height|vote-lock|does not extend local tip|refus|committed QC|vote_count|quarantine|diverg' "$log" | tail -n 120 || true
      else
        echo "missing log: $log"
      fi
    done
  } > "$evidence"
  echo "evidence_path=$evidence"
  write_markdown_report
}

cleanup() {
  local index
  for index in 1 2 3 4 5; do
    stop_validator "$index"
  done
  echo "mixed-runtime repro workspace preserved at: $WORKDIR"
}
trap cleanup EXIT

OLD_SHA="$(sha256_for_file "$OLD_BINARY")"
NEW_SHA="$(sha256_for_file "$NEW_BINARY")"

echo "starting old-runtime local mesh workdir=$WORKDIR old_sha=$OLD_SHA"
START_VALIDATOR_COUNT=5 MIN_HEIGHT="$OLD_MIN_HEIGHT" TIMEOUT_SECS="$TIMEOUT_SECS" \
  SKIP_PEER_MESH_CHECK=true \
  "$ROOT_DIR/scripts/testnet/smoke-local-validator-mesh.sh" \
  --binary "$OLD_BINARY" \
  --timeout "$TIMEOUT_SECS" \
  --workdir "$WORKDIR" \
  --leave-running

echo "old runtime mesh reached minimum height"
height_table
START_HEIGHT="$(min_height_for_indices 1 2 3 4 5)"

echo "stopping validator-5 to simulate Val5 containment"
stop_validator 5
wait_for_advance "$FOUR_VALIDATOR_ADVANCE" 1 2 3 4
POST_STOP_HEIGHT="$(min_height_for_indices 1 2 3 4)"

echo "replacing validator-3 with new runtime"
INSERTION_HEIGHT="$(min_height_for_indices 1 2 3 4)"
TARGET_HEIGHT=$((INSERTION_HEIGHT + MIXED_RUNTIME_ADVANCE))
stop_validator 3
start_validator_with_binary 3 "$NEW_BINARY" "$NEW_SHA"

if wait_until_height "$TARGET_HEIGHT" 1 2 3 4; then
  FINAL_HEIGHT="$(min_height_for_indices 1 2 3 4)"
  FINAL_HASH="$(common_hash_at_height "$FINAL_HEIGHT" 1 2 3 4 || true)"
  echo "mixed runtime accepted: four active validators advanced ${MIXED_RUNTIME_ADVANCE} blocks"
  collect_evidence
  exit 0
fi

echo "mixed runtime stalled or failed to advance within timeout" >&2
FINAL_HEIGHT="$(min_height_for_indices 1 2 3 4)"
if [[ "$FINAL_HEIGHT" -ge 0 ]]; then
  FINAL_HASH="$(common_hash_at_height "$FINAL_HEIGHT" 1 2 3 4 || true)"
fi
collect_evidence
exit 2
