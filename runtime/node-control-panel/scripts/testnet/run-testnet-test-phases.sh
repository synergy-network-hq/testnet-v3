#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPC_URL="${RPC_URL:-http://127.0.0.1:48650}"
AUTO_FAILURES="false"

RUN_NODE_SCRIPT="$ROOT_DIR/scripts/testnet/run-node.sh"
LOAD_SCRIPT="$ROOT_DIR/scripts/testnet/load-generator.sh"
CHAOS_SCRIPT="$ROOT_DIR/scripts/testnet/chaos-node.sh"
DETERMINISM_SCRIPT="$ROOT_DIR/scripts/testnet/check-determinism.sh"
SXCP_PHASE_SCRIPT="$ROOT_DIR/scripts/testnet/sxcp-test-phases.sh"

usage() {
  cat <<USAGE
Usage: $0 [--rpc-url URL] [--auto-failures]

Runs an automated subset of testnet validation phases.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --auto-failures)
      AUTO_FAILURES="true"
      shift
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

rpc_call() {
  local method="$1"
  local params="${2:-[]}"
  curl -sS -m 5 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params},\"id\":1}"
}

json_get_result_field() {
  local payload="$1"
  local field="$2"
  python3 - "$payload" "$field" <<'PY'
import json
import sys
payload = sys.argv[1]
field = sys.argv[2]
try:
    data = json.loads(payload)
except Exception:
    print("")
    sys.exit(0)
result = data.get("result", {})
if isinstance(result, dict):
    print(result.get(field, ""))
else:
    print(result if field == "_self" else "")
PY
}

block_number() {
  local response
  response="$(rpc_call "synergy_blockNumber" "[]" || true)"
  python3 - "$response" <<'PY'
import json
import sys
try:
    payload = json.loads(sys.argv[1])
    print(int(payload.get("result", 0)))
except Exception:
    print(0)
PY
}

phase_banner() {
  local title="$1"
  echo
  echo "===================================================="
  echo "$title"
  echo "===================================================="
}

phase_banner "Phase 1 - Network Stability"
start_height="$(block_number)"
sleep 10
end_height="$(block_number)"
echo "Block height moved from $start_height to $end_height"
if (( end_height <= start_height )); then
  echo "[WARN] Block height did not advance during stability probe"
fi

if [[ "$AUTO_FAILURES" == "true" ]]; then
  phase_banner "Phase 2 - Consensus Failure Simulation"
  echo "Stopping validator node-05 for 20 seconds"
  "$RUN_NODE_SCRIPT" stop node-05 || true
  before_failure="$(block_number)"
  sleep 20
  after_failure="$(block_number)"
  echo "Height during validator outage: $before_failure -> $after_failure"
  "$RUN_NODE_SCRIPT" start node-05 || true
  sleep 5
else
  phase_banner "Phase 2 - Consensus Failure Simulation (manual)"
  echo "Manual action required: stop 1-2 validators and confirm block production continues."
fi

phase_banner "Phase 3 - Transaction System Validation"
RPC_URL="$RPC_URL" TX_PER_MINUTE=10000 DURATION_MINUTES=1 WORKERS=30 MODE=sendTokens "$LOAD_SCRIPT"

phase_banner "Phase 4 - Malicious Behavior Testing"
RPC_URL="$RPC_URL" ITERATIONS=300 CONCURRENCY=20 "$CHAOS_SCRIPT"

phase_banner "Phase 5 - SXCP Interoperability Validation"
"$SXCP_PHASE_SCRIPT" --rpc-url "$RPC_URL"

phase_banner "Phase 6 - Economic Logic Sanity"
validators_response="$(rpc_call "synergy_getValidators" "[]" || true)"
validator_count="$(python3 - "$validators_response" <<'PY'
import json
import sys
try:
    payload = json.loads(sys.argv[1])
    result = payload.get("result", [])
    if isinstance(result, list):
        print(len(result))
    else:
        print(0)
except Exception:
    print(0)
PY
)"
echo "Active validators returned by RPC: $validator_count"

phase_banner "Phase 7 - State Determinism"
"$DETERMINISM_SCRIPT"

phase_banner "Phase 8 - Long Duration Stability"
echo "Run this script repeatedly from cron/systemd for 7-14 days and archive outputs."
echo "Recommended cadence: every 5 minutes for block/peer/determinism checks."

echo
echo "Test phase runner complete."
