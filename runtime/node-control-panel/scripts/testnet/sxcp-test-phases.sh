#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
BOOTSTRAP_SCRIPT="$ROOT_DIR/scripts/testnet/bootstrap-sxcp-testnet.sh"
SMOKE_SCRIPT="$ROOT_DIR/scripts/testnet/sxcp-smoke-test.sh"

default_rpc_port="$(awk -F, 'NR > 1 && tolower($5)=="rpc-gateway" {print $8; exit}' "$INVENTORY_FILE" 2>/dev/null || true)"
default_rpc_port="${default_rpc_port:-5646}"
RPC_URL="${RPC_URL:-http://127.0.0.1:${default_rpc_port}}"

usage() {
  cat <<USAGE
Usage: $0 [--rpc-url URL]

Runs SXCP-focused testnet phases:
1) Relayer bootstrap
2) Quorum attestation + replay rejection
3) Slashing simulation + relayer restore
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)
      RPC_URL="$2"
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

rpc_call() {
  local method="$1"
  local params_json="${2:-[]}"
  local id="${3:-1}"
  curl -sS -m 8 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"${method}\",\"params\":${params_json},\"id\":${id}}"
}

phase_banner() {
  local title="$1"
  echo
  echo "===================================================="
  echo "$title"
  echo "===================================================="
}

phase_banner "SXCP Phase 1 - Bootstrap Relayer Set"
"$BOOTSTRAP_SCRIPT" "$RPC_URL"

phase_banner "SXCP Phase 2 - Quorum Attestation + Replay Guard"
"$SMOKE_SCRIPT" "$RPC_URL"

phase_banner "SXCP Phase 3 - Slashing Simulation + Restore"
relayer_set="$(rpc_call "synergy_getRelayerSet" "[]" 90)"
candidate_json="$(python3 - "$relayer_set" <<'PY'
import json
import sys

payload = json.loads(sys.argv[1])
result = payload.get("result", {})
relayers = result.get("relayers", [])

eligible = []
for relayer in relayers:
    if relayer.get("active") and (not relayer.get("slashed")):
        address = relayer.get("address")
        public_key = relayer.get("public_key")
        if isinstance(address, str) and isinstance(public_key, str) and address and public_key:
            eligible.append((address, public_key))

eligible.sort(key=lambda item: item[0])
if not eligible:
    print("{}")
    sys.exit(0)

address, public_key = eligible[0]
print(json.dumps({"address": address, "public_key": public_key}))
PY
)"

selected_address="$(python3 - "$candidate_json" <<'PY'
import json, sys
payload = json.loads(sys.argv[1] or "{}")
print(payload.get("address", ""))
PY
)"
selected_pubkey="$(python3 - "$candidate_json" <<'PY'
import json, sys
payload = json.loads(sys.argv[1] or "{}")
print(payload.get("public_key", ""))
PY
)"

if [[ -z "$selected_address" || -z "$selected_pubkey" ]]; then
  echo "No active relayer available for slashing simulation." >&2
  exit 1
fi

echo "Slashing relayer candidate: $selected_address"
slash_response="$(rpc_call "synergy_slashRelayer" "[\"$selected_address\",\"chaos-test-invalid-signature\",30]" 91)"
if command -v jq >/dev/null 2>&1; then
  echo "$slash_response" | jq
else
  echo "$slash_response"
fi

slash_success="$(python3 - "$slash_response" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
result = payload.get("result", {})
print("true" if result.get("success") else "false")
PY
)"

if [[ "$slash_success" != "true" ]]; then
  echo "Slashing simulation failed." >&2
  exit 1
fi

restore_response="$(rpc_call "synergy_registerRelayer" "[\"$selected_address\",\"$selected_pubkey\"]" 92)"
if command -v jq >/dev/null 2>&1; then
  echo "$restore_response" | jq
else
  echo "$restore_response"
fi

echo "Final SXCP status:"
final_status="$(rpc_call "synergy_getSxcpStatus" "[]" 93)"
if command -v jq >/dev/null 2>&1; then
  echo "$final_status" | jq
else
  echo "$final_status"
fi

echo
echo "SXCP phase tests complete."
