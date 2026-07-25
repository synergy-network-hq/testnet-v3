#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"

usage() {
  cat <<USAGE
Usage: $0 [--inventory path] [--rpc node=http://ip:port,...]

Checks deterministic state across nodes using synergy_getDeterminismDigest.
USAGE
}

CUSTOM_TARGETS=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory)
      INVENTORY_FILE="$2"
      shift 2
      ;;
    --rpc)
      CUSTOM_TARGETS="$2"
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

targets=()

if [[ -n "$CUSTOM_TARGETS" ]]; then
  IFS=',' read -r -a parts <<< "$CUSTOM_TARGETS"
  for part in "${parts[@]}"; do
    targets+=("$part")
  done
else
  if [[ ! -f "$INVENTORY_FILE" ]]; then
    echo "Missing inventory file: $INVENTORY_FILE" >&2
    exit 1
  fi
  while IFS=, read -r node_slot_id _ _ _ _ _ _ rpc_port _ _ _ host management_host _ _ _ || [[ -n "${node_slot_id:-}" ]]; do
    [[ "$node_slot_id" == "node_slot_id" ]] && continue
    endpoint_host="${management_host:-$host}"
    [[ -z "$endpoint_host" || -z "$rpc_port" ]] && continue
    targets+=("${node_slot_id}=http://${endpoint_host}:${rpc_port}")
  done < "$INVENTORY_FILE"
fi

if [[ "${#targets[@]}" -eq 0 ]]; then
  echo "No RPC targets found" >&2
  exit 1
fi

reference_node=""
reference_state_root=""
reference_block_hash=""
reference_receipt_hash=""

mismatch=0

echo "Determinism check across ${#targets[@]} nodes"

action_rpc() {
  local url="$1"
  curl -sS -m 5 -X POST "$url" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"synergy_getDeterminismDigest","params":[],"id":1}'
}

json_get() {
  local payload="$1"
  local key="$2"
  if command -v jq >/dev/null 2>&1; then
    echo "$payload" | jq -r "$key" 2>/dev/null || true
    return
  fi
  python3 - "$payload" "$key" <<'PY'
import json
import sys

payload = sys.argv[1]
key = sys.argv[2]
try:
    data = json.loads(payload)
except Exception:
    print("")
    sys.exit(0)

result = data.get("result", {})
mapping = {
    ".result.state_root // empty": result.get("state_root", ""),
    ".result.block_hash // empty": result.get("block_hash", ""),
    ".result.receipt_hash // empty": result.get("receipt_hash", ""),
    ".result.block_height // 0": result.get("block_height", 0),
}
print(mapping.get(key, ""))
PY
}

for pair in "${targets[@]}"; do
  node_name="${pair%%=*}"
  node_url="${pair#*=}"

  response="$(action_rpc "$node_url" || true)"
  if [[ -z "$response" ]]; then
    echo "[FAIL] $node_name ($node_url) no response"
    mismatch=1
    continue
  fi

  state_root="$(json_get "$response" '.result.state_root // empty')"
  block_hash="$(json_get "$response" '.result.block_hash // empty')"
  receipt_hash="$(json_get "$response" '.result.receipt_hash // empty')"
  block_height="$(json_get "$response" '.result.block_height // 0')"

  if [[ -z "$state_root" || -z "$block_hash" ]]; then
    echo "[FAIL] $node_name ($node_url) invalid determinism payload"
    mismatch=1
    continue
  fi

  if [[ -z "$reference_state_root" ]]; then
    reference_node="$node_name"
    reference_state_root="$state_root"
    reference_block_hash="$block_hash"
    reference_receipt_hash="$receipt_hash"
    echo "[REF ] $node_name height=$block_height state_root=$state_root"
    continue
  fi

  if [[ "$state_root" != "$reference_state_root" || "$block_hash" != "$reference_block_hash" || "$receipt_hash" != "$reference_receipt_hash" ]]; then
    echo "[MISMATCH] $node_name height=$block_height"
    echo "  state_root:  $state_root"
    echo "  block_hash:  $block_hash"
    echo "  receipt_hash:$receipt_hash"
    mismatch=1
  else
    echo "[OK  ] $node_name height=$block_height"
  fi
done

if [[ "$mismatch" -ne 0 ]]; then
  echo "Determinism check FAILED"
  exit 2
fi

echo "Determinism check passed."
