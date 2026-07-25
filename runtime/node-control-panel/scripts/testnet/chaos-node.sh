#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:48650}"
ITERATIONS="${ITERATIONS:-200}"
CONCURRENCY="${CONCURRENCY:-10}"

usage() {
  cat <<USAGE
Usage: $0 [--rpc-url URL] [--iterations N] [--concurrency N]

Simulates hostile client behaviors against RPC:
- malformed JSON-RPC payloads
- invalid signature-like transaction objects
- replayed transaction hashes
- burst request flooding
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --iterations)
      ITERATIONS="$2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
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

attack_one() {
  local idx="$1"
  local mode=$((idx % 5))

  case "$mode" in
    0)
      # malformed JSON
      curl -sS -m 3 -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_sendTransaction",' >/dev/null || true
      ;;
    1)
      # invalid transaction signature/object fields
      curl -sS -m 3 -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_sendTransaction","params":[{"from":"attacker","to":"victim","amount":"oops","signature":"not-a-signature"}],"id":1}' >/dev/null || true
      ;;
    2)
      # replay-like duplicate payload flood
      curl -sS -m 3 -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_sendTokens","params":["synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07","synw1replay0000000000000000000000000000000","SNRG",1],"id":1}' >/dev/null || true
      ;;
    3)
      # unsupported method spam
      curl -sS -m 3 -X POST "$RPC_URL" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"synergy_proposeForkBlock","params":["malicious"],"id":1}' >/dev/null || true
      ;;
    4)
      # large payload request
      local big
      big="$(printf 'A%.0s' $(seq 1 2048))"
      curl -sS -m 3 -X POST "$RPC_URL" -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"synergy_registerValidator\",\"params\":[\"$big\",\"$big\",\"$big\",1],\"id\":1}" >/dev/null || true
      ;;
  esac
}

export RPC_URL
export -f attack_one

echo "Starting chaos simulation"
echo "- rpc_url: $RPC_URL"
echo "- iterations: $ITERATIONS"
echo "- concurrency: $CONCURRENCY"

seq 1 "$ITERATIONS" | xargs -I{} -n1 -P "$CONCURRENCY" bash -c 'attack_one "$@"' _ {}

echo "Chaos simulation completed"
