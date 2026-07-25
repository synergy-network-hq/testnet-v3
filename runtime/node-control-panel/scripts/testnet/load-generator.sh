#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:48650}"
TX_PER_MINUTE="${TX_PER_MINUTE:-10000}"
DURATION_MINUTES="${DURATION_MINUTES:-1}"
WORKERS="${WORKERS:-20}"
FROM_ADDRESS="${FROM_ADDRESS:-synw1lfgerdqglc6p74p9u6k8ghfssl59q8jzhuwm07}"
TOKEN_SYMBOL="${TOKEN_SYMBOL:-SNRG}"
AMOUNT="${AMOUNT:-1}"
MODE="${MODE:-sendTokens}"

usage() {
  cat <<USAGE
Usage: $0 [--rpc-url URL] [--rpm N] [--minutes N] [--workers N] [--mode sendTokens|status]

Environment overrides:
  RPC_URL, TX_PER_MINUTE, DURATION_MINUTES, WORKERS, MODE
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --rpm)
      TX_PER_MINUTE="$2"
      shift 2
      ;;
    --minutes)
      DURATION_MINUTES="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
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

TOTAL_TX=$((TX_PER_MINUTE * DURATION_MINUTES))
if (( TOTAL_TX <= 0 )); then
  echo "Total tx count must be > 0" >&2
  exit 1
fi

send_one() {
  local idx="$1"
  local to_address
  to_address="synwtest$(printf '%032x' "$idx")"

  local payload
  if [[ "$MODE" == "status" ]]; then
    payload='{"jsonrpc":"2.0","method":"synergy_status","params":[],"id":1}'
  else
    payload="{\"jsonrpc\":\"2.0\",\"method\":\"synergy_sendTokens\",\"params\":[\"${FROM_ADDRESS}\",\"${to_address}\",\"${TOKEN_SYMBOL}\",${AMOUNT}],\"id\":1}"
  fi

  curl -sS -m 5 -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$payload" >/dev/null
}

export RPC_URL FROM_ADDRESS TOKEN_SYMBOL AMOUNT MODE
export -f send_one

started="$(date +%s)"
echo "Starting load test"
echo "- rpc_url: $RPC_URL"
echo "- mode: $MODE"
echo "- tx_per_minute target: $TX_PER_MINUTE"
echo "- duration_minutes: $DURATION_MINUTES"
echo "- workers: $WORKERS"
echo "- total_requests: $TOTAL_TX"

seq 1 "$TOTAL_TX" | xargs -I{} -n1 -P "$WORKERS" bash -c 'send_one "$@"' _ {}

ended="$(date +%s)"
elapsed=$((ended - started))
if (( elapsed <= 0 )); then
  elapsed=1
fi
actual_rps=$(awk -v total="$TOTAL_TX" -v secs="$elapsed" 'BEGIN { printf "%.2f", total/secs }')
actual_rpm=$(awk -v rps="$actual_rps" 'BEGIN { printf "%.2f", rps*60 }')

echo "Load generation completed"
echo "- elapsed_seconds: $elapsed"
echo "- achieved_rps: $actual_rps"
echo "- achieved_rpm: $actual_rpm"
