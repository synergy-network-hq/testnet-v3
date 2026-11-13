#!/usr/bin/env bash
set -euo pipefail

# Fund a validator with the required stake amount, then submit a
# staking transaction from the validator's local wallet RPC when available.
#
# Usage:
#   scripts/fund-validator-stake.sh <validator_address> [amount_snrg]
#
# Environment:
#   SYNERGY_RPC_ENDPOINT        Public RPC used by the faucet transfer
#   SYNERGY_STAKE_RPC_ENDPOINT  Validator-local RPC used to submit staking tx
#   SYNERGY_FAUCET_ADDRESS      Faucet wallet address available on the public RPC
#   SYNERGY_SKIP_STAKE=1        Only fund the validator wallet

RPC_ENDPOINT="${SYNERGY_RPC_ENDPOINT:-https://testnet-core-rpc.synergy-network.io}"
STAKE_RPC_ENDPOINT="${SYNERGY_STAKE_RPC_ENDPOINT:-http://127.0.0.1:5640}"
FAUCET_ADDRESS="${SYNERGY_FAUCET_ADDRESS:-synw1zp7cxme7xm838663yrd43lxtxlw0ck90z4am}"
TOKEN_SYMBOL="${SYNERGY_TOKEN_SYMBOL:-SNRG}"
NWEI_PER_SNRG=1000000000

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

rpc() {
  local endpoint="$1"
  local method="$2"
  local params_json="${3:-[]}"
  local payload response

  payload="$(jq -cn --arg method "$method" --argjson params "$params_json" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"

  response="$(curl --fail --silent --show-error --max-time 25 \
    -H "Content-Type: application/json" \
    --data "$payload" \
    "$endpoint")"

  if jq -e '.error != null' >/dev/null 2>&1 <<<"$response"; then
    jq -r '.error.message // .error // "Unknown RPC error"' <<<"$response" >&2
    return 1
  fi

  printf '%s\n' "$response"
}

format_nwei_as_snrg() {
  python3 - "$1" "$NWEI_PER_SNRG" <<'PY'
from decimal import Decimal, getcontext
import sys

getcontext().prec = 80
value = Decimal(sys.argv[1]) / Decimal(sys.argv[2])
text = f"{value:.9f}"
print(text.rstrip("0").rstrip(".") if "." in text else text)
PY
}

wait_for_tx() {
  local endpoint="$1"
  local tx_hash="$2"
  local label="$3"

  if [[ -z "$tx_hash" ]]; then
    return 1
  fi

  for _ in {1..45}; do
    sleep 2

    if response="$(rpc "$endpoint" synergy_getTransactionReceipt "$(jq -cn --arg hash "$tx_hash" '[$hash]')" 2>/dev/null)"; then
      if jq -e '.result != null and .result != ""' >/dev/null 2>&1 <<<"$response"; then
        echo "$label confirmed on-chain."
        return 0
      fi
    fi

    if response="$(rpc "$endpoint" synergy_getTransactionByHash "$(jq -cn --arg hash "$tx_hash" '[$hash]')" 2>/dev/null)"; then
      if jq -e '.result != null and .result != ""' >/dev/null 2>&1 <<<"$response"; then
        echo "$label found on-chain."
        return 0
      fi
    fi
  done

  echo "$label was submitted, but confirmation was not observed within 90 seconds." >&2
  return 1
}

require_cmd curl
require_cmd jq
require_cmd python3

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <validator_address> [amount_snrg]" >&2
  exit 1
fi

VALIDATOR_ADDRESS="$(printf '%s' "$1" | tr -d '[:space:]')"
AMOUNT_SNRG="${2:-5000}"
AMOUNT_SNRG="${AMOUNT_SNRG//,/}"

if [[ ! "$VALIDATOR_ADDRESS" =~ ^synv1[0-9a-z]{20,70}$ ]]; then
  echo "Invalid validator address: $VALIDATOR_ADDRESS" >&2
  echo "Expected a lowercase validator address beginning with synv1." >&2
  exit 1
fi

if [[ ! "$AMOUNT_SNRG" =~ ^[0-9]+$ || "$AMOUNT_SNRG" == "0" ]]; then
  echo "Amount must be a positive whole-SNRG integer." >&2
  exit 1
fi

REQUESTED_NWEI=$((AMOUNT_SNRG * NWEI_PER_SNRG))

echo "Synergy Testnet Validator Stake Funding"
echo "Funding RPC: $RPC_ENDPOINT"
echo "Stake RPC:   $STAKE_RPC_ENDPOINT"
echo "Faucet:      $FAUCET_ADDRESS"
echo "Validator:   $VALIDATOR_ADDRESS"
echo "Amount:      $AMOUNT_SNRG $TOKEN_SYMBOL"
echo

balance_response="$(rpc "$RPC_ENDPOINT" synergy_getTokenBalance "$(jq -cn --arg address "$FAUCET_ADDRESS" --arg token "$TOKEN_SYMBOL" '[$address,$token]')")"
faucet_balance_nwei="$(jq -r '.result // "0"' <<<"$balance_response")"

if ! python3 - "$faucet_balance_nwei" "$REQUESTED_NWEI" <<'PY'
import sys
sys.exit(0 if int(sys.argv[1]) >= int(sys.argv[2]) else 1)
PY
then
  echo "Insufficient faucet balance." >&2
  echo "Requested: $AMOUNT_SNRG $TOKEN_SYMBOL" >&2
  echo "Available: $(format_nwei_as_snrg "$faucet_balance_nwei") $TOKEN_SYMBOL" >&2
  exit 1
fi

memo="validator stake funding $(date -u +%Y-%m-%dT%H:%M:%SZ)"
send_params="$(jq -cn \
  --arg from "$FAUCET_ADDRESS" \
  --arg to "$VALIDATOR_ADDRESS" \
  --arg token "$TOKEN_SYMBOL" \
  --arg memo "$memo" \
  --argjson amount "$AMOUNT_SNRG" \
  '[$from,$to,$token,$amount,$memo]')"

echo "Submitting faucet transfer..."
send_response="$(rpc "$RPC_ENDPOINT" synergy_sendTokens "$send_params")"
if [[ "$(jq -r '.result.success // false' <<<"$send_response")" != "true" ]]; then
  jq -r '.result.error // .error.message // "Unknown transfer failure"' <<<"$send_response" >&2
  exit 1
fi

send_hash="$(jq -r '.result.tx_hash // empty' <<<"$send_response")"
echo "Funding transaction: $send_hash"
wait_for_tx "$RPC_ENDPOINT" "$send_hash" "Funding transaction" || true

if [[ "${SYNERGY_SKIP_STAKE:-0}" == "1" ]]; then
  echo "Funding complete. Staking was skipped by SYNERGY_SKIP_STAKE=1."
  exit 0
fi

stake_params="$(jq -cn \
  --arg staker "$VALIDATOR_ADDRESS" \
  --arg validator "$VALIDATOR_ADDRESS" \
  --arg token "$TOKEN_SYMBOL" \
  --argjson amount "$AMOUNT_SNRG" \
  '[$staker,$validator,$token,$amount]')"

echo "Submitting validator staking transaction from $STAKE_RPC_ENDPOINT..."
stake_response="$(rpc "$STAKE_RPC_ENDPOINT" synergy_stakeTokens "$stake_params")" || {
  echo "Funding completed, but staking could not be submitted from the validator RPC." >&2
  echo "After the validator wallet is imported, submit the stake transaction from the validator RPC:" >&2
  echo "  curl -sS -X POST $STAKE_RPC_ENDPOINT -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"method\":\"synergy_stakeTokens\",\"params\":[\"$VALIDATOR_ADDRESS\",\"$VALIDATOR_ADDRESS\",\"$TOKEN_SYMBOL\",$AMOUNT_SNRG],\"id\":1}'" >&2
  exit 2
}

if [[ "$(jq -r '.result.success // false' <<<"$stake_response")" != "true" ]]; then
  jq -r '.result.error // .error.message // "Unknown staking failure"' <<<"$stake_response" >&2
  exit 2
fi

stake_hash="$(jq -r '.result.tx_hash // empty' <<<"$stake_response")"
echo "Staking transaction: $stake_hash"
wait_for_tx "$STAKE_RPC_ENDPOINT" "$stake_hash" "Staking transaction" || true

echo "Validator funding and staking workflow submitted."
