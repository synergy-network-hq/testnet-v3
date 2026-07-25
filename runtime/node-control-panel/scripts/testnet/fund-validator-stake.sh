#!/usr/bin/env bash
set -euo pipefail

# Fund a validator with the required 50,000 SNRG stake and, when a
# validator-local RPC is available, submit the staking transaction from that wallet.

RPC_ENDPOINT="${SYNERGY_RPC_ENDPOINT:-https://testnet-rpc.synergy-network.io}"
STAKE_RPC_ENDPOINT="${SYNERGY_STAKE_RPC_ENDPOINT:-http://127.0.0.1:5640}"
FAUCET_ADDRESS="${SYNERGY_FAUCET_ADDRESS:-synw1zp7cxme7xm838663yrd43lxtxlw0ck90z4am}"
TOKEN_SYMBOL="${SYNERGY_TOKEN_SYMBOL:-SNRG}"
AMOUNT_SNRG="${2:-50000}"

rpc() {
  local endpoint="$1"
  local method="$2"
  local params_json="${3:-[]}"
  local payload

  payload="$(jq -cn --arg method "$method" --argjson params "$params_json" \
    '{jsonrpc:"2.0",id:1,method:$method,params:$params}')"
  curl --fail --silent --show-error --max-time 25 \
    -H "Content-Type: application/json" \
    --data "$payload" \
    "$endpoint"
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <validator_address> [amount_snrg]" >&2
  exit 1
fi

for command_name in curl jq; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
done

VALIDATOR_ADDRESS="$(printf '%s' "$1" | tr -d '[:space:]')"
AMOUNT_SNRG="${AMOUNT_SNRG//,/}"

if [[ ! "$VALIDATOR_ADDRESS" =~ ^synv1[0-9a-z]{20,70}$ ]]; then
  echo "Invalid validator address: $VALIDATOR_ADDRESS" >&2
  exit 1
fi

if [[ ! "$AMOUNT_SNRG" =~ ^[0-9]+$ || "$AMOUNT_SNRG" == "0" ]]; then
  echo "Amount must be a positive whole-SNRG integer." >&2
  exit 1
fi

echo "Funding validator stake"
echo "Faucet RPC: $RPC_ENDPOINT"
echo "Stake RPC:  $STAKE_RPC_ENDPOINT"
echo "Validator:  $VALIDATOR_ADDRESS"
echo "Amount:     $AMOUNT_SNRG $TOKEN_SYMBOL"

send_params="$(jq -cn \
  --arg from "$FAUCET_ADDRESS" \
  --arg to "$VALIDATOR_ADDRESS" \
  --arg token "$TOKEN_SYMBOL" \
  --arg memo "validator stake funding" \
  --argjson amount "$AMOUNT_SNRG" \
  '[$from,$to,$token,$amount,$memo]')"

send_response="$(rpc "$RPC_ENDPOINT" synergy_sendTokens "$send_params")"
if [[ "$(jq -r '.result.success // false' <<<"$send_response")" != "true" ]]; then
  jq -r '.result.error // .error.message // "Funding transaction failed"' <<<"$send_response" >&2
  exit 1
fi

send_hash="$(jq -r '.result.tx_hash // empty' <<<"$send_response")"
echo "Funding transaction submitted: $send_hash"

if [[ "${SYNERGY_SKIP_STAKE:-0}" == "1" ]]; then
  echo "Skipped staking transaction because SYNERGY_SKIP_STAKE=1."
  exit 0
fi

stake_params="$(jq -cn \
  --arg staker "$VALIDATOR_ADDRESS" \
  --arg validator "$VALIDATOR_ADDRESS" \
  --arg token "$TOKEN_SYMBOL" \
  --argjson amount "$AMOUNT_SNRG" \
  '[$staker,$validator,$token,$amount]')"

stake_response="$(rpc "$STAKE_RPC_ENDPOINT" synergy_stakeTokens "$stake_params")" || {
  echo "Funding was submitted, but staking could not be submitted from $STAKE_RPC_ENDPOINT." >&2
  echo "Run again from the validator machine after its wallet is imported, or set SYNERGY_SKIP_STAKE=1 for funding-only mode." >&2
  exit 2
}

if [[ "$(jq -r '.result.success // false' <<<"$stake_response")" != "true" ]]; then
  jq -r '.result.error // .error.message // "Staking transaction failed"' <<<"$stake_response" >&2
  exit 2
fi

stake_hash="$(jq -r '.result.tx_hash // empty' <<<"$stake_response")"
echo "Staking transaction submitted: $stake_hash"
