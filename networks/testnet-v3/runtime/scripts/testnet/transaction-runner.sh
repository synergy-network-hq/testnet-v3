#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${RPC_URL:-http://127.0.0.1:5646}"
MODE="${MODE:-single}"
DURATION_SECONDS="${DURATION_SECONDS:-60}"
INTERVAL_MS="${INTERVAL_MS:-1000}"
WORKERS="${WORKERS:-1}"
REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS:-10}"
TRANSACTIONS_FILE="${TRANSACTIONS_FILE:-}"
METHOD="${METHOD:-}"
PARAMS_JSON="${PARAMS_JSON:-}"
VERBOSE="${VERBOSE:-0}"
SKIP_PREFLIGHT="${SKIP_PREFLIGHT:-0}"

usage() {
  cat <<'USAGE'
Usage:
  transaction-runner.sh --method METHOD --params-json JSON [options]
  transaction-runner.sh --transactions-file FILE [options]

Modes:
  single       Repeat the first transaction for the full duration.
  round-robin  Cycle through all transactions in order across workers.
  random       Pick a random transaction each iteration.

Required input:
  Either:
    --method METHOD --params-json JSON
  Or:
    --transactions-file FILE

Options:
  --rpc-url URL                  JSON-RPC endpoint (default: http://127.0.0.1:5646)
  --mode MODE                    single | round-robin | random (default: single)
  --duration-seconds N           Run duration in seconds (default: 60)
  --interval-ms N                Delay between requests per worker in ms (default: 1000)
  --workers N                    Number of concurrent workers (default: 1)
  --request-timeout-seconds N    Per-request timeout (default: 10)
  --transactions-file FILE       JSON array of {label?, method, params}
  --method METHOD                Single RPC method to repeat
  --params-json JSON             JSON array of params for --method
  --skip-preflight               Skip RPC and sender-wallet validation
  --verbose                      Print successful responses too
  -h, --help                     Show this help

Examples:
  transaction-runner.sh \
    --method synergy_sendTokens \
    --params-json '["synwFrom...","synwTo...","SNRG",1]' \
    --duration-seconds 120 \
    --interval-ms 750

  transaction-runner.sh \
    --transactions-file scripts/testnet/transaction-scenarios.example.json \
    --mode round-robin \
    --duration-seconds 300 \
    --workers 4 \
    --interval-ms 500
USAGE
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)
      RPC_URL="$2"
      shift 2
      ;;
    --mode)
      MODE="$2"
      shift 2
      ;;
    --duration-seconds)
      DURATION_SECONDS="$2"
      shift 2
      ;;
    --interval-ms)
      INTERVAL_MS="$2"
      shift 2
      ;;
    --workers)
      WORKERS="$2"
      shift 2
      ;;
    --request-timeout-seconds)
      REQUEST_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --transactions-file)
      TRANSACTIONS_FILE="$2"
      shift 2
      ;;
    --method)
      METHOD="$2"
      shift 2
      ;;
    --params-json)
      PARAMS_JSON="$2"
      shift 2
      ;;
    --skip-preflight)
      SKIP_PREFLIGHT=1
      shift
      ;;
    --verbose)
      VERBOSE=1
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

require_command curl
require_command jq

case "$MODE" in
  single|round-robin|random)
    ;;
  *)
    echo "Invalid mode: $MODE" >&2
    usage
    exit 1
    ;;
esac

if ! [[ "$DURATION_SECONDS" =~ ^[0-9]+$ ]] || (( DURATION_SECONDS <= 0 )); then
  echo "--duration-seconds must be a positive integer" >&2
  exit 1
fi

if ! [[ "$INTERVAL_MS" =~ ^[0-9]+$ ]]; then
  echo "--interval-ms must be a non-negative integer" >&2
  exit 1
fi

if ! [[ "$WORKERS" =~ ^[0-9]+$ ]] || (( WORKERS <= 0 )); then
  echo "--workers must be a positive integer" >&2
  exit 1
fi

if ! [[ "$REQUEST_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || (( REQUEST_TIMEOUT_SECONDS <= 0 )); then
  echo "--request-timeout-seconds must be a positive integer" >&2
  exit 1
fi

build_transactions_file_from_method() {
  local output_file="$1"

  if [[ -z "$METHOD" || -z "$PARAMS_JSON" ]]; then
    echo "Provide either --transactions-file or both --method and --params-json" >&2
    exit 1
  fi

  if ! jq -e . >/dev/null 2>&1 <<<"$PARAMS_JSON"; then
    echo "--params-json must be valid JSON" >&2
    exit 1
  fi

  if ! jq -e 'type == "array"' >/dev/null 2>&1 <<<"$PARAMS_JSON"; then
    echo "--params-json must be a JSON array" >&2
    exit 1
  fi

  jq -cn \
    --arg method "$METHOD" \
    --argjson params "$PARAMS_JSON" \
    '[{label:$method, method:$method, params:$params}]' >"$output_file"
}

validate_transactions_file() {
  local file="$1"

  if [[ ! -f "$file" ]]; then
    echo "Transactions file not found: $file" >&2
    exit 1
  fi

  if ! jq -e '
    type == "array"
    and length > 0
    and all(
      .[];
      (.method | type == "string" and length > 0)
      and ((.params // null) | type == "array")
      and ((.label // "") | type == "string")
    )
  ' "$file" >/dev/null; then
    echo "Transactions file must be a non-empty JSON array of {label?, method, params}" >&2
    exit 1
  fi
}

rpc_request() {
  local method="$1"
  local params_json="$2"
  local request_id="${3:-1}"
  local payload

  payload="$(jq -cn \
    --arg method "$method" \
    --argjson params "$params_json" \
    --argjson id "$request_id" \
    '{jsonrpc:"2.0", method:$method, params:$params, id:$id}')"

  curl -sS --max-time "$REQUEST_TIMEOUT_SECONDS" \
    -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$payload"
}

resolve_scenario_placeholders() {
  local latest_resp head_num head_hash profile_path
  profile_path="${PROFILE_PATH:-$HOME/.synergy/testnet/network/profile.json}"

  if ! grep -q '\${' "$TRANSACTIONS_FILE" 2>/dev/null; then
    return 0
  fi

  declare -A subs=()

  if latest_resp="$(rpc_request "synergy_getLatestBlock" '[]' 0 2>/dev/null)" \
      && jq -e '.result != null' >/dev/null 2>&1 <<<"$latest_resp"; then
    head_num="$(jq -r '.result.block_index // .result.number // empty' <<<"$latest_resp")"
    head_hash="$(jq -r '.result.hash // empty' <<<"$latest_resp")"
    if [[ -n "$head_num" ]]; then
      subs["HEAD_BLOCK_NUMBER"]="$head_num"
      subs["LATEST_BLOCK_NUMBER"]="$head_num"
      subs["HEAD_MINUS_1_BLOCK_NUMBER"]="$(( head_num > 0 ? head_num - 1 : 0 ))"
      subs["HEAD_MINUS_5_BLOCK_NUMBER"]="$(( head_num > 4 ? head_num - 5 : 0 ))"
    fi
    if [[ -n "$head_hash" ]]; then
      subs["LATEST_BLOCK_HASH"]="$head_hash"
    fi
  fi

  if [[ -n "${subs[HEAD_MINUS_1_BLOCK_NUMBER]:-}" ]]; then
    local prev_resp prev_hash
    if prev_resp="$(rpc_request "synergy_getBlockByNumber" \
          "$(jq -cn --argjson n "${subs[HEAD_MINUS_1_BLOCK_NUMBER]}" '[$n]')" 0 2>/dev/null)" \
        && jq -e '.result != null' >/dev/null 2>&1 <<<"$prev_resp"; then
      prev_hash="$(jq -r '.result.hash // empty' <<<"$prev_resp")"
      [[ -n "$prev_hash" ]] && subs["HEAD_MINUS_1_BLOCK_HASH"]="$prev_hash"
    fi
  fi

  if [[ -f "$profile_path" ]]; then
    local faucet treasury stake_vault
    faucet="$(jq -r '.faucet_wallet.address // empty' "$profile_path" 2>/dev/null)"
    treasury="$(jq -r '.treasury_wallet.address // empty' "$profile_path" 2>/dev/null)"
    stake_vault="$(jq -r '.stake_vault_wallet.address // empty' "$profile_path" 2>/dev/null)"
    [[ -n "$faucet" ]] && subs["FAUCET_WALLET"]="$faucet"
    [[ -n "$treasury" ]] && subs["TREASURY_WALLET"]="$treasury"
    [[ -n "$stake_vault" ]] && subs["STAKE_VAULT_WALLET"]="$stake_vault"
  fi

  # Allow callers to inject their own via env: SCENARIO_VAR_FOO=bar => ${FOO}.
  while IFS='=' read -r env_name env_value; do
    [[ -n "$env_name" ]] || continue
    subs["${env_name#SCENARIO_VAR_}"]="$env_value"
  done < <(printenv | awk -F= '/^SCENARIO_VAR_/ {print}')

  if (( ${#subs[@]} == 0 )); then
    return 0
  fi

  local tmp_file
  tmp_file="$(mktemp "$WORK_DIR/transactions.XXXXXX.json")"
  local jq_args=(--argjson raw "$(cat "$TRANSACTIONS_FILE")")
  local jq_program='$raw'
  for key in "${!subs[@]}"; do
    jq_args+=(--arg "v_${key}" "${subs[$key]}")
    jq_program+=' | walk(if type == "string" then gsub("\\$\\{'"$key"'\\}"; $v_'"$key"') else . end)'
  done
  jq -c "$jq_program" "${jq_args[@]}" > "$tmp_file"
  mv "$tmp_file" "$TRANSACTIONS_FILE"
}

validate_no_placeholder_params() {
  local unresolved

  unresolved="$(
    jq -r '
      .[]
      | (.params // [])[]
      | select(type == "string")
      | select(test("ReplaceWith|\\$\\{[A-Za-z_][A-Za-z0-9_]*\\}"))
    ' "$TRANSACTIONS_FILE" | sort -u
  )"

  if [[ -n "$unresolved" ]]; then
    echo "Transactions file contains unresolved placeholder values:" >&2
    printf '%s\n' "$unresolved" >&2
    exit 1
  fi
}

validate_rpc_endpoint() {
  local response

  if ! response="$(rpc_request "synergy_blockNumber" '[]' 0 2>&1)"; then
    echo "RPC endpoint preflight failed: $response" >&2
    exit 1
  fi

  if ! jq -e '.result != null and .error == null' >/dev/null 2>&1 <<<"$response"; then
    echo "RPC endpoint did not return a usable synergy_blockNumber response:" >&2
    echo "$response" >&2
    exit 1
  fi
}

validate_required_sender_wallets() {
  local sender_addresses
  local sender
  local response

  sender_addresses="$(
    jq -r '
      .[]
      | select(.method == "synergy_sendTokens" or .method == "synergy_stakeTokens" or .method == "synergy_signTransaction")
      | .params[0] // empty
    ' "$TRANSACTIONS_FILE" | sort -u
  )"

  [[ -n "$sender_addresses" ]] || return 0

  while IFS= read -r sender; do
    [[ -n "$sender" ]] || continue
    if ! response="$(rpc_request "synergy_getWallet" "$(jq -cn --arg sender "$sender" '[$sender]')" 0 2>&1)"; then
      echo "Failed to validate sender wallet $sender: $response" >&2
      exit 1
    fi

    if ! jq -e '.error == null and (.result | type == "object")' >/dev/null 2>&1 <<<"$response"; then
      echo "Sender wallet is not loaded on the target RPC node: $sender" >&2
      echo "Load that wallet into Node-RPC or use direct token-manager methods in the scenario file." >&2
      exit 1
    fi
  done <<<"$sender_addresses"
}

WORK_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

if [[ -n "$TRANSACTIONS_FILE" ]]; then
  validate_transactions_file "$TRANSACTIONS_FILE"
  cp "$TRANSACTIONS_FILE" "$WORK_DIR/transactions.json"
else
  build_transactions_file_from_method "$WORK_DIR/transactions.json"
fi

TRANSACTIONS_FILE="$WORK_DIR/transactions.json"
TRANSACTION_COUNT="$(jq 'length' "$TRANSACTIONS_FILE")"

if (( SKIP_PREFLIGHT == 0 )); then
  validate_no_placeholder_params
  validate_rpc_endpoint
  validate_required_sender_wallets
fi

sleep_interval_seconds="$(awk -v ms="$INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')"
end_epoch="$(( $(date +%s) + DURATION_SECONDS ))"

worker_loop() {
  local worker_id="$1"
  local stats_file="$WORK_DIR/worker-${worker_id}.stats"
  local success_count=0
  local failure_count=0
  local iteration_count=0

  while (( $(date +%s) < end_epoch )); do
    local tx_index
    case "$MODE" in
      single)
        tx_index=0
        ;;
      round-robin)
        tx_index=$(( (worker_id + iteration_count * WORKERS) % TRANSACTION_COUNT ))
        ;;
      random)
        tx_index=$(( RANDOM % TRANSACTION_COUNT ))
        ;;
    esac

    local tx_json
    local label
    local method
    local params_json
    local request_id
    local payload
    local response
    local outcome
    local tx_hash
    local error_message

    tx_json="$(jq -c ".[$tx_index]" "$TRANSACTIONS_FILE")"
    label="$(jq -r '.label // .method' <<<"$tx_json")"
    method="$(jq -r '.method' <<<"$tx_json")"
    params_json="$(jq -c '.params' <<<"$tx_json")"
    request_id=$(( worker_id * 1000000 + iteration_count + 1 ))
    payload="$(jq -cn \
      --arg method "$method" \
      --argjson params "$params_json" \
      --argjson id "$request_id" \
      '{jsonrpc:"2.0", method:$method, params:$params, id:$id}')"

    if response="$(curl -sS --max-time "$REQUEST_TIMEOUT_SECONDS" \
  -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "$payload" 2>&1)"; then

  if ! jq -e . >/dev/null 2>&1 <<<"$response"; then
    outcome="failure"
    error_message="Non-JSON RPC response: $response"
  elif jq -e '.error != null' >/dev/null 2>&1 <<<"$response"; then
    outcome="failure"
    error_message="$(jq -r '.error.message // (.error|tostring) // "RPC error"' <<<"$response")"
  elif jq -e '.result.success == false' >/dev/null 2>&1 <<<"$response"; then
    outcome="failure"
    error_message="$(jq -r '.result.error // "RPC returned success=false"' <<<"$response")"
  else
    outcome="success"
    tx_hash="$(jq -r '.result.tx_hash? // .result.transaction?.hash? // empty' <<<"$response" 2>/dev/null)"
  fi
else
  outcome="failure"
  error_message="$response"
fi

    if [[ "$outcome" == "success" ]]; then
      success_count=$((success_count + 1))
      if (( VERBOSE == 1 )); then
        echo "[worker:$worker_id] ok label=$label method=$method tx_hash=${tx_hash:-none}"
      fi
    else
      failure_count=$((failure_count + 1))
      echo "[worker:$worker_id] failed label=$label method=$method error=$error_message" >&2
    fi

    iteration_count=$((iteration_count + 1))

    if (( INTERVAL_MS > 0 )); then
      sleep "$sleep_interval_seconds"
    fi
  done

  printf '%s\t%s\t%s\n' "$success_count" "$failure_count" "$iteration_count" >"$stats_file"
}

echo "Starting transaction runner"
echo "- rpc_url: $RPC_URL"
echo "- mode: $MODE"
echo "- duration_seconds: $DURATION_SECONDS"
echo "- interval_ms: $INTERVAL_MS"
echo "- workers: $WORKERS"
echo "- request_timeout_seconds: $REQUEST_TIMEOUT_SECONDS"
echo "- transaction_count: $TRANSACTION_COUNT"

for worker_id in $(seq 0 $((WORKERS - 1))); do
  worker_loop "$worker_id" &
done

wait

total_success=0
total_failure=0
total_attempts=0
for stats_file in "$WORK_DIR"/worker-*.stats; do
  [[ -f "$stats_file" ]] || continue
  read -r worker_success worker_failure worker_attempts < <(
    awk -F '\t' '{print $1, $2, $3}' "$stats_file"
  )
  total_success=$((total_success + worker_success))
  total_failure=$((total_failure + worker_failure))
  total_attempts=$((total_attempts + worker_attempts))
done

elapsed_seconds="$DURATION_SECONDS"
achieved_rps="$(awk -v total="$total_attempts" -v secs="$elapsed_seconds" 'BEGIN { printf "%.2f", total / secs }')"

echo "Transaction runner completed"
echo "- attempts: $total_attempts"
echo "- successes: $total_success"
echo "- failures: $total_failure"
echo "- achieved_rps: $achieved_rps"
