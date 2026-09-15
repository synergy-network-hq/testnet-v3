#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENESIS_PATH="${GENESIS_PATH:-$ROOT_DIR/config/genesis.json}"
CLI_MANIFEST_PATH="${CLI_MANIFEST_PATH:-$ROOT_DIR/src/Cargo.toml}"
SENDER_ADDRESS_PATH="${SENDER_ADDRESS_PATH:-$ROOT_DIR/node-control-panel/testnet/runtime/keys/GenVal-01/address.txt}"
SENDER_PRIVATE_KEY_PATH="${SENDER_PRIVATE_KEY_PATH:-$ROOT_DIR/node-control-panel/testnet/runtime/keys/GenVal-01/private.key}"
RECIPIENT_ALLOCATION_NAME="${RECIPIENT_ALLOCATION_NAME:-Faucet}"
AMOUNT_SNRG="${AMOUNT_SNRG:-1}"
MEMO="${MEMO:-launch-block-1}"
REQUIRED_BLOCK_INDEX="${REQUIRED_BLOCK_INDEX:-1}"
TIMESTAMP="${TIMESTAMP:-$(date +%s)}"
NWEI_PER_SNRG=1000000000

DEFAULT_OUTPUTS=(
  "$ROOT_DIR/node-control-panel/testnet/runtime/installers/GenVal-01/config/launch-block1-transaction.json"
  "$ROOT_DIR/node-control-panel/testnet/runtime/installers/GenVal-02/config/launch-block1-transaction.json"
  "$ROOT_DIR/node-control-panel/testnet/runtime/installers/GenVal-04/config/launch-block1-transaction.json"
)

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

build_output_targets() {
  if [[ -n "${OUTPUT_PATH:-}" ]]; then
    OUTPUT_TARGETS=("$OUTPUT_PATH")
    return 0
  fi

  if [[ -n "${OUTPUT_PATHS:-}" ]]; then
    IFS=':' read -r -a OUTPUT_TARGETS <<<"$OUTPUT_PATHS"
    return 0
  fi

  OUTPUT_TARGETS=("${DEFAULT_OUTPUTS[@]}")
}

normalize_private_key_hex() {
  local key_material="$1"
  if [[ "$key_material" =~ ^[0-9A-Fa-f]+$ ]]; then
    printf '%s\n' "$key_material"
    return 0
  fi

  printf '%s' "$key_material" \
    | openssl base64 -d -A 2>/dev/null \
    | xxd -p -c 999999
}

read_trimmed_file() {
  local path="$1"
  tr -d '\r\n[:space:]' < "$path"
}

require_command jq
require_command cargo
require_command node
require_command openssl
require_command xxd

if [[ ! -f "$GENESIS_PATH" ]]; then
  echo "Canonical genesis not found: $GENESIS_PATH" >&2
  exit 1
fi

if [[ ! -f "$CLI_MANIFEST_PATH" ]]; then
  echo "CLI manifest not found: $CLI_MANIFEST_PATH" >&2
  exit 1
fi

if ! [[ "$AMOUNT_SNRG" =~ ^[0-9]+$ ]] || (( AMOUNT_SNRG <= 0 )); then
  echo "AMOUNT_SNRG must be a positive integer" >&2
  exit 1
fi

if ! [[ "$REQUIRED_BLOCK_INDEX" =~ ^[0-9]+$ ]] || (( REQUIRED_BLOCK_INDEX != 1 )); then
  echo "REQUIRED_BLOCK_INDEX must be exactly 1" >&2
  exit 1
fi

if ! [[ "$TIMESTAMP" =~ ^[0-9]+$ ]]; then
  echo "TIMESTAMP must be a unix timestamp" >&2
  exit 1
fi

if [[ ! -f "$SENDER_ADDRESS_PATH" ]]; then
  echo "Sender address file not found: $SENDER_ADDRESS_PATH" >&2
  exit 1
fi

if [[ ! -f "$SENDER_PRIVATE_KEY_PATH" ]]; then
  echo "Sender private key file not found: $SENDER_PRIVATE_KEY_PATH" >&2
  exit 1
fi

SENDER_ADDRESS="${SENDER_ADDRESS:-$(read_trimmed_file "$SENDER_ADDRESS_PATH")}"
if [[ -z "$SENDER_ADDRESS" ]]; then
  echo "Sender address file is empty: $SENDER_ADDRESS_PATH" >&2
  exit 1
fi

RECIPIENT_ADDRESS="${RECIPIENT_ADDRESS:-}"
if [[ -z "$RECIPIENT_ADDRESS" && -n "${RECIPIENT_ADDRESS_PATH:-}" ]]; then
  if [[ ! -f "$RECIPIENT_ADDRESS_PATH" ]]; then
    echo "Recipient address file not found: $RECIPIENT_ADDRESS_PATH" >&2
    exit 1
  fi
  RECIPIENT_ADDRESS="$(read_trimmed_file "$RECIPIENT_ADDRESS_PATH")"
fi

if [[ -z "$RECIPIENT_ADDRESS" ]]; then
  RECIPIENT_ADDRESS="$(
    jq -r \
      --arg allocation_name "$RECIPIENT_ALLOCATION_NAME" \
      '[.allocations[] | select(.name == $allocation_name) | .address][0] // empty' \
      "$GENESIS_PATH"
  )"
fi

if [[ -z "$RECIPIENT_ADDRESS" ]]; then
  echo "Unable to resolve recipient address from genesis allocation name: $RECIPIENT_ALLOCATION_NAME" >&2
  exit 1
fi

SENDER_PRIVATE_KEY_RAW="$(read_trimmed_file "$SENDER_PRIVATE_KEY_PATH")"
if [[ -z "$SENDER_PRIVATE_KEY_RAW" ]]; then
  echo "Sender private key file is empty: $SENDER_PRIVATE_KEY_PATH" >&2
  exit 1
fi
SENDER_PRIVATE_KEY_HEX="$(normalize_private_key_hex "$SENDER_PRIVATE_KEY_RAW")"
if [[ -z "$SENDER_PRIVATE_KEY_HEX" ]]; then
  echo "Failed to normalize sender private key into hex: $SENDER_PRIVATE_KEY_PATH" >&2
  exit 1
fi

AMOUNT_NWEI=$(( AMOUNT_SNRG * NWEI_PER_SNRG ))
GAS_PRICE_NWEI=1000
GAS_LIMIT=21000
REQUIRED_BALANCE_NWEI=$(( AMOUNT_NWEI + (GAS_PRICE_NWEI * GAS_LIMIT) ))

SENDER_BALANCE_NWEI="$(
  jq -r \
    --arg sender "$SENDER_ADDRESS" \
    '[.balances[] | select(.address == $sender) | .balance_nwei][0] // "0"' \
    "$GENESIS_PATH"
)"
if ! [[ "$SENDER_BALANCE_NWEI" =~ ^[0-9]+$ ]]; then
  echo "Canonical genesis returned a non-numeric balance for $SENDER_ADDRESS: $SENDER_BALANCE_NWEI" >&2
  exit 1
fi

if ! node -e 'const [have, need] = process.argv.slice(1).map((value) => BigInt(value)); process.exit(have >= need ? 0 : 1);' \
  "$SENDER_BALANCE_NWEI" \
  "$REQUIRED_BALANCE_NWEI"; then
  echo "Sender $SENDER_ADDRESS has insufficient canonical genesis balance: need $REQUIRED_BALANCE_NWEI nWei, have $SENDER_BALANCE_NWEI nWei" >&2
  exit 1
fi

DATA_FIELD="$(jq -rn \
  --arg to "$RECIPIENT_ADDRESS" \
  --arg token "SNRG" \
  --argjson amount "$AMOUNT_NWEI" \
  --arg memo "$MEMO" \
  '"token_transfer:{\"to\":\"\($to)\",\"token\":\"\($token)\",\"amount\":\($amount),\"memo\":\(($memo|tojson))}"')"

UNSIGNED_TRANSACTION_JSON="$(jq -cn \
  --arg sender "$SENDER_ADDRESS" \
  --arg receiver "$RECIPIENT_ADDRESS" \
  --argjson amount "$AMOUNT_NWEI" \
  --argjson nonce 0 \
  --argjson timestamp "$TIMESTAMP" \
  --arg data "$DATA_FIELD" \
  '{
    sender: $sender,
    receiver: $receiver,
    amount: $amount,
    nonce: $nonce,
    signature: [],
    timestamp: $timestamp,
    gas_price: '"$GAS_PRICE_NWEI"',
    gas_limit: '"$GAS_LIMIT"',
    data: $data,
    signature_algorithm: "fndsa"
  }')"

SIGNED_TRANSACTION_JSON="$(
  cargo run --quiet --manifest-path "$CLI_MANIFEST_PATH" --bin wallet-pqc-cli -- \
    sign-tx \
    --private-key "$SENDER_PRIVATE_KEY_HEX" \
    --tx "$UNSIGNED_TRANSACTION_JSON" \
  | jq -c '.transaction'
)"

ENVELOPE_JSON="$(jq -cn \
  --arg description "Deterministic launch transaction required in block 1" \
  --argjson required_block_index "$REQUIRED_BLOCK_INDEX" \
  --argjson transaction "$SIGNED_TRANSACTION_JSON" \
  '{
    description: $description,
    required_block_index: $required_block_index,
    transaction: $transaction
  }')"

build_output_targets

for output_path in "${OUTPUT_TARGETS[@]}"; do
  mkdir -p "$(dirname "$output_path")"
  printf '%s\n' "$ENVELOPE_JSON" > "$output_path"
  echo "Wrote launch block-1 transaction envelope: $output_path"
done

TX_HASH="$(printf '%s' "$SIGNED_TRANSACTION_JSON" | jq -r '.hash // empty')"
echo "Prepared deterministic launch block-1 transaction:"
echo "  from:   $SENDER_ADDRESS"
echo "  to:     $RECIPIENT_ADDRESS"
echo "  amount: ${AMOUNT_SNRG} SNRG (${AMOUNT_NWEI} nWei)"
echo "  fee:    $((GAS_PRICE_NWEI * GAS_LIMIT)) nWei"
echo "  memo:   $MEMO"
if [[ -n "$TX_HASH" ]]; then
  echo "  hash:   $TX_HASH"
fi
