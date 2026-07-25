#!/usr/bin/env bash
# run-signed-load.sh
#
# Launch a signed-transaction load test against testnet. Wraps
# signed-transaction-runner.py with public-RPC defaults and a
# foreground/background mode. Sender and private key are intentionally explicit;
# do not use validator operational keys for routine transaction tests.
#
# Usage:
#   scripts/testnet/run-signed-load.sh [options] [-- ...extra-args]
#
# Common options:
#   --rpc-url URL            JSON-RPC endpoint (default: public testnet RPC)
#   --duration-seconds N     Run duration (default: 10800 = 3 hours)
#   --interval-seconds F     Seconds between txs (default: 120)
#   --amount-nwei N          Per-tx amount in nWei (default: 1)
#   --gas-price N            (default: 1000)
#   --gas-limit N            (default: 21000)
#   --sender ADDR            Sender address (required unless SENDER is set)
#   --receiver ADDR          Receiver address (default: genesis Faucet)
#   --private-key-file PATH  Sender private key file (required unless PRIVATE_KEY_FILE is set)
#   --background             Run detached, log to scripts/testnet/logs
#   --foreground             Run attached (default)
#   --max-tx N               Optional cap on total tx count
#   --no-rebuild-cli         Skip auto-build of wallet-pqc-cli
#
# Extra args after `--` are passed verbatim to signed-transaction-runner.py.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$ROOT_DIR/scripts/testnet"
LOG_DIR="$SCRIPT_DIR/logs"
PY_RUNNER="$SCRIPT_DIR/signed-transaction-runner.py"
CLI_BIN="$ROOT_DIR/target/debug/wallet-pqc-cli"
CARGO_MANIFEST="$ROOT_DIR/src/Cargo.toml"

# Defaults. Sender/private key must be supplied by CLI args or environment.
RPC_URL="${RPC_URL:-https://testnet-core-rpc.synergy-network.io}"
SENDER="${SENDER:-}"
RECEIVER="${RECEIVER:-synw1y9vkp3pfdq88vs32v5378dvq23py2k9kkavm}"
PRIVATE_KEY_FILE="${PRIVATE_KEY_FILE:-}"
DURATION_SECONDS="${DURATION_SECONDS:-10800}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-120}"
AMOUNT_NWEI="${AMOUNT_NWEI:-1}"
GAS_PRICE="${GAS_PRICE:-1000}"
GAS_LIMIT="${GAS_LIMIT:-21000}"
MEMO="${MEMO:-load-test}"
MAX_TX="${MAX_TX:-0}"
MODE="foreground"
REBUILD_CLI=1
PASSTHROUGH=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rpc-url)            RPC_URL="$2"; shift 2 ;;
    --duration-seconds)   DURATION_SECONDS="$2"; shift 2 ;;
    --interval-seconds)   INTERVAL_SECONDS="$2"; shift 2 ;;
    --amount-nwei)        AMOUNT_NWEI="$2"; shift 2 ;;
    --gas-price)          GAS_PRICE="$2"; shift 2 ;;
    --gas-limit)          GAS_LIMIT="$2"; shift 2 ;;
    --memo)               MEMO="$2"; shift 2 ;;
    --max-tx)             MAX_TX="$2"; shift 2 ;;
    --sender)             SENDER="$2"; shift 2 ;;
    --receiver)           RECEIVER="$2"; shift 2 ;;
    --private-key-file)   PRIVATE_KEY_FILE="$2"; shift 2 ;;
    --background)         MODE="background"; shift ;;
    --foreground)         MODE="foreground"; shift ;;
    --no-rebuild-cli)     REBUILD_CLI=0; shift ;;
    --)                   shift; PASSTHROUGH+=("$@"); break ;;
    -h|--help)
      sed -n '2,28p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if [[ -z "$SENDER" ]]; then
  echo "--sender or SENDER is required" >&2
  exit 1
fi

if [[ -z "$PRIVATE_KEY_FILE" ]]; then
  echo "--private-key-file or PRIVATE_KEY_FILE is required" >&2
  exit 1
fi

if [[ ! -x "$CLI_BIN" ]]; then
  if (( REBUILD_CLI == 1 )); then
    echo "wallet-pqc-cli not found at $CLI_BIN — building"
    (cd "$ROOT_DIR/src" && cargo build --quiet --bin wallet-pqc-cli)
  else
    echo "wallet-pqc-cli missing and --no-rebuild-cli given: $CLI_BIN" >&2
    exit 1
  fi
fi

if [[ ! -f "$PRIVATE_KEY_FILE" ]]; then
  echo "Private key file not found: $PRIVATE_KEY_FILE" >&2
  exit 1
fi

mkdir -p "$LOG_DIR"

CMD=(
  python3 -u "$PY_RUNNER"
  --rpc-url "$RPC_URL"
  --cli "$CLI_BIN"
  --sender "$SENDER"
  --receiver "$RECEIVER"
  --private-key-file "$PRIVATE_KEY_FILE"
  --amount-nwei "$AMOUNT_NWEI"
  --gas-price "$GAS_PRICE"
  --gas-limit "$GAS_LIMIT"
  --memo "$MEMO"
  --duration-seconds "$DURATION_SECONDS"
  --interval-seconds "$INTERVAL_SECONDS"
)
if (( MAX_TX > 0 )); then
  CMD+=(--max-tx "$MAX_TX")
fi
if (( ${#PASSTHROUGH[@]} > 0 )); then
  CMD+=("${PASSTHROUGH[@]}")
fi

TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$LOG_DIR/signed-runner-$TS.log"
PID_FILE="$LOG_DIR/signed-runner-live.pid"

if [[ "$MODE" == "background" ]]; then
  echo "Launching detached. Log: $LOG_FILE"
  nohup "${CMD[@]}" >"$LOG_FILE" 2>&1 &
  PID=$!
  echo "$PID" > "$PID_FILE"
  echo "PID $PID written to $PID_FILE"
  echo "Tail with: tail -f \"$LOG_FILE\""
else
  echo "Running attached; log also tee'd to $LOG_FILE"
  "${CMD[@]}" 2>&1 | tee "$LOG_FILE"
fi
