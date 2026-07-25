#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="$ROOT_DIR/target/release/synergy-testnet"

usage() {
  cat <<USAGE
Usage: $0 <start|stop|restart|status|logs> <node-slot-id> [--follow]

Examples:
  $0 start node-01
  $0 status node-01
  $0 logs node-01 --follow
  $0 stop node-01
USAGE
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

ACTION="$1"
NODE_SLOT_ID="$2"
FOLLOW_FLAG="${3:-}"

CONFIG_FILE="$ROOT_DIR/testnet/runtime/configs/${NODE_SLOT_ID}.toml"
DATA_DIR="$ROOT_DIR/data/testnet15/${NODE_SLOT_ID}"
PID_FILE="$DATA_DIR/node.pid"
LOG_DIR="$DATA_DIR/logs"
OUT_FILE="$LOG_DIR/node.out"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config not found: $CONFIG_FILE" >&2
  echo "Run scripts/testnet/render-configs.sh first." >&2
  exit 1
fi

if [[ ! -x "$BINARY" ]]; then
  echo "Binary not found at $BINARY; building release binary..."
  (cd "$ROOT_DIR" && cargo build --release)
fi

mkdir -p "$LOG_DIR" "$DATA_DIR/chain"

is_running() {
  if [[ -f "$PID_FILE" ]]; then
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

start_node() {
  if is_running; then
    echo "$NODE_SLOT_ID is already running (PID $(cat "$PID_FILE"))"
    exit 0
  fi

  nohup "$BINARY" start --config "$CONFIG_FILE" > "$OUT_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  echo "Started $NODE_SLOT_ID with PID $(cat "$PID_FILE")"
  echo "Log output: $OUT_FILE"
}

stop_node() {
  if ! is_running; then
    echo "$NODE_SLOT_ID is not running"
    rm -f "$PID_FILE"
    exit 0
  fi

  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true

  for _ in {1..10}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done

  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi

  rm -f "$PID_FILE"
  echo "Stopped $NODE_SLOT_ID"
}

status_node() {
  if is_running; then
    echo "$NODE_SLOT_ID is running (PID $(cat "$PID_FILE"))"
  else
    echo "$NODE_SLOT_ID is stopped"
  fi
}

show_logs() {
  if [[ ! -f "$OUT_FILE" ]]; then
    echo "Log file not found: $OUT_FILE"
    exit 1
  fi

  if [[ "$FOLLOW_FLAG" == "--follow" ]]; then
    tail -f "$OUT_FILE"
  else
    tail -n 100 "$OUT_FILE"
  fi
}

case "$ACTION" in
  start)
    start_node
    ;;
  stop)
    stop_node
    ;;
  restart)
    stop_node
    start_node
    ;;
  status)
    status_node
    ;;
  logs)
    show_logs
    ;;
  *)
    usage
    exit 1
    ;;
esac
