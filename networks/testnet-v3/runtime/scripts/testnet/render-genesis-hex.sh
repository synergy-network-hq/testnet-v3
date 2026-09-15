#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GENESIS_FILE="${1:-$ROOT_DIR/genesis.testnet.json}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/release-artifacts/testnet}"

exec python3 "$ROOT_DIR/scripts/testnet/genesis_tool.py" \
  --root "$ROOT_DIR" \
  export --genesis "$GENESIS_FILE" --out-dir "$OUT_DIR"
