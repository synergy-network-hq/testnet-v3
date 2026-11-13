#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEY_DIR="${1:-/Users/devpup/Desktop/testnet-keyfiles}"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/release-artifacts/testnet}"

exec python3 "$ROOT_DIR/scripts/testnet/genesis_tool.py" \
  --root "$ROOT_DIR" \
  rebuild-keyfiles "$KEY_DIR" \
  --out-dir "$OUT_DIR"
