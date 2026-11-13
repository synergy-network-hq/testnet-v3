#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUBLIC_MANIFEST="${1:-$ROOT_DIR/testnet-public-validator-manifest.json}"

exec python3 "$ROOT_DIR/scripts/testnet/genesis_tool.py" \
  --root "$ROOT_DIR" \
  rebuild-public-manifest "$PUBLIC_MANIFEST"
