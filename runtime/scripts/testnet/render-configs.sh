#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CANONICAL_SCRIPT="$ROOT_DIR/node-control-panel/scripts/testnet/render-configs.sh"

if [[ ! -x "$CANONICAL_SCRIPT" ]]; then
  echo "Canonical render script missing or not executable: $CANONICAL_SCRIPT" >&2
  exit 1
fi

exec "$CANONICAL_SCRIPT" "$@"
