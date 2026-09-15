#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if ! command -v npm >/dev/null 2>&1; then
  echo "Error: npm is required to run SDK integration tests." >&2
  exit 1
fi

cd "${SDK_ROOT}"

if [[ ! -d node_modules ]]; then
  npm install
fi

npm run test:integration
