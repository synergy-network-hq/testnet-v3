#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CANONICAL_GENESIS_FILE="${SYNERGY_TESTNET_CANONICAL_GENESIS_FILE:-$ROOT_DIR/../config/genesis.json}"
OUTPUT_FILE="${1:-$ROOT_DIR/testnet/runtime/configs/genesis/genesis.json}"
INSTALLERS_ROOT="${INSTALLERS_ROOT:-$ROOT_DIR/testnet/runtime/installers}"
BOOTSTRAP_ROOT="${BOOTSTRAP_ROOT:-$ROOT_DIR/../bootstrap-bundles}"

if [[ ! -f "$CANONICAL_GENESIS_FILE" ]]; then
  echo "Missing canonical genesis file: $CANONICAL_GENESIS_FILE" >&2
  exit 1
fi

copy_genesis() {
  local target_file="$1"
  mkdir -p "$(dirname "$target_file")"
  cp "$CANONICAL_GENESIS_FILE" "$target_file"
  echo "Canonical genesis synced to: $target_file"
}

sync_setup_package_genesis() {
  local package_file="$1"
  python3 - "$CANONICAL_GENESIS_FILE" "$package_file" <<'PY'
import json
import pathlib
import sys

canonical_path = pathlib.Path(sys.argv[1])
package_path = pathlib.Path(sys.argv[2])

canonical_genesis = json.loads(canonical_path.read_text(encoding="utf-8"))
package = json.loads(package_path.read_text(encoding="utf-8"))
artifacts = package.setdefault("artifacts", {})
artifacts["genesis"] = canonical_genesis
package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
PY
  echo "Canonical genesis embedded into setup package: $package_file"
}

copy_genesis "$OUTPUT_FILE"

if [[ -d "$INSTALLERS_ROOT" ]]; then
  while IFS= read -r installer_genesis; do
    copy_genesis "$installer_genesis"
  done < <(find "$INSTALLERS_ROOT" -path '*/config/genesis.json' | sort)

  while IFS= read -r setup_package; do
    sync_setup_package_genesis "$setup_package"
  done < <(find "$INSTALLERS_ROOT" -path '*/keys/setup-package.json' | sort)
fi

if [[ -d "$BOOTSTRAP_ROOT" ]]; then
  while IFS= read -r bootstrap_genesis; do
    copy_genesis "$bootstrap_genesis"
  done < <(find "$BOOTSTRAP_ROOT" -path '*/config/genesis.json' | sort)
fi
