#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLERS_DIR="$ROOT_DIR/testnet/runtime/installers"
LEGACY_BASE_DIR="${LEGACY_SETUP_PACKAGES_BASE_DIR:-$ROOT_DIR/../../genesis-nodes/machine6-macmini-validator1}"

destinations=(
  "$HOME/Desktop/setup-packages"
  "$LEGACY_BASE_DIR/setup-packages"
  "$LEGACY_BASE_DIR/setup-packages 2"
)

sources=(
  "validator-1:$INSTALLERS_DIR/Validator-01/keys/setup-package.json"
  "validator-2:$INSTALLERS_DIR/Validator-02/keys/setup-package.json"
  "validator-3:$INSTALLERS_DIR/Validator-03/keys/setup-package.json"
  "validator-4:$INSTALLERS_DIR/Validator-04/keys/setup-package.json"
  "validator-5:$INSTALLERS_DIR/Validator-05/keys/setup-package.json"
)

for destination in "${destinations[@]}"; do
  mkdir -p "$destination"
  for entry in "${sources[@]}"; do
    name="${entry%%:*}"
    source_file="${entry#*:}"
    if [[ ! -f "$source_file" ]]; then
      echo "Missing generated setup package: $source_file" >&2
      exit 1
    fi
    cp "$source_file" "$destination/${name}-setup-package.json"
    echo "Synced $name -> $destination/${name}-setup-package.json"
  done
done
