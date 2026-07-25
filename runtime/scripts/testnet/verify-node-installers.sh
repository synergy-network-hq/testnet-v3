#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLERS_DIR="$ROOT_DIR/testnet/runtime/installers"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"

if [[ ! -d "$INSTALLERS_DIR" ]]; then
  echo "Installers directory missing: $INSTALLERS_DIR" >&2
  exit 1
fi

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Inventory file missing: $INVENTORY_FILE" >&2
  exit 1
fi

required_files=(
  "bin/synergy-testnet-linux-amd64"
  "bin/synergy-testnet-darwin-arm64"
  "bin/synergy-testnet-windows-amd64.exe"
  "config/node.toml"
  "node.env"
  "install_and_start.sh"
  "nodectl.sh"
  "install_and_start.ps1"
  "nodectl.ps1"
  "COMMANDS.txt"
  "README.txt"
  "BINARY_STATUS.txt"
)

missing_count=0
syntax_fail_count=0
fallback_linux_count=0
fallback_windows_count=0

while IFS=, read -r machine_id _ || [[ -n "${machine_id:-}" ]]; do
  [[ "$machine_id" == "machine_id" ]] && continue
  node_dir="$INSTALLERS_DIR/$machine_id"

  if [[ ! -d "$node_dir" ]]; then
    echo "MISSING installer folder: $node_dir" >&2
    missing_count=$((missing_count + 1))
    continue
  fi

  for rel_path in "${required_files[@]}"; do
    if [[ ! -f "$node_dir/$rel_path" ]]; then
      echo "MISSING file: $node_dir/$rel_path" >&2
      missing_count=$((missing_count + 1))
    fi
  done

  if [[ -f "$node_dir/install_and_start.sh" ]] && ! bash -n "$node_dir/install_and_start.sh"; then
    echo "SYNTAX ERROR: $node_dir/install_and_start.sh" >&2
    syntax_fail_count=$((syntax_fail_count + 1))
  fi

  if [[ -f "$node_dir/nodectl.sh" ]] && ! bash -n "$node_dir/nodectl.sh"; then
    echo "SYNTAX ERROR: $node_dir/nodectl.sh" >&2
    syntax_fail_count=$((syntax_fail_count + 1))
  fi

  if [[ -f "$node_dir/BINARY_STATUS.txt" ]] && grep -q "Linux Binary" "$node_dir/BINARY_STATUS.txt"; then
    if grep -q "fallback-prebuilt(binaries/synergy-testnet-linux-amd64)" "$node_dir/BINARY_STATUS.txt"; then
      fallback_linux_count=$((fallback_linux_count + 1))
    fi
  fi

  if [[ -f "$node_dir/BINARY_STATUS.txt" ]] && grep -q "Windows Binary" "$node_dir/BINARY_STATUS.txt"; then
    if grep -q "fallback-prebuilt(binaries/synergy-testnet-windows-amd64.exe)" "$node_dir/BINARY_STATUS.txt"; then
      fallback_windows_count=$((fallback_windows_count + 1))
    fi
  fi
done < "$INVENTORY_FILE"

echo "Installer verification summary:"
echo "- missing_items: $missing_count"
echo "- script_syntax_failures: $syntax_fail_count"
echo "- installers_with_fallback_linux_binary: $fallback_linux_count"
echo "- installers_with_fallback_windows_binary: $fallback_windows_count"

if [[ "$missing_count" -gt 0 || "$syntax_fail_count" -gt 0 ]]; then
  exit 2
fi

if [[ "$fallback_linux_count" -gt 0 ]]; then
  echo "WARNING: One or more installers use fallback Linux binaries." >&2
fi

if [[ "$fallback_windows_count" -gt 0 ]]; then
  echo "WARNING: One or more installers use fallback Windows binaries." >&2
fi

echo "PASS: installer structure and script syntax checks succeeded."
