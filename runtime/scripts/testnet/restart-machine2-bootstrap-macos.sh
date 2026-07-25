#!/usr/bin/env bash
set -euo pipefail

BOOTNODE_DIR="${BOOTNODE_DIR:-$HOME/bootnode2}"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Missing required file: $path" >&2
    exit 1
  fi
}

print_step() {
  printf '\n==> %s\n' "$1"
}

require_file "$BOOTNODE_DIR/install_and_start.sh"
require_file "$BOOTNODE_DIR/nodectl.sh"
require_file "$BOOTNODE_DIR/bin/synergy-testnet-darwin-arm64"

print_step "Checking bootnode2 bundle"
arch="$(uname -m)"
echo "machine architecture: $arch"
if [[ "$arch" != "arm64" ]]; then
  echo "bootnode2 currently requires an Apple Silicon Mac. Found: $arch" >&2
  exit 1
fi
grep -n "xattr -dr com.apple.quarantine" "$BOOTNODE_DIR/install_and_start.sh"

print_step "Restarting bootnode2"
chmod +x \
  "$BOOTNODE_DIR/install_and_start.sh" \
  "$BOOTNODE_DIR/nodectl.sh" \
  "$BOOTNODE_DIR/bin/synergy-testnet-darwin-arm64"
xattr -dr com.apple.quarantine "$BOOTNODE_DIR" 2>/dev/null || true
codesign --force --sign - "$BOOTNODE_DIR/bin/synergy-testnet-darwin-arm64"
"$BOOTNODE_DIR/nodectl.sh" stop || true
"$BOOTNODE_DIR/install_and_start.sh"
"$BOOTNODE_DIR/nodectl.sh" status
"$BOOTNODE_DIR/nodectl.sh" logs

print_step "Completed"
echo "bootnode2 was restarted from:"
echo "  $BOOTNODE_DIR"
