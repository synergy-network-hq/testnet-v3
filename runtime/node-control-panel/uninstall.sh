#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -s)" in
  Linux)
    exec "$SCRIPT_DIR/scripts/uninstall/clean-uninstall-linux.sh" "$@"
    ;;
  Darwin)
    exec "$SCRIPT_DIR/scripts/uninstall/clean-uninstall-macos.sh" "$@"
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    echo "Use scripts/uninstall/clean-uninstall-windows.ps1 on Windows." >&2
    exit 1
    ;;
esac
