#!/bin/sh
set -eu
test "${1:-}" = "--remove-binaries-only" || { echo "explicit --remove-binaries-only required" >&2; exit 1; }
rm -f /usr/local/bin/synergy-node
echo "node state and keys retained"
