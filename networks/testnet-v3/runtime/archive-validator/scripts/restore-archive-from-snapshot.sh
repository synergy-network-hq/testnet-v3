#!/usr/bin/env bash
set -euo pipefail
snapshot="${1:?snapshot path required}"
synergy-archive verify-snapshot --snapshot "${snapshot}"
echo "Snapshot verified. Restore must install only verified state and preserve evidence."
