#!/usr/bin/env bash
set -euo pipefail
command -v aegis-pqvm >/dev/null 2>&1 || { echo "aegis-pqvm is unavailable" >&2; exit 1; }
aegis-pqvm --version >/dev/null 2>&1 || { echo "aegis-pqvm failed version check" >&2; exit 1; }
echo "aegis-pqvm available"
