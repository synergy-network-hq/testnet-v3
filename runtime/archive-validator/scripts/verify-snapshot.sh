#!/usr/bin/env bash
set -euo pipefail
snapshot="${1:?snapshot path required}"
synergy-archive verify-snapshot --snapshot "${snapshot}"
