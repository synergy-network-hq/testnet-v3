#!/usr/bin/env bash
set -euo pipefail

runtime_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/posy-five-node.XXXXXX")}"
fresh_p3_genesis="$runtime_root/../launch/posy-v3-genesis-inputs/fresh-p3-genesis-predeployment-public-input.json"

test -f "$fresh_p3_genesis"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export SYNERGY_GENESIS_FILE="$fresh_p3_genesis"

cd "$runtime_root"
cargo run --locked -p synergy-testnet --bin posy-simplified-five-node-harness -- run --work-dir "$work_dir"
