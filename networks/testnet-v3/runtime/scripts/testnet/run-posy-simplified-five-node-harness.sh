#!/usr/bin/env bash
set -euo pipefail

runtime_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/posy-five-node.XXXXXX")}"
fresh_p3_genesis="${SYNERGY_GENESIS_FILE:?set SYNERGY_GENESIS_FILE to the complete, signed fresh-P3 Genesis}"

test -f "$fresh_p3_genesis"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export SYNERGY_GENESIS_FILE="$fresh_p3_genesis"

cd "$runtime_root"
cargo run --locked -p synergy-testnet --bin posy-simplified-five-node-harness -- run --work-dir "$work_dir"
