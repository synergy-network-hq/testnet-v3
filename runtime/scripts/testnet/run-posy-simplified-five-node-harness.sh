#!/usr/bin/env bash
set -euo pipefail

runtime_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/posy-five-node.XXXXXX")}"

cd "$runtime_root"
cargo run -p synergy-testnet --bin posy-simplified-five-driver-harness -- run --work-dir "$work_dir"
