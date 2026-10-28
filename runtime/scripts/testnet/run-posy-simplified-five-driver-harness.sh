#!/usr/bin/env bash
set -euo pipefail

runtime_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="${1:-$(mktemp -d "${TMPDIR:-/tmp}/posy-five-driver.XXXXXX")}"

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

cd "$runtime_root"
cargo run --locked -p synergy-testnet --bin posy-simplified-five-driver-harness -- run --work-dir "$work_dir"
