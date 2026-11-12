#!/usr/bin/env bash

set -euo pipefail

find_synq_workspace_root() {
  local dir="$1"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "$dir/Cargo.toml" ]] && grep -q '"aegis-pqsynq/pqsynq"' "$dir/Cargo.toml"; then
      echo "$dir"
      return 0
    fi
    dir="$(dirname "$dir")"
  done
  return 1
}

configure_wasi_env() {
  if [[ -n "${WASI_SDK_DIR:-}" ]]; then
    return 0
  fi

  local candidates=(
    "/Users/devpup/Desktop/Synergy/synergy-components/current-focus2/wasi-sdk-20.0/share/wasi-sysroot"
    "$WORKSPACE_ROOT/../current-focus2/wasi-sdk-20.0/share/wasi-sysroot"
    "$HOME/.cache/synq/wasi-sdk-20.0/share/wasi-sysroot"
  )

  for candidate in "${candidates[@]}"; do
    if [[ -d "$candidate" ]]; then
      export WASI_SDK_DIR="$candidate"
      break
    fi
  done

  if [[ -z "${WASI_SDK_DIR:-}" ]]; then
    return 1
  fi

  if [[ -z "${CC_wasm32_wasi:-}" ]]; then
    local sdk_bin
    sdk_bin="$(cd "$WASI_SDK_DIR/../.." && pwd)/bin/clang"
    if [[ -x "$sdk_bin" ]]; then
      export CC_wasm32_wasi="$sdk_bin"
    fi
  fi

  return 0
}

WORKSPACE_ROOT="$(find_synq_workspace_root "$PWD" || true)"
if [[ -z "$WORKSPACE_ROOT" ]]; then
  echo "Error: could not find SynQ workspace root with member 'aegis-pqsynq/pqsynq'."
  echo "Run this script from / within the SynQ workspace."
  exit 1
fi

cd "$WORKSPACE_ROOT"

echo "=========================================="
echo "aegis-pqsynq validation suite"
echo "workspace: $WORKSPACE_ROOT"
echo "=========================================="

echo "[1/14] cargo fmt -p aegis-pqsynq --check"
cargo fmt -p aegis-pqsynq -- --check

echo "[2/14] cargo clippy -p aegis-pqsynq --all-targets --all-features --no-deps --locked"
cargo clippy -p aegis-pqsynq --all-targets --all-features --no-deps --locked -- -D warnings

echo "[3/14] cargo audit (optional)"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "Warning: cargo-audit not installed; skipping dependency vulnerability audit."
fi

echo "[4/14] cargo test -p aegis-pqsynq --all-targets --all-features --locked"
cargo test -p aegis-pqsynq --all-targets --all-features --locked

echo "[5/14] cargo doc -p aegis-pqsynq --no-deps --locked"
cargo doc -p aegis-pqsynq --no-deps --locked

echo "[6/14] cargo bench -p aegis-pqsynq --no-run --locked"
cargo bench -p aegis-pqsynq --no-run --locked

echo "[7/14] cargo check -p aegis-pqsynq --no-default-features --locked"
cargo check -p aegis-pqsynq --no-default-features --locked

echo "[8/14] cargo check -p aegis-pqsynq --target wasm32-unknown-unknown --no-default-features --locked"
cargo check -p aegis-pqsynq --target wasm32-unknown-unknown --no-default-features --locked

echo "[9/14] cargo check -p pqsynq-no-std-smoke --target wasm32-wasip1 --locked"
echo "[10/14] cargo check -p aegis-pqsynq --target wasm32-wasip1 --no-default-features --features mlkem,mldsa,fndsa,hqckem --locked"
if configure_wasi_env; then
  cargo check -p pqsynq-no-std-smoke --target wasm32-wasip1 --locked
  cargo check -p aegis-pqsynq --target wasm32-wasip1 --no-default-features --features "mlkem,mldsa,fndsa,hqckem" --locked
else
  echo "Warning: WASI SDK not found (WASI_SDK_DIR unset and no known local path found)."
  echo "Run: bash aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh"
  echo "Skipping wasm32-wasip1 no-std and full-feature checks."
fi

echo "[11/14] wasm32-wasip1 runtime smoke"
bash aegis-pqsynq/pqsynq/scripts/run_wasm_runtime_smoke.sh

echo "[12/14] cargo test -p cli --test integration_test --locked"
cargo test -p cli --test integration_test --locked

echo "[13/14] SDK integration tests"
bash sdk/scripts/run_integration_tests.sh

echo "[14/14] generate compliance report artifact"
bash aegis-pqsynq/pqsynq/scripts/generate_compliance_report.sh >/dev/null

echo "=========================================="
echo "Validation complete: PASS"
echo "=========================================="
