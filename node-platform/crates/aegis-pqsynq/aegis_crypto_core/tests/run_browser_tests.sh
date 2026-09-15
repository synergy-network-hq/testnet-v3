#!/usr/bin/env bash
set -euo pipefail

# Headless browser wasm build check (wasm32-unknown-unknown).
# Prereqs:
#   - rustup target add wasm32-unknown-unknown
#   - A headless browser available (chromium or firefox)
#   - Optionally set: WASM_BINDGEN_TEST_BROWSER=chrome or firefox

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRATE_DIR="$ROOT_DIR/aegis_crypto_core"

echo "[INFO] Using ROOT_DIR: $ROOT_DIR"

# Ensure target added
if ! rustup target list --installed | grep -q "^wasm32-unknown-unknown$"; then
  echo "[INFO] Installing rust target wasm32-unknown-unknown..."
  rustup target add wasm32-unknown-unknown
fi

# Ensure a browser is available for wasm-bindgen-test-runner
if [ -z "${WASM_BINDGEN_TEST_BROWSER:-}" ]; then
  # Try to select a reasonable default
  if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || command -v google-chrome >/dev/null 2>&1; then
    export WASM_BINDGEN_TEST_BROWSER=chrome
  elif command -v firefox >/dev/null 2>&1; then
    export WASM_BINDGEN_TEST_BROWSER=firefox
  else
    echo "[WARN] No chromium/chrome or firefox found in PATH."
    echo "       Set WASM_BINDGEN_TEST_BROWSER=chrome or firefox and ensure the browser binary is installed and discoverable."
    echo "       Proceeding; wasm-bindgen-test-runner may fail without a browser."
  fi
fi
echo "[INFO] Using browser: ${WASM_BINDGEN_TEST_BROWSER:-auto-detect-failed}"

echo "[INFO] Building browser WASM target (wasm32-unknown-unknown + features wasm,js-bindings)..."
(
  cd "$CRATE_DIR"
  cargo build --target wasm32-unknown-unknown --no-default-features --features "mlkem,mldsa,fndsa,wasm,js-bindings"
)

echo "[INFO] Browser WASM build completed."
