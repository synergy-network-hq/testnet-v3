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
  if [[ -n "${WASI_SDK_DIR:-}" && -n "${CC_wasm32_wasi:-}" ]]; then
    return 0
  fi

  local candidates=(
    "$HOME/.cache/synq/wasi-sdk-20.0/share/wasi-sysroot"
    "$WORKSPACE_ROOT/../current-focus2/wasi-sdk-20.0/share/wasi-sysroot"
    "/Users/devpup/Desktop/Synergy/synergy-components/current-focus2/wasi-sdk-20.0/share/wasi-sysroot"
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
    local clang_path
    clang_path="$(cd "$WASI_SDK_DIR/../.." && pwd)/bin/clang"
    if [[ -x "$clang_path" ]]; then
      export CC_wasm32_wasi="$clang_path"
    fi
  fi

  [[ -n "${CC_wasm32_wasi:-}" ]]
}

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js is required for wasm runtime smoke execution." >&2
  exit 1
fi

WORKSPACE_ROOT="$(find_synq_workspace_root "$PWD" || true)"
if [[ -z "$WORKSPACE_ROOT" ]]; then
  WORKSPACE_ROOT="$(find_synq_workspace_root "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)" || true)"
fi
if [[ -z "$WORKSPACE_ROOT" ]]; then
  echo "Error: could not locate SynQ workspace root with member 'aegis-pqsynq/pqsynq'." >&2
  exit 1
fi

if ! configure_wasi_env; then
  echo "Error: WASI SDK not configured." >&2
  echo "Run: bash aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh" >&2
  exit 1
fi

cd "$WORKSPACE_ROOT"

cargo build -p wasm-runtime-smoke \
  --target wasm32-wasip1 \
  --locked

WASM_ARTIFACT="$WORKSPACE_ROOT/target/wasm32-wasip1/debug/wasm-runtime-smoke.wasm"
if [[ ! -f "$WASM_ARTIFACT" ]]; then
  echo "Error: wasm artifact not found at $WASM_ARTIFACT" >&2
  exit 1
fi

WASM_ARTIFACT="$WASM_ARTIFACT" node --input-type=module <<'NODE'
import { readFileSync } from 'node:fs';
import { WASI } from 'node:wasi';

const artifactPath = process.env.WASM_ARTIFACT;
if (!artifactPath) {
  console.error('WASM artifact path not provided');
  process.exit(1);
}

const wasi = new WASI({
  version: 'preview1',
  args: [],
  env: process.env,
  preopens: {}
});

const wasm = await WebAssembly.compile(readFileSync(artifactPath));
const instance = await WebAssembly.instantiate(wasm, {
  wasi_snapshot_preview1: wasi.wasiImport
});

wasi.start(instance);
NODE

echo "WASM runtime smoke complete: PASS"
