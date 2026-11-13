# WASI Toolchain Bootstrap (Pinned)

## Purpose

Provide a deterministic local bootstrap for WASI-enabled validation of `aegis-pqsynq`.

## Pinned Version

- WASI SDK major: `20`
- WASI SDK version: `20.0`
- Default install location: `${HOME}/.cache/synq/wasi-sdk-20.0`

## Bootstrap Command

```bash
bash aegis-pqsynq/pqsynq/scripts/bootstrap_wasi_sdk.sh
```

## Environment Exports

```bash
export WASI_SDK_DIR="$HOME/.cache/synq/wasi-sdk-20.0/share/wasi-sysroot"
export CC_wasm32_wasi="$HOME/.cache/synq/wasi-sdk-20.0/bin/clang"
```

## Validation

```bash
cargo check -p aegis-pqsynq --target wasm32-wasip1 \
  --no-default-features --features "mlkem,mldsa,fndsa,hqckem"
```

## Notes

- `aegis-pqsynq/pqsynq/scripts/run_tests.sh` auto-detects this install path.
- CI wiring for this bootstrap is implemented in `aegis-pqsynq/pqsynq/.github/workflows/ci.yml`.
