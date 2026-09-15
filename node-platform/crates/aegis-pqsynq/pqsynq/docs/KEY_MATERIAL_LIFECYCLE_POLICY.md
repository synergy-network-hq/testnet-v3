# Key Material Lifecycle and Zeroization Policy (SynQ PQ Profile)

## Scope

This policy applies to all secret-bearing material handled by `aegis-pqsynq`:
- KEM secret keys
- KEM shared secrets
- Signature secret keys
- Detached/full signatures before publication
- Context-bearing signed payloads prior to persistence

## Control Objectives

1. Keep secret data lifetime as short as practical.
2. Keep secret data out of logs, traces, and panic messages.
3. Zeroize mutable secret buffers after use.
4. Prefer scoped ownership for secrets over long-lived global buffers.

## Required Handling Rules

1. Secret buffers must be owned by the minimum practical scope.
2. Secret buffers must not be formatted or logged (`Debug`, `Display`, telemetry payloads).
3. Secret buffers copied into temporary `Vec<u8>` values must be wiped with `zeroize_bytes` as soon as no longer needed.
4. Long-lived secret ownership must use `SecretBytes` so buffers are wiped on `Drop`.
5. API boundaries that must expose raw bytes should convert from `SecretBytes` only at the narrowest boundary.

## Implementation Hooks

`aegis-pqsynq` provides:
- `pqsynq::utils::zeroize_bytes(&mut [u8])`
- `pqsynq::SecretBytes` (`Drop`-based zeroization wrapper)

These primitives are mandatory for all new SynQ runtime/SDK secret-handling code.

## Current Limitations

1. Public APIs currently return owned `Vec<u8>` for compatibility with existing SynQ integration layers.
2. Automatic zeroization cannot be guaranteed once callers clone or persist returned secret vectors.
3. FFI implementations may retain internal transient state outside Rust ownership control.

## Engineering Standard Going Forward

1. New APIs should prefer `SecretBytes` for secret outputs and inputs.
2. Existing APIs should be migrated progressively with compatibility shims.
3. Every new secret-bearing pathway must include one negative misuse test (wrong key/wrong context/tamper).
4. Release candidates must pass the `key_material_tests` suite and vector replay suite.
