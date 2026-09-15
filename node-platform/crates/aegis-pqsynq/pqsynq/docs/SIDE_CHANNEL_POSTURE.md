# Side-Channel Posture and Assumptions

## Scope

This statement covers `aegis-pqsynq` as a Rust facade over underlying PQClean-based `pqrust` primitives.

## Security Posture

1. `aegis-pqsynq` does not claim formal side-channel resistance on all deployment targets.
2. Primary guarantees are functional correctness and explicit failure propagation.
3. Constant-time behavior is delegated to upstream primitive implementations where provided.

## Assumptions

1. Execution environments are not fully hostile microarchitectural probing environments by default.
2. Callers enforce process isolation and minimize cross-tenant key-sharing exposure.
3. Compiler/runtime configurations avoid debug instrumentation in production cryptographic paths.

## Controls in This Layer

1. Zeroization helpers are provided (`SecretBytes`, `zeroize_bytes`) to reduce key retention windows.
2. Error handling avoids panic-based failure paths for shipped KEM/signature wrappers.
3. Misuse-resistance tests validate wrong-key/wrong-context/tamper behavior on exposed APIs.

## Out-of-Scope for This Layer

1. Cache-timing hardening guarantees for every CPU and compiler target.
2. Power/EM side-channel resistance claims.
3. Fault-injection resistance claims.

## Required Operational Guidance

1. Run production builds with hardened compiler/linker settings.
2. Avoid sharing cryptographic execution cores between mutually untrusted tenants.
3. Treat side-channel hardening as a platform + runtime responsibility, not solely a library responsibility.
