# CMVP/FIPS Boundary and Self-Test Readiness - Aegis PQVM

## Candidate cryptographic boundary
Included:
- `src/pqc/**` algorithm bindings
- deterministic integration dispatch and ABI parser (`src/integrations/**`)
- key lifecycle/security utility modules

Excluded:
- benchmark binaries and test harnesses
- archived logs and local development artifacts
- fuzz-only harnesses and workflow glue

## Self-test strategy
- KAT replay during validation phase through deterministic test suite
- startup/runtime self-test hooks for security primitives (`SelfTest` trait)
- integrity verification of release manifest and checksum bundle before deployment

## Required package set for CMVP readiness
- module boundary narrative and service mapping
- error-state behavior and fail-closed policy description
- operational environment constraints per target chain runtime
- archived KAT/self-test evidence linked to exact release artifact hashes
