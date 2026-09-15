# No-Stub PQC Audit Checklist

Scope: canonical Aegis-PQC PQVM module.

## Fixed

- Merged Synergy integration routing into the canonical PQVM module.
- Added Synergy chain constants, RPC route metadata, deterministic ABI dispatch tests, and Synergy platform gating.
- Replaced hard-coded license MAC defaults with fail-closed `AEGIS_LICENSE_SECRET` resolution.
- Removed the `dev-license-secret` feature so production builds cannot compile in a default secret.
- Kept test licensing explicit: tests must run with `AEGIS_LICENSE_SECRET` in the environment.
- Confirmed active Rust source uses FIPS names (`ML-KEM`, `ML-DSA`, `FN-DSA`) rather than Kyber/Dilithium implementation names.

## Verified

- `cargo check --all-features`
- `AEGIS_LICENSE_SECRET=0123456789abcdef0123456789abcdef cargo test --test abi_roundtrip --test licensing_adapter_smoke --test synergy_integration --test integrations_dispatch --test vm_validation`
- Active-source scan over `src` and `Cargo.toml` returned no hits for Kyber, Dilithium, stub markers, placeholder markers, or built-in license defaults.

## Notes

- Legacy benchmark and functional harnesses under `tests/benchmarks` and `tests/functional` still contain inherited fixture and simulation terminology. They are not active Rust PQVM source, and they were excluded from the active-source gate above.
