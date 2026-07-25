# License-Ready Package Bundle - Aegis PQVM

## Bundle contents
- module source (`src`, `tests`, `examples`, `vendor`, `pqcore`)
- manifests and build scripts (`Cargo.toml`, `Cargo.lock`, `build.rs`)
- security/compliance/release documentation (`docs/**`)
- release evidence artifacts (`artifacts/**`)

## Generation
```bash
cd aegis-pqvm
./scripts/package_customer_bundle.sh
```

## Validation
- verify `artifacts/package/*.tgz.sha256`
- verify manifest and SBOM presence
- confirm excluded local build directories are absent from package
