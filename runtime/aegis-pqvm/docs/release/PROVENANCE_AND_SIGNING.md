# Provenance and Signing - Aegis PQVM

## Mechanism
- GitHub build provenance attestation via `actions/attest-build-provenance@v2`
- release checksum manifests from `scripts/generate_release_manifest.sh`
- SBOM generation from `scripts/generate_sbom.sh`

## Required evidence
- `artifacts/checksums/release-manifest.txt`
- `artifacts/checksums/release-manifest.sha256`
- `artifacts/sbom/aegis-pqvm.cdx.json`
- attestation metadata bound to packaged bundle and checksum subjects
