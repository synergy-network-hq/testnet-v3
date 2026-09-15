# Snapshot Format

Each snapshot contains canonical `manifest.json`, detached `manifest.aegis.sig`, state chunks, required headers and QCs, validator and cluster proofs, protocol proof, verification report, chunk hashes, and content root.

Manifest domain: `SYNERGY_ARCHIVE_SNAPSHOT_MANIFEST_V1`.

Published archive-validator distributions use a `distribution-manifest.json` plus `distribution-manifest.sig`, a zstd-compressed tar archive, 512 MiB chunk files, `archive.sha256`, `chunk-checksums.sha256`, `source-snapshot-manifest.json`, and `verification-report.json`.

The receiver contract is platform-neutral: the distribution manifest declares `supported_receiver_operating_systems = ["macos", "linux", "windows"]`, and the archive contains only relative launch-approved state files. Platform-specific installers or scripts must not reinterpret snapshot contents; they only download, verify, extract, and copy those state files into the node workspace.
