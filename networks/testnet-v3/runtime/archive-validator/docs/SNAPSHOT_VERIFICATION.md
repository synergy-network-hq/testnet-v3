# Snapshot Verification

Validators must reject snapshots with missing or invalid Aegis PQC signatures, wrong chain ID, wrong network ID, wrong genesis hash, wrong state root, invalid QC, corrupted content root, corrupted chunk hash, unauthorized signer, or unsupported state format.

Receivers must also reject wrong-class snapshots before download or extraction. The default scheduled classes are `validator-pruned`, `support-relayer`, `support-observer`, `indexer-replay`, `support-rpc`, and `archive-full`; `indexer-full` and `archive-bootstrap` remain bounded manual repair classes only. Distribution archives use zstd, 512 MiB chunks, per-chunk SHA-256, and whole-archive SHA-256.

Published distribution manifests must declare `supported_receiver_operating_systems` with `macos`, `linux`, and `windows`. The snapshot state files remain platform-neutral; macOS, Linux, and Windows receivers differ only in installer/service control and archive extraction tooling.
