# New Validator Fast Sync

A new validator in `SYNCING` selects the highest verified `validator-pruned` archive snapshot at or below the latest finalized height, verifies it, restores only launch-approved chain state, speed-syncs remaining finalized blocks, then enters `SNAPSHOT_VERIFIED` and `REPLAYING` before `SHADOW`.

The receiver OS must not change snapshot semantics. macOS, Linux, and Windows validators consume the same signed archive-validator catalog and the same `validator-pruned` snapshot class. Platform-specific tooling is limited to service management, download/extraction commands, and local workspace paths.

Windows validators use `archive-validator/windows/Setup-WindowsValidatorFromArchiveSnapshot.ps1` or `archive-validator/windows/Restore-ValidatorSnapshot.ps1`. Those scripts require the published distribution manifest to declare `supported_receiver_operating_systems` containing `windows`, then enforce chain ID, network ID, genesis hash, role/class compatibility, chunk checksums, archive checksum, source file checksums, and the Windows runtime `verify-snapshot` result before copying state into `data\`.
