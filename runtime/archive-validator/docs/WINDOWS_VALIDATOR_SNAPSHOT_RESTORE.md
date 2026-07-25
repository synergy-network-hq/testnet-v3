# Windows Validator Snapshot Restore

Windows validators must use the same signed archive-validator snapshot catalog as macOS and Linux receivers. The snapshot payload is OS-neutral chain state; the Windows-specific part is the receiver tooling that downloads, verifies, extracts, and applies it into a Windows validator workspace.

## Requirements

- PowerShell 5.1 or newer
- The unpacked Windows validator workspace with `node.env`, `config\node.toml`, `nodectl.ps1`, and `bin\synergy-testnet-windows-amd64.exe`
- `zstd.exe` available on `PATH`, or passed with `-ZstdPath`
- `tar.exe` available on `PATH`, or passed with `-TarPath`
- The validator process stopped before restore

## New Validator Setup

Run PowerShell from the archive-validator package root:

```powershell
.\windows\Setup-WindowsValidatorFromArchiveSnapshot.ps1 `
  -Workspace "C:\Synergy\validator-7" `
  -CatalogUrl "http://73.79.66.255:48640/catalog.json" `
  -StartAfterRestore
```

Download the Windows receiver package from the archive endpoint:

```powershell
Invoke-WebRequest `
  -Uri "http://73.79.66.255:48640/receivers/synergy-archive-validator-testnet-v3-windows-receiver.zip" `
  -OutFile "synergy-archive-validator-testnet-v3-windows-receiver.zip"
```

The wrapper runs the workspace setup step, restores the newest green `validator-pruned` snapshot for the `validator` role, then calls `nodectl.ps1 sync` when `-StartAfterRestore` is provided.

## Restore Only

Use this when the Windows validator workspace is already installed and stopped:

```powershell
.\windows\Restore-ValidatorSnapshot.ps1 `
  -Workspace "C:\Synergy\validator-7" `
  -CatalogUrl "http://73.79.66.255:48640/catalog.json" `
  -TargetRole validator `
  -SnapshotClass validator-pruned
```

To restore an exact catalog entry:

```powershell
.\windows\Restore-ValidatorSnapshot.ps1 `
  -Workspace "C:\Synergy\validator-7" `
  -CatalogUrl "http://73.79.66.255:48640/catalog.json" `
  -SnapshotId snapshot-000601891
```

## What The Script Verifies

The restore script fails closed unless all of these pass:

- Catalog `chain_id`, `network_id`, and `genesis_hash`
- Published green snapshot status
- Snapshot class and allowed target role
- `supported_receiver_operating_systems` includes `windows`
- Distribution manifest chain identity
- Source snapshot manifest chain identity and restore role
- Chunk SHA-256 checksums
- Reassembled archive SHA-256
- Every launch-approved state file checksum
- Runtime `verify-snapshot` from the Windows Synergy binary, unless `-SkipRuntimeVerify` is explicitly passed

The script only copies launch-approved chain state files into `data\`: `chain.json`, `committed_blocks.jsonl`, `canonical_locks.json`, `committed_qcs.json`, `committed_qcs.jsonl`, `dag_state.json`, `validator_registry.json`, `token_state.json`, `account_state.json`, and `state_checkpoint.json`.

It does not copy keys, configs, genesis files, TLS material, node identity, logs, or runtime binaries.

## Evidence

Every restore writes evidence under:

```text
<workspace>\data\snapshot-restore-evidence\<timestamp>-<snapshot_id>\
```

That directory contains the selected catalog entry, runtime verification output, target-state backup, and `restore-report.json`.

## Other Roles

Windows receivers use the same class mapping as macOS and Linux:

- `validator`, `onboarding_validator`, `quarantined_validator`: `validator-pruned`
- `rpc`, `rpc_gateway`: `support-rpc`
- `relayer`: `support-relayer`
- `observer`: `support-observer`
- `indexer`, `explorer`, `atlas_indexer`, `explorer_indexer`: `indexer-replay`
- `archive`, `archive_validator`, `snapshot_authority`: `archive-full`
