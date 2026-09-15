# Synergy Archive Validator Node

This package installs a non-consensus Archive Validator Node for Synergy Testnet.

Protocol role: `ARCHIVE_OBSERVER`

The archive node verifies finalized chain data, stores full archival data, creates role-specific signed snapshots, chunks zstd archives at 512 MiB, retains two verified snapshots by class, and serves verified snapshots to new validators, self-healing validators, relayers, observers, RPC nodes, and indexers. It never votes, never proposes, never aggregates QCs, and never counts toward quorum.

Default scheduled snapshot classes: `validator-pruned`, `support-relayer`, `support-observer`, `indexer-replay`, `support-rpc`, and `archive-full`. `archive-full` is created every 15,000 finalized blocks; all other default classes are created every 5,000 finalized blocks.

Public Testnet snapshot catalog: `http://73.79.66.255:48640/catalog.json`. New validators and support-node recovery flows should consume role-specific snapshots from this archive-validator catalog instead of validator-local state or VPN-only paths.

Linux install:

```bash
unzip synergy-archive-validator-testnet-v3-linux-x64.zip
cd archive-validator
sudo ./setup-archive-validator.sh --chain-id 1264 --network-id synergy-testnet-v3 --genesis-file ./config/genesis.testnet.json.template --expected-genesis-hash <hash> --yes
```

Windows validator snapshot restore:

```powershell
.\windows\Setup-WindowsValidatorFromArchiveSnapshot.ps1 `
  -Workspace "C:\Synergy\validator-7" `
  -CatalogUrl "http://73.79.66.255:48640/catalog.json" `
  -StartAfterRestore
```

The Windows receiver package is also served by the archive endpoint at `http://73.79.66.255:48640/receivers/synergy-archive-validator-testnet-v3-windows-receiver.zip`.

Windows receivers use the same signed catalog and role-specific snapshot classes as macOS and Linux. The helper downloads the newest green `validator-pruned` snapshot, verifies chain identity, role compatibility, chunk checksums, archive checksum, source manifest checksums, and the Windows runtime `verify-snapshot` result before copying chain state into the validator workspace.

Apple Silicon M4 internal teammate handoff:

```bash
unzip synergy-archive-validator-testnet-v3-macos-m4.zip
cd synergy-archive-validator-testnet-v3-macos-m4
sudo ./setup-archive-validator-m4.sh --public-host <archive-node-public-host> --yes
sudo ./verify-archive-validator-m4.sh
```

The M4 zip includes the Apple Silicon archive runtime, the Aegis CLI, the archive snapshot control plane, checksums, launchd persistence, policy, and handoff instructions. It is an internal operations handoff artifact. A public macOS installer still requires a signed, notarized, and stapled package.

Private keys are not included. Aegis PQC archive peer and snapshot signing identities must be generated or referenced through `aegis-pqvm`.
