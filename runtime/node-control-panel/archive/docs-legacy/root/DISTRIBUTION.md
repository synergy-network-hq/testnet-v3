# Synergy Testnet Control Panel Distribution Notes

## Data locations
- **macOS**: `~/Library/Application Support/synergy/control-panel` (state) and `~/.synergy/control-panel` (node sandboxes, binaries, configs).
- **Linux**: `~/.config/synergy/control-panel` (state) and `~/.synergy/control-panel` (node sandboxes, binaries, configs).
- **Windows**: `%AppData%\\synergy\\control-panel` (state) and `%UserProfile%\\.synergy\\control-panel` (node sandboxes, binaries, configs).

Each node gets its own sandbox under `nodes/<node_id>` containing `config`, `data`, `logs`, and `keys`.

## Resetting a setup
1. Stop any running nodes from the dashboard.
2. Delete the node sandbox directory under `~/.synergy/control-panel/nodes/<node_id>`.
3. Remove the control panel state file at `~/.synergy/control-panel/state.json` if you need a full reset.
4. Restart the app; Jarvis will prompt for setup again and reuse any surviving binaries/configs when possible.

## Binary download and verification
- The validator setup downloads the unified binary using `SYNERGY_UNIFIED_BINARY_URL` (manifest) and the platform key from `SYNERGY_BINARY_PLATFORM_*`.
- Checksums are verified when provided by the manifest. You can enforce verification via platform-specific env vars:
  - `SYNERGY_BINARY_CHECKSUM_DARWIN_ARM64`
  - `SYNERGY_BINARY_CHECKSUM_DARWIN_AMD64`
  - `SYNERGY_BINARY_CHECKSUM_LINUX_AMD64`
  - `SYNERGY_BINARY_CHECKSUM_LINUX_ARM64`
  - `SYNERGY_BINARY_CHECKSUM_WINDOWS_AMD64`
- Binaries are stored at `~/.synergy/control-panel/bin/<SYNERGY_BINARY_NAME>` and marked executable after download.

## Default ports
- P2P: `SYNERGY_DEFAULT_P2P_PORT` (default 38638)
- RPC/HTTP: `SYNERGY_DEFAULT_RPC_PORT` (default 48638)
- WebSocket: `SYNERGY_DEFAULT_WS_PORT` (default 58638)
- Metrics: `SYNERGY_DEFAULT_METRICS_PORT` (default 9090)

## Runtime permissions
- Filesystem: write access to the control panel directories above (creates sandboxes, keys, configs, logs).
- Network: outbound HTTPS to `SYNERGY_UNIFIED_BINARY_URL` for manifest/binary downloads; outbound RPC/WS/API connections to the Synergy testnet endpoints defined in `.env`.
- Execution: ability to spawn the downloaded binary from the sandbox `bin/` directory.
