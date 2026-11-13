# macOS Install

Expected operator flow:

```bash
unzip synergy-archive-validator-testnet-v3-macos-universal.zip
sudo installer -pkg SynergyArchiveValidator.pkg -target /
sudo /usr/local/synergy/bin/synergy-archive status
```

Install locations:

- Binary: `/usr/local/synergy/bin/synergy-archive`
- Storage root: `/Volumes/Synergy_Archive/archive-validator`
- Config: `/Volumes/Synergy_Archive/archive-validator/config`
- Data: `/Volumes/Synergy_Archive/archive-validator`
- Logs: `/Volumes/Synergy_Archive/archive-validator/logs`
- LaunchDaemons: `/Library/LaunchDaemons/io.synergynetwork.archive-*.plist`

The installer fails closed if `aegis-pqvm` is unavailable or if the post-install health check fails. Uninstall without deleting data:

```bash
sudo /usr/local/synergy/share/archive-validator/uninstall-macos.sh
```

Data deletion requires the explicit `--purge-data` flag.

## Temporary Testnet Archive Testing Workaround

If the signed and notarized macOS `.pkg` is not available yet, authorized Synergy Testnet archive-validator testing may use the portable zip after checksum verification. Do not disable Gatekeeper globally and do not run `spctl --master-disable`.

```bash
shasum -a 256 synergy-archive-validator-testnet-v3.zip
xattr -d com.apple.quarantine synergy-archive-validator-testnet-v3.zip 2>/dev/null || true
unzip synergy-archive-validator-testnet-v3.zip
xattr -dr com.apple.quarantine ./archive-validator
cd archive-validator
sudo ./setup-archive-validator.sh
```

This is a temporary operator workaround only. The release-grade macOS path remains a signed, notarized, and stapled installer package.
