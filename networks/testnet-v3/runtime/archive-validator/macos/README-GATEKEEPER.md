# Synergy Archive Validator macOS Gatekeeper Notes

The normal macOS distribution artifact is `SynergyArchiveValidator.pkg` inside `synergy-archive-validator-testnet-v3-macos-universal.zip`.

The package must be signed with the Synergy Developer ID Installer certificate, all executables inside it must be signed with the Synergy Developer ID Application certificate using hardened runtime, and the package must be notarized and stapled before release.

Operators should not need to disable Gatekeeper or approve unsigned binaries manually. Do not run `spctl --master-disable`.

## Temporary Testnet Archive Testing Workaround

Until the signed and notarized macOS package is published, use the quarantine workaround below only for authorized Synergy Testnet archive-validator testing after verifying the artifact checksum.

1. Verify checksum first:

   ```bash
   shasum -a 256 synergy-archive-validator-testnet-v3.zip
   ```

2. Remove quarantine from the zip before extraction if needed:

   ```bash
   xattr -d com.apple.quarantine synergy-archive-validator-testnet-v3.zip 2>/dev/null || true
   ```

3. Extract:

   ```bash
   unzip synergy-archive-validator-testnet-v3.zip
   ```

4. Remove quarantine recursively from the extracted package:

   ```bash
   xattr -dr com.apple.quarantine ./archive-validator
   ```

5. Run setup:

   ```bash
   cd archive-validator
   sudo ./setup-archive-validator.sh
   ```

This workaround is not the long-term release path. If a signed/notarized `.pkg` is available and Gatekeeper blocks it, treat that as a release failure and rebuild through the signed/notarized CI path.
