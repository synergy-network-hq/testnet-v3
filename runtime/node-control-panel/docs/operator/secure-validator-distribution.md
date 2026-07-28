# Secure Validator Installer Distribution

Testnet-v3 uses 21 installer-bound validator packages. Each validator receives
one macOS DMG and one Linux DEB containing only that validator's:

- encrypted five-role identity bundle and public manifest;
- WireGuard private/public key pair;
- complete `sy-vpn.conf` topology for all 21 validators and relayers;
- VPN binding and checksum-bound assignment metadata.

The identity passphrase is never placed in an installer. Treat every unique
installer as custody-sensitive because it contains an encrypted private
identity and a WireGuard private key. Do not publish these artifacts in the
generic GitHub release.

## Build on each native release host

Build DMGs on the signed and notarizing macOS release host:

```bash
npm run release:build-validator-installers -- \
  --identity-root /secure/testnet-v3-identity-files \
  --platform mac \
  --output /secure/releases/testnet-v3/validators/macos
```

Build DEBs on the Linux release host:

```bash
npm run release:build-validator-installers -- \
  --identity-root /secure/testnet-v3-identity-files \
  --platform linux \
  --output /secure/releases/testnet-v3/validators/linux
```

The command stages and validates exactly one assignment at a time, builds the
native installer, assigns a validator-specific filename, records its SHA-256
digest, and clears the secret staging directory before the next build and on
exit. The default range is Validator 01 through Validator 21. `--from` and
`--to` may be used only for a controlled resume.

The macOS release host must have the Developer ID and notarization credentials
required by `electron-builder.yml`. Linux packages must be built on Linux.

## Release checks

Before distribution:

1. Confirm each platform manifest contains exactly 21 unique assignments and
   21 unique artifacts.
2. Verify every checksum in each `SHA256SUMS`.
3. Mount or extract a sample from Validators 01, 06, 07, and 21 and confirm its
   `assignment.json`, identity manifest, VPN binding, and checksums agree.
4. Confirm Validators 01–06 are marked `initial-six`; Validators 07–21 are
   marked `gradual-activation`.
5. Confirm every `sy-vpn.conf` contains the complete topology and that only the
   assigned validator's `[Interface]` private key is present.
6. Gatekeeper-check and notarization-check every DMG. Inspect every DEB with
   `dpkg-deb --info` and `dpkg-deb --contents`.

Deliver each validator's pair through the approved private custody channel.
Do not interchange packages between validators.

## Operator activation

The operator unlocks and installs the assigned identity locally, then enters
only the one-time token supplied by the VPN coordinator. The control panel
creates the assignment-bound identity proof automatically, sends the packaged
VPN address/public key/config version to the coordinator, installs the
checksum-verified `sy-vpn.conf`, starts `sy-vpn`, and waits for a real
WireGuard handshake. Only after both the client and coordinator observe that
handshake is the token permanently consumed and the signed membership receipt
recorded.

VPN activation does not activate consensus. Validators 01–06 form the initial
cohort; Validators 07–21 remain provisioned but inactive until their separate
consensus activation approval.
