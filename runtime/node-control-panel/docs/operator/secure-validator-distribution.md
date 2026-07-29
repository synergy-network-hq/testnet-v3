# Secure Validator Installer Distribution

Testnet-v3 uses 21 installer-bound validator packages. Each validator receives
one macOS DMG and one Linux DEB containing only that validator's:

- encrypted five-role identity bundle and public manifest;
- WireGuard public key and an encrypted complete 24-peer topology for all 21
  validators, the coordinator, and relayers;
- VPN binding and checksum-bound assignment metadata.

The identity passphrase, WireGuard private key, complete WireGuard
configuration, and VPN onboarding token are never placed in an installer.
Treat every unique installer as custody-sensitive because it contains an
encrypted private identity. Do not publish these artifacts in the generic
GitHub release.

## Issue tokens before staging

Before building an installer, a Synergy coordinator custodian creates exactly
one assignment-bound validator VPN token from the coordinator. The token must
be bound to that validator's `assignmentId`, `synv` address, consensus public
key, provisioned VPN IP, and configuration version. A token belongs to one
validator only and expires before it can be used elsewhere.

On the protected native release host, store each issued token in its own file,
for example `validator-01.token` through `validator-21.token`, in a directory
outside the repository and release output. Restrict that directory and every
file to the release custodian (`0700` directory, `0600` files). Never place a
token in shell history, CI variables, logs, installer metadata, Git, or a
release manifest.

The release staging process uses that file only to create an AES-256-GCM
envelope. The envelope key is derived from the one-time token using HKDF-SHA-256
and assignment-bound authenticated data. The encrypted payload contains the
assigned WireGuard private key and complete configuration; only the matching
token can unlock it.

## Build on each native release host

Build DMGs on the signed and notarizing macOS release host:

```bash
npm run release:build-validator-installers -- \
  --identity-root /secure/testnet-v3-identity-files \
  --vpn-onboarding-token-directory /secure/testnet-v3-vpn-onboarding-tokens \
  --platform mac \
  --output /secure/releases/testnet-v3/validators/macos
```

Build DEBs on the Linux release host:

```bash
npm run release:build-validator-installers -- \
  --identity-root /secure/testnet-v3-identity-files \
  --vpn-onboarding-token-directory /secure/testnet-v3-vpn-onboarding-tokens \
  --platform linux \
  --output /secure/releases/testnet-v3/validators/linux
```

The command stages and validates exactly one assignment at a time, builds the
native installer, notarizes and staples every DMG, extracts or mounts every
artifact to verify its one embedded assignment and checksums, assigns a
validator-specific filename, records its SHA-256 digest, and clears the
temporary staging directory before the next build and on exit. Verification
decrypts the embedded VPN envelope only in release-host memory with the
matching protected token file. The default range is
Validator 01 through Validator 21. `--from` and `--to` may be used only for a
controlled resume.

The macOS release host must have the Developer ID and notarization credentials
required by `electron-builder.yml`. Linux packages must be built on Linux.

## Release checks

Before distribution:

1. Confirm each platform manifest contains exactly 21 unique assignments and
   21 unique artifacts.
2. Verify every checksum in each `SHA256SUMS`.
3. Confirm the build log records a successful mount/extract, signature check,
   and embedded assignment/checksum verification for every artifact.
4. Confirm Validators 01–06 are marked `initial-six`; Validators 07–21 are
   marked `gradual-activation`.
5. Confirm every encrypted `wireguard-config.envelope.json` decrypts only with
   its matching protected token file and contains the complete 24-peer topology
   plus only the assigned validator's `[Interface]` private key.
6. Confirm the automated Gatekeeper and notarization checks passed for every
   DMG, and `dpkg-deb --info` passed for every DEB.

Deliver each validator's pair through the approved private custody channel.
Do not interchange packages between validators.

## Operator activation

The Synergy team sends the assigned installer and its coordinator-issued token
through separate approved channels. The operator unlocks and installs the
assigned identity locally, then enters only that one-time token in the Control
Panel. The Control Panel creates the assignment-bound identity proof
automatically, sends the packaged VPN address/public key/config version to the
coordinator, unlocks the checksum-verified WireGuard configuration only in
memory, installs it, starts `sy-vpn`, and waits for a real WireGuard handshake.
Only after both the client and coordinator observe that handshake is the token
permanently consumed and the signed membership receipt recorded. A package
without its matching token cannot activate the VPN.

VPN activation does not activate consensus. Validators 01–06 form the initial
cohort; Validators 07–21 remain provisioned but inactive until their separate
consensus activation approval.
