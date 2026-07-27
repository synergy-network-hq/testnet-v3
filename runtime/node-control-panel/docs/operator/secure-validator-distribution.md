# Secure Validator Distribution

The Validator 1–21 artifact matrix is built only from the signed generic Node Control Panel macOS `.dmg` and Linux `.deb` releases. It must never be assembled from validator runtime directories, local key stores, backups, or custody exports.

Before the release, derive the nonsecret assignment map from the authoritative allocation manifest and public identity registry. This command reads only `identity.pub.json` records and verifies every `synv…` address derivation with the bundled coordinator utility; it never opens encrypted identity bundles.

```bash
npm run release:extract-validator-assignments -- \
  --allocation-manifest /secure-testnet-inputs/testnet-allocation-manifest.json \
  --identity-registry /secure-testnet-inputs/identity-registry.public.json \
  --verifier ./binaries/synergy-control-darwin-arm64 \
  --output /secure-release-inputs/validator-identities.json
```

Use `synergy-control-linux-amd64` or the appropriate platform sidecar name when running the verification command on another release host.

Use the full verified map for the Validator 1–21 release workflow. Provision only its Validator 7–21 subset as Forge's deployment-only `NODE_OPERATOR_ASSIGNMENTS` value; do not put either map in browser assets or a public download location.

```bash
npm run release:validator-distribution -- \
  --macos electron-dist/Synergy.Node.Control.Panel-<version>-arm64.dmg \
  --linux electron-dist/synergy-node-control-panel_<version>_amd64.deb \
  --assignments /secure-release-inputs/validator-identities.json
```

The nonsecret assignment map must contain exactly one unique `synv…` identity and its matching FN-DSA public key for every Validator 1–21. The command fails closed if it is incomplete, duplicated, malformed, or reuses a public key. It then creates `Validator-01` through `Validator-21`, each with macOS and Linux artifacts, identity-bound nonsecret assignment metadata, installation instructions, and SHA-256 checksums. Validators 1–6 are retained for the internal launch; Validators 7–21 are released by the protected Forge Node Operators delivery service.

Every download is generic until enrollment. The operator receives the encrypted validator-specific bundle through the approved custody channel, then enters the package assignment ID and single-use coordinator token in Node Control Panel. The panel displays a domain-separated enrollment message. The local custody bundle signs that exact message with the assigned FN-DSA key; the panel submits the detached proof and nonsecret public key. The coordinator verifies both the `synv…` derivation and the proof before it issues the Innernet invite. Innernet then proves possession of the newly generated WireGuard key through the confirmed handshake; the coordinator observes or securely receives the endpoint, updates routing, and permanently consumes the token. The installer must not contain a reusable validator private identity key, custody passphrase, or unencrypted consensus private key. VPN enrollment does not activate consensus; that approval remains separate.

For a Forge Node Operators package, the coordinator must also send the opaque `enrollmentClaim` from `assignment.json` to Forge's authenticated consume endpoint after the server-observed WireGuard handshake succeeds. This marks the Forge allocation terminal using the claim, never a predictable URL or private identity material.

Do not move the private key into the downloadable ZIP to make this easier. The custody bundle is delivered only after the coordinator validates the claim and is installed locally with restrictive permissions. To create an offline proof without printing key material, use the bundled `synergy-control sign-validator-enrollment-proof --private-key-file <path> --message-file <path>` command, then paste only its detached signature into Node Control Panel.
