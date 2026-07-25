# Archive Validator Snapshot Publication

Archive-validator snapshots are created from a verified runtime checkpoint and published through Cloudflare R2. The archive validator never copies live chain files directly and never includes validator identity, credential, key, or WireGuard material in a snapshot.

## Required environment

Set these only on the archive-validator host or its deployment secret store:

```text
SYNERGY_ARCHIVE_RUNTIME=/opt/synergy/bin/synergy-testnet
SYNERGY_AEGIS_CLI=/opt/synergy/bin/synergy-aegis
SYNERGY_AEGIS_ARCHIVE_IDENTITY=/etc/synergy/aegis-archive-identity.json
SYNERGY_AEGIS_ARCHIVE_SIGNER_SHA256=<pinned-public-key-sha256>
SYNERGY_SNAPSHOT_R2_ENDPOINT=https://1311255048f053d71c4bca4a0f590f44.r2.cloudflarestorage.com
SYNERGY_SNAPSHOT_R2_BUCKET=testnet-snapshot
SYNERGY_SNAPSHOT_R2_ACCESS_KEY_ID=<r2-access-key>
SYNERGY_SNAPSHOT_R2_SECRET_ACCESS_KEY=<r2-secret-key>
SYNERGY_SNAPSHOT_PUBLIC_BASE_URL=https://archive-store.synergynode.xyz
```

The host also needs the AWS CLI. The publisher passes the R2 credentials only to the child process environment; they are not written to snapshot manifests, logs, catalog entries, or support bundles.

## Publication contract

1. Validate consensus and runtime evidence, then create an approved-state checkpoint.
2. Build a deterministic `tar.zst` archive and Aegis-signed distribution manifest.
3. Publish the archive, every declared chunk, manifest, signature, checksums, and verification report under `snapshots/{height}/`. Require matching SHA-256 object metadata and read every object back before it can appear in the public catalog.
4. Publish `snapshots/latest.json.sig`, then atomically publish `snapshots/latest.json` last.

The public catalog advertises a validator-pruned snapshot with `archive_validator` provenance, public artifact URLs, checksums, receiver format, and the compressed byte count. A stale `GENESIS_VALIDATOR` role is rejected by the consumer before any chain data is changed.

The catalog retains two active snapshots per class. Older entries are marked retired only after the new artifacts and their verified catalog are available.

## Consumer compatibility and verification

Consumers must validate the signed catalog and distribution manifest with the packaged Aegis verifier and their required detached `.sig` files before any archive download or state mutation. A missing verifier or signature is a hard failure. A `AEGIS_PQC_VERIFIED` status field is descriptive metadata; it is not a substitute for detached signature verification.

Official desktop installers set `SYNERGY_AEGIS_CLI` to their platform-specific
bundled verifier automatically. That verifier is compiled against the pinned,
canonical `Aegis-PQC/aegis-pqvm` source revision and uses ML-DSA-87 for detached
archive signatures. Archive-validator deployments must install the same trusted
`synergy-aegis` binary at the configured host path.

Create the archive signing identity once, on the archive validator only:

```text
umask 077
/opt/synergy/bin/synergy-aegis init-archive-identity \
  --output /etc/synergy/aegis-archive-identity.json
```

The identity file contains the ML-DSA-87 private key and must remain mode 0600,
outside the snapshot workspace and every published artifact path. Consumers do
not need this file. They require the public-key SHA-256 pinned in
`testnet/runtime/configs/archive-snapshot-authority.json`; verification fails if
the document, domain, key identifier, signature, or signer identity changes.
Trusting only the public key embedded in a detached signature is forbidden.

Every public catalog entry must identify the stable producer contract:

```text
producer_role: archive_validator
producer_node_kind: archive-validator
catalog_schema: synergy-archive-snapshot-catalog-v1
distribution_schema: synergy-archive-snapshot-distribution-v1
binary_compatibility: synergy-testnet-v3-validator-pruned-v1
```

The entry must also provide public `https://` URLs for `snapshot_url`,
`manifest_url`, `manifest_signature_url`, and `checksums_url`. Consumers must
use those catalog-provided URLs and reject local paths, URL-derived fallbacks,
missing URLs, unexpected artifact paths, `GENESIS_VALIDATOR` provenance, schema
drift, stale catalog or verification timestamps, or incompatible binary
metadata before downloading or applying state.
