# Archive Manager

Archive Manager controls snapshot eligibility and archive safety. It does not re-enable archive services by itself.

## States

| State | Meaning |
| --- | --- |
| `CONTAINED` | Archive is isolated; publish controls disabled. |
| `VERIFYING` | Canonical verification is running. |
| `CANONICAL` | Snapshot source has quorum, hash, manifest, checksum, and validator-set proof. |
| `NONCANONICAL` | Verification rejected the archive. |
| `RESEED_REQUIRED` | Archive must be rebuilt from quorum-verified validators. |
| `PUBLISH_DISABLED` | Snapshot catalog is visible but publish controls are disabled. |
| `PUBLISH_ELIGIBLE` | Publish can be enabled only after canonical proof and separate authorization. |

## Rejection Codes

Archive verification surfaces structured blockers including:

- `SNAPSHOT_VERIFIER_CRASHED`
- `SNAPSHOT_QUORUM_BELOW_THRESHOLD`
- `ARCHIVE_NOT_CANONICAL`
- `PACKAGE_ARCHIVE_NOT_CANONICAL`
- `SNAPSHOT_HASH_MISSING`
- `PACKAGE_UNSIGNED`
- `PACKAGE_NO_GO_DENYLIST`

The operator message must explain low quorum, noncanonical hash, manifest signature failure, checksum failure, validator-set digest mismatch, known bad branch, or stale verification without exposing raw panics as the primary UI text.

Archive snapshots cannot be used for onboarding until the archive source is canonical. Unsafe snapshots are listed and can be quarantined with a confirmed evidence-producing mutation.
