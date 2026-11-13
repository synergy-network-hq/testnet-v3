# Archive Validator Setup

The archive validator must run as `ARCHIVE_OBSERVER` on chain `1264`, network `synergy-testnet-v3`.

It fails closed when `aegis-pqvm` is unavailable, when genesis hash validation fails, or when archive/snapshot signing identities cannot be verified.
