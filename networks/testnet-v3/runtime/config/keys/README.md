# Local Key Material

This directory is reserved for machine-local Synergy identity files.

Do not commit live `*_identity.json` files or private keys. The repository keeps
only placeholder examples; generated or operator-provided identity files are
ignored by `.gitignore`.

Expected local files include:

- `dao_identity.json`
- `fee_collector_identity.json`

Use the matching `*.example.json` files as the JSON shape reference.
