# Validator Keys

Live key files are validator-specific and secret-bearing. Commit only `.example` files with safe placeholders.

Expected live files:

- `validator-key.json`
- `node-identity-key.json`
- `p2p-key.json`
- `consensus-key.json`
- `account-key.json`

Live files must be owned by `node:node` and mode `0600`.

