# Secret Handling

Do not commit live secrets.

Files that normally contain secrets are committed only as `.example` files. Replace placeholders only on the target validator host.

Secret-bearing file types include:

- validator private keys
- account keys
- node identity private keys
- P2P private keys
- consensus keys
- WireGuard private keys
- RPC tokens
- API tokens
- passwords
- seed phrases

The masking tools redact any value whose key name includes `private`, `secret`, `token`, `password`, `seed`, `mnemonic`, or `key`, except public-key fields.

