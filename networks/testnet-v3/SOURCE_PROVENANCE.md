# Source provenance

Prepared on 2026-07-24 from:

- Source directory: `../01-Testnet/synergy-testnet`
- Source repository: `https://github.com/synergy-network-hq/testnet.git`
- Source branch: `runtime-fork-recovery-v19.0.49-hotfix`
- Source commit: `8354743c2c14f0e66f6177a7e2cd8600794d5218`
- Validator workspace commit: `db7d584b8d4dc52316d6058baf1770c6f3cdf49a`
- Destination repository: `https://github.com/synergy-network-hq/testnet-v3.git`

The source runtime had uncommitted changes when this snapshot was made:

- modified `ops/README.md`
- modified `scripts/qa/synergy-rpc-router-test.py`
- modified `scripts/testnet/synergy-rpc-router.py`
- modified `src/consensus/diagnostics.rs`
- modified `src/recovery.rs`
- untracked `ops/systemd/`

Build caches, nested Git metadata, release caches, generated evidence, old
release artifacts, binary bootstrap payloads, `.env` files, and ZIP archives
were excluded.

Retired Testnet-v2 source hashes:

- Genesis: `085c4283cf587ff8a22e8bf4a3de022f86a99d8af7d9fe9b4c0dbdfd082a5a95`
- Network identifiers: `bc223d1e49d5780b24314fe1896b2dbc22b1cf1d139b788953eef7de11eef6b2`
- Operational manifest: `b3a1c7fd38667898449db0233ca2ef84cdd823435ee25b0ee1c2fa51fc9a1e48`

The retired genesis hash is explicitly rejected by the Testnet-v3 launch gate.
