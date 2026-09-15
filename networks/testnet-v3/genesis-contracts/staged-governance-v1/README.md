# Staged governance-authorization artifacts — NOT FROZEN

Rebuilt after the canonical governance-authorization migration (session 13j).
Three independent builds produced byte-identical output for all nine contracts.

These are **staged**, not frozen: no genesis document binds these hashes, and no
contract address has been derived from them. Freezing happens once, atomically,
with the nine-contract rebind.

`genesis-contracts/contracts/` still holds the previous committed artifacts and
is deliberately left stale, which is why
`all_eight_genesis_contracts_deploy_call_restart_and_replay_deterministically`
is red. That red is the artifact/runtime coherence gate and must not be patched.
