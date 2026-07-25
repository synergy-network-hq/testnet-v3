# Testnet Fees, Rewards, And Burn Deployment Notes

These notes cover safe rollout of the testnet fee, rewards, Treasury Recovery, and burn implementation.

## Current Protocol Addresses

| Purpose | Address |
| --- | --- |
| Network fee collector | `synf1y42p7p6jrxrg472ts6jea5y34yg7tgj6qg2j` |
| Validator rewards pool | `synw1at607x35rkmsmvgz069nx0j3q5km93krrvge` |
| DAO treasury | `synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r` |
| Treasury recovery | `synw1syv3tnu6r2y5e3u9f0wqmxhavylfxena0z92` |
| Network burn address | `syn00000000000000000000000000000000000000` |

## Pre-Deployment Checklist

1. Confirm the active runtime checkout:

```bash
git rev-parse --show-toplevel
git status --short
```

2. Run focused local checks:

```bash
cargo fmt --manifest-path src/Cargo.toml -- --check
cargo test --manifest-path src/Cargo.toml gas::tests
cargo test --manifest-path src/Cargo.toml transaction::tests
cargo test --manifest-path src/Cargo.toml execution::tests
cargo test --manifest-path src/Cargo.toml token::tests
cargo test --manifest-path src/Cargo.toml rewards::tests
cargo test --manifest-path src/Cargo.toml rpc::rpc_server::tests
cargo test --manifest-path src/Cargo.toml validator::tests
```

3. Back up live state before deploying binaries or migrations:

- testnet genesis
- chain config
- validator configs
- node databases if a migration or hardfork is required
- env files and systemd unit overrides

4. Build release artifacts through the approved release workflow for testnet runtime binaries.

## Local Scenario

Before live rollout, run a local testnet scenario with at least three validators:

1. Start local validators in one or more clusters.
2. Submit native sends for `1 SNRG`, `100 SNRG`, and `10,000 SNRG`.
3. Submit a native burn using a signed `burn:{"asset":"SNRG","amount":"10000000000"}` payload.
4. Submit at least one failed transaction.
5. Advance through an epoch close.
6. Verify fee collector, treasury, validator reward pool, cluster escrow, pending rewards, and Treasury Recovery.
7. Advance through epoch `N+1` and verify settlement.
8. Run `synergy_checkRewardInvariants` for the affected epochs.

## Live Testnet Verification

After deploying to a non-critical node, verify read surfaces:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getFeeSchedule","params":[]}
{"jsonrpc":"2.0","id":2,"method":"synergy_estimateFee","params":[{"from":"synw1...","to":"synw1...","value":"1000000000"}]}
{"jsonrpc":"2.0","id":3,"method":"synergy_getBurnLedger","params":["SNRG"]}
```

After epoch close:

```json
{"jsonrpc":"2.0","id":4,"method":"synergy_getEpochFeeDistribution","params":[42]}
{"jsonrpc":"2.0","id":5,"method":"synergy_getClusterRewardEscrow","params":["syngrp1cluster-a",42]}
{"jsonrpc":"2.0","id":6,"method":"synergy_getTreasuryRecovery","params":[42]}
{"jsonrpc":"2.0","id":7,"method":"synergy_checkRewardInvariants","params":[42]}
```

Roll out to the rest of the validators only after:

- the node stays synced
- fee-bearing transactions credit the fee collector
- send amount changes affect total network fee
- direct burn-address transfer appears as a burn-address transfer
- explicit burn appears as supply-reducing burn
- epoch close distributes the fee collector bucket once
- cluster escrows receive rewards
- epoch `N+1` settlement pays validators and routes unreleased rewards to Treasury Recovery

## Rollback Notes

If deployment must be rolled back:

1. Stop at the smallest affected node set.
2. Preserve logs and state snapshots before changing binaries.
3. Restore the previous runtime binary and config.
4. Do not delete chain data unless an explicit recovery plan requires it.
5. Re-check RPC height, finalized head, fee collector balance, and invariant status after restart.

Old epochs that predate the implementation may remain marked as pre-rewards implementation. Do not retroactively recompute old epoch fees unless a separate deterministic migration is approved.
