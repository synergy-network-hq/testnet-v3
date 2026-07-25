# Validator VPN Bootstrap Readiness - 2026-07-04

## Scope

Read-only readiness pass for the validator-only VPN bootstrap covering relayers 1-3 and validators 1-6.

The live recovery order changed after the first readiness pass. The chain must
not be started or repeatedly restarted while nodes are split between the retired
`wg0` VPN assumptions and the new validator-only VPN architecture.

## Evidence Summary

- SSH aliases exist and are reachable for `synergy-index`, `synergy-relayer1`, `synergy-relayer2`, `synergy-relayer3`, and `synergy-val1` through `synergy-val6`.
- The new target validator VPN interface `sy-validator0` is not present yet on the bootstrap fleet.
- Existing legacy WireGuard evidence shows `wg0` on relayer1, relayer2, and validators, but that is not the new bootstrap interface or the new address plan. The old `wg0` material must be backed up and removed from active config locations before `sy-validator0` is applied.
- `synergy-relayer3` is SSH reachable but read-only probes found no `wg` binary and no `/etc/wireguard` configuration.
- Stop-gate recheck on 2026-07-04: `synergy-val1`, `synergy-val2`, `synergy-val3`, `synergy-val4`, and `synergy-val6` are stopped and inactive; `synergy-val5` remains active because the workbook-backed sudo credential did not authenticate.
- Public RPC was intermittently unstable with HTTP 502 during earlier probing; earlier successful samples around height `760986` showed block timestamp deltas near `300` seconds, not the target near-1-second cadence.

## Blockers Before Live Apply

1. Stop all six validator services. This gate is incomplete until `synergy-val5` is inactive.
2. Back up then disable and remove active old `wg0`/retired WireGuard config files on every validator and relayer. Do not leave any node partially migrated.
3. Install and verify WireGuard tooling on `synergy-relayer3`.
4. Generate or confirm local WireGuard keys on each bootstrap node without exporting private keys.
5. Register relayers 1-3 and validators 1-6 with the coordinator so the first signed peer snapshot is based on real public keys.
6. Apply `sy-validator0` and verify reachability before changing validator consensus peer preferences.
7. Align validator and relayer runtime/config/binary state from canonical source.
8. Re-sample chain height, qRPC latency, validator peers, relayer health, quorum, and block timestamp deltas only after VPN and config checks are green.

## Current Decision

Do not switch validator consensus traffic to the new validator VPN yet. The
bootstrap population is reachable over SSH, but the target VPN interface is not
deployed, relayer3 lacks WireGuard readiness, and the all-validator stop gate is
blocked on `synergy-val5` sudo authentication from the workbook.
