# Synergy Testnet Rewards Settlement

This document describes the testnet validator rewards flow implemented in protocol state. It is intended for operators, Atlas, indexers, and deployment verification.

## Protocol Accounts

| Purpose | Address |
| --- | --- |
| Network fee collector | `synf1y42p7p6jrxrg472ts6jea5y34yg7tgj6qg2j` |
| Validator rewards pool | `synw1at607x35rkmsmvgz069nx0j3q5km93krrvge` |
| DAO treasury | `synw1pqwglyfjynrxt7ms9nvggntav6x3lx9c2l4r` |
| Treasury recovery | `synw1syv3tnu6r2y5e3u9f0wqmxhavylfxena0z92` |
| Cluster reward escrow | `syngrp1...` cluster addresses |

The canonical burn address is never a validator payout, cluster escrow, or treasury recovery destination.

## Fee Split

At epoch close, collected fees are split by basis points:

```text
validator_fee_share_bps = 7000
treasury_fee_share_bps = 3000
burn_fee_share_bps = 0
```

Integer rounding dust is assigned deterministically to treasury. Closing an epoch is idempotent: a closed epoch cannot be closed again for a second transfer.

The closed distribution records:

- total collected fees
- validator reward pool amount
- treasury amount
- burn amount, currently zero by default
- rounding dust
- distribution block height

## Phase 1: Pending Validator Rewards

At the end of epoch `N`, the validator reward pool amount for epoch `N` is allocated to clusters and validators.

Phase 1 weights:

| Metric | Weight BPS |
| --- | ---: |
| Consensus participation | 3500 |
| Block proposal participation | 2000 |
| Validation accuracy | 2000 |
| Cluster contribution | 1500 |
| Synergy score modifier | 1000 |

The allocation score is an integer weighted average. Cluster allocations use cluster health coefficients and are escrowed to `syngrp1...` addresses. Validator pending rewards are recorded with status `pending_phase2`.

## Phase 2: N+1 Settlement

At the end of epoch `N+1`, pending rewards from epoch `N` are settled using accountability metrics.

Phase 2 weights:

| Metric | Weight BPS |
| --- | ---: |
| Uptime | 3500 |
| Consensus responsiveness | 2500 |
| No jail or slash | 2000 |
| Cluster stability | 1000 |
| Governance or PoSy participation | 1000 |

The release coefficient is the minimum of weighted accountability score and configured caps. Released rewards are paid from the cluster escrow to validator payout addresses. Unreleased rewards are sent to Treasury Recovery, not burn.

## Treasury Recovery

Treasury Recovery records unreleased validator rewards separately from ordinary treasury fee share:

- pending epoch
- settlement epoch
- validator ID
- cluster ID
- recovered amount
- reason codes
- treasury recovery wallet

Query:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getTreasuryRecovery","params":[42]}
```

## RPC Surfaces

Epoch fee distribution:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getEpochFeeDistribution","params":[42]}
```

Cluster escrow:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getClusterRewardEscrow","params":["syngrp1cluster-a",42]}
```

Epoch reward audit events:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_getEpochRewardAudit","params":[42]}
```

Invariant check:

```json
{"jsonrpc":"2.0","id":1,"method":"synergy_checkRewardInvariants","params":[42]}
```

The invariant checker verifies fee accumulator totals, fee distribution totals, cluster escrow and pending reward reconciliation, settlement idempotency, treasury recovery accounting, burn-address exclusions, and duplicate-close or duplicate-pay conditions.
