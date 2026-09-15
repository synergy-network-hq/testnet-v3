# `BASELINE_VALIDATOR_COUNT` discrepancy — needs governing intent

**Status: OPEN. Not resolved. Do not "fix" by flipping the constant.**

Two public constants share the name and disagree:

| Location | Value |
|---|---|
| `runtime/src/recovery.rs:40` | **6** |
| `runtime/src/consensus/self_realign.rs:30` | **5** |

`runtime/src/consensus/diagnostics.rs:16` imports the **self_realign (5)** one.

The Testnet-v3 genesis defines **six** active validators, and the governed
schedule is 6 eligible → 1 cluster → strict 5-of-6 count quorum. So `5` *looks*
like an inherited Testnet-v2 baseline.

## Why it was NOT changed

Setting `self_realign::BASELINE_VALIDATOR_COUNT = 6` was tried and **reverted**:

```
before flip : 1078 pass /  24 fail
after  flip : 1035 pass /  69 fail   <-- 45 additional failures
```

The regression spread across `self_realign`, `p2p::networking`, `rpc_server`,
`validator`, `telemetry` and `sync::manager` — i.e. far beyond the diagnostics
fixtures. That breadth is evidence the two constants denote **different
concepts** (a self-realignment/snapshot baseline vs. the genesis active-set
baseline) rather than one simply being stale.

Resolving it correctly requires the governing intent for the self-realignment
baseline. Guessing would either:
- silently change snapshot/realignment quorum semantics on a live network, or
- leave 45 tests failing to satisfy a renamed constant.

## Observable consequence today

`recovery.rs:2531` enforces `active.len() == 6` while diagnostics fixtures build
five-validator registries, producing:

```
active validator registry has 5 canonical validator(s), expected 6
```

This is the shared cause behind the remaining diagnostics/rejoin failures.

## To close

1. Confirm whether the self-realignment baseline is intended to be the genesis
   active-set size (6) or an independent minimum (5).
2. If they are the same concept: delete one constant, re-export the other, and
   migrate the ~45 dependent tests deliberately.
3. If they are different concepts: **rename** `self_realign`'s to something
   unambiguous (e.g. `SELF_REALIGN_BASELINE_VALIDATORS`) and document the
   distinction at both definitions.
4. Add a test asserting whichever invariant is chosen.
