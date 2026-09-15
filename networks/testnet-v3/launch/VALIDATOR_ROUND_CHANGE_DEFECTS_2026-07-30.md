# Validator round-change defects — 2026-07-30

Continues `launch/TYPED_FINALITY_OBSERVER_DEFECT_ANALYSIS_2026-07-30.md`.
Records what was fixed, what was deployed, and the remaining defect that keeps
Testnet-v3 from advancing.

## 1. Status

| Tier | State |
|---|---|
| Validators 1–6 | active, runtime `5c07a554…`, **stalled at height 37**, coordinator idle |
| Relayers 1–3 | active, runtime `c94a090e…`, observer stores followed the new chain to 37 |
| RPC gateway | active, runtime `c9212ad9…`, serving a **stale** height 90 from its RocksDB |
| Explorer indexer / Atlas | active, Atlas Postgres still holds the pre-reset chain |

The chain was reset to genesis at 14:10:43Z. It produced blocks immediately —
0 → 37 in about three minutes, all six validators in exact lockstep — then
stalled at 37 and has not advanced since.

## 2. What was fixed and proven

### 2.1 Observer defects (deployed, proven)

Both blockers from the previous document are fixed and verified in production.
After the relayer switch, across all three relayers: **zero**
`round 1 is not authorized` and **zero** `not from a configured public service
role`, with `Verified typed finality observer records` importing normally.
Public RPC and Atlas moved from 0 to 90 on the pre-reset chain, and after the
reset all three relayer observer stores tracked the new chain in lockstep with
the validators. Round changes are exercised continuously by this path, so both
fixes are proven against live round-greater-than-zero traffic.

### 2.2 Timeout-slot deadlock (deployed, proven)

`CONSENSUS_SIGNING_CONFLICT: Timeout slot already authorizes candidate` no
longer occurs. After deploying `1b92a06`, `signing_conflicts_since_up` is **0**
on all six validators, and validators 2 and 3 recorded **0 restarts** where
previously every node restarted every ~25 seconds. The crash loop is gone.

## 3. The remaining defect: the driver cannot survive a round change

Fixing the timeout slot removed the crash loop but revealed the underlying
cause. On the fresh chain the validators failed closed with three distinct
conditions, all clustered on round changes:

```text
TYPED_DRIVER_SOURCE_CONFLICT: validation certificates disagree on the certified candidate
TYPED_DRIVER_SOURCE_CONFLICT: timeout certificate requests carry-forward without a prepared VC
CONSENSUS_SIGNING_CONFLICT: Finality slot already authorizes candidate Some(BlockId("33fbc013..."))
```

Observed sequence on `synergy-val1` after the reset:

```text
16:13:22 CEST  TYPED_DRIVER_SOURCE_CONFLICT: validation certificates disagree ...
16:13:23 CEST  Main process exited, code=exited, status=1/FAILURE
16:13:53 CEST  CONSENSUS_SIGNING_CONFLICT: Finality slot already authorizes candidate 33fbc013...
16:13:58 CEST  restart counter at 2
```

### 3.1 Interpretation

The three conditions are one mechanism seen from three angles.

1. **The driver disagrees with itself across rounds.** Validation certificates
   from different rounds of the same height are treated as a source conflict
   rather than as a legitimate round change. `timeout certificate requests
   carry-forward without a prepared VC` is the same fault stated directly: the
   TC asks the node to carry a prepared candidate forward, and the node has no
   prepared VC to carry.

2. **A prepared `ValidationCertificate` is in-memory only.** This is exactly the
   durability asymmetry fixed for the Timeout signing slot, but it also lives in
   the driver and in the Finality slot. Any mid-height crash destroys the state
   needed to re-derive the same authorization.

3. **Fail-closed guards then convert a crash into a permanent stall.** The
   Finality slot key is height-scoped (`round: None`), so once a node signs
   finality for a candidate at height H it can never sign a different one at H —
   correct for safety. But after a crash the node may re-derive a different
   candidate, hit the guard, and fail closed forever. `safety_halts` is 0
   throughout: no equivocation ever occurred. These are liveness failures, not
   safety failures.

After the final restart the coordinator starts (`Starting finalized typed PoSy
consensus worker`) and then goes **completely idle** — `votes_collected 0`,
`votes_required 0`, `leader_info{leader="",reason=""}` — and never resumes
consensus for the recovered tip. This is why the chain stops permanently rather
than recovering, and it reproduced identically at height 91 before the reset and
at height 37 after it.

### 3.2 Why the reset did not resolve it

The reset proved the machinery works from a clean start and that both observer
fixes hold under live round changes. It did not and could not fix the driver:
the network reaches its first round change within a few minutes and fails the
same way. The pre-reset height-91 state was genuinely unrecoverable — mixed,
mutually inconsistent authorizations across nodes with the deciding certificates
permanently gone — so the reset was still the correct call, but the defect is in
the code, not in the state.

## 4. Recommended next work

This needs design, not a hot patch. The three conditions must be resolved
together, in `runtime/src/consensus/typed_coordinator.rs`,
`runtime/src/consensus/posy.rs`, and the typed PoSy driver:

1. **Make prepared-VC state durable.** The highest prepared `ValidationCertificate`
   must survive a restart, so both the driver and the Finality/Timeout signing
   slots can re-derive an identical authorization. The journal-reuse approach
   already applied to the Timeout slot is the narrow version of this fix; the
   general version is to persist the prepared certificate itself.
2. **Let the driver accept VCs from different rounds of the same height.**
   Disagreement across rounds is normal after a round change and must not be a
   source conflict. Only disagreement *within* a round is evidence of a fault.
3. **Make the coordinator resume after restart.** It currently starts and idles
   at the recovered tip. It must rejoin consensus at `tip + 1`, or fail loudly
   rather than sitting silent.
4. **Add round-change tests that survive a restart**, including: a crash between
   prepare and finality, a TC requesting carry-forward after a restart, VCs from
   two rounds at one height, and a full six-node round change with a mid-round
   process kill.

## 5. Current operational state

All quarantined state is **moved, never deleted**:

```text
validators  /var/backups/synergy-testnet-v3/genesis-reset-validator-20260730T141043Z
relayers    /var/backups/synergy-testnet-v3/genesis-reset-relayer-20260730T141043Z
runtime     /var/backups/synergy-testnet-v3/runtime-hotfix-<role>-<timestamp>
```

Still outstanding, unrelated to the driver defect:

- The RPC gateway RocksDB at `/var/lib/synergy-testnet-v3-rpc-gateway/data/chain`
  and the Atlas Postgres database still hold the pre-reset chain and report
  height 90. Both need clearing once the chain advances, or the public tier will
  keep serving the abandoned chain.
- Cloudflare Authenticated Origin Pulls remain disabled while Nginx requires a
  client certificate.
- Boot persistence is still not enabled.
