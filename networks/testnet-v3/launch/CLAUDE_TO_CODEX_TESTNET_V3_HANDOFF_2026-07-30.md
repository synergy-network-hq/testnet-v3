# Testnet-v3 launch handoff: Claude to Codex

Last verified: **2026-07-30 14:45 UTC**

Supersedes the status sections of
`launch/CODEX_TO_CLAUDE_TESTNET_V3_HANDOFF_2026-07-30.md`. That document's
"Executive status" is obsolete in one important way: it described the validator
set as *live and advancing*. It was not. The chain died at 11:56:58 UTC, seven
minutes before that handoff was written, so its author never saw it.

Supporting analysis:

- `launch/TYPED_FINALITY_OBSERVER_DEFECT_ANALYSIS_2026-07-30.md`
- `launch/VALIDATOR_ROUND_CHANGE_DEFECTS_2026-07-30.md`

---

## 1. Executive status

Four defects were found, fixed, built, and deployed. Three are fully proven in
production. The chain now runs from genesis with **no crashes and no consensus
conflicts**, but it **halts silently at height 37** on the first round change
that no proposer can serve.

| Item | State |
|---|---|
| Observer round>0 rejection | **fixed, deployed, proven** |
| Observer service-role rejection | **fixed, deployed, proven** |
| Timeout-slot signing deadlock | **fixed, deployed, proven** |
| Round-change false conflicts | **fixed, deployed, proven** (no crashes) |
| Carry-forward liveness gap | **OPEN — this is the remaining blocker** |
| RPC RocksDB / Atlas Postgres | stale, still hold an abandoned chain |

Live state at 14:45 UTC:

```text
validators 1-6   height 37, records 37, restarts 0, zero conflicts
relayers 1-3     observer stores v3, height 37, following in lockstep
RPC / Atlas      serving a stale abandoned chain (see section 6)
```

**The single thing that matters next is section 4.**

---

## 2. Current authorized release

| Field | Value |
|---|---|
| Source revision | `24c274facb7c85d9eb9032d49c6468daa9117c6d` |
| Testnet `main` | same |
| Workflow run | `30552010319` (`build-linux-runtime-hotfix`) |
| generic | `cd5dd34a27fff8433974ea0ab1740b2cf4e12886c59c1b2b258e4ac28d488e61` |
| relayer | `82ff699fa6a6a662d388391f61d2176e0033ab056b01d3a7df1765f9b1fd0365` |
| validator | `93388ed6f467f17979e0ac4a4a654a327cb377ca917e270d42f1e925b34873f6` |

Local verified artifact:
`/Users/devpup/Documents/Codex/2026-07-28/we/work/testnet-v3-v20-runtime-hotfix-30552010319`

All five entries pass `sha256sum -c SHA256SUMS`, the release-config manifest is
byte-identical to the canonical source file, and all three binaries are Linux
x86-64 ELF. `launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json` is now current
(the old stale record from handoff "Incomplete 4" is fixed).

**Both deploy guards hardcode the authorized revision.** When you build a new
runtime you must rotate the SHA in *both* or staging fails closed:

```text
scripts/stage-testnet-v3-v20-runtime-hotfix.sh          (~line 76)
scripts/testnet-v3-v20-runtime-hotfix-remote.sh         (~line 48)
```

The Control Panel workflow takes the revision as a dispatch input; no file edit
is needed there. Repo variables `TESTNET_SOURCE_REV` and
`TESTNET_V3_LINUX_RUNTIME_RELEASE` are already set to `24c274f`.

```bash
gh workflow run 247499611 \
  --repo synergy-network-hq/synergy-node-control-panel --ref main \
  -f runtime_hotfix=true \
  -f testnet_source_revision=<SHA> \
  -f testnet_v3_linux_runtime_release=<SHA>
```

---

## 3. What was fixed (all merged to `main`)

| Commit | Fix |
|---|---|
| `86d5dd8` | observer round>0 recovery + DNS-named support-role resolution |
| `1b92a06` | durable timeout-slot recovery |
| `24c274f` | round-change false conflicts in the typed driver |

### 3.1 Observer rejected every round>0 record

`verify_record` called `validate_core_proposal`, whose `require_authorized_round`
reads `authorized_rounds`. That map is only written by `advance_round_after_tc`,
and a timeout certificate is deliberately **not** part of a durable
`TypedFinalityRecord`, so a non-signing observer could never populate it.
Testnet-v3 finalized **height 1 at round 1**, so this rejected the very first
record and no observer store was ever created.

Fixed by parameterising `validate_core_proposal` with `RoundAuthoritySource`.
Signing paths keep `LiveTimeoutCertificate`; the observer uses
`validate_finalized_core_record`, which skips only the live TC lookup. The round
stays bound by the proposer schedule for that exact round, the proposer's
ML-DSA-87 signature over the full header, the supermajority finality QC, and
forward `parent_block_hash` linkage. `candidate_id()` zeroes `round`, so those
bindings — not the QC alone — are what make it sound.

### 3.2 Relayers rejected the RPC gateway

`connected_endpoint_host_matches_configured_address` called `to_socket_addrs()`
on a **bare host** after stripping the port, which always errors. Every
DNS-named allowlist entry was unmatchable inbound. The RPC gateway advertises
`rpc.synergynode.xyz:5623`, so its numeric entry matched the source host but not
the advertised address, and its DNS entry matched the advertisement but never
resolved — no single entry satisfied both. The indexer advertises a numeric
address and was unaffected, which is why only one requester was rejected.

### 3.3 Timeout-slot deadlock (the original chain killer)

All six validators crash-looped ~220 times each from 11:56:58 UTC:

```text
CONSENSUS_SIGNING_CONFLICT: Timeout slot already authorizes candidate
Some(BlockId("c305e182cb5d41eb4d2c9543b454a80c179a50d82ecc7e8d33642cf04c2e6fee"))
```

`timeout_vote` derives its authorization from the in-memory highest prepared
`ValidationCertificate`. The slot key excludes `candidate_id`, so a slot can
only be authorized once. A VC is memory-only, so after a restart the node
re-derived an *empty* candidate for a slot whose durable record named
`c305e182`, the guard correctly refused, and the replay was byte-identical
forever. Journals confirmed the asymmetry: val1 recorded `TIMEOUT(91,0)` with
candidate `c305e182` and a VC root; val3 recorded the same slot with neither.

Fixed with `recorded_authorization_for_slot`: `timeout_vote` now re-emits
exactly what it already committed to, taking the idempotent branch. A genuinely
different candidate for a used slot is still refused.

### 3.4 Round-change false conflicts

```text
TYPED_DRIVER_SOURCE_CONFLICT: validation certificates disagree on the certified candidate
TYPED_DRIVER_SOURCE_CONFLICT: timeout certificate requests carry-forward without a prepared VC
```

`record_validation_certificate` compared a new VC against the retained prepared
VC **without comparing rounds**. `install_verified_timeout_certificate`
deliberately keeps the prepared VC across a round change for carry-forward, so
when a TC carries no candidate forward the next round legitimately certifies a
different one — and every such round change was fatal. Now the driver adopts the
highest-round prepared VC, ignores delayed lower-round ones, and reports a
conflict only for two certificates in the *same* round.

`try_emit_scheduled_proposal` also killed the process when it could not
reconstruct the carried candidate. Those four reconstruction gaps are now
non-fatal.

**This last change is what created the open issue in section 4. Read it.**

---

## 4. THE REMAINING BLOCKER — carry-forward liveness gap

### What happens

The chain builds cleanly from genesis to height 37, all six validators in exact
lockstep, then stops. There is **no crash, no restart, and no error of any
kind**:

```text
restarts=0  state=active  tip=37  records=37
conflicts (last 9 min):   <none>
last failure lines:       <none>
synergy_current_consensus_height 0
synergy_current_consensus_round 0
```

Both the pre-reset chain and the post-reset chain stopped at **exactly 37**, so
the trigger is deterministic — the first round change where no eligible proposer
can serve the carried-forward candidate.

### Why — and be aware this is a regression I introduced

Commit `24c274f` made the carry-forward reconstruction gaps in
`try_emit_scheduled_proposal` return `Ok(())` instead of a fatal
`TYPED_DRIVER_SOURCE_CONFLICT`. That correctly stops the process from dying on
an ordinary liveness gap. But it added **no recovery**: a node that cannot
reconstruct the carried candidate simply does not propose. When every eligible
proposer is in that state, nobody proposes, the round times out forever, and the
chain halts silently.

A loud crash was traded for a quiet halt. The underlying gap — that the prepared
`ValidationCertificate` is memory-only and unreconstructable — was never closed.

Relevant code:

```text
runtime/src/consensus/typed_coordinator.rs   try_emit_scheduled_proposal  (~line 1761)
runtime/src/consensus/typed_coordinator.rs   record_validation_certificate (~line 2165)
runtime/src/consensus/typed_coordinator.rs   install_verified_timeout_certificate (~line 2281)
runtime/src/consensus/posy.rs                timeout_vote (~line 1094)
runtime/src/consensus/signing_authority.rs   recorded_authorization_for_slot
```

### Recommended fix

1. **Make the prepared `ValidationCertificate` durable.** This single change
   underlies defects 3.3 and 3.4 and this blocker. Persist it beside the
   finality store so both the driver and the Timeout/Finality signing slots can
   re-derive an identical authorization after a restart. The
   `recorded_authorization_for_slot` approach is the narrow version; this is the
   general one.
2. **Add peer recovery for carry-forward material.** When a TC carries a
   candidate this node lacks, request the VC and proposal body from peers and
   retry, rather than silently skipping the round. A bounded request/retry on
   the existing typed consensus transport is enough.
3. **Make the coordinator resume after restart.** It currently starts
   (`Starting finalized typed PoSy consensus worker`) and then idles at the
   recovered tip with `votes_collected 0` and `leader=""`. It must rejoin at
   `tip + 1` or fail loudly. This was observed at height 91 pre-reset and at 37
   post-reset.
4. **Consider a proposal-timeout fallback.** If no proposer can serve a carried
   candidate for N consecutive rounds, the protocol needs a defined escape. Do
   not invent one without checking the PoSy safety argument — a wrong choice
   here breaks the carry-forward guarantee.

### Tests to add

None of these exist today, and every one of them would have caught a defect
fixed in this session:

- round change followed by a process restart, mid-height
- crash between prepare and finality, then recovery
- TC requesting carry-forward when the local node holds no prepared VC
- VCs from two different rounds at one height
- six-node round change with a mid-round process kill
- observer import of a record finalized at round > 0 (exists, `24c274f`)

---

## 5. Verification commands

Validator heights (expect all six equal and rising):

```bash
for h in synergy-val1 synergy-val2 synergy-val3 synergy-val4 synergy-val5 synergy-val6; do
  printf '%-16s ' "$h"
  ssh -o BatchMode=yes -o ControlMaster=auto -o ControlPersist=900 \
      -o ControlPath=/tmp/synergy-tv3-status-%C "$h" \
    'sudo -n jq -r "[.store_version,(.records|length),.records[-1].height]|@tsv" \
       /var/lib/synergy/validator/data/typed-posy-finality.json'
done
```

Conflict classes (expect empty):

```bash
sudo -n journalctl -u synergy-validator.service --since "10 min ago" --no-pager \
  | grep -aoE "(TYPED_DRIVER_SOURCE_CONFLICT: [a-z -]+|CONSENSUS_SIGNING_CONFLICT: [A-Za-z]+ slot)" \
  | sort | uniq -c
```

Relayer observer stores are under `.../relayN/data/`, **not** `.../relayN/`:

```bash
/var/lib/synergy/testnet-v3/relay1/data/typed-posy-finality.json
```

Public tier:

```bash
curl -fsS -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}' \
  https://testnet-core-rpc.synergy-network.io

curl -fsS -A 'SynergyLaunchVerifier/20.0.0' \
  'https://testnet-atlas.synergy-network.io/api/v1/network/summary'
```

**Note on `journalctl --since`:** it is interpreted in the *host's* local
timezone (CEST/EDT), not UTC. Use relative windows (`--since "10 min ago"`) or
you will read the wrong era — this cost real time during this session.

---

## 6. Also outstanding

1. **Stale public tier.** The RPC gateway RocksDB at
   `/var/lib/synergy-testnet-v3-rpc-gateway/data/chain` and the Atlas PostgreSQL
   database still hold a pre-reset chain and report height 90 from an abandoned
   chain. Both must be cleared once the chain advances, or the public tier keeps
   serving it. RPC and indexer hold **no** durable observer store, so only those
   two need clearing.
2. **Cloudflare AOP** is still disabled while Nginx requires a client
   certificate (`ssl_verify_client on`). Unchanged from the previous handoff.
3. **Boot persistence** is still not enabled.
4. **Seven pre-existing `p2p::networking` test failures.** Not introduced by
   this session — verified against a clean-tree baseline (141 passed / 7 failed,
   six identical, the seventh a flaky sibling in the same `service_sync_*`
   timing pair). The consensus suite also fails a *different* single test on each
   parallel run and is fully green serialized (`-- --test-threads=1`, 360/360),
   because those tests share process-id-keyed temp paths and a process-wide
   signing authority. Worth a separate cleanup pass.

---

## 7. Backups — nothing was deleted

Every quarantine was a **move**:

```text
/var/backups/synergy-testnet-v3/genesis-reset-validator-20260730T141043Z
/var/backups/synergy-testnet-v3/genesis-reset-relayer-20260730T141043Z
/var/backups/synergy-testnet-v3/round-change-reset-validator-20260730T143540Z
/var/backups/synergy-testnet-v3/round-change-reset-relayer-20260730T143540Z
/var/backups/synergy-testnet-v3/runtime-hotfix-<role>-<timestamp>
```

The `genesis-reset-*` directories hold the original 90-block chain and its
signing journals, including the poisoned height-91 state, if it is ever needed
for forensics.

---

## 8. Things not to do

Carried forward from the previous handoff, still true, plus additions:

- Do not regenerate genesis, identities, custody bundles, contract addresses,
  consensus keys, ETDAG keys, or VPN identities.
- Do not run the genesis ceremony again or apply another finalizer.
- Do not use `wg-quick@sy-vpn`; the transport is innernet-managed.
- Do not use the retired `synergy-testnet-relayer.service`.
- Do not treat active systemd units as proof of chain health — the chain has
  twice been fully "active" and completely stopped.
- Do not relax a signing guard to get past a `CONSENSUS_SIGNING_CONFLICT`.
  Every one seen this session was the guard working correctly against an
  unreproducible authorization; the fix is to make the input durable, never to
  weaken the check.
- Do not resolve the section 4 blocker by reverting `24c274f`. That would only
  restore the crash loop.
