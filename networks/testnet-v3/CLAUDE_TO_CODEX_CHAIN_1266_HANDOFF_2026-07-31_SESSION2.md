# Chain 1266 Stabilization — Claude → Codex Handoff (Session 2)

**Author:** Claude (incident commander, session 2)
**Recipient:** Codex
**Date:** 2026-07-31
**Supersedes nothing.** This is a *continuation* of
`CLAUDE_CHAIN_1266_STABILIZATION_HANDOFF_2026-07-31.md`. That document remains
the controlling directive. Read it first, in full. This file records only what
changed during session 2 and where to resume.

**Controlling branch:** `release/chain1266-consensus-invariants`
**HEAD at handoff:** `267b7955fb33a28ee40fb6ab4f2a0964b72b45cb`
**Working tree:** DIRTY and MUST BE PRESERVED. See §3.
**Repository root:** `/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3`

---

## 0. Read this before doing anything

1. Read `CHAIN_1266_STALL_LOG.md` from first line to last. Mandatory. Session 2
   did this; you must do it too. No incident entry was appended during session 2
   because no mutating action was taken against the fleet.
2. Read the original handoff `CLAUDE_CHAIN_1266_STABILIZATION_HANDOFF_2026-07-31.md`
   in full.
3. Then read this file.
4. Do **not** run `git reset --hard`, `git clean`, `git checkout --`, or
   `git stash`. The working tree contains unpushed, uncommitted, partially
   verified work.

---

## 1. What session 2 actually established (verified facts, not claims)

### 1.1 The public Chain 1266 fleet is ALREADY FULLY STOPPED

This is the single most important discovery of session 2 and it changes the
sequencing in the original handoff.

A read-only inventory was taken via
`python3 scripts/chain1266/control-plane.py inventory`
(output preserved at `/tmp/c1266-inventory.json`, 14 nodes, collected
2026-07-31T18:06:43Z).

Result:

| Node | systemd ActiveState | SubState | NRestarts |
|---|---|---|---|
| validator-node-01 .. 06 | inactive | dead | 0 |
| relay1, relay2, relay3 | inactive | dead | 0 |
| rpc-gateway | inactive | dead | 0 |
| explorer-indexer | inactive | dead | 0 |
| observer | inactive | dead | 0 |
| atlas-api | **active** | **running** | 0 |
| atlas-indexer | **active** | **running** | 1 |

Consequences:

- Original handoff §11 steps 3–6 ("stop relayers, stop validators, confirm no
  role process remains") are **already satisfied**. Do not treat stopping them
  as pending work.
- **Atlas API and Atlas Indexer are the ONLY things still running**, and they
  are still serving chain-derived data publicly. This is exactly the stale-data
  hazard recorded in incident `C1266-2026-07-30-003`. They must be stopped
  before the offline Atlas schema reset (§11 step 1, and `atlas/ops/reset-schema.sh`).
- The six validator machines are **idle and available**, which is what makes the
  Ring 2 decision in §5 below workable.

Reported metrics showed height 0 / blocks 1 on the chain roles. Treat these as
**stale cached values, not live readings** — the services are dead and cannot be
serving live metrics. Do not conclude "the chain is at height 0 and healthy."

### 1.2 Anomaly to resolve during staging — validator-node-03

`validator-node-03` reported **no `GenesisSHA256`** in the inventory while
val1, val2, val4, val5, val6, relay1, relay2, relay3 all reported
`ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf`.

Direct SSH shows val3's directory layout is byte-identical in structure to val1
(`/var/lib/synergy/validator/{config,data}`, owner `node:node`). It is probably
a transient read failure in the control plane, **not** a real difference.

**Do not assume.** Verify explicitly during §12.1 staging. A genesis mismatch on
one validator is precisely the failure mode that produces a 5/6 split after
consensus release. Note also that `ee554c19…` is the **file SHA-256 of
genesis.json on disk**, which is NOT the same value as the canonical
incarnation-4 **genesis block hash** `859c40e3…`. Do not confuse them.

### 1.3 §6.2 FN-DSA transport test — RESOLVED, PASSING

The original handoff listed this as an unknown ("in final compile phase when
Codex usage ended, no recorded result"). Session 2 confirmed **no such process
survived** — it had to be rerun from scratch.

It now **passes**. `p2p::networking::tests::signed_aegis_pqc_handshake_verifies`
was repointed (in the uncommitted working tree) from the validator path to the
downstream relay path and now asserts `aegis_pq_public_key_algorithm == "fndsa"`
after a real `verify_handshake_pq_signature` call. That is a genuine
FN-DSA-1024 sign-then-verify, not interface creation.

### 1.4 Twelve targeted tests confirmed passing

Run on the working tree with `CARGO_BUILD_JOBS=1`, all 12 passed in 26.27s:

```
consensus::typed_coordinator::tests::authenticated_messages_buffer_before_mailbox_install_and_drain_in_order
consensus::typed_coordinator::tests::authenticated_finalized_height_retries_are_ignored_before_pq_verification
consensus::typed_coordinator::tests::observer_identity_cannot_advertise_a_validator_recovery_checkpoint
consensus::typed_coordinator::tests::randomized_signature_replay_keeps_one_vote_subject
consensus::typed_coordinator::tests::driver_deduplicates_only_exact_authenticated_vote_replays
consensus::signing_authority::tests::atomic_recovery_checkpoint_survives_interrupted_temp_write_and_rejects_tampering
consensus::self_realign::tests::snapshot_manifest_rejects_old_chain_incarnation
crypto::aegis_pqvm::tests::consensus_vote_restart_replays_the_exact_durable_randomized_signature
desired_state::tests::desired_state_signature_is_real_mldsa87_and_digest_bound
p2p::networking::tests::old_chain_incarnation_handshake_is_rejected_before_pq_verification
p2p::networking::tests::signed_aegis_pqc_handshake_verifies
p2p::networking::tests::direct_vote_handshake_capability_is_signed_and_verifiable
```

Notably this includes the stale-finalized-height regression, which is the fix
for the failure that invalidated the previous Ring 1 run.

### 1.5 Working-tree audit clean for secrets

No credentials, build artifacts, local databases, or generated test output are
staged. `backend/` has **not** reappeared. The only secret-shaped string in the
diff is `POSTGRES_PASSWORD: atlas_qualification` in
`.github/workflows/chain1266-release.yml`, which is a disposable Ring 2
qualification value and is acceptable.

### 1.6 Runtime diffs reviewed and judged correct

- `runtime/src/p2p/networking.rs`: validators still take the ML-DSA-65
  custody-key branch via `local_consensus_handshake_required(config)`; only
  downstream roles reach the new `generate_and_register_fndsa_peer_identity`.
  Handshakes carry `chain_incarnation` and `consensus_state_schema_version`.
  New `VERIFIED_MLDSA65_HANDSHAKES` / `VERIFIED_FNDSA_HANDSHAKES` counters are
  incremented only *after* successful verification.
- `runtime/src/consensus/typed_coordinator.rs`: the stale-height filter is
  correctly placed — it authorizes the peer first, then discards, and returns
  `StaleFinalizedHeightIgnored` **before** PQ verification. `FinalityCheckpoint*`
  messages correctly return `None` from `typed_message_height` and are exempt.
- `runtime/src/desired_state.rs`: `verify_signed_desired_state_file` pins
  chain_id, incarnation, quorum, schema, namespace `chain-1266/incarnation-4`,
  and the Governance fingerprint before verifying the signature.
- `runtime/src/telemetry.rs`: exposes
  `p2p_verified_handshakes_total{algorithm="ML-DSA-65"|"FN-DSA-1024"}`.

---

## 2. Gaps session 2 FOUND that the original handoff assumed were closed

These are real and must be fixed before Ring 1 is meaningful.

### 2.1 CRITICAL — the Ring 1 matrix never got the new regression added

`scripts/chain1266/run-ring1-fault-matrix.sh` still has 21 cases. The diff to
that file only changed failure *reporting* (`failed_case`, `break` instead of
`exit 1`, SHA256SUMS path). **The `cases=(...)` array was not touched.**

Therefore `authenticated_finalized_height_retries_are_ignored_before_pq_verification`
— the test written specifically to fix the failure that broke the last Ring 1
run — **is not in the matrix**. Running Ring 1 as-is would not re-test the thing
that failed.

**Required fix:** add at minimum one case. Original handoff §7 case 20 requires
"Exact replay, duplicate flood, **stale finalized-height retries**, and
pre-crypto filtering" — currently only `old_incarnation_precrypto_rejection`
(a *handshake* test) covers that slot.

Suggested addition to the `cases=(...)` array:

```
"stale_finalized_height_precrypto_rejection|consensus::typed_coordinator::tests::authenticated_finalized_height_retries_are_ignored_before_pq_verification"
```

Adding cases is permitted (strengthening). Removing or weakening cases is
forbidden by §7 ("Do not weaken or skip a case to obtain a green result").

### 2.2 No signing-journal compaction / retirement-watermark test exists

Original handoff §6.6 explicitly requires "Journal compaction/watermark
behavior". The logic **is implemented** in
`runtime/src/consensus/signing_authority.rs` `load_unlocked()` (approx. lines
961–984): it rejects a journal that retains a record at or below
`retired_through_height`, rejects a watermark that disagrees with the atomic
recovery checkpoint's `finalized_height`, and rejects a nonzero watermark with
no checkpoint.

There is **no test** for any of it. Grep of that file's `#[cfg(test)]` module
confirms: no `compact`, no `watermark`, no `retire` test.

**Required:** write one. It should prove (a) finalized slots compact behind the
watermark, (b) a journal retaining a retired slot is rejected, (c) a watermark
disagreeing with the checkpoint is rejected, (d) the journal stays bounded over
a long run (relevant to §6.5's 10,000-block unbounded-growth audit).

### 2.3 ML-DSA-65 validator handshake coverage was silently REMOVED

The working tree repointed `signed_aegis_pqc_handshake_verifies` from the
validator path to the relay path (see §1.3). Net effect: FN-DSA-1024 **gained**
coverage and ML-DSA-65 **lost** it. Original handoff §6.6 requires "ML-DSA
validator transport authentication" as a distinct item.

**Important context — read before attempting this.** A unit test cannot perform
a real ML-DSA-65 validator handshake using the canonical Genesis fixture,
because `runtime/config/genesis.testnet-v3.test-fixture.json` ships validator
**public** keys only. `build_local_handshake` on the validator path calls
`load_local_validator_keypair` → `expected_validator_public_key_for_height`,
which fails with `validator synv1local is not registered`. This is why the test
was repointed in the first place.

Justin clarified that in **production** each validator does hold its own
ML-DSA-65 private key locally on its machine. The limitation is purely the test
fixture, not the design.

Two viable options — **pick one, do not leave this gap open**:

- **(a) Preferred.** Build a real ML-DSA-65 handshake test using the pattern in
  `consensus/typed_coordinator.rs::six_validator_startup_fixture` (approx. line
  4537), which generates real disposable ML-DSA-65 keypairs via
  `AegisPqvmSigner::generate_and_register_key(...)` and has both public and
  private key in hand. You will additionally need to register the validator in
  `VALIDATOR_MANAGER` (see `validator.rs:1561 register_validator`) and cache the
  private key via `consensus/validator_keys.rs::register_test_validator_signing_key`
  (a `#[cfg(test)]` helper, approx. line 831). Assert
  `aegis_pq_public_key_algorithm == "mldsa65"`, that the typed PoSy validator
  capability is advertised, and that
  `p2p_handshake_metrics_snapshot().mldsa65_verified` increments.
- **(b) Fallback.** Keep the placeholder session 2 left in the tree (see §3.2),
  which proves the weaker but still valuable property that the validator path
  fails closed and never silently falls back to the FN-DSA identity generator.
  If you choose this, you MUST rely on Ring 1 case
  `real_mldsa_six_validator_burn_in` and the Ring 2
  `p2p_verified_handshakes_total{algorithm="ML-DSA-65"}` counter as the actual
  ML-DSA-65 proof, and say so explicitly in the Ring 1 report.

### 2.4 Minor — governance signature tamper coverage

`desired_state::tests::desired_state_signature_is_real_mldsa87_and_digest_bound`
proves digest-binding tamper rejection (changing `desired_state_sha256`
invalidates). It does **not** test flipping bytes in the signature itself.
Low risk, but §6.6 says "Governance-signature verification and tamper
rejection". Consider adding a signature-byte mutation assertion.

---

## 3. EXACT working-tree state — preserve this

`git status --short --branch` at handoff:

```
## release/chain1266-consensus-invariants
 M .github/workflows/chain1266-release.yml
 M atlas/README.md
 M launch/CHAIN_1266_FLEET.json
 D runtime/node-control-panel/build/validator-package/.gitkeep
 M runtime/src/consensus/typed_coordinator.rs
 M runtime/src/crypto/aegis_pqvm.rs
 M runtime/src/desired_state.rs
 M runtime/src/p2p/networking.rs
 M runtime/src/telemetry.rs
 M scripts/chain1266/control-plane.py
 M scripts/chain1266/run-ring1-fault-matrix.sh
 M scripts/chain1266/run-ring2-private-qualification.sh
?? atlas/ops/
?? launch/chain1266-systemd/chain1266-role-service
?? launch/chain1266-systemd/synergy-chain1266-role@.service
?? runtime/src/bin/verify-chain1266-release-authorization.rs
```

### 3.1 ACTION REQUIRED — restore the deleted .gitkeep

```
 D runtime/node-control-panel/build/validator-package/.gitkeep
```

This deletion **was not present at the start of session 2**. It appeared during
the session as a side effect of a build/tooling run. It is unintended.

```bash
git checkout -- runtime/node-control-panel/build/validator-package/.gitkeep
```

Do this before committing. Do not let it into the immutable candidate.

### 3.2 UNCOMMITTED, UNVERIFIED source edit made by session 2

Session 2 added exactly one thing to the source that was **never successfully
compiled or run**. Treat it as unverified.

**File:** `runtime/src/p2p/networking.rs`
**Location:** in `mod tests`, immediately after
`signed_aegis_pqc_handshake_verifies` and immediately before
`old_chain_incarnation_handshake_is_rejected_before_pq_verification`
**Test name:** `validator_handshake_never_falls_back_to_the_fndsa_peer_identity`

What it asserts: that `local_consensus_handshake_required(&config)` is true for
a configured validator address, that `build_local_handshake` returns `Err`, that
the error mentions `ML-DSA-65`, and that the error does **not** mention `fndsa`.

History, so you do not repeat the loop:

1. First version asserted a *successful* ML-DSA-65 handshake. It failed at
   runtime with `validator synv1local is not registered` (see §2.3).
2. It was rewritten to the fail-closed form now in the tree.
3. The rewritten version **has never compiled successfully** — the build was
   killed by an unrelated OOM before it produced a result.

An earlier compile error in version 1 was a scope issue, already fixed by adding
an inner `use crate::p2p::networking::{...}`. The current version does not
reference those symbols, so that `use` was removed. If you see a leftover unused
import, remove it.

**Your first job on this file:** compile and run that one test. If it passes,
decide between §2.3 option (a) and (b). If you pick (a), replace it.

---

## 4. Build system — READ THIS, IT COST SESSION 2 ABOUT 90 MINUTES

The machine is a **macOS arm64 laptop with 8 GB RAM and a 5 GB swap file**.
It cannot compile this workspace in parallel.

### 4.1 Hard rules

- **`CARGO_BUILD_JOBS=1` always.** Non-negotiable on this hardware.
- **Never run two cargo processes at once.** Session 2 did, and it corrupted the
  incremental cache, producing
  `error: unable to copy ... .rcgu.o: No such file or directory (os error 2)`.
- **Never set `CARGO_INCREMENTAL=0`.** Session 2 set it to work around the
  corruption. That forced a full non-incremental rebuild of **456 crates**,
  which drove swap to 4.2 GB of 5 GB, and a `rustc` process was OOM-killed
  during the `wasmtime` / `wasm-compose` crates. Restoring incremental reduced
  the same work to **6 crates**.
- **`timeout` is NOT installed** (`/opt/homebrew/bin/bash: timeout: command not
  found`). Use `nohup ... &` plus polling, or the inline Python timeout harness
  already present in `run-ring1-fault-matrix.sh`.

### 4.2 How to tell a hung build from a slow one

A quiet log does **not** mean progress. Session 2 lost 17 minutes to a build
that was already dead. Cargo will hold `target/debug/.cargo-lock` forever with
no child process if its compiler is killed.

Check for a live child, not elapsed time:

```bash
ps -axo pid,%cpu,rss,comm | grep -iE 'rustc|cc1plus|clang|c\+\+' | grep -v grep
sysctl vm.swapusage
```

If cargo is alive but there is **no** `rustc`/`clang` child and CPU is 0.0, it is
hung. Recover with:

```bash
pkill -9 -f "cargo test"
rm -f runtime/target/debug/.cargo-lock
# then restart WITHOUT CARGO_INCREMENTAL=0
```

### 4.3 Build state at handoff

A build was **in flight** when session 2 ended:

```bash
cd runtime/src && CARGO_BUILD_JOBS=1 nohup cargo test --lib --no-run > /tmp/c1266-build2.log 2>&1 &
```

Progress at handoff: 6 crates queued, sitting on `librocksdb-sys v0.17.3+10.4.2`
(a large C++ build; 329 object files were already emitted, `clang` at 83% CPU,
swap recovered to 2.9 GB). It was healthy and progressing. Estimated ~10–20
minutes remaining to a runnable test binary.

**Check it first.** It may have completed, or it may have been killed when the
session ended.

```bash
grep -c '^   Compiling' /tmp/c1266-build2.log
tail -5 /tmp/c1266-build2.log
```

---

## 5. Decisions Justin made during session 2 — these override the original handoff

### 5.1 Ring 2 runs on the REAL validator machines, with disposable everything else

Justin instructed: "use the actual validator machines."

This was flagged as conflicting with original handoff §8.1 and §16, which forbid
production keys and VPN credentials in Ring 2. The agreed resolution:

- **USE** the six production validator **hosts** (they are idle — see §1.1).
- **DO NOT USE** production validator custody keys, production node identity
  keys, or production WireGuard credentials.
- **GENERATE** six disposable validator identities and disposable full-mesh
  WireGuard credentials for the ring.
- **USE** a separate qualification state namespace and database, distinct from
  `chain-1266/incarnation-4`.
- **ENSURE** the private ring cannot peer with or accept messages from public
  Chain 1266 (all public roles are already stopped, which helps, but firewall
  it explicitly — do not rely on "the services happen to be down").

This preserves every §8.1 property that matters while honouring the instruction.
**Do not silently escalate to production keys.**

### 5.2 Passphrase handling relaxed for testnet

Justin's exact position: "ordinarily I would agree about the passphrases,
however this is testnet and we are trying to get everything operating correctly.
we can rotate keys and passphrases and all of that shit some other time, AFTER
we have a working, stable, healthy chain."

Interpretation: do not build elaborate no-context secret-piping machinery. Use
the passphrase directly. Still avoid gratuitously echoing it into chat output,
CI logs, or committed files — that costs nothing to avoid. It is not a blocker.

### 5.3 Scope

Justin authorized proceeding all the way through the destructive public wipe and
incarnation-4 restart, with one checkpoint: **stop for explicit confirmation at
the dry-run deletion manifest** (§10 of the original handoff) before executing
any destructive reset.

---

## 6. Governance signing — path fully traced, ONE blocker

### 6.1 The authority is identified

**`SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY`** — a dedicated ceremony identity. It
is **not** the workbook's `DAO-A01` and **not** any `CTL-SIGNER-*` row.

Confirmed by matching the fingerprint hard-pinned at
`runtime/src/desired_state.rs:31-32`:

```rust
const PRODUCTION_GOVERNANCE_FINGERPRINT: &str =
    "sha256:7f296c61ad8c636dd21eb8c3dd360e981ba720cdef1b2a7e84f3c1107f6eb200";
```

against
`testnet-v3-identity-files/SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY/manifest.json`,
which reports the identical `public_key_fingerprint`, `algorithm: ML-DSA-87`,
`chain_id: 1266`, `network_id: synergy-testnet-v3`, `test_fixture: false`,
`custody_scheme: ml-kem-1024-hybrid+aes-256-gcm`, `kdf: argon2id`
(m_cost 65536, t_cost 3, p_cost 1).

Bundle contents:
`identity.enc.json`, `identity.pub.json`, `manifest.json`,
`correspondence.json`, `SHA256SUMS`.

### 6.2 The tooling already exists — do not write new signing code

- `synergy-address-engine/src/bin/sign_chain1266_release_authorization.rs`
  — purpose-built for exactly this signature.
- `runtime/src/bin/build-chain1266-desired-state.rs` — builds the manifest.
- `runtime/src/bin/sign-chain1266-desired-state.rs` — takes `--desired-state`,
  `--private-key` (base64 ML-DSA-87), `--output`. Its own header says
  *"Qualification uses a disposable key; production uses the Governance
  Authority through its custody signer."*
- `runtime/src/bin/verify-chain1266-release-authorization.rs` (untracked, new)
  — the independent verifier required by original handoff §9.10.

Decryption goes through the Address Engine, not through repo code:
`synergy-keygen decrypt <enc_path> --stdout`, located via `SYNERGY_KEYGEN_BIN`
or defaulting to
`/Volumes/xcode/Synergy-Network-Projects/protocol-components/synergy-address-engine/target/release/synergy-keygen`.
See `runtime/src/bin/synergy-genesis-ceremony.rs:120-157`.

### 6.3 PREREQUISITE — the Address Engine is not built

```bash
ls /Volumes/xcode/Synergy-Network-Projects/protocol-components/synergy-address-engine/target/release/synergy-keygen
# -> No such file or directory
```

The repo exists; the binary does not. **Build it** (`cargo build --release`,
`CARGO_BUILD_JOBS=1`, and **only when no other cargo build is running** — see
§4.1). Session 2 deliberately did not start it to avoid a second concurrent
build.

### 6.4 BLOCKER — the Governance passphrase is not in the workbook

Justin supplied `node-machine-credentials.xlsx`. It was examined
programmatically. Findings:

- Sheet `Testnet-v3 Identities` holds **64 identities** with **64 distinct**
  per-identity passphrases (column `Encryption Passphrase`, 53 chars each).
  There is no shared master passphrase.
- `testnet-v3-identity-files/` on disk contains **70** identity bundles.
- The **6 bundles with no workbook entry** are precisely the protocol authority
  bundles:

```
SNRG-TESTNET-V3-GOVERNANCE-AUTHORITY          <-- needed for §6.4 of the original handoff
SNRG-TESTNET-V3-GENESIS-DEPLOYER
SNRG-TESTNET-V3-EMERGENCY-PAUSE-AUTHORITY
SNRG-TESTNET-V3-EMERGENCY-SLASHING
SNRG-TESTNET-V3-REWARD-DISTRIBUTOR-AUTHORITY
SNRG-TESTNET-V3-VALIDATOR-REGISTRY-AUTHORITY
```

All three copies of the workbook on disk were checked and none contain them:

```
/Volumes/xcode/Synergy-Network-Projects/node-machine-credentials.xlsx
/Volumes/xcode/Synergy-Network-Projects/documentation/unorganized-files/node-machine-credentials.xlsx
/Volumes/xcode/Synergy-Network-Projects/outputs/019f9b88-.../node-machine-credentials.xlsx
```

**Ask Justin for the Governance Authority passphrase when you reach signing.**

### 6.5 This does NOT block Ring 1 or Ring 2

Qualification signs with a **disposable** key by design. Run both rings and
stage everything first. Only the final production manifest (original handoff
§9.9) and the public start require the Governance secret.

### 6.6 Note on the interactive prompt

`sign_chain1266_release_authorization.rs:300` explicitly **rejects environment
passphrases** ("environment passphrases are forbidden; use the interactive
prompt") and `synergy-genesis-ceremony.rs` requires a TTY. This is a deliberate
guard. You can drive it through a pty, but Justin may prefer to type it himself.
**Ask; do not assume.**

### 6.7 The file `inspect-credentials-workbook.mjs` does not exist

Original handoff §6.3 says it "was created as the last recorded file action."
It is **not** in the repo, `/tmp`, `/Users/devpup`, or anywhere under
`/Volumes/xcode`. It was never persisted. §6.3 is moot — do not hunt for it.
The workbook is read directly with `openpyxl` (already installed, 3.1.5).

---

## 7. Resume point — do these in order

1. **Check the in-flight build** (§4.3). Restart per §4.1 rules if dead.
2. **Restore the deleted `.gitkeep`** (§3.1).
3. **Compile and run** `validator_handshake_never_falls_back_to_the_fndsa_peer_identity`
   (§3.2). Resolve §2.3 — option (a) or (b).
4. **Write the journal compaction/watermark test** (§2.2).
5. **Add the stale-finalized-height case to the Ring 1 matrix** (§2.1).
   Consider also adding the signature-tamper assertion (§2.4).
6. **Complete the §6.5 source audit** from the original handoff. Session 2 did
   NOT do this. Still outstanding: identity derived from signature/certificate
   bytes, proof roots, or signer ordering; incarnation/schema fields in every
   constructor and deserializer with no silent default fallback; every
   observer→validator message path; queue/buffer/journal/cache/incident-bundle
   bounds for a 10,000-block run.
7. **Review `atlas/ops/reset-schema.sh`** (untracked, new, 4173 bytes) against
   the original handoff §11 preserve-list. Session 2 did NOT review it. This is
   the single most dangerous file in the change set — it must destroy only
   chain-derived schemas/tables/queues/caches/materialized views and must
   preserve user, profile, and administrative data.
8. **Review `scripts/chain1266/run-ring2-private-qualification.sh`** (+359
   lines) and adapt it to the §5.1 model (real hosts, disposable identities).
9. `cargo fmt`, compile all role/tool binaries as v20.0.0, commit, record the
   full SHA, confirm a clean tree, **freeze**.
10. **Run the full Ring 1 matrix** against that frozen commit. Any single
    failure invalidates the candidate: one consolidated fix, new commit, rerun
    **from case 1**.
11. **Ring 2** per §5.1. Then the signed release, then the §10 dry-run manifest
    — **stop there for Justin's explicit confirmation** — then wipe, then start.

---

## 8. Useful commands and artifacts

```bash
REPO=/Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnetv3

# read-only fleet inventory (safe, non-mutating)
python3 $REPO/scripts/chain1266/control-plane.py inventory

# control-plane subcommands (in intended order of use)
#   inventory, capture, monitor, assert-mutation-ready, validate-promotable,
#   stop-for-reset, wipe-all-chain-state, reset-atlas-offline, stage-release,
#   start-support, start-validators-paused, assert-paused-barrier,
#   distribute-start-command, activate-atlas

# Ring 1
CHAIN1266_QUALIFICATION_REPORT_DIR=... $REPO/scripts/chain1266/run-ring1-fault-matrix.sh

# targeted tests
cd $REPO/runtime/src && CARGO_BUILD_JOBS=1 cargo test --lib -- --exact <test_path>
```

Preserved session-2 artifacts:

- `/tmp/c1266-inventory.json` — the §1.1 read-only fleet inventory
- `/tmp/c1266-build2.log` — the in-flight build log

SSH aliases are in `~/.ssh/config` (`synergy-val1..6`, `synergy-relayer1..3`,
`synergy-rpc`, `synergy-index`, `synergy-observer`, `synergy-bootseed1..3`,
`synergy-main`). Passwordless sudo is available. Note `synergy-val4` and
`synergy-archive` share HostName `73.79.66.255`.

Canonical identity (unchanged):

```
Chain ID:          1266
Chain incarnation: 4
State schema:      4
Genesis hash:      859c40e33cca7e02e7a3b3ebeafecbbf04ce29080863313ef893a8a5e6341c1d
Validator quorum:  5 of 6
Runtime version:   v20.0.0 release-candidate family
```

---

## 9. What session 2 did NOT do

State this plainly so nothing is assumed complete:

- Did **not** commit anything. HEAD is still `267b795`.
- Did **not** mutate any live node. No service was started, stopped, staged, or
  reset. No chain state was deleted.
- Did **not** append to `CHAIN_1266_STALL_LOG.md` (no mutating action occurred,
  so no incident entry was warranted).
- Did **not** complete the §6.5 source audit.
- Did **not** review `atlas/ops/reset-schema.sh`.
- Did **not** review the Ring 2 script or the +811-line `control-plane.py` diff
  in detail.
- Did **not** run the Ring 1 matrix.
- Did **not** start Ring 2.
- Did **not** build the Address Engine.
- Did **not** obtain or use the Governance passphrase.
- Did **not** build any release artifact or sign any manifest.

---

## 10. Prohibited actions — carried forward, still binding

From the original handoff §16, plus session-2 additions:

- Do not resume the old patch/restart cycle or deploy the prior cache-only
  artifact.
- Do not wipe the chain before both rings pass and the manifest is signed.
- Do not reuse the old chain incarnation.
- Do not let observer roles send authoritative recovery evidence to validators.
- Do not compare consensus decisions by signature bytes, proof root, signer
  order, or certificate serialization.
- Do not run uncached PQ verification on the async coordinator thread.
- Do not open chain-derived state before desired-state verification succeeds.
- Do not use production custody/validator/VPN keys in Ring 2 (§5.1).
- Do not manually type an unverified source SHA into a release workflow.
- Do not use Atlas as the consensus-health authority.
- Do not claim health from process status or a small block count. Do not call
  the chain stable at block 6, 17, 51, 100, or 300. STABLE means 10,000
  consecutive finalized blocks with all HEALTHY gates still satisfied.
- Do not run `git reset --hard`, `git clean`, or discard the working tree.
- **(new)** Do not run two cargo builds concurrently, and do not set
  `CARGO_INCREMENTAL=0` (§4.1).
- **(new)** Do not weaken the Ring 1 matrix to get a green result; §2.1 requires
  *adding* a case, not swapping one out.
