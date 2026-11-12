# Integrated Linux recovery and five-validator comparison

The corrected implementation has passed isolated storage, cryptographic safety,
retention, encrypted transaction, package and Linux lifecycle checks. **It has not
been deployed. All five real validators and the soak remain stopped.** The old
installed release passed the new identical conformance policy on every host at
2026-10-27 08:45:01–04 UTC. A subsequent stopped-state check independently found
inactive/dead/MainPID0, unchanged limits and no active qualification units.

This report covers the integrated engineering recovery objective
`8e5005ee-d2d0-44fe-a908-2bb038bae29a`. Raw evidence is under
`node-platform/target/engineering-recovery-20261026` (E below). No real validator
keys, genesis, journals, databases, VPN settings or application files were changed.
Credential rotation remains deferred. Atlas dashboard restoration is a separate
pending task; this report does not claim it was restored.

## Ownership and implemented results

| Owner | Completed implementation | Verification |
|---|---|---|
| Hercules | Indexed exact-byte PoSy archive; bounded historical reader/cache; untouched legacy compatibility; durable pair commits and conflict rejection. Also corrected package lifecycle ownership, interrupted upgrade completion and explicit installation stages. | 45 PoSy library tests; native signature/QC/finality tests; 8,192-height storage measurement; captured-history compatibility; actual process crash tests; 32 package tests. |
| Einstein | Verified prior memory repairs in deployed source inventory; removed redundant reservation root hashing; fixed finalized-read/prune race and empty-transaction full-World reconstruction. Corrected dynamic TPS domains, native registry metadata, bounded RPC authorization decoding and a test-only RPC listener handoff race. | Component, encrypted ETDAG, pressure/drain, snapshot/rejoin and restart tests; 2,048-height root equivalence; 70 Python tests; 11 RPC tests serial/parallel; handoff regression 100/100. Linux resource addendum binds exact executable and 331 source inputs. |
| Codex | Integrated one generated master/installer; closed inventory/schema/effective-unit conformance; sealed build provenance; all-five governed workload-authority preflight; Linux VM acceptance and fleet/deployment evidence. | Same policy PASS all five old installations; 61 native cross-network checks on exact new Linux binaries; current Linux PoSy suite 45/45; native existing-public-history rehearsal; Linux install/identity/registered and unregistered upgrade/uninstall acceptance; authorized encrypted finality/effects regression. |

Strict integrated Clippy with `-D warnings` and formatting passed. The formatting
scope excludes vendored Aegis. Linker deprecation and ExFAT cache hardlink fallback
messages are retained in logs; no source lint suppression was added.

## One five-column fleet comparison

The symbols H, P and C expand to complete hashes immediately below the table.
Independent file counts are structural inventory results, not expected equal
ledger contents. Because the nodes are stopped, **there is no running executable
to inspect now**. These are installed hashes and configured next-exec paths;
the earlier running-process/library verification is separately attributed below.

| Val2 | Val3 | Val4 | Val5 | Val6 |
|---|---|---|---|---|
| **State:** stopped, PID0 | **State:** stopped, PID0 | **State:** stopped, PID0 | **State:** stopped, PID0 | **State:** stopped, PID0 |
| **Installed node/package:** H / P | **Installed node/package:** H / P | **Installed node/package:** H / P | **Installed node/package:** H / P | **Installed node/package:** H / P |
| **Normalized effective config:** C | **Normalized effective config:** C | **Normalized effective config:** C | **Normalized effective config:** C | **Normalized effective config:** C |
| **Root/schema:** `/opt/Synergy`; storage1; 12 sealed files | **Root/schema:** same | **Root/schema:** same | **Root/schema:** same | **Root/schema:** same |
| **Checked runtime files/directories:** 73,667 / 132 | **Checked runtime files/directories:** 72,249 / 92 | **Checked runtime files/directories:** 73,893 / 92 | **Checked runtime files/directories:** 72,843 / 94 | **Checked runtime files/directories:** 73,733 / 92 |
| **Systemd:** canonical node+VPN units; no drop-ins | **Systemd:** same | **Systemd:** same | **Systemd:** same | **Systemd:** same |
| **Limits:** 1GiB; swap0; Tasks512; unlimited CPU quota | **Limits:** same | **Limits:** same | **Limits:** same | **Limits:** same |
| **CPU/RAM:** EPYC, 8 threads, 23.46GiB | **CPU/RAM:** EPYC, 8 threads, 23.46GiB | **CPU/RAM:** Xeon X5675, 24 threads, 121.53GiB | **CPU/RAM:** EPYC, 6 threads, 11.68GiB | **CPU/RAM:** EPYC, 8 threads, 23.46GiB |
| **Filesystem:** ext4, commit30 | **Filesystem:** ext4, commit30 | **Filesystem:** ZFS, rpool root | **Filesystem:** ext4, commit30 | **Filesystem:** ext4, commit30 |
| **Transport:** canonical signed registry; wt0 MTU1280 | **Transport:** same | **Transport:** same | **Transport:** same | **Transport:** same |
| **Unexpected application components/overrides:** none under policy | **Unexpected application components/overrides:** none | **Unexpected application components/overrides:** none | **Unexpected application components/overrides:** none | **Unexpected application components/overrides:** none |
| **Corrected release:** awaiting deployment approval | **Corrected release:** awaiting deployment approval | **Corrected release:** awaiting deployment approval | **Corrected release:** awaiting deployment approval | **Corrected release:** awaiting deployment approval |

- H: `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`.
- P: `fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8`.
- C: `025941aa67e9cf32e97c6e97e70a18cde2c0949d3e7754bd7909255565d83214`.

Evidence: E/`existing-release-readonly-conformance-completion.json` and
E/`fleet-stopped-completion.json`. The configuration fingerprint differs from
older reports because the verifier now normalizes with stricter path/endpoint
rules; it is not evidence of a live configuration change. It retains ports,
address family, loopback/wildcard scope, peer count/order and all nonidentity
consensus/ETDAG/queue/retention parameters. Full normalized config is preserved.
All five currently share kernel `7.0.0-38-generic`, x86_64.

## Differences, significance and smallest corrective action

| Classification and exact source | Difference and operational significance | Smallest safe action |
|---|---|---|
| EXPECTED — completion conformance JSON, per-host normalized configurations and runtime inventories | Own node/key identifiers, signed endpoints, independent histories, cache/log/evidence counts. Same permitted locations, types and schema; no byte equality required for independent state. | None. Preserve each host's identity, journals and databases. |
| JUSTIFIED — completion stopped JSON, `cpu`, `ram`, `storage` | Val4 Xeon/ZFS and greater RAM; Val5 fewer cores/RAM. Different scheduling, storage/cache accounting and potential contention. Same protocol and cgroup policy. | No homogenization or resource increase. Include filesystem/host accounting in a separately approved qualification. No causal stall conclusion. |
| JUSTIFIED — `FIVE_VALIDATOR_REBUILD_EXECUTION_20261026.md`, final runtime environment evidence | Val4 Ubuntu26.04.1/en_US.UTF-8 versus other26.04/C.UTF-8; earlier running mapped library hashes matched. Val2 uses OS networkd integration with wt0 unmanaged. | Preserve supported host integration. These are previously observed facts, not a fresh package-version/clock/firewall audit during the stopped check. |
| UNEXPLAINED CAUSALITY — retained finality/transport evidence | Historical 33s/43s stalls, loss/backoff and delayed handoff correlations remain without proof of the exact blocking operation. Fleet consistency does not prove the cause. | Preserve evidence. Resume only the specifically approved critical-path diagnosis after the storage/deployment boundary; no speculative protocol change. |
| CONFIRMED SHARED DEFECT — Hercules report and `persistence/evidence_store.rs` | Every old installation shares per-message historical-file proliferation; equivalence does not make that design acceptable. | Same tested archive implementation and software-only upgrade on all five after approval; no history deletion. |
| CONFIRMED WORKLOAD DEFECT — original native rejection receipts and TPS correction reports | Funded benchmark wallets lack canonical finalized authority bindings. Local registry possession and funding are insufficient. | Fail before authoring unless all five finalized bindings match the selected signed context. Any future governed binding change needs its own authority. Never resubmit previous transactions. |

No unexplained or unsafe **application deployment/configuration difference** was
found within the final conformance policy's scope. Clock offset bounds, live I/O
latency, TCP bandwidth/loss and thermal throttling were not freshly measured;
they cannot be certified equivalent or blamed for a stall. Earlier full host
audit and rebuild evidence remain in
`VALIDATOR_FLEET_CONSISTENCY_AUDIT_20261025.md` and
`FIVE_VALIDATOR_REBUILD_EXECUTION_20261026.md`; these historical observations are
not represented as current active-process measurements.

## Consensus storage correction and measurements

Old failure: approximately 7.02–7.21 new files and 220–225KB logical historical
data per finalized block. READY, validation, QCs, finality and exact signatures
were individually retained. Required evidence was not eligible for arbitrary
deletion. The replacement keeps exact evidence BLOBs and digests in indexed
bundled SQLite schema1, with rollback journaling, EXTRA/fullfsync durability,
atomic QC/finality commits, immutable conflict detection and bounded reader cache.
Active sign-once and delivery journals remain independent safety owners. No
quorum, signed domain, phase, proposer or three-QC rule changed.

| Isolated measurement | Legacy representation | Indexed representation |
|---|---:|---:|
| Histories measured | 1,024 heights / 7 records per height | 8,192 heights / 7 records per height |
| Files | 7,169 | 2, stable across sampled heights |
| Logical bytes | 29,360,128 | 267,661,312 |
| Record payload | 28,672B per height | Same payload; about32,673.5B/height including SQLite pages |
| Historical lookup | Per-record legacy files | 35 indexed lookups, zero full-scan steps |
| Reader/cache | Legacy access path | 536,320B reported cache, fixed policy; no mmap |

These synthetic fixtures use 4KiB records and do not establish compression of the
failed real-chain 220–225KB/block payload. Historical bytes intentionally grow.
SQLite page writes were measured (227,105 at H8192); they exclude rollback-journal,
metadata and device writes. There is no controlled old/new physical-media I/O
comparison. Do not infer one from fewer files.

Exact captured public-state rehearsal on the new Linux test executable passed:
50 records, 2,275,946 original bytes; every stage verified 8 exact PQ signatures,
12 QCs, 8 three-QC finality records, 8 READY, 8 validation and 4 timeout records.
The sign-once floor10167 remains, and below-floor reservation is rejected. Input
hashes matched before and after. The stage named `fully_indexed_restart` reopens
stores within the same process; actual process crash/reopen is separately tested
by the archive crash suite and lifecycle hot-journal test. Legacy-only rollback
uses the new compatibility reader; **old-binary downgrade after new writes is
not qualified**. No actual host migration occurred.

## Memory, retention and I/O

The saved 570s old-release fleet interval grew principally in file cache
(about164–166MiB) and slab (about16MiB), with stable anonymous memory and no new
recorded OOM/max events. Val4's ZFS ARC is host-wide and cannot be inferred from
its smaller service charge. This explains the observed accounting categories;
it is not a proof that future pressure is harmless.

The Linux release fixture completed 2,048 heights: 1,536 empty and512 transfers,
16 store reconstructions and16 snapshot rejoin cycles. Root/outcomes matched the
Mac fixture: `81a44944056563239bd4bad7233dedf992a3c10398756ed84b6df0a4fce0ef10`.
Active heap208,988B plateaued H256–2048; peak346,233B; after owner drain1,712B;
World reservations0. Retained files269 from H128 onward, final logical size275,937B,
7,934 retired records. Sampled RSS maximum3,260,416B; cgroup peak16,400,384B;
sampled swap/events/PSI0. The executed runner asserted1GiB/swap0 before child
launch; cap files were not separately serialized.

Elapsed112.062s, cgroup CPU64.262s. Process storage writes143,593,472B; cgroup raw
`io.stat` writes148,525,056B/read405,504B. The scopes include different final
report/cleanup/sampler operations. Raw io.stat populated despite systemd's0B
summary. The 41.64x reduced logical World-codec payload is not a physical-I/O
improvement claim. QEMU/ext4 release measurements versus Mac/ExFAT debug are not
a controlled speed comparison. These are bounded-workload invariants, not live
fleet capacity, arbitrary-state bounds or24h OOM qualification.

## TPS authorization and transaction correctness

The original11 rejected requests were specifically
`identity has no canonical finalized authorization binding`. The32 funded
benchmark wallets remain unauthorized. No registration, refund, resubmission or
protocol bypass occurred. The harness now checks all-five exact finalized
authority bindings before any authoring, pins authenticated chain/network context,
and reports zero-finalized/rejected runs as failures. Reusable signing and ID
helpers require explicit selected chain ID. Cross-language vectors passed9001,
9002,1266 and u64MAX; registry metadata now comes from native governed state.

The final native encrypted regression passed in130.26s: properly authorized
encrypted admission, pending work spanning blocks, finality and exact wallet
effects, restart/retirement behavior. This uses an isolated five-socket fixture;
it is not a live sustainable TPS measurement. The earlier partial stopped-stage
proof remains preserved and unreconciled where receipts are unavailable; never
resubmit it.

## Canonical candidate and Linux acceptance

One master is generated from `node-platform/tools/linux-node` at
`/Volumes/PortableSSD/Synergy-Network/Node-Architecture/Linux/Synergy`.
The builder rejects unexpected existing files rather than sealing them. The
installer/upgrader/start gates use the same conformance policy. No whole runtime
directory is excluded. Config fields derive from native Rust schema; path
containment, file types/modes, storage schemas, exact effective systemd units,
override absence and external dependency boundaries are enforced.

- Release ID: `synergy-linux-3e2ede6cd37aaf44`.
- Package manifest SHA256: `5a9e87db51f431cf7490806ad98e813206a44e2d34fbb08d3b3a25f4f95a91bf`.
- Source content revision: `3e2ede6cd37aaf44e777bbf9987b8c6c542c9e9a2af92d64bdf2fe572b6d76b8`.
- Node SHA256: `a52ae7f2e50445ae2b8141107cb741f071226ffeef833908f9887708a981b366`.
- Keytool SHA256: `e5a0f49cf565bd4920ae185c5b83ce995bc762ec17f7bc4b5858bc2186ef1b68`.
- Genesis tool SHA256: `0c6e911a0fb9ad2ab1752ca0d202f71fdcc69c3608af6f383a560bd8775ddef4`.
- NetBird pin unchanged: `4eb4d7a2f5fe1a224362c68f6c8129502247635711db1970cc85ed921896780d`.
- Transfer tar SHA256: `1c5ab1e1aefee17be4729d4ab5d1a7922297cfc859840f3835e91f08394eb9b8`.

Native artifacts were compiled to APFS from the canonical source, flushed,
ELF-checked and double-hashed; copied master hashes match. Build before/after/
after-package inventories match exactly. Final code-freeze inventory also
matched before report/version-control metadata updates. This is a content-bound
candidate, not a newly signed/publicly published release. Template version-control
receipt and preserved unrelated staged changes are in E; no unrelated work was
committed into this candidate's policy checkpoint.

Linux acceptance used a disposable local Debian12/x86_64 VM, kernel6.1.0-54,
Python3.11.2/systemd252/ext4. No actual validator identity or VPN enrollment was
imported. Fresh install/native identity, registered and unregistered upgrade,
inode/hash preservation, refusal to seize foreign units and complete uninstall
passed. No PoSy/VPN service was started there. Native dependencies resolved;
NetBird is static. The manifest explicitly declares required OS dependencies;
application self-containment does not mean bundling Linux/glibc/systemd.

Test corrections are preserved: no-unit `systemctl list-unit-files` returns1;
the final verifier checked both empty filtered and full inventories. A first
cross-network transfer omitted legacy fixtures; a complete hash-pinned public
fixture set then passed all61 checks. An ExFAT-linked zero-filled test artifact
was rejected; a prior accidental36-test old-binary run is historical only. The
accepted current PoSy executable is SHA256
`2e928bcca3431bae854a7d529162d7ab53b576ec47a8012ad9e660f46fe9d0ab`;
the accepted node rehearsal executable is
`112b03245ec11846832d2d917ce4dcea2194ef4c85876616d295d2debfbfeeee`.
Neither acceptance selected a fallback executable.

## Remaining boundary and approval

All six offline gates have supporting evidence; real-host deployment is
**PENDING EXPLICIT APPROVAL**, as allowed by the objective. The exact universal
software-only procedure is `INTEGRATED_LINUX_UPGRADE_PACKET_20261027.md`.
It preserves state and does not start PoSy or VPN. The existing identities,
genesis and chain are retained; no wipe or mandatory historical import is needed.

Still NOT PROVEN:24h live stability, sustainable TPS, real-host corrected-release
OOM/IO behavior, historical stall causality, post-new-write old-binary downgrade,
every possible community OS/filesystem, new-release live VPN restart/enrollment,
and completed public/signed release publication. No test waives the original
5s readiness,30s finality/max-gap, cadence,1GiB/swap0/OOM0 gates.

Primary evidence index: E/`COMPLETION-EVIDENCE-MANIFEST.json`. Owner reports:
`target/consensus-storage-qualification-20261026/HERCULES_CONSENSUS_STORAGE_REPORT.md`,
`target/einstein-resource-20261026/REPORT.md`,
`TPS-CORRECTIONS-REPORT.md`, `RPC-HANDOFF-REPORT.md` and
`LINUX-INTEGRATION-RESOURCE-ADDENDUM.md`. Read those measured scopes before
promoting a fixture result to any live qualification claim.
