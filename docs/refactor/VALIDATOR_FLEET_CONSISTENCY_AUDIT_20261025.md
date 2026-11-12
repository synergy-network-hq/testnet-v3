# Five-validator consistency audit — 25 October 2026

**Disposition: same running r8 software and normalized protocol configuration; fleet-wide operational equivalence is NOT certified. No corrections have been made.** Qualification, releases, deployment, performance work and new soaks remain stopped pending review. This report precedes any correction or deployment-tooling change, as requested.

Evidence collection: 2026-10-25T19:43:32.937326+00:00 through 2026-10-25T19:49:04.629131+00:00 (UTC). This is an audit snapshot, not continuous health or stability qualification. Production excluded. Only the existing persistent SSH masters were used.

The most consequential new finding is Val5’s native failure at **16:59:13.281285 UTC**, `service posy failed during polling: processing proposal staging is full`. Systemd recorded exit status 1 and automatically restarted it at 16:59:28.318310 UTC under the pre-existing `Restart=on-failure` policy. This audit did not trigger that restart. Its current PID is 1920264 and NRestarts=1; the previous PID 1583633 is no longer the current baseline. No OOM cause is established by this record.

## One five-column comparison

**H** = verified running `/proc/PID/exe` SHA-256 `45c4d52bd3013b93b9fbbf484619ee1436366fb50cae98a96629c44feb1e3c9e`. **C** = normalized node JSON fingerprint `884d4133a4544655378a9ccbd9732fc761df6206dce42ff0ac7af857ea6d74e5`. **S** = normalized active storage-directory schema fingerprint `81a8f07921dd6ddfd9656fd9cc626237935ccc31359739a396075adaa714e965`. E values below are the first 12 characters of full effective-configuration SHA-256 values listed later. E retains diagnostic flags, LANG, NetBird path and inherited task limits; it deliberately does not hide those differences.

| Val2 | Val3 | Val4 | Val5 | Val6 |
|---|---|---|---|---|
| Running executable: **H**, PID 1609905 | Running executable: **H**, PID 1539009 | Running executable: **H**, PID 2163528 | Running executable: **H**, PID 1920264 | Running executable: **H**, PID 1801096 |
| Version 0.1.0; signed sequence 13; config/DB schema 1 | Version 0.1.0; signed sequence 13; config/DB schema 1 | Version 0.1.0; signed sequence 13; config/DB schema 1 | Version 0.1.0; signed sequence 13; config/DB schema 1 | Version 0.1.0; signed sequence 13; config/DB schema 1 |
| Node configuration: **C** | Node configuration: **C** | Node configuration: **C** | Node configuration: **C** | Node configuration: **C** |
| Effective configuration: **146b9f3fb95f** | Effective configuration: **abd0fd3efcc1** | Effective configuration: **34279a8b5675** | Effective configuration: **fdf9d52d16ce** | Effective configuration: **e956dd55b412** |
| Active storage schema: **S** | Active storage schema: **S** | Active storage schema: **S** | Active storage schema: **S** | Active storage schema: **S** |
| Systemd: 15 drop-ins; NetBird base-path parameter | Systemd: 15 drop-ins; extra sync-poll diagnostic | Systemd: 17 drop-ins; extra r7 + r8 diagnostics | Systemd: 15 drop-ins; common overrides | Systemd: 16 drop-ins; extra r8 diagnostics |
| Diagnostic process env: none | Diagnostic env: sync poll | Diagnostic env: sync poll + transport trace/config | Diagnostic process env: none | Diagnostic env: sync poll + transport trace/config |
| Memory limit 1 GiB; swap limit/use 0; CPU quota unlimited; NOFILE 65536 | Memory limit 1 GiB; swap limit/use 0; CPU quota unlimited; NOFILE 65536 | Memory limit 1 GiB; swap limit/use 0; CPU quota unlimited; NOFILE 65536 | Memory limit 1 GiB; swap limit/use 0; CPU quota unlimited; NOFILE 65536 | Memory limit 1 GiB; swap limit/use 0; CPU quota unlimited; NOFILE 65536 |
| TasksMax 26156; NPROC 87188 | TasksMax 26156; NPROC 87188 | TasksMax 128074; NPROC 426915 | TasksMax 12652; NPROC 42175 | TasksMax 26156; NPROC 87188 |
| 8 vCPU EPYC; 23.46 GiB RAM | 8 vCPU EPYC; 23.46 GiB RAM | 24 threads Xeon X5675; 121.53 GiB RAM | 6 vCPU EPYC; 11.68 GiB RAM | 8 vCPU EPYC; 23.46 GiB RAM |
| ext4 /dev/sda1; virtual 400G | ext4 /dev/sda1; virtual 400G | ZFS /var/lib; Samsung 870 EVO 2TB | ext4 /dev/sda1; virtual 200G | ext4 /dev/sda1; virtual 400G |
| ext4 commit=30; discard; durable every_commit | ext4 commit=30; discard; durable every_commit | ZFS sync=standard; lz4; 128 KiB records; durable every_commit | ext4 commit=30; discard; durable every_commit | ext4 commit=30; discard; durable every_commit |
| Uplink eth0/pfifo_fast; wt0 MTU 1280 | Uplink eth0/pfifo_fast; wt0 MTU 1280 | Uplink enp15s0/fq_codel, 1 Gbit/s link; wt0 MTU 1280 | Uplink eth0/pfifo_fast; wt0 MTU 1280 | Uplink eth0/pfifo_fast; wt0 MTU 1280 |
| NetBird 0.77.1, same binary hash; 4/4 direct P2P peers | NetBird 0.77.1, same binary hash; 4/4 direct P2P peers | NetBird 0.77.1, same binary hash; 4/4 direct P2P peers | NetBird 0.77.1, same binary hash; 4/4 direct P2P peers | NetBird 0.77.1, same binary hash; 4/4 direct P2P peers |
| memory.events max=60217; current=971.1 MiB; current-lifetime OOM counters=0 | memory.events max=88013; current=948.4 MiB; current-lifetime OOM counters=0 | memory.events max=0; current=203.0 MiB; current-lifetime OOM counters=0 | memory.events max=3976; current=742.3 MiB; current-lifetime OOM counters=0 | memory.events max=11895; current=945.0 MiB; current-lifetime OOM counters=0 |
| Current NRestarts=0; start Sat 2026-10-24 23:34:30 UTC | Current NRestarts=0; start Sat 2026-10-24 23:34:53 UTC | Current NRestarts=0; start Sun 2026-10-25 13:22:54 UTC | Current NRestarts=1; start Sun 2026-10-25 16:59:28 UTC | Current NRestarts=0; start Sun 2026-10-25 13:22:33 UTC |
| Ubuntu 26.04; kernel 7.0.0-38 | Ubuntu 26.04; kernel 7.0.0-38 | Ubuntu 26.04.1; kernel 7.0.0-38 | Ubuntu 26.04; kernel 7.0.0-38 | Ubuntu 26.04; kernel 7.0.0-38 |
| chrony synced; +83.951 us fast | chrony synced; 25.170 us slow | chrony synced; 412.280 us slow | chrony synced; +89.687 us fast | chrony synced; 293.417 us slow |
| Extra owner assets: wallet custody, signing/load/soak artifacts | Extra inactive sync-trace1/2 candidates | Extra inactive r7 candidate; desktop/AI host services | Smaller host; one fatal staging-full exit/restart | Extra preserved phase-trace qualification artifacts |

## What is verified equal

The exact running executable path on every host is `/usr/local/libexec/synergy/posy-async-canary-20261022-rc1/sync-known-head1-r8-candidate-20261024/synergy-node`. It is 11,841,672 bytes. Running image and on-disk image hashes match; the process remained the same during collection and the final read-only checks. Arguments are exactly `<that executable> start --config /etc/synergy/posy-async-canary-20261022-rc1/node.json`. The version subcommand was run through each live process’s executable image, not an arbitrary PATH binary.

All five native keytools successfully verified the same signed sequence-13 release, artifact digest and Linux architecture. Its release.json SHA-256 is `a2f5c6b5222db1fb2eb680021381d53db88f4fb250283cf5b75fe6dd4f068871`, version 0.1.0, config schema 1, database schema 1, release format 2. The build review binds H to source inventory SHA-256 `7dd0e12c4b8fd5f14b3ee0b493cc05a00439949d99a0fa85938d54b14e4426d7` (49,169 files; unchanged through build). This is content provenance, not an embedded Git revision: runtime source_revision and artifact_digest telemetry are null on all five. The release’s per-domain protocols list is empty; protocol context is instead established by identical governed public artifacts and the executable. See D12.

The mapped dynamic-library paths and installed file hashes match on all five: glibc loader, libc.so.6, libpthread.so.0 and libdl.so.2. ELF NEEDED names are identical. The loaded file hashes were checked, not inferred solely from package labels. This does not hash every in-memory mapped page or certify against arbitrary memory modification. Relevant versions match: glibc 2.43-2ubuntu2.4, systemd 259.5-0ubuntu3.4, iproute2 6.19.0-1ubuntu1.1, libgcc 16-20260322-1ubuntu1, OpenSSL/libssl3t64 3.5.5-1ubuntu3.7, chrony 4.8-2ubuntu1, Python 3.14.3-0ubuntu2, util-linux 2.41.3-3ubuntu2.2, nftables 1.1.6-1. NetBird CLI and actual daemon images all hash to `4eb4d7a2f5fe1a224362c68f6c8129502247635711db1970cc85ed921896780d`, version 0.77.1.

Protocol configuration is byte-equivalent after replacing only own validator identity names/key-path labels and own listener address. All five share chain 1266, isolated network identity, validator role, PoSy validate_and_vote, proposal/round timeouts 2000/5000 ms, max_rounds_behind=64; ETDAG enabled, lookahead=5, admission capacity=4096, max vertex=2 MiB, proposal material wait=1500 ms; peer limit=32, pending handshakes=16, frame cap=4 MiB, fanout=4; dial/idle timeouts=5000/60000 ms; RPC loopback 8545, 1 MiB requests/64 concurrent requests. No differing worker or transport queue parameter is supplied in node JSON or actual process environment; compiled defaults are the same executable, not separate per-host overrides.

Public network-manifest, genesis, authority, authority-root public key, P2P bindings and transport registry hashes are identical. They bind `posy/3.0`, `POSY-ETDAG-v3.0`, protected version 2, `single-cluster-processing-groups-v1`, ML-DSA-65 signing and ML-KEM-1024 ingress. They are not validator identity keys copied between machines. The thirteen runtime service identities match: identity, storage, network, admin-api, sync, etdag, execution, health, posy, rpc, telemetry, vpn, websocket. All reported ready in this single sample; that is not a finality/stability certification.

## Filesystem and storage compatibility

All five use the same installation base `/usr/local/libexec/synergy/posy-async-canary-20261022-rc1`, configuration base `/etc/synergy/posy-async-canary-20261022-rc1`, runtime base `/var/lib/synergy/posy-async-canary-20261022-rc1` and admin socket `/run/synergy-posy-async-canary-20261022-rc1/admin.sock`. No symlinks were found inside the three enumerated application trees. Referenced paths exist. Directory traversal caps were not reached. File data sizes, timestamps, independent object IDs and live transaction staging children were not treated as architecture differences.

The active data-directory schema matches for blocks/execution-candidates, processing-proposal-inputs-v1 and its certified/certified-groups/certified-ids/inputs/validations stores; consensus/posy/finality, verified-qcs/qc, verified-timeouts, validator-management; etdag/admission-receipts, availability-shards, protected-pipeline/processing-v1 and reveal-shares; metadata/admin-audit and sync; peers; state/execution with finalized-history/finalized-world/processing-pinned-history; state/snapshots with chunk and manifest-index; state/sxcp-relay-outbox. Atomic transaction staging directories are common; their transient children may legitimately differ. No separate incompatible execution database or ETDAG storage engine was found. The shared implementation is synergy-storage AtomicStore, including durable file and directory sync per commit; storage-service source rejects incompatible WAL policy.

A final targeted read at 19:56:26 UTC verified the actual `data/metadata/schema-version` marker on all five: `synergy-node-storage:1`, 22 bytes, root:root 0600, SHA-256 `c414ee7216a14cd0baf9b7214f57edabac188350df77f65a77a649a8b0a0a8e1`. This directly confirms the live store format marker, separately from the release declaration and directory comparison. Sources: `valN-schema-marker.json`; no journal or database record contents were exported.

Storage settings match: world memory budget 1 GiB, every_commit durability, max_open_files=128, minimum free space 2 GiB, finalized execution-history retirement=64 heights. This is not a blanket prune policy for every consensus signature/QC/finality record: those stores contain much longer independent history on every host. Recovery/snapshot namespace conventions match. No differing archive or recovery-retention override was found; no snapshot restore or database-integrity replay was performed against a live store.

Every observed data directory is root:root 0700. Config/install files and all private-key path metadata were enumerated: private keys root:root 0600 with required ML-DSA/ML-KEM lengths; public identity/config files root:root 0644; runtime admin socket root:root 0600. Sampled signing reservations are root:root 0600. No group/world-writable file was found in the samples; complete config/install file checks also found none. **Permissions of every file among roughly 1.8–1.9 million live-state entries per validator were not certified.** State contents and signing-journal bytes were not copied or compared; this is structural compatibility, not a database consistency/integrity proof.

## Difference register — exact source, meaning and smallest safe action

### D01 — Val5 alone failed closed and restarted.

**UNSAFE operational condition; underlying occupancy cause UNEXPLAINED.** Source: `val5-final-checks.json#/fatal_exit_tail`, application journal 16:59:13.281285 UTC; `val5-detail.json#/restart_journal`; `val5.json#/unit/NRestarts`.

The staging-full failure is proven; why that bounded staging store filled is not. All five use the same capacity/configuration, so this is not evidence that Val5 was configured with a smaller queue. The initial memory peak was 1G, but exit-code 1 is not OOM proof. Current cgroup OOM counters cannot reconstruct a prior process lifetime.

Smallest safe action: Retain failure and prior process evidence; hold qualification. Before proposing any repair, identify the exact staged-parent/input lifecycle that filled it. Do not clear staging, enlarge caps, disable fail-closed checks or manually restart. No software correction is justified yet.

### D02 — Val3 keeps SYNERGY_SYNC_POLL_DIAGNOSTIC=1; Val4/6 also keep timing config and transport-only flags.

**JUSTIFIED historical diagnostic exceptions; baseline standardization still incomplete.** Source: Actual `/proc/PID/environ`; Val3 `98-sync-trace1-diagnostic.conf`; Val4/6 `zzz-r8-handoff-diagnostic1-20261025T000754Z.conf`.

The flags are real process differences, not nominal files. Val4/6 `UnsetEnvironment=` clears the earlier exclusion list and enables their approved diagnostic. Transport windows have native end records; owner polling is bounded by 1800 s/7200 rows. Persistent flags/drop-ins can arm fresh diagnostics on a future restart even after this process’s window ended.

Smallest safe action: After report review, prepare removal of only the temporary diagnostic overrides/flags in a canonical offline unit fixture. Any actual process-env cleanup requires a separately authorized rolling restart. Do not rearm or restart now.

### D03 — Many historical ExecStart overrides remain, with different extra diagnostic overrides on Val3/4/6.

**UNEXPLAINED configuration-maintenance debt; current precedence resolved.** Source: `comparison.json#/unit_inventory` and each `valN.json#/unit_files`; see exact inventory below.

Latest zz-r8 overrides all earlier executable paths. Old 91/95 timing Environment values remain visible in manager metadata but are removed by effective UnsetEnvironment on Val2/3/5; they are not active in those processes. Val3 lacks 98-sync-prune1.conf but zz-r8 still selects the correct binary. Val4 retains r7 override, also superseded. No active alternate executable was found.

Smallest safe action: Prepare one canonical effective unit plus explicit temporary diagnostic parameter; compare resolved policy offline against this report. Preserve historical artifacts. No deletion, daemon-reload or restart before approval.

### D04 — Val2 names /usr/local/bin/netbird; others /opt/synergy/netbird-client/bin/netbird.

**JUSTIFIED host-specific path.** Source: Base service Environment line, process environment; `valN-detail.json#/netbird_configured` and `/netbird_processes`.

Both configured executable paths and every running daemon resolve to identical 0.77.1 bytes. No VPN software-version drift is demonstrated.

Smallest safe action: Represent NetBird binary path as a checked host parameter. No live relocation or reinstall is needed.

### D05 — Val4 uses physical Xeon/ZFS/Samsung SSD; other hosts are EPYC VMs on ext4/QEMU disks; Val5 is smaller.

**JUSTIFIED environmental difference; performance/cgroup equivalence UNEXPLAINED.** Source: `valN.json#/host/lscpu`, `/host/meminfo`, `/host/mount`, `/host/lsblk`; `val4-detail.json#/storage`.

Equivalent application schemas do not imply equivalent filesystem latency or memory accounting. Val4 ZFS has sync=standard (not disabled), lz4, 128 KiB recordsize, atime on, logbias latency, dedup off; pool ONLINE and no known errors. ext4 uses relatime,discard,commit=30; every_commit still requests fsync. ZFS cache is not directly comparable to ext4 page-cache/slab charges under the same service cgroup. VM backing hardware/durability is not visible.

Smallest safe action: Document and validate an explicit supported host/storage profile offline. Do not convert a filesystem, move databases, disable durability or raise the 1 GiB cap. Filesystem difference is a hypothesis input, not a confirmed stall cause.

### D06 — TasksMax/NPROC differ: 26156/87188 on Val2/3/6; 128074/426915 on Val4; 12652/42175 on Val5.

**JUSTIFIED inherited host limits; needs explicit canonical policy.** Source: `valN.json#/unit` and `/host/process_limits`; cgroup cpuset/cpu.max.

MemoryMax, swap, open-file limit and CPU quota match. TasksMax/NPROC derive from differing host defaults; no observed task-limit exhaustion or CPU-quota throttling. Unrestricted CPU does not reserve the same number or speed of cores.

Smallest safe action: Make task/process policy explicit in the future template after selecting supported values from actual usage. Do not change host/systemd limits during this audit.

### D07 — Cgroup memory.current and max-event counts differ sharply, especially ext4 vs ZFS.

**EXPECTED independent runtime state; pressure significance UNEXPLAINED.** Source: `valN.json#/cgroup/memory.current`, `/memory.events`, `/memory.stat`, `/memory.pressure`.

Snapshot totals are in the comparison. Ext4 file-cache and reclaimable slab dominate much of cgroup usage, whereas Val4 file charge is very small; process RSS is much smaller than cgroup memory. Counters have unequal lifetimes, especially after Val5 restart. They cannot be compared as equal-duration rates or as proof of historical stall causation.

Smallest safe action: Keep original caps and distinguish anon/file/slab/cache, per-lifetime deltas and filesystem profile in future qualified measurements. No cache purge, cap change or synthetic load.

### D08 — Val4 uses enp15s0 with fq_codel; VM uplinks eth0 use pfifo_fast; all wt0 use noqueue/MTU 1280.

**JUSTIFIED network topology; tuning differences UNEXPLAINED.** Source: `valN-detail.json#/tc`, `/interfaces`; `valN.json#/network/links`, `/routes`, `/rules`, `/tcp`.

No tc class/filter bandwidth limiter was found on inspected interfaces. Physical Val4 link reports 1 Gbit/s; VM speed is unknown (-1), not measured bandwidth. All peers were direct P2P and connected; saved NetBird latency samples vary from ~3 ms to ~136 ms, with Val5 consistently ~111–133 ms in its own snapshot. TCP RTT/queues/retransmission totals differ by connection/lifetime.

Smallest safe action: Parameterize interface/profile and document existing qdisc policy; no immediate retuning. Prove an event-local timing relationship before attributing finality stalls to topology, qdisc or retransmissions.

### D09 — Val3/5/6 retain rules referring to nonexistent sy-vpn; Val4 has a substantially different host firewall context.

**UNEXPLAINED obsolete firewall rules; no demonstrated 5622 block.** Source: `valN.json#/network/firewall_nft`, `/firewall_iptables`; `comparison.json#/firewall_rule_lines_differing_from_all_five_common_lines`.

Current interface is wt0, not sy-vpn. Dormant sy-vpn rules cannot match that interface. All five have wt0 allowance and active authenticated TCP5622 peers. Broad wt0 allowances and other host services require a separately reviewed intended firewall baseline; this audit does not certify least privilege or blame these rules for stalls.

Smallest safe action: Prepare an exact intended interface/peer allowlist diff from existing network policy; validate offline. Remove only obsolete rules after approval and preserve SSH/VPN access. No firewall action now.

### D10 — Val4 has desktop, ZFS, AI/tunnel and additional management services; VMs have server/virtualization services.

**JUSTIFIED different host role; contention equivalence UNEXPLAINED.** Source: `comparison.json#/host_service_presence_differences`; `valN.json#/host/services`, `/enabled`, `/contention`.

Enabled differs from actually running. Val4 services include different desktop/network/power management and horizon-qwen related units. Existing load/PSI snapshots and one-second iostat windows are not an interference proof. VMs lack exposed CPU frequency/thermal counters; Val4 uses schedutil and sampled thermal-throttle counters are zero.

Smallest safe action: Define the supported co-resident-service profile; verify necessity of extra workloads with the host owner before any stop/disable action. No service changes during audit.

### D11 — Identity/key-path names, own addresses, PID/start time, locale (Val4 en_US.UTF-8; others C.UTF-8), NTP source/offset and host route/default gateway differ.

**EXPECTED identity/localization/clock differences.** Source: Node JSON identity pointers, `/proc/PID/environ`, `/host/os_release`, `/clock`, `/network/addresses` and `/routes`.

The relevant application settings remain equal; UTF-8 locales share protocol byte formats in the same binary. chrony reports synchronized/Normal on all five. Current sub-millisecond estimated system offsets have tens-of-milliseconds upstream error bounds and do not reconstruct historical cross-host clock precision. Val4 OS banner is 26.04.1 while others 26.04; relevant checked packages/kernel/libs match.

Smallest safe action: Keep required identity/network parameters independent; no key/state synchronization. Pin locale/host OS profile in the future template if desired. Do not step clocks or claim historical offset accuracy.

### D12 — All runtime release telemetry has source_revision=null and artifact_digest=null; signed release protocols=[]. Root release.json is historical sequence 1.

**UNEXPLAINED common provenance/telemetry gap, not fleet drift.** Source: `valN.json#/rpc/synergy_chainTelemetry/result/release`; `/public_files`; signed release at `/etc/synergy/posy-async-canary-20261022-rc1/releases/sync-known-head1-r8-candidate-20261024/release.json`.

Exact running-byte equality and native sequence13 verification succeed independently. A root-level historical release file must not be mistaken for the selected running release; no immutable Git revision is embedded to quote. Build source inventory is recorded separately.

Smallest safe action: Future preflight must resolve selected ExecStart plus /proc image and the selected signed release, not root release.json or version string alone. Preserve source-inventory provenance. Filling telemetry/build provenance is future reviewed work, not an emergency live patch.

### D13 — Val2 alone has 32-wallet/receiver custody, signing and owner/load artifacts; inactive candidate and diagnostic directories vary.

**EXPECTED owner/test artifacts and independent state.** Source: `comparison.json#/directory_presence_differences` and `/unit_inventory`; each raw `/trees`.

These do not change the current active data-root schema. No extra wallet custody is required on other validators. Independent signature/QC/finality counts, pending transactions, snapshots and temporary transaction directories are expected to differ. Stale files can confuse tooling that discovers candidates by presence.

Smallest safe action: Keep custody and evidence in place; never synchronize secrets, journals, live DBs or old workloads. Future verifier must select active paths rather than demand identical archive contents. No cleanup now.

### D14 — Val4/6 diagnostic resource/passive units are now inactive/success and native resource/transport end records exist.

**JUSTIFIED bounded diagnostics; persistent override caveat in D02.** Source: `val4-final-checks.json#/observer_units`, `/diagnostic_end_records`; corresponding Val6 record.

The older continuation describing live observers is stale. These are ended observations, not an active soak. Transport sparse caps/drops and prior Val6 packet loss prevent full traffic coverage. They do not establish cause or stability.

Smallest safe action: Preserve ended evidence and leave units stopped. Do not extend, rearm, recapture or automatically restart to remove flags.

### D15 — All hosts have ~1.31–1.38 million entries directly under consensus/posy and ~264.6k each in finality and verified-qcs/qc.

**EXPECTED different durable histories; common retention scope requires care.** Source: Each `valN.json#/trees/runtime/directories` entry/count.

The common 64-height execution-history setting does not promise bounded consensus signing/QC files. Differing numbers reflect independent signatures and collection times; all share this much larger historical footprint. It plausibly changes metadata/cache cost, without proving a particular stall or authorizing deletion.

Smallest safe action: Record retained-store scope explicitly in canonical policy and inspect retention semantics read-only before any separate repair proposal. Never reset/delete safety journals or clone another validator’s state.

### D16 — Large live-state permissions are sampled; provider storage/bandwidth and historic clocks are not fully observable.

**UNEXPLAINED audit coverage limits; no blanket safety certification.** Source: Raw `/coverage`, detail `/permission_inventory`, and collection-limit notes below.

No observed active schema/config mismatch is a narrower finding than every-file integrity, equivalent physical durability or stability. Current cgroup OOM=0 on a restarted process is not all-history OOM=0.

Smallest safe action: Keep report scope explicit. Resolve only decision-relevant unknowns with bounded reads or offline fixtures after report review, not a new load/capture campaign.

## Exact override and extra-component inventory

All paths below are under `/etc/systemd/system/synergy-posy-async-canary-20261022-rc1.service.d/`. Full file text, mode and SHA-256 are in raw `/unit_files`; full cross-host hashes are in `comparison.json#/unit_inventory`.
- `synergy-posy-async-canary-20261022-rc1.service`: present Val2–Val6; base content differs only in checked NetBird path.
- `20-peer-finality1.conf`: present Val2–Val6; same SHA-256 on all five.
- `30-qc-tail1.conf`: present Val2–Val6; same SHA-256 on all five.
- `40-order-finality2.conf`: present Val2–Val6; same SHA-256 on all five.
- `50-echo-retry1.conf`: present Val2–Val6; same SHA-256 on all five.
- `60-reveal-replay1.conf`: present Val2–Val6; same SHA-256 on all five.
- `70-vertex-retry1.conf`: present Val2–Val6; same SHA-256 on all five.
- `80-input-retry1.conf`: present Val2–Val6; same SHA-256 on all five.
- `90-phase-trace1.conf`: present Val2–Val6; same SHA-256 on all five.
- `91-phase-trace1-diagnostics.conf`: present Val2–Val6; same SHA-256 on all five.
- `94-live-variant1.conf`: present Val2–Val6; same SHA-256 on all five.
- `95-live-variant1-diagnostics.conf`: present Val2–Val6; same SHA-256 on all five.
- `96-live-variant1-diagnostics-disabled.conf`: present Val2–Val6; same SHA-256 on all five.
- `97-reveal-fence1.conf`: present Val2–Val6; same SHA-256 on all five.
- `98-sync-prune1.conf`: present Val2, Val4, Val5, Val6.
- `98-sync-trace1-diagnostic.conf`: present Val3.
- `99-transport-sparse1-r7-diagnostic.conf`: present Val4.
- `zz-sync-known-head1-r8-20261024.conf`: present Val2–Val6; same SHA-256 on all five.
- `zzz-r8-handoff-diagnostic1-20261025T000754Z.conf`: present Val4, Val6.

All five service units are loaded/active but **disabled** for boot, consistent across the isolated fleet; no daemon reload is pending. Existing Restart=on-failure/15s is common, not introduced by the audit. The standardization proposal must preserve an explicit isolated start/boot policy; enabling boot or disabling recovery would be a separate reviewed change.

The full directory-presence and enabled/running-service difference lists are in the machine-readable comparison, with exact per-validator membership. Non-state top-level runtime differences:
- `distributed-phase-trace1-qualification-20261023`: Val6.
- `measurements`: Val2.
- `paced1-candidate-signing-20261022`: Val2.
- `profile-peer-finality1-20261022`: Val4.
- `signing-20261022-rc1`: Val2.

Extra installation candidate directories beyond the common set:
- `sync-trace1-diagnostic-20261024`: Val3.
- `sync-trace2-diagnostic-20261024`: Val3.
- `transport-sparse1-r7-diagnostic-20261024`: Val4.

## Canonical-template proposal — documentation only, not implemented

Reuse `node-platform/tools/validator/prepare-stability-launch.py` as the canonical JSON generator and existing signed stage/qualification tooling. The reviewed template should have a common node schema, a single resolved service definition, explicit binary/release pins, explicit memory/swap/CPU/task/open-file policy and host/storage/VPN profiles. Required independent parameters are validator number/public identity/secret-path labels, own listener/address, host interface and NetBird executable path. Temporary diagnostic flags must be an explicit exception with bounded run identity and restart behavior, not an accumulated permanent override chain.

The future pre-qualification read-only gate should fail on the actual /proc image mismatch, selected signed-release mismatch, normalized config/public-authority mismatch, unexpected Environment/UnsetEnvironment/drop-in precedence, storage-schema mismatch, unsafe file permissions, unexpected restarts or resource-policy divergence. Test identity normalization, masked stale env, overridden ExecStart, unexpected extra drop-in, missing path and process-image-versus-disk divergence with offline fixtures. Do not generate configuration from another validator’s private state. This report does not create or deploy that gate: the user requested the full report before changes.

## Evidence, fingerprints and limitations

Node-config, effective-config and storage-schema SHA-256 values are computed over UTF-8 JSON with sorted keys and compact separators; all normalized documents are preserved in the machine-readable comparison. All five C and S fingerprints match. E differs because actual diagnostic environment and documented host defaults differ:
- Val2: E `146b9f3fb95fe2d450a7097b5d287748b1cac309fff68761122210f047738337`; raw node.json `dedf099023bffe521f9baf13320dc7da6966d538010df140b0b26434ce3a6c0b`.
- Val3: E `abd0fd3efcc10392ea544588c82fc2299b643ed5ac7e24a38e9e215e61e1f54c`; raw node.json `767c92fe7039db85edb280264d43dc8960887ecacfe6563887c6d5b8e911ad2a`.
- Val4: E `34279a8b56757f44905de5c88b8d63131ee06eb6a17824c1b4497226babc157b`; raw node.json `dbbadb11b5a47ec16f39a89ff3fb327cd18fdf55002653c24f0f7b5e1b2b6ffc`.
- Val5: E `fdf9d52d16ce0a6b4825b0d08adcd824370fc244f781dcea216e13fa854bdee3`; raw node.json `7adf79fb3c3c609ab80eaff9cfd97952974b5dae2a5b3017d72560a978d0efcc`.
- Val6: E `e956dd55b4128c7d84a6b1f5bc8f047e426a87a197455431f308165eda06407e`; raw node.json `dc2f470aa107f4184845bd606ad5763173536adb743a5b8e0bf4dbec0b6a4648`.

No validator, network, key, journal, database or service configuration was changed; no validator was stopped/restarted by the audit; no load, capture or performance experiment was launched. A first attempt to enumerate every live-state file’s permissions exceeded the 120-second read-only collector bound. Its exact audit Python processes were then terminated by matching the complete command-code SHA-256, and bounded metadata sampling replaced it. Cleanup receipts identify only those audit PIDs. This audit activity itself may affect metadata-cache/I/O snapshots; do not interpret iostat as clean performance benchmarking. Relevant I/O evidence is passive one-second whole-device observation, not application fsync latency or historical causation.

Raw application-state contents were not copied; only the public storage-schema marker was read. Full configuration/install permissions and referenced secret-path metadata were checked; large live-state file permissions were sampled up to 128 entries per directory. This report cannot certify every inode, private-key correctness by reading secrets, database replay, provider physical write durability, thermal behavior hidden by a hypervisor, available end-to-end bandwidth or historical clock offsets. No new agents were spawned. Required global AOS bootstrap files referenced by workspace AGENTS were absent on this Mac; the available root/scoped workspace rules and explicit user instructions were followed.

Read-only evidence indexes: [index.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/fleet-consistency-20261025T194328Z/index.json), [bounded-detail-index.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/fleet-consistency-20261025T194328Z/bounded-detail-index.json), [final-checks-index.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/fleet-consistency-20261025T194328Z/final-checks-index.json), [schema-marker-index.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/fleet-consistency-20261025T194328Z/schema-marker-index.json). Machine-readable full comparison: [comparison.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/fleet-consistency-20261025T194328Z/comparison.json). Build provenance: [sync-known-head1-r8-linux-candidate-review-20261024.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/posy-async-conformance-audit-20261021/sync-known-head1-r8-linux-candidate-review-20261024.json).

**Decision:** retain the hold. Do not certify the fleet as fully equivalent or resume qualification/performance work. Review the diagnostic-policy cleanup and canonical-template proposal, investigate the verified Val5 staging-full failure without modifying live state, and resolve the documented environmental equivalence questions before a new operational certification. No deployment/restart approval is requested by this report.
