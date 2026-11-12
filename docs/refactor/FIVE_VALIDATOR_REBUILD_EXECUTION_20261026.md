# Five-validator rebuild execution report — 26 October 2026

All five fresh validators are running, communicating through the validator VPN and finalizing the same new Synergy Testnet. Both genuine encrypted transfers finalized with correct wallet effects on all five. The sequential Val3→Val4→Val5→Val6 clean replacements and necessary common package correction are complete. Val2 was upgraded without another wipe. This is initial functional acceptance, not a 24-hour soak or proof that historical stalls/OOM are resolved.

## Five-validator comparison

Resource snapshot: 2026-10-26T20:48:29.927793+00:00. Native same-height finality proof and later advancing telemetry are separate observations. All five use 1GiB cgroup memory limit, zero allowed swap, TasksMax512, NOFILE65536, unlimited CPU quota and the same Restart=on-failure policy. The thirteen native services, including PoSy, ETDAG, Execution and Sync, report running/healthy/ready.

| Val2 | Val3 | Val4 | Val5 | Val6 |
|---|---|---|---|---|
| **Fresh validator address:** synv11xr6tjlf0gnt7e29lwnzfg823rlujtrwx8nu | **Fresh validator address:** synv11t9ef6mthv5vc8tmfl8rvxpx5x3aw3azj0lu | **Fresh validator address:** synv118admj9mnf9f93vdfjs704cl92ep5rvw90tq | **Fresh validator address:** synv119cgkl8wfzpqxm6awetzle83cvczms8mt0rq | **Fresh validator address:** synv11e0ctu60mvacgjejgasjherek60482uqp82q |
| **Installation root:** /opt/Synergy | **Installation root:** /opt/Synergy | **Installation root:** /opt/Synergy | **Installation root:** /opt/Synergy | **Installation root:** /opt/Synergy |
| **Executable / genesis / normalized configuration:** H / G / C | **Executable / genesis / normalized configuration:** H / G / C | **Executable / genesis / normalized configuration:** H / G / C | **Executable / genesis / normalized configuration:** H / G / C | **Executable / genesis / normalized configuration:** H / G / C |
| **Filesystem and storage implementation:** Storage schema 1; same native layout | **Filesystem and storage implementation:** Storage schema 1; same native layout | **Filesystem and storage implementation:** Storage schema 1; same native layout | **Filesystem and storage implementation:** Storage schema 1; same native layout | **Filesystem and storage implementation:** Storage schema 1; same native layout |
| **Active systemd drop-ins:** 0 node / 0 VPN | **Active systemd drop-ins:** 0 node / 0 VPN | **Active systemd drop-ins:** 0 node / 0 VPN | **Active systemd drop-ins:** 0 node / 0 VPN | **Active systemd drop-ins:** 0 node / 0 VPN |
| **PoSy process:** Running PID 2050439; restarts 0 | **PoSy process:** Running PID 1957958; restarts 0 | **PoSy process:** Running PID 2387588; restarts 0 | **PoSy process:** Running PID 2021073; restarts 0 | **PoSy process:** Running PID 1971274; restarts 0 |
| **Readiness from actual exec:** 0.297210s / 5s | **Readiness from actual exec:** 0.349097s / 5s | **Readiness from actual exec:** 0.346103s / 5s | **Readiness from actual exec:** 0.222811s / 5s | **Readiness from actual exec:** 0.208225s / 5s |
| **VPN address and verified reachability:** 10.69.106.160; connected; 4/4 reachable | **VPN address and verified reachability:** 10.69.11.219; connected; 4/4 reachable | **VPN address and verified reachability:** 10.69.56.215; connected; 4/4 reachable | **VPN address and verified reachability:** 10.69.184.171; connected; 4/4 reachable | **VPN address and verified reachability:** 10.69.140.27; connected; 4/4 reachable |
| **Matching finalized commitment:** H1045 commitment F; later H1079 | **Matching finalized commitment:** H1045 commitment F; later H1079 | **Matching finalized commitment:** H1045 commitment F; later H1079 | **Matching finalized commitment:** H1045 commitment F; later H1079 | **Matching finalized commitment:** H1045 commitment F; later H1079 |
| **RSS / cgroup memory:** 72.9 / 337.0 MiB | **RSS / cgroup memory:** 67.4 / 337.0 MiB | **RSS / cgroup memory:** 56.7 / 64.5 MiB | **RSS / cgroup memory:** 63.0 / 328.7 MiB | **RSS / cgroup memory:** 60.3 / 329.2 MiB |
| **Managed entries / PoSy files:** 8,303 / 7,580 | **Managed entries / PoSy files:** 8,426 / 7,730 | **Managed entries / PoSy files:** 8,480 / 7,790 | **Managed entries / PoSy files:** 8,315 / 7,619 | **Managed entries / PoSy files:** 8,421 / 7,726 |
| **Logical / allocated installation size:** 289.1 / 303.2 MiB | **Logical / allocated installation size:** 293.0 / 307.3 MiB | **Logical / allocated installation size:** 294.5 / 211.5 MiB | **Logical / allocated installation size:** 289.9 / 304.0 MiB | **Logical / allocated installation size:** 292.4 / 306.6 MiB |
| **Storage mount / VPN MTU:** ext4 on /dev/sda1; MTU1280 | **Storage mount / VPN MTU:** ext4 on /dev/sda1; MTU1280 | **Storage mount / VPN MTU:** zfs on rpool/ROOT/ubuntu_tl6adi; MTU1280 | **Storage mount / VPN MTU:** ext4 on /dev/sda1; MTU1280 | **Storage mount / VPN MTU:** ext4 on /dev/sda1; MTU1280 |
| **Host CPU/RAM:** 8 threads; 23.46 GiB RAM | **Host CPU/RAM:** 8 threads; 23.46 GiB RAM | **Host CPU/RAM:** 24 threads; 121.53 GiB RAM | **Host CPU/RAM:** 6 threads; 11.68 GiB RAM | **Host CPU/RAM:** 8 threads; 23.46 GiB RAM |
| **Cleanup:** Old attributed paths absent; stage empty | **Cleanup:** Old attributed paths absent; stage empty | **Cleanup:** Old attributed paths absent; stage empty | **Cleanup:** Old attributed paths absent; stage empty | **Cleanup:** Old attributed paths absent; stage empty |

**H**, verified from every running `/proc/PID/exe`: `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`. Actual path and arguments: `/opt/Synergy/bin/synergy-node start --config /opt/Synergy/config/node.json`. Version0.1.0, management/config schemas1. Loaded shared-library paths/file hashes are identical on all five.

**G**, identical authenticated Genesis file SHA-256: `a34547918d494bb35b0eca9fc26bacb5ccbaf6bf4f49d58e0154391224bf6a20`. **C**, normalized actual node configuration SHA-256: `b724e22b16cf6f6c7e7b5288dd29b356cd66bd3690baa3c7e54c0ecd12caa8bb`. Only node name, own VPN address and own role-key identifiers are normalized. All other consensus, ETDAG, storage, queue and transport parameters remain in the comparison.

Sealed master package SHA-256: `fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8`. One canonical master: `/Volumes/PortableSSD/Synergy-Network/Node-Architecture/Linux/Synergy`. Installed package receipts and every sealed application-file hash match. Canonical node-unit SHA-256 `719d835cb2529efcdc8e21b6dc8336b3ba121fbd197cc3ea500964c21f91b038`; VPN-unit SHA-256 `3895fcde88b36915d50e4f6740b8f26187e221e5e83ca1e07c73b12c3cbeaeba`. No EnvironmentFiles or drop-ins, and no diagnostic process environment flags. The shared `SYNERGY_NETBIRD_BINARY` selects `/opt/Synergy/tools/netbird-client` on every host.

This is the content-bound working-tree build, not a newly published or signed release sequence. It is not the historical signed r8/sequence13 artifact. The before/after build source inventories match; `transport-corrected-build` preserves exact provenance and build log. Reusable runtime selects chain identity from authenticated genesis/configuration. The prior cross-network initialization/rejection results are documented in `CONFIGURED_NETWORK_CHAIN_ID_AUDIT_20261026.md`; they were not needlessly rerun for the isolated route-policy correction.

## Network, finality and real transactions

Fresh network: `synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99`, numeric chain1266, protocol`posy/3.0`. Five locally generated unique validator identities and possession proofs passed; private keys stayed on their hosts. All five have identical signed genesis, authority, authority trust, P2P bindings, network manifest and generation2 transport registry. The fresh authenticated network identity provides replay isolation when reusing1266; the number was not arbitrarily changed.

Twenty directed VPN ping pairs and twenty directed TCP5622 pairs passed before PoSy started; bounded temporary listeners exited. Fresh autonomous enrollment and server-side peer attribution passed for Val3–Val6, one-off setup keys were deleted, and native VPN restart preserved each new peer identity. Existing fresh Val2 enrollment was retained. Actual node startup verified signed routes and peer-authentication inputs. Native QCs/finality and encrypted execution demonstrate functioning authenticated inter-validator communication. The management API does not expose an exact live authenticated-session count, so no invented “four current sessions” metric is used.

**F**, same native finalized commitment at H1045: block `fcc5d7ed598c05dc06cbdfa162de47bf1630dab6c80c04a39dabe9334b31ff9c`; state `8446cfaa7382cb9e9881171df729443ab1ab9919df1e136bd7fa2ef5e1d743b7`; protected root `7600eaedc961a67169f9b78780ec34cca9de6c3c896ee5bfe8a9df2b1a0c7285`; finality certificate `de6332555e9890723005db08420e7e3cf2e0932110f0e000fc71781485a95d59`. Every validator's durable native verified-QC store contains the three contiguous QCs with matching parent references and finality certificate. This audit checked structural ancestry and native verified records; it did not independently rerun PQ signature verification offline. Subsequent telemetry advanced all five to H1079.

| Native encrypted transfer | Finalized height | Amount (nwei) | Actual fee (nwei) | All-five wallet effects | First observed finality |
|---|---:|---:|---:|---|---:|
| `ae4e9fe5c60867ef3d9fb183795b706d73ba186bebdeb9a1d737a4e037bebd7b` | 33 | 1000000000 | 840000 | Exact debit/credit and sender nonce+1 | 26.525s |
| `15bd1d6b1965a5bc9fb3f751c7f95673ae0744c80dfab7360279a15de36fb87a` | 537 | 2000000000 | 840000 | Exact debit/credit and sender nonce+1 | 10.541s |

Both were submitted once through native signed/encrypted admission, then accepted/applied and reconciled on all five at the same height. Neither admission nor queued status was counted as finality. The second transfer reverses direction. No old transaction or old wallet cohort was resubmitted. No finality, quorum, three-QC, readiness5s or transaction30s gate was relaxed.

## Focused resource and retention checks

Five samples span H6→H1079 (about15minutes), including H121/122, H251 and H675. Every sampled process retained its approved PID, NRestarts0 and original caps. All sampled memory.events high/max/oom/oom_kill counters and cgroup swap remained zero. Final RSS is56.7–72.9MiB; cgroup usage64.5–337.0MiB includes differently charged filesystem cache. This is sampled evidence, not continuous peak surveillance.

| Metric after H251→H1079 | Val2 | Val3 | Val4 | Val5 | Val6 |
|---|---:|---:|---:|---:|---:|
| Distinct surviving new/changed files per block (lower bound) | 7.61 | 7.82 | 7.85 | 7.66 | 7.78 |
| Net managed entries per block | 6.96 | 7.16 | 7.20 | 7.02 | 7.13 |
| Logical disk growth (KiB/s) | 254.93 | 262.47 | 263.65 | 257.23 | 260.93 |
| Allocated disk growth (KiB/s) | 268.35 | 276.30 | 198.97 | 270.84 | 274.73 |
| Process physical writes (KiB/s) | 1581.43 | 1596.64 | 1369.87 | 1551.85 | 1578.77 |
| Process logical reads (KiB/s) | 3422.61 | 3159.93 | 2802.35 | 3124.27 | 2802.30 |
| Process physical reads (KiB/s) | 0.00 | 0.02 | 0.00 | 0.00 | 0.00 |
| Write syscalls per finalized block | 69.53 | 70.38 | 73.05 | 70.44 | 71.70 |

The file-write metric compares file size/mtime snapshots; files created and removed between samples are absent, so it is a lower bound rather than an exact write-event count. Write syscalls are reported separately and are not mislabeled as files. Live filesystem scans are not atomic; one vanished path is recorded in Val2’s final sample. Process I/O is Linux accounting, not a storage-device benchmark.

Execution working history actually prunes: finalized-history65 records at H251, H675 and H1079; candidate indices66–67; finalized-world124→100→120 records across those heights. Final world heights960–1079 demonstrate old ancestry retirement across many64-block cycles. The 64-block checkpoint/delta anchor can require up to127 finalized-world records, plus speculative candidate worlds. Source: `crates/synergy-state/src/world_history.rs:14,487`. This is retained ancestry, not a full world snapshot per historical height.

Snapshot namespace grew from1 file initially to10–11 byH1079; this is modest independent Sync/recovery state, not one snapshot per block. Its long-term bound is not established. Durable signature/QC/finality records continue to grow with height: total managed entries and about255–264KiB/s logical growth remain measurable. The initial sample does not prove total disk growth bounded or write amplification eliminated. No safety records were indiscriminately pruned. Final telemetry’s most recent128 cadence samples show maximum gaps5.56–5.72s, with median~0.79–0.81s; these rolling windows do not certify the entire run or explain historical33s/43s stalls.

## Exact correction and remaining differences

The first coordinated launch failed closed on all five with `InvalidRoute(WrongScope)`: the legacy policy accepted only10.69.10.* although authenticated NetBird had allocated addresses throughout10.69/16. All five were stopped by the guard, preserving their fresh state. The correction was made once in canonical source and deployed in the same sealed package to all five.

- `crates/synergy-vpn/src/route_policy.rs:7`: validate canonical validator identity, canonical private IPv4 socket endpoint and TCP5622. Overlay allocation is authorized by the signature-verified exact registry. Legacy scope tests remain unchanged. Export added in `crates/synergy-vpn/src/lib.rs`.
- `crates/synergy-transport-registry/src/lib.rs:62`: retain validator-scope restriction and duplicate-identity/endpoint checks; validate endpoint shape after authenticated snapshot verification.
- `crates/synergy-transport-registry/src/verifier.rs:391`: signed private allocations accepted; tampered endpoint invalidates signature; signed public/wrong-port endpoints rejected. Network/provider-plan/generation/rollback/equivocation checks remain.
- Focused native tests: `cargo test --locked -p synergy-vpn -p synergy-transport-registry` **12 passed** (9registry+3VPN). Linux release build passed with before/after identical source inventories; exact resulting native executable passed real all-five startup, finality and encrypted transfers. No consensus redesign or historical-stall causal claim.

Remaining differences are classified below. No unexplained application configuration or unsafe deployment drift was found in these checks. Operational equivalence does not mean identical hardware or identical independent state.

| Classification | Exact source / difference | Significance and smallest safe action |
|---|---|---|
| EXPECTED | Per-host node.json node_name, VPN listen/advertised IP, local key identifiers; separate keys/data journals/transactions/logs | Required identity, routing and independent state. Keep parameterized; never copy private keys or live databases. |
| EXPECTED | Val2 keys/authority, keys/transport and two test-wallet custody roots; small submission receipts | Explicit fresh-network signing and test ownership. Not a second validator implementation. Keep local0600 custody; public records now in original workbook. |
| JUSTIFIED | final-runtime-environment.json: Val4 Xeon24threads/121.53GiB RAM/ZFS root; others EPYC8/23.46GiB except Val5 EPYC6/11.68GiB | Same executable/resource policy, different scheduling/storage/cache accounting. No causal finality-stall conclusion. No host reconfiguration required for this acceptance. |
| JUSTIFIED | Val4 Ubuntu26.04.1/en_US.UTF-8; others26.04/C.UTF-8; all x86_64 and same mapped library hashes | OS locale/patch label differs; native protocol configuration and libraries match. No correction required. |
| JUSTIFIED | Val4 has8GiB host swap configured, currently unused; every node cgroup MemorySwapMax0/current0 | Host capacity is distinct from validator swap permission. Preserve host OS and shared services. No swap-policy relaxation. |
| JUSTIFIED | Val2 /etc/systemd/networkd.conf.d/99-netbird.conf: ManageForeignRoutes=no, ManageForeignRoutingPolicyRules=no; other four absent | NetBird OS integration, not a node-service override. networkctl proves wt0 unmanaged on active networkd hosts; networkd inactive onVal4. Preserve; no networkd/VPN reload needed. |
| JUSTIFIED | chronyc tracking per host: distinct references/offsets, leap statusNormal; current absolute reported system offset<0.6ms | Snapshot only, not bounds on earlier inter-host clocks. No precision-based historical causal assertion or clock change. |
| EXPECTED | resource-final.json: filesystem sizes/counts, Sync artifacts, cgroup cache and per-node durable records differ | Independent execution/recovery observation and filesystem accounting. Compare schema and retention, not artificial byte equality. No automatic synchronization/deletion. |

The prior pre-rebuild audit remains in `VALIDATOR_FLEET_CONSISTENCY_AUDIT_20261025.md`; its old PIDs, flags and paths are historical. Current cleanup verified each exact attributed deletion manifest absent (Val3 61targets, Val4 89, Val5 65, Val6 57), plus earlier Val2 wipe and additional residual cleanup. No old installation backup/archive was made. Fresh custody possession and root0600/0700 permissions passed. No superseded binary, old application unit/drop-in or temporary installation stage remains in the audited installation. Completed transfer scratch was removed, retaining only small submission intent/response records. OS, SSH, unrelated applications and the VPN coordinator remain intact.

## Workbook, evidence and outstanding qualifications

The sole Desktop workbook `/Users/jhutzler/Desktop/node-machine-credentials.xlsx` was edited IN PLACE at 2026-10-26T20:48:17.918620+00:00:501 public/path/status cells on7existing sheets,4additional identity records and6public-key records. Original20tabs, unrelated cells/styles/native worksheet features and unrelated ZIP parts were verified preserved. Private-key bytes were not exported. No workbook copy/backup. Result SHA-256 `12600078334fed27f75c92a3b81c13a8ad6af871e8381727c73869eb2a3b4d9d`. Credential rotation is deferred per operator instruction.

Raw receipts, source/build/test provenance, each native finality proof, exact transaction effects, resource samples and workbook verification live under `node-platform/target/remaining-validator-rebuild-20261026`. `COMPLETION-EVIDENCE-MANIFEST.json` pins the files; AppleDouble sidecars are excluded. Do not rerun consumed destructive/init/enrollment/start/upgrade/submission scripts.

The working five-validator rebuild objective is met. Long-duration RSS/cgroup stability, durable-ledger and Sync-snapshot growth bounds, full sustained workload qualification, fault recovery over long intervals and a future24-hour soak remain unproven. No24-hour soak was started. The historical finality-stall causes are not closed by this fresh installation or by the authenticated-route correction.
