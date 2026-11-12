# Val2 clean rebuild and native installation report — 2026-10-25

Val2's attributed old installation has been logically removed. A fresh native Linux installation generated a new validator identity, verified possession of its keys, and enrolled a new VPN identity without browser interaction. **PoSy remains stopped. This is not a completed validator architecture, a fresh-chain acceptance, or a five-machine rebuild.**

The VPN coordinator was used only for authenticated VPN management. No Synergy application installation test ran there. The operator's explicit “wipe validator 2 and use that machine” instruction selected Val2 as the first test/rebuild machine. No other validator has been erased.

## Changes and current boundary

| Item | Verified result |
|---|---|
| Old isolated network | All five old PoSy units stopped before Val2 signing state deletion. Val3 terminated with exit1/VPN polling error during stop; MainPID0, failure preserved. Other four stops succeeded. |
| Destruction scope | Exactly 173 paths in the presented destruction manifest. Logical removal completed 21:41:18.903804UTC; all 173 still absent at 21:57:43 audit. No old-install backup or relocation. |
| Host preserved | OS, SSH, accounts, unrelated applications, generic development tools/caches, independent language checkout and mixed OS records retained. Only the two attributed Synergy UDP51820 UFW rules removed. No firewall flush or global sysctl reload. |
| New installation | `/opt/Synergy`; root-owned, no symlinks or nested mounts. No dependency on a developer workspace is used for installed application execution. Linux/systemd/Python/glibc/network utilities remain host prerequisites. |
| Master | `/Volumes/PortableSSD/Synergy-Network/Node-Architecture/Linux/Synergy/`; 20 canonical role directories, only validator under implementation. No other role was implemented. |
| Installed package | Manifest SHA256 `48c96c9064527a063436e41132edee9f62d462d5563dee9827360031c925cfd0`; all sealed installed file hashes match. This is a development package, not a newly signed release. |
| Native executable | `synergy-node` SHA256 `e847a075491d97898b4cb3754d89c2ee526b8442166764b552f905196b65dc5e`; actually executed native version/initialization/verification commands on Val2. It is not the old r8 executable. No node daemon is running. |
| New node address | `synv11xr6tjlf0gnt7e29lwnzfg823rlujtrwx8nu` |
| Native keys | Local FN-DSA-1024 root, separate ML-DSA-65 P2P and consensus keys, ML-KEM-1024 ingress key. All four secret files root-owned0600, custody directories0700. Native correspondence/possession verification passed before and after VPN restart. No private bytes exported or copied between machines. |
| Fresh storage | Actual initializer reports `synergy-node-storage:1`, fresh native storage, no consensus start. Safety journal remains empty until actual signer operations. No old database was imported. |
| New systemd integrations | Only `synergy-node.service` and `synergy-vpn.service`, with ownership receipt. Both disabled for boot, no drop-ins. Node inactive/MainPID0; MemoryMax1GiB, swap0, TasksMax512. VPN active/PID2043679 at audit. VPN uses host-default resource limits; it is not included in the node's 1GiB cgroup. |
| Current VPN | Actual running `/opt/Synergy/bin/netbird` SHA256 `4eb4d7a2f5fe1a224362c68f6c8129502247635711db1970cc85ed921896780d`; new peer `dbf7fiaf611ohpqj0640`, IP `10.69.106.160/16`. Management/signal connected, same machine-specific WireGuard public key retained across restart. Native wt0 pings to all four existing peer IPs passed. This is not rebuilt five-node mesh or PoSy port readiness. |
| Old VPN retirement | Old Val2 peer `dab92p2f611ghl16e2f0` and two attributed obsolete setup keys deleted; absence verified, other peer registrations preserved. |
| Fresh enrollment credential | One-off/usage-limit1 key `dbf7fhif611ohpqj060g` issued on VPN host and deleted after attempt. PAT stayed on VPN host. Authenticated audit event63 attributes the new peer to this enrollment; `used_times` was not retained before deletion and is not claimed as measured. Temporary on-node enrollment secret absent. |
| Credentials workbook | Sole Desktop workbook updated in place at22:01:29UTC:61 cells across seven existing sheets. New public identities/keys and local secret paths recorded, obsolete local custody passphrases removed, legacy NCP authorization cleared from its cell and explicitly marked revocation unverified. Other cells/styles and unrelated ZIP parts preserved; no workbook copy/backup. |

## Failures and resolved installation-tool issues

1. NetBird's CLI `--hostname` supplies the API **name**, while API **hostname** remains the OS hostname. The original binding check failed after successful enrollment. The comparison was corrected and independently attributed against authenticated audit event63; Val2 was not enrolled twice.
2. Python import wrote `__pycache__` into a sealed staging tree. Package verification rejected it before mutation. Bytecode creation was suppressed before import; a tool-only reseal was installed through the stopped lifecycle upgrade. Custody/state were not copied. Its first final-check driver returned1 without retaining the exact failing assertion. Subsequent independent bounded checks verified installed hashes, key possession, same VPN identity, all four pings and node MainPID0; the driver exit is not represented as an uninterrupted acceptance pass.
3. A second cached Cargo build reported success, but its target `synergy-keytool` was not ELF. No corrupted target binary was deployed. All four master/native files were checked against the successful build1 pins. The tool-only reseal reuses those verified binaries and does not claim a new native rebuild. A clean native rebuild and provenance verification remain required before a final release.

Seven focused offline package-boundary tests pass. They are not real consensus or fresh-chain acceptance tests. Workbook export preservation checks refused several proposed outputs before writing; the final in-place update passed cell and ZIP preservation checks. One tool-generated inspection sidecar was removed without reading; subsequent exports used nonpersistent pipes for both workbook bytes and automated inspection output.

## Blocking fresh-chain findings — do not erase Val3

The planned fresh chain is `1185228207`, network `synergy-linux-rebuild-20261025-31303316dd024ce685a1dc99`. These are preparation identifiers only. Final genesis/authority cannot be constructed until all five actual fresh public identities are available. No old domain was silently reused.

The current native implementation explicitly restricts critical validation paths to1266:

| Exact source under `01-Core-Protocol/node-platform/` | Consequence / smallest safe correction |
|---|---|
| `bin/synergy-genesis/src/network.rs:14` | Fresh genesis network rejected. Carry a validated fresh network binding through native genesis construction. |
| `crates/synergy-crypto/src/domain.rs:12` | Non1266 signing domain rejected. Make the actual configured domain authoritative and prove old/new cross-domain verification rejects replay. |
| `crates/synergy-posy/src/membership/epoch.rs:68` | Fresh authority epoch rejected. Bind membership to the same approved fresh chain/genesis, preserving PoSy ownership and quorum/finality rules. |
| `crates/synergy-etdag/src/admission/context.rs:113`; `processing.rs:102` | Fresh ETDAG contexts rejected. Propagate the same validated domain; preserve verification requirements. |
| `crates/synergy-sync/src/state/manifest.rs:28`; `crates/synergy-manifest/src/verifier.rs:14` | Fresh synchronization/network manifests rejected. Validate against explicit chain authority rather than a global1266 constant. |
| `crates/synergy-transport-registry/src/verifier.rs:15–19,184` | Registry binds fixed1266/testnet/testnet-v3 values. Generate and verify the actual fresh public transport registry against its signed authority. |
| `crates/synergy-snapshot/src/manifest.rs:61`; `crates/synergy-data-availability/src/proof.rs:24` | Fresh recovery/DA objects rejected. Preserve domain separation and authority checks across recovery paths. |

This is a supported implementation blocker, not evidence for the historical finality-stall cause. No speculative PoSy/ETDAG protocol change was made to bypass it. Other authority/manifest builders and entry points must also be reviewed before calling the domain work complete; this table is not a claim that replacing these constants alone is sufficient.

At the Val2 chain-binding audit, `/opt/Synergy/config/node.json`, final genesis and `config/start-authorized.json` are **absent**. The native initializer created storage, not a complete launch configuration. The installation receipt records the planned new chain; that receipt does not establish native runtime support. The systemd condition and lifecycle checks remain closed. Full uninstall of an enrolled fresh installation and complete fresh-chain startup/shutdown/transaction qualification are not yet accepted.

## Residual limits and precise next actions

- Val3–Val6 old installation roots remain present; old PoSy MainPID0 independently verified at21:59:48UTC. Their signing/database state was not reset. Do not erase the next host while Val2/master acceptance is incomplete.
- Old live kernel sysctl values may remain until a separately reviewed baseline is applied; removing their snippets is not proof of live kernel reversion. Do not guess a new global baseline or reload unrelated host settings.
- NetBird's socket is writable by mode inside root-owned0700 installation/run ancestry; unprivileged traversal remains denied. No public socket exposure is inferred from the socket mode alone.
- Old NCP authorization revocation is unverified. Local removal and VPN peer deletion do not prove that independent central credential was revoked. Determine exact broker authority semantics before an attributable credential retirement; do not restart or reconfigure the VPN host as an application test.
- Logical removal is verified in the attributed scope. Forensic erasure of SSD/hypervisor/provider snapshots and mixed OS audit records is not proven; unrelated storage was not wiped.
- Finish native configurable fresh-genesis/domain support with focused signature/replay/authority/storage/recovery tests and clean Linux artifact provenance. Complete the canonical effective launch configuration and validate it without starting PoSy. Review the exact next-machine destruction plan only after the first-machine gates pass; do not infer five-machine wipe permission from the Val2 selection.
- Keep the old soak automation paused. No new workload, qualification, performance experiment or soak ran during these installation checks. No broader completion or fleet-equivalence certification is asserted.

## Evidence

`node-platform/target/universal-linux-package-20261025/VAL2-REBUILD-EVIDENCE-MANIFEST.json` pins24 bounded evidence files, including exact destruction authority, actual removal terminal result, native identity/VPN observations, API audit attribution, current installed-file verification, root-boundary checks and workbook update verification. Raw private validator keys and the management PAT are not in this evidence set.

The full pre-change five-validator comparison remains `docs/refactor/VALIDATOR_FLEET_CONSISTENCY_AUDIT_20261025.md`, SHA256 `cc0b044e6b8137159d6517a5eb819ea8f9134890903599df1bbb2c91828d281d`. It describes the old fleet before this authorized decommission and must not be represented as the new installation's current state.

Security note: an unrelated workbook credential and a legacy Val2 NCP authorization were inadvertently exposed in earlier tool output. Their values are not repeated here. No unrelated credential rotation or central NCP revocation is claimed.
