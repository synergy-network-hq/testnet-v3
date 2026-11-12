# Configured-network Chain ID audit and Val2 acceptance — 2026-10-26

The reusable runtime no longer selects Chain1266 or1264. Chain identity is supplied through selected configuration and authenticated Genesis; native startup rejects a mismatch. The rebuilt Linux package passed offline cross-network validation on Val2 and replaced its sealed application files once. PoSy was never started. Val3–Val6 were not modified, erased, deployed or restarted in this work.

This report follows the earlier [full five-validator comparison](VALIDATOR_FLEET_CONSISTENCY_AUDIT_20261025.md) and [Val2 clean rebuild report](VAL2_CLEAN_REBUILD_REPORT_20261025.md). Those reports preserve the before-change fleet evidence. This task does not certify the currently mixed fleet as standardized or qualified. No finality stall cause is established here.

## Actual blocking sources and changes

The initial source scan was performed before corrections. Concrete original numeric gates included crypto/domain:12, genesis/network:14, PoSy epoch:68, ETDAG context:113 and processing:102, Sync manifest:28, snapshot manifest:61 and builder:30/50, DA proof:24, SXCP independence:15 and manifest verifier:14. Additional blockers were the transaction constructor, wallet/import tools, fixed transport tuple, SynQ testnet policy, optional PQVM1264 integration and installer’s refusal of1266. These were actual local source restrictions, not assumptions about an old executable.

Current source pointers below identify the implemented replacements. No quorum, proposer selection, round ownership, timeout, readiness deadline or resource cap was loosened.

| Boundary | Current source | Implemented correction |
|---|---|---|
| Cryptographic domains | [crates/synergy-crypto/src/domain.rs:12](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-crypto/src/domain.rs:12) | Rejects zero/invalid shape; signs the supplied chain/network, never a fixed chain. |
| Genesis network validation | [bin/synergy-genesis/src/network.rs:14](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-genesis/src/network.rs:14) | Accepts an explicit nonzero u64 and bounded network identity. |
| PoSy epoch membership | [crates/synergy-posy/src/membership/epoch.rs:68](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-posy/src/membership/epoch.rs:68) | Uses the authenticated epoch context; no chain1266 gate. |
| ETDAG admission | [crates/synergy-etdag/src/admission/context.rs:113](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-etdag/src/admission/context.rs:113) | Uses selected chain and network with existing target-height/epoch checks. |
| ETDAG processing AAD | [crates/synergy-etdag/src/admission/processing.rs:102](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-etdag/src/admission/processing.rs:102) | Retains signed/encrypted context bindings with dynamic chain identity. |
| Sync state manifest | [crates/synergy-sync/src/state/manifest.rs:28](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-sync/src/state/manifest.rs:28) | Validates selected network state instead of accepting only1266. |
| Snapshot verification/build | [crates/synergy-snapshot/src/manifest.rs:61](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-snapshot/src/manifest.rs:61) | Snapshot builder now requires chain_id; Sync supplies its manifest context. |
| DA proofs | [crates/synergy-data-availability/src/proof.rs:24](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-data-availability/src/proof.rs:24) | Dynamic chain domain, existing proof/signature requirements retained. |
| SXCP finality anchors | [crates/synergy-sxcp/src/independence.rs:15](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-sxcp/src/independence.rs:15) | Dynamic chain identity; existing independent finality requirements retained. |
| Manifest comparison | [crates/synergy-manifest/src/verifier.rs:14](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-manifest/src/verifier.rs:14) | Now compares against expected.chain_id, fixing a real expected-context omission. |
| Transactions | [crates/synergy-transaction/src/transaction.rs:15](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-transaction/src/transaction.rs:15) | Replaces testnet-only constructor with NetworkBinding::new(chain_id, network_id). |
| Authority verifier | [bin/synergy-node/src/services/authority.rs:507](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-node/src/services/authority.rs:507) | Rejects a signing context whose chain differs from the verified authority. |
| Transport snapshot trust | [crates/synergy-transport-registry/src/verifier.rs:38](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-transport-registry/src/verifier.rs:38) | SnapshotContext is pinned by the caller; signed snapshots must match the complete tuple. |
| VPN configuration | [crates/synergy-config/src/vpn.rs:15](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-config/src/vpn.rs:15) | Explicit transport_context replaces the built-in testnet tuple. |
| Authenticated CLI boundary | [bin/synergy-node/src/commands/selected_network.rs:27](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-node/src/commands/selected_network.rs:27) | Verifies signed Genesis under the configured trust key, then chain/network/hash/protocol and initial authority. |
| CLI start | [bin/synergy-node/src/commands/start.rs:220](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-node/src/commands/start.rs:220) | Authenticates selected network before opening node services; preflight and join use the same boundary. |
| Configuration | [crates/synergy-config/src/node.rs:28](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-config/src/node.rs:28) | Adds genesis_path; old configuration may decode for inspection, but cannot start without authenticated selection. |
| Wallet/key tooling | [bin/synergy-keytool/src/wallet.rs:96](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-keytool/src/wallet.rs:96) | Generation, authorization, transaction signing, processing and session admission receive explicit chain context. |
| Consensus custody import | [bin/synergy-keytool/src/import_consensus.rs:73](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/bin/synergy-keytool/src/import_consensus.rs:73) | Possession/import commands require explicit chain ID and retain public-key and identity checks. |
| SynQ runtime policy | [crates/synergy-aegis/src/pqsynq.rs:48](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/synergy-aegis/src/pqsynq.rs:48) | Policy derives from node chain/network; removes automatic testnet-name aliasing. |
| SynQ network tag | [crates/aegis-pqsynq/pqsynq/src/domain.rs:19](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/aegis-pqsynq/pqsynq/src/domain.rs:19) | V2 internal signer tag hashes full network identity; full chain/network are still signed and checked. |
| Optional PQVM Synergy integration | [crates/aegis-pqvm/src/integrations/synergy/mod.rs:9](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/crates/aegis-pqvm/src/integrations/synergy/mod.rs:9) | Removes1264/0x4f0 built-in network selection; chain/network/precompile address come from host configuration. |
| Linux installer | [tools/linux-node/synergy_linux.py:127](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/tools/linux-node/synergy_linux.py:127) | Accepts1266 or any explicit nonzero u64; no forced replacement number. |
| Linux start gate | [tools/linux-node/lifecycle.py:140](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/tools/linux-node/lifecycle.py:140) | Requires signed native Genesis and authority preflight before start authorization can proceed. |
| Ingress edge | [services/chain1266-user-ingress/server.mjs:7](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/services/chain1266-user-ingress/server.mjs:7) | Uses a deployment-pinned context file and digest; rejects upstream chain/genesis/incarnation mismatch. |
| Generic Genesis schema | [schemas/genesis.schema.json:18](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/schemas/genesis.schema.json:18) | Removes const1266; retains nonzero u64 range. |
| Build guard | [tools/linux-node/build_package.py:35](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/tools/linux-node/build_package.py:35) | Runs reviewed chain-selection audit before a clean sealed Linux build. |

## Classification of every retained identifier occurrence

Search covered current tracked and untracked workspace text, including Rust, utilities, scripts, tests, schemas, network inputs and bundled integrations. Build outputs, Git internals, AppleDouble files, credential/key files and binary inputs were excluded from text inspection. Public signed fixtures and build evidence were preserved separately. The broad initial search retained2,565 matching lines across357 files; the final identifier-specific inventory is narrower and contains344 occurrences across155 files.

| Classification | Final occurrences | Disposition |
|---|---:|---|
| Prohibited hardcoded reusable restriction | 0 | Identified restrictions corrected. Build guard reports zero remaining1264/1266 assignments/comparisons in its reusable-source scope. |
| Legitimate dynamic/protocol/search value | 4 | Audit search expressions and unrelated cryptographic numeric tables; no chain selection. |
| Network-specific test fixture | 242 | Explicit tests, examples and isolated-testnet operational recipes. They are not defaults and are excluded from the universal installation architecture. |
| Intentionally pinned historical artifact | 98 | Historical inputs, V1 signature namespaces and an unselected nested vendor snapshot. They were not rewritten. |

Each retained occurrence has its exact file, line, classification, reason and file SHA256 in [final-classification.json](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/configured-chain-domain-20261025/final-classification.json). The initial broad and Rust literal scans are in the same evidence directory. The scan is a reviewed static guard, not an assertion that arbitrary future code can be proven safe by a regular expression.

The old `tools/validator` canary/stability recipes still intentionally describe that named testnet and its pinned release checks. They are classified as network-specific operational fixtures; they must not be used as a universal installer. The universal package uses `tools/linux-node` exclusively. The unselected nested `crates/aegis-pqsynq/aegis-pqsynq/` snapshot remains historical; the built dependency is `crates/aegis-pqsynq/pqsynq`.

## Cryptographic isolation and compatibility

A fresh Genesis does **not** require a different numeric chain ID. The same executable accepted1266 twice, using distinct authenticated network identities and Genesis hashes. It also accepted9001 and9002 as fixture networks; these are test vectors, not actual Mainnet Beta/Mainnet assignments.

Generic transaction signing binds chain ID and full network ID. Peer/session and authority checks additionally bind authenticated Genesis. The generic transaction envelope does not independently include Genesis hash or a chain-incarnation counter. Therefore a new Genesis hash alone, while retaining both chain ID and network ID, is not established as sufficient transaction replay isolation. Keep the numeric ID if desired, and select a distinct authenticated network/incarnation identity. Tests reject the original signature under that new network identity using the same key and numeric chain ID. No new consensus phase or certificate was introduced.

Fresh Genesis and signed-manifest tooling support network-neutral format2 domains. Explicit format1 preserves historical hash/signature bytes for offline verification; the exact reproduction regression passes. Runtime preflight/start/join requires format2 and refuses historical format1. This is a compatibility boundary, **not a drop-in upgrade for a running format1 chain**.

SynQ’s old three-name-to-number map was also a hardcoded network restriction. New runtime policy selects V2 internal signer identifiers derived from the full configured network name. The two-byte routing tag is never admission authority: full chain/network values remain signed and checked. Historical serialized V1 policy/vector verification is retained separately using its pinned chain-derived tag; frozen signed vectors were not regenerated. V2 is an internal execution signer identifier, not a replacement public account address. A format1 chain needs an explicit reviewed migration rather than silently reinterpreting its old identifiers.

## Tests and exact Linux package

| Suite | Result |
|---|---|
| Crypto/config/transaction/manifest/ETDAG/PoSy/Sync/snapshot/DA/SXCP/transport/genesis/keytool components |166 passed,0 failed |
| Node command tests |3 passed,0 failed |
| Bundled Aegis library and integration tests |124 passed,0 failed, serial test execution with an explicit disposable license-test secret |
| Focused SynQ network and frozen deploy-vector tests |20 passed,0 failed; overlaps the broader Aegis suite |
| Ingress rejection tests |4 passed |
| Linux package refusal tests |7 passed |
| Native macOS offline cross-network suite |61 passed,0 failed |
| Exact rebuilt Linux binaries on Val2 |61 passed,0 failed |

The61 checks exercise four authenticated network contexts, signed Genesis/authority verification, fresh disposable storage initialization and refusal to overwrite it, wrong chain/network/trust, absent Genesis, mismatched transport protocol, another Genesis, wrong manifest and authority, wrong Genesis hash, tampered signed content, historical runtime rejection and historical offline verification. `init` initializes storage only; it does not join a chain. Native preflight performs authentication. No test invokes node start, network consensus or workload submission.

The initial feature-only Aegis test invocation failed linking omitted native libraries; a second invocation tried examples whose disabled-feature APIs were unavailable. The correctly enabled library/integration suite then exposed missing test-license configuration. All were retained as failed attempts; the final configured suite passes. A real historical signer-vector regression was corrected with explicit historical verification, not by replacing the vectors. The macOS temporary-path fixture was canonicalized to satisfy the existing symlink refusal; the production refusal remains.

Clean Linux target: `/Users/jhutzler/.cache/synergy-configured-chain-linux`. Target architecture x86_64, glibc2.28 minimum, release build, no default node features or diagnostic feature flags. All three native binaries passed structural ELF checks. Source inventories before and after compilation match exactly. Build-time Git revision is `b338dcc223c1ce33599e12c424858cd000772637`; this is a working-tree build with the recorded complete content inventory, not a clean published Git revision or signed release. Existing nested Git AppleDouble index warnings remain in the build-driver log; they were not silently cleaned or treated as release qualification.

| Artifact | SHA256 |
|---|---|
| Sealed package.json |`61faead2376c1257a8efa5fde7ca22098edf57fe5d6389b961ac561add612aa6` |
| synergy-node |`65f505fad1d5d3cc0b5322714892364a919f45af61bd3e4e17df4b8ec19fa7dc` |
| synergy-keytool |`74abd0703fbb6c2d4e3f7609ebc8ed6152ac9d971c8402130512f2873ceefa21` |
| synergy-genesis |`c3f2764e89b282d0048f43ed6c259821d02c6e0f23496fddfb5e6b7d425d1607` |
| Unchanged NetBird |`4eb4d7a2f5fe1a224362c68f6c8129502247635711db1970cc85ed921896780d` |
| Build-time source inventory content binding |`669e32f0d68afd5f1e5aca2ef45efc35edbcef50fe0944f64eab8687c492c085` |

Canonical generated master: `/Volumes/PortableSSD/Synergy-Network/Node-Architecture/Linux/Synergy`. Native implementation remains only in the canonical node-platform checkout; no source mirror was made. The master carries20 role directories with validator as the only implemented role. Its build-time acceptance marker remains unqualified; actual offline acceptance is recorded externally, without modifying the sealed package after testing.

## Val2 execution and remaining fleet boundary

At13:27:18UTC, Val2’s old installed package hash and every sealed file matched; node PID0/inactive,1GiB memory/swap0/no drop-ins, existing VPN connected. A new public-only package/fixture stage was created under `/opt/Synergy/tmp/configured-chain-20261026`. Candidate native checks passed before upgrade. The existing lifecycle upgrade then replaced only sealed application files once; it refuses keys/data/config/network/other mutable state. No old binary backup, key copy, database copy, enrollment, wipe or rollback was performed.

The combined driver exited nonzero after the upgrade and VPN start. It failed to retain the exact post-check failure; that attempt is not described as an uninterrupted successful run. Read-only follow-up established that upgrade had already completed, so it was **not rerun**. Independent final acceptance at13:33:22UTC verified:

- All installed sealed hashes match the package and installation receipt.
- Native root, P2P, consensus and ingress possession checks pass for unchanged address `synv11xr6tjlf0gnt7e29lwnzfg823rlujtrwx8nu`.
- VPN remains connected with the same public WireGuard identity and10.69.106.160/16 address; one bounded ping to each10.69.10.3/4/5/6 passed.
- Node remains inactive/PID0 with no drop-ins,1GiB memory and swap0. Version reports0.1.0, management/config schema1.
- Final `config/node.json`, `network/genesis.json` and `config/start-authorized.json` remain absent. Public disposable fixtures were not installed as the real network.
- Val3–Val6 were not modified. Their old installations are intentionally not represented as equivalent to this new Val2 package; no fresh all-five health claim is made.

The current installed public identity and native possession are verified. The initial failed driver did not retain its pre/post inode comparison, so this report does not invent that additional evidence. Upgrade’s explicit file allowlist and unchanged identity are the verified preservation boundaries.

No new real five-validator Genesis, signed release, coordinated rollout, PoSy startup, qualification, soak or finality repair is claimed. The earlier numeric1185228207 plan is not a runtime requirement or final chain-ID decision. The sole Desktop credentials workbook was not duplicated, backed up or changed by this task because no identity/key/VPN enrollment was replaced.

## Evidence and continuation

[Evidence manifest](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/configured-chain-domain-20261025/EVIDENCE-MANIFEST.json) SHA256 `9162687126ea9464cf449dabc2071df2a98a1411e37b00e477d2f86b6cfeb630` pins168 raw/result files. [Val2 acceptance](/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/target/configured-chain-domain-20261025/val2-acceptance.json) contains the exact native Linux checks and final observed unit/network state. Public fixtures remain separated from real installation configuration.

The chain-ID blocker is resolved for offline universal initialization/authentication. Performance and release activity remain stopped. The remaining fleet rebuild and actual authenticated five-identity network configuration require their own concrete acceptance and existing operator authority; nothing in these offline results authorizes erasing another validator or starting PoSy.
