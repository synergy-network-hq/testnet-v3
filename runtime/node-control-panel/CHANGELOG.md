# Changelog

Historical release notes reconstructed from local git tag ranges for the control panel versions shown in the screenshots. Where the underlying commits were too generic to support a precise summary, the entry is marked as a maintenance release with broader wording.

## Unreleased

- Prepare Testnet-v3 chain 1266 onboarding with 21 installer-bound encrypted validator identity bundles and complete per-validator WireGuard topology files; Validators 01–06 are the initial cohort and Validators 07–21 remain provisioned for gradual activation.
- Reduce packaged-validator VPN onboarding to the coordinator-issued one-time token: the panel creates the assignment-bound identity proof, installs the checksum-verified `sy-vpn.conf`, verifies client and coordinator handshakes, and only then consumes the token.
- Repair the Settings route so defaults render even when the desktop settings bridge is unavailable, with a visible warning instead of a blank screen.
- Add native macOS DMG and Linux DEB release tooling that stages one validator at a time, creates uniquely named artifacts for Validators 01–21, emits SHA-256 manifests, and clears secret staging on exit.
- Route all 66 Operations actions through an owner-scoped, allowlisted local PTY bridge while preserving typed control-service execution and single-copy command output.
- Reconstruct validator membership on service-node restart from finalized activation evidence so relayer and RPC snapshots cannot remain on a stale registry epoch while the chain advances.
- Report validator-set transition height and independent per-cluster quorum semantics explicitly, including the strict `3*q > 2*n` threshold (4-of-5 for each cluster at ten active validators).
- Migrate coordinator VPN allocation, bootstrap routes, enrollment validation, and persisted leases to the canonical `10.70.10.0/24` validator and `10.70.20.0/24` relayer ranges, with legacy state cleanup and release-literal enforcement.
- Keep the embedded runtime on the last verified build while the restart-safe membership fix is completed; source and bundle versions will be aligned before the next installer release.

## v19.0.35 - 2026-07-15

- Add an explicit **Complete Validator Self-Bond** action between validator funding and bond verification. It uses the already-funded validator account, preserves the 1 SNRG fee reserve, and retains duplicate-submission protection.
- Let normal peer sync hand ongoing catch-up to guarded onboarding instead of hiding Launch & Activate until the UI observes a zero-block gap.
- Reuse a healthy running validator during repeated normal-sync checks when coordinator-signed transport configuration has not changed, preventing polling from repeatedly restarting catch-up.
- Retain all three canonical Innernet relayer targets when applying signed validator transport routes so an unactivated validator can catch up from authorized support sources before self-bond and activation.
- Reject self-bond submission before the local validator matches canonical balance, stake, peer, and sync evidence, replacing misleading local `Insufficient balance for staking` failures with actionable readiness details.
- Persist the real Operations terminal session and bounded transcript across route changes, add explicit clipboard paste, expand the executable operation catalog, and require every visible action to resolve to a real service method and Rust command.

## v19.0.34 - 2026-07-15

- Bundle the matching Synergy Testnet `v19.0.34` runtime that restores authenticated validator status propagation across the full validator mesh.
- Keep status recovery available after a verified peer handshake while preserving fail-closed authorization for blocks, headers, and bodies.
- Require exact handshake and status validator identities so status recovery cannot change or establish a peer's validator identity.
- Preserve automatic onboarding and activation without temporary peer-isolation or operator-managed validator firewall changes.
- Align the Control Panel, control service, release tag, source tag, and bundled native runtime on `v19.0.34`.

## v19.0.30 - 2026-07-15

- Keep onboarding and recovery validators on authenticated support-only synchronization until canonical activation, without requiring operators or administrators to add or remove per-validator firewall rules.
- Make canonical validators reject status, header, body, and block-history requests from unactivated or quarantined peers while retaining coordinator-authenticated support sources for onboarding.
- Replay finalized validator activations during startup before membership reconciliation so an activated validator resumes consensus automatically after a stale or missing local registry.
- Require public/local balance and stake parity, reserve 1 SNRG for protocol fees, and submit exactly one 50,000 SNRG self-bond without duplicate activation transactions.
- Publish validator-pruned snapshots atomically, reject stale or incomplete recovery state, and keep the archive worker on a persistent 2,500-block freshness cadence.
- Route every executable Operations action through the local terminal transcript, retain the real PTY session, and provide plain-language hover help across the expanded command catalog.
- Align the Control Panel, control service, release tag, and bundled Synergy Testnet runtime on `v19.0.30`.

## v19.0.26 - 2026-07-14

- Accept the archive validator's signed runtime-manifest envelope while preserving fail-closed snapshot identity checks.
- Restart an already-running validator after coordinator transport reconciliation and require at least one connected remote peer before normal sync can report `syncing`.
- Mirror every Operations command, stdout/stderr payload, informational result, and final status into the in-app terminal without executing the action twice.
- Align the Control Panel, control service, release tag, and bundled Synergy Testnet runtime on `v19.0.26`.

## v19.0.17 - 2026-07-13

- Repair legacy confirmed Innernet enrollments by fetching a fresh coordinator-signed validator transport map with the existing membership receipt instead of requiring another one-time invitation.
- Persist refreshed transport evidence into the validator workspace while retaining a valid signed cached map during temporary coordinator outages.
- Replace the simulated Operations console with an interactive local PTY terminal, including resize, reconnect, copy, and clear controls without retaining typed commands or password input.
- Expand Operations from 27 to 36 backend-mapped controls, add plain-language hover help to every catalog action, and replace misleading status/readiness shortcuts with exact VPN, snapshot, eligibility, rewards, sync, and update commands.
- Allow a confirmed validator funding balance to proceed through sync before the local self-bond, carry the selected sync mode through Jarvis and v18 onboarding, and accept verified normal peer synchronization as a real snapshot fallback.
- Record setup-sync completion only after verified live catch-up, persist activation-pending state, prevent duplicate activation submissions, and keep monitoring until canonical activation plus active-consensus evidence is confirmed.
- Add contract coverage for the receipt-authenticated refresh endpoint and keep the Control Panel, control service, and bundled Testnet runtime aligned on `v19.0.17`.

## v19.0.16 - 2026-07-13

- Preserve and verify the archive catalog's exact downloaded bytes so valid Aegis signatures are not invalidated by JSON reserialization.
- Reconcile existing Innernet validator workspaces on resume, including canonical synv1 identity fields, signed peer routes, and 10.70.10.x transport validation.
- Bind the Control Panel and packaged Synergy Testnet runtime to matching version `v19.0.16`.

## v19.0.15 - 2026-07-13

- Bind the Control Panel to Synergy Testnet runtime `v19.0.15`, including bounded committed-QC lookup, generation-safe service sync handoff, and the sustained six-validator/three-relayer recovery build.
- Persist the archive-validator runtime with current `network.synergy.archive-*` launchd services, quorum-based health supervision, bounded restart policy, and fail-closed health gates for snapshot and catalog publication.
- Make live snapshot publication race-free by creating the validator-pruned snapshot first, verifying its finished height and hash against public canonical RPC, then packaging it through the existing verified import path.
- Keep the local Cloudflare R2 uploader dependent on remote archive health, validate every signed catalog and snapshot artifact before promotion, and publish public manifest paths that new operators can retrieve.
- Add regression coverage for root-owned health evidence, service-user gate access, inherited archive locks, runtime persistence, and post-create canonical snapshot proof.

## v19.0.12 - 2026-07-12

- Resume an already-redeemed Innernet interface when retrying installation returns the server's duplicate peer-IP constraint instead of the local existing-config error.
- Allow delayed coordinator confirmation after invite expiry only when the original confirmation secret and a fresh authoritative server-side handshake prove the peer was redeemed in time.
- Retain encrypted redeemed-invite confirmation state for a bounded recovery window so a restarted desktop can finish confirmation without requesting a second peer assignment.
- Exclude every IP already present in the authoritative Innernet database when allocating a genuinely new validator or relayer address.
- Recover a lost desktop confirmation credential for the same redeemed dynamic peer only after the coordinator verifies its exact identity, assigned IP, and fresh server-side handshake.

## v19.0.11 - 2026-07-12

- Prevent wallet-session persistence from dereferencing a null wallet during initial renderer mount.
- Resume a coordinator-assigned Innernet interface when its configuration already exists instead of retrying one-time invite installation and failing the onboarding flow.

## v19.0.10 - 2026-07-12

- Reconcile bootstrap memberships created before server-verification metadata was introduced only after all nine exact canonical peers are independently proven active, redeemed, and freshly handshaken by the coordinator.
- Make Innernet redemption fully noninteractive, bundle the macOS WireGuard userspace tools, preserve their signed helper path during administrator authorization, and report privileged command failures instead of mislabeling them as canceled prompts.
- Use software rendering on macOS and recover a failed renderer process so the operator window does not remain black.
- Treat transiently unavailable Wagmi account state as disconnected instead of dereferencing a null `chainId` and crashing the renderer.

## v19.0.9 - 2026-07-12

- Use the native macOS administrator authorization dialog and Linux desktop PolicyKit flow when secure-network setup requires elevated Innernet or WireGuard commands.
- Retain an issued Innernet invitation after a local redemption failure, including across app restarts through OS-backed encrypted storage, so retrying reuses the same peer assignment instead of colliding with a duplicate coordinator peer.
- Expire retained invitations deterministically and align the Control Panel, control service, release workflow, and bundled Testnet runtime on `19.0.9`.

## v19.0.8 - 2026-07-11

- Persist approved mobile wallet sessions across control-panel restarts while migrating existing session-only records safely.
- Keep the newly-created validator ID and address ahead of stale panel selection during local and remote onboarding.
- Align control-panel metadata on `19.0.8` and require the matching Testnet source, manifest, and native runtime versions during release.

## v19.0.7 - 2026-07-11

- Corrected the native runtime version gates to capture complete `--version` output before selecting the canonical first line, avoiding Rust broken-pipe exits caused by piping directly into `head`.
- Preserved the Ubuntu 22.04 Linux runtime baseline, exact-round quorum-certificate fix, VPN enrollment fix, and exact version-alignment contract from the preceding candidates.

## v19.0.6 - 2026-07-11

- Matched the Control Panel, control service, Testnet source package, Testnet release tag, and bundled native runtime version at `19.0.6`.
- Rebuilt the Linux Testnet runtime on Ubuntu 22.04 so official binaries remain compatible with the control panel's supported Linux baseline instead of requiring `GLIBC_2.39`.
- Added a Testnet release gate that executes every freshly built native runtime and verifies its version against the package and release tag before publishing binaries.
- Corrected the control-panel version gate to compare the runtime's canonical first version line while allowing subsequent build metadata lines.

## v19.0.5 - 2026-07-11

- Bundled matching Synergy Testnet runtime `v19.0.5`, which requires every vote counted in a quorum certificate to match the certificate's exact epoch and round.
- Added a fail-closed release gate requiring the Control Panel version, Testnet source tag and package version, trusted runtime tag, and native binary `--version` output to match exactly.
- Prevented prior-round recovery votes from being counted or embedded in current-round committed certificates, closing the malformed mixed-round QC path observed on the archive validator.
- Added Testnet regressions for mixed rounds `[2, 6, 8, 8]`, strict committed-QC verification, and current-round invalid-duplicate handling.

## v19.0.4 - 2026-07-11

- Fixed secure validator network enrollment so the generated validator address is included in the coordinator request instead of raising an undefined-variable error before token redemption.
- Added release regression coverage for the VPN enrollment validator-address binding.
- Aligned archive-validator snapshot creation with the Testnet runtime's `VALIDATOR` source-role policy while preserving signed `archive_validator` publication provenance.
- Allowed atomic catalog publication on SMB-backed archive storage when directory `fsync` is explicitly unsupported, while retaining hard failure for actual synchronization errors.

## v19.0.3 - 2026-07-11

- Replaced macOS ShipIt in-place updates with a version-pinned handoff to the signed and notarized DMG, preventing Gatekeeper from evaluating a partially replaced application bundle.
- Kept native background download and restart installation behavior for supported Linux packages while disabling automatic download-on-quit on macOS.
- Added updater policy tests for platform routing, release-version validation, and exact macOS installer asset URLs.

## v19.0.2 - 2026-07-11

- Fixed validator setup so confirmed 50,000 SNRG funding advances to secure-network bootstrap instead of presenting a self-bond action before the local runtime wallet exists.
- Made Launch & Activate start the guarded validator runtime, submit the local self-bond exactly once, wait for canonical bonded-stake confirmation, and continue onboarding without another wallet transfer.
- Preserved machine-readable onboarding actions separately from operator-facing status messages so the control panel cannot stall on the self-bond stage.
- Allowed coordinator-managed Innernet bootstrap from freshly verified validator funding while retaining bonded-stake requirements for validator registration, activation, and consensus participation.

## v19.0.1 - 2026-07-11

- Added a fail-closed release gate for the signed public archive snapshot catalog, detached Aegis signatures, declared chunks, checksums, and snapshot freshness before official installers can be published.
- Bound official control-panel builds to the Synergy Testnet `v19.0.1` runtime, including verified archive bootstrap recovery, portable snapshot application, and scoped post-restore permission repair.
- Published consumer-ready archive catalog metadata and immutable public snapshot URLs so onboarding can discover and verify the current validator-pruned snapshot without operator-specific paths.
- Hardened snapshot publishing so finalized archive signatures are replaced atomically and R2 publication uploads every declared chunk before the signed latest catalog is promoted.

## v19.0.0 - 2026-07-09

- Rebuilt the operator experience around a live Operations dashboard, metric trend panels, a nine-category control catalog, and the supplied Node Operator Control Panel banner.
- Added wallet-session continuity that preserves the paired Synergy wallet identity across control-panel navigation without storing private key material.
- Fixed validator onboarding funding recognition: a confirmed 50,000 SNRG transfer to the validator is detected on-chain, then the validator completes its own protocol-locked self-bond without asking the operator to send the stake again.
- Reworked archive-validator bootstrap into explicit discover, download, verify, apply, and speed-sync phases. Snapshot state is now staged and validated before an atomic store swap, with the prior full store retained as a backup.
- Enforced detached Aegis verification for public snapshot catalogs and distribution manifests, and bundle a tamper-tested ML-DSA-87 verifier compiled from the pinned canonical Aegis-PQC source into official macOS and Linux installers.
- Hardened coordinator behavior: public health checks no longer disclose host paths, public peer snapshots omit operator wallet addresses, legacy snapshots containing those addresses rotate to a newly signed redacted generation, and propagation stays incomplete until every active validator reports a verified WireGuard handshake.
- Replaced the placeholder Innernet command adapter with the supported non-interactive `innernet-server add-peer` contract and documented the required migration from the existing static validator mesh.

## v18.2.1 - 2026-07-09

- Prepared v18.2.1 as a validator-onboarding hotfix release.
- Fixed existing installs so the monitor workspace always refreshes bundled validator VPN assets, including `testnet/runtime/validator-vpn/validator-vpn-coordinator.env`, before VPN setup validates required resources.
- Corrected validator staking eligibility to count only active owner-wallet staking entries assigned to the generated `synv1...` validator address; validator registry stake telemetry no longer satisfies setup eligibility by itself.
- Prevented setup from advancing into provisioning/activation after a submitted stake request until canonical RPC confirms the operator wallet has bonded the required 50,000 SNRG stake to that validator.
- Removed stale prefetched nonces from mobile wallet stake envelopes so the Synergy Wallet approval signer owns nonce selection at signing time.

- Fixed public validator VPN coordinator deployment mode so coordinator services honor configured monitor workspaces and do not attempt to start a local desktop testnet agent.
- Fixed packaged validator onboarding to use the public validator VPN coordinator endpoint by default instead of requiring local coordinator verifier/signing secrets in each desktop install.
- Added public validator VPN coordinator enrollment routes that are limited to validator nodes and require verified 50,000 SNRG bonded stake for the connected owner wallet before enrollment is accepted.
- Updated validator VPN peer snapshots so the public coordinator signing key is carried with the signed snapshot, allowing operator installs to verify snapshots without shipping private coordinator material.
- Added public-P2P validator onboarding gates to Jarvis: NAT mode selection, custom public P2P ports, desktop external reachability checks, seed `/register` plus `/heartbeat`, and dial-back success before activation can continue.
- Kept new-validator P2P discovery separate from consensus activation: seed registration makes a validator reachable, while the existing Path C dynamic validator-set activation policy remains the only path to active consensus status.
- Updated new-validator onboarding guidance to use `synergynode.xyz` bootnodes/seeds, `_dnsaddr.bootstrap.synergynode.xyz`, archive-safe public P2P language, and explicit seed dial-back requirements.

## v18.0.0 - 2026-07-04

- Rebuilt the desktop control panel around the six-screen v18 app shell: Overview, Setup Node, Validator, Monitoring, Logs, and Settings.
- Added the dedicated Synergy wallet connection component from the master `synergy-wallet-connection` copy and configured the control panel to hide and disable EVM and non-EVM wallet lanes.
- Added mandatory validator eligibility gating: Setup Node starts with a Synergy wallet connection and blocks onboarding unless 50,000 SNRG active validator stake is verified.
- Added typed frontend service adapters for node operations, validator eligibility, validator provisioning, and persisted settings.
- Represented autonomous validator VPN enrollment in the provisioning checklist and blocked activation until backend enrollment returns a valid result.
- Paused Windows installer validation expectations while Windows installer builds remain commented out for future re-enablement.

## v17.0.0 - 2026-07-01

- Reworked **Sync Catch Up** into a live runtime catch-up request that calls `synergy_startSync`, keeps a running validator online, and reports long-running sync as still in progress instead of killing or restarting the node.
- Pins validator bootstrap peers to public sync sources only, including the relayer pair plus public history peers, so restored validators can catch up from large gaps without using legacy DNS or private/VPN-only validator endpoints.
- Bundles Testnet runtime `v17.0.0`, which exposes the live sync RPC and prefers public history sources during deep catch-up.

## v16.0.3 - 2026-06-29

- Removed the legacy mandatory chain-sync setup modal on Windows, macOS, and Linux; Jarvis now restores the archive-validator-produced validator-pruned snapshot and hands the operator directly to the dashboard.
- Validator start now enforces verified archive snapshot evidence, runs P2P speed-sync from the restored snapshot state to chain tip before launch, and refuses unsafe runtime start when that speed-sync fails.
- Added a non-blocking global validator speed-sync progress strip that remains visible across dashboard navigation and reports snapshot height, current height, verified target, remaining gap, and progress phase.

## v16.0.2 - 2026-06-29

- Fixed macOS and Windows validator provisioning so the desktop app creates the new validator appliance layout under the operator's user-writable control-panel directory instead of trying to create Linux's `/var/lib/synergy/validator` path.
- Linux validator provisioning continues to use `/var/lib/synergy/validator`, preserving the same appliance file structure used by Linux machines.

## v16.0.1 - 2026-06-29

- Fixed Jarvis validator setup so snapshot restore failures show the actual backend reason instead of collapsing into a generic restart message.
- Corrected snapshot progress handling so the modal transitions from **Downloading Snapshot** to **Applying Snapshot** with the apply progress starting from zero.
- Bundles Testnet runtime `v16.0.1`, which allows snapshot verification against the new validator appliance `state/store` layout instead of requiring the legacy `data` directory.

## v16.0.0 - 2026-06-29

- Replaced the desktop app icon across packaged Windows, Linux, and macOS installers, using the supplied PNG for Windows/Linux icon resources and the supplied macOS Icon Composer `.icon` package for macOS dynamic light/dark artwork.
- Updated in-app control panel branding to match the new desktop app icon.

## v15.0.8 - 2026-06-29

- Ships the public archive-validator snapshot catalog as the default validator bootstrap source, so new validators can restore `validator-pruned` snapshots without VPN-only archive access.
- Aligns Jarvis and the control-service runtime on the Linux validator appliance root `/var/lib/synergy/validator`, while storing snapshot catalog/cache files under the new `state/snapshots/validator-pruned` appliance path.
- Moves validator-pruned snapshot download and application into the Jarvis setup chat with live download/apply progress before handing the operator to the dashboard.
- Updated user-facing Node Control Panel onboarding and control workflows to remove legacy validator category language from ongoing operator messaging.
- Documentation now uses plain `validator` language and `preassigned validator package` phrasing for package-import restrictions and onboarding guidance.

## v15.0.1 - 2026-06-22

- Bundles Testnet runtime `v15.0.1`, which runs offline snapshot verification/restoration commands on an explicit large stack to avoid Windows stack overflows during validator-pruned snapshot verification.
- Keeps new public validators inside the setup sync gate after reload until archive-validator-produced validator-pruned snapshot restore evidence exists and peer speed sync is completed.
- Records verified setup-sync completion evidence before the control panel can leave the chain sync portion of validator setup.

## v15.0.0 - 2026-06-22

- Made archive-validator-produced `validator-pruned` snapshots the mandatory bootstrap source for new validators, with verified download/restore evidence followed by P2P speed sync and no full-chain RPC fallback.
- Added autonomous post-stake onboarding so an operator requests 50,000 SNRG funding, submits the stake in the control panel, and the validator proceeds through observation, shadowing, and activation gates without additional manual actions.
- Replaced fixed validator-count, quorum, and cluster assumptions with the six-validator Testnet inventory, dynamic two-thirds quorum, and balanced clusters that split only when at least two five-validator clusters can be maintained.
- Removed legacy DNS bootstrap endpoints and restricted preassigned validator setup packages to approved package-import flows.
- Pinned installer builds to Testnet runtime `v13.0.72`, which contains the matching snapshot, quorum, and validator-lifecycle runtime changes.

## v14.0.2 - 2026-06-06

- Corrected validator lifecycle and feature screens so they no longer infer active/voting/zero-stake placeholder data when RPC payloads are missing; live validator status now uses onboarding shadow evidence and local funding proof for submitted stake.
- Reorganized Node Details and Validator Lifecycle surfaces so P2P/topology data stays on the P2P screen, jail/quarantine/self-realignment cards only appear when relevant, and validator state focuses on the current lifecycle gate.
- Cleaned up the shared shell by removing redundant health/peer/status badges, adding an editable validator nickname, and surfacing a Connect Wallet entry for the Rewards withdrawal workflow.
- Reworked the Jarvis drawer with the Jarvis icon header, chat-style transcript, contextual operator responses, and animated typing indicators.

## v14.0.1 - 2026-06-06

- Updated the bundled Explorer backend installer dependencies to patched Fastify, Fastify plugin, YAML, fast-uri, and brace-expansion versions to clear the GitHub Dependabot alerts for the runtime backend package lock.
- Rebuilt the checked-in Explorer backend dependency bundle so the packaged installer payload no longer carries the vulnerable transitive packages.

## v14.0.0 - 2026-06-06

- Added verified archive-validator-produced snapshot restore for onboarding validators, including validator-pruned snapshot catalog selection, chunk/archive verification, runtime verifier evidence, and safer catch-up from restored state.
- Hardened new-validator onboarding evidence so activation remains blocked until trusted local-plus-relayer source-majority proof, closed duty-gate proof, and a complete zero-mismatch shadow epoch are present.
- Updated release packaging so Control Panel installer builds can bundle the trusted Testnet runtime ref independently of the control-panel tag while preserving shellcheck-safe workflow generation.
- Extended restored-validator startup handling and blocked unsafe RPC full-chain fallback against large restored chain state.

## v13.0.30 - 2026-06-04

- Added post-fork FN-DSA metadata throughout the Control Panel state, validator live status, generated `node.toml`, and Settings surfaces for chain `1264`, network `synergy-testnet-v3`, fork height `204216`, and fail-closed parser mode.
- Added a validator **Resync Time** control that runs platform-scoped time synchronization commands and writes local evidence for onboarding preflight.
- Added proof-only **Verify Onboarding** and mutation-scoped **Run Safe Onboarding** paths so operators can prove readiness without starting runtime, staking, or activating accidentally.
- Split staking and activation into explicit eligible actions; **Sync Catch Up** and safe onboarding no longer auto-activate validators.
- Promoted validator onboarding into Basic navigation and the validator top bar so new operators do not need Developer mode to find the flow.
- Added `synergy-control prove-onboarding --node-id <id>` for CLI dry-run onboarding evidence.
- Hardened new validator bootstrap generation with direct bootnode and seed-IP fallbacks alongside DNS entries, so onboarding can continue while seed DNS records are corrected.
- Added a dedicated macOS, Linux, and Windows installation plus new-validator onboarding guide covering dependencies, provisioning, time sync, seed registration, `50,000 SNRG` staking, activation, and final proof commands.

## v12.2.3 - 2026-05-17

- Added a guided Node Overview activation flow for validators, including Core team funding instructions for the validator `synv1...` address, balance detection, staking, and activation gating.
- Hardened validator activation preflight around canonical chain 1264 genesis, canonical local chain data, two-block sync tolerance, relayer peer visibility, seed registration, wallet readiness, and bonded stake.
- Added a bundled operational manifest and release validation for relayer-only public onboarding, including the canonical relayer-1 private address used by observer and release assets.

## v12.1.0 - 2026-05-13

- Added a dedicated Sync Catch Up workflow for validators that stops the runtime, runs fast chain sync, restarts, checks validator preflight, and rejoins consensus when checks pass.
- Surfaced Sync Catch Up on Dashboard and Node Details with block-gap status, step receipts, and operator repair buttons for failed preflight checks.
- Corrected validator sync control so validator nodes no longer skip offline fast-sync in favor of restart-only rejoin.

## v12.0.0 - 2026-05-13

- Rebuilt the post-setup control panel shell around Basic, Advanced, and gated Developer views with compact current-node status, visible Help access, floating Jarvis, and route compatibility redirects.
- Removed Node Slots from the configured-node experience and moved wallet, deposit, stake, unstake, and withdraw workflows out of Node Details into Rewards.
- Added distinct page compositions for Alerts, Identity/Security, Diagnostics, Configuration, and protocol/system screens, plus compact Settings cards with a collapsed Danger Zone.

## v11.0.0 - 2026-05-10

- Clarified Jarvis setup so normal validator provisioning creates the workspace directly on the validator machine and does not require importing a setup package first.
- Updated the help center and operator guide with the current validator sequence: provision, sync, seed-register, fund, stake, and activate.
- Replaced the mirrored feature-screen action sets with screen-specific runtime actions and corrected validator activation preflight readiness handling in the dashboard and node detail views.

## v10.1.8 - 2026-05-10

- Enabled activated validators to enter the consensus membership instead of being capped by the original fixed-validator release configuration.
- Hardened validator activation so a synced validator can start consensus after its activation transaction is applied, while preassigned validators skip the public join sync gate.
- Regenerated and validated the bundled Testnet runtime assets, setup packages, and operator guide for the validator funding, staking, and activation flow.

## v8.0.18 - 2026-04-14

- Aligned the bundled validator generator and runtime assets around the private WireGuard validator mesh so canonical setup packages and rendered validator configs stop drifting apart.
- Regenerated the bundled validator installers and workspace manifest from the updated mesh inventory, disabled public bootstrap dependencies in the validator plane, and kept the packaged setup files consistent with the desktop validator rollout path.
- Fixed the bundle-prep and validation path so a tagged release can regenerate fresh bundled assets and publish installers without failing its own manifest freshness checks.

## v8.0.0 - 2026-04-09

- Aligned the control-panel app version, bundled workspace manifest, and release tag so published installers report the same `v8.0.0` release line in-app and in release metadata.
- Re-enabled Windows installer production in the release workflow and switched bundled Testnet source selection to the current release tag instead of a stale hard-coded ref.
- Refreshed the Testnet dashboard and validator connectivity presentation around the current 5-validator topology, bootstrap-only infrastructure, and stricter peer identity requirements.

## v7.1.0 - 2026-04-08

- Fixed the developer-mode local peer list so weak inbound socket entries are merged into the canonical validator peer card instead of rendering as duplicate peers when the same validator is visible by both its public endpoint and an ephemeral incoming connection.
- Filled in validator identities for hostname-only peer entries by mapping known `genesisval*.synergy-network.io` hosts back to their configured validator addresses, so validator peers no longer show `Unknown` when the RPC payload has not yet populated `validator_address`.
- Added a validator runtime pill to peer cards that shows `Live`, `Syncing`, `Starting`, or `Offline`; the `Live` state now renders with an animated cyan/lime/blue/purple gradient glow to make block-producing validators immediately visible.

## v7.0.2 - 2026-04-08

- Fixed the control-service topology host selection so preassigned validators keep their public `genesisval*.synergy-network.io` identity for RPC/read paths while control-plane generation, SSH targeting, and installer rewrites continue to use `management_host`.
- Prevented topology refreshes from collapsing validator machine-management state onto the public validator DNS names, which was causing duplicate node generation and overload across the RPC, bootnode, and seed infrastructure after the hostname migration.
- Added regression tests covering the `genesisval1.synergy-network.io` plus `192.168.11.228` case to lock the public-host versus management-host split in place.

## v5.13.0 - 2026-04-04

- Advanced the bundled Testnet source pin to `v5.13.0-testnet-source`, which includes the runtime-root migration, canonical genesis refresh, and current validator/bootstrap assets used for the clean reinstall path.
- Hardened local node control so duplicate `start` actions now detect an already-running process from the installed `node.toml`, and regenerated every bundled installer `nodectl` script with the same live-PID safeguard.
- Fixed peer-list presentation by deduplicating repeated sessions that announce the same validator or public address, updated runtime-root documentation paths, and kept the control-service monitor/control-plane host fixtures aligned with the legacy overlay range we still migrate away from.

## v5.12.4 - 2026-04-03

- Advanced the bundled Testnet source pin to `v5.12.4-testnet-source`, which includes the P2P discovery fix that keeps bootnodes and other non-validator discovery peers connected even when they do not advertise a genesis hash in their status payload.
- Preserved the runtime-root launcher/runtime fix, the faster startup readiness probe, and the reduced monitor RPC timeouts already landed in the control panel release line.
- Rebuilt the installers so the packaged `synergy-testnet` binary matches the current top-level source used for genesis-validator operation.

## v5.12.3 - 2026-04-03

- Switched the Testnet release source pin from a raw commit SHA to the reachable top-level tag `v5.12.2-testnet-source`, which points to the same fixed source commit but can be fetched reliably by `actions/checkout`.
- Preserved the v5.12.2 source-graph fix that removed the stale top-level `node-control-panel` gitlink, along with the runtime-root and readiness-probe fixes already landed in the control panel.
- Re-ran the control-panel installer release against the tagged top-level source so checkout and binary bundling resolve from stable refs on every runner.

## v5.12.2 - 2026-04-03

- Advanced the Testnet release source pin to commit `c7aab0ef41a2f154869845b0579dc3d36a75c235`, which removes the stale `node-control-panel` gitlink from the top-level source tree so `actions/checkout` no longer fails during auth cleanup.
- Kept the runtime-root launcher fix, the runtime-root-aware node binary, the faster startup readiness probe, and the reduced monitor RPC timeouts from v5.12.1.
- Rebuilt the installer release on top of the corrected top-level source graph so the packaged control panel and packaged node now ship from the same fixed lineage.

## v5.12.1 - 2026-04-03

- Corrected the Testnet release source pin so installer builds now compile `synergy-testnet` from commit `476a159956eaeffe5d6f4cb4c1caf94156828716`, which includes the runtime-root detection fix required for validator workspaces launched outside the source checkout.
- Preserved the v5.12.0 control-service launcher fix that exports `SYNERGY_PROJECT_ROOT` and `SYNERGY_CONFIG_PATH`, while ensuring the bundled node binary now understands those runtime-root environment variables too.
- Disabled submodule cleanup for the pinned Testnet checkout in the release workflow so GitHub Actions no longer trips over the broken `node-control-panel` gitlink metadata during post-job cleanup.

## v5.12.0 - 2026-04-03

- Fixed Testnet node launches from generated validator workspaces by exporting `SYNERGY_PROJECT_ROOT` and `SYNERGY_CONFIG_PATH` into every control-service runner invocation, which stops the validator restart loop caused by runtime root detection failures.
- Added focused regression coverage for workspace-scoped runner environment propagation and strengthened the start-path test so it validates the local RPC readiness gate instead of depending on an ambient service on the default port.
- Regenerated the bundled testnet runtime assets and installer bundles for the repaired workspace launch flow.

## v5.11.3 - 2026-04-03

- Fixed Jarvis Genesis Setup so validator `setup-package.json` files remain package-driven from selection through import instead of dropping into a manual ceremony-role prompt when the package role should already be known.
- Hardened ceremony import so the control service can infer the role directly from the approved validator package when no manual role is supplied, while preserving the explicit bootstrap-bundle role path for legacy bootnode and seed archives.
- Kept the discovery-only bootnode genesis-hash handshake allowance verified in the testnet runtime and rebuilt the control-panel installers around the repaired Genesis Setup flow.

## v5.11.2 - 2026-04-02

- Completed the monitor/control-service rename from `vpn_ip` detection to machine-level `management_host` detection so the setup wizard, monitor dashboard, node page, and operator agent snapshot all use the same identity model.
- Fixed the headless control-service release build by shipping the matching monitor API and agent-health fields instead of a partial command rename.
- Regenerated the bundled `testnet/runtime` assets and installers for the repaired release tag.

## v5.11.1 - 2026-04-02

- Reworked Jarvis genesis setup so the ceremony flow starts with the assigned setup package JSON, derives the role from that package, and pauses on an explicit machine-specific port-forwarding confirmation before sending the operator to the dashboard.
- Fixed the Testnet node details tabs so shared runtime/network values are available across the wallet and connectivity views instead of throwing render-time errors when those tabs open.
- Added the developer-mode live peer list to the node-details Connectivity tab and reduced initial dashboard/detail latency by caching local state and parallelizing the control-service live-status network probes.

## v5.11.0 - 2026-04-02

- Added a Settings-level `Developer Mode` toggle and exposed the live peer list on the dashboard Connectivity tab when that mode is enabled.
- Refreshed the bundled testnet runtime defaults for genesis launch: removed the hard `max_validators = 4` ceiling while preserving `min_validators = 4`, and regenerated the runtime/genesis assets accordingly.
- Pinned the installer release workflow to the updated testnet source commit that includes real network vote collection, explicit equivocation evidence handling, rolling missed-vote jailing/slashing, and the current RPC/runtime fixes needed for fresh binaries.

## v5.10.5 - 2026-04-02

- Fixed validator crash loop on macOS arm64: the `synergy-testnet-macos-arm64` binary search was incorrectly taking priority over the fixed `synergy-testnet-darwin-arm64` binary. The control service binary search order now tries `darwin-arm64` first, with `macos-arm64` as a fallback only. The `macos-arm64` binary on disk has also been replaced with the fixed `darwin-arm64` build. This restored all 4 validators to active quorum (`qc_cumulative_weight: 4.0`).
- Removed confidential payout equation from node detail view: `payoutEquation` no longer renders in the Rewards Standard definition panel or any associated copy-block paragraphs.
- Dashboard overhaul across all tabs: replaced the 4-card status grid and verbose Network Overview panel with a compact inline status strip showing live network metrics. Stripped all non-data description text from Connectivity, Rewards, Files, and Chain tabs. Added copy-to-clipboard buttons next to node and wallet addresses. Added "Open Workspace" and "Open Logs" directory shortcuts to the Files tab.
- Settings page enhancements: added "Check for Updates" button with live status feedback wired to the Electron auto-updater bridge. Added "Refresh All Bootstrap" to re-fetch and rewrite `peers.toml` from live seed servers for all nodes in one action. Workspace Inventory now shows direct "Logs" and "Details →" links per node.
- Connectivity tab: removed redundant stat descriptions from SXCP cards; fallback discovery sequence now displayed inline as a single `A → B → C` chain instead of a two-column grid.

## v5.10.3 - 2026-04-01
- Bundled updated testnet node binaries (darwin-arm64, linux-amd64, windows-amd64) built from the mutex deadlock fix in `token.rs` and the seed-server registration fix in `networking.rs`.
- Redesigned the Settings page Operator Console button section: buttons are now grouped in compact inline rows with distinct color-coded group labels (Services, Connectivity, Processes, Logs) instead of large card layouts.
- Added new operator actions: Show Disk Usage, Flush DNS Cache, Find Zombie Processes, Kill Zombie Processes, Kill All Nodes, Tail Node Logs, Clear Log Files.

## v2.9.2 - 2026-03-08
- Updated the `synergy-testnet-agent` sidecar crate dependencies, including adding `reqwest` to support follow-on agent networking and sync work.
- Maintenance release with no large UI or workflow delta clearly exposed in the tag range.

## v2.8.3 - 2026-03-08
- Added placeholder lab surfaces for `Test Transactions` and `Let's Break Stuff`, built on a reusable `FutureLabPage` and new supporting styles.
- Expanded updater handling with version comparison helpers and Linux install-mode awareness.
- Refined monitor and backend integration around topology-aware node views and app update behavior.

## v2.8.1 - 2026-03-08
- Regenerated `runtime` installer bundles after topology changes across the testnet fleet.
- Updated per-node install/start scripts and binary status markers.
- Primarily a topology and installer refresh release.

## v2.8.0 - 2026-03-08
- Hardened fleet sync behavior and dashboard machine metadata handling.
- Fixed Windows installer refresh when a node binary is already running.
- Reworked `runtime` topology assets, including genesis data, node roles, hosts examples, installer configs, and cross-platform install scripts.

## v2.7.2 - 2026-03-07
- Fixed Windows node setup scripts and process launch behavior to avoid broken or stuck installs.
- Added stronger stop/restart cleanup in the testnet agent so orphaned node processes are killed before resets or restarts.
- Improved updater UX with app relaunch support and clearer Linux manual-update messaging.

## v2.7.1 - 2026-03-07
- Prevented setup freezes by offloading long-running agent and terminal commands and increasing timeouts for setup, start, and reset operations.
- Added fleet-control functions and resume logic so setup can infer the target machine from existing SSH bindings when VPN detection is unavailable.
- Cleaned up chain ID presentation so the dashboard shows the observed value directly instead of rewriting it.

## v2.6.11 - 2026-03-06
- Fixed Windows PowerShell command execution in the monitor terminal runner, including quoted-argument handling.
- Prevented partial installer rebuilds by making installer output paths configurable and tightening release preflight behavior.
- Reliability release focused on Windows setup and release-pipeline stability.

## v2.6.10 - 2026-03-06
- Split `synergy-testnet-agent` into a dedicated sidecar crate and updated sidecar builds to use the new manifest and target directory.
- Strengthened release asset generation by normalizing filenames, validating `latest.json`, URL-encoding asset names, and requiring updater signatures.
- Refined topology application and machine-control plumbing, including regenerated `hosts.env`, fallback node-address discovery, and remote-path normalization.
- Refreshed a large set of generated installer and sidecar artifacts as part of the release.

## v2.6.8 - 2026-03-06
- Added the machine agent used for fleet control.
- Added agent reachability visibility in the control panel.
- Clarified the difference between machines and nodes across inventory, tooling, and fleet-control flows.
- Various fixes and improvements around the fleet-control rollout.

## v2.6.4 - 2026-03-06
- Fixed Linux installer refresh failures caused by `ETXTBSY` when replacing in-use binaries.
- Maintenance release focused on installer-asset refresh reliability.

## v2.6.3 - 2026-03-06
- Fixed monitor startup recursion.
- Stability release for monitor boot and initialization.

## v2.6.2 - 2026-03-06
- Restored the macOS updater bundle target in the release pipeline, including special handling for Intel mac builds.
- Added missing workflow permissions to satisfy code-scanning and security requirements.

## v2.4.2 - 2026-03-04
- Updated `runtime` machine installer configs and validator allowlists in the node inventory.
- Temporarily disabled the in-app updater path and removed updater UI while signing and release configuration was being corrected.
- Simplified release workflow signing setup during that transition.

## v2.2.4 - 2026-03-04
- Maintenance/versioning release. The tag range does not show clear functional changes beyond version and package metadata updates.
- Various fixes and improvements.

## v2.0.7 - 2026-03-03
- Updated node inventory and orchestration scripts to better handle multiple logical nodes sharing a physical machine.
- Improved machine-level network generation so shared physical machines reuse the same machine-level identity.
- Added stale-process cleanup to remote stop, restart, and reset flows, and refreshed setup/operator UI around the updated topology.

## v2.0.6 - 2026-03-03
- Added explicit release versioning updates in the GitHub Actions workflow and release messaging.
- Fixed Windows multi-node stop handling by invoking `taskkill` during forced shutdown cleanup.
