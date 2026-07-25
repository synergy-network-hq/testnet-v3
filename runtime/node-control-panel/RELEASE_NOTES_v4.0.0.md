# Release Notes — v4.0.0

**Release date:** March 2026

---

## Overview

Release v4.0.0 upgrades the control panel from a remote-agent recovery tool into a fully packaged operator workstation. Desktop installers now bundle the `synergy-testnet-agent` sidecars needed for remote deployment, the node detail page can reinstall and restart the local agent without SSH keys when opened on the target machine, and the monitor experience has been redesigned around clearer metrics, faster per-node controls, and a more operator-focused interface.

Key outcomes:

- Release installers now carry the service-agent payloads required for deployment.
- Operators can repair agents locally from the affected machine.
- Live dashboard cards now expose actual average block time, throughput, agent reachability, and average RPC latency.
- The network monitor and top-level navigation have been reorganized to reduce friction during daily operations.

---

## Release Summary

| Field | Value |
|---|---|
| Version | v4.0.0 |
| Release Date | March 2026 |
| Product | Synergy Testnet Control Panel |
| Components | Electron Shell (Rust) • React Frontend • Agent Services • Release Packaging |
| Status | Major Release — Ready for Deployment |

---

## Change Log Summary

| Type | Area | Description |
|---|---|---|
| FEATURE | Release Pipeline | GitHub Actions now builds agent sidecars per target platform and bundles them into the shipped Electron installers. |
| FEATURE | Build Tooling | `scripts/build-sidecars.sh` now supports native, Linux, Windows, and `--all` sidecar builds with `cargo-zigbuild` guidance. |
| FEATURE | Agent Management | Node detail page can perform same-machine local agent reinstall and restart without SSH keys via `Update Local Agent`. |
| FIX | Agent Runtime | Local agent binary replacement is now atomic and autostart reload/restart paths are validated on launchd/systemd. |
| FEATURE | Monitoring | Dashboard snapshot now includes live average block time and throughput metrics derived from RPC node status and latest block data. |
| FEATURE | Dashboard UX | Network monitor summary cards, action layout, agent reachability, average RPC latency, auto-refresh placement, and row-level controls were redesigned. |
| FEATURE | Navigation | Header/footer status layout was reworked, the brand was recentered, route buttons were normalized into a two-row grid, `Settings` became `Operator Settings`, and lab/SXCP pages were retitled and refreshed. |
| FEATURE | Visual Design | The control panel now uses Sora as the primary UI typeface, denser stat cards, hover glow affordances, and a more consistent action-button system. |
| FIX | Sync and Reset | `sync_node` now routes cleanly through `nodectl sync` fallback, single-node reset triggers explorer reindex, and pre-start sync attempts are individually time-capped. |
| DOCS | Operations | Added `COMMANDS.md` / `COMMANDS.docx` operator reference documentation under `docs/reference/`. |

---

## 1. Release Packaging and Installer-Bundled Agents

The release pipeline now builds testnet-agent binaries ahead of the main Electron build and injects them into `binaries/` before installer creation. This means the shipped control panel installer carries the agent payloads required to deploy or refresh service agents on remote machines.

### Release workflow

A dedicated `build-agents` job was added to `.github/workflows/release.yml`. It produces Linux, macOS, and Windows sidecars as artifacts and the app-build job downloads them back into `binaries/` so Electron bundles them as resources.

### Sidecar build tooling

`scripts/build-sidecars.sh` was expanded from a single native build path into a release-oriented tool that supports native output, Linux cross-builds, Windows cross-builds, and a `--all` mode. The script now validates `cargo-zigbuild` installation correctly and gives explicit setup guidance for missing toolchains.

- Remote Linux deployment no longer depends on a developer remembering to hand-build the correct sidecar file.
- The release workflow guarantees that installers include the same agent binaries operators use for deployment.
- The node installer template also adds a per-attempt timeout around pre-start sync so a hung binary cannot stall the full sync loop indefinitely.

---

## 2. Local Agent Self-Update Without SSH Keys

v4.0.0 introduces a same-machine repair path for the testnet agent. When the control panel is opened on the same physical machine as the selected node, the node detail page now switches from a remote SSH deployment flow to a local self-update flow.

### Node detail behavior

The per-node `Update Agent` button now becomes `Update Local Agent` when the selected node belongs to the local physical machine. The control calls a new `monitor_update_local_agent` backend command, reinstalls the bundled agent binary from the control panel resources, and restarts the local runtime.

### Runtime hardening

Local binary installation now uses an atomic copy-and-rename flow to avoid partially replaced binaries. The autostart paths for launchd and systemd user services were tightened so reload, enable, and restart failures are surfaced explicitly instead of being silently ignored.

### Operational model change

The dashboard no longer exposes `Update All Agents` as a primary fleet action. The workflow now emphasizes updating the agent from the target machine itself when SSH-less recovery is the goal, while the existing orchestrator path remains available where remote deployment is still appropriate.

---

## 3. Monitor Dashboard and Navigation Overhaul

The monitor experience was substantially reorganized to surface network health faster and reduce click depth for common operator actions.

### Dashboard summary cards

The old `Total Nodes`-focused card strip was replaced with a compact summary grid showing Online, Offline, Syncing, Highest Block, Average Block Time, Throughput, Agent Reachability, and Average RPC Latency. Online/offline/syncing now display `X/total` ratios, the new performance cards are populated from live snapshot data rather than placeholder copy, and the cards use color-grouped borders to distinguish network-health categories at a glance.

### Table controls and visibility

The nodes table now includes an agent reachability column, wider spacing, centered headers, vertically aligned rows, and a `Controls` column with `Start`, `Stop`, and `Details` actions. Auto-refresh controls were moved beneath the table, and the fleet action toolbar was reorganized into a compact three-row control grid for faster access.

### Header and page naming

The top navigation was rebalanced around a centered brand lockup that remains visually fixed regardless of button position. The updater status now appears in the footer center, `Check for Updates` returned to the right-side route group, route buttons share a consistent two-row layout, `Settings` is now labeled `Operator Settings`, `Let's Break Stuff` was renamed `Resilience Drills`, and the SXCP page now uses the same future-lab presentation style as the other operational placeholder pages under the title `SXCP Operations Center`.

### Typography and action styling

The control panel now uses Sora as the primary UI typeface while keeping code and console surfaces monospace. Summary cards and global actions use thicker borders and hover glow states, and the fleet-level `Start All` / `Stop All` buttons now match the color system used by the per-node controls.

---

## 4. Sync, Reset, and Control Reliability Improvements

Several backend control paths were tightened so the monitor behaves more predictably during resets, sync operations, and offline-node recovery.

### `sync_node` fallback parity

The remote-node-orchestrator now exposes `sync_node` directly through `nodectl sync`, aligning the orchestrator layer with the service-agent action set. This gives the control plane a consistent path for syncing nodes that need block catch-up without starting them.

### Explorer reset parity

Single-node `reset_chain` operations now trigger the same explorer reindex notification that was previously limited to bulk resets. This reduces the chance that the explorer continues showing stale state after an individual machine is reset.

### Live metric collection

The monitor snapshot probe was extended to pull average block time from `synergy_getNodeStatus` and derive a network throughput estimate from latest-block transaction counts. The snapshot prefers head nodes when aggregating these values so stale nodes do not skew the cards.

---

## 5. Documentation and Operator Reference

A new `COMMANDS` reference was added under `docs/reference` in both Markdown and DOCX form. This gives operators a single place to review the supported command surface and reduces the need to infer control-plane behavior from scripts alone.

---

## 6. Files Changed

| File / Path | Change |
|---|---|
| `.github/workflows/release.yml` | New `build-agents` job; downloads bundled sidecars into `binaries/` before Electron release builds |
| `scripts/build-sidecars.sh` | Expanded native/cross-platform sidecar build workflow; improved `cargo-zigbuild` detection and release guidance |
| `scripts/testnet/build-node-installers.sh` | Added per-attempt timeout guard for pre-start sync attempts |
| `scripts/testnet/remote-node-orchestrator.sh` | Added `sync_node` -> `nodectl sync` mapping |
| `control-service/src/agent.rs` | Added `force_update_local_testnet_agent`, atomic binary replacement, and stronger local runtime restart/autostart handling |
| `control-service/src/monitor.rs` | Added local agent update command, live throughput/block-time metrics, sync fallback wiring, and single-reset explorer reindex hook |
| `src/components/NetworkMonitorNodePage.jsx` | Same-machine `Update Local Agent` behavior and messaging |
| `src/components/NetworkMonitorDashboard.jsx` | Dashboard redesign, live summary cards, per-row `Start`/`Stop`/`Details` controls, and auto-refresh/footer layout |
| `src/components/Layout.jsx` / `src/styles.css` | Header/status layout refresh and button standardization; `Operator Settings` rename |
| `src/components/SXCPDashboard.jsx` / `src/components/BreakStuffPage.jsx` | Retitled and restyled SXCP / Resilience Drills placeholder pages |
| `src/styles/monitor.css` | New summary-card system, live stat-card theming, row-control styling, hover glow states, and toolbar grid changes |
| `src/styles/typography.css` / `src/styles/synergy.css` | Switched primary UI typography to Sora while preserving monospace styling for logs and code surfaces |
| `docs/reference/COMMANDS.md` / `docs/reference/COMMANDS.docx` | Added operator command reference documentation |

---

## 7. Deployment & Upgrade Notes

The recommended operator workflow for v4.0.0 is now:

- Build or download installers from the tagged release so the desktop app includes the bundled agent sidecars.
- On a target machine, use the node detail page `Update Local Agent` action to refresh the local service without SSH keys when the control panel is running on that machine.
- Use the redesigned dashboard for fleet-level `Start`, `Stop`, `Restart`, `Sync All`, and `Reset Chain to Genesis` actions; use the row-level controls for single-node interventions.
- Refer to `COMMANDS.md` / `COMMANDS.docx` for the operator command reference.

Prepared by Synergy Protocol - Testnet Engineering from the changes between `v2.10.0` and the `v4.0.0` release candidate.
