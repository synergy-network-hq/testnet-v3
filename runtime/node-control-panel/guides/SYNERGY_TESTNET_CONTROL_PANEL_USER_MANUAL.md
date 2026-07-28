# Synergy Node Control Panel User Manual

Version: 2026-06-26
Applies to: Synergy Node Control Panel `15.0.5` or newer for Synergy TESTNET
Audience: node operators, validator operators, support staff, and advanced users

## Table Of Contents

1. [What The Control Panel Does](#what-the-control-panel-does)
2. [Important Safety Rules](#important-safety-rules)
3. [System Requirements](#system-requirements)
4. [Prerequisites Before Installation](#prerequisites-before-installation)
5. [Download The Installer](#download-the-installer)
6. [Install On Windows](#install-on-windows)
7. [Install On Ubuntu Or Debian Linux](#install-on-ubuntu-or-debian-linux)
8. [Install On macOS](#install-on-macos)
9. [Update The Control Panel](#update-the-control-panel)
10. [First Launch And Workspace Locations](#first-launch-and-workspace-locations)
11. [First-Time Setup With Jarvis](#first-time-setup-with-jarvis)
12. [Node Roles You Can Provision](#node-roles-you-can-provision)
13. [Main App Layout](#main-app-layout)
14. [View Modes](#view-modes)
15. [Dashboard](#dashboard)
16. [My Node Or Node Details](#my-node-or-node-details)
17. [Connections](#connections)
18. [Rewards And Stake](#rewards-and-stake)
19. [Activity And Logs](#activity-and-logs)
20. [Advanced Feature Pages](#advanced-feature-pages)
21. [Settings](#settings)
22. [Help Center](#help-center)
23. [Button And Action Reference](#button-and-action-reference)
24. [Operate A Validator](#operate-a-validator)
25. [Operate Service Nodes](#operate-service-nodes)
26. [Routine Operations](#routine-operations)
27. [Troubleshooting](#troubleshooting)
28. [Manual Verification Commands](#manual-verification-commands)
29. [Security And Key Handling](#security-and-key-handling)
30. [Glossary](#glossary)

## What The Control Panel Does

Synergy Node Control Panel is the desktop operator console for Synergy TESTNET. It installs and manages a local node workspace, starts and stops the bundled Testnet runtime, monitors sync and peer health, guides validator activation, exposes rewards and staking state, and keeps operator documentation inside the app.

The app includes three major parts:

- Electron desktop interface: the visible app, dashboard, Help Center, and controls.
- Local Rust `control-service`: the local machine service that performs setup, runtime control, log reads, readiness checks, staking calls, and diagnostics.
- Bundled Testnet assets: trusted Synergy node binaries, generated configs, canonical genesis, operational manifest, runtime installers, and this manual.

Normal operators do not need to install Node.js, Rust, Git, or the source repository. Those tools are only needed if you are building the Control Panel from source.

For the current post-fork new-validator setup flow, use the dedicated guide at `guides/CONTROL_PANEL_INSTALL_AND_NEW_VALIDATOR_ONBOARDING.md`. It is the launch-critical onboarding guide for macOS, Linux, and Windows operators.

Control Panel v2 adds the normal validator recovery path: Validator Onboarding, Validator Detail, Cluster Manager, State Sync, Archive Manager, and Incidents. These screens use structured control-service envelopes, disable unsafe actions, and write evidence for failed safety gates and confirmed mutations.

## Important Safety Rules

- Use the Control Panel as the single owner of the node it provisions. Do not also run a separate launchd, systemd, NSSM, or manually-started validator using the same workspace and ports.
- Never reuse one of the five preassigned bootstrap packages for a new public validator. A normal new validator must get its own locally generated `synv1...` validator address.
- Fund and stake the validator address only. Validator addresses start with `synv1`. Regular wallet addresses such as `synw...` are not validator identities.
- Do not activate a validator until it is synced near chain head, registered with seeds, funded, bonded, and passing Activation Preflight.
- The current six-validator testnet is not a fixed topology. Cluster count, quorum threshold, active count, and proposer eligibility come from the dynamic cluster registry.
- Operators must not edit validator config files, peer files, genesis, validator registries, consensus JSON/JSONL, or QC logs to recover a node.
- Archive snapshots must not be used for onboarding or repair until Archive Manager reports canonical state.
- State Sync replaces manual snapshot transfer. Vote-only rejoin and proposer probation replace unsafe immediate activation after repair.
- Do not re-enable archive services, deploy live changes, restart validators, or mutate live validator state unless a separate operational instruction explicitly authorizes it.
- Do not expose local admin, metrics, or RPC ports to the public internet unless the role specifically requires a public service surface.
- Use Clean Install Reset only when you intentionally want to remove this machine's local Testnet workspace. It does not erase remote validators or remote chain data.
- Keep identity passphrases, private keys, setup packages, and exported key material private.

## System Requirements

### Supported Operating Systems

| Platform | Minimum | Recommended |
| --- | --- | --- |
| Windows | Windows 10 64-bit | Windows 11 64-bit |
| Ubuntu/Debian Linux | Ubuntu 22.04 LTS or Debian-based equivalent | Ubuntu 24.04 LTS with a desktop session |
| macOS | macOS 12 Monterey | macOS 14 or newer |

Linux server installs need a graphical session for the desktop app. If you run Ubuntu Server without a desktop, install a desktop environment or use remote desktop access before trying to operate the GUI.

### CPU, Memory, And Disk

| Use case | Minimum | Recommended |
| --- | --- | --- |
| Open the app and inspect docs | 2 CPU cores, 4 GB RAM, 1 GB free disk | 4 CPU cores, 8 GB RAM, 5 GB free disk |
| Validator or public node | 4 CPU cores, 8 GB RAM, 25 GB free disk | 4-8 CPU cores, 16 GB RAM, 100 GB+ SSD |
| RPC gateway or indexer | 4 CPU cores, 8 GB RAM, 50 GB free disk | 8 CPU cores, 16-32 GB RAM, 250 GB+ SSD |
| Archive, analytics, or data availability roles | 4 CPU cores, 16 GB RAM, 100 GB free disk | 8+ CPU cores, 32 GB RAM, high-capacity SSD |

Disk needs grow with chain data, logs, snapshots, and indexer history. The app installer itself is much smaller than a live node workspace.

### Network Requirements

- Stable broadband connection.
- Stable public IP address or DNS name for public validators, RPC gateways, indexers, and other public service nodes.
- Ability to open inbound TCP ports for the selected role.
- Ability to reach Synergy public endpoints over HTTPS.
- Localhost traffic must be allowed between the app and the local control service.

### Default Ports

| Port | Purpose |
| --- | --- |
| `5620/tcp` | Bootnode P2P listener |
| `5621/tcp` | Seed service listener |
| `5622/tcp` | Default node P2P listener |
| `5640/tcp` | Default local JSON-RPC and gRPC port |
| `5660/tcp` | Default WebSocket port |
| `5680/tcp` | Default discovery port |
| `6030/tcp` | Default metrics port |
| `47891+` | Local control-service or agent port range |

RPC Gateway uses public-facing role ports `5623`, `5641`, `5661`, and `5681` in the canonical fleet profile. If Jarvis or the node config shows a different assigned port, use the assigned value shown by the app.

### Public TESTNET Endpoints

| Service | Endpoint |
| --- | --- |
| Core RPC | `https://testnet-core-rpc.synergy-network.io` |
| Core WebSocket | `wss://testnet-core-ws.synergy-network.io` |
| Testnet API | `https://testnet-api.synergy-network.io` |
| Explorer / Atlas | `https://testnet-explorer.synergy-network.io` |
| Atlas API | `https://testnet-atlas-api.synergy-network.io` |
| Chain ID | `1266` |
| Network ID | `synergy-testnet-v3` |
| Genesis height | `0` |
| Genesis parent height | `0` |
| Fork parent hash | `0000000000000000000000000000000000000000000000000000000000000000` |
| New consensus | `FN-DSA` |
| Consensus key algorithm | `ML-DSA-65` |
| Parser mode | `fail_closed` |
| Token | `SNRG` |

## Prerequisites Before Installation

### Required For All Platforms

- Administrator rights for installation and firewall changes.
- Internet access for downloads, update checks, public RPC, seed registration, and sync.
- Enough disk space for the node workspace.
- A stable machine hostname and clock. Keep automatic time synchronization enabled.
- Security software that allows the app, bundled Synergy runtime, and local control service to run.

### Required For Validators

- Public IP address or DNS name reachable from the internet.
- Inbound P2P port open, normally `5622/tcp`.
- Identity encryption passphrase with at least 8 characters.
- Validator address generated by Jarvis or imported from an approved package.
- Required stake: `50,000 SNRG`, equal to `50,000,000,000,000 nWei`.
- No other validator process using the same workspace, P2P port, or RPC port.

### Required For Linux

Install the common GUI and runtime libraries if your distribution does not install them automatically:

```bash
sudo apt-get update
sudo apt-get install -y \
  ca-certificates \
  curl \
  libgtk-3-0 \
  libwebkit2gtk-4.1-0 \
  libayatana-appindicator3-1 \
  librsvg2-2 \
  libssl3 \
  libfuse2
```

For firewall changes from the GUI, install and enable one firewall tool, usually `ufw`:

```bash
sudo apt-get install -y ufw
sudo ufw enable
```

If the app needs elevated firewall changes from a GUI session, Linux may show a `pkexec` or sudo prompt.

### Required For Windows

- PowerShell 5 or newer.
- Microsoft Visual C++ Redistributable x64 if Windows reports missing `VCRUNTIME140.dll` or similar runtime files.
- Windows Defender Firewall permission for the app and node runtime.
- Administrator PowerShell if you manually create firewall rules.

Example validator P2P firewall rule:

```powershell
New-NetFirewallRule `
  -DisplayName "Synergy Testnet P2P 5622" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 5622 `
  -Action Allow
```

### Required For macOS

- Apple Silicon or Intel Mac matching the published macOS installer artifact.
- Administrator password for first launch permission prompts and firewall changes.
- Network permission when macOS asks whether the app may accept incoming connections.
- Gatekeeper approval if macOS blocks a newly downloaded build.

### Optional Developer Or Source-Build Tools

These are not required for normal installation from the official release page. Install them only if you are building or testing the Control Panel from source:

- Node.js `20` and npm.
- Rust stable toolchain and Cargo.
- Git.
- Platform packaging tools:
  - Windows: Visual Studio Build Tools if native Node modules must compile.
  - Linux: `build-essential`, `libssl-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`, `patchelf`, and packaging tools.
  - macOS: Xcode Command Line Tools.
- Docker only if you are running the optional observability stack.

## Download The Installer

1. Open the official release page: `https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases`.
2. Open the latest published release.
3. Download the installer for your platform:
   - Windows: `.exe` installer.
   - Ubuntu/Debian Linux: `.deb` package, or `.AppImage` if published for your build.
   - macOS: `.dmg` installer matching your CPU architecture.
4. Keep the downloaded file until you confirm the app launches.

Do not download installers from screenshots, chat attachments, unknown mirrors, or old working folders. The official releases repository is the trusted installer source.

## Install On Windows

1. Download the `.exe` installer.
2. Double-click the installer.
3. If Windows shows SmartScreen, click **More info**, then **Run anyway** only if the file came from the official release page.
4. Choose whether to install for the current user or a custom folder.
5. Finish the installer.
6. Launch **Synergy Node Control Panel** from the Start menu.
7. If Windows Firewall prompts for access, allow private network access. For a public validator, add the required inbound P2P firewall rule.

### Windows Verification

After launch:

1. Open **Help** and confirm the manual loads.
2. Open **Settings** and confirm the app version appears.
3. Confirm the workspace path is under:

```text
%USERPROFILE%\.synergy-node-control-panel\monitor-workspace
```

Validator appliance roots for new Linux validators are normally under:

```text
/var/lib/synergy/validator
```

## Install On Ubuntu Or Debian Linux

1. Download the `.deb` package.
2. Open a terminal in the download folder.
3. Install the package:

```bash
sudo dpkg -i synergy-node-control-panel_*_amd64.deb
```

4. If dependency installation is incomplete, repair it:

```bash
sudo apt-get install -f
```

5. Launch from the application menu, or run:

```bash
synergy-node-control-panel
```

If you use the `.AppImage`, mark it executable first:

```bash
chmod +x Synergy*.AppImage
./Synergy*.AppImage
```

### Ubuntu Firewall Example

For a public validator using the default P2P port:

```bash
sudo ufw allow 5622/tcp
sudo ufw status numbered
```

For an RPC gateway, open the assigned public ports only if this machine is intentionally serving public RPC or WebSocket traffic.

### Linux Verification

After launch:

1. Open **Settings** and confirm the platform is detected as Linux.
2. Confirm the workspace path is under:

```bash
~/.synergy-node-control-panel/monitor-workspace
```

3. Confirm Linux validator appliances use the canonical root:

```bash
/var/lib/synergy/validator
```

## Install On macOS

1. Download the `.dmg` file.
2. Open the DMG.
3. Drag **Synergy Node Control Panel** into **Applications**.
4. Open **Applications** and launch the app.
5. If macOS blocks the app, open **System Settings > Privacy & Security** and choose **Open Anyway**.
6. Allow network and file prompts that are needed for node operation.

If Gatekeeper still blocks a trusted release from the official page, remove the quarantine flag:

```bash
sudo xattr -rd com.apple.quarantine "/Applications/Synergy Node Control Panel.app"
```

### macOS Verification

After launch:

1. Open **Settings** and confirm the machine and app version appear.
2. Confirm the monitor workspace is under:

```bash
~/.synergy-node-control-panel/monitor-workspace
```

3. Confirm validator appliance guidance points to the Linux validator root:

```bash
/var/lib/synergy/validator
```

## Update The Control Panel

The app checks for published updates while it is running.

Use the top-right update button:

- **Check updates**: asks the release channel whether a newer build exists.
- **Update `<version>`**: downloads the available update.
- **Downloading `<percent>%`**: update download is in progress.
- **Restart to update**: restarts the app and applies the downloaded update.

Platform notes:

- Windows updates normally upgrade in place through the installer.
- macOS updates may require replacing the app in Applications if automatic update is not available.
- Linux `.deb` installs may need the new `.deb` downloaded and installed manually:

```bash
sudo dpkg -i synergy-node-control-panel_*_amd64.deb
```

After any update, launch the app once so the local control service and bundled runtime assets are refreshed.

## First Launch And Workspace Locations

On launch, the app shows the splash screen, starts the local control service, extracts bundled resources, and checks whether this machine already has a configured node.

The monitor workspace stores app-owned operational data:

| Platform | Monitor workspace |
| --- | --- |
| Windows | `%USERPROFILE%\.synergy-node-control-panel\monitor-workspace` |
| Linux | `~/.synergy-node-control-panel/monitor-workspace` |
| macOS | `~/.synergy-node-control-panel/monitor-workspace` |

Validator appliance roots are stored separately:

| Platform | Validator appliance root |
| --- | --- |
| Windows | `/var/lib/synergy/validator` for Linux validator appliance provisioning |
| Linux | `/var/lib/synergy/validator` |
| macOS | `/var/lib/synergy/validator` for Linux validator appliance provisioning |

A typical validator appliance root contains:

```text
identity/
config/
state/store/
state/derived/
state/checkpoints/
state/snapshots/
state/quarantine/
evidence/
logs/
runtime/releases/
rollback/
```

Important appliance files include:

- `config/node.toml`: node role, ports, RPC, P2P, and consensus settings.
- `config/peers.toml`: bootstrap, seed, and dial target settings.
- `config/genesis.json`: canonical TESTNET genesis.
- `config/operational-manifest.json`: runtime manifest and operational assumptions.
- `identity/address.txt`: node or validator address.
- `identity/private.key` or encrypted identity files: local signing material.
- `state/store/`: primary local consensus state store.
- `evidence/`: setup receipts, package receipts, and monitoring registration artifacts.
- `logs/`: runtime and control-service logs.

## First-Time Setup With Jarvis

If no node exists on the machine, the app opens Jarvis setup automatically.

### Standard Setup Flow

1. Read the welcome messages.
2. Choose a node type from the dropdown.
3. Click **Choose**.
4. Review the detected computer details.
5. Click **Continue** or **Refresh Detection**.
6. For public roles, enter the public IP address or DNS name, or choose **Use Detected** if it is correct.
7. Review the private workspace folder.
8. Click **Use This Folder** or paste a custom folder path.
9. For validator setup, enter an identity encryption passphrase with at least 8 characters.
10. Click **Provision Node**.
11. Wait for Jarvis to create the workspace, write config files, create the node wallet, refresh peers, and apply port settings.
12. Let the sync gate start the runtime and check initial sync before regular operations.

### Jarvis Setup Controls

- **Choose**: confirms the selected node role.
- **Continue**: accepts the detected machine details.
- **Refresh Detection**: rescans hostname, home directory, OS, and network clues.
- **Use Detected**: uses the detected public IP address.
- **Use This Folder**: accepts the suggested workspace path.
- **Send**: sends typed text to Jarvis.
- **Provision Node**: creates the local node workspace and config.
- **Restart Setup**: restarts the setup conversation after an error.
- **Dashboard**, **Not now**, or **Later**: defers setup and opens the dashboard shell.
- **Open terminal** or **I need a terminal**: opens the setup terminal.
- **Developer data please**: shows additional setup diagnostics.

### Setup Packages And Genesis Imports

Most users should use standard Jarvis setup. A setup package is only for an approved import where the validator identity or role package was generated outside this machine.

Use a setup package only when the Synergy Core team explicitly assigned one to this machine. Do not import a preassigned bootstrap package for a new validator.

For imported validator packages, the Control Panel should be the single runtime owner. Stop any separate service using the same workspace or ports before starting the imported node.

## Node Roles You Can Provision

Jarvis exposes the current public operator roles:

| Role | What it does | Typical operator focus |
| --- | --- | --- |
| Validator Node | Participates in PoSy consensus after sync, funding, staking, and activation. | uptime, sync, peer visibility, preflight, stake, activation |
| Witness Node | Observes assigned events and emits attestations. | event ingestion, attestation success, receipt integrity |
| Data-Availability Node | Stores and serves proof-complete blobs. | storage capacity, proof availability, retention |
| RPC Gateway Node | Publishes read access to the chain without signing authority. | request latency, upstream health, rate limits |
| Indexer & Explorer Node | Indexes chain data for Atlas/explorer and query APIs. | ingest lag, reorg recovery, query performance |
| Archive Validator Node | Maintains full history, proofs, and snapshots. | disk health, proof generation, snapshot freshness |
| Audit Validator Node | Observes consensus behavior and emits audit receipts. | alert latency, receipt fidelity, anomaly detection |
| Governance Auditor Node | Reviews governance artifacts without execution authority. | proposal audit, signed review receipts |
| Analytics & Simulation Node | Runs replayable analytics and simulation workloads. | CPU/RAM, replay success, job throughput |
| Observer / Light Node | Verifies headers and proofs with minimal state. | proof checks, header verification, low storage footprint |

Some internal roles may exist in source code but remain hidden from the standard setup flow. Use only the roles Jarvis shows unless the Synergy Core team gives you specific instructions.

## Main App Layout

### Sidebar

The left sidebar contains:

- Synergy brand banner.
- **Current Node** card with node label, runtime health, sync gap, peer count, and **Open Node**.
- Navigation groups for the current view mode.
- **Views** mode switcher.

### Top Bar

The top bar shows:

- Environment: should show TESTNET.
- Selected Node.
- Health.
- Peer count.
- **Settings** icon.
- **Help** icon.
- Update button.
- **Rewards** shortcut.

### Floating Jarvis Button

The floating Jarvis button opens the assistant drawer. Jarvis can route you to pages, explain the current view, and warn when a requested action is risky. Destructive or state-changing actions are performed through page controls and confirmations, not hidden chat commands.

### Developer Terminal Dock

Developer view exposes the terminal dock for operators who need shell and RPC work. Use it only if you understand the commands you are running. The normal dashboard controls are safer for routine actions.

## View Modes

The Control Panel has three operator modes.

| Mode | Best for | What changes |
| --- | --- | --- |
| Basic | non-technical or routine operators | plain-language health, fewer controls, next-step guidance |
| Advanced | experienced node operators | more metrics, topology, logs, readiness, and action controls |
| Developer | engineers and incident responders | raw payloads, config inspectors, diagnostics, developer-only pages |

Developer mode is hidden by default. Enable it from **Settings > Operator Experience > Enable Developer View**. The app asks for confirmation because Developer mode exposes raw diagnostics, configuration, and advanced node operations.

## Dashboard

The Dashboard is the main operating screen.

### Basic Dashboard

Use Basic Dashboard to answer:

- Is my node online?
- Is it keeping up?
- Does it have peers?
- Are there warnings?
- What should I do next?

Important controls:

- **Refresh**: reloads the current live snapshot.
- Primary health action:
  - **Start node** if the node is stopped.
  - **Sync Catch Up** if the node is far behind.
  - **Reconnect** if the node is running but needs peer refresh.
- Time chips **30m**, **1h**, **6h**, **24h**: change chart windows.
- **Open Connections**: opens peer topology.

### Advanced Dashboard

Use Advanced Dashboard to compare node health, peer count, sync lag, public RPC state, action history, topology, and recent warnings.

Important controls:

- Node chips: switch between provisioned nodes if more than one exists.
- **Reconnect peers**: refreshes seed registration and peer routing.
- **Open workspace**: opens the node workspace folder.
- **Open logs**: opens the logs view.
- **Open Connectivity**: opens detailed topology.
- **Boost peers**: asks the runtime to improve peer/sync posture.

### Developer Dashboard

Developer Dashboard adds dense telemetry, raw inspectors, action audit, subsystem health, log pipeline state, and workspace/log folder shortcuts.

Use it during incidents when two surfaces disagree, for example when the dashboard says a node is online but local RPC or logs disagree.

## My Node Or Node Details

The Node Details page is the main runtime control surface for the selected node.

### Runtime Controls

- **Start**: starts the local Synergy runtime for this workspace.
- **Stop**: stops the runtime.
- **Restart**: stops and starts the runtime.
- **Bootstrap / reconnect**: refreshes peers, re-registers with seeds, restarts, and rejoins the network path.
- **Re-register**: refreshes seed server registration.
- **Sync Catch Up**: runs catch-up and rejoin logic for a node that is behind.
- **Resync Time**: runs the platform time synchronization command and writes evidence under the workspace logs.
- **Preflight** or **Activation Preflight**: runs validator readiness checks.
- **Validator Lifecycle**: opens the validator lifecycle feature page.
- **Rewards** or **Rewards Ledger**: opens wallet, stake, and rewards.
- **Open logs** or **Tail logs**: opens the workspace log folder.
- **Open workspace**: opens the workspace folder.

### Validator Activation Guide

For validator nodes, the page shows a step-by-step activation guide:

1. Verify canonical chain `1266`.
2. Verify network `synergy-testnet-v3`, genesis height `0`, parent hash `0000000000000000000000000000000000000000000000000000000000000000`, parser mode `fail_closed`, and Testnet-v3 ML-DSA-65 consensus.
3. Sync through relayers and register discovery.
4. Request Core team funding for the validator address.
5. Stake the received SNRG.
6. Activate at the safe gate.

Important controls:

- **Run Preflight**: checks whether activation is safe.
- **Sync Catch Up**: catches up if the node is behind.
- **Re-register**: refreshes seed registration.
- **Copy Address**: copies the validator `synv1...` address for funding.
- **Check Balance** or **Refresh Balance**: re-checks funding.
- **Stake Validator**: bonds `50,000 SNRG` from the validator address.
- **Activate Validator**: submits validator activation after all checks pass.
- **Open Rewards Ledger**: opens the economics page.
- **Refresh Activation State**: reloads activation status.

### Readiness And Identity

Node Details also shows:

- role and runtime status
- public host
- node address
- workspace root
- config paths
- peer topology
- readiness checklist
- recent action receipts
- raw config comparison in Developer mode

## Connections

Connections shows peer and bootstrap health.

### Basic Connections

Use Basic Connections to see whether the node has enough peers to stay healthy.

Important controls:

- **Refresh**: reloads the live status.
- **Reconnect peers**: asks the node to rebuild peer connectivity.

### Advanced Connections

Use Advanced Connections for regional peer visibility, live peer table, bootnode status, and selected peer details.

Important controls:

- Region chips: filter the topology by region.
- **Export peer snapshot**: copies the current peer topology JSON.
- **Refresh topology**: refreshes seed registration and topology.
- Globe or table selection: selects a peer and opens its details.

### Developer Connections

Developer Connections adds raw peer session tables, logical graph, warning stream, and seed/bootstrap inspector.

Important controls:

- **Reset view**: clears the region filter.
- **Copy peer snapshot JSON**: copies raw peer topology data.

## Rewards And Stake

Rewards + Stake is the economics page for validator balances, staking, reward history, and payout workflows.

### Common Controls

- **Refresh State**: refreshes node and rewards data.
- **Node Details**: returns to the selected node details page.
- **Export Raw Data** or **Export Snapshot**: saves a JSON file containing the current reward payload and node context.
- **Connect Wallet** or **Update Wallet**: stores the wallet address used for withdrawal destination workflows.
- **Copy Deposit Address**: copies the validator/node deposit address.
- **Stake**: stakes the amount in the Stake SNRG field.
- **Unstake**: submits an unstake request for the amount in the Unstake SNRG field.
- **Withdraw**: transfers validator tokens to the connected wallet address.

### Stake Fields

- **Wallet address**: payout or withdrawal destination.
- **Stake SNRG**: whole-number stake amount. Default is `50000`.
- **Unstake SNRG**: whole-number amount to unbond.
- **Withdraw SNRG**: whole-number amount to transfer after a wallet is connected.

Use Node Details **Stake Validator** for the guided validator activation path. Use Rewards + Stake for ongoing stake, unstake, withdraw, and reward inspection.

## Activity And Logs

Activity and Logs show interpreted events, source logs, filters, and developer streams.

### Basic Activity

Basic mode summarizes important moments in plain language and hides raw paths until requested.

Important controls:

- **Show Technical Details**: reveals more raw event context.
- **Open Node**: opens Node Details for the selected node.
- **Open Activity** links from other pages route here when a warning needs context.

### Advanced Logs

Advanced mode adds severity, subsystem, and time filters.

Important controls:

- Severity chips: filter by log severity.
- Subsystem chips: filter by source area.
- Time chips: filter by recent window.
- **Copy Filtered Logs**: copies the visible filtered log set.
- **Open Source**: opens a selected log source file when available.
- **Open Logs Folder**: opens the workspace logs folder.
- **Clear Selection**: clears the selected timeline row.

### Developer Logs

Developer mode adds live stream controls.

Important controls:

- **Pause stream**: stops live auto-updates.
- **Auto scroll**: toggles automatic scroll-to-bottom.
- **Bookmark**: marks the selected stream item.
- **Copy line**: copies the selected log line.

## Advanced Feature Pages

Advanced and Developer navigation exposes feature-specific pages. Each page has **Refresh** in the header and action buttons in the page body.

### Alerts

Shows operator incidents generated from logs, readiness checks, and RPC health.

Actions:

- **Refresh Live State**
- **Run Readiness Check**
- **Inspect Recent Logs**

### Validator Lifecycle

Shows validator activation readiness, performance, validator RPC data, and safe lifecycle controls.

Actions:

- **Activation Preflight**
- **Sync Catch Up**
- **Activate Validator**
- **Refresh Seeds**

### Identity + Security

Shows identity files, key presence, slashing status, and safety guardrails.

Actions:

- **Run Readiness Check**
- **Inspect Recent Logs**
- **Refresh Live State**

### Identity + Keys

Developer-only page for raw identity metadata, key path inventory, and validator address proofs.

Actions:

- **Run Readiness Check**
- **Activation Preflight**
- **Inspect Recent Logs**

### Consensus

Shows block validation, validator activity, sync status, latest block, and finality evidence.

Actions:

- **Refresh Live State**
- **Run Readiness Check**
- **Refresh Seeds**
- **Sync Catch Up**

### DAG Explorer

Shows recent block graph, parent links, vertices, certificates, and convergence signals.

Actions:

- **Refresh Live State**
- **Inspect Recent Logs**
- **Boost Sync**

### Transactions

Shows pending transactions, recent block transactions, gas price, and transaction RPC probes.

Actions:

- **Inspect Recent Logs**
- **Refresh Live State**
- **Run Readiness Check**

### Storage + Snapshots

Shows workspace size, logs footprint, chain data footprint, disk free space, and storage sections.

Actions:

- **Refresh Live State**
- **Inspect Recent Logs**
- **Open Settings**

### API/RPC

Shows the selected node JSON-RPC endpoint, method probe status, latency, and chain ID.

Actions:

- **Refresh Live State**
- **Run Readiness Check**
- **Inspect Recent Logs**

### Maintenance

Shows controlled repair actions tied to live runtime state.

Actions:

- **Restart Runtime**
- **Sync Catch Up**
- **Rejoin Network**
- **Boost Sync**
- **Stop Node**

### Diagnostics

Developer-only page for process, listener, disk, RPC, bootstrap, log, and config checks.

Actions:

- **Refresh Live State**
- **Inspect Recent Logs**
- **Run Readiness Check**

### Configuration

Developer-only page for actual `node.toml`, `peers.toml`, `node.env`, genesis, and runtime manifest data.

Actions:

- **Refresh Live State**
- **Run Readiness Check**
- **Inspect Recent Logs**

## Settings

Settings is the local maintenance page.

### General Preferences

Shows:

- app name and version
- environment
- chain ID
- machine hostname
- operating system

### Operator Experience

Controls Developer View.

- **Enable Developer View**: unlocks Developer navigation and raw diagnostics after confirmation.
- **Disable Developer View**: hides Developer navigation.
- **Cancel**: closes the Developer View confirmation.

### App Updates

- **Check for Updates**: starts an update check for the installed version.

The top bar update button performs the actual update/download/restart flow.

### Workspace + Local Data

Shows the local Testnet workspace root, number of provisioned nodes, and bootnode status.

- **Open Workspace** or **Open Folder**: opens the local Testnet workspace root.

### Diagnostics Shortcuts

- **Open Diagnostics**: opens the Diagnostics page.
- **Open Help**: opens this manual.

### Danger Zone

The Danger Zone contains **Clean Install Reset**.

Use it only when you want to remove this machine's local Testnet data and start fresh.

1. Expand **Destructive Local Actions**.
2. Read the warning.
3. Type `ERASE`.
4. Click the platform-specific erase button.

Clean Install Reset stops local Synergy processes and removes this machine's local Testnet workspace. It does not erase remote validators, remote chain data, or public TESTNET state.

## Help Center

Help renders this bundled manual from:

```text
guides/SYNERGY_TESTNET_CONTROL_PANEL_USER_MANUAL.md
```

Important controls:

- **Open Dashboard**: returns to the main dashboard.
- **Open Atlas**: opens the public explorer.
- **Reload Manual**: reloads the bundled manual from the local workspace.
- Section chips: jump to manual sections.

If Help cannot load the manual, close and reopen the app so the monitor workspace and bundled resources are re-extracted.

## Button And Action Reference

| Button or action | Where it appears | What it does | Use when |
| --- | --- | --- | --- |
| Start | Dashboard, Node Details, Maintenance | Starts the selected node runtime. | Node is stopped and workspace is valid. |
| Stop | Node Details, Maintenance | Stops the selected node runtime. | You need maintenance or safe shutdown. |
| Restart | Node Details | Stops then starts the selected runtime. | Runtime is stale, hung, or config changed. |
| Restart Runtime | Maintenance | Same intent as Restart from the maintenance page. | You are in maintenance mode. |
| Reconnect | Dashboard | Refreshes seed registration for the selected node. | Node is online but peers are thin. |
| Bootstrap / reconnect | Node Details | Refreshes bootstrap config, re-registers with seeds, restarts, and rejoins. | Node has no peers or is behind. |
| Rejoin Network | Maintenance | Runs rejoin flow from the maintenance page. | Peer state needs a fuller rebuild. |
| Re-register | Node Details | Registers this node with seed services. | Seed registration check is failing. |
| Refresh Seeds | Feature pages | Runs the seed registration refresh. | Feature page reports poor discovery. |
| Mesh Reconnect | Node Details | Generic validator-recovery action. Restarts networking and captures mesh/qRPC evidence before and after reconnect. | Peer mesh is unstable during validator recovery and evidence is required. |
| State Diagnostics | Node Details | Generic validator-recovery triage (state files, qRPC snapshot, consensus checks) without mutating node state. | Gather recovery evidence before any mutable repair action. |
| Sync Catch Up | Dashboard, Node Details, Validator Lifecycle, Maintenance | Runs catch-up and rejoin logic. | Sync gap is high or node is behind. |
| Chain-Body Repair | Node Details | Generic validator-recovery mutation that repairs committed chain body and records repair evidence. | Use only for declared chain-body corruption recovery paths after dry-run diagnostics. |
| Resync Time | Feature pages, Validator Lifecycle | Runs the OS time sync command and saves evidence under workspace logs. | Before provisioning, before activation, or after clock-skew warnings. |
| Boost Sync | Feature pages, Dashboard tools | Boosts peer/sync posture. | Peer set is thin or sync is slow. |
| Preflight / Activation Preflight | Node Details, Validator Lifecycle | Runs validator activation checks. | Before staking or activation. |
| Copy Address | Validator activation guide | Copies validator `synv1...` address. | Requesting Core team funding. |
| Stake Validator | Validator activation guide | Bonds the required validator stake. | Funding is visible and preflight allows staking. |
| Activate Validator | Validator activation guide, Validator Lifecycle | Submits activation transaction. | All activation checks pass. |
| Refresh / Refresh State / Refresh Live State | Most pages | Reloads live app and runtime state. | Data looks stale. |
| Open workspace | Dashboard, Node Details, Settings | Opens the workspace folder. | You need files, logs, or config. |
| Open logs / Open Logs Folder | Dashboard, Node Details, Logs | Opens logs or the logs view. | You need runtime evidence. |
| Export peer snapshot | Connections | Copies peer topology JSON. | Sharing topology evidence. |
| Export Raw Data | Rewards | Saves reward payload JSON. | Preserving economics evidence. |
| Connect Wallet | Rewards | Stores a payout or withdrawal address. | Preparing withdraw workflow. |
| Stake | Rewards | Stakes a whole-number SNRG amount. | Managing ongoing stake. |
| Unstake | Rewards | Starts unstaking a whole-number SNRG amount. | Reducing bonded position. |
| Withdraw | Rewards | Transfers validator tokens to connected wallet. | Moving funds after wallet connection. |
| Enable Developer View | Settings | Unlocks Developer navigation. | You need raw diagnostics. |
| Erase Local Node Data | Settings Danger Zone | Removes local Testnet workspace after typing `ERASE`. | Clean reinstall on this machine. |

## Operate A Validator

### New Validator Workflow

1. Install the current Control Panel on the machine that will run the validator.
2. Launch the app once so the local control service starts.
3. In Jarvis setup, choose **Validator Node**.
4. Confirm the machine details.
5. Enter the public IP address or DNS name peers can reach.
6. Accept or customize the workspace folder.
7. Enter an identity encryption passphrase.
8. Click **Provision Node**.
9. Open **Onboarding** from the Basic sidebar or validator top bar.
10. Click **Verify Onboarding**. This is proof-only and does not start the runtime, resync time, restore snapshots, stake, or activate.
11. Review the proof and confirm the address starts with `synv1`.
12. Confirm the generated workspace uses chain `1266`, network `synergy-testnet-v3`, genesis height `0`, parent hash `0000000000000000000000000000000000000000000000000000000000000000`, consensus `ML-DSA-65`, consensus key algorithm `ML-DSA-65`, and parser mode `fail_closed`.
13. Click **Run Safe Onboarding** when the proof shows only retryable start, seed, snapshot, or catch-up work remains.
14. Wait for runtime health to show running.
15. Click **Bootstrap / reconnect** if peer count is low.
16. Click **Sync Catch Up** if sync lag is high.
17. Click **Re-register** if seed registration is failing.
18. Wait until sync lag is `2` blocks or less.
19. Click **Activation Preflight**.
20. Use **Copy Address** and request `50,000 SNRG` funding to the validator `synv1...` address.
21. After funding appears, click **Stake Validator**.
22. Run **Activation Preflight** again.
23. Confirm source-majority proof uses at least `3` trusted non-public-RPC sources.
24. Confirm a full shadow epoch passed with at least `1,000` observed blocks, `0` mismatches, and `0` missed observations.
25. Confirm duty gates remained closed: voting, proposing, QC aggregation, quorum counting, proposer scheduling, canonical-source service, and real vote signing must all be disabled before activation.
26. Click **Activate Validator** only after preflight and all activation-policy evidence gates pass.
27. Keep the node running and monitor Validator Lifecycle, Rewards + Stake, Connections, and Logs.

### Autonomous Onboarding And Validator States

The Control Panel is designed to run new-validator onboarding as a guarded local workflow. It writes the workspace, generates FN-DSA validator identity material, records evidence, registers bootstrap discovery, checks readiness, prepares eligible actions, and blocks unsafe signing. **Verify Onboarding** is proof-only. **Run Safe Onboarding** may start, register, restore, and catch up, but staking and activation require the explicit **Stake Validator** and **Activate Validator** buttons. The operator still owns the public endpoint, passphrase, funding, and final approvals.

| State or phase | What it means | Operator action |
| --- | --- | --- |
| `VERIFY_ONLY` | Dry-run onboarding evidence was produced without mutating runtime, stake, or activation. | Review blockers, then run safe onboarding only when the proof is clean. |
| `REGISTERED` | The validator identity and local workspace exist. | Confirm the validator address starts with `synv1`. |
| `KEY_BOUND` | FN-DSA identity and signing material are present. | Protect the workspace and do not replace key files. |
| `STAKE_REQUIRED` | The validator needs liquid or bonded SNRG. | Fund the validator address with at least `50,000 SNRG`. |
| `STAKE_SUBMITTED` | Stake was submitted. | Wait for inclusion and refresh preflight. |
| `STAKE_CONFIRMED` | `50,000 SNRG` is bonded or more. | Continue sync, shadow, and activation gates. |
| `SYNCING` | The validator is behind public chain head. | Keep it running and use **State Sync** when repair evidence is required. |
| `SNAPSHOT_VERIFIED` | A trusted snapshot/catalog entry passed canonical verification. | Let Archive Manager and State Sync use the verified source; do not copy arbitrary chain data. |
| `REPLAYING` | The runtime is replaying canonical state after repair. | Wait until replay completes and preserve the repair receipt. |
| `VOTE_ONLY` | The validator can vote after repair but proposer duties remain disabled. | Keep it online until proposer probation becomes eligible. |
| `PROPOSER_PROBATION` | The validator is proving proposer safety under observation. | Wait for probation evidence before activation. |
| `READY` | Preflight checks are passing. | Stake or activate, depending on the remaining gate. |
| `PENDING_ACTIVATION` | Activation is submitted or waiting for the deterministic epoch boundary. | Keep the node online. |
| `ACTIVE` | Validator is participating in consensus. | Monitor uptime, peers, sync, rewards, and logs. |
| `QUARANTINED` | Safety logic disabled consensus duties because chain state or evidence needs reconciliation. | Use Archive Manager, State Sync, vote-only rejoin, and proposer probation before activation. |
| `FAILED_CLOSED` | A consensus-critical check failed. | Do not bypass. Fix the failed check and rerun **Activation Preflight**. |

State Sync, generic validator-recovery triage, mesh reconnect, chain-body repair, proposer probation, and activation are separate phases.

**State Diagnostics** runs read-only triage across state files, consensus diagnostics, and live qRPC checks for recovery evidence.

**Mesh Reconnect** is a generic validator-recovery action that collects evidence around mesh and qRPC state before and after a service/network reconnect.

**Chain-Body Repair** is a generic validator-recovery mutation that runs committed-chain-body repair logic and writes an evidence report. The control panel requires explicit confirmation before it executes.

**State Sync** should be used to show source peers, quorum agreement, repair range, repair reason, estimated download, mutation summary, backup path, dry-run result, and repair receipt before any mutation is allowed.

Only after recovery steps complete should the validator rejoin as vote-only, complete proposer probation, and only then proceed to activation when all preflight gates pass.

For a validator already in vote-only recovery, use **Promote Vote-only** from the node detail page's role-specific operations. Enter the vote-only rejoin height from the recovery proof when prompted. The Control Panel calls the workbook-backed `validator-appliance-recovery.sh wait-promote-vote-only-to-active` helper and the runtime still fails closed unless the public probation height, committed-QC proof, block hash proof, and vote-lock checks pass.

### Validator Preflight Checks

Activation Preflight checks:

- validator role
- canonical `synv1...` validator address
- canonical workspace genesis
- canonical chain state
- chain ID `1266`
- network ID `synergy-testnet-v3`
- genesis height `0`
- parent hash `0000000000000000000000000000000000000000000000000000000000000000`
- consensus `ML-DSA-65`
- validator key algorithm `FN-DSA-1024`
- parser mode `fail_closed`
- public P2P endpoint
- local RPC readiness
- local signing key
- runtime wallet loaded
- sync within the accepted gap
- relayer peers visible
- seed registration
- wallet funding
- bonded stake

Do not bypass failed checks. Fail-closed behavior is intentional: if chain metadata, fork metadata, key material, parser mode, local chain state, runtime wallet import, or signing readiness is wrong, the app must block staking or activation instead of letting the validator sign on unsafe state. Fix the failed condition and run preflight again.

### Confirm Validator Address

On Linux:

```bash
cat /var/lib/synergy/validator/identity/address.txt
```

On macOS or Windows, use the same Linux validator appliance root when inspecting a Linux validator host:

```bash
cat /var/lib/synergy/validator/identity/address.txt
```

The address must start with `synv1`.

## Operate Service Nodes

### RPC Gateway

Use RPC Gateway for public read access. It should not hold validator signing authority.

Check:

- public RPC port and WebSocket port match the assigned role config
- upstream relayers are healthy
- admin and metrics surfaces are private
- public DNS and TLS point to the intended host
- API/RPC page probes pass

### Indexer & Explorer

Use Indexer & Explorer for Atlas/explorer data.

Check:

- indexer ingest is running
- query API is reachable
- ingest lag is acceptable
- reorg-aware mode is enabled in the role profile
- Atlas or explorer pages show current chain data

### Observer / Light Node

Use Observer for read-only proof and header verification.

Check:

- proof checks pass
- header verification is current
- storage growth remains minimal
- no signing authority is present

### Archive, Data Availability, And Analytics Roles

These roles need more disk, CPU, or memory than a basic node.

Check:

- disk free space
- workspace storage trends
- log growth
- proof or job success
- snapshot freshness where applicable

## Routine Operations

### Daily Operator Checklist

1. Open Dashboard.
2. Confirm runtime is online.
3. Confirm sync gap is near zero.
4. Confirm peer count is healthy.
5. Open Connections if peer count is low.
6. Open Activity or Logs if warnings are present.
7. For validators, open Rewards + Stake and confirm participation state.
8. Run Activation Preflight only when onboarding or troubleshooting validator activation.

### Before Restarting A Node

1. Check Dashboard health and recent warnings.
2. Open Activity or Logs.
3. If the node is a validator, open State Sync, Cluster Manager, Archive Manager, and Incidents first.
4. Confirm no active repair, onboarding, archive verification, assignment, or activation operation is already running.
5. Use **Restart** only for a stale or hung local process, not as the primary recovery path.
6. Wait for local RPC to return.
7. Check sync gap, peers, lifecycle state, and any vote-only or proposer-probation gate after restart.

### Before Updating The App

1. Note the current app version in Settings.
2. Confirm node state is stable.
3. Download or apply the update.
4. Relaunch the app.
5. Confirm the new version in Settings.
6. Confirm the node is still running from the updated app.
7. Check for stale or deleted old processes if troubleshooting a Linux host.

### Before Clean Install Reset

1. Confirm this is the correct machine.
2. Export or preserve any logs needed for support.
3. Confirm you do not need local chain state.
4. Stop the node.
5. Use Settings Danger Zone.
6. Type `ERASE`.
7. Confirm the local workspace is removed.
8. Relaunch and run setup again.

## Troubleshooting

### App Does Not Launch On Windows

Symptoms:

- SmartScreen warning.
- Missing `VCRUNTIME140.dll`.
- App opens then closes.

Fix:

1. Confirm the installer came from the official release page.
2. For SmartScreen, use **More info > Run anyway**.
3. Install Microsoft Visual C++ Redistributable x64 if a runtime DLL is missing.
4. Check antivirus quarantine.
5. Reinstall the latest `.exe`.

### App Does Not Launch On Linux

Symptoms:

- App does nothing after click.
- Terminal reports missing shared libraries.
- AppImage will not execute.

Fix:

1. Install Linux prerequisites from this manual.
2. For `.deb`, run `sudo apt-get install -f`.
3. For `.AppImage`, run `chmod +x`.
4. Confirm you are in a desktop session.
5. Launch from terminal to capture errors:

```bash
synergy-node-control-panel
```

### App Is Blocked On macOS

Symptoms:

- macOS says the app cannot be checked.
- macOS says the app is damaged.
- App is blocked after download.

Fix:

1. Confirm it came from the official release page.
2. Open **System Settings > Privacy & Security > Open Anyway**.
3. If needed, run:

```bash
sudo xattr -rd com.apple.quarantine "/Applications/Synergy Node Control Panel.app"
```

### Help Manual Does Not Load

Symptoms:

- Help shows failed to load manual.
- Manual path is missing.

Fix:

1. Close and reopen the app.
2. Click **Reload Manual**.
3. Open Settings and confirm the workspace path exists.
4. Reinstall the app if bundled resources are missing.

### Control Service Is Unreachable

Symptoms:

- Dashboard does not load.
- Actions fail immediately.
- Local service errors mention port `47891`.

Fix:

1. Close and reopen the app.
2. Allow localhost traffic in firewall or VPN software.
3. Check that security software did not quarantine `control-service`.
4. Restart the machine if a stale service process is stuck.
5. Reinstall the latest app if extraction failed.

### Time Resync Reports A Warning

Symptoms:

- **Resync Time** finishes with a warning.
- Activation Preflight reports clock skew.
- Runtime logs show rejected messages or signatures close to a time boundary.

Fix:

1. Run **Resync Time** again from the Control Panel.
2. Open logs and preserve the generated `time-resync-*.json` evidence file.
3. On macOS, enable network time and run `sudo sntp -sS time.apple.com`.
4. On Linux, run `sudo timedatectl set-ntp true`; if installed, run `sudo chronyc -a makestep`.
5. On Windows, run Administrator PowerShell and execute `w32tm /resync /force`.
6. Rerun Activation Preflight only after the OS time service is healthy.

### Setup Cannot Detect Public IP

Symptoms:

- Jarvis cannot auto-detect IP.
- **Use Detected** is empty.

Fix:

1. Enter the public IP or DNS manually.
2. Do not enter `localhost`, `.local`, private RFC1918 addresses, or VPN-only addresses for a public validator.
3. Confirm the public DNS resolves to this machine.
4. Confirm the P2P port is forwarded and open.

### Provision Node Fails

Symptoms:

- Jarvis reports setup failed.
- Workspace is partially created.

Fix:

1. Check whether the chosen folder is writable.
2. Use a fresh folder path.
3. Make sure the identity passphrase is at least 8 characters for validators.
4. Confirm security software is not blocking bundled binaries.
5. Restart setup from Jarvis.
6. If the workspace is broken, use Clean Install Reset only after preserving needed logs.

### Node Will Not Start

Symptoms:

- **Start** fails.
- Runtime remains offline.
- Local RPC never becomes ready.

Fix:

1. Open Activity or Logs.
2. Check whether another process is already using the ports.
3. Stop any manually-started duplicate runtime.
4. Use **Restart** from the app.
5. Confirm `config/node.toml` exists.
6. Confirm the bundled node binary exists and is executable.

### Node Has No Peers

Symptoms:

- Peer count is zero.
- Connections says poor quality.
- Seed registration check fails.

Fix:

1. Click **Re-register**.
2. Click **Bootstrap / reconnect**.
3. Open the P2P firewall port.
4. Confirm public IP or DNS is correct.
5. Open Connections and check bootnode or seed service reachability.
6. Run **Boost Sync** in Advanced or Developer mode.

### Node Is Behind

Symptoms:

- Sync gap is high.
- Dashboard primary action is **Sync Catch Up**.
- Validator activation preflight fails on sync.

Fix:

1. Keep the node running.
2. Click **Sync Catch Up**.
3. Click **Bootstrap / reconnect** if peer count is low.
4. Wait for local RPC to catch up.
5. Compare local block number with public RPC.

### Snapshot Restore Or Catch-Up Is Blocked

Symptoms:

- Validator Lifecycle shows snapshot discovery, snapshot verification, replay, or self-realignment blocked.
- Sync Catch Up finishes but preflight still has blockers.
- The node remains quarantined or not ready to rejoin.

Fix:

1. Do not copy old chain databases or random snapshots into the workspace.
2. Use **Sync Catch Up** from the Control Panel.
3. If the app reports snapshot verification failure, preserve the evidence path shown in Validator Lifecycle or Logs.
4. Fix the first failing readiness or preflight check.
5. Keep the validator in shadow/recovery states until the app reports ready to rejoin.
6. Activate only after canonical chain state, local RPC, peer visibility, seed registration, funding, and bonded stake pass.

### Shadow State Does Not Finish

Symptoms:

- Validator Lifecycle shows `SHADOW`, `SHADOW_OBSERVING`, or shadow progress that is not complete.
- The node is synced but activation remains blocked.

Fix:

1. Keep the runtime online.
2. Check Connections for peer and relayer visibility.
3. Run **Activation Preflight** after the shadow period updates.
4. Do not manually force the validator to active state.
5. If the same shadow check keeps failing, export logs and the Validator Lifecycle evidence for support.

### Activation Preflight Fails

Common failed checks and fixes:

| Failed check | What to do |
| --- | --- |
| Public P2P endpoint | Fix public IP/DNS and firewall. |
| Canonical workspace genesis | Re-provision from the current TESTNET bundle. |
| Canonical chain state | Stop the node and reset stale local chain data before retrying. |
| Local RPC ready | Start or restart the node. |
| Synced near chain head | Run Sync Catch Up and wait. |
| Relayer peers visible | Check Connections, firewall, and seed registration. |
| Seed registration | Click Re-register. |
| Wallet funding | Send SNRG to the validator `synv1...` address. |
| Bonded stake | Click Stake Validator after funding is visible. |
| Fork metadata, FN-DSA, or parser mode | Re-provision from the current Control Panel build; do not hand-edit stale configs. |
| Local signing key or runtime wallet loaded | Restart the runtime after provisioning or import the approved validator identity package. |

### Fail-Closed Or Quarantine Appears

Symptoms:

- Validator Lifecycle shows `FAILED_CLOSED`, `QUARANTINED`, or self-realignment.
- Consensus duties are disabled.
- The app reports voting, proposing, QC aggregation, quorum counting, or proposer scheduling disabled.

Fix:

1. Treat this as a safety block, not a cosmetic status.
2. Open Validator Lifecycle and identify the first failed gate.
3. Confirm chain `1266`, network `synergy-testnet-v3`, genesis height `0`, parent hash `0000000000000000000000000000000000000000000000000000000000000000`, consensus `ML-DSA-65`, consensus key algorithm `ML-DSA-65`, and parser mode `fail_closed`.
4. Use **Sync Catch Up** for chain lag or stale state.
5. Use **Bootstrap / reconnect** and **Re-register** for peer or seed failures.
6. Restart the runtime if the runtime wallet or local signing key check does not load after provisioning.
7. Rerun **Activation Preflight** and activate only when every required check passes.

### Funding Does Not Show Up

Fix:

1. Confirm the receiver is the validator `synv1...` address, not a `synw...` wallet.
2. Confirm the amount is at least `50,000 SNRG`.
3. Confirm RPC units: `50,000 SNRG` equals `50,000,000,000,000 nWei`.
4. Check public RPC with `synergy_getBalance`.
5. Re-run Activation Preflight.
6. Let Atlas/explorer indexing catch up before relying only on the explorer page.

### Stake Validator Is Disabled

Reasons:

- Funding is not visible.
- Preflight does not allow staking yet.
- Stake is already bonded.
- Node is not a validator.

Fix:

1. Run Activation Preflight.
2. Confirm funding.
3. Confirm validator address starts with `synv1`.
4. Wait for the funding transaction to be included.

### Activate Validator Is Disabled

Reasons:

- Preflight is failing.
- Stake is not bonded.
- Node is not synced.
- Seed registration or peers are missing.

Fix:

1. Run Activation Preflight.
2. Fix every failed check.
3. Run Activation Preflight again.
4. Click Activate Validator only when all checks pass.

### Rewards Are Empty

Fix:

1. Confirm the node is running.
2. Confirm sync gap is near zero.
3. Confirm the node has peers.
4. Confirm validator is active.
5. Open Rewards + Stake and check telemetry gaps.
6. Export raw reward data if support needs evidence.

### Linux Update Installed But Old App Still Runs

Symptoms:

- Package manager shows new version.
- Running app still behaves like an old build.

Fix:

1. Fully close the app.
2. Check for old processes.
3. Reopen from the installed application launcher.
4. If troubleshooting from terminal, confirm the running executable is not a deleted old inode:

```bash
pgrep -af 'Synergy Node Control Panel|synergy-node-control-panel'
```

### Firewall Changes Fail On Linux

Symptoms:

- Setup says firewall configuration failed.
- `pkexec` or sudo prompt does not appear.

Fix:

1. Install `ufw` or another firewall tool.
2. Run the app from a GUI session.
3. Manually open the required port:

```bash
sudo ufw allow 5622/tcp
```

4. For automation, configure controlled passwordless sudo for only the firewall command if your security policy allows it.

## Manual Verification Commands

Use these only when you need to verify outside the UI.

### Public Chain Height

```bash
curl -s https://testnet-core-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

### Local Chain Height

macOS/Linux:

```bash
curl -s http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

Windows PowerShell:

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:5640" `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

### Local Peer Info

```bash
curl -s http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getPeerInfo","params":[]}'
```

### Validator Balance

Replace `synv1...` with the validator address:

```bash
VALIDATOR_ADDRESS='synv1...'

curl -s https://testnet-core-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"synergy_getBalance\",\"params\":[\"$VALIDATOR_ADDRESS\"]}"
```

### Validator Staked Balance

```bash
VALIDATOR_ADDRESS='synv1...'

curl -s https://testnet-core-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"synergy_getStakedBalance\",\"params\":[\"$VALIDATOR_ADDRESS\",\"SNRG\"]}"
```

### Active Validators

```bash
curl -s https://testnet-core-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getValidators","params":[]}'
```

## Security And Key Handling

- Treat `keys/` folders as sensitive.
- Do not email setup packages or private key files.
- Do not paste private keys into chat or tickets.
- Use the app's **Copy Address** button for public addresses only.
- Keep identity passphrases in a password manager.
- Prefer one node identity per machine and role.
- If a machine may be compromised, stop the node, preserve evidence, and contact the Synergy Core team before reusing its identity.
- Developer View exposes raw paths and metadata. Do not screen-share it publicly if paths or identity details are sensitive.

## Glossary

| Term | Meaning |
| --- | --- |
| Activation Preflight | Validator readiness check that must pass before activation. |
| Atlas | Synergy explorer surface for chain, transaction, and validator visibility. |
| Bonded stake | SNRG locked to a validator identity for participation. |
| Control service | Local Rust service used by the desktop app to control runtime actions. |
| Preassigned bootstrap package | Validator included in the original Testnet bootstrap set. Do not reuse its package for new validators. |
| Jarvis | In-app setup and guidance assistant. |
| Local RPC | JSON-RPC endpoint served by the node on the local machine. |
| nWei | Smallest SNRG unit used by RPC balances. |
| P2P | Peer-to-peer networking between Synergy nodes. |
| Seed registration | Process where a node advertises reachable peer details to seed services. |
| Sync gap | Difference between this node's local height and the best verified chain height. |
| Validator address | `synv1...` address used for validator funding, stake, and activation. |
| Wallet address | Regular wallet address, often `synw...`; not a validator identity. |

## Support Checklist

When asking for support, include:

- app version from Settings
- operating system
- node role
- workspace path
- current Dashboard status
- sync gap and peer count
- failed button/action name
- exact error message
- recent logs or exported raw data when safe to share

Do not include passwords, private keys, raw seed phrases, or private setup package contents in support requests.
