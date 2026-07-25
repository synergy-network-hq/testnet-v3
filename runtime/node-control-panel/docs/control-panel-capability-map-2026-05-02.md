# Synergy Node Control Panel Capability Map

Date: 2026-05-02

This map condenses the 43-section master specification and the 27 Google Stitch screen renderings from `/Users/devpup/Desktop/new control panel screens` into the current Synergy Node Control Panel app structure.

## Design Direction

- Keep the existing Synergy control-panel shell: dark navy runtime workspace, left operator rail, Sora UI text, Orbitron utility labels, cyan/purple/lime status accents, panel cards, Jarvis guidance, and Basic/Advanced/Expert operating modes.
- Treat the Stitch renderings as information architecture references, not a replacement skin. The current app styling remains authoritative.
- Build operator screens around the three constant questions: "Am I safe?", "Am I participating correctly?", and "What should I do next?"
- Keep destructive validator, slashing, pruning, key-export, and migration actions behind explicit review workflows.

## Top-Level Screen Coverage

| App route | Screen | Spec sections covered |
| --- | --- | --- |
| `/` | Dashboard | 1, 19, 37, 43 |
| `/node/:nodeId` | Node Details | 4, 5, 6, 7, 39 |
| `/connectivity` | Network / P2P | 17, 18, 29, 35 |
| `/logs` | Logs / Audit | 20, 21, 39 |
| `/rewards` | Rewards | 11, 12, 32 |
| `/alerts` | Incident Response & Alerts | 21, 38, 39, 42 |
| `/validator` | Validator Lifecycle Management | 2, 10, 11, 13, 29, 42 |
| `/security` | Security & Slashing Protection | 13, 14, 22, 36, 42 |
| `/identity` | Identity, Wallet, Key & Signer Management | 14, 15, 22, 36, 42 |
| `/consensus` | Consensus & Finality Monitoring | 8, 10, 41 |
| `/dag` | DAG Topology & Graph View | 8, 9, 16, 18, 24, 41 |
| `/transactions` | Transactions, Mempool & DAG Pool | 15, 16, 23, 24, 25 |
| `/storage` | Storage & Snapshot Management | 7, 27, 28, 42 |
| `/api` | API/RPC & Developer Tools | 23, 24, 25, 26 |
| `/maintenance` | Maintenance & Update Center | 6, 28, 30, 33, 38, 39, 42 |
| `/fleet` | Enterprise Fleet Overview | 29, 34, 35 |
| `/governance` | Governance & Protocol Administration | 30, 31, 33 |
| `/compliance` | Compliance & Financial Reporting | 12, 20, 32, 36 |
| `/settings` | Local Settings / Configuration | 5, 22, 36, 37 |

## Stitch Rendering Mapping

- Screens 1, 8: alerts, logs, audit trails.
- Screens 2, 10, 17, 18: dashboard, consensus, finality, health center.
- Screens 3, 21: staking and economics.
- Screens 4, 15: identity, wallet, signer, transaction history.
- Screens 5, 27: maintenance and updates.
- Screens 6, 22: storage, snapshots, backup verification.
- Screens 7, 23: validator lifecycle and irreversible actions.
- Screens 11, 12: DAG topology, local/network graph view, pruning point.
- Screens 13, 24: developer tools and RPC console.
- Screens 14, 25: enterprise fleet overview.
- Screen 16: network topology and peer diversity.
- Screens 19, 20: security and slashing protection.
- Screen 26: governance and protocol administration.

## Implementation Notes

- New feature routes are data-driven from `src/components/control-panel/controlPanelFeatureScreens.js`.
- The shared renderer is `src/components/control-panel/ControlPanelFeaturePage.jsx`.
- Navigation is grouped into Core, Safety, Protocol, and Operations in `ControlPanelShell.jsx`.
- Basic/Advanced/Developer modes are relabeled in the UI as Beginner/Advanced/Expert while preserving the existing internal mode IDs for compatibility.
- The current implementation provides the UI shell, screen layout, audit receipts, guided review controls, and live selected-node context. Runtime execution hooks still need to be attached per action where backend support is not already present.
