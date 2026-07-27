# macOS Operator Guide

Use this guide for a validator running on the same Mac that runs the Synergy Node Control Panel. For the onboarding steps after installation, use [Validator lifecycle](validator-lifecycle.md).

## Requirements

- macOS 12 Monterey or newer. macOS 14 or newer is recommended.
- Apple Silicon. The current v20.0.0 signed macOS release is `arm64`; do not install it on an Intel Mac unless the releases page provides a separate signed Intel build.
- 8 logical CPU cores, 16 GB RAM, and 200 GB free SSD space. The Control Panel enforces these values in **Run Device Check**.
- A stable internet connection, automatic date and time, and a macOS administrator account available when the app requests secure-network approval.
- `50,001 SNRG` available through the operator's Synergy Wallet and a coordinator-issued one-time onboarding token.

Normal installation does not require Node.js, Rust, Git, Xcode, Homebrew, a standalone WireGuard application, or manually opening a validator port.

## Install The Signed App

1. Open the official [Node Control Panel releases](https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases) page.
2. For the current release, download `Synergy.Node.Control.Panel-20.0.0-arm64.dmg`. The same release also provides a signed ZIP for update delivery.
3. Open the DMG and drag **Synergy Node Control Panel** into **Applications**.
4. Start the app from **Applications**. When macOS asks to open a signed app from the official release, approve it.
5. Open **Settings** and confirm the version. It must match the bundled runtime version shown by the app.

Do not remove quarantine attributes or bypass Gatekeeper for an unknown download. If macOS reports a problem with an official installer, remove that copy, download the signed DMG again from the release page, and verify its checksum against `SHA256SUMS` before retrying.

## Secure Network Approval

During setup, **Connect Secure Network** may open a macOS administrator dialog. Approve the dialog only after you initiated the action in the Control Panel. The app installs and manages its own `sy-vpn` secure-network client; it does not require a manually created WireGuard interface or a fixed port-forward rule.

Continue only when the screen says **Secure Network Confirmed** and displays coordinator confirmation plus a peer-handshake result. A temporary `sy-vpn` interface from a prior failed setup is handled by the Control Panel reset path; do not remove files from `/etc/innernet` by hand.

## Update

- Use **Settings > Updates > Check Now** or the top-right update action.
- When an in-app update is available, choose **Install Update** and let the app restart.
- If the update flow cannot replace an app launched from a disk image, move the app to **Applications**, launch it there, and retry.
- If no in-app update is offered, install the current signed DMG over the application. Do not use **Erase All Node Files** merely to update the app.

An application update preserves the validator workspace, identity, evidence, and snapshot cache.

## Wallet Session During Setup

Click **Connect Synergy Wallet**, scan the QR code using the mobile wallet, and approve the pairing. The Control Panel restores the approved connection when you move between its screens during the active app session. It stores connection metadata and the wallet address, not a wallet private key.

- **Disconnect** intentionally clears the connection.
- Pair again after the session expires, the app storage is cleared, or the mobile approval fails.
- After reconnecting, use **Refresh Status** or **Verify Bond**. A restored wallet connection never bypasses the current on-chain stake checks.

## Local Checks

The primary public RPC is read-only and does not expose your local validator:

```bash
curl -sS https://testnet-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

If the Control Panel asks for a local-RPC diagnostic, use the generated local endpoint, normally `127.0.0.1:5640`:

```bash
curl -sS http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

Matching heights help prove sync only. They do not prove bonded stake or validator activation.

## Operations Terminal And Reset

The **Operations** terminal is a real local shell on this Mac. It supports ordinary interactive input, paste, scrolling, and `Ctrl+C`; it is not a shell on a remote validator. The structured Operations buttons run approved local actions and show their output in the same terminal. Hover over an action briefly to read a plain-language explanation before choosing it.

If you deliberately discard a failed local setup, use **Settings > Erase All Node Files**, confirm the warning, obtain a fresh token, and create a new identity. This is destructive to local validator data; it is not an update or a routine troubleshooting step.
