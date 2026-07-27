# Ubuntu Desktop Operator Guide

Use this guide for a validator running on an Ubuntu or Debian desktop. Continue with [Validator lifecycle](validator-lifecycle.md) after the Control Panel is installed.

## Requirements

- Ubuntu 22.04 LTS or newer. Ubuntu 24.04 LTS is recommended. A compatible Debian-based desktop may work when the required runtime libraries are present.
- Linux `x86_64`/`amd64`. The published v20.0.0 Linux installer assets are amd64.
- A graphical desktop session. The Control Panel is a desktop application.
- 8 logical CPU cores, 16 GB RAM, and 200 GB free SSD space. **Run Device Check** is authoritative and blocks setup when the selected machine fails.
- An account that can use `sudo` for package installation and secure-network setup.
- Stable internet, automatic time synchronization, `50,001 SNRG` through the operator wallet, and a coordinator-issued one-time token.

Install the desktop libraries when the package manager has not already provided them:

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

## Install

The official release offers both a Debian package and an AppImage. Prefer the Debian package on Ubuntu and Debian.

### Debian package

1. Download `synergy-node-control-panel_20.0.0_amd64.deb` from the official [releases page](https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases).
2. Install it:

```bash
sudo dpkg -i synergy-node-control-panel_20.0.0_amd64.deb
sudo apt-get install -f
```

3. Open **Synergy Node Control Panel** from the applications menu, or run:

```bash
synergy-node-control-panel
```

### AppImage

Download `Synergy.Node.Control.Panel-20.0.0.AppImage`, verify it against `SHA256SUMS`, then run:

```bash
chmod +x Synergy.Node.Control.Panel-20.0.0.AppImage
./Synergy.Node.Control.Panel-20.0.0.AppImage
```

Open **Settings**, check the displayed version, and run **Run Device Check** before beginning setup.

## Secure Network Approval

When you click **Connect Secure Network**, enter the Linux `sudo` password only for the action you started. The app configures the coordinator-managed `sy-vpn` client and validates the coordinator receipt and handshake. Do not manually run the retired VPN helper, create a second WireGuard interface, import a peer list, or open `5622/tcp` to the internet.

Normal onboarding does not require a fixed inbound UDP port forward. If the Control Panel cannot verify a peer handshake, use the exact evidence shown in the app when contacting support; do not change ports at random.

## Update

- Check **Settings > Updates > Check Now** first.
- Linux native updates may not be available for every package format. When the app says manual installation is required, install the current `.deb` over the existing package:

```bash
sudo dpkg -i synergy-node-control-panel_<version>_amd64.deb
sudo apt-get install -f
```

- An update replaces the application package only. It must not remove the validator workspace, backup, state, or snapshot cache.

## Wallet Connection During Setup

Use **Connect Synergy Wallet**, scan the pairing QR code, and approve it in the mobile wallet. The app preserves the approved session while you navigate through the current Control Panel session. **Disconnect**, expired sessions, cleared app storage, and failed pairing approval require a new QR connection.

No private key is copied from the wallet to the desktop app. After reconnecting, use **Refresh Status** or **Verify Bond** to reload canonical stake evidence.

## Local Checks

Check the public chain without exposing your validator:

```bash
curl -sS https://testnet-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

The generated local RPC is normally `127.0.0.1:5640`:

```bash
curl -sS http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

Use the [Validator lifecycle](validator-lifecycle.md) guide for stake, sync, shadowing, activation, Operations, and recovery. The Operations terminal is a real shell on this desktop, not an SSH terminal for another machine.
