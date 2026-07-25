# Synergy Node Control Panel — Releases

Official installer downloads for the **Synergy Node Control Panel**, the desktop operator console for the Synergy Testnet network.

---

## Downloads

Each release includes pre-built installers for the supported desktop platforms:

| Platform | File | Format |
|----------|------|--------|
| **macOS** | `Synergy Node Control Panel-<version>.dmg` | DMG disk image |
| **Linux** | `synergy-node-control-panel_<version>_amd64.deb` or `.AppImage` | Debian package or AppImage |

Go to [**Releases**](https://github.com/synergy-network-hq/synergy-node-control-panel-releases/releases) and download the installer for your platform.

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| **OS** | macOS 12+ on Apple Silicon, or Ubuntu 22.04+ amd64 (or Debian-based equivalent) |
| **RAM** | 4 GB |
| **Disk** | 500 MB free (for the app and bundled node binaries) |
| **Network** | Active internet connection for node sync and fleet communication |

---

## Installation

### macOS

1. Download the `.dmg` file from the latest release.
2. Open the DMG and drag **Synergy Node Control Panel** into your Applications folder.
3. Launch **Synergy Node Control Panel** from Applications. Current macOS builds are Developer ID signed and notarized.

### Linux (Debian / Ubuntu)

1. Download the `.deb` package from the latest release.
2. Install it:
   ```bash
   sudo dpkg -i synergy-node-control-panel_*_amd64.deb
   ```
3. If there are missing dependencies:
   ```bash
   sudo apt-get install -f
   ```
4. Launch from your application menu or run:
   ```bash
   synergy-node-control-panel
   ```

---

## Troubleshooting

### macOS: "The app is damaged and can't be opened" / app blocked by Gatekeeper

Current macOS builds are Developer ID signed and notarized. If Gatekeeper still blocks an app, first confirm that you installed the current release from the official release page. Older unsigned builds can show one of these messages:

- *"Synergy Node Control Panel.app is damaged and can't be opened. You should move it to the Trash."*
- *"Synergy Node Control Panel.app can't be opened because Apple cannot check it for malicious software."*
- *"Synergy Node Control Panel.app can't be opened because it is from an unidentified developer."*

**Fix — run this script in Terminal after installing:**

```bash
#!/bin/bash
# ──────────────────────────────────────────────────────────────
# fix-macos-gatekeeper.sh
# Removes the macOS quarantine flag from the Synergy Node
# Control Panel so Gatekeeper stops blocking it.
# ──────────────────────────────────────────────────────────────

APP_PATH="/Applications/Synergy Node Control Panel.app"

if [ ! -d "$APP_PATH" ]; then
    echo "Error: App not found at $APP_PATH"
    echo "If you installed it elsewhere, run:"
    echo "  sudo xattr -rd com.apple.quarantine /path/to/Synergy Node Control Panel.app"
    exit 1
fi

echo "Removing quarantine flag from Synergy Node Control Panel..."
sudo xattr -rd com.apple.quarantine "$APP_PATH"

echo "Done. You can now open the app normally."
```

Or as a one-liner:

```bash
sudo xattr -rd com.apple.quarantine "/Applications/Synergy Node Control Panel.app"
```

You only need to do this once per install/update.

**Alternative (GUI method):**

1. Try to open the app — it will be blocked.
2. Open **System Settings** → **Privacy & Security**.
3. Scroll down — you will see a message about "Synergy Node Control Panel" being blocked.
4. Click **"Open Anyway"** and confirm.

> Note: The GUI method may need to be repeated for embedded binaries. The terminal command above is the most reliable fix.

---

### macOS: "Synergy Node Control Panel" wants to access files / network prompts

macOS may prompt for permission to access your Documents, Downloads, or network. These are normal — the control panel needs:

- **Network access** to communicate with Synergy testnet nodes.
- **File access** to store node configuration and key material.

Click **Allow** when prompted.

---

### Linux: App doesn't launch / missing shared libraries

If the app fails to start on Linux, install the common dependencies:

```bash
sudo apt-get update
sudo apt-get install -y \
    libgtk-3-0 \
    libwebkit2gtk-4.1-0 \
    libayatana-appindicator3-1 \
    librsvg2-2 \
    libssl3
```

---

### Linux: No tray icon showing

Some Linux desktop environments don't support the AppIndicator tray protocol by default. Install the appropriate extension:

- **GNOME:** Install the [AppIndicator extension](https://extensions.gnome.org/extension/615/appindicator-support/).
- **KDE Plasma:** Tray icons should work out of the box.

---

### All Platforms: Control service fails to start

The control panel launches a local background service on startup. If the dashboard shows the service as unreachable:

1. **Check if the port is in use.** The service defaults to port `47891`. If another process is using it, the service will try the next available port automatically — but firewalls or VPNs can interfere.
2. **Restart the app.** Close and reopen the control panel. The service is re-extracted and restarted on each launch.
3. **Check your firewall.** Ensure `localhost` traffic on ports `47891+` is not blocked by your local firewall or VPN client.

---

### All Platforms: Node binaries not found after install

The control panel bundles pre-compiled node binaries. If the setup wizard reports missing binaries:

1. Close and reopen the control panel — binaries are extracted from the app bundle on startup.
2. If the problem persists, check that your antivirus or security software hasn't quarantined files in the app's resource directory.

---

### Updating to a New Version

- **macOS:** Download the new `.dmg`, drag the app to Applications (replacing the old version), and re-run the quarantine removal command.
- **Linux:** Download the new `.deb` and install it over the existing version:
  ```bash
  sudo dpkg -i synergy-node-control-panel_*_amd64.deb
  ```

---

## Network Information

The control panel connects to the Synergy Testnet network:

| Service | Endpoint |
|---------|----------|
| RPC | `https://testnet-core-rpc.synergy-network.io` |
| WebSocket | `wss://testnet-core-ws.synergy-network.io` |
| API | `https://testnet-api.synergy-network.io` |
| Explorer | `https://testnet-explorer.synergy-network.io` |
| Faucet | `https://testnet-faucet.synergy-network.io` |

**Chain ID:** `1264`

**Default Ports:**

| Port | Purpose |
|------|---------|
| `5620` | Bootnode listener |
| `5621` | Seed-service listener |
| `5622 + assignment` | Node P2P |
| `5640 + assignment` | Node RPC |
| `5660 + assignment` | Node WebSocket |
| `5680 + assignment` | Node discovery |
| `6030 + slot` | Node metrics |

---

## Support

- **Documentation:** [https://docs.synergy-network.io](https://docs.synergy-network.io)
- **Discord:** [https://discord.gg/synergy](https://discord.gg/synergy)
- **Issues:** [Open an issue](https://github.com/synergy-network-hq/synergy-node-control-panel-releases/issues) in this repository.

---

## License

Copyright © 2026 Synergy Network. All rights reserved.
