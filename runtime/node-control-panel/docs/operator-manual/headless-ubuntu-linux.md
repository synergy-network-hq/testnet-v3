# Headless Ubuntu/Linux Guide

The Node Control Panel is a desktop app. For a validator on a Linux server with no desktop, run the Control Panel on a trusted macOS or Linux desktop and select **Remote server over SSH**. The Control Panel manages the remote target through one authenticated SSH control connection and its signed Linux sidecar.

## Remote Target Requirements

- Ubuntu 22.04 LTS or newer is recommended.
- Linux `x86_64`/`amd64`. The current remote sidecar and secure-network runtime support Linux amd64.
- 8 logical CPU cores, 16 GB RAM, and 200 GB free durable SSD space.
- Stable internet, automatic time synchronization, and a dedicated non-root account with the scoped `sudo` access requested by the Control Panel.
- SSH reachability from the desktop operator machine. Restrict SSH using a firewall or security group to the operator's management network.
- A coordinator-issued one-time onboarding token and an operator wallet with `50,001 SNRG`.

Keep validator P2P, local RPC, WebSocket, metrics, and control-service endpoints private. Do not expose `5622/tcp`, `5640`, `5660`, `6030`, or the local sidecar/control port to the internet. Public service nodes use the relayer tier rather than a direct public validator connection.

## Add The SSH Target

1. On the desktop Control Panel, choose **Validator**, then choose **Remote server over SSH** in **Validator Identity**.
2. Select **Add SSH Target**.
3. Choose **NCP managed SSH key**, **Existing SSH key**, or **One-time password bootstrap**. A one-time password is only for initial bootstrap; do not retain it as the normal operating method.
4. Protect any managed key with the requested key-storage passphrase. For an existing key, select its absolute local path.
5. Click **Test SSH Connection**. Correct the host, port, username, host-key, SSH permission, storage, or elevation error before moving on.

The Control Panel verifies Linux amd64, transfers a signed `synergy-control-linux-amd64` sidecar under the remote user's local application directory, verifies its SHA-256, and uses allowlisted actions for the selected workspace. Do not copy a runtime binary or sidecar to the server manually.

## Complete Remote Onboarding

Follow this order in the desktop Control Panel:

1. Create the remote validator identity, export its encrypted backup outside the target workspace, and confirm the backup.
2. Connect **Synergy Wallet** on the desktop operator machine. The remote server never receives the wallet private key.
3. Use **Fund 50,001 SNRG** for the displayed remote `synv1...` address and wait for the Control Panel to report confirmed funding.
4. Click **Complete Validator Self-Bond** once it becomes available. It creates the exact local `50,000 SNRG` protocol bond from the funds already confirmed in that validator account. Do not send a second transfer.
5. Run **Run Device Check**, enter the one-time token, and click **Connect Secure Network**.
6. Continue only after **Secure Network Confirmed** shows the coordinator receipt, assigned private address, and peer-handshake evidence.
7. Use **Fast Snapshot Sync** when a verified snapshot is offered. Use **Use Normal Sync** only when that Control Panel action is available and reports that it can proceed.
8. Click **Continue to Launch & Activate**, then **Start Validator Onboarding**. The Control Panel starts the remote runtime, verifies guarded catch-up, records the shadow window, and shows activation preflight.
9. Click **Submit Activation Transaction** only when the Control Panel enables it. Wait for canonical registry confirmation before treating the server as a validator.

The coordinator assigns the secure-network address and distributes topology. An operator does not add peers, edit transport maps, access the coordinator host, or configure a fixed port forward as part of normal onboarding.

## Remote Verification

Use the Control Panel's **Validator Detail**, **Connections**, **Logs**, **Incidents**, and **Diagnostics** surfaces for routine evidence. For a support-requested local RPC check, run it only through the approved SSH target or another private management path:

```bash
curl -sS http://127.0.0.1:5640 \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```

The Operations terminal is a shell on the desktop computer running the Control Panel. Selecting a remote target does not convert it into a shell on the Linux server. Use the structured action buttons for routine remote work and use an SSH command only when Synergy support gives an exact, reviewed command.

## Recovery Or A Fresh Attempt

Use the Control Panel's recovery and incident actions first. A failed SSH connection, a stale snapshot, incomplete secure-network evidence, or a pending transaction is a blocker, not authorization to edit state or peer files by hand.

If you intentionally discard a remote setup, use the Control Panel's erase/reset flow for that target, then create a new identity and request a new one-time token. Do not reuse a prior token, identity, snapshot cache, or stake transaction for a fresh validator attempt.
