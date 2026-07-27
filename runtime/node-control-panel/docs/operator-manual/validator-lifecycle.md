# Validator Lifecycle

This is the end-to-end runbook for a new Synergy Testnet validator using the Node Control Panel. It applies to a local macOS/Linux desktop validator and to a Linux amd64 target managed over SSH from the Control Panel.

## What You Need Before Starting

- A current signed Control Panel release. This manual covers v20.0.0.
- A target that passes **Run Device Check**: 8 logical CPU cores, 16 GB RAM, 200 GB free SSD space, a writable workspace, working internet, and correct system time.
- A durable location for the encrypted identity backup and its passphrase. Do not keep the only backup inside the active validator workspace.
- A Synergy Wallet with `50,001 SNRG` available for this validator plus any wallet-side network fee.
- A one-time secure-network token from a Synergy coordinator administrator. Tokens are single-use and expire; do not ask a community operator to access the coordinator server.

The validator self-bond is exactly `50,000 SNRG`. The additional `1 SNRG` stays in the validator account as a fee reserve. Never send another transfer just because the UI is checking, catching up, or awaiting confirmation.

## 1. Choose The Validator And Create Its Identity

1. Open **Setup Node** and choose **Validator**.
2. Choose **This computer** for a local machine, or **Remote server over SSH** for a headless server. For remote setup, add and test the SSH target before continuing.
3. Enter a simple validator name using letters, numbers, spaces, hyphens, or underscores. Avoid punctuation that can produce an unsupported-character error.
4. Select **Synergy Testnet**, choose the durable workspace location, and create an encryption passphrase of at least eight characters.
5. Click **Create Validator Identity**. Verify that the displayed validator address begins with `synv1`.
6. Click **Export Encrypted Backup**, store it outside the workspace, then confirm that the backup and passphrase are safely stored.

Do not reuse an identity from an earlier failed attempt. Every new validator begins with a fresh identity and backup.

## 2. Connect Wallet, Fund, And Self-Bond

1. Open **Wallet & Stake** and click **Connect Synergy Wallet**.
2. Scan the QR code in the mobile wallet and approve the connection. The Control Panel restores the wallet connection while you navigate through the active app session.
3. Confirm that the displayed operator wallet and generated `synv1...` validator address are correct.
4. Click **Fund 50,001 SNRG** and approve the wallet request. This is the only funding transfer for this validator.
5. Wait for **Funding Confirmed**. If the screen says funding is pending, use **Refresh Status** or **Verify Bond**; do not send another transfer.
6. When **Complete Validator Self-Bond** becomes enabled, click it once. The action locks the exact `50,000 SNRG` already in the validator account. It is not another transfer from the owner wallet.
7. Wait for **Bonded Stake Verified**, then select **Continue to Device & Network**.

If a self-bond submission is pending or its result is unknown, do not retry blindly. Refresh the status and keep using the same setup flow; the Control Panel uses a replay guard to prevent duplicate bonds.

## 3. Device Check And Secure Validator Network

1. Click **Run Device Check**. Resolve any CPU, RAM, free-disk, workspace, RPC, wallet, or command-access failure shown by the app.
2. Enter the coordinator-issued **One-time onboarding token**.
3. Click **Connect Secure Network** and approve the macOS administrator dialog or Linux `sudo` request that the app initiates.
4. Continue only after **Secure Network Confirmed** shows coordinator confirmation, an assigned private network address, and peer-handshake evidence.

The coordinator owns addresses, peer assignments, and transport maps. Do not manually edit peer lists, import a static VPN configuration, run the retired VPN helper, or choose a public VPN port. Normal onboarding needs no public `5622/tcp` forwarding; public service nodes reach validators through relayers.

If a previous attempt left a stale `sy-vpn` interface, use the Control Panel's reset/erase workflow rather than deleting Innernet files manually. A fresh start also requires a newly issued one-time token.

Before canonical activation, the runtime automatically keeps the new validator in authenticated support-only mode so it can synchronize without voting, proposing, or serving as a history source. Canonical activation automatically removes that restriction and starts consensus participation. Operators do not need a separate peer-unblock command, firewall change, validator allowlist edit, or manual service restart after activation.

## 4. Sync From A Verified Source

The Control Panel offers two safe paths:

- **Fast Snapshot Sync** is preferred. Click **Retry Snapshot** to discover, download, verify, apply, and catch up from the latest compatible `validator-pruned` archive snapshot.
- **Normal Sync** is available only when **Use Normal Sync** is enabled by the Control Panel. It starts guarded peer synchronization after the secure network is confirmed.

The app rejects snapshots with an invalid signature, wrong chain or fork, wrong restore role, mismatched identity, stale verification, missing manifest/hash, or an untrusted source. Do not download or apply snapshot files manually to bypass those checks.

When the selected sync path reports ready, click **Continue to Launch & Activate**. The app will reconcile the local and public chain state before it lets the validator proceed.

## 5. Launch, Shadow, And Activation

1. On **Launch & Activate**, click **Start Validator Onboarding**. If setup was interrupted, use **Resume Validator Onboarding** instead of starting a second runtime.
2. The Control Panel starts the guarded validator service, verifies secure-network routes, peer visibility, canonical head agreement, wallet state, and bonded stake.
3. The validator enters observation or shadow mode. It synchronizes and observes the active network without voting or proposing. The required shadow proof covers 1,000 canonical blocks.
4. When **Activation Preflight** is green, **Submit Activation Transaction** becomes available. Click it once and keep the runtime running.
5. Wait for **Validator Active** and the canonical registry confirmation for the same `synv1...` address.

Do not infer activation from peer count, a zero sync gap, a funded balance, a submitted transaction, or a process status. Only canonical activation completes onboarding.

## 6. Cluster Assignment And Consensus

Operators do not choose a validator cluster or change a quorum threshold manually. The runtime assigns a new eligible validator to the least-populated eligible cluster and recalculates the required threshold from the active set.

At 10 active validators, the runtime creates two clusters of five validators with a 3-of-5 quorum in each cluster. At 21 active validators, it creates three clusters of seven with a 5-of-7 quorum. Later expansions add a cluster for each additional seven validators. Epoch boundaries are fixed at 1,000 blocks: blocks 1 through 1,000 are epoch 0, blocks 1,001 through 2,000 are epoch 1, and so on.

Cluster rotation is disabled until three clusters exist. Once there are three or more, the runtime rotates the two lowest-scoring validators in each cluster at an epoch boundary and performs a full cluster shuffle every tenth epoch. These are protocol actions, not Control Panel tasks.

## 7. Operations Screen

The **Operations** screen groups available actions into nine areas:

1. Lifecycle
2. Network & VPN
3. Sync & Chain State
4. Snapshots & Recovery
5. Staking & Rewards
6. Consensus
7. Wallet & Keys
8. Logs & Diagnostics
9. Updates & Maintenance

Each action is tied to the selected workspace and writes an operator-readable result. Hover briefly over an action for a plain-language explanation. Read-only actions are safe to inspect; actions that stop services, alter data, change keys, or begin recovery require confirmation.

The terminal on this screen is a real interactive shell on the computer where the Control Panel is running. It supports normal input, paste, terminal resizing, scrolling, and interrupts. It is not automatically a shell on a remote target. Commands run with the desktop user's permissions and may request macOS administrator approval or Linux `sudo`.

Do not paste private keys, passphrases, one-time tokens, or coordinator credentials into the terminal. For routine node work, prefer the structured action buttons because they use the selected workspace and preserve evidence.

## 8. Recovery Or A Fresh Setup

For a failed validator, open **Logs**, **Incidents**, and the recovery actions first. Preserve the incident ID, exact blocker, chain height, evidence path, rollback path, and snapshot result. A quarantine, diverged state, unavailable snapshot, invalid network receipt, or pending transaction is a real safety gate.

Use a recovery action only after its plan and evidence are green. Do not delete consensus data, edit a quarantine marker, copy state from another validator, or manually change peer routes to force a rejoin.

To intentionally start over on a local machine, use **Settings > Erase All Node Files**, accept the warning, then create a fresh identity and request a new one-time token. This action removes local validator data and stale `sy-vpn` client state. It does not make an old token reusable and it does not turn a prior stake transfer into funding for a new identity.

## 9. Support Evidence

Before requesting help, provide these items with secrets redacted:

- Control Panel version and target mode.
- Validator `synv1...` address, chain ID, and network ID.
- Exact on-screen error or blocker code.
- Current setup step, timestamp, `evidence_path`, `rollback_path`, and next action.
- Snapshot ID, source, hash, and verification result when sync is involved.
- Funding or self-bond transaction hash and the current **Verify Bond** result.
- Secure-network enrollment ID, assigned address, configuration generation, and confirmation status. Do not include the token.

The public chain height can be checked without exposing local services:

```bash
curl -sS https://testnet-rpc.synergy-network.io \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"synergy_blockNumber","params":[]}'
```
