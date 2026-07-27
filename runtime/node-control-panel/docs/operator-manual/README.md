# Synergy Node Control Panel Operator Manual

This is the community guide for operating a Synergy Testnet validator with the Synergy Node Control Panel. It documents the current v20.0.0 release and its bundled runtime. Always use the newest signed release from the official release page; the Control Panel, control service, and runtime must report the same version.

## Choose Your Guide

| Your validator machine | Start here |
| --- | --- |
| A Mac with a desktop | [macOS](macos.md) |
| An Ubuntu or Debian machine with a desktop | [Ubuntu desktop](ubuntu-desktop.md) |
| An Ubuntu/Linux server with no desktop | [Headless Ubuntu/Linux](headless-ubuntu-linux.md) |
| The complete setup, activation, operations, and recovery flow | [Validator lifecycle](validator-lifecycle.md) |

## Current Testnet Profile

| Item | Value |
| --- | --- |
| Control Panel release covered here | `20.0.0` |
| Chain ID | `1264` (`0x4f0`) |
| Network ID | `synergy-testnet-v3` |
| Consensus and validator key algorithm | `FN-DSA` / `FN-DSA-1024` |
| Required self-bond | `50,000 SNRG` (`50,000,000,000,000 nWei`) |
| Initial validator funding | `50,001 SNRG` (bond plus `1 SNRG` fee reserve) |
| Validator address prefix | `synv1...` |
| Primary public JSON-RPC | `https://testnet-rpc.synergy-network.io` |
| Validator P2P transport | Coordinator-managed Innernet secure network |

## System And Network Requirements

The Control Panel will not continue until its **Run Device Check** passes. Plan for at least:

- 8 logical CPU cores.
- 16 GB RAM.
- 200 GB free space on a durable SSD for the validator workspace. More capacity is recommended for long-running operation, logs, evidence, and snapshot working space.
- Stable internet with automatic time synchronization. Do not run a validator from an intermittently connected laptop or a network that blocks ordinary outbound HTTPS or UDP traffic.
- Local administrator approval on macOS or `sudo` on Linux when the Control Panel configures the secure validator network.
- A Synergy Wallet with at least `50,001 SNRG` available for the new validator and any wallet-side network fee.
- A one-time onboarding token issued by a Synergy Network coordinator administrator. Community operators do not log in to the coordinator host and do not create their own token.

No public validator RPC, metrics, control-service, or P2P port is required for normal onboarding. The Control Panel uses the private coordinator-managed network and NAT traversal. Do not configure a fixed port forward or expose `5622/tcp` unless Synergy support gives a machine-specific instruction after reviewing the Control Panel evidence.

## Safe Operating Rules

- Use one Control Panel and one validator runtime for each workspace. Do not start another copy of the validator by hand.
- Create a new identity for every new validator. Never reuse a bootstrap package, an old validator workspace, or another operator's identity.
- Keep the encrypted identity backup and passphrase separate from the validator machine.
- The one-time network token, wallet pairing approval, passphrase, private keys, and coordinator credentials are secrets. Do not paste them into tickets, chat, terminal history, or screenshots.
- Do not edit `node.toml`, peer lists, genesis files, validator registries, consensus data, or quarantine files to force a setup gate to pass.
- A running process, a visible peer, a submitted transaction, or a funded balance is not proof that the validator is active. The final proof is canonical activation for the same `synv1...` identity.

## Setup At A Glance

1. Install the signed Control Panel and run **Run Device Check**.
2. Choose **Validator**, create a new identity, export its encrypted backup, and confirm the backup.
3. Connect **Synergy Wallet**, fund the displayed validator address with `50,001 SNRG`, then wait for canonical funding confirmation.
4. Click **Complete Validator Self-Bond** once it becomes available. It locks exactly `50,000 SNRG` already held by the validator; it does not send a second funding transfer.
5. Enter the coordinator-issued one-time token and click **Connect Secure Network**. Continue only after **Secure Network Confirmed** shows coordinator and handshake evidence.
6. Choose **Fast Snapshot Sync** when a verified snapshot is offered, or use **Use Normal Sync** only when that Control Panel action is available.
7. Click **Continue to Launch & Activate**, then **Start Validator Onboarding**. The Control Panel starts the guarded runtime, verifies sync, and observes the required shadow window.
8. When preflight enables it, click **Submit Activation Transaction** and wait for canonical registry confirmation.

Use [Validator lifecycle](validator-lifecycle.md) for the exact steps and for what each gate means.

## Starting Over Safely

Use **Settings > Erase All Node Files** only when you intentionally want to discard the local validator workspace and begin with a new identity. It stops local node processes, removes the local workspace and stale `sy-vpn` client state, and recreates an empty local registry. It does not transfer stake, delete a remote validator, or revoke a coordinator record. After an intentional erase, obtain a fresh one-time token and start a new setup flow; never reuse an old token or identity.

## Before Contacting Support

Collect the app version, target mode, validator `synv1...` address, exact on-screen blocker, timestamp, evidence path, snapshot ID if applicable, and transaction hash with secrets redacted. Do not send an identity file, backup passphrase, wallet secret, SSH private key, one-time token, or coordinator administrator credential.
