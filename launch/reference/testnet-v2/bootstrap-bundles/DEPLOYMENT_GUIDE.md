# Synergy Public Testnet 1264 Deployment Guide

This directory contains bootstrap and service bundles for Synergy Testnet v3, chain ID `1264`.

Before starting any node on this chain, stop any retired pre-Testnet-v2 process and remove retired chain database state from the node runtime. Do not reuse a `data/chain` directory from a retired network.

Canonical identity:

- Network: `synergy-testnet-v3`
- Chain ID: `1264`
- CAIP-2: `synergy:testnet`
- Reserved EIP-155: `eip155:1264`
- Genesis hash: `f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789`
- Network magic bytes: `d5d5bb99`

Port model:

- Bootnodes: P2P `5620`, discovery `5680`
- Seed services: P2P `5621`, discovery `5681`
- Validators, relayers, observer, indexer: P2P `5622`, qRPC `5640`, WS `5660`, discovery `5680`, metrics `6030`
- RPC Gateway: P2P `5623`, qRPC `5641`, WS `5661`, discovery `5681`, metrics `6031`

Deployment order:

1. Install updated control panel/runtime packages.
2. Stop all retired pre-Testnet-v2 services.
3. Remove old chain databases and old genesis artifacts from each runtime data directory.
4. Install the chain `1264` bundle with the canonical `config/genesis.json`.
5. Start bootnodes and seed services.
6. Start the five genesis validators.
7. Verify a single genesis hash and increasing block height across all validators.
8. Start relayers, observer, RPC gateway, and Atlas indexer.
9. Verify Grafana/Atlas report chain `1264` and the canonical genesis hash.
