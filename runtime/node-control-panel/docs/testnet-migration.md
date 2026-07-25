# Technical Specification: Testnet Transport Migration

**Document Status:** Draft
**Version:** 0.1
**Date:** 2026-03-10

## Executive Summary

The current control panel is built for a closed testnet with private-overlay reachability, overlay-based machine identity, and agent trust derived from a legacy private management network. That model is causing operational friction and does not fit a broader testnet where each node publishes its own stable public endpoint.

The migration target is a public-endpoint testnet where:
- every node has a public RPC hostname such as `node0202.synergy-network.io`
- node health and status checks use public endpoints
- local same-machine operations do not require overlay identity
- remote control is no longer coupled to a private overlay

## Problem

The current design assumes:
- `host` and `management_host` are effectively the same private address
- local machine identity is derived from a legacy private overlay address
- the testnet agent is reachable only from trusted private-network peers
- installer generation rewrites config and inventory around private overlay addresses

That is appropriate for a closed testnet and inappropriate for a public testnet.

## Goals

- Support public per-node RPC endpoints in inventory.
- Decouple read-path monitoring from private control transport.
- Allow same-machine local actions without overlay detection.
- Preserve backward compatibility while the old testnet profile still exists.

## Non-Goals

- Exposing the current unauthenticated testnet agent directly to the public internet.
- Rewriting the entire testnet/bootstrap pipeline in one cutover.
- Removing every legacy private-overlay code path in the same change.

## Transport Model

### Read Path

Public status, RPC, and diagnostics should use explicit public endpoint data from inventory:
- `public_rpc_url`
- `public_rpc_host`
- `rpc_host`
- `public_host`

These fields are ordered from most explicit to least explicit. If none are present, the system falls back to the current `host` field.

### Control Path

Control must be separated from public RPC:
- local same-machine actions can run `nodectl` directly
- operator-managed SSH can remain an optional compatibility path
- any future public control plane needs authentication and authorization, not IP-based trust

### Local Machine Identity

For testnet and non-overlay deployments, local identity should be allowed via:
- `SYNERGY_MACHINE_ID=<physical_machine_id>`

This provides a deterministic local-machine mapping when no overlay address exists.

## First Slice Implemented

The current repo changes support:
- inventory-driven public RPC resolution without changing control host semantics
- `SYNERGY_MACHINE_ID` as a local identity override for same-machine actions

This is enough to begin migrating the read path to public node endpoints.

## Follow-Up Work Required

### P0

- Introduce an explicit control transport model instead of overloading `host`.
- Add inventory columns for `control_host` and `public_rpc_url`.
- Rename UI/documentation from "closed testnet" to "testnet" for the selected profile.

### P1

- Replace private-overlay-only agent trust with authenticated control.
- Add per-operator credentials or signed action tokens.
- Allow agent reachability checks against authenticated public control endpoints.

### P2

- Remove topology rewrites that force `host` and `management_host` to the same private address.
- Add a dedicated `testnet` inventory/profile beside `testnet/runtime`.
- Rework installer templates so bind/public addresses are not forced to private overlay IPs.

## Acceptance Criteria

- A node inventory row can specify a public RPC target and the dashboard uses it for health checks.
- A same-machine operator can run local control actions with `SYNERGY_MACHINE_ID` set and no overlay network present.
- Existing closed-testnet inventory continues to work unchanged.
