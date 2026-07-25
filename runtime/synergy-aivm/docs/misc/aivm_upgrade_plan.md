# Horizon AIVM Upgrade Plan

## Overview

Horizon is the demo surface for Synergy Network's Artificial Intelligence Virtual Machine, or AIVM. The upgrade plan connects verified AI models, distributed compute, validator consensus, post-quantum proof verification, and tokenized metering into a single trustless AI execution layer.

The AIVM is designed to move AI workloads away from a single opaque provider and toward Synergy validator clusters that can coordinate model execution, compare results, attach proofs, and settle rewards on the network.

## Objectives

- Expose a marketplace where model publishers can register capabilities, pricing, verification requirements, and usage examples.
- Route AI work to attested compute providers based on latency, cost, region, and assurance requirements.
- Execute critical AI tasks through validator-backed consensus rather than relying on one provider response.
- Meter inference and training work through SNRG and Horizon credits.
- Attach post-quantum signatures to model outputs, proof receipts, and provider attestations.
- Give developers clear RPC and SDK paths for deploying AI-enhanced workflows.

## AIVM Architecture

The AIVM upgrade introduces a layered architecture:

1. Model Registry: records model metadata, version history, publisher identity, supported modalities, pricing, and attestation status.
2. Compute Registry: tracks provider regions, GPU classes, available slots, uptime, SLA score, and proof capabilities.
3. Task Router: selects an execution lane based on model requirements, user policy, cost ceilings, latency goals, and consensus threshold.
4. Validator Execution Layer: distributes work across validator clusters and compares returned outputs.
5. Proof Aggregator: collects signatures, applies the consensus threshold, produces a final receipt, and anchors the result.
6. Rewards Engine: settles fees to model publishers, compute providers, validators, and governance-controlled reserves.

## Consensus Workflow

A Horizon task starts with a signed request. The router expands that request into a shard plan, selects validators and compute providers, and dispatches replicas. Validators return outputs, confidence values, telemetry, and proof signatures.

When the configured threshold is met, Horizon emits a result receipt. If consensus fails, the task can be retried with a wider validator set, downgraded to a lower assurance lane, or returned as unresolved.

## Model Marketplace

The marketplace should make trust visible. Each model listing includes model size, capability category, cost, latency, popularity, rating, usage examples, and performance charts. Later production versions should also include publisher reputation, open audit notes, reproducible evaluation traces, and current staking requirements.

## Compute Marketplace

Compute providers list GPU type, region, available slots, price per hour, SLA score, proof features, and operational status. The request flow should support burst inference, fine-tuning, streaming agents, and vision pipelines.

Provider onboarding should require identity checks, uptime monitoring, test workloads, proof signing, and governance-defined minimum performance.

## Developer Tooling

Developers need a clean path from prototype to verified execution:

- API explorer for request and response examples.
- SDK snippets for JavaScript, Python, and Rust.
- SynQ code sandbox for AIVM task scripts.
- Result receipts that include proof digest, latency, consensus score, and token metering.
- Documentation pages that cover RPC methods, marketplace publishing, provider onboarding, and governance policy.

## Governance

Governance controls the high-impact parameters: reward bands, marketplace verification tiers, compute provider admission, gas schedules, proof thresholds, and slashing policies.

Voting previews in this demo use sample balances and proposal data, but the intended production path is wallet-signed governance with transparent proposal history and execution status.

## Token And Wallet Flow

Horizon uses wallet state for access, metering, rewards, and governance. The wallet flow should support:

- SNRG balances for network-level settlement.
- HZN credits for Horizon-specific usage.
- veHZN voting power for governance.
- Reward claims for compute providers, model publishers, and validators.
- Transaction history for inference, training, governance locks, and reward settlements.

## Security And PQC

AIVM results should be tamper-evident. The upgrade plan prioritizes post-quantum cryptography, validator attestation, quorum-based verification, replay protection, and visible proof receipts.

Security work should focus on validator identity, model version integrity, provider isolation, input privacy, fee metering correctness, and safe fallback behavior when consensus fails.

## Roadmap

### Phase 1: Sandbox Demo

Ship a polished Horizon UI on the sandbox domain with model marketplace, compute marketplace, developer tools, governance, token previews, and the AIVM report page.

### Phase 2: Testnet API Preview

Expose read-only model and provider registries, add signed task receipts, and connect the demo to live testnet metadata where safe.

### Phase 3: Verified Execution

Add validator-backed task execution, proof aggregation, task status RPC methods, and wallet-signed metering.

### Phase 4: Production Readiness

Harden provider onboarding, add governance controls, complete audit trails, and prepare operational documentation for model publishers and compute providers.

## Open Questions

- Which model categories require validator consensus versus single-provider execution?
- What is the minimum acceptable quorum for high-assurance tasks?
- How should provider slashing interact with transient GPU or network failures?
- Which proof fields should be surfaced in consumer wallets?
- How should AIVM metering map to SNRG and Horizon credits over time?

## Implementation Notes

The sandbox UI should stay visually aligned with Synergy Network while giving Horizon its own identity: dark gray background, subtle grid, left vertical navigation, strong purple accent color, glassmorphism, and smooth motion.

The demo should avoid production-only commitments while still feeling complete enough for team review. Every interactive control should respond locally, and public copy should be framed as Horizon platform previews rather than unfinished placeholders.
