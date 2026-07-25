# Control Panel Onboarding v2

Validator onboarding is a sixteen-phase control workflow. Each phase reads a `ControlActionEnvelope` with checks, blockers, warnings, next actions, evidence path, mutation flag, and rollback path.

## Phases

1. Welcome
2. Machine Check
3. Network Check
4. Enrollment Token
5. Package Verify
6. Identity
7. Backup Verify
8. Cluster Assignment
9. Config Render
10. State Source
11. Observer Sync
12. Stake
13. Vote-only
14. Proposer Probation
15. Activation
16. Success

Unsafe actions are disabled when the envelope has blockers. Mutating actions require explicit confirmation, write evidence, and return a rollback path. Confirmation alone never overrides a safety blocker.

## Operator Boundary

Normal community operators should not use terminal commands, SSH to other validators, edit `node.toml`, edit `peers.toml`, edit genesis, edit registries, edit consensus JSON or JSONL, copy snapshots by hand, run temporary HTTP servers, choose a branch manually, or guess why a snapshot failed.

The Control Panel is the normal path for onboarding, recovery, state verification, state-sync repair, cluster assignment, vote-only rejoin, proposer probation, activation, and incident evidence.

## Safety Gates

Onboarding fails closed on wrong network, wrong chain, closed P2P, unsigned package, NO-GO package, archive contained/noncanonical, low snapshot quorum, missing state proof, missing backup verification, or unsafe cluster assignment.

No live deployment, validator restart, live validator mutation, or archive service re-enable is part of this workflow without separate operator authorization.
