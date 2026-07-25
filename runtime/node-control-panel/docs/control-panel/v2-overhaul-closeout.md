# Node Control Panel v2 Overhaul Closeout

Date: 2026-06-26

## Completed

- Implemented the v2 control-service envelope contract and command dispatcher.
- Implemented fail-closed model coverage for validator appliance package safety, identity backup proof, state-sync quorum, archive canonical verification, lifecycle gates, and dynamic cluster assignment.
- Implemented the v2 React surface for onboarding, validator detail, clusters, state-sync, archive, and incidents.
- Updated docs to make State Sync, vote-only rejoin, and proposer probation the normal recovery path instead of manual snapshot transfer or restart-first recovery.
- Fixed the rendered runtime crash caused by `ControlPanelShared.jsx` using `SNRGButton` without importing it.

## Evidence

- Targeted v2 Rust tests: 17 passed.
- Production frontend build: passed.
- Static Control Panel UI/UX acceptance script: passed.
- Browser smoke: all v2 routes rendered with required text, no framework overlay, no fresh runtime errors, and no horizontal overflow at desktop width or 390x844 State Sync viewport.
- Public read-only chain status: RPC block `647415`; Atlas latestBlock `647414`; Atlas activeValidators `6` of `6`.

## Remaining Non-v2 Caveat

The full control-service Rust suite still has legacy/environment failures unrelated to this v2 branch. See `docs/control-panel/node-control-panel-v2-pr-readiness.md` for exact failure names and root causes.

## Live-Safety Statement

This closeout did not deploy, restart, or mutate live validators. It did not re-enable archive validator services, APIs, or workers.
