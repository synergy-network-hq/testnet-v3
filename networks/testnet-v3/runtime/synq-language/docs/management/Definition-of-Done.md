# SynQ Definition of Done (DoD)

> This DoD is policy guidance, not an implementation-status source. AIVM
> execution tasks live in
> `../../../synergy-aivm/docs/readiness/SMART_CONTRACT_PRODUCTION_READINESS.md`.

## Purpose

This document defines non-negotiable completion criteria for SynQ workstreams. No task is considered complete unless all applicable DoD criteria are satisfied.

## Global DoD (All Workstreams)

A task is done only if all are true:

1. Implementation is committed in tracked source files.
2. Tests exist for behavior changed or added.
3. Relevant docs are updated in the same change window.
4. Validation commands pass locally.
5. No known blocker is hidden; open blockers are recorded in the owning project's readiness checklist.

## Workstream-Specific DoD

## Compiler/Parser

- Parser/AST behavior has positive and negative tests.
- New syntax is lowered to executable IR/bytecode path or explicitly rejected.
- No parser TODO placeholders remain for the completed task scope.
- Required Gate:
  - `cargo test -p compiler --tests --locked`

## VM

- Opcode/runtime behavior is covered by integration tests.
- Stack/memory/error behavior for changed paths is validated.
- Gas behavior changes are reflected in tests/docs where applicable.
- Required Gate:
  - `cargo test -p vm --tests --locked`

## CLI

- New CLI subcommand has integration test coverage.
- Help text and command semantics are documented.
- Non-destructive behavior on user files is verified.
- Required Gate:
  - `cargo test -p cli --test integration_test --locked`

## SDK

- Public API methods have integration tests.
- Package scripts and runtime assumptions are documented.
- Serialization/RPC payload behavior is deterministic.
- Required Gate:
  - `npm run test:integration` (in `sdk/`)

## PQ Foundation (`aegis-pqsynq`)

- Claimed algorithm paths are implemented and testable.
- KAT/replay evidence is present for shipped algorithms.
- Validation matrix script passes completely.
- Required Gate:
  - `bash aegis-pqsynq/pqsynq/scripts/run_tests.sh`

## Documentation

- Any implementation-affecting change updates impacted docs.
- Status docs do not claim unsupported features.
- Evidence commands referenced in docs are runnable.

## CI Gate Mapping

- Formatting/Lint:
  - `cargo fmt --all -- --check`
  - `cargo clippy -p aegis-pqsynq --all-targets --all-features --no-deps --locked -- -D warnings`
- Test Matrix:
  - `cargo test --workspace --all-targets --locked`
  - `bash aegis-pqsynq/pqsynq/scripts/run_tests.sh`

## Ready-for-Release Candidate Checklist

1. All M3-required backlog tasks are marked DONE with evidence.
2. Security and threat-model docs are current.
3. RC validation command set passes without manual patch-ups.
4. Change-log and known limitations are documented.
