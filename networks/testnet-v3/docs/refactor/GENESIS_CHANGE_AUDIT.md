# Genesis change audit — 2026-09-10

## Scope

This audit covers the consensus-critical files that briefly appeared changed
during the node-refactor session:

- `runtime/src/bin/synergy-genesis-ceremony.rs`
- `runtime/src/genesis.rs`
- `runtime/src/genesis_deployment.rs`
- `runtime/src/sgen.rs`

## Determination

The files were clean at session entry. A whole-workspace formatter invocation
introduced large formatting-only diffs (`+173/-39`, `+12/-5`, `+8/-2`, and
`+547/-126`, respectively). It did not intentionally change any genesis,
serialization, ceremony, validator-initialization, cryptographic-binding, or
deployment behavior. The exact formatter hunks were then reversed without
touching any unrelated working-tree files.

Current verification against `HEAD` is empty for all four paths:

```text
git diff --name-status HEAD -- runtime/src/bin/synergy-genesis-ceremony.rs runtime/src/genesis.rs runtime/src/genesis_deployment.rs runtime/src/sgen.rs
git status --short -- runtime/src/bin/synergy-genesis-ceremony.rs runtime/src/genesis.rs runtime/src/genesis_deployment.rs runtime/src/sgen.rs
```

Both commands produced no entries on 2026-09-10. Consequently there is no
remaining source change to inspect for a changed genesis hash or serialized
artifact, and no user modification in these four files was discarded. Git
history retains the existing intentional genesis work (for example `d9dd95f`,
`ba5adc1`, and `3011bfa`); none was authored or altered by this refactor.

## Guardrail

No subsequent networking, Admin API, or ETDAG extraction work may alter these
files unless a change explicitly requires genesis behavior and includes a
targeted serialization/hash/ceremony regression test. Formatting this
consensus-critical area must be scoped to intentionally edited files.
