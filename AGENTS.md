# Core Protocol single source of truth

## Canonical repository and implementation

The only authoritative Core Protocol checkout is:

`/home/node/Synergy-Network/01-Core-Protocol`

on `synergy-val4`.

The one canonical universal node implementation is:

`/home/node/Synergy-Network/01-Core-Protocol/node-platform`

Network-specific governed artifacts belong below `networks/<network>/` and do
not own the universal node implementation. The former Testnet-v3 monolithic
runtime at `networks/testnet-v3/runtime/` is a frozen semantic reference during
caller migration and must not remain an active production owner.

## Canonical migration ledgers

These repository-relative files are the one canonical versions:

- `docs/refactor/IMPLEMENTATION_STATUS.md`
- `docs/refactor/MIGRATION_MAP.md`
- `docs/refactor/NODE_ARCHITECTURE_COMPLETION_CHECKLIST.md`
- `docs/refactor/NODE_ARCHITECTURE_FILE_TREE_CHECKLIST.md`
- `docs/refactor/NODE_PLATFORM_ACTUAL_FILE_TREE.md`

Every canonical clone contains the same tracked files. Update them in place.
Never create alternate, renamed, or divergent copies. Absolute paths may
describe a checkout location but never define canonical file identity. Keep
`IMPLEMENTED`, `CALLERS_MIGRATED`, `LEGACY_REMOVED`, and `VERIFIED` as distinct
states.

Production code must be edited directly in the Val4 `node-platform` directory.
Never create source mirrors, staging worktrees, duplicate implementations,
`*.current.*`, `*.remote.*`, `*.old.*`, `*.backup.*`, or alternate migration
ledgers. Testnet-v3 execution-control files remain at
`networks/testnet-v3/docs/refactor/CODEX_MIGRATION_CONTINUATION.md` and
`CODEX_PRODUCTION_MIGRATION_QUEUE.txt`; they are not substitutes for the five
canonical repository ledgers.

## Testnet-v3 operational instructions

For every Chain 1266 stall or node incident, read
`networks/testnet-v3/CHAIN_1266_STALL_LOG.md` from top to bottom before
mutating any node. Append the incident and every recovery attempt using that
log's required format.

Never declare the chain healthy from an active service alone. Require an
advancing identical finalized tip across all five initial validators, zero new
fatal consensus/signing conflicts, bounded observer/public-tier lag, and live
Atlas data.

Do not alter live validator state, validator keys, databases, production
configuration, NetBird credentials, approved releases, or
`/opt/synergy/chain1266/releases` during source migration.

## Source-integrity boundary

Do not create nested clones, long-lived worktrees, or copied Core Protocol or
Testnet trees. A temporary worktree requires a named purpose, reconciliation
into this checkout, and removal with `git worktree remove`. Testnet-v2 source
and runtime artifacts are forbidden. The Node Control Panel source belongs only
at `/Volumes/xcode/Synergy-Network/07-Node-Control-Panel`; do not copy it into
Core Protocol.

## Agent operating system

Before every task, read and follow
`/Users/jhutzler/.codex/agent-operating-system/AGENTS.md` and its canonical
memory package. Preserve these repository rules with the global operating
system. System and developer instructions remain higher priority, and explicit
user instructions govern the task. Do not copy global memory into this
repository unless the user explicitly requests it.
