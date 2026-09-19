# Testnet-v3 operational instructions

For every Chain 1266 stall or node incident, read
`CHAIN_1266_STALL_LOG.md` from top to bottom before diagnosing or mutating any
node. Append the incident and every recovery attempt, including unsuccessful
attempts and exact outcomes, using the required format in that log.

Never declare the chain healthy from an active service alone. Require an
advancing, identical finalized tip across all five initial validators, zero new fatal
consensus/signing conflicts, bounded observer/public-tier lag, and live Atlas
data.

## Source-integrity boundary

The only Testnet-v3 development checkout is
`/Volumes/xcode/Synergy-Network/01-Core-Protocol/testnet-v3`.

Do not create nested clones, long-lived worktrees, or copied Testnet trees. A
temporary worktree must have a named purpose, be reconciled into this checkout
before its task is complete, and then be removed with `git worktree remove`.
Testnet-v2 source and runtime artifacts are forbidden in this tree. The Node
Control Panel source belongs only at
`/Volumes/xcode/Synergy-Network/07-Node-Control-Panel`; do not embed or copy it
under Testnet-v3.

<!-- BEGIN GLOBAL AGENT OPERATING SYSTEM -->
## Global Agent Operating System

Before beginning any task in this repository, read and follow the global Agent
Operating System at `/Users/devpup/.codex/AGENTS.md`. Its canonical supporting
package is `/Users/devpup/.codex/agent-operating-system`; resolve its
`MEMORY.md`, `.agent-memory/`, templates, and linter from that package root.
Retrieve only the memory relevant to the current task.

Preserve and reconcile this repository's existing instructions with the global
operating system. System and developer instructions remain higher priority,
and explicit user instructions govern the current task. Do not copy global
memory into this repository unless the user explicitly requests that.
<!-- END GLOBAL AGENT OPERATING SYSTEM -->
