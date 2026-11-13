# Simplified PoSy v1 Gate

Status: **historical Phase-One proposal; not a PoSy v3 specification or
operator runbook.**

Do not use this document for the fresh Chain `1266` / network `testnet` /
`posy/3.0` chain. Its coordinated six-validator assumptions, message phases,
and activation sequence are retained only as historical design evidence. The
authoritative P3 candidate documentation starts at
`docs/posy-v3/POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md`.

This page records the post-Phase-One gate only. It does not introduce a second
engine, wire any messages, or activate a consensus schedule.

Simplified PoSy may be implemented only after coordinated mode has produced
5,000 consecutive finalized blocks and a machine-verifiable report confirms
the six-validator tips, producer rotation, recovery behavior, and real Atlas
indexing/display. Until then `coordinated_round_robin_v1` is the only planned
temporary replacement and the existing typed PoSy source remains inactive
whenever coordinated mode is selected.

When authorized, simplified PoSy must use one global six-validator committee,
one proposer per round, prevotes, precommits, and one final commit proof. It
must remove the obsolete certificate layers rather than run both systems at
one height. Migration must occur at an explicitly configured, canonical
one-based 1,000-block epoch boundary without resetting balances, accounts,
contracts, nonces, receipts, state, or block history.

The current code has no Phase-Two implementation claim.
