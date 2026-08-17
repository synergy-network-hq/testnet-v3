# PoSy v3 legacy retirement and precedence

Status: proposed, not activated. This map prevents historical and future
algorithms from being read as simultaneous sources of proposal authority.

## Source-of-truth rule

Before a governed v3 activation boundary, canonical Genesis and the finalized
v2.2 parameter binding remain authoritative. At and after a valid v3 boundary,
the canonical schema-4 manifest plus `POSY-00E` become the sole consensus
algorithm source. The branch contains no implicit date, environment-variable,
or operator toggle that can substitute for that boundary.

## Retired at v3 activation

The following behaviors have no authority in `posy/3.0`:

- repeated ordinary VALIDATE/VC/FINALITY voting ceremonies;
- local-live-set leader skipping or peer-health-based proposer changes;
- wall-clock-driven round/leader advancement without a valid TC;
- stake-, score-, or floating-point-weighted leader selection;
- one-block proposer rotation where it conflicts with ten-block leases;
- stale-lock age, manual lock clearing, forced height, or forced leader;
- single-authority/authority-mode consensus shortcuts;
- inherited `ProofOfSynergy`/`DualQuorumConsensus` production entry points.

The old Rust engines remain source-visible for historical tests and migration
analysis, but their production entry point remains disabled. They must not be
called as a fallback if v3 startup or quorum fails.

## Preserved compatibility

Historical v2.1/v2.2 objects may be parsed only by explicitly versioned
recovery or audit paths. They do not contribute authority in a v3 epoch.
Testnet-v2 material under `launch/reference/testnet-v2/` is archival. Generic
floating-point values used for telemetry, gas, performance reporting, or
legacy parsing are not v3 scheduling inputs.

Dynamic cluster documentation remains the pre-activation topology source. The
v3 profile narrows its first activation to exactly five ACTIVE validators in
one cluster because that is the initial hardware-backed set. Five is not a
protocol limit. Future topology expansion becomes authoritative through an
approved, finalized v3 epoch transition that freezes the complete next set,
weights, keys, cluster map, and leader ring; the production transition bridge
and runtime integration remain activation blockers on this branch.

## Deliberately unchanged

Aegis ML-DSA-65 consensus authorization, durable signer journaling,
SafetyHalt, canonical roots/serialization, exact strict dual quorum, ETDAG
separation, and protected execution validation remain mandatory. Boot, seed,
relay, archive, RPC, explorer, and observer roles retain zero implicit vote
power unless their validator identity is in the frozen active set.
