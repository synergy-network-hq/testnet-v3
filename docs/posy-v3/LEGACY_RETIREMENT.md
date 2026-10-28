# PoSy v3 legacy retirement and precedence

Status: fresh-P3 source policy. This map prevents historical algorithms from
being read as Genesis, proposal, or validator authority.

## Source-of-truth rule

The separate P3 chain starts at block zero. Its signed Genesis, canonical
schema-4 manifest, Genesis-bound five-validator activation, governed ETDAG
binding, and `POSY-00E` are the sole consensus authority. Retired-chain
Genesis, parameter roots, blocks, deployment state, and validator identities
are not migration inputs. No date, environment variable, operator toggle, or
local configuration can substitute for the signed P3 Genesis authority.

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

The old Rust engines remain source-visible for explicitly versioned historical
tests only; their production entry point remains disabled. They must not be
called as a fallback if v3 startup or quorum fails.

## Preserved compatibility

Historical v2.1/v2.2 objects may be parsed only by explicitly versioned audit
paths. They do not contribute authority in a v3 epoch or fresh-chain recovery.
Testnet-v2 material is retained outside the active worktree. Generic
floating-point values used for telemetry, gas, performance reporting, or
legacy parsing are not v3 scheduling inputs.

The Genesis activation record is the topology source. The v3 profile narrows
its first epoch to exactly five ACTIVE validators in
one cluster because that is the initial hardware-backed set. Five is not a
protocol limit. Future topology expansion becomes authoritative through an
approved, finalized v3 epoch transition that freezes the complete next set,
weights, keys, cluster map, and leader ring; the production transition bridge
and runtime integration remain later-epoch onboarding gates.

## Deliberately unchanged

Aegis ML-DSA-65 consensus authorization, durable signer journaling,
SafetyHalt, canonical roots/serialization, exact strict dual quorum, ETDAG
separation, and protected execution validation remain mandatory. Boot, seed,
relay, archive, RPC, explorer, and observer roles retain zero implicit vote
power unless their validator identity is in the frozen active set.
