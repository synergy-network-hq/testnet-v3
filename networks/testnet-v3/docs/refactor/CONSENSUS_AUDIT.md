# Consensus audit

## Authority-semantics integrity gate — 2026-09-10

The current authoritative PoSy v3 profile is **not** an equal-numeric-weight
protocol. It uses two independent finality conditions over an approved, frozen
epoch context:

- a strict validator-count quorum; and
- a strict quorum of the approved frozen validator weights.

`protocol/posy-v3/POSY-00E-SIMPLIFIED-CONSENSUS-AMENDMENT.md:18-25` requires both
checked quorums (`3 * distinct_signers > 2 * active_validators` and
`3 * signed_weight > 2 * total_frozen_weight`). Its frozen-context definition
at `:27-44` requires the active-set and frozen-weight roots to be finalized at
the epoch boundary. `protocol/posy-v3/WHITEPAPER_ENGINEERING_UPDATE.md:7-15`
states that leader scheduling ranks frozen validator IDs without stake or
Synergy Score, while finality retains the approved frozen weights and count
and weight quorums. It also explicitly records the one-third frozen-weight
liveness constraint.

Therefore the prior `validate_uniform_posy_authority` check was unsupported
and has been removed from fresh-Genesis bootstrap and dynamic-topology
validation. The replacement regression test,
`frozen_validator_weight_commitment_preserves_non_uniform_weights`, protects
the approved non-zero frozen-weight commitment rather than inventing an
equal-weight rule.

## Required separations

- PoSy participation requires a finalized active validator in the epoch
  context. Process role selection, a local validator configuration, and VPN
  membership do not grant that authority.
- Stake is excluded from proposer authority by POSY-00E `:25`; it is not a
  substitute for the approved frozen finality-weight source.
- Synergy Score is excluded from proposer authority by POSY-00E `:25` and the
  whitepaper update `:7`. Runtime QC verification independently enforces the
  frozen-weight quorum in `runtime/src/consensus/dual_quorum.rs:2100-2108`;
  its nearby invariant states that Synergy Score affects rewards and rotation
  policy, never finality.
- ETDAG certificates remain transaction-layer evidence and cannot finalize a
  block or lower a PoSy quorum (POSY-00E `:12`, `:95-97`).

## Field provenance and code traces

`ValidatorRecord.voting_weight` is the current approved frozen
validator-weight value used by the v3 count-and-weight quorum. It is not shown
by the active PoSy v3 specification to be stake-derived. The field is
committed by `ValidatorSet::frozen_bonded_weight_root` in
`runtime/src/synergy_types.rs:1598-1612`, which canonicalizes
`(validator_id, voting_weight)` under the historical domain
`SYNERGY_FROZEN_BONDED_WEIGHT_ROOT_V1`. Git blame attributes that implementation
to commit `3011bfa` ("Verifying alignment with PoSy Specification Docs").
The `bonded` name is legacy and misleading; it does not prove that the current
committed value is stake.

`assigned_cluster_total_voting_weight` is the checked sum of the approved
active members in the assigned cluster. It is derived in
`runtime/src/synergy_types.rs:500-542`, bound into the height context, and
recomputed at verification boundaries including
`runtime/src/etdag.rs:497-532` and
`runtime/src/consensus/dual_quorum.rs:2100-2103`. It is consequently a
consensus-context commitment, not a cached or trusted certificate total.

The ETDAG names must not be mechanically removed or renamed: they are part of
the protected-input and finality bindings. Their semantic migration, if one is
approved, must version every dependent object and preserve validation of
existing commitments. The present code keeps them as frozen approved validator
weights, not as inferred PoS stake.

## Follow-up audit boundary

Legacy code still contains terms such as `bonded_weight`, `voting_power`, and
`stake_weight`. Each occurrence must be classified by its actual data source
before a migration. A legacy name alone is not proof of PoS leakage. Conversely,
a verified economic-stake dependency in the finality-weight derivation is a
release-blocking defect and must be removed with a versioned commitment
migration and regression tests.
