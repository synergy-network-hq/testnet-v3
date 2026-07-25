# Proof Of Synergy Validator Lifecycle

The offline onboarding lifecycle is:

1. Enrollment token verification.
2. Identity bundle verification.
3. Appliance package compatibility verification.
4. Cluster assignment preview.
5. Config render manifest verification.
6. Observer sync proof.
7. Vote-only eligibility.
8. Proposer probation eligibility.
9. Activation eligibility.

Each stage is evidence-driven and fail-closed. These checks do not authorize
live activation, service restart, key creation, WireGuard changes, archive
snapshot use, or chain-state mutation.

## Duty Gates

- `observer`: can sync and prove finalized/high-QC/state evidence, but cannot
  vote or propose.
- `vote_only`: can request vote-only rejoin after finalized head, high QC,
  config digest, validator-set digest, binary digest, approval, and fork checks
  pass. It cannot propose.
- `proposer_probation`: can become proposer-eligible only after the configured
  clean probation window passes.
- `active`: requires a clean proof chain across enrollment token, identity
  bundle, package, cluster assignment, config render, observer sync, vote-only,
  proposer probation, and state proof.

## Activation Blockers

Activation fails closed when:

- chain or network identity is wrong;
- enrollment token is expired, revoked, scoped incorrectly, or signature
  unverified;
- package artifact decision is not GO or embeds secrets;
- identity bundle lacks verified key-role proofs or backup proof;
- cluster assignment is unsafe or depends on archive-contained evidence;
- config render uses live config paths instead of `.example` templates or
  contains secrets;
- observer sync has finalized-head, high-QC, or state-proof mismatch;
- observer or vote-only stages request proposer duties;
- proposer probation is missing or incomplete;
- archive-contained evidence is present;
- latest finalized state proof is missing or unverified.
