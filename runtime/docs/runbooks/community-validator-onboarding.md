# Community Validator Onboarding Runbook

This runbook covers dry-run onboarding preflight, bundle planning, dry-run
vote-only join checks, and offline activation eligibility gates. It does not
authorize live validator activation, validator restarts, key changes, WireGuard
changes, archive snapshot use, or chain-state mutation.

## Preflight

```bash
synergy-node validator onboarding-preflight \
  --input candidate-validator.json \
  --output onboarding-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The command prints a machine-readable report and exits nonzero on `NO_GO`.

## Bundle Manifest

```bash
synergy-node validator onboarding-bundle \
  --input validator-bundle-input.json \
  --output validator-bundle-manifest.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

The bundle command emits a dry-run manifest for the standardized validator
workspace. It requires signed release, network config, validator-set, and
checkpoint manifest digests. It emits `.example` paths for operator-editable
config, systemd, firewall, and optional WireGuard material and must not include
real keys or secrets.

## Dry-Run Join

```bash
synergy-node validator onboarding-dry-run-join \
  --input validator-join-input.json \
  --output validator-join-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

Dry-run join only approves the next `vote_only` stage when observer sync is
complete, finalized head and high QC match quorum evidence, config and
validator-set digests match, the binary digest is approved, no unresolved local
fork evidence exists, an approval record is present, and proposer probation is
configured.

## Offline Closeout Gates

```bash
synergy-node validator enrollment-token verify \
  --input enrollment-token.json \
  --output enrollment-token-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator package verify \
  --manifest validator-package.json \
  --output validator-package-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator identity-bundle verify \
  --input identity-bundle.json \
  --output identity-bundle-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator cluster-assignment preview \
  --input cluster-assignment.json \
  --output cluster-assignment-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3

synergy-node validator activation-eligibility \
  --input activation-eligibility.json \
  --output activation-eligibility-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v3
```

These commands validate enrollment token evidence, appliance package
compatibility, identity bundle schema, backup verification proof, dynamic
cluster assignment preview, config render manifest, observer sync proof,
vote-only eligibility, proposer probation eligibility, and final activation
eligibility. All are offline and dry-run only.

## Required Evidence

- Testnet v3 chain ID and network ID.
- Unique validator ID and validator UMA ID.
- Finalized slashable stake of at least `50,000 SNRG`.
- Verified Aegis/PQC consensus, peer, and operator key roles.
- NAT, P2P, and discovery reachability.
- Dynamic cluster assignment and expanded planned validator count.
- Explicit rollback plan.
- Bundle manifest path before handoff.
- Signed release binary digest, network config digest, validator-set digest, and
  checkpoint manifest digest.
- Quorum finalized head, high QC, config digest, validator-set digest, and
  approved binary digest for dry-run join.
- Enrollment token scope, expiry, revocation, and issuer-signature proof.
- Appliance package GO artifact decision, signed release digest, config schema,
  target architecture, and no-secret declaration.
- Identity bundle manifest digest and backup restore-test proof.
- Dynamic cluster assignment preview with anti-affinity and fault-domain
  diversity proof.
- Config render manifest with `.example` operator-editable paths and rollback
  plan.
- Observer sync proof, vote-only proof, proposer probation proof, and verified
  latest finalized state proof for activation eligibility.

## Fail-Closed Conditions

Preflight rejects wrong chain/network, duplicate identity, insufficient stake,
missing key-role proof, failed NAT/P2P/discovery checks, missing cluster
assignment, non-expanding validator count, or missing rollback plan.

Bundle generation also rejects missing signed digests, failed preflight, missing
workspace root, or missing service user. Dry-run join rejects observer sync
gaps, finalized-head or high-QC mismatch, digest mismatch, unapproved binary
digest, unresolved local fork evidence, missing approval, missing vote-only
request, or missing proposer probation.

Enrollment token verification rejects expired, revoked, wrong-chain,
wrong-network, wrong-scope, or signature-unverified tokens. Package verification
rejects NO-GO artifacts, secret-bearing packages, missing digests, and archive
snapshot dependencies. Identity bundle verification rejects missing backup
proof or unverified key roles. Cluster assignment preview rejects unsafe dynamic
assignments. Activation eligibility rejects observer/vote-only proposer
requests, missing proposer probation, archive-contained dependency, missing or
unverified latest state proof, and any incomplete upstream gate.
