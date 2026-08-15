# PoSy v3 single-authority to five-validator migration

Status: preparation only. Do not execute against live validators from this branch.

## Decision

Prefer a declared epoch-boundary protocol activation that preserves the last uncontested certified state. A clean Testnet-v3 re-genesis remains an alternative only if rehearsal shows that the current single-authority state cannot supply one unambiguous, fully verifiable transition anchor. Re-genesis changes continuity, application state, explorer history, addresses that bind genesis, wallet expectations, and audit evidence; it requires a separate operator/governance decision.

## Required migration record

Before rehearsal, create one signed/reviewed record containing:

- current single-authority final height, block ID, QC/context root, state root, receipts root, and protocol/parameter root;
- declared v3 activation epoch and exact first v3 height;
- five approved validator IDs and their public ML-DSA-65 key IDs/lifecycle records;
- five-validator active-set, key, frozen-weight, epoch-context, and leader-ring roots;
- canonical v3 parameter-manifest SHA3-512 root and governance approval ID;
- signed binary/release hashes and configuration-package hash;
- each validator's signer-journal format/readiness attestation without journal contents that expose secrets;
- all-five pre-activation and transition-state agreement;
- ETDAG activation state and protected-execution compatibility statement;
- named go/no-go authority and incident channel.

No field may be filled with a locally invented identity, key, credential, root, or activation coordinate.

## Offline rehearsal sequence

1. Verify the current v2.2 canonical manifest and root remain identical to the applied record.
2. Build the exact candidate binary reproducibly and verify its signatures/hashes on all five rehearsal hosts.
3. Load only the approved public identity topology. Verify exactly five active validators, one cluster, unique validator/key IDs, ML-DSA-65 key sizes/roles, nonzero weights, and no voting role for seed/relay/archive/RPC/explorer nodes.
4. Run the leave-one-out weight preflight. Reject any topology where one validator has one-third or more of total frozen voting weight or any four-validator subset lacks strict weight quorum.
5. Derive the v3 epoch context independently on all five nodes. Compare canonical bytes and active-set, key, weight, parameter, leader-ring, and context roots.
6. Verify every node has the same uncontested v2.2 transition anchor and application state. Stop if any root or finalized pointer differs.
7. Start shadow verification without v3 signing. Replay proposals/QCs/TCs, restart every node independently, and state-sync a blank rehearsal node from the certified bundle.
8. Run the five-process and full network failure matrix: each leader unavailable in turn, two unavailable, delayed/duplicated messages, partitions, heal, lease boundary, epoch boundary, and repeated failure.
9. Exercise ETDAG/BOC/reveal/protected execution under the exact activation state. It may delay proposals but must never create leader authority or lower quorum.
10. Capture latency, PQC, certificate-size, restart, and rejoin distributions over at least 10,000 representative blocks.
11. Rehearse abort before activation, inability to reach quorum after activation, conflicting-QC SafetyHalt, and state-sync corruption. No rehearsal may use journal deletion, forced leader, height editing, or ordered restart magic.
12. Submit the evidence package for governance/release approval. Only the finalized manifest and transition record may make the profile activatable.

## Boundary execution plan (future, separately authorized)

- Before the boundary: all five nodes stay on v2.2 authority and confirm the same transition anchor. Abort on any mismatch, missing signer/key, noncanonical manifest, missing release signature, or failed gate.
- At the boundary: accept the finalized transition certificate, atomically install the v3 context, restore/initialize durable v3 safety state, and require the scheduled owner from the committed ring. No node may infer the boundary from wall time.
- After the boundary: v2.2 consensus messages are sync/evidence only. Observe three-chain commits, TC authority, all roots, and node state. Do not call the network healthy until sustained evidence meets the existing launch policy.

## Rollback and fail-closed conditions

Before activation, aborting means continue the outgoing finalized profile and issue a new governed activation proposal. After any valid v3 QC, do not locally roll back to v2.2 or single authority. Halt signing and invoke governed recovery if there is a conflicting valid QC, divergent epoch/parameter/validator/key/weight/ring root, corrupted/missing durable safety record, signer-journal inconsistency, unverified transition anchor, or inability to establish the safe certified chain.

Loss of quorum is a safe stall, not a rollback trigger. Restore connectivity/availability or use separately governed membership recovery from the last valid QC. Never lower quorum.

## Re-genesis alternative

Choose re-genesis only through a separate decision when the current chain lacks a unique verifiable continuity anchor or rehearsal proves state conversion unsafe. The decision must enumerate state to preserve/discard, chain/network identifier impact, contract/address effects, wallet/explorer/indexer reset, allocation and supply reconciliation, old-chain archival, new genesis ceremony, public disclosure, and explicit prohibition on reusing incompatible identities or secrets.

