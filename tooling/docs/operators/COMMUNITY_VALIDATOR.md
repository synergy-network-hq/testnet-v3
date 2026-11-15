# Community validator candidate workflow

Status: development candidate; onboarding and production qualification remain open.
This procedure never authorizes membership changes or live fleet operations.

1. Select a versioned release for the actual Linux architecture. Verify its
   independently authenticated release manifest, software hashes and Aegis source
   provenance before executing any binary. Supported hardware capacity remains
   subject to sustained five-host RSS, disk and finality qualification; no measured
   community hardware minimum is currently established.
2. Install with the canonical `node-platform/tools/linux-node` package lifecycle.
   Run its conformance verifier against the authenticated package manifest. Keep
   the signed network inputs and private custody outside public download roots.
3. Provision fresh custody through APQE, rather than the retired embedded keytool
   entry point. `node-platform/tools/validator/generate-identity.sh` forwards six
   explicit arguments to `/usr/bin/apqe validator-provision`: trusted native build
   report, independently authenticated report SHA256, `synv1` validator class, 32-byte lowercase
   hexadecimal chain ID, genesis hash and a new private directory. An explicit
   `APQE_BIN` can select the verified installed APQE executable. APQE prompts for
   the custody passphrase. Do not pass secrets on command lines or in logs. Store
   encrypted custody and passphrase backups separately with operator-controlled
   recovery access. Never clone an active validator signing identity.
4. The resulting enrollment request is public submission material, not active
   consensus membership. Have the network operator verify custody possession,
   chain/genesis binding and the exact consensus key against an approved admission
   decision. New governance/membership activation requires operational approval.
   APQE encrypted custody still needs the canonical node custody/signing-journal
   adapter before it can replace provisioned runtime keys; do not extract plaintext
   keys manually or point the node at an incompatible APQE JSON file.
5. Obtain independently authenticated signed Genesis, manifest, frozen authority,
   trust root, approved validator endpoints and validator-network enrollment from
   the operator. Numeric chain ID alone cannot identify a network incarnation.
   The historical five-node configuration is not permission to join it. Use the
   signed parameters for quorum and algorithm profiles, including protected ingress
   ML-KEM-1024 where selected; do not assume the older ML-KEM-768 profile.
6. Configure `aegis_provider.report_path` as an absolute protected native report
   path and `aegis_provider.authenticated_report_sha256` as its independently
   authenticated 64-character lowercase SHA256. Keep the report, provider libraries
   and loader dependencies immutable for node lifetime. Production authority,
   consensus, transport and execution initialization requires this explicit provider
   selection; the test fixture's embedded provider selection is unavailable in a
   production build. Then prepare an explicit validator configuration and run
   `synergy-node preflight --config /absolute/path/config.json`. This read-only
   command verifies signed Genesis/authority, startup plan, public identity and,
   for `validate_and_vote`, exact active frozen membership and consensus key ID.
   Inspect its `validator_membership_verified`, `consensus_key_id` and
   `active_validator_count` fields. Preflight never proves private-key possession,
   live connectivity, signing-journal safety or sustained finality.
7. Before approved startup, pass canonical package conformance and possession
   checks; ensure private key files and signing journals have restricted ownership
   and permissions. Isolate admin Unix sockets and validator RPC from public
   traffic. Approve VPN enrollment explicitly; peers must authenticate Synergy
   identity as well as network connectivity. Never publish VPN credentials.
8. Synchronize and observe the admitted validator with the approved release.
   Require identical advancing finalized block/state commitments across quorum
   peers, genuine funded transaction finality and clean signing safety. A running
   process or a connected VPN is insufficient. Monitor finality lag, peer
   authentication failures, memory, disk growth and signing/recovery errors.
9. Rehearse stop/restart, catch-up, partitions and interrupted persistence on an
   isolated fleet using the same release bytes. Preserve signing journals,
   authenticated Genesis, identity and required chain history. Never delete safety
   state, regenerate keys or change Genesis to cure a stall. Keep bounded diagnostic
   output only while needed for immediate diagnosis; remove disposable output when
   its verification purpose is complete.
10. Upgrade only through the package lifecycle after source and exact-byte
    qualification. Rehearse rollback compatibility before release; software rollback
    never authorizes restoring an obsolete signing journal or signing twice. Submit
    exact release identity, topology/membership delta, tests, rollback plan and go/no-go
    checks for operational approval before touching an active fleet.

Current release gates: authoritative APQE consumption in the canonical node,
Linux target execution/provenance, runtime custody/journal import, independent PQ
interoperability, sustained resource bounds and five-host operational acceptance.
The successful local funded-wallet socket regression does not close these gates.
