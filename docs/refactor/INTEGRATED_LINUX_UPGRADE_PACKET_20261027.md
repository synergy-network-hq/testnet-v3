# Five-validator software-only upgrade packet — NOT EXECUTED

This packet is reviewable preparation, **not authorization**. The five real
validators and soak remain stopped. Approval must name this exact candidate and
software-only scope. No state import/deletion, key or genesis change, VPN restart,
PoSy start, qualification or load is included.

## Exact candidate

Release `synergy-linux-3e2ede6cd37aaf44`, manifest SHA256
`5a9e87db51f431cf7490806ad98e813206a44e2d34fbb08d3b3a25f4f95a91bf`;
node SHA256 `a52ae7f2e50445ae2b8141107cb741f071226ffeef833908f9887708a981b366`.
Canonical master:
`/Volumes/PortableSSD/Synergy-Network/Node-Architecture/Linux/Synergy`.
Sealed transfer archive:
`node-platform/target/engineering-recovery-20261026/linux-release-build2/package.tar`,
SHA256 `1c5ab1e1aefee17be4729d4ab5d1a7922297cfc859840f3835e91f08394eb9b8`.

Current all-five expected manifest:
`fe6ed3f0f061e2a272b0b5efca180eaa300ab3b7be5625bb1c4676565be81ae8`;
node `9b989c5f39df9fcc05f7f1c57d7b5fd6ec77101558b49322216dddf941d927c4`.
Current normalized configuration fingerprint:
`025941aa67e9cf32e97c6e97e70a18cde2c0949d3e7754bd7909255565d83214`.
Every host is `/opt/Synergy`, commissioned, storage marker1. Preserve every
host's existing network/identity/runtime bytes; do not use Val2 as a state source.

## Preflight after approval, before any staging

1. Re-read canonical continuation, latest report and operator authorization.
   Reuse exactly one existing SSH master per host. No generic retry loop.
2. Refresh identical read-only old-release conformance all five using
   `tools/validator/audit-linux-fleet.py`, selected old manifest above, and current
   schema/policy. Refuse any unexplained drift. Independently require node
   inactive/dead/MainPID0, no active qualification/load/soak and no conflicting
   application process. Preserve active owned VPN; no VPN restart is authorized.
3. Verify local master14-file inventory, exact manifest and tar hashes. Verify
   candidate source/template receipt. No release rebuild or reseal in deployment.
4. Capture per-host read-only runtime file inventory/hashes/inodes and public
   network/config commitments before replacement. Do not export private key
   contents or any database. Keep local keys/root-owned permissions unchanged.
   Record effective unit bytes, active VPN PID/executable inode and current
   `/opt/Synergy/package.json`/installation receipt.
5. If a SQLite archive/hot journal unexpectedly exists, halt and review its
   provenance. The current old release should have no new archive. Standalone
   conformance is read-only; do not delete a journal to make it pass. Explicit
   SQLite recovery, if needed, is a separate reviewed state operation.

## Same procedure on Val2, Val3, Val4, Val5, Val6

Proceed sequentially, stop on first unexplained failure. For each host, transfer
only the sealed **software** archive to an operator-approved temporary location
outside `/opt/Synergy`; this is an ephemeral deployment artifact, never a second
source checkout or alternate installation. Restrict staging to root0700 and
files0600/required executable0700. Reject absolute/traversing/symlink archive
members and AppleDouble metadata. Verify tar hash before extraction and exact
package manifest/file hashes afterward. No private or network identity comes
from the package.

With `CANDIDATE` bound to that reviewed extracted package directory, run:

```sh
sudo python3 -B "$CANDIDATE/tools/synergy_linux.py" verify-package "$CANDIDATE"
sudo python3 -B "$CANDIDATE/tools/lifecycle.py" upgrade \
  --root /opt/Synergy --package "$CANDIDATE"
sudo python3 -B /opt/Synergy/tools/conformance.py \
  --root /opt/Synergy --expected-manifest "$CANDIDATE/package.json" --host
```

The upgrader checks attributed effective units and stopped PoSy, validates old
software and configuration, records a durable package-bound intent, replaces
sealed software atomically, updates only attributed unit/wrapper definitions,
and completes new receipt/conformance. It starts neither PoSy nor VPN. An owned
active VPN keeps its old executable inode; `vpn_restart_required` is a report,
not permission to restart it. The unchanged pinned NetBird binary does not waive
that boundary.

After each host, independently require new exact software hashes and the same
normalized configuration; root/schema/caps/unit paths/drop-in absence; nodePID0;
unchanged active VPN PID/inode and public identity; and unchanged key/state/
journal/config/network inodes and bytes except explicitly recorded software
receipts. Do not call lifecycle `start-check` during deployment: it may perform
native SQLite recovery. Never invoke `start`, `restart`, enrollment, init, genesis
generation, historical import or workload scripts.

After all five, run the identical fleet verifier against the new reviewed
manifest; retain per-host results. Remove only attributed transfer scratch after
verification, leaving durable upgrade receipts. Review any unexpected footprint;
do not broaden the conformance allowlist on a live host to bypass it.

## Interrupted replacement, history and rollback

An interrupted software replacement is recovered by **forward completion with
the exact same package** and recorded intent. Third-party bytes or another
candidate fail closed. Do not reset/delete the intent or restore old journals.
If a failure cannot be explained by the verified forward path, keep PoSy stopped
and preserve all bytes. There is no automatic rollback.

Legacy histories remain readable without import or deletion. New history uses
the exact-byte indexed archive when consensus later runs under separate approval.
The Linux public-state rehearsal checks old/mixed/indexed compatibility and
legacy-only reopening before new work. It does not qualify old-binary downgrade.
Archive process crash/rollback recovery is separately tested. Never erase legacy
files merely because import succeeded.

Once any new signing reservation, exact signature, QC, finality, archive-only
record or delivery progress exists, old readers/journal restoration may lose
safety history. **No post-activation downgrade/export is qualified.** Preserve
everything and obtain an explicitly tested recovery procedure. Even before new
writes, software reversal requires demonstrated complete state compatibility;
it is not authorized by this packet.

## Evidence supporting this packet

See `INTEGRATED_LINUX_RECOVERY_REPORT_20261027.md`, its completion evidence
manifest, Linux21-operation lifecycle transcript, native50-record public-state
rehearsal, process crash/hot-journal tests, exact source/build/ELF receipts and
all-five old-release conformance. The VM contained disposable fixture keys only;
uninstall tests were confined to that VM. Do not run uninstall against the fleet.

After an approved application, report installed hashes and stopped state per
host. Network restart, governed workload authorization, TPS and soak require
their own concrete approvals and unchanged qualification gates.
