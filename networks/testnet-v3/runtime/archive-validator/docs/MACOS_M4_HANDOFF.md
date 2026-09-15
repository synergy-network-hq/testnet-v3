# Synergy Testnet Archive Validator M4 Handoff

This zip is the internal Apple Silicon handoff for the non-consensus Synergy
Testnet 1264 Archive Validator. It includes the archive runtime, Aegis CLI,
snapshot authority controller, role policy, launchd persistence, and checksums.
It does not include private keys, credentials, or a preloaded chain database.
The default non-VPN topology uses Relayer1 and Relayer2 as persistent peers:

- `195.26.241.95:5622`
- `94.72.117.108:5622`

The package does not use obsolete legacy bootnode or seed DNS defaults, and it
does not configure direct private validator addresses.

## Install

On the target M4 Mac Mini:

```bash
cd /Volumes/Synergy_Archive
shasum -a 256 synergy-archive-validator-testnet-v3-macos-m4-storage-volume.zip
unzip -o synergy-archive-validator-testnet-v3-macos-m4-storage-volume.zip
cd synergy-archive-validator-testnet-v3-macos-m4
sudo env PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" \
  bash ./setup-archive-validator-m4.sh \
  --public-host 73.79.66.255 \
  --snapshot-api-bind 0.0.0.0:48640 \
  --yes
sudo ./verify-archive-validator-m4.sh
```

The installer fails closed unless `/Volumes/Synergy_Archive` is mounted as a
filesystem before setup starts. The mounted volume is used only for snapshot
publication and bootstrap staging. Binaries and launchd plists are installed in
the normal system locations, while live runtime/workspace/log/evidence/tmp/key
storage stays on the local M4 system disk under:

```text
/Users/Shared/Synergy/archive-validator
```

SMB-backed storage is limited to:

```text
/Volumes/Synergy_Archive/archive-validator/snapshots
/Volumes/Synergy_Archive/archive-validator/incoming/bootstrap
```

The split paths are one installation contract. The defaults above can be
overridden together with `--app-root`, `--publish-root`, and `--storage-volume`
or with `SYNERGY_ARCHIVE_APP_ROOT`, `SYNERGY_SNAPSHOT_PUBLISH_ROOT`, and
`SYNERGY_ARCHIVE_STORAGE_VOLUME`. The installer rejects a publish tree inside
the local runtime tree and rejects a publish tree outside the selected storage
volume. Do not substitute a similarly named volume.

The installer verifies the packaged checksums and Apple Silicon executables,
installs `zstd` through Homebrew if required, removes quarantine attributes from
the package and installed payloads, sets root-owned executable and LaunchDaemon
permissions, ad-hoc signs the installed executables, creates the archive Aegis
identity locally, installs three launchd services, bootstraps/enables/kickstarts
them, and fails closed unless the services stay running with the required
listeners:

- `io.synergynetwork.archive-validator`
- `io.synergynetwork.archive-snapshot-api`
- `io.synergynetwork.archive-snapshot-worker`

Required listener proof at install/verify time:

- archive P2P: `127.0.0.1:5622`
- snapshot API: `0.0.0.0:48640`
- archive qRPC: `127.0.0.1:5640`
- archive WS: `127.0.0.1:5660`
- archive metrics: `127.0.0.1:6030`

`archive_validator_verify_ok=true` is printed only after the verifier proves the
installed payload signatures/permissions, launchd running state, required
listeners, and a live `synergy_getLatestBlock` qRPC response.

The archive node syncs chain state into local storage:

```text
/Users/Shared/Synergy/archive-validator/workspace/data
```

Published snapshots and the signed catalog live under:

```text
/Volumes/Synergy_Archive/archive-validator/snapshots
```

## Manual Bootstrap Restore

If the archive node is at genesis and organic deep sync is unavailable, restore
a verified `archive-full` or explicitly limited `archive-bootstrap` artifact
before recording majority proof or publishing snapshots. `archive-bootstrap` is
a launch seed for getting the Archive Validator near head; it is not proof that
the node has complete historical archive coverage from genesis. Put the
bootstrap file on the Mac under the SMB bootstrap staging path, then run:

```bash
cd synergy-archive-validator-testnet-v3-macos-m4
sudo mkdir -p /Volumes/Synergy_Archive/archive-validator/incoming/bootstrap
sudo cp /path/to/archive-bootstrap-data.tar.zst \
  /Volumes/Synergy_Archive/archive-validator/incoming/bootstrap/
sudo ./restore-archive-bootstrap-m4.sh \
  --snapshot /Volumes/Synergy_Archive/archive-validator/incoming/bootstrap/synergy-archive-bootstrap-postfork-h<height>-v13.0.69.tar.zst \
  --sha256 <expected-sha256> \
  --yes
```

The restore helper stops the archive node and snapshot worker, verifies the
archive checksum, validates the bootstrap manifest class and post-fork metadata,
rejects `validator-pruned` unless a dangerous explicit override is passed,
rejects key/config material inside the restored data payload, backs up the
existing workspace data, restores the bootstrap data into:

```text
/Users/Shared/Synergy/archive-validator/workspace/data
```

Then it restarts and kickstarts the archive node, snapshot API, and snapshot
worker. For `archive-bootstrap`, the helper writes
`/Users/Shared/Synergy/archive-validator/evidence/archive-bootstrap-limitation.json`
with `historical_archive_complete_from_genesis=false`. `archive_bootstrap_restore_ok=true`
is printed only after the restored archive qRPC returns
`synergy_getLatestBlock`. After restore, preserve local qRPC height/hash parity
before enabling publication:

```bash
curl -s http://127.0.0.1:5640/ \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}'
```

Do not run `record-majority-proof`, `create-snapshot`, or `publish-snapshot`
while local archive qRPC is still at genesis or materially behind public RPC.

## Snapshot Publication Gate

The worker is intentionally fail-closed until current validator-majority proof
has been preserved and recorded. After the archive node reaches validator
parity, preserve the evidence file and run:

```bash
sudo /usr/local/synergy/bin/synergy-archive record-majority-proof \
  --height <validator-common-height> \
  --hash <validator-common-hash> \
  --evidence-path <preserved-validator-monitor-evidence.json> \
  --output "/Users/Shared/Synergy/archive-validator/evidence/source-majority-branch-proven.json"
```

The unattended worker must run without `--snapshot-class`. In that default mode
it walks only the currently used role classes and publishes eligible
`validator-pruned`, `support-relayer`, `support-observer`, `indexer-replay`,
`support-rpc`, and `archive-full` artifacts at their configured cadences.
`archive-full` is created every 15,000 finalized blocks; all other default
classes are created every 5,000 finalized blocks. A class-specific
`--snapshot-class` is only for bounded manual repair runs.

The worker launchd job uses `KeepAlive` plus a five-minute `StartInterval` and
passes both resolved roots explicitly. It remains fail-closed when the proof
marker is missing, invalid, stale, or does not match the latest local canonical
height and hash, so a disconnected or lagging archive cannot publish an older
snapshot.

For an operator-triggered snapshot:

```bash
sudo /usr/local/synergy/bin/synergy-archive create-snapshot \
  --workspace "/Users/Shared/Synergy/archive-validator/workspace" \
  --snapshot-class validator-pruned \
  --majority-proof-marker "/Users/Shared/Synergy/archive-validator/evidence/source-majority-branch-proven.json"
```

The publisher checks finalized QC proof, class compatibility, manifest
signature, file checksums, state consistency, forbidden material, free space,
zstd integrity, chunk hashes, reconstructed archive hash, and receiver-side
runtime verification before atomically updating the signed catalog.

## Operator Checks

```bash
sudo ./verify-archive-validator-m4.sh
sudo /usr/local/synergy/bin/synergy-archive status
sudo /usr/local/synergy/bin/synergy-archive catalog
sudo /usr/local/synergy/bin/synergy-archive prune
```

Use `prune --apply` only after reviewing the dry run. Published snapshots can be
pinned with `pin` and unpinned with `unpin`; pruning enforces the class retention
minimum and 24-hour retirement grace period.

## Receiver Verification

Receivers must verify the class before extraction:

```bash
/usr/local/synergy/bin/synergy-archive verify-distribution \
  --input <downloaded-snapshot-directory> \
  --workspace <receiver-workspace> \
  --target-role validator \
  --extract-root <temporary-verification-directory>
```

A `support-rpc`, `support-relayer`, or `indexer-replay` receiver uses its own
role. Wrong-class artifacts are rejected before extraction or apply.

## Local Acceptance

The handoff zip can be retested on an Apple Silicon Mac without installing
system services:

```bash
./run-isolated-mac-acceptance.sh
```

The isolated run verifies installer behavior, installed checksums/signatures,
launchd-equivalent startup using the rendered plist `ProgramArguments`, required
alternate-port listeners, live qRPC latest-block response, worker fail-closed
pending majority proof, Aegis PQC sign/verify, archive-role qRPC startup, signed
catalog publication, zstd chunk reassembly, runtime receiver verification,
wrong-class rejection, resumable HTTP range serving, staging-path denial, and
launchd plist syntax.
