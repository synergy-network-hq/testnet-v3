# Archive Canonical Reseed Runbook

This runbook is for the archive validator only. It does not authorize live
validator restarts, quorum changes, archive snapshot publication, or recovery
from archive snapshots before canonical reseed is verified.

## Safety Boundary

- Keep archive validator services stopped and unloaded until every gate below
  passes.
- Keep qRPC, metrics, P2P, WS, snapshot API, proxies, and monitoring from
  serving stale archive state during reseed.
- Do not use archive state as a validator recovery source until canonical
  identity, source proof, restore role, and current live height alignment are
  verified.
- Quarantine noncanonical archive data into a timestamped directory before any
  replacement.
- Use workbook-backed access and established host aliases for live work. Do not
  commit credentials, SSH commands with secrets, workbooks, private keys, or
  production logs.

## Required Inputs

- Canonical live source node role and read-only RPC endpoint.
- Expected chain ID `1264`, network ID `synergy-testnet-v3`, genesis hash, and
  operational manifest hash.
- Source height, source block hash, committed QC proof, and canonical lock proof.
- Archive target role and allowed restore role.
- Snapshot class: `archive-bootstrap` for initial restore or `archive-full` for
  complete archive reseed.

## Fail-Closed Gates

1. Archive disabled: service is stopped/unloaded and no archive runtime process
   is serving old state.
2. Identity match: chain ID, network ID, genesis hash, config identity, and
   validator identity material match the canonical testnet.
3. Source proof: source block hash, committed QC, canonical lock, and parent
   continuity are verified at the chosen height.
4. Snapshot class: manifest class is `archive-bootstrap` or `archive-full`, not a
   validator-pruned/support snapshot.
5. Restore role: manifest explicitly allows archive restore and rejects validator
   restore.
6. Hash roots: content root, state root, manifest digest, and file digests match
   before install.
7. Unsafe inventory: stale/noncanonical snapshots are listed and marked unsafe or
   quarantined.
8. Publication disabled: snapshot API and archive publication remain disabled
   until post-reseed verification passes.

## Command Surface

Target command names for the archive tooling:

```bash
synergy-node archive status --archive-services-disabled --snapshot-api-disabled --snapshot-worker-disabled --archive-publication-disabled --unsafe-inventory-reviewed --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive verify-canonical --manifest <signed-manifest.json> --snapshot-root <dir> --expected-height <height> --expected-block-hash <hash> --expected-snapshot-class <class> --source-canonical --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive reseed-plan --manifest <signed-manifest.json> --snapshot-root <dir> --archive-services-disabled --archive-publication-disabled --unsafe-inventory-reviewed --output <plan.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive reseed --dry-run --plan <plan.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive publish-snapshot --dry-run --manifest <signed-manifest.json> --snapshot-root <dir> --snapshot-api-disabled --snapshot-worker-disabled --source-canonical --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive list-unsafe-snapshots --inventory <inventory.json> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive mark-unsafe-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> --chain-id 1264 --network-id synergy-testnet-v3
synergy-node archive quarantine-snapshot --snapshot-id <id> --height <height> --snapshot-class <class> --block-hash <hash> --reason <reason> --chain-id 1264 --network-id synergy-testnet-v3
```

All commands above are implemented as offline/dry-run safety gates. They verify
signed manifests, file digests, state root, QC evidence, exact height/hash/class
proofs, archive restore role, containment flags, unsafe inventory state, and
publication/source safety, then exit nonzero on `NO_GO`. They do not install
data, delete snapshot data, start archive services, start snapshot API, start
snapshot worker, or publish snapshots.

`archive verify-canonical` may accept a validator-pruned support snapshot only
when `--allow-validator-pruned-support-snapshot` is present and exact
height/hash/class/source-canonical proof matches. Validator-pruned snapshots are
not trusted for archive reseed.

## Reseed Flow

1. Capture read-only live source evidence: latest height/hash, source height/hash,
   committed QC, canonical lock, and source node health.
2. Confirm archive containment: service stopped, ports not serving, stale process
   absent, and old state quarantined.
3. Generate or obtain a supported archive snapshot manifest from a canonical
   source node.
4. Run canonical verification against the manifest and snapshot root.
5. Build a reseed plan and review every file mutation before execution.
6. Run reseed in dry-run mode and confirm it refuses unsafe manifests while
   keeping archive services, snapshot API, and snapshot worker disabled.
7. Execute reseed only after operator approval and all fail-closed gates pass.
8. Start archive services only after data install and verification succeed.
9. Verify archive qRPC, metrics, P2P, monitoring, indexed height, and live-height
   catch-up state.
10. Keep snapshot publication disabled until a separate publish dry-run and
    public API safety review pass.

## Rollback

- Stop archive services.
- Move the attempted reseed data directory into a timestamped quarantine folder.
- Restore the prior contained/offline marker.
- Re-run `archive status` and document the blocker.
- Do not reconnect archive or publish snapshots after rollback unless the full
  canonical reseed flow passes again.
