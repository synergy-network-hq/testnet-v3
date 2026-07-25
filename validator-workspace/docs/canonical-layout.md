# Canonical Layout

Every Synergy Testnet validator must use the same layout unless a validator-specific value is explicitly allowed in `template/IDENTITY_FIELDS.yaml`.

## Users and Ownership

- Runtime user: `node`
- Runtime group: `node`
- Service unit owner: `root:root`
- Runtime config owner: `root:node`
- Runtime data owner: `node:node`
- Secret key files owner: `node:node`, mode `0600`

## Paths

| Purpose | Canonical path |
| --- | --- |
| User home | `/home/node` |
| Workspace | `/home/node/.synergy/testnet/nodes/validator-workspace` |
| Config | `/etc/synergy/validator` |
| Keys | `/etc/synergy/validator/keys` |
| Binary | `/opt/synergy/bin/synergy-validator` |
| Scripts | `/opt/synergy/scripts` |
| Data | `/var/lib/synergy/validator` |
| Logs | `/var/log/synergy/validator` |
| Backups | `/var/backups/synergy/validator` |
| Systemd service | `/etc/systemd/system/synergy-validator.service` |
| Optional control panel service | `/etc/systemd/system/synergy-node-control-panel.service` |
| WireGuard | `/etc/wireguard` |

The workspace under `/home/node` is the operator-facing root. Symlinks from that workspace may point to `/etc`, `/var/lib`, and `/var/log`, but active services must use the canonical absolute paths above.

## Hot-Path Retention

Every validator service must include these non-secret environment settings in `/etc/synergy/validator/node.env`:

- `SYNERGY_CANONICAL_LOCK_RETAIN_ENTRIES=512`
- `SYNERGY_COMMITTED_QC_HOT_RETENTION_BLOCKS=4096`

Without canonical-lock retention, `canonical_locks.json` grows with the full chain and is rewritten on each block, which can push block times above the target cadence.

## Old Paths

Active services must not reference:

- `/home/justin/.synergy/testnet/nodes/validator-workspace`
- `/home/rob/.synergy/testnet/nodes/validator-workspace`
- `/home/synergyop/.synergy/testnet/nodes/validator-6-control-panel`
- Any `validator-6-control-panel` runtime path
