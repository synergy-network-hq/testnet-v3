# Preflight Validator Standardization Report

Date: 2026-06-15

## Repository Access

- `synergy-network-hq/validator-workspace`: accessible; initialized by this work.
- `synergy-network-hq/genval1`: accessible; local inventory checkout present.
- `synergy-network-hq/genval2`: accessible; local inventory checkout present.
- `synergy-network-hq/genval3`: accessible; local inventory checkout present.
- `synergy-network-hq/genval4`: accessible; local inventory checkout present.
- `synergy-network-hq/genval5`: accessible; local inventory checkout present.
- `synergy-network-hq/val6`: accessible; local inventory checkout present.
- `synergy-network-hq/synergy-node-control-panel`: accessible through local `node-control-panel` checkout.

## Current Inventory Status

Known pre-migration active workspace paths:

| Validator | Current user | Current workspace |
| --- | --- | --- |
| Val1 | `justin` | `/home/justin/.synergy/testnet/nodes/validator-workspace` |
| Val2 | `rob` | `/home/rob/.synergy/testnet/nodes/validator-workspace` |
| Val3 | `rob` | `/home/rob/.synergy/testnet/nodes/validator-workspace` |
| Val4 | `node` | `/home/node/.synergy/testnet/nodes/validator-workspace` |
| Val5 | `justin` | `/home/justin/.synergy/testnet/nodes/validator-workspace` |
| Val6 | `synergyop` | `/home/synergyop/.synergy/testnet/nodes/validator-6-control-panel` |

Required target for all validators:

- user: `node`
- workspace: `/home/node/.synergy/testnet/nodes/validator-workspace`
- service: `synergy-validator.service`
- binary: `/opt/synergy/bin/synergy-validator`
- config: `/etc/synergy/validator`
- data: `/var/lib/synergy/validator`
- logs: `/var/log/synergy/validator`

## Live Health Gate

Read-only live sampling before migration found:

- Val1, Val2, Val3, and Val6 were active/synced.
- Val4 and Val5 were synced but held in `QUARANTINED` duty-disabled state by `data/validator_quarantine.json`.
- Val4 and Val5 quarantine reason was `operator_approved_stopped_stale_validator_quarantine` from an earlier stale-validator recovery flow.
- Current block timing before this template work was around 7 seconds or higher, outside the 0.5s to 2.5s target.
- Val1 through Val5 active binary hash was `9c58e9cca3449c50d99c561111a74386ca6d22e79652034be926fb8028c31e49`.
- Val6 runs from a control-panel bundle path rather than the canonical binary path.

## Val4/Val5 Quarantine Recovery

During this preflight, the stale Val4/Val5 quarantine state was corrected before continuing broad standardization:

- Active binary rejoin preflight failed on both validators with `committed QC has 4 vote(s), 5 required`.
- Recovery helper `/tmp/synergy-testnet-linux-amd64.snapshot-6val` with hash `66b26c379456b5e7404900a67ec67778dcfc61ac6e235ec92426b5de2065c8e4` passed the same rejoin proof.
- Common activation proof used height `328000` and hash `45fae2950462206ac7f49c1ece88be3184ffac890371ab356bac40ae978d9c43`.
- Val4 rejoin result: `ACTIVE`, latest committed QC height `328600`, vote count `4`.
- Val5 rejoin result: `ACTIVE`, latest committed QC height `328598`, vote count `4`.
- Both validators preserved the old quarantine marker under `data/self-heal-evidence/<timestamp>-rejoin/validator_quarantine.json`.
- Post-rejoin RPC on Val4 and Val5 reported no active quarantine marker and all duty gates true.

Follow-up required:

- Promote the expanded active-set recovery verifier fix into the canonical binary deployed to every validator.
- Treat helper-binary drift as a hard parity failure until every validator runs the same canonical binary hash.

## Current Known Differences And Risks

- Users differ across validators: `justin`, `rob`, `node`, and `synergyop`.
- Val6 uses a custom `validator-6-control-panel` workspace and bundle-relative binary path.
- Val1 and Val3 did not expose local qRPC on `127.0.0.1:5640` during one post-rejoin sample, even though their validator processes were running.
- Val2 showed evidence of a transient duplicate validator process during one triage sample; a later process inspection showed only one active validator process. This still requires drift monitoring.
- Active services are not all using the canonical `synergy-validator.service` layout.
- Binary path and release provenance are not canonical across the fleet.
- Control panel installers currently create bundle-relative layouts and must be changed before future validators are onboarded.

## Proposed Migration Order

1. Finish and push this canonical template.
2. Update and tag the control panel so future validators use the canonical layout.
3. Reconcile canonical binary version/hash across the fleet.
4. Migrate Val4 first because it already uses user `node`; use it as the canonical Linux layout pilot.
5. Migrate Val5 or Val6 next only after a fresh health sample shows all active validators are stable.
6. Migrate Val3, Val2, and Val1 one at a time.
7. Keep Val6 migration last if control-panel state requires additional installer compatibility handling.

## Rollback Strategy

For each validator:

1. Capture service, process, config, key, data, genesis, binary, peer, qRPC, metrics, and quarantine status.
2. Create `/var/backups/synergy/validator/pre-node-migration-<timestamp>`.
3. Archive current config, key metadata, service files, and workspace metadata.
4. Preserve identity material in place or move it once into `/etc/synergy/validator/keys` with `0600` permissions.
5. Do not delete old workspace or chain data until post-migration health and parity checks pass.
6. Roll back only through `rollback-validator-migration.sh` or explicit operator-reviewed commands.

## Secret-Bearing Files

These live files must never be committed and must appear only as `.example` files in this repository:

- `/etc/synergy/validator/node.env`
- `/etc/synergy/validator/keys/validator-key.json`
- `/etc/synergy/validator/keys/node-identity-key.json`
- `/etc/synergy/validator/keys/p2p-key.json`
- `/etc/synergy/validator/keys/consensus-key.json`
- `/etc/synergy/validator/keys/account-key.json`
- `/etc/wireguard/wg0.conf`
- any control-panel token, RPC token, API token, password, seed phrase, or private key file

## Canonical Template Structure

The repository now includes:

- documentation under `docs/`
- real filesystem template under `template/`
- manifest under `template/MANIFEST.yaml`
- identity allowlist under `template/IDENTITY_FIELDS.yaml`
- drift policy under `template/DRIFT_CHECKS.yaml`
- schemas under `schemas/`
- safe examples under `examples/`
- validation tests under `tests/`
- GitHub Actions validation under `.github/workflows/validate-template.yml`

