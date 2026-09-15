# Synergy Validator Workspace

Canonical filesystem template, migration tooling, drift checks, and operator documentation for Synergy Testnet validators.

The live validator standard is:

- Linux user: `node`
- Workspace: `/home/node/.synergy/testnet/nodes/validator-workspace`
- Runtime data: `/var/lib/synergy/validator`
- Logs: `/var/log/synergy/validator`
- Config: `/etc/synergy/validator`
- Binary: `/opt/synergy/bin/synergy-validator`
- Service: `synergy-validator.service`
- Optional control panel service: `synergy-node-control-panel.service`

Secrets are never committed here. Files that normally hold private keys, passwords, tokens, WireGuard private keys, or validator identity material are represented only as `.example` files with placeholder values.

## Contents

- `template/` mirrors the target validator filesystem layout.
- `template/MANIFEST.yaml` defines required ownership, permissions, and drift behavior.
- `template/IDENTITY_FIELDS.yaml` lists the only values allowed to differ by validator.
- `template/DRIFT_CHECKS.yaml` defines byte-identical, mask-identical, expected-different, and forbidden paths.
- `template/opt/synergy/scripts/` contains dry-run-first install, migration, verify, rollback, drift, and block-time tools.
- `schemas/` contains machine-readable schemas for inventory and template validation.
- `tests/` validates that the template is complete and does not contain likely secrets.

## Required Workflow

1. Run the template tests before pushing changes:

   ```sh
   tests/test-required-files.sh
   tests/test-template-no-secrets.sh
   tests/test-render-config.sh
   python3 tests/test-mask-identity.py
   ```

2. For live hosts, run every mutation script in dry-run mode first.
3. Capture rollback backups before changing services, users, configs, keys, or data.
4. Migrate only one validator at a time.
5. Verify health before moving to the next validator.

