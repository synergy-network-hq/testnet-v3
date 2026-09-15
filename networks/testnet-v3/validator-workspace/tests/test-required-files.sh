#!/usr/bin/env bash
set -euo pipefail

required=(
  README.md
  VERSION
  CHANGELOG.md
  docs/canonical-layout.md
  docs/migration-guide.md
  docs/secret-handling.md
  template/MANIFEST.yaml
  template/IDENTITY_FIELDS.yaml
  template/DRIFT_CHECKS.yaml
  template/etc/synergy/validator/config.toml.example
  template/etc/synergy/validator/node.env.example
  template/etc/synergy/validator/genesis.json.example
  template/etc/synergy/validator/chain-spec.json.example
  template/etc/synergy/validator/keys/validator-key.json.example
  template/etc/wireguard/wg0.conf.example
  template/etc/systemd/system/synergy-validator.service
  template/opt/synergy/scripts/install-validator-workspace.sh
  template/opt/synergy/scripts/migrate-validator-to-node-user.sh
  template/opt/synergy/scripts/verify-validator-workspace.sh
  template/opt/synergy/scripts/compare-validator-workspace.sh
  template/opt/synergy/scripts/check-block-times.sh
  schemas/validator-layout.schema.json
  examples/validator-identity.example.json
)

for path in "${required[@]}"; do
  [[ -e "$path" ]] || { echo "missing required file: $path" >&2; exit 1; }
done

echo "required files present"

