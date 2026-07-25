#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT_DIR/scripts/testnet/validator-vpn-coordinator-readiness.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

valid_env="$TMP_DIR/validator-vpn-coordinator.env"
cat >"$valid_env" <<'ENV'
SYNERGY_RESOURCE_ROOT=/opt/synergy/node-control-panel
SYNERGY_APP_DATA_DIR=/var/lib/synergy/node-control-panel
SYNERGY_CONTROL_SERVICE_DISABLE_LOCAL_AGENT=true
SYNERGY_VALIDATOR_VPN_COORDINATOR_URL=https://vpn-coordinator.synergy-network.io
SYNERGY_VALIDATOR_VPN_ENROLLMENT_SIGNATURE_MODE=challenge-sha256
SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN=test-token-for-readiness
SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY=ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
SYNERGY_VALIDATOR_VPN_COORDINATOR_PUBLIC_KEY=ed25519:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
SYNERGY_INNERNET_SERVER_COMMAND=/usr/local/bin/innernet-server
SYNERGY_INNERNET_INTERFACE=sy-vpn
SYNERGY_INNERNET_VALIDATOR_CIDR=validators
SYNERGY_INNERNET_RELAYER_CIDR=relayers
SYNERGY_INNERNET_VALIDATOR_ADDRESS_CIDR=10.70.10.0/24
SYNERGY_INNERNET_RELAYER_ADDRESS_CIDR=10.70.20.0/24
SYNERGY_INNERNET_CONFIG_DIR=/etc/innernet-server
SYNERGY_INNERNET_DATA_DIR=/var/lib/innernet-server
SYNERGY_INNERNET_INVITE_DIR=/var/lib/synergy/node-control-panel/innernet-invites
SYNERGY_INNERNET_INVITE_EXPIRES=30m
SYNERGY_INNERNET_MIGRATION_ID=testnet-innernet-v19
SYNERGY_INNERNET_COORDINATOR_SIGNING_KEY=ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY=ed25519:ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
ENV

"$SCRIPT" --env-file "$valid_env" --skip-http >"$TMP_DIR/valid.out"
grep -q "readiness passed" "$TMP_DIR/valid.out"

"$SCRIPT" --env-file "$valid_env" --url http://127.0.0.1:47895 --allow-http --skip-http >"$TMP_DIR/local-http.out"
grep -q "local HTTP" "$TMP_DIR/local-http.out"

if "$SCRIPT" --env-file "$valid_env" --url http://127.0.0.1:47895 --skip-http >"$TMP_DIR/local-http-denied.out" 2>&1; then
  echo "expected readiness to require --allow-http for local HTTP checks" >&2
  exit 1
fi
grep -q "local HTTP readiness requires --allow-http" "$TMP_DIR/local-http-denied.out"

missing_token_env="$TMP_DIR/missing-token.env"
grep -v '^SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN=' "$valid_env" >"$missing_token_env"
if "$SCRIPT" --env-file "$missing_token_env" --skip-http >"$TMP_DIR/missing-token.out" 2>&1; then
  echo "expected readiness to fail without SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN" >&2
  exit 1
fi
grep -q "SYNERGY_VALIDATOR_VPN_COORDINATOR_TOKEN is missing" "$TMP_DIR/missing-token.out"

bad_key_env="$TMP_DIR/bad-key.env"
sed 's#^SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY=.*#SYNERGY_VALIDATOR_VPN_COORDINATOR_SIGNING_KEY=sha256-legacy-key#' "$valid_env" >"$bad_key_env"
if "$SCRIPT" --env-file "$bad_key_env" --skip-http >"$TMP_DIR/bad-key.out" 2>&1; then
  echo "expected readiness to fail without an Ed25519 signing seed" >&2
  exit 1
fi
grep -q "coordinator signing key must use ed25519" "$TMP_DIR/bad-key.out"

bad_invite_expiry_env="$TMP_DIR/bad-invite-expiry.env"
sed 's#^SYNERGY_INNERNET_INVITE_EXPIRES=.*#SYNERGY_INNERNET_INVITE_EXPIRES=0m#' "$valid_env" >"$bad_invite_expiry_env"
if "$SCRIPT" --env-file "$bad_invite_expiry_env" --skip-http >"$TMP_DIR/bad-invite-expiry.out" 2>&1; then
  echo "expected readiness to reject a zero Innernet invite expiry" >&2
  exit 1
fi
grep -q "SYNERGY_INNERNET_INVITE_EXPIRES must match" "$TMP_DIR/bad-invite-expiry.out"

fake_bin="$TMP_DIR/fake-bin"
fake_config_dir="$TMP_DIR/innernet-config"
fake_data_dir="$TMP_DIR/innernet-data"
migration_env="$TMP_DIR/innernet-migration.env"
mkdir -p "$fake_bin" "$fake_config_dir" "$fake_data_dir"
printf '%s\n' '#!/usr/bin/env bash' 'echo 0' >"$fake_bin/id"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$fake_bin/systemctl"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$fake_bin/ip"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$fake_bin/wg"
printf '%s\n' '#!/usr/bin/env bash' 'echo "innernet-server 2.0.0"' >"$fake_bin/innernet-server"
chmod +x "$fake_bin/id" "$fake_bin/systemctl" "$fake_bin/ip" "$fake_bin/wg" "$fake_bin/innernet-server"
cp "$valid_env" "$migration_env"
printf '%s\n' \
  'SYNERGY_INNERNET_MIGRATION_READY=true' \
  "SYNERGY_INNERNET_SERVER_COMMAND=$fake_bin/innernet-server" \
  "SYNERGY_INNERNET_CONFIG_DIR=$fake_config_dir" \
  "SYNERGY_INNERNET_DATA_DIR=$fake_data_dir" >>"$migration_env"
printf '%s\n' 'private-key = "test"' >"$fake_config_dir/sy-vpn.conf"
printf '%s\n' 'test-db' >"$fake_data_dir/sy-vpn.db"
PATH="$fake_bin:$PATH" "$SCRIPT" --env-file "$migration_env" --skip-http >"$TMP_DIR/innernet-conf.out"
grep -q "Innernet server configuration, database, service, and WireGuard interface are active" "$TMP_DIR/innernet-conf.out"
rm "$fake_config_dir/sy-vpn.conf"
printf '%s\n' 'private-key = "test"' >"$fake_config_dir/sy-vpn.toml"
PATH="$fake_bin:$PATH" "$SCRIPT" --env-file "$migration_env" --skip-http >"$TMP_DIR/innernet-toml.out"
grep -q "Innernet server configuration, database, service, and WireGuard interface are active" "$TMP_DIR/innernet-toml.out"

echo "validator VPN coordinator readiness QA passed"
