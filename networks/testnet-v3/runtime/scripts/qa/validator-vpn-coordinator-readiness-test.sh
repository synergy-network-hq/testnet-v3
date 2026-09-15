#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
readiness="$repo_root/scripts/testnet/validator-vpn-coordinator-readiness.sh"
deploy_dir="$repo_root/deploy/validator-vpn-coordinator"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

failures=0
pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; failures=$((failures + 1)); }

assert_contains() {
  local path="$1" pattern="$2" description="$3"
  if grep -Eq -- "$pattern" "$path"; then pass "$description"; else fail "$description"; fi
}

assert_contains "$deploy_dir/innernet-server@.service" '^User=root$' 'serve unit is explicitly root'
assert_contains "$deploy_dir/innernet-server-add-peer@.service" '^User=root$' 'add-peer unit is explicitly root'
assert_contains "$deploy_dir/innernet-server-add-peer@.service" 'EnvironmentFile=-/etc/default/validator-vpn-coordinator' 'add-peer unit loads coordinator environment'
assert_contains "$deploy_dir/innernet-server-add-peer@.service" '^IPAddressDeny=any$' 'add-peer trigger denies network access by default'
assert_contains "$deploy_dir/innernet-server-add-peer@.service" '^IPAddressAllow=127\.0\.0\.1$' 'add-peer trigger retains localhost exposure'
assert_contains "$deploy_dir/validator-vpn-coordinator-add-peer.sh" --auto-ip 'add-peer is auto-addressed'
assert_contains "$deploy_dir/validator-vpn-coordinator-add-peer.sh" --admin=false 'add-peer does not prompt for admin status'
assert_contains "$deploy_dir/validator-vpn-coordinator-add-peer.sh" --yes 'add-peer bypasses confirmation'
assert_contains "$deploy_dir/validator-vpn-coordinator-add-peer.sh" --save-config 'add-peer saves an invitation without prompting'
assert_contains "$deploy_dir/validator-vpn-coordinator-add-peer.sh" 'SYNERGY_INNERNET_INVITE_EXPIRES:-30m' 'add-peer has a 30m expiry fallback'
assert_contains "$deploy_dir/validator-vpn-coordinator.env.example" '^SYNERGY_INNERNET_INVITE_EXPIRES=30m$' 'deployment env recommends a 30m invite expiry'

chmod +x "$readiness" "$deploy_dir/validator-vpn-coordinator-add-peer.sh"

stub_bin="$tmp_dir/bin"
mkdir -p "$stub_bin" "$tmp_dir/etc/innernet-server" "$tmp_dir/var/lib/innernet-server" "$tmp_dir/unit"
printf 'private-key = "test"\nlisten-port = 51820\naddress = "10.70.10.1"\nnetwork-cidr-prefix = 24\n' > "$tmp_dir/etc/innernet-server/sy-validator0.conf"
printf 'sqlite-placeholder\n' > "$tmp_dir/var/lib/innernet-server/sy-validator0.db"
printf '[Service]\nUser=root\n' > "$tmp_dir/unit/innernet-server@.service"

cat > "$stub_bin/id" <<'EOF'
#!/usr/bin/env bash
printf '0\n'
EOF
cat > "$stub_bin/innernet-server" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == --version ]]; then printf 'innernet-server 2.0.0\n'; fi
EOF
cat > "$stub_bin/innernet-server-capture" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${INNERNET_CAPTURE_FILE:?}"
EOF
cat > "$stub_bin/systemctl" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  show) printf 'root\n' ;;
  is-enabled|is-active) exit 0 ;;
  *) exit 1 ;;
esac
EOF
cat > "$stub_bin/ip" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$stub_bin/wg" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$stub_bin"/*

if PATH="$stub_bin:$PATH" \
  ID_BIN="$stub_bin/id" \
  INNERNET_SERVER_BIN="$stub_bin/innernet-server-capture" \
  INNERNET_INVITE_ROOT="$tmp_dir/invites" \
  SYNERGY_INNERNET_INVITE_EXPIRES=30m \
  PEER_NAME=validator-7 \
  PEER_CIDR=validators \
  PEER_INVITE_PATH="$tmp_dir/invites/validator-7.toml" \
  INNERNET_CAPTURE_FILE="$tmp_dir/innernet-argv" \
  "$deploy_dir/validator-vpn-coordinator-add-peer.sh" sy-validator0 && \
  grep -Fxq -- '--invite-expires' "$tmp_dir/innernet-argv" && \
  grep -Fxq -- '30m' "$tmp_dir/innernet-argv"; then
  pass 'add-peer wrapper passes the configured 30m expiry to innernet-server'
else
  fail 'add-peer wrapper must pass the configured expiry to innernet-server'
fi

if PATH="$stub_bin:$PATH" \
  SYNERGY_INNERNET_MIGRATION_READY=true \
  SYNERGY_INNERNET_INVITE_EXPIRES=30m \
  INNERNET_SERVER_BIN="$stub_bin/innernet-server" \
  SYNERGY_INNERNET_UNIT_FILE="$tmp_dir/unit/innernet-server@.service" \
  INNERNET_CONFIG_DIR="$tmp_dir/etc/innernet-server" \
  INNERNET_DATA_DIR="$tmp_dir/var/lib/innernet-server" \
  INNERNET_CONFIG_FILE="$tmp_dir/etc/innernet-server/sy-validator0.conf" \
  INNERNET_DATABASE_FILE="$tmp_dir/var/lib/innernet-server/sy-validator0.db" \
  SYNERGY_INNERNET_SERVICE=innernet-server@sy-validator0.service \
  "$readiness" >/dev/null; then
  pass 'positive readiness path validates root, service, version, config, database, and interface'
else
  fail 'positive readiness path should pass with staged prerequisites'
fi

if PATH="$stub_bin:$PATH" \
  SYNERGY_INNERNET_MIGRATION_READY=true \
  INNERNET_SERVER_BIN="$stub_bin/innernet-server" \
  SYNERGY_INNERNET_UNIT_FILE="$tmp_dir/unit/innernet-server@.service" \
  INNERNET_CONFIG_DIR="$tmp_dir/etc/innernet-server" \
  INNERNET_DATA_DIR="$tmp_dir/var/lib/innernet-server" \
  INNERNET_CONFIG_FILE="$tmp_dir/etc/innernet-server/missing.conf" \
  INNERNET_DATABASE_FILE="$tmp_dir/var/lib/innernet-server/missing.db" \
  SYNERGY_INNERNET_SERVICE=innernet-server@sy-validator0.service \
  "$readiness" >/dev/null 2>&1; then
  fail 'negative readiness path should reject missing initialized state'
else
  pass 'negative readiness path rejects missing initialized state'
fi

if PATH="$stub_bin:$PATH" \
  SYNERGY_INNERNET_MIGRATION_READY=false \
  SYNERGY_INNERNET_INVITE_EXPIRES=0m \
  INNERNET_SERVER_BIN="$stub_bin/innernet-server" \
  SYNERGY_INNERNET_UNIT_FILE="$tmp_dir/unit/innernet-server@.service" \
  "$readiness" >/dev/null 2>&1; then
  fail 'readiness should reject zero-valued invite expiry'
else
  pass 'readiness rejects zero-valued invite expiry'
fi

if (( failures > 0 )); then
  printf 'validator-vpn-coordinator-readiness-test: FAILED (%d failure(s))\n' "$failures" >&2
  exit 1
fi
printf 'validator-vpn-coordinator-readiness-test: PASS\n'
