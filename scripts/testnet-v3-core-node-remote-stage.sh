#!/usr/bin/env bash
# Runs on exactly one target host as root. It stages Testnet-v3 artifacts only;
# it never starts, restarts, enables, or disables a service.
set -euo pipefail

fail() {
  printf 'testnet-v3-core-node-remote-stage: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: testnet-v3-core-node-remote-stage.sh \
  --stage-dir <remote temporary directory> \
  --role <validator|relayer> \
  --expected-binary-sha256 <hex> \
  --expected-config-sha256 <hex> \
  --expected-genesis-sha256 <hex> \
  --expected-dropin-sha256 <hex>
EOF
  exit 2
}

stage_dir=
role=
expected_binary_sha256=
expected_config_sha256=
expected_genesis_sha256=
expected_dropin_sha256=

while (($#)); do
  case "$1" in
    --stage-dir) stage_dir=${2:-}; shift 2 ;;
    --role) role=${2:-}; shift 2 ;;
    --expected-binary-sha256) expected_binary_sha256=${2:-}; shift 2 ;;
    --expected-config-sha256) expected_config_sha256=${2:-}; shift 2 ;;
    --expected-genesis-sha256) expected_genesis_sha256=${2:-}; shift 2 ;;
    --expected-dropin-sha256) expected_dropin_sha256=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ ${EUID} -eq 0 ]] || fail 'must run as root'
[[ -d $stage_dir ]] || fail "stage directory does not exist: $stage_dir"
[[ $role == validator || $role == relayer ]] || usage
for digest in "$expected_binary_sha256" "$expected_config_sha256" "$expected_genesis_sha256" "$expected_dropin_sha256"; do
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || fail 'expected SHA-256 values must be lowercase hex'
done

case "$role" in
  validator)
    unit=synergy-validator.service
    binary_destination=/opt/synergy/bin/synergy-validator
    config_destination=/etc/synergy/validator/config.toml
    dropin_destination=/etc/systemd/system/synergy-validator.service.d/50-synergy-testnet-v3-genesis.conf
    expected_exec_start='ExecStart=/opt/synergy/bin/synergy-validator start --config /etc/synergy/validator/config.toml'
    ;;
  relayer)
    unit=synergy-testnet-relayer.service
    binary_destination=/opt/synergy/testnet/relayer/bin/synergy-testnet-linux-amd64
    config_destination=/opt/synergy/testnet/relayer/config/node.toml
    dropin_destination=/etc/systemd/system/synergy-testnet-relayer.service.d/50-synergy-testnet-v3-genesis.conf
    expected_exec_start='ExecStart=./bin/synergy-testnet-linux-amd64 start --config config/node.toml'
    ;;
esac

genesis_destination=/etc/synergy/testnet-v3/genesis.json
staged_binary="$stage_dir/runtime.bin"
staged_config="$stage_dir/node.toml"
staged_genesis="$stage_dir/genesis.json"
staged_dropin="$stage_dir/50-synergy-testnet-v3-genesis.conf"
staged_apply="$stage_dir/testnet-v3-core-node-remote-stage.sh"

for path in "$staged_binary" "$staged_config" "$staged_genesis" "$staged_dropin" "$staged_apply"; do
  [[ -f $path ]] || fail "required staged payload missing: $path"
done

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

[[ $(hash_file "$staged_binary") == "$expected_binary_sha256" ]] || fail 'staged runtime binary SHA-256 mismatch'
[[ $(hash_file "$staged_config") == "$expected_config_sha256" ]] || fail 'staged node config SHA-256 mismatch'
[[ $(hash_file "$staged_genesis") == "$expected_genesis_sha256" ]] || fail 'staged Genesis SHA-256 mismatch'
[[ $(hash_file "$staged_dropin") == "$expected_dropin_sha256" ]] || fail 'staged Genesis drop-in SHA-256 mismatch'

[[ $(systemctl show "$unit" -p LoadState --value) == loaded ]] || fail "required systemd unit is not loaded: $unit"
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] || fail "unit must be inactive before staging: $unit"
[[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == disabled ]] || fail "unit must be disabled before staging: $unit"
systemctl cat "$unit" | grep -Fqx "$expected_exec_start" || fail "unit ExecStart contract changed: $unit"

for port in 5622 5640 5660 5680 6030; do
  if ss -H -ltn "sport = :$port" | grep -q .; then
    fail "required Testnet-v3 port is already listening: $port"
  fi
done

if [[ -f $config_destination ]] && grep -Eqi '^[[:space:]]*[^#]*(private|secret|pass(word)?|token)[[:alnum:]_.-]*[[:space:]]*=' "$config_destination"; then
  fail "existing config contains a sensitive assignment; require a separate explicit migration: $config_destination"
fi
if [[ -e $genesis_destination ]] && [[ $(hash_file "$genesis_destination") != "$expected_genesis_sha256" ]]; then
  fail "refusing to replace a noncanonical Genesis file: $genesis_destination"
fi

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_directory="/var/backups/synergy-testnet-v3/core-stage-${role}-${timestamp}"
install -d -m 0700 -o root -g root "$backup_directory"

if [[ -e $binary_destination ]]; then
  cp -a "$binary_destination" "$backup_directory/previous-runtime.bin"
fi
if [[ -e $config_destination ]]; then
  cp -a "$config_destination" "$backup_directory/previous-node.toml"
fi
if [[ -e $dropin_destination ]]; then
  cp -a "$dropin_destination" "$backup_directory/previous-genesis-dropin.conf"
fi

install -d -m 0755 -o root -g root "$(dirname "$binary_destination")"
runtime_pending="${binary_destination}.testnet-v3-pending.$$"
install -m 0755 -o root -g root "$staged_binary" "$runtime_pending"
[[ $(hash_file "$runtime_pending") == "$expected_binary_sha256" ]] || fail 'installed pending runtime binary SHA-256 mismatch'
mv -f "$runtime_pending" "$binary_destination"

install -d -m 0755 -o root -g root "$(dirname "$config_destination")"
config_pending="${config_destination}.testnet-v3-pending.$$"
install -m 0640 -o root -g root "$staged_config" "$config_pending"
[[ $(hash_file "$config_pending") == "$expected_config_sha256" ]] || fail 'installed pending config SHA-256 mismatch'
mv -f "$config_pending" "$config_destination"

if [[ ! -e $genesis_destination ]]; then
  install -d -m 0755 -o root -g root "$(dirname "$genesis_destination")"
  install -m 0444 -o root -g root "$staged_genesis" "$genesis_destination"
fi
[[ $(hash_file "$genesis_destination") == "$expected_genesis_sha256" ]] || fail 'installed Genesis SHA-256 mismatch'

install -d -m 0755 -o root -g root "$(dirname "$dropin_destination")"
install -m 0644 -o root -g root "$staged_dropin" "$dropin_destination"
[[ $(hash_file "$dropin_destination") == "$expected_dropin_sha256" ]] || fail 'installed Genesis drop-in SHA-256 mismatch'

systemctl daemon-reload
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] || fail "unit changed state during staging: $unit"
[[ $(systemctl is-enabled "$unit" 2>/dev/null || true) == disabled ]] || fail "unit changed enablement during staging: $unit"

printf '{"result":"TESTNET_V3_CORE_NODE_STAGED","role":"%s","unit":"%s","backup":"%s","runtime_sha256":"%s","config_sha256":"%s","genesis_sha256":"%s","service_started":false}\n' \
  "$role" "$unit" "$backup_directory" "$expected_binary_sha256" "$expected_config_sha256" "$expected_genesis_sha256" | tee "$backup_directory/stage-evidence.json"
