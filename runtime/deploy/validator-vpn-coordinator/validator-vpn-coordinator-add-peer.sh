#!/usr/bin/env bash
set -Eeuo pipefail

interface="${1:?interface argument is required}"
server_bin="${INNERNET_SERVER_BIN:-/usr/bin/innernet-server}"
config_dir="${INNERNET_CONFIG_DIR:-/etc/innernet-server}"
data_dir="${INNERNET_DATA_DIR:-/var/lib/innernet-server}"
invite_root="${INNERNET_INVITE_ROOT:-/var/lib/validator-vpn-coordinator/invitations}"

die() {
  printf 'validator-vpn-coordinator-add-peer: %s\n' "$1" >&2
  exit 1
}

[[ "$(id -u)" == 0 ]] || die 'must run as UID 0'
[[ "$interface" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die 'invalid interface'
[[ -x "$server_bin" ]] || die "innernet-server is not executable: $server_bin"

peer_name="${PEER_NAME:-}"
peer_cidr="${PEER_CIDR:-}"
invite_path="${PEER_INVITE_PATH:-}"
invite_expires="${PEER_INVITE_EXPIRES:-${SYNERGY_INNERNET_INVITE_EXPIRES:-30m}}"

[[ "$peer_name" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die 'PEER_NAME must be a DNS-safe peer name'
[[ "$peer_cidr" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || die 'PEER_CIDR must be a DNS-safe CIDR name'
[[ "$invite_path" == "$invite_root/"* ]] || die 'PEER_INVITE_PATH must stay below INNERNET_INVITE_ROOT'
[[ "$invite_path" != *..* ]] || die 'PEER_INVITE_PATH must not contain ..'
[[ "$invite_path" != */ ]] || die 'PEER_INVITE_PATH must name a file'

[[ "$invite_expires" =~ ^[1-9][0-9]*[smhdw]$ ]] || die 'invite expiry must be a positive innernet timestring (for example 30m)'

mkdir -p "$invite_root"
chmod 0700 "$invite_root"

args=(
  --config-dir "$config_dir"
  --data-dir "$data_dir"
  add-peer "$interface"
  --name "$peer_name"
  --auto-ip
  --cidr "$peer_cidr"
  --admin=false
  --yes
  --save-config "$invite_path"
)
if [[ -n "$invite_expires" ]]; then
  args+=(--invite-expires "$invite_expires")
fi

exec "$server_bin" "${args[@]}"
