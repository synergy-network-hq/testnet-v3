#!/usr/bin/env bash
set -Eeuo pipefail

readonly script_name="validator-vpn-coordinator-readiness"
readonly interface="${SYNERGY_INNERNET_INTERFACE:-sy-validator0}"
readonly service="${SYNERGY_INNERNET_SERVICE:-innernet-server@${interface}.service}"
readonly server_bin="${INNERNET_SERVER_BIN:-/usr/bin/innernet-server}"
readonly config_dir="${INNERNET_CONFIG_DIR:-/etc/innernet-server}"
readonly data_dir="${INNERNET_DATA_DIR:-/var/lib/innernet-server}"
readonly config_file="${INNERNET_CONFIG_FILE:-${config_dir}/${interface}.conf}"
readonly database_file="${INNERNET_DATABASE_FILE:-${data_dir}/${interface}.db}"
readonly unit_file="${SYNERGY_INNERNET_UNIT_FILE:-/etc/systemd/system/innernet-server@.service}"
readonly migration_ready="${SYNERGY_INNERNET_MIGRATION_READY:-false}"
readonly invite_expires="${SYNERGY_INNERNET_INVITE_EXPIRES:-30m}"
readonly systemctl_bin="${SYSTEMCTL_BIN:-systemctl}"
readonly ip_bin="${IP_BIN:-ip}"
readonly wg_bin="${WG_BIN:-wg}"
readonly id_bin="${ID_BIN:-id}"

failures=0

pass() { printf 'PASS %s: %s\n' "$1" "$2"; }
fail() { printf 'FAIL %s: %s\n' "$1" "$2" >&2; failures=$((failures + 1)); }
skip() { printf 'SKIP %s: %s\n' "$1" "$2"; }

check_command() {
  local label="$1" command_path="$2"
  if [[ -x "$command_path" ]] || command -v "$command_path" >/dev/null 2>&1; then
    pass "$label" "$command_path is available"
  else
    fail "$label" "$command_path is not available"
  fi
}

check_root() {
  if [[ "$($id_bin -u 2>/dev/null)" == 0 ]]; then
    pass root 'readiness is running as UID 0'
  else
    fail root 'readiness must run as UID 0'
  fi
}

check_unit_root() {
  if [[ ! -r "$unit_file" ]]; then
    fail unit-root "unit file is missing: $unit_file"
    return
  fi
  if grep -Eq '^[[:space:]]*User=root[[:space:]]*$' "$unit_file"; then
    pass unit-root 'innernet-server unit explicitly runs as root'
  else
    fail unit-root 'innernet-server unit must contain User=root'
  fi
}

check_service() {
  local user
  if ! user="$($systemctl_bin show "$service" --property=User --value 2>/dev/null)"; then
    fail service-root "cannot inspect $service"
  elif [[ "$user" == root ]]; then
    pass service-root "$service reports User=root"
  else
    fail service-root "$service reports User=${user:-unset}; expected root"
  fi

  if "$systemctl_bin" is-enabled --quiet "$service" >/dev/null 2>&1; then
    pass service-enabled "$service is enabled"
  else
    fail service-enabled "$service is not enabled"
  fi

  if [[ "$migration_ready" == true ]]; then
    if "$systemctl_bin" is-active --quiet "$service" >/dev/null 2>&1; then
      pass service-active "$service is active"
    else
      fail service-active "$service is not active"
    fi
  else
    skip service-active 'migration is not enabled; service activation is checked after staging'
  fi
}

check_initialized_state() {
  if [[ "$migration_ready" != true ]]; then
    skip initialized-config 'SYNERGY_INNERNET_MIGRATION_READY is false'
    skip initialized-interface 'SYNERGY_INNERNET_MIGRATION_READY is false'
    return
  fi

  if [[ -s "$config_file" ]] && grep -Eq '^[[:space:]]*(private-key|listen-port|address|network-cidr-prefix)[[:space:]]*=' "$config_file"; then
    pass initialized-config "$config_file is present and contains innernet server fields"
  else
    fail initialized-config "missing or incomplete innernet config: $config_file"
  fi
  if [[ -s "$database_file" ]]; then
    pass initialized-database "$database_file is present"
  else
    fail initialized-database "missing innernet database: $database_file"
  fi

  if "$ip_bin" link show "$interface" >/dev/null 2>&1 && "$wg_bin" show "$interface" >/dev/null 2>&1; then
    pass initialized-interface "$interface is present and inspectable by wg"
  else
    fail initialized-interface "$interface is not present or wg cannot inspect it"
  fi
}

check_invite_expiry() {
  if [[ "$invite_expires" =~ ^[1-9][0-9]*[smhdw]$ ]]; then
    pass invite-expiry "SYNERGY_INNERNET_INVITE_EXPIRES=$invite_expires has a positive innernet timestring shape"
  else
    fail invite-expiry 'SYNERGY_INNERNET_INVITE_EXPIRES must match ^[1-9][0-9]*[smhdw]$ (recommended: 30m)'
  fi
}

check_command innernet-server "$server_bin"
check_command systemctl "$systemctl_bin"
check_root
check_unit_root
check_invite_expiry

if [[ "$migration_ready" != true && "$migration_ready" != false ]]; then
  fail migration-flag 'SYNERGY_INNERNET_MIGRATION_READY must be exactly true or false'
elif [[ "$migration_ready" == true ]]; then
  pass migration-flag 'migration readiness is explicitly enabled'
else
  pass migration-flag 'migration readiness remains disabled'
fi

if [[ "$migration_ready" == true ]]; then
  if [[ -x "$server_bin" ]] && version="$($server_bin --version 2>/dev/null)" && [[ "$version" == *'2.0.0'* ]]; then
    pass binary-version "innernet-server reports v2.0.0"
  else
    fail binary-version 'innernet-server v2.0.0 is required'
  fi
else
  skip binary-version 'migration is not enabled; version is checked at activation'
fi

check_service
check_initialized_state

if (( failures > 0 )); then
  printf '%s: NOT READY (%d failure(s))\n' "$script_name" "$failures" >&2
  exit 1
fi
printf '%s: READY\n' "$script_name"
