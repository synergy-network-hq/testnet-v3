#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="${1:-$ROOT_DIR/testnet/runtime/configs}"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"

if [[ ! -d "$CONFIG_DIR" ]]; then
  echo "Config directory not found: $CONFIG_DIR" >&2
  exit 1
fi

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Inventory file not found: $INVENTORY_FILE" >&2
  exit 1
fi

is_private_host() {
  local host="$1"
  if [[ "$host" == "0.0.0.0" ]]; then
    return 0
  fi
  if [[ "$host" == "localhost" ]]; then
    return 0
  fi
  if [[ "$host" =~ ^127\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^10\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^192\.168\. ]]; then
    return 0
  fi
  if [[ "$host" =~ ^172\.([1][6-9]|2[0-9]|3[0-1])\. ]]; then
    return 0
  fi
  if [[ "$host" =~ \.internal$ ]]; then
    return 0
  fi
  return 1
}

is_assigned_synergy_host() {
  local host
  host="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ -n "$host" && "$host" == *.synergy-network.io ]]
}

extract_toml_string() {
  local key="$1"
  local file="$2"
  sed -n "s/^${key} = \"\\([^\"]*\\)\"$/\\1/p" "$file" | head -n 1
}

extract_bootnode_hosts() {
  local file="$1"
  local line
  line="$(sed -n 's/^bootnodes = //p' "$file" | head -n 1)"
  if [[ -z "$line" || "$line" == "[]" ]]; then
    return 0
  fi
  echo "$line" | grep -oE '@[^",\]]+' | sed 's/^@//' | cut -d: -f1
}

failures=0
checked=0

for config in "$CONFIG_DIR"/*.toml; do
  [[ -f "$config" ]] || continue
  checked=$((checked + 1))
  name="$(basename "$config")"

  if ! rg -q '^name = "synergy-testnet"$' "$config"; then
    echo "[$name] network name is not synergy-testnet" >&2
    failures=$((failures + 1))
  fi

  if ! rg -q '^enable_discovery = false$' "$config"; then
    echo "[$name] p2p discovery must be disabled" >&2
    failures=$((failures + 1))
  fi

  if ! rg -q '^cors_enabled = false$' "$config"; then
    echo "[$name] rpc cors_enabled must be false" >&2
    failures=$((failures + 1))
  fi

  if ! rg -q '^cors_origins = \[\]$' "$config"; then
    echo "[$name] rpc cors_origins must be []" >&2
    failures=$((failures + 1))
  fi

  for key in bind_address listen_address; do
    value="$(extract_toml_string "$key" "$config")"
    if [[ -z "$value" ]]; then
      echo "[$name] missing ${key}" >&2
      failures=$((failures + 1))
      continue
    fi
    host="${value%:*}"
    if ! is_private_host "$host"; then
      echo "[$name] ${key} host is not private/internal: ${host}" >&2
      failures=$((failures + 1))
    fi
  done

  value="$(extract_toml_string "public_address" "$config")"
  if [[ -z "$value" ]]; then
    echo "[$name] missing public_address" >&2
    failures=$((failures + 1))
  else
    host="${value%:*}"
    if ! is_private_host "$host" && ! is_assigned_synergy_host "$host"; then
      echo "[$name] public_address host must be private/internal or *.synergy-network.io: ${host}" >&2
      failures=$((failures + 1))
    fi
  fi

  while IFS= read -r boot_host; do
    [[ -z "$boot_host" ]] && continue
    if ! is_assigned_synergy_host "$boot_host"; then
      echo "[$name] bootnode host must resolve to *.synergy-network.io: ${boot_host}" >&2
      failures=$((failures + 1))
    fi
  done < <(extract_bootnode_hosts "$config")

  if ! rg -q '^seed_servers = \[\]$' "$config"; then
    echo "[$name] validator configs must keep seed_servers empty" >&2
    failures=$((failures + 1))
  fi
  if ! rg -q '^bootstrap_dns_records = \[\]$' "$config"; then
    echo "[$name] validator configs must keep bootstrap_dns_records empty" >&2
    failures=$((failures + 1))
  fi
  if ! rg -q '^additional_dial_targets = \[' "$config"; then
    echo "[$name] validator configs must define additional_dial_targets" >&2
    failures=$((failures + 1))
  fi
done

validator_count="$(
  awk -F, '
    NR == 1 {
      for (i = 1; i <= NF; i++) {
        header[$i] = i
      }
      next
    }
    {
      idx = header["node_type"]
      if (!idx) {
        next
      }
      v = tolower($(idx))
      if (v == "validator") {
        c++
      }
    }
    END { print c + 0 }
  ' "$INVENTORY_FILE"
)"
if (( validator_count < 3 )); then
  echo "[inventory] requires at least 3 validators, found ${validator_count}" >&2
  failures=$((failures + 1))
fi

if (( checked == 0 )); then
  echo "No node config files found in $CONFIG_DIR" >&2
  exit 1
fi

if (( failures > 0 )); then
  echo "Closed-testnet validation failed (${failures} issue(s))." >&2
  exit 2
fi

echo "Closed-testnet validation passed (${checked} config files checked, validators=${validator_count})."
