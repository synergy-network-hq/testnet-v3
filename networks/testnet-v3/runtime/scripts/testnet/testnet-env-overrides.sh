#!/usr/bin/env bash

testnet_env_dir() {
  if [[ -n "${TESTNET_ENV_DIR_RESOLVED:-}" && -d "${TESTNET_ENV_DIR_RESOLVED:-}" ]]; then
    printf '%s\n' "$TESTNET_ENV_DIR_RESOLVED"
    return 0
  fi

  local candidate
  for candidate in \
    "${SYNERGY_TESTNET_ENV_DIR:-}" \
    "${TESTNET_ENV_DIR_DEFAULT:-}" \
    "$HOME/Downloads/synergy-env-files"
  do
    if [[ -n "${candidate:-}" && -d "$candidate" ]]; then
      TESTNET_ENV_DIR_RESOLVED="$candidate"
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

testnet_setup_package_dir() {
  if [[ -n "${TESTNET_SETUP_PACKAGE_DIR_RESOLVED:-}" && -d "${TESTNET_SETUP_PACKAGE_DIR_RESOLVED:-}" ]]; then
    printf '%s\n' "$TESTNET_SETUP_PACKAGE_DIR_RESOLVED"
    return 0
  fi

  local candidate
  for candidate in \
    "${SYNERGY_TESTNET_SETUP_PACKAGE_DIR:-}" \
    "$HOME/Desktop/setup-packages" \
    "$HOME/Desktop/deliverables/launch-assets/packages" \
    "$HOME/Desktop/deliverables/launch-assets/deliverables" \
    "$HOME/Desktop/Testnet/genesis-nodes" \
    "$HOME/Desktop/Testnet/synergy-address-engine/genesis-app/tmp/ceremony/launch-assets/packages"
  do
    if [[ -n "${candidate:-}" && -d "$candidate" ]]; then
      TESTNET_SETUP_PACKAGE_DIR_RESOLVED="$candidate"
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

testnet_find_setup_package_file() {
  local filename="$1"
  local setup_dir
  setup_dir="$(testnet_setup_package_dir)" || return 1

  local candidate
  candidate="$(find "$setup_dir" -type f -name "$filename" 2>/dev/null | sort | head -n 1)"
  [[ -n "$candidate" ]] || return 1
  printf '%s\n' "$candidate"
}

testnet_env_value() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || return 1

  awk -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/\r$/, "", line)
      eq = index(line, "=")
      if (eq == 0) {
        next
      }
      name = substr(line, 1, eq - 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name != key) {
        next
      }
      value = substr(line, eq + 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "$file"
}

testnet_env_has_key() {
  local file="$1"
  local key="$2"
  [[ -f "$file" ]] || return 1

  awk -v key="$key" '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      line = $0
      sub(/\r$/, "", line)
      eq = index(line, "=")
      if (eq == 0) {
        next
      }
      name = substr(line, 1, eq - 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
      if (name == key) {
        found = 1
        exit
      }
    }
    END {
      exit(found ? 0 : 1)
    }
  ' "$file"
}

testnet_first_nonempty() {
  local value
  for value in "$@"; do
    if [[ -n "${value:-}" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

testnet_env_file_for_validator_address() {
  local validator_address="$1"
  local env_dir
  env_dir="$(testnet_env_dir)" || return 1
  local file
  for file in "$env_dir"/*.env; do
    [[ -f "$file" ]] || continue
    if [[ "$(testnet_env_value "$file" "NODE_WALLET" || true)" == "$validator_address" ]]; then
      printf '%s\n' "$file"
      return 0
    fi
  done
  return 1
}

testnet_validator_env_value() {
  local validator_address="$1"
  local key="$2"
  local fallback="${3:-}"
  local file value
  file="$(testnet_env_file_for_validator_address "$validator_address" || true)"
  if [[ -n "$file" ]]; then
    value="$(testnet_env_value "$file" "$key" || true)"
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  printf '%s\n' "$fallback"
}

testnet_env_file_for_bootnode_name() {
  local name="$1"
  local env_dir
  env_dir="$(testnet_env_dir)" || return 1
  case "$name" in
    node-0a|Node-0A|bootnode1) printf '%s\n' "$env_dir/genesisboot1.env" ;;
    node-0b|Node-0B|bootnode2) printf '%s\n' "$env_dir/genesisboot2.env" ;;
    node-0c|Node-0C|bootnode3) printf '%s\n' "$env_dir/genesisboot3.env" ;;
    bootnode1) printf '%s\n' "$env_dir/genesisboot1.env" ;;
    bootnode2) printf '%s\n' "$env_dir/genesisboot2.env" ;;
    bootnode3) printf '%s\n' "$env_dir/genesisboot3.env" ;;
    *) return 1 ;;
  esac
}

testnet_legacy_key_dir_for_inventory_node() {
  local normalized
  normalized="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    validator-01|validator1|genval-01|genesisval1|node-01) printf '%s\n' "node-01" ;;
    validator-02|validator2|genval-02|genesisval2|node-02) printf '%s\n' "node-02" ;;
    validator-03|validator3|genval-03|genesisval3|node-04) printf '%s\n' "node-04" ;;
    validator-04|validator4|genval-04|genesisval4|node-06) printf '%s\n' "node-06" ;;
    validator-05|validator5|genval-05|genesisval5|node-16) printf '%s\n' "node-16" ;;
    node-rpc|genesisrpc|node-13) printf '%s\n' "node-13" ;;
    node-exp|genesisindexer|node-14) printf '%s\n' "node-14" ;;
    *) return 1 ;;
  esac
}

testnet_setup_package_file_for_inventory_node() {
  local normalized_slot normalized_role normalized_type
  normalized_slot="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  normalized_type="$(printf '%s' "${2:-}" | tr '[:upper:]' '[:lower:]')"
  normalized_role="$(printf '%s' "${3:-}" | tr '[:upper:]' '[:lower:]' | tr '-' '_')"

  case "$normalized_slot" in
    validator-01|validator1|genval-01|genesisval1|node-01) testnet_find_setup_package_file "validator-1-setup-package.json" && return 0 ;;
    validator-02|validator2|genval-02|genesisval2|node-02) testnet_find_setup_package_file "validator-2-setup-package.json" && return 0 ;;
    validator-03|validator3|genval-03|genesisval3|node-04) testnet_find_setup_package_file "validator-3-setup-package.json" && return 0 ;;
    validator-04|validator4|genval-04|genesisval4|node-06) testnet_find_setup_package_file "validator-4-setup-package.json" && return 0 ;;
    validator-05|validator5|genval-05|genesisval5|node-16) testnet_find_setup_package_file "validator-5-setup-package.json" && return 0 ;;
    node-rpc|genesisrpc|node-13) testnet_find_setup_package_file "rpc-gateway-setup-package.json" && return 0 ;;
    node-exp|genesisindexer|node-14) testnet_find_setup_package_file "indexer-explorer-setup-package.json" && return 0 ;;
  esac

  case "$normalized_type:$normalized_role" in
    validator:validator) return 1 ;;
    rpc-gateway:rpc_gateway|rpc-gateway:rpc-gateway) testnet_find_setup_package_file "rpc-gateway-setup-package.json" && return 0 ;;
    indexer:indexer|indexer:indexer_explorer) testnet_find_setup_package_file "indexer-explorer-setup-package.json" && return 0 ;;
  esac

  return 1
}

testnet_env_file_for_inventory_node() {
  local node_slot_id="$1"
  local node_type="$2"
  local validator_address="$3"
  local host="${4:-}"
  local env_dir
  local normalized_slot
  env_dir="$(testnet_env_dir)" || return 1
  normalized_slot="$(printf '%s' "$node_slot_id" | tr '[:upper:]' '[:lower:]')"

  if [[ -n "$validator_address" ]]; then
    testnet_env_file_for_validator_address "$validator_address" && return 0
  fi

  case "$node_type" in
    bootnode)
      testnet_env_file_for_bootnode_name "$normalized_slot" && return 0
      ;;
    rpc-gateway)
      printf '%s\n' "$env_dir/genesisrpc.env"
      return 0
      ;;
    indexer)
      printf '%s\n' "$env_dir/genesisindexer.env"
      return 0
      ;;
  esac

  case "$normalized_slot" in
    node-0a|bootnode1) printf '%s\n' "$env_dir/genesisboot1.env" ; return 0 ;;
    node-0b|bootnode2) printf '%s\n' "$env_dir/genesisboot2.env" ; return 0 ;;
    node-0c|bootnode3) printf '%s\n' "$env_dir/genesisboot3.env" ; return 0 ;;
    validator-01|validator1|genval-01|genesisval1|node-01) printf '%s\n' "$env_dir/genesisval01.env" ; return 0 ;;
    validator-02|validator2|genval-02|genesisval2|node-02) printf '%s\n' "$env_dir/genesisval02.env" ; return 0 ;;
    validator-03|validator3|genval-03|genesisval3|node-04) printf '%s\n' "$env_dir/genesisval03.env" ; return 0 ;;
    validator-04|validator4|genval-04|genesisval4|node-06) printf '%s\n' "$env_dir/genesisval04.env" ; return 0 ;;
    validator-05|validator5|genval-05|genesisval5|node-16) printf '%s\n' "$env_dir/genesisval05.env" ; return 0 ;;
    node-rpc|genesisrpc|node-13) printf '%s\n' "$env_dir/genesisrpc.env" ; return 0 ;;
    node-exp|genesisindexer|node-14) printf '%s\n' "$env_dir/genesisindexer.env" ; return 0 ;;
  esac

  if [[ -n "$host" ]]; then
    local file
    for file in "$env_dir"/*.env; do
      [[ -f "$file" ]] || continue
      if [[ "$(testnet_env_value "$file" "HOSTNAME" || true)" == "$host" ]]; then
        printf '%s\n' "$file"
        return 0
      fi
    done
  fi

  return 1
}

testnet_inventory_env_value() {
  local node_slot_id="$1"
  local node_type="$2"
  local validator_address="$3"
  local host="$4"
  local key="$5"
  local fallback="${6:-}"
  local file value
  file="$(testnet_env_file_for_inventory_node "$node_slot_id" "$node_type" "$validator_address" "$host" || true)"
  if [[ -n "$file" ]]; then
    value="$(testnet_env_value "$file" "$key" || true)"
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  printf '%s\n' "$fallback"
}

testnet_inventory_env_value_allow_empty() {
  local node_slot_id="$1"
  local node_type="$2"
  local validator_address="$3"
  local host="$4"
  local key="$5"
  local fallback="${6:-}"
  local file
  file="$(testnet_env_file_for_inventory_node "$node_slot_id" "$node_type" "$validator_address" "$host" || true)"
  if [[ -n "$file" ]] && testnet_env_has_key "$file" "$key"; then
    testnet_env_value "$file" "$key" || true
    return 0
  fi
  printf '%s\n' "$fallback"
}

testnet_bootnode_env_value() {
  local name="$1"
  local key="$2"
  local fallback="${3:-}"
  local file value
  file="$(testnet_env_file_for_bootnode_name "$name" || true)"
  if [[ -n "$file" ]]; then
    value="$(testnet_env_value "$file" "$key" || true)"
    if [[ -n "$value" ]]; then
      printf '%s\n' "$value"
      return 0
    fi
  fi
  printf '%s\n' "$fallback"
}
