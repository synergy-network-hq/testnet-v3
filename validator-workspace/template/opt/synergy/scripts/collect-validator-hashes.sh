#!/usr/bin/env bash
set -euo pipefail

MASKER=${MASKER:-/opt/synergy/scripts/mask-validator-identity.py}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

hash_file() {
  local label=$1 path=$2
  if [[ -f "$path" ]]; then
    printf '%s  %s  %s\n' "$(sha256sum "$path" | awk '{print $1}')" "$label" "$path"
  fi
}

hash_masked() {
  local label=$1 path=$2
  if [[ -f "$path" ]]; then
    "$MASKER" "$path" > "$tmp/$label.masked"
    printf '%s  %s.masked  %s\n' "$(sha256sum "$tmp/$label.masked" | awk '{print $1}')" "$label" "$path"
  fi
}

hash_file binary /opt/synergy/bin/synergy-validator
hash_file genesis /etc/synergy/validator/genesis.json
hash_file chain_spec /etc/synergy/validator/chain-spec.json
hash_file service /etc/systemd/system/synergy-validator.service
hash_masked env /etc/synergy/validator/node.env
hash_masked config /etc/synergy/validator/config.toml
hash_masked peers /etc/synergy/validator/peers.toml
hash_masked wireguard /etc/wireguard/wg0.conf

