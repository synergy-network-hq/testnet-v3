#!/usr/bin/env bash
set -euo pipefail

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

SYNERGY_VALIDATOR_NAME=validator-test \
SYNERGY_VALIDATOR_INDEX=1 \
SYNERGY_VALIDATOR_ADDRESS=synv11example \
SYNERGY_PUBLIC_IP=203.0.113.10 \
SYNERGY_PRIVATE_IP=10.69.0.10 \
SYNERGY_PEER_ID=peer-example \
  template/opt/synergy/scripts/render-validator-config.sh \
  template/etc/synergy/validator/config.toml.example \
  "$tmp/config.toml"

grep -q 'validator_name = "validator-test"' "$tmp/config.toml"
grep -q 'public_ip = "203.0.113.10"' "$tmp/config.toml"
grep -q 'data_dir = "/var/lib/synergy/validator"' "$tmp/config.toml"
echo "render config ok"

