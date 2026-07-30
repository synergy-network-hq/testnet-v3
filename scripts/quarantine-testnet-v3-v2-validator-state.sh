#!/usr/bin/env bash
# Quarantines the explicitly incompatible prelaunch v2 typed-finality state on
# one already-stopped validator. It does not start the service or delete data.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail() {
  printf 'quarantine-testnet-v3-v2-validator-state: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: quarantine-testnet-v3-v2-validator-state.sh \' \
    '  --host <ssh synergy-val1..6> \' \
    '  --expected-height <positive integer> \' \
    '  --expected-block-id <64 lowercase hex> --apply' >&2
  exit 2
}

host=
expected_height=
expected_block_id=
apply=false
while (($#)); do
  case "$1" in
    --host) host=${2:-}; shift 2 ;;
    --expected-height) expected_height=${2:-}; shift 2 ;;
    --expected-block-id) expected_block_id=${2:-}; shift 2 ;;
    --apply) apply=true; shift ;;
    *) usage ;;
  esac
done

[[ $apply == true ]] || usage
[[ $host == synergy-val[1-6] ]] || fail "validator host is not approved: $host"
[[ $expected_height =~ ^[1-9][0-9]*$ ]] || fail 'expected height must be positive'
[[ $expected_block_id =~ ^[0-9a-f]{64}$ ]] || fail 'expected block ID is invalid'

remote_apply="$root/scripts/testnet-v3-v2-validator-state-remote-quarantine.sh"
[[ -f $remote_apply ]] || fail "remote helper is missing: $remote_apply"

ssh_options=(
  -o BatchMode=yes
  -o ConnectTimeout=8
  -o ControlMaster=auto
  -o ControlPersist=900
  -o ControlPath=/tmp/synergy-tv3-status-%C
)
remote_stage=$(
  ssh "${ssh_options[@]}" "$host" \
    'umask 077; mktemp -d /tmp/synergy-testnet-v3-v2-quarantine.XXXXXX'
)
[[ $remote_stage == /tmp/synergy-testnet-v3-v2-quarantine.* ]] ||
  fail 'remote staging directory did not have the required isolated prefix'
scp "${ssh_options[@]}" "$remote_apply" "$host:$remote_stage/remote-quarantine.sh"
ssh "${ssh_options[@]}" "$host" sudo -n /bin/bash \
  "$remote_stage/remote-quarantine.sh" \
  --expected-height "$expected_height" \
  --expected-block-id "$expected_block_id" \
  --apply
