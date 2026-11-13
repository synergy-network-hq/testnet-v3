#!/usr/bin/env bash
# Root-only, exact-path quarantine for the prelaunch store version that cannot
# safely resume under the finalized v20 context-root rules.
set -euo pipefail

fail() {
  printf 'testnet-v3-v2-validator-state-remote-quarantine: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: testnet-v3-v2-validator-state-remote-quarantine.sh \' \
    '  --expected-height <positive integer> \' \
    '  --expected-block-id <64 lowercase hex> --apply' >&2
  exit 2
}

expected_height=
expected_block_id=
apply=false
while (($#)); do
  case "$1" in
    --expected-height) expected_height=${2:-}; shift 2 ;;
    --expected-block-id) expected_block_id=${2:-}; shift 2 ;;
    --apply) apply=true; shift ;;
    *) usage ;;
  esac
done

[[ ${EUID} -eq 0 ]] || fail 'must run as root'
[[ $apply == true ]] || usage
[[ $expected_height =~ ^[1-9][0-9]*$ ]] || fail 'expected height must be positive'
[[ $expected_block_id =~ ^[0-9a-f]{64}$ ]] || fail 'expected block ID is invalid'

unit=synergy-validator.service
data_root=/var/lib/synergy/validator/data
typed_store="$data_root/typed-posy-finality.json"
signing_journal="$data_root/consensus_signing_authorizations.json"
vote_locks="$data_root/consensus_vote_locks.json"
proposal_cache="$data_root/consensus_proposals"

[[ $(systemctl show "$unit" -p LoadState --value) == loaded ]] ||
  fail "validator unit is not loaded: $unit"
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] ||
  fail "validator unit must be inactive before quarantine: $unit"
[[ -f $typed_store ]] || fail "typed finality store is missing: $typed_store"
[[ -f $signing_journal ]] || fail "signing authorization journal is missing: $signing_journal"
[[ $(jq -r '.store_version' "$typed_store") == 2 ]] ||
  fail 'typed finality store is not the explicitly incompatible version 2'
[[ $(jq -r '.records | length' "$typed_store") == "$expected_height" ]] ||
  fail 'typed finality record count does not equal the expected height'
[[ $(jq -r '.records[-1].height' "$typed_store") == "$expected_height" ]] ||
  fail 'typed finality tip height does not match the expected height'
[[ $(jq -r '.records[-1].block_id' "$typed_store") == "$expected_block_id" ]] ||
  fail 'typed finality tip block ID does not match the expected block'
[[ $(jq -r '.format' "$signing_journal") == 'synergy-consensus-signing-journal-v2' ]] ||
  fail 'signing authorization journal has an unexpected format'

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_directory="/var/backups/synergy-testnet-v3/prelaunch-v2-validator-state-${timestamp}"
install -d -m 0700 -o root -g root "$backup_directory"

printf '%s\n' \
  "typed_store=$typed_store" \
  "typed_store_sha256=$(sha256sum "$typed_store" | awk '{print $1}')" \
  "store_version=2" \
  "record_count=$expected_height" \
  "last_block_id=$expected_block_id" \
  "signing_journal=$signing_journal" \
  "signing_journal_sha256=$(sha256sum "$signing_journal" | awk '{print $1}')" \
  "signing_authorization_count=$(jq -r '.records | length' "$signing_journal")" \
  > "$backup_directory/quarantine-plan.txt"

mv "$typed_store" "$backup_directory/typed-posy-finality.v2.json"
mv "$signing_journal" "$backup_directory/consensus_signing_authorizations.v2.json"
if [[ -e $vote_locks ]]; then
  mv "$vote_locks" "$backup_directory/consensus_vote_locks.v2.json"
fi
if [[ -e $proposal_cache ]]; then
  mv "$proposal_cache" "$backup_directory/consensus_proposals.v2"
fi

[[ ! -e $typed_store ]] || fail 'typed finality store remained at the live path'
[[ ! -e $signing_journal ]] || fail 'signing authorization journal remained at the live path'
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] ||
  fail 'validator unit changed state during quarantine'

printf '{"result":"TESTNET_V3_PRELAUNCH_V2_VALIDATOR_STATE_QUARANTINED","store_version":2,"last_height":%s,"last_block_id":"%s","backup":"%s","service_active":false}\n' \
  "$expected_height" \
  "$expected_block_id" \
  "$backup_directory" |
  tee "$backup_directory/quarantine-evidence.json"
