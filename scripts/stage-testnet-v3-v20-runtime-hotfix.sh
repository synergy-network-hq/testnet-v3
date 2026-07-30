#!/usr/bin/env bash
# Stages one checksum-bound v20.0.0 runtime artifact on the actual Testnet-v3
# service contract. The remote helper performs a recoverable service switch.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail() {
  printf 'stage-testnet-v3-v20-runtime-hotfix: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: stage-testnet-v3-v20-runtime-hotfix.sh \' \
    '  --artifact-dir <verified GitHub artifact directory> \' \
    '  --role <relayer|rpc-gateway|explorer-indexer|validator> \' \
    '  --host <approved ssh synergy-* alias> --apply' >&2
  exit 2
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

artifact_dir=
role=
host=
apply=false
leave_inactive=false
while (($#)); do
  case "$1" in
    --artifact-dir) artifact_dir=${2:-}; shift 2 ;;
    --role) role=${2:-}; shift 2 ;;
    --host) host=${2:-}; shift 2 ;;
    --leave-inactive) leave_inactive=true; shift ;;
    --apply) apply=true; shift ;;
    *) usage ;;
  esac
done
[[ $apply == true && -n $artifact_dir && -n $role && -n $host ]] || usage
[[ -d $artifact_dir ]] || fail "artifact directory does not exist: $artifact_dir"
if [[ $leave_inactive == true && $role != validator ]]; then
  fail '--leave-inactive is permitted only for a coordinated validator switch'
fi

case "$role:$host" in
  relayer:synergy-relayer[1-3])
    artifact_name=synergy-relayer-node-linux-amd64
    ;;
  rpc-gateway:synergy-rpc | explorer-indexer:synergy-index)
    artifact_name=synergy-node-linux-amd64
    ;;
  validator:synergy-val[1-6])
    artifact_name=synergy-validator-node-linux-amd64
    ;;
  *)
    fail "role/host mapping is not approved: $role $host"
    ;;
esac

required_payloads=(
  "$artifact_dir/SHA256SUMS"
  "$artifact_dir/TESTNET_SOURCE_REVISION"
  "$artifact_dir/$artifact_name"
)
# The non-signing generic runtime is built and released independently of the
# validator and relayer packages.  It must still checksum-bind both its
# executable and immutable source revision, but it does not carry those
# roles' configuration manifest.
if [[ $role == relayer || $role == validator ]]; then
  required_payloads+=("$artifact_dir/release-config-manifest.json")
fi
for required in "${required_payloads[@]}"; do
  [[ -f $required ]] || fail "required artifact payload is missing: $required"
done

source_revision=$(tr -d '[:space:]' < "$artifact_dir/TESTNET_SOURCE_REVISION")
[[ $source_revision =~ ^[0-9a-f]{40}$ ]] || fail 'artifact source revision is invalid'
[[ $source_revision == 528f594ac491b34935de3669dd4273c414a51d48 ]] ||
  fail "artifact is not bound to the authorized Testnet-v3 source revision: $source_revision"

checksum_entries=0
while read -r expected recorded_path; do
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || fail 'artifact checksum manifest contains an invalid digest'
  name=${recorded_path##*/}
  case "$role:$name" in
    rpc-gateway:synergy-node-linux-amd64|\
      rpc-gateway:synergy-validator-node-linux-amd64|\
      rpc-gateway:synergy-relayer-node-linux-amd64|\
      rpc-gateway:release-config-manifest.json|\
      rpc-gateway:TESTNET_SOURCE_REVISION|\
      explorer-indexer:synergy-node-linux-amd64|\
      explorer-indexer:synergy-validator-node-linux-amd64|\
      explorer-indexer:synergy-relayer-node-linux-amd64|\
      explorer-indexer:release-config-manifest.json|\
      explorer-indexer:TESTNET_SOURCE_REVISION)
      ;;
    relayer:synergy-node-linux-amd64|\
      relayer:synergy-validator-node-linux-amd64|\
      relayer:synergy-relayer-node-linux-amd64|\
      relayer:release-config-manifest.json|\
      relayer:TESTNET_SOURCE_REVISION|\
      validator:synergy-node-linux-amd64|\
      validator:synergy-validator-node-linux-amd64|\
      validator:synergy-relayer-node-linux-amd64|\
      validator:release-config-manifest.json|\
      validator:TESTNET_SOURCE_REVISION)
      ;;
    *)
      fail "artifact checksum manifest contains an unexpected path: $recorded_path"
      ;;
  esac
  [[ -f $artifact_dir/$name ]] || fail "checksummed artifact payload is missing: $name"
  [[ $(sha256 "$artifact_dir/$name") == "$expected" ]] ||
    fail "artifact checksum mismatch: $name"
  checksum_entries=$((checksum_entries + 1))
done < "$artifact_dir/SHA256SUMS"
expected_checksum_entries=5
[[ $checksum_entries -eq $expected_checksum_entries ]] ||
  fail "artifact checksum manifest must contain exactly $expected_checksum_entries entries for $role"

binary="$artifact_dir/$artifact_name"
binary_sha256=$(sha256 "$binary")
genesis="$root/genesis.testnet-v3.identity-assigned.json"
genesis_sha256=$(sha256 "$genesis")
[[ $genesis_sha256 == ee554c197a878cbfdaf7d470a0274ab2859a7a0c14c87e425908a69c6fbb51cf ]] ||
  fail 'local canonical Genesis checksum changed'

remote_apply="$root/scripts/testnet-v3-v20-runtime-hotfix-remote.sh"
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
    'umask 077; mktemp -d /tmp/synergy-testnet-v3-v20-runtime.XXXXXX'
)
[[ $remote_stage == /tmp/synergy-testnet-v3-v20-runtime.* ]] ||
  fail 'remote staging directory did not have the required isolated prefix'

scp "${ssh_options[@]}" "$binary" "$host:$remote_stage/runtime.bin"
scp "${ssh_options[@]}" "$remote_apply" "$host:$remote_stage/remote-apply.sh"

remote_arguments=(
  "$remote_stage/remote-apply.sh" \
  --stage-dir "$remote_stage" \
  --role "$role" \
  --expected-binary-sha256 "$binary_sha256" \
  --expected-genesis-sha256 "$genesis_sha256" \
  --source-revision "$source_revision"
)
if [[ $leave_inactive == true ]]; then
  remote_arguments+=(--leave-inactive)
fi
remote_arguments+=(--apply)

ssh "${ssh_options[@]}" "$host" sudo -n /bin/bash \
  "${remote_arguments[@]}"
