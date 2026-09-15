#!/usr/bin/env bash
# Stage one inactive Testnet-v3 validator or relayer from the local release
# checkout. This script deliberately never starts, restarts, enables, or
# disables a remote service.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

fail() {
  printf 'stage-testnet-v3-core-node: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: stage-testnet-v3-core-node.sh --role <validator|relayer> --host <ssh synergy alias> --apply

Accepted hosts:
  validator  synergy-val1 through synergy-val6
  relayer    synergy-relayer1 through synergy-relayer3

The script checksum-verifies local release artifacts, rechecks remote unit and
port preconditions, takes recoverable backups remotely, then stages artifacts.
It never starts, restarts, enables, or disables a service.
EOF
  exit 2
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

role=
host=
apply=false
while (($#)); do
  case "$1" in
    --role) role=${2:-}; shift 2 ;;
    --host) host=${2:-}; shift 2 ;;
    --apply) apply=true; shift ;;
    *) usage ;;
  esac
done
[[ $apply == true && ( $role == validator || $role == relayer ) && -n $host ]] || usage

case "$role:$host" in
  validator:synergy-val[1-6])
    number=${host#synergy-val}
    config="$root/launch/production-node-configs/validators/val${number}.toml"
    dropin="$root/launch/production-node-configs/deployment/validators/val${number}/systemd/synergy-validator.service.d/50-synergy-testnet-v3-genesis.conf"
    ;;
  relayer:synergy-relayer[1-3])
    number=${host#synergy-relayer}
    config="$root/launch/production-node-configs/relayers/relay${number}.toml"
    dropin="$root/launch/production-node-configs/deployment/relayers/relay${number}/systemd/synergy-testnet-relayer.service.d/50-synergy-testnet-v3-genesis.conf"
    ;;
  *) fail "role/host mapping is not approved: $role $host" ;;
esac

release_manifest="$root/launch/TESTNET_V3_LINUX_RUNTIME_RELEASE.json"
genesis="$root/genesis.testnet-v3.identity-assigned.json"
remote_apply="$root/scripts/testnet-v3-core-node-remote-stage.sh"
python3 "$root/scripts/verify-testnet-v3-linux-runtime-release.py"

binary_relative=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["artifacts"][sys.argv[2]]["local_path"])' "$release_manifest" "$role")
binary_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["artifacts"][sys.argv[2]]["sha256"])' "$release_manifest" "$role")
genesis_sha256=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["genesis_file_sha256"])' "$release_manifest")
binary="$root/$binary_relative"

for path in "$binary" "$config" "$dropin" "$genesis" "$remote_apply"; do
  [[ -f $path ]] || fail "required local release payload is missing: $path"
done
[[ $(sha256 "$binary") == "$binary_sha256" ]] || fail 'local runtime binary checksum mismatch'
[[ $(sha256 "$genesis") == "$genesis_sha256" ]] || fail 'local Genesis checksum mismatch'
config_sha256=$(sha256 "$config")
dropin_sha256=$(sha256 "$dropin")

phrase="STAGE TESTNET-V3 ${role} ${host}"
printf 'Type the confirmation phrase to stage this inactive node without starting it:\n  %s\n> ' "$phrase"
IFS= read -r confirmation
[[ $confirmation == "$phrase" ]] || fail 'confirmation phrase did not match; nothing was transferred'

remote_stage=$(ssh "$host" 'umask 077; mktemp -d /tmp/synergy-testnet-v3-core-stage.XXXXXX')
[[ $remote_stage == /tmp/synergy-testnet-v3-core-stage.* ]] || fail 'remote staging directory did not have the required isolated prefix'

scp "$binary" "$host:$remote_stage/runtime.bin"
scp "$config" "$host:$remote_stage/node.toml"
scp "$genesis" "$host:$remote_stage/genesis.json"
scp "$dropin" "$host:$remote_stage/50-synergy-testnet-v3-genesis.conf"
scp "$remote_apply" "$host:$remote_stage/testnet-v3-core-node-remote-stage.sh"
ssh -tt "$host" "sudo /bin/bash '$remote_stage/testnet-v3-core-node-remote-stage.sh' --stage-dir '$remote_stage' --role '$role' --expected-binary-sha256 '$binary_sha256' --expected-config-sha256 '$config_sha256' --expected-genesis-sha256 '$genesis_sha256' --expected-dropin-sha256 '$dropin_sha256'"
