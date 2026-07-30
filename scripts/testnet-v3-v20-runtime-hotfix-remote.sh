#!/usr/bin/env bash
# Root-only remote helper for an exact, recoverable Testnet-v3 v20 runtime
# switch. It never removes or replaces chain data.
set -euo pipefail

fail() {
  printf 'testnet-v3-v20-runtime-hotfix-remote: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: testnet-v3-v20-runtime-hotfix-remote.sh \' \
    '  --stage-dir <isolated directory> \' \
    '  --role <relayer|rpc-gateway|explorer-indexer|validator> \' \
    '  --expected-binary-sha256 <hex> \' \
    '  --expected-genesis-sha256 <hex> \' \
    '  --source-revision <full git sha> --apply' >&2
  exit 2
}

stage_dir=
role=
expected_binary_sha256=
expected_genesis_sha256=
source_revision=
apply=false
leave_inactive=false
while (($#)); do
  case "$1" in
    --stage-dir) stage_dir=${2:-}; shift 2 ;;
    --role) role=${2:-}; shift 2 ;;
    --expected-binary-sha256) expected_binary_sha256=${2:-}; shift 2 ;;
    --expected-genesis-sha256) expected_genesis_sha256=${2:-}; shift 2 ;;
    --source-revision) source_revision=${2:-}; shift 2 ;;
    --leave-inactive) leave_inactive=true; shift ;;
    --apply) apply=true; shift ;;
    *) usage ;;
  esac
done

[[ ${EUID} -eq 0 ]] || fail 'must run as root'
[[ $apply == true ]] || usage
[[ -d $stage_dir ]] || fail "stage directory does not exist: $stage_dir"
[[ $expected_binary_sha256 =~ ^[0-9a-f]{64}$ ]] || fail 'binary SHA-256 is invalid'
[[ $expected_genesis_sha256 =~ ^[0-9a-f]{64}$ ]] || fail 'Genesis SHA-256 is invalid'
[[ $source_revision =~ ^[0-9a-f]{40}$ ]] || fail 'source revision is invalid'
[[ $source_revision == 528f594ac491b34935de3669dd4273c414a51d48 ]] ||
  fail 'source revision is not the authorized Testnet-v3 release'

staged_binary="$stage_dir/runtime.bin"
[[ -f $staged_binary ]] || fail 'staged runtime binary is missing'
[[ $(sha256sum "$staged_binary" | awk '{print $1}') == "$expected_binary_sha256" ]] ||
  fail 'staged runtime binary checksum mismatch'
[[ $("$staged_binary" --version 2>&1 | head -n 1) == 'Synergy Testnet Node v20.0.0' ]] ||
  fail 'staged runtime version is not v20.0.0'

case "$role" in
  validator)
    unit=synergy-validator.service
    binary_destination=/opt/synergy/bin/synergy-validator
    binding_kind=fixed-binary
    config_path=/etc/synergy/validator/config.toml
    genesis_path=/etc/synergy/testnet-v3/genesis.json
    ;;
  relayer)
    unit=synergy-testnet-v3-relayer.service
    binary_destination="/opt/synergy/testnet-v3/relayer/synergy-relayer-node-v20.0.0-$expected_binary_sha256"
    binding_kind=relayer-dropin
    config_path=$(
      systemctl show "$unit" -p Environment --value |
        tr ' ' '\n' |
        sed -n 's/^SYNERGY_CONFIG_PATH=//p'
    )
    genesis_path=/etc/synergy/testnet-v3/genesis.json
    [[ $config_path =~ ^/etc/synergy/testnet-v3/relay[1-3]\.toml$ ]] ||
      fail "relayer config path is outside the approved contract: $config_path"
    ;;
  rpc-gateway)
    unit=synergy-testnet-v3-rpc-gateway.service
    binary_destination="/opt/synergy/testnet-v3/bin/synergy-node-v20.0.0-$expected_binary_sha256"
    binding_kind=runtime-env
    runtime_env=/etc/synergy/testnet-v3/rpc-gateway/runtime.env
    config_path=/etc/synergy/testnet-v3/rpc-gateway/node.toml
    genesis_path=/etc/synergy/testnet-v3/rpc-gateway/genesis.json
    ;;
  explorer-indexer)
    unit=synergy-testnet-v3-explorer-indexer.service
    binary_destination="/opt/synergy/testnet-v3/bin/synergy-node-v20.0.0-$expected_binary_sha256"
    binding_kind=runtime-env
    runtime_env=/etc/synergy/testnet-v3/explorer-indexer/runtime.env
    config_path=/etc/synergy/testnet-v3/explorer-indexer/node.toml
    genesis_path=/etc/synergy/testnet-v3/explorer-indexer/genesis.json
    ;;
  *)
    usage
    ;;
esac
if [[ $leave_inactive == true && $role != validator ]]; then
  fail '--leave-inactive is permitted only for a coordinated validator switch'
fi

[[ $(systemctl show "$unit" -p LoadState --value) == loaded ]] ||
  fail "required unit is not loaded: $unit"
required_initial_state=active
if [[ $leave_inactive == true ]]; then
  required_initial_state=inactive
fi
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == "$required_initial_state" ]] ||
  fail "required unit state before the switch is $required_initial_state: $unit"
[[ -f $config_path ]] || fail "bound config is missing: $config_path"
[[ -f $genesis_path ]] || fail "bound Genesis is missing: $genesis_path"
[[ $(sha256sum "$genesis_path" | awk '{print $1}') == "$expected_genesis_sha256" ]] ||
  fail "bound Genesis checksum is not canonical: $genesis_path"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_directory="/var/backups/synergy-testnet-v3/runtime-hotfix-${role}-${timestamp}"
install -d -m 0700 -o root -g root "$backup_directory"

fragment_path=$(systemctl show "$unit" -p FragmentPath --value)
[[ $fragment_path == /etc/systemd/system/*.service ]] ||
  fail "unit fragment is outside the approved systemd path: $fragment_path"
cp -a "$fragment_path" "$backup_directory/unit.before.service"
cp -a "$config_path" "$backup_directory/config.before.toml"
cp -a "$genesis_path" "$backup_directory/genesis.before.json"

if [[ $leave_inactive == true ]]; then
  running_binary=$binary_destination
else
  running_pid=$(systemctl show "$unit" -p MainPID --value)
  running_args=$(ps -p "$running_pid" -o args=)
  running_binary=$(printf '%s\n' "$running_args" | awk '{print $1}')
  if [[ $running_binary == */synergy-release-guard ]]; then
    running_binary=$(printf '%s\n' "$running_args" | awk '{print $2}')
  fi
fi
[[ -f $running_binary ]] || fail "cannot resolve current runtime binary: $running_binary"
cp -a "$running_binary" "$backup_directory/runtime.before.bin"

previous_binding_present=false
case "$binding_kind" in
  relayer-dropin)
    dropin=/etc/systemd/system/synergy-testnet-v3-relayer.service.d/60-v20-runtime-hotfix.conf
    install -d -m 0755 -o root -g root "$(dirname "$dropin")"
    if [[ -e $dropin ]]; then
      cp -a "$dropin" "$backup_directory/binding.before"
      previous_binding_present=true
    fi
    ;;
  runtime-env)
    [[ -f $runtime_env ]] || fail "runtime environment is missing: $runtime_env"
    cp -a "$runtime_env" "$backup_directory/binding.before"
    previous_binding_present=true
    [[ $(grep -c '^SYNERGY_RELEASE_RUNTIME_BINARY=' "$runtime_env") -eq 1 ]] ||
      fail 'runtime environment must contain exactly one runtime binary binding'
    [[ $(grep -c '^SYNERGY_RELEASE_RUNTIME_SHA256=' "$runtime_env") -eq 1 ]] ||
      fail 'runtime environment must contain exactly one runtime checksum binding'
    ;;
esac

config_sha256=$(sha256sum "$config_path" | awk '{print $1}')
printf '%s\n' \
  "unit=$unit" \
  "role=$role" \
  "source_revision=$source_revision" \
  "runtime_before=$running_binary" \
  "runtime_before_sha256=$(sha256sum "$running_binary" | awk '{print $1}')" \
  "runtime_after=$binary_destination" \
  "runtime_after_sha256=$expected_binary_sha256" \
  "config=$config_path" \
  "config_sha256=$config_sha256" \
  "genesis=$genesis_path" \
  "genesis_sha256=$expected_genesis_sha256" \
  > "$backup_directory/switch-plan.txt"

if [[ $leave_inactive == true ]]; then
  pending_binary="${binary_destination}.pending.$$"
  install -m 0755 -o root -g root "$staged_binary" "$pending_binary"
  [[ $(sha256sum "$pending_binary" | awk '{print $1}') == "$expected_binary_sha256" ]] ||
    fail 'installed pending runtime checksum mismatch'
  mv "$pending_binary" "$binary_destination"
  [[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] ||
    fail "validator unit changed state during inactive staging: $unit"
  printf '{"result":"TESTNET_V3_V20_RUNTIME_STAGED_INACTIVE","role":"%s","unit":"%s","source_revision":"%s","runtime_sha256":"%s","backup":"%s","service_active":false}\n' \
    "$role" \
    "$unit" \
    "$source_revision" \
    "$expected_binary_sha256" \
    "$backup_directory" |
    tee "$backup_directory/switch-evidence.json"
  exit 0
fi

rollback() {
  set +e
  systemctl stop "$unit"
  case "$binding_kind" in
    fixed-binary)
      install -m 0755 -o root -g root \
        "$backup_directory/runtime.before.bin" "$binary_destination"
      ;;
    relayer-dropin)
      if [[ $previous_binding_present == true ]]; then
        install -m 0644 -o root -g root "$backup_directory/binding.before" "$dropin"
      elif [[ -e $dropin ]]; then
        mv "$dropin" "$backup_directory/failed-new-binding.conf"
      fi
      ;;
    runtime-env)
      install -m 0644 -o root -g root "$backup_directory/binding.before" "$runtime_env"
      ;;
  esac
  systemctl daemon-reload
  systemctl start "$unit"
  printf 'ROLLBACK_PERFORMED\n' > "$backup_directory/rollback.txt"
}
trap 'rollback' ERR

systemctl stop "$unit"
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == inactive ]] ||
  fail "unit did not stop cleanly: $unit"

install -d -m 0755 -o root -g root "$(dirname "$binary_destination")"
install -m 0755 -o root -g root "$staged_binary" "$binary_destination"
[[ $(sha256sum "$binary_destination" | awk '{print $1}') == "$expected_binary_sha256" ]] ||
  fail 'installed runtime checksum mismatch'

case "$binding_kind" in
  fixed-binary)
    ;;
  relayer-dropin)
    guard=/opt/synergy/testnet-v3/relayer/synergy-release-guard
    [[ -x $guard ]] || fail "release guard is missing: $guard"
    pending="${dropin}.pending.$$"
    {
      printf '[Service]\n'
      printf 'ExecStart=\n'
      printf 'ExecStart=%s %s %s %s %s %s %s start --config %s\n' \
        "$guard" \
        "$binary_destination" \
        "$expected_binary_sha256" \
        "$config_path" \
        "$config_sha256" \
        "$genesis_path" \
        "$expected_genesis_sha256" \
        "$config_path"
    } > "$pending"
    install -m 0644 -o root -g root "$pending" "$dropin"
    mv "$pending" "$backup_directory/generated-binding.conf"
    ;;
  runtime-env)
    pending="${runtime_env}.pending.$$"
    awk \
      -v binary="$binary_destination" \
      -v digest="$expected_binary_sha256" \
      'BEGIN { binary_count=0; digest_count=0 }
       /^SYNERGY_RELEASE_RUNTIME_BINARY=/ {
         print "SYNERGY_RELEASE_RUNTIME_BINARY=" binary
         binary_count++
         next
       }
       /^SYNERGY_RELEASE_RUNTIME_SHA256=/ {
         print "SYNERGY_RELEASE_RUNTIME_SHA256=" digest
         digest_count++
         next
       }
       { print }
       END {
         if (binary_count != 1 || digest_count != 1) {
           exit 1
         }
       }' "$runtime_env" > "$pending"
    install -m 0644 -o root -g root "$pending" "$runtime_env"
    mv "$pending" "$backup_directory/generated-runtime.env"
    ;;
esac

systemctl daemon-reload
systemctl start "$unit"
for _ in $(seq 1 60); do
  [[ $(systemctl is-active "$unit" 2>/dev/null || true) == active ]] && break
  sleep 1
done
[[ $(systemctl is-active "$unit" 2>/dev/null || true) == active ]] ||
  fail "unit did not become active after runtime switch: $unit"

new_pid=
new_args=
for _ in $(seq 1 60); do
  new_pid=$(systemctl show "$unit" -p MainPID --value)
  new_args=$(ps -p "$new_pid" -o args= 2>/dev/null || true)
  [[ $new_args == *"$binary_destination"* ]] && break
  [[ $(systemctl is-active "$unit" 2>/dev/null || true) == active ]] ||
    fail "unit stopped while waiting for the staged runtime process: $unit"
  sleep 1
done
[[ $new_args == *"$binary_destination"* ]] ||
  fail "live process is not using the staged runtime after 60 seconds: $new_args"

rpc_response=
for _ in $(seq 1 180); do
  rpc_response=$(
    curl -sS --max-time 2 \
      -H 'content-type: application/json' \
      --data '{"jsonrpc":"2.0","id":1,"method":"synergy_chainId","params":[]}' \
      http://127.0.0.1:5640 2>/dev/null || true
  )
  [[ $rpc_response == *'"chain_id":1266'* ]] && break
  sleep 1
done
[[ $rpc_response == *'"chain_id":1266'* ]] || fail 'local RPC did not return chain 1266'
[[ $rpc_response == *'c087b6b7c1aae6f13f4c0140ba9a230a12dea0fa52b611777dee69369457de3d'* ]] ||
  fail 'local RPC did not return the canonical Testnet-v3 Genesis hash'

trap - ERR
printf '{"result":"TESTNET_V3_V20_RUNTIME_SWITCHED","role":"%s","unit":"%s","source_revision":"%s","runtime_sha256":"%s","backup":"%s","service_active":true}\n' \
  "$role" \
  "$unit" \
  "$source_revision" \
  "$expected_binary_sha256" \
  "$backup_directory" |
  tee "$backup_directory/switch-evidence.json"
