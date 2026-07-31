#!/usr/bin/env bash
# Run the release-candidate private qualification on the six actual validator
# machines.  This is deliberately separate from run-ring2-private-
# qualification.sh: that script is a CI preflight and cannot be promotion
# evidence for a distributed fleet.
set -euo pipefail

release_host="${CHAIN1266_RING2_RELEASE_HOST:-synergy-val1}"
release_dir="${CHAIN1266_RING2_RELEASE_DIR:?CHAIN1266_RING2_RELEASE_DIR is required (remote path on synergy-val1)}"
release_id="${CHAIN1266_RING2_RELEASE_ID:?CHAIN1266_RING2_RELEASE_ID is required}"
output="${CHAIN1266_RING2_OUTPUT_DIR:?CHAIN1266_RING2_OUTPUT_DIR is required}"
target_height="${CHAIN1266_RING2_TARGET_HEIGHT:-10000}"
run_id="${CHAIN1266_RING2_RUN_ID:-c1266q$(date -u +%Y%m%d%H%M%S)}"
preflight_only="${CHAIN1266_RING2_PREFLIGHT_ONLY:-0}"

[[ "$release_host" == synergy-val1 ]] || { echo "Ring-2 release host must be synergy-val1" >&2; exit 2; }
[[ "$release_id" =~ ^chain1266-incarnation-4-rc[0-9]+$ ]] || { echo "invalid release ID" >&2; exit 2; }
[[ "$release_dir" == /* && "$release_dir" != *$'\n'* ]] || { echo "release directory must be an absolute one-line remote path" >&2; exit 2; }
[[ "$target_height" =~ ^[0-9]+$ ]] && (( target_height >= 10000 )) || { echo "target height must be at least 10000" >&2; exit 2; }
[[ "$run_id" =~ ^c1266q[a-z0-9]{6,24}$ ]] || { echo "run ID must be a compact c1266q identifier" >&2; exit 2; }
[[ "$preflight_only" == 0 || "$preflight_only" == 1 ]] || { echo "preflight-only must be 0 or 1" >&2; exit 2; }

# Keep every logical command on a host multiplexed through exactly one
# workbook-backed SSH master.  This is intentionally the only SSH interface
# used by this runner; it never accepts hostnames or addresses as arguments.
control_path="${CHAIN1266_SSH_CONTROL_PATH:-/tmp/synergy-chain1266-control-%C}"
ssh_options=(-o BatchMode=yes -o ConnectTimeout=8 -o ControlMaster=auto -o ControlPersist=900 -o "ControlPath=$control_path")
ssh_run() { local alias="$1"; shift; ssh "${ssh_options[@]}" "$alias" bash -s <<<"$*"; }
ssh_capture() { local alias="$1"; shift; ssh "${ssh_options[@]}" "$alias" bash -s <<<"$*"; }
q() { printf '%q' "$1"; }

declare -a hosts=(synergy-val1 synergy-val2 synergy-val3 synergy-val4 synergy-val5 synergy-val6)
declare -A host_number=([synergy-val1]=1 [synergy-val2]=2 [synergy-val3]=3 [synergy-val4]=4 [synergy-val5]=5 [synergy-val6]=6)
declare -A hosted_roles=(
  [synergy-val1]='validator-node-01'
  [synergy-val2]='validator-node-02'
  [synergy-val3]='validator-node-03'
  [synergy-val4]='validator-node-04 relay1'
  [synergy-val5]='validator-node-05 relay2 rpc-gateway'
  [synergy-val6]='validator-node-06 relay3 explorer-indexer observer'
)
declare -A role_ip=(
  [validator-node-01]=10.70.10.1 [validator-node-02]=10.70.10.2
  [validator-node-03]=10.70.10.3 [validator-node-04]=10.70.10.4
  [validator-node-05]=10.70.10.5 [validator-node-06]=10.70.10.6
  [relay1]=10.70.20.1 [relay2]=10.70.20.2 [relay3]=10.70.20.3
  [rpc-gateway]=10.70.30.1 [explorer-indexer]=10.70.30.2 [observer]=10.70.30.3
)
declare -A role_binary=(
  [validator-node-01]=synergy-validator-node [validator-node-02]=synergy-validator-node
  [validator-node-03]=synergy-validator-node [validator-node-04]=synergy-validator-node
  [validator-node-05]=synergy-validator-node [validator-node-06]=synergy-validator-node
  [relay1]=synergy-relayer-node [relay2]=synergy-relayer-node [relay3]=synergy-relayer-node
  [rpc-gateway]=synergy-rpc-gateway-node [explorer-indexer]=synergy-indexer-and-explorer-node
  [observer]=synergy-observer-light-node
)
declare -A role_config=(
  [validator-node-01]=validators/val1.toml [validator-node-02]=validators/val2.toml
  [validator-node-03]=validators/val3.toml [validator-node-04]=validators/val4.toml
  [validator-node-05]=validators/val5.toml [validator-node-06]=validators/val6.toml
  [relay1]=relayers/relay1.toml [relay2]=relayers/relay2.toml [relay3]=relayers/relay3.toml
  [rpc-gateway]=rpc-gateway/rpc-gateway.toml
  [explorer-indexer]=explorer-indexer/explorer-indexer.toml [observer]=observer/observer.toml
)
declare -A role_host=()
for host in "${hosts[@]}"; do for role in ${hosted_roles[$host]}; do role_host[$role]="$host"; done; done
roles=(validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06 relay1 relay2 relay3 rpc-gateway explorer-indexer observer)

root="/opt/synergy/chain1266-qualification/$run_id"
data_root="/var/lib/synergy/chain1266-qualification/$run_id"
iface="c1266q${run_id: -6}"
fw_chain="C1266Q${run_id: -6}"
qualification_unit="/run/systemd/system/synergy-chain1266-role@.service"
mkdir -p "$output"
chmod 0700 "$output"

cleanup_started=false
cleanup() {
  [[ "$cleanup_started" == false ]] || return
  cleanup_started=true
  for host in "${hosts[@]}"; do
    ssh_run "$host" "
      set +e
      run=$(q "$run_id"); root=$(q "$root"); data=$(q "$data_root"); iface=$(q "$iface"); chain=$(q "$fw_chain"); unit_file=$(q "$qualification_unit")
      [[ \"\$run\" =~ ^c1266q[a-z0-9]{6,24}\$ ]] || exit 0
      for unit in \$(systemctl list-units --all --plain --no-legend 'synergy-chain1266-role@'\"\$run\"'-*.service' 2>/dev/null | awk '{print \$1}'); do sudo -n systemctl stop \"\$unit\" || true; done
      sudo -n rm -f /run/synergy-chain1266/\"\$run\"-*.env 2>/dev/null || true
      sudo -n rm -f /run/systemd/system/synergy-chain1266-role@.service.d/\"\$run\".conf 2>/dev/null || true
      sudo -n rm -f \"\$unit_file\" 2>/dev/null || true
      sudo -n systemctl daemon-reload || true
      sudo -n iptables -D INPUT -d 10.70.0.0/16 -j \"\$chain\" 2>/dev/null || true
      sudo -n iptables -F \"\$chain\" 2>/dev/null || true
      sudo -n iptables -X \"\$chain\" 2>/dev/null || true
      sudo -n ip link delete \"\$iface\" 2>/dev/null || true
      sudo -n find \"\$root\" -mindepth 1 -delete 2>/dev/null || true
      sudo -n rmdir \"\$root\" 2>/dev/null || true
      sudo -n find \"\$data\" -mindepth 1 -delete 2>/dev/null || true
      sudo -n rmdir \"\$data\" 2>/dev/null || true
    " || true
  done
}
# A preflight is intentionally read-only.  The control-plane command that
# appends RING2_REAL_HOST_QUALIFICATION_BEGIN must be run immediately before
# this script, after this succeeds and before any of the mutations below.
for host in "${hosts[@]}"; do
  ssh_run "$host" '
    set -eu
    for command in sudo systemctl ip wg iptables curl jq sha256sum journalctl tc; do command -v "$command" >/dev/null; done
    sudo -n true
    for service in synergy-chain1266-role@validator-node-01.service synergy-chain1266-role@validator-node-02.service synergy-chain1266-role@validator-node-03.service synergy-chain1266-role@validator-node-04.service synergy-chain1266-role@validator-node-05.service synergy-chain1266-role@validator-node-06.service; do
      [[ "$(systemctl is-active "$service" 2>/dev/null || true)" != active ]]
    done
    [[ ! -e /run/systemd/system/synergy-chain1266-role@.service ]]
  '
done

declare -A endpoint=() wg_public=()
for host in "${hosts[@]}"; do
  configured_host="$(ssh -G "$host" | awk '$1 == "hostname" {print $2; exit}')"
  endpoint[$host]="$(python3 - "$configured_host" <<'PY'
import socket, sys
for family, _, _, _, sockaddr in socket.getaddrinfo(sys.argv[1], None, socket.AF_INET, socket.SOCK_DGRAM):
    print(sockaddr[0]); break
PY
)"
  [[ -n "${endpoint[$host]}" ]] || { echo "could not resolve workbook alias $host for WireGuard" >&2; exit 1; }
done

if [[ "$preflight_only" == 1 ]]; then
  echo "CHAIN1266_RING2_REAL_HOST_PREFLIGHT_PASS release=$release_id run=$run_id"
  exit 0
fi

trap cleanup EXIT INT TERM

# Create the entire disposable source tree on val1.  No production state,
# identity, WireGuard key, or canonical service file is read by this step.
ssh_run synergy-val1 "
  set -euo pipefail
  release=$(q "$release_dir"); root=$(q "$root")
  test -x \"\$release/bin/build-chain1266-private-ring-material\"
  test -x \"\$release/bin/build-chain1266-desired-state\"
  test -x \"\$release/bin/sign-chain1266-desired-state\"
  test -f \"\$release/qualification-tools/prepare-ring2-configs.py\"
  sudo -n install -d -m 0700 \"\$root\" \"\$root/shared\" \"\$root/private\"
  sudo -n cp -a \"\$release/bin\" \"\$release/systemd\" \"\$root/\"
  sudo -n cp \"\$release/genesis.json\" \"\$root/shared/source-genesis.json\"
  sudo -n \"\$root/bin/build-chain1266-private-ring-material\" --source-genesis \"\$root/shared/source-genesis.json\" --output-genesis \"\$root/shared/genesis.json\" --key-root \"\$root/private\"
  sudo -n python3 \"\$release/qualification-tools/prepare-ring2-configs.py\" --release-dir \"\$release\" --genesis \"\$root/shared/genesis.json\" --output \"\$root/config\"
  release_id=$(q "$release_id")
  tag=chain1266-v20.0.0-rc.\${release_id##*rc}
  testnet=\$(jq -er .source.testnet_v3_revision \"\$release/desired-state.json\")
  synq=\$(jq -er .source.synq_revision \"\$release/desired-state.json\")
  aegis=\$(jq -er .source.aegis_revision \"\$release/desired-state.json\")
  args=(--release-id \"\$release_id\" --release-tag \"\$tag\" --testnet-revision \"\$testnet\" --synq-revision \"\$synq\" --aegis-revision \"\$aegis\" --genesis \"\$root/shared/genesis.json\" --start-authority \"\$root/private/start-authority.public.json\")
  for binary in validator_node relayer_node observer_light_node rpc_gateway_node indexer_and_explorer_node; do :; done
  args+=(--artifact validator_node=\"\$root/bin/synergy-validator-node\" --artifact relayer_node=\"\$root/bin/synergy-relayer-node\" --artifact observer_light_node=\"\$root/bin/synergy-observer-light-node\" --artifact rpc_gateway_node=\"\$root/bin/synergy-rpc-gateway-node\" --artifact indexer_and_explorer_node=\"\$root/bin/synergy-indexer-and-explorer-node\")
  for n in 1 2 3 4 5 6; do args+=(--configuration validator-node-0\"\$n\"=\"\$root/config/validators/val\"\$n\".toml\"); done
  for n in 1 2 3; do args+=(--configuration relay\"\$n\"=\"\$root/config/relayers/relay\"\$n\".toml\"); done
  args+=(--configuration rpc-gateway=\"\$root/config/rpc-gateway/rpc-gateway.toml\" --configuration explorer-indexer=\"\$root/config/explorer-indexer/explorer-indexer.toml\" --configuration observer=\"\$root/config/observer/observer.toml\")
  sudo -n \"\$root/bin/build-chain1266-desired-state\" \"\${args[@]}\" --output \"\$root/shared/desired-state.json\"
  sudo -n \"\$root/bin/sign-chain1266-desired-state\" --desired-state \"\$root/shared/desired-state.json\" --private-key \"\$root/private/start-authority.private.key\" --output \"\$root/shared/desired-state.signature.json\"
"

stream_to_host() {
  local host="$1" number="${host_number[$1]}"
  # The private validator key is one selected file; everything else is public
  # qualification material.  It streams controller-to-controller and is never
  # written to the workstation filesystem.
  ssh "${ssh_options[@]}" synergy-val1 "sudo -n tar -C $(q "$root") -cf - bin systemd shared config private/validator-$number" \
    | ssh "${ssh_options[@]}" "$host" "sudo -n install -d -m 0700 $(q "$root"); sudo -n tar -C $(q "$root") -xf -"
}
for host in "${hosts[@]}"; do [[ "$host" == synergy-val1 ]] || stream_to_host "$host"; done

for host in "${hosts[@]}"; do
  ips=(); for role in ${hosted_roles[$host]}; do ips+=("${role_ip[$role]}/16"); done
  key="$(ssh_capture "$host" "
    set -euo pipefail
    root=$(q "$root"); iface=$(q "$iface")
    sudo -n install -d -m 0700 \"\$root/wireguard\"
    sudo -n ip link add \"\$iface\" type wireguard
    umask 077; wg genkey | sudo -n tee \"\$root/wireguard/private.key\" >/dev/null
    sudo -n chmod 0600 \"\$root/wireguard/private.key\"
    sudo -n wg set \"\$iface\" private-key \"\$root/wireguard/private.key\" listen-port $((51830 + ${host_number[$host]}))
    $(for ip in "${ips[@]}"; do printf 'sudo -n ip address add %q dev "$iface"\n' "$ip"; done)
    sudo -n ip link set \"\$iface\" up
    sudo -n wg show \"\$iface\" public-key
  ")"
  wg_public[$host]="$(tr -d '[:space:]' <<<"$key")"
  [[ "${wg_public[$host]}" =~ ^[A-Za-z0-9+/]{42,44}=$ ]] || { echo "WireGuard public key generation failed on $host" >&2; exit 1; }
done

for host in "${hosts[@]}"; do
  peer_args=()
  for peer in "${hosts[@]}"; do
    [[ "$peer" == "$host" ]] && continue
    allowed=(); for role in ${hosted_roles[$peer]}; do allowed+=("${role_ip[$role]}/32"); done
    peer_args+=(peer "${wg_public[$peer]}" allowed-ips "$(IFS=,; echo "${allowed[*]}")" endpoint "${endpoint[$peer]}:$((51830 + ${host_number[$peer]}))" persistent-keepalive 5)
  done
  quoted=(); for part in "${peer_args[@]}"; do quoted+=("$(q "$part")"); done
  ssh_run "$host" "set -euo pipefail; sudo -n wg set $(q "$iface") ${quoted[*]}; sudo -n iptables -N $(q "$fw_chain"); sudo -n iptables -A $(q "$fw_chain") -i lo -j RETURN; sudo -n iptables -A $(q "$fw_chain") -i $(q "$iface") -j RETURN; sudo -n iptables -A $(q "$fw_chain") -j DROP; sudo -n iptables -I INPUT -d 10.70.0.0/16 -j $(q "$fw_chain"); ip route show default dev $(q "$iface") | grep -q . && exit 1 || true"
done

for host in "${hosts[@]}"; do
  ssh_run "$host" "sudo -n install -m 0644 $(q "$root")/systemd/synergy-chain1266-role@.service $(q "$qualification_unit"); sudo -n systemctl daemon-reload"
done

for host in "${hosts[@]}"; do
  for role in ${hosted_roles[$host]}; do
    unit="$run_id-$role"; binary="${role_binary[$role]}"; config="${role_config[$role]}"; ip="${role_ip[$role]}"
    validator_env=''
    if [[ "$role" == validator-* ]]; then
      number="${role##*-0}"
      validator_env="SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=$root/private/validator-$number/mldsa65-consensus.private.key
CONSENSUS_START_PAUSED=1
SYNERGY_CONSENSUS_START_RELEASE_FILE=$root/shared/start-consensus.json"
    fi
    ssh_run "$host" "
      set -euo pipefail
      root=$(q "$root"); data=$(q "$data_root"); unit=$(q "$unit"); role=$(q "$role")
      sudo -n install -d -m 0755 /run/synergy-chain1266 /run/systemd/system/synergy-chain1266-role@.service.d \"\$data/\$role/data\" \"\$root/project/\$role\"
      sudo -n tee /run/systemd/system/synergy-chain1266-role@.service.d/$(q "$run_id").conf >/dev/null <<'EOF'
[Service]
EnvironmentFile=
EnvironmentFile=/run/synergy-chain1266/%i.env
ExecStart=
ExecStart=$root/systemd/chain1266-role-service
EOF
      sudo -n tee /run/synergy-chain1266/\"\$unit\".env >/dev/null <<EOF
CHAIN1266_ROLE_BINARY=$root/bin/$binary
CHAIN1266_ROLE_CONFIG=$root/config/$config
SYNERGY_PROJECT_ROOT=$root/project/$role
SYNERGY_DATA_PATH=\$data/$role/data
SYNERGY_GENESIS_FILE=$root/shared/genesis.json
SYNERGY_DESIRED_STATE_MANIFEST=$root/shared/desired-state.json
SYNERGY_DESIRED_STATE_MANIFEST_SHA256=\$(sudo -n sha256sum \"\$root/shared/desired-state.json\" | awk '{print \$1}')
SYNERGY_DESIRED_STATE_SIGNATURE=$root/shared/desired-state.signature.json
SYNERGY_CHAIN1266_QUALIFICATION_MODE=1
SYNERGY_ENABLE_METRICS=true
SYNERGY_METRICS_BIND=$ip:6030
$validator_env
EOF
      sudo -n chmod 0600 /run/synergy-chain1266/\"\$unit\".env
      sudo -n systemctl daemon-reload
    "
  done
done

start_role() { local role="$1" host="${role_host[$1]}"; ssh_run "$host" "sudo -n systemctl reset-failed synergy-chain1266-role@$(q "$run_id-$role").service || true; sudo -n systemctl start synergy-chain1266-role@$(q "$run_id-$role").service"; }
stop_role() { local role="$1" host="${role_host[$1]}"; ssh_run "$host" "sudo -n systemctl stop synergy-chain1266-role@$(q "$run_id-$role").service"; }
metric_text() { local role="$1" host="${role_host[$1]}"; ssh_capture "$host" "curl --fail --silent --max-time 3 http://$(q "${role_ip[$role]}"):6030/metrics"; }
metric() { local role="$1" name="$2"; metric_text "$role" | awk -v n="$name" '$1 == n {print $2; exit}'; }

for role in relay1 relay2 relay3 rpc-gateway explorer-indexer observer validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05; do start_role "$role"; done
sleep 5
start_role validator-node-06

deadline=$((SECONDS + 600))
while :; do
  ready=0
  for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
    if metric_text "$role" 2>/dev/null | grep -q 'consensus_startup_phase_info{phase="PAUSED_READY"} 1'; then ready=$((ready + 1)); fi
  done
  (( ready == 6 )) && break
  (( SECONDS < deadline )) || { echo "validators did not reach PAUSED_READY" >&2; exit 1; }
  sleep 2
done

for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
  [[ "$(metric "$role" consensus_finalized_height || echo 0)" == 0 ]] || {
    echo "a validator finalized before the signed start release" >&2
    exit 1
  }
done
mesh_deadline=$((SECONDS + 60))
while :; do
  mesh_ready=true
  for host in "${hosts[@]}"; do
    handshakes="$(ssh_capture "$host" "sudo -n wg show $(q "$iface") latest-handshakes | awk '\$2 > 0 {count++} END {print count + 0}'")"
    [[ "$handshakes" == 5 ]] || mesh_ready=false
  done
  [[ "$mesh_ready" == true ]] && break
  (( SECONDS < mesh_deadline )) || { echo "disposable WireGuard mesh did not handshake before consensus release" >&2; exit 1; }
  sleep 2
done
activate_ms="$(( $(ssh_capture synergy-val1 'date +%s') * 1000 + 10000 ))"
ssh_run synergy-val1 "sudo -n $(q "$root")/bin/sign-chain1266-start-command --desired-state $(q "$root")/shared/desired-state.json --private-key $(q "$root")/private/start-authority.private.key --activate-unix-ms $(q "$activate_ms") --output $(q "$root")/shared/start-consensus.json"
for host in "${hosts[@]}"; do [[ "$host" == synergy-val1 ]] || ssh "${ssh_options[@]}" synergy-val1 "sudo -n tar -C $(q "$root/shared") -cf - start-consensus.json" | ssh "${ssh_options[@]}" "$host" "sudo -n tar -C $(q "$root/shared") -xf -"; done

last_height=0; last_progress=$SECONDS; faults_done=false
while :; do
  heights=(); ids=()
  for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
    text="$(metric_text "$role")"
    heights+=("$(awk '$1 == "consensus_finalized_height" {print int($2); exit}' <<<"$text")")
    ids+=("$(sed -n 's/^consensus_finalized_block_id{block_id="\([^"]*\)"} 1$/\1/p' <<<"$text")")
    printf '%s\n' "$text" >"$output/$role.metrics"
  done
  min="$(printf '%s\n' "${heights[@]}" | sort -n | head -1)"; max="$(printf '%s\n' "${heights[@]}" | sort -n | tail -1)"
  (( max - min <= 2 )) || { echo "validator tip spread exceeded two blocks: ${heights[*]}" >&2; exit 1; }
  [[ "$(printf '%s\n' "${ids[@]}" | sort -u | sed '/^$/d' | wc -l | tr -d ' ')" -le 1 ]] || { echo "validator finalized block IDs diverged" >&2; exit 1; }
  if (( min > last_height )); then last_height="$min"; last_progress=$SECONDS; elif (( SECONDS - last_progress > 30 )); then echo "finality stalled" >&2; exit 1; fi
  if (( min >= 1000 && "$faults_done" == false )); then
    before="$min"; stop_role validator-node-06; sleep 10
    progressed="$(metric validator-node-01 consensus_finalized_height || echo 0)"; (( progressed > before )) || { echo "five-validator quorum did not continue" >&2; exit 1; }
    start_role validator-node-06; rejoin_deadline=$((SECONDS + 180)); while (( $(metric validator-node-01 consensus_finalized_height || echo 999999) - $(metric validator-node-06 consensus_finalized_height || echo 0) > 2 )); do (( SECONDS < rejoin_deadline )) || { echo "validator 6 failed to rejoin" >&2; exit 1; }; sleep 2; done
    ssh_run synergy-val6 "sudo -n tc qdisc add dev $(q "$iface") root netem loss 10%"; before_loss="$(metric validator-node-01 consensus_finalized_height)"; sleep 12; ssh_run synergy-val6 "sudo -n tc qdisc del dev $(q "$iface") root"; (( $(metric validator-node-01 consensus_finalized_height) > before_loss )) || { echo "quorum failed during peer impairment" >&2; exit 1; }
    stop_role observer; ssh_run synergy-val6 "set -eu; d=$(q "$data_root")/observer/data; sudo -n find \"\$d\" -mindepth 1 -delete; sudo -n touch \"\$d/.reset_flag\""; start_role observer
    observer_deadline=$((SECONDS + 180)); while (( $(metric validator-node-01 consensus_finalized_height || echo 999999) - $(metric observer consensus_finalized_height || echo 0) > 2 )); do (( SECONDS < observer_deadline )) || { echo "wiped observer failed to resynchronize" >&2; exit 1; }; sleep 2; done
    faults_done=true
    jq -n --argjson before "$before" --argjson after "$(metric validator-node-01 consensus_finalized_height)" '{single_validator_restart:"PASS",packet_loss:"PASS",observer_wipe_resync:"PASS",height_before:$before,height_after:$after}' >"$output/fault-recovery.json"
  fi
  (( min >= target_height )) && [[ "$faults_done" == true ]] && break
  sleep 1
done

for role in "${roles[@]}"; do ssh_capture "${role_host[$role]}" "sudo -n journalctl -u synergy-chain1266-role@$(q "$run_id-$role").service --no-pager -n 200 -o short-iso-precise" >"$output/$role.log" || true; done
final_height="$last_height"; mldsa="$(awk '/^p2p_verified_handshakes_total\{algorithm="ML-DSA-65"\}/ {s+=$2} END {print s+0}' "$output"/*.metrics)"; fndsa="$(awk '/^p2p_verified_handshakes_total\{algorithm="FN-DSA-1024"\}/ {s+=$2} END {print s+0}' "$output"/*.metrics)"
(( mldsa > 0 && fndsa > 0 )) || { echo "real PQ handshake counters are incomplete" >&2; exit 1; }
for role in relay1 relay2 relay3 rpc-gateway explorer-indexer observer; do
  (( final_height - $(metric "$role" consensus_finalized_height || echo 0) <= 2 )) || { echo "$role is more than two blocks behind at stable gate" >&2; exit 1; }
done
rows="$output/validator-health.jsonl"; : >"$rows"
for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
  text="$(<"$output/$role.metrics")"
  h="$(awk '$1=="consensus_finalized_height"{print int($2);exit}' <<<"$text")"; samples="$(awk '$1=="consensus_finality_interval_sample_count"{print int($2);exit}' <<<"$text")"; mean="$(awk '$1=="consensus_finality_interval_mean_seconds"{print $2;exit}' <<<"$text")"; median="$(awk '$1=="consensus_finality_interval_median_seconds"{print $2;exit}' <<<"$text")"; p95="$(awk '$1=="consensus_finality_interval_p95_seconds"{print $2;exit}' <<<"$text")"; ratio="$(awk '$1=="consensus_round_zero_ratio"{print $2;exit}' <<<"$text")"
  jq -n --arg role "$role" --argjson height "${h:-0}" --argjson samples "${samples:-0}" --argjson mean "${mean:-999}" --argjson median "${median:-999}" --argjson p95 "${p95:-999}" --argjson ratio "${ratio:-0}" '{node:$role,finalized_height:$height,sample_count:$samples,mean_finality_interval_seconds:$mean,median_finality_interval_seconds:$median,p95_finality_interval_seconds:$p95,round_zero_ratio:$ratio}' >>"$rows"
done
jq -se --argjson target "$target_height" 'all(.[]; .finalized_height >= $target and .sample_count >= 9999 and .mean_finality_interval_seconds <= 2 and .median_finality_interval_seconds <= 1.5 and .p95_finality_interval_seconds <= 3 and .round_zero_ratio >= .99)' "$rows" >/dev/null || { echo "direct finality health gate failed" >&2; exit 1; }
desired_sha="$(ssh_capture synergy-val1 "sudo -n sha256sum $(q "$root")/shared/desired-state.json | awk '{print \$1}'")"
jq -n --arg release "$release_id" --arg desired "$desired_sha" --argjson height "$final_height" --argjson mldsa "$mldsa" --argjson fndsa "$fndsa" '{schema_version:1,ring:2,result:"PASS",operational_state:"STABLE",release_id:$release,desired_state_sha256:$desired,qualification_environment:"six-real-validator-hosts",isolated_public_network:true,wireguard_overlay:true,wireguard_credentials_disposable:true,real_pq_handshakes:{mldsa65_verified:$mldsa,fndsa1024_verified:$fndsa},canonical_systemd_unit:"synergy-chain1266-role@.service",production_custody_material_used:false,validator_count:6,quorum:5,finalized_height:$height}' >"$output/report.json"
find "$output" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum | sed "s#  $output/#  #" >"$output/SHA256SUMS"
echo "CHAIN1266_RING2_REAL_HOST_PASS release=$release_id height=$final_height output=$output"
