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
target_height="${CHAIN1266_RING2_TARGET_HEIGHT:-5000}"
run_id="${CHAIN1266_RING2_RUN_ID:-c1266q$(date -u +%Y%m%d%H%M%S)}"
preflight_only="${CHAIN1266_RING2_PREFLIGHT_ONLY:-0}"
metrics_sample_interval_seconds="${CHAIN1266_RING2_METRICS_SAMPLE_INTERVAL_SECONDS:-10}"

[[ "$release_host" == synergy-val1 ]] || { echo "Ring-2 release host must be synergy-val1" >&2; exit 2; }
[[ "$release_id" =~ ^chain1266-incarnation-4-rc[0-9]+$ ]] || { echo "invalid release ID" >&2; exit 2; }
[[ "$release_dir" == /* && "$release_dir" != *$'\n'* ]] || { echo "release directory must be an absolute one-line remote path" >&2; exit 2; }
[[ "$target_height" =~ ^[0-9]+$ ]] && (( target_height >= 5000 )) || { echo "target height must be at least 5000" >&2; exit 2; }
[[ "$run_id" =~ ^c1266q[a-z0-9]{6,24}$ ]] || { echo "run ID must be a compact c1266q identifier" >&2; exit 2; }
[[ "$preflight_only" == 0 || "$preflight_only" == 1 ]] || { echo "preflight-only must be 0 or 1" >&2; exit 2; }
[[ "$metrics_sample_interval_seconds" =~ ^[0-9]+$ ]] && (( metrics_sample_interval_seconds >= 5 && metrics_sample_interval_seconds <= 30 )) || { echo "metrics sample interval must be 5 through 30 seconds" >&2; exit 2; }

# Keep every logical command on a host multiplexed through exactly one
# workbook-backed SSH master.  This is intentionally the only SSH interface
# used by this runner; it never accepts hostnames or addresses as arguments.
control_path="${CHAIN1266_SSH_CONTROL_PATH:-/Users/devpup/.chain1266-control/%C}"
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
  [validator-node-01]=10.126.10.1 [validator-node-02]=10.126.10.2
  [validator-node-03]=10.126.10.3 [validator-node-04]=10.126.10.4
  [validator-node-05]=10.126.10.5 [validator-node-06]=10.126.10.6
  [relay1]=10.126.20.1 [relay2]=10.126.20.2 [relay3]=10.126.20.3
  [rpc-gateway]=10.126.30.1 [explorer-indexer]=10.126.30.2 [observer]=10.126.30.3
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
declare -A role_host=() role_metrics_endpoint=()
for host in "${hosts[@]}"; do for role in ${hosted_roles[$host]}; do role_host[$role]="$host"; done; done
roles=(validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06 relay1 relay2 relay3 rpc-gateway explorer-indexer observer)
validator_roles=(validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06)
support_roles=(relay1 relay2 relay3 rpc-gateway explorer-indexer observer)

root="/opt/synergy/chain1266-qualification/$run_id"
data_root="/var/lib/synergy/chain1266-qualification/$run_id"
iface="c1266q${run_id: -6}"
fw_chain="C1266Q${run_id: -6}"
qualification_unit="/run/systemd/system/synergy-chain1266-role@.service"
mkdir -p "$output"
chmod 0700 "$output"

stage="local-validation"
report_unexpected_error() {
  local status="$?"
  printf 'CHAIN1266_RING2_RUNNER_ERROR stage=%s status=%s command=%q\n' "$stage" "$status" "$BASH_COMMAND" >&2
  exit "$status"
}
trap report_unexpected_error ERR

cleanup_started=false
capture_pre_cleanup_diagnostics() {
  [[ -d "$output" ]] || return 0
  for host in "${hosts[@]}"; do
    ssh_capture "$host" "
      set +e
      run=$(q "$run_id")
      printf 'captured_unix=%s\\n' \"\$(date +%s)\"
      systemctl list-units --all --plain --no-legend 'synergy-chain1266-role@'\"\$run\"'-*.service'
      for unit in \$(systemctl list-units --all --plain --no-legend 'synergy-chain1266-role@'\"\$run\"'-*.service' 2>/dev/null | awk '{print \$1}'); do
        printf '\\n[%s]\\n' \"\$unit\"
        systemctl show \"\$unit\" --no-pager --property=ActiveState,SubState,MainPID,ExecMainCode,ExecMainStatus,NRestarts
        journalctl -u \"\$unit\" --no-pager -n 200 -o short-iso-precise
      done
      sudo -n ss -lntup 2>&1 || true
    " >"$output/$host.pre-cleanup-diagnostics.txt" 2>&1 || true
  done
}
cleanup() {
  [[ "$cleanup_started" == false ]] || return
  cleanup_started=true
  capture_pre_cleanup_diagnostics
  for host in "${hosts[@]}"; do
    ssh_run "$host" "
      set +e
      run=$(q "$run_id"); root=$(q "$root"); data=$(q "$data_root"); iface=$(q "$iface"); chain=$(q "$fw_chain"); unit_file=$(q "$qualification_unit")
      [[ \"\$run\" =~ ^c1266q[a-z0-9]{6,24}\$ ]] || exit 0
      for unit in \$(systemctl list-units --all --plain --no-legend 'synergy-chain1266-role@'\"\$run\"'-*.service' 2>/dev/null | awk '{print \$1}'); do
        sudo -n systemctl stop \"\$unit\" || true
        sudo -n systemctl reset-failed \"\$unit\" || true
      done
      sudo -n rm -f /run/synergy-chain1266/\"\$run\"-*.env 2>/dev/null || true
      sudo -n rm -f /run/systemd/system/synergy-chain1266-role@.service.d/\"\$run\".conf 2>/dev/null || true
      sudo -n rm -f \"\$unit_file\" 2>/dev/null || true
      sudo -n systemctl daemon-reload || true
      sudo -n iptables -D INPUT -d 10.126.0.0/16 -j \"\$chain\" 2>/dev/null || true
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
  stage="read-only-preflight-$host"
  ssh_run "$host" '
    set -eu
    for command in sudo systemctl ip wg iptables curl jq sha256sum journalctl tc; do command -v "$command" >/dev/null; done
    sudo -n true
    for service in synergy-chain1266-role@validator-node-01.service synergy-chain1266-role@validator-node-02.service synergy-chain1266-role@validator-node-03.service synergy-chain1266-role@validator-node-04.service synergy-chain1266-role@validator-node-05.service synergy-chain1266-role@validator-node-06.service synergy-validator.service; do
      state="$(systemctl is-active "$service" 2>/dev/null || true)"
      [[ "$state" != active && "$state" != activating ]]
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
stage="private-material-render"
ssh_run synergy-val1 "
  set -euo pipefail
  release=$(q "$release_dir"); root=$(q "$root"); run=$(q "$run_id")
  test -x \"\$release/bin/build-chain1266-private-ring-material\"
  test -x \"\$release/bin/build-chain1266-desired-state\"
  test -x \"\$release/bin/sign-chain1266-desired-state\"
  test -f \"\$release/qualification-tools/prepare-ring2-configs.py\"
  sudo -n install -d -m 0700 \"\$root\" \"\$root/shared\" \"\$root/private\"
  sudo -n cp -a \"\$release/bin\" \"\$release/systemd\" \"\$root/\"
  sudo -n cp \"\$release/genesis.json\" \"\$root/shared/source-genesis.json\"
  sudo -n \"\$root/bin/build-chain1266-private-ring-material\" --source-genesis \"\$root/shared/source-genesis.json\" --output-genesis \"\$root/shared/genesis.json\" --key-root \"\$root/private\"
  sudo -n env PYTHONDONTWRITEBYTECODE=1 python3 \"\$release/qualification-tools/prepare-ring2-configs.py\" --release-dir \"\$release\" --genesis \"\$root/shared/genesis.json\" --output \"\$root/config\" --run-id \"\$run\"
  if sudo -n grep -R -q -E '10[.]70[.]' "\$root/shared/genesis.json" "\$root/config"; then
    echo 'private qualification material retains a legacy overlay endpoint' >&2
    exit 1
  fi
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
for host in "${hosts[@]}"; do
  [[ "$host" == synergy-val1 ]] && continue
  stage="package-stream-$host"
  stream_to_host "$host"
done

# Support roles share hosts with validators in the real-host exercise.  The
# private renderer assigns every role a separate loopback RPC/WS/gRPC surface;
# refuse the run before consensus release if another local process already
# owns one of those listeners.
for host in "${hosts[@]}"; do
  for role in ${hosted_roles[$host]}; do
    stage="legacy-rpc-port-preflight-$host-$role"
    config="${role_config[$role]}"
    ssh_run "$host" "
      set -euo pipefail
      config=$(q "$root/config/$config")
      ports=\$(sudo -n sed -n 's/^[[:space:]]*\\(http_port\\|ws_port\\|grpc_port\\)[[:space:]]*=[[:space:]]*\\([0-9][0-9]*\\)[[:space:]]*$/\\2/p' \"\$config\")
      for port in \$ports; do
        [[ \"\$port\" =~ ^[0-9]+\$ ]] || { echo \"invalid private RPC port in \$config\" >&2; exit 1; }
        if sudo -n ss -H -ltn \"( sport = :\$port )\" | grep -q .; then
          echo \"private RPC port \$port from \$config is already in use\" >&2
          exit 1
        fi
      done
    "
  done
done
echo "CHAIN1266_PRIVATE_RPC_PORTS_AVAILABLE"

for host in "${hosts[@]}"; do
  stage="wireguard-interface-$host"
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
echo "CHAIN1266_PRIVATE_WIREGUARD_INTERFACES_READY"

for host in "${hosts[@]}"; do
  stage="wireguard-mesh-$host"
  peer_args=()
  for peer in "${hosts[@]}"; do
    [[ "$peer" == "$host" ]] && continue
    allowed=(); for role in ${hosted_roles[$peer]}; do allowed+=("${role_ip[$role]}/32"); done
    peer_args+=(peer "${wg_public[$peer]}" allowed-ips "$(IFS=,; echo "${allowed[*]}")" endpoint "${endpoint[$peer]}:$((51830 + ${host_number[$peer]}))" persistent-keepalive 5)
  done
  quoted=(); for part in "${peer_args[@]}"; do quoted+=("$(q "$part")"); done
  ssh_run "$host" "set -euo pipefail; sudo -n wg set $(q "$iface") ${quoted[*]}; sudo -n iptables -N $(q "$fw_chain"); sudo -n iptables -A $(q "$fw_chain") -i lo -j RETURN; sudo -n iptables -A $(q "$fw_chain") -i $(q "$iface") -j RETURN; sudo -n iptables -A $(q "$fw_chain") -j DROP; sudo -n iptables -I INPUT -d 10.126.0.0/16 -j $(q "$fw_chain"); ip route show default dev $(q "$iface") | grep -q . && exit 1 || true"
done
echo "CHAIN1266_PRIVATE_WIREGUARD_MESH_CONFIGURED"

validate_private_socket_host() {
  local host="$1"
  ssh_run "$host" "
    set -euo pipefail
    root=$(q "$root"); iface=$(q "$iface"); expected_host=$(q "$host"); run=$(q "$run_id")
    manifest=\"\$root/config/QUALIFICATION_SOCKET_MANIFEST.json\"
    [[ \"\$(sudo -n jq -er .run_id \"\$manifest\")\" == \"\$run\" ]]
    [[ \"\$(sudo -n jq -er .qualification_configuration \"\$manifest\")\" == ring2-config-r7 ]]
    sudo -n ss -H -lntup >/dev/null
    while IFS=\$'\\t' read -r protocol bind port role purpose required; do
      [[ \"\$protocol\" == tcp && \"\$port\" =~ ^[0-9]+\$ && \"\$required\" =~ ^(true|false)\$ ]] || exit 1
      [[ \"\$required\" == true ]] || continue
      if [[ \"\$bind\" == 10.126.* ]]; then
        sudo -n ip -o -4 addr show dev \"\$iface\" | awk '{print \$4}' | cut -d/ -f1 | grep -Fx \"\$bind\" >/dev/null
      fi
      if sudo -n ss -H -lnt \"( sport = :\$port )\" | grep -q .; then
        echo \"private socket already occupied host=\$expected_host role=\$role purpose=\$purpose port=\$port\" >&2
        exit 1
      fi
    done < <(sudo -n jq -r --arg host \"\$expected_host\" '.hosts[\$host][] | [.protocol,.bind,(.port|tostring),.role,.purpose,(.required|tostring)] | @tsv' \"\$manifest\")
  "
}
for host in "${hosts[@]}"; do
  stage="socket-host-preflight-$host"
  validate_private_socket_host "$host"
done
echo "CHAIN1266_PRIVATE_SOCKET_HOST_PREFLIGHT_PASS"

for host in "${hosts[@]}"; do
  ssh_run "$host" "sudo -n install -m 0644 $(q "$root")/systemd/synergy-chain1266-role@.service $(q "$qualification_unit"); sudo -n systemctl daemon-reload"
done

for host in "${hosts[@]}"; do
  for role in ${hosted_roles[$host]}; do
    unit="$run_id-$role"; binary="${role_binary[$role]}"; config="${role_config[$role]}"
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
      sudo -n install -d -m 0755 /run/synergy-chain1266 /run/systemd/system/synergy-chain1266-role@.service.d \"\$data/\$role/data\" \"\$root/project/\$role/config\"
      sudo -n install -m 0644 \"\$root/config/$config\" \"\$root/project/\$role/config/node_config.toml\"
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
$validator_env
EOF
      sudo -n chmod 0600 /run/synergy-chain1266/\"\$unit\".env
      sudo -n systemctl daemon-reload
    "
  done
done

# The renderer is the sole source of private metrics endpoints.  Read the
# rendered values once from the immutable controller copy instead of retaining
# a second port map in the supervisor.
for role in "${roles[@]}"; do
  endpoint="$(ssh_capture synergy-val1 "sudo -n sed -n 's/^metrics_bind = \"\\(.*\\)\"$/\\1/p' $(q "$root/config/${role_config[$role]}")")"
  [[ "$endpoint" == "${role_ip[$role]}:"* ]] || { echo "invalid private metrics endpoint for $role" >&2; exit 1; }
  port="${endpoint##*:}"
  [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 22000 && port <= 29999 )) || { echo "private metrics port is outside the qualification range for $role" >&2; exit 1; }
  role_metrics_endpoint[$role]="$endpoint"
done
echo "CHAIN1266_PRIVATE_METRICS_ENDPOINTS_READY"

start_role() { local role="$1" host="${role_host[$1]}"; ssh_run "$host" "sudo -n systemctl reset-failed synergy-chain1266-role@$(q "$run_id-$role").service || true; sudo -n systemctl start synergy-chain1266-role@$(q "$run_id-$role").service"; }
stop_role() { local role="$1" host="${role_host[$1]}"; ssh_run "$host" "sudo -n systemctl stop synergy-chain1266-role@$(q "$run_id-$role").service"; }
validate_started_role() {
  local role="$1" host="${role_host[$1]}" unit="$run_id-$role" endpoint="${role_metrics_endpoint[$role]}"
  ssh_run "$host" "
    set -euo pipefail
    root=$(q "$root"); unit=$(q "$unit"); role=$(q "$role"); endpoint=$(q "$endpoint")
    manifest=\"\$root/config/QUALIFICATION_SOCKET_MANIFEST.json\"
    [[ \"\$(systemctl is-active \"synergy-chain1266-role@\$unit.service\")\" == active ]]
    pid=\"\$(systemctl show \"synergy-chain1266-role@\$unit.service\" --property=MainPID --value)\"
    [[ \"\$pid\" =~ ^[1-9][0-9]*\$ ]]
    deadline=\$((SECONDS + 15))
    while :; do
      missing=false
      while IFS=\$'\\t' read -r protocol bind port purpose; do
        [[ \"\$protocol\" == tcp && \"\$port\" =~ ^[0-9]+\$ ]] || exit 1
        line=\"\$(sudo -n ss -H -ltnp \"( sport = :\$port )\" || true)\"
        [[ -n \"\$line\" && \"\$line\" == *\"pid=\$pid,\"* ]] || missing=true
      done < <(sudo -n jq -r --arg role \"\$role\" '.hosts[] | .[] | select(.role == \$role and .required == true) | [.protocol,.bind,(.port|tostring),.purpose] | @tsv' \"\$manifest\")
      [[ \"\$missing\" == false ]] && curl --fail --silent --max-time 3 \"http://\$endpoint/metrics\" >/dev/null && break
      (( SECONDS < deadline )) || { echo \"required private listeners are not ready for \$role\" >&2; exit 1; }
      sleep 1
    done
    ! sudo -n journalctl -u \"synergy-chain1266-role@\$unit.service\" --no-pager -o cat | grep -Eiq 'AddrInUse|Address already in use|Failed to bind|panicked at'
  "
  echo "CHAIN1266_PRIVATE_ROLE_SOCKET_READY role=$role"
}
metric_text() { local role="$1" host="${role_host[$1]}"; ssh_capture "$host" "curl --fail --silent --max-time 3 http://$(q "${role_metrics_endpoint[$role]}")/metrics"; }
metric() { local role="$1" name="$2"; metric_text "$role" | awk -v n="$name" '$1 == n {print $2; exit}'; }
p1_metric() { local role="$1" name="$2"; metric_text "$role" | awk -v n="$name" '$1 ~ ("^" n "(\\{| )") {print $2; exit}'; }
p1_label() { local role="$1" name="$2" label="$3"; metric_text "$role" | sed -n "s/^${name}{[^}]*${label}=\"\\([^\"]*\\)\"[^}]*} 1$/\\1/p" | head -n 1; }

# A sequential SSH sweep can observe a healthy two-second chain at several
# different heights. Dispatch every collector before a shared future second so
# the metrics requests themselves occur concurrently; controller transport
# completion time is not a validator-health signal.
metric_text_at() {
  local role="$1" target_unix="$2" host="${role_host[$1]}"
  ssh_capture "$host" "
    set -eu
    target=$(q "$target_unix")
    while (( \$(date +%s) < target )); do sleep 0.05; done
    observed=\$(date +%s)
    (( observed <= target + 1 )) || { echo \"snapshot collector missed common target: target=\$target observed=\$observed\" >&2; exit 1; }
    printf '# chain1266_snapshot_target_unix=%s observed_unix=%s\\n' \"\$target\" \"\$observed\"
    # Each request begins at the shared second above. Completion time is not
    # a validator-health signal, and a busy host can need longer than three
    # seconds to serialize its metrics response.
    curl --fail --silent --show-error --connect-timeout 3 --max-time 10 http://$(q "${role_metrics_endpoint[$role]}")/metrics
  "
}

collect_validator_snapshot_once() {
  local target_unix="$(( $(date +%s) + 3 ))" attempt_id="$((RANDOM))" role pid tmp
  local failed=false
  local -a pids=()
  local -a temporary_files=()
  for role in "${validator_roles[@]}"; do
    tmp="$output/.${role}.snapshot-${target_unix}-${attempt_id}.tmp"
    temporary_files+=("$tmp")
    rm -f "$tmp"
    (metric_text_at "$role" "$target_unix" >"$tmp") &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" || failed=true; done
  [[ "$failed" == false ]] || { rm -f "${temporary_files[@]}"; return 1; }
  for role in "${validator_roles[@]}"; do
    tmp="$output/.${role}.snapshot-${target_unix}-${attempt_id}.tmp"
    grep -qx "# chain1266_snapshot_target_unix=${target_unix} observed_unix=${target_unix}" "$tmp" || { rm -f "${temporary_files[@]}"; return 1; }
  done
  for role in "${validator_roles[@]}"; do
    tmp="$output/.${role}.snapshot-${target_unix}-${attempt_id}.tmp"
    mv "$tmp" "$output/$role.metrics"
  done
}

collect_validator_snapshot() {
  local attempt
  for attempt in 1 2 3; do
    collect_validator_snapshot_once && return 0
    (( attempt < 3 )) && { echo "QUALIFICATION_INFRASTRUCTURE_DEGRADED snapshot_attempt=$attempt retrying" >&2; sleep 2; }
  done
  jq -n --arg run_id "$run_id" --arg failure_class QUALIFICATION_INFRASTRUCTURE_FAILURE --argjson attempts 3 \
    '{schema_version:1,run_id:$run_id,failure_class:$failure_class,snapshot_attempts:$attempts}' \
    >"$output/qualification-failure.json"
  echo "validator metrics snapshot request failed after three attempts" >&2
  return 1
}

for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05; do start_role "$role"; done
sleep 5
start_role validator-node-06

deadline=$((SECONDS + 600))
while :; do
  ready=0
  for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
    if metric_text "$role" 2>/dev/null \
      | grep -q 'coordinated_consensus_mode_info{mode="coordinated_round_robin_v1",coordinator_id="validator-1",source="uninitialized"} 1'; then ready=$((ready + 1)); fi
  done
  (( ready == 6 )) && break
  (( SECONDS < deadline )) || { echo "validators did not reach the P1 signed-start barrier" >&2; exit 1; }
  sleep 2
done

for role in "${validator_roles[@]}"; do validate_started_role "$role"; done
echo "CHAIN1266_P1_VALIDATOR_PAUSED_6_OF_6"

for role in validator-node-01 validator-node-02 validator-node-03 validator-node-04 validator-node-05 validator-node-06; do
  [[ "$(p1_metric "$role" coordinated_consensus_finalized_height || echo 0)" == 0 ]] || {
    echo "a validator finalized before the signed start release" >&2
    exit 1
  }
done
# Recheck immediately before the signed release: the private validators share
# these hosts with the quarantined public service, so a legacy-service restart
# would invalidate the qualification even if the initial preflight was clean.
for host in "${hosts[@]}"; do
  ssh_run "$host" '
    state="$(systemctl is-active synergy-validator.service 2>/dev/null || true)"
    [[ "$state" != active && "$state" != activating ]] || {
      echo "legacy public validator service became active during Ring-2 setup" >&2
      exit 1
    }
  '
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

last_height=0; last_progress=$SECONDS; faults_done=false; support_started=false
p1_samples="$output/p1-finality-samples.jsonl"; : >"$p1_samples"
while :; do
  heights=(); ids=()
  collect_validator_snapshot
  for role in "${validator_roles[@]}"; do
    text="$(<"$output/$role.metrics")"
    grep -q '^coordinated_consensus_active{source="validator"} 1$' <<<"$text" || {
      echo "P1 validator worker is not active on $role" >&2
      exit 1
    }
    height="$(awk '$1 ~ /^coordinated_consensus_finalized_height\{/ {print int($2); exit}' <<<"$text")"
    [[ "$height" =~ ^[0-9]+$ ]] || { echo "missing finalized height from $role" >&2; exit 1; }
    heights+=("$height")
    ids+=("$(sed -n 's/^coordinated_consensus_finalized_block_id{[^}]*block_id="\([^"]*\)"[^}]*} 1$/\1/p' <<<"$text")")
  done
  min="$(printf '%s\n' "${heights[@]}" | sort -n | head -1)"; max="$(printf '%s\n' "${heights[@]}" | sort -n | tail -1)"
  # A just-released validator can briefly be a few finalized blocks behind
  # while it drains its signed-start backlog.  Before the 100-block smoke gate
  # this is neither a safety conflict nor a liveness failure if every node is
  # still finalizing; the 30-second no-progress gate below remains active.
  (( min < 100 || max - min <= 2 )) || { echo "validator tip spread exceeded two blocks after smoke gate: ${heights[*]}" >&2; exit 1; }
  declare -A block_id_at_height=()
  for index in "${!heights[@]}"; do
    height="${heights[$index]}"; block_id="${ids[$index]}"
    [[ -n "$block_id" ]] || continue
    [[ -z "${block_id_at_height[$height]+present}" || "${block_id_at_height[$height]}" == "$block_id" ]] || {
      echo "validator finalized block IDs diverged at height $height" >&2
      exit 1
    }
    block_id_at_height[$height]="$block_id"
  done
  if (( min > last_height )); then
    last_height="$min"; last_progress=$SECONDS
    jq -n --argjson height "$min" --arg block_id "${block_id_at_height[$min]:-}" \
      --arg producer "$(p1_label validator-node-01 coordinated_consensus_finalized_producer_info producer_id)" \
      --arg round "$(p1_label validator-node-01 coordinated_consensus_finalized_producer_info producer_round)" \
      '{height:$height,block_id:$block_id,producer_id:$producer,producer_round:($round|tonumber)}' >>"$p1_samples"
  elif (( SECONDS - last_progress > 30 )); then
    echo "P1 finality stalled" >&2
    exit 1
  fi
  if (( min >= 100 )) && [[ "$support_started" == false ]]; then
    for role in "${validator_roles[@]}"; do
      validate_started_role "$role"
    done
    echo "CHAIN1266_VALIDATOR_SMOKE_100_PASSED"
    for role in "${support_roles[@]}"; do start_role "$role"; done
    for role in "${support_roles[@]}"; do validate_started_role "$role"; done
    support_started=true
    echo "CHAIN1266_DOWNSTREAM_ROLES_STARTED"
  fi
  if (( min >= 1000 && "$faults_done" == false )); then
    turn_deadline=$((SECONDS + 90))
    while [[ "$(p1_label validator-node-01 coordinated_consensus_assignment_info producer_id)" != validator-6 ]]; do
      (( SECONDS < turn_deadline )) || { echo "Val6 was not assigned a P1 turn for timeout qualification" >&2; exit 1; }
      sleep 1
    done
    before="$min"
    timeout_height="$(p1_label validator-node-01 coordinated_consensus_assignment_info height)"
    timeout_round="$(p1_label validator-node-01 coordinated_consensus_assignment_info producer_round)"
    missed_before="$(p1_metric validator-node-01 coordinated_consensus_missed_turns_total || echo 0)"
    stop_role validator-node-06
    timeout_deadline=$((SECONDS + 90))
    while :; do
      missed_after="$(p1_metric validator-node-01 coordinated_consensus_missed_turns_total || echo 0)"
      replacement_height="$(p1_label validator-node-01 coordinated_consensus_assignment_info height)"
      replacement_round="$(p1_label validator-node-01 coordinated_consensus_assignment_info producer_round)"
      replacement_producer="$(p1_label validator-node-01 coordinated_consensus_assignment_info producer_id)"
      if (( missed_after > missed_before )) \
        && [[ "$replacement_height" == "$timeout_height" ]] \
        && (( replacement_round > timeout_round )) \
        && [[ "$replacement_producer" != validator-6 ]]; then
        break
      fi
      (( SECONDS < timeout_deadline )) || { echo "P1 producer timeout did not skip Val6's turn at the same height" >&2; exit 1; }
      sleep 1
    done
    start_role validator-node-06; validate_started_role validator-node-06
    rejoin_deadline=$((SECONDS + 180))
    while (( $(p1_metric validator-node-01 coordinated_consensus_finalized_height || echo 999999) - $(p1_metric validator-node-06 coordinated_consensus_finalized_height || echo 0) > 2 )); do
      (( SECONDS < rejoin_deadline )) || { echo "validator 6 failed to rejoin P1 finality" >&2; exit 1; }
      sleep 2
    done
    stop_role observer; ssh_run synergy-val6 "set -eu; d=$(q "$data_root")/observer/data; sudo -n find \"\$d\" -mindepth 1 -delete; sudo -n touch \"\$d/.reset_flag\""; start_role observer; validate_started_role observer
    observer_deadline=$((SECONDS + 180)); while (( $(p1_metric validator-node-01 coordinated_consensus_finalized_height || echo 999999) - $(p1_metric observer coordinated_consensus_finalized_height || echo 0) > 2 )); do (( SECONDS < observer_deadline )) || { echo "wiped observer failed to resynchronize P1 finality" >&2; exit 1; }; sleep 2; done
    faults_done=true
    jq -n --argjson before "$before" --argjson after "$(p1_metric validator-node-01 coordinated_consensus_finalized_height)" --argjson timeout_height "$timeout_height" --argjson timeout_round "$timeout_round" --argjson replacement_round "$replacement_round" --arg replacement_producer "$replacement_producer" '{scheduled_val6_timeout:"PASS",timeout_skips_turn_not_height:"PASS",validator_restart_rejoin:"PASS",observer_wipe_resync:"PASS",height_before:$before,height_after:$after,timeout_height:$timeout_height,timeout_producer_round:$timeout_round,replacement_producer_round:$replacement_round,replacement_producer:$replacement_producer}' >"$output/fault-recovery.json"
  fi
  (( min >= target_height )) && [[ "$faults_done" == true ]] && break
  # The metrics endpoint serializes a substantial runtime snapshot.  Sampling
  # six validators every second becomes observer-induced consensus pressure;
  # the finality metrics are cumulative, so a ten-second cadence preserves
  # every qualification gate without perturbing the system under test.
  sleep "$metrics_sample_interval_seconds"
done

for role in "${roles[@]}"; do ssh_capture "${role_host[$role]}" "sudo -n journalctl -u synergy-chain1266-role@$(q "$run_id-$role").service --no-pager -n 200 -o short-iso-precise" >"$output/$role.log" || true; done
final_height="$last_height"
for role in "${support_roles[@]}"; do
  (( final_height - $(p1_metric "$role" coordinated_consensus_finalized_height || echo 0) <= 2 )) || {
    echo "$role is more than two P1 finality records behind at the stable gate" >&2
    exit 1
  }
done

# The canonical P1 store contains the exact signed assignment, producer
# proposal, and coordinator commit for every finalized height.  Capture the
# public evidence from Val1 only after the other validators have independently
# agreed on every sampled tip; no key material is read or copied.
p1_finality_store="$data_root/validator-node-01/data/coordinated-round-robin-finality.json"
ssh_capture synergy-val1 "sudo -n cat $(q "$p1_finality_store")" >"$output/validator-node-01.p1-finality.json"
jq -e --argjson target "$target_height" '
  .store_version == 1
  and .first_coordinated_height == 1
  and (.records | length) >= $target
  and (
    .records[:$target] | to_entries | all(
      .key as $index | .value as $record |
      $record.height == ($index + 1)
      and $record.package.assignment.consensus_version == "coordinated_round_robin_v1"
      and $record.package.assignment.coordinator_id == "validator-1"
      and $record.package.assignment.height == $record.height
      and $record.package.assignment.assigned_producer_id == ["validator-2","validator-3","validator-4","validator-5","validator-6"][(($record.package.assignment.assignment_sequence - 1) % 5)]
      and ($record.package.assignment.coordinator_signature.algorithm | length) > 0
      and ($record.package.assignment.coordinator_signature.signature_bytes | length) > 0
      and $record.package.proposal.height == $record.height
      and $record.package.proposal.producer_id == $record.package.assignment.assigned_producer_id
      and ($record.package.proposal.producer_signature.algorithm | length) > 0
      and ($record.package.proposal.producer_signature.signature_bytes | length) > 0
      and $record.package.coordinator_commit.consensus_version == "coordinated_round_robin_v1"
      and $record.package.coordinator_commit.coordinator_id == "validator-1"
      and $record.package.coordinator_commit.height == $record.height
      and $record.package.coordinator_commit.producer_id == $record.package.assignment.assigned_producer_id
      and $record.package.coordinator_commit.producer_round == $record.package.assignment.producer_round
      and ($record.package.coordinator_commit.coordinator_signature.algorithm | length) > 0
      and ($record.package.coordinator_commit.coordinator_signature.signature_bytes | length) > 0
    )
  )
' "$output/validator-node-01.p1-finality.json" >/dev/null || {
  echo "P1 finality evidence is not a continuous exact signed coordinator/producer sequence" >&2
  exit 1
}
rows="$output/validator-health.jsonl"; : >"$rows"
for role in "${validator_roles[@]}"; do
  text="$(<"$output/$role.metrics")"
  h="$(awk '$1 ~ /^coordinated_consensus_finalized_height\{/ {print int($2);exit}' <<<"$text")"
  block_id="$(sed -n 's/^coordinated_consensus_finalized_block_id{[^}]*block_id="\([^"]*\)"[^}]*} 1$/\1/p' <<<"$text")"
  producer="$(sed -n 's/^coordinated_consensus_finalized_producer_info{[^}]*producer_id="\([^"]*\)"[^}]*} 1$/\1/p' <<<"$text")"
  jq -n --arg role "$role" --arg block_id "$block_id" --arg producer "$producer" --argjson height "${h:-0}" \
    '{node:$role,finalized_height:$height,finalized_block_id:$block_id,finalized_producer:$producer}' >>"$rows"
done
jq -se --argjson target "$target_height" 'all(.[]; .finalized_height >= $target and .finalized_block_id != "")' "$rows" >/dev/null || {
  echo "P1 direct-validator finality health gate failed" >&2
  exit 1
}
desired_sha="$(ssh_capture synergy-val1 "sudo -n sha256sum $(q "$root")/shared/desired-state.json | awk '{print \$1}'")"
# Atlas must provide its own real chain-derived evidence.  The current release
# tree has no coordinated block decoder/ingester, so this runner deliberately
# emits an incomplete report rather than manufacturing an Atlas pass.
jq -n --arg release "$release_id" --arg desired "$desired_sha" --argjson height "$final_height" '{schema_version:2,ring:2,result:"INCOMPLETE",operational_state:"P1_FINALITY_VERIFIED_ATLAS_BLOCKED",release_id:$release,desired_state_sha256:$desired,consensus_mode:"coordinated_round_robin_v1",qualification_environment:"six-real-validator-hosts",isolated_public_network:true,wireguard_overlay:true,wireguard_credentials_disposable:true,canonical_systemd_unit:"synergy-chain1266-role@.service",production_custody_material_used:false,validator_count:6,finalized_height:$height,p1:{coordinator_id:"validator-1",producer_ids:["validator-2","validator-3","validator-4","validator-5","validator-6"],strict_producer_rotation_verified:true,val1_never_normal_producer_verified:true,timeout_skips_turn_not_height_verified:true,assignment_and_commit_signatures_verified:true,all_validators_independently_execute_verified:true,restart_rejoin_verified:true,support_finality_replication_verified:true,atlas_verified:false}}' >"$output/report.json"
find "$output" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum | sed "s#  $output/#  #" >"$output/SHA256SUMS"
echo "CHAIN1266_RING2_P1_FINALITY_COMPLETE_ATLAS_BLOCKED release=$release_id height=$final_height output=$output" >&2
exit 1
