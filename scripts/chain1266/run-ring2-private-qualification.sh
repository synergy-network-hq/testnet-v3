#!/usr/bin/env bash
set -euo pipefail

# Ring 2 runs the immutable Linux artifacts in twelve isolated network
# namespaces: six validators, three relayers, RPC, Explorer, and a read-only
# observer.  The bridge has no host address and no default route, so no process
# can reach or be reached by public Chain 1266.

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release="${CHAIN1266_RELEASE_DIR:?CHAIN1266_RELEASE_DIR is required}"
qualification="${CHAIN1266_QUALIFICATION_ROOT:?CHAIN1266_QUALIFICATION_ROOT is required}"
target_height="${CHAIN1266_RING2_TARGET_HEIGHT:-10000}"
startup_ceiling="${CHAIN1266_RING2_STARTUP_CEILING_SECONDS:-600}"
progress_ceiling="${CHAIN1266_RING2_PROGRESS_CEILING_SECONDS:-30}"
atlas_database_url="${CHAIN1266_RING2_ATLAS_DATABASE_URL:?CHAIN1266_RING2_ATLAS_DATABASE_URL is required}"

case "$qualification" in
  /tmp/*|/home/runner/work/_temp/*) ;;
  *) echo "Ring-2 qualification root must be an ephemeral runner path" >&2; exit 1 ;;
esac
[[ "$target_height" =~ ^[0-9]+$ ]] && ((target_height >= 10000)) || {
  echo "Ring-2 target must be at least 10,000 finalized blocks" >&2
  exit 1
}
for command in ip tc wg jq curl python3 psql sha256sum systemctl journalctl; do
  command -v "$command" >/dev/null || {
    echo "Ring-2 requires $command" >&2
    exit 1
  }
done
for binary in \
  synergy-validator-node \
  synergy-relayer-node \
  synergy-observer-light-node \
  synergy-rpc-gateway-node \
  synergy-indexer-and-explorer-node \
  build-chain1266-desired-state \
  build-chain1266-private-ring-material \
  sign-chain1266-desired-state \
  sign-chain1266-start-command
do
  [[ -x "$release/bin/$binary" ]] || {
    echo "Ring-2 release omits executable $binary" >&2
    exit 1
  }
done

network_prefix="c1266q${GITHUB_RUN_ID:-$$}"
network_prefix="${network_prefix:0:10}"
bridge="${network_prefix}br"
private_root="$qualification/private"
evidence="$qualification/evidence"
configs="$qualification/config"
projects="$qualification/nodes"
pids="$qualification/pids"
logs="$evidence/logs"
qualification_state_root="/var/lib/synergy/chain1266-qualification/$network_prefix"
mkdir -p "$private_root" "$evidence" "$projects" "$pids" "$logs"

nodes=(
  validator-node-01 validator-node-02 validator-node-03
  validator-node-04 validator-node-05 validator-node-06
  relay1 relay2 relay3 rpc-gateway explorer-indexer observer
)
declare -A node_ip=(
  [validator-node-01]=10.70.10.1 [validator-node-02]=10.70.10.2
  [validator-node-03]=10.70.10.3 [validator-node-04]=10.70.10.4
  [validator-node-05]=10.70.10.5 [validator-node-06]=10.70.10.6
  [relay1]=10.70.20.1 [relay2]=10.70.20.2 [relay3]=10.70.20.3
  [rpc-gateway]=10.70.30.1 [explorer-indexer]=10.70.30.2
  [observer]=10.70.30.3
)
declare -A node_ns=()
declare -A process_pid=()
declare -A underlay_ip=()
declare -A wireguard_port=()
declare -A wireguard_public_key=()
role_unit="synergy-chain1266-role@"
installed_unit="/etc/systemd/system/synergy-chain1266-role@.service"
installed_launcher="/usr/local/libexec/synergy/chain1266-role-service"
service_environment_root="/run/synergy-chain1266"

cleanup() {
  set +e
  for node in "${nodes[@]}"; do
    sudo systemctl stop "${role_unit}${node}.service" >/dev/null 2>&1
  done
  sudo rm -f "$installed_unit" "$installed_launcher"
  sudo rm -rf "$service_environment_root"
  if [[ "$qualification_state_root" == /var/lib/synergy/chain1266-qualification/c1266q* ]]; then
    sudo rm -rf -- "$qualification_state_root"
  fi
  sudo systemctl daemon-reload >/dev/null 2>&1
  for node in "${nodes[@]}"; do
    ns="${node_ns[$node]:-}"
    [[ -n "$ns" ]] && sudo ip netns delete "$ns" >/dev/null 2>&1
  done
  sudo ip link delete "$bridge" >/dev/null 2>&1
  # Disposable qualification private keys must not survive the job.
  if [[ -d "$private_root" && "$private_root" == "$qualification/private" ]]; then
    find "$private_root" -type f -exec shred -u {} + 2>/dev/null
    find "$private_root" -depth -type d -empty -delete 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

sudo ip link add "$bridge" type bridge
sudo ip link set "$bridge" up
for index in "${!nodes[@]}"; do
  node="${nodes[$index]}"
  ns="${network_prefix}n${index}"
  host_veth="${network_prefix}h${index}"
  peer_veth="${network_prefix}p${index}"
  node_ns[$node]="$ns"
  underlay_ip[$node]="172.31.126.$((index + 10))"
  wireguard_port[$node]="$((51820 + index))"
  sudo ip netns add "$ns"
  sudo ip link add "$host_veth" type veth peer name "$peer_veth"
  sudo ip link set "$host_veth" master "$bridge"
  sudo ip link set "$host_veth" up
  sudo ip link set "$peer_veth" netns "$ns"
  sudo ip -n "$ns" link set "$peer_veth" name eth0
  sudo ip -n "$ns" addr add "${underlay_ip[$node]}/24" dev eth0
  sudo ip -n "$ns" link set lo up
  sudo ip -n "$ns" link set eth0 up
  if sudo ip -n "$ns" route show default | grep -q .; then
    echo "$node unexpectedly has a default route" >&2
    exit 1
  fi
done

# Build an isolated full-mesh WireGuard transport using disposable credentials.
# The Ethernet bridge is underlay-only; every Chain 1266 role binds and dials
# through the same 10.70.0.0/16 overlay used by the public role configs.
wireguard_root="$private_root/wireguard"
mkdir -p "$wireguard_root"
chmod 0700 "$wireguard_root"
for node in "${nodes[@]}"; do
  private_key="$wireguard_root/$node.private"
  public_key="$wireguard_root/$node.public"
  umask 077
  wg genkey >"$private_key"
  wg pubkey <"$private_key" >"$public_key"
  wireguard_public_key[$node]="$(<"$public_key")"
  sudo ip -n "${node_ns[$node]}" link add sy-vpn type wireguard
  sudo ip -n "${node_ns[$node]}" addr add "${node_ip[$node]}/16" dev sy-vpn
  sudo ip netns exec "${node_ns[$node]}" \
    wg set sy-vpn \
      private-key "$private_key" \
      listen-port "${wireguard_port[$node]}"
done
for node in "${nodes[@]}"; do
  peer_args=()
  for peer in "${nodes[@]}"; do
    [[ "$peer" == "$node" ]] && continue
    peer_args+=(
      peer "${wireguard_public_key[$peer]}"
      allowed-ips "${node_ip[$peer]}/32"
      endpoint "${underlay_ip[$peer]}:${wireguard_port[$peer]}"
      persistent-keepalive 5
    )
  done
  sudo ip netns exec "${node_ns[$node]}" wg set sy-vpn "${peer_args[@]}"
  sudo ip -n "${node_ns[$node]}" link set sy-vpn up
  peer_count="$(
    sudo ip netns exec "${node_ns[$node]}" wg show sy-vpn peers | sed '/^$/d' | wc -l | tr -d ' '
  )"
  [[ "$peer_count" == 11 ]] || {
    echo "$node WireGuard peer count is $peer_count, expected 11" >&2
    exit 1
  }
done

sudo install -d -m 0755 "$(dirname "$installed_launcher")" "$service_environment_root"
sudo install -m 0755 \
  "$release/systemd/chain1266-role-service" \
  "$installed_launcher"
sudo install -m 0644 \
  "$release/systemd/synergy-chain1266-role@.service" \
  "$installed_unit"
sudo systemctl daemon-reload

"$release/bin/build-chain1266-private-ring-material" \
  --source-genesis "$release/genesis.json" \
  --output-genesis "$qualification/genesis.json" \
  --key-root "$private_root"
python3 "$repo/scripts/chain1266/prepare-ring2-configs.py" \
  --release-dir "$release" \
  --genesis "$qualification/genesis.json" \
  --output "$configs"

source_desired="$release/desired-state.json"
release_id="$(jq -er .release_id "$source_desired")"
release_tag="$(jq -er .release_tag "$source_desired")"
testnet_revision="$(jq -er .source.testnet_v3_revision "$source_desired")"
synq_revision="$(jq -er .source.synq_revision "$source_desired")"
aegis_revision="$(jq -er .source.aegis_revision "$source_desired")"
desired_args=(
  --release-id "$release_id"
  --release-tag "$release_tag"
  --testnet-revision "$testnet_revision"
  --synq-revision "$synq_revision"
  --aegis-revision "$aegis_revision"
  --genesis "$qualification/genesis.json"
  --start-authority "$private_root/start-authority.public.json"
  --artifact "validator_node=$release/bin/synergy-validator-node"
  --artifact "relayer_node=$release/bin/synergy-relayer-node"
  --artifact "observer_light_node=$release/bin/synergy-observer-light-node"
  --artifact "rpc_gateway_node=$release/bin/synergy-rpc-gateway-node"
  --artifact "indexer_and_explorer_node=$release/bin/synergy-indexer-and-explorer-node"
)
for number in 1 2 3 4 5 6; do
  desired_args+=(--configuration "validator-node-0${number}=$configs/validators/val${number}.toml")
done
for number in 1 2 3; do
  desired_args+=(--configuration "relay${number}=$configs/relayers/relay${number}.toml")
done
desired_args+=(--configuration "rpc-gateway=$configs/rpc-gateway/rpc-gateway.toml")
desired_args+=(--configuration "explorer-indexer=$configs/explorer-indexer/explorer-indexer.toml")
desired_args+=(--configuration "observer=$configs/observer/observer.toml")
"$release/bin/build-chain1266-desired-state" "${desired_args[@]}" \
  --output "$qualification/desired-state.json"
desired_sha="$(sha256sum "$qualification/desired-state.json" | awk '{print $1}')"
"$release/bin/sign-chain1266-desired-state" \
  --desired-state "$qualification/desired-state.json" \
  --private-key "$private_root/start-authority.private.key" \
  --output "$qualification/desired-state.signature.json"

config_for() {
  case "$1" in
    validator-node-0?) printf '%s/validators/val%s.toml' "$configs" "${1##*0}" ;;
    relay?) printf '%s/relayers/%s.toml' "$configs" "$1" ;;
    rpc-gateway) printf '%s/rpc-gateway/rpc-gateway.toml' "$configs" ;;
    explorer-indexer) printf '%s/explorer-indexer/explorer-indexer.toml' "$configs" ;;
    observer) printf '%s/observer/observer.toml' "$configs" ;;
  esac
}

binary_for() {
  case "$1" in
    validator-*) printf '%s/bin/synergy-validator-node' "$release" ;;
    relay*) printf '%s/bin/synergy-relayer-node' "$release" ;;
    rpc-gateway) printf '%s/bin/synergy-rpc-gateway-node' "$release" ;;
    explorer-indexer) printf '%s/bin/synergy-indexer-and-explorer-node' "$release" ;;
    observer) printf '%s/bin/synergy-observer-light-node' "$release" ;;
  esac
}

start_node() {
  local node="$1"
  local project="$projects/$node"
  local config
  local source_config
  local binary
  local environment_file="$service_environment_root/$node.env"
  source_config="$(config_for "$node")"
  config="$project/config/node_config.toml"
  binary="$(binary_for "$node")"
  state_root="$qualification_state_root/$node/data"
  mkdir -p "$state_root" "$project/config"
  cp "$source_config" "$config"
  cp "$qualification/genesis.json" "$project/config/genesis.json"
  if [[ ! -f "$project/.ring2-initialized" ]]; then
    : >"$state_root/.reset_flag"
    : >"$project/.ring2-initialized"
  fi
  if [[ "$node" == validator-* ]]; then
    number="${node##*0}"
    validator_id="validator-$number"
  fi
  {
    printf 'CHAIN1266_ROLE_BINARY=%s\n' "$binary"
    printf 'CHAIN1266_ROLE_CONFIG=%s\n' "$config"
    printf 'CHAIN1266_NETWORK_NAMESPACE=%s\n' "${node_ns[$node]}"
    printf 'SYNERGY_PROJECT_ROOT=%s\n' "$project"
    printf 'SYNERGY_DATA_PATH=%s\n' "$state_root"
    printf 'SYNERGY_GENESIS_FILE=%s\n' "$qualification/genesis.json"
    printf 'SYNERGY_DESIRED_STATE_MANIFEST=%s\n' "$qualification/desired-state.json"
    printf 'SYNERGY_DESIRED_STATE_MANIFEST_SHA256=%s\n' "$desired_sha"
    printf 'SYNERGY_DESIRED_STATE_SIGNATURE=%s\n' \
      "$qualification/desired-state.signature.json"
    printf 'SYNERGY_CHAIN1266_QUALIFICATION_MODE=1\n'
    printf 'SYNERGY_ENABLE_METRICS=true\n'
    if [[ "$node" == validator-* ]]; then
      printf 'SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=%s\n' \
        "$private_root/$validator_id/mldsa65-consensus.private.key"
      printf 'CONSENSUS_START_PAUSED=1\n'
      printf 'SYNERGY_CONSENSUS_START_RELEASE_FILE=%s\n' \
        "$qualification/start-consensus.json"
    fi
  } | sudo tee "$environment_file" >/dev/null
  sudo chmod 0600 "$environment_file"
  sudo systemctl reset-failed "${role_unit}${node}.service" >/dev/null 2>&1 || true
  sudo systemctl start "${role_unit}${node}.service"
  process_pid[$node]="$(
    sudo systemctl show "${role_unit}${node}.service" --property=MainPID --value
  )"
  printf '%s\n' "${process_pid[$node]}" >"$pids/$node.pid"
}

stop_node() {
  sudo systemctl stop "${role_unit}$1.service"
}

node_is_active() {
  sudo systemctl is-active --quiet "${role_unit}$1.service"
}

node_log_tail() {
  sudo journalctl -u "${role_unit}$1.service" --no-pager -n "${2:-100}"
}

metric() {
  local node="$1"
  local name="$2"
  sudo ip netns exec "${node_ns[$node]}" \
    curl --fail --silent --max-time 2 http://127.0.0.1:6030/metrics \
    | awk -v metric="$name" '$1 == metric {print $2; exit}'
}

metrics_text() {
  sudo ip netns exec "${node_ns[$1]}" \
    curl --fail --silent --max-time 2 http://127.0.0.1:6030/metrics
}

write_direct_health_gate() {
  local output="$1"
  local required_height="$2"
  local rows="$qualification/direct-health-rows.jsonl"
  : >"$rows"
  for node in \
    validator-node-01 validator-node-02 validator-node-03 \
    validator-node-04 validator-node-05 validator-node-06
  do
    text="$(metrics_text "$node")"
    height="$(awk '$1 == "consensus_finalized_height" {print int($2); exit}' <<<"$text")"
    samples_count="$(
      awk '$1 == "consensus_finality_interval_sample_count" {print int($2); exit}' <<<"$text"
    )"
    mean="$(
      awk '$1 == "consensus_finality_interval_mean_seconds" {print $2; exit}' <<<"$text"
    )"
    median="$(
      awk '$1 == "consensus_finality_interval_median_seconds" {print $2; exit}' <<<"$text"
    )"
    p95="$(
      awk '$1 == "consensus_finality_interval_p95_seconds" {print $2; exit}' <<<"$text"
    )"
    ratio="$(awk '$1 == "consensus_round_zero_ratio" {print $2; exit}' <<<"$text")"
    restarts="$(awk '$1 == "consensus_restart_count" {print int($2); exit}' <<<"$text")"
    jq -n \
      --arg node "$node" \
      --argjson height "${height:-0}" \
      --argjson sample_count "${samples_count:-0}" \
      --argjson mean "${mean:-999}" \
      --argjson median "${median:-999}" \
      --argjson p95 "${p95:-999}" \
      --argjson round_zero_ratio "${ratio:-0}" \
      --argjson restart_count "${restarts:-0}" \
      '{
        node:$node,
        finalized_height:$height,
        sample_count:$sample_count,
        mean_finality_interval_seconds:$mean,
        median_finality_interval_seconds:$median,
        p95_finality_interval_seconds:$p95,
        round_zero_ratio:$round_zero_ratio,
        restart_count:$restart_count
      }' >>"$rows"
  done
  jq -s \
    --argjson required_height "$required_height" \
    '{
      source:"direct_typed_consensus_metrics",
      required_height:$required_height,
      validators:.
    }' "$rows" >"$output"
  jq -e '
    .required_height as $height
    | ([($height - 1), 10000] | min) as $required_samples
    | (.validators | length) == 6
      and all(.validators[];
        .finalized_height >= $height
        and .sample_count >= $required_samples
        and .mean_finality_interval_seconds <= 2.0
        and .median_finality_interval_seconds <= 1.5
        and .p95_finality_interval_seconds <= 3.0
        and .round_zero_ratio >= 0.99
      )
  ' "$output" >/dev/null
}

for node in relay1 relay2 relay3 rpc-gateway explorer-indexer observer; do
  start_node "$node"
done
for node in \
  validator-node-01 validator-node-02 validator-node-03 \
  validator-node-04 validator-node-05
do
  start_node "$node"
done
delayed_validator_start_seconds=5
sleep "$delayed_validator_start_seconds"
start_node validator-node-06

startup_deadline=$((SECONDS + startup_ceiling))
while :; do
  ready=0
  for node in \
    validator-node-01 validator-node-02 validator-node-03 \
    validator-node-04 validator-node-05 validator-node-06
  do
    if metrics_text "$node" 2>/dev/null \
      | grep -q 'consensus_startup_phase_info{phase="PAUSED_READY"} 1'; then
      ready=$((ready + 1))
    elif ! node_is_active "$node"; then
      echo "$node exited before PAUSED_READY" >&2
      node_log_tail "$node" 100 >&2
      exit 1
    fi
  done
  ((ready == 6)) && break
  if ((SECONDS >= startup_deadline)); then
    echo "Ring-2 validators did not reach PAUSED_READY before the state-aware ceiling" >&2
    exit 1
  fi
  sleep 1
done
prestart_height_max=0
for node in \
  validator-node-01 validator-node-02 validator-node-03 \
  validator-node-04 validator-node-05 validator-node-06
do
  height="$(metric "$node" consensus_finalized_height || echo 0)"
  ((height <= prestart_height_max)) || prestart_height_max="$height"
done
((prestart_height_max == 0)) || {
  echo "A validator finalized before the signed readiness-barrier release" >&2
  exit 1
}
jq -n \
  --argjson delayed_start_seconds "$delayed_validator_start_seconds" \
  '{
    result:"PASS",
    delayed_validator:"validator-node-06",
    delayed_start_seconds:$delayed_start_seconds,
    all_six_paused_ready:true,
    finalized_height_before_signed_start:0
  }' >"$evidence/delayed-validator-startup.json"

wireguard_deadline=$((SECONDS + 30))
while :; do
  overlay_ready=0
  for node in "${nodes[@]}"; do
    handshakes="$(
      sudo ip netns exec "${node_ns[$node]}" wg show sy-vpn dump \
        | awk 'NR > 1 && $5 > 0 {count++} END {print count + 0}'
    )"
    ((handshakes == 11)) && overlay_ready=$((overlay_ready + 1))
  done
  ((overlay_ready == ${#nodes[@]})) && break
  ((SECONDS < wireguard_deadline)) || {
    echo "Ring-2 disposable WireGuard mesh did not complete all handshakes" >&2
    exit 1
  }
  sleep 1
done

activate_unix_ms="$(( $(date +%s) * 1000 + 5000 ))"
"$release/bin/sign-chain1266-start-command" \
  --desired-state "$qualification/desired-state.json" \
  --private-key "$private_root/start-authority.private.key" \
  --activate-unix-ms "$activate_unix_ms" \
  --output "$qualification/start-consensus.json"

cat >"$qualification/collect-health.py" <<'PY'
import json
import math
import pathlib
import statistics
import sys

samples = []
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.strip():
        samples.append(json.loads(line))
intervals = [row["interval"] for row in samples if row["height"] > 1 and row["interval"] > 0]
if not intervals:
    raise SystemExit("no finality interval samples")
ordered = sorted(intervals)
def percentile(p):
    index = max(0, math.ceil((p / 100) * len(ordered)) - 1)
    return ordered[index]
report = {
    "sample_count": len(intervals),
    "mean_finality_interval_seconds": statistics.fmean(intervals),
    "median_finality_interval_seconds": statistics.median(intervals),
    "p95_finality_interval_seconds": percentile(95),
    "round_zero_ratio": samples[-1]["round_zero_ratio"],
    "finalized_height": samples[-1]["height"],
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

samples="$evidence/finality-samples.jsonl"
: >"$samples"
last_height=0
last_progress=$SECONDS
operational_recorded=false
healthy_recorded=false
faults_complete=false
while :; do
  heights=()
  block_ids=()
  rounds=()
  for node in \
    validator-node-01 validator-node-02 validator-node-03 \
    validator-node-04 validator-node-05 validator-node-06
  do
    text="$(metrics_text "$node")"
    heights+=("$(awk '$1 == "consensus_finalized_height" {print int($2); exit}' <<<"$text")")
    block_ids+=("$(sed -n 's/^consensus_finalized_block_id{block_id="\([^"]*\)"} 1$/\1/p' <<<"$text")")
    rounds+=("$(awk '$1 == "consensus_current_round" {print int($2); exit}' <<<"$text")")
  done
  min_height="$(printf '%s\n' "${heights[@]}" | sort -n | head -1)"
  max_height="$(printf '%s\n' "${heights[@]}" | sort -n | tail -1)"
  if ((min_height > last_height)); then
    val1="$(metrics_text validator-node-01)"
    interval="$(awk '$1 == "consensus_finality_interval_seconds" {print $2; exit}' <<<"$val1")"
    ratio="$(awk '$1 == "consensus_round_zero_ratio" {print $2; exit}' <<<"$val1")"
    printf '{"height":%s,"interval":%s,"round_zero_ratio":%s}\n' \
      "$min_height" "${interval:-0}" "${ratio:-0}" >>"$samples"
    last_height="$min_height"
    last_progress=$SECONDS
  elif ((SECONDS - last_progress > progress_ceiling)); then
    echo "Ring-2 made no finality progress for ${progress_ceiling}s" >&2
    exit 1
  fi
  if ((max_height - min_height > 2)); then
    echo "Ring-2 validator tip spread exceeded two blocks: ${heights[*]}" >&2
    exit 1
  fi
  if ((min_height >= 100)) && [[ "$operational_recorded" == false ]]; then
    jq -n \
      --arg state OPERATIONAL \
      --argjson height "$min_height" \
      '{state:$state,consecutive_finalized_blocks:$height}' \
      >"$evidence/gate-100-operational.json"
    operational_recorded=true
    # Atlas' endpoint contract is exercised only after typed consensus is active.
    cat >"$qualification/atlas-network.json" <<JSON
{"schema_version":1,"chain_id":1266,"chain_incarnation":4,"network_id":"synergy-testnet-v3","genesis_hash":"$(jq -er .integrity.genesis_hash "$qualification/genesis.json")","network_magic":"c1266004","finalization":{"status":"final","approval_sha256":"$(printf qualification | sha256sum | awk '{print $1}')","release_sha256":"$desired_sha"},"endpoints":{"rpc":"http://127.0.0.1:5640","api":"http://127.0.0.1:5640","websocket":"wss://qualification.invalid"},"token_metadata":{"source_url":"http://qualification.invalid/token","sha256":"$desired_sha"},"validator_registry":{"source_url":"http://qualification.invalid/validators","sha256":"$desired_sha"},"contracts":{"source_url":"http://qualification.invalid/contracts","sha256":"$desired_sha"},"fee_reward":{"source_url":"http://qualification.invalid/fees","sha256":"$desired_sha"},"posy_etdag":{"source_url":"http://qualification.invalid/posy","sha256":"$desired_sha","target_block_time_ms":2000}}
JSON
    sudo ip netns exec "${node_ns[rpc-gateway]}" \
      node "$repo/atlas/scripts/preflight-live-rpc.mjs" "$qualification/atlas-network.json" \
      >"$evidence/atlas-rpc-preflight.json"
    psql "$atlas_database_url" -v ON_ERROR_STOP=1 \
      -f "$repo/atlas/schema/001_atlas_v3.sql" \
      >"$evidence/atlas-schema-install.log"
    psql "$atlas_database_url" -v ON_ERROR_STOP=1 <<SQL
INSERT INTO atlas_network (
  chain_id, chain_incarnation, network_id, genesis_hash, network_magic,
  rpc_url, api_url, websocket_url, manifest_sha256
) VALUES (
  1266, 4, 'synergy-testnet-v3',
  '$(jq -er .integrity.genesis_hash "$qualification/genesis.json")',
  'c1266004', 'http://10.70.30.1:5640', 'qualification://atlas-api',
  'qualification://atlas-websocket', '$desired_sha'
);
SQL
    psql "$atlas_database_url" -At -F $'\t' -v ON_ERROR_STOP=1 \
      -c "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE' AND table_name <> 'atlas_network' AND NOT EXISTS (SELECT 1 FROM information_schema.columns c WHERE c.table_schema='public' AND c.table_name=information_schema.tables.table_name AND c.column_name='chain_incarnation') ORDER BY table_name" \
      >"$evidence/atlas-tables-without-incarnation.txt"
    [[ ! -s "$evidence/atlas-tables-without-incarnation.txt" ]] || {
      echo "Atlas schema contains rows without chain_incarnation binding" >&2
      exit 1
    }
    jq -n \
      --argjson activated_at_height "$min_height" \
      --arg genesis_hash "$(jq -er .integrity.genesis_hash "$qualification/genesis.json")" \
      '{
        result:"ATLAS_BOUND_AFTER_OPERATIONAL",
        activated_at_height:$activated_at_height,
        chain_id:1266,
        chain_incarnation:4,
        genesis_hash:$genesis_hash,
        schema_rows_incarnation_bound:true
      }' >"$evidence/atlas-activation.json"
  fi
  if ((min_height >= 1000)) && [[ "$healthy_recorded" == false ]]; then
    write_direct_health_gate "$evidence/gate-1000-health.json" 1000
    jq -e 'all(.validators[]; .restart_count == 0)' \
      "$evidence/gate-1000-health.json" >/dev/null
    healthy_recorded=true
  fi
  if ((min_height >= 1000)) && [[ "$faults_complete" == false ]]; then
    before_fault="$min_height"
    stop_node validator-node-06
    wait_deadline=$((SECONDS + 25))
    observed_nonzero=false
    while ((SECONDS < wait_deadline)); do
      for node in \
        validator-node-01 validator-node-02 validator-node-03 \
        validator-node-04 validator-node-05
      do
        round="$(metric "$node" consensus_current_round || echo 0)"
        ((round > 0)) && observed_nonzero=true
      done
      progressed="$(metric validator-node-01 consensus_finalized_height || echo 0)"
      [[ "$observed_nonzero" == true ]] && ((progressed > before_fault)) && break
      sleep 1
    done
    [[ "$observed_nonzero" == true ]] || {
      echo "Single-validator delay did not exercise non-zero-round recovery" >&2
      exit 1
    }
    # A single guarded restart must rejoin from its durable checkpoint.
    start_node validator-node-06
    rejoin_deadline=$((SECONDS + 180))
    while :; do
      h6="$(metric validator-node-06 consensus_finalized_height || echo 0)"
      h1="$(metric validator-node-01 consensus_finalized_height || echo 0)"
      ((h1 - h6 <= 2)) && break
      ((SECONDS < rejoin_deadline)) || {
        echo "Restarted validator 6 did not rejoin within two blocks" >&2
        exit 1
      }
      sleep 1
    done
    # WireGuard-style packet impairment is applied only to the restarted sixth
    # validator; the other five must retain finality.
    sudo ip netns exec "${node_ns[validator-node-06]}" \
      tc qdisc add dev sy-vpn root netem loss 10%
    impairment_before="$(metric validator-node-01 consensus_finalized_height)"
    sleep 12
    sudo ip netns exec "${node_ns[validator-node-06]}" \
      tc qdisc del dev sy-vpn root
    impairment_after="$(metric validator-node-01 consensus_finalized_height)"
    ((impairment_after > impairment_before)) || {
      echo "Five-validator quorum stopped under one-peer packet loss" >&2
      exit 1
    }
    # Observer state is disposable and must reconstruct without influencing
    # any validator's locks or recovery authority.
    stop_node observer
    sleep 2
    observer_state="$qualification_state_root/observer/data"
    find "$observer_state" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
    : >"$observer_state/.reset_flag"
    start_node observer
    observer_deadline=$((SECONDS + 180))
    while :; do
      observer_height="$(metric observer consensus_finalized_height || echo 0)"
      quorum_height="$(metric validator-node-01 consensus_finalized_height || echo 0)"
      ((quorum_height - observer_height <= 2)) && break
      ((SECONDS < observer_deadline)) || {
        echo "Wiped observer did not resynchronize within two blocks" >&2
        exit 1
      }
      sleep 1
    done
    jq -n \
      --argjson before "$before_fault" \
      --argjson after "$impairment_after" \
      '{single_validator_restart:"PASS",delayed_validator:"PASS",packet_loss:"PASS",nonzero_round_recovery:"PASS",observer_wipe_resync:"PASS",height_before:$before,height_after:$after}' \
      >"$evidence/fault-recovery.json"
    faults_complete=true
  fi
  if ((min_height >= target_height)) && [[ "$faults_complete" == true ]]; then
    break
  fi
  sleep 1
done

write_direct_health_gate "$evidence/gate-10000-stable.json" 10000
jq -e '
  all(.validators[];
    if .node == "validator-node-06"
    then .restart_count == 1
    else .restart_count == 0
    end
  )
' "$evidence/gate-10000-stable.json" >/dev/null
final_validator_height="$(metric validator-node-01 consensus_finalized_height)"
for node in relay1 relay2 relay3 rpc-gateway explorer-indexer observer; do
  support_height="$(metric "$node" consensus_finalized_height || echo 0)"
  ((final_validator_height - support_height <= 2)) || {
    echo "$node is more than two blocks behind at the stable gate" >&2
    exit 1
  }
done

for node in "${nodes[@]}"; do
  metrics_text "$node" >"$evidence/$node.metrics"
  sudo journalctl -u "${role_unit}${node}.service" --no-pager -o short-iso-precise \
    >"$logs/$node.log"
  sudo ip netns exec "${node_ns[$node]}" wg show sy-vpn dump \
    | awk 'NR == 1 {$1 = "[REDACTED-PRIVATE-KEY]"} {print}' \
    >"$evidence/$node.wireguard.txt"
done
verified_mldsa65_handshakes="$(
  awk '/^p2p_verified_handshakes_total\\{algorithm="ML-DSA-65"\\}/ {total += $2} END {print total + 0}' \
    "$evidence"/*.metrics
)"
verified_fndsa_handshakes="$(
  awk '/^p2p_verified_handshakes_total\\{algorithm="FN-DSA-1024"\\}/ {total += $2} END {print total + 0}' \
    "$evidence"/*.metrics
)"
((verified_mldsa65_handshakes > 0)) || {
  echo "Ring-2 did not prove a real ML-DSA-65 P2P handshake" >&2
  exit 1
}
((verified_fndsa_handshakes > 0)) || {
  echo "Ring-2 did not prove a real FN-DSA-1024 P2P handshake" >&2
  exit 1
}
jq -n \
  --arg result PASS \
  --arg state STABLE \
  --arg release_id "$release_id" \
  --arg desired_state_sha256 "$desired_sha" \
  --arg genesis_hash "$(jq -er .integrity.genesis_hash "$qualification/genesis.json")" \
  --argjson target_height "$target_height" \
  --argjson verified_mldsa65_handshakes "$verified_mldsa65_handshakes" \
  --argjson verified_fndsa_handshakes "$verified_fndsa_handshakes" \
  '{
    schema_version:1,
    ring:2,
    result:$result,
    operational_state:$state,
    release_id:$release_id,
    desired_state_sha256:$desired_state_sha256,
    qualification_environment:"single-host-ci-preflight",
    isolated_public_network:true,
    wireguard_overlay:true,
    wireguard_credentials_disposable:true,
    real_pq_handshakes:{
      mldsa65_verified:$verified_mldsa65_handshakes,
      fndsa1024_verified:$verified_fndsa_handshakes
    },
    canonical_systemd_unit:"synergy-chain1266-role@.service",
    systemd_resource_profile:{memory_max_bytes:4294967296,cpu_quota_percent:100,limit_nofile:8192,restart:"no"},
    production_custody_material_used:false,
    validator_count:6,
    quorum:5,
    support_roles:{relayers:3,rpc:1,explorer:1,observer:1},
    chain:{chain_id:1266,incarnation:4,genesis_hash:$genesis_hash},
    finalized_height:$target_height
  }' >"$evidence/report.json"
find "$evidence" -type f ! -name SHA256SUMS -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sed "s#  $evidence/#  #" >"$evidence/SHA256SUMS"
echo "CHAIN1266_RING2_PASS state=STABLE height=$target_height evidence=$evidence"
