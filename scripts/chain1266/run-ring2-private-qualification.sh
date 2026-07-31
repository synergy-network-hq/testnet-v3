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

case "$qualification" in
  /tmp/*|/home/runner/work/_temp/*) ;;
  *) echo "Ring-2 qualification root must be an ephemeral runner path" >&2; exit 1 ;;
esac
[[ "$target_height" =~ ^[0-9]+$ ]] && ((target_height >= 10000)) || {
  echo "Ring-2 target must be at least 10,000 finalized blocks" >&2
  exit 1
}
for command in ip tc jq curl python3 sha256sum prlimit nice; do
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

cleanup() {
  set +e
  for node in "${nodes[@]}"; do
    pid="${process_pid[$node]:-}"
    [[ -n "$pid" ]] && sudo kill -TERM "$pid" >/dev/null 2>&1
  done
  sleep 1
  for node in "${nodes[@]}"; do
    pid="${process_pid[$node]:-}"
    [[ -n "$pid" ]] && sudo kill -KILL "$pid" >/dev/null 2>&1
  done
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
  sudo ip netns add "$ns"
  sudo ip link add "$host_veth" type veth peer name "$peer_veth"
  sudo ip link set "$host_veth" master "$bridge"
  sudo ip link set "$host_veth" up
  sudo ip link set "$peer_veth" netns "$ns"
  sudo ip -n "$ns" link set "$peer_veth" name eth0
  sudo ip -n "$ns" addr add "${node_ip[$node]}/16" dev eth0
  sudo ip -n "$ns" link set lo up
  sudo ip -n "$ns" link set eth0 up
  if sudo ip -n "$ns" route show default | grep -q .; then
    echo "$node unexpectedly has a default route" >&2
    exit 1
  fi
done

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
  local project="$projects/$node/chain-1266/incarnation-4"
  local config
  local source_config
  local binary
  local key_args=()
  source_config="$(config_for "$node")"
  config="$project/config/node_config.toml"
  binary="$(binary_for "$node")"
  state_root="$project/data"
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
    key_args=(
      "SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE=$private_root/$validator_id/mldsa65-consensus.private.key"
      "CONSENSUS_START_PAUSED=1"
      "SYNERGY_CONSENSUS_START_RELEASE_FILE=$qualification/start-consensus.json"
    )
  fi
  sudo ip netns exec "${node_ns[$node]}" \
    env \
      "SYNERGY_PROJECT_ROOT=$project" \
      "SYNERGY_DATA_PATH=$state_root" \
      "SYNERGY_GENESIS_FILE=$qualification/genesis.json" \
      "SYNERGY_DESIRED_STATE_MANIFEST=$qualification/desired-state.json" \
      "SYNERGY_DESIRED_STATE_MANIFEST_SHA256=$desired_sha" \
      "SYNERGY_DESIRED_STATE_SIGNATURE=$qualification/desired-state.signature.json" \
      "SYNERGY_CHAIN1266_QUALIFICATION_MODE=1" \
      "SYNERGY_ENABLE_METRICS=true" \
      "${key_args[@]}" \
    prlimit --nofile=8192:8192 --as=4294967296 \
    nice -n 5 \
    "$binary" start --config "$config" \
    >"$logs/$node.log" 2>&1 &
  process_pid[$node]=$!
  printf '%s\n' "$!" >"$pids/$node.pid"
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

for node in relay1 relay2 relay3 rpc-gateway explorer-indexer observer; do
  start_node "$node"
done
for node in \
  validator-node-01 validator-node-02 validator-node-03 \
  validator-node-04 validator-node-05 validator-node-06
do
  start_node "$node"
done

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
    elif ! sudo kill -0 "${process_pid[$node]}" 2>/dev/null; then
      echo "$node exited before PAUSED_READY" >&2
      tail -100 "$logs/$node.log" >&2
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
  fi
  if ((min_height >= 1000)) && [[ "$healthy_recorded" == false ]]; then
    python3 "$qualification/collect-health.py" "$samples" "$evidence/gate-1000-health.json"
    jq -e '
      .mean_finality_interval_seconds <= 2.0 and
      .median_finality_interval_seconds <= 1.5 and
      .p95_finality_interval_seconds <= 3.0 and
      .round_zero_ratio >= 0.99
    ' "$evidence/gate-1000-health.json" >/dev/null
    healthy_recorded=true
  fi
  if ((min_height >= 1000)) && [[ "$faults_complete" == false ]]; then
    before_fault="$min_height"
    stopped_pid="${process_pid[validator-node-06]}"
    sudo kill -TERM "$stopped_pid"
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
      tc qdisc add dev eth0 root netem loss 10%
    impairment_before="$(metric validator-node-01 consensus_finalized_height)"
    sleep 12
    sudo ip netns exec "${node_ns[validator-node-06]}" \
      tc qdisc del dev eth0 root
    impairment_after="$(metric validator-node-01 consensus_finalized_height)"
    ((impairment_after > impairment_before)) || {
      echo "Five-validator quorum stopped under one-peer packet loss" >&2
      exit 1
    }
    # Observer state is disposable and must reconstruct without influencing
    # any validator's locks or recovery authority.
    observer_pid="${process_pid[observer]}"
    sudo kill -TERM "$observer_pid"
    sleep 2
    observer_state="$projects/observer/chain-1266/incarnation-4/data"
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

python3 "$qualification/collect-health.py" "$samples" "$evidence/gate-10000-stable.json"
jq -e '
  .finalized_height >= 10000 and
  .mean_finality_interval_seconds <= 2.0 and
  .median_finality_interval_seconds <= 1.5 and
  .p95_finality_interval_seconds <= 3.0 and
  .round_zero_ratio >= 0.99
' "$evidence/gate-10000-stable.json" >/dev/null

for node in "${nodes[@]}"; do
  metrics_text "$node" >"$evidence/$node.metrics"
done
jq -n \
  --arg result PASS \
  --arg state STABLE \
  --arg release_id "$release_id" \
  --arg desired_state_sha256 "$desired_sha" \
  --arg genesis_hash "$(jq -er .integrity.genesis_hash "$qualification/genesis.json")" \
  --argjson target_height "$target_height" \
  '{
    schema_version:1,
    ring:2,
    result:$result,
    operational_state:$state,
    release_id:$release_id,
    desired_state_sha256:$desired_state_sha256,
    isolated_public_network:true,
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
