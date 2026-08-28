#!/usr/bin/env bash
# Local-only R11 qualification harness for the *production* validator role.
#
# This script deliberately does not generate Genesis, validator configurations,
# private keys, ingress KEM registries, or network endpoints.  It accepts only
# explicit, externally approved artifacts; all supplied paths are copied or
# read without modification.  The five child processes are always local
# `synergy-validator-node` processes and never SSH to, restart, or otherwise
# contact a real validator.
#
# A successful run is evidence only when every assertion below is observed.
# In particular, a process staying alive, a successful config parse, or a
# partial finality WAL is not a qualification result.

set -euo pipefail

readonly VALIDATORS=(validator-02 validator-03 validator-04 validator-05 validator-06)
readonly MIN_BLOCK_INTERVAL_MS=100
readonly MAX_BLOCK_INTERVAL_MS=1100
readonly REQUIRED_FINALIZED_HEIGHT=20
readonly POST_RESTART_FINALITY_ADVANCE=3

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime_root="$(cd "$script_dir/../.." && pwd)"

usage() {
    cat <<'USAGE'
Usage:
  run-posy-v3-r11-production-role-harness.sh \
    --genesis PATH --ingress-kem-registry-dir PATH \
    --desired-state PATH --desired-state-sha256 SHA256 \
    --release-approval PATH --authority-record PATH --release-candidate PATH \
    --validator-02-config PATH --validator-02-key PATH \
    --validator-03-config PATH --validator-03-key PATH \
    --validator-04-config PATH --validator-04-key PATH \
    --validator-05-config PATH --validator-05-key PATH \
    --validator-06-config PATH --validator-06-key PATH \
    [--binary PATH] [--work-dir PATH] [--timeout-secs SECONDS]

All artifact paths are mandatory and must name the approved fresh-P3 release:

  * Genesis is a signed, fresh Chain 1266 PoSy/3.0 document.
  * Registry directory contains canonical signed ingress-KEM registry artifacts
    for every target H3 through H20, under the runtime's exact
    epoch-root/epoch-0-height-N-cluster-C.json directory layout.
  * Desired state, its SHA-256, the dated V4 authority record, signed V4
    approval, and immutable release candidate are all mandatory. They are
    passed unchanged to the production verifier; no qualification bypass exists.
  * Configurations are rendered validator profiles for validator-02 through
    validator-06, use technical network_id `testnet`, bind only loopback
    transports, and have distinct local P2P/RPC/metrics ports.
  * Key files are explicit local ML-DSA-65 custody paths. They are read in
    place and are never copied, printed, or logged.

The harness persists its evidence under --work-dir and leaves it intact. It
never deploys or contacts live infrastructure.
USAGE
}

fail() {
    printf 'R11_PRODUCTION_ROLE_HARNESS_FAILED: %s\n' "$*" >&2
    exit 1
}

# A timeout is evidence only if it identifies the protocol edge which has not
# occurred.  Keep this on disk as well as stderr: parent processes commonly
# terminate the harness after a timeout and otherwise lose the useful cause.
first_missing_transition() {
    local edge="$1"
    local detail="${2:-}"
    mkdir -p "$work_dir/evidence"
    printf 'FIRST_MISSING_TRANSITION=%s\n' "$edge" \
        | tee "$work_dir/evidence/first-missing-transition.txt" >&2
    [[ -z "$detail" ]] || printf 'FIRST_MISSING_DETAIL=%s\n' "$detail" \
        | tee -a "$work_dir/evidence/first-missing-transition.txt" >&2
}

fail_transition() {
    local edge="$1"
    shift
    first_missing_transition "$edge" "$*"
    fail "$*"
}

require_file() {
    [[ -f "$1" && -r "$1" ]] || fail "required readable file is missing: $1"
}

require_directory() {
    [[ -d "$1" && -r "$1" ]] || fail "required readable directory is missing: $1"
}

require_qualification_file() {
    local edge="$1"
    local path="$2"
    [[ -f "$path" && -r "$path" ]] || fail_transition "$edge" \
        "required readable qualification artifact is missing: $path"
}

require_qualification_directory() {
    local edge="$1"
    local path="$2"
    [[ -d "$path" && -r "$path" ]] || fail_transition "$edge" \
        "required readable qualification artifact directory is missing: $path"
}

now_ms() {
    perl -MTime::HiRes=time -e 'printf "%.0f\n", time() * 1000'
}

config_for() {
    local validator="$1"
    local index
    for index in "${!VALIDATORS[@]}"; do
        [[ "${VALIDATORS[$index]}" == "$validator" ]] && {
            printf '%s\n' "${configs[$index]}"
            return
        }
    done
    return 1
}

key_for() {
    local validator="$1"
    local index
    for index in "${!VALIDATORS[@]}"; do
        [[ "${VALIDATORS[$index]}" == "$validator" ]] && {
            printf '%s\n' "${keys[$index]}"
            return
        }
    done
    return 1
}

assert_no_retired_input() {
    local path="$1"
    # These are the retired technical identifiers, not merely display names.
    # Rejecting them keeps a local harness from accidentally attaching the
    # former six-validator/incarnation-4 release to the fresh P3 code path.
    if rg -n --fixed-strings \
        -e '"protocol_version": "posy/2.' \
        -e '"consensus_version": "posy/2.' \
        -e '"runtime_network_id": "synergy-testnet-v3"' \
        -e '"network_slug": "synergy-testnet-v3"' \
        "$path" >/dev/null 2>&1; then
        fail "retired Chain 1266 input rejected: $path"
    fi
}

assert_local_only_config() {
    local config="$1"
    local label="$2"

    # The production binary performs its own typed TOML validation. These
    # checks are intentionally narrower: the harness must never dial a public
    # address because it is only a local qualification environment.
    if rg -n -i 'https?://|synergy-[a-z0-9.-]+\.(io|xyz|net|com|org)' "$config" >/dev/null; then
        fail "$label config contains a public endpoint; local harness refuses it"
    fi
    python3 - "$config" <<'PY' || fail "$label config contains a non-loopback IPv4 address"
import ipaddress
import pathlib
import re
import sys
text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for candidate in re.findall(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", text):
    try:
        if not ipaddress.ip_address(candidate).is_loopback:
            raise SystemExit(1)
    except ValueError:
        raise SystemExit(1)
PY
    if ! rg -n '^\s*listen_address\s*=\s*"(127\.0\.0\.1|\[::1\]|localhost):[0-9]+"\s*$' "$config" >/dev/null; then
        fail "$label config must bind P2P listen_address to an explicit loopback address"
    fi
    if rg -n '^\s*(bootnodes|seed_servers|bootstrap_dns_records|register_endpoints|heartbeat_endpoints)\s*=\s*\[[^]]*[^[:space:],\[\]]' "$config" >/dev/null; then
        fail "$label config contains non-local bootstrap or registration endpoints"
    fi
}

config_mesh_identity() {
    local config="$1"
    python3 - "$config" <<'PY'
import ipaddress
import json
import sys
import tomllib

path = sys.argv[1]
with open(path, "rb") as handle:
    config = tomllib.load(handle)

identity = config.get("identity", {})
network = config.get("network", {})
p2p = config.get("p2p", {})
rpc = config.get("rpc", {})
address = str(identity.get("address", "")).strip()
p2p_port = int(network.get("p2p_port", 0))
rpc_port = int(network.get("rpc_port", 0))
listen = str(p2p.get("listen_address", ""))
rpc_bind = str(rpc.get("bind_address", ""))

def split_endpoint(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, port = value[1:].split("]:", 1)
    else:
        host, port = value.rsplit(":", 1)
    return host, int(port)

def loopback(value: str, expected_port: int) -> bool:
    try:
        host, port = split_endpoint(value)
        return port == expected_port and (
            host == "localhost" or ipaddress.ip_address(host).is_loopback
        )
    except (ValueError, TypeError):
        return False

if not address or not (0 < p2p_port < 65536) or not (0 < rpc_port < 65536):
    raise SystemExit(1)
if not loopback(listen, p2p_port) or not loopback(rpc_bind, rpc_port):
    raise SystemExit(1)
targets = network.get("additional_dial_targets", [])
if not isinstance(targets, list) or len(targets) != 4 or len(set(targets)) != 4:
    raise SystemExit(1)
for field in ("bootnodes", "seed_servers", "bootstrap_dns_records", "persistent_peers"):
    if network.get(field, []):
        raise SystemExit(1)
if any(not loopback(str(target), split_endpoint(str(target))[1]) for target in targets):
    raise SystemExit(1)
print(f"{address}\t{p2p_port}\t{rpc_port}\t{json.dumps(targets, separators=(',', ':'))}")
PY
}

validate_registry_directory() {
    local height artifact found candidate_count
    [[ -z "$(find "$registry_dir" -maxdepth 1 -type f -name '*.json' -print -quit)" ]] || \
        fail "ingress KEM registries must be rooted by epoch-context digest directories, not flat files"
    for height in $(seq 3 "$REQUIRED_FINALIZED_HEIGHT"); do
        found=0
        candidate_count=0
        while IFS= read -r artifact; do
            candidate_count=$((candidate_count + 1))
            jq -e --argjson height "$height" '
                .format == "synergy-posy-simplified-ingress-kem-registry-v1" and
                .epoch == 0 and .target_height == $height and
                (.epoch_context_root | type == "array" and length == 32) and
                (.registry_root | type == "string" and length == 128) and
                .registry.registry_version == 1 and
                .registry.chain_id == 1266 and
                .registry.network_id == "testnet" and
                .registry.protocol_version == "posy/3.0" and
                .registry.epoch == 0 and .registry.target_height == $height and
                (.registry.records | length) == 5 and
                (.registry.records | map(
                    (.validator_id | type == "string") and
                    (.ingress_key_id | type == "string") and
                    (.share_index | type == "number" and . > 0) and
                    (.key_bytes | type == "array" and length == 1568 and all(.[]; type == "number" and . >= 0 and . <= 255))
                ) | all)
            ' "$artifact" >/dev/null 2>&1 || fail "invalid runtime ingress KEM registry shape: $artifact"
            found=1
        done < <(find "$registry_dir" -mindepth 2 -maxdepth 2 -type f \
            -path "*/epoch-0-height-${height}-cluster-*.json" -print | LC_ALL=C sort)
        (( candidate_count == 1 && found == 1 )) || \
            fail "need exactly one runtime-layout fresh-P3 ingress KEM registry for H${height}"
    done
    python3 - "$registry_dir" <<'PY' || fail "ingress KEM registry namespace or canonical encoding is invalid"
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
epoch_roots = set()
artifacts = sorted(root.glob("*/epoch-0-height-*-cluster-*.json"))
if len(artifacts) != 18:
    raise SystemExit(1)
for artifact in artifacts:
    raw = artifact.read_bytes()
    value = json.loads(raw)
    canonical = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if raw != canonical:
        raise SystemExit(1)
    encoded_root = "".join(f"{byte:02x}" for byte in value["epoch_context_root"])
    if artifact.parent.name != encoded_root or not re.fullmatch(r"[0-9a-f]{64}", encoded_root):
        raise SystemExit(1)
    match = re.fullmatch(r"epoch-0-height-(\d+)-cluster-(\d+)\.json", artifact.name)
    if match is None:
        raise SystemExit(1)
    if int(match.group(1)) != value["target_height"]:
        raise SystemExit(1)
    if int(match.group(2)) != value["assigned_cluster_id"]:
        raise SystemExit(1)
    epoch_roots.add(encoded_root)
if len(epoch_roots) != 1:
    raise SystemExit(1)
PY
}

validate_artifacts() {
    require_qualification_file "SIGNED_GENESIS->ROLE_PREFLIGHT" "$genesis"
    require_qualification_directory "SIGNED_INGRESS_REGISTRIES->NORMAL_TARGET_ADMISSION" "$registry_dir"
    require_qualification_file "DESIRED_STATE->ROLE_PREFLIGHT" "$desired_state"
    require_qualification_file "V4_AUTHORITY_RECORD->ROLE_PREFLIGHT" "$authority_record"
    require_qualification_file "V4_RELEASE_APPROVAL->ROLE_PREFLIGHT" "$release_approval"
    require_qualification_file "V4_RELEASE_CANDIDATE->ROLE_PREFLIGHT" "$release_candidate"
    [[ "$desired_state_sha256" =~ ^[0-9a-f]{64}$ ]] || fail_transition \
        "DESIRED_STATE_HASH->ROLE_PREFLIGHT" "--desired-state-sha256 must be lowercase SHA-256"
    [[ "$(shasum -a 256 "$desired_state" | awk '{print $1}')" == "$desired_state_sha256" ]] || fail_transition \
        "DESIRED_STATE_HASH->ROLE_PREFLIGHT" "desired-state SHA-256 does not match --desired-state-sha256"
    command -v jq >/dev/null || fail "jq is required for fail-closed artifact checks"
    command -v perl >/dev/null || fail "perl with Time::HiRes is required for timing evidence"
    command -v python3 >/dev/null || fail "Python 3 with tomllib is required for typed local mesh checks"
    command -v rg >/dev/null || fail "rg is required for local-only transport checks"

    assert_no_retired_input "$genesis"
    jq -e '
        .network.chain_id == 1266 and
        .consensus.posy_v3_activation.manifest.protocol_version == "posy/3.0" and
        .consensus.posy_v3_activation.manifest.network_id == "testnet" and
        .consensus.posy_v3_activation.manifest.active_validator_count == 5 and
        ([.consensus.posy_v3_activation.frozen_validator_set.validators[].validator_id] | sort) ==
          ["validator-02", "validator-03", "validator-04", "validator-05", "validator-06"]
    ' "$genesis" >/dev/null || fail "Genesis is not the signed fresh-P3 five-validator artifact"

    validate_registry_directory

    local index validator config key parsed mesh_identity
    for index in "${!VALIDATORS[@]}"; do
        validator="${VALIDATORS[$index]}"
        config="${configs[$index]}"
        key="${keys[$index]}"
        require_qualification_file "RENDERED_CONFIG->ROLE_PREFLIGHT($validator)" "$config"
        require_qualification_file "LOCAL_VALIDATOR_CUSTODY->ROLE_PREFLIGHT($validator)" "$key"
        assert_no_retired_input "$config"
        assert_local_only_config "$config" "$validator"
        parsed="$($validator_binary validate-config --config "$config" 2>&1)" || fail "$validator config failed runtime parser: $parsed"
        [[ "$parsed" == *"validator_id=$validator"* ]] || fail "$validator config does not bind expected validator identity: $parsed"
        [[ "$parsed" == *'chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3'* ]] || fail "$validator config has an invalid fresh-P3 runtime binding: $parsed"
        mesh_identity="$(config_mesh_identity "$config")" || fail \
            "$validator config must bind one local RPC/P2P endpoint and exactly four loopback dial targets"
        IFS=$'\t' read -r validator_addresses[$index] p2p_ports[$index] rpc_ports[$index] mesh_targets[$index] <<<"$mesh_identity"
    done

    [[ "$(printf '%s\n' "${validator_addresses[@]}" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == "5" ]] || \
        fail "validator configurations do not bind five distinct consensus addresses"
    [[ "$(printf '%s\n' "${p2p_ports[@]}" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == "5" ]] || \
        fail "validator configurations do not bind five distinct local P2P ports"
    [[ "$(printf '%s\n' "${rpc_ports[@]}" | LC_ALL=C sort -u | wc -l | tr -d ' ')" == "5" ]] || \
        fail "validator configurations do not bind five distinct local RPC ports"
    local expected_targets target_index
    for index in "${!VALIDATORS[@]}"; do
        expected_targets=()
        for target_index in "${!VALIDATORS[@]}"; do
            [[ "$target_index" == "$index" ]] && continue
            expected_targets+=("127.0.0.1:${p2p_ports[$target_index]}")
        done
        python3 - "${mesh_targets[$index]}" "${expected_targets[@]}" <<'PY' || \
            fail "${VALIDATORS[$index]} does not dial the exact other four loopback validators"
import json
import sys
actual = json.loads(sys.argv[1])
expected = sys.argv[2:]
raise SystemExit(0 if sorted(actual) == sorted(expected) else 1)
PY
    done

    # Fail at the byte-binding edge before invoking five independent role
    # preflights.  The production verifier performs the authoritative check;
    # this duplicate is diagnostic only and deliberately compares exact file
    # bytes rather than parsed config structures.  Without it, a rebuilt
    # validator or rerendered config is reported only as a generic role
    # preflight failure and obscures the first actionable release transition.
    local actual_sha expected_sha
    actual_sha="$(shasum -a 256 "$validator_binary" | awk '{print $1}')"
    expected_sha="$(jq -er '
        if (.artifacts | type) == "object" and
           (.artifacts | keys) == ["validator_node"] and
           (.artifacts.validator_node | type) == "string"
        then .artifacts.validator_node else empty end
    ' "$desired_state" 2>/dev/null || true)"
    [[ "$actual_sha" == "$expected_sha" ]] || fail_transition \
        "RELEASE_BINARY->DESIRED_STATE_BINDING" \
        "desired state does not bind the exact supplied synergy-validator-node bytes"

    for index in "${!VALIDATORS[@]}"; do
        validator="${VALIDATORS[$index]}"
        actual_sha="$(shasum -a 256 "${configs[$index]}" | awk '{print $1}')"
        expected_sha="$(jq -er --arg validator "$validator" '
            if (.configuration | type) == "object" and
               (.configuration | keys) == [
                   "validator-02", "validator-03", "validator-04",
                   "validator-05", "validator-06"
               ] and
               (.configuration[$validator] | type) == "string"
            then .configuration[$validator] else empty end
        ' "$desired_state" 2>/dev/null || true)"
        [[ "$actual_sha" == "$expected_sha" ]] || fail_transition \
            "RENDERED_CONFIG->DESIRED_STATE_BINDING($validator)" \
            "desired state does not bind the exact supplied $validator configuration bytes"
    done
}

workspace_for() {
    printf '%s/nodes/%s\n' "$work_dir" "$1"
}

data_for() {
    printf '%s/chain-1266/incarnation-5/data\n' "$(workspace_for "$1")"
}

export_release_binding() {
    local qualification_root="${1:-$work_dir/nodes}"
    export SYNERGY_DESIRED_STATE_MANIFEST="$desired_state"
    export SYNERGY_DESIRED_STATE_MANIFEST_SHA256="$desired_state_sha256"
    export SYNERGY_TESTNET_V3_RELEASE_APPROVAL="$release_approval"
    export SYNERGY_TESTNET_V3_AUTHORITY_RECORD="$authority_record"
    export SYNERGY_TESTNET_V3_RELEASE_CANDIDATE="$release_candidate"
    export SYNERGY_CHAIN1266_QUALIFICATION_MODE=1
    export SYNERGY_CHAIN1266_QUALIFICATION_ROOT="$qualification_root"
}

prepare_workspace() {
    local validator="$1"
    local node_dir data_dir config
    node_dir="$(workspace_for "$validator")"
    data_dir="$(data_for "$validator")"
    config="$(config_for "$validator")"
    mkdir -p "$node_dir/config" "$data_dir"
    cp "$config" "$node_dir/config/node.toml"
    # Artifacts are public.  Copying them into each isolated runtime root is
    # required because the production role resolves this read-only source from
    # its own data directory. Keys remain outside the work directory.
    mkdir -p "$data_dir/posy-v3-ingress-kem-registries"
    cp -R "$registry_dir/." "$data_dir/posy-v3-ingress-kem-registries/"
    # Public governance identity material is resolved relative to each
    # isolated project root by the production verifier. Keep the authority
    # record itself external, but replicate only its public bundle beside the
    # node so every role can independently validate the same V4 key binding.
    local authority_bundle
    authority_bundle="$(dirname "$authority_record")/authority-bundle"
    if [[ -d "$authority_bundle" ]]; then
        cp -R "$authority_bundle" "$node_dir/local-r11-authority-bundle"
    fi
}

start_node() {
    local index="$1"
    local validator="${VALIDATORS[$index]}"
    local node_dir data_dir key log
    node_dir="$(workspace_for "$validator")"
    data_dir="$(data_for "$validator")"
    key="$(key_for "$validator")"
    log="$work_dir/logs/$validator.log"
    mkdir -p "$work_dir/logs"

    (
        cd "$node_dir"
        export SYNERGY_PROJECT_ROOT="$node_dir"
        export SYNERGY_CONFIG_PATH="$node_dir/config/node.toml"
        export SYNERGY_DATA_PATH="$data_dir"
        export SYNERGY_GENESIS_FILE="$genesis"
        export SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE="$key"
        export_release_binding "$node_dir"
        exec "$validator_binary" start --config "$node_dir/config/node.toml"
    ) >>"$log" 2>&1 &
    pids[$index]=$!
}

stop_nodes() {
    local index pid
    if [[ -n "${finality_observer_pid:-}" ]] && kill -0 "$finality_observer_pid" 2>/dev/null; then
        kill -TERM "$finality_observer_pid" 2>/dev/null || true
        wait "$finality_observer_pid" 2>/dev/null || true
    fi
    for index in "${!pids[@]}"; do
        pid="${pids[$index]:-}"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for index in "${!pids[@]}"; do
        pid="${pids[$index]:-}"
        [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
    done
}

processes_are_healthy() {
    local index pid validator log
    for index in "${!VALIDATORS[@]}"; do
        validator="${VALIDATORS[$index]}"
        pid="${pids[$index]:-}"
        log="$work_dir/logs/$validator.log"
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || fail "$validator process exited; inspect $log"
        if rg -n -i 'consensus startup failed closed|safetyhalt|panic|fatal consensus/signing' "$log" >/dev/null; then
            fail "$validator emitted a fatal role/consensus log; inspect $log"
        fi
    done
}

processes_are_healthy_except() {
    local skipped="$1"
    local index pid validator log
    for index in "${!VALIDATORS[@]}"; do
        [[ "$index" == "$skipped" ]] && continue
        validator="${VALIDATORS[$index]}"
        pid="${pids[$index]:-}"
        log="$work_dir/logs/$validator.log"
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || fail "$validator process exited; inspect $log"
        if rg -n -i 'consensus startup failed closed|safetyhalt|panic|fatal consensus/signing' "$log" >/dev/null; then
            fail "$validator emitted a fatal role/consensus log; inspect $log"
        fi
    done
}

wait_for_log_marker() {
    local marker="$1"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local index validator log all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_found=1
        for index in "${!VALIDATORS[@]}"; do
            validator="${VALIDATORS[$index]}"
            log="$work_dir/logs/$validator.log"
            rg -F "$marker" "$log" >/dev/null 2>&1 || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.05
    done
    fail_transition "ROLE_STARTUP->SIMPLIFIED_POSY_DRIVER" \
        "timed out waiting for every production role log to emit: $marker"
}

rpc_four_peer_mesh_status() {
    local index="$1"
    local expected=()
    local target_index
    for target_index in "${!VALIDATORS[@]}"; do
        [[ "$target_index" == "$index" ]] && continue
        expected+=("${validator_addresses[$target_index]}")
    done
    python3 - "${rpc_ports[$index]}" "${validator_addresses[$index]}" "${expected[@]}" <<'PY'
import json
import sys
import urllib.request

port = int(sys.argv[1])
self_address = sys.argv[2]
expected = set(sys.argv[3:])
payload = json.dumps({
    "jsonrpc": "2.0",
    "method": "synergy_getPeerInfo",
    "params": [],
    "id": 1,
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=1) as response:
        body = json.loads(response.read().decode())
except Exception as error:
    print(json.dumps({"status": "rpc-unavailable", "error": str(error)}, separators=(",", ":")))
    raise SystemExit(1)
result = body.get("result", {})
peers = result.get("peers", [])
seen = {
    str(peer.get("validator_address", "")).strip()
    for peer in peers
    if str(peer.get("validator_address", "")).strip()
}
seen.discard(self_address)
connected = int(result.get("connected_validator_count", 0))
status = {
    "status": "ok" if seen == expected and connected == 4 else "incomplete",
    "self": self_address,
    "connected_validator_count": connected,
    "seen": sorted(seen),
    "expected": sorted(expected),
}
print(json.dumps(status, separators=(",", ":")))
raise SystemExit(0 if status["status"] == "ok" else 1)
PY
}

wait_for_full_four_peer_mesh() {
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local index all_ready status
    mkdir -p "$work_dir/evidence/mesh"
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_ready=1
        for index in "${!VALIDATORS[@]}"; do
            status="$(rpc_four_peer_mesh_status "$index" 2>/dev/null)" || all_ready=0
            printf '%s\n' "$status" >"$work_dir/evidence/mesh/${VALIDATORS[$index]}.json"
        done
        (( all_ready == 1 )) && return
        sleep 0.05
    done
    fail_transition "FOUR_PEER_LOOPBACK_MESH->SIMPLIFIED_POSY_DRIVER" \
        "every production validator must authenticate the exact other four loopback peers; inspect $work_dir/evidence/mesh"
}

finality_record_for() {
    local validator="$1"
    local height="$2"
    find "$(data_for "$validator")/posy-v3-finality" -type f \
        -name "finality-$(printf '%020d' "$height").json" -print -quit 2>/dev/null
}

highest_finality_height() {
    local validator="$1"
    local path name digits highest=0 height
    while IFS= read -r path; do
        name="${path##*/}"
        digits="${name#finality-}"
        digits="${digits%.json}"
        [[ "$digits" =~ ^[0-9]+$ ]] || continue
        height=$((10#$digits))
        (( height > highest )) && highest=$height
    done < <(find "$(data_for "$validator")/posy-v3-finality" -maxdepth 1 -type f \
        -name 'finality-*.json' -print 2>/dev/null)
    printf '%s\n' "$highest"
}

assert_finality_record() {
    local validator="$1"
    local height="$2"
    local record
    record="$(finality_record_for "$validator" "$height")"
    [[ -n "$record" ]] || return 1
    jq -e --argjson height "$height" '
        .format == "synergy-posy-simplified-finality-wal-record-v2" and
        .receipt.target_finalized.height == $height and
        .transaction.target_finalized.height == $height and
        (.transaction.finality_witness | length) == 3
    ' "$record" >/dev/null 2>&1
}

# The bootstrap heights intentionally have no normal target record.  Their
# proof is the persisted material selected by the production adapter, tied to
# the same height and carrying the GenesisBootstrap execution source.
assert_genesis_bootstrap_material() {
    local validator="$1"
    local height="$2"
    local material
    while IFS= read -r material; do
        jq -e --argjson height "$height" '
            .format == "synergy-posy-simplified-protected-material-v3" and
            .candidate_subject.context.height == $height and
            .protected_execution_input != null and
            .protected_execution_input.source == "GENESIS_BOOTSTRAP" and
            .protected_execution_input.target_context.kind == "GENESIS_BOOTSTRAP" and
            .next_protected_batch_commitment != null
        ' "$material" >/dev/null 2>&1 && return 0
    done < <(find "$(data_for "$validator")/posy-v3-protected-material" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null)
    return 1
}

wait_for_genesis_bootstrap_finality() {
    local height="$1"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_found=1
        for validator in "${VALIDATORS[@]}"; do
            assert_finality_record "$validator" "$height" || all_found=0
            assert_genesis_bootstrap_material "$validator" "$height" || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.05
    done
    fail_transition "GENESIS_BOOTSTRAP(H$height)->PROPOSAL_VC_QC_FINALIZED(H$height)" \
        "H$height did not durably finalize with a GenesisBootstrap execution input on every production role"
}

observe_finality_arrivals() {
    local height deadline validator all_found timestamp
    : >"$work_dir/evidence/finality-arrivals.tsv"
    for height in $(seq 1 "$REQUIRED_FINALIZED_HEIGHT"); do
        deadline=$(( $(now_ms) + timeout_secs * 1000 ))
        all_found=0
        while (( $(now_ms) < deadline )); do
            all_found=1
            for validator in "${VALIDATORS[@]}"; do
                assert_finality_record "$validator" "$height" || all_found=0
            done
            if (( all_found == 1 )); then
                timestamp="$(now_ms)"
                printf '%s\t%s\n' "$height" "$timestamp" >>"$work_dir/evidence/finality-arrivals.tsv"
                break
            fi
            sleep 0.01
        done
        if (( all_found == 0 )); then
            printf 'timing observer did not see H%s on every validator\n' "$height" \
                >"$work_dir/evidence/finality-observer-error.txt"
            return 1
        fi
    done
}

start_finality_observer() {
    observe_finality_arrivals &
    finality_observer_pid=$!
}

await_finality_observer() {
    [[ -n "$finality_observer_pid" ]] || fail "finality timing observer was not started"
    wait "$finality_observer_pid" || fail_transition \
        "FINALIZED(H1-H20)->CONSECUTIVE_TIMING_EVIDENCE" \
        "the concurrent finality observer missed a required height; inspect $work_dir/evidence/finality-observer-error.txt"
    finality_observer_pid=""
}

wait_for_finality_height() {
    local height="$1"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_found=1
        for validator in "${VALIDATORS[@]}"; do
            assert_finality_record "$validator" "$height" || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.025
    done
    fail_transition "QC(H$height)->FINALIZED(H$height)" \
        "timed out waiting for all five production roles to durably finalize H$height"
}

wait_for_four_validator_finality() {
    local height="$1"
    local offline_index="$2"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local index validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy_except "$offline_index"
        all_found=1
        for index in "${!VALIDATORS[@]}"; do
            [[ "$index" == "$offline_index" ]] && continue
            validator="${VALIDATORS[$index]}"
            assert_finality_record "$validator" "$height" || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.025
    done
    fail_transition "FOUR_OF_FIVE_LIVENESS->FINALIZED(H$height)" \
        "the remaining four production validators did not finalize H$height while ${VALIDATORS[$offline_index]} was offline"
}

assert_same_finalized_block() {
    local height="$1"
    local validator record block_id expected=""
    for validator in "${VALIDATORS[@]}"; do
        record="$(finality_record_for "$validator" "$height")"
        block_id="$(jq -r '.receipt.target_finalized.block_id // empty' "$record")"
        [[ -n "$block_id" ]] || fail "$validator has no finalized block identity at H$height"
        if [[ -z "$expected" ]]; then
            expected="$block_id"
        elif [[ "$block_id" != "$expected" ]]; then
            fail "finalized block mismatch at H$height: $validator differs from the five-validator tip"
        fi
    done
}

assert_lifecycle_finality() {
    local validator="$1"
    local height="$2"
    local record
    record="$(find "$(data_for "$validator")/protected-pipeline-v1/lifecycle" -type f -name "h$height-*.json" -print -quit 2>/dev/null)"
    [[ -n "$record" ]] || return 1
    jq -e --argjson height "$height" '
        .format == "synergy-posy-protected-pipeline-lifecycle-v2" and
        .record.record_version == 2 and
        .record.target.target_height == $height and
        .record.finality != null and
        .record.finality_observation != null
    ' "$record" >/dev/null 2>&1
}

wait_for_lifecycle_finality() {
    local height="$1"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_found=1
        for validator in "${VALIDATORS[@]}"; do
            assert_lifecycle_finality "$validator" "$height" || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.05
    done
    fail_transition "QC(H$height)->PROTECTED_LIFECYCLE_FINALIZED(H$height)" \
        "timed out waiting for complete durable protected lifecycle finality at H$height"
}

pipeline_record_for() {
    local validator="$1"
    local height="$2"
    find "$(data_for "$validator")/protected-pipeline-v1" -maxdepth 1 -type f \
        -name "h$height-*.json" -print -quit 2>/dev/null
}

normal_pipeline_record_is_complete() {
    local validator="$1"
    local height="$2"
    local source="$3"
    local record
    record="$(pipeline_record_for "$validator" "$height")"
    [[ -n "$record" ]] || return 1
    jq -e --argjson height "$height" --arg source "$source" '
        .format == "synergy-protected-pipeline-v1" and
        .record.target.target_height == $height and
        .record.source == $source and
        (.record.certified_vertices | length) >= 4 and
        .record.cut_proof != null and
        .record.protected_batch != null and
        (.record.observations.parent_proposals | length) > 0 and
        (.record.observations.reveal_authorizations | length) > 0 and
        (.record.observations.reveal_shares | length) >= 4 and
        .record.execution_input != null and
        (.record.observations.qc_roots | length) > 0 and
        (.record.observations.finality_roots | length) > 0 and
        .record.fault == null
    ' "$record" >/dev/null 2>&1
}

normal_pipeline_first_missing() {
    local validator="$1"
    local height="$2"
    local expected_source="$3"
    local record commitment
    record="$(pipeline_record_for "$validator" "$height")"
    [[ -n "$record" ]] || {
        printf 'ETDAG_INGRESS->DURABLE_TARGET_RECORD\n'
        return
    }
    jq -e --arg source "$expected_source" '.record.source == $source' "$record" >/dev/null 2>&1 || {
        printf 'TARGET_REGISTRATION->EXPECTED_PROTECTED_SOURCE\n'
        return
    }
    jq -e '(.record.certified_vertices | length) >= 4' "$record" >/dev/null 2>&1 || {
        printf 'CIPHERTEXT_INGRESS->AVAILABILITY_QUORUM\n'
        return
    }
    jq -e '.record.cut_proof != null' "$record" >/dev/null 2>&1 || {
        printf 'AVAILABILITY_QUORUM->CUT_READY\n'
        return
    }
    jq -e '.record.protected_batch != null' "$record" >/dev/null 2>&1 || {
        printf 'CUT_READY->ORDER_READY\n'
        return
    }
    jq -e '(.record.observations.parent_proposals | length) > 0' "$record" >/dev/null 2>&1 || {
        printf 'ORDER_READY->PARENT_COMMITMENT\n'
        return
    }
    jq -e '(.record.observations.reveal_authorizations | length) > 0' "$record" >/dev/null 2>&1 || {
        printf 'PARENT_COMMITMENT->REVEAL_AUTHORIZED\n'
        return
    }
    jq -e '(.record.observations.reveal_shares | length) >= 4' "$record" >/dev/null 2>&1 || {
        printf 'REVEAL_AUTHORIZED->REVEAL_QUORUM\n'
        return
    }
    while IFS= read -r commitment; do
        [[ -n "$commitment" ]] || continue
        jq -e --arg id "$commitment" --argjson height "$height" '
            .format == "synergy-posy-protected-ciphertext-material-v1" and
            .semantic_id == $id and .target_height == $height and
            .object.encrypted_submission != null
        ' "$(data_for "$validator")/posy-v3-protected-ciphertexts/$commitment.json" >/dev/null 2>&1 || {
            printf 'REVEAL_QUORUM->CIPHERTEXT_RETRIEVED\n'
            return
        }
    done < <(jq -r '.record.protected_batch.ordered_transaction_ids[]? // empty' "$record")
    jq -e '.record.execution_input != null' "$record" >/dev/null 2>&1 || {
        printf 'CIPHERTEXT_RETRIEVED->DECRYPTION_VERIFIED\n'
        return
    }
    jq -e '(.record.observations.qc_roots | length) > 0' "$record" >/dev/null 2>&1 || {
        printf 'EXECUTION_INPUT_READY->QC\n'
        return
    }
    jq -e '(.record.observations.finality_roots | length) > 0' "$record" >/dev/null 2>&1 || {
        printf 'QC->FINALIZED\n'
        return
    }
    printf 'UNKNOWN_PROTECTED_PIPELINE_TRANSITION\n'
}

wait_for_normal_pipeline_finality() {
    local height="$1"
    local source="$2"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        all_found=1
        for validator in "${VALIDATORS[@]}"; do
            normal_pipeline_record_is_complete "$validator" "$height" "$source" || all_found=0
        done
        (( all_found == 1 )) && return
        sleep 0.05
    done
    validator="${VALIDATORS[0]}"
    fail_transition "$(normal_pipeline_first_missing "$validator" "$height" "$source")" \
        "H$height normal protected pipeline failed on $validator; inspect $work_dir/logs/$validator.log"
}

assert_block_timing() {
    local timing="$work_dir/evidence/finality-arrivals.tsv"
    local report="$work_dir/evidence/block-timing-ms.tsv"
    awk -F '\t' -v min="$MIN_BLOCK_INTERVAL_MS" -v max="$MAX_BLOCK_INTERVAL_MS" '
        NR == 1 { previous_height = $1; previous_ms = $2; next }
        {
            delta = $2 - previous_ms
            print previous_height "->" $1 "\t" delta
            if (previous_height >= 3 && $1 <= 20 && (delta < min || delta > max)) {
                bad = 1
            }
            previous_height = $1
            previous_ms = $2
        }
        END {
            if (previous_height < 20) bad = 1
            exit bad
        }
    ' "$timing" >"$report" || fail "observed finalized block interval is outside ${MIN_BLOCK_INTERVAL_MS}-${MAX_BLOCK_INTERVAL_MS} ms; inspect $report"
    local steady_samples="$work_dir/evidence/block-timing-steady-state-ms.txt"
    awk -F '\t' '$1 ~ /^(3|4|5|6|7|8|9|1[0-9])->/ { print $2 }' "$report" | sort -n >"$steady_samples"
    local sample_count p50_index p95_index
    sample_count="$(wc -l <"$steady_samples" | tr -d ' ')"
    [[ "$sample_count" == "17" ]] || fail "expected 17 H3-H20 timing intervals, found $sample_count"
    block_time_min_ms="$(sed -n '1p' "$steady_samples")"
    p50_index=$(( (sample_count + 1) / 2 ))
    p95_index=$(( (sample_count * 95 + 99) / 100 ))
    block_time_p50_ms="$(sed -n "${p50_index}p" "$steady_samples")"
    block_time_p95_ms="$(sed -n "${p95_index}p" "$steady_samples")"
    block_time_max_ms="$(sed -n "${sample_count}p" "$steady_samples")"
    [[ "$block_time_min_ms" =~ ^[0-9]+$ && "$block_time_p50_ms" =~ ^[0-9]+$ && \
       "$block_time_p95_ms" =~ ^[0-9]+$ && "$block_time_max_ms" =~ ^[0-9]+$ ]] || \
        fail "could not compute steady-state block timing statistics"
}

restart_and_assert_replay() {
    local restart_index=4
    local validator="${VALIDATORS[$restart_index]}"
    local previous_pid="${pids[$restart_index]}"
    local log="$work_dir/logs/$validator.log"
    local starts_before finality_before lifecycle_before continued_height highest=0 observed index
    starts_before="$(rg -F -c 'Starting finalized simplified PoSy consensus worker' "$log" || true)"
    assert_finality_record "$validator" "$REQUIRED_FINALIZED_HEIGHT" || fail "cannot restart $validator without durable H$REQUIRED_FINALIZED_HEIGHT WAL"
    finality_before="$(shasum -a 256 "$(finality_record_for "$validator" "$REQUIRED_FINALIZED_HEIGHT")" | awk '{print $1}')"
    lifecycle_before="$(find "$(data_for "$validator")/protected-pipeline-v1/lifecycle" -type f -name 'h20-*.json' -exec shasum -a 256 {} \; 2>/dev/null | awk '{print $1}' | head -1)"
    [[ -n "$lifecycle_before" ]] || fail "cannot restart $validator without durable H20 lifecycle evidence"

    for index in "${!VALIDATORS[@]}"; do
        observed="$(highest_finality_height "${VALIDATORS[$index]}")"
        (( observed > highest )) && highest=$observed
    done
    (( highest >= REQUIRED_FINALIZED_HEIGHT )) || fail "restart test observed no durable H20-or-later chain tip"
    continued_height=$(( highest + POST_RESTART_FINALITY_ADVANCE ))
    printf 'offline_validator=%s\npre_stop_highest_finalized=%s\nrequired_four_of_five_finalized=%s\n' \
        "$validator" "$highest" "$continued_height" >"$work_dir/evidence/validator-06-restart-plan.txt"

    kill -TERM "$previous_pid" 2>/dev/null || fail "could not stop $validator for local restart test"
    wait "$previous_pid" 2>/dev/null || true
    pids[$restart_index]=""
    # Three new QCs are required before the post-restart target can itself be
    # finalized.  This explicitly proves 4/5 liveness while the node is down.
    wait_for_four_validator_finality "$continued_height" "$restart_index"
    start_node "$restart_index"

    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        local starts_now
        starts_now="$(rg -F -c 'Starting finalized simplified PoSy consensus worker' "$log" || true)"
        if (( starts_now > starts_before )) \
            && assert_finality_record "$validator" "$continued_height" \
            && assert_lifecycle_finality "$validator" "$REQUIRED_FINALIZED_HEIGHT"; then
            [[ "$(shasum -a 256 "$(finality_record_for "$validator" "$REQUIRED_FINALIZED_HEIGHT")" | awk '{print $1}')" == "$finality_before" ]] \
                || fail "restart rewrote durable H$REQUIRED_FINALIZED_HEIGHT finality evidence"
            [[ "$(find "$(data_for "$validator")/protected-pipeline-v1/lifecycle" -type f -name 'h20-*.json' -exec shasum -a 256 {} \; 2>/dev/null | awk '{print $1}' | head -1)" == "$lifecycle_before" ]] \
                || fail "restart rewrote durable H20 protected lifecycle evidence"
            assert_same_finalized_block "$continued_height"
            wait_for_full_four_peer_mesh
            return
        fi
        sleep 0.05
    done
    fail_transition "DURABLE_REPLAY->REJOIN_FINALIZED(H$continued_height)" \
        "$validator restart did not rejoin the production simplified worker and finalize H$continued_height"
}

genesis=""
registry_dir=""
desired_state=""
desired_state_sha256=""
release_approval=""
authority_record=""
release_candidate=""
validator_binary="$runtime_root/target/debug/synergy-validator-node"
work_dir=""
timeout_secs=180
configs=("" "" "" "" "")
keys=("" "" "" "" "")
pids=("" "" "" "" "")
validator_addresses=("" "" "" "" "")
p2p_ports=("" "" "" "" "")
rpc_ports=("" "" "" "" "")
mesh_targets=("" "" "" "" "")
finality_observer_pid=""

while (( $# > 0 )); do
    case "$1" in
        --genesis) genesis="${2:-}"; shift 2 ;;
        --ingress-kem-registry-dir) registry_dir="${2:-}"; shift 2 ;;
        --desired-state) desired_state="${2:-}"; shift 2 ;;
        --desired-state-sha256) desired_state_sha256="${2:-}"; shift 2 ;;
        --release-approval) release_approval="${2:-}"; shift 2 ;;
        --authority-record) authority_record="${2:-}"; shift 2 ;;
        --release-candidate) release_candidate="${2:-}"; shift 2 ;;
        --binary) validator_binary="${2:-}"; shift 2 ;;
        --work-dir) work_dir="${2:-}"; shift 2 ;;
        --timeout-secs) timeout_secs="${2:-}"; shift 2 ;;
        --validator-02-config) configs[0]="${2:-}"; shift 2 ;;
        --validator-02-key) keys[0]="${2:-}"; shift 2 ;;
        --validator-03-config) configs[1]="${2:-}"; shift 2 ;;
        --validator-03-key) keys[1]="${2:-}"; shift 2 ;;
        --validator-04-config) configs[2]="${2:-}"; shift 2 ;;
        --validator-04-key) keys[2]="${2:-}"; shift 2 ;;
        --validator-05-config) configs[3]="${2:-}"; shift 2 ;;
        --validator-05-key) keys[3]="${2:-}"; shift 2 ;;
        --validator-06-config) configs[4]="${2:-}"; shift 2 ;;
        --validator-06-key) keys[4]="${2:-}"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[[ -n "$genesis" ]] || fail "--genesis is required"
[[ -n "$registry_dir" ]] || fail "--ingress-kem-registry-dir is required"
[[ -n "$desired_state" ]] || fail "--desired-state is required"
[[ -n "$desired_state_sha256" ]] || fail "--desired-state-sha256 is required"
[[ -n "$release_approval" ]] || fail "--release-approval is required"
[[ -n "$authority_record" ]] || fail "--authority-record is required"
[[ -n "$release_candidate" ]] || fail "--release-candidate is required"
[[ "$timeout_secs" =~ ^[1-9][0-9]*$ ]] || fail "--timeout-secs must be a positive integer"

if [[ -z "$work_dir" ]]; then
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/synergy-r11-production-role.XXXXXX")"
else
    [[ ! -e "$work_dir" ]] || fail "--work-dir must not already exist: $work_dir"
    mkdir -p "$work_dir"
fi
mkdir -p "$work_dir/evidence"
trap stop_nodes EXIT INT TERM

[[ -f "$validator_binary" && -x "$validator_binary" ]] || fail_transition \
    "BUILD->SYNERGY_VALIDATOR_NODE" \
    "required executable production validator binary is missing: $validator_binary"

validate_artifacts
for validator in "${VALIDATORS[@]}"; do
    prepare_workspace "$validator"
done

# The production role preflight verifies the signed release/Genesis binding,
# profile, and local key binding before the harness starts networking. This is
# intentionally repeated per isolated node because a single success proves
# nothing about the other four custody/configuration bindings.
for index in "${!VALIDATORS[@]}"; do
    validator="${VALIDATORS[$index]}"
    node_dir="$(workspace_for "$validator")"
    data_dir="$(data_for "$validator")"
    preflight_log="$work_dir/evidence/$validator-preflight.log"
    (
        cd "$node_dir"
        export SYNERGY_PROJECT_ROOT="$node_dir"
        export SYNERGY_CONFIG_PATH="$node_dir/config/node.toml"
        export SYNERGY_DATA_PATH="$data_dir"
        export SYNERGY_GENESIS_FILE="$genesis"
        export SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE="${keys[$index]}"
        export_release_binding "$node_dir"
        exec "$validator_binary" preflight-release --config "$node_dir/config/node.toml"
    ) >"$preflight_log" 2>&1 || fail "$validator production-role release preflight failed; inspect $preflight_log"
    rg -F 'CHAIN1266_ROLE_RELEASE_PREFLIGHT_VERIFIED' "$preflight_log" >/dev/null || fail "$validator preflight emitted no verified role marker"
done

for index in "${!VALIDATORS[@]}"; do
    start_node "$index"
done

start_finality_observer
wait_for_full_four_peer_mesh
wait_for_log_marker 'Starting finalized simplified PoSy consensus worker'
wait_for_genesis_bootstrap_finality 1
assert_same_finalized_block 1
wait_for_genesis_bootstrap_finality 2
assert_same_finalized_block 2
wait_for_normal_pipeline_finality 3 NORMAL_ETDAG
assert_same_finalized_block 3
wait_for_lifecycle_finality 3
wait_for_normal_pipeline_finality 4 NORMAL_ETDAG_STEADY_STATE
assert_same_finalized_block 4
wait_for_lifecycle_finality 4
for height in $(seq 5 "$REQUIRED_FINALIZED_HEIGHT"); do
    wait_for_finality_height "$height"
    wait_for_normal_pipeline_finality "$height" NORMAL_ETDAG_STEADY_STATE
    assert_same_finalized_block "$height"
    wait_for_lifecycle_finality "$height"
done
await_finality_observer
assert_block_timing
restart_and_assert_replay

cat >"$work_dir/evidence/qualification-summary.txt" <<SUMMARY
H1_H2_BOOTSTRAP_FINALIZED=YES
H3_NORMAL_ETDAG_FINALIZED=YES
H4_STEADY_STATE_FINALIZED=YES
HARNESS_20_BLOCK_PASS=YES
VALIDATOR_RESTART_PASS=YES
BLOCK_TIME_TARGET_MS=${MIN_BLOCK_INTERVAL_MS}-${MAX_BLOCK_INTERVAL_MS}
BLOCK_TIME_MIN_MS=${block_time_min_ms}
BLOCK_TIME_P50_MS=${block_time_p50_ms}
BLOCK_TIME_P95_MS=${block_time_p95_ms}
BLOCK_TIME_MAX_MS=${block_time_max_ms}
FINALIZED_HEIGHT=${REQUIRED_FINALIZED_HEIGHT}
SUMMARY
printf 'R11_PRODUCTION_ROLE_HARNESS_PASS evidence_dir=%s\n' "$work_dir/evidence"
