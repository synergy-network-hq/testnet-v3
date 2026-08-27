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

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runtime_root="$(cd "$script_dir/../.." && pwd)"

usage() {
    cat <<'USAGE'
Usage:
  run-posy-v3-r11-production-role-harness.sh \
    --genesis PATH --ingress-kem-registry-dir PATH \
    --validator-02-config PATH --validator-02-key PATH \
    --validator-03-config PATH --validator-03-key PATH \
    --validator-04-config PATH --validator-04-key PATH \
    --validator-05-config PATH --validator-05-key PATH \
    --validator-06-config PATH --validator-06-key PATH \
    [--binary PATH] [--work-dir PATH] [--timeout-secs SECONDS]

All artifact paths are mandatory and must name the approved fresh-P3 release:

  * Genesis is a signed, fresh Chain 1266 PoSy/3.0 document.
  * Registry directory contains canonical signed ingress-KEM registry artifacts
    for every target H3 through H20, under the runtime's epoch-root directory.
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
    if rg -n -P '(?<!127\.0\.0\.1)(?<!\[::1\])(?<!localhost)\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' "$config" >/dev/null; then
        fail "$label config contains a non-loopback IPv4 address"
    fi
    if ! rg -n '^\s*listen_address\s*=\s*"(127\.0\.0\.1|\[::1\]|localhost):[0-9]+"\s*$' "$config" >/dev/null; then
        fail "$label config must bind P2P listen_address to an explicit loopback address"
    fi
    if rg -n '^\s*(bootnodes|seed_servers|bootstrap_dns_records|register_endpoints|heartbeat_endpoints)\s*=\s*\[[^]]*[^[:space:],\[\]]' "$config" >/dev/null; then
        fail "$label config contains non-local bootstrap or registration endpoints"
    fi
}

validate_registry_directory() {
    local artifact
    local -a artifacts=()
    while IFS= read -r artifact; do
        artifacts+=("$artifact")
    done < <(find "$registry_dir" -type f -name '*.json' -print | LC_ALL=C sort)

    (( ${#artifacts[@]} > 0 )) || fail "ingress KEM registry directory has no JSON artifacts"
    local height
    for height in $(seq 3 "$REQUIRED_FINALIZED_HEIGHT"); do
        local found=0
        for artifact in "${artifacts[@]}"; do
            jq -e --argjson height "$height" '
                .format == "synergy-posy-simplified-ingress-kem-registry-v1" and
                .epoch == 0 and .target_height == $height and
                .registry.registry_version == 1 and
                .registry.chain_id == 1266 and
                .registry.network_id == "testnet" and
                .registry.protocol_version == "posy/3.0" and
                .registry.epoch == 0 and .registry.target_height == $height and
                (.registry.records | length) == 5
            ' "$artifact" >/dev/null 2>&1 || continue
            found=1
            break
        done
        (( found == 1 )) || fail "missing signed/canonical-shaped fresh-P3 ingress KEM registry for H${height}"
    done
}

validate_artifacts() {
    require_file "$genesis"
    require_directory "$registry_dir"
    command -v jq >/dev/null || fail "jq is required for fail-closed artifact checks"
    command -v perl >/dev/null || fail "perl with Time::HiRes is required for timing evidence"
    command -v rg >/dev/null || fail "rg is required for local-only transport checks"

    assert_no_retired_input "$genesis"
    jq -e '
        .network.chain_id == 1266 and
        .consensus.posy_v3_activation.manifest.protocol_version == "posy/3.0" and
        .consensus.posy_v3_activation.manifest.network_id == "testnet" and
        .consensus.posy_v3_activation.manifest.initial_validator_ids ==
          ["validator-02", "validator-03", "validator-04", "validator-05", "validator-06"]
    ' "$genesis" >/dev/null || fail "Genesis is not the signed fresh-P3 five-validator artifact"

    validate_registry_directory

    local index validator config key parsed
    for index in "${!VALIDATORS[@]}"; do
        validator="${VALIDATORS[$index]}"
        config="${configs[$index]}"
        key="${keys[$index]}"
        require_file "$config"
        require_file "$key"
        assert_no_retired_input "$config"
        assert_local_only_config "$config" "$validator"
        parsed="$($validator_binary validate-config --config "$config" 2>&1)" || fail "$validator config failed runtime parser: $parsed"
        [[ "$parsed" == *"validator_id=$validator"* ]] || fail "$validator config does not bind expected validator identity: $parsed"
        [[ "$parsed" == *'chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3'* ]] || fail "$validator config has an invalid fresh-P3 runtime binding: $parsed"
    done
}

workspace_for() {
    printf '%s/nodes/%s\n' "$work_dir" "$1"
}

prepare_workspace() {
    local validator="$1"
    local node_dir config
    node_dir="$(workspace_for "$validator")"
    config="$(config_for "$validator")"
    mkdir -p "$node_dir/config" "$node_dir/data"
    cp "$config" "$node_dir/config/node.toml"
    # Artifacts are public.  Copying them into each isolated runtime root is
    # required because the production role resolves this read-only source from
    # its own data directory. Keys remain outside the work directory.
    mkdir -p "$node_dir/data/posy-v3-ingress-kem-registries"
    cp -R "$registry_dir/." "$node_dir/data/posy-v3-ingress-kem-registries/"
}

start_node() {
    local index="$1"
    local validator="${VALIDATORS[$index]}"
    local node_dir key log
    node_dir="$(workspace_for "$validator")"
    key="$(key_for "$validator")"
    log="$work_dir/logs/$validator.log"
    mkdir -p "$work_dir/logs"

    (
        cd "$node_dir"
        export SYNERGY_PROJECT_ROOT="$node_dir"
        export SYNERGY_CONFIG_PATH="$node_dir/config/node.toml"
        export SYNERGY_DATA_PATH="$node_dir/data"
        export SYNERGY_GENESIS_FILE="$genesis"
        export SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE="$key"
        exec "$validator_binary" start --config "$node_dir/config/node.toml"
    ) >>"$log" 2>&1 &
    pids[$index]=$!
}

stop_nodes() {
    local index pid
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

finality_record_for() {
    local validator="$1"
    local height="$2"
    local node_dir
    node_dir="$(workspace_for "$validator")"
    find "$node_dir/data/posy-v3-finality" -type f \
        -name "finality-$(printf '%020d' "$height").json" -print -quit 2>/dev/null
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
    local node_dir material
    node_dir="$(workspace_for "$validator")"
    while IFS= read -r material; do
        jq -e --argjson height "$height" '
            .format == "synergy-posy-simplified-protected-material-v3" and
            .candidate_subject.context.height == $height and
            .protected_execution_input != null and
            .protected_execution_input.source == "GENESIS_BOOTSTRAP" and
            .protected_execution_input.target_context.kind == "GENESIS_BOOTSTRAP" and
            .next_protected_batch_commitment != null
        ' "$material" >/dev/null 2>&1 && return 0
    done < <(find "$node_dir/data/posy-v3-protected-material" -maxdepth 1 -type f -name '*.json' -print 2>/dev/null)
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

record_timing_samples() {
    local height record timestamp key
    for height in $(seq 1 "$REQUIRED_FINALIZED_HEIGHT"); do
        key="h$height"
        [[ -n "${seen_heights[$height]:-}" ]] && continue
        record="$(finality_record_for "${VALIDATORS[0]}" "$height")"
        [[ -n "$record" ]] || continue
        assert_finality_record "${VALIDATORS[0]}" "$height" || fail "validator-02 wrote malformed finality WAL at H$height"
        timestamp="$(now_ms)"
        printf '%s\t%s\n' "$height" "$timestamp" >>"$work_dir/evidence/finality-arrivals.tsv"
        seen_heights[$height]="$timestamp"
    done
}

wait_for_finality_height() {
    local height="$1"
    local deadline=$(( $(now_ms) + timeout_secs * 1000 ))
    local validator all_found
    while (( $(now_ms) < deadline )); do
        processes_are_healthy
        record_timing_samples
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
    local node_dir record
    node_dir="$(workspace_for "$validator")"
    record="$(find "$node_dir/data/protected-pipeline-v1/lifecycle" -type f -name "h$height-*.json" -print -quit 2>/dev/null)"
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
    local node_dir
    node_dir="$(workspace_for "$validator")"
    find "$node_dir/data/protected-pipeline-v1" -maxdepth 1 -type f \
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
    local record node_dir commitment
    node_dir="$(workspace_for "$validator")"
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
        ' "$node_dir/data/posy-v3-protected-ciphertexts/$commitment.json" >/dev/null 2>&1 || {
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
}

restart_and_assert_replay() {
    local restart_index=0
    local validator="${VALIDATORS[$restart_index]}"
    local previous_pid="${pids[$restart_index]}"
    local log="$work_dir/logs/$validator.log"
    local starts_before finality_before lifecycle_before continued_height=23
    starts_before="$(rg -F -c 'Starting finalized simplified PoSy consensus worker' "$log" || true)"
    assert_finality_record "$validator" "$REQUIRED_FINALIZED_HEIGHT" || fail "cannot restart $validator without durable H$REQUIRED_FINALIZED_HEIGHT WAL"
    finality_before="$(shasum -a 256 "$(finality_record_for "$validator" "$REQUIRED_FINALIZED_HEIGHT")" | awk '{print $1}')"
    lifecycle_before="$(find "$(workspace_for "$validator")/data/protected-pipeline-v1/lifecycle" -type f -name 'h20-*.json' -exec shasum -a 256 {} \; 2>/dev/null | awk '{print $1}' | head -1)"
    [[ -n "$lifecycle_before" ]] || fail "cannot restart $validator without durable H20 lifecycle evidence"

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
            [[ "$(find "$(workspace_for "$validator")/data/protected-pipeline-v1/lifecycle" -type f -name 'h20-*.json' -exec shasum -a 256 {} \; 2>/dev/null | awk '{print $1}' | head -1)" == "$lifecycle_before" ]] \
                || fail "restart rewrote durable H20 protected lifecycle evidence"
            return
        fi
        sleep 0.05
    done
    fail_transition "DURABLE_REPLAY->REJOIN_FINALIZED(H$continued_height)" \
        "$validator restart did not rejoin the production simplified worker and finalize H$continued_height"
}

genesis=""
registry_dir=""
validator_binary="$runtime_root/target/debug/synergy-validator-node"
work_dir=""
timeout_secs=180
configs=("" "" "" "" "")
keys=("" "" "" "" "")
pids=("" "" "" "" "")
declare -a seen_heights

while (( $# > 0 )); do
    case "$1" in
        --genesis) genesis="${2:-}"; shift 2 ;;
        --ingress-kem-registry-dir) registry_dir="${2:-}"; shift 2 ;;
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
[[ "$timeout_secs" =~ ^[1-9][0-9]*$ ]] || fail "--timeout-secs must be a positive integer"
require_file "$validator_binary"

if [[ -z "$work_dir" ]]; then
    work_dir="$(mktemp -d "${TMPDIR:-/tmp}/synergy-r11-production-role.XXXXXX")"
else
    [[ ! -e "$work_dir" ]] || fail "--work-dir must not already exist: $work_dir"
    mkdir -p "$work_dir"
fi
mkdir -p "$work_dir/evidence"
trap stop_nodes EXIT INT TERM

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
    preflight_log="$work_dir/evidence/$validator-preflight.log"
    (
        cd "$node_dir"
        export SYNERGY_PROJECT_ROOT="$node_dir"
        export SYNERGY_CONFIG_PATH="$node_dir/config/node.toml"
        export SYNERGY_DATA_PATH="$node_dir/data"
        export SYNERGY_GENESIS_FILE="$genesis"
        export SYNERGY_VALIDATOR_MLDSA65_CONSENSUS_PRIVATE_KEY_FILE="${keys[$index]}"
        exec "$validator_binary" preflight-release --config "$node_dir/config/node.toml"
    ) >"$preflight_log" 2>&1 || fail "$validator production-role release preflight failed; inspect $preflight_log"
    rg -F 'CHAIN1266_ROLE_RELEASE_PREFLIGHT_VERIFIED' "$preflight_log" >/dev/null || fail "$validator preflight emitted no verified role marker"
done

for index in "${!VALIDATORS[@]}"; do
    start_node "$index"
done

wait_for_log_marker 'Starting finalized simplified PoSy consensus worker'
wait_for_genesis_bootstrap_finality 1
wait_for_genesis_bootstrap_finality 2
wait_for_normal_pipeline_finality 3 NORMAL_ETDAG
wait_for_normal_pipeline_finality 4 NORMAL_ETDAG_STEADY_STATE
wait_for_lifecycle_finality 3
wait_for_lifecycle_finality 4
wait_for_finality_height "$REQUIRED_FINALIZED_HEIGHT"
assert_same_finalized_block "$REQUIRED_FINALIZED_HEIGHT"
assert_block_timing
restart_and_assert_replay

cat >"$work_dir/evidence/qualification-summary.txt" <<SUMMARY
H1_H2_BOOTSTRAP_FINALIZED=YES
H3_NORMAL_ETDAG_FINALIZED=YES
H4_STEADY_STATE_FINALIZED=YES
HARNESS_20_BLOCK_PASS=YES
VALIDATOR_RESTART_PASS=YES
BLOCK_TIME_TARGET_MS=${MIN_BLOCK_INTERVAL_MS}-${MAX_BLOCK_INTERVAL_MS}
FINALIZED_HEIGHT=${REQUIRED_FINALIZED_HEIGHT}
SUMMARY
printf 'R11_PRODUCTION_ROLE_HARNESS_PASS evidence_dir=%s\n' "$work_dir/evidence"
