#!/usr/bin/env bash
# Deterministically bind one final R11 validator binary and five rendered
# configurations into the canonical fresh-P3 desired-state schema.

set -euo pipefail

readonly VALIDATORS=(validator-02 validator-03 validator-04 validator-05 validator-06)

fail() {
    printf 'R11_DESIRED_STATE_REFRESH_FAILED: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
Usage:
  prepare-posy-v3-r11-harness-desired-state.sh \
    --builder PATH --binary PATH --genesis PATH --config-dir DIR \
    --release-id ID --release-tag TAG \
    --testnet-revision SHA --synq-revision SHA --aegis-revision SHA \
    --output PATH

The binary must expose `build-provenance` and must have been compiled with the
same three source revisions supplied here. The output path must not exist.
USAGE
    exit 2
}

require_file() {
    [[ -f "$1" && -r "$1" ]] || fail "required readable file is missing: $1"
}

require_executable() {
    [[ -f "$1" && -x "$1" ]] || fail "required executable is missing: $1"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

builder=""
binary=""
genesis=""
config_dir=""
release_id=""
release_tag=""
testnet_revision=""
synq_revision=""
aegis_revision=""
output=""

while (( $# > 0 )); do
    case "$1" in
        --builder) builder="${2:-}"; shift 2 ;;
        --binary) binary="${2:-}"; shift 2 ;;
        --genesis) genesis="${2:-}"; shift 2 ;;
        --config-dir) config_dir="${2:-}"; shift 2 ;;
        --release-id) release_id="${2:-}"; shift 2 ;;
        --release-tag) release_tag="${2:-}"; shift 2 ;;
        --testnet-revision) testnet_revision="${2:-}"; shift 2 ;;
        --synq-revision) synq_revision="${2:-}"; shift 2 ;;
        --aegis-revision) aegis_revision="${2:-}"; shift 2 ;;
        --output) output="${2:-}"; shift 2 ;;
        --help|-h) usage ;;
        *) fail "unknown argument: $1" ;;
    esac
done

for value in "$builder" "$binary" "$genesis" "$config_dir" "$release_id" \
    "$release_tag" "$testnet_revision" "$synq_revision" "$aegis_revision" "$output"; do
    [[ -n "$value" ]] || usage
done

require_executable "$builder"
require_executable "$binary"
require_file "$genesis"
[[ -d "$config_dir" && -r "$config_dir" ]] || fail "configuration directory is missing: $config_dir"
[[ ! -e "$output" ]] || fail "refusing to overwrite desired state: $output"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v cmp >/dev/null 2>&1 || fail "cmp is required"
for revision in "$testnet_revision" "$synq_revision" "$aegis_revision"; do
    [[ "$revision" =~ ^[0-9a-f]{40}$ && ! "$revision" =~ ^0+$ ]] || \
        fail "every source revision must be a full nonzero lowercase Git SHA"
done

provenance="$($binary build-provenance 2>/dev/null)" || \
    fail "validator binary did not emit build provenance"
jq -e \
    --arg testnet "$testnet_revision" \
    --arg synq "$synq_revision" \
    --arg aegis "$aegis_revision" '
        .schema_version == 1 and
        .artifact == "synergy-validator-node" and
        .source == {
            testnet_v3_revision: $testnet,
            synq_revision: $synq,
            aegis_revision: $aegis
        }
    ' <<<"$provenance" >/dev/null || \
    fail "validator binary provenance does not match the requested source revisions"

configurations=()
for validator in "${VALIDATORS[@]}"; do
    config="$config_dir/$validator/config.toml"
    require_file "$config"
    parsed="$($binary validate-config --config "$config" 2>&1)" || \
        fail "$validator failed the production config parser: $parsed"
    [[ "$parsed" == *"validator_id=$validator"* && \
       "$parsed" == *'chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3'* ]] || \
        fail "$validator config parser did not return the exact fresh-P3 identity"
    configurations+=(--configuration "$validator=$config")
done

output_parent="$(dirname "$output")"
mkdir -p "$output_parent"
temporary="$(mktemp -d "$output_parent/.r11-desired-state.XXXXXX")"
cleanup() {
    [[ -d "$temporary" ]] && rm -rf -- "$temporary"
}
trap cleanup EXIT INT TERM

common=(
    --release-id "$release_id"
    --release-tag "$release_tag"
    --testnet-revision "$testnet_revision"
    --synq-revision "$synq_revision"
    --aegis-revision "$aegis_revision"
    --genesis "$genesis"
    --artifact "validator_node=$binary"
    "${configurations[@]}"
)

"$builder" "${common[@]}" --output "$temporary/desired-state-1.json" >/dev/null
"$builder" "${common[@]}" --output "$temporary/desired-state-2.json" >/dev/null
cmp -s "$temporary/desired-state-1.json" "$temporary/desired-state-2.json" || \
    fail "canonical desired-state builder was not byte-deterministic"

binary_sha="$(sha256_file "$binary")"
jq_args=(--arg release_id "$release_id" --arg release_tag "$release_tag")
jq_args+=(--arg testnet "$testnet_revision" --arg synq "$synq_revision" --arg aegis "$aegis_revision")
jq_args+=(--arg binary_sha "$binary_sha")
for validator in "${VALIDATORS[@]}"; do
    jq_args+=(--arg "${validator//-/_}_sha" "$(sha256_file "$config_dir/$validator/config.toml")")
done
jq -e "${jq_args[@]}" '
    .schema_version == 1 and
    .release_id == $release_id and .release_tag == $release_tag and
    .chain.chain_id == 1266 and .chain.incarnation == 5 and
    .state == {
        consensus_schema_version: 5,
        directory_namespace: "chain-1266/incarnation-5",
        mode: "posy_simplified_v3",
        coordinator_id: "",
        producer_ids: [],
        producer_turn_timeout_ms: 0
    } and
    .source == {
        testnet_v3_revision: $testnet,
        synq_revision: $synq,
        aegis_revision: $aegis
    } and
    .artifacts == {validator_node: $binary_sha} and
    .configuration == {
        "validator-02": $validator_02_sha,
        "validator-03": $validator_03_sha,
        "validator-04": $validator_04_sha,
        "validator-05": $validator_05_sha,
        "validator-06": $validator_06_sha
    }
' "$temporary/desired-state-1.json" >/dev/null || \
    fail "canonical builder output does not bind the final R11 release inputs"

mv "$temporary/desired-state-1.json" "$output"
printf 'R11_DESIRED_STATE_REFRESHED=YES\n'
printf 'DESIRED_STATE_SHA256=%s\n' "$(sha256_file "$output")"
printf 'DESIRED_STATE=%s\n' "$output"
