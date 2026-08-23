#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
runtime_manifest="$repo_root/runtime/Cargo.toml"
mode="${1:-full}"

case "$mode" in
  static|full) ;;
  *)
    echo "usage: $0 [static|full]" >&2
    exit 2
    ;;
esac

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

cd "$repo_root"

run git diff --check
run git diff --cached --check
run bash -n \
  runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh \
  runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh \
  runtime/scripts/testnet/verify-posy-v3-pr.sh
run cargo fmt --manifest-path "$runtime_manifest" --all -- --check
printf '+ cargo metadata --locked --manifest-path %q --no-deps --format-version 1\n' \
  "$runtime_manifest"
cargo metadata --locked --manifest-path "$runtime_manifest" --no-deps \
  --format-version 1 >/dev/null
printf '+ unzip -t %q\n' \
  launch/PoSy_Consensus_Parameter_Control_Workbook_v3_PROPOSAL.xlsx
unzip -t launch/PoSy_Consensus_Parameter_Control_Workbook_v3_PROPOSAL.xlsx \
  >/dev/null

run python3 - \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_PROPOSAL.json \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_SCHEMA_V4.json \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_PROPOSAL_VERIFICATION.json \
  launch/POSY_V3_PR_DEPENDENCIES.lock.json \
  launch/posy-v3-etdag-governance-inputs/etdag-parameter-manifest.input.json \
  launch/posy-v3-etdag-governance-inputs/etdag-fee-schedule-manifest.input.json \
  launch/posy-v3-etdag-governance-inputs/expected-derivations.json <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    proposal_path,
    schema_path,
    verification_path,
    dependency_lock_path,
    parameter_path,
    fee_path,
    derivations_path,
) = map(Path, sys.argv[1:])

proposal_bytes = proposal_path.read_bytes()
proposal = json.loads(proposal_bytes)
schema = json.loads(schema_path.read_bytes())
verification = json.loads(verification_path.read_bytes())
dependency_lock = json.loads(dependency_lock_path.read_bytes())
parameter = json.loads(parameter_path.read_bytes())
fee = json.loads(fee_path.read_bytes())
derivations = json.loads(derivations_path.read_bytes())

expected_boundary = {
    "schema_version": 4,
    "release_id": "testnet-v3",
    "status": "PROPOSED_NOT_ACTIVATED",
    "governance_approval_id": None,
    "chain_id": 1266,
    "network_id": "testnet",
    "protocol_version": "posy/3.0",
    "activation_boundary": "fresh_genesis_block_zero",
    "activation_epoch": None,
    "activation_height": None,
    "active_validator_count": 5,
    "healthy_path": ["PROPOSAL", "VOTE", "QC"],
    "required_distinct_signers": 4,
    "leader_lease_blocks": 10,
    "chained_qc_commit_depth": 3,
    "allow_quorum_reduction": False,
    "allow_local_leader_election": False,
    "require_single_validator_failure_liveness": True,
    "signer_journal_required": True,
    "safety_halt_on_conflicting_valid_qcs": True,
    "etdag_finality_separation_required": True,
    "protected_execution_binding_required": True,
}
for key, expected in expected_boundary.items():
    actual = proposal.get(key)
    if actual != expected:
        raise SystemExit(f"proposal {key}: expected {expected!r}, found {actual!r}")

if schema.get("properties", {}).get("network_id", {}).get("const") != "testnet":
    raise SystemExit("schema does not freeze technical network_id to testnet")
if schema.get("properties", {}).get("protocol_version", {}).get("const") != "posy/3.0":
    raise SystemExit("schema does not freeze protocol_version to posy/3.0")

checks = {
    "canonical_byte_length": len(proposal_bytes),
    "sha256_file_digest": hashlib.sha256(proposal_bytes).hexdigest(),
    "sha512_file_digest": hashlib.sha512(proposal_bytes).hexdigest(),
    "consensus_parameter_root": hashlib.sha3_512(proposal_bytes).hexdigest(),
}
for key, actual in checks.items():
    expected = verification.get(key)
    if actual != expected:
        raise SystemExit(f"verification {key}: expected {expected!r}, computed {actual!r}")

if verification.get("status") != "PROPOSAL_VERIFIED_NOT_ACTIVATABLE":
    raise SystemExit("proposal verification must remain non-activatable")

expected_dependency_boundary = {
    "schema": "synergy-posy-v3-pr-dependencies-v1",
    "status": "PR_QUALIFICATION_INPUT_NOT_RELEASE_APPROVAL",
    "chain_id": 1266,
    "network_id": "testnet",
    "release_id": "testnet-v3",
    "protocol_version": "posy/3.0",
}
for key, expected in expected_dependency_boundary.items():
    actual = dependency_lock.get(key)
    if actual != expected:
        raise SystemExit(f"dependency lock {key}: expected {expected!r}, found {actual!r}")
for label, revision in (
    ("Core source base", dependency_lock.get("core", {}).get("source_base_revision")),
    ("SynQ", dependency_lock.get("synq", {}).get("revision")),
    (
        "SynQ Aegis submodule",
        dependency_lock.get("synq", {}).get("aegis_pqsynq_submodule_revision"),
    ),
    ("Core vendored Aegis", dependency_lock.get("aegis", {}).get("revision")),
):
    if not isinstance(revision, str) or len(revision) != 40:
        raise SystemExit(f"{label} revision is not a 40-character Git object ID")
    try:
        int(revision, 16)
    except ValueError as error:
        raise SystemExit(f"{label} revision is not lowercase hexadecimal") from error
    if revision.lower() != revision:
        raise SystemExit(f"{label} revision is not lowercase hexadecimal")

for label, artifact in (("parameter", parameter), ("fee", fee)):
    if artifact.get("chain_id") != 1266:
        raise SystemExit(f"{label} artifact chain_id is not 1266")
    if artifact.get("network_id") != "testnet":
        raise SystemExit(f"{label} artifact network_id is not testnet")
    if artifact.get("consensus_protocol_version") != "posy/3.0":
        raise SystemExit(f"{label} artifact protocol is not posy/3.0")

if derivations.get("status") != "UNSIGNED_INPUTS_AWAITING_FROZEN_AUTHORITY_RELEASE_APPROVAL":
    raise SystemExit("ETDAG derivations must remain explicitly unsigned before approval")

print("PoSy V3 static artifact invariants passed")
PY

dependency_lock=launch/POSY_V3_PR_DEPENDENCIES.lock.json
source_base="$(jq -er '.core.source_base_revision' "$dependency_lock")"
if git show-ref --verify --quiet refs/remotes/origin/main; then
  actual_source_base="$(git merge-base HEAD origin/main)"
  [[ "$actual_source_base" == "$source_base" ]] || {
    echo "P3 dependency lock source base is stale: $source_base != $actual_source_base" >&2
    exit 1
  }
fi

synq_root="$(cd runtime/src/../../../synq-language && pwd -P)"
expected_synq="$(jq -er '.synq.revision' "$dependency_lock")"
expected_synq_aegis="$(jq -er '.synq.aegis_pqsynq_submodule_revision' "$dependency_lock")"
expected_core_aegis="$(jq -er '.aegis.revision' "$dependency_lock")"
[[ "$(git -C "$synq_root" rev-parse HEAD)" == "$expected_synq" ]]
[[ "$(git -C "$synq_root" rev-parse HEAD:aegis-pqsynq)" == "$expected_synq_aegis" ]]
[[ "$(git -C "$synq_root/aegis-pqsynq" rev-parse HEAD)" == "$expected_synq_aegis" ]]
[[ "$(git rev-parse HEAD:runtime/aegis-pqvm)" == "$expected_core_aegis" ]]
[[ -z "$(git status --porcelain -- runtime/aegis-pqvm)" ]]
echo "PoSy V3 dependency-lock identities passed"

if [[ "$mode" == "static" ]]; then
  echo "PoSy V3 static PR verification passed"
  exit 0
fi

evidence_root="${POSY_V3_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/posy-v3-pr-evidence.XXXXXX")}"
mkdir -p "$evidence_root"
printf '%s\n' "$evidence_root" >"$evidence_root/evidence-directory.txt"

scrub_ephemeral_harness_keys() {
  local harness_dir
  for harness_dir in \
    "$evidence_root/state-machine-five-node" \
    "$evidence_root/production-driver-five-node"
  do
    if [[ -d "$harness_dir" ]]; then
      find "$harness_dir" -maxdepth 1 -type f \
        -name 'validator-*-private-key.msgpack' -delete
    fi
  done
}
trap scrub_ephemeral_harness_keys EXIT

run_test_family() {
  local evidence_name="$1"
  local test_filter="$2"
  local list_path="$evidence_root/test-${evidence_name}.list"
  local log_path="$evidence_root/test-${evidence_name}.log"
  local test_count

  printf '+ cargo test --locked --manifest-path %q --package synergy-testnet --lib %q -- --list\n' \
    "$runtime_manifest" "$test_filter"
  cargo test --locked --manifest-path "$runtime_manifest" \
    --package synergy-testnet --lib "$test_filter" -- --list \
    | tee "$list_path"
  test_count="$(grep -c ': test$' "$list_path" || true)"
  if [[ ! "$test_count" =~ ^[1-9][0-9]*$ ]]; then
    echo "test family $evidence_name selected zero tests with filter $test_filter" >&2
    exit 1
  fi

  printf '+ cargo test --locked --manifest-path %q --package synergy-testnet --lib %q -- --test-threads=1\n' \
    "$runtime_manifest" "$test_filter"
  cargo test --locked --manifest-path "$runtime_manifest" \
    --package synergy-testnet --lib "$test_filter" -- --test-threads=1 \
    | tee "$log_path"
}

run_test_family simplified-consensus 'consensus::simplified_posy::'
run_test_family simplified-parameter-loader 'posy_simplified_parameters::tests::'
run_test_family finalized-parameter-loader 'consensus_parameters::tests::'
run_test_family etdag-governance 'etdag_governance::tests::'
run_test_family release-approval 'testnet_v3_release_approval::tests::'
run_test_family genesis 'genesis::tests::'
run_test_family etdag-admission 'testnet_v3_etdag_admission::tests::'
run_test_family execution-bootstrap 'testnet_v3_execution_bootstrap::tests::'
run_test_family production-role-runtime 'role_runtime::tests::'
run_test_family p2p-message-framing 'p2p::messages::tests::'
run_test_family p2p-simplified-networking 'p2p::networking::tests::simplified_'

printf '+ runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh %q\n' \
  "$evidence_root/state-machine-five-node"
runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh \
  "$evidence_root/state-machine-five-node" \
  | tee "$evidence_root/state-machine-five-node-report.json"

printf '+ runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh %q\n' \
  "$evidence_root/production-driver-five-node"
runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh \
  "$evidence_root/production-driver-five-node" \
  | tee "$evidence_root/production-driver-five-node-report.json"

run python3 - \
  "$evidence_root/state-machine-five-node-report.json" \
  "$evidence_root/production-driver-five-node-report.json" <<'PY'
import json
import sys
from pathlib import Path

state_machine = json.loads(Path(sys.argv[1]).read_text())
driver = json.loads(Path(sys.argv[2]).read_text())

if state_machine.get("status") != "PASS":
    raise SystemExit("state-machine five-node harness did not report PASS")
if driver.get("status") != "passed":
    raise SystemExit("production-driver five-node harness did not report passed")

required_state_scenarios = {
    "one_unavailable_four_of_five_qc_progress",
    "two_unavailable_three_of_five_fail_closed",
    "three_qc_chained_finality",
    "two_sequential_tc_lease_inheritance",
    "restart_preserves_verified_takeover",
    "restart_preserves_last_vote_and_signer_journal",
    "ten_block_lease_and_boundary_reset",
}
required_driver_scenarios = {
    "four_of_five_autonomous_progress",
    "three_of_five_fail_closed",
    "real_timer_leader_takeover",
    "future_qc_state_sync_heal",
    "durable_process_restart",
    "three_chain_finalization",
}
missing_state = required_state_scenarios - set(state_machine.get("scenarios", []))
missing_driver = required_driver_scenarios - set(driver.get("scenarios", []))
if missing_state:
    raise SystemExit(f"state-machine harness omitted scenarios: {sorted(missing_state)}")
if missing_driver:
    raise SystemExit(f"production-driver harness omitted scenarios: {sorted(missing_driver)}")
if driver.get("parent_constructed_votes_qcs_tcs") is not False:
    raise SystemExit("production-driver parent must not construct consensus authority")

print("PoSy V3 harness reports contain the required evidence")
PY

cat >"$evidence_root/verification-status.json" <<'JSON'
{"schema":"synergy-posy-v3-pr-verification-status-v1","chain_id":1266,"network_id":"testnet","release_id":"testnet-v3","protocol_version":"posy/3.0","focused_test_families":11,"focused_tests":"PASS","state_machine_five_node_harness":"PASS","production_driver_five_node_harness":"PASS"}
JSON

echo "PoSy V3 full PR verification passed; evidence: $evidence_root"
