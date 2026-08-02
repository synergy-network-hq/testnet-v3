#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
runtime="$root/runtime/src"
report_dir="${CHAIN1266_QUALIFICATION_REPORT_DIR:-$root/launch/chain1266-qualification/ring1}"
mkdir -p "$report_dir"
started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
source_revision="${CHAIN1266_TESTNET_REVISION:-$(git -C "$root" rev-parse HEAD)}"
synq_revision="${CHAIN1266_SYNQ_REVISION:-$(git -C "$root/../synq-language" rev-parse HEAD)}"
aegis_revision="${CHAIN1266_AEGIS_REVISION:-$(git -C "$root" rev-parse "HEAD:runtime/aegis-pqvm")}"
for revision in "$source_revision" "$synq_revision" "$aegis_revision"; do
  [[ "$revision" =~ ^[a-f0-9]{40,64}$ ]] || {
    echo "Ring-1 source revision is not a canonical Git object ID" >&2
    exit 1
  }
done
log="$report_dir/fault-matrix.log"
: >"$log"

cases=(
  "canonical_val1_assignment|consensus::coordinated_round_robin::tests::assignments_require_the_canonical_coordinator_key_and_epoch"
  "p1_config_exactly_one_coordinator_five_producers|consensus::coordinated_round_robin::tests::configuration_requires_one_coordinator_and_five_distinct_producers"
  "dedicated_authenticated_consensus_ingress|consensus::coordinated_round_robin::tests::coordinated_messages_require_an_authenticated_session_and_dedicated_mailbox"
  "no_legacy_consensus_fallback|consensus::coordinated_round_robin::tests::coordinated_messages_fail_closed_without_a_running_worker"
  "strict_val2_to_val6_rotation|consensus::coordinated_round_robin::tests::five_producers_rotate_strictly_after_successful_blocks"
  "timeout_skips_turn_not_height|consensus::coordinated_round_robin::tests::missed_turn_advances_producer_not_block_height"
  "replacement_assignment_recovers_lagging_validator|consensus::coordinated_round_robin::tests::lagging_validator_reconstructs_a_signed_replacement_assignment"
  "stale_producer_round_rejected|consensus::coordinated_round_robin::tests::stale_producer_round_is_rejected_after_missed_turn"
  "coordinator_cannot_equivocate_at_height|consensus::coordinated_round_robin::tests::coordinator_cannot_commit_two_hashes_at_one_height"
  "coordinator_cursor_is_durable|consensus::coordinated_round_robin::tests::state_persists_and_recovers_pending_assignment_without_resetting_cursor"
  "assignment_and_block_signatures_are_durable|consensus::coordinated_runtime::tests::assigned_producer_journals_and_replays_the_exact_signed_block"
  "independent_execution_of_user_transaction|consensus::coordinated_runtime::tests::assigned_producer_builds_and_all_validators_verify_an_admitted_user_transaction"
  "runtime_timeout_preserves_height|consensus::coordinated_runtime::tests::timeout_replacement_uses_the_same_height_and_next_scheduled_round"
  "coordinator_persists_committed_finality|consensus::coordinated_runtime::tests::coordinator_finalizes_signed_block_and_repairs_a_persisted_finality_gap"
  "exact_finality_packages_are_anchored|consensus::coordinated_finality_store::tests::persists_exact_packages_from_the_immutable_migration_anchor"
  "support_observer_verifies_without_signing|consensus::coordinated_finality_observer::tests::imports_a_verified_finalized_package_without_signing_authority"
  "user_admission_is_exact_and_deterministic|consensus::coordinated_admission::tests::coordinated_admission_binds_the_exact_user_transaction_and_witness"
  "fresh_reset_requires_genesis_only|role_runtime::tests::fresh_reset_marker_requires_exactly_the_canonical_genesis_block"
  "fresh_reset_rejects_stale_p1_finality|role_runtime::tests::fresh_reset_marker_rejects_stale_coordinated_finality_history"
  "support_roles_are_non_signing_observers|role_runtime::tests::only_support_roles_start_non_signing_coordinated_finality_observer"
)

passed=0
failed_case=""
for entry in "${cases[@]}"; do
  case_id="${entry%%|*}"
  test_name="${entry#*|}"
  printf 'CASE_START id=%s test=%s\n' "$case_id" "$test_name" | tee -a "$log"
  if python3 - "$runtime" "$log" "$test_name" <<'PY'
import os
import pathlib
import signal
import subprocess
import sys

runtime, log, test_name = sys.argv[1:]
command = ["cargo", "test", "--lib", test_name, "--", "--exact", "--nocapture"]
environment = dict(os.environ)
environment["CARGO_BUILD_JOBS"] = "1"
with pathlib.Path(log).open("ab") as output:
    process = subprocess.Popen(
        command,
        cwd=runtime,
        env=environment,
        stdout=output,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    try:
        return_code = process.wait(timeout=600)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        output.write(b"\nCHAIN1266_RING1_CASE_TIMEOUT_SECONDS=600\n")
        return_code = 124
sys.exit(return_code)
PY
  then
    printf 'CASE_PASS id=%s\n' "$case_id" | tee -a "$log"
    passed=$((passed + 1))
  else
    printf 'CASE_FAIL id=%s\n' "$case_id" | tee -a "$log"
    failed_case="$case_id"
    break
  fi
done

finished_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$report_dir/report.json" "$started_utc" "$finished_utc" \
  "$source_revision" "$synq_revision" "$aegis_revision" "$passed" "${#cases[@]}" \
  "$failed_case" <<'PY'
import json
import pathlib
import sys

path, started, finished, testnet, synq, aegis, passed, total, failed_case = sys.argv[1:]
case_ids = [
    entry.split("id=", 1)[1].split(" ", 1)[0]
    for entry in pathlib.Path(path).with_name("fault-matrix.log").read_text().splitlines()
    if entry.startswith("CASE_START id=")
]
report = {
    "schema_version": 2,
    "ring": 1,
    "consensus_mode": "coordinated_round_robin_v1",
    "result": "PASS" if passed == total else "FAIL",
    "started_utc": started,
    "finished_utc": finished,
    "source": {
        "testnet_v3_revision": testnet,
        "synq_revision": synq,
        "aegis_revision": aegis,
    },
    "cases_passed": int(passed),
    "cases_total": int(total),
    "failed_case": failed_case or None,
    "case_ids": case_ids,
    "p1_invariants": {
        "coordinator_id": "validator-1",
        "producer_ids": ["validator-2", "validator-3", "validator-4", "validator-5", "validator-6"],
        "val1_is_not_a_normal_producer": True,
        "timeout_skips_producer_turn_not_height": True,
        "assignment_and_commit_signatures_required": True,
        "all_validators_execute_identically": True,
        "legacy_posy_qc_vc_tc_vote_aggregation_disabled": True,
        "durable_signing_and_restart_replay": True,
        "fresh_reset_requires_block_zero_genesis": True,
        "support_roles_verify_without_signing": True,
    },
    "validator_count": 6,
}
pathlib.Path(path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY
(
  cd "$report_dir"
  sha256sum report.json fault-matrix.log >SHA256SUMS
)
if [[ -n "$failed_case" ]]; then
  printf 'CHAIN1266_RING1_FAIL passed=%s total=%s failed_case=%s report=%s\n' \
    "$passed" "${#cases[@]}" "$failed_case" "$report_dir/report.json" >&2
  exit 1
fi
printf 'CHAIN1266_RING1_PASS cases=%s report=%s\n' "$passed" "$report_dir/report.json"
