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
  "five_of_six_signer_subsets|consensus::typed_coordinator::tests::equivalent_timeout_certificates_with_different_strict_quorum_subsets_are_not_conflicts"
  "carry_and_no_carry_timeout|consensus::typed_coordinator::tests::mixed_prepared_and_plain_timeout_votes_advance_one_round"
  "different_proof_roots_same_candidate|consensus::typed_coordinator::tests::timeout_certificate_canonicalizes_vc_roots_for_one_prepared_candidate"
  "randomized_vote_signatures|consensus::typed_coordinator::tests::randomized_signature_replay_keeps_one_vote_subject"
  "certificate_before_proposal|consensus::typed_coordinator::tests::future_round_validation_certificate_waits_for_its_proposal_envelope"
  "proposal_before_supporting_certificate|consensus::typed_coordinator::tests::six_validator_driver_finalizes_healthy_round_without_waiting_for_deadlines"
  "missed_proposal|consensus::typed_coordinator::tests::six_validator_driver_recovers_carried_candidate_for_missing_next_proposer"
  "missed_validation_certificate|consensus::typed_coordinator::tests::six_validator_driver_survives_startup_loss_two_timeout_rounds_and_first_finality"
  "missed_finality_certificate|consensus::typed_coordinator::tests::six_validator_driver_recovers_a_missed_finality_qc_then_continues_together"
  "crash_after_sign_before_send|crypto::aegis_pqvm::tests::consensus_vote_restart_replays_the_exact_durable_randomized_signature"
  "crash_after_send_before_persistence|consensus::typed_coordinator::tests::driver_deduplicates_only_exact_authenticated_vote_replays"
  "crash_during_atomic_persistence|consensus::signing_authority::tests::atomic_recovery_checkpoint_survives_interrupted_temp_write_and_rejects_tampering"
  "journal_compaction_retirement_watermark|consensus::signing_authority::tests::retirement_watermark_compacts_long_journals_and_rejects_inconsistent_history"
  "delayed_validator_startup|consensus::typed_coordinator::tests::six_validator_driver_survives_startup_loss_two_timeout_rounds_and_first_finality"
  "messages_before_coordinator_readiness|consensus::typed_coordinator::tests::authenticated_messages_buffer_before_mailbox_install_and_drain_in_order"
  "duplicate_and_replay_floods|consensus::typed_coordinator::tests::driver_deduplicates_only_exact_authenticated_vote_replays"
  "out_of_order_future_round_evidence|consensus::typed_coordinator::tests::future_round_validation_certificate_waits_for_its_proposal_envelope"
  "multiple_consecutive_timeout_rounds|consensus::typed_coordinator::tests::six_validator_driver_survives_startup_loss_two_timeout_rounds_and_first_finality"
  "later_round_checkpoint_recovery|consensus::typed_coordinator::tests::verified_round_one_hundred_timeout_recovers_and_persists_round_authority"
  "observer_stale_finality_injection|consensus::typed_coordinator::tests::observer_identity_cannot_advertise_a_validator_recovery_checkpoint"
  "old_incarnation_precrypto_rejection|p2p::networking::tests::old_chain_incarnation_handshake_is_rejected_before_pq_verification"
  "stale_finalized_height_precrypto_rejection|consensus::typed_coordinator::tests::authenticated_finalized_height_retries_are_ignored_before_pq_verification"
  "real_mldsa_six_validator_burn_in|consensus::typed_coordinator::tests::six_validator_actual_mldsa_multi_height_burn_in_preserves_round_zero_liveness"
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
report = {
    "schema_version": 1,
    "ring": 1,
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
    "real_mldsa": True,
    "mldsa65_transport_authentication": {
        "unit_guard": "validator_handshake_never_falls_back_to_the_fndsa_peer_identity",
        "ring1_proof": "real_mldsa_six_validator_burn_in",
        "ring2_proof": "p2p_verified_handshakes_total{algorithm=ML-DSA-65}",
    },
    "validator_count": 6,
    "quorum": 5,
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
