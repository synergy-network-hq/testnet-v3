import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import posy_async_rpc_baseline as adapter

SPEC = importlib.util.spec_from_file_location("async_harness_test", Path(__file__).with_name("run-posy-tps-baseline.py"))
harness = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(harness)


class AsyncProofTests(unittest.TestCase):
    def test_native_operator_registry_validation_uses_eof_without_authoring(self):
        h=SimpleNamespace(subprocess=SimpleNamespace(run=lambda *a,**k:None,DEVNULL=object()),BaselineError=ValueError)
        with patch.object(h.subprocess,"run",return_value=SimpleNamespace(returncode=0)) as native:
            adapter.verify_operator_registry(Path('/native/keytool'),Path('/custody/registry.json'),h)
            self.assertEqual(native.call_args.args[0],['/native/keytool','prepare-wallet-admission-session-operator','/custody/registry.json'])
            self.assertIs(native.call_args.kwargs['stdin'],h.subprocess.DEVNULL)
        with patch.object(h.subprocess,"run",return_value=SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(ValueError,"no transaction authored"):
                adapter.verify_operator_registry(Path('/native/keytool'),Path('/custody/registry.json'),h)

    def test_first_use_requires_native_authoring_and_existing_bindings_stay_exact(self):
        public = {"genesis_binding_commitment": {"binding_payload_sha3_256": "a" * 64}}
        view = {"balance_nwei": "100000000000", "nonce": 0, "authorization_binding": None}
        self.assertEqual(adapter.validate_wallet_authority({name: view for name in harness.VALIDATORS}, public), "native_first_use_required")
        with self.assertRaisesRegex(ValueError, "explicit all-validator"):
            adapter.validate_wallet_authority({"val2": view}, public)
        with self.assertRaisesRegex(ValueError, "explicit all-validator"):
            adapter.validate_wallet_authority({"val2": {"nonce": 0}}, public)
        view["authorization_binding"] = public["genesis_binding_commitment"]
        self.assertEqual(adapter.validate_wallet_authority({name: view for name in harness.VALIDATORS}, public), "existing_binding_verified")
        for other in (None, {}, {"binding_payload_sha3_256": "b" * 64}):
            with self.assertRaisesRegex(ValueError, "funding is insufficient"):
                adapter.validate_wallet_authority({**{name: view for name in harness.VALIDATORS}, "val3": {**view, "authorization_binding": other}}, public)

    def test_slow_proof_reader_does_not_block_scheduler_or_queue_more_observers(self):
        entered = threading.Event(); release = threading.Event()
        observer = adapter.SingleFlightObserver(threading.Event())
        def read():
            entered.set()
            if not release.wait(2):
                raise RuntimeError("test did not release blocked reader")
        try:
            self.assertTrue(observer.start(read))
            self.assertTrue(entered.wait(1))
            offered = 0
            for _ in range(20):
                self.assertFalse(observer.poll())
                self.assertFalse(observer.start(lambda: self.fail("queued a second reader")))
                offered += 1
            self.assertEqual(offered, 20)
        finally:
            release.set()
            observer.close()
        self.assertEqual(observer.durations.count, 1)

    def test_observer_failure_cancels_authoring_and_returns_original_error(self):
        cancellation = threading.Event()
        observer = adapter.SingleFlightObserver(cancellation)
        def broken():
            raise RuntimeError("exact invalid proof")
        observer.start(broken)
        self.assertTrue(cancellation.wait(1))
        try:
            with self.assertRaisesRegex(RuntimeError, "exact invalid proof"):
                observer.close()
        finally:
            observer.executor.shutdown(wait=True)


    def test_stage_observations_do_not_invent_skipped_milestones_or_native_tps(self):
        record = {"transaction_id": "tx", "submission_started": True, "submitted_mono": 1,
                  "context_started_mono": 0, "finalized_mono": 20, "accepted": True}
        adapter.record_lifecycle_stage(record, {"lifecycle_status": "execution_completed",
            "stage_evidence": {"completion_root": "native"}}, 10)
        adapter.record_lifecycle_stage(record, {"lifecycle_status": "execution_completed",
            "stage_evidence": {"completion_root": "native"}}, 15)
        totals = adapter.WorkloadTotals(30)
        totals.consume(record)
        stages = totals.processing_stage_summary(30)
        self.assertEqual(stages["execution_completed"]["native_reported_observations"], 1)
        self.assertEqual(stages["certified"]["native_reported_observations"], 0)
        self.assertIsNone(stages["certified"]["actual_stage_tps"])
        self.assertIsNone(stages["execution_completed"]["actual_stage_tps"])
        with self.assertRaisesRegex(ValueError, "stage evidence"):
            adapter.record_lifecycle_stage({}, {"lifecycle_status": "certified"}, 1)

    def test_selected_chain_context_is_universal_and_rejects_cross_network(self):
        response = self.context()
        response["context"]["authority"]["chain_id"] = 9001
        adapter.validate_context(response, "n", 1, 9001)
        with self.assertRaises(ValueError):
            adapter.validate_context(response, "n", 1, 9002)

    def test_operator_context_cannot_substitute_ingress_keys(self):
        authority={"protected":{"ingress_kem_registry":{"records":[{"key":"pinned"}]}}}
        adapter.validate_operator_context({"ingress_kem_registry":{"records":[{"key":"pinned"}]}},authority)
        for response in ({},{"ingress_kem_registry":{"records":[{"key":"other"}]}}):
            with self.assertRaisesRegex(ValueError,"pinned operator"):
                adapter.validate_operator_context(response,authority)

    def context(self):
        return {"profile_id": adapter.PROFILE, "context": {"context_version": 1, "profile_id": adapter.PROFILE,
                "authority": {"chain_id": 1266, "network_id": "n", "epoch": 1, "target_height": 15}}, "ingress_kem_registry": {}}

    def test_context_has_authorization_anchor_without_inclusion_deadline(self):
        response = self.context()
        self.assertEqual(adapter.validate_context(response, "n", 1, 1266)["target_height"], 15)
        for field, value in (("network_id", "other"), ("epoch", 2), ("chain_id", 1)):
            changed = copy.deepcopy(response)
            changed["context"]["authority"][field] = value
            with self.assertRaises(ValueError):
                adapter.validate_context(changed, "n", 1, 1266)
        for value in (None, [], {"context": []}):
            with self.assertRaises(ValueError):
                adapter.validate_context(value, "n", 1, 1266)

    def test_exact_native_receipt_bytes_are_hashed_without_json_reordering(self):
        encoded = b'{"request":{"nonce":0},"identity_authorization":{"z":1,"a":2}}'
        domain = b"SYNERGY_LOCAL_PROCESSING_ADMISSION_RECEIPT_V1"
        expected = hashlib.sha3_512(len(domain).to_bytes(8, "big") + domain + len(encoded).to_bytes(8, "big") + encoded).hexdigest()
        self.assertEqual(adapter.processing_receipt_id(encoded), expected)
        self.assertNotEqual(adapter.processing_receipt_id(encoded), adapter.processing_receipt_id(json.dumps(json.loads(encoded), sort_keys=True).encode()))

    def test_block_mismatch_and_duplicate_receipts_reject(self):
        block = {"height": 100, "block_hash": "block", "state_root": "state", "finality_certificate_id": "qc",
                 "protected_execution_root": "execution", "transactions": [{}], "receipts": [{"transaction_id": "tx"}]}
        views = {name: copy.deepcopy(block) for name in harness.VALIDATORS}
        self.assertEqual(adapter.validate_block_views(views, 100)["height"], 100)
        views["val6"]["state_root"] = "conflict"
        with self.assertRaisesRegex(ValueError, "disagree"):
            adapter.validate_block_views(views, 100)
        block["transactions"].append({})
        block["receipts"].append({"transaction_id": "tx"})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            adapter.validate_block_views({name: block for name in harness.VALIDATORS}, 100)

    def test_observation_gaps_are_never_divided_into_fabricated_block_times(self):
        previous = {"height": 10, "observed_mono": 1.0}
        self.assertEqual(adapter.observe_intervals(previous, {"height": 11, "observed_mono": 3.0}), {"interval_seconds": 2.0, "height_gap": 0})
        self.assertEqual(adapter.observe_intervals(previous, {"height": 14, "observed_mono": 3.0}), {"interval_seconds": None, "height_gap": 3})
        with self.assertRaises(ValueError):
            adapter.observe_intervals(previous, {"height": 9, "observed_mono": 3.0})

    def test_drain_default_is_unbounded_and_explicit_control_is_not_tx_latency(self):
        self.assertIsNone(harness.operational_drain_deadline(SimpleNamespace(), 10))
        self.assertEqual(harness.operational_drain_deadline(SimpleNamespace(drain_timeout_seconds=90), 10), 100)
        for seconds in (0, -1, float("nan"), float("inf"), 86401, True):
            with self.assertRaises(harness.BaselineError):
                harness.operational_drain_deadline(SimpleNamespace(drain_timeout_seconds=seconds), 10)

    def test_exact_unsigned_intent_rejects_changed_signed_fee_or_timestamp(self):
        record = {"sender":"s", "nonce":0, "intent":{"receiver":"r", "amount_nwei":1,"gas_limit":21000,"max_fee_per_gas_nwei":1,"timestamp_unix":100}}
        transaction = {"signature_algorithm":"ML-DSA-87", "unsigned":{"network":{"chain_id":1266,"network_id":"n"},"class":"user","sender":"s","receiver":"r","amount_nwei":1,"nonce":0,"fee_limit":{"gas_limit":21000,"max_fee_per_gas_nwei":1},"timestamp_unix":100,"payload":[]}}
        adapter.validate_finalized_intent(transaction, record, "n", 1266)
        transaction["unsigned"]["fee_limit"]["max_fee_per_gas_nwei"] = 2
        with self.assertRaisesRegex(ValueError, "signed intent"):
            adapter.validate_finalized_intent(transaction, record, "n", 1266)

    def test_rpc_driver_reuses_nonce_only_after_later_exact_inclusion(self):
        self.simulated_async()

    def test_legitimate_first_use_pool_is_not_blocked_by_missing_genesis_binding(self):
        report, _ = self.simulated_async(first_use=True)
        self.assertFalse(report["workload_wallet_authority_verified_all_five"])
        self.assertEqual(set(report["workload_wallet_authority_modes"].values()), {"native_first_use_required"})
        self.assertEqual(report["finalized_transactions"], 3)

    def test_pending_processing_over_thirty_seconds_keeps_empty_blocks_advancing(self):
        report, rows = self.simulated_async(inclusion_delay=45, max_tx=1)
        self.assertGreater(report["observed_client_latency_seconds"]["context_to_finality"]["maximum"], 30)
        self.assertGreater(report["drain"]["seconds_after_offered_window"], 30)
        empty = [row for row in rows if row["kind"] == "common_finalized_block" and row["transaction_count"] == 0]
        self.assertGreater(len(empty), 30)
        self.assertIsNone(report["transaction_latency_limit_seconds"])
        self.assertGreater(report["end_to_end_finalized_tps"], 0)

    def test_cancellation_without_error_text_still_retains_uncertain_accepted_intent(self):
        report, _ = self.simulated_async(inclusion_delay=90, max_tx=1,
            cancel_after_submit=True, failure="KeyboardInterrupt")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["remaining_in_flight"], 1)
        self.assertFalse(report["measurement_complete"])

    def test_explicit_drain_control_preserves_original_nonce_without_resubmit(self):
        self.simulated_async(inclusion_delay=90, max_tx=1, drain_timeout=5, failure="operational drain deadline")

    def test_unhealthy_chain_stops_default_drain_without_resubmit(self):
        self.simulated_async(inclusion_delay=90, max_tx=1, stalled=True, failure="finality stalled")

    def test_future_nonces_share_one_finalized_block_without_fabricated_account_snapshots(self):
        report, rows = self.simulated_async(inclusion_delay=15, max_tx=4, per_wallet=4, batch=True)
        finalized = [row["record"] for row in rows if row["kind"] == "finalized_transfer"]
        self.assertEqual(report["transactions"], [])
        self.assertEqual({r["nonce"] for r in finalized}, {0, 1, 2, 3})
        self.assertEqual(len({r["block_height"] for r in finalized}), 1)
        cohorts = [row["sender_block_cohort"] for row in rows if row["kind"] == "finalized_transfer"]
        self.assertEqual([len(c) for c in cohorts], [4] * 4)

    def test_multiple_independent_wallets_pipeline_future_nonces_with_global_bound(self):
        report, rows = self.simulated_async(inclusion_delay=15, max_tx=8, per_wallet=4, wallet_count=2, batch=True)
        self.assertEqual(report["finalized_transactions"], 8)
        self.assertLessEqual(report["peak_in_flight"], 8)
        self.assertEqual(report["generator_limits"]["per_wallet_in_flight_cap"], 4)
        self.assertEqual({row["record"]["sender"] for row in rows if row["kind"] == "finalized_transfer"}, {"sender", "sender-1"})

    def test_async_wallet_window_32_reserves_each_nonce_once_and_releases_terminal_records(self):
        report, rows = self.simulated_async(inclusion_delay=15, max_tx=32, per_wallet=32, batch=True)
        finalized = [row["record"] for row in rows if row["kind"] == "finalized_transfer"]
        self.assertEqual(report["finalized_transactions"], 32)
        self.assertEqual({r["nonce"] for r in finalized}, set(range(32)))
        self.assertEqual(report["transactions"], [])
        self.assertLessEqual(report["peak_in_flight"], 32)

    def test_ambiguous_accepted_nonce_freezes_wallet_without_resubmit_or_successor(self):
        report, rows = self.simulated_async(inclusion_delay=15, max_tx=4, per_wallet=4, ambiguous=True)
        finalized = [row["record"] for row in rows if row["kind"] == "finalized_transfer"]
        self.assertEqual(report["transactions"], [])
        self.assertEqual([r["nonce"] for r in finalized], [0])
        self.assertTrue(finalized[0]["ambiguous_response"])
        self.assertEqual(report["finalized_transactions"], 1)
        self.assertFalse(report["clean_load_step"])

    def test_same_block_sender_nonce_or_balance_mismatch_fails_closed(self):
        for corrupt in ("nonce", "balance"):
            with self.subTest(corrupt=corrupt):
                self.simulated_async(inclusion_delay=15, max_tx=4, per_wallet=4, batch=True,
                                     corrupt=corrupt, failure="transfer cohort/fee bound")

    def test_due_slots_are_batched_and_expired_offers_are_not_caught_up(self):
        slots, next_slot, missed = adapter.due_offer_slots(1.0, .995, 1000, 8)
        self.assertGreater(len(slots), 1)
        self.assertEqual(missed, 0)
        self.assertGreater(next_slot, 1.0)
        slots, next_slot, missed = adapter.due_offer_slots(1.0, 0, 1000, 8)
        self.assertEqual(len(slots), 8)
        self.assertGreaterEqual(missed, 990)
        self.assertTrue(all(.99 <= slot <= 1 for slot in slots))

    def test_steady_counts_exclude_warmup_and_drain_without_losing_total(self):
        totals = adapter.WorkloadTotals(100, steady_start=25)
        for submitted, admitted, finalized in ((1, 2, 5), (30, 31, 40), (99, 101, 110)):
            totals.consume({"transaction_id": str(submitted), "submission_started": True,
                "submitted_mono": submitted, "context_started_mono": submitted - 1,
                "admitted_mono": admitted, "finalized_mono": finalized, "accepted": True})
        self.assertEqual(totals.counts["finalized"], 3)
        self.assertEqual(totals.counts["submitted_steady"], 2)
        self.assertEqual(totals.counts["admitted_steady"], 1)
        self.assertEqual(totals.counts["finalized_steady"], 1)

    def test_terminal_aggregation_retains_no_payload_or_per_transaction_history(self):
        totals = adapter.WorkloadTotals(100)
        payload = "x" * 1000000
        for i in range(100000):
            totals.consume({"transaction_id": str(i), "submission_started": True,
                "submitted_mono": 2, "context_started_mono": 1, "admitted_mono": 3,
                "finalized_mono": 5, "accepted": True, "submission_response": payload})
        self.assertEqual(totals.counts["finalized"], 100000)
        self.assertEqual(totals.counts["submitted_window"], 100000)
        self.assertEqual(totals.latency_summary()["submission_to_finality"]["maximum"], 3)
        self.assertLess(sum(len(hist.bins) for hist in totals.latencies.values()), 20)
        self.assertNotIn(payload[:100], repr(totals.__dict__))
        self.assertEqual(totals.rejections, [])

    def test_fixed_histogram_counts_and_exact_max_do_not_grow_with_samples(self):
        values = adapter.BoundedDistribution()
        for i in range(100000): values.append((i % 1000) / 10)
        result = values.summary()
        self.assertEqual(result["count"], 100000)
        self.assertEqual(result["maximum"], 99.9)
        self.assertLess(len(values.bins), 3201)
        self.assertGreaterEqual(result["p50"], 49.9)
        self.assertLess(result["p50"], 50.5)

    def simulated_async(self, inclusion_delay=1, max_tx=3, drain_timeout=None, stalled=False, failure=None,
                        per_wallet=1, wallet_count=1, batch=False, ambiguous=False, corrupt=None, first_use=False, cancel_after_submit=False):
        real_sleep = time.sleep
        class Clock:
            value = 0.0
            lock = threading.Lock()
            def monotonic(self):
                with self.lock:
                    return self.value
            def sleep(self, delay):
                with self.lock:
                    self.value += delay
                real_sleep(0.0001)
            def time(self):
                return 1_700_000_000 + self.monotonic()
        clock = Clock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            authority = root / "authority.json"
            authority.write_text(json.dumps({"payload": {"chain_id": 9001, "network_id": "posy-isolated-test", "epoch": 1, "epoch_start_height": 1,
                "protected": {"version": 2, "cutoff_relationship": "processing_groups_v1", "epoch_start_timestamp_ms": 1_700_000_000_000, "target_block_time_ms": 1000}}}))
            registry = root / "registry.json"
            registry.write_text(json.dumps({"chain_id": 9001, "fixture_root":str(root), "authority_binding_path": str(authority), "wallets": [
                {"wallet_id": "wallet", "wallet_public_path": str(root / "public.json"), "transaction_secret_path": str(root / "secret.key")}]}))
            (root / "public.json").write_text(json.dumps({"genesis_binding_commitment": {"fixture": True}}))
            (root / "secret.key").write_bytes(b"not-read-by-python")
            (root / "secret.key").chmod(0o600)
            keytool = root / "keytool"
            keytool.touch()
            keytool.chmod(0o700)
            wallets = [{"wallet_id": "wallet" if i == 0 else f"wallet-{i}",
                        "sender": "sender" if i == 0 else f"sender-{i}"} for i in range(wallet_count)]
            entries = json.loads(registry.read_text())
            entries["wallets"] = [{"wallet_id": w["wallet_id"], "wallet_public_path": str(root / "public.json"),
                                  "transaction_secret_path": str(root / "secret.key")} for w in wallets]
            registry.write_text(json.dumps(entries))
            included = []
            authored_nonces = []
            authored_by_sender = {w["sender"]: [] for w in wallets}
            native_lock = threading.Lock()
            receipt_ids = set()
            def height():
                return 100 + int(min(clock.monotonic(), 15) if stalled else clock.monotonic())
            def fleet(*args, **kwargs):
                self.assertEqual(kwargs["expected_chain_id"], 9001)
                return {name: {"common_height": height(), "height": height(), "native_epoch": 1} for name in harness.VALIDATORS}
            def account(endpoints, address, at, **kwargs):
                own = [tx for tx in included if tx["height"] <= at]
                sender = address in authored_by_sender
                count = sum(tx["transaction"]["unsigned"]["sender"] == address for tx in own) if sender else len(own)
                value = {"authorization_binding": None if first_use and count == 0 else {"fixture": True}, "nonce": count if sender else 0,
                         "balance_nwei": 1000000 - 2 * count if sender else count}
                if sender and count and corrupt == "nonce":
                    value["nonce"] += 1
                if sender and count and corrupt == "balance":
                    value["balance_nwei"] -= 100
                return {**value, "validator_views": {name: value for name in harness.VALIDATORS}}
            def native_sign(argv, **kwargs):
                self.assertEqual(argv[1], "prepare-wallet-processing-admission")
                transfer = json.loads(Path(argv[2]).read_text())
                # This fake boundary proves scheduling, not cryptography (covered natively in keytool tests).
                with native_lock:
                    authored_nonces.append(transfer["nonce"])
                    expected = len(authored_by_sender[transfer["sender"]])
                    self.assertEqual(transfer["nonce"], expected)
                    authored_by_sender[transfer["sender"]].append(transfer["nonce"])
                if per_wallet == 1:
                    self.assertEqual(transfer["nonce"], account({}, transfer["sender"], height())["nonce"])
                Path(argv[3]).write_text(json.dumps({"request": {"transfer": transfer}}, separators=(",", ":")))
                return SimpleNamespace(returncode=0)
            methods = []
            def rpc(url, method, params, **kwargs):
                methods.append(method)
                if method == "synergy_getProcessingContextV1":
                    result = self.context()
                    result["context"]["authority"]["network_id"] = "posy-isolated-test"
                    result["context"]["authority"]["chain_id"] = 9001
                    return result
                if method == "synergy_submitProcessingTransactionV1":
                    transfer = params["request"]["transfer"]
                    txid = harness.transaction_id("posy-isolated-test", transfer["sender"], "receiver", 1, transfer["nonce"], 21000, 1, transfer["timestamp_unix"], chain_id=9001)
                    included.append({"height": 110 + inclusion_delay if batch else height() + inclusion_delay, "transaction": {"signature_algorithm":"ML-DSA-87", "unsigned": {"network":{"chain_id":9001,"network_id":"posy-isolated-test"},"class":"user","sender": transfer["sender"], "receiver": "receiver", "nonce": transfer["nonce"], "amount_nwei": 1, "fee_limit":{"gas_limit":21000,"max_fee_per_gas_nwei":1},"timestamp_unix":transfer["timestamp_unix"],"payload":[]}},
                                     "receipt": {"transaction_id": txid, "status": "applied", "gas_used": 1}})
                    encoded = json.dumps(params, separators=(",", ":")).encode()
                    rid = adapter.processing_receipt_id(encoded)
                    receipt_ids.add(rid)
                    if ambiguous:
                        raise harness.BaselineError("response lost after actual acceptance")
                    return {"receipt_id": rid, "status": "queued"}
                if method == "synergy_getProtectedAdmissionReceipt":
                    self.assertIn(params["receipt_id"], receipt_ids)
                    return {"receipt_id": params["receipt_id"], "status": "accepted", "admitted": True}
                if method == "synergy_getProtectedAdmissionStats":
                    return {"queued_requests": 0}
                if method == "synergy_chainTelemetry":
                    if cancel_after_submit and included:
                        raise KeyboardInterrupt()
                    at = height()
                    return {"chain_id": 9001, "network_identity": "posy-isolated-test", "epoch": 1, "finalized_height": at,
                            "common_finalized_commitment": {"height": at, "block_id": str(at), "state_root": "state", "finality_certificate_id": "qc"}}
                if method == "synergy_getBlock":
                    at = params["height"]
                    own = [tx for tx in included if tx["height"] == at]
                    return {"height": at, "block_hash": str(at), "state_root": "state", "finality_certificate_id": "qc", "protected_execution_root": "execution",
                            "transactions": [tx["transaction"] for tx in own], "receipts": [tx["receipt"] for tx in own]}
                self.fail("unexpected RPC: " + method)
            rows = []
            class CapturingProof(harness.RawProofStream):
                def append(self, value):
                    rows.append(copy.deepcopy(value))
                    return super().append(value)
            h = SimpleNamespace(**{name: getattr(harness, name) for name in ("BaselineError", "VALIDATORS", "MAX_FINALIZED_LAG", "POLL_SECONDS", "operational_drain_deadline", "validate_pool_workload", "pool_offer_slot", "transaction_id", "order_key", "RawProofStream", "RpcResponseError", "utc_now")})
            h.RawProofStream = CapturingProof
            h.wallet_pool_public = lambda *a: wallets
            h.sample_fleet = fleet
            h.tip_record = lambda state: {"height": state["val2"]["height"]}
            h.pool_account = account
            h.rpc = rpc
            h.observe_pool_receipt = lambda url, record: rpc(url, "synergy_getProtectedAdmissionReceipt", {"receipt_id": record["receipt_id"]})
            h.subprocess = SimpleNamespace(run=native_sign, DEVNULL=None)
            args = SimpleNamespace(validator_rpc=[(name, name) for name in harness.VALIDATORS], network_id="posy-isolated-test", workload_mode="offered-rate",
                execute=True, submit_validator="val2", wallet_registry=registry, remote_signer=False, signer_dir=None, operator_wallet_registry=False,
                output=root / "report.json", duration_seconds=12, max_tx=max_tx, rate_tps=float(per_wallet * wallet_count),
                max_in_flight=per_wallet * wallet_count, max_in_flight_per_wallet=per_wallet, stability_seconds=10,
                drain_timeout_seconds=drain_timeout, maximum_gap_seconds=30, receiver="receiver", amount_nwei=1, gas_limit=21000,
                max_fee_per_gas_nwei=1, gas_class_units=21000, fee_class=1, keytool=keytool, raw_proof_stream=None,
                raw_proof_budget_bytes=4*1024*1024, temp_dir=root)
            with patch.object(adapter, "time", clock):
                if failure:
                    with self.assertRaisesRegex(KeyboardInterrupt if cancel_after_submit else harness.BaselineError,
                                                "" if cancel_after_submit else failure):
                        adapter.run_async(args, h)
                    self.assertEqual(authored_nonces, list(range(max_tx)) if corrupt else [0])
                    report = args._partial_report
                    self.assertEqual(report["remaining_in_flight"], max_tx if corrupt else 1)
                    self.assertEqual(report["transactions"][0]["nonce"], 0)
                    self.assertTrue(report["transactions"][0]["submission_started"])
                    self.assertFalse(report["measurement_complete"])
                    return report, []
                report = adapter.run_async(args, h)
            self.assertEqual(report["status"], "completed")
            expected_count = 1 if ambiguous else max_tx
            self.assertEqual(len(authored_nonces), expected_count)
            for nonces in authored_by_sender.values():
                self.assertEqual(nonces, list(range(len(nonces))))
            self.assertEqual(report["finalized_transactions"], expected_count)
            self.assertTrue(report["wallet_effects_verified_all_five"])
            self.assertTrue(report["generator_observer"]["offered_scheduler_independent"])
            self.assertEqual(report["generator_observer"]["maximum_concurrent_reads"], 1)
            self.assertGreater(report["generator_resources"]["process_peak_rss_bytes"], 0)
            self.assertGreaterEqual(report["generator_resources"]["process_cpu_seconds"], 0)
            self.assertTrue(all(record["block_height"] > record["authorization_height"] for record in report["transactions"]))
            self.assertGreaterEqual(report["elapsed_seconds"], 12)
            self.assertNotIn("synergy_getProtectedAdmissionContextV2", methods)
            self.assertNotIn("synergy_submitProtectedTransaction", methods)
            self.assertTrue(report["raw_proof_stream"]["complete"])
            persisted = [json.loads(row) for row in Path(report["raw_proof_stream"]["path"]).read_text().splitlines()]
            self.assertEqual(persisted[0]["kind"], "active_intent_checkpoint")
            self.assertEqual(persisted[0]["active"], [])
            self.assertFalse(any(row["kind"] == "finalized_transfer" for row in persisted))
            self.assertEqual({row["validator"] for row in rows if row["kind"] == "finalized_block_observation"}, set(harness.VALIDATORS))
            return report, rows


if __name__ == "__main__":
    unittest.main()
