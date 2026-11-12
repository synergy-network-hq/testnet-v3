import io
import concurrent.futures
import hashlib
import tempfile
import importlib.util
import json
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SCRIPT = Path(__file__).with_name("run-posy-tps-baseline.py")
SPEC = importlib.util.spec_from_file_location("posy_tps_baseline", SCRIPT)
HARNESS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HARNESS)


class MockRpcHandler(BaseHTTPRequestHandler):
    heights = {"val2": 100, "val3": 101, "val4": 102, "val5": 100, "val6": 101}
    conflicting_validator = None
    unready_validator = None

    def do_POST(self):
        name = self.path.strip("/")
        height = self.heights[name]
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request["method"]
        if method == "synergy_nodeStatus":
            result = {"ready": name != self.unready_validator, "chain_id": 1266}
        elif method == "synergy_getProtectedAdmissionContext":
            result = {"parameters":{"profile_id":"POSY-ETDAG-v3.0","target_height_offset":5},"context": {"chain_id":1266,"source_finalized_height": height,
                                  "target_height": height + 5,
                                  "network_id": "test-network"}}
        elif method == "synergy_getProtectedAdmissionStats":
            result = {"accepted_total": 10, "etdag_ordered_total": 9,
                      "queued_requests": 1, "queued_bytes": 32}
        elif method == "synergy_getBlock":
            block_height = request["params"]["height"]
            if block_height is None:
                block_height = height
            suffix = "-conflict" if name == self.conflicting_validator else ""
            result = {"height": block_height, "block_hash": "common-hash" + suffix,
                      "state_root": "common-state" + suffix,
                      "finality_certificate_id": "common-finality" + suffix}
        else:
            self.send_error(400, "unexpected RPC method")
            return
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class BaselineMockRpcTests(unittest.TestCase):
    def test_cli_default_has_no_transaction_latency_deadline(self):
        with patch("sys.argv", ["run-posy-tps-baseline.py"]):
            args = HARNESS.parse_args()
        self.assertIsNone(args.drain_timeout_seconds)
        self.assertFalse(hasattr(args, "finality_budget_seconds"))
        self.assertEqual(args.maximum_gap_seconds, 30)
        with patch("sys.argv", ["run-posy-tps-baseline.py", "--drain-timeout-seconds", "90"]):
            self.assertEqual(HARNESS.parse_args().drain_timeout_seconds, 90)

    def test_private_vpn_rpc_token_is_explicit_and_not_redirected(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("test-private-run-token")
            token.chmod(0o600)
            try:
                with self.assertRaises(HARNESS.BaselineError):
                    HARNESS.configure_rpc_transport(None, ["100.64.0.2"])
                HARNESS.configure_rpc_transport(token, ["100.64.0.2"])
                self.assertEqual(HARNESS.validate_rpc_url("http://100.64.0.2:28745"),
                                 "http://100.64.0.2:28745")
                with self.assertRaises(HARNESS.BaselineError):
                    HARNESS.validate_rpc_url("http://100.64.0.3:28745")
                with self.assertRaisesRegex(HARNESS.BaselineError, "redirects"):
                    HARNESS.NoRpcRedirect().redirect_request(None, None, None, None, None, None)
                token.chmod(0o644)
                with self.assertRaisesRegex(HARNESS.BaselineError, "private"):
                    HARNESS.configure_rpc_transport(token, ["100.64.0.2"])
            finally:
                HARNESS.configure_rpc_transport()

    def test_rpc_sends_token_header_only_after_private_file_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / "token"
            token.write_text("test-private-run-token")
            token.chmod(0o600)
            try:
                HARNESS.configure_rpc_transport(token)
                opener = unittest.mock.Mock()
                opener.open.return_value = io.BytesIO(b'{"result":123}')
                with patch.object(HARNESS.urllib.request, "build_opener", return_value=opener):
                    self.assertEqual(HARNESS.rpc(self.url, "synergy_chainTelemetry", {}), 123)
                request = opener.open.call_args.args[0]
                self.assertEqual(request.get_header("Authorization"), "Bearer test-private-run-token")
            finally:
                HARNESS.configure_rpc_transport()

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockRpcHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        MockRpcHandler.heights = {"val2": 100, "val3": 101, "val4": 102,
                                  "val5": 100, "val6": 101}
        MockRpcHandler.conflicting_validator = None
        MockRpcHandler.unready_validator = None

    def test_closed_context_is_transient_but_closed_submission_is_fatal(self):
        error = {"jsonrpc": "2.0", "id": 1, "error": {
            "code": -32000, "message": "fresh local protected admission is closed"}}
        def response(*_args, **_kwargs):
            return io.BytesIO(json.dumps(error).encode())
        with patch.object(HARNESS.urllib.request, "urlopen", side_effect=response):
            with self.assertRaises(HARNESS.TransientSampleError):
                HARNESS.rpc(self.url, "synergy_getProtectedAdmissionContext", {})
            with self.assertRaises(HARNESS.TransientSampleError):
                HARNESS.rpc(self.url, "synergy_getProtectedAdmissionContextV2", {})
            with self.assertRaisesRegex(HARNESS.BaselineError, "admission is closed") as caught:
                HARNESS.rpc(self.url, "synergy_submitProtectedTransaction", {})
            self.assertNotIsInstance(caught.exception, HARNESS.TransientSampleError)

        error["error"]["code"] = -32603
        with patch.object(HARNESS.urllib.request, "urlopen", side_effect=response):
            with self.assertRaises(HARNESS.BaselineError) as caught:
                HARNESS.rpc(self.url, "synergy_getProtectedAdmissionContext", {})
            self.assertNotIsInstance(caught.exception, HARNESS.TransientSampleError)

    def test_rpc_rejects_oversized_wire_bytes_before_json_decode(self):
        with patch.object(HARNESS.urllib.request, "urlopen",
                          return_value=io.BytesIO(b" " * (4 * 1024 * 1024 + 1))), \
                patch.object(HARNESS.json, "loads") as decode:
            with self.assertRaisesRegex(HARNESS.BaselineError, "exceeds the 4 MiB bound"):
                HARNESS.rpc(self.url, "synergy_getProtectedAdmissionContextV2", {})
            decode.assert_not_called()

    def test_rpc_does_not_reserialize_the_received_proof(self):
        raw = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "result": {"proof": [1, 2, 3]}}).encode()
        with patch.object(HARNESS.urllib.request, "urlopen", return_value=io.BytesIO(raw)), \
                patch.object(HARNESS.json, "dumps", wraps=json.dumps) as encode:
            self.assertEqual(HARNESS.rpc(self.url, "synergy_getProtectedAdmissionContextV2", {}),
                             {"proof": [1, 2, 3]})
            self.assertEqual(encode.call_count, 1, "only the outgoing RPC request is encoded")

    def test_fresh_context_waits_through_closed_cutoff_until_new_target(self):
        responses = [
            {"error": {"code": -32000, "message": "fresh local protected admission is closed"}},
            {"result": {"context": {"target_height": 105}}},
            {"result": {"context": {"target_height": 106}}},
        ]
        def response(*_args, **_kwargs):
            return io.BytesIO(json.dumps(responses.pop(0)).encode())
        with patch.object(HARNESS.urllib.request, "urlopen", side_effect=response), \
                patch.object(HARNESS.time, "sleep"):
            context = HARNESS.fresh_admission_context(self.url)
        self.assertEqual(context["context"]["target_height"], 106)
        self.assertEqual(responses, [])

    def test_passive_ingress_readiness_does_not_replace_finality_proof(self):
        MockRpcHandler.unready_validator = "val3"
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        def pointer(name):
            return {"network_id":"test-network","state":{"finalized_height":MockRpcHandler.heights[name],"finalized_block_id":"common-hash","state_root":"common-state"}}
        with patch.object(HARNESS, "finalized_peer_pointer", side_effect=pointer):
            states = HARNESS.sample_fleet(endpoints, "test-network", "val2")
        self.assertFalse(states["val3"]["status"]["ready"])
        self.assertEqual(states["val3"]["common_height"], 100)
        self.assertIsNone(states["val3"]["context"])
        MockRpcHandler.conflicting_validator = "val3"
        with patch.object(HARNESS, "finalized_peer_pointer", side_effect=pointer):
            with self.assertRaisesRegex(HARNESS.BaselineError, "durable/RPC disagreement"):
                HARNESS.sample_fleet(endpoints, "test-network", "val2")

    def test_fleet_uses_common_finalized_height_and_reports_lag(self):
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        states = HARNESS.sample_fleet(endpoints, "test-network")
        self.assertEqual(states["val2"]["common_height"], 100)
        self.assertEqual(states["val2"]["block_hash"], "common-hash")
        self.assertEqual({name: state["lag_blocks"] for name, state in states.items()},
                         {"val2": 2, "val3": 1, "val4": 0, "val5": 2, "val6": 1})
        self.assertEqual(states["val4"]["distance_above_common"], 2)

    def test_fleet_far_behind_is_rejected_by_two_block_bound(self):
        MockRpcHandler.heights["val5"] = 96
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        with self.assertRaisesRegex(HARNESS.BaselineError, "spread exceeds 2 blocks"):
            HARNESS.sample_fleet(endpoints, "test-network")

    def test_conflicting_common_finalized_roots_are_rejected(self):
        MockRpcHandler.conflicting_validator = "val6"
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        with self.assertRaisesRegex(HARNESS.BaselineError, "disagree on the common finalized"):
            HARNESS.sample_fleet(endpoints, "test-network")

    def test_context_source_above_common_tip_is_verified_at_available_tips(self):
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        states = HARNESS.sample_fleet(endpoints, "test-network")
        context = {"parameters":{"profile_id":"POSY-ETDAG-v3.0","target_height_offset":5},"context": {"chain_id":1266,"network_id": "test-network",
                               "source_finalized_height": 102,
                               "source_finality_context_root": "source-root",
                               "target_height": 107}}
        HARNESS.verify_context_source_block(context, states, endpoints, "val4")

    def test_signed_profile_mapping_and_bootstrap_boundaries(self):
        def context(profile, offset, source, target):
            return {"parameters":{"profile_id":profile,"target_height_offset":offset},
                    "context":{"chain_id":1266,"source_finalized_height":source,"target_height":target,"target_height_offset":offset}}
        self.assertEqual(HARNESS.validate_context_target(context("POSY-ETDAG-v3.0",5,10,15)),5)
        experimental = HARNESS.EXPERIMENTAL_LOOKAHEAD_PROFILE
        self.assertEqual(HARNESS.validate_context_target(context(experimental,8,10,18)),8)
        for target in (3,8):
            HARNESS.validate_context_target(context(experimental,8,0,target))
        for item in [context("POSY-ETDAG-v3.0",8,10,18),context(experimental,5,10,15),
                     context(experimental,17,10,27),context(experimental,8,10,15),
                     context(experimental,8,0,2),context(experimental,8,0,9),
                     context(experimental,8,-1,7)]:
            with self.assertRaises(HARNESS.BaselineError):
                HARNESS.validate_context_target(item)
        item = context(experimental,8,10,18)
        del item["context"]["target_height_offset"]
        with self.assertRaises(HARNESS.BaselineError):
            HARNESS.validate_context_target(item)

    def test_counter_rates_use_supplied_load_window(self):
        start = {name: {"accepted_total": 10, "etdag_ordered_total": 8}
                 for name in HARNESS.VALIDATORS}
        end = {name: {"accepted_total": 30, "etdag_ordered_total": 18}
               for name in HARNESS.VALIDATORS}
        self.assertEqual(HARNESS.counter_rates(start, end, "accepted_total", 10.0)["val2"], 2.0)
        self.assertEqual(HARNESS.counter_rates(start, end, "etdag_ordered_total", 10.0)["val2"], 1.0)

    def test_preflight_cadence_metadata_preserves_fleet_shape(self):
        endpoints = {name: f"{self.url}/{name}" for name in HARNESS.VALIDATORS}
        states = HARNESS.sample_fleet(endpoints, "test-network")
        states["val2"]["preflight_average_block_time_seconds"] = 1.8
        tip = HARNESS.tip_record(states)
        self.assertEqual(set(tip["validators"]), set(HARNESS.VALIDATORS))

    def test_plain_remote_rpc_is_refused(self):
        with self.assertRaises(HARNESS.BaselineError):
            HARNESS.validate_rpc_url("http://192.0.2.1:8545")


class PersistentSignerContracts(unittest.TestCase):
    def test_remote_signer_uses_configured_existing_master_socket(self):
        calls=[]
        class Owner:
            def configured_master_socket(self, host):
                if host!="synergy-val2":raise AssertionError(host)
                return "/tmp/existing-master"
            def remote(self, host, socket, argv, data=None):
                calls.append((host,socket,argv,data))
                return json.dumps({"sender":"wallet","identity_authorization":{"binding":{"identity_address":"wallet"}}}).encode()
        with patch.object(HARNESS,"remote_owner",return_value=Owner()):
            self.assertEqual(HARNESS.read_remote_wallet(Path("/var/lib/synergy/test-wallet"))[0],"wallet")
        self.assertEqual([(host,socket) for host,socket,_,_ in calls],[("synergy-val2","/tmp/existing-master")])
        self.assertFalse(hasattr(HARNESS,"REMOTE_SOCKET"))

    def signer(self):
        from types import SimpleNamespace
        signer=object.__new__(HARNESS.PersistentNativeSigner)
        signer.lock=threading.Lock();signer.request_id=0;signer.buffer=bytearray();signer.failure=False
        signer.cancellation=threading.Event()
        signer.process=SimpleNamespace(stdin=io.BytesIO(),stdout=SimpleNamespace(fileno=lambda:777),terminate=lambda:None)
        signer._write_frame=lambda frame,deadline:signer.process.stdin.write(frame)
        signer.selector=SimpleNamespace(select=lambda timeout:[True])
        return signer

    def test_native_signer_response_id_must_match_serial_request(self):
        signer=self.signer()
        response=json.dumps({"session_version":1,"request_id":2,"status":"signed","receipt_id":"a"*128}).encode()+b"\n"
        with patch.object(HARNESS.os,"read",return_value=response):
            with self.assertRaises(HARNESS.BaselineError):signer.sign("wallet-0",{}, {})
        frame=json.loads(signer.process.stdin.getvalue())
        self.assertEqual(frame["request_id"],1)
        self.assertIn("context_response",frame)
        self.assertNotIn("transaction_secret_path",frame)

    def test_native_signer_input_bound_precedes_pipe_write(self):
        signer=self.signer()
        with self.assertRaises(HARNESS.BaselineError):
            signer.sign("wallet-0",{"oversized":"x"*(1024*1024)}, {})
        self.assertEqual(signer.process.stdin.getvalue(),b"")

    def test_signed_target_receipt_disagreement_is_safety_failure(self):
        count=[0]
        lock=threading.Lock()
        def lookup(url,method,params):
            self.assertEqual(method,"synergy_getBlock")
            self.assertEqual(params,{"height":10,"hash":None})
            with lock:count[0]+=1;index=count[0]
            return {"height":10,"block_hash":"common","finality_certificate_id":"qc",
                    "transactions":[{"unsigned":{"nonce":0}}],
                    "receipts":[{"transaction_id":"tx","status":"applied","gas_used":21000+index}]}
        with patch.object(HARNESS,"rpc",side_effect=lookup) as mocked:
            with self.assertRaises(HARNESS.BaselineError):
                HARNESS.all_finalized({name:"unused" for name in HARNESS.VALIDATORS},"tx",10)
        self.assertEqual(mocked.call_count,len(HARNESS.VALIDATORS))
        self.assertTrue(all(call.args[1] == "synergy_getBlock" for call in mocked.call_args_list))

    def test_signed_target_receipt_missing_does_not_search_history(self):
        def lookup(_url,method,params):
            self.assertEqual(method,"synergy_getBlock")
            self.assertEqual(params,{"height":10,"hash":None})
            return {"height":10,"block_hash":"common","finality_certificate_id":"qc",
                    "transactions":[],"receipts":[]}
        with patch.object(HARNESS,"rpc",side_effect=lookup) as mocked:
            self.assertIsNone(HARNESS.all_finalized(
                {name:"unused" for name in HARNESS.VALIDATORS},"tx",10))
        self.assertEqual(mocked.call_count,len(HARNESS.VALIDATORS))

    def test_signed_target_receipt_returns_matching_five_validator_views(self):
        def lookup(_url,method,params):
            self.assertEqual(method,"synergy_getBlock")
            self.assertEqual(params,{"height":10,"hash":None})
            return {"height":10,"block_hash":"common","finality_certificate_id":"qc",
                    "transactions":[{"unsigned":{"sender":"wallet","nonce":0}}],
                    "receipts":[{"transaction_id":"tx","status":"applied","gas_used":21000}]}
        with patch.object(HARNESS,"rpc",side_effect=lookup):
            result=HARNESS.all_finalized({name:"unused" for name in HARNESS.VALIDATORS},"tx",10,include_views=True)
        self.assertEqual(result["block_height"],10)
        self.assertEqual(set(result["validator_views"]),set(HARNESS.VALIDATORS))

    def test_wallet_effect_queries_pin_one_common_finalized_height(self):
        with patch.object(HARNESS,"rpc",return_value={"balance_nwei":"90","nonce":1}) as mocked:
            view=HARNESS.pool_account({name:"unused" for name in HARNESS.VALIDATORS},"wallet",10)
        self.assertEqual(view,{"balance_nwei":90,"nonce":1})
        self.assertTrue(all(call.args[2]["at_height"]==10 for call in mocked.call_args_list))

    def test_wallet_proofs_read_all_five_concurrently_before_acceptance(self):
        barrier=threading.Barrier(5)
        def lookup(url,method,params):
            self.assertEqual(method,"synergy_getAccount")
            self.assertEqual(params,{"address":"wallet","at_height":10})
            barrier.wait(timeout=2)
            return {"balance_nwei":"90","nonce":1}
        endpoints={name:name for name in HARNESS.VALIDATORS}
        with patch.object(HARNESS,"rpc",side_effect=lookup):
            view=HARNESS.pool_account(endpoints,"wallet",10,include_views=True)
        self.assertEqual(set(view["validator_views"]),set(endpoints))
        self.assertEqual(view["nonce"],1)

    def test_concurrent_wallet_proofs_reject_one_disagreeing_validator(self):
        def lookup(url,method,params):
            return {"balance_nwei":"89" if url=="val6" else "90","nonce":1}
        with patch.object(HARNESS,"rpc",side_effect=lookup):
            with self.assertRaisesRegex(HARNESS.BaselineError,"wallet state disagreement"):
                HARNESS.pool_account({name:name for name in HARNESS.VALIDATORS},"wallet",10,include_views=True)



class EvidenceStreamAndCancellationTests(unittest.TestCase):
    def test_raw_stream_offsets_hashes_and_durable_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"proof.jsonl"
            stream=HARNESS.RawProofStream(path,4*1024*1024)
            first=stream.append({"kind":"finalized_transfer","transaction_id":"one"})
            second=stream.append({"kind":"finalized_transfer","transaction_id":"two"})
            self.assertFalse(stream.metadata()["complete"])
            stream.close()
            raw=path.read_bytes()
            self.assertTrue(stream.metadata()["complete"])
            self.assertEqual(stream.metadata()["sha3_256"],hashlib.sha3_256(raw).hexdigest())
            self.assertEqual(first["offset"],0)
            self.assertEqual(second["offset"],first["length"])
            for reference in (first,second):
                line=raw[reference["offset"]:reference["offset"]+reference["length"]]
                self.assertTrue(line.endswith(b"\n"))
                self.assertEqual(reference["sha3_256"],hashlib.sha3_256(line).hexdigest())
            with self.assertRaises(FileExistsError):
                HARNESS.RawProofStream(path,4*1024*1024)

    def test_compact_proof_atomically_replaces_consumed_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"proof.jsonl"
            stream=HARNESS.RawProofStream(path,4*1024*1024)
            stream.append({"consumed":"old"})
            reference=stream.compact({"kind":"active_intent_checkpoint","active":[{"nonce":3}]})
            self.assertEqual(reference["generation"],1)
            self.assertEqual(stream.records,1)
            stream.append({"kind":"submission","nonce":4});stream.close()
            self.assertNotIn(b'consumed',path.read_bytes())
            self.assertEqual(len(path.read_bytes().splitlines()),2)
            self.assertEqual(path.stat().st_mode & 0o777,0o600)
            self.assertEqual([entry.resolve() for entry in Path(directory).iterdir()],[path])
            self.assertEqual(stream.metadata()["sha3_256"],hashlib.sha3_256(path.read_bytes()).hexdigest())

    def test_failed_compaction_preserves_only_authoritative_original(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory).resolve()/"proof.jsonl"
            stream=HARNESS.RawProofStream(path,4*1024*1024)
            stream.append({"active_nonce":8})
            with patch.object(HARNESS.os,"replace",side_effect=OSError("replace failed")):
                with self.assertRaises(OSError):stream.compact({"active_nonce":9})
            self.assertEqual(stream.generation,0)
            stream.append({"active_nonce":10});stream.close()
            self.assertEqual([json.loads(line)["active_nonce"] for line in path.read_text().splitlines()],[8,10])
            self.assertEqual([entry.resolve() for entry in Path(directory).iterdir()],[path])

    def test_stream_budget_failure_does_not_append_or_claim_chain_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            stream=HARNESS.RawProofStream(Path(directory).resolve()/"proof.jsonl",4*1024*1024)
            stream.budget=1
            try:
                with self.assertRaisesRegex(HARNESS.BaselineError,"chain capacity unknown"):
                    stream.append({"kind":"finalized_transfer","transaction_id":"one"})
                self.assertEqual(stream.length,0)
                self.assertEqual(stream.records,0)
            finally: stream.close()

    def test_cancelled_signer_never_starts_another_native_request(self):
        signer=object.__new__(HARNESS.PersistentNativeSigner)
        signer.lock=threading.Lock();signer.failure=False
        signer.cancellation=threading.Event();signer.cancellation.set()
        with patch.object(signer,"_sign_locked") as author:
            with self.assertRaisesRegex(HARNESS.BaselineError,"cancelled"):
                signer.sign("wallet",{}, {})
            author.assert_not_called()

    def test_wrong_context_worker_stops_sibling_signing_and_submission(self):
        cancellation=threading.Event()
        sibling_ready=threading.Event()
        signer=object.__new__(HARNESS.PersistentNativeSigner)
        signer.lock=threading.Lock();signer.failure=False;signer.cancellation=cancellation
        authored=[];submitted=[]
        signer._sign_locked=lambda *args:authored.append(args)
        def wrong_context():
            self.assertTrue(sibling_ready.wait(2))
            raise HARNESS.BaselineError("wrong signing network")
        def sibling():
            sibling_ready.set()
            self.assertTrue(cancellation.wait(2))
            signer.sign("wallet",{}, {})
            submitted.append("unexpected")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            waiting=pool.submit(sibling)
            failed=pool.submit(HARNESS.cancellation_guard,cancellation,wrong_context)
            with self.assertRaisesRegex(HARNESS.BaselineError,"wrong signing network"):failed.result(timeout=3)
            with self.assertRaisesRegex(HARNESS.BaselineError,"cancelled"):waiting.result(timeout=3)
        self.assertEqual(authored,[])
        self.assertEqual(submitted,[])

    def test_operator_registry_requires_explicit_mode_and_custody_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700)
            public=root/"wallet.json"
            public.write_text(json.dumps({"sender":"wallet","identity_authorization":{"binding":{"identity_address":"wallet"}}}))
            registry=root/"registry.json"
            data={"session_version":1,"synthetic":False,"network_id":"approved-fresh-chain",
                  "fixture_root":str(root),"genesis_path":str(root/"genesis.sgen"),
                  "custody_kind":"operator-wallet-allowlist-v1",
                  "wallets":[{"wallet_id":"wallet","wallet_public_path":str(public)}]}
            registry.write_text(json.dumps(data));registry.chmod(0o600)
            with self.assertRaises(HARNESS.BaselineError):
                HARNESS.wallet_pool_public(registry,"approved-fresh-chain")
            self.assertEqual(HARNESS.wallet_pool_public(registry,"approved-fresh-chain",operator=True),
                             [{"wallet_id":"wallet","sender":"wallet"}])
            del data["custody_kind"];registry.write_text(json.dumps(data))
            with self.assertRaises(HARNESS.BaselineError):
                HARNESS.wallet_pool_public(registry,"approved-fresh-chain",operator=True)



class NativeTipObservationTests(unittest.TestCase):
    def states(self):
        return {name: {"status":{"chain_id":1266},"height": 100 + i, "context": {"context": {"epoch": 7}}}
                for i, name in enumerate(HARNESS.VALIDATORS)}

    def response(self, name, params, heights=None):
        height = (heights or {}).get(name, 110)
        pinned = params.get("at_height", height)
        return {"chain_id": 1266, "network_identity": "native-network", "epoch": 7,
                "finalized_height": height,
                "common_finalized_commitment": {"height": pinned, "block_id": "native-block",
                    "state_root": "native-state", "finality_certificate_id": "native-finality",
                    "protected_execution_root": "native-protected"}}

    def test_stale_authoring_snapshots_do_not_replace_concurrent_native_tips(self):
        states = self.states()
        barrier = threading.Barrier(5)
        def rpc(name, method, params, **_kwargs):
            self.assertEqual(method, "synergy_chainTelemetry")
            barrier.wait(timeout=2)  # Both tip and pinned reads must be parallel.
            return self.response(name, params)
        endpoints = {name: name for name in HARNESS.VALIDATORS}
        with patch.object(HARNESS, "rpc", side_effect=rpc) as mocked:
            blocks = HARNESS.native_fleet_observation(endpoints, "native-network", states)
        self.assertEqual(mocked.call_count, 10)
        self.assertTrue(all(s["height"] == 110 for s in states.values()))
        self.assertEqual({s["admission_source_height"] for s in states.values()}, set(range(100, 105)))
        self.assertTrue(all(b["height"] == 110 and b["block_hash"] == "native-block" for b in blocks.values()))
        self.assertTrue(all(call.args[1] == "synergy_chainTelemetry" for call in mocked.call_args_list))

    def test_pool_sample_uses_native_height_and_rejects_conflicting_pinned_blocks(self):
        for conflict in (False, True):
            states = self.states()
            for value in states.values(): value["network_id"] = "native-network"
            def rpc(name, method, params, **_kwargs):
                value = self.response(name, params)
                if conflict and name == "val6" and params:
                    value["common_finalized_commitment"]["block_id"] = "conflicting-block"
                return value
            with self.subTest(conflict=conflict), \
                    patch.object(HARNESS, "native_endpoint_state", side_effect=lambda name, *_args: states[name]), \
                    patch.object(HARNESS, "rpc", side_effect=rpc):
                if conflict:
                    with self.assertRaisesRegex(HARNESS.BaselineError, "disagree on the common finalized"):
                        HARNESS.sample_fleet({n: n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True)
                else:
                    sampled = HARNESS.sample_fleet({n: n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True)
                    self.assertTrue(all(value["common_height"] == 110 for value in sampled.values()))
                    self.assertTrue(all(value["lag_blocks"] == 0 for value in sampled.values()))

    def test_live_progress_keeps_startup_gate_and_checks_fresh_commitments(self):
        for conflict in (False, True):
            states = self.states()
            for value in states.values():
                value.update(context=None, native_epoch=7, network_id="native-network",
                             native_finality_warmup={"null_height_samples":0})
                value["status"]["ready"] = True
            def rpc(name, method, params, **_kwargs):
                value = self.response(name, params)
                value.update(lifecycle="active", services=[{"id":key, "state":"running", "health":"healthy", "readiness":{"status":"pending", "reason":"verified synchronization remains in progress"} if key == "sync" else {"status":"ready"}} for key in ("identity", "storage", "network", "sync", "etdag", "execution", "posy", "rpc")])
                if conflict and name == "val6" and params:
                    value["common_finalized_commitment"]["block_id"] = "conflict"
                return value
            with self.subTest(conflict=conflict), patch.object(HARNESS, "native_endpoint_state") as startup, patch.object(HARNESS, "rpc", side_effect=rpc):
                if conflict:
                    with self.assertRaisesRegex(HARNESS.BaselineError, "disagree on the common finalized"):
                        HARNESS.sample_fleet({n:n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True, native_prior_state=states)
                else:
                    result = HARNESS.sample_fleet({n:n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True, native_prior_state=states)
                    self.assertTrue(all(v["common_height"] == 110 and v["readiness_rechecked"] is False for v in result.values()))
                    self.assertEqual(states["val2"]["height"], 100)
                startup.assert_not_called()

    def test_live_progress_rejects_missing_initial_readiness_gate(self):
        with patch.object(HARNESS, "rpc") as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError, "lacks the initial readiness"):
                HARNESS.sample_fleet({n:n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True, native_prior_state=self.states())
            rpc.assert_not_called()

    def test_only_lag_observations_retry_and_preserve_first_failed_snapshot(self):
        counts = {name: 0 for name in HARNESS.VALIDATORS}
        lock = threading.Lock()
        def rpc(name, method, params, **_kwargs):
            with lock:
                counts[name] += 1
                first = counts[name] == 1
            return self.response(name, params, {"val6": 106} if first else None)
        states = self.states()
        with patch.object(HARNESS, "rpc", side_effect=rpc), patch.object(HARNESS.time, "sleep"):
            HARNESS.native_fleet_observation({n: n for n in HARNESS.VALIDATORS}, "native-network", states)
        self.assertEqual(len(states["val2"]["native_tip_observations"]), 2)
        self.assertEqual(states["val2"]["native_tip_observations"][0]["heights"]["val6"], 106)
        self.assertEqual(set(counts.values()), {3})

    def test_genuine_native_lag_retains_two_block_gate_and_bounded_failure_evidence(self):
        def rpc(name, method, params, **_kwargs):
            return self.response(name, params, {"val6": 106})
        # First deadline is5; the clock after first snapshot is6, so no sleep/retry.
        with patch.object(HARNESS, "rpc", side_effect=rpc) as mocked, \
                patch.object(HARNESS.time, "monotonic", side_effect=[0] + [6] * 30):
            with self.assertRaisesRegex(HARNESS.BaselineError, "spread exceeds 2 blocks.*observations="):
                HARNESS.native_fleet_observation({n: n for n in HARNESS.VALIDATORS}, "native-network", self.states())
        self.assertEqual(mocked.call_count, 5)

    def test_distinct_valid_native_epochs_cannot_pass_as_one_fleet(self):
        states = self.states()
        states["val6"]["context"]["context"]["epoch"] = 8
        with patch.object(HARNESS, "rpc") as mocked:
            with self.assertRaisesRegex(HARNESS.BaselineError, "authority epochs disagree"):
                HARNESS.native_fleet_observation({n: n for n in HARNESS.VALIDATORS}, "native-network", states)
        mocked.assert_not_called()

    def test_native_domain_epoch_regression_and_pinned_conflicts_fail_closed(self):
        for mutation in ("network_identity", "epoch", "height", "commitment"):
            def rpc(name, method, params, **_kwargs):
                value = self.response(name, params)
                if name == "val6":
                    if mutation == "network_identity": value[mutation] = "wrong-network"
                    if mutation == "epoch": value[mutation] = 8
                    if mutation == "height": value["finalized_height"] = 99
                    if mutation == "commitment" and params: value["common_finalized_commitment"]["protected_execution_root"] = "wrong-root"
                return value
            with self.subTest(mutation=mutation), patch.object(HARNESS, "rpc", side_effect=rpc) as mocked:
                with self.assertRaises(HARNESS.BaselineError):
                    HARNESS.native_fleet_observation({n: n for n in HARNESS.VALIDATORS}, "native-network", self.states())
                self.assertLessEqual(mocked.call_count, 10)


class NativeEndpointStartupTests(unittest.TestCase):
    def native(self, **changes):
        value={"chain_id":1266,"network_identity":"startup-network","epoch":1,"finalized_height":None}
        value.update(changes)
        return value

    def clock(self):
        from types import SimpleNamespace
        now=[0.0]
        return now,SimpleNamespace(monotonic=lambda:now[0],sleep=lambda delay:now.__setitem__(0,now[0]+delay))

    def test_ready_null_then_finalized_observes_no_context_or_signed_work(self):
        now,clock=self.clock()
        responses=[{"chain_id":1266,"ready":True},self.native(),self.native(finalized_height=1),{}]
        with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=responses) as rpc:
            result=HARNESS.native_endpoint_state("val6","loopback","startup-network")
        self.assertEqual(result["height"],1);self.assertEqual(result["native_epoch"],1)
        self.assertEqual(result["native_finality_warmup"]["null_height_samples"],1)
        self.assertEqual([call.args[1] for call in rpc.call_args_list],
                         ["synergy_nodeStatus","synergy_chainTelemetry","synergy_chainTelemetry","synergy_getProtectedAdmissionStats"])
        self.assertAlmostEqual(now[0],0.1)
        self.assertTrue(all(0<call.kwargs["timeout"]<=5 for call in rpc.call_args_list))

    def test_only_null_height_wait_is_bounded_and_retains_public_field_diagnostics(self):
        now,clock=self.clock()
        def response(_url,method,_params,**_kwargs):
            return {"chain_id":1266,"ready":True} if method=="synergy_nodeStatus" else self.native()
        with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=response) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"within 5 seconds.*null_height_samples") as failure:
                HARNESS.native_endpoint_state("val6","loopback","startup-network")
        self.assertLessEqual(rpc.call_count,52);self.assertLessEqual(now[0],5)
        self.assertIn('"network_identity_matches": true',str(failure.exception))
        self.assertIn('"type": "NoneType"',str(failure.exception))

    def test_readiness_and_first_finality_share_one_absolute_budget(self):
        now,clock=self.clock();statuses=[0]
        def response(_url,method,_params,**_kwargs):
            if method=="synergy_nodeStatus":
                statuses[0]+=1
                if statuses[0]==1:now[0]=4.8
                return {"chain_id":1266,"ready":statuses[0]>1}
            return self.native()
        with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=response) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"within 5 seconds"):
                HARNESS.native_endpoint_state("val6","loopback","startup-network")
        self.assertLessEqual(now[0],5)
        telemetry=[call for call in rpc.call_args_list if call.args[1]=="synergy_chainTelemetry"]
        self.assertTrue(telemetry)
        self.assertTrue(all(call.kwargs["timeout"]<=0.11 for call in telemetry))

    def test_wrong_immutable_identity_is_immediate_even_with_null_height(self):
        for changes in ({"network_identity":"DO_NOT_ECHO_ARBITRARY_NETWORK"},{"chain_id":1267},
                        {"chain_id":1266.0},{"epoch":-1},{"epoch":True},{"epoch":"1"}):
            with self.subTest(changes=changes):
                now,clock=self.clock()
                with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=[{"chain_id":1266,"ready":True},self.native(**changes)]) as rpc:
                    with self.assertRaisesRegex(HARNESS.BaselineError,"invalid native identity/epoch/height; fields=") as failure:
                        HARNESS.native_endpoint_state("val6","loopback","startup-network")
                self.assertEqual(rpc.call_count,2);self.assertEqual(now[0],0)
                self.assertNotIn("DO_NOT_ECHO_ARBITRARY_NETWORK",str(failure.exception))

    def test_live_sync_requires_healthy_services_and_does_not_claim_startup_ready(self):
        services = [{"id":key,"state":"running","health":"healthy","readiness":
                    {"status":"pending","reason":"verified synchronization remains in progress"} if key=="sync" else {"status":"ready"}}
                    for key in ("identity","storage","network","sync","etdag","execution","posy","rpc")]
        for blocked in (False, True):
            native=self.native(finalized_height=100,lifecycle="active",services=services,process_id=123)
            if blocked: services[4]["health"]="unhealthy"
            with self.subTest(blocked=blocked),patch.object(HARNESS,"rpc",side_effect=[{"chain_id":1266,"ready":False},native,{}]):
                if blocked:
                    with self.assertRaisesRegex(HARNESS.BaselineError,"unhealthy or blocked"):
                        HARNESS.native_endpoint_state("val5","loopback","startup-network",live_progress=True)
                else:
                    value=HARNESS.native_endpoint_state("val5","loopback","startup-network",live_progress=True)
                    self.assertFalse(value["status"]["ready"])
                    self.assertFalse(value["readiness_rechecked"])
                    self.assertEqual(value["native_process_id"],123)

    def test_missing_or_malformed_height_never_enters_null_warmup(self):
        invalid=[self.native(finalized_height=value) for value in (-1,True,"1",1.0,{},[])]
        missing=self.native();del missing["finalized_height"];invalid.append(missing)
        for value in invalid:
            with self.subTest(value=value):
                now,clock=self.clock()
                with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=[{"chain_id":1266,"ready":True},value]) as rpc:
                    with self.assertRaisesRegex(HARNESS.BaselineError,"invalid native identity/epoch/height; fields="):
                        HARNESS.native_endpoint_state("val6","loopback","startup-network")
                self.assertEqual(rpc.call_count,2);self.assertEqual(now[0],0)

    def test_null_warmup_never_allows_epoch_change_or_late_valid_result(self):
        now,clock=self.clock()
        with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=[{"chain_id":1266,"ready":True},self.native(),self.native(epoch=2,finalized_height=1)]) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"invalid native identity/epoch/height"):
                HARNESS.native_endpoint_state("val6","loopback","startup-network")
        self.assertEqual(rpc.call_count,3)
        now,clock=self.clock()
        def response(_url,method,_params,**_kwargs):
            if method=="synergy_nodeStatus":return {"chain_id":1266,"ready":True}
            if method=="synergy_chainTelemetry":now[0]=5;return self.native(finalized_height=1)
            raise AssertionError("late finality must not initiate another RPC")
        with patch.object(HARNESS,"time",clock),patch.object(HARNESS,"rpc",side_effect=response):
            with self.assertRaisesRegex(HARNESS.BaselineError,"within 5 seconds"):
                HARNESS.native_endpoint_state("val6","loopback","startup-network")


class SelectedChainDomainTests(unittest.TestCase):
    def test_native_fleet_accepts_selected_domain_and_rejects_mixed_domains(self):
        endpoints = {name:name for name in HARNESS.VALIDATORS}
        def response(name, method, params, **kwargs):
            if method == "synergy_nodeStatus":
                return {"chain_id":9001, "ready":True}
            if method == "synergy_getProtectedAdmissionStats":
                return {}
            value = NativeTipObservationTests().response(name, params)
            value["chain_id"] = 9001
            return value
        with patch.object(HARNESS,"rpc",side_effect=response):
            states = HARNESS.sample_fleet(endpoints,"native-network",native_tips=True,expected_chain_id=9001)
            self.assertEqual({v["status"]["chain_id"] for v in states.values()}, {9001})
            with self.assertRaisesRegex(HARNESS.BaselineError,"wrong chain"):
                HARNESS.sample_fleet(endpoints,"native-network",native_tips=True,expected_chain_id=9002)
        def mixed(name, method, params, **kwargs):
            value = response(name, method, params, **kwargs)
            if method in ("synergy_nodeStatus", "synergy_chainTelemetry") and name == "val6":
                value["chain_id"] = 9002
            return value
        with patch.object(HARNESS,"rpc",side_effect=mixed):
            with self.assertRaisesRegex(HARNESS.BaselineError,"identities disagree"):
                HARNESS.sample_fleet(endpoints,"native-network",native_tips=True)

    def test_transaction_domain_is_explicit_positive_u64(self):
        args = ("selected-network", "s", "r", 7, 2, 21000, 3, 1700000000)
        self.assertNotEqual(HARNESS.transaction_id(*args,chain_id=9001), HARNESS.transaction_id(*args,chain_id=1266))
        with self.assertRaises(TypeError):
            HARNESS.transaction_id(*args)
        for invalid in (True, 0, -1, 2**64, "9001", None):
            with self.subTest(chain_id=invalid), self.assertRaises(HARNESS.BaselineError):
                HARNESS.transaction_id(*args,chain_id=invalid)


class PoolBoundaryObservationTests(unittest.TestCase):
    response = NativeTipObservationTests.response
    def context(self, target=115, epoch=7):
        return {"signing_context": {"parameters": {"profile_id": "POSY-ETDAG-v3.0", "target_height_offset": 5},
                "context": {"chain_id":1266,"network_id": "native-network", "epoch": epoch,
                            "source_finalized_height": target-5, "target_height": target}}}

    def test_native_pool_preflight_never_requests_closed_legacy_or_v2_context(self):
        methods = []
        def rpc(name, method, params, **_kwargs):
            methods.append(method)
            if method == "synergy_nodeStatus": return {"chain_id": 1266, "ready": True}
            if method == "synergy_chainTelemetry": return self.response(name, params)
            if method == "synergy_getProtectedAdmissionStats": return {}
            raise HARNESS.TransientSampleError("all admission windows closed")
        with patch.object(HARNESS, "rpc", side_effect=rpc):
            result = HARNESS.sample_fleet({n:n for n in HARNESS.VALIDATORS}, "native-network", native_tips=True)
            HARNESS.tip_record(result)
        self.assertTrue(all(s["context"] is None and s["common_height"]==110 for s in result.values()))
        self.assertFalse(any("Context" in method for method in methods))

    def test_v2_closed_reads_then_open_do_not_sign_or_submit(self):
        closed = HARNESS.TransientSampleError("protected admission context unavailable")
        with patch.object(HARNESS,"rpc",side_effect=[closed,self.context(),self.context(target=116)]) as rpc, patch.object(HARNESS.time,"sleep"):
            value, observations = HARNESS.pool_admission_context("node","native-network",7,threading.Event())
        self.assertEqual(value,self.context(target=116))
        self.assertEqual(len(observations),3)
        self.assertTrue(all(call.args[1]=="synergy_getProtectedAdmissionContextV2" for call in rpc.call_args_list))

    def test_v2_identity_conflict_is_not_retried(self):
        with patch.object(HARNESS,"rpc",return_value=self.context(epoch=8)) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"native network/epoch"):
                HARNESS.pool_admission_context("node","native-network",7,threading.Event())
        self.assertEqual(rpc.call_count,1)

    def test_v2_closed_read_budget_fails_and_retains_observation(self):
        with patch.object(HARNESS,"rpc",side_effect=HARNESS.TransientSampleError("closed")) as rpc, \
                patch.object(HARNESS.time,"monotonic",side_effect=[0,0,0,6,6,6]), patch.object(HARNESS.time,"sleep"):
            with self.assertRaisesRegex(HARNESS.BaselineError,"bounded read-only.*closed"):
                HARNESS.pool_admission_context("node","native-network",7,threading.Event())
        self.assertEqual(rpc.call_count,1)

    def test_v2_waits_for_target_advance_and_rejects_regression(self):
        for targets in ([115,115,116],[115,114]):
            with self.subTest(targets=targets), patch.object(HARNESS,"rpc",side_effect=[self.context(t) for t in targets]) as rpc, patch.object(HARNESS.time,"sleep"):
                if targets[-1]<targets[0]:
                    with self.assertRaisesRegex(HARNESS.BaselineError,"target regressed"):
                        HARNESS.pool_admission_context("node","native-network",7,threading.Event())
                else:
                    context, observations=HARNESS.pool_admission_context("node","native-network",7,threading.Event())
                    self.assertEqual(context,self.context(116));self.assertEqual(len(observations),3)
                self.assertEqual(rpc.call_count,len(targets))

    def test_v2_cancellation_and_unready_native_node_cannot_pass(self):
        cancelled=threading.Event();cancelled.set()
        with patch.object(HARNESS,"rpc") as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"cancelled"):
                HARNESS.pool_admission_context("node","native-network",7,cancelled)
            rpc.assert_not_called()
        with patch.object(HARNESS,"rpc",return_value={"ready":False,"chain_id":1266}) as rpc, patch.object(HARNESS.time,"sleep"):
            with self.assertRaisesRegex(HARNESS.BaselineError,"observation bound"):
                HARNESS.native_endpoint_state("val2","node","native-network")
        self.assertEqual(rpc.call_count,51)

    def test_submission_explicit_rejection_preserves_cause_and_never_retries(self):
        record={"receipt_id":"signed-id","ambiguous_response":False}
        error=HARNESS.RpcResponseError("synergy_submitProtectedTransaction",-32602,"fresh local protected admission is closed")
        with patch.object(HARNESS,"rpc",side_effect=error) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"explicit protected submission rejection"):
                HARNESS.submit_pool_admission("node",{},record)
        self.assertEqual(rpc.call_count,1)
        self.assertEqual(record["submission_rejection"]["code"],-32602)
        self.assertFalse(record["ambiguous_response"])

    def test_ambiguous_transport_keeps_error_and_observes_finality_despite_absent_receipt(self):
        record={"receipt_id":"signed-id","transaction_id":"tx","target_height":115,"ambiguous_response":False}
        with patch.object(HARNESS,"rpc",side_effect=HARNESS.BaselineError("transport failed")) as rpc:
            HARNESS.submit_pool_admission("node",{},record)
        self.assertEqual(rpc.call_count,1)
        self.assertEqual(record["submission_error"],"transport failed")
        error=HARNESS.RpcResponseError("synergy_getProtectedAdmissionReceipt",-32000,"admission receipt unavailable; verify finalized transaction before retry")
        for final in (None,{"proof":"all-five"}):
            with patch.object(HARNESS,"rpc",side_effect=error), patch.object(HARNESS,"all_finalized",return_value=final) as observed:
                receipt, result=HARNESS.observe_pool_finality({"val2":"node"},"val2",record)
            self.assertIsNone(receipt);self.assertEqual(result,final)
            observed.assert_called_once_with({"val2":"node"},"tx",115,include_views=True)
            self.assertNotIn("accepted",record)

    def test_unknown_receipt_error_and_durable_rejection_remain_fatal(self):
        record={"receipt_id":"signed-id","transaction_id":"tx","target_height":115}
        for response in (HARNESS.RpcResponseError("receipt",-32000,"other unavailable"),
                         {"receipt_id":"signed-id","status":"rejected","reason":"cutoff"},
                         {"receipt_id":"wrong-id","status":"accepted"}, {}):
            with patch.object(HARNESS,"rpc",side_effect=response if isinstance(response,Exception) else None,return_value=response), \
                    patch.object(HARNESS,"all_finalized") as finalized:
                with self.assertRaises(HARNESS.BaselineError):
                    HARNESS.observe_pool_finality({"val2":"node"},"val2",record)
            finalized.assert_not_called()


class ClosedLoopMemoryTests(unittest.TestCase):
    def args(self, **overrides):
        from types import SimpleNamespace
        values=dict(workload_mode="closed-loop-memory",max_tx=30,duration_seconds=300,max_in_flight=4)
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_closed_loop_profile_is_explicit_bounded_and_pool_only(self):
        self.assertTrue(HARNESS.validate_pool_workload(self.args(),4))
        self.assertFalse(HARNESS.validate_pool_workload(self.args(workload_mode="offered-rate",max_tx=1,duration_seconds=1,max_in_flight=32),32))
        for changes,count in [({"max_tx":29},4),({"duration_seconds":301},4),({"max_in_flight":5},4),({},5),({},0)]:
            with self.assertRaises(HARNESS.BaselineError):
                HARNESS.validate_pool_workload(self.args(**changes),count)
        with self.assertRaisesRegex(HARNESS.BaselineError,"wallet pool"):
            HARNESS.run(self.args(wallet_registry=None))

    def test_count_scheduler_has_no_clock_and_offered_scheduler_keeps_missed_slots(self):
        self.assertEqual(HARNESS.pool_offer_slot(True,25,None,float("nan")),(25,None,0))
        self.assertEqual(HARNESS.pool_offer_slot(False,25,20,1),(25,26,5))

    def test_count_completion_requires_all_30_exact_issued_proofs_before_deadline(self):
        records=[{"finalized_mono":99,"raw_proof_ref":{"offset":i},"submission_started":True} for i in range(30)]
        self.assertTrue(HARNESS.closed_loop_deadline_met(30,records,0,100,99))
        for attempted,items,remaining,verified_at in [(29,records,0,99),(30,records[:29],0,99),(30,records,1,99),(30,records,0,100)]:
            self.assertFalse(HARNESS.closed_loop_deadline_met(attempted,items,remaining,100,verified_at))
        for change in ({"finalized_mono":100},{"finalized_mono":None},{"raw_proof_ref":None},{"submission_started":False}):
            changed=[dict(record) for record in records];changed[-1].update(change)
            self.assertFalse(HARNESS.closed_loop_deadline_met(30,changed,0,100,99))

    def test_deadline_guard_stops_context_rpc_and_late_context_return(self):
        event=threading.Event()
        with patch.object(HARNESS.time,"monotonic",return_value=100),patch.object(HARNESS,"rpc") as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"count deadline"):
                HARNESS.pool_admission_context("node","network",1,event,operation_deadline=100)
        rpc.assert_not_called();self.assertTrue(event.is_set())
        event=threading.Event()
        # Even an RPC returning a target advancement at the deadline is stale
        # for this workload; no signing may follow the late observation.
        with patch.object(HARNESS.time,"monotonic",side_effect=[0,0,0,100]),patch.object(HARNESS,"rpc",return_value={}) as rpc:
            with self.assertRaisesRegex(HARNESS.BaselineError,"count deadline"):
                HARNESS.pool_admission_context("node","network",1,event,operation_deadline=100)
        self.assertEqual(rpc.call_count,1)

    def test_serial_signer_checks_deadline_after_waiting_for_session_lock(self):
        from unittest.mock import Mock
        signer=object.__new__(HARNESS.PersistentNativeSigner)
        signer.lock=threading.Lock();signer.lock.acquire()
        signer.cancellation=threading.Event();signer.failure=False;signer._sign_locked=Mock()
        clock=[0];errors=[];started=threading.Event()
        def queued():
            started.set()
            try:signer.sign("wallet",{}, {},operation_deadline=100)
            except Exception as error:errors.append(error)
        with patch.object(HARNESS.time,"monotonic",side_effect=lambda:clock[0]):
            worker=threading.Thread(target=queued);worker.start();self.assertTrue(started.wait(1))
            clock[0]=100;signer.lock.release();worker.join(1)
        self.assertFalse(worker.is_alive());signer._sign_locked.assert_not_called()
        self.assertEqual(len(errors),1);self.assertIn("after session lock",str(errors[0]))
        self.assertTrue(signer.cancellation.is_set())

    def simulated_pool(self, mode="closed-loop-memory", proof_seconds=2.0, signing_seconds=0.0):
        """Execute the real scheduling/reconciliation loop with slow proof IO."""
        import sys
        from types import SimpleNamespace
        from contextlib import ExitStack
        clock=[0.0];height=[0];bank={f"sender-{i}":{"nonce":0,"balance_nwei":10000} for i in range(4)}
        bank["receiver"]={"nonce":0,"balance_nwei":0}
        signed=[];submitted=[]
        class ImmediatePool:
            def __init__(self,**_kwargs):pass
            def submit(self,fn,*args):
                future=concurrent.futures.Future()
                try:future.set_result(fn(*args))
                except Exception as error:future.set_exception(error)
                return future
            def shutdown(self,**_kwargs):pass
        class Signer:
            def __init__(self,*_args):pass
            def sign(self,wallet,envelope,transfer,**kwargs):
                signed.append((clock[0],kwargs.get("operation_deadline")))
                clock[0]+=signing_seconds
                return {"receipt_id":wallet+"-"+str(transfer["nonce"]),"admission":{}}
            def close(self):pass
        class Proof:
            def __init__(self,*_args):self.length=0;self.budget=1000000
            def append(self,value):self.length+=1;return {"offset":self.length,"length":1,"hash":"proof"}
            def metadata(self):return {"length":self.length}
            def close(self):pass
        def sample(*_args,**_kwargs):
            height[0]+=1
            return {name:{"status":{"chain_id":1266},"common_height":height[0],"native_epoch":1,"stats":{}} for name in HARNESS.VALIDATORS}
        def account(_endpoints,address,_height,**_kwargs):
            return dict(bank[address],validator_views={name:dict(bank[address]) for name in HARNESS.VALIDATORS})
        def context(*_args,**kwargs):
            if kwargs.get("operation_deadline") is not None and clock[0]>=kwargs["operation_deadline"]:
                raise HARNESS.BaselineError("late context")
            return {"signing_context":{"context":{"network_id":"network","target_height":100}}},[]
        def observe(_endpoints,_validator,record):
            clock[0]+=proof_seconds
            bank[record["sender"]]["nonce"]+=1;bank[record["sender"]]["balance_nwei"]-=1
            bank["receiver"]["balance_nwei"]+=1
            return {"status":"accepted"},{"transaction":{"unsigned":{"sender":record["sender"],"nonce":record["nonce"],"receiver":"receiver","amount_nwei":1}},"receipt":{"gas_used":0},"block_height":100,"validator_views":{name:{} for name in HARNESS.VALIDATORS}}
        def submit(_url,_admission,record):submitted.append(clock[0])
        args=self.args(workload_mode=mode,duration_seconds=300 if mode=="closed-loop-memory" else 30,
            validator_rpc=[(name,name) for name in HARNESS.VALIDATORS],network_id="network",execute=True,
            remote_signer=False,signer_dir=None,rate_tps=1.0,stability_seconds=10,
            finality_budget_seconds=20,maximum_gap_seconds=30,wallet_registry=Path("unused"),
            receiver="receiver",amount_nwei=1,gas_limit=1,max_fee_per_gas_nwei=1,gas_class_units=1,fee_class=1,
            keytool=Path(sys.executable),submit_validator="val2",raw_proof_stream=Path("unused-proof"))
        fake_time=SimpleNamespace(monotonic=lambda:clock[0],sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds),time=lambda:1000000+clock[0])
        with ExitStack() as stack:
            for name,value in {"time":fake_time,"wallet_pool_public":lambda *_args:[{"sender":f"sender-{i}","wallet_id":f"wallet-{i}"} for i in range(4)],
                "sample_fleet":sample,"tip_record":lambda state:{"height":state["val2"]["common_height"]},"pool_account":account,
                "PersistentNativeSigner":Signer,"RawProofStream":Proof,"pool_admission_context":context,
                "validate_context_target":lambda *_args:None,"submit_pool_admission":submit,"observe_pool_finality":observe,
                "transaction_id":lambda _network,sender,_receiver,_amount,nonce,*_args,**_kwargs:sender+"-"+str(nonce)}.items():
                stack.enter_context(patch.object(HARNESS,name,value))
            stack.enter_context(patch.object(HARNESS.concurrent.futures,"ThreadPoolExecutor",ImmediatePool))
            report=HARNESS.run_wallet_pool(args)
        return report,signed,submitted

    def test_slow_proof_observation_completes_all_30_closed_loop_without_dropped_slots(self):
        report,signed,submitted=self.simulated_pool()
        self.assertEqual(report["status"],"completed");self.assertTrue(report["workload_deadline_met"])
        for field in ("attempted_transactions","submitted_transactions","finalized_transactions"):
            self.assertEqual(report[field],30)
        self.assertEqual(report["remaining_in_flight"],0);self.assertTrue(report["wallet_effects_verified_all_five"])
        self.assertLessEqual(report["peak_in_flight"],4)
        self.assertEqual(report["workload_deadline_mono"]-report["workload_start_mono"],300)
        self.assertLess(report["all_five_effects_verified_mono"],report["workload_deadline_mono"])
        self.assertLess(report["workload_elapsed_seconds"],300)
        for field in ("offered_rate_tps","generator_missed_offered_slots","generator_limited","measured_submitted_tps","finalized_tps","accepted_tps_by_validator","etdag_ordered_tps_by_validator"):
            self.assertIsNone(report[field])
        self.assertFalse(report["TPS_qualified"]);self.assertFalse(report["capacity_result"])
        self.assertTrue(all(when<deadline for when,deadline in signed));self.assertEqual(len(submitted),30)

    def test_identical_slow_proof_observation_preserves_offered_rate_failure(self):
        report,_,_=self.simulated_pool(mode="offered-rate")
        self.assertEqual(report["status"],"failed")
        self.assertGreater(report["generator_missed_offered_slots"],0)
        self.assertIn("cohort",report["failure"])

    def test_offered_pool_measures_late_proofs_without_tx_latency_rejection(self):
        report, _, _ = self.simulated_pool(mode="offered-rate", proof_seconds=45)
        self.assertGreater(report["observed_client_latency_seconds"]["context_to_finality"]["maximum"], 30)
        self.assertIn("cohort", report["failure"])
        self.assertNotIn("finality budget", report["failure"])
        self.assertEqual(report["remaining_in_flight"], 0)
        self.assertGreater(report["end_to_end_finalized_tps"], 0)

    def test_late_proof_completion_cannot_pass_closed_loop(self):
        report,signed,submitted=self.simulated_pool(proof_seconds=10.0)
        self.assertEqual(report["status"],"failed");self.assertFalse(report["workload_deadline_met"])
        self.assertGreaterEqual(report["all_five_effects_verified_mono"],report["workload_deadline_mono"])
        self.assertGreaterEqual(report["workload_elapsed_seconds"],300)
        self.assertTrue(all(when<deadline for when,deadline in signed))
        self.assertLessEqual(len(submitted),30)

    def test_signing_that_crosses_count_deadline_never_starts_submission(self):
        report,signed,submitted=self.simulated_pool(signing_seconds=301)
        self.assertEqual(len(signed),1);self.assertEqual(submitted,[])
        self.assertEqual(report["submitted_transactions"],0)
        self.assertEqual(report["remaining_in_flight"],0)
        self.assertEqual(report["status"],"failed");self.assertFalse(report["workload_deadline_met"])


if __name__ == "__main__":
    unittest.main()
