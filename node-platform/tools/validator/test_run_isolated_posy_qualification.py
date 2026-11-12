import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location("isolated_qualification",Path(__file__).with_name("run-isolated-posy-qualification.py"))
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

class ExplicitProcessingProfile(unittest.TestCase):
    def test_fresh_resource_activation_is_explicit_and_retained_mismatch_is_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/"config.json"
            original={"storage":{"world_memory_budget_bytes":67108864,"prune_finalized_history_after_blocks":None}}
            config.write_text(json.dumps(original))
            for budget,retention in ((None,None),(1073741824,None),(1073741824,0),(2147483648,64)):
                with self.assertRaises(ValueError):MODULE.configure_processing_resources([config],True,budget,retention,True)
                self.assertEqual(json.loads(config.read_text()),original)
            with self.assertRaisesRegex(ValueError,"retained"):
                MODULE.configure_processing_resources([config],True,1073741824,64,False)
            self.assertEqual(json.loads(config.read_text()),original)
            metadata=MODULE.configure_processing_resources([config],True,1073741824,64,True)
            self.assertEqual(json.loads(config.read_text())["storage"],
                {"world_memory_budget_bytes":1073741824,"prune_finalized_history_after_blocks":64})
            self.assertEqual(metadata["per_node_world_accounting_limit_bytes"],1073741824)
            self.assertEqual(MODULE.configure_processing_resources([config],True,1073741824,64,False),metadata)

    def test_legacy_resource_configuration_is_preserved(self):
        self.assertEqual(MODULE.configure_processing_resources([],False,None,None,False),{})
        with self.assertRaises(ValueError):MODULE.configure_processing_resources([],False,1073741824,64,True)

    def test_export_selection_is_explicit_and_does_not_mutate_inherited_environment(self):
        inherited={"OTHER":"unchanged","SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE":"inherited"}
        self.assertEqual(MODULE.processing_export_environment(inherited,False),{"OTHER":"unchanged"})
        self.assertEqual(MODULE.processing_export_environment(inherited,True),
            {"OTHER":"unchanged","SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE":MODULE.PROCESSING_PROFILE})
        self.assertEqual(inherited["SYNERGY_POSY_ISOLATED_PROCESSING_PROFILE"],"inherited")

    def test_native_signed_policy_selects_matching_traffic_adapter(self):
        status={"network_id":"isolated"}
        for enabled,version,cutoff in ((False,1,"vc_event_context_v1"),(True,2,"processing_groups_v1")):
            authority={"payload":{"network_id":"isolated","protected":{"version":version,"cutoff_relationship":cutoff}},"signature":"retained-native-signature"}
            before=json.dumps(authority,sort_keys=True)
            result=MODULE.require_fixture_profile(status,authority,enabled)
            self.assertEqual(result["protected_policy_version"],version)
            self.assertEqual(result["processing_profile_id"],MODULE.PROCESSING_PROFILE if enabled else None)
            self.assertEqual(MODULE.processing_traffic_arguments(enabled),["--async-processing"] if enabled else [])
            with self.assertRaises(ValueError):MODULE.require_fixture_profile(status,authority,not enabled)
            self.assertEqual(json.dumps(authority,sort_keys=True),before)

    def test_status_cannot_override_native_policy_or_network(self):
        authority={"payload":{"network_id":"isolated","protected":{"version":1,"cutoff_relationship":"vc_event_context_v1"}}}
        with self.assertRaises(ValueError):
            MODULE.require_fixture_profile({"network_id":"isolated","processing_profile_id":MODULE.PROCESSING_PROFILE},authority,True)
        authority["payload"]["protected"]={"version":2,"cutoff_relationship":"processing_groups_v1"}
        with self.assertRaises(ValueError):MODULE.require_fixture_profile({"network_id":"different"},authority,True)

class FailureEvidenceRetention(unittest.TestCase):
    def test_funded_phase_failure_preserves_real_samples_and_original_error(self):
        observations=[]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"native-observations.json"
            with self.assertRaisesRegex(RuntimeError,"funded transfer failed"):
                with MODULE.retain_native_observation_evidence(path,lambda:{"observations":list(observations)}):
                    observations.append({"by_validator":{"validator-02":{"native":{"finalized_height":28}}}})
                    raise RuntimeError("funded transfer failed")
            report=json.loads(path.read_text())
            self.assertEqual(report["observations"],observations)
            self.assertEqual(report["run_status"],"failed")
            self.assertEqual(report["failure_type"],"RuntimeError")
            self.assertFalse(report["GateD_qualified"])
            self.assertFalse(report["GateE_qualified"])
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_success_retains_observations_without_qualification_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"native-observations.json"
            with MODULE.retain_native_observation_evidence(path,lambda:{"observations":[]}):pass
            report=json.loads(path.read_text())
            self.assertEqual(report["run_status"],"completed")
            self.assertIsNone(report["failure_type"])
            self.assertFalse(report["GateD_qualified"])

    def test_existing_evidence_is_not_overwritten_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"native-observations.json";path.write_text("prior evidence")
            with self.assertRaisesRegex(RuntimeError,"original failure"):
                with MODULE.retain_native_observation_evidence(path,lambda:{"observations":[]}):
                    raise RuntimeError("original failure")
            self.assertEqual(path.read_text(),"prior evidence")

class ArtifactPinProjection(unittest.TestCase):
    @staticmethod
    def provenance():
        pin={"length":64,"sha3_256":"a"*64}
        return {"artifact":dict(pin),"companions":{name:dict(pin) for name in
            ("synergy-keytool","synergy-genesis","synergy-fixture-exporter")},
            "before":{"files":[{"path":"source","sha256":"b"*64}]},
            "after":{"files":[{"path":"source","sha256":"b"*64}]}}

    def test_projection_discards_complete_inventory_and_unneeded_artifact_metadata(self):
        import weakref
        class Document(dict):pass
        references=[]
        def read_document(_path):
            document=Document(self.provenance())
            document["artifact"]["unneeded"]="x"*1024*1024
            references.append(weakref.ref(document))
            return document
        with patch.object(MODULE,"read",side_effect=read_document):
            pins=MODULE.read_artifact_pins(Path("/original-provenance.json"))
        self.assertIsNone(references[0]())
        self.assertEqual(set(pins),{"artifact","companions"})
        self.assertEqual(set(pins["companions"]),{"synergy-keytool","synergy-genesis","synergy-fixture-exporter"})
        for pin in [pins["artifact"],*pins["companions"].values()]:
            self.assertEqual(pin,{"length":64,"sha3_256":"a"*64})

    def test_missing_artifact_or_companion_pin_fails_closed(self):
        for name in ("artifact","synergy-keytool","synergy-genesis","synergy-fixture-exporter"):
            for field in ("length","sha3_256"):
                with self.subTest(name=name,field=field):
                    document=self.provenance()
                    value=document["artifact"] if name=="artifact" else document["companions"][name]
                    del value[field]
                    with patch.object(MODULE,"read",return_value=document):
                        with self.assertRaises(KeyError):MODULE.read_artifact_pins(Path("/original-provenance.json"))

    def test_second_projection_independently_rereads_original_pins(self):
        first=self.provenance();second=self.provenance()
        second["artifact"]["sha3_256"]="b"*64
        path=Path("/original-provenance.json")
        with patch.object(MODULE,"read",side_effect=[first,second]) as reader:
            early=MODULE.read_artifact_pins(path)
            later=MODULE.read_artifact_pins(path)
        self.assertEqual(reader.call_args_list,[unittest.mock.call(path),unittest.mock.call(path)])
        self.assertNotEqual(early["artifact"],later["artifact"])

    def test_projection_preserves_regular_bounded_input_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=root/"provenance.json"
            original.write_text(json.dumps(self.provenance()))
            link=root/"link.json";link.symlink_to(original)
            with self.assertRaises(ValueError):MODULE.read_artifact_pins(link)
            with original.open("wb") as output:output.truncate(64*1024*1024+1)
            with self.assertRaises(ValueError):MODULE.read_artifact_pins(original)


class CapacityPlanContracts(unittest.TestCase):
    def test_ladder_orders_funded_baseline_then_steps_then_highest_ten_minutes(self):
        stages=MODULE.capacity_stages(8)
        self.assertEqual(stages[:3],[("steady-state-transfer",1,1,1),("baseline-30",1,30,30),("baseline-600",1,600,600)])
        self.assertEqual(stages[3:6],[("offered-2",2,120,240),("offered-4",4,120,480),("offered-8",8,120,960)])
        self.assertEqual(stages[-1],("highest-clean-600",8,600,4800))
        traffic_budget=sum(duration+90 for _,_,duration,_ in stages)+20
        self.assertLess(traffic_budget+180,3600)
        self.assertGreater(traffic_budget+30,sum(stage[2] for stage in stages))

    def test_declared_ceiling_obeys_generator_transaction_cap_and_launcher_lifetime(self):
        for maximum in (2,4,8,16,32,64,128):
            stages=MODULE.capacity_stages(maximum)
            self.assertTrue(all(count<=100000 for _,_,_,count in stages))
            self.assertLessEqual(sum(duration+90 for _,_,duration,_ in stages)+200,3600)
        for invalid in (0,1,3,256,True):
            with self.assertRaises(ValueError):MODULE.capacity_stages(invalid)

    def test_stream_keeps_native_failure_samples_and_enforces_disk_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"native-observations.jsonl"
            stream=MODULE.NativeObservationStream(path,budget=128)
            from types import SimpleNamespace
            with patch.object(MODULE.shutil,"disk_usage",return_value=SimpleNamespace(free=2*1024**3)):
                stream.append({"by_validator":{"validator-02":{"error":"TimeoutError"}}})
            with self.assertRaises(ValueError):stream.append({"oversized":"x"*128})
            stream.close()
            sample=json.loads(path.read_text())
            self.assertEqual(sample["by_validator"]["validator-02"]["error"],"TimeoutError")
            self.assertEqual(stream.summary()["samples"],1)
            self.assertEqual(stream.summary()["sha3_256"],MODULE.hash_file(path))
            self.assertTrue(stream.summary()["closed"])

    def test_stream_reserve_failure_preserves_prior_frames(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"native-observations.jsonl"
            stream=MODULE.NativeObservationStream(path)
            with patch.object(MODULE.shutil,"disk_usage",return_value=SimpleNamespace(free=0)):
                with self.assertRaises(ValueError):stream.append({"sample":1})
            stream.close();self.assertEqual(path.read_bytes(),b"")


class ThreadLocalRelayContracts(unittest.TestCase):
    def environment(self, connection_failure=None, response_status=200, payload=b'{"result":1}', restore_failure=False, enter_failure=False):
        from contextlib import ExitStack
        from types import SimpleNamespace
        import threading
        state=threading.local();events=[]
        def opened(path,flags):
            self.assertEqual(path,"/proc/thread-self/ns/net")
            self.assertTrue(flags & MODULE.os.O_CLOEXEC)
            state.namespace="origin";events.append("open-origin");return 73
        def setns(fd,kind):
            self.assertEqual(kind,0x40000000)
            if fd==73:
                events.append("restore")
                if restore_failure:raise OSError("restore failure")
                state.namespace="origin"
            else:
                events.append("enter")
                if enter_failure:raise OSError("enter failure")
                state.namespace="target"
        def connect(host,port,timeout):
            self.assertEqual((host,port,timeout),("127.0.0.1",8547,10))
            self.assertEqual(state.namespace,"target");events.append("connect")
            def request(method,path,body,headers):
                self.assertEqual(state.namespace,"target")
                self.assertEqual((method,path,body),("POST","/",b'{}'))
                if connection_failure:raise connection_failure
            def read(limit):
                self.assertEqual(limit,MODULE.MAX+1);self.assertEqual(state.namespace,"target")
                return payload
            def close():
                self.assertEqual(state.namespace,"target");events.append("socket-close")
            return SimpleNamespace(request=request,getresponse=lambda:SimpleNamespace(status=response_status,read=read),close=close)
        stack=ExitStack()
        stack.enter_context(patch.object(MODULE.sys,"platform","linux"))
        stack.enter_context(patch.object(MODULE.os,"CLONE_NEWNET",0x40000000,create=True))
        stack.enter_context(patch.object(MODULE.os,"setns",side_effect=setns,create=True))
        stack.enter_context(patch.object(MODULE.os,"open",side_effect=opened))
        stack.enter_context(patch.object(MODULE.os,"close",side_effect=lambda fd:events.append(("close-origin",fd))))
        stack.enter_context(patch.object(MODULE.http.client,"HTTPConnection",side_effect=connect))
        spawned=stack.enter_context(patch.object(MODULE.subprocess,"run",side_effect=AssertionError("per-request subprocess forbidden")))
        stack.enter_context(patch.object(MODULE.subprocess,"Popen",side_effect=AssertionError("per-request subprocess forbidden")))
        return stack,state,events,spawned

    def test_success_closes_socket_then_restores_same_thread_without_subprocess(self):
        stack,state,events,spawned=self.environment()
        with stack:
            self.assertEqual(MODULE.relay_native_rpc(99,2,b'{}'),b'{"result":1}')
        self.assertEqual(state.namespace,"origin")
        self.assertEqual(events,["open-origin","enter","connect","socket-close","restore",("close-origin",73)])
        spawned.assert_not_called()

    def test_native_error_timeout_size_and_connection_failures_restore_namespace(self):
        for kwargs in ({"connection_failure":ConnectionRefusedError()}, {"connection_failure":TimeoutError()},
                       {"response_status":503}, {"payload":b'x'*(MODULE.MAX+1)}):
            with self.subTest(kwargs=list(kwargs)):
                stack,state,events,_=self.environment(**kwargs)
                with stack,self.assertRaises((OSError,ValueError)):
                    MODULE.relay_native_rpc(99,2,b'{}')
                self.assertEqual(state.namespace,"origin")
                self.assertLess(events.index("socket-close"),events.index("restore"))
                self.assertEqual(events[-1],("close-origin",73))

    def test_enter_failure_restores_original_and_never_opens_socket(self):
        stack,state,events,_=self.environment(enter_failure=True)
        with stack,self.assertRaisesRegex(OSError,"enter failure"):
            MODULE.relay_native_rpc(99,2,b'{}')
        self.assertNotIn("connect",events)
        self.assertEqual(state.namespace,"origin")
        self.assertEqual(events[-1],("close-origin",73))

    def test_restore_failure_cannot_return_success_and_closes_original_descriptor(self):
        stack,_,events,_=self.environment(restore_failure=True)
        with stack,self.assertRaisesRegex(OSError,"restore failure"):
            MODULE.relay_native_rpc(99,2,b'{}')
        self.assertEqual(events[-1],("close-origin",73))

    def test_unsupported_host_fails_before_opening_namespace_or_spawning(self):
        for platform,supported in (("darwin",True),("linux",False)):
            with patch.object(MODULE.sys,"platform",platform),patch.object(MODULE.os,"setns",None if not supported else lambda *_:None,create=True), \
                    patch.object(MODULE.os,"open") as opened,patch.object(MODULE.subprocess,"run") as spawned:
                with self.assertRaisesRegex(RuntimeError,"Linux thread-local"):
                    MODULE.relay_native_rpc(99,2,b'{}')
                opened.assert_not_called();spawned.assert_not_called()

    def test_shutdown_keeps_accepted_worker_namespace_pinned_until_worker_exit(self):
        import threading
        from types import SimpleNamespace
        relay=object.__new__(MODULE.Relay)
        relay.namespace_fd=99;relay.namespace_lock=threading.Lock()
        relay.request_namespace=threading.local();relay.slots=threading.BoundedSemaphore(32)
        relay.socket=SimpleNamespace(close=lambda:None)
        work=[]
        def thread(**kwargs):
            work.append(kwargs);return SimpleNamespace(start=lambda:None)
        def serve(_request,_address):
            self.assertEqual(relay.request_namespace.fd,177)
        with patch.object(MODULE.os,"dup",return_value=177) as duplicated,patch.object(MODULE.os,"close") as closed, \
                patch.object(MODULE.threading,"Thread",side_effect=thread), \
                patch.object(MODULE.http.server.ThreadingHTTPServer,"process_request_thread",side_effect=serve):
            relay.process_request("request","address")
            duplicated.assert_called_once_with(99)
            relay.server_close()
            closed.assert_called_once_with(99)
            self.assertIsNone(relay.namespace_fd)
            work[0]["target"](*work[0]["args"])
            self.assertEqual(closed.call_args_list,[unittest.mock.call(99),unittest.mock.call(177)])
            self.assertFalse(hasattr(relay.request_namespace,"fd"))
        self.assertEqual(relay.slots._value,32)

    def test_worker_start_failure_releases_pinned_descriptor_and_slot(self):
        import threading
        from types import SimpleNamespace
        relay=object.__new__(MODULE.Relay)
        relay.namespace_fd=99;relay.namespace_lock=threading.Lock();relay.slots=threading.BoundedSemaphore(32)
        def fail():raise RuntimeError("worker start failed")
        with patch.object(MODULE.os,"dup",return_value=177),patch.object(MODULE.os,"close") as closed, \
                patch.object(MODULE.threading,"Thread",return_value=SimpleNamespace(start=fail)):
            with self.assertRaisesRegex(RuntimeError,"worker start failed"):
                relay.process_request("request","address")
            closed.assert_called_once_with(177)
        self.assertEqual(relay.slots._value,32)

    def test_invalid_request_never_enters_namespace(self):
        with patch.object(MODULE,"relay_network_namespace") as namespace:
            for index,body in ((-1,b'{}'),(5,b'{}'),(True,b'{}'),(0,b''),(0,b'x'*(1024*1024+1))):
                with self.assertRaises(ValueError):MODULE.relay_native_rpc(99,index,body)
            namespace.assert_not_called()

if __name__=="__main__":unittest.main()

class ScheduledMemoryInterval(unittest.TestCase):
    def test_declared_cohort_drains_before_fault_with_rejoin_interval(self):
        stages,budget,stop,lifetime=MODULE.traffic_schedule("memory")
        self.assertEqual(sum(count for _,_,_,count in stages),31)
        self.assertIsNone(stages[1][1])
        self.assertEqual(stages[1][2],300)
        self.assertEqual(stages[1][3],30)
        self.assertGreater(stop,10+sum(duration+90 for _,_,duration,_ in stages))
        self.assertGreaterEqual(lifetime-(stop+30),120)
        self.assertLess(lifetime+30,900)
        self.assertEqual((budget,stop,lifetime),(501,531,681))

    def test_schedule_cannot_silently_select_an_unknown_workload(self):
        with self.assertRaises(ValueError):MODULE.traffic_schedule("unrecognized")

class ClosedLoopMemoryAcceptance(unittest.TestCase):
    def test_memory_arguments_have_count_deadline_and_no_offered_rate(self):
        args=MODULE.traffic_stage_arguments("memory","funded-memory-30",None,300,30)
        self.assertIn("closed-loop-memory",args)
        self.assertNotIn("--rate-tps",args)
        self.assertEqual(args[args.index("--max-tx")+1],"30")
        self.assertEqual(args[args.index("--duration-seconds")+1],"300")
        initial=MODULE.traffic_stage_arguments("memory","steady-state-transfer",1,1,1)
        self.assertIn("--rate-tps",initial)
        self.assertNotIn("--workload-mode",initial)

    def test_count_alone_cannot_pass_without_deadline_and_exact_effects(self):
        report=dict(status="completed",finalized_transactions=30,generator_limited=False,
            generator_missed_offered_slots=None,workload_mode="closed-loop-memory",
            requested_transactions=30,attempted_transactions=30,submitted_transactions=30,
            remaining_in_flight=0,wallet_effects_verified_all_five=True,
            workload_deadline_seconds=300,workload_deadline_met=True,TPS_qualified=False,
            capacity_result=False,offered_rate_tps=None)
        MODULE.validate_scheduled_traffic_result("memory","funded-memory-30",30,report)
        for field,value in [("workload_deadline_met",False),("wallet_effects_verified_all_five",False),
                ("attempted_transactions",29),("remaining_in_flight",1),("offered_rate_tps",1),
                ("capacity_result",True),("TPS_qualified",True)]:
            with self.subTest(field=field),self.assertRaises(RuntimeError):
                MODULE.validate_scheduled_traffic_result("memory","funded-memory-30",30,dict(report,**{field:value}))
