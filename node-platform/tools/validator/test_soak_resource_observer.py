import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

SPEC = importlib.util.spec_from_file_location('soak_observer', Path(__file__).with_name('soak-resource-observer.py'))
OBS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBS)


def sample(height=100, at=0):
    return {'unit': {'MainPID': '4', 'NRestarts': '0', 'ActiveState': 'active', 'ControlGroup': '/node',
            'ExecMainStartTimestampMonotonic': '10'}, 'boot_id': 'boot', 'unix_s': 1000 + at,
        'monotonic_s': at, 'process': {'status': {'VmSwap': '0 kB'},
            'stat': {'starttime_ticks': 11}, 'io': {'write_bytes': height * 50, 'read_bytes': 20}},
        'cgroup': {'memory.max': '1073741824', 'memory.swap.max': '0', 'memory.swap.current': '0',
            'memory.events': 'max 1097\noom 2\noom_kill 1\n', 'cpu.stat': 'usage_usec 5\n',
            'io.stat': '8:0 rbytes=10 wbytes=20 rios=1 wios=2\n',
            **{kind+'.pressure': 'some avg10=0.00 total=10\nfull avg10=0.00 total=0\n' for kind in ('cpu','memory','io')}},
        'telemetry': {'chain_id': 9001, 'network_identity': 'selected', 'finalized_height': height,
            'common_finalized_commitment': {'height': height, 'block_id': 'block', 'state_root': 'state',
                'finality_certificate_id': 'qc', 'protected_execution_root': 'execution'},
            'chain': {'finalized_total': 1, 'cadence': {'samples': 7, 'current_gap_ms': 100, 'maximum_gap_ms': 1000}}}}


class MonitorTests(unittest.TestCase):
    def test_baseline_historical_events_are_not_new_ooms(self):
        monitor = OBS.Monitor(9001, 'selected')
        monitor.check(sample())
        current = sample(102, 15)
        current['cgroup']['memory.events'] = 'max 1098\noom 2\noom_kill 1\n'
        summary = monitor.check(current)
        self.assertEqual(summary['memory_events_delta'], {'max': 1, 'oom': 0, 'oom_kill': 0})
        self.assertEqual(summary['process_io_per_finalized_block']['write_bytes'], 50)
        self.assertIsNone(summary['transaction_finality_latency_ms'])

    def test_oom_restart_counter_reset_identity_clock_and_stall_fail(self):
        cases = []
        def change(section, key, value):
            current = sample(101, 15); current[section][key] = value; return current
        cases += [change('unit','MainPID','5'), change('unit','NRestarts','1'), change('unit','ActiveState','failed'),
            change('cgroup','memory.events','max 1097\noom 3\noom_kill 1\n'),
            change('cgroup','memory.events','max 0\noom 0\noom_kill 0\n'),
            change('cgroup','memory.swap.current','4096'), change('cgroup','memory.max','2147483648'),
            change('telemetry','chain_id',1266), change('telemetry','network_identity','foreign')]
        current = sample(101,15); current['boot_id']='reboot';cases.append(current)
        current = sample(101,15); current['unix_s']+=6;cases.append(current)
        current = sample(101,15); current['process']['stat']['starttime_ticks']=12;cases.append(current)
        current = sample(101,15); current['process']['io']['read_bytes']=0;cases.append(current)
        cases.append(sample(99,15));cases.append(sample(100,31))
        for current in cases:
            with self.subTest(current=current):
                monitor=OBS.Monitor(9001,'selected');monitor.check(sample())
                with self.assertRaises(OBS.Failure):monitor.check(current)

    def test_native_cadence_required_and_30second_rule_preserved(self):
        for key,value in [('current_gap_ms',30000.01),('maximum_gap_ms',None),('samples',0),('current_gap_ms',float('nan'))]:
            current=sample();current['telemetry']['chain']['cadence'][key]=value
            with self.subTest(field=key,value=value),self.assertRaises(OBS.Failure):
                OBS.Monitor(9001,'selected').check(current)

    def test_pre_window_maximum_does_not_require_a_validator_restart(self):
        monitor = OBS.Monitor(9001, 'selected')
        first = sample()
        first['telemetry']['chain']['cadence']['maximum_gap_ms'] = 90000
        monitor.check(first)
        current = sample(110, 15)
        current['telemetry']['chain']['cadence']['maximum_gap_ms'] = 90000
        monitor.check(current)
        # A smaller-than-historical gap must not disappear behind the90s max.
        late = sample(112, 46)
        late['telemetry']['chain']['cadence']['maximum_gap_ms'] = 90000
        with self.assertRaisesRegex(OBS.Failure, 'interval'):
            monitor.check(late)

    def test_new_gap_current_gap_and_lost_coverage_fail_despite_old_maximum(self):
        for mutate in ('new_maximum', 'current_gap', 'stationary', 'maximum_reset'):
            with self.subTest(mutate=mutate):
                monitor = OBS.Monitor(9001, 'selected')
                first = sample()
                first['telemetry']['chain']['cadence']['maximum_gap_ms'] = 90000
                monitor.check(first)
                current = sample(101, 15)
                cadence = current['telemetry']['chain']['cadence']
                cadence['maximum_gap_ms'] = 90000
                if mutate == 'new_maximum':
                    cadence['maximum_gap_ms'] = 100000
                elif mutate == 'current_gap':
                    cadence['current_gap_ms'] = 30001
                elif mutate == 'stationary':
                    current = sample(100, 31)
                    current['telemetry']['chain']['cadence']['maximum_gap_ms'] = 90000
                else:
                    cadence['maximum_gap_ms'] = 80000
                with self.assertRaises(OBS.Failure):
                    monitor.check(current)

    def test_new_io_device_is_unknown_delta_not_zero(self):
        first=sample();first['cgroup']['io.stat']=''
        monitor=OBS.Monitor(9001,'selected');monitor.check(first)
        self.assertIsNone(monitor.check(sample(101,15))['cgroup_io_delta']['8:0'])


class InventoryEvidenceTests(unittest.TestCase):
    def test_incremental_inventory_counts_without_following_symlinks_or_opening_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);app=root/'app';posy=app/'data/consensus/posy';posy.mkdir(parents=True)
            for relative in ['sign-once.json','delivery.json','recovery.json','.synergy-writer.lock',
                'consensus-evidence-v1.sqlite3','consensus-evidence-v1.sqlite3-journal',
                'verified-qcs/qc/1.json','finality/h1.json','verified-timeouts/h1r0.json',
                '.transactions/1/staged/2','ready-h1.json','validation-h1.json','signature-a.json',
                'archive/segment-00000000000000000001.sya']:
                path=posy/relative;path.parent.mkdir(exist_ok=True,parents=True);path.write_bytes(b'123')
            (posy/'archive/segment-00000000000000000002.sya').write_bytes(b'1234567')
            (app/'outside').symlink_to(root, target_is_directory=True)
            inventory=OBS.Inventory(app,100)
            result=None;steps=0
            original=OBS.os.open
            def only_directories(path,flags,*args,**kwargs):
                self.assertTrue(flags & os.O_DIRECTORY,'inventory must not read file contents')
                return original(path,flags,*args,**kwargs)
            with patch.object(OBS.os,'open',side_effect=only_directories):
                while result is None:
                    result=inventory.step(101,limit=1,seconds=1);steps+=1
            self.assertGreater(steps,10)
            groups=result['groups']
            self.assertEqual(groups['posy_active_safety']['files'],4)
            self.assertEqual(groups['posy_indexed_history']['files'],1)
            self.assertEqual(groups['posy_legacy_history']['files'],6)
            self.assertEqual(groups['posy_ephemeral_working']['files'],2)
            self.assertEqual(groups['posy_segment_history']['files'],2)
            self.assertEqual(groups['posy_segment_history']['directories'],1)
            self.assertEqual(groups['posy_segment_history']['logical_bytes'],10)
            self.assertEqual(groups['posy_segment_history']['max_file_bytes'],7)
            self.assertEqual(groups['posy_active_safety']['max_file_bytes'],3)
            self.assertEqual(groups['other_application']['symlinks'],1)
            self.assertFalse(result['snapshot_atomic']);self.assertIsNone(result['indexed_history_rows'])
            self.assertEqual(inventory.stack,[])
            self.assertIsInstance(result['end_monotonic_s'],float)
            self.assertGreaterEqual(result['end_monotonic_s'],inventory.started_mono)

    def test_inventory_bound_closes_descriptors_and_reports_no_partial_total(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'a').write_text('a');(root/'b').write_text('b')
            inventory=OBS.Inventory(root,1,max_entries=1)
            with self.assertRaises(OBS.Failure):inventory.step(2,seconds=1)
            self.assertEqual(inventory.stack,[])

    def test_private_evidence_atomic_terminal_and_no_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);root.chmod(0o700)
            writer=OBS.Evidence(root);writer.append('samples.jsonl',{'height':1})
            writer.save('terminal.json',{'status':'FAILED','soak_pass':False});writer.close()
            self.assertEqual(json.loads((root/'terminal.json').read_text())['status'],'FAILED')
            self.assertEqual((root/'terminal.json').stat().st_mode & 0o777,0o600)
            with self.assertRaises(OBS.Failure):OBS.Evidence(root)

    def test_startup_failure_is_durable_and_has_no_node_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);root.chmod(0o700)
            args=SimpleNamespace(evidence=root,evidence_budget_bytes=8*1024*1024,run_id='fresh',validator='val2',
                duration_seconds=87000,sample_seconds=15,inventory_seconds=300,
                expected_executable_sha256='a'*64,normalized_config_sha256='b'*64,app_root=Path('/opt/Synergy'),
                chain_id=9001,network_id='selected',relay_address=None)
            with patch.object(OBS,'bounded_read',side_effect=OBS.Failure('fixture preflight failure')),patch.object(OBS.signal,'signal'):
                self.assertEqual(OBS.run(args),1)
            terminal=json.loads((root/'terminal.json').read_text())
            self.assertEqual(terminal['status'],'FAILED');self.assertEqual(terminal['node_action'],'none')
            self.assertIn('never stitch',terminal['instruction'])

    def test_complete_short_observer_window_never_claims_soak_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);evidence=root/'evidence';evidence.mkdir(mode=0o700)
            app=root/'app';(app/'data').mkdir(parents=True)
            genesis=root/'genesis';genesis.write_text('signed fixture')
            authority=root/'authority';authority.write_text('signed authority fixture')
            config=root/'node.json';config.write_text(json.dumps({'chain_id':9001,'network_id':'selected',
                'genesis_path':str(genesis),'consensus':{'authority_binding':str(authority)},
                'storage':{'data_directory':str(app/'data')},'rpc':{'enabled':True,'listen_address':'127.0.0.1:8545'}}))
            args=SimpleNamespace(evidence=evidence,evidence_budget_bytes=8*1024*1024,run_id='fresh',validator='val2',
                duration_seconds=1,sample_seconds=1,inventory_seconds=300,config=config,service='synergy-node.service',
                expected_executable_sha256='a'*64,expected_config_sha256=OBS.hash_file(config),
                expected_genesis_sha256=OBS.hash_file(genesis),expected_authority_sha256=OBS.hash_file(authority),
                normalized_config_sha256='b'*64,app_root=app,chain_id=9001,network_id='selected',rpc_url=None,relay_address=None)
            original_read,original_hash=OBS.bounded_read,OBS.hash_file
            def read(path,*args):
                if str(path)=='/proc/self/cgroup':return b'0::/observer\n'
                if str(path).endswith('/observer/cpu.max'):return b'25000 100000'
                return original_read(path,*args)
            def hashed(path,*a,**k):
                return 'a'*64 if str(path).startswith('/proc/') else original_hash(path,*a,**k)
            count=[0]
            def collect(*unused):
                count[0]+=1;value=sample(100+count[0],time.monotonic())
                value['utc']=OBS.utc();value['telemetry']['chain']['finalized_total']=count[0]
                return value
            with patch.object(OBS,'bounded_read',side_effect=read),patch.object(OBS,'hash_file',side_effect=hashed), \
                    patch.object(OBS,'read_cgroup',return_value={'memory.max':'67108864','memory.swap.max':'0'}), \
                    patch.object(OBS,'system_unit',return_value={'MainPID':'4'}),patch.object(OBS,'collect',side_effect=collect), \
                    patch.object(OBS.ProcessDetails,'enrich'),patch.object(OBS.signal,'signal'):
                self.assertEqual(OBS.run(args),0)
            terminal=json.loads((evidence/'terminal.json').read_text())
            self.assertEqual(terminal['status'],'OBSERVATION_WINDOW_COMPLETE_NEEDS_CONTROLLER_QUALIFICATION')
            self.assertFalse(terminal['soak_pass']);self.assertFalse(terminal['full_24h_elapsed'])
            self.assertEqual(terminal['finalized_transaction_count_delta'],1)
            self.assertEqual(len((evidence/'samples.jsonl').read_text().splitlines()),2)

    def test_rpc_endpoint_uses_config_and_rejects_nonloopback_or_admin_socket(self):
        self.assertEqual(OBS.local_url({'rpc':{'enabled':True,'listen_address':'127.0.0.1:8545'}}),'http://127.0.0.1:8545/')
        self.assertEqual(OBS.local_url({'rpc':{'enabled':True,'listen_address':'[::1]:8545'}}),'http://[::1]:8545/')
        for config in [{},{'admin_socket_path':'/opt/Synergy/run/admin.sock'}, {'rpc':{'enabled':True,'listen_address':'0.0.0.0:8545'}}]:
            with self.assertRaises(OBS.Failure):OBS.local_url(config)
        for override in ['http://10.0.0.1:8545/','https://127.0.0.1/','http://user:secret@127.0.0.1/']:
            with self.assertRaises(OBS.Failure):OBS.local_url({},override)

    def test_header_and_body_allocation_limits_before_parser(self):
        limited=OBS.LimitedInput(io.BytesIO(b'X'*8193+b'\r\n'))
        with self.assertRaises(ValueError):limited.readline()
        limited=OBS.LimitedInput(io.BytesIO(b'\r\n'+b'x'*OBS.MAX_REQUEST))
        limited.readline();self.assertEqual(len(limited.read1(OBS.MAX_REQUEST)),OBS.MAX_REQUEST)
        with self.assertRaises(ValueError):limited.read1(1)


class DetailedMemoryTests(unittest.TestCase):
    def test_duration_specific_projection_and_actual_quota_fail_closed(self):
        projection=OBS.evidence_projection(24000,87000,5,300,512*1024*1024)
        self.assertEqual(projection['sample_count'],17401)
        self.assertTrue(projection['fits_budget'])
        self.assertFalse(projection['future_growth_guaranteed'])
        self.assertFalse(OBS.evidence_projection(40000,87000,5,300,512*1024*1024)['fits_budget'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory);path.chmod(0o700)
            writer=OBS.Evidence(path,budget=1024*1024+10)
            try:
                with self.assertRaisesRegex(OBS.Failure,'budget'):
                    writer.append('samples.jsonl',{'must_not_partially_write':True})
                self.assertEqual((path/'samples.jsonl').stat().st_size,0)
            finally:writer.close()

    def test_only_canonical_archive_segment_names_are_history(self):
        prefix='data/consensus/posy/'
        self.assertEqual(OBS.storage_class(prefix+'archive/segment-00000000000000000001.sya'),'posy_segment_history')
        self.assertEqual(OBS.storage_class(prefix+'archive'),'posy_segment_history')
        for name in ('archive/segment-1.sya','archive/segment-00000000000000000001.sya.tmp',
                     'archive/foreign-00000000000000000001.sya','archive/segment-0000000000000000000x.sya'):
            self.assertEqual(OBS.storage_class(prefix+name),'posy_other')
        self.assertEqual(OBS.storage_class(prefix+'consensus-evidence-v1.sqlite3'),'posy_indexed_history')

    def test_rollup_units_missing_optional_fields_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory);(proc/'4').mkdir()
            path=proc/'4/smaps_rollup'
            raw='0000-ffff ---p 00000000 00:00 0 [rollup]\nRss: 12 kB\nPss: 9 kB\nPrivate_Dirty: 3 kB\nSwap: 0 kB\nPss_Anon: 8 kB\n'
            path.write_text(raw)
            result=OBS.read_smaps_rollup(4,proc)
            self.assertEqual(result['fields_bytes']['Pss'],9216)
            self.assertEqual(result['fields_bytes']['Pss_Anon'],8192)
            self.assertNotIn('Pss_File',result['fields_bytes'])
            self.assertIn('Pss_File',result['unavailable_fields'])
            path.write_text(raw.replace('12 kB','12 MB'))
            with self.assertRaisesRegex(OBS.Failure,'counter'):OBS.read_smaps_rollup(4,proc)
            path.write_text('x'*65537)
            with self.assertRaisesRegex(OBS.Failure,'bound'):OBS.read_smaps_rollup(4,proc)
            path.unlink();self.assertFalse(OBS.read_smaps_rollup(4,proc)['supported'])

    def test_precise_memory_and_fd_cadences_do_not_repeat_directory_walks(self):
        details=OBS.ProcessDetails();observations=[]
        def value(at):
            return {'monotonic_s':at,'utc':str(at),'unit':{'MainPID':'4'},'process':{},
                    'observer':{'pid':5,'process':{}}}
        with patch.object(OBS,'read_smaps_rollup',return_value={'supported':True,'fields_bytes':{'Pss':8192}}) as rollup, \
                patch.object(OBS,'read_fds',return_value=17) as fds:
            for at in (0,5,29,30,59,60):
                current=value(at);details.enrich(current);observations.append(current)
            self.assertEqual(rollup.call_count,6)  #2processes x t0,t30,t60.
            self.assertEqual(fds.call_count,4)  #2processes x t0,t60.
            self.assertEqual(observations[4]['process']['smaps_rollup']['monotonic_s'],30)
            self.assertEqual(observations[4]['process']['fd_observation']['monotonic_s'],0)
            self.assertEqual(observations[5]['process']['fd_observation']['monotonic_s'],60)
            self.assertEqual(observations[0]['process']['smaps_rollup']['monotonic_s'],0)

    def test_local_oom_counters_are_checked_independently_of_ancestor_totals(self):
        for local in ('max 20\noom 3\noom_kill 1\n','max 0\noom 0\noom_kill 0\n',
                      'max 20\noom 2\n',None):
            first=sample();first['cgroup']['memory.events.local']='max 20\noom 2\noom_kill 1\n'
            monitor=OBS.Monitor(9001,'selected');monitor.check(first)
            current=sample(101,5)
            if local is not None:current['cgroup']['memory.events.local']=local
            with self.assertRaisesRegex(OBS.Failure,'memory event|OOM'):monitor.check(current)


class Backend(BaseHTTPRequestHandler):
    calls=[]
    claimed_size=None
    native_error=False
    stream_bytes=0
    def log_message(self,*args):pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']));value=json.loads(body)
        type(self).calls.append(value)
        encoded=json.dumps({'jsonrpc':'2.0','id':value['id'], **({'error':{'code':-32000,'message':'admission receipt unavailable; verify finalized transaction before retry'}} if self.native_error else {'result':{'height':101}})}).encode()
        self.send_response(200);self.send_header('Content-Length',str(self.claimed_size or self.stream_bytes or len(encoded)));self.end_headers()
        if self.stream_bytes:
            remaining=self.stream_bytes
            while remaining:
                block=b'x'*min(16384,remaining);self.wfile.write(block);remaining-=len(block)
        else:
            self.wfile.write(encoded)


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend=HTTPServer(('127.0.0.1',0),Backend)
        cls.backthread=threading.Thread(target=cls.backend.serve_forever,daemon=True);cls.backthread.start()
        cls.token=b'a'*48
        cls.relay=OBS.Relay(('127.0.0.1',0),'http://127.0.0.1:'+str(cls.backend.server_port)+'/',cls.token,'run')
        cls.thread=threading.Thread(target=lambda:cls.relay.serve_forever(poll_interval=0.05),daemon=True);cls.thread.start()
        cls.url='http://127.0.0.1:'+str(cls.relay.server_port)
    @classmethod
    def tearDownClass(cls):
        cls.relay.stop();cls.thread.join();cls.backend.shutdown();cls.backend.server_close();cls.backthread.join()
    def setUp(self):Backend.calls=[];Backend.claimed_size=None;Backend.native_error=False;Backend.stream_bytes=0
    def request(self,body=None,token=None,path='/'):
        headers={'Authorization':'Bearer '+(token or self.token).decode()}
        return urllib.request.urlopen(urllib.request.Request(self.url+path,data=body,headers=headers),timeout=6)

    def test_implemented_transaction_read_is_allowed_and_nonexistent_receipt_is_denied(self):
        self.assertIn('synergy_getTransaction', OBS.READ_METHODS)
        self.assertNotIn('synergy_getProcessingTransactionReceipt', OBS.READ_METHODS)
        body=json.dumps({'jsonrpc':'2.0','id':7,'method':'synergy_getTransaction','params':{'transaction_id':'ab'}}).encode()
        with self.request(body) as response:self.assertEqual(json.load(response)['id'],7)
        self.assertEqual(Backend.calls[-1]['method'],'synergy_getTransaction')
        rejected=json.dumps({'jsonrpc':'2.0','id':8,'method':'synergy_getProcessingTransactionReceipt','params':{}}).encode()
        with self.assertRaises(urllib.error.HTTPError) as error:self.request(rejected)
        self.assertEqual(error.exception.code,403)
        self.assertEqual(len(Backend.calls),1)

    def test_authenticated_exact_allowlist_and_native_error_envelope_pass_through(self):
        for method in OBS.READ_METHODS:
            body=json.dumps({'jsonrpc':'2.0','id':7,'method':method,'params':{}}).encode()
            with self.request(body) as response:self.assertEqual(json.load(response)['id'],7)
        self.assertEqual({v['method'] for v in Backend.calls},OBS.READ_METHODS)
        Backend.native_error=True
        body=json.dumps({'jsonrpc':'2.0','id':9,'method':'synergy_getProtectedAdmissionReceipt','params':{}}).encode()
        with self.request(body) as response:
            value=json.load(response)
        self.assertEqual(value['error']['code'],-32000);self.assertEqual(value['id'],9)

    def test_submission_admin_batch_wrong_token_and_large_body_never_reach_node(self):
        for value in [{'jsonrpc':'2.0','id':1,'method':'synergy_submitProcessingTransactionV1','params':{}},
            {'jsonrpc':'2.0','id':1,'method':'synergy_stop','params':{}}, {'jsonrpc':'2.0','id':1,'method':{},'params':{}},[],{'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':[]}]:
            with self.assertRaises(urllib.error.HTTPError) as error:self.request(json.dumps(value).encode())
            self.assertEqual(error.exception.code,403)
        with self.assertRaises(urllib.error.HTTPError) as error:self.request(b'{}',b'wrong')
        self.assertEqual(error.exception.code,401)
        with self.assertRaises(urllib.error.HTTPError) as error:self.request(b'x'*(OBS.MAX_REQUEST+1))
        self.assertEqual(error.exception.code,413)
        with self.assertRaises(urllib.error.HTTPError) as error:self.request(b'['*65+b'0'+b']'*65)
        self.assertEqual(error.exception.code,400)
        self.assertEqual(Backend.calls,[])

    def test_cached_sample_authenticated_and_response_cap(self):
        self.relay.publish({'run_id':'run','utc':'actual','telemetry':{'finalized_height':102}})
        with self.request(path='/sample') as response:self.assertEqual(json.load(response)['telemetry']['finalized_height'],102)
        Backend.claimed_size=OBS.MAX_RESPONSE+1
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':{}}).encode()
        with self.assertRaises(urllib.error.HTTPError) as error:self.request(body)
        self.assertEqual(error.exception.code,502)

    def test_four_worker_bound_rejects_excess_without_thread_queue(self):
        held=[]
        try:
            for _ in range(4):
                held.append(socket.create_connection(self.relay.server_address,timeout=1))
            end=time.monotonic()+2
            while time.monotonic()<end:
                with self.relay.guard:count=len(self.relay.active)
                if count==4:break
                time.sleep(0.005)
            self.assertEqual(count,4)
            excess=socket.create_connection(self.relay.server_address,timeout=1);excess.settimeout(1)
            self.assertEqual(excess.recv(1),b'');excess.close()
            with self.relay.guard:self.assertEqual(len(self.relay.active),4)
        finally:
            for stream in held:stream.close()
            end=time.monotonic()+2
            while time.monotonic()<end:
                with self.relay.guard:count=len(self.relay.active)
                if not count:break
                time.sleep(0.005)

    def test_streaming_response_does_not_require_a_full_body_buffer(self):
        Backend.stream_bytes=2*1024*1024
        body=json.dumps({'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':{}}).encode()
        count=0
        with self.request(body) as response:
            while True:
                block=response.read(32768)
                if not block:break
                self.assertEqual(block,b'x'*len(block));count+=len(block)
        self.assertEqual(count,Backend.stream_bytes)

    def test_incomplete_header_cannot_hold_worker_beyond_total_deadline(self):
        stream=socket.create_connection(self.relay.server_address,timeout=1);stream.settimeout(6.5)
        started=time.monotonic();stream.sendall(b'POST / HTTP/1.1\r\nX-Incomplete: ')
        try:
            self.assertEqual(stream.recv(1),b'')
            self.assertLess(time.monotonic()-started,6.5)
        finally:stream.close()

    def test_token_regular_private_file_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'token';path.write_bytes(self.token);path.chmod(0o600)
            self.assertEqual(OBS.read_token(path),self.token)
            path.chmod(0o644)
            with self.assertRaises(OBS.Failure):OBS.read_token(path)
            alias=path.with_name('alias');alias.symlink_to(path)
            with self.assertRaises(OBS.Failure):OBS.read_token(alias)


if __name__=='__main__':unittest.main()
