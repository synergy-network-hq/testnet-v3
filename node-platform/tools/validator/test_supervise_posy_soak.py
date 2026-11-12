import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request

spec = importlib.util.spec_from_file_location('supervisor', Path(__file__).with_name('supervise-posy-soak.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
observer = s.module(Path(__file__).with_name('soak-resource-observer.py'), 'supervisor_test_observer')


def observer_sample(name, at=1000, inventory_at=None):
    """Native observer schema; its host clock deliberately differs from controller time."""
    return {'run_id': 'qualification', 'validator': name, 'boot_id': 'boot-' + name,
        'unix_s': 10000 + at, 'monotonic_s': at, 'end_monotonic_s': at + .25,
        'unit': {'MainPID': '4', 'NRestarts': '0', 'ActiveState': 'active',
                 'ControlGroup': '/node', 'ExecMainStartTimestampMonotonic': '10'},
        'process': {'status': {'VmSwap': '0 kB'}, 'stat': {'starttime_ticks': 11},
                    'io': {'read_bytes': 0, 'write_bytes': 100}},
        'cgroup': {'memory.max': '1073741824', 'memory.swap.max': '0', 'memory.swap.current': '0',
            'memory.events': 'max 1097\noom 2\noom_kill 1\n', 'cpu.stat': 'usage_usec 5\n',
            'io.stat': '', **{kind + '.pressure': 'some avg10=0 total=0\nfull avg10=0 total=0\n'
                              for kind in ('cpu', 'memory', 'io')}},
        'telemetry': {'chain_id': 9001, 'network_identity': 'selected', 'finalized_height': 100,
            'common_finalized_commitment': {'height': 100, 'block_id': 'block', 'state_root': 'state',
                'finality_certificate_id': 'qc', 'protected_execution_root': 'execution'},
            'chain': {'finalized_total': 1, 'cadence': {'samples': 10, 'current_gap_ms': 100,
                                                     'maximum_gap_ms': 1000}}},
        'inventory': {'end_monotonic_s': at if inventory_at is None else inventory_at,
            'groups': {'posy_legacy_history': {'files': 70000},
                       'posy_indexed_history': {'files': 1, 'logical_bytes': 4096}}}}


class SupervisorObservationTests(unittest.TestCase):
    def controller(self):
        names = ('val2', 'val3', 'val4', 'val5', 'val6')
        c = object.__new__(s.Controller)
        c.config = {'run_id': 'qualification', 'network_id': 'selected', 'chain_id': 9001}
        c.endpoints = {name: 'read-' + name for name in names}
        c.h = SimpleNamespace(VALIDATORS=names, sample_fleet=Mock(return_value={'all_five': True}),
                              tip_record=Mock(return_value={'common_finalized_height': 100}))
        c.obs = SimpleNamespace(read_process=Mock(return_value={'separate': 'controller'}),
                                read_cgroup=Mock(return_value={'memory.max': '67108864'}))
        c.monitors = {name: observer.Monitor(9001, 'selected') for name in names}
        c.first = c.previous = None
        c.last_fresh = {}
        c.event = Mock()
        c.cached = {name: observer_sample(name) for name in names}
        c.get_sample = lambda name: (name, c.cached[name])
        return c

    def observe(self, c, now=10):
        with patch.object(s.time, 'monotonic', return_value=now), \
                patch.object(s.Path, 'read_text', return_value='0::/qualification-controller\n'):
            return c.observe()

    def test_requires_first_complete_inventory_on_every_validator(self):
        c = self.controller()
        c.cached['val6']['inventory'] = None
        with self.assertRaisesRegex(RuntimeError, 'inventory'):
            self.observe(c)
        c.h.sample_fleet.assert_not_called()

    def test_first_inventory_must_be_fresh_before_immutable_start(self):
        for invalid in (399, 1001, float('nan')):
            with self.subTest(inventory_end=invalid):
                c = self.controller()
                c.cached['val6']['inventory']['end_monotonic_s'] = invalid
                with self.assertRaisesRegex(RuntimeError, 'inventory'):
                    self.observe(c)
                c.h.sample_fleet.assert_not_called()

    def test_inventory_age_uses_collection_end_on_the_same_remote_clock(self):
        c = self.controller()
        # The scan completed after collection began, which is normal. A remote
        # timestamp must never be subtracted from the controller's clock (10).
        for sample in c.cached.values():
            sample['inventory']['end_monotonic_s'] = 1000.2
        self.observe(c)
        c.h.sample_fleet.assert_called_once_with(c.endpoints, 'selected', native_tips=True,
                                                expected_chain_id=9001, live_progress=True, native_prior_state=None)
        self.assertEqual(c.event.call_args.args[0]['controller_resources']['process'],
                         {'separate': 'controller'})

    def test_repeated_cache_does_not_rebaseline_and_expires(self):
        c = self.controller()
        self.observe(c, 10)
        baseline = c.monitors['val2'].baseline
        self.observe(c, 39)
        self.assertIs(c.monitors['val2'].baseline, baseline)
        with self.assertRaisesRegex(RuntimeError, 'fresh'):
            self.observe(c, 41)

    def test_native_gap_or_common_proof_disagreement_cannot_be_sampled_as_success(self):
        c = self.controller()
        c.cached['val5']['telemetry']['chain']['cadence']['current_gap_ms'] = 30001
        with self.assertRaisesRegex(observer.Failure, 'gap'):
            self.observe(c)
        c.event.assert_not_called()
        c = self.controller()
        c.h.sample_fleet.side_effect = RuntimeError('validators disagree on pinned state')
        with self.assertRaisesRegex(RuntimeError, 'disagree'):
            self.observe(c)
        c.event.assert_not_called()


class CachedRelayIntegrationTests(unittest.TestCase):
    def test_controller_reads_actual_authenticated_cached_relay_and_pins_identity(self):
        token = 'a' * 48
        relay = observer.Relay(('127.0.0.1', 0), 'http://127.0.0.1:1/', token.encode(), 'qualification')
        worker = threading.Thread(target=lambda: relay.serve_forever(poll_interval=.01), daemon=True)
        worker.start()
        try:
            c = object.__new__(s.Controller)
            c.config = {'run_id': 'qualification',
                'observer_endpoints': {'val2': 'http://127.0.0.1:' + str(relay.server_port)},
                'validators': {'val2': {'pid': 4, 'boot_id': 'boot-val2', 'starttime_ticks': 11}}}
            c.h = SimpleNamespace(RPC_TOKEN=token, NoRpcRedirect=urllib.request.HTTPRedirectHandler)
            original = observer_sample('val2')
            relay.publish(original)
            self.assertEqual(c.get_sample('val2'), ('val2', original))
            # A reachable server can keep returning exactly the same cache;
            # fetching it again must not manufacture a new observer timestamp.
            self.assertEqual(c.get_sample('val2')[1]['end_monotonic_s'], original['end_monotonic_s'])
            advanced = observer_sample('val2', at=1015)
            relay.publish(advanced)
            self.assertEqual(c.get_sample('val2')[1]['monotonic_s'], 1015)
            advanced['process']['stat']['starttime_ticks'] = 12
            relay.publish(advanced)
            with self.assertRaisesRegex(RuntimeError, 'identity'):
                c.get_sample('val2')
        finally:
            relay.stop()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())


class LoadCancellationIntegrationTests(unittest.TestCase):
    def stage_controller(self, root, completed=True):
        c = object.__new__(s.Controller)
        c.root, c.stop, c.end = root, threading.Event(), time.monotonic() + 1000
        c.number, c.stage_results, c.child = 0, [], None
        c.config = {'evidence_budget_bytes': 1024**3}
        c.h = SimpleNamespace(utc_now=lambda: 'actual-test-time')
        c.event = Mock()
        def command(rate, duration, output, proof, budget):
            report = dict(status='completed', clean_load_step=True, measurement_complete=True,
                wallet_effects_verified_all_five=True, remaining_in_flight=0, rejection_count=0,
                generator_limited=False, attempted_transactions=1, admitted_transactions=1,
                finalized_transactions=1, finalized_tps=.2,
                observed_client_latency_seconds={'context_to_finality': {'p50': 45, 'maximum': 45}},
                drain={'unresolved': 0})
            record = {'transaction_id': 'original-tx', 'receipt_id': 'original-receipt',
                      'sender': 'independent-wallet', 'wallet_id': 'wallet1', 'nonce': 7,
                      'submission_started': True}
            frames = [{'kind': 'submission', 'record': record}]
            if completed:
                frames.append({'kind': 'finalized_transfer', 'record': record})
            code = ('import pathlib,sys;pathlib.Path(sys.argv[1]).write_text(sys.argv[3]);'
                    'pathlib.Path(sys.argv[2]).write_text(sys.argv[4]);'
                    'print("disposable subprocess output");sys.exit(int(sys.argv[5]))')
            return [sys.executable, '-c', code, str(output), str(proof), json.dumps(report),
                    ''.join(json.dumps(frame) + '\n' for frame in frames), '0' if completed else '1']
        c.command = command
        return c

    def test_consumed_stage_deletes_raw_outputs_but_keeps_operating_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.stage_controller(Path(directory))
            with patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
                result = c.stage(.2, 1, 'fixture')
            self.assertTrue(result['clean'])
            self.assertEqual(result['latency']['context_to_finality']['maximum'], 45)
            self.assertEqual(c.stage_results, [result])
            self.assertEqual(list(c.root.iterdir()), [])
            self.assertIsNone(c.child)

    def test_failed_stage_consumes_raw_bytes_and_keeps_only_original_nonce_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            c = self.stage_controller(Path(directory), completed=False)
            with patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
                with self.assertRaisesRegex(RuntimeError, 'reconcile'):
                    c.stage(.2, 1, 'fixture')
            paths = list(c.root.iterdir())
            self.assertEqual(len(paths), 1)
            self.assertTrue(paths[0].name.endswith('-intent.json'))
            intent = json.loads(paths[0].read_text())
            self.assertTrue(intent['never_replay'])
            self.assertEqual(intent['unresolved_or_possibly_submitted'][0]['transaction_id'], 'original-tx')
            self.assertEqual(intent['unresolved_or_possibly_submitted'][0]['nonce'], 7)
            self.assertIn('Reconcile every registry wallet', intent['instruction'])
            self.assertEqual(c.stage_results, [])

    def test_active_checkpoint_restores_only_unresolved_original_intents(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'proof'
            active={'transaction_id':'original','sender':'wallet','nonce':7,'intent':{'amount_nwei':1}}
            path.write_text(json.dumps({'kind':'active_intent_checkpoint','active':[active],'totals':{'finalized':500}})+'\n')
            result=s.failure_reconciliation(path)
            self.assertTrue(result['proof_stream_complete'])
            self.assertEqual(result['unresolved_or_possibly_submitted'],[active])

    def test_partial_proof_does_not_license_resubmission_or_unbounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'proof'
            path.write_bytes(b'{"kind":"submission","record":{"transaction_id":"original","nonce":8}}\n{"partial"')
            value = s.failure_reconciliation(path)
            self.assertFalse(value['proof_stream_complete'])
            self.assertEqual(value['unresolved_or_possibly_submitted'][0]['nonce'], 8)
            path.write_bytes(b'x' * (4 * 1024**2 + 1))
            self.assertFalse(s.failure_reconciliation(path)['proof_stream_complete'])

    def test_evidence_scan_exception_still_terminates_live_load_child(self):
        with tempfile.TemporaryDirectory() as directory:
            c = object.__new__(s.Controller)
            c.root = Path(directory)
            c.stop = threading.Event()
            c.end = time.monotonic() + 1000
            c.number = 0
            c.config = {'evidence_budget_bytes': 1024**3}
            c.h = SimpleNamespace(utc_now=lambda: 'actual-test-time')
            c.command = Mock(return_value=[sys.executable, '-c', 'import time; time.sleep(60)'])
            c.event = Mock()
            children = []
            real_popen = subprocess.Popen

            def launch(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child

            try:
                with patch.object(s.subprocess, 'Popen', side_effect=launch), \
                        patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)), \
                        patch.object(s, 'evidence_bytes', side_effect=[0, RuntimeError('evidence scan fixture')]):
                    with self.assertRaisesRegex(RuntimeError, 'evidence scan fixture'):
                        c.stage(.2, 1, 'evidence-failure')
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll(), 'stage exception orphaned its load process')
            finally:
                for child in children:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=3)

    def test_evidence_total_includes_nested_scratch_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'sample').write_bytes(b'a' * 7)
            scratch = root / 'scratch' / 'author'
            scratch.mkdir(parents=True)
            (scratch / 'working').write_bytes(b'b' * 13)
            self.assertEqual(s.evidence_bytes(root), 20)
            (scratch / 'escape').symlink_to(root / 'sample')
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                s.evidence_bytes(root)

    def test_insufficient_remaining_evidence_budget_prevents_authoring(self):
        with tempfile.TemporaryDirectory() as directory:
            c = object.__new__(s.Controller)
            c.root = Path(directory)
            c.stop = threading.Event()
            c.end = time.monotonic() + 1000
            c.number = 0
            c.config = {'evidence_budget_bytes': 64 * 1024**2}
            c.command = Mock()
            with patch.object(s.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(RuntimeError, 'quota'):
                    c.stage(.2, 1, 'no-evidence-reserve')
                spawn.assert_not_called()
                c.command.assert_not_called()
            self.assertEqual(list(c.root.iterdir()), [])

    def test_failure_cancels_only_own_isolated_load_process_and_preserves_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            c = object.__new__(s.Controller)
            c.root = Path(directory)
            c.stop = threading.Event()
            c.end = time.monotonic() + 1000
            c.number = 0
            c.config = {'evidence_budget_bytes': 1024**3}
            c.h = SimpleNamespace(utc_now=lambda: 'actual-test-time')
            c.command = Mock(return_value=[sys.executable, '-c', 'import time; time.sleep(60)'])
            c.event = Mock()
            started = threading.Event()
            real_popen = subprocess.Popen
            children, failures = [], []

            def launch(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                started.set()
                return child

            def run():
                try:
                    c.stage(.2, 1, 'cancellation-fixture')
                except BaseException as error:
                    failures.append(error)

            with patch.object(s.subprocess, 'Popen', side_effect=launch), \
                    patch.object(s.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)), \
                    patch.object(s.os, 'killpg', wraps=os.killpg) as kill:
                worker = threading.Thread(target=run)
                worker.start()
                try:
                    self.assertTrue(started.wait(3), 'load child never started')
                    c.stop.set()
                    worker.join(timeout=5)
                    self.assertFalse(worker.is_alive(), 'controller left load running')
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    kill.assert_called_once_with(children[0].pid, signal.SIGTERM)
                    self.assertEqual(len(failures), 1)
                    self.assertIn('cancelled', str(failures[0]))
                    intent = json.loads(next(c.root.glob('*-intent.json')).read_text())
                    self.assertTrue(intent['never_replay'])
                    self.assertFalse((c.root / 'terminal.json').exists())
                finally:
                    c.stop.set()
                    for child in children:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=3)
                    worker.join(timeout=3)


class PrearmFreshnessTests(unittest.TestCase):
    def test_all_five_caches_must_advance_before_start_is_eligible(self):
        c = object.__new__(s.Controller)
        c.stop = SimpleNamespace(wait=Mock(return_value=False))
        names = ('val2', 'val3', 'val4', 'val5', 'val6')
        calls = []

        def observe():
            index = len(calls)
            calls.append(index)
            c.previous = {name: {'monotonic_s': 1015 if index and (name != 'val6' or index == 2)
                                else 1000} for name in names}
            return {'common_finalized_height': 100 + index}

        c.observe = observe
        with patch.object(s.time, 'monotonic', return_value=10):
            result = c.prearm()
        self.assertEqual(calls, [0, 1, 2])
        self.assertEqual(result['common_finalized_height'], 102)
        self.assertFalse(hasattr(c, 'start'), 'prearming must not start/reset the actual clock')

    def test_reachable_unchanging_cache_has_bounded_prearm_failure_without_clock(self):
        c = object.__new__(s.Controller)
        c.stop = SimpleNamespace(wait=Mock(return_value=False))

        def observe():
            c.previous = {'val2': {'monotonic_s': 1000}, 'val3': {'monotonic_s': 50000}}
            return {'common_finalized_height': 100}

        c.observe = Mock(side_effect=observe)
        with patch.object(s.time, 'monotonic', side_effect=[0, 0, 15, 30, 46]):
            with self.assertRaisesRegex(RuntimeError, 'fresh'):
                c.prearm()
        self.assertEqual(c.observe.call_count, 4)
        self.assertFalse(hasattr(c, 'start'))


class ImmutableWindowTests(unittest.TestCase):
    def run_fixture(self, root, interrupt_at=None, start_before=None):
        # Advance the real immutable86400-second contract on a deterministic
        # virtual clock. This is controller logic evidence, never a live soak.
        clock = SimpleNamespace(now=0.)
        c = object.__new__(s.Controller)
        c.root = root
        c.config = {'duration_seconds': 86400, 'sustainable_tps': 10, 'evidence_budget_bytes': 1024**3, 'validators': {
            name: {'executable_sha256': 'exe', 'package_sha256': 'sha'}
            for name in ('val2', 'val3', 'val4', 'val5', 'val6')},
            'release_manifest': 'manifest', 'package_sha256': 'sha',
            'executable_sha256': 'exe', 'functional_proof': str(root / 'functional.json'),
            'functional_proof_sha256': 'sha', 'network_id': 'selected', 'chain_id': 9001}
        if start_before is not None:
            c.config['start_before_monotonic'] = start_before
        (root / 'functional.json').write_text(json.dumps({'status': 'PASS',
            'wallet_effects_verified_all_five': True, 'network_id': 'selected', 'chain_id': 9001,
            'executable_sha256': 'exe'}))
        (root / 'TPS-RESULT.json').write_text('{}')
        c.h = SimpleNamespace(VALIDATORS=tuple(c.config['validators']), utc_now=lambda: str(clock.now))
        c.previous = {name: {'monotonic_s': 0} for name in c.config['validators']}
        c.prearm = lambda: {'common_finalized_height': 100}

        def observe():
            c.previous = {name: {'monotonic_s': clock.now} for name in c.config['validators']}
            return {'common_finalized_height': 100 + int(clock.now)}

        c.observe = observe
        c.stage_results = [{'finalized': 3}]
        c.failure = None

        class Stop:
            def wait(self, duration):
                self.assert_no_early_terminal()
                clock.now += duration
                return interrupt_at is not None and clock.now >= interrupt_at
            def assert_no_early_terminal(self):
                if clock.now < 86400 and (root / 'terminal.json').exists():
                    raise AssertionError('terminal created before immutable window elapsed')
            def set(self):
                pass

        class Workload:
            def __init__(self, target):
                pass
            def start(self):
                c.workload_done = True
            def join(self, timeout):
                pass
            def is_alive(self):
                return False

        c.stop = Stop()
        c.workloads = Mock()
        with patch.object(s.time, 'monotonic', side_effect=lambda: clock.now), \
                patch.object(s.threading, 'Thread', Workload), patch.object(s, 'digest', return_value='sha'):
            c.run()
        return clock

    def test_completion_requires_86400_seconds_and_end_audit_without_resetting_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clock = self.run_fixture(root)
            self.assertEqual(clock.now, 86404)  # Two post-deadline cache generations.
            manifest = json.loads((root / 'manifest.json').read_text())
            terminal = json.loads((root / 'terminal.json').read_text())
            self.assertEqual(manifest['actual_start_monotonic'], 0)
            self.assertEqual(terminal['status'], 'OBSERVATION_COMPLETE_REQUIRES_RETENTION_AND_END_AUDIT')
            self.assertFalse(terminal['soak_pass'])
            self.assertTrue(terminal['interval_checks_passed'])
            self.assertEqual(terminal['elapsed_seconds'], 86404)
            self.assertEqual(terminal['actual_start_utc'], manifest['actual_start_utc'])

    def test_interruption_cannot_pass_or_replace_start_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                self.run_fixture(root, interrupt_at=30)
            self.assertFalse((root / 'terminal.json').exists())
            manifest = json.loads((root / 'manifest.json').read_text())
            self.assertEqual(manifest['actual_start_monotonic'], 0)

    def test_expired_observer_coverage_cannot_start_or_reset_the_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, 'observer coverage'):
                self.run_fixture(root, start_before=-1)
            self.assertFalse((root / 'manifest.json').exists())


class ClosingCoverageTests(unittest.TestCase):
    def controller(self):
        c = object.__new__(s.Controller)
        c.previous = {name: {'monotonic_s': 1000} for name in ('val2', 'val3', 'val4', 'val5', 'val6')}
        c.stop = SimpleNamespace(wait=Mock(return_value=False))
        c.start, c.end = 100, 86500
        return c

    def test_two_post_deadline_generations_required_for_every_validator(self):
        c = self.controller()
        calls = []

        def observe():
            number = len(calls) + 1
            calls.append(number)
            c.previous = {name: {'monotonic_s': 1000 + 15 * number if name != 'val6'
                                else (1000 if number == 1 else 1015 if number < 4 else 1030)}
                          for name in c.previous}
            return {'common_finalized_height': 100 + number}

        c.observe = observe
        with patch.object(s.time, 'monotonic', return_value=86500):
            self.assertEqual(c.closing_barrier(), {'common_finalized_height': 104})
        self.assertEqual(calls, [1, 2, 3, 4])
        self.assertEqual((c.start, c.end), (100, 86500))

    def test_closing_stale_unreachable_or_interrupted_evidence_cannot_pass(self):
        c = self.controller()
        c.observe = Mock(return_value={'common_finalized_height': 100})
        with patch.object(s.time, 'monotonic', side_effect=[0, 0, 15, 30, 61]):
            with self.assertRaisesRegex(RuntimeError, 'end evidence'):
                c.closing_barrier()
        self.assertEqual(c.observe.call_count, 3)
        c = self.controller()
        c.observe = Mock(side_effect=RuntimeError('observer relay unreachable'))
        with self.assertRaisesRegex(RuntimeError, 'unreachable'):
            c.closing_barrier()
        c = self.controller()
        c.stop.wait.return_value = True
        c.observe = Mock()
        with self.assertRaisesRegex(RuntimeError, 'interrupted'):
            c.closing_barrier()
        c.observe.assert_not_called()


class SoakSafetyTests(unittest.TestCase):
    def report(self):
        return dict(status='completed', clean_load_step=True, measurement_complete=True,
            wallet_effects_verified_all_five=True, remaining_in_flight=0,
            rejection_count=0, generator_limited=False, finalized_transactions=3)

    def test_no_clean_claim_for_generator_saturation_or_unresolved_work(self):
        report = self.report()
        self.assertTrue(s.clean_stage(report))
        for key, bad in [('generator_limited', True), ('remaining_in_flight', 1),
                ('wallet_effects_verified_all_five', False), ('rejection_count', 1),
                ('finalized_transactions', 0), ('status', 'failed')]:
            changed = {**report, key: bad}
            self.assertFalse(s.clean_stage(changed), key)
        s.complete_stage({**report, 'generator_limited': True})
        with self.assertRaisesRegex(RuntimeError, 'drain'):
            s.complete_stage({**report, 'remaining_in_flight': 1})

    def test_storage_growth_gate_preserves_legacy_and_bounds_segments(self):
        first = {'groups': {'posy_legacy_history': {'files': 70000,'logical_bytes':2000000,'allocated_bytes':2100000},
            'posy_indexed_history': {'files': 1, 'logical_bytes': 4096}}}
        current = json.loads(json.dumps(first))
        current['groups']['posy_indexed_history']['logical_bytes'] = 65536
        s.storage_check(first, current)
        current['groups']['posy_legacy_history']['files'] += 7
        with self.assertRaisesRegex(RuntimeError, 'legacy'):
            s.storage_check(first, current)
        current['groups']['posy_legacy_history']['files'] -= 7
        for metric in ('logical_bytes','allocated_bytes'):
            current['groups']['posy_legacy_history'][metric] += 4096
            with self.assertRaisesRegex(RuntimeError,'legacy'):s.storage_check(first,current)
            current['groups']['posy_legacy_history'][metric] -= 4096
        current['groups']['posy_segment_history']={'files':2,'max_file_bytes':64*1024*1024}
        s.storage_check(first,current)
        current['groups']['posy_segment_history']['max_file_bytes']=80*1024*1024+1
        with self.assertRaisesRegex(RuntimeError,'segment'):s.storage_check(first,current)
        del current['groups']['posy_segment_history']['max_file_bytes']
        with self.assertRaisesRegex(RuntimeError,'segment'):s.storage_check(first,current)
        del current['groups']['posy_segment_history']
        current['groups']['posy_unexpected_sqlite_sidecar'] = {'entries': 1}
        with self.assertRaisesRegex(RuntimeError, 'WAL'):
            s.storage_check(first, current)

    def test_manifest_create_never_overwrites_clock_or_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'manifest.json'
            s.create(path, {'actual_start_utc': 'original'})
            with self.assertRaises(FileExistsError):
                s.create(path, {'actual_start_utc': 'replacement'})
            self.assertEqual(json.loads(path.read_text())['actual_start_utc'], 'original')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_duration_cannot_shrink_to_a_shorter_passing_window(self):
        controller = object.__new__(s.Controller)
        controller.config = {'duration_seconds': 60}
        with self.assertRaisesRegex(RuntimeError, 'actual24h'):
            controller.run()

    def test_authoring_remains_local_and_full_ladder_is_present(self):
        self.assertEqual(s.RATES, (100, 1000, 5000, 10000, 25000))
        c = object.__new__(s.Controller)
        c.config = {'release_manifest': '/run/reviewed-package.json', 'network_id': 'network-from-config',
            'wallet_registry': '/private/existing-wallets.json', 'receiver': 'existing-receiver',
            'rpc_token_file': '/private/run-token', 'max_in_flight': 32, 'vpn_peers': ['100.64.0.3']}
        c.here, c.root = Path('/tools'), Path('/fresh-run')
        c.endpoints = {'val2': 'http://127.0.0.1:8545', 'val3': 'http://100.64.0.3:28745'}
        command = c.command(10000, 60, Path('/fresh-run/report.json'), Path('/fresh-run/proof.jsonl'))
        self.assertEqual(command[command.index('--max-tx') + 1], '600000')
        self.assertIn('val2=http://127.0.0.1:8545', command)
        self.assertIn('--rpc-token-file', command)
        self.assertNotIn('1266', command)
        self.assertNotIn('--finality-budget-seconds', command)
        self.assertEqual(command[command.index('--max-in-flight-per-wallet') + 1], '4')
        self.assertEqual(command[command.index('--maximum-gap-seconds') + 1], '30')

    def workload_fixture(self, results):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        c = object.__new__(s.Controller)
        c.root, c.stop = Path(temporary.name), threading.Event()
        c.end, c.stage_results = 1000, []
        c.config = {'sustainable_tps': 100, 'max_in_flight': 32, 'capacity_rates': [100,1000], 'capacity_refinements': 0}
        c.h = SimpleNamespace(utc_now=lambda: 'fixture')
        c.failure, c.workload_done = None, False
        def stage(rate, duration, phase):
            item = results.pop(0)
            if isinstance(item, Exception): raise item
            result = {'rate':rate, 'finalized_tps':.1, 'end_to_end_finalized_tps':.09, 'drain':{'seconds_after_offered_window':0}, **item}
            c.stage_results.append(result)
            return result
        c.stage = Mock(side_effect=stage)
        return c

    def test_capacity_generator_limit_is_not_a_blockchain_upper_bound(self):
        c = self.workload_fixture([{'clean':True}, {'clean':False,'generator_limited':True}, {'clean':True}])
        result = c.capacity_discovery()
        self.assertEqual([call.args for call in c.stage.call_args_list],
            [(100,60,'capacity-escalation'),(1000,60,'capacity-escalation'),(100,600,'capacity-sustained')])
        self.assertEqual(result['first_limitation'], 'generator delivery')
        self.assertIsNone(result['backlog_pressure_offered_upper_tps'])
        self.assertFalse(result['capacity_result'])

    def test_first_generator_limit_does_not_schedule_sustained_or_lower_fake_capacity(self):
        c=self.workload_fixture([{'clean':False,'generator_limited':True}])
        result=c.capacity_discovery()
        self.assertEqual(c.stage.call_count,1)
        self.assertIsNone(result['sustained_finalized_tps'])

    def test_soak_uses_one_explicit_fixed_rate(self):
        c=self.workload_fixture([{'clean':True},{'clean':True}])
        with patch.object(s.time,'monotonic',side_effect=[0,1,501]):c.workloads()
        self.assertTrue(c.workload_done);self.assertFalse(c.stop.is_set())
        self.assertEqual([call.args for call in c.stage.call_args_list],
            [(100,300,'fixed-sustainable-workload'),(100,300,'fixed-sustainable-workload')])
        self.assertTrue(json.loads((c.root/'TPS-RESULT.json').read_text())['workload_unchanged'])

    def test_generator_limit_interrupts_fixed_soak_without_lowering_workload(self):
        c=self.workload_fixture([{'clean':False,'generator_limited':True}])
        with patch.object(s.time,'monotonic',return_value=0):c.workloads()
        self.assertTrue(c.stop.is_set());self.assertEqual(c.stage.call_count,1)

    def test_capacity_brackets_delivered_backlog_and_never_claims_causal_ceiling(self):
        c=self.workload_fixture([{'clean':True}, {'clean':True,'drain':{'seconds_after_offered_window':40}},
            {'clean':True}, {'clean':True}])
        c.config['capacity_refinements']=1
        result=c.capacity_discovery()
        self.assertEqual(c.stage.call_args_list[2].args,(316.228,60,'capacity-bracket'))
        self.assertEqual(result['backlog_pressure_offered_upper_tps'],1000)
        self.assertFalse(result['capacity_result'])

    def test_capacity_concurrency_grows_only_to_explicit_generator_ceiling(self):
        c=self.workload_fixture([{'clean':False,'generator_limited':True}])
        c.config['capacity_max_in_flight']=1024
        c.capacity_discovery()
        self.assertEqual(c.config['max_in_flight'],1024)

    def test_capacity_invalid_windows_do_not_author(self):
        for config in ({'capacity_refinements':100}, {'capacity_rates':[100,10]},
                       {'capacity_max_in_flight':8192}, {'capacity_pipeline_seconds':float('inf')}):
            c=self.workload_fixture([]);c.config.update(config)
            with self.assertRaises(RuntimeError):c.capacity_discovery()
            c.stage.assert_not_called()

    def test_real_failure_or_unexplained_nonclean_still_stops_soak(self):
        for result in (RuntimeError('exact proof failed'),{'clean':False,'generator_limited':False}):
            c=self.workload_fixture([result]);c.workloads()
            self.assertTrue(c.stop.is_set());self.assertIsNotNone(c.failure)
            self.assertEqual(c.stage.call_count,1)
            self.assertFalse((c.root/'TPS-RESULT.json').exists())


if __name__ == '__main__':
    unittest.main()
