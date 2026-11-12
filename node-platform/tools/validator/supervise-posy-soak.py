#!/usr/bin/env python3
"""Single-use remote 24h controller for the existing encrypted TPS harness.

Qualification only. Never deploys, signs directly, restarts nodes, changes limits,
replays a stage or resumes a clock. Run under a separate durable systemd unit.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse

DURATION = 86400
RATES = (100, 1000, 5000, 10000, 25000)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            value.update(block)
    return value.hexdigest()


def create(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def clean_stage(report):
    return (report.get('status') == 'completed' and report.get('clean_load_step') is True
        and report.get('wallet_effects_verified_all_five') is True
        and report.get('remaining_in_flight') == 0 and report.get('rejection_count') == 0
        and report.get('generator_limited') is False
        and report.get('finalized_transactions', 0) > 0)


def complete_stage(report):
    if (report.get('status') != 'completed' or not report.get('measurement_complete')
            or not report.get('wallet_effects_verified_all_five')
            or report.get('remaining_in_flight') != 0 or report.get('rejection_count') != 0
            or report.get('finalized_transactions', 0) <= 0):
        raise RuntimeError('encrypted stage failed or exact effects/backlog drain incomplete')


def storage_check(initial, current):
    before, after = initial['groups'], current['groups']
    for metric in ('files', 'logical_bytes', 'allocated_bytes'):
        if (after.get('posy_legacy_history', {}).get(metric, 0)
                != before.get('posy_legacy_history', {}).get(metric, 0)):
            raise RuntimeError('legacy consensus filesystem objects/bytes changed under indexed release')
    if after.get('posy_unexpected_sqlite_sidecar', {}).get('entries', 0):
        raise RuntimeError('unexpected SQLite WAL/SHM objects')
    if after.get('posy_indexed_history', {}).get('files', 0) != 1:
        raise RuntimeError('indexed consensus archive missing or duplicated')
    segments = after.get('posy_segment_history', {})
    if segments.get('files', 0):
        maximum = segments.get('max_file_bytes')
        if maximum is None or not 0 < maximum <= 80 * 1024 * 1024:
            raise RuntimeError('consensus segment size bound missing or exceeded')


def evidence_bytes(root):
    total, entries = 0, 0
    for directory, subdirectories, files in os.walk(root, followlinks=False):
        for name in subdirectories + files:
            path = Path(directory) / name
            try:
                metadata = path.lstat()
            except FileNotFoundError:
                continue  # Bounded authoring scratch may retire during a scan.
            if path.is_symlink():
                raise RuntimeError('unexpected symlink in qualification evidence')
            entries += 1
            if entries > 100000:
                raise RuntimeError('qualification evidence object bound reached')
            if path.is_file():
                total += metadata.st_size
    return total


def failure_reconciliation(proof):
    """Consume public proof frames into bounded, never-replay nonce identities."""
    pending = {}
    complete = proof.is_file()
    if proof.is_file():
        with proof.open('rb') as stream:
            while True:
                raw = stream.readline(4 * 1024**2 + 1)
                if not raw:
                    break
                if len(raw) > 4 * 1024**2 or not raw.endswith(b'\n'):
                    complete = False
                    break
                try:
                    frame = json.loads(raw)
                    if frame.get('kind') == 'active_intent_checkpoint':
                        active = frame.get('active')
                        if not isinstance(active, list) or len(active) > 4096:
                            complete = False; break
                        replacement = {}
                        for item in active:
                            if not isinstance(item, dict) or not isinstance(item.get('transaction_id'), str):
                                complete = False; break
                            replacement[item['transaction_id']] = item
                        if not complete: break
                        pending = replacement
                        continue
                    record = frame.get('record', {})
                    txid = record.get('transaction_id')
                    if frame.get('kind') not in ('authored_processing_admission', 'submission', 'finalized_transfer'):
                        continue
                    if not isinstance(txid, str) or not txid:
                        complete = False
                        break
                    if frame['kind'] == 'finalized_transfer' or record.get('submission_rejection') or record.get('admission_rejection'):
                        pending.pop(txid, None)
                    else:
                        pending[txid] = {key: record.get(key) for key in
                            ('transaction_id', 'receipt_id', 'wallet_id', 'sender', 'nonce', 'intent', 'submission_started', 'ambiguous_response')}
                        if len(pending) > 4096:
                            complete = False
                            break
                except (ValueError, TypeError, AttributeError):
                    complete = False
                    break
    return {'unresolved_or_possibly_submitted': list(pending.values())[:4096],
        'proof_stream_complete': complete,
        'instruction': 'Reconcile every registry wallet nonce and original transaction outcome before authoring again; never replay this stage.'}


class Controller:
    def __init__(self, config, root):
        self.config, self.root = config, root
        self.here = Path(__file__).resolve().parent
        sys.path.insert(0, str(self.here))
        self.h = module(self.here / 'run-posy-tps-baseline.py', 'soak_tps_harness')
        self.obs = module(self.here / 'soak-resource-observer.py', 'soak_resource_collector')
        self.stop = threading.Event()
        self.child = None
        self.lock = threading.Lock()
        self.stage_results = []
        self.failure = None
        self.event_bytes = 0
        self.number = 0
        self.h.configure_rpc_transport(Path(config['rpc_token_file']), config['vpn_peers'])
        self.endpoints = config['rpc_endpoints']
        if set(self.endpoints) != set(self.h.VALIDATORS):
            raise RuntimeError('exact five distinct endpoints required')
        for endpoint in self.endpoints.values():
            self.h.validate_rpc_url(endpoint)
        local = urllib.parse.urlsplit(config['local_rpc_url'])
        if (self.endpoints['val2'] != config['local_rpc_url'] or local.scheme != 'http'
                or local.hostname not in ('127.0.0.1', '::1', 'localhost')):
            raise RuntimeError('signing/submission must remain on Val2 local RPC')
        if config['maximum_gap_seconds'] != 30:
            raise RuntimeError('original block finality gap limit required')
        self.monitors = {name: self.obs.Monitor(config['chain_id'], config['network_id'])
                         for name in self.h.VALIDATORS}
        self.first = self.previous = None
        self.last_fresh = {}

    def event(self, value):
        raw = (json.dumps({'utc': self.h.utc_now(), **value}, separators=(',', ':')) + '\n').encode()
        with self.lock:
            self.event_bytes += len(raw)
            if self.event_bytes > self.config['evidence_budget_bytes']:
                raise RuntimeError('controller evidence budget reached; incomplete coverage')
            with (self.root / 'samples.jsonl').open('ab') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())

    def get_sample(self, name):
        request = urllib.request.Request(self.config['observer_endpoints'][name] + '/sample',
            headers={'Authorization': 'Bearer ' + self.h.RPC_TOKEN})
        with urllib.request.build_opener(self.h.NoRpcRedirect()).open(request, timeout=5) as response:
            raw = response.read(512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            raise RuntimeError('observer sample exceeds bound')
        sample = json.loads(raw)
        if sample.get('run_id') != self.config['run_id'] or sample.get('validator') != name:
            raise RuntimeError('observer sample identity mismatch')
        frozen = self.config['validators'][name]
        if (str(sample['unit']['MainPID']) != str(frozen['pid'])
                or sample['boot_id'] != frozen['boot_id']
                or sample['process']['stat']['starttime_ticks'] != frozen['starttime_ticks']):
            raise RuntimeError('validator identity changed from frozen launch proof')
        return name, sample

    def observe(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as readers:
            samples = dict(readers.map(self.get_sample, self.h.VALIDATORS))
        now = time.monotonic()
        for name, sample in samples.items():
            if self.previous and sample['monotonic_s'] < self.previous[name]['monotonic_s']:
                raise RuntimeError('remote monotonic sample regressed')
            fresh = not self.previous or sample['monotonic_s'] > self.previous[name]['monotonic_s']
            if fresh:
                self.last_fresh[name] = now
                self.monitors[name].check(sample)
            elif now - self.last_fresh[name] > 30:
                raise RuntimeError('observer stopped producing fresh samples')
            inventory = sample.get('inventory')
            if inventory is None:
                raise RuntimeError('completed baseline filesystem inventory required before soak start')
            baseline = self.first[name]['inventory'] if self.first else inventory
            storage_check(baseline, inventory)
            age = sample['end_monotonic_s'] - inventory['end_monotonic_s']
            if not 0 <= age <= 600:
                raise RuntimeError('filesystem inventory coverage expired')
        state = self.h.sample_fleet(self.endpoints, self.config['network_id'], native_tips=True,
                                   expected_chain_id=self.config['chain_id'], live_progress=True,
                                   native_prior_state=getattr(self, 'native_state', None))
        self.native_state = state
        proof = self.h.tip_record(state)
        if self.first is None:
            self.first = samples
        self.previous = samples
        group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        # Observers already own the bounded raw sample stream. Consume it here
        # without writing a second copy of all five payloads every15seconds.
        self.event({'kind': 'fleet_sample', 'elapsed_seconds': max(0, now - getattr(self, 'start', now)),
                    'validators': {name: self.monitors[name].summary(sample) for name, sample in samples.items()},
                    'common_finality': proof,
                    'controller_resources': {'process': self.obs.read_process(os.getpid()),
                                             'cgroup': self.obs.read_cgroup(group)}})
        return proof

    def prearm(self):
        """A reachable old cache cannot establish a fresh actual start."""
        self.observe()
        baseline = {name: sample['monotonic_s'] for name, sample in self.previous.items()}
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.stop.wait(2):
                raise RuntimeError('controller interrupted before actual start')
            proof = self.observe()
            if all(self.previous[name]['monotonic_s'] > baseline[name] for name in baseline):
                return proof
        raise RuntimeError('all-five fresh observer samples unavailable before actual start')

    def closing_barrier(self):
        # Two serial cache generations are required: the first may have started
        # collection before the deadline and only published afterward. The next
        # generation starts after that publication on the collector's one loop.
        baseline = {name: sample['monotonic_s'] for name, sample in self.previous.items()}
        advances = {name: 0 for name in baseline}
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.stop.wait(2):
                raise RuntimeError('controller interrupted during closing audit')
            proof = self.observe()
            for name, sample in self.previous.items():
                if sample['monotonic_s'] > baseline[name]:
                    advances[name] += 1
                    baseline[name] = sample['monotonic_s']
            if all(count >= 2 for count in advances.values()):
                return proof
        raise RuntimeError('post-deadline all-five fresh end evidence unavailable')

    @staticmethod
    def stop_child(child):
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()

    def command(self, rate, duration, output, proof, proof_budget=512 * 1024**2):
        c = self.config
        argv = [sys.executable, str(self.here / 'run-posy-tps-baseline.py'),
            '--async-processing', '--operator-wallet-registry', '--execute',
            '--installation-root', '/opt/Synergy', '--release-manifest', c['release_manifest'],
            '--network-id', c['network_id'], '--wallet-registry', c['wallet_registry'],
            '--keytool', '/opt/Synergy/bin/synergy-keytool', '--receiver', c['receiver'],
            '--rpc-token-file', c['rpc_token_file'], '--max-in-flight', str(c['max_in_flight']),
            '--max-in-flight-per-wallet', str(c.get('max_in_flight_per_wallet', 4)),
            '--author-workers', str(c.get('author_workers', 8)),
            '--amount-nwei', '1', '--gas-limit', '21000', '--gas-class-units', '21000',
            '--max-fee-per-gas-nwei', '40', '--fee-class', '1', '--rate-tps', str(rate),
            '--duration-seconds', str(duration), '--max-tx', str(math.ceil(rate * duration)),
            '--stability-seconds', '10', '--maximum-gap-seconds', '30',
            '--temp-dir', str(self.root / 'scratch'), '--raw-proof-budget-bytes', str(proof_budget),
            '--output', str(output), '--raw-proof-stream', str(proof)]
        for wallet_id in c.get('wallet_ids', []):
            argv += ['--wallet-id', wallet_id]
        for name, endpoint in self.endpoints.items():
            argv += ['--validator-rpc', name + '=' + endpoint]
        for peer in c['vpn_peers']:
            argv += ['--rpc-vpn-peer', peer]
        return argv

    def stage(self, rate, duration, phase):
        if self.stop.is_set() or time.monotonic() + duration + 100 >= self.end:
            raise RuntimeError('stage cannot fit within immutable soak window')
        self.number += 1
        name = f'{self.number:04d}-{phase}-{rate:g}tps'
        output, proof = self.root / (name + '.json'), self.root / (name + '.proof.jsonl')
        remaining = self.config['evidence_budget_bytes'] - evidence_bytes(self.root)
        proof_budget = min(512 * 1024**2, remaining - 64 * 1024**2)
        if proof_budget < 4 * 1024**2 or shutil.disk_usage(self.root).free < proof_budget + 1024**3:
            raise RuntimeError('insufficient evidence quota/reserve before authoring; no stage started')
        argv = self.command(rate, duration, output, proof, proof_budget)
        intent = self.root / (name + '-intent.json')
        log_path = self.root / (name + '.log')
        action = {'argv': argv, 'utc': self.h.utc_now(), 'never_replay': True,
                  'phase': phase, 'offered_tps': rate}
        create(intent, action)
        consumed = False
        try:
            self.event({'kind': 'stage_start', 'stage': name, 'rate': rate, 'duration': duration,
                'max_in_flight': self.config.get('max_in_flight'),
                'max_in_flight_per_wallet': self.config.get('max_in_flight_per_wallet', 4),
                'author_workers': self.config.get('author_workers', 8)})
            with log_path.open('xb') as log:
                child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                self.child = child
                try:
                    # Transaction latency has no30s acceptance ceiling. Drain
                    # may use the remaining immutable qualification window;
                    # never turn a new per-stage timeout into a consensus rule.
                    deadline = self.end
                    while child.poll() is None:
                        exhausted = (evidence_bytes(self.root) > self.config['evidence_budget_bytes'] - 16 * 1024**2
                                     or shutil.disk_usage(self.root).free < 1024**3)
                        if self.stop.wait(1) or time.monotonic() > deadline or exhausted:
                            raise RuntimeError('load cancelled, evidence bound or stage deadline exceeded; never replay')
                finally:
                    self.stop_child(child)
                    self.child = None
            if child.returncode != 0 or not output.is_file() or not proof.is_file():
                raise RuntimeError('load subprocess failed; reconcile original nonces and never replay')
            report = json.loads(output.read_text())
            complete_stage(report)
            result = {'stage': name, 'rate': rate, 'phase': phase,
                'clean': clean_stage(report), 'generator_limited': report.get('generator_limited'),
                'requested': report.get('requested_transactions'),
                'submitted': report.get('submitted_transactions'),
                'missed_offered_slots': report.get('generator_missed_offered_slots'),
                'end_to_end_finalized_tps': report.get('end_to_end_finalized_tps'),
                'attempted': report['attempted_transactions'], 'admitted': report['admitted_transactions'],
                'finalized': report['finalized_transactions'], 'finalized_tps': report['finalized_tps'],
                'latency': report['observed_client_latency_seconds'], 'drain': report['drain'],
                'native_processing_stage_observations': report.get('native_processing_stage_observations'),
                'native_stage_measurement_basis': report.get('native_stage_measurement_basis'),
                'generator_resources': report.get('generator_resources'),
                'generator_observer': report.get('generator_observer'),
                'offered_window_seconds': report.get('offered_window_seconds', duration),
                'peak_in_flight': report.get('peak_in_flight'),
                'consumed_disposable_outputs': True}
            self.stage_results.append(result)
            self.event({'kind': 'stage_end', **result})
            consumed = True
            return result
        except BaseException as error:
            # Preserve only the actionable operation/nonce boundary. Exact
            # public proof bodies and redundant subprocess output are consumed.
            action.update(failure=str(error)[:1024], **failure_reconciliation(proof))
            temporary = intent.with_suffix('.tmp')
            create(temporary, action)
            os.replace(temporary, intent)
            raise
        finally:
            for path in (output, proof, log_path):
                # An incomplete nonce summary cannot replace the only exact
                # actionable intents. Keep that one stream for reconciliation.
                if path == proof and not consumed and not action.get('proof_stream_complete', False):
                    continue
                path.unlink(missing_ok=True)
            if consumed:
                intent.unlink()

    def workloads(self):
        """The soak's declared sustainable offered load never changes mid-run."""
        try:
            rate = self.config.get('sustainable_tps')
            if (not isinstance(rate, (int, float)) or isinstance(rate, bool)
                    or not math.isfinite(rate) or not 0 < rate <= 25000):
                raise RuntimeError('explicit measured sustainable_tps required before soak')
            while not self.stop.is_set() and time.monotonic() < self.end - 500:
                result = self.stage(rate, 300, 'fixed-sustainable-workload')
                if not result['clean']:
                    raise RuntimeError('declared sustainable workload not delivered; qualification interrupted')
            create(self.root / 'TPS-RESULT.json', {'utc': self.h.utc_now(),
                'workload_mode': 'fixed-sustainable', 'offered_tps': rate,
                'workload_unchanged': True, 'results': self.stage_results,
                'capacity_result': False, 'TPS_qualified': False})
            self.workload_done = True
        except BaseException as error:
            self.failure = 'workload: ' + str(error)
            self.stop.set()

    def capacity_discovery(self):
        """Rapid offered-load search, separate from the immutable 24h soak.

        A generator limit is never a blockchain upper bound. Delivered-load
        backlog pressure brackets a measurement candidate, not a causal claim.
        Full drain and exact all-five effects are required by stage().
        """
        c = self.config
        duration = c.get('capacity_stage_seconds', 60)
        refinements = c.get('capacity_refinements', 3)
        if type(refinements) is not int or not 0 <= refinements <= 8:
            raise RuntimeError('capacity_refinements must be 0..8')
        sustain = c.get('capacity_sustain_seconds', 600)
        rates = c.get('capacity_rates', list(RATES))
        if (type(duration) is not int or not 30 <= duration <= 600
                or type(sustain) is not int or not 60 <= sustain <= 3600
                or not isinstance(rates, list) or not rates or len(rates) > 16
                or any(type(r) not in (int, float) or not math.isfinite(r) or not 0 < r <= 25000 for r in rates)
                or rates != sorted(set(rates))):
            raise RuntimeError('bounded increasing capacity rates and measurement windows required')
        low, high, limit = None, None, None
        initial_window = c['max_in_flight']
        ceiling = c.get('capacity_max_in_flight', initial_window)
        if type(ceiling) is not int or not initial_window <= ceiling <= 4096:
            raise RuntimeError('explicit capacity concurrency ceiling must be initial..4096')
        latency_hint = c.get('capacity_pipeline_seconds', 30)
        if type(latency_hint) not in (int, float) or not math.isfinite(latency_hint) or not 1 <= latency_hint <= 3600:
            raise RuntimeError('bounded pipeline sizing estimate required')
        def stage(rate, seconds, phase):
            # A sizing estimate, not a per-transaction deadline. Native custody,
            # authorization, funding and exact nonce checks remain in harness.
            c['max_in_flight'] = min(ceiling, max(initial_window, math.ceil(rate * latency_hint)))
            return self.stage(rate, seconds, phase)
        def pressured(result):
            # Compare complete delivery with drain cost; this deliberately does
            # not turn individual transaction latency into a failure deadline.
            return result['drain']['seconds_after_offered_window'] > duration * .5
        for rate in rates:
            result = stage(rate, duration, 'capacity-escalation')
            if result.get('generator_limited'):
                limit = 'generator delivery'; break
            if not result['clean']:
                raise RuntimeError('capacity stage failed correctness or unexplained delivery check')
            if pressured(result):
                high, limit = rate, 'delivered-load backlog pressure'; break
            low = rate
        # Only refine a delivered-load pressure bracket; never repeat an
        # incomplete generator cohort or implicitly replay accepted requests.
        for _ in range(refinements):
            if low is None or high is None or high / low <= 1.25:
                break
            rate = round(math.sqrt(low * high), 3)
            result = stage(rate, duration, 'capacity-bracket')
            if result.get('generator_limited'):
                limit = 'generator delivery'; break
            if not result['clean']:
                raise RuntimeError('bracket stage failed correctness')
            if pressured(result): high = rate
            else: low = rate
        repeated = stage(low, sustain, 'capacity-sustained') if low is not None else None
        result = {'utc': self.h.utc_now(), 'workload_mode': 'capacity-discovery',
            'highest_delivered_unpressured_offered_tps': low,
            'backlog_pressure_offered_upper_tps': high,
            'first_limitation': limit, 'concurrency_ceiling': ceiling,
            'pipeline_sizing_estimate_seconds': latency_hint, 'transaction_latency_deadline_seconds': None,
            'sustained_finalized_tps': repeated['finalized_tps'] if repeated else None,
            'sustained_end_to_end_finalized_tps': repeated['end_to_end_finalized_tps'] if repeated else None,
            'sustained_generator_limited': repeated.get('generator_limited') if repeated else None,
            'results': self.stage_results, 'capacity_result': False, 'TPS_qualified': False,
            'interpretation': 'Observed throughput and backlog bracket only. Cold-window finalized rate is not steady-state maximum; identify limiting subsystem from native stage/resource counters.'}
        create(self.root / 'TPS-RESULT.json', result)
        return result

    def run(self):
        c = self.config
        if c.get('duration_seconds') != DURATION:
            raise RuntimeError('actual24h duration required')
        rate = c.get('sustainable_tps')
        if (type(rate) not in (int, float) or not math.isfinite(rate) or not 0 < rate <= 25000):
            raise RuntimeError('explicit measured sustainable_tps required before soak')
        if not 256 * 1024**2 <= c['evidence_budget_bytes'] <= 64 * 1024**3:
            raise RuntimeError('bounded controller evidence budget required')
        if set(c['validators']) != set(self.h.VALIDATORS):
            raise RuntimeError('exact all-five frozen launch proofs required')
        if digest(c['release_manifest']) != c['package_sha256']:
            raise RuntimeError('selected package manifest changed')
        for name, details in c['validators'].items():
            if (details['executable_sha256'] != c['executable_sha256']
                    or details['package_sha256'] != c['package_sha256']):
                raise RuntimeError('frozen all-five release hashes differ')
        proof_path = Path(c['functional_proof'])
        if digest(proof_path) != c['functional_proof_sha256']:
            raise RuntimeError('functional encrypted transfer proof changed')
        proof = json.loads(proof_path.read_text())
        if (proof.get('status') != 'PASS' or proof.get('wallet_effects_verified_all_five') is not True
                or proof.get('network_id') != c['network_id'] or proof.get('chain_id') != c['chain_id']
                or proof.get('executable_sha256') != c['executable_sha256']):
            raise RuntimeError('real all-five encrypted effects proof required')
        first_tip = self.prearm()
        self.start = time.monotonic()
        if self.start > c.get('start_before_monotonic', float('inf')):
            raise RuntimeError('observer coverage cannot contain a fresh full86400-second window')
        self.end = self.start + DURATION
        actual = self.h.utc_now()
        create(self.root / 'manifest.json', {**c, 'actual_start_utc': actual,
            'actual_start_monotonic': self.start, 'actual_duration_seconds': DURATION,
            'first_common_finality': first_tip, 'status': 'RUNNING; not a PASS',
            'controller_pid': os.getpid(), 'no_automatic_restart_or_resume': True})
        self.workload_done = False
        worker = threading.Thread(target=self.workloads)
        worker.start()
        last_tip, samples = first_tip, 0
        try:
            while time.monotonic() < self.end:
                if self.stop.wait(min(15, self.end - time.monotonic())):
                    raise RuntimeError(self.failure or 'controller interrupted')
                last_tip = self.observe(); samples += 1
            last_tip = self.closing_barrier()
            worker.join(timeout=180)
            if worker.is_alive() or not self.workload_done or self.failure:
                raise RuntimeError('workload did not complete/drain within soak')
            elapsed = time.monotonic() - self.start
            height_delta = last_tip['common_finalized_height'] - first_tip['common_finalized_height']
            mean = elapsed / height_delta if height_delta > 0 else float('inf')
            if not .5 <= mean <= 1.5 or not (self.root / 'TPS-RESULT.json').is_file():
                raise RuntimeError('full-window cadence or sustained TPS proof failed')
            create(self.root / 'terminal.json', {'status': 'OBSERVATION_COMPLETE_REQUIRES_RETENTION_AND_END_AUDIT',
                'soak_pass': False, 'interval_checks_passed': True, 'actual_start_utc': actual,
                'actual_end_utc': self.h.utc_now(), 'elapsed_seconds': elapsed, 'samples': samples,
                'finalized_height_delta': height_delta, 'mean_block_seconds': mean,
                'final_common_finality': last_tip, 'transactions_finalized': sum(s['finalized'] for s in self.stage_results),
                'requires_independent_end_audit': True, 'node_action': 'none'})
        finally:
            self.stop.set(); worker.join(timeout=30)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--capacity-only', action='store_true', help='bounded adaptive capacity discovery; never starts or passes a soak')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    root = Path(config['run_directory'])
    if root.exists():
        raise RuntimeError('run directory already exists; never resume or reset a soak')
    root.mkdir(mode=0o700, parents=True); (root / 'scratch').mkdir(mode=0o700)
    controller = None
    try:
        controller = Controller(config, root)
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: controller.stop.set())
        if args.capacity_only:
            seconds = config.get('capacity_budget_seconds', 3600)
            if type(seconds) is not int or not 600 <= seconds <= 14400:
                raise RuntimeError('capacity-only budget must be 600..14400 seconds')
            first_tip = controller.prearm()
            controller.start = time.monotonic(); controller.end = controller.start + seconds
            create(root / 'manifest.json', {**config, 'actual_start_utc': controller.h.utc_now(),
                'actual_start_monotonic': controller.start, 'mode': 'capacity-only; not a soak',
                'first_common_finality': first_tip})
            def watch():
                try:
                    while not controller.stop.wait(15): controller.observe()
                except BaseException as error:
                    controller.failure = str(error); controller.stop.set()
            watcher = threading.Thread(target=watch); watcher.start()
            try:
                controller.capacity_discovery()
                if controller.failure: raise RuntimeError(controller.failure)
            finally:
                controller.stop.set(); watcher.join(timeout=30)
        else:
            controller.run()
        return 0
    except BaseException as error:
        if controller:
            controller.stop.set()
        if not (root / 'terminal.json').exists():
            create(root / 'terminal.json', {'status': 'FAILED', 'end_utc': controller.h.utc_now() if controller else None,
                'reason': str(error), 'node_action': 'none', 'soak_pass': False,
                'soak_started': (root / 'manifest.json').exists(), 'never_stitch_intervals': True})
        raise


if __name__ == '__main__':
    raise SystemExit(main())
