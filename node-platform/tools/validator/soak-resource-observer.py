#!/usr/bin/env python3
"""Qualification-only remote observer. Never changes node state or submits work.

Run in a separate systemd service: MemoryMax=64M, MemorySwapMax=0,
CPUQuota=25%, IOAccounting=yes, Restart=no, UMask=0077. Delete disposable
output after its named engineering purpose is consumed.
The caller stages this file outside /opt/Synergy, under its approved fresh run.
No Python packages, development Mac, SSH, or SQLite access are required.

Relay: Authorization: Bearer <contents of the private token file>. Only the
explicit read allowlist is forwarded, using bounded streaming and four workers.
Window completion is NOT a soak PASS: the central controller must independently
prove all-five common-height agreement and exact encrypted transaction effects.
"""
import argparse
import datetime
import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import threading
import time
import urllib.request

SCHEMA = 1
READ_METHODS = frozenset(('synergy_nodeStatus', 'synergy_chainTelemetry', 'synergy_getBlock',
    'synergy_getAccount', 'synergy_getProtectedAdmissionStats', 'synergy_getProtectedAdmissionReceipt',
    'synergy_getTransaction'))
CGROUP_FILES = ('memory.current', 'memory.peak', 'memory.max', 'memory.swap.current',
    'memory.swap.max', 'memory.stat', 'memory.events', 'memory.events.local', 'memory.pressure',
    'cpu.stat', 'cpu.pressure', 'io.stat', 'io.pressure', 'pids.current', 'pids.events')
UNIT_FIELDS = ('MainPID', 'ControlGroup', 'NRestarts', 'ActiveState', 'SubState', 'Result',
    'ExecMainStartTimestampMonotonic', 'ExecMainCode', 'ExecMainStatus', 'MemoryMax', 'MemorySwapMax')
MAX_READ = 512 * 1024
MAX_REQUEST = 64 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
MAX_INVENTORY_RECORD = 16 * 1024


def evidence_projection(sample_bytes, duration, cadence, inventory_cadence, budget):
    # A projection from the largest observed frame is explicitly not a promise
    # about future telemetry. Actual append limits remain authoritative.
    samples = math.ceil(duration / cadence) + 1
    inventories = math.ceil(duration / inventory_cadence) + 1
    projected = samples * (sample_bytes + 1024) + inventories * MAX_INVENTORY_RECORD + 1024 * 1024
    return {'basis': 'largest observed sample plus1KiB/frame; bounded inventory and terminal reserve',
        'duration_seconds': duration, 'sample_seconds': cadence, 'sample_count': samples,
        'largest_observed_sample_bytes': sample_bytes, 'projected_evidence_bytes': projected,
        'evidence_budget_bytes': budget, 'fits_budget': projected <= budget,
        'future_growth_guaranteed': False}


class Failure(RuntimeError):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def bounded_read(path, maximum=MAX_READ):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise Failure('bounded input exceeded: ' + str(path))
    return data


def hash_file(path, maximum=128 * 1024 * 1024, follow=False):
    fd = os.open(path, os.O_RDONLY | (0 if follow else os.O_NOFOLLOW))
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise Failure('hash input is not regular')
        total = 0
        while True:
            block = stream.read(256 * 1024)
            if not block:
                return digest.hexdigest()
            total += len(block)
            if total > maximum:
                raise Failure('hash input exceeds bound')
            digest.update(block)


def counters(raw):
    result = {}
    for line in raw.splitlines():
        parts = line.replace(':', '').split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def pressure(raw):
    return {line.split()[0]: {k: float(v) for k, v in (p.split('=') for p in line.split()[1:])}
            for line in raw.splitlines() if line.split()}


def io_devices(raw):
    return {p[0]: {k: int(v) for k, v in (item.split('=') for item in p[1:])}
            for p in (line.split() for line in raw.splitlines()) if p}


def delta(old, new):
    return {k: new[k] - old[k] for k in old.keys() & new.keys()}


def system_unit(service):
    result = subprocess.run(['systemctl', 'show', service, *['--property=' + p for p in UNIT_FIELDS]],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if len(result.stdout) > 32768:
        raise Failure('unit property response exceeds bound')
    return dict(line.split('=', 1) for line in result.stdout.decode().splitlines())


def local_url(config, override=None):
    if override:
        from urllib.parse import urlsplit
        parsed = urlsplit(override)
        if (parsed.scheme != 'http' or parsed.username or parsed.password or parsed.query or parsed.fragment
                or not parsed.hostname or not ipaddress.ip_address(parsed.hostname).is_loopback):
            raise Failure('only explicit loopback HTTP RPC is permitted')
        return override
    rpc = config.get('rpc', {})
    address = rpc.get('listen_address')
    if not rpc.get('enabled') or not isinstance(address, str):
        raise Failure('configured TCP RPC endpoint is unavailable; admin IPC is not JSON-RPC')
    host = address.rsplit(':', 1)[0].strip('[]')
    if not ipaddress.ip_address(host).is_loopback:
        raise Failure('configured RPC is not loopback; explicit local --rpc-url required')
    return 'http://' + address + '/'


def rpc(url, method, params=None):
    request = urllib.request.Request(url, data=json.dumps({'jsonrpc': '2.0', 'id': 1,
        'method': method, 'params': params or {}}).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read(MAX_READ + 1)
    if len(body) > MAX_READ:
        raise Failure('local observation RPC exceeds bound')
    value = json.loads(body)
    if not isinstance(value, dict) or 'error' in value or 'result' not in value:
        raise Failure('local observation RPC failed: ' + method)
    return value['result']


def read_fds(pid, proc=Path('/proc')):
    count = 0
    with os.scandir(proc / str(pid) / 'fd') as entries:
        for _ in entries:
            count += 1
            if count > 131072:
                raise Failure('process FD observation bound exceeded')
    return count


def read_smaps_rollup(pid, proc=Path('/proc')):
    # Read one kernel aggregate rather than traversing/retaining every mapping.
    try:
        raw = bounded_read(proc / str(pid) / 'smaps_rollup', 65536).decode()
    except FileNotFoundError:
        return {'supported': False, 'reason': 'kernel smaps_rollup unavailable', 'fields_bytes': {}}
    selected = ('Rss', 'Pss', 'Pss_Anon', 'Pss_File', 'Pss_Shmem', 'Private_Clean',
                'Private_Dirty', 'Shared_Clean', 'Shared_Dirty', 'Anonymous', 'Swap', 'SwapPss')
    values = {}
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0].rstrip(':') in selected:
            if len(fields) != 3 or fields[2] != 'kB' or not fields[1].isdigit():
                raise Failure('invalid kernel smaps_rollup byte counter')
            values[fields[0][:-1]] = int(fields[1]) * 1024
    if not all(name in values for name in ('Rss', 'Pss', 'Private_Dirty', 'Swap')):
        raise Failure('kernel smaps_rollup lacks required totals')
    return {'supported': True, 'fields_bytes': values,
            'unavailable_fields': [name for name in selected if name not in values]}


class ProcessDetails:
    """At most two cached small process summaries; no mapping/file-name list."""
    def __init__(self, proc=Path('/proc')):
        self.proc, self.cached = proc, {}

    def enrich(self, sample):
        now = sample['monotonic_s']
        for pid, process in ((int(sample['unit']['MainPID']), sample['process']),
                             (sample['observer']['pid'], sample['observer']['process'])):
            cached = self.cached.setdefault(pid, {})
            if 'smaps' not in cached or now - cached['smaps']['monotonic_s'] >= 30:
                cached['smaps'] = {**read_smaps_rollup(pid, self.proc), 'monotonic_s': now,
                                  'utc': sample['utc'], 'source': '/proc/PID/smaps_rollup'}
            if 'fds' not in cached or now - cached['fds']['monotonic_s'] >= 60:
                cached['fds'] = {'count': read_fds(pid, self.proc), 'monotonic_s': now,
                                 'utc': sample['utc'], 'source': '/proc/PID/fd'}
            process['smaps_rollup'] = cached['smaps']
            process['fd_count'] = cached['fds']['count']
            process['fd_observation'] = cached['fds']
        if len(self.cached) > 2:
            raise Failure('process detail PID changed; bounded observer cannot rearm')


def read_process(pid, proc=Path('/proc'), include_fds=True):
    root = proc / str(pid)
    raw = bounded_read(root / 'status').decode()
    fields = dict(line.split(':', 1) for line in raw.splitlines() if ':' in line)
    selected = {k: fields.get(k, '').strip() for k in ('VmRSS', 'RssAnon', 'RssFile', 'RssShmem',
        'VmSwap', 'VmHWM', 'Threads', 'FDSize', 'voluntary_ctxt_switches', 'nonvoluntary_ctxt_switches')}
    text = bounded_read(root / 'stat').decode()
    # comm may itself contain spaces and parentheses: split after the LAST ')'.
    values = text[text.rfind(')') + 2:].split()
    return {'status': selected, 'stat': {'utime_ticks': int(values[11]), 'stime_ticks': int(values[12]),
        'starttime_ticks': int(values[19]), 'minor_faults': int(values[7]), 'major_faults': int(values[9])},
        'io': counters(bounded_read(root / 'io').decode()),
        'fd_count': read_fds(pid, proc) if include_fds else None}


def read_cgroup(relative, cgroot=Path('/sys/fs/cgroup')):
    if not relative.startswith('/') or '..' in Path(relative).parts:
        raise Failure('invalid service cgroup path')
    root = cgroot / relative.lstrip('/')
    result = {}
    for name in CGROUP_FILES:
        try:
            result[name] = bounded_read(root / name).decode().strip()
        except FileNotFoundError:
            if name not in ('memory.events.local', 'pids.events'):
                raise
    return result


def host_memory(proc=Path('/proc')):
    memory = {}
    for line in bounded_read(proc / 'meminfo').decode().splitlines():
        k, value = line.split(':', 1)
        if k in ('MemTotal', 'MemAvailable', 'Cached', 'Slab', 'SReclaimable', 'SUnreclaim', 'SwapTotal', 'SwapFree'):
            memory[k] = int(value.split()[0]) * 1024
    arc = {}
    try:
        for line in bounded_read(proc / 'spl/kstat/zfs/arcstats').decode().splitlines():
            p = line.split()
            if len(p) == 3 and p[0] in ('size', 'c', 'c_min', 'c_max', 'data_size', 'metadata_size', 'hdr_size'):
                arc[p[0]] = int(p[2])
    except FileNotFoundError:
        pass
    return {'memory_bytes': memory, 'zfs_arc_hostwide_only': arc}


def storage_class(relative):
    prefix = 'data/consensus/posy/'
    if not relative.startswith(prefix):
        return 'other_application'
    name = relative[len(prefix):]
    if name == 'archive' or re.fullmatch(r'archive/segment-[0-9]{20}\.sya', name):
        return 'posy_segment_history'
    if name == 'consensus-evidence-v1.sqlite3':
        return 'posy_indexed_history'
    if name == 'consensus-evidence-v1.sqlite3-journal' or (name == '.transactions' or name.startswith('.transactions/')):
        return 'posy_ephemeral_working'
    if name.endswith(('-wal', '-shm')) and name.startswith('consensus-evidence-v1.sqlite3'):
        return 'posy_unexpected_sqlite_sidecar'
    if name in ('sign-once.json', 'delivery.json', 'recovery.json', '.synergy-writer.lock'):
        return 'posy_active_safety'
    if (name.startswith(('verified-qcs/', 'finality/', 'verified-timeouts/', 'signature-', 'ready-h', 'validation-h'))):
        return 'posy_legacy_history'
    return 'posy_other'


class Inventory:
    """Bounded DFS descriptors, no per-file map, no symlinks or SQLite reads."""
    def __init__(self, root, height, max_entries=2_000_000):
        self.started_utc, self.started_mono, self.start_height = utc(), time.monotonic(), height
        self.max_entries, self.entries, self.absences = max_entries, 0, 0
        self.groups = {}
        self.stack = []
        self._push(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW), '')

    def _push(self, fd, relative):
        if len(self.stack) >= 64:
            os.close(fd)
            raise Failure('inventory directory depth exceeds bound')
        self.stack.append((fd, relative, os.scandir(fd)))

    def close(self):
        while self.stack:
            fd, _, iterator = self.stack.pop()
            iterator.close()
            os.close(fd)

    def step(self, height, limit=8192, seconds=0.5):
        start, count = time.monotonic(), 0
        while self.stack and count < limit and time.monotonic() - start < seconds:
            fd, parent, iterator = self.stack[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                iterator.close(); os.close(fd); self.stack.pop()
                continue
            count += 1; self.entries += 1
            if self.entries > self.max_entries or time.monotonic() - self.started_mono > 600:
                self.close()
                raise Failure('bounded inventory could not complete; coverage is incomplete')
            relative = parent + '/' + entry.name if parent else entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
                group = self.groups.setdefault(storage_class(relative), {'entries': 0, 'files': 0,
                    'directories': 0, 'symlinks': 0, 'logical_bytes': 0, 'allocated_bytes': 0,
                    'max_file_bytes': 0})
                group['entries'] += 1
                if stat.S_ISREG(metadata.st_mode):
                    group['files'] += 1; group['logical_bytes'] += metadata.st_size
                    group['allocated_bytes'] += metadata.st_blocks * 512
                    group['max_file_bytes'] = max(group['max_file_bytes'], metadata.st_size)
                elif stat.S_ISLNK(metadata.st_mode):
                    group['symlinks'] += 1
                elif stat.S_ISDIR(metadata.st_mode):
                    group['directories'] += 1
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    self._push(child, relative)
            except FileNotFoundError:
                self.absences += 1
        if self.stack:
            return None
        return {'scan_start_utc': self.started_utc, 'scan_end_utc': utc(),
            'scan_elapsed_seconds': time.monotonic() - self.started_mono, 'end_monotonic_s': time.monotonic(),
            'start_height': self.start_height, 'end_height': height, 'entries_visited': self.entries,
            'transient_absences': self.absences, 'groups': self.groups,
            'snapshot_atomic': False, 'indexed_history_rows': None,
            'row_count_reason': 'no native constant-time counter; no SQLite query/full-history scan'}


class Evidence:
    def __init__(self, root, budget=512 * 1024 * 1024):
        self.root, self.budget, self.used = root, budget, 0
        if not root.is_dir() or root.is_symlink() or stat.S_IMODE(root.stat().st_mode) != 0o700:
            raise Failure('fresh private evidence directory must already exist with mode0700')
        if any((root / n).exists() for n in ('status.json', 'run-manifest.json', 'samples.jsonl', 'terminal.json', 'baseline.json', 'inventories.jsonl', 'events.jsonl')):
            raise Failure('existing run cannot resume or stitch intervals; use a fresh run ID')
        self.streams = {}
        for name in ('samples.jsonl', 'inventories.jsonl', 'events.jsonl'):
            self.streams[name] = (root / name).open('xb', buffering=0)
            os.chmod(root / name, 0o600)

    def append(self, name, value):
        data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        volume = os.statvfs(self.root)
        bound = MAX_INVENTORY_RECORD if name == 'inventories.jsonl' else MAX_READ
        if (len(data) > bound or self.used + len(data) > self.budget - 1024 * 1024
                or volume.f_bavail * volume.f_frsize < 16 * 1024 * 1024):
            raise Failure('observer evidence budget reached; no partial window qualifies')
        pending = memoryview(data)
        while pending:
            written = self.streams[name].write(pending)
            if not written:
                raise Failure('short evidence write')
            pending = pending[written:]
        os.fsync(self.streams[name].fileno()); self.used += len(data)

    def save(self, name, value):
        data = json.dumps(value, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(data) > MAX_READ:
            raise Failure('observer status exceeds bound')
        temporary = self.root / ('.' + name + '.tmp')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, self.root / name)
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def close(self):
        for stream in self.streams.values():
            stream.close()


class Monitor:
    def __init__(self, chain_id, network_id, maximum_gap=30):
        self.chain_id, self.network_id, self.maximum_gap = chain_id, network_id, maximum_gap
        self.baseline = self.previous = None
        self.last_progress = None

    def check(self, sample):
        unit, cg, telemetry = sample['unit'], sample['cgroup'], sample['telemetry']
        if unit.get('ActiveState') != 'active' or int(unit.get('MainPID', 0)) <= 0:
            raise Failure('validator service is not active')
        if type(telemetry.get('chain_id')) is not int or telemetry.get('chain_id') != self.chain_id or telemetry.get('network_identity') != self.network_id:
            raise Failure('validator chain/network identity changed or differs')
        height = telemetry.get('finalized_height')
        if type(height) is not int or height < 1:
            raise Failure('validator lacks native finalized height')
        commitment = telemetry.get('common_finalized_commitment')
        if not isinstance(commitment, dict) or commitment.get('height') != height or not all(
                isinstance(commitment.get(k), str) and commitment[k] for k in
                ('block_id', 'state_root', 'finality_certificate_id', 'protected_execution_root')):
            raise Failure('native finalized commitment is incomplete')
        cadence = (telemetry.get('chain') or {}).get('cadence')
        if not isinstance(cadence, dict) or type(cadence.get('samples')) is not int or cadence['samples'] < 1:
            raise Failure('native finality interval coverage unavailable')
        for field in ('current_gap_ms', 'maximum_gap_ms'):
            value = cadence.get(field)
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or (field == 'current_gap_ms' and value > self.maximum_gap * 1000)):
                raise Failure('native finality gap invalid/exceeds threshold: ' + field)
        # maximum_gap_ms is process-lifetime state, not this observation window.
        # Never reset the validator merely to clear a pre-window maximum. The
        # latest finalized timestamp is recoverable on this host's monotonic
        # clock from current_gap_ms. Bound successive observed timestamps too:
        # this conservatively rejects lost interval coverage even if several
        # blocks finalized between samples and an older maximum masks a gap.
        finalized_at = sample['monotonic_s'] - cadence['current_gap_ms'] / 1000
        if cg.get('memory.max') != '1073741824' or cg.get('memory.swap.max') != '0':
            raise Failure('validator resource policy changed; expected1GiB/swap0')
        if int(cg['memory.swap.current']) or sample['process']['status'].get('VmSwap', '').split()[0] != '0':
            raise Failure('validator swap is nonzero')
        if self.baseline is None:
            self.baseline = sample; self.last_progress = sample['monotonic_s']
        else:
            first = self.baseline
            for name in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic', 'ControlGroup'):
                if unit.get(name) != first['unit'].get(name):
                    raise Failure('validator restarted/process identity changed: ' + name)
            if sample['process']['stat']['starttime_ticks'] != first['process']['stat']['starttime_ticks']:
                raise Failure('validator PID was reused')
            for name in ('memory.events', 'memory.events.local'):
                if (name in first['cgroup']) != (name in cg):
                    raise Failure('memory event coverage changed: ' + name)
                if name not in cg:
                    continue
                old_events, new_events = counters(first['cgroup'][name]), counters(cg[name])
                if old_events.keys() != new_events.keys():
                    raise Failure('memory event keys changed: ' + name)
                events = delta(old_events, new_events)
                if any(v < 0 for v in events.values()) or any(events.get(k, 0) for k in ('oom', 'oom_kill', 'oom_group_kill')):
                    raise Failure('new OOM event or reset memory event counters: ' + name)
            if height < self.previous['telemetry']['finalized_height']:
                raise Failure('finalized height regressed')
            previous_cadence = self.previous['telemetry']['chain']['cadence']
            if (cadence['maximum_gap_ms'] > previous_cadence['maximum_gap_ms']
                    and cadence['maximum_gap_ms'] > self.maximum_gap * 1000):
                raise Failure('new native finalized gap exceeds threshold')
            previous_finalized_at = self.previous['monotonic_s'] - previous_cadence['current_gap_ms'] / 1000
            if height > self.previous['telemetry']['finalized_height']:
                if finalized_at - previous_finalized_at > self.maximum_gap:
                    raise Failure('finalized interval exceeds threshold or interval coverage is incomplete')
            elif sample['monotonic_s'] - previous_finalized_at > self.maximum_gap:
                raise Failure('current finalized gap exceeds threshold')
            if cadence['maximum_gap_ms'] < previous_cadence['maximum_gap_ms']:
                raise Failure('native lifetime finality maximum regressed')
            if height > self.previous['telemetry']['finalized_height']:
                self.last_progress = sample['monotonic_s']
            if sample['monotonic_s'] - self.last_progress > self.maximum_gap:
                raise Failure('no observed finalized advancement beyond threshold')
            if sample['boot_id'] != first['boot_id']:
                raise Failure('host reboot interrupted soak')
            if abs((sample['unix_s'] - first['unix_s']) - (sample['monotonic_s'] - first['monotonic_s'])) > 5:
                raise Failure('UTC clock stepped by more than5seconds')
        if self.previous is not None:
            for key in ('rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes'):
                if sample['process']['io'].get(key, 0) < self.previous['process']['io'].get(key, 0):
                    raise Failure('process I/O counter regressed: ' + key)
            if (sample['monotonic_s'] < self.previous['monotonic_s']
                    or counters(cg['cpu.stat']).get('usage_usec', 0) < counters(self.previous['cgroup']['cpu.stat']).get('usage_usec', 0)):
                raise Failure('monotonic/CPU counter regressed')
        self.previous = sample
        return self.summary(sample)

    def summary(self, sample):
        first = self.baseline
        height_delta = sample['telemetry']['finalized_height'] - first['telemetry']['finalized_height']
        elapsed = sample['monotonic_s'] - first['monotonic_s']
        io_delta = delta(first['process']['io'], sample['process']['io'])
        return {'elapsed_seconds': elapsed, 'finalized_height_delta': height_delta,
            'process_io_delta': io_delta,
            'process_io_per_finalized_block': {k: v / height_delta for k, v in io_delta.items()} if height_delta > 0 else None,
            'cgroup_cpu_delta_usec': delta(counters(first['cgroup']['cpu.stat']), counters(sample['cgroup']['cpu.stat'])),
            'memory_events_delta': delta(counters(first['cgroup']['memory.events']), counters(sample['cgroup']['memory.events'])),
            'cgroup_io_delta': {dev: (delta(io_devices(first['cgroup']['io.stat'])[dev], values)
                if dev in io_devices(first['cgroup']['io.stat']) else None)
                for dev, values in io_devices(sample['cgroup']['io.stat']).items()},
            'pressure_total_delta_usec': {kind: {scope: values['total'] - pressure(first['cgroup'][kind + '.pressure']).get(scope, {}).get('total', 0)
                for scope, values in pressure(sample['cgroup'][kind + '.pressure']).items()} for kind in ('memory', 'cpu', 'io')},
            'transaction_finality_latency_ms': None,
            'latency_reason': 'requires controller correlated admission/finalized receipt proof; never inferred from tip polling'}


class Relay(http.server.HTTPServer):
    def __init__(self, address, local, token, run_id):
        self.local, self.token, self.run_id = local, token, run_id
        self.sample = None; self.guard = threading.Lock(); self.slots = threading.BoundedSemaphore(4)
        self.active = {}; self.stats = {'requests': 0, 'rejected': 0, 'timeouts': 0, 'response_bytes': 0}
        super().__init__(address, RelayHandler)

    def process_request(self, request, address):
        if not self.slots.acquire(False):
            request.close()
            return
        with self.guard:
            self.active[request] = time.monotonic() + 5
        def worker():
            try:
                request.settimeout(5)
                self.finish_request(request, address)
            except (OSError, ValueError):
                pass
            finally:
                self.shutdown_request(request)
                with self.guard:
                    self.active.pop(request, None)
                self.slots.release()
        threading.Thread(target=worker, daemon=True).start()

    def service_actions(self):
        with self.guard:
            expired = [s for s, deadline in self.active.items() if time.monotonic() >= deadline]
        for stream in expired:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if expired:
            with self.guard:
                self.stats['timeouts'] += len(expired)

    def publish(self, sample):
        data = json.dumps(sample, separators=(',', ':'), allow_nan=False).encode()
        if len(data) > MAX_READ:
            raise Failure('relay cached sample exceeds bound')
        with self.guard:
            self.sample = data

    def stop(self):
        self.shutdown()
        with self.guard:
            active = list(self.active)
        for stream in active:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.server_close()


class LimitedInput:
    """Bound headers before email/http parsing allocates their representation."""
    def __init__(self, raw):
        self.raw, self.header_bytes, self.body_bytes, self.headers_done = raw, 0, 0, False

    def __getattr__(self, name):
        return getattr(self.raw, name)

    def readline(self, maximum=-1):
        remaining = 8192 - self.header_bytes
        data = self.raw.readline(min(maximum, remaining + 1) if maximum >= 0 else remaining + 1)
        self.header_bytes += len(data)
        if self.header_bytes > 8192:
            raise ValueError('relay HTTP headers exceed8192bytes')
        if data in (b'\r\n', b'\n'):
            self.headers_done = True
        return data

    def read1(self, maximum):
        if not self.headers_done or self.body_bytes + maximum > MAX_REQUEST:
            raise ValueError('relay body read exceeds bound')
        data = self.raw.read1(maximum)
        self.body_bytes += len(data)
        return data


class RelayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def setup(self):
        super().setup()
        self.rfile = LimitedInput(self.rfile)

    def log_message(self, *_args):
        pass

    def answer(self, code, body=b''):
        self.send_response(code); self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Type', 'application/json'); self.end_headers()
        self.wfile.write(body)

    def authenticated(self):
        with self.server.guard:
            self.server.stats['requests'] += 1
        header = self.headers.get('Authorization', '')
        valid = hmac.compare_digest(header.encode(), b'Bearer ' + self.server.token)
        if not valid:
            with self.server.guard:
                self.server.stats['rejected'] += 1
            self.answer(401)
        return valid

    def do_GET(self):
        if not self.authenticated():
            return
        if self.path != '/sample':
            return self.answer(404)
        with self.server.guard:
            sample = self.server.sample
        return self.answer(200, sample) if sample is not None else self.answer(503)

    def do_POST(self):
        if not self.authenticated():
            return
        if self.path not in ('', '/') or self.headers.get('Transfer-Encoding'):
            return self.answer(400)
        try:
            length = int(self.headers.get('Content-Length', '-1'))
            if not 0 < length <= MAX_REQUEST:
                return self.answer(413)
            with self.server.guard:
                deadline = self.server.active[self.connection]
            body = bytearray()
            while len(body) < length:
                self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                block = self.rfile.read1(min(16384, length - len(body)))
                if not block:
                    return self.answer(400)
                body.extend(block)
            depth, quoted, escaped = 0, False, False
            for byte in body:
                if quoted:
                    if escaped:
                        escaped = False
                    elif byte == 92:
                        escaped = True
                    elif byte == 34:
                        quoted = False
                elif byte == 34:
                    quoted = True
                elif byte in (91, 123):
                    depth += 1
                    if depth > 64:
                        return self.answer(400)
                elif byte in (93, 125):
                    depth -= 1
            value = json.loads(body)
            if (not isinstance(value, dict) or value.get('jsonrpc') != '2.0'
                    or not isinstance(value.get('method'), str) or value['method'] not in READ_METHODS or not isinstance(value.get('params', {}), dict)
                    or type(value.get('id')) not in (int, str) or len(str(value['id'])) > 128):
                return self.answer(403)
            request = urllib.request.Request(self.server.local, data=bytes(body), headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(request, timeout=max(0.001, deadline - time.monotonic())) as response:
                size = int(response.headers.get('Content-Length', '-1'))
                if not 0 <= size <= MAX_RESPONSE:
                    return self.answer(502)
                self.send_response(200); self.send_header('Content-Length', str(size))
                self.send_header('Content-Type', 'application/json'); self.end_headers()
                remaining = size
                while remaining:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('relay request deadline')
                    block = response.read(min(16384, remaining))
                    if not block:
                        raise Failure('truncated local RPC response')
                    self.connection.settimeout(max(0.001, deadline - time.monotonic()))
                    self.wfile.write(block); remaining -= len(block)
                with self.server.guard:
                    self.server.stats['response_bytes'] += size
        except (OSError, ValueError, Failure):
            self.close_connection = True


def read_token(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise Failure('relay token requires a regular non-symlink0600file')
    token = bounded_read(path, 256).strip()
    if len(token) < 32 or not re.fullmatch(rb'[A-Za-z0-9_-]+', token):
        raise Failure('relay token must be32..256randomURL-safecharacters')
    return token


def verify_bind(address, interface):
    ip = ipaddress.ip_address(address)
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        raise Failure('relay must bind the explicit actual VPN address')
    raw = subprocess.run(['ip', '-j', 'address', 'show', 'dev', interface], check=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout
    if len(raw) > 65536:
        raise Failure('interface observation exceeds bound')
    present = {entry['local'] for item in json.loads(raw) for entry in item.get('addr_info', [])}
    if str(ip) not in present:
        raise Failure('relay address is not present on the declared VPN interface')


def collect(args, unit, url):
    now, mono = time.time(), time.monotonic()
    pid = int(unit['MainPID'])
    if pid < 1:
        raise Failure('validator MainPID is absent')
    own_group = next(line.split(':', 2)[2] for line in bounded_read(Path('/proc/self/cgroup')).decode().splitlines() if line.startswith('0::'))
    own_cgroup = read_cgroup(own_group)
    if own_group == unit['ControlGroup']:
        raise Failure('observer must not share the node cgroup')
    sample = {'schema_version': SCHEMA, 'run_id': args.run_id, 'validator': args.validator,
        'utc': utc(), 'unix_s': now, 'monotonic_s': mono,
        'boot_id': bounded_read(Path('/proc/sys/kernel/random/boot_id'), 128).decode().strip(),
        'unit': unit, 'process': read_process(pid, include_fds=False), 'cgroup': read_cgroup(unit['ControlGroup']),
        'telemetry': rpc(url, 'synergy_chainTelemetry'),
        'admission_stats': rpc(url, 'synergy_getProtectedAdmissionStats'), 'host': host_memory(),
        'network_namespace_sockstat': bounded_read(Path('/proc') / str(pid) / 'net/sockstat').decode(),
        'observer': {'pid': os.getpid(), 'process': read_process(os.getpid(), include_fds=False), 'cgroup': own_cgroup,
            'evidence_scope': 'separate qualification observer, never node allocation accounting'}}
    sample['duration_seconds'] = time.monotonic() - mono
    if system_unit(args.service)['MainPID'] != str(pid):
        raise Failure('validator changed during observation')
    return sample


def run(args):
    writer = Evidence(args.evidence, args.evidence_budget_bytes)
    relay = inventory = None
    stopped = threading.Event()
    def stop(_signum, _frame):
        stopped.set()
    signal.signal(signal.SIGTERM, stop); signal.signal(signal.SIGINT, stop)
    started, start_utc = time.monotonic(), utc()
    manifest = {'schema_version': SCHEMA, 'run_id': args.run_id, 'validator': args.validator,
        'actual_start_utc': start_utc, 'clock_scope': 'observer prearm window; central controller owns immutable actual soak start', 'chain_id': args.chain_id, 'network_id': args.network_id, 'duration_seconds': args.duration_seconds, 'sample_seconds': args.sample_seconds,
        'inventory_seconds': args.inventory_seconds, 'smaps_rollup_seconds': 30, 'fd_count_seconds': 60,
        'evidence_budget_bytes': args.evidence_budget_bytes,
        'collector_sha256': hash_file(Path(__file__)), 'qualification_only': True,
        'expected_executable_sha256': args.expected_executable_sha256,
        'normalized_config_sha256_declared_by_controller': args.normalized_config_sha256,
        'qualification_status': 'RUNNING; not a PASS', 'app_root': str(args.app_root),
        'latency_and_all_five_agreement': 'independently verified by central controller',
        'relay_allowlist': sorted(READ_METHODS) if args.relay_address else []}
    writer.save('run-manifest.json', manifest)
    writer.append('events.jsonl', {'schema_version': SCHEMA, 'kind': 'observer_started', 'utc': start_utc, 'run_id': args.run_id, 'soak_pass': False})
    monitor = Monitor(args.chain_id, args.network_id)
    details = ProcessDetails()
    last = last_inventory = None
    next_inventory, next_sample = started, started
    maximum_sample_bytes = 0
    try:
        own_group = next(line.split(':', 2)[2] for line in bounded_read(Path('/proc/self/cgroup')).decode().splitlines() if line.startswith('0::'))
        own = read_cgroup(own_group)
        cpu_policy = bounded_read(Path('/sys/fs/cgroup') / own_group.lstrip('/') / 'cpu.max').decode().split()
        if (own['memory.max'] != '67108864' or own['memory.swap.max'] != '0' or cpu_policy[0] == 'max'
                or int(cpu_policy[0]) / int(cpu_policy[1]) > 0.25):
            raise Failure('observer requires separate64MiB/swap0/CPUatmost25percent policy')
        manifest['observer_resource_policy'] = {'memory.max': own['memory.max'], 'memory.swap.max': own['memory.swap.max'], 'cpu.max': ' '.join(cpu_policy)}
        config = json.loads(bounded_read(args.config))
        for path, expected, label in [(args.config, args.expected_config_sha256, 'config'),
                (Path(config['genesis_path']), args.expected_genesis_sha256, 'signed_genesis'),
                (Path(config['consensus']['authority_binding']), args.expected_authority_sha256, 'signed_authority')]:
            actual = hash_file(path)
            if actual != expected:
                raise Failure('pinned ' + label + ' differs')
            manifest[label + '_sha256'] = actual
        if config['chain_id'] != args.chain_id or config['network_id'] != args.network_id:
            raise Failure('configured chain/network differs')
        if Path(config['storage']['data_directory']) != args.app_root / 'data':
            raise Failure('inventory root does not contain configured canonical data')
        url = local_url(config, args.rpc_url)
        unit = system_unit(args.service)
        actual = hash_file(Path('/proc') / unit['MainPID'] / 'exe', follow=True)
        if actual != args.expected_executable_sha256:
            raise Failure('running executable differs from sealed candidate')
        manifest['running_executable_sha256'] = actual
        manifest['local_rpc'] = url
        writer.save('run-manifest.json', manifest)
        if args.relay_address:
            verify_bind(args.relay_address, args.relay_interface)
        while True:
            if stopped.is_set():
                raise Failure('observer interrupted; this window cannot resume')
            before = time.monotonic()
            if before < next_sample:
                stopped.wait(min(next_sample - before, 1))
                continue
            if last is not None and before - last['monotonic_s'] > args.sample_seconds + 10:
                raise Failure('observer sampling gap exceeded coverage budget')
            sample = collect(args, system_unit(args.service), url)
            details.enrich(sample)
            try:
                summary = monitor.check(sample)
            except Exception as error:
                sample['validation_failure'] = str(error)[:1024]
                writer.append('samples.jsonl', sample)
                raise
            if last is None:
                writer.save('baseline.json', sample)
                if args.relay_address:
                    relay = Relay((args.relay_address, 28745), url, read_token(args.relay_token_file), args.run_id)
                    threading.Thread(target=lambda: relay.serve_forever(poll_interval=0.1), daemon=True).start()
            if inventory is None and before >= next_inventory:
                inventory = Inventory(args.app_root, sample['telemetry']['finalized_height'])
                next_inventory = before + args.inventory_seconds
            if inventory:
                result = inventory.step(sample['telemetry']['finalized_height'])
                if result is not None:
                    if last_inventory:
                        dh = result['end_height'] - last_inventory['end_height']
                        result['per_finalized_block_since_previous_complete_scan'] = {
                            group: {k: (values[k] - last_inventory['groups'].get(group, {}).get(k, 0)) / dh
                                for k in ('entries', 'files', 'logical_bytes', 'allocated_bytes')}
                            for group, values in result['groups'].items()} if dh > 0 else None
                    writer.append('inventories.jsonl', result)
                    last_inventory = result; inventory = None
            sample['inventory'] = last_inventory
            sample['end_monotonic_s'] = time.monotonic()
            sample['deltas_from_baseline'] = summary
            maximum_sample_bytes = max(maximum_sample_bytes,
                len(json.dumps(sample, separators=(',', ':'), allow_nan=False).encode()))
            projection = evidence_projection(maximum_sample_bytes, args.duration_seconds,
                args.sample_seconds, args.inventory_seconds, args.evidence_budget_bytes)
            if not projection['fits_budget']:
                raise Failure('observed sample size projects beyond declared evidence budget')
            if relay:
                with relay.guard:
                    sample['relay'] = dict(relay.stats)
                relay.publish(sample)
            writer.append('samples.jsonl', sample)
            elapsed = sample['monotonic_s'] - started
            state = {'schema_version': SCHEMA, 'run_id': args.run_id, 'validator': args.validator,
                'actual_start_utc': start_utc, 'heartbeat_utc': utc(), 'elapsed_seconds': elapsed,
                'status': 'RUNNING', 'last_height': sample['telemetry']['finalized_height'],
                'last_inventory_complete': last_inventory is not None, 'evidence_bytes': writer.used,
                'evidence_projection': projection}
            writer.save('status.json', state)
            last = sample
            if elapsed >= args.duration_seconds:
                initial = (monitor.baseline['telemetry'].get('chain') or {}).get('finalized_total')
                final = (sample['telemetry'].get('chain') or {}).get('finalized_total')
                if last_inventory is None:
                    raise Failure('no complete bounded filesystem inventory')
                if type(initial) is not int or type(final) is not int or final <= initial:
                    raise Failure('window lacks native successfully finalized transaction activity')
                state.update(status='OBSERVATION_WINDOW_COMPLETE_NEEDS_CONTROLLER_QUALIFICATION',
                    end_utc=utc(), finalized_transaction_count_delta=final - initial,
                    full_24h_elapsed=elapsed >= 86400, soak_pass=False)
                writer.save('terminal.json', state); writer.save('status.json', state)
                return 0
            next_sample = before + args.sample_seconds
    except Exception as error:
        terminal = {'schema_version': SCHEMA, 'run_id': args.run_id, 'validator': args.validator,
            'status': 'FAILED', 'actual_start_utc': start_utc, 'end_utc': utc(),
            'elapsed_seconds': time.monotonic() - started, 'reason': str(error)[:1024],
            'failure_type': type(error).__name__, 'node_action': 'none', 'soak_pass': False,
            'last_successful_sample_utc': last.get('utc') if last else None,
            'instruction': 'central controller must stop load/escalation; never stitch this interval'}
        writer.save('terminal.json', terminal); writer.save('status.json', terminal)
        return 1
    finally:
        if inventory:
            inventory.close()
        if relay:
            relay.stop()
        writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--validator', choices=['val' + str(i) for i in range(2, 7)], required=True)
    parser.add_argument('--app-root', type=Path, default=Path('/opt/Synergy'))
    parser.add_argument('--config', type=Path, default=Path('/opt/Synergy/config/node.json'))
    parser.add_argument('--service', default='synergy-node.service')
    parser.add_argument('--chain-id', type=int, required=True)
    parser.add_argument('--network-id', required=True)
    for field in ('expected-executable-sha256', 'expected-config-sha256', 'expected-genesis-sha256', 'expected-authority-sha256', 'normalized-config-sha256'):
        parser.add_argument('--' + field, required=True)
    parser.add_argument('--rpc-url')
    parser.add_argument('--duration-seconds', type=int, default=87000)
    parser.add_argument('--sample-seconds', type=float, default=5)
    parser.add_argument('--inventory-seconds', type=float, default=300)
    parser.add_argument('--evidence-budget-bytes', type=int, default=512 * 1024 * 1024)
    parser.add_argument('--relay-address')
    parser.add_argument('--relay-interface', choices=['wt0'], default='wt0')
    parser.add_argument('--relay-token-file', type=Path)
    args = parser.parse_args()
    for field in ('expected_executable_sha256', 'expected_config_sha256', 'expected_genesis_sha256', 'expected_authority_sha256', 'normalized_config_sha256'):
        if not re.fullmatch('[0-9a-f]{64}', getattr(args, field)):
            parser.error('explicit lowercase SHA256 pins are required')
    if (not 0 < args.chain_id < 2**64 or not re.fullmatch('[A-Za-z0-9_-]{1,96}', args.run_id)
            or not 1 <= args.duration_seconds <= 90000 or not 1 <= args.sample_seconds <= 15
            or not 300 <= args.inventory_seconds <= 3600
            or not 8 * 1024 * 1024 <= args.evidence_budget_bytes <= 1024 * 1024 * 1024):
        parser.error('invalid bounded observation parameters')
    if bool(args.relay_address) != bool(args.relay_token_file):
        parser.error('relay requires both explicit VPN address and private token file')
    for path in (args.evidence, args.app_root, args.config):
        if not path.is_absolute() or '..' in path.parts:
            parser.error('canonical absolute paths are required')
    os.umask(0o077)
    raise SystemExit(run(args))


if __name__ == '__main__':
    main()
