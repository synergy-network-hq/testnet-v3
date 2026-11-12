#!/usr/bin/env python3
"""Read saved cgroup/process telemetry without contacting or modifying validators."""
import argparse
import json
from pathlib import Path


MEMORY_BYTE_FIELDS = frozenset('anon file kernel kernel_stack pagetables sec_pagetables percpu sock vmalloc shmem zswap zswapped file_mapped file_dirty file_writeback swapcached anon_thp file_thp shmem_thp inactive_anon active_anon inactive_file active_file unevictable slab_reclaimable slab_unreclaimable slab hugetlb'.split())


def counters(raw):
    if not isinstance(raw, str):
        return {}
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
    result = {}
    for line in (raw or '').splitlines():
        fields = line.split()
        if fields:
            result[fields[0]] = {key: float(value) for key, value in
                                 (item.split('=', 1) for item in fields[1:])}
    return result


def delta(first, last):
    return {key: last[key] - first[key] for key in first.keys() & last.keys()}


def analyze(rows):
    hosts = {}
    invalid = []
    for index, row in enumerate(rows):
        for host, sample in row.get('validators', {}).items():
            if not all(key in sample for key in ('cgroup', 'process_status', 'telemetry', 'utc')):
                invalid.append({'row': index, 'validator': host})
                continue
            hosts.setdefault(host, []).append(sample)
    result = {'schema_version': 1, 'invalid_samples': invalid, 'validators': {},
              'limitations': ['Sampled interval only; no 24-hour stability proof.',
                             'memory.stat file/slab subdivisions overlap; never sum them with their parent.',
                             'Kernel counters are asynchronous; residual is not untracked process memory.',
                             'ZFS ARC is host-level and cannot be inferred from this service cgroup.',
                             'Near-limit lifetime peaks/events predate this window unless deltas say otherwise.',
                             'No corrected-release live measurements are implied.']}
    for host, samples in sorted(hosts.items()):
        first, last = samples[0], samples[-1]
        stats = [counters(sample['cgroup'].get('memory.stat')) for sample in samples]
        events = [counters(sample['cgroup'].get('memory.events')) for sample in samples]
        io = [counters(sample.get('process_io')) for sample in samples]
        heights = [sample['telemetry'].get('finalized_height') for sample in samples]
        elapsed = last['host_monotonic'] - first['host_monotonic']
        height_delta = heights[-1] - heights[0]
        def point(sample, stat):
            current = int(sample['cgroup']['memory.current'])
            status = {key: int(value.split()[0]) * 1024 for key, value in
                      sample['process_status'].items() if key.startswith(('Vm', 'Rss'))}
            return {'utc': sample['utc'], 'height': sample['telemetry']['finalized_height'],
                    'current_bytes': current, 'stat_bytes': {key: value for key, value in stat.items() if key in MEMORY_BYTE_FIELDS}, 'stat_counters': {key: value for key, value in stat.items() if key not in MEMORY_BYTE_FIELDS}, 'process_bytes': status,
                    'partition_residual_bytes': current - sum(stat.get(key, 0) for key in ('anon', 'file', 'kernel', 'sock')),
                    'shared_world_reservations': sample['telemetry'].get('resource_budget'),
                    'admission': sample.get('admission_stats')}
        pressure_delta = {}
        for kind in ('memory', 'cpu', 'io'):
            before, after = (pressure(sample['cgroup'].get(f'{kind}.pressure')) for sample in (first, last))
            pressure_delta[kind] = {scope: after[scope]['total'] - before[scope]['total']
                                   for scope in before.keys() & after.keys()}
        io_delta = delta(io[0], io[-1])
        result['validators'][host] = {
            'samples': len(samples), 'elapsed_seconds': elapsed, 'height_delta': height_delta,
            'first': point(first, stats[0]), 'last': point(last, stats[-1]),
            'stat_delta_bytes': {key: value for key, value in delta(stats[0], stats[-1]).items() if key in MEMORY_BYTE_FIELDS},
            'stat_counter_deltas': {key: value for key, value in delta(stats[0], stats[-1]).items() if key not in MEMORY_BYTE_FIELDS},
            'events_before': events[0], 'events_delta': delta(events[0], events[-1]),
            'maximum_sampled_current_bytes': max(int(sample['cgroup']['memory.current']) for sample in samples),
            'lifetime_peak_before_bytes': int(first['cgroup']['memory.peak']),
            'lifetime_peak_after_bytes': int(last['cgroup']['memory.peak']),
            'maximum_sampled_anon_bytes': max(stat.get('anon', 0) for stat in stats),
            'maximum_sampled_sock_bytes': max(stat.get('sock', 0) for stat in stats),
            'maximum_sampled_swap_bytes': max(int(sample['cgroup']['memory.swap.current']) for sample in samples),
            'pressure_total_delta_microseconds': pressure_delta,
            'process_io_delta': io_delta,
            'process_io_per_finalized_block': {key: value / height_delta for key, value in io_delta.items()} if height_delta else {},
            'process_cpu_delta_microseconds': delta(counters(first['cgroup'].get('cpu.stat')),
                                                    counters(last['cgroup'].get('cpu.stat'))),
            'same_process': len({sample['unit']['MainPID'] for sample in samples}) == 1,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('telemetry', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = analyze([json.loads(line) for line in args.telemetry.read_text().splitlines() if line.strip()])
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'validators': list(result['validators']), 'invalid_samples': len(result['invalid_samples']),
                      'output': str(args.output)}))


if __name__ == '__main__':
    main()
