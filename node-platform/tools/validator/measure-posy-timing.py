#!/usr/bin/env python3
"""Offline, provenance-unverified Gate A diagnostics; never activates protocols.

Durations are computed inside one collector clock instance only. Incomplete and
rejected attempts remain reportable; unsafe identities remain fatal input errors.
"""
import argparse
import json
import math
import re
from pathlib import Path

PHASES = {
    'admission': ('target_open', 'context_read', 'author_start', 'author_end',
                  'submit_start', 'rpc_enqueue', 'durable_admission',
                  'durable_availability', 'cutoff_close', 'finalized'),
    'window': ('target_open', 'cutoff_close', 'finalized'),
    'proposal': ('proposal_start', 'qc_verified'),
    'cadence': ('start', 'end'), 'runtime': ('start', 'end'),
}
REASONS = {'admission_closed', 'queue_full', 'invalid_input', 'verification_failed',
           'storage_failed', 'worker_failed', 'cancelled', 'timeout'}
TERMINALS = {'rejected', 'failed'}

class MeasurementError(ValueError):
    pass

def distribution(values):
    ordered = sorted(values)
    if not ordered:
        raise MeasurementError('empty phase distribution')
    def percentile(p):
        return ordered[max(0, math.ceil(len(ordered) * p) - 1)]
    return dict(count=len(ordered), min_ns=ordered[0], p50_ns=percentile(.50),
                p95_ns=percentile(.95), p99_ns=percentile(.99), max_ns=ordered[-1])

def aggregate(events, minimum_samples=30):
    if type(minimum_samples) is not int or minimum_samples < 1:
        raise MeasurementError('minimum_samples must be positive')
    groups, run, artifact = {}, None, None
    for index, event in enumerate(events):
        if index >= 100_000 or not isinstance(event, dict):
            raise MeasurementError('invalid or oversized event input')
        for field in ('run_id', 'artifact_sha3_256', 'node_id', 'clock_id', 'trace_id', 'kind', 'phase'):
            if not isinstance(event.get(field), str) or not event[field] or len(event[field]) > 512:
                raise MeasurementError('missing event identity')
        if event.get('platform') != 'linux' or event.get('isolated') is not True:
            raise MeasurementError('only isolated Linux evidence is eligible')
        if not re.fullmatch('[0-9a-f]{64}', event['artifact_sha3_256']):
            raise MeasurementError('invalid artifact digest')
        identity = event['run_id'], event['artifact_sha3_256']
        if run is None:
            run, artifact = identity
        elif identity != (run, artifact):
            raise MeasurementError('mixed runs or artifacts')
        kind, phase = event['kind'], event['phase']
        if kind not in PHASES or phase not in (*PHASES[kind], *TERMINALS):
            raise MeasurementError('unknown phase')
        if phase in TERMINALS and event.get('reason') not in REASONS:
            raise MeasurementError('invalid terminal reason')
        if phase not in TERMINALS and event.get('reason') is not None:
            raise MeasurementError('reason on nonterminal event')
        ns = event.get('monotonic_ns')
        if type(ns) is not int or not 0 <= ns < 2**64:
            raise MeasurementError('invalid monotonic timestamp')
        for field in ('attempt', 'target_height', 'generation'):
            if type(event.get(field)) is not int or not 0 <= event[field] < 2**64:
                raise MeasurementError('missing or invalid attempt/target/generation')
        if kind in {'admission', 'window'} and event['target_height'] == 0:
            raise MeasurementError('admission requires explicit positive target')
        role, classification = event.get('role'), event.get('classification')
        if role not in {'origin', 'participant'} or classification not in {'healthy', 'recovered', 'observed'}:
            raise MeasurementError('invalid observation role/classification')
        if event.get('clock_basis') not in {'process_instant', 'linux_clock_monotonic'}:
            raise MeasurementError('unsupported clock basis; no external mapping implemented')
        key = event['node_id'], event['trace_id'], event['attempt'], event['target_height'], event['generation'], role
        group = groups.setdefault(key, dict(kind=kind, clock=event['clock_id'], classification=classification,
                                           healthy=event.get('healthy'), events={}, reason=None))
        if (group['kind'], group['clock'], group['classification'], group['healthy']) != (kind, event['clock_id'], classification, event.get('healthy')):
            raise MeasurementError('attempt crosses kind, clock or classification')
        if phase in group['events']:
            raise MeasurementError('duplicate phase')
        group['events'][phase] = ns
        if phase in TERMINALS:
            group['reason'] = event['reason']
    metrics, per_node, coverage, diagnostics = {}, {}, {}, []
    successful_origins, origin_nodes, windows, availability = 0, set(), [], {}
    failed, incomplete, violations = 0, 0, []
    qualified_proposal = {}
    nodes = sorted({key[0] for key in groups})
    for key, group in groups.items():
        violations_before = len(violations)
        node, trace, attempt, target, generation, role = key
        kind, times, classification = group['kind'], group['events'], group['classification']
        terminal = next((phase for phase in TERMINALS if phase in times), None)
        if len(set(times) & TERMINALS) > 1:
            raise MeasurementError('multiple terminal outcomes')
        if terminal:
            failed += 1
            if any(value > times[terminal] for phase, value in times.items() if phase != terminal):
                violations.append('event after terminal')
        phases = PHASES[kind]
        if kind == 'admission' and role == 'participant':
            phases = ('durable_availability',)
            if any(phase in times for phase in ('target_open', 'context_read', 'author_start', 'author_end', 'submit_start')):
                violations.append('participant claims client authoring')
        complete = not terminal and set(phases).issubset(times)
        if not complete and not terminal:
            incomplete += 1
        # Partial order: availability may be observed/persisted after cutoff.
        edges = [('target_open', 'context_read'), ('context_read', 'author_start'),
                 ('author_start', 'author_end'), ('author_end', 'submit_start'),
                 ('submit_start', 'rpc_enqueue'), ('rpc_enqueue', 'durable_admission'),
                 ('durable_admission', 'durable_availability'), ('cutoff_close', 'finalized'),
                 ('durable_availability', 'finalized')]
        if kind not in {'admission'}:
            edges = list(zip(phases, phases[1:]))
        for start, end in edges:
            if start in times and end in times and times[end] < times[start]:
                violations.append(f'{kind}.{start}_to_{end} negative')
        pairs = [(f'{a}_to_{b}', a, b) for a, b in edges]
        if kind == 'admission':
            pairs += [('total', 'target_open', 'finalized'), ('window', 'target_open', 'cutoff_close'),
                      ('client_to_durable', 'context_read', 'durable_admission'),
                      ('context_to_durable_availability', 'context_read', 'durable_availability')]
        elif kind == 'window':
            pairs += [('window', 'target_open', 'cutoff_close'), ('total', phases[0], phases[-1])]
        else:
            pairs += [('total', phases[0], phases[-1])]
        if terminal:
            pairs += [('reached_to_terminal', phases[0], terminal)]
        group_metrics = {}
        for name, start, end in pairs:
            if start in times and end in times and times[end] >= times[start]:
                duration = times[end] - times[start]
                metric = f'{kind}.{classification}.{name}'
                metrics.setdefault(metric, []).append(duration)
                per_node.setdefault(node, {}).setdefault(metric, []).append(duration)
                group_metrics[name] = duration
        diagnostics.append(dict(node_id=node, trace_id=trace, attempt=attempt, target_height=target,
                                generation=generation, role=role, classification=classification,
                                status=terminal or ('measured' if complete else 'insufficient'), clock_id=group['clock'],
                                reason=group['reason'], reached_phases=sorted(times), durations_ns=group_metrics))
        if kind == 'window' and 'target_open' in times and 'cutoff_close' in times and times['cutoff_close'] >= times['target_open']:
            windows.append(times['cutoff_close'] - times['target_open'])
        qualified = complete and classification == 'healthy' and not terminal and len(violations) == violations_before
        if kind == 'proposal':
            qualified = qualified and group['healthy'] is True
        if qualified and kind == 'proposal':
            qualified_proposal.setdefault(node, []).append(times['qc_verified'] - times['proposal_start'])
        if qualified:
            coverage[node, kind] = coverage.get((node, kind), 0) + 1
        if qualified and kind == 'admission' and role == 'origin':
            successful_origins += 1
            origin_nodes.add(node)
            windows.append(times['cutoff_close'] - times['target_open'])
            availability.setdefault(node, []).append(times['durable_availability'] - times['context_read'])
    stats = {name: distribution(values) for name, values in sorted(metrics.items())}
    node_stats = {node: {name: distribution(values) for name, values in values.items()} for node, values in per_node.items()}
    proposal_p99s = [distribution(values)['p99_ns'] for values in qualified_proposal.values()]
    worst_proposal = max(proposal_p99s) if proposal_p99s else None
    proposed_interval = None if worst_proposal is None else ((worst_proposal * 5 + 399_999_999) // 400_000_000) * 100
    worst_availability = max((distribution(values)['p99_ns'] for values in availability.values()), default=None)
    required_window = None if worst_availability is None else (worst_availability * 3 + 1) // 2
    actual_window = min(windows) if windows else None
    window_met = None if required_window is None or actual_window is None else actual_window > 0 and actual_window >= required_window
    coverage_met = len(nodes) == 5 and successful_origins >= minimum_samples and set(nodes) == origin_nodes and all(coverage.get((node, kind), 0) >= minimum_samples for node in nodes for kind in ('proposal', 'cadence'))
    status = 'failed' if failed or violations or window_met is False else ('measured' if coverage_met and not incomplete else 'insufficient')
    return dict(schema_version=2, run_id=run, artifact_sha3_256=artifact, nodes=nodes,
                status=status, metrics=stats, per_node_metrics=node_stats, traces=diagnostics,
                incomplete_traces=incomplete, failed_traces=failed, ordering_violations=violations,
                coverage_met=coverage_met, successful_origin_submissions=successful_origins,
                proposed_interval_ms=proposed_interval, required_minimum_admission_window_ns=required_window,
                actual_minimum_admission_window_ns=actual_window, admission_window_requirement_met=window_met,
                provenance_verified=False, clock_mapping_verified=False,
                qualification_eligible=False, protocol_activation_authorized=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('events', type=Path)
    parser.add_argument('--minimum-samples', type=int, default=30)
    args = parser.parse_args()
    try:
        with args.events.open() as source:
            result = aggregate((json.loads(line) for line in source if line.strip()), args.minimum_samples)
    except (OSError, ValueError) as error:
        parser.exit(2, f'timing measurement rejected: {error}\n')
    print(json.dumps(result, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
