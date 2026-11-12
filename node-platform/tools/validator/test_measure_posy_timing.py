import copy
import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('measure', Path(__file__).with_name('measure-posy-timing.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def fixture():
    events = []
    timelines = {'admission': [0, 10, 20, 100, 110, 120, 200, 300, 1000, 2000],
                 'window': [0, 1000, 2000], 'proposal': [0, 1_700_000_000], 'cadence': [0, 500_000_000], 'runtime': [0, 100_000_000]}
    for node in range(5):
        for kind, phases in module.PHASES.items():
            for phase, ns in zip(phases, timelines[kind]):
                events.append(dict(run_id='isolated', artifact_sha3_256='a'*64, platform='linux', isolated=True,
                    node_id=str(node), clock_id=f'process-instance-{node}', clock_basis='process_instant',
                    trace_id=kind, kind=kind, phase=phase, monotonic_ns=ns,
                    attempt=0, target_height=5, generation=0, role='origin', classification='healthy',
                    healthy=True if kind == 'proposal' else None))
    return events

class Tests(unittest.TestCase):
    def test_exact_measured_budget_never_claims_qualification(self):
        result = module.aggregate(list(reversed(fixture())), 1)
        self.assertEqual(result['status'], 'measured')
        self.assertEqual(result['proposed_interval_ms'], 2200)
        self.assertEqual(result['required_minimum_admission_window_ns'], 435)
        self.assertTrue(result['admission_window_requirement_met'])
        self.assertFalse(result['qualification_eligible'])
        self.assertFalse(result['provenance_verified'])
    def test_rejection_preserves_reached_phase_durations(self):
        events = fixture()
        events = [e for e in events if not (e['node_id']=='0' and e['kind']=='admission' and e['phase'] in module.PHASES['admission'][6:])]
        event = copy.deepcopy(next(e for e in events if e['node_id']=='0' and e['kind']=='admission'))
        event.update(phase='rejected', reason='admission_closed', monotonic_ns=150)
        events.append(event)
        result=module.aggregate(events, 1)
        self.assertEqual(result['status'], 'failed')
        trace=next(t for t in result['traces'] if t['node_id']=='0' and t['trace_id']=='admission')
        self.assertEqual(trace['durations_ns']['author_start_to_author_end'], 80)
        self.assertNotIn('client_to_durable', trace['durations_ns'])
    def test_incomplete_does_not_erase_diagnostics(self):
        result=module.aggregate(fixture()[:-1], 1)
        self.assertEqual(result['status'], 'insufficient')
        self.assertEqual(result['incomplete_traces'], 1)
        self.assertTrue(result['metrics'])
    def test_recovered_availability_after_cutoff_is_legal(self):
        events=fixture()
        for e in events:
            if e['kind']=='admission' and e['node_id']=='0':
                e['classification']='recovered'
                if e['phase']=='durable_availability':e['monotonic_ns']=1500
        result=module.aggregate(events,1)
        self.assertEqual(result['ordering_violations'], [])
        self.assertIn('admission.recovered.context_to_durable_availability',result['metrics'])
        self.assertEqual(result['required_minimum_admission_window_ns'],435)
    def test_inadequate_window_reports_false(self):
        events=fixture()
        for e in events:
            if e['kind']=='admission' and e['phase']=='durable_availability':e['monotonic_ns']=900
        result=module.aggregate(events,1)
        self.assertEqual(result['status'],'failed')
        self.assertFalse(result['admission_window_requirement_met'])
        self.assertEqual(result['actual_minimum_admission_window_ns'],1000)
    def test_worst_node_and_unhealthy_exclusion(self):
        events=fixture()
        for e in events:
            if e['kind']=='proposal' and e['node_id']=='0' and e['phase']=='qc_verified':e['monotonic_ns']=4_000_000_000
        self.assertEqual(module.aggregate(events,1)['proposed_interval_ms'],5000)
        for e in events:
            if e['kind']=='proposal' and e['node_id']=='0':e['healthy']=False
        result=module.aggregate(events,1)
        self.assertEqual(result['proposed_interval_ms'],2200)
        self.assertFalse(result['coverage_met'])
    def test_unsafe_identity_duplicate_clock_and_reason_rejected(self):
        for mutate in [lambda e:e.append(e[0].copy()),lambda e:e[1].update(clock_id='other'),
            lambda e:e[0].update(platform='macos'),lambda e:e[0].update(artifact_sha3_256='b'*64),
            lambda e:e[0].update(monotonic_ns=True),lambda e:e[0].update(phase='rejected',reason='arbitrary-secret')]:
            events=fixture();mutate(events)
            with self.assertRaises(module.MeasurementError):module.aggregate(events,1)
    def test_participant_does_not_require_client_authoring(self):
        events=fixture()
        participant=[]
        for e in events:
            if e['kind']=='admission' and e['phase'] in ('durable_availability','cutoff_close','finalized'):
                n=copy.deepcopy(e);n.update(trace_id='participant',role='participant',classification='recovered');participant.append(n)
        result=module.aggregate(events+participant,1)
        self.assertEqual(result['ordering_violations'],[])
        self.assertEqual(result['status'],'measured')
    def test_real_linux_basis_does_not_authorize_cross_domain_join(self):
        events=fixture()
        for e in events:e['clock_basis']='linux_clock_monotonic'
        self.assertFalse(module.aggregate(events,1)['clock_mapping_verified'])
        events[1]['clock_id']='different-time-namespace'
        with self.assertRaisesRegex(module.MeasurementError,'clock'):
            module.aggregate(events,1)
    def test_actual_participant_storage_and_window_do_not_invent_client_latency(self):
        base = fixture()[0]
        events = []
        for phase, ns in [('rpc_enqueue', 10), ('durable_admission', 20), ('durable_availability', 30)]:
            e = dict(base, trace_id='envelope-a', kind='admission', phase=phase,
                     monotonic_ns=ns, role='participant', classification='observed')
            events.append(e)
        for phase, ns in [('target_open', 0), ('cutoff_close', 100), ('finalized', 200)]:
            events.append(dict(base, trace_id='target-window', kind='window', phase=phase,
                               monotonic_ns=ns, role='participant', classification='observed'))
        result = module.aggregate(events, 1)
        self.assertEqual(result['ordering_violations'], [])
        self.assertEqual(result['metrics']['admission.observed.rpc_enqueue_to_durable_admission']['count'], 1)
        self.assertEqual(result['actual_minimum_admission_window_ns'], 100)
        self.assertIsNone(result['required_minimum_admission_window_ns'])
        self.assertFalse(result['coverage_met'])
        self.assertNotIn('admission.observed.context_to_durable_availability', result['metrics'])

    def test_distinct_envelopes_at_one_height_keep_independent_timings(self):
        base = fixture()[0]
        events = []
        for trace, delay in [('envelope-a', 10), ('envelope-b', 40)]:
            for phase, ns in [('durable_admission', 0), ('durable_availability', delay)]:
                events.append(dict(base, trace_id=trace, kind='admission', phase=phase,
                                   monotonic_ns=ns, role='participant', classification='observed'))
        result = module.aggregate(events, 1)
        self.assertEqual(result['metrics']['admission.observed.durable_admission_to_durable_availability']['count'], 2)
        self.assertFalse(result['qualification_eligible'])

    def test_percentiles(self):
        self.assertEqual(module.distribution(list(range(1,101)))['p99_ns'],99)

if __name__=='__main__':unittest.main()
