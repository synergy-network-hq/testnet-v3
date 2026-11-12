import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('accounting', Path(__file__).with_name('analyze-memory-accounting.py'))
accounting = importlib.util.module_from_spec(spec)
spec.loader.exec_module(accounting)


class AccountingTests(unittest.TestCase):
    def test_overlapping_stat_categories_are_not_double_counted_and_lifetime_events_are_deltas(self):
        def sample(t, height, current, stat, maximum, io):
            return {'utc': str(t), 'host_monotonic': t, 'unit': {'MainPID': '10'},
                    'process_status': {'VmRSS': '10 kB', 'RssAnon': '8 kB'},
                    'telemetry': {'finalized_height': height}, 'process_io': f'write_bytes: {io}\n',
                    'cgroup': {'memory.current': str(current), 'memory.peak': '1024',
                               'memory.stat': stat, 'memory.events': f'max {maximum}\noom 0\n',
                               'memory.swap.current': '0'}}
        first = sample(1, 1, 100, 'anon 10\nfile 60\nkernel 25\nslab_reclaimable 20\nsock 5\n', 7, 100)
        last = sample(3, 3, 140, 'anon 10\nfile 95\nkernel 30\nslab_reclaimable 25\nsock 5\n', 7, 140)
        got = accounting.analyze([{'validators': {'2': first}}, {'validators': {'2': last}}])['validators']['2']
        self.assertEqual(got['last']['partition_residual_bytes'], 0)
        self.assertEqual(got['events_before']['max'], 7)
        self.assertEqual(got['events_delta']['max'], 0)
        self.assertEqual(got['process_io_per_finalized_block']['write_bytes'], 20)
        self.assertEqual(got['first']['process_bytes']['VmRSS'], 10240)
        self.assertEqual(got['stat_delta_bytes']['anon'], 0)

    def test_missing_sample_is_recorded_instead_of_silently_becoming_zero(self):
        result = accounting.analyze([{'validators': {'4': {'error': 'unavailable'}}}])
        self.assertEqual(result['invalid_samples'], [{'row': 0, 'validator': '4'}])
        self.assertEqual(result['validators'], {})

    def test_pressure_preserves_each_scope_and_total(self):
        got = accounting.pressure('some avg10=0.00 avg60=0.50 avg300=0.00 total=13\nfull avg10=0.00 total=7\n')
        self.assertEqual(got['some']['total'], 13)
        self.assertEqual(got['full']['total'], 7)
        self.assertEqual(got['some']['avg60'], .5)


if __name__ == '__main__':
    unittest.main()
