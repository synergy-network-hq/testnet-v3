import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('native_measurement',Path(__file__).with_name('measure_native_fixture.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class NativeMeasurementTests(unittest.TestCase):
    def fixture(self,root):
        proc=root/'proc';(proc/'self').mkdir(parents=True);(proc/'self/cgroup').write_text('0::/fixture\n')
        cgroot=root/'cgroup';group=cgroot/'fixture';group.mkdir(parents=True)
        for name in m.COUNTERS:
            value='0\n'
            if name=='memory.max':value='1073741824\n'
            elif name=='memory.high':value='max\n'
            elif name.startswith('memory.events'):value='max 7\noom 2\noom_kill 1\n'
            elif name=='memory.stat':value='anon 4096\nfile 8192\nslab 1024\n'
            elif name.endswith('.pressure'):value='some avg10=0.00 total=0\nfull avg10=0.00 total=0\n'
            elif name=='cpu.stat':value='usage_usec 100\nuser_usec 60\nsystem_usec 40\n'
            elif name=='io.stat':value=''
            (group/name).write_text(value)
        return proc,cgroot,group

    def test_actual_caps_and_counter_scopes_serialized_without_faking_empty_io(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc,cgroot,_=self.fixture(root);evidence=root/'evidence'
            code=m.measure(evidence,[sys.executable,'-c','import time;time.sleep(.15)'],.1,proc=proc,cgroot=cgroot)
            self.assertEqual(code,0)
            result=json.loads((evidence/'measurement.json').read_text())
            self.assertEqual(result['before']['counters']['memory.max'].strip(),'1073741824')
            self.assertEqual(result['before']['counters']['memory.swap.max'].strip(),'0')
            self.assertEqual(result['after']['counters']['io.stat'],'')
            self.assertEqual(result['memory_event_deltas']['memory.events.local']['oom'],0)
            self.assertTrue(result['resource_checks_passed']);self.assertGreater(result['native_pid'],0)
            self.assertIn('cpu.pressure',result['after']['counters'])
            self.assertGreater(len((evidence/'samples.jsonl').read_text().splitlines()),0)
            with self.assertRaises(FileExistsError):m.measure(evidence,['unused'],proc=proc,cgroot=cgroot)

    def test_wrong_cap_fails_before_any_child_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc,cgroot,group=self.fixture(root)
            (group/'memory.max').write_text('2147483648\n')
            with patch.object(m.subprocess,'Popen') as spawn:
                self.assertEqual(m.measure(root/'evidence',['unused'],proc=proc,cgroot=cgroot),1)
                spawn.assert_not_called()
            self.assertFalse(json.loads((root/'evidence/measurement.json').read_text())['resource_checks_passed'])

    def test_local_new_oom_stops_own_child_and_preserves_failed_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);proc,cgroot,group=self.fixture(root);evidence=root/'evidence'
            original=m.snapshot;calls=[]
            def snapshot(path):
                if calls:(group/'memory.events.local').write_text('max 7\noom 3\noom_kill 1\n')
                calls.append(1);return original(path)
            with patch.object(m,'snapshot',side_effect=snapshot):
                self.assertEqual(m.measure(evidence,[sys.executable,'-c','import time;time.sleep(60)'],.1,
                                          proc=proc,cgroot=cgroot),1)
            result=json.loads((evidence/'measurement.json').read_text())
            self.assertFalse(result['resource_checks_passed']);self.assertIn('OOM',result['reason'])
            self.assertIn('oom 3',result['last_sample']['counters']['memory.events.local'])
            self.assertIsNotNone(result['exit_code'])

    def test_proc_details_are_bounded_and_sampled_on_distinct_cadences(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory);root=proc/'4';root.mkdir();(root/'fd').mkdir()
            for name in ('status','stat','io','smaps_rollup'):(root/name).write_text('first')
            for i in range(3):(root/'fd'/str(i)).touch()
            sampler=m.ProcessSampler(4,proc)
            first=sampler.sample(0)
            (root/'smaps_rollup').write_text('second');(root/'fd/4').touch()
            self.assertEqual(sampler.sample(29)['smaps_rollup']['value'],'first')
            self.assertEqual(sampler.sample(30)['smaps_rollup']['value'],'second')
            self.assertEqual(sampler.sample(59)['fd_count']['value'],3)
            self.assertEqual(sampler.sample(60)['fd_count']['value'],4)
            self.assertEqual(first['smaps_rollup']['monotonic_s'],0)
            (root/'smaps_rollup').write_text('x'*65537)
            with self.assertRaisesRegex(RuntimeError,'bound'):sampler.sample(90)


if __name__=='__main__':unittest.main()
