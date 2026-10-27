#!/usr/bin/env python3
"""Measure one isolated native fixture inside its caller-provided Linux cgroup.

Never creates or changes a cgroup/service. The caller must supply memory.max=1GiB
and memory.swap.max=0; observation includes this small Python parent.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def measure(evidence, argv):
    evidence.mkdir(mode=0o700)
    leaf = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
    cgroup = Path('/sys/fs/cgroup') / leaf.lstrip('/')
    assert (cgroup/'memory.max').read_text().strip() == '1073741824', 'exact 1GiB cgroup required'
    assert (cgroup/'memory.swap.max').read_text().strip() == '0', 'swap must remain zero'
    counters = ('memory.current','memory.peak','memory.swap.current','memory.events','memory.stat','memory.pressure','io.stat','cpu.stat')
    def snapshot():
        return {'monotonic_s':time.monotonic(), 'counters':{name:(cgroup/name).read_text() for name in counters}}
    before = snapshot()
    started = time.monotonic()
    with (evidence/'stdout.log').open('xb') as output, (evidence/'stderr.log').open('xb') as errors, (evidence/'samples.jsonl').open('x') as samples:
        child = subprocess.Popen(argv,stdout=output,stderr=errors)
        while child.poll() is None:
            samples.write(json.dumps(snapshot())+'\n');samples.flush();time.sleep(0.25)
        code = child.wait()
    result = {'argv':argv,'exit_code':code,'elapsed_s':time.monotonic()-started,
              'before':before,'after':snapshot(),'cgroup':leaf,
              'measurement_scope':'native fixture plus Python sampling parent; emulated Linux, no live capacity claim'}
    (evidence/'measurement.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'exit_code':code,'elapsed_s':result['elapsed_s'],'evidence':str(evidence)}))
    return code


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('command',nargs=argparse.REMAINDER)
    a=p.parse_args();command=a.command[1:] if a.command[:1]==['--'] else a.command
    if not command:p.error('native executable required')
    raise SystemExit(measure(a.evidence,command))
