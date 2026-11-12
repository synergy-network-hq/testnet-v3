#!/usr/bin/env python3
"""Measure one isolated native fixture inside its caller-provided Linux cgroup.

Never creates or changes a cgroup/service. The caller must supply memory.max=1GiB
and memory.swap.max=0; observation includes this small Python parent.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import signal
import time


COUNTERS = ('memory.current','memory.peak','memory.max','memory.high','memory.swap.current',
    'memory.swap.max','memory.events','memory.events.local','memory.stat','memory.pressure',
    'io.stat','io.pressure','cpu.stat','cpu.pressure')
OPTIONAL = frozenset(('memory.peak','memory.high','memory.events.local'))


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def read(path, optional=False):
    try:
        with Path(path).open('rb') as stream:value=stream.read(65537)
    except FileNotFoundError:
        if optional:return None
        raise
    if len(value)>65536:raise RuntimeError('measurement input exceeds bound')
    return value.decode()


def snapshot(cgroup):
    values={name:read(cgroup/name,name in OPTIONAL) for name in COUNTERS}
    if values['memory.max'].strip()!='1073741824' or values['memory.swap.max'].strip()!='0':
        raise RuntimeError('exact1GiB/swap0 cgroup required throughout fixture')
    if int(values['memory.swap.current']):raise RuntimeError('fixture swap became nonzero')
    return {'utc':utc(),'monotonic_s':time.monotonic(),'counters':values}


def event_deltas(before, after):
    result={}
    for name in ('memory.events','memory.events.local'):
        old,new=before['counters'].get(name),after['counters'].get(name)
        if (old is None)!=(new is None):raise RuntimeError('memory event coverage changed')
        if old is None:result[name]=None;continue
        first={p[0]:int(p[1]) for p in map(str.split,old.splitlines())}
        last={p[0]:int(p[1]) for p in map(str.split,new.splitlines())}
        if set(first)!=set(last):raise RuntimeError('memory event keys changed')
        result[name]={key:last[key]-first[key] for key in first}
        if any(v<0 for v in result[name].values()):raise RuntimeError('memory event counters reset')
        if any(result[name].get(k,0) for k in ('oom','oom_kill','oom_group_kill')):
            raise RuntimeError('new fixture OOM event: '+name)
    return result


class ProcessSampler:
    def __init__(self,pid,proc=Path('/proc')):
        self.root,self.cached=proc/str(pid),{}
    def sample(self,now):
        result={name:read(self.root/name,True) for name in ('status','stat','io')}
        if result['status'] is None:return {'unavailable':'native process exited during observation'}
        for name,cadence in (('smaps_rollup',30),('fd_count',60)):
            if name not in self.cached or now-self.cached[name]['monotonic_s']>=cadence:
                value=None
                if name=='fd_count':
                    try:
                        value=0
                        with os.scandir(self.root/'fd') as entries:
                            for _ in entries:
                                value+=1
                                if value>131072:raise RuntimeError('native FD observation bound exceeded')
                    except FileNotFoundError:value=None
                else:value=read(self.root/name,True)
                self.cached[name]={'value':value,'monotonic_s':now,'utc':utc()}
            result[name]=self.cached[name]
        return result


def stop_child(child):
    if child is not None and child.poll() is None:
        os.killpg(child.pid,signal.SIGTERM)
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait()


def measure(evidence, argv, sample_seconds=.25, evidence_budget=256*1024*1024,
            proc=Path('/proc'),cgroot=Path('/sys/fs/cgroup')):
    if not .1<=sample_seconds<=5 or not 8*1024**2<=evidence_budget<=1024**3:
        raise ValueError('bounded measurement cadence/budget required')
    os.umask(0o077)
    evidence.mkdir(mode=0o700)
    started=time.monotonic();child=None;used=0
    result={'argv':argv,'actual_start_utc':utc(),'sample_seconds':sample_seconds,
        'smaps_rollup_seconds':30,'fd_count_seconds':60,'evidence_budget_bytes':evidence_budget,
        'measurement_scope':'native fixture plus Python sampling parent; no live capacity/soak claim'}
    try:
        leaf=next(line.split(':',2)[2] for line in read(proc/'self/cgroup').splitlines() if line.startswith('0::'))
        if not leaf.startswith('/') or '..' in Path(leaf).parts:raise RuntimeError('invalid cgroup path')
        cgroup=cgroot/leaf.lstrip('/');result['cgroup']=leaf
        before=snapshot(cgroup);result['before']=before
        with (evidence/'stdout.log').open('xb') as output,(evidence/'stderr.log').open('xb') as errors, \
                (evidence/'samples.jsonl').open('xb') as samples:
            child=subprocess.Popen(argv,stdout=output,stderr=errors,start_new_session=True)
            process=ProcessSampler(child.pid,proc)
            while child.poll() is None:
                current=snapshot(cgroup);result['last_sample']=current;event_deltas(before,current)
                current['native_process']=process.sample(current['monotonic_s'])
                raw=(json.dumps(current,separators=(',',':'),allow_nan=False)+'\n').encode()
                if len(raw)>256*1024 or used+len(raw)+output.tell()+errors.tell()>evidence_budget-1024**2:
                    raise RuntimeError('native measurement evidence quota reached')
                samples.write(raw);samples.flush();used+=len(raw);time.sleep(sample_seconds)
            code=child.wait()
        after=snapshot(cgroup);result['after']=after
        result.update(exit_code=code,after=after,memory_event_deltas=event_deltas(before,after),
            status='COMPLETE' if code==0 else 'FAILED',resource_checks_passed=code==0)
        return_code=code
    except BaseException as error:
        stop_child(child)
        result.update(status='FAILED',resource_checks_passed=False,exit_code=child.poll() if child else None,
            failure_type=type(error).__name__,reason=str(error)[:1024])
        return_code=1
    finally:
        stop_child(child)
        result.update(actual_end_utc=utc(),elapsed_s=time.monotonic()-started,sample_bytes=used,
            native_pid=child.pid if child else None)
        with (evidence/'measurement.json').open('x') as stream:
            json.dump(result,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'exit_code':return_code,'elapsed_s':result['elapsed_s'],'evidence':str(evidence)}))
    return return_code


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True)
    p.add_argument('--sample-seconds',type=float,default=.25)
    p.add_argument('--evidence-budget-bytes',type=int,default=256*1024*1024)
    p.add_argument('command',nargs=argparse.REMAINDER)
    a=p.parse_args();command=a.command[1:] if a.command[:1]==['--'] else a.command
    if not command:p.error('native executable required')
    raise SystemExit(measure(a.evidence,command,a.sample_seconds,a.evidence_budget_bytes))
