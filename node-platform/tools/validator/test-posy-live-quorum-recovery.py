#!/usr/bin/env python3
"""Controlled retained-journal seq18 quorum test; no hosts unless --execute."""
import argparse
import importlib.util
import json
import time
from pathlib import Path

ROOT=Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
STOP_STATE="import json,subprocess;print(json.dumps(dict(v.split('=',1) for v in subprocess.check_output(['systemctl','show','synergy-posy-stability.service','-p','MainPID','-p','ActiveState','-p','NRestarts']).decode().strip().splitlines())))"
CURSOR="import subprocess;print(subprocess.check_output(['journalctl','-u','synergy-posy-stability.service','-n','0','--show-cursor','--no-pager']).decode().strip())"

def emit(event,**values):
    print(json.dumps(dict(event=event,**values),sort_keys=True),flush=True)

def require_zero(states):
    if set(states)!=set(range(2,7)):raise RuntimeError('exact all-five evidence required')
    for n,s in states.items():
        if int(s['service']['NRestarts'])!=0:raise RuntimeError(f'Val{n} automatic restarts present')

def cleanup(roll,stopped):
    failures=[]
    for n in sorted(stopped):
        try:roll.remote(n,['systemctl','start',roll.SERVICE]);emit('cleanup_start',validator=n)
        except Exception as error:failures.append({'validator':n,'error':str(error)})
    if failures:raise RuntimeError('cleanup start failed: '+json.dumps(failures))

def pointers(states):
    return {n:{k:s['commitment'][k] for k in ['finalized_height','finalized_block_id','state_root']} for n,s in states.items()}

def four_sample(roll,baseline):
    states=dict(roll.read(n) for n in [2,3,4,5])
    for n,s in states.items():
        if int(s['service']['NRestarts'])!=baseline[n]:raise RuntimeError('automatic restart during four-validator recovery')
        if s['service']['ActiveState']!='active' or s['service']['SubState']!='running':return None,states
        if not (s.get('readiness') or {}).get('result',{}).get('ready'):return None,states
        services=(s.get('health') or {}).get('result',{}).get('services',[])
        if not services or any(v['health']!='healthy' for v in services):return None,states
    if any(not s.get('commitment') for s in states.values()):return None,states
    heights=[s['commitment']['finalized_height'] for s in states.values()]
    if max(heights)-min(heights)>2:return None,states
    height=min(heights);proofs=dict(roll.read(n,height) for n in states)
    blocks=[(s.get('block') or {}).get('result') for s in proofs.values()]
    if any(not b or b.get('height')!=height or not b.get('block_hash') or not b.get('state_root') for b in blocks):return None,states
    if any(b!=blocks[0] for b in blocks[1:]):raise RuntimeError('four-validator finalized commitments disagree')
    for s in states.values():
        d=s['commitment']
        if d['finalized_height']==height and (d['finalized_block_id'],d['state_root'])!=(blocks[0]['block_hash'],blocks[0]['state_root']):raise RuntimeError('four-validator durable/RPC mismatch')
    return height,states

def run(roll,timeout):
    binary=roll.TOOLS+'synergy-node-r3-rpc-isolation'
    if len(roll.R3_RPC_ISOLATION_SHA3)!=64:raise RuntimeError('seq18 artifact unpinned')
    verify=[roll.TOOLS+'synergy-keytool','verify-release',roll.BASE+'/release-r3-rpc-isolation.json',binary,'1266','val2-posy-consensus-v1',roll.BASE+'/authority-root.pub','17']
    _,initial=roll.sample();require_zero(initial)
    baseline={n:0 for n in initial}
    ready=roll.wait_advancing('live quorum preflight',baseline,timeout);require_zero(ready)
    for n,s in ready.items():
        if s.get('exe')!=binary:raise RuntimeError('mixed release preflight')
        roll.remote(n,verify)
        unit=json.loads(roll.remote(n,['python3','-c',roll.EDIT,json.dumps(verify),'preflight']))
        if not unit.get('unit_commands_verified') or unit['change_required']:raise RuntimeError('unit not exactly bound to seq18')
    # Capture the native journal cursor without exporting whole logs.
    cursors={}
    for n in ready:
        cursor=roll.remote(n,['python3','-c',CURSOR])
        cursors[n]=(cursor.decode() if isinstance(cursor,bytes) else cursor).strip()
    emit('preflight_pass',services={n:s['service'] for n,s in ready.items()},pointers=pointers(ready),journal_cursors=cursors)
    stopped=set()
    try:
        for n in [5,6]:
            stopped.add(n) # Cleanup includes a stop whose transport response is lost.
            roll.remote(n,['systemctl','stop',roll.SERVICE])
            service=json.loads(roll.remote(n,['python3','-c',STOP_STATE]))
            if int(service['MainPID'])!=0 or service['ActiveState'] not in {'inactive','failed'}:raise RuntimeError('validator did not stop')
            emit('validator_stopped',validator=n,service=service)
        time.sleep(20)
        first=dict(roll.read(n) for n in [2,3,4]);time.sleep(10)
        second=dict(roll.read(n) for n in [2,3,4])
        for n,s in list(first.items())+list(second.items()):
            if int(s['service']['NRestarts'])!=0 or s['service']['ActiveState']!='active' or s['service']['SubState']!='running':raise RuntimeError('survivor failed during below-quorum observation')
        emit('below_quorum_observation',before=pointers(first),after=pointers(second))
        if pointers(first)!=pointers(second):raise RuntimeError('finality changed below quorum after settling')
        roll.remote(5,['systemctl','start',roll.SERVICE]);stopped.remove(5)
        deadline=time.monotonic()+timeout;initial_height=None
        while time.monotonic()<deadline:
            height,states=four_sample(roll,baseline)
            if height is not None:
                if initial_height is None:initial_height=height
                elif height>initial_height:
                    emit('four_validator_recovery_pass',height=height,pointers=pointers(states));break
            time.sleep(2)
        else:raise RuntimeError('four validators did not recover advancing finality')
        roll.remote(6,['systemctl','start',roll.SERVICE]);stopped.remove(6)
        final=roll.wait_advancing('all-five rejoin',baseline,timeout);require_zero(final)
        emit('LIVE_QUORUM_RECOVERY_PASS',pointers=pointers(final),services={n:s['service'] for n,s in final.items()})
    except Exception as error:
        emit('LIVE_QUORUM_RECOVERY_FAIL',error=str(error));raise
    finally:cleanup(roll,stopped)

def self_test():
    class Mock:
        SERVICE='service'
        def __init__(self):self.calls=[]
        def remote(self,n,args):self.calls.append(n)
    mock=Mock();cleanup(mock,{5,6});assert mock.calls==[5,6]
    cleanup(mock,set());assert mock.calls==[5,6]
    for states in [{},{n:{'service':{'NRestarts':1 if n==5 else 0}} for n in range(2,7)}]:
        try:require_zero(states)
        except RuntimeError:pass
        else:raise AssertionError('unsafe preflight accepted')
    require_zero({n:{'service':{'NRestarts':0}} for n in range(2,7)})
    class Failing(Mock):
        def remote(self,n,args):super().remote(n,args);raise RuntimeError('fixture failure')
    failing=Failing()
    try:cleanup(failing,{5,6})
    except RuntimeError:pass
    else:raise AssertionError('cleanup failure hidden')
    assert failing.calls==[5,6]
    compile(STOP_STATE,'stop probe','exec');compile(CURSOR,'cursor probe','exec')
    emit('LIVE_QUORUM_OFFLINE_SELF_TEST_PASS')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');parser.add_argument('--self-test',action='store_true');parser.add_argument('--timeout',type=int,default=300);args=parser.parse_args()
    if args.self_test and args.execute:parser.error('self-test cannot execute')
    if not 60<=args.timeout<=900:parser.error('timeout must be 60..900')
    if not args.execute:self_test();return
    spec=importlib.util.spec_from_file_location('roll',ROOT/'tools/validator/roll-r1-tip.py');roll=importlib.util.module_from_spec(spec);spec.loader.exec_module(roll)
    run(roll,args.timeout)

if __name__=='__main__':main()
