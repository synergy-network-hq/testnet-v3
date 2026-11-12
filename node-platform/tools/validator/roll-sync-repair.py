#!/usr/bin/env python3
"""Guarded root-owned one-at-a-time rollout; never resets custody or state."""
import importlib.util,json,time,os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
ROOT=Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
def module(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
owner=module('provision',ROOT/'tools/validator/provision-stability-hosts.py')
observer=module('observe',ROOT/'tools/validator/observe-stability-fleet.py')
def matched():
 with ThreadPoolExecutor(max_workers=5) as p:states=dict(p.map(observer.read,range(2,7)))
 if any(s['service']['SubState']!='running' for s in states.values()):return False,states
 heights=[s['durable_height'] for s in states.values()]
 if min(heights)<1 or max(heights)-min(heights)>2:return False,states
 with ThreadPoolExecutor(max_workers=5) as p:proofs=dict(p.map(lambda n:observer.read(n,min(heights)),range(2,7)))
 blocks=[s.get('block',{}).get('result') for s in proofs.values()]
 if any(b is None for b in blocks):return False,states
 if any(b!=blocks[0] for b in blocks[1:]):raise RuntimeError('finalized RPC conflict; rollout refused')
 return True,states

def wait_ready(label,timeout=900):
 end=time.monotonic()+timeout;last=None
 while time.monotonic()<end:
  ready,states=matched()
  if ready:
   print(json.dumps({'event':'matching_fleet_ready','label':label,'heights':{n:s['durable_height'] for n,s in states.items()}}),flush=True);return
  current=tuple((n,s['service']['SubState'],s['durable_height']//20) for n,s in states.items())
  if current!=last:
   print(json.dumps({'event':'verified_catchup_wait','label':label,'heights':{n:s['durable_height'] for n,s in states.items()},'running':{n:s['service']['SubState'] for n,s in states.items()}}),flush=True);last=current
  time.sleep(15)
 raise RuntimeError('fleet did not regain matching live finality; no further restart performed')
EDIT="""from pathlib import Path;import os
p=Path('/etc/systemd/system/synergy-posy-stability.service');assert not p.is_symlink()
s=p.read_text();assert 'synergy-node start --config' in s
s=s.replace('synergy-node start --config','synergy-node-sync-repair start --config')
with p.open('w') as f:f.write(s);f.flush();os.fsync(f.fileno())
"""
if __name__=='__main__':
 wait_ready('Val3 repaired catch-up')
 for n in [6,2,4]:
  h=f'synergy-val{n}';sock=f'/Users/jhutzler/.ssh/posy-val{n}-control';base='/etc/synergy/posy-stability';tool='/usr/local/libexec/synergy/posy-stability/'
  owner.remote(h,sock,[tool+'synergy-keytool','verify-release',base+'/release-sync-repair.json',tool+'synergy-node-sync-repair','1266','val2-posy-consensus-v1',base+'/authority-root.pub','1'])
  owner.remote(h,sock,['python3','-c',EDIT])
  owner.remote(h,sock,['systemctl','daemon-reload'])
  owner.remote(h,sock,['systemctl','restart','synergy-posy-stability.service'])
  print(json.dumps({'event':'repair_restarted','validator':n}),flush=True)
  wait_ready(f'Val{n} repaired restart')
 observer.observe()
 print('ROLLING_REPAIR_COMPLETE',flush=True)
