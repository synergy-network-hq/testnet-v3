#!/usr/bin/env python3
"""Read actual service/durable/RPC state and append public launch evidence."""
import subprocess,json,shlex,datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
REMOTE=r"""import json,subprocess,sys,urllib.request
from pathlib import Path
service=subprocess.check_output(['systemctl','show','synergy-posy-stability.service','-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts']).decode()
config=json.loads(Path('/etc/synergy/posy-stability/node.json').read_text())
data=Path(config['storage']['data_directory'])
finalized=json.loads((data/'state/execution/finalized-state.json').read_text())['state']
head=int(finalized['finalized_height'])
r={'service':dict(line.split('=',1) for line in service.strip().splitlines()),'durable_height':head,'durable_block_id':finalized.get('finalized_block_id'),'durable_state_root':finalized.get('state_root')}
if len(sys.argv)>1:
 try:
  q={'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':{'height':int(sys.argv[1]),'hash':None}}
  r['block']=json.load(urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8545',json.dumps(q).encode(),{'Content-Type':'application/json'}),timeout=10))
 except Exception:r['rpc_unavailable']=True
print(json.dumps(r))
"""
def read(n,height=None):
 argv=['ssh','-T','-S',f'/Users/jhutzler/.ssh/posy-val{n}-control','-o','ControlMaster=no','-o','ProxyCommand=/usr/bin/false',f'synergy-val{n}','exec sudo -n -- '+shlex.join(['python3','-c',REMOTE]+([] if height is None else [str(height)]))]
 r=subprocess.run(argv,capture_output=True,text=True,timeout=20)
 if r.returncode:raise RuntimeError('fleet observation failed')
 return n,json.loads(r.stdout)
def observe():
 with ThreadPoolExecutor(max_workers=5) as pool:states=dict(pool.map(read,range(2,7)))
 running=[s['durable_height'] for s in states.values() if s['service']['SubState']=='running']
 height=min(running,default=0)
 with ThreadPoolExecutor(max_workers=5) as pool:checked=dict(pool.map(lambda n:read(n,height),range(2,7)))
 evidence={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checked_height':height,'validators':checked}
 out=Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform/networks/testnet/posy-stability/live-observations.jsonl')
 with out.open('a') as f:f.write(json.dumps(evidence,sort_keys=True)+'\n')
 for n,s in checked.items():
		b=s.get('block',{}).get('result') or {}
		print(json.dumps({'validator':n,'service':s['service'],'durable_height':s['durable_height'],'durable_block_id':s['durable_block_id'],'durable_state_root':s['durable_state_root'],'checked_height':height,'block_hash':b.get('block_hash'),'state_root':b.get('state_root'),'rpc_unavailable':s.get('rpc_unavailable',False)}))
if __name__=='__main__':observe()
