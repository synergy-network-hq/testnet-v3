#!/usr/bin/env python3
"""Owner-operated staging only, using existing verified SSH masters."""
import importlib.util,hashlib,json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
ROOT=Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
OUT=ROOT/'networks/testnet/posy-stability'
spec=importlib.util.spec_from_file_location('provision',ROOT/'tools/validator/provision-stability-hosts.py')
owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
BASE='/etc/synergy/posy-stability';TOOL='/usr/local/libexec/synergy/posy-stability/'
PUBLIC_RECEIVER=r"""
import os,sys,hashlib
from pathlib import Path
p=Path(sys.argv[1]);d=sys.stdin.buffer.read(16777217)
if len(d)>16777216 or hashlib.sha256(d).hexdigest()!=sys.argv[2]:raise SystemExit(1)
if p.exists():
 if p.is_symlink() or not p.is_file() or p.read_bytes()!=d:raise SystemExit(1)
else:
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 with os.fdopen(fd,'wb') as f:f.write(d);f.flush();os.fsync(f.fileno())
"""
UNIT="""[Unit]
Description=Synergy fresh PoSy stability validator
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=3

[Service]
Type=simple
User=root
Group=root
Environment=SYNERGY_NETBIRD_BINARY=/usr/local/bin/netbird
ExecStart=/usr/local/libexec/synergy/posy-stability/synergy-node start --config /etc/synergy/posy-stability/node.json
Restart=on-failure
RestartSec=15
KillSignal=SIGINT
TimeoutStopSec=120
RuntimeDirectory=synergy-posy-stability
RuntimeDirectoryMode=0700
UMask=0077
LimitNOFILE=65536
MemoryMax=4G
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/lib/synergy/posy-stability /run/synergy-posy-stability

[Install]
WantedBy=multi-user.target
"""
def stage(number):
 host=f'synergy-val{number}';socket=f'/Users/jhutzler/.ssh/posy-val{number}-control'
 def remote(argv,data=None):return owner.remote(host,socket,argv,data)
 def public(path,data):remote(['python3','-c',PUBLIC_RECEIVER,path,hashlib.sha256(data).hexdigest()],data)
 binary=(ROOT/'target/x86_64-unknown-linux-gnu/release/synergy-node').read_bytes()
 if hashlib.sha256(binary).hexdigest()!='528425f3878725cd404b119b6ea384c55b636a471c21bfae580b0ab15388374d':raise RuntimeError('node hash changed')
 code=owner.RECEIVER.replace(TOOL+'synergy-keytool',TOOL+'synergy-node')
 remote(['python3','-c',code,'binary',len(binary),hashlib.sha256(binary).hexdigest()],binary)
 for name in ['genesis.json','authority.json','authority-root.pub','network-manifest.json','p2p-bindings.json','transport-registry.json','release.json']:
  public(BASE+'/'+name,(OUT/name).read_bytes())
 public(BASE+'/node.json',(OUT/f'val{number}.json').read_bytes())
 netbird='/usr/local/bin/netbird' if number==2 else '/opt/synergy/netbird-client/bin/netbird'
 public('/etc/systemd/system/synergy-posy-stability.service',UNIT.replace('/usr/local/bin/netbird',netbird).encode())
 remote(['python3','-c',"import os;from pathlib import Path;p=Path('/var/lib/synergy/posy-stability');p.mkdir(mode=0o700,exist_ok=True);assert not p.is_symlink();[os.chmod(x,0o600) for x in Path('/etc/synergy/posy-stability/custody').glob('*/*.secret.key')]"])
 remote(['test','-x',netbird])
 remote([TOOL+'synergy-keytool','verify-authority',BASE+'/authority.json','1266','synergy-posy-stability-20261009','val2-posy-consensus-v1',BASE+'/authority-root.pub'])
 remote([TOOL+'synergy-keytool','verify-release',BASE+'/release.json',TOOL+'synergy-node','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','0'])
 remote(['systemd-analyze','verify','/etc/systemd/system/synergy-posy-stability.service'])
 return {'validator':number,'native_version':remote([TOOL+'synergy-node','--version']).decode().strip(),'signed_release_verified':True,'started':False}

FRESH_PREFLIGHT = r"""
import os,stat,sys
from pathlib import Path
base,executables,state,runtime=map(Path,sys.argv[1:5])
def directory(path):
 for item in reversed([path,*path.parents]):
  if item.is_symlink():raise ValueError('symlink deployment root refused')
  if not item.exists():item.mkdir(mode=0o700)
  st=item.lstat()
  if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe deployment directory')
for path in [base,executables,state.parent]:directory(path)
if state.is_symlink() or (state.exists() and (not state.is_dir() or any(state.iterdir()))):raise ValueError('fresh canary state must be empty')
for proc in Path('/proc').iterdir():
 if proc.name.isdigit():
  try:
   if Path(os.readlink(proc/'exe').removesuffix(' (deleted)')).name.startswith('synergy-node'):raise ValueError('validator process must be stopped before fresh stage')
  except (FileNotFoundError,ProcessLookupError):pass
"""


def stage_fresh(number, host, socket, public_directory, node_binary, node_sha256,
                network_id, trust_key_id, deployment_name, memory_max_bytes,
                installed_sequence=0):
 """Stage an exact isolated async candidate; never start or alter an old service.

 Public/config/custody generation and signing must already be complete. The
 caller supplies its existing verified SSH master and exact qualified binary.
 """
 paths=owner.fresh_deployment_paths(deployment_name)
 if deployment_name is None:raise ValueError('explicit separate canary required')
 network_id=owner.fresh_network_id(network_id)
 if number not in range(2,7) or not isinstance(installed_sequence,int) or installed_sequence<0:
  raise ValueError('invalid validator or installed release sequence')
 if not isinstance(trust_key_id,str) or not trust_key_id.strip():raise ValueError('explicit trust key ID required')
 if type(memory_max_bytes) is not int or memory_max_bytes<=0:
  raise ValueError('explicit qualified memory limit required')
 output=Path(public_directory)
 if output!=paths['public_directory'] or not output.is_dir() or output.is_symlink():
  raise ValueError('matching canonical fresh canary public directory required')
 binary=owner.fingerprint_binary(node_binary,node_sha256)
 if binary[:7]!=b'\x7fELF\x02\x01\x01' or binary[18:20]!=b'\x3e\x00':raise ValueError('qualified Linux node required')
 def read(name):
  p=output/name
  if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=16*1024*1024:
   raise ValueError('bounded regular public canary artifact required')
  return p.read_bytes()
 names=['genesis.json','authority.json','authority-root.pub','network-manifest.json',
        'p2p-bindings.json','transport-registry.json','release.json']
 artifacts={name:read(name) for name in names}
 configuration=read(f'val{number}.json')
 config=json.loads(configuration)
 authority=json.loads(artifacts['authority.json'])['payload']
 policy=authority.get('protected',{})
 if (authority.get('network_id')!=network_id or policy.get('version')!=2
     or policy.get('cutoff_relationship')!='processing_groups_v1' or config.get('network_id')!=network_id
     or authority.get('chain_id')!=1266 or config.get('chain_id')!=1266):
  raise ValueError('exact signed asynchronous network binding required')
 base=paths['configuration'];executables=paths['executables'];state=paths['state']
 runtime='/run/synergy-'+deployment_name
 expected={
  'manifest_path':base+'/network-manifest.json',
  'aegis_key_bindings_path':base+'/p2p-bindings.json',
  'admin_socket_path':runtime+'/admin.sock',
 }
 if any(config.get(k)!=v for k,v in expected.items()):raise ValueError('config escapes isolated canary paths')
 if (config['storage']['data_directory']!=state
     or config['consensus']['authority_binding']!=base+'/authority.json'
     or config['consensus']['authority_trust_key_path']!=base+'/authority-root.pub'
     or config['vpn']['signed_registry_path']!=base+'/transport-registry.json'):
  raise ValueError('canary authority/state/transport paths differ')
 for path in [config['public_identity_path'],config['aegis_signing_key_path'],
              config['consensus']['signing_key_path'],config['etdag']['ingress_kem_secret_key_path']]:
  if not isinstance(path,str) or not Path(path).is_relative_to(base+'/custody') or '..' in Path(path).parts:
   raise ValueError('fresh canary must use its own custody')
 owner.master_arguments(host,socket)
 def remote(argv,data=None):return owner.remote(host,socket,argv,data)
 remote(['python3','-c',FRESH_PREFLIGHT,base,executables,state,runtime])
 receiver=(owner.RECEIVER.replace('/etc/synergy/posy-stability',base)
           .replace('/usr/local/libexec/synergy/posy-stability',executables)
           .replace("synergy-keytool')", "synergy-node')"))
 remote(['python3','-c',receiver,'binary',len(binary),node_sha256],binary)
 def public(path,data):remote(['python3','-c',PUBLIC_RECEIVER,path,hashlib.sha256(data).hexdigest()],data)
 for name,data in artifacts.items():public(base+'/'+name,data)
 public(base+'/node.json',configuration)
 netbird='/usr/local/bin/netbird' if number==2 else '/opt/synergy/netbird-client/bin/netbird'
 unit=(UNIT.replace('/usr/local/libexec/synergy/posy-stability',executables)
       .replace('/etc/synergy/posy-stability',base)
       .replace('/var/lib/synergy/posy-stability',str(Path(state).parent))
       .replace('synergy-posy-stability','synergy-'+deployment_name)
       .replace('MemoryMax=4G','MemoryMax='+str(memory_max_bytes)+'\nMemorySwapMax=0')
       .replace('/usr/local/bin/netbird',netbird))
 # A fresh candidate uses the caller's exact qualified cgroup limit. The legacy
 # unit and legacy staging entry point retain their existing policy unchanged.
 public('/etc/systemd/system/synergy-'+deployment_name+'.service',unit.encode())
 remote(['test','-x',netbird])
 remote([executables+'/synergy-keytool','verify-authority',base+'/authority.json','1266',network_id,trust_key_id,base+'/authority-root.pub'])
 remote([executables+'/synergy-keytool','verify-release',base+'/release.json',executables+'/synergy-node','1266',trust_key_id,base+'/authority-root.pub',str(installed_sequence)])
 remote(['systemd-analyze','verify','/etc/systemd/system/synergy-'+deployment_name+'.service'])
 return {'validator':number,'network_id':network_id,'deployment_name':deployment_name,
         'binary_sha256':node_sha256,'memory_max_bytes':memory_max_bytes,
         'signed_release_verified':True,'started':False}

if __name__=='__main__':
 with ThreadPoolExecutor(max_workers=5) as pool:
  for result in pool.map(stage,range(2,7)):print(json.dumps(result),flush=True)
