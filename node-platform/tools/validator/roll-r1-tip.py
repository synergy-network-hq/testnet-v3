#!/usr/bin/env python3
"""Guarded signed PoSy release rollout. Default is read-only; --execute authorizes rollout."""
import argparse
import importlib.util
import json
import shlex
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
BASE = '/etc/synergy/posy-stability'
TOOLS = '/usr/local/libexec/synergy/posy-stability/'
BINARY = TOOLS + 'synergy-node-r1-tip-recovery'
UNIT = '/etc/systemd/system/synergy-posy-stability.service'
SERVICE = 'synergy-posy-stability.service'
ORDER = [3, 2, 4, 6]
PREFETCH_SHA3 = 'bfedf400d8b76ff9473f2f23ad6c4cddd4a9832c81ddd189eeaf00960ca93845'  # Sequence 9 is unavailable until the release owner pins the built artifact.
CHUNK_RECOVERY_SHA3 = '94d9b97520d1fbb7c15daaa564938c66e853472a14f54b9c57a3054f42e88bec'
R3_RECOVERY_SHA3 = 'ed2d34d55d845949218c50bac2dedbda77714a9f6e5e8ef149e6a3871159fded'
R3_ADMISSION_CUTOFF_SHA3 = 'eb7c8182c971b7d3bc893fa7c8b2fec50c095520efa366a825cbd4d9ef84fdb3'  # Fail closed until qualified native build is pinned.
R3_RPC_ISOLATION_SHA3 = '5e359fa39688198586e5ddb3b755e5058012e8d905b666aeb87e3e83c0226e34'  # Pin only after qualified native build.
R3_ETDAG_CACHE_SHA3 = 'fabd22210e371020c4571a9a4c1d46c96967825c370a8841635b6e89f1fcdd9b'  # Pin only after qualified native build.
R3_RETAINED_RECOVERY_SHA3 = '8850162e502467e75e661c9817fd8bc6a8f7aa63343bd21f7461621f7c8cd003'
R3_ACTIVATION_COMMITMENT = 'posy-r1-r2-r3:sha3-256:233f4634a74497ee88ebf267eb6d89604a864c25f891741943baf69e7c057989'
VERIFY = [TOOLS + 'synergy-keytool', 'verify-release', BASE + '/release-r1-tip.json',
          BINARY, '1266', 'val2-posy-consensus-v1', BASE + '/authority-root.pub', '3']
spec = importlib.util.spec_from_file_location('provision', ROOT / 'tools/validator/provision-stability-hosts.py')
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

READ = r'''
import hashlib, json, subprocess, sys, urllib.request, os, shlex
from pathlib import Path
service = subprocess.check_output(['systemctl','show','synergy-posy-stability.service',
    '-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts']).decode()
s = dict(line.split('=',1) for line in service.strip().splitlines())
configuration = json.loads(Path('/etc/synergy/posy-stability/node.json').read_text())
root = Path(configuration['storage']['data_directory'])
if not root.is_absolute() or not str(root).startswith('/var/lib/synergy/posy-stability/'):raise RuntimeError('unexpected active data directory')
pointer = root / 'state/execution/finalized-state.json'
d = json.loads(pointer.read_text()) if pointer.is_file() else None
r = {'service':s, 'commitment':None if d is None else d['state']}
if int(s['MainPID']) > 0:
    r['exe'] = os.readlink('/proc/'+s['MainPID']+'/exe')
    cli = r['exe']
    for action in ['health','readiness','status']:
        result = subprocess.run([cli,action,'--admin-socket','/run/synergy-posy-stability/admin.sock','--output','json'],
                                capture_output=True,text=True,timeout=10)
        if result.returncode: r[action] = None
        else: r[action] = json.loads(result.stdout)
# Narrow migration for the documented pre-sequence-8 lifecycle defect. Each
# tuple pins a previously signed native artifact; unknown/new releases never
# receive compatibility readiness. Catch-up Pending remains a hard rejection.
legacy_profiles={
 'synergy-node':('release.json',1,'posy-stability-20261009','9c134ccd45121ec017113c4266e2ee86da5a2a41a6592a48e21e6713d7cb5437'),
 'synergy-node-sync-repair':('release-sync-repair.json',2,'posy-stability-20261009-sync-repair','6b2a03d0952305cef5b3bff54797e57227a2235e1d4d40e163453ca937cefc12'),
 'synergy-node-r1-recovery':('release-r1.json',3,'posy-stability-20261009-r1-recovery','6be74abde046d419093684589a9ca427368edb2855eb20781bb9696d283bf4fd'),
 'synergy-node-r1-tip-recovery':('release-r1-tip.json',4,'posy-stability-20261009-r1-tip-recovery','e5f7eafd2a6ed037d9d8ca5af55cee65a5e8a4f3622e76a7ee360e8f51c5a096'),
 'synergy-node-r1-performance':('release-r1-performance.json',5,'posy-stability-20261009-r1-performance','5788c29603dd96386c426adacd086aa787f846ffe740ee7bc79eb30037ea118d'),
 'synergy-node-r1-startup-performance':('release-r1-startup-performance.json',6,'posy-stability-20261009-r1-startup-performance','6f6977240e3e10b408591ef991401b252933ee9d70d8e6367aff3df4d5fe186e'),
 'synergy-node-r1-gap-wait':('release-r1-gap-wait.json',7,'posy-stability-20261009-r1-gap-wait','094bf6917a55e9e3176335ba73c466266314650236d9c4151d5b92f49764b58d')}
r['verified_legacy_readiness']=False
health=r.get('health') or {}; readiness=r.get('readiness') or {}; status=r.get('status') or {}
observations=health.get('result',{}).get('services',[])
if (readiness.get('ok') is True and readiness.get('result',{}).get('ready') is False
    and health.get('ok') is True and observations
    and all(v.get('state')=='running' and v.get('health')=='healthy' and v.get('readiness',{}).get('status')=='ready' for v in observations)
    and status.get('ok') is True and status.get('result',{}).get('lifecycle')=='shadowing'
    and status.get('result',{}).get('chain_id')==1266 and status.get('result',{}).get('role')=='validator'):
    tools='/usr/local/libexec/synergy/posy-stability/';base='/etc/synergy/posy-stability'
    profile=legacy_profiles.get(Path(r.get('exe','')).name)
    if profile and r['exe']==tools+Path(r['exe']).name:
        metadata,sequence,release_id,expected_hash=profile
        verify=[tools+'synergy-keytool','verify-release',base+'/'+metadata,r['exe'],
                '1266','val2-posy-consensus-v1',base+'/authority-root.pub',str(sequence-1)]
        release=json.loads(Path(verify[2]).read_text())['release']
        if (release['sequence']!=sequence or release['release_id']!=release_id
            or release['artifact']['sha3_256']!=expected_hash):
            raise RuntimeError('legacy readiness release metadata mismatch')
        digest=hashlib.sha3_256()
        with open(r['exe'],'rb') as artifact:
            for chunk in iter(lambda:artifact.read(1048576),b''):digest.update(chunk)
        if digest.hexdigest()!=expected_hash:raise RuntimeError('legacy readiness native SHA3 mismatch')
        subprocess.run(verify,check=True,capture_output=True,text=True,timeout=30)
        unit=Path('/etc/systemd/system/synergy-posy-stability.service')
        if unit.is_symlink() or not unit.is_file():raise RuntimeError('unsafe legacy unit')
        lines=unit.read_text().splitlines()
        starts=[shlex.split(v.split('=',1)[1]) for v in lines if v.startswith('ExecStart=')]
        pres=[shlex.split(v.split('=',1)[1]) for v in lines if v.startswith('ExecStartPre=')]
        if starts!=[[r['exe'],'start','--config',base+'/node.json']]:raise RuntimeError('legacy unit running binary mismatch')
        # The observed sequence 1 and 2 units predate release ExecStartPre.
        # The pinned native verifier above remains mandatory for both.
        if pres!=[verify] and not (sequence in {1,2} and not pres):raise RuntimeError('legacy unit release verifier mismatch')
        r['verified_legacy_readiness']=True
        r['legacy_readiness_release']={'sequence':sequence,'release_id':release_id,'sha3_256':expected_hash}
# Installed sequence 14 evidence is mandatory for the pure stalled preflight.
# Unknown binaries produce no evidence; a claimed seq14 path fails on any mismatch.
if r.get('exe')=='/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission':
    tools='/usr/local/libexec/synergy/posy-stability/';base='/etc/synergy/posy-stability'
    expected_hash='47340f2d40f88703c1beee3e9aa2aba9526e19a61fb959b9a2f5388183dcdd35'
    commitment='posy-r1-r2:sha3-256:66c5487be69d182733d24998b24ea5b0707674f9325a77526278d206a22bc945'
    verify=[tools+'synergy-keytool','verify-release',base+'/release-wallet-admission.json',r['exe'],
            '1266','val2-posy-consensus-v1',base+'/authority-root.pub','13']
    release=json.loads(Path(verify[2]).read_text())['release']
    if (release['sequence']!=14 or release['release_id']!='posy-stability-20261010-wallet-admission'
        or release['artifact']['sha3_256']!=expected_hash or release.get('protocol_activation_commitment')!=commitment):
        raise RuntimeError('installed sequence14 signed metadata mismatch')
    digest=hashlib.sha3_256()
    with open(r['exe'],'rb') as artifact:
        for chunk in iter(lambda:artifact.read(1048576),b''):digest.update(chunk)
    if digest.hexdigest()!=expected_hash:raise RuntimeError('installed sequence14 native hash mismatch')
    subprocess.run(verify,check=True,capture_output=True,text=True,timeout=30)
    unit=Path('/etc/systemd/system/synergy-posy-stability.service')
    if unit.is_symlink() or not unit.is_file():raise RuntimeError('unsafe installed sequence14 unit')
    lines=unit.read_text().splitlines()
    starts=[shlex.split(v.split('=',1)[1]) for v in lines if v.startswith('ExecStart=')]
    pres=[shlex.split(v.split('=',1)[1]) for v in lines if v.startswith('ExecStartPre=')]
    if starts!=[[r['exe'],'start','--config',base+'/node.json']] or pres!=[verify]:
        raise RuntimeError('installed sequence14 unit tuple mismatch')
    r['installed_release']={'sequence':14,'release_id':release['release_id'],'sha3_256':expected_hash,
        'protocol_activation_commitment':commitment,'verifier':verify,'native_verified':True,'unit_commands_verified':True}
if len(sys.argv)>1:
    q={'jsonrpc':'2.0','id':1,'method':'synergy_getBlock','params':{'height':int(sys.argv[1]),'hash':None}}
    req=urllib.request.Request('http://127.0.0.1:8545',json.dumps(q).encode(),{'Content-Type':'application/json'})
    r['block']=json.load(urllib.request.urlopen(req,timeout=10))
print(json.dumps(r))
'''
# The remote editor checks both unit directives before any mutation. It only
# accepts known canonical commands and retains every other unit line verbatim.
EDIT = r'''
import hashlib,json,os,shlex,sys
from pathlib import Path
p=Path('/etc/systemd/system/synergy-posy-stability.service')
if p.is_symlink() or not p.is_file():raise RuntimeError('unsafe unit path')
s=p.read_text();lines=s.splitlines(keepends=True)
verify=json.loads(sys.argv[1])
profiles={
 '/etc/synergy/posy-stability/release-r1-tip.json':(4,'posy-stability-20261009-r1-tip-recovery','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-tip-recovery','3'),
 '/etc/synergy/posy-stability/release-r1-performance.json':(5,'posy-stability-20261009-r1-performance','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-performance','4'),
 '/etc/synergy/posy-stability/release-r1-startup-performance.json':(6,'posy-stability-20261009-r1-startup-performance','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-startup-performance','5'),
 '/etc/synergy/posy-stability/release-r1-gap-wait.json':(7,'posy-stability-20261009-r1-gap-wait','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-gap-wait','6'),
 '/etc/synergy/posy-stability/release-r1-stable-recovery.json':(8,'posy-stability-20261009-r1-stable-recovery','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-stable-recovery','7'),
 '/etc/synergy/posy-stability/release-r1-prefetch.json':(9,'posy-stability-20261009-r1-prefetch','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-prefetch','8'),
 '/etc/synergy/posy-stability/release-r1-chunk-recovery.json':(10,'posy-stability-20261009-r1-chunk-recovery','/usr/local/libexec/synergy/posy-stability/synergy-node-r1-chunk-recovery','9'),
 '/etc/synergy/posy-stability/release-r2-lease-convergence.json':(11,'posy-stability-20261010-r2-lease-convergence','/usr/local/libexec/synergy/posy-stability/synergy-node-r2-lease-convergence','10'),
 '/etc/synergy/posy-stability/release-r2-network-drain.json':(12,'posy-stability-20261010-r2-network-drain','/usr/local/libexec/synergy/posy-stability/synergy-node-r2-network-drain','11'),
 '/etc/synergy/posy-stability/release-r2-prefetch-assembly.json':(13,'posy-stability-20261010-r2-prefetch-assembly','/usr/local/libexec/synergy/posy-stability/synergy-node-r2-prefetch-assembly','12'),
 '/etc/synergy/posy-stability/release-wallet-admission.json':(14,'posy-stability-20261010-wallet-admission','/usr/local/libexec/synergy/posy-stability/synergy-node-wallet-admission','13'),
 '/etc/synergy/posy-stability/release-r3-recovery.json':(15,'posy-stability-20261011-r3-recovery','/usr/local/libexec/synergy/posy-stability/synergy-node-r3-recovery','14'),
 '/etc/synergy/posy-stability/release-r3-retained-recovery.json':(16,'posy-stability-20261011-r3-retained-recovery','/usr/local/libexec/synergy/posy-stability/synergy-node-r3-retained-recovery','15'),
 '/etc/synergy/posy-stability/release-r3-etdag-cache.json':(17,'posy-stability-20261011-r3-etdag-cache','/usr/local/libexec/synergy/posy-stability/synergy-node-r3-etdag-cache','16'),
 '/etc/synergy/posy-stability/release-r3-rpc-isolation.json':(18,'posy-stability-20261011-r3-rpc-isolation','/usr/local/libexec/synergy/posy-stability/synergy-node-r3-rpc-isolation','17'),
 '/etc/synergy/posy-stability/release-r3-admission-cutoff.json':(19,'posy-stability-20261011-r3-admission-cutoff','/usr/local/libexec/synergy/posy-stability/synergy-node-r3-admission-cutoff','18')}
if len(verify)!=8 or verify[:2]!=['/usr/local/libexec/synergy/posy-stability/synergy-keytool','verify-release'] or verify[4:7]!=['1266','val2-posy-consensus-v1','/etc/synergy/posy-stability/authority-root.pub']:raise RuntimeError('unexpected selected release verifier')
if verify[2] not in profiles:raise RuntimeError('unsupported release profile')
sequence,release_id,binary,floor=profiles[verify[2]]
if verify[3]!=binary or verify[7]!=floor:raise RuntimeError('mismatched binary/release/floor')
release=json.loads(Path(verify[2]).read_text())['release']
if release['sequence']!=sequence or release['release_id']!=release_id:raise RuntimeError('unexpected signed release sequence/profile')
if sequence in {11,12,13,14} and release.get('protocol_activation_commitment') != 'posy-r1-r2:sha3-256:66c5487be69d182733d24998b24ea5b0707674f9325a77526278d206a22bc945':
    raise RuntimeError('R2 signed activation commitment mismatch')
if sequence in {15,16,17,18,19} and release.get('protocol_activation_commitment')!='__R3_ACTIVATION_COMMITMENT__':raise RuntimeError('R3 signed activation commitment mismatch')
if sequence in {7,8,9,10,11,12,13,14,15,16,17,18,19}:
    expected_hash={7:'094bf6917a55e9e3176335ba73c466266314650236d9c4151d5b92f49764b58d',
                   8:'2d5777eae2eee5c73db85b1ff13bab46bba2635e5084be7afc8dcef086958b8c',
                   9:'__PREFETCH_SHA3__',
                   10:'__CHUNK_RECOVERY_SHA3__',
                   11:'151d3eb37f16aeb0c018d9f02dd59f224753f5942e6056e45e4c19c12f85cd73',
                   12:'ddbabd6969e12ce0b8140ece11ff8229a9f32a9479cb153fd59830f5eb357928',
                   13:'45134dbf7064b3869c7dbaad3d30df895f3c71e4ea6eccc28ffc576dced89387',
                   14:'47340f2d40f88703c1beee3e9aa2aba9526e19a61fb959b9a2f5388183dcdd35',
                   15:'__R3_RECOVERY_SHA3__',16:'__R3_RETAINED_RECOVERY_SHA3__',17:'__R3_ETDAG_CACHE_SHA3__',18:'__R3_RPC_ISOLATION_SHA3__',19:'__R3_ADMISSION_CUTOFF_SHA3__'}[sequence]
    if len(expected_hash)!=64:raise RuntimeError('selected release hash has not been pinned')
    digest=hashlib.sha3_256()
    with open(binary,'rb') as artifact:
        for chunk in iter(lambda:artifact.read(1048576),b''):digest.update(chunk)
    if digest.hexdigest()!=expected_hash or release['artifact']['sha3_256']!=expected_hash:
        raise RuntimeError('unexpected selected release binary hash')
base='/etc/synergy/posy-stability';tools='/usr/local/libexec/synergy/posy-stability/'
allowed={'synergy-node','synergy-node-sync-repair','synergy-node-r1-recovery','synergy-node-r1-tip-recovery','synergy-node-r1-performance','synergy-node-r1-startup-performance','synergy-node-r1-gap-wait','synergy-node-r1-stable-recovery','synergy-node-r1-prefetch','synergy-node-r1-chunk-recovery','synergy-node-r2-lease-convergence','synergy-node-r2-network-drain','synergy-node-r2-prefetch-assembly','synergy-node-wallet-admission','synergy-node-r3-recovery','synergy-node-r3-retained-recovery','synergy-node-r3-etdag-cache','synergy-node-r3-rpc-isolation','synergy-node-r3-admission-cutoff'}
start=[i for i,l in enumerate(lines) if l.startswith('ExecStart=')]
pre=[i for i,l in enumerate(lines) if l.startswith('ExecStartPre=')]
if len(start)!=1 or len(pre)>1:raise RuntimeError('unexpected unit directive multiplicity')
old=shlex.split(lines[start[0]].split('=',1)[1])
if len(old)!=4 or old[0] not in {tools+n for n in allowed} or old[1:]!=['start','--config',base+'/node.json']:
    raise RuntimeError('unexpected active binary/config command')
if pre:
    oldpre=shlex.split(lines[pre[0]].split('=',1)[1])
    oldprofiles=dict(profiles)
    oldprofiles.update({base+'/release.json':(1,'posy-stability-20261009',tools+'synergy-node','0'),base+'/release-sync-repair.json':(2,'posy-stability-20261009-sync-repair',tools+'synergy-node-sync-repair','1'),base+'/release-r1.json':(3,'posy-stability-20261009-r1-recovery',tools+'synergy-node-r1-recovery','2')})
    profile=oldprofiles.get(oldpre[2]) if len(oldpre)==8 else None
    if not profile or oldpre!=[tools+'synergy-keytool','verify-release',oldpre[2],profile[2],'1266','val2-posy-consensus-v1',base+'/authority-root.pub',profile[3]] or old[0]!=profile[2]:
        raise RuntimeError('unexpected active release verifier tuple')
elif old[0] not in {tools+'synergy-node',tools+'synergy-node-sync-repair'}:
    raise RuntimeError('missing active release verifier')
newstart='ExecStart='+binary+' start --config '+base+'/node.json\n'
newpre='ExecStartPre='+shlex.join(json.loads(sys.argv[1]))+'\n'
lines[start[0]]=newstart
if pre:lines[pre[0]]=newpre
else:lines.insert(start[0],newpre)
new=''.join(lines)
print(json.dumps({'unit_commands_verified':True,'change_required':new!=s,'execute':sys.argv[2]=='execute'}))
if sys.argv[2]=='execute' and new!=s:
    fd=os.open(p,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
    with os.fdopen(fd,'w') as f:f.write(new);f.flush();os.fsync(f.fileno())
'''.replace('__PREFETCH_SHA3__', PREFETCH_SHA3 or '').replace('__CHUNK_RECOVERY_SHA3__', CHUNK_RECOVERY_SHA3).replace('__R3_RECOVERY_SHA3__', R3_RECOVERY_SHA3).replace('__R3_RETAINED_RECOVERY_SHA3__', R3_RETAINED_RECOVERY_SHA3).replace('__R3_ETDAG_CACHE_SHA3__', R3_ETDAG_CACHE_SHA3).replace('__R3_RPC_ISOLATION_SHA3__', R3_RPC_ISOLATION_SHA3).replace('__R3_ADMISSION_CUTOFF_SHA3__', R3_ADMISSION_CUTOFF_SHA3).replace('__R3_ACTIVATION_COMMITMENT__', R3_ACTIVATION_COMMITMENT)

def remote(n, args):
    return owner.remote(f'synergy-val{n}', f'/Users/jhutzler/.ssh/posy-val{n}-control', args)


def read(n, height=None):
    args = ['python3', '-c', READ] + ([] if height is None else [str(height)])
    return n, json.loads(remote(n, args))


def sample(baseline=None):
    with ThreadPoolExecutor(max_workers=5) as pool:
        states = dict(pool.map(read, range(2, 7)))
    if baseline:
        for n, state in states.items():
            if int(state['service']['NRestarts']) > baseline[n]:
                raise RuntimeError(f'Val{n} automatic restart count increased; rollout stopped')
    for state in states.values():
        if state['service']['ActiveState'] != 'active' or state['service']['SubState'] != 'running':
            return None, states
        readiness = state.get('readiness') or {}
        if not state.get('commitment') or not readiness.get('ok') or not (readiness.get('result', {}).get('ready') is True or state.get('verified_legacy_readiness') is True):
            return None, states
        health = state.get('health') or {}
        services = health.get('result', {}).get('services', [])
        if not health.get('ok') or not services or any(s['health'] != 'healthy' for s in services):
            return None, states
    heights = [s['commitment']['finalized_height'] for s in states.values()]
    if min(heights) < 1 or max(heights) - min(heights) > 2:
        return None, states
    height = min(heights)
    with ThreadPoolExecutor(max_workers=5) as pool:
        proofs = dict(pool.map(lambda n: read(n, height), range(2, 7)))
    blocks = [p.get('block', {}).get('result') for p in proofs.values()]
    if any(block is None for block in blocks):
        return None, states
    if any(block != blocks[0] for block in blocks[1:]):
        raise RuntimeError('canonical finalized RPC mismatch; rollout stopped')
    for n, state in states.items():
        if state['commitment']['finalized_height'] == height:
            if state['commitment']['finalized_block_id'] != blocks[0]['block_hash'] or state['commitment']['state_root'] != blocks[0]['state_root']:
                raise RuntimeError(f'Val{n} durable/RPC commitment mismatch')
    return height, states


def validate_stalled_fleet_preflight(previous, current):
    """Pure evidence check only; never authorizes activation or replaces advancement.

    Both snapshots must contain the five validators and exact RPC block proofs.
    installed_release evidence must be produced by an independently verified
    native release/unit probe. The READ probe produces that evidence only for the exact installed
    sequence-14 profile; absent evidence fails closed here.
    """
    expected = {
        'sequence': 14,
        'release_id': 'posy-stability-20261010-wallet-admission',
        'sha3_256': '47340f2d40f88703c1beee3e9aa2aba9526e19a61fb959b9a2f5388183dcdd35',
        'protocol_activation_commitment': 'posy-r1-r2:sha3-256:66c5487be69d182733d24998b24ea5b0707674f9325a77526278d206a22bc945',
        'verifier': [TOOLS+'synergy-keytool', 'verify-release', BASE+'/release-wallet-admission.json',
                     TOOLS+'synergy-node-wallet-admission', '1266', 'val2-posy-consensus-v1',
                     BASE+'/authority-root.pub', '13'],
        'native_verified': True, 'unit_commands_verified': True,
    }
    tip = None
    counters = {}
    for label, snapshot in [('previous', previous), ('current', current)]:
        if set(snapshot) != set(range(2, 7)):
            raise RuntimeError(label+': missing or extra validator evidence')
        for n, state in snapshot.items():
            try:
                service = state['service']
                if service['ActiveState'] != 'active' or service['SubState'] != 'running' or int(service['MainPID']) <= 0:
                    raise ValueError('service inactive')
                count = int(service['NRestarts'])
                if count < 0 or (label == 'current' and count != counters[n]):
                    raise ValueError('restart counter unstable')
                counters[n] = count
                health = state['health']
                services = health['result']['services']
                if health['ok'] is not True or not services or any(
                        v['state'] != 'running' or v['health'] != 'healthy'
                        or v['readiness']['status'] != 'ready' for v in services):
                    raise ValueError('services not healthy and ready')
                if state['readiness']['ok'] is not True or state['readiness']['result']['ready'] is not True:
                    raise ValueError('native readiness missing')
                if state['exe'] != expected['verifier'][3] or state['installed_release'] != expected:
                    raise ValueError('installed signed release evidence missing or mismatched')
                durable = state['commitment']
                height = durable['finalized_height']
                block = state['block']['result']
                if isinstance(height, bool) or not isinstance(height, int) or height < 1 or not block:
                    raise ValueError('missing finalized proof')
                identity = (height, durable['finalized_block_id'], durable['state_root'])
                if any(not isinstance(v, str) or len(v) != 64 or any(c not in '0123456789abcdef' for c in v) for v in identity[1:]):
                    raise ValueError('invalid commitment digest')
                if (block['height'], block['block_hash'], block['state_root']) != identity:
                    raise ValueError('durable/RPC mismatch')
                if tip is None:
                    tip = identity
                elif tip != identity:
                    raise ValueError('fleet not at same stable tip')
            except (KeyError, TypeError, ValueError) as error:
                raise RuntimeError(f'{label} Val{n}: invalid or missing preflight evidence: {error}') from error
    return {'preflight_evidence_validated': True, 'finalized_height': tip[0],
            'block_hash': tip[1], 'state_root': tip[2],
            'activation_authorized': False, 'chain_running_verified': False}


def wait_advancing(label, baseline, timeout):
    deadline = time.monotonic() + timeout
    initial = None
    while time.monotonic() < deadline:
        height, states = sample(baseline)
        if height is not None:
            if initial is None:
                initial = height
            elif height > initial:
                print(json.dumps({'event':'matching_advancing_fleet','label':label,'height':height,'verified_legacy_validators':[n for n,s in states.items() if s.get('verified_legacy_readiness') is True]}), flush=True)
                return states
        time.sleep(10)
    raise RuntimeError(f'{label}: fleet did not regain matching advancing durable finality; no further update')


def require_chunk_compatible_fleet(states):
    """V2 requests terminate old Sync decoders; a mixed rolling upgrade is unsafe."""
    expected = TOOLS + 'synergy-node-r1-chunk-recovery'
    incompatible = [n for n in range(2, 7) if states.get(n, {}).get('exe') != expected]
    if incompatible:
        raise RuntimeError('sequence 10 cannot roll across mixed V2/legacy validators; '
                           f'Val{incompatible} require a separately coordinated stop/start; no mutations')


def self_test():
    compile(READ, 'remote fleet reader', 'exec')
    compile(EDIT, 'remote unit guard', 'exec')
    """Exercise the actual remote probe with mocked I/O; never connect to a host."""
    import copy
    import io
    import subprocess
    import sys
    from contextlib import ExitStack, redirect_stdout
    from types import SimpleNamespace
    from unittest.mock import patch

    expected_hash = '094bf6917a55e9e3176335ba73c466266314650236d9c4151d5b92f49764b58d'
    binary = TOOLS + 'synergy-node-r1-gap-wait'
    verifier = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-gap-wait.json',
                binary,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','6']
    default = {
        'exe': binary,
        'health': {'ok': True, 'result': {'services': [
            {'state': 'running', 'health': 'healthy', 'readiness': {'status': 'ready'}}]}},
        'readiness': {'ok': True, 'result': {'ready': False}},
        'status': {'ok': True, 'result': {'lifecycle': 'shadowing', 'chain_id': 1266,
                                       'role': 'validator'}},
        'release': {'sequence': 7, 'release_id': 'posy-stability-20261009-r1-gap-wait',
                    'artifact': {'sha3_256': expected_hash}},
        'unit': 'ExecStart='+shlex.join([binary,'start','--config',BASE+'/node.json'])+'\n'
                +'ExecStartPre='+shlex.join(verifier)+'\n',
        'hash': expected_hash,
        'verify_fails': False,
        'symlink': False,
    }

    def probe(fixture):
        verified = []
        fixture_verifier = fixture.get('verifier', verifier)

        def run(argv, **kwargs):
            if argv[0] == TOOLS+'synergy-keytool':
                assert argv == fixture_verifier, 'native verifier lost its pinned trust arguments'
                verified.append(argv)
                if fixture['verify_fails']:
                    raise subprocess.CalledProcessError(1, argv)
                return SimpleNamespace(returncode=0, stdout='verified')
            return SimpleNamespace(returncode=0, stdout=json.dumps(fixture[argv[1]]))

        def read_text(path, **kwargs):
            if str(path) == '/etc/synergy/posy-stability/node.json':
                return json.dumps({'storage': {'data_directory': '/var/lib/synergy/posy-stability/data'}})
            if str(path) == UNIT:
                return fixture['unit']
            if str(path) == fixture_verifier[2]:
                return json.dumps({'release': fixture['release']})
            if str(path).endswith('/state/execution/finalized-state.json'):
                return json.dumps({'state': {'finalized_height': 100}})
            raise AssertionError('unexpected read '+str(path))

        class Digest:
            def update(self, value):
                pass

            def hexdigest(self):
                return fixture['hash']

        with ExitStack() as stack:
            stack.enter_context(patch('subprocess.check_output', return_value=
                b'ActiveState=active\nSubState=running\nMainPID=123\nNRestarts=0\n'))
            stack.enter_context(patch('subprocess.run', side_effect=run))
            stack.enter_context(patch('os.readlink', return_value=fixture['exe']))
            stack.enter_context(patch.object(Path, 'is_file', return_value=True))
            stack.enter_context(patch.object(Path, 'is_symlink', return_value=fixture['symlink']))
            stack.enter_context(patch.object(Path, 'read_text', read_text))
            stack.enter_context(patch('builtins.open', side_effect=lambda *a, **k: io.BytesIO(b'artifact')))
            stack.enter_context(patch('hashlib.sha3_256', Digest))
            stack.enter_context(patch.object(sys, 'argv', ['probe']))
            output = stack.enter_context(redirect_stdout(io.StringIO()))
            exec(compile(READ, '<remote-readiness-probe>', 'exec'), {})
        return json.loads(output.getvalue()), verified

    result, verified = probe(copy.deepcopy(default))
    assert result['verified_legacy_readiness'] is True and len(verified) == 1
    historical_missing_pre = [
        ('synergy-node', 'release.json', 1, 'posy-stability-20261009',
         '9c134ccd45121ec017113c4266e2ee86da5a2a41a6592a48e21e6713d7cb5437'),
        ('synergy-node-sync-repair', 'release-sync-repair.json', 2,
         'posy-stability-20261009-sync-repair',
         '6b2a03d0952305cef5b3bff54797e57227a2235e1d4d40e163453ca937cefc12'),
        ('synergy-node-r1-recovery', 'release-r1.json', 3,
         'posy-stability-20261009-r1-recovery',
         '6be74abde046d419093684589a9ca427368edb2855eb20781bb9696d283bf4fd'),
    ]
    for executable, metadata, sequence, release_id, digest in historical_missing_pre:
        fixture = copy.deepcopy(default)
        fixture['exe'] = TOOLS+executable
        fixture['hash'] = digest
        fixture['release'] = {'sequence': sequence, 'release_id': release_id,
                              'artifact': {'sha3_256': digest}}
        fixture['verifier'] = [TOOLS+'synergy-keytool', 'verify-release', BASE+'/'+metadata,
                               fixture['exe'], '1266', 'val2-posy-consensus-v1',
                               BASE+'/authority-root.pub', str(sequence-1)]
        fixture['unit'] = 'ExecStart='+shlex.join([fixture['exe'],'start','--config',BASE+'/node.json'])+'\n'
        try:
            result, verified = probe(fixture)
        except RuntimeError:
            assert sequence >= 3, 'observed legacy sequence wrongly rejected'
            continue
        assert sequence <= 2 and result['verified_legacy_readiness'] is True and len(verified) == 1
    cases = [
        ('corrected sequence 8', ('exe',), TOOLS+'synergy-node-r1-stable-recovery'),
        ('corrected sequence 9', ('exe',), TOOLS+'synergy-node-r1-prefetch'),
        ('noncanonical executable', ('exe',), '/tmp/synergy-node-r1-gap-wait'),
        ('native readiness true', ('readiness','result','ready'), True),
        ('readiness RPC failed', ('readiness','ok'), False),
        ('health RPC failed', ('health','ok'), False),
        ('empty services', ('health','result','services'), []),
        ('service not running', ('health','result','services',0,'state'), 'stopped'),
        ('service unhealthy', ('health','result','services',0,'health'), 'degraded'),
        ('service catch-up pending', ('health','result','services',0,'readiness','status'), 'pending'),
        ('status RPC failed', ('status','ok'), False),
        ('wrong lifecycle', ('status','result','lifecycle'), 'recovering'),
        ('wrong chain', ('status','result','chain_id'), 1267),
        ('wrong role', ('status','result','role'), 'observer'),
        ('wrong signed sequence', ('release','sequence'), 8),
        ('wrong signed release ID', ('release','release_id'), 'different'),
        ('wrong signed artifact hash', ('release','artifact','sha3_256'), '0'*64),
        ('wrong native hash', ('hash',), '0'*64),
        ('native verification fails', ('verify_fails',), True),
        ('unit symlink', ('symlink',), True),
        ('wrong unit executable', ('unit',), default['unit'].replace('ExecStart='+binary,
                                                                    'ExecStart='+TOOLS+'synergy-node')),
        ('wrong unit config', ('unit',), default['unit'].replace('--config '+BASE+'/node.json',
                                                                '--config /tmp/node.json')),
        ('missing unit verifier', ('unit',), default['unit'].split('ExecStartPre=')[0]),
        ('wrong unit verifier floor', ('unit',), default['unit'].replace('authority-root.pub 6',
                                                                       'authority-root.pub 0')),
    ]
    for name, keys, value in cases:
        fixture = copy.deepcopy(default)
        container = fixture
        for key in keys[:-1]:
            container = container[key]
        container[keys[-1]] = value
        try:
            result, _ = probe(fixture)
        except (RuntimeError, subprocess.CalledProcessError):
            continue
        assert result['verified_legacy_readiness'] is False, name+' incorrectly allowed bridge'
    compatible = {n: {'exe': TOOLS+'synergy-node-r1-chunk-recovery'} for n in range(2, 7)}
    require_chunk_compatible_fleet(compatible)
    for n in range(2, 7):
        for old in [TOOLS+'synergy-node-r1-prefetch', None]:
            mixed = copy.deepcopy(compatible)
            mixed[n]['exe'] = old
            try:
                require_chunk_compatible_fleet(mixed)
            except RuntimeError:
                continue
            raise AssertionError('mixed-version chunk rollout was allowed')
    target_binary = TOOLS+'synergy-node-r3-recovery'
    target_verify = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-recovery.json',target_binary,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','14']
    old_binary = TOOLS+'synergy-node-wallet-admission'
    old_verify = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-wallet-admission.json',old_binary,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','13']
    edit_default = {'verify':target_verify, 'unit':'[Service]\nExecStart='+shlex.join([old_binary,'start','--config',BASE+'/node.json'])+'\nExecStartPre='+shlex.join(old_verify)+'\n', 'release':{'sequence':15,'release_id':'posy-stability-20261011-r3-recovery','artifact':{'sha3_256':R3_RECOVERY_SHA3},'protocol_activation_commitment':R3_ACTIVATION_COMMITMENT}, 'hash':R3_RECOVERY_SHA3}
    def edit_probe(fixture):
        class Digest:
            def update(self,value):pass
            def hexdigest(self):return fixture['hash']
        def text(path,**kwargs):
            if str(path)==UNIT:return fixture['unit']
            if str(path)==fixture['verify'][2]:return json.dumps({'release':fixture['release']})
            raise AssertionError('unexpected edit read '+str(path))
        with ExitStack() as stack:
            stack.enter_context(patch.object(Path,'is_file',return_value=True))
            stack.enter_context(patch.object(Path,'is_symlink',return_value=False))
            stack.enter_context(patch.object(Path,'read_text',text))
            stack.enter_context(patch('builtins.open',side_effect=lambda *a,**k:io.BytesIO(b'artifact')))
            stack.enter_context(patch('hashlib.sha3_256',Digest))
            stack.enter_context(patch('os.open',side_effect=AssertionError('preflight attempted mutation')))
            stack.enter_context(patch.object(sys,'argv',['edit',json.dumps(fixture['verify']),'preflight']))
            output=stack.enter_context(redirect_stdout(io.StringIO()))
            exec(compile(fixture.get('edit_code',EDIT),'<remote-unit-edit>','exec'),{})
        return json.loads(output.getvalue())
    assert edit_probe(copy.deepcopy(edit_default))['change_required'] is True
    same=copy.deepcopy(edit_default)
    same['unit']='ExecStart='+shlex.join([target_binary,'start','--config',BASE+'/node.json'])+'\nExecStartPre='+shlex.join(target_verify)+'\n'
    assert edit_probe(same)['change_required'] is False
    import re
    seq17=copy.deepcopy(edit_default)
    seq17['verify']=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-etdag-cache.json',TOOLS+'synergy-node-r3-etdag-cache','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','16']
    retained_verify=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-retained-recovery.json',TOOLS+'synergy-node-r3-retained-recovery','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','15']
    seq17['unit']='ExecStart='+shlex.join([retained_verify[3],'start','--config',BASE+'/node.json'])+'\nExecStartPre='+shlex.join(retained_verify)+'\n'
    seq17['release']=dict(seq17['release'],sequence=17,release_id='posy-stability-20261011-r3-etdag-cache',artifact={'sha3_256':'a'*64})
    seq17['hash']='a'*64
    # Test the exact new tuple using a mock artifact pin; production remains unpinned.
    seq17['edit_code']=re.sub(r"17:'[0-9a-f]*'", "17:"+repr('a'*64), EDIT)
    assert edit_probe(seq17)['change_required'] is True
    for oldfloor in ['14','16']:
        bad=copy.deepcopy(seq17);bad['unit']=bad['unit'].replace('authority-root.pub 15','authority-root.pub '+oldfloor)
        try:edit_probe(bad)
        except RuntimeError:pass
        else:raise AssertionError('wrong installed sequence16 floor accepted')
    bad=copy.deepcopy(seq17);bad['verify'][7]='15'
    try:edit_probe(bad)
    except RuntimeError:pass
    else:raise AssertionError('wrong target sequence17 floor accepted')
    seq18=copy.deepcopy(edit_default)
    seq18['verify']=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-rpc-isolation.json',TOOLS+'synergy-node-r3-rpc-isolation','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','17']
    retained_verify=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-etdag-cache.json',TOOLS+'synergy-node-r3-etdag-cache','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','16']
    seq18['unit']='ExecStart='+shlex.join([retained_verify[3],'start','--config',BASE+'/node.json'])+'\nExecStartPre='+shlex.join(retained_verify)+'\n'
    seq18['release']=dict(seq18['release'],sequence=18,release_id='posy-stability-20261011-r3-rpc-isolation',artifact={'sha3_256':'a'*64})
    seq18['hash']='a'*64
    # Test the exact new tuple using a mock artifact pin; production remains unpinned.
    seq18['edit_code']=re.sub(r"18:'[0-9a-f]*'", "18:"+repr('a'*64), EDIT)
    assert edit_probe(seq18)['change_required'] is True
    for oldfloor in ['15','17']:
        bad=copy.deepcopy(seq18);bad['unit']=bad['unit'].replace('authority-root.pub 16','authority-root.pub '+oldfloor)
        try:edit_probe(bad)
        except RuntimeError:pass
        else:raise AssertionError('wrong installed sequence17 floor accepted')
    bad=copy.deepcopy(seq18);bad['verify'][7]='16'
    try:edit_probe(bad)
    except RuntimeError:pass
    else:raise AssertionError('wrong target sequence18 floor accepted')
    seq19=copy.deepcopy(edit_default)
    seq19['verify']=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-admission-cutoff.json',TOOLS+'synergy-node-r3-admission-cutoff','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','18']
    installed18=[TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-rpc-isolation.json',TOOLS+'synergy-node-r3-rpc-isolation','1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','17']
    seq19['unit']='ExecStart='+shlex.join([installed18[3],'start','--config',BASE+'/node.json'])+'\nExecStartPre='+shlex.join(installed18)+'\n'
    seq19['release']=dict(seq19['release'],sequence=19,release_id='posy-stability-20261011-r3-admission-cutoff',artifact={'sha3_256':'a'*64})
    seq19['hash']='a'*64
    seq19['edit_code']=re.sub(r"19:'[0-9a-f]*'", "19:"+repr('a'*64), EDIT)
    assert edit_probe(seq19)['change_required'] is True
    for oldfloor in ['16','18']:
        bad=copy.deepcopy(seq19);bad['unit']=bad['unit'].replace('authority-root.pub 17','authority-root.pub '+oldfloor)
        try:edit_probe(bad)
        except RuntimeError:pass
        else:raise AssertionError('wrong installed sequence18 floor accepted')
    for newfloor in ['17','19']:
        bad=copy.deepcopy(seq19);bad['verify'][7]=newfloor
        try:edit_probe(bad)
        except RuntimeError:pass
        else:raise AssertionError('wrong target sequence19 floor accepted')
    print('SEQ19_EDIT_SELF_TEST_PASSED: exact 18-to-19 transition and four wrong-floor negatives; no mutations')
    negatives=[]
    for label,old_index,value in [('floor',7,'12'),('release',2,BASE+'/release-r2-prefetch-assembly.json'),('binary',3,TOOLS+'synergy-node-r2-prefetch-assembly')]:
        f=copy.deepcopy(edit_default);v=old_verify.copy();v[old_index]=value
        f['unit']=f['unit'].replace(shlex.join(old_verify),shlex.join(v));negatives.append((label,f))
    for field,value in [('sequence',14),('release_id','other'),('protocol_activation_commitment','other')]:
        f=copy.deepcopy(edit_default);f['release'][field]=value;negatives.append((field,f))
    f=copy.deepcopy(edit_default);f['hash']='0'*64;negatives.append(('native hash',f))
    f=copy.deepcopy(edit_default);f['release']['artifact']['sha3_256']='0'*64;negatives.append(('metadata hash',f))
    f=copy.deepcopy(edit_default);f['verify'][7]='13';negatives.append(('target floor',f))
    f=copy.deepcopy(edit_default);f['verify'][4]='1267';negatives.append(('target chain',f))
    for label,f in negatives:
        try:edit_probe(f)
        except RuntimeError:continue
        raise AssertionError(label+' wrongly accepted by EDIT')
    print(f'R3_EDIT_SELF_TEST_PASSED: 2 positive and {len(negatives)} negative cases; no host access or mutations')
    installed = {'sequence':14, 'release_id':'posy-stability-20261010-wallet-admission',
                 'sha3_256':'47340f2d40f88703c1beee3e9aa2aba9526e19a61fb959b9a2f5388183dcdd35',
                 'protocol_activation_commitment':'posy-r1-r2:sha3-256:66c5487be69d182733d24998b24ea5b0707674f9325a77526278d206a22bc945',
                 'verifier':old_verify, 'native_verified':True, 'unit_commands_verified':True}
    seq14_fixture=copy.deepcopy(default)
    seq14_fixture.update({'exe':old_binary,'verifier':old_verify,'hash':installed['sha3_256'],
                          'release':{k:installed[k] for k in ['sequence','release_id','protocol_activation_commitment']},
                          'unit':edit_default['unit']})
    seq14_fixture['release']['artifact']={'sha3_256':installed['sha3_256']}
    evidence,verified=probe(seq14_fixture)
    assert evidence['installed_release']==installed and len(verified)==1
    seq14_bad=[]
    for key,value in [('hash','0'*64),('verify_fails',True),('symlink',True),
                      ('unit',edit_default['unit'].replace('authority-root.pub 13','authority-root.pub 12'))]:
        f=copy.deepcopy(seq14_fixture);f[key]=value;seq14_bad.append(f)
    f=copy.deepcopy(seq14_fixture);f['unit']=f['unit'].replace('ExecStart='+old_binary,'ExecStart='+TOOLS+'synergy-node-r2-prefetch-assembly');seq14_bad.append(f)
    f=copy.deepcopy(seq14_fixture);f['release']['artifact']['sha3_256']='0'*64;seq14_bad.append(f)
    f=copy.deepcopy(seq14_fixture);f['release']['protocol_activation_commitment']='wrong';seq14_bad.append(f)
    for f in seq14_bad:
        try:probe(f)
        except (RuntimeError,subprocess.CalledProcessError):continue
        raise AssertionError('invalid installed seq14 evidence accepted')
    unknown=copy.deepcopy(seq14_fixture);unknown['exe']='/tmp/synergy-node-wallet-admission'
    evidence,verified=probe(unknown)
    assert 'installed_release' not in evidence and not verified
    print('INSTALLED_SEQ14_SELF_TEST_PASSED: 1 positive and 8 negative cases; no host access')
    stalled_state = {'service':{'ActiveState':'active','SubState':'running','MainPID':'12','NRestarts':'0'},
                     'health':default['health'], 'readiness':{'ok':True,'result':{'ready':True}},
                     'exe':old_binary, 'installed_release':installed,
                     'commitment':{'finalized_height':47,'finalized_block_id':'a'*64,'state_root':'b'*64},
                     'block':{'result':{'height':47,'block_hash':'a'*64,'state_root':'b'*64}}}
    fleet = {n:copy.deepcopy(stalled_state) for n in range(2,7)}
    assert validate_stalled_fleet_preflight(fleet,copy.deepcopy(fleet))['activation_authorized'] is False
    bad_fields = [('service','NRestarts','1'), ('service','MainPID','0'),
                  ('readiness','ok',False), ('installed_release','native_verified',False),
                  ('installed_release','unit_commands_verified',False), ('installed_release','sequence',15),
                  ('commitment','finalized_height',48), ('block','result',None)]
    for a,b,value in bad_fields:
        bad=copy.deepcopy(fleet);bad[2][a][b]=value
        try:validate_stalled_fleet_preflight(fleet,bad)
        except RuntimeError:continue
        raise AssertionError('stalled preflight accepted '+a+'.'+b)
    bad=copy.deepcopy(fleet);del bad[6]
    try:validate_stalled_fleet_preflight(fleet,bad)
    except RuntimeError:pass
    else:raise AssertionError('missing validator accepted')
    bad=copy.deepcopy(fleet);del bad[2]['installed_release']
    try:validate_stalled_fleet_preflight(fleet,bad)
    except RuntimeError:pass
    else:raise AssertionError('missing signed evidence accepted')
    print('STALLED_PREFLIGHT_SELF_TEST_PASSED: 1 positive and 10 negative cases; pure evidence only')
    print('CHUNK_COMPATIBILITY_SELF_TEST_PASSED: 1 positive and 10 negative cases; no host access')
    print(f'READINESS_BRIDGE_SELF_TEST_PASSED: 3 positive and {len(cases)+1} negative cases; no host access')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    global BINARY, VERIFY
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--self-test', action='store_true', help='mocked readiness guards only; no host access')
    parser.add_argument('--release', choices=['r1-tip','r1-performance','r1-startup-performance','r1-gap-wait','r1-stable-recovery','r1-prefetch','r1-chunk-recovery','r2-lease-convergence','r2-network-drain','r2-prefetch-assembly','r3-recovery','r3-retained-recovery','r3-etdag-cache','r3-rpc-isolation','r3-admission-cutoff'], default='r1-tip')
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    if args.self_test:
        if args.execute:
            parser.error('--self-test cannot be combined with --execute')
        self_test()
        return
    if args.release == 'r1-performance':
        BINARY = TOOLS + 'synergy-node-r1-performance'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-performance.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','4']
    elif args.release == 'r1-startup-performance':
        BINARY = TOOLS + 'synergy-node-r1-startup-performance'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-startup-performance.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','5']
    elif args.release == 'r1-gap-wait':
        BINARY = TOOLS + 'synergy-node-r1-gap-wait'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-gap-wait.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','6']
    elif args.release == 'r1-stable-recovery':
        BINARY = TOOLS + 'synergy-node-r1-stable-recovery'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-stable-recovery.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','7']
    elif args.release == 'r1-prefetch':
        if PREFETCH_SHA3 is None:
            parser.error('sequence 9 release hash has not been pinned; no host access attempted')
        BINARY = TOOLS + 'synergy-node-r1-prefetch'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-prefetch.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','8']
    elif args.release == 'r1-chunk-recovery':
        BINARY = TOOLS + 'synergy-node-r1-chunk-recovery'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r1-chunk-recovery.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','9']
    elif args.release == 'r2-lease-convergence':
        BINARY = TOOLS + 'synergy-node-r2-lease-convergence'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r2-lease-convergence.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','10']
    elif args.release == 'r2-network-drain':
        BINARY = TOOLS + 'synergy-node-r2-network-drain'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r2-network-drain.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','11']
    elif args.release == 'r2-prefetch-assembly':
        BINARY = TOOLS + 'synergy-node-r2-prefetch-assembly'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r2-prefetch-assembly.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','12']
    elif args.release == 'r3-recovery':
        BINARY = TOOLS + 'synergy-node-r3-recovery'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-recovery.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','14']
    elif args.release == 'r3-retained-recovery':
        if len(R3_RETAINED_RECOVERY_SHA3)!=64:parser.error('sequence 16 hash unpinned; no host access attempted')
        BINARY = TOOLS + 'synergy-node-r3-retained-recovery'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-retained-recovery.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','15']
    elif args.release == 'r3-etdag-cache':
        if len(R3_ETDAG_CACHE_SHA3)!=64:parser.error('sequence17 hash unpinned; no host access attempted')
        BINARY = TOOLS + 'synergy-node-r3-etdag-cache'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-etdag-cache.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','16']
    elif args.release == 'r3-rpc-isolation':
        if len(R3_RPC_ISOLATION_SHA3)!=64:parser.error('sequence18 hash unpinned; no host access attempted')
        BINARY = TOOLS + 'synergy-node-r3-rpc-isolation'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-rpc-isolation.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','17']
    elif args.release == 'r3-admission-cutoff':
        if len(R3_ADMISSION_CUTOFF_SHA3)!=64:parser.error('sequence19 hash unpinned; no host access attempted')
        BINARY = TOOLS + 'synergy-node-r3-admission-cutoff'
        VERIFY = [TOOLS+'synergy-keytool','verify-release',BASE+'/release-r3-admission-cutoff.json',
                  BINARY,'1266','val2-posy-consensus-v1',BASE+'/authority-root.pub','18']
    if args.timeout < 60 or args.timeout > 1800:
        parser.error('timeout must be 60..1800 seconds')
    _, observed = sample()
    if args.execute and args.release == 'r1-chunk-recovery':
        require_chunk_compatible_fleet(observed)
    baseline = {n:int(s['service']['NRestarts']) for n,s in observed.items()}
    ready = wait_advancing('initial all-five gate', baseline, args.timeout)
    if ready[5].get('exe') != BINARY:
        raise RuntimeError('Val5 must already run the verified selected-release binary')
    remote(5, VERIFY)
    val5_unit = json.loads(remote(5, ['python3','-c',EDIT,json.dumps(VERIFY),'preflight']))
    if val5_unit['change_required']:
        raise RuntimeError('Val5 unit must already bind the verified selected release')
    for n in ORDER:
        remote(n, VERIFY)
        remote(n, ['python3','-c',EDIT,json.dumps(VERIFY),'preflight'])
    if not args.execute:
        print('R1_RELEASE_PREFLIGHT_PASSED_NO_MUTATIONS', flush=True)
        return
    for n in ORDER:
        states = wait_advancing(f'before Val{n}', baseline, args.timeout)
        if args.release == 'r1-chunk-recovery':
            require_chunk_compatible_fleet(states)
        remote(n, VERIFY)
        unit = json.loads(remote(n, ['python3','-c',EDIT,json.dumps(VERIFY),'preflight']))
        if not unit['change_required'] and states[n].get('exe') == BINARY:
            print(json.dumps({'event':'verified_selected_release_already_running','validator':n}), flush=True)
            continue
        remote(n, ['python3','-c',EDIT,json.dumps(VERIFY),'execute'])
        remote(n, ['systemd-analyze','verify',UNIT])
        remote(n, ['systemctl','daemon-reload'])
        remote(n, ['systemctl','restart',SERVICE])
        # Explicit starts reset systemd's per-invocation auto-restart counter.
        # The new invocation must perform zero automatic retries.
        baseline[n] = 0
        states = wait_advancing(f'after Val{n}', baseline, args.timeout)
        if states[n].get('exe') != BINARY:
            raise RuntimeError(f'Val{n} running executable differs from verified selected-release binary')
    print('R1_RELEASE_ROLLING_UPDATE_COMPLETE', flush=True)

if __name__ == '__main__':
    main()
