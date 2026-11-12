#!/usr/bin/env python3
"""Stage immutable R3 files only; default validates locally without host access."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
OUT = ROOT / 'networks/testnet/posy-stability'
BINARY = '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-recovery'
RELEASE = '/etc/synergy/posy-stability/release-r3-recovery.json'
PROFILES = {'r3-recovery': (15, 'posy-stability-20261011-r3-recovery'),
            'r3-retained-recovery': (16, 'posy-stability-20261011-r3-retained-recovery'),
            'r3-etdag-cache': (17, 'posy-stability-20261011-r3-etdag-cache'),
            'r3-rpc-isolation': (18, 'posy-stability-20261011-r3-rpc-isolation'),
            'r3-admission-cutoff': (19, 'posy-stability-20261011-r3-admission-cutoff')}
COMMITMENT = 'posy-r1-r2-r3:sha3-256:233f4634a74497ee88ebf267eb6d89604a864c25f891741943baf69e7c057989'
RECEIVER = r'''
import hashlib,os,stat,sys
from pathlib import Path
allowed={'/usr/local/libexec/synergy/posy-stability/synergy-node-r3-recovery':0o755,
         '/etc/synergy/posy-stability/release-r3-recovery.json':0o644,
         '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-retained-recovery':0o755,
         '/etc/synergy/posy-stability/release-r3-retained-recovery.json':0o644,
         '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-etdag-cache':0o755,
         '/etc/synergy/posy-stability/release-r3-etdag-cache.json':0o644,
         '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-rpc-isolation':0o755,
         '/etc/synergy/posy-stability/release-r3-rpc-isolation.json':0o644,
         '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-admission-cutoff':0o755,
         '/etc/synergy/posy-stability/release-r3-admission-cutoff.json':0o644}
p=Path(sys.argv[1])
if str(p) not in allowed:raise RuntimeError('unapproved staging path')
for parent in p.parents:
 if parent.is_symlink() or not parent.is_dir():raise RuntimeError('unsafe staging parent')
length=int(sys.argv[2])
if length<1 or length>16777216:raise RuntimeError('invalid staging length')
data=sys.stdin.buffer.read(length+1)
if len(data)!=length or hashlib.sha3_256(data).hexdigest()!=sys.argv[3]:raise RuntimeError('staging bytes mismatch')
mode=allowed[str(p)]
if p.exists() or p.is_symlink():
 if p.is_symlink() or not p.is_file():raise RuntimeError('unsafe existing staging target')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  if f.read(length+1)!=data or stat.S_IMODE(os.fstat(f.fileno()).st_mode)!=mode:raise RuntimeError('existing staging target differs')
else:
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 with os.fdopen(fd,'wb') as f:
  os.fchmod(f.fileno(),mode);f.write(data);f.flush();os.fsync(f.fileno())
print('IMMUTABLE_FILE_STAGED')
'''

def validate(binary, metadata, profile='r3-recovery'):
    sequence, release_id = PROFILES[profile]
    if not binary.startswith(b'\x7fELF\x02\x01') or int.from_bytes(binary[18:20], 'little') != 62:
        raise RuntimeError('candidate must be ELF64 little-endian x86_64')
    if metadata.get('sequence') != sequence or metadata.get('release_id') != release_id or metadata.get('protocol_activation_commitment') != COMMITMENT:
        raise RuntimeError('unexpected R3 release identity/commitment')
    artifact = metadata['artifact']
    if artifact['platform'] != 'x86_64-unknown-linux-gnu' or artifact['length'] != len(binary) or artifact['sha3_256'] != hashlib.sha3_256(binary).hexdigest():
        raise RuntimeError('candidate differs from unsigned artifact metadata')


def self_test():
    import io
    import tempfile
    import sys
    from contextlib import redirect_stdout
    from unittest.mock import patch
    binary=b'\x7fELF\x02\x01'+b'\0'*12+b'\x3e\0'+b'test'
    metadata={'sequence':15,'release_id':'posy-stability-20261011-r3-recovery','protocol_activation_commitment':COMMITMENT,
              'artifact':{'platform':'x86_64-unknown-linux-gnu','length':len(binary),'sha3_256':hashlib.sha3_256(binary).hexdigest()}}
    validate(binary,metadata)
    retained=dict(metadata,sequence=16,release_id=PROFILES['r3-retained-recovery'][1])
    validate(binary,retained,'r3-retained-recovery')
    cached=dict(metadata,sequence=17,release_id=PROFILES['r3-etdag-cache'][1])
    validate(binary,cached,'r3-etdag-cache')
    isolated=dict(metadata,sequence=18,release_id=PROFILES['r3-rpc-isolation'][1])
    validate(binary,isolated,'r3-rpc-isolation')
    cutoff=dict(metadata,sequence=19,release_id=PROFILES['r3-admission-cutoff'][1])
    validate(binary,cutoff,'r3-admission-cutoff')
    try:validate(binary,cached,'r3-retained-recovery')
    except RuntimeError:pass
    else:raise AssertionError('sequence17 cross-profile metadata accepted')
    try:validate(binary,retained)
    except RuntimeError:pass
    else:raise AssertionError('cross-profile metadata accepted')
    try:validate(binary+b'changed',metadata)
    except RuntimeError:pass
    else:raise AssertionError('wrong hash accepted')
    with tempfile.TemporaryDirectory() as directory:
        target=str(Path(directory).resolve()/'artifact')
        code=RECEIVER.replace(repr(BINARY),repr(target))
        def receive(path,data):
            with patch.object(sys,'argv',['receiver',path,str(len(data)),hashlib.sha3_256(data).hexdigest()]),patch.object(sys,'stdin',type('Input',(),{'buffer':io.BytesIO(data)})()),redirect_stdout(io.StringIO()):
                exec(compile(code,'<immutable-receiver>','exec'),{})
        receive(target,binary);receive(target,binary)
        for path,data in [(target,b'changed'),(str(Path(directory)/'wrong'),binary)]:
            try:receive(path,data)
            except RuntimeError:continue
            raise AssertionError('unsafe staging accepted')
        assert Path(target).read_bytes()==binary
    print('R3_STAGING_SELF_TEST_PASSED: artifact hash, create-new/idempotence, path and existing mismatch guards; no host access')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', choices=PROFILES, default='r3-recovery')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--self-test',action='store_true')
    parser.add_argument('--validator',type=int,choices=range(2,7),action='append')
    args=parser.parse_args()
    if args.self_test:
        if args.execute:parser.error('self-test cannot execute')
        self_test();return
    global BINARY, RELEASE
    BINARY='/usr/local/libexec/synergy/posy-stability/synergy-node-'+args.release
    RELEASE='/etc/synergy/posy-stability/release-'+args.release+'.json'
    binary=(ROOT/'target/x86_64-unknown-linux-gnu/release/synergy-node').read_bytes()
    metadata=json.loads((OUT/('release-'+args.release+'.unsigned.json')).read_text())
    metadata=metadata.get('release',metadata)
    validate(binary,metadata,args.release)
    if args.release in {'r3-etdag-cache','r3-rpc-isolation','r3-admission-cutoff'}:
        # Read the single canonical rollout pin without loading transport owners.
        import ast
        tree=ast.parse((ROOT/'tools/validator/roll-r1-tip.py').read_text())
        pin=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                 and any(isinstance(t,ast.Name) and t.id=={'r3-etdag-cache':'R3_ETDAG_CACHE_SHA3','r3-rpc-isolation':'R3_RPC_ISOLATION_SHA3','r3-admission-cutoff':'R3_ADMISSION_CUTOFF_SHA3'}[args.release] for t in node.targets))
        if len(pin)!=64 or metadata['artifact']['sha3_256']!=pin:
            raise RuntimeError('selected artifact unpinned or differs; no host access attempted')
    if not args.execute:
        print(json.dumps({'local_artifact_verified':True,'length':len(binary),'sha3_256':hashlib.sha3_256(binary).hexdigest(),'host_access':False,'started':False}));return
    if not args.validator:parser.error('--execute requires explicit --validator selections')
    envelope=(OUT/('release-'+args.release+'.json')).read_bytes()
    signed=json.loads(envelope)
    if signed.get('release')!=metadata or not signed.get('signature') or not signed.get('public_key'):
        raise RuntimeError('existing signed envelope missing or differs from unsigned candidate')
    spec=importlib.util.spec_from_file_location('provision',ROOT/'tools/validator/provision-stability-hosts.py')
    owner=importlib.util.module_from_spec(spec);spec.loader.exec_module(owner)
    for n in dict.fromkeys(args.validator):
        def remote(argv,data=None):return owner.remote(f'synergy-val{n}',f'/Users/jhutzler/.ssh/posy-val{n}-control',argv,data)
        for path,data in [(BINARY,binary),(RELEASE,envelope)]:
            remote(['python3','-c',RECEIVER,path,str(len(data)),hashlib.sha3_256(data).hexdigest()],data)
        remote(['/usr/local/libexec/synergy/posy-stability/synergy-keytool','verify-release',RELEASE,BINARY,'1266','val2-posy-consensus-v1','/etc/synergy/posy-stability/authority-root.pub',str(PROFILES[args.release][0]-1)])
        print(json.dumps({'validator':n,'staged_native_release_verified':True,'started':False}),flush=True)

if __name__=='__main__':main()
