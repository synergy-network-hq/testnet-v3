#!/usr/bin/env python3
"""Owner-invoked provisioning over existing verified SSH masters only.

No action runs on import. No SSH authentication, source copy, temporary custody,
workbook modification, secret output, or secret argument is implemented here.
Existing mismatched/partial/unreceipted custody fails closed. An existing
receipt verifies public files only; private possession is a runtime gate.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shlex
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/node-platform')
IDENTITIES = ROOT.parent / 'testnet-v3/testnet-v3-identity-files'
REMOTE_KEYTOOL = '/usr/local/libexec/synergy/posy-stability/synergy-keytool'
REMOTE_CUSTODY = '/etc/synergy/posy-stability/custody'
REMOTE_PUBLIC = '/etc/synergy/posy-stability/identity-root.pub.json'
MAX_BINARY = 256 * 1024 * 1024

# This program is passed as public command text, not stored on any host.
RECEIVER = r'''
import sys,os,json,hashlib,stat,grp,subprocess,base64
from pathlib import Path
base=Path('/etc/synergy/posy-stability')
tool=Path('/usr/local/libexec/synergy/posy-stability/synergy-keytool')
gid=grp.getgrnam('synergy-validator').gr_gid
def directory(path,mode=0o750):
    path=Path(path)
    if path != path.parent: directory(path.parent,0o755)
    if not path.exists():
        path.mkdir(mode=mode)
        os.chown(path,0,gid)
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022: raise ValueError()
def regular(path,maximum):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or not 0<st.st_size<=maximum: raise ValueError()
    return path.read_bytes()
def receive(path,length,digest,mode,elf=False):
    path=Path(path); directory(path.parent)
    if path.exists() or path.is_symlink():
        data=regular(path,256*1024*1024)
        if len(data)!=length or hashlib.sha256(data).hexdigest()!=digest: raise ValueError()
        # Drain the bounded input so a repeated owner call does not break its pipe.
        data=sys.stdin.buffer.read(length+1)
        if len(data)!=length or hashlib.sha256(data).hexdigest()!=digest: raise ValueError()
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    try:
        h=hashlib.sha256(); count=0; header=b''
        with os.fdopen(fd,'wb') as out:
            while True:
                chunk=sys.stdin.buffer.read(min(65536,length-count+1))
                if not chunk: break
                if not header: header=chunk[:64]
                count+=len(chunk)
                if count>length: raise ValueError()
                h.update(chunk); out.write(chunk)
            if count!=length or h.hexdigest()!=digest: raise ValueError()
            if elf and (header[:7]!=b'\x7fELF\x02\x01\x01' or header[18:20]!=b'\x3e\x00'): raise ValueError()
            out.flush(); os.fsync(out.fileno())
        os.chown(path,0,gid); os.chmod(path,mode)
        d=os.open(path.parent,os.O_RDONLY); os.fsync(d); os.close(d)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
def public_bundle(number,role):
    prefix=f'val{number}-posy-{role}-v1'; path=base/'custody'/role
    files=[prefix+'.metadata.json',prefix+'.public.key',prefix+'.secret.key']
    if role=='p2p': files.append(prefix+'.identity.json')
    present=[(path/name).exists() or (path/name).is_symlink() for name in files]
    if any(present) and not all(present): raise ValueError()
    if not any(present): return None
    metadata_bytes=regular(path/files[0],1024*1024)
    metadata=json.loads(metadata_bytes); public=regular(path/files[1],4096)
    expected={'p2p':('p2p_identity','ML-DSA-65',1952,4032),'consensus':('posy_consensus','ML-DSA-65',1952,4032),'ingress':('etdag_decryption','ML-KEM-1024',1568,3168)}[role]
    purpose,algorithm,plen,slen=expected
    identity=json.loads(regular(base/'identity-root.pub.json',65536))
    fingerprint=hashlib.sha3_256(b'SYNERGY_KEY_FINGERPRINT_V1'+len(public).to_bytes(8,'big')+public).hexdigest()
    if (metadata['format_version']!=1 or metadata['node_address']!=identity['address'] or metadata['algorithm']!=algorithm or metadata['record']['id']!=prefix or metadata['record']['purpose']!=purpose or metadata['record']['public_key']!=list(public) or len(public)!=plen or metadata['public_key_fingerprint']!=fingerprint): raise ValueError()
    st=(path/files[2]).lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size!=slen: raise ValueError()
    if role=='consensus' and public.hex()!=identity['consensus_key']['public_key']: raise ValueError()
    exported={files[0]:metadata_bytes,files[1]:public}
    if role=='p2p':
        data=regular(path/files[3],65536); operational=json.loads(data)
        if operational['node_address']!=identity['address'] or operational['public_key_fingerprint']!=fingerprint: raise ValueError()
        exported[files[3]]=data
    return exported
def run():
    action=sys.argv[1]
    if action in ['binary','identity']:
        length=int(sys.argv[2]); digest=sys.argv[3]
        if not 0<length<=(256*1024*1024 if action=='binary' else 65536): raise ValueError()
        receive(tool if action=='binary' else base/'identity-root.pub.json',length,digest,0o755 if action=='binary' else 0o644,action=='binary')
        return {'ok':True}
    number=int(sys.argv[2]); role=sys.argv[3]
    if number not in range(2,7) or role not in ['p2p','ingress','consensus']: raise ValueError()
    directory(base/'custody'/role)
    receipt=base/'custody'/role/'public-provisioning-receipt.json'
    # Owner invokes complete only immediately after a successful native import.
    # Its new secret is still root:root0600 until the normalization below.
    if action=='complete':
        if role!='consensus' or receipt.exists(): raise ValueError()
        existing=None
    else:
        existing=public_bundle(number,role)
    if action=='status':
        if existing is None: return {'ok':True,'exists':False}
        saved=json.loads(regular(receipt,65536))
        expected={name:hashlib.sha256(data).hexdigest() for name,data in existing.items()}
        if saved!={'version':1,'number':number,'role':role,'public_sha256':expected}: raise ValueError()
        return {'ok':True,'exists':True,'public_sha256':expected}
    if action=='generate':
        if existing is not None or receipt.exists(): raise ValueError()
        prefix=f'val{number}-posy-{role}-v1'
        identity=json.loads(regular(base/'identity-root.pub.json',65536))
        if role=='p2p': args=[str(tool),'generate-node',prefix,str(base/'identity-root.pub.json'),str(base/'custody'/role),'--validator']
        elif role=='ingress': args=[str(tool),'generate-etdag-1024',identity['address'],prefix,str(base/'custody'/role)]
        else: raise ValueError()
        if subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60).returncode: raise ValueError()
    elif action!='complete': raise ValueError()
    # Called immediately after successful native generation/import. Never reads
    # or exports secret bytes; grant only the verified runtime group access.
    secret=base/'custody'/role/f'val{number}-posy-{role}-v1.secret.key'
    st=secret.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or stat.S_IMODE(st.st_mode) not in (0o600,0o640): raise ValueError()
    os.chown(secret,0,0); os.chmod(secret,0o600)
    exported=public_bundle(number,role)
    value={'version':1,'number':number,'role':role,'public_sha256':{name:hashlib.sha256(data).hexdigest() for name,data in exported.items()}}
    payload=json.dumps(value,sort_keys=True).encode()
    fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out: out.write(payload); out.flush(); os.fsync(out.fileno())
    return {'ok':True}
try:
    if sys.argv[1]=='export':
        number=int(sys.argv[2]); result={}
        for role in ['p2p','consensus','ingress']:
            files=public_bundle(number,role)
            if files is None: raise ValueError()
            result.update({name:base64.b64encode(data).decode() for name,data in files.items()})
        print(json.dumps({'ok':True,'public_files':result}))
    else: print(json.dumps(run()))
except BaseException:
    print(json.dumps({'ok':False})); sys.exit(1)
'''


class ProvisionError(Exception):
    pass


def fingerprint_binary(path, expected):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BINARY:
        raise ProvisionError('approved regular binary missing')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ProvisionError('approved binary hash mismatch')
    return data


def configured_master_socket(host):
    result=subprocess.run(['ssh','-G',host],check=True,capture_output=True,text=True,timeout=15)
    sockets=[line.partition(' ')[2].strip() for line in result.stdout.splitlines()
             if line.startswith('controlpath ')]
    if len(sockets)!=1 or not Path(sockets[0]).is_absolute():
        raise ProvisionError('one configured persistent SSH master required')
    return sockets[0]


def master_arguments(host, socket):
    socket = Path(socket)
    if not socket.is_absolute() or socket.is_symlink():
        raise ProvisionError('explicit verified master socket required')
    metadata = socket.stat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise ProvisionError('master socket ownership or permissions invalid')
    return ['ssh', '-T', '-S', str(socket), '-o', 'ControlMaster=no', '-o', 'RequestTTY=no',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ProxyCommand=/usr/bin/false', host]


def remote(host, socket, argv, data=None):
    command = 'exec sudo -n -- ' + shlex.join(map(str, argv))
    try:
        result = subprocess.run(master_arguments(host, socket) + [command], input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120, check=False)
        if result.returncode or len(result.stdout) > 1024 * 1024:
            raise ProvisionError('owner remote provisioning command failed')
        return result.stdout
    except ProvisionError:
        raise
    except Exception:
        raise ProvisionError('owner remote provisioning transport failed') from None


def action(host, socket, name, *args, data=None):
    output = remote(host, socket, ['python3', '-c', RECEIVER, name, *map(str, args)], data)
    try:
        value = json.loads(output)
        if value.get('ok') is not True:
            raise ProvisionError('remote public provisioning check refused')
        return value
    except (ValueError, TypeError):
        raise ProvisionError('remote public provisioning response invalid') from None


def save_public(directory, files):
    if directory.is_symlink():
        raise ProvisionError('canonical public output directory is a symlink')
    directory.mkdir(mode=0o755, exist_ok=True)
    for name, encoded in files.items():
        if '/' in name or not (name.endswith('.public.key') or name.endswith('.metadata.json') or name.endswith('.identity.json')):
            raise ProvisionError('private or unexpected export filename refused')
        data = base64.b64decode(encoded, validate=True)
        if len(data) > 1024 * 1024:
            raise ProvisionError('public export exceeds bound')
        path = directory / name
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
                raise ProvisionError('canonical public output differs; overwrite refused')
            continue
        with path.open('xb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())


def provision_all(hosts, linux_keytool, linux_sha256, native_keytool, native_sha256, engine, engine_sha256):
    """Root owner only: hosts [{number,host,socket}], exactly val2 through val6.

    Returns fixed public status fields only. Does not publish a deployment or
    runtime readiness claim, sign Genesis, start services, or edit the workbook.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sorted(h['number'] for h in hosts) != list(range(2, 7)):
        raise ProvisionError('exact val2 through val6 master inventory required')
    linux = fingerprint_binary(linux_keytool, linux_sha256)
    if linux[:7] != b'\x7fELF\x02\x01\x01' or linux[18:20] != b'\x3e\x00':
        raise ProvisionError('approved Linux keytool is not x86-64 ELF')
    fingerprint_binary(native_keytool, native_sha256)
    fingerprint_binary(engine, engine_sha256)
    spec = importlib.util.spec_from_file_location('existing_consensus', Path(__file__).with_name('provision-existing-consensus.py'))
    custody = importlib.util.module_from_spec(spec); spec.loader.exec_module(custody)
    results = []
    for host in sorted(hosts, key=lambda h: h['number']):
        number, name, socket = host['number'], host['host'], host['socket']
        directory = IDENTITIES / f'VNS-A{number+1:02}_validator-{number:02}'
        public = (directory / 'identity.pub.json').read_bytes()
        action(name, socket, 'binary', len(linux), linux_sha256, data=linux)
        action(name, socket, 'identity', len(public), hashlib.sha256(public).hexdigest(), data=public)
        for role in ['p2p', 'ingress']:
            if not action(name, socket, 'status', number, role)['exists']:
                action(name, socket, 'generate', number, role)
        source = 'existing public receipt; private possession pending runtime'
        if not action(name, socket, 'status', number, 'consensus')['exists']:
            def supply(public_path, address, key_id, secret):
                remote(name, socket, [REMOTE_KEYTOOL, 'import-consensus-public-bound', address, key_id,
                                     REMOTE_PUBLIC, REMOTE_CUSTODY + '/consensus'], secret)
            source = custody.recover_and_supply(number, engine, engine_sha256, native_keytool, native_sha256, supply)
            action(name, socket, 'complete', number, 'consensus')
        exported = action(name, socket, 'export', number)['public_files']
        save_public(directory / 'operational', exported)
        results.append({'validator': number, 'public_custody_exported': True,
                        'consensus_source': source, 'runtime_private_possession': 'pending'})
    return results



# Fresh custody mode deliberately does not reuse RECEIVER, IDENTITY inventories
# or provision-existing-consensus. All private generation stays on its host.
FRESH_RECEIVER = r'''
import base64,hashlib,json,os,stat,subprocess,sys
from pathlib import Path
base=Path('/etc/synergy/posy-stability')
custody=base/'custody'
tool=Path('/usr/local/libexec/synergy/posy-stability/synergy-keytool')
state=Path('/var/lib/synergy/posy-stability/data')
number=int(sys.argv[2]);network=sys.argv[3];expected=sys.argv[4]
if number not in range(2,7) or not network or len(network)>128 or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in network):raise ValueError('invalid fresh identity')
def plain(path):
 if any(p.is_symlink() for p in [path,*path.parents]):raise ValueError('symlink refused')
def empty(path):
 plain(path)
 if path.exists() and (not path.is_dir() or any(path.iterdir())):raise ValueError('existing or partial fresh custody/state refused')
def run(args):
 if subprocess.run([str(tool),*map(str,args)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120).returncode:raise ValueError('native fresh generation or possession check failed')
def preflight():
 plain(tool);st=tool.stat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or hashlib.sha256(tool.read_bytes()).hexdigest()!=expected:raise ValueError('canonical keytool pin differs')
 for p in Path('/proc').iterdir():
  if p.name.isdigit():
   try:
    if Path(os.readlink(p/'exe').removesuffix(' (deleted)')).name.startswith('synergy-node'):raise ValueError('validator must be stopped')
   except (FileNotFoundError,ProcessLookupError):pass
 empty(custody);empty(state)
preflight()
if sys.argv[1]=='preflight':
 print(json.dumps({'ok':True,'empty_fresh_custody':True,'stopped':True}));sys.exit(0)
if sys.argv[1]!='generate':raise ValueError('invalid fresh action')
custody.mkdir(mode=0o700,exist_ok=True);os.chmod(custody,0o700)
for role in ['identity','p2p','consensus','ingress']:
 path=custody/role;path.mkdir(mode=0o700);os.chmod(path,0o700)
root_id=f'val{number}-identity-root-v1'
root_json=custody/'identity'/(root_id+'.identity-root.json')
root_secret=custody/'identity'/(root_id+'.secret.key')
run(['generate-validator-root',root_id,network,custody/'identity'])
run(['verify-validator-root',root_json,root_secret,network])
root=json.loads(root_json.read_text());address=root['address']
exports={root_json.name:base64.b64encode(root_json.read_bytes()).decode()}
roles={'p2p':'generate-node','consensus':'generate-consensus','ingress':'generate-etdag-1024'}
for role,command in roles.items():
 key=f'val{number}-posy-{role}-v1';directory=custody/role
 args=[command,key,root_json,directory,'--validator'] if role=='p2p' else [command,address,key,directory]
 run(args)
 metadata=directory/(key+'.metadata.json');public=directory/(key+'.public.key');secret=directory/(key+'.secret.key')
 run(['verify-key-pair',metadata,public,secret,address,key])
 os.chmod(secret,0o600)
 for path in [metadata,public,*([directory/(key+'.identity.json')] if role=='p2p' else [])]:
  exports[path.name]=base64.b64encode(path.read_bytes()).decode()
print(json.dumps({'ok':True,'number':number,'network_id':network,'address':address,
 'native_private_possession_verified':True,'public_files':exports}))
'''


def fresh_network_id(value):
    if (not isinstance(value,str) or not value or len(value)>128
            or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for c in value)
            or value in ('synergy-posy-stability-20261009','synergy-posy-baseline-20261010')):
        raise ProvisionError('explicit new network incarnation ID required')
    return value


def fresh_deployment_paths(deployment_name=None):
    """An explicit canary label cannot select a retired or production root."""
    if deployment_name is None:
        return {"name": "posy-stability", "public_directory": ROOT / "networks/testnet/posy-stability",
                "configuration": "/etc/synergy/posy-stability",
                "executables": "/usr/local/libexec/synergy/posy-stability",
                "state": "/var/lib/synergy/posy-stability/data"}
    if (not isinstance(deployment_name, str)
            or not deployment_name.startswith("posy-async-canary-")
            or len(deployment_name) > 80
            or not deployment_name.removeprefix("posy-async-canary-")
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in deployment_name)):
        raise ProvisionError("explicit separate asynchronous canary deployment name required")
    return {"name": deployment_name, "public_directory": ROOT / "networks/testnet" / deployment_name,
            "configuration": "/etc/synergy/" + deployment_name,
            "executables": "/usr/local/libexec/synergy/" + deployment_name,
            "state": "/var/lib/synergy/" + deployment_name + "/data"}


def fresh_receiver(deployment_name=None):
    paths = fresh_deployment_paths(deployment_name)
    return (FRESH_RECEIVER.replace("/etc/synergy/posy-stability", paths["configuration"])
            .replace("/usr/local/libexec/synergy/posy-stability", paths["executables"])
            .replace("/var/lib/synergy/posy-stability/data", paths["state"]))


def provision_fresh_keytool(hosts, linux_keytool, linux_sha256, deployment_name):
    """Install only an exact fresh-canary keytool; never replace existing bytes."""
    paths = fresh_deployment_paths(deployment_name)
    if deployment_name is None:
        raise ProvisionError("separate canary deployment required")
    if sorted(h['number'] for h in hosts) != list(range(2, 7)):
        raise ProvisionError('exact val2 through val6 master inventory required')
    linux = fingerprint_binary(linux_keytool, linux_sha256)
    if linux[:7] != b'\x7fELF\x02\x01\x01' or linux[18:20] != b'\x3e\x00':
        raise ProvisionError('approved native Linux keytool required')
    receiver = (RECEIVER.replace('/etc/synergy/posy-stability', paths['configuration'])
                .replace('/usr/local/libexec/synergy/posy-stability', paths['executables'])
                .replace("        receive(tool if action=='binary'",
                         "        directory(base)\n        receive(tool if action=='binary'"))
    for host in hosts:
        master_arguments(host['host'], host['socket'])
    for host in hosts:
        raw = remote(host['host'], host['socket'], ['python3', '-c', receiver, 'binary',
                     len(linux), linux_sha256], linux)
        if json.loads(raw).get('ok') is not True:
            raise ProvisionError('fresh keytool install refused')


def provision_fresh_all(hosts, linux_keytool, linux_sha256, network_id, public_directory, deployment_name=None):
    """Generate new host-local custody only after every actual host is empty.

    This function never imports identities, signs Genesis, starts services or
    resumes partial generation. The operator owns the separately approved reset.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    network_id=fresh_network_id(network_id)
    if sorted(h['number'] for h in hosts)!=list(range(2,7)):
        raise ProvisionError('exact val2 through val6 master inventory required')
    linux=fingerprint_binary(linux_keytool,linux_sha256)
    if linux[:7]!=b'\x7fELF\x02\x01\x01' or linux[18:20]!=b'\x3e\x00':
        raise ProvisionError('approved native Linux keytool required')
    directory=Path(public_directory)
    paths=fresh_deployment_paths(deployment_name)
    canonical=paths['public_directory']
    if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink() or directory!=canonical:
        raise ProvisionError('existing canonical network public directory required')
    for h in hosts:
        master_arguments(h['host'],h['socket'])
    def fresh_action(h,operation):
        raw=remote(h['host'],h['socket'],['python3','-c',fresh_receiver(deployment_name),operation,h['number'],network_id,linux_sha256])
        try:
            result=json.loads(raw)
            if result.get('ok') is not True:raise ValueError()
            return result
        except (ValueError,TypeError):
            raise ProvisionError('fresh host custody operation refused') from None
    # All five preflight before any host can create custody.
    for h in sorted(hosts,key=lambda h:h['number']):
        fresh_action(h,'preflight')
        target=directory/f"val{h['number']}"
        if target.exists() or target.is_symlink():
            raise ProvisionError('existing public fresh custody export refused')
    results=[]
    for h in sorted(hosts,key=lambda h:h['number']):
        result=fresh_action(h,'generate')
        exported=result['public_files']
        if any(not(name.endswith('.public.key') or name.endswith('.metadata.json')
                   or name.endswith('.identity.json') or name.endswith('.identity-root.json'))
               or '/' in name for name in exported):
            raise ProvisionError('non-public fresh export refused')
        target=directory/f"val{h['number']}"
        target.mkdir(mode=0o755)
        for name,encoded in exported.items():
            data=base64.b64decode(encoded,validate=True)
            if not 0<len(data)<=1024*1024:raise ProvisionError('fresh public export exceeds bound')
            with (target/name).open('xb') as output:
                output.write(data);output.flush();os.fsync(output.fileno())
        results.append({k:result[k] for k in ('number','network_id','address','native_private_possession_verified')})
    return results


# One operator-approved candidate installation replaces the sole canonical file.
# No create-new/staging/rollback executable is permitted in this mode.
SINGLE_PATH_BINARY = '/usr/local/libexec/synergy/posy-stability/synergy-node-r3-admission-cutoff'
SINGLE_PATH_RELEASE = '/etc/synergy/posy-stability/release-r3-admission-cutoff.json'
SINGLE_PATH_UNIT = '/etc/systemd/system/synergy-posy-stability.service'
SINGLE_PATH_ISSUES = '/var/lib/synergy/posy-stability/VALIDATOR_ISSUES.md'
SINGLE_PATH_REMOTE = r"""
import datetime,hashlib,json,os,shlex,stat,subprocess,sys,time
from pathlib import Path
BINARY=Path('/usr/local/libexec/synergy/posy-stability/synergy-node-r3-admission-cutoff')
RELEASE=Path('/etc/synergy/posy-stability/release-r3-admission-cutoff.json')
UNIT=Path('/etc/systemd/system/synergy-posy-stability.service')
ISSUES=Path('/var/lib/synergy/posy-stability/VALIDATOR_ISSUES.md')
SERVICE='synergy-posy-stability.service'
CONFIG=Path('/etc/synergy/posy-stability/node.json')
KEYTOOL=Path('/usr/local/libexec/synergy/posy-stability/synergy-keytool')
TRUST=Path('/etc/synergy/posy-stability/authority-root.pub')
def regular(p,limit=268435456):
 p=Path(p)
 if any(a.is_symlink() for a in [p,*p.parents]):raise ValueError('symlink canonical path rejected')
 st=p.stat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_nlink!=1 or not 0<st.st_size<=limit:raise ValueError('unsafe canonical file')
 return st

def digest(p):
 regular(p);h=hashlib.sha3_256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
 return h.hexdigest()

def service():
 raw=subprocess.check_output(['systemctl','show',SERVICE,'-p','MainPID','-p','ActiveState','-p','NRestarts','-p','ExecStart'],timeout=15).decode()
 return dict(line.split('=',1) for line in raw.strip().splitlines())

def processes():
 found=[]
 for path in Path('/proc').iterdir():
  if not path.name.isdigit():continue
  try:
   exe=os.readlink(path/'exe')
   if not Path(exe.removesuffix(' (deleted)')).name.startswith('synergy-node'):continue
   fields=(path/'stat').read_text().rsplit(')',1)[1].split()
   found.append({'pid':int(path.name),'exe':exe,'start_ticks':fields[19]})
  except (FileNotFoundError,ProcessLookupError):continue
 return sorted(found,key=lambda p:p['pid'])

def commands():
 lines=UNIT.read_text().splitlines()
 start=[shlex.split(line.split('=',1)[1]) for line in lines if line.startswith('ExecStart=')]
 pre=[shlex.split(line.split('=',1)[1]) for line in lines if line.startswith('ExecStartPre=')]
 if start!=[[str(BINARY),'start','--config',str(CONFIG)]] or len(pre)!=1 or pre[0][:6]!=[str(KEYTOOL),'verify-release',str(RELEASE),str(BINARY),'1266','val2-posy-consensus-v1'] or pre[0][6]!=str(TRUST) or len(pre[0])!=8:
  raise ValueError('canonical service commands differ')
 return pre[0]

def snapshot():
 for p in [BINARY,RELEASE,UNIT,CONFIG,KEYTOOL,TRUST,ISSUES]:regular(p)
 commands();state=service();ps=processes();pid=int(state['MainPID'])
 if pid:
  if len(ps)!=1 or ps[0]['pid']!=pid or ps[0]['exe']!=str(BINARY):raise ValueError('unexpected or parallel validator process')
 elif ps:raise ValueError('residual validator process outside service')
 return {'service':state,'processes':ps,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
  'binary_sha3':digest(BINARY),'binary_length':BINARY.stat().st_size,'release_sha3':digest(RELEASE),
  'unit_sha3':digest(UNIT),'config_sha3':digest(CONFIG),'trust_sha3':digest(TRUST),
  'installed_sequence':json.loads(RELEASE.read_text())['release']['sequence']}

def stopped():
 state=service()
 if int(state['MainPID'])!=0 or state['ActiveState'] not in ('inactive','failed') or processes():raise ValueError('validator not completely stopped')
 return state

def started_snapshot():
 # systemctl may return while its child has not yet exec'd the validator.
 deadline=time.monotonic()+5
 while True:
  state=service();ps=processes();pid=int(state['MainPID'])
  if len(ps)>1 or (ps and ps[0]['pid']!=pid):raise ValueError('unexpected or parallel validator process')
  if state['ActiveState']!='active' or pid==0:raise ValueError('started validator is not active')
  if ps:return snapshot()
  if time.monotonic()>=deadline:raise ValueError('validator executable did not appear after start')
  time.sleep(0.05)

def log(event,details):
 regular(ISSUES,16*1024*1024)
 line='\n- '+datetime.datetime.now(datetime.timezone.utc).isoformat()+' '+event+' '+json.dumps(details,sort_keys=True,separators=(',',':'))+'\n'
 if ISSUES.stat().st_size+len(line.encode())>16*1024*1024:raise ValueError('canonical issue ledger limit exceeded')
 fd=os.open(ISSUES,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
 with os.fdopen(fd,'a') as out:out.write(line);out.flush();os.fsync(out.fileno())

def inventory():
 files=[]
 for p in sorted(BINARY.parent.glob('synergy-node*')):
  if p==BINARY:continue
  try:st=regular(p);files.append({'path':str(p),'length':st.st_size,'sha3_256':digest(p)})
  except Exception:files.append({'path':str(p),'unsafe':True})
 references=[]
 for folder in [Path('/etc/systemd/system'),Path('/usr/lib/systemd/system')]:
  for p in sorted(folder.glob('*.service')):
   if p.is_symlink() or not p.is_file() or p.stat().st_size>1048576:continue
   text=p.read_text(errors='replace')
   for item in files:
    if item['path'] in text:references.append({'file':str(p),'binary':item['path']})
 return {'historical_binaries':files,'systemd_references':references,
  'cleanup_action':'review exact paths and all references; no automatic deletion; artifact history remains in provenance/evidence',
  'reference_scope':'direct systemd service files only; other scripts/configuration references require explicit review'}

try:
 action=sys.argv[1];request=json.loads(sys.argv[2])
 if action=='probe':result={'snapshot':snapshot(),'cleanup_inventory':inventory()}
 elif action=='stop':
  current=snapshot()
  if current!=request['expected_snapshot']:raise ValueError('host changed after reviewed preflight')
  subprocess.run(['systemctl','stop',SERVICE],check=True,timeout=150)
  result={'stopped':stopped(),'boot_id':current['boot_id'],'config_sha3':digest(CONFIG),'unit_sha3':digest(UNIT)}
  log('candidate_install_stopped',{'candidate_sha3':request['candidate_sha3']})
 elif action=='replace':
  stopped()
  if digest(CONFIG)!=request['config_sha3'] or digest(UNIT)!=request['unit_sha3'] or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=request['boot_id']:raise ValueError('stopped configuration or boot changed')
  target=BINARY if request['kind']=='binary' else RELEASE if request['kind']=='release' else None
  if target is None:raise ValueError('single canonical replacement target required')
  limit=268435456 if target==BINARY else 1048576
  length=request['length']
  if type(length) is not int or not 0<length<=limit:raise ValueError('replacement length exceeds bound')
  data=sys.stdin.buffer.read(length+1)
  if len(data)!=length or hashlib.sha3_256(data).hexdigest()!=request['sha3_256']:raise ValueError('replacement transport bytes differ')
  if target==BINARY and (data[:7]!=b'\x7fELF\x02\x01\x01' or data[18:20]!=b'\x3e\0'):raise ValueError('exact Linux artifact required')
  old=regular(target);stopped() # Last process guard immediately before opening writable inode.
  fd=os.open(target,os.O_WRONLY|os.O_NOFOLLOW)
  with os.fdopen(fd,'wb') as output:
   current=os.fstat(output.fileno())
   if (current.st_dev,current.st_ino)!=(old.st_dev,old.st_ino):raise ValueError('canonical inode changed')
   os.ftruncate(output.fileno(),0);output.write(data);output.flush();os.fsync(output.fileno())
  directory=os.open(target.parent,os.O_RDONLY);os.fsync(directory);os.close(directory)
  if digest(target)!=request['sha3_256']:raise ValueError('installed bytes differ')
  log('candidate_install_replaced',{'kind':request['kind'],'sha3_256':request['sha3_256'],'length':length,'qualified':False})
  result={'installed_sha3':request['sha3_256'],'qualified':False}
 elif action=='verify':
  stopped();regular(KEYTOOL);regular(TRUST);pre=commands()
  if digest(BINARY)!=request['binary_sha3'] or digest(RELEASE)!=request['release_sha3'] or digest(CONFIG)!=request['config_sha3'] or digest(TRUST)!=request['trust_sha3']:raise ValueError('installed candidate binding changed')
  subprocess.run([str(KEYTOOL),'verify-release',str(RELEASE),str(BINARY),'1266','val2-posy-consensus-v1',str(TRUST),str(request['installed_sequence'])],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
  # Update only existing native pre-start anti-rollback sequence in the same unit.
  text=UNIT.read_text();old_line='ExecStartPre='+shlex.join(pre);new_line='ExecStartPre='+shlex.join(pre[:-1]+[str(request['installed_sequence'])])
  lines=text.splitlines(keepends=True)
  updated=''.join((new_line+'\n') if line.startswith('ExecStartPre=') else line for line in lines)
  if updated!=text:
   regular(UNIT);fd=os.open(UNIT,os.O_WRONLY|os.O_NOFOLLOW)
   with os.fdopen(fd,'w') as out:os.ftruncate(out.fileno(),0);out.write(updated);out.flush();os.fsync(out.fileno())
  subprocess.run(['systemd-analyze','verify',str(UNIT)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
  subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
  log('candidate_install_native_verified',{'candidate_sha3':request['binary_sha3'],'qualified':False})
  result={'native_release_verified':True,'binary_sha3':digest(BINARY),'release_sha3':digest(RELEASE),'unit_sha3':digest(UNIT),'config_sha3':digest(CONFIG),'trust_sha3':digest(TRUST),'installed_sequence':request['installed_sequence'],'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
 elif action=='start':
  stopped()
  if any(digest(path)!=request[name] for path,name in [(BINARY,'binary_sha3'),(RELEASE,'release_sha3'),(UNIT,'unit_sha3'),(CONFIG,'config_sha3'),(TRUST,'trust_sha3')]) or Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=request['boot_id']:raise ValueError('verified installation changed before start')
  subprocess.run([str(KEYTOOL),'verify-release',str(RELEASE),str(BINARY),'1266','val2-posy-consensus-v1',str(TRUST),str(request['installed_sequence'])],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
  subprocess.run(['systemctl','start',SERVICE],check=True,timeout=150)
  result={'snapshot':started_snapshot(),'candidate_installed':True,'qualified':False}
  log('candidate_install_started',{'candidate_sha3':request['binary_sha3'],'qualified':False})
 elif action=='fail_stop':
  subprocess.run(['systemctl','stop',SERVICE],check=True,timeout=150);result={'stopped':stopped()}
  log('candidate_install_failed_no_rollback',{'candidate_sha3':request['candidate_sha3'],'qualified':False})
 else:raise ValueError('unknown single-path action')
 print(json.dumps(result,sort_keys=True))
except Exception as error:
 print(json.dumps({'error_type':type(error).__name__,'action':sys.argv[1],'failed_closed':True}));sys.exit(1)
"""


def single_path_remote(host, socket, action_name, request=None, data=None):
    """Only the existing verified master transports bounded candidate bytes."""
    argv=['python3','-c',SINGLE_PATH_REMOTE,action_name,json.dumps(request or {},sort_keys=True)]
    command='exec sudo -n -- '+shlex.join(argv)
    result=subprocess.run(master_arguments(host,socket)+[command],input=data,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,timeout=180,check=False)
    if result.returncode or len(result.stdout)>1024*1024:
        raise ProvisionError('single-path '+action_name+' failed; fleet owner must stop all candidates')
    value=json.loads(result.stdout)
    if not isinstance(value,dict):raise ProvisionError('invalid single-path response')
    return value
