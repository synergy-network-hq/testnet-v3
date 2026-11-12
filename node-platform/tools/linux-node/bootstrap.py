#!/usr/bin/env python3
"""Fixed root-only NodeNetwork bootstrap, embedded by the native Portal bridge.

Protocol: one <=16KiB JSON header line then a bounded uncompressed tar stream,
package.json FIRST. The native caller authenticates the release pin and the SSH
host; the renderer never supplies code. Installs no validator runtime, generates
no keys, starts no services, and grants no qualified mutations or membership.
"""
from fnmatch import fnmatchcase
import grp
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
sys.dont_write_bytecode=True
ROOT=Path('/opt/Synergy')
LIMIT=256*1024*1024
ENGINE=('controller.py','synergy_linux.py','lifecycle.py','conformance.py','apqe_layout.py','vpn.py','canary_rpc_relay.py')
HOST_LINKS={'sshd.conf':Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'),
            'sudoers':Path('/etc/sudoers.d/synergy-nodenetwork')}
DIRECTORIES={'bin','lib','assets','config','network','systemd','tools','data','keys','logs','cache','tmp','run','vpn','snapshots','recovery','evidence','roles'}
VALIDATOR_UNIT_PATTERNS=('synergy-node.service','synergy-vpn.service','synergy-canary-*.service',
                         'synergy-posy-*.service')


def require(value,message):
    if not value:raise ValueError(message)


def require_clean_service_namespace():
    # A missing /opt/Synergy does not establish a clean host. Disabled units,
    # masks, dangling registrations and loaded-but-unlinked units can survive
    # a previous deployment. Check both installed and effective namespaces
    # before writing any bootstrap files. Independently owned OS/Chain1266
    # services are outside these patterns.
    for operation in ('list-unit-files','list-units'):
        # Some systemd versions return 1 for a filtered list with no matches.
        # List first so a command failure cannot be mistaken for a clean host.
        result=subprocess.run(['/usr/bin/systemctl',operation,'--all','--no-legend',
                               '--no-pager','--plain'],
                              capture_output=True,text=True,check=True,timeout=8)
        require(len(result.stdout)<=2_000_000,'Service inventory exceeds bound')
        for line in result.stdout.splitlines():
            fields=line.split()
            if not fields or not any(fnmatchcase(fields[0],pattern) for pattern in VALIDATOR_UNIT_PATTERNS):continue
            if operation=='list-units' and fields[1:3]==['not-found','inactive']:continue
            require(False,'Legacy validator service registration requires review')


def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb') as file:
        os.fchmod(file.fileno(),0o600);file.write(data);file.flush();os.fsync(file.fileno())


def public_header(line):
    require(0<len(line)<=16384 and line.endswith(b'\n'),'Invalid bootstrap header')
    value=json.loads(line)
    require(isinstance(value,dict) and set(value)=={'version','manifest_sha256','release_id','operator_public_key','network_id','chain_id','node_name'} and type(value['version']) is int and value['version']==1,'Unsupported bootstrap request')
    require(isinstance(value['manifest_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['manifest_sha256']),'Invalid manifest pin')
    require(isinstance(value['release_id'],str) and re.fullmatch('[A-Za-z0-9._-]{1,128}',value['release_id']),'Invalid release ID')
    require(isinstance(value['operator_public_key'],str) and re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]{68}={0,2}',value['operator_public_key']),'An explicit public operator SSH key is required')
    require(isinstance(value['network_id'],str) and re.fullmatch('[a-z0-9][a-z0-9_-]{1,127}',value['network_id']) and type(value['chain_id']) is int and 0<value['chain_id']<2**64 and isinstance(value['node_name'],str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',value['node_name']),'Invalid network selection')
    return value


def extract(stream,stage,header):
    seen=set();expected=None;total=0;directories=set()
    with tarfile.open(fileobj=stream,mode='r|') as tar:
        for member in tar:
            name=member.name;relative=PurePosixPath(name)
            require(name and name==relative.as_posix() and not relative.is_absolute() and '..' not in relative.parts and name not in seen,'Unsafe or duplicate package member')
            seen.add(name)
            require(len(seen)<=8192,'Package member count exceeds bound')
            require(member.isfile() or member.isdir(),'Package links and special members are forbidden')
            require(member.size>=0 and member.size<=LIMIT-total,'Package exceeds bound');total+=member.size
            if expected is None:
                require(name=='package.json' and member.isfile() and member.size<=1024*1024,'First archive member must be the manifest')
                raw=tar.extractfile(member).read()
                require(hashlib.sha256(raw).hexdigest()==header['manifest_sha256'],'Manifest differs from authenticated native selection')
                manifest=json.loads(raw)
                require(manifest.get('format')=='synergy-universal-linux-v1' and manifest.get('architecture')=='x86_64' and manifest.get('release_id')==header['release_id'] and isinstance(manifest.get('files'),dict),'Invalid selected package')
                expected=manifest['files']
                require(len(expected)<=4096 and all(isinstance(n,str) and n==PurePosixPath(n).as_posix() and not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and isinstance(d,str) and re.fullmatch('[a-f0-9]{64}',d) for n,d in expected.items()),'Unsafe manifest inventory')
                save(stage/name,raw);continue
            if member.isdir():
                directories.add(name);(stage/name).mkdir(parents=True,exist_ok=True,mode=0o700);continue
            require(name in expected,'Undeclared package file')
            data=tar.extractfile(member).read()
            require(hashlib.sha256(data).hexdigest()==expected[name],'Package file digest mismatch')
            save(stage/name,data)
    require(expected is not None and seen-directories==set(expected)|{'package.json'},'Incomplete package inventory')
    roles=json.loads((stage/'roles/roles.json').read_bytes())['roles']
    require(isinstance(roles,list) and len(roles)==20 and len(set(roles))==20
            and all(isinstance(name,str) and re.fullmatch('[a-z][a-z0-9_-]{0,63}',name) for name in roles),'Invalid role directory inventory')
    allowed=DIRECTORIES|{'roles/'+name for name in roles}
    allowed|={str(p) for name in expected for p in PurePosixPath(name).parents if str(p)!='.'}
    require(directories<=allowed,'Undeclared package directory')
    for name in sorted(allowed,key=lambda n:n.count('/')):(stage/name).mkdir(parents=True,exist_ok=True,mode=0o700)
    for name in ENGINE:require('tools/'+name in expected,'Required canonical controller tool absent')
    return manifest


def host_contents(public_key):
    command='/usr/bin/sudo -n /usr/bin/python3 -I -B /opt/Synergy/tmp/controller/controller.py'
    return {
      'authorized_keys':('restrict,command="'+command+'" '+public_key+'\n').encode(),
      'sshd.conf':b'''Match User synergy-nodenetwork
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
    AuthorizedKeysFile none
    AuthorizedKeysCommand /usr/bin/cat /opt/Synergy/tmp/controller/host/authorized_keys
    AuthorizedKeysCommandUser root
    ForceCommand /usr/bin/sudo -n /usr/bin/python3 -I -B /opt/Synergy/tmp/controller/controller.py
    PermitTTY no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
Match all
''',
      'sudoers':b'synergy-nodenetwork ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B /opt/Synergy/tmp/controller/controller.py\n'}


def bootstrap(stream):
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64','Linux x86_64 root target required')
    os.umask(0o077)
    header=public_header(stream.readline(16385))
    # The native binary supplies this constant only after checking its compiled
    # trust table or independently PQ-authenticated release authority. It is not
    # a field in the renderer request or package being installed.
    require(globals().get('NATIVE_AUTHENTICATED_MANIFEST_SHA256')==header['manifest_sha256'],
            'No independent native release authorization')
    require(not ROOT.exists() and not ROOT.is_symlink(),'Fresh root required; no merge or overwrite')
    require(ROOT.parent.is_dir() and ROOT.parent.resolve()==ROOT.parent,'Unsafe installation parent')
    for ancestor in (ROOT.parent,*ROOT.parent.parents):
        metadata=ancestor.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==0 and not metadata.st_mode&0o022,'Unsafe privileged installation ancestry')
    for target in HOST_LINKS.values():require(not target.exists() and not target.is_symlink(),'Conflicting host registration')
    require(subprocess.run(['/usr/bin/id','-u','synergy-nodenetwork'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Dedicated account already exists; operator review required')
    try:grp.getgrnam('synergy-nodenetwork')
    except KeyError:pass
    else:raise ValueError('Conflicting group exists; operator review required')
    require_clean_service_namespace()
    ROOT.mkdir(mode=0o700);stage=ROOT/'tmp/bootstrap-master';control=ROOT/'tmp/controller'
    linked=[];account=False
    try:
        stage.mkdir(parents=True,mode=0o700)
        manifest=extract(stream,stage,header)
        for name in ENGINE:
            target=control/'controller.py' if name=='controller.py' else control/'tools'/name
            save(target,(stage/'tools'/name).read_bytes())
        (control/'grants').mkdir(mode=0o700)
        host=host_contents(header['operator_public_key'])
        for name,data in host.items():save(control/'host'/name,data)
        policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(ROOT),'community_enrollment':False,
                'qualified_operations':[],
                'engine_files':{name:hashlib.sha256((stage/'tools'/name).read_bytes()).hexdigest() for name in ENGINE},
                'host_files':{name:hashlib.sha256(data).hexdigest() for name,data in host.items()},
                'releases':{header['release_id']:{'manifest_sha256':header['manifest_sha256'],'inventory_authenticated':True,
                            'networks':{header['network_id']:header['chain_id']}}}}
        subprocess.run(['/usr/sbin/visudo','-c','-f',str(control/'host/sudoers')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        # Use an existing unprivileged group so removal never deletes a group
        # or a home/mail directory the installer did not create.
        label='Synergy NodeNetwork '+secrets.token_hex(16)
        subprocess.run(['/usr/sbin/useradd','--system','--no-create-home','--no-user-group',
                        '--gid','65534','--comment',label,'--home-dir','/nonexistent',
                        '--shell','/bin/sh','synergy-nodenetwork'],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True);account=True
        # An unusable password value that is not a locked-account marker lets
        # public-key-only sshd work on hosts that reject locked Unix accounts.
        subprocess.run(['/usr/sbin/usermod','--password','*','synergy-nodenetwork'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        entry=pwd.getpwnam('synergy-nodenetwork')
        require(entry.pw_uid>0 and entry.pw_gid==65534 and entry.pw_gecos==label
                and entry.pw_dir=='/nonexistent' and entry.pw_shell=='/bin/sh',
                'Dedicated account creation differed from requested scope')
        policy['host_account']={'uid':entry.pw_uid,'gid':entry.pw_gid,'label':label}
        save(control/'policy.json',json.dumps(policy,sort_keys=True).encode())
        for name,target in HOST_LINKS.items():target.symlink_to(control/'host'/name);linked.append(target)
        subprocess.run(['/usr/sbin/sshd','-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        subprocess.run(['/usr/bin/systemctl','reload','ssh.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        return {'root':str(ROOT),'stagedRelease':manifest['release_id'],'manifestSha256':header['manifest_sha256'],
                'controllerEnrolled':True,'softwareInstalled':False,'activationAuthorized':False,'communityEnrollment':False,
                'operatorAuthorizationRequired':True,'hostManagedRecords':['system-account:synergy-nodenetwork',*[str(p) for p in linked]]}
    except Exception:
        for target in reversed(linked):
            if target.is_symlink() and str(target.readlink()).startswith(str(control)+'/host/'):target.unlink()
        if account:subprocess.run(['/usr/sbin/userdel','synergy-nodenetwork'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        shutil.rmtree(ROOT)
        raise


def main():
    try:result={'version':1,'ok':True,'result':bootstrap(sys.stdin.buffer)}
    except Exception:result={'version':1,'ok':False,'error':{'code':'bootstrap_refused','message':'Bootstrap validation or enrollment failed; no validator activated'}}
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
