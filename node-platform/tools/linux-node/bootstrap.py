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
ROOT=Path('/opt/synergy')
LIMIT=256*1024*1024
ENGINE=('controller.py','synergy_linux.py','lifecycle.py','conformance.py','apqe_layout.py','vpn.py','canary_rpc_relay.py','root_guard.py')
HOST_LINKS={'sshd.conf':Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'),
            'sudoers':Path('/etc/sudoers.d/synergy-nodenetwork')}
DIRECTORIES={'bin','lib','assets','config','network','systemd','tools','data','keys','logs','cache','tmp','run','vpn','snapshots','recovery','evidence','roles'}
VALIDATOR_UNIT_PATTERNS=('synergy-node.service','synergy-vpn.service','synergy-canary-*.service',
                         'synergy-posy-*.service','synergy-installation-guard.service')


def require(value,message):
    if not value:raise ValueError(message)


def require_clean_service_namespace():
    # A missing /opt/synergy does not establish a clean host. Disabled units,
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
    command='/usr/bin/sudo -n /usr/bin/python3 -I -B /opt/synergy/tmp/controller/controller.py'
    return {
      'authorized_keys':('restrict,command="'+command+'" '+public_key+'\n').encode(),
      'sshd.conf':b'''Match User synergy-nodenetwork
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
    AuthorizedKeysFile none
    AuthorizedKeysCommand /usr/bin/cat /opt/synergy/tmp/controller/host/authorized_keys
    AuthorizedKeysCommandUser root
    ForceCommand /usr/bin/sudo -n /usr/bin/python3 -I -B /opt/synergy/tmp/controller/controller.py
    PermitTTY no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    AllowAgentForwarding no
Match all
''',
      'sudoers':b'synergy-nodenetwork ALL=(root) NOPASSWD: NOSETENV: /usr/bin/python3 -I -B /opt/synergy/tmp/controller/controller.py\n'}


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
    old_root=ROOT.with_name('Synergy')
    require(not old_root.exists() and not old_root.is_symlink(),
            'Legacy mixed-case validator root requires operator retirement before installation')
    require(ROOT.parent.is_dir() and ROOT.parent.resolve()==ROOT.parent,'Unsafe installation parent')
    for ancestor in (ROOT.parent,*ROOT.parent.parents):
        metadata=ancestor.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==0 and not metadata.st_mode&0o022,'Unsafe privileged installation ancestry')
    for target in HOST_LINKS.values():require(not target.exists() and not target.is_symlink(),'Conflicting host registration')
    require(subprocess.run(['/usr/bin/id','-u','synergy-nodenetwork'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'Dedicated account already exists; operator review required')
    try:grp.getgrnam('synergy-nodenetwork')
    except KeyError:pass
    else:raise ValueError('Conflicting group exists; operator review required')
    for path in (Path('/etc/systemd/system/synergy-installation-guard.service'),
                 Path('/etc/systemd/system/multi-user.target.wants/synergy-installation-guard.service')):
        require(not path.exists() and not path.is_symlink(),'Previous installation retirement is incomplete')
    require_clean_service_namespace()
    ROOT.mkdir(mode=0o700);stage=ROOT/'tmp/bootstrap-master';control=ROOT/'tmp/controller'
    linked=[];account=False;guard_pin=None
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
        for name,target in HOST_LINKS.items():target.symlink_to(control/'host'/name);linked.append(target)
        subprocess.run(['/usr/sbin/sshd','-t'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        subprocess.run(['/usr/bin/systemctl','reload','ssh.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        # Execute only the copy whose bytes were checked against the native
        # authenticated manifest, never a module imported from the host CWD.
        import runpy
        guard=runpy.run_path(str(control/'tools/root_guard.py'))
        source=(control/'tools/root_guard.py').read_bytes()
        guard_pin=guard['install'](ROOT,policy['host_account'],source)
        policy['root_guard_sha256']=guard_pin
        save(control/'policy.json',json.dumps(policy,sort_keys=True).encode())
        return {'root':str(ROOT),'stagedRelease':manifest['release_id'],'manifestSha256':header['manifest_sha256'],
                'controllerEnrolled':True,'softwareInstalled':False,'activationAuthorized':False,'communityEnrollment':False,
                'operatorAuthorizationRequired':True,'rootDeletionGuardActive':True,
                'hostManagedRecords':['system-account:synergy-nodenetwork',*[str(p) for p in linked],
                                      *[str(p) for p in guard['paths']()]]}
    except Exception:
        if guard_pin is not None:
            # The active OS guard owns teardown once the root is gone.
            shutil.rmtree(ROOT)
            guard['wait_for_retirement']()
            raise
        for target in reversed(linked):
            if target.is_symlink() and str(target.readlink()).startswith(str(control)+'/host/'):target.unlink()
        if account:subprocess.run(['/usr/sbin/userdel','synergy-nodenetwork'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        shutil.rmtree(ROOT)
        raise


def stage_engineering_update(stream, release_id, pin):
    """Adopt a sealed candidate and its controller on a quiescent engineering host.

    The root operator supplies the independently authenticated pin. This
    neither grants an upgrade request nor replaces installed validator files.
    """
    import ctypes
    import fcntl
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64','Linux x86_64 root target required')
    require(re.fullmatch(r'[a-zA-Z0-9._-]{1,128}',release_id) and re.fullmatch(r'[a-f0-9]{64}',pin),'Exact update release and manifest pin required')
    require(ROOT.resolve()==ROOT and stat.S_IMODE(ROOT.lstat().st_mode)==0o700 and ROOT.stat().st_uid==0,'Private canonical installation required')
    os.umask(0o077)
    root=ROOT
    old=root/'tmp/controller'
    pending=root/'tmp/update-master'
    replacement=root/'tmp/controller-update'
    # Import the enrolled engine only after independently checking its pins.
    policy_path=old/'policy.json'
    require(policy_path.resolve()==policy_path and stat.S_IMODE(policy_path.lstat().st_mode)==0o600
            and policy_path.stat().st_uid==0,'Unsafe host policy')
    policy=json.loads(policy_path.read_bytes())
    require(set(policy.get('engine_files',{}))==set(ENGINE),'Incomplete enrolled engine')
    for name in ENGINE:
        path=old/name if name=='controller.py' else old/'tools'/name
        require(path.resolve()==path and path.is_file() and path.stat().st_uid==0
                and not path.stat().st_mode&0o022
                and hashlib.sha256(path.read_bytes()).hexdigest()==policy['engine_files'][name],
                'Enrolled controller engine drift')
    sys.path.insert(0,str(old/'tools'))
    sys.path.insert(0,str(old))
    from controller import HOST_REMOVAL, VPN_ENROLLMENT, control_inventory
    from lifecycle import _sealed_receipt, _unit_state, _assert_no_application_processes, _sync_directory, UPGRADE_INTENT
    from synergy_linux import verify_package
    lock=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        receipt,_=_sealed_receipt(root)
        network=receipt['network_id']
        require(receipt.get('role')=='validator' and re.fullmatch(r'nodenetwork-formation-disposable-[a-z0-9]+(?:-[a-z0-9]+)*',network),
                'This controller staging operation is limited to disposable formation')
        control_inventory(root)
        require(not any((old/'grants').iterdir())
                and not any((old/name).exists() for name in (HOST_REMOVAL,VPN_ENROLLMENT))
                and not (root/UPGRADE_INTENT).exists(),'Prior operator request requires reconciliation')
        status=_unit_state('synergy-node.service')
        require(status.get('MainPID','0')=='0' and status.get('ActiveState') in ('inactive','failed'),
                'Stop the validator before adopting an update')
        vpn=_unit_state('synergy-vpn.service')
        _assert_no_application_processes(root,vpn_pid=vpn.get('MainPID'))
        require(not any(p.exists() or p.is_symlink() for p in (pending,replacement)),'Prior update staging requires reconciliation')
        pending.mkdir(mode=0o700)
        exchanged=False
        try:
            manifest=extract(stream,pending,{'manifest_sha256':pin,'release_id':release_id})
            require(verify_package(pending)==manifest,'Candidate verification differs')
            guard_pin=policy.get('root_guard_sha256')
            if guard_pin is not None:
                from root_guard import check_registration, render
                check_registration(guard_pin)
                guard_source=pending/'tools/root_guard.py'
                require('tools/root_guard.py' in manifest['files'] and
                        hashlib.sha256(render(root,policy['host_account'],guard_source.read_bytes())).hexdigest()==guard_pin,
                        'Update changes the registered deletion guard; authenticated guard migration required')
            shutil.copytree(old,replacement)
            for name in ENGINE:
                target=replacement/name if name=='controller.py' else replacement/'tools'/name
                target.unlink()
                save(target,(pending/'tools'/name).read_bytes())
            policy['engine_files']={name:manifest['files']['tools/'+name] for name in ENGINE}
            releases=policy['releases']
            selected={'manifest_sha256':pin,'inventory_authenticated':True,'networks':{network:receipt['chain_id']}}
            require(release_id not in releases or releases[release_id]==selected,'Release ID already names another inventory')
            releases[release_id]=selected
            (replacement/'policy.json').unlink()
            save(replacement/'policy.json',json.dumps(policy,sort_keys=True).encode())
            for path in sorted(replacement.rglob('*'),key=lambda p:-len(p.parts)):
                if path.is_dir():_sync_directory(path)
                else:
                    with path.open('rb') as f:os.fsync(f.fileno())
            _sync_directory(replacement)
            _sync_directory(root/'tmp')
            # Keep all fixed SSH, sudo, and authorized-key paths resolvable.
            exchange=ctypes.CDLL(None,use_errno=True).renameat2
            exchange.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
            exchange.restype=ctypes.c_int
            if exchange(-100,os.fsencode(old),-100,os.fsencode(replacement),2):
                raise OSError(ctypes.get_errno(),'Controller directory exchange failed')
            exchanged=True
            _sync_directory(root/'tmp')
            control_inventory(root)
            shutil.rmtree(replacement)
            _sync_directory(root/'tmp')
        except Exception:
            if not exchanged:
                if replacement.exists():shutil.rmtree(replacement)
                shutil.rmtree(pending)
                _sync_directory(root/'tmp')
            raise
        return {'stagedRelease':release_id,'manifestSha256':pin,'controllerAdopted':True,'validatorUpgraded':False}
    finally:
        os.close(lock)


def main():
    try:
        if len(sys.argv)==4 and sys.argv[1]=='--stage-engineering-update':
            operation=stage_engineering_update(sys.stdin.buffer,sys.argv[2],sys.argv[3])
        else:
            require(len(sys.argv)==1,'Unsupported bootstrap invocation')
            operation=bootstrap(sys.stdin.buffer)
        result={'version':1,'ok':True,'result':operation}
    except Exception:result={'version':1,'ok':False,'error':{'code':'bootstrap_refused','message':'Bootstrap validation or enrollment failed; no validator activated'}}
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
