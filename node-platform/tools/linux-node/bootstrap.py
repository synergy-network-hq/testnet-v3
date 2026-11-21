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
OPTIONAL_ENGINE=('guest_lifecycle.py','vpn_authorization.py','treasury_send.py','runtime_probe.py')
def engine_names(files):
    return (*ENGINE,*(name for name in OPTIONAL_ENGINE if 'tools/'+name in files))

def initial_engine_pins(stage, manifest):
    # The extractor already authenticated this exact manifest. Include optional
    # qualified modules in policy only when the pinned package actually owns them.
    return {name:hashlib.sha256((stage/'tools'/name).read_bytes()).hexdigest()
            for name in engine_names(manifest['files'])}

def enrolled_engine(policy):
    names=set(policy.get('engine_files',{}))
    require(set(ENGINE)<=names<=set((*ENGINE,*OPTIONAL_ENGINE)),'Incomplete enrolled engine')
    return tuple(sorted(names))

HOST_LINKS={'sshd.conf':Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'),
            'sudoers':Path('/etc/sudoers.d/synergy-nodenetwork')}
DIRECTORIES={'bin','lib','assets','config','network','systemd','tools','data','keys','logs','cache','tmp','run','vpn','snapshots','recovery','evidence','roles'}
VALIDATOR_UNIT_PATTERNS=('synergy-node.service','synergy-vpn.service','synergy-canary-*.service',
                         'synergy-posy-*.service','synergy-installation-guard.service')


def require(value,message):
    if not value:raise ValueError(message)


def inert_missing_unit(unit):
    # systemd retains a failed-state tombstone after its unit file is removed.
    # A filtered list row alone cannot prove that it owns no runtime resources.
    fields=('LoadState','ActiveState','SubState','MainPID','ControlPID','FragmentPath',
            'SourcePath','DropInPaths','UnitFileState','Triggers','TriggeredBy','Job')
    result=subprocess.run(['/usr/bin/systemctl','show',unit,'--property='+','.join(fields)],
                          capture_output=True,text=True,check=False,timeout=8)
    require(result.returncode==0 and not result.stderr and isinstance(result.stdout,str)
            and len(result.stdout)<=65536,'Missing unit state could not be verified')
    values={}
    for line in result.stdout.splitlines():
        key,separator,value=line.partition('=')
        require(separator and key in fields and key not in values,'Invalid missing unit state')
        values[key]=value
    return (set(values)==set(fields) and values['LoadState']=='not-found'
            and (values['ActiveState'],values['SubState']) in (('inactive','dead'),('failed','failed'))
            and values['MainPID']==values['ControlPID']=='0'
            and all(values[key]=='' for key in fields[5:]))


def require_clean_service_namespace():
    # A missing /opt/synergy does not establish a clean host. Disabled units,
    # masks, dangling registrations and loaded-but-unlinked units can survive
    # a previous deployment. Check both installed and effective namespaces
    # before writing any bootstrap files. Independently owned OS/Chain1266
    # services are outside these patterns.
    for operation in ('list-unit-files','list-units'):
        # Bound systemd's filesystem walk to our owned namespace. Some versions
        # return 1 for list-unit-files with no matches; only its exactly empty,
        # diagnostic-free response has that meaning. The subsequent list-units
        # must still succeed, so an unavailable manager never proves cleanliness.
        result=subprocess.run(['/usr/bin/systemctl',operation,'--all','--no-legend',
                               '--no-pager','--plain',*VALIDATOR_UNIT_PATTERNS],
                              capture_output=True,text=True,check=False,timeout=8)
        stderr=result.stderr or ''
        require(isinstance(result.stdout,str) and isinstance(stderr,str)
                and len(result.stdout)<=2_000_000 and len(stderr)<=65536,'Service inventory exceeds bound')
        no_matches=(operation=='list-unit-files' and result.returncode==1
                    and result.stdout=='' and stderr=='')
        require((result.returncode==0 or no_matches) and stderr=='',
                'Service inventory failed; cannot establish a clean namespace')
        for line in result.stdout.splitlines():
            fields=line.split()
            if not fields:continue
            require(any(fnmatchcase(fields[0],pattern) for pattern in VALIDATOR_UNIT_PATTERNS),
                    'Service inventory returned an unrelated or malformed row')
            if (operation=='list-units' and len(fields)>=4 and fields[1]=='not-found'
                    and fields[2:4] in (['inactive','dead'],['failed','failed'])
                    and inert_missing_unit(fields[0])):continue
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


def master_archive_limit(manifest):
    declaration=manifest.get('managed_guest_resources')
    if declaration is None:
        require(not any(name.startswith(('hosted-machines/','lib/guest-tools/')) for name in manifest['files']),
                'Guest assets require an authenticated declaration')
        return LIMIT
    required={'hosted-machines/images/os.qcow2','lib/guest-tools/bios.bin',
              *('lib/guest-tools/bin/'+name for name in ('qemu-system-x86_64','qemu-img','ssh-keygen','genisoimage','ld-linux-x86-64.so.2'))}
    require(isinstance(declaration,dict) and set(declaration)=={'version','manifest_sha256','archive_limit_bytes','files'}
            and type(declaration['version']) is int and declaration['version']==1
            and isinstance(declaration['manifest_sha256'],str) and re.fullmatch('[a-f0-9]{64}',declaration['manifest_sha256'])
            and type(declaration['archive_limit_bytes']) is int and declaration['archive_limit_bytes'] in (512*1024**2,1024**3)
            and isinstance(declaration['files'],dict) and 7<=len(declaration['files'])<=135
            and required<=set(declaration['files']),'Invalid guest master declaration')
    for name,pin in declaration['files'].items():
        require(name in required or re.fullmatch(r'lib/guest-tools/lib/[A-Za-z0-9][A-Za-z0-9._+-]{0,127}',name),
                'Unsafe guest master resource path')
        require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),'Invalid guest master resource pin')
    require({name:pin for name,pin in manifest['files'].items() if name.startswith(('hosted-machines/','lib/guest-tools/'))}==declaration['files'],
            'Guest master resource inventory differs')
    return declaration['archive_limit_bytes']


def save_stream(path,stream,size,expected):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    digest=hashlib.sha256();remaining=size
    try:
        with path.open('xb') as target:
            os.fchmod(target.fileno(),0o600)
            while remaining:
                chunk=stream.read(min(1024*1024,remaining))
                require(bool(chunk),'Truncated package member')
                target.write(chunk);digest.update(chunk);remaining-=len(chunk)
            require(digest.hexdigest()==expected,'Package file digest mismatch')
            target.flush();os.fsync(target.fileno())
    except Exception:
        # Never remove an existing member after an exclusive-open refusal.
        # The caller owns cleanup of the fresh extraction root on failure.
        raise


def extract(stream,stage,header):
    seen=set();expected=None;total=0;directories=set();limit=LIMIT
    with tarfile.open(fileobj=stream,mode='r|') as tar:
        for member in tar:
            name=member.name;relative=PurePosixPath(name)
            require(name and name==relative.as_posix() and not relative.is_absolute() and '..' not in relative.parts and name not in seen,'Unsafe or duplicate package member')
            seen.add(name)
            require(len(seen)<=8192,'Package member count exceeds bound')
            require(member.isfile() or member.isdir(),'Package links and special members are forbidden')
            require(member.size>=0 and member.size<=limit-total,'Package exceeds bound');total+=member.size
            if expected is None:
                require(name=='package.json' and member.isfile() and member.size<=1024*1024,'First archive member must be the manifest')
                raw=tar.extractfile(member).read()
                require(hashlib.sha256(raw).hexdigest()==header['manifest_sha256'],'Manifest differs from authenticated native selection')
                manifest=json.loads(raw)
                require(manifest.get('format')=='synergy-universal-linux-v1' and manifest.get('architecture')=='x86_64' and manifest.get('release_id')==header['release_id'] and isinstance(manifest.get('files'),dict),'Invalid selected package')
                expected=manifest['files']
                limit=master_archive_limit(manifest)
                require(len(expected)<=4096 and all(isinstance(n,str) and n==PurePosixPath(n).as_posix() and not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts and isinstance(d,str) and re.fullmatch('[a-f0-9]{64}',d) for n,d in expected.items()),'Unsafe manifest inventory')
                save(stage/name,raw);continue
            if member.isdir():
                directories.add(name);(stage/name).mkdir(parents=True,exist_ok=True,mode=0o700);continue
            require(name in expected,'Undeclared package file')
            save_stream(stage/name,tar.extractfile(member),member.size,expected[name])
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


def verify_executable_stage(stage):
    # Extraction stays non-executable until the complete inventory is verified.
    from apqe_layout import require_frozen_tree
    from synergy_linux import verify_package
    manifest=verify_package(stage)
    require_frozen_tree(stage)
    for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird'):
        member='bin/'+name
        if member not in manifest['files']:continue
        fd=os.open(stage/member,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink==1,'Exact regular staged binary required')
            with os.fdopen(os.dup(fd),'rb') as source:
                digest=hashlib.sha256()
                for chunk in iter(lambda:source.read(1024*1024),b''):digest.update(chunk)
                require(digest.hexdigest()==manifest['files'][member],
                        'Staged binary changed after verification')
            os.fchmod(fd,0o700);os.fsync(fd)
        finally:os.close(fd)
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
        for name in engine_names(manifest['files']):
            target=control/'controller.py' if name=='controller.py' else control/'tools'/name
            save(target,(stage/'tools'/name).read_bytes())
        (control/'grants').mkdir(mode=0o700)
        host=host_contents(header['operator_public_key'])
        for name,data in host.items():save(control/'host'/name,data)
        policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(ROOT),'community_enrollment':False,
                'qualified_operations':[],
                'engine_files':initial_engine_pins(stage,manifest),
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


def bare_metadata(path, maximum=1024*1024):
    require(path.is_absolute() and path.resolve()==path,'Bare bootstrap path contains a link')
    metadata=path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0 and metadata.st_nlink==1
            and stat.S_IMODE(metadata.st_mode)==0o600 and metadata.st_size<=maximum,
            'Bare bootstrap file is unsafe')
    return metadata


def bare_file(path, maximum=1024*1024):
    bare_metadata(path,maximum)
    return path.read_bytes()


def bare_digest(path, maximum=LIMIT):
    bare_metadata(path,maximum)
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def bare_tree(root, manifest, authorization_files=()):
    """Exact bootstrap-only namespace; never a generic installation remover."""
    stage=root/'tmp/bootstrap-master'
    limit=master_archive_limit(manifest)
    files={'tmp/controller/policy.json','tmp/bootstrap-master/package.json',*authorization_files}
    files|={'tmp/bootstrap-master/'+name for name in manifest['files']}
    files|={'tmp/controller/'+name if name=='controller.py' else 'tmp/controller/tools/'+name
            for name in engine_names(manifest['files'])}
    files|={'tmp/controller/host/'+name for name in ('authorized_keys','sshd.conf','sudoers')}
    roles=json.loads(bare_file(stage/'roles/roles.json'))['roles']
    require(isinstance(roles,list) and len(roles)==20 and len(set(roles))==20
            and all(isinstance(name,str) and re.fullmatch('[a-z][a-z0-9_-]{0,63}',name) for name in roles),
            'Bare staged role inventory differs')
    directories={'tmp','tmp/controller','tmp/controller/tools','tmp/controller/host','tmp/controller/grants',
                 'tmp/bootstrap-master'}
    directories|={'tmp/bootstrap-master/'+name for name in DIRECTORIES}
    directories|={'tmp/bootstrap-master/roles/'+name for name in roles}
    for name in files:
        directories|={str(parent) for parent in PurePosixPath(name).parents if str(parent)!='.'}
    # Bootstrap may create no root presets today; permit only fixed EMPTY ones.
    directories|=DIRECTORIES-{'tmp'}
    observed_files=set();observed_dirs=set();snapshot=[];total=0
    for current, children, members in os.walk(root,followlinks=False):
        children.sort()
        require(len(snapshot)<=8192,'Bare namespace exceeds bound')
        for name in sorted(children+members):
            path=Path(current)/name;relative=path.relative_to(root).as_posix();metadata=path.lstat()
            require(metadata.st_uid==0 and not path.is_symlink(),'Bare namespace owner/link differs')
            if stat.S_ISDIR(metadata.st_mode):
                # Existing authorization staging creates this intermediate
                # public-input directory with the OS umask, beneath controller700.
                modes=(0o700,0o755) if authorization_files and relative=='tmp/controller/authorization' else (0o700,)
                require(relative in directories and stat.S_IMODE(metadata.st_mode) in modes,
                        'Unknown or unsafe bare directory')
                observed_dirs.add(relative)
            else:
                require(relative in files,'Bare bootstrap contains state, authorization or unknown files')
                bare_metadata(path,limit);total+=metadata.st_size
                require(total<=limit+4*1024*1024,'Bare namespace exceeds byte bound')
                observed_files.add(relative)
            snapshot.append([relative,metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size,
                             metadata.st_mtime_ns,metadata.st_ctime_ns])
    require(observed_files==files,'Bare bootstrap inventory incomplete')
    required={'tmp','tmp/controller','tmp/controller/tools','tmp/controller/host','tmp/controller/grants','tmp/bootstrap-master'}
    require(required<=observed_dirs,'Bare bootstrap directories incomplete')
    # Any fixed presets outside the stage must remain empty (including data,
    # keys, network and VPN). No hosted-machines, custody or journal is allowed.
    for name in DIRECTORIES-{'tmp'}:
        path=root/name
        require(not path.exists() or not any(path.iterdir()),'Bare bootstrap preset contains state')
    return snapshot


def bare_guard(root,policy,source):
    import runpy
    import shlex
    guard=runpy.run_path(str(root/'tmp/controller/tools/root_guard.py'))
    account=policy['host_account'];pin=policy['root_guard_sha256']
    unit=guard['render'](root,account,source)
    require(hashlib.sha256(unit).hexdigest()==pin,'Bare guard differs from original pinned source')
    guard['check_registration'](pin)
    require(guard['account_present'](account['uid'],account['label'].rsplit(' ',1)[1]),
            'Bare bootstrap account is absent')
    state=guard['state'](guard['UNIT']);pid=state.get('MainPID','')
    require(pid.isdecimal() and int(pid)>1,'Bare guard is not running')
    process=Path('/proc')/pid
    require(process.stat().st_uid==0 and (process/'exe').resolve()==Path('/usr/bin/python3').resolve(),
            'Bare guard process attribution differs')
    command=[line[10:] for line in unit.decode('ascii').splitlines() if line.startswith('ExecStart=')]
    require(len(command)==1,'Bare guard command is absent')
    expected=b'\x00'.join(word.encode() for word in shlex.split(command[0]))+b'\x00'
    require(bare_process_cmdline(process)==expected,'Bare guard loaded source differs')
    for path in HOST_LINKS.values():
        require(path.is_symlink() and path.lstat().st_uid==0
                and os.readlink(path)==str(root/'tmp/controller/host'/next(k for k,v in HOST_LINKS.items() if v==path)),
                'Bare host registration is not attributed')
    # Bootstrap has no application service registration, even stopped ones.
    for name in ('synergy-node.service','synergy-vpn.service','synergy-canary-rpc-relay.service'):
        state=guard['state'](name)
        require(state.get('LoadState')=='not-found' and state.get('MainPID')=='0'
                and state.get('ControlPID')=='0' and not state.get('FragmentPath') and not state.get('DropInPaths'),
                'Bare bootstrap has a runtime service')
        require(not (guard['SYSTEM']/name).exists() and not (guard['SYSTEM']/name).is_symlink(),
                'Bare bootstrap has a runtime registration')
    return guard


def bare_process_cmdline(process):
    with (process/'cmdline').open('rb') as stream:return stream.read(32769)


def bare_mounts(root):
    # Bind mounts can share st_dev, so inspect explicit mount boundaries too.
    with open('/proc/self/mountinfo') as stream:
        for line in stream:
            mount=line.split()[4]
            for encoded,decoded in (('\\040',' '),('\\011','\t'),('\\012','\n'),('\\134','\\')):mount=mount.replace(encoded,decoded)
            require(not (mount==str(root) or mount.startswith(str(root)+'/')),'Mounted bare subtree requires independent recovery')


def bare_administrative_hashes():
    return {name:hashlib.sha256(Path(name).read_bytes()).hexdigest()
            for name in ('/etc/ssh/sshd_config','/etc/sudoers')}


def bare_no_application_processes(root, pins, proc=Path('/proc')):
    """Use only the enrolled, manifest-verified process guard, never CWD imports."""
    import importlib.util
    import runpy
    paths={name:root/'tmp/controller/tools'/name for name in ('synergy_linux.py','lifecycle.py')}
    for name,path in paths.items():
        require(bare_digest(path,1024*1024)==pins.get(name),'Bare process guard engine drift')
    previous=sys.modules.get('synergy_linux')
    try:
        spec=importlib.util.spec_from_file_location('synergy_linux',paths['synergy_linux.py'])
        module=importlib.util.module_from_spec(spec);sys.modules['synergy_linux']=module
        spec.loader.exec_module(module)
        lifecycle=runpy.run_path(str(paths['lifecycle.py']))
        lifecycle['_assert_no_application_processes'](root,proc=proc)
    finally:
        if previous is None:sys.modules.pop('synergy_linux',None)
        else:sys.modules['synergy_linux']=previous


def bare_initial_authorization(root,policy,release_id,pin):
    """Cancel only the independently pinned, wholly unused initial grant set."""
    base={'format','root','community_enrollment','qualified_operations','releases',
          'engine_files','host_files','host_account','root_guard_sha256'}
    if 'engineering_authorization' not in policy:
        require(set(policy)==base and policy.get('qualified_operations')==[],
                'Bootstrap is no longer bare or has authorization')
        return None,{},set()
    expected=globals().get('NATIVE_AUTHENTICATED_BARE_AUTHORIZATION_SHA256')
    raw=globals().get('NATIVE_AUTHENTICATED_BARE_AUTHORIZATION_JSON')
    require(isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected)
            and isinstance(raw,str) and 0<len(raw.encode())<=65536
            and hashlib.sha256(raw.encode()).hexdigest()==expected,
            'Bootstrap is no longer bare without independent initial authorization')
    preliminary=json.loads(raw)
    require(isinstance(preliminary,dict) and type(preliminary.get('expires_at')) is int,
            'Invalid original initial authorization')
    # Reuse its strict bounded schema while deliberately permitting expiry for
    # cancellation only. No operation or grant is executed by this path.
    doc=authorization_document(raw,expected,preliminary['expires_at']-1)
    additional={'engineering_selection','engineering_target','engineering_authorization',
                'engineering_initial_authorization_sha256','authorization_files',
                'authorization_predecessor_sha256','validator_formation_sha256'}
    require(set(policy)==base|additional and doc['sequence']==1 and doc['genesis_pins'] is None
            and set(doc['artifacts'])=={'formation-context.json'},
            'Only unused initial formation authorization may be cancelled')
    require(policy['engineering_authorization']=={'sha256':expected,'sequence':1,'expires_at':doc['expires_at']}
            and policy['engineering_initial_authorization_sha256']==expected
            and policy['engineering_target']==doc['target']
            and isinstance(policy['authorization_predecessor_sha256'],str)
            and re.fullmatch('[a-f0-9]{64}',policy['authorization_predecessor_sha256']),
            'Initial authorization receipt differs or has continued')
    selection={key:doc[key] for key in ('release_id','manifest_sha256','network_id','chain_id','node_name')}
    require(policy['engineering_selection']==selection and selection['release_id']==release_id
            and selection['manifest_sha256']==pin
            and policy['releases'][release_id]['networks']=={doc['network_id']:doc['chain_id']},
            'Initial authorization changes the pinned bootstrap selection')
    require(policy['authorization_files']==doc['artifacts']
            and policy['validator_formation_sha256']==doc['artifacts']['formation-context.json'],
            'Initial public formation inventory differs')
    artifact='tmp/controller/authorization/inputs/formation-context.json'
    payload=bare_file(root/artifact,4096)
    require(hashlib.sha256(payload).hexdigest()==doc['artifacts']['formation-context.json'],
            'Initial public formation bytes differ')
    formation=json.loads(payload)
    require(isinstance(formation,dict) and set(formation)=={'network_id','chain_id_hex','formation_id'}
            and formation['network_id']==doc['network_id'] and formation['chain_id_hex']==format(doc['chain_id'],'064x')
            and isinstance(formation['formation_id'],str) and re.fullmatch('[a-f0-9]{64}',formation['formation_id'])
            and formation['formation_id']!='0'*64,'Initial formation context differs')
    operations=[];grants={};files={artifact}
    for request in doc['requests']:
        operation=request['operation'];key=request['request_sha256']
        require(operation in ('gateway_install','gateway_target_generate','gateway_target_commission','install','commission','register','start','stop','restart','upgrade','uninstall',
            'identity_generate','formation_prepare','treasury_prepare','treasury_send_prepare','treasury_send_submit','genesis_stage','genesis_bind','network_formation_prepare',
            'network_formation_sign','network_transport_prepare','network_transport_sign','gateway_admission_prepare','gateway_admission_sign','vpn_enroll','vpn_bind','vpn_retire','vpn_cancel_unused','vpn_stop','vpn_resume','boot_policy',
            'guest_create','guest_stop','guest_resume','guest_remove') and key not in grants,'Invalid initial grant inventory')
        relative='tmp/controller/grants/'+key+'.json';grant_raw=bare_file(root/relative,65536)
        grant=json.loads(grant_raw)
        require(grant=={'root':str(root),'operation':operation,'request_sha256':key,'expires_at':doc['expires_at'],
                       'authorization_sha256':expected,'authorization_sequence':1},
                'Original initial grant changed or was consumed')
        grants[key]=hashlib.sha256(grant_raw).hexdigest();files.add(relative);operations.append(operation)
    require(policy['qualified_operations']==sorted(set(operations)), 'Original initial operation set differs')
    require({path.name for path in (root/'tmp/controller/grants').iterdir()}=={key+'.json' for key in grants},
            'Original initial grant set is incomplete or has extras')
    return expected,{'authorization_sha256':expected,'grants':grants,'artifacts':doc['artifacts']},files


def bare_snapshot(release_id,pin):
    require(re.fullmatch('[a-zA-Z0-9._-]{1,128}',release_id) and re.fullmatch('[a-f0-9]{64}',pin),
            'Exact bare bootstrap release and pin required')
    require(globals().get('NATIVE_AUTHENTICATED_MANIFEST_SHA256')==pin,
            'No independent native rollback authorization')
    root=ROOT;metadata=root.lstat()
    require(root.resolve()==root and stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==0
            and stat.S_IMODE(metadata.st_mode)==0o700,'Unsafe bare installation root')
    bare_mounts(root)
    stage=root/'tmp/bootstrap-master';raw=bare_file(stage/'package.json')
    require(hashlib.sha256(raw).hexdigest()==pin,'Bare staged master differs from native old pin')
    manifest=json.loads(raw)
    require(manifest.get('format')=='synergy-universal-linux-v1' and manifest.get('architecture')=='x86_64'
            and manifest.get('release_id')==release_id and isinstance(manifest.get('files'),dict)
            and len(manifest['files'])<=4096,'Invalid bare staged master')
    for name,expected in manifest['files'].items():
        path=PurePosixPath(name)
        require(isinstance(name,str) and name==path.as_posix() and not path.is_absolute()
                and '..' not in path.parts and isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected),
                'Unsafe bare manifest inventory')
    # Public native-approved authorization is parsed without importing tools;
    # its exact file set then joins the same closed bare namespace.
    policy_raw=bare_file(root/'tmp/controller/policy.json');policy=json.loads(policy_raw)
    require(isinstance(policy,dict) and policy.get('format')=='synergy-nodenetwork-host-policy-v1'
            and policy.get('root')==str(root) and policy.get('community_enrollment') is False,
            'Bootstrap is no longer bare or has authorization')
    authorization_sha256,authorization_review,authorization_files=bare_initial_authorization(root,policy,release_id,pin)
    inventory=bare_tree(root,manifest,authorization_files)
    require(set(policy['releases'])=={release_id},'Bare bootstrap release inventory differs')
    selected=policy['releases'][release_id]
    require(set(selected)=={'manifest_sha256','inventory_authenticated','networks'}
            and selected['manifest_sha256']==pin and selected['inventory_authenticated'] is True
            and isinstance(selected['networks'],dict) and len(selected['networks'])==1,
            'Bare bootstrap release approval differs')
    require(set(policy['engine_files'])==set(engine_names(manifest['files']))
            and set(policy['host_files'])=={'authorized_keys','sshd.conf','sudoers'},'Bare engine/host inventory differs')
    for name,expected in manifest['files'].items():
        require(bare_digest(stage/name,master_archive_limit(manifest))==expected,'Bare staged payload drift')
    for name,expected in policy['engine_files'].items():
        path=root/'tmp/controller'/name if name=='controller.py' else root/'tmp/controller/tools'/name
        require(manifest['files'].get('tools/'+name)==expected
                and hashlib.sha256(bare_file(path)).hexdigest()==expected,'Bare enrolled engine drift')
    for name,expected in policy['host_files'].items():
        require(isinstance(expected,str) and re.fullmatch('[a-f0-9]{64}',expected)
                and hashlib.sha256(bare_file(root/'tmp/controller/host'/name)).hexdigest()==expected,
                'Bare host registration drift')
    account=policy['host_account']
    require(isinstance(account,dict) and set(account)=={'uid','gid','label'} and type(account['uid']) is int
            and 0<account['uid']<2**32-1 and account['gid']==65534 and isinstance(account['label'],str)
            and re.fullmatch('Synergy NodeNetwork [a-f0-9]{32}',account['label']), 'Bare account attribution differs')
    # No import or execution of a staged tool occurs above this point.
    guard=bare_guard(root,policy,bare_file(root/'tmp/controller/tools/root_guard.py'))
    bare_no_application_processes(root,policy['engine_files'])
    administrative=bare_administrative_hashes()
    review={'root':str(root),'release_id':release_id,'manifest_sha256':pin,
            'root_identity':[metadata.st_dev,metadata.st_ino],
            'policy_sha256':hashlib.sha256(policy_raw).hexdigest(),'inventory':inventory,
            'root_guard_sha256':policy['root_guard_sha256'],'administrative':administrative,
            'initial_authorization':authorization_review}
    digest=hashlib.sha256(json.dumps(review,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'schema':'nodenetwork-bare-bootstrap-rollback-preflight-v1','root':str(root),
            'release_id':release_id,'manifest_sha256':pin,'review_sha256':digest,
            'controller_enrolled':True,'software_installed':False,'authorization_sha256':authorization_sha256,
            'root_guard_sha256':policy['root_guard_sha256']},guard,policy,administrative


def bare_rollback(release_id,pin,review_sha256=None):
    import fcntl
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64',
            'Linux x86_64 root target required')
    lock=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        locked=os.fstat(lock);current=ROOT.lstat()
        require((locked.st_dev,locked.st_ino)==(current.st_dev,current.st_ino),'Bare root changed before lock')
        result,guard,policy,administrative=bare_snapshot(release_id,pin)
        if review_sha256 is None:return result
        require(isinstance(review_sha256,str) and re.fullmatch('[a-f0-9]{64}',review_sha256)
                and review_sha256==result['review_sha256'],'Bare rollback review changed; inspect again')
        # Only the proven empty bootstrap is removed. Its original active guard
        # owns account and OS-registration retirement; no alternate teardown.
        current=ROOT.lstat()
        require((locked.st_dev,locked.st_ino)==(current.st_dev,current.st_ino),'Bare root changed after review')
        shutil.rmtree(ROOT)
        guard['wait_for_retirement']()
        require(not ROOT.exists() and not ROOT.is_symlink(),'Bare root remains')
        require(all(not path.exists() and not path.is_symlink() for path in HOST_LINKS.values()),
                'Bare host registrations remain')
        require(not guard['account_present'](policy['host_account']['uid'],policy['host_account']['label'].rsplit(' ',1)[1]),
                'Bare managed account remains')
        require(all(hashlib.sha256(Path(name).read_bytes()).hexdigest()==expected for name,expected in administrative.items()),
                'Administrative configuration changed during retirement')
        return {'schema':'nodenetwork-bare-bootstrap-rollback-v1','release_id':release_id,
                'manifest_sha256':pin,'review_sha256':review_sha256,'authorization_sha256':result.get('authorization_sha256'),'root_removed':True,
                'registrations_removed':True,'administrative_configuration_preserved':True}
    finally:os.close(lock)


def effective_engineering_selection(root,policy):
    module=__import__('controller')
    if hasattr(module,'engineering_effective_selection'):
        return module.engineering_effective_selection(root,policy)
    # The first update may upgrade the original approved controller itself.
    # An old controller may describe only its immutable original selection.
    require(policy.get('engineering_update') is None,'Old controller cannot authenticate an update lineage')
    return policy.get('engineering_selection')


def engineering_update_context(policy,previous,release_id,pin,now):
    context=globals().get('NATIVE_AUTHENTICATED_UPDATE_CONTEXT')
    require(isinstance(context,dict) and set(context) in ({'initial_sha256','parent_sha256','formation_sha256','target','selection','release_id','manifest_sha256','expires_at'}, {'initial_sha256','parent_sha256','formation_sha256','target','selection','release_id','manifest_sha256','expires_at','commission_grant_preservation'}),
            'Native update review context required')
    require(type(context['expires_at']) is int and now<context['expires_at']<=now+300,
            'Native update review expired')
    require(context['initial_sha256']==policy.get('engineering_initial_authorization_sha256')
            and context['parent_sha256']==policy.get('engineering_authorization',{}).get('sha256')
            and context['formation_sha256']==policy.get('validator_formation_sha256')
            and isinstance(context['formation_sha256'],str)
            and context['target']==policy.get('engineering_target') and context['selection']==previous
            and context['release_id']==release_id and context['manifest_sha256']==pin,
            'Update changes the authenticated target, formation or current receipt')
    require(pin!=previous['manifest_sha256'] and release_id!=previous['release_id'],'Update must name a distinct release')
    return context


def validate_guard_update(root, policy, receipt, manifest, pending):
    """Validate a sealed candidate plan only; staging never changes services."""
    pin=policy.get('root_guard_sha256')
    if pin is None:return
    from root_guard import check_registration, render
    check_registration(pin)
    member='tools/root_guard.py'
    require(member in manifest['files'],'Authenticated candidate guard required')
    source=(pending/member).read_bytes()
    require(0<len(source)<=22000 and hashlib.sha256(source).hexdigest()==manifest['files'][member],
            'Candidate guard changed after verification')
    previous=receipt.get('package_files',{}).get(member)
    require(isinstance(previous,str) and re.fullmatch('[a-f0-9]{64}',previous),
            'Installed guard source lacks package provenance')
    if hashlib.sha256(source).hexdigest()==previous:
        require(hashlib.sha256(render(root,policy['host_account'],source)).hexdigest()==pin,
                'Unchanged guard differs from registered unit')
        return
    # Never ask the legacy renderer to interpret a new guard source/profile.
    # Execute the already rehashed master bytes to inspect its pure plan only.
    candidate={'__name__':'nodenetwork_authenticated_guard_candidate'}
    exec(compile(source,str(pending/member),'exec'),candidate)
    require(callable(candidate.get('migration_plan')),'Candidate lacks authenticated guard migration')
    candidate['migration_plan'](root,policy['host_account'],source,previous,pin)


# Public diagnostic labels only: never serialize exception text, paths, policy,
# credentials or subprocess output. The native UI needs the failed trust boundary.
UPDATE_PHASES={
    'entry':'platform and private-root validation',
    'engine':'enrolled controller byte authentication',
    'receipt':'installed release and effective selection',
    'context':'fresh native review context',
    'namespace':'controller inventory',
    'requests':'outstanding operator requests and commissioning preservation',
    'grant_scope':'exact expired commissioning grant scope',
    'grant_artifacts':'unchanged approved commissioning artifacts',
    'grant_audit':'unused commissioning audit',
    'grant_state':'unpublished commissioning state',
    'quiescence':'stopped validator and attributed process checks',
    'package':'exact staged package verification',
    'adoption':'exact native-reviewed update lineage',
    'verifier':'fresh adopted-controller inventory verification',
    'backup_inventory':'bounded predecessor metadata inventory',
    'backup_policy':'exact predecessor policy transformation',
    'backup_members':'exact predecessor file attribution',
    'cleanup':'attributed predecessor cleanup',
    'exchange':'durable controller directory exchange',
}
_UPDATE_PHASE=None

def update_phase(phase):
    global _UPDATE_PHASE
    require(phase in UPDATE_PHASES,'Unknown public update phase')
    _UPDATE_PHASE=phase


def verify_adopted_controller(root):
    """Do not reuse the predecessor interpreter after an engine-set exchange."""
    code = r"""import hashlib,json,os,re,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);control=root/'tmp/controller'
policy_path=control/'policy.json'
st=policy_path.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600
policy=json.loads(policy_path.read_bytes());pins=policy['engine_files']
base={'controller.py','synergy_linux.py','lifecycle.py','conformance.py','apqe_layout.py','vpn.py','canary_rpc_relay.py','root_guard.py'}
assert base<=set(pins)<=base|{'guest_lifecycle.py','vpn_authorization.py','treasury_send.py','runtime_probe.py'}
for name,pin in pins.items():
 p=control/name if name=='controller.py' else control/'tools'/name
 st=p.lstat()
 assert p.resolve()==p and stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o600
 assert re.fullmatch('[a-f0-9]{64}',pin) and hashlib.sha256(p.read_bytes()).hexdigest()==pin
sys.path[:0]=[str(control),str(control/'tools')]
from controller import control_inventory
control_inventory(root)
"""
    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(root)],stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=False)
    require(result.returncode==0,'Adopted controller verification failed')


def retire_update_backup(root, manifest, context, previous, policy):
    """Remove only the authenticated predecessor; retain its policy until last."""
    update_phase('backup_inventory')
    backup=root/'tmp/controller-update';current=root/'tmp/controller'
    if not backup.exists() and not backup.is_symlink():return
    def inventory(directory):
        st=directory.lstat()
        require(directory.resolve()==directory and stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700,'Unsafe update controller directory')
        # Historical install normalized policy-pinned tools to 0700. Older
        # public authorization ancestors could inherit umask 022; neither
        # compatibility applies to arbitrary members or writable directories.
        local_policy={}
        policy_file=directory/'policy.json'
        if policy_file.exists() or policy_file.is_symlink():
            pst=policy_file.lstat()
            require(stat.S_ISREG(pst.st_mode) and pst.st_nlink==1 and pst.st_uid==os.geteuid()
                    and stat.S_IMODE(pst.st_mode)==0o600 and pst.st_size<=1024*1024,'Unsafe update policy metadata')
            local_policy=json.loads(policy_file.read_bytes());enrolled_engine(local_policy)
        executable={'tools/'+name for name in local_policy.get('engine_files',{}) if name!='controller.py'}
        public_dirs=set()
        for name in local_policy.get('authorization_files',{}):
            relative=Path('authorization/inputs')/name
            require(not Path(name).is_absolute() and '..' not in Path(name).parts,'Unsafe public input namespace')
            public_dirs.update(parent.as_posix() for parent in relative.parents if parent!=Path('.'))
        entries={};total=0
        for parent,dirs,files in os.walk(directory,followlinks=False):
            require(len(entries)+len(dirs)+len(files)<=256,'Update controller inventory capacity exceeded')
            for name in dirs+files:
                path=Path(parent)/name;st=path.lstat();relative=path.relative_to(directory).as_posix()
                modes=((0o700,0o755) if relative in public_dirs else (0o700,)) if stat.S_ISDIR(st.st_mode) else ((0o600,0o700) if relative in executable else (0o600,))
                require(st.st_uid==os.geteuid() and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode) and st.st_nlink==1)
                        and stat.S_IMODE(st.st_mode) in modes,'Unsafe update controller member')
                if stat.S_ISREG(st.st_mode):
                    total+=st.st_size
                    require(total<=32*1024*1024,'Update controller byte inventory capacity exceeded')
                entries[relative]=None if stat.S_ISDIR(st.st_mode) else hashlib.sha256(path.read_bytes()).hexdigest()
        return entries
    actual=inventory(backup);live=inventory(current)
    if not actual:
        update_phase('cleanup')
        backup.rmdir()
        descriptor=os.open(root/'tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        return
    update_phase('backup_policy')
    original_path=backup/'policy.json'
    require(actual.get('policy.json') is not None,'Original update policy required for reconciliation')
    original=json.loads(original_path.read_bytes())
    enrolled_engine(original)
    expected=json.loads(json.dumps(original))
    expected['engine_files']={name:manifest['files']['tools/'+name] for name in engine_names(manifest['files'])}
    expected['releases'][manifest['release_id']]={'manifest_sha256':context['manifest_sha256'],'inventory_authenticated':True,'networks':{previous['network_id']:previous['chain_id']}}
    expected['engineering_update']={'initial_sha256':context['initial_sha256'],'parent_sha256':context['parent_sha256'],
        'formation_sha256':context['formation_sha256'],'previous_selection':previous,
        'selection':{**previous,'release_id':manifest['release_id'],'manifest_sha256':context['manifest_sha256']},
        'request_sha256':hashlib.sha256(json.dumps({'version':1,'operation':'update_stage','parameters':{'release_id':manifest['release_id'],'manifest_sha256':context['manifest_sha256']}},sort_keys=True,separators=(',',':')).encode()).hexdigest()}
    require(expected==policy,'Update backup does not match the exact adopted policy')
    update_phase('backup_members')
    allowed=dict(live)
    allowed['policy.json']=actual['policy.json']
    for name in engine_names(manifest['files']):
        relative=name if name=='controller.py' else 'tools/'+name
        allowed.pop(relative,None)
    for name,pin in original['engine_files'].items():
        require(name in enrolled_engine(original),'Unknown predecessor engine')
        allowed[name if name=='controller.py' else 'tools/'+name]=pin
    require(all(name in allowed and allowed[name]==pin for name,pin in actual.items()),'Update backup member is outside the exact predecessor')
    update_phase('cleanup')
    # Missing members are allowed only for resuming this already-attributed cleanup.
    for name,value in sorted(actual.items(),key=lambda row:-len(Path(row[0]).parts)):
        if name=='policy.json':continue
        path=backup/name
        if value is None:path.rmdir()
        else:path.unlink()
    original_path.unlink();backup.rmdir()
    descriptor=os.open(root/'tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)


def guest_management_quiescence(root,policy,process_guard,vpn_pid=None,proc=Path('/proc')):
    """Exclude only the enrolled-engine-attributed guest, never a validator."""
    if not isinstance(policy.get('managed_guest'),dict):return process_guard(root,vpn_pid=vpn_pid,proc=proc)
    from guest_lifecycle import GuestManager
    guest=GuestManager(root,policy);guest.verify_guard()
    observed=guest.status({'guest_id':guest.spec['guest_id']})
    pid=str(observed.get('pid',0))
    if pid=='0':return process_guard(root,vpn_pid=vpn_pid,proc=proc)
    # status authenticated exact /proc executable/argv; preserve that check on
    # both sides of the complete remaining-process scan.
    version=guest.receipt().get('runtime_version',1)
    if version==1:guest.verify_process(pid) # Legacy API defaults to its v1 argv.
    else:guest.verify_process(pid,version)
    class GuestProcessView:
        def __truediv__(self,value):return proc/value
        def iterdir(self):return (p for p in proc.iterdir() if p.name!=pid)
    process_guard(root,vpn_pid=vpn_pid,proc=GuestProcessView())
    after=guest.status({'guest_id':guest.spec['guest_id']})
    require(after==observed,'Managed guest changed during process verification')


def update_commission_grant(root,policy,now):
    """Read-only attribution of one expired, unused public-transport permission."""
    from controller import Controller,request_digest,HOST_REMOVAL,VPN_ENROLLMENT,MUTATIONS
    import lifecycle as life
    c=Controller(root);control=c.control
    for path in (control/HOST_REMOVAL,control/VPN_ENROLLMENT,root/life.UPGRADE_INTENT):
        require(not path.exists() and not path.is_symlink(),'Outstanding operator mutation')
    update_phase('grant_scope')
    paths=list((control/'grants').iterdir())
    if not paths:return None
    from apqe_layout import FORMATION_PUBLIC_INPUTS
    key=request_digest({'version':1,'operation':'commission','parameters':{}})
    require(len(paths)==1 and paths[0].name==key+'.json','Unknown outstanding request')
    grant_path=c.direct(paths[0],True,65536);raw=grant_path.read_bytes();grant=json.loads(raw)
    auth=policy.get('engineering_authorization',{})
    require(type(auth.get('sequence')) is int and auth['sequence']>0
        and isinstance(auth.get('sha256'),str) and re.fullmatch('[a-f0-9]{64}',auth['sha256'])
        and type(auth.get('expires_at')) is int and 0<auth['expires_at']<=now
        and grant=={'root':str(root),'operation':'commission','request_sha256':key,'expires_at':auth['expires_at'],
                    'authorization_sha256':auth['sha256'],'authorization_sequence':auth['sequence']},
        'Only the exact expired unused commissioning grant may be preserved')
    update_phase('grant_artifacts')
    pins=policy.get('validator_commissioning_files')
    require(isinstance(pins,dict) and set(pins)==FORMATION_PUBLIC_INPUTS,'Complete commissioning approval required')
    for name,pin in pins.items():
        require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin)
                and policy.get('authorization_files',{}).get('commissioning/'+name)==pin,
                'Commissioning approval differs')
        path=c.direct(control/'authorization/inputs/commissioning'/name,True,4*1024*1024)
        require(hashlib.sha256(path.read_bytes()).hexdigest()==pin,'Approved commissioning bytes changed')
    require(all(pins['network/'+name]==pin for name,pin in c.genesis_pins().items()),'Commissioning Genesis differs')
    update_phase('grant_audit')
    audit=control/'audit.jsonl'
    if audit.exists() or audit.is_symlink():
        rows=c.direct(audit,True,1024*1024).read_bytes().splitlines()
        require(len(rows)<=4096,'Commissioning audit exceeds bound')
        for line in rows:
            row=json.loads(line)
            require(isinstance(row,dict) and set(row)=={'request_sha256','operation','time'}
                    and isinstance(row['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',row['request_sha256'])
                    and row['operation'] in MUTATIONS and type(row['time']) is int and 0<=row['time']<=now,
                    'Malformed commissioning audit')
            require(row['request_sha256']!=key and row['operation']!='commission','Commissioning request was consumed')
    update_phase('grant_state')
    require(not any((root/name).exists() or (root/name).is_symlink() for name in (
        'data','tmp/commissioning','tmp/existing-network-identity-request.json',
        'evidence/application-replacement-intent.json','evidence/authority-recovery-intent.json',
        'evidence/autonomous-epoch-intent.json')) and not any((root/'tmp').glob('commission-prepare-*'))
        and not any((root/'tmp').glob('commission-observe-*'))
        and all((root/name).is_dir() and not (root/name).is_symlink() and not any((root/name).iterdir()) for name in ('config','network')),
        'Published or partial commissioning state cannot preserve a grant')
    life._commission_fresh_keys(root)
    require(c.policy()==policy,'Commissioning policy changed')
    return {'request_sha256':key,'grant_sha256':hashlib.sha256(raw).hexdigest(),'expires_at':grant['expires_at'],
            'commissioning_sha256':hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest()}


def inspect_update_commission_grant(wire):
    import time
    require(isinstance(wire,dict) and set(wire)=={'context','challenge'},'Exact preservation proof required')
    context=wire['context'];now=int(time.time())
    require(isinstance(context,dict) and set(context)=={'initial_sha256','parent_sha256','formation_sha256','target','selection','expires_at'}
        and type(context['expires_at']) is int and now<=context['expires_at']<=now+300,'Preservation review expired')
    require(all(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) for value in (wire['challenge'],context['initial_sha256'],context['parent_sha256'],context['formation_sha256']))
        and context['initial_sha256']==globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256'),'Native preservation scope required')
    root=ROOT;control=root/'tmp/controller';path=control/'policy.json'
    for ancestor in (control,*control.parents):
        m=ancestor.lstat();require(stat.S_ISDIR(m.st_mode) and not ancestor.is_symlink() and m.st_uid==os.geteuid() and not m.st_mode&0o022,'Unsafe preservation ancestry')
    m=path.lstat();require(stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid() and stat.S_IMODE(m.st_mode)==0o600 and m.st_size<=1024*1024,'Unsafe preservation policy')
    policy=json.loads(path.read_bytes())
    for name in enrolled_engine(policy):
        p=control/name if name=='controller.py' else control/'tools'/name;m=p.lstat()
        require(p.resolve()==p and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid() and not m.st_mode&0o022
                and m.st_size<=1024*1024 and hashlib.sha256(p.read_bytes()).hexdigest()==policy['engine_files'][name],'Preservation engine drift')
    sys.path[:0]=[str(control),str(control/'tools')]
    from controller import Controller,control_inventory
    import lifecycle as life
    with life._lifecycle_lock(root):
        control_inventory(root);receipt,_=life._sealed_receipt(root)
        require(context['initial_sha256']==policy.get('engineering_initial_authorization_sha256')
                and context['parent_sha256']==policy.get('engineering_authorization',{}).get('sha256')
                and context['formation_sha256']==policy.get('validator_formation_sha256')
                and context['target']==policy.get('engineering_target') and context['selection']==effective_engineering_selection(root,policy)
                and receipt['package_sha256']==context['selection']['manifest_sha256'],'Preservation scope changed')
        state=life._unit_state('synergy-node.service');vpn=life._unit_state('synergy-vpn.service')
        require(state.get('MainPID')=='0' and state.get('ActiveState') in ('inactive','failed'),'Stop validator before preservation review')
        guest_management_quiescence(root,policy,life._assert_no_application_processes,vpn.get('MainPID'))
        preservation=update_commission_grant(root,policy,now)
        require(Controller(root).policy()==policy,'Preservation policy changed')
        return {'schema':'nodenetwork-update-commission-grant-v1','challenge':wire['challenge'],
                'parent_sha256':context['parent_sha256'],'authorization_sequence':policy['engineering_authorization']['sequence'],
                'preservation':preservation,'mutation_performed':False}


def stage_engineering_update(stream, release_id, pin, reconcile=False):
    """Adopt authenticated software/controller only; no upgrade grant or runtime change."""
    import ctypes
    import fcntl
    import time
    update_phase('entry')
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64','Linux x86_64 root target required')
    require(re.fullmatch(r'[a-zA-Z0-9._-]{1,128}',release_id) and re.fullmatch(r'[a-f0-9]{64}',pin),'Exact update release and manifest pin required')
    require(ROOT.resolve()==ROOT and stat.S_IMODE(ROOT.lstat().st_mode)==0o700 and ROOT.stat().st_uid==0,'Private canonical installation required')
    os.umask(0o077)
    root=ROOT
    old=root/'tmp/controller'
    pending=root/'tmp/update-master'
    replacement=root/'tmp/controller-update'
    update_phase('engine')
    # Import the enrolled engine only after independently checking its pins.
    policy_path=old/'policy.json'
    require(policy_path.resolve()==policy_path and stat.S_IMODE(policy_path.lstat().st_mode)==0o600
            and policy_path.stat().st_uid==0,'Unsafe host policy')
    policy=json.loads(policy_path.read_bytes())
    for name in enrolled_engine(policy):
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
        update_phase('receipt')
        receipt,_=_sealed_receipt(root)
        network=receipt['network_id']
        previous=effective_engineering_selection(root,policy)
        update_phase('context')
        context=engineering_update_context(policy,previous,release_id,pin,int(time.time()))
        require(receipt.get('role')=='validator'
                and all(receipt.get(key)==previous[key] for key in ('network_id','chain_id','node_name')),
                'Installed validator differs from the independently approved engineering selection')
        update_phase('namespace')
        control_inventory(root)
        update_phase('requests')
        preservation=update_commission_grant(root,policy,int(time.time()))
        require(('commission_grant_preservation' not in context and preservation is None)
                or (preservation is not None and context.get('commission_grant_preservation')==preservation),
                'Outstanding commissioning grant needs exact native preservation review')
        update_phase('quiescence')
        status=_unit_state('synergy-node.service')
        require(status.get('MainPID','0')=='0' and status.get('ActiveState') in ('inactive','failed'),
                'Stop the validator before adopting an update')
        vpn=_unit_state('synergy-vpn.service')
        guest_management_quiescence(root,policy,_assert_no_application_processes,vpn.get('MainPID'))
        if reconcile:
            update_phase('package')
            require(pending.resolve()==pending and pending.is_dir(),'Exact staged package required')
            manifest=verify_package(pending)
            require(hashlib.sha256((pending/'package.json').read_bytes()).hexdigest()==pin and manifest['release_id']==release_id,'Staged package differs from native review')
            update_phase('adoption')
            expected_update={'initial_sha256':context['initial_sha256'],'parent_sha256':context['parent_sha256'],
                'formation_sha256':context['formation_sha256'],'previous_selection':previous,
                'selection':{**previous,'release_id':release_id,'manifest_sha256':pin},
                'request_sha256':__import__('controller').request_digest({'version':1,'operation':'update_stage','parameters':{'release_id':release_id,'manifest_sha256':pin}})}
            require(policy.get('engineering_update')==expected_update
                    and policy.get('engine_files')=={name:manifest['files']['tools/'+name] for name in engine_names(manifest['files'])}
                    and policy.get('releases',{}).get(release_id)=={'manifest_sha256':pin,'inventory_authenticated':True,'networks':{previous['network_id']:previous['chain_id']}},
                    'Exact interrupted update adoption required')
            update_phase('verifier')
            verify_adopted_controller(root)
            retire_update_backup(root,manifest,context,previous,policy)
            return {'schema':'nodenetwork-update-stage-v1','stagedRelease':release_id,'manifestSha256':pin,'controllerAdopted':True,'validatorUpgraded':False,'initial_sha256':context['initial_sha256'],'parent_sha256':context['parent_sha256']}
        superseded=globals().get('NATIVE_AUTHENTICATED_SUPERSEDED_UPGRADE')
        if superseded is not None:
            require(superseded is True and globals().get('NATIVE_AUTHENTICATED_MANIFEST_SHA256')==pin,
                    'Superseded staging lacks independent native approval')
            require(not replacement.exists() and not replacement.is_symlink(),'Prior controller exchange requires reconciliation')
            line=stream.readline(2*1024*1024+1)
            require(0<len(line)<=2*1024*1024 and line.endswith(b'\n'),'Superseded proof exceeds bound')
            proof=json.loads(line)
            require(proof.get('context')=={key:context[key] for key in ('initial_sha256','parent_sha256','formation_sha256','target','selection','expires_at')}
                    and proof.get('adoption')==policy.get('engineering_update')
                    and proof['request']['parameters']!={'release_id':release_id,'manifest_sha256':pin},
                    'Superseded proof changes native update scope')
            upgrade_not_applied_proof(proof,_already_locked=True,_retiring=True)
            retire_superseded_update(root,proof['adoption']['selection'])
        require(not any(p.exists() or p.is_symlink() for p in (pending,replacement)),'Prior update staging requires reconciliation')
        pending.mkdir(mode=0o700)
        exchanged=False
        try:
            update_phase('package')
            manifest=extract(stream,pending,{'manifest_sha256':pin,'release_id':release_id})
            require(verify_executable_stage(pending)==manifest,'Candidate verification differs')
            validate_guard_update(root,policy,receipt,manifest,pending)
            shutil.copytree(old,replacement)
            for name in engine_names(manifest['files']):
                target=replacement/name if name=='controller.py' else replacement/'tools'/name
                if target.exists():target.unlink()
                save(target,(pending/'tools'/name).read_bytes())
            policy['engine_files']={name:manifest['files']['tools/'+name] for name in engine_names(manifest['files'])}
            releases=policy['releases']
            selected={'manifest_sha256':pin,'inventory_authenticated':True,'networks':{network:receipt['chain_id']}}
            require(release_id not in releases or releases[release_id]==selected,'Release ID already names another inventory')
            releases[release_id]=selected
            policy['engineering_update']={'initial_sha256':context['initial_sha256'],
                'parent_sha256':context['parent_sha256'],'formation_sha256':context['formation_sha256'],
                'previous_selection':previous,'selection':{**previous,'release_id':release_id,'manifest_sha256':pin},
                'request_sha256':__import__('controller').request_digest({'version':1,'operation':'update_stage','parameters':{'release_id':release_id,'manifest_sha256':pin}})}
            (replacement/'policy.json').unlink()
            save(replacement/'policy.json',json.dumps(policy,sort_keys=True).encode())
            for path in sorted(replacement.rglob('*'),key=lambda p:-len(p.parts)):
                if path.is_dir():_sync_directory(path)
                else:
                    with path.open('rb') as f:os.fsync(f.fileno())
            _sync_directory(replacement)
            _sync_directory(root/'tmp')
            # Keep all fixed SSH, sudo, and authorized-key paths resolvable.
            update_phase('exchange')
            exchange=ctypes.CDLL(None,use_errno=True).renameat2
            exchange.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
            exchange.restype=ctypes.c_int
            if exchange(-100,os.fsencode(old),-100,os.fsencode(replacement),2):
                raise OSError(ctypes.get_errno(),'Controller directory exchange failed')
            exchanged=True
            _sync_directory(root/'tmp')
            update_phase('verifier')
            verify_adopted_controller(root)
            retire_update_backup(root,manifest,context,previous,policy)
            _sync_directory(root/'tmp')
        except Exception:
            if not exchanged:
                if replacement.exists():shutil.rmtree(replacement)
                shutil.rmtree(pending)
                _sync_directory(root/'tmp')
            raise
        return {'schema':'nodenetwork-update-stage-v1','stagedRelease':release_id,'manifestSha256':pin,'controllerAdopted':True,'validatorUpgraded':False,'initial_sha256':context['initial_sha256'],'parent_sha256':context['parent_sha256']}
    finally:
        os.close(lock)



# Only an independently pinned isolated native build can authorize this path.
# The document is not a public policy issuer, membership proof or credential API.
AUTHORIZATION_PROFILE='nodenetwork-isolated-formation-authorization-v1'
AUTHORIZATION_LIMIT=12*1024*1024
AUTHORIZATION_FILES={'network-provisioning.json':16384,'gateway-purpose.json':16384,'commissioning-readiness.json':128*1024,'managed-guest.json':16384,'formation-context.json':4096,'vpn-ca.pem':128*1024,'vpn-provider.json':16384,'vpn-enrollment.json':16384,'vpn-server-binding.json':16384,'vpn-retirement.json':16384,'vpn-unused-cancellation.json':16384,
    'commissioning/config/node.json':1024*1024,'commissioning/config/start-authorized.json':65536,
    **{'commissioning/network/'+name:limit for name,limit in {
        'genesis.json':4*1024*1024,'authority.json':1024*1024,'authority-root.pub':8192,
        'network-manifest.json':1024*1024,'transport-registry.json':1024*1024,'transport-root.pub':8192}.items()}}


def guest_target_binding(guest):
    import base64
    require(isinstance(guest,dict) and set(guest)=={'guest_id','create_request_sha256','ssh_host_public_key','ssh_host_fingerprint'}
            and isinstance(guest['guest_id'],str) and re.fullmatch('[a-z][a-z0-9-]{0,31}',guest['guest_id'])
            and isinstance(guest['create_request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',guest['create_request_sha256'])
            and isinstance(guest['ssh_host_public_key'],str) and len(guest['ssh_host_public_key'])<=128,
            'Exact managed guest target binding required')
    parts=guest['ssh_host_public_key'].split(' ')
    require(len(parts)==2 and parts[0]=='ssh-ed25519','Managed guest public SSH key is not canonical')
    raw=base64.b64decode(parts[1],validate=True)
    require(len(raw)==51 and raw[:19]==b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 '
            and base64.b64encode(raw).decode()==parts[1]
            and guest['ssh_host_fingerprint']=='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='),
            'Managed guest public identity and fingerprint differ')
    return guest


def verify_guest_local_ssh(guest):
    guest_target_binding(guest)
    path=Path('/etc/ssh/ssh_host_ed25519_key.pub');metadata=path.lstat()
    require(path.resolve()==path and stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0
            and metadata.st_nlink==1 and not metadata.st_mode&0o022 and metadata.st_size<=1024,
            'Managed guest local public SSH key is unsafe')
    parts=path.read_text(encoding='ascii').split()
    require(len(parts)>=2 and ' '.join(parts[:2])==guest['ssh_host_public_key'],
            'Managed guest local SSH identity differs from its authenticated physical-host receipt')


def authorization_document(raw,authenticated_pin,now):
    import base64
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'Duplicate authorization field');value[key]=item
        return value
    require(isinstance(raw,str) and 0<len(raw.encode())<=65536 and
            hashlib.sha256(raw.encode()).hexdigest()==authenticated_pin,
            'Authorization differs from independent native approval')
    doc=json.loads(raw,object_pairs_hook=unique)
    fields={'version','profile','target','release_id','manifest_sha256','network_id','chain_id','node_name',
            'sequence','expires_at','artifacts','requests','genesis_pins'}
    require(isinstance(doc,dict) and set(doc)==fields and type(doc['version']) is int and doc['version']==1
            and doc['profile']==AUTHORIZATION_PROFILE,'Unsupported engineering authorization')
    target=doc['target']
    base_target={'kind','host','port','root','host_key','machine_id_sha256'}
    require(isinstance(target,dict) and set(target) in (base_target,base_target|{'guest'})
            and target['root']==str(ROOT),'Authorization target differs')
    if 'guest' in target:
        guest_target_binding(target['guest'])
        require(target['kind']=='remote','Managed guests require an authenticated physical host')
    require(target['kind'] in ('local','remote'),'Unsupported authorization target')
    if target['kind']=='local':
        require(target['host'] is None and target['port'] is None and target['host_key'] is None\
                and isinstance(target['machine_id_sha256'],str) and re.fullmatch('[a-f0-9]{64}',target['machine_id_sha256']),'Exact local machine identity required')
    else:
        require(target['machine_id_sha256'] is None,'Remote target identity must use its independently pinned SSH key')
        require(isinstance(target['host'],str) and 0<len(target['host'])<=253
                and re.fullmatch(r'[a-zA-Z0-9.:\[\]-]+',target['host'])
                and type(target['port']) is int and 0<target['port']<65536,'Invalid remote target')
        label=target['host'].strip('[]')
        label=label if target['port']==22 else '['+label+']:'+str(target['port'])
        require(isinstance(target['host_key'],str) and len(target['host_key'])<2048
                and re.fullmatch(re.escape(label)+r' ssh-ed25519 [A-Za-z0-9+/]{68}={0,2}',target['host_key']),
                'Exact independently pinned administrative host key required')
    require(isinstance(doc['release_id'],str) and re.fullmatch('[A-Za-z0-9._-]{1,128}',doc['release_id'])
            and isinstance(doc['manifest_sha256'],str) and re.fullmatch('[a-f0-9]{64}',doc['manifest_sha256'])
            and isinstance(doc['network_id'],str) and re.fullmatch('[a-z0-9][a-z0-9_-]{1,127}',doc['network_id'])
            and type(doc['chain_id']) is int and 0<doc['chain_id']<2**64
            and isinstance(doc['node_name'],str) and re.fullmatch('[A-Za-z0-9_-]{1,64}',doc['node_name']),
            'Invalid selected installation context')
    require(type(doc['sequence']) is int and 0<doc['sequence']<2**53
            and type(doc['expires_at']) is int and now<doc['expires_at']<=now+3600,'Authorization expired or exceeds lifetime')
    require(isinstance(doc['artifacts'],dict) and set(doc['artifacts'])<=set(AUTHORIZATION_FILES)
            and all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in doc['artifacts'].values()),
            'Only fixed, digest-bound authorization artifacts are allowed')
    pins=doc['genesis_pins']
    require(pins is None or isinstance(pins,dict) and set(pins)=={'genesis.json','authority.json','authority-root.pub'}
            and all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in pins.values()),'Invalid independent Genesis pins')
    require(isinstance(doc['requests'],list) and 0<len(doc['requests'])<=16,'Bounded exact requests required')
    # Request semantics are checked again against the enrolled canonical engine.
    require(all(isinstance(r,dict) and set(r)=={'operation','request_sha256'}\
                and isinstance(r['operation'],str) and isinstance(r['request_sha256'],str)\
                and re.fullmatch('[a-f0-9]{64}',r['request_sha256']) for r in doc['requests']),
            'Exact controller operation and request digests required')
    return doc


def authorization_inputs(doc,encoded):
    import base64
    require(isinstance(encoded,dict) and set(encoded)==set(doc['artifacts']),'Authorization artifacts incomplete')
    result={}
    for name,pin in doc['artifacts'].items():
        text=encoded[name];limit=AUTHORIZATION_FILES[name]
        require(isinstance(text,str) and len(text)<=4*((limit+2)//3),'Authorization artifact exceeds bound')
        data=base64.b64decode(text,validate=True)
        require(0<len(data)<=limit and base64.b64encode(data).decode()==text
                and hashlib.sha256(data).hexdigest()==pin,'Authorization artifact digest or encoding differs')
        result[name]=data
    gateway_install=any(row['operation']=='gateway_install' for row in doc['requests'])
    profile_raw=result.get('network-provisioning.json')
    if profile_raw is not None:
        require(gateway_install, 'Gateway network settings require the exact initial installation grant')
        from synergy_linux import network_provisioning_profile
        profile=network_provisioning_profile(json.loads(profile_raw), dict(doc, role='rpc_gateway'))
        require(all(doc['artifacts'].get('commissioning/network/'+name)==pin for name,pin in profile['origin'].items()),
                'Network profile origin differs from the approved signed files')
    if gateway_install:
        names={'commissioning/network/'+name for name in ('genesis.json','authority.json','authority-root.pub','network-manifest.json','transport-registry.json','transport-root.pub')}
        expected=names|{'formation-context.json'}
        if profile_raw is not None:expected.add('network-provisioning.json')
        require(set(result)==expected and len(doc['requests'])==1 and isinstance(doc['genesis_pins'],dict)
                and all(doc['genesis_pins'].get(name)==doc['artifacts'].get('commissioning/network/'+name) for name in ('genesis.json','authority.json','authority-root.pub')),
                'Gateway installation requires only its exact public formation and six-file origin with one gateway grant')
    if 'gateway-purpose.json' in result:
        require(set(result)=={'gateway-purpose.json'} and len(doc['requests'])==1
                and doc['requests'][0]['operation']=='gateway_admission_prepare',
                'Gateway purpose requires its one exact prepare grant only')
        purpose=json.loads(result['gateway-purpose.json'])
        fields={'format','purpose','formation_sha256','transport_review_sha256','issuer_root_sha256','gateway_enrollment_sha256',
                'genesis_sha256','authority_sha256','registry_sha256','valid_from_unix','expires_at_unix'}
        require(isinstance(purpose,dict) and set(purpose)==fields and purpose['format']=='synergy-engineering-gateway-purpose-v1'
                and purpose['purpose']=='engineering-rpc-gateway-admission-v1'
                and all(isinstance(purpose[k],str) and re.fullmatch('[a-f0-9]{64}',purpose[k]) for k in fields-{'format','purpose','valid_from_unix','expires_at_unix'})
                and type(purpose['valid_from_unix']) is int and type(purpose['expires_at_unix']) is int
                and 0<purpose['valid_from_unix']<purpose['expires_at_unix']<2**53
                and purpose['expires_at_unix']-purpose['valid_from_unix']<=7*86400,
                'Exact isolated gateway additional-purpose approval required')
    if 'commissioning-readiness.json' in result:
        # This public evidence cannot carry configuration or any other grant.
        expected=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},
            sort_keys=True,separators=(',',':')).encode()).hexdigest()
        require(set(result)=={'commissioning-readiness.json'} and doc['requests']==[
            {'operation':'commission','request_sha256':expected}],
            'Readiness requires its one exact commissioning grant only')
    return result



def readiness_refresh_allowed(root,policy,doc,inputs,continuation,consumed):
    """Refresh only exact unused prestart readiness under the controller exchange lock."""
    name='commissioning-readiness.json';root=Path(root)
    source=root/'tmp/controller/authorization/inputs'/name
    if name not in inputs:return False
    from controller import Controller,request_digest
    c=Controller(root)
    present=source.exists() or source.is_symlink()
    pinned=name in policy.get('authorization_files',{})
    require(present==pinned,'Prior readiness artifact and approval are incomplete')
    first=not present
    if present:
        raw=c.direct(source,True,128*1024).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==policy['authorization_files'][name],
                'Prior readiness artifact differs from approved policy')
    require(continuation and set(inputs)=={name}
            and doc['target']==policy['engineering_target']
            and all(doc[k]==effective_engineering_selection(root,policy)[k] for k in ('release_id','manifest_sha256','network_id','chain_id','node_name'))
            and doc['genesis_pins']==policy.get('validator_identity_network'),
            'Readiness refresh changes its approved target or network')
    from apqe_layout import FORMATION_PUBLIC_INPUTS
    approved=policy.get('validator_commissioning_files',{})
    require(set(approved)==FORMATION_PUBLIC_INPUTS,'Exact existing commissioning input approval required')
    for name,expected in approved.items():
        path=c.direct(c.control/'authorization/inputs/commissioning'/name,True,4*1024*1024)
        require(hashlib.sha256(path.read_bytes()).hexdigest()==expected,'Existing commissioning input changed')
    key=request_digest({'version':1,'operation':'commission','parameters':{}})
    require(doc['requests']==[{'operation':'commission','request_sha256':key}] and key not in consumed,
            'Consumed or foreign commissioning review cannot be refreshed')
    previous=policy['engineering_authorization']
    grant_path=c.control/'grants'/(key+'.json')
    # A completed software authorization may retire the expired transport grant.
    # Only the first readiness addition may supply that still-unaudited request.
    if not first or grant_path.exists() or grant_path.is_symlink():
        grant=c.public_json(grant_path,True)
        require(grant=={'root':str(root),'operation':'commission','request_sha256':key,
            'expires_at':previous['expires_at'],'authorization_sha256':previous['sha256'],
            'authorization_sequence':previous['sequence']},'Original commissioning grant is absent, consumed or changed')
    require(not any((root/path).exists() or (root/path).is_symlink() for path in (
        'data','tmp/commissioning','tmp/existing-network-identity-request.json',
        'evidence/upgrade-intent.json','evidence/application-replacement-intent.json',
        'evidence/authority-recovery-intent.json','evidence/autonomous-epoch-intent.json'))
        and not any((root/'tmp').glob('commission-prepare-*')) and not any((root/'tmp').glob('commission-observe-*'))
        and all((root/name).is_dir() and not any((root/name).iterdir()) for name in ('config','network')),
        'Readiness refresh refuses published or uncertain application state')
    from lifecycle import _commission_fresh_keys
    _commission_fresh_keys(root)
    return True


def authorization_reconciliation(policy,pin,raw):
    previous=policy.get('engineering_authorization')
    require(previous is None or isinstance(previous,dict) and set(previous)=={'sha256','sequence','expires_at'}
            and isinstance(previous['sha256'],str) and re.fullmatch('[a-f0-9]{64}',previous['sha256'])
            and type(previous['sequence']) is int and previous['sequence']>0,'Invalid prior authorization receipt')
    if previous is None or previous['sha256']!=pin:return None
    require(isinstance(raw,str) and hashlib.sha256(raw.encode()).hexdigest()==pin,'Authorization bytes differ')
    return {'schema':'nodenetwork-engineering-authorization-v1',**previous,
            'applied':True,'reconciled':True,'grants_recreated':False}


def authorization_tree_digest(directory):
    # Previous controller contains no one-use VPN input (checked before staging).
    # This digest permits cleanup only of the exact exchanged predecessor tree.
    digest=hashlib.sha256();members=sorted(directory.rglob('*'));total=0
    require(len(members)<=8192,'Controller predecessor inventory exceeds bound')
    for path in members:
        st=path.lstat()
        require(st.st_uid==0 and not stat.S_ISLNK(st.st_mode)
                and (stat.S_ISREG(st.st_mode) and st.st_nlink==1 or stat.S_ISDIR(st.st_mode)),
                'Unsafe controller predecessor')
        name=path.relative_to(directory).as_posix().encode()
        digest.update(len(name).to_bytes(8,'big'));digest.update(name)
        digest.update(stat.S_IMODE(st.st_mode).to_bytes(4,'big'))
        if path.is_file():
            total+=st.st_size;require(total<=16*1024*1024,'Controller predecessor exceeds bound')
            digest.update(st.st_size.to_bytes(8,'big'));digest.update(hashlib.sha256(path.read_bytes()).digest())
        else:digest.update(b'directory')
    return digest.hexdigest()


def active_guest_policy_only(continuation,inputs,doc,policy):
    # This exception changes only contained guest policy/grant, never the
    # running validator's Genesis, identity, configuration or current master.
    return (continuation and set(inputs)=={'managed-guest.json'}
            and len(doc['requests'])==1 and doc['requests'][0]['operation']=='guest_create'
            and doc['genesis_pins']==policy.get('validator_identity_network')
            and 'guest' not in doc['target'])


def gateway_issuer_policy_only(root,continuation,inputs,doc,policy):
    if not (continuation and len(doc['requests'])==1 and doc['genesis_pins']==policy.get('validator_identity_network')):return False
    op=doc['requests'][0]['operation']
    if not (op=='gateway_admission_prepare' and set(inputs)=={'gateway-purpose.json'} or op=='gateway_admission_sign' and not inputs):return False
    from controller import Controller
    from canary_rpc_relay import _gateway_scope,_gateway_approval
    c=Controller(root);_,scope,review,_,_=_gateway_scope(c)
    if op=='gateway_admission_sign':_gateway_approval(c,policy,scope,review)
    else:
        a=json.loads(inputs['gateway-purpose.json'])
        require(all(a[k]==scope[k] for k in ('formation_sha256','genesis_sha256','authority_sha256','registry_sha256'))
                and a['transport_review_sha256']==review['review_sha256'] and a['issuer_root_sha256']==review['issuer_root_sha256'],
                'Gateway purpose changes the exact installed owner origin')
    from lifecycle import _attributed_units
    _attributed_units(root)
    return True


def transport_authorization(continuation,inputs,doc,policy):
    names={n for n in AUTHORIZATION_FILES if n.startswith('commissioning/')}
    key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return (continuation and set(inputs)==names and set(doc['artifacts'])==names
        and doc['requests']==[{'operation':'commission','request_sha256':key}]
        and isinstance(doc['genesis_pins'],dict) and set(doc['genesis_pins'])=={'genesis.json','authority.json','authority-root.pub'} and doc['genesis_pins']==policy.get('validator_identity_network')
        and all(doc['artifacts']['commissioning/network/'+n]==v for n,v in doc['genesis_pins'].items()))


def stage_engineering_authorization(stream):
    """Atomic exact engineering grants through the native application's admin transport.

    No renderer pin or package content can authorize itself. Repeating an applied
    document returns the durable receipt without recreating a consumed grant.
    """
    import ctypes
    import fcntl
    import time
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64','Linux x86_64 root required')
    os.umask(0o077)
    raw=stream.read(AUTHORIZATION_LIMIT+1)
    require(0<len(raw)<=AUTHORIZATION_LIMIT,'Authorization transfer exceeds bound')
    wire=json.loads(raw)
    require(isinstance(wire,dict) and set(wire)=={'authorization','artifacts'},'Invalid authorization transfer')
    pin=globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256')
    require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),'No independent native authorization')
    require(ROOT.resolve()==ROOT and ROOT.stat().st_uid==0 and stat.S_IMODE(ROOT.stat().st_mode)==0o700,'Private canonical root required')
    old=ROOT/'tmp/controller';replacement=ROOT/'tmp/controller-authorization'
    # Authenticate the installed engine before importing privileged code.
    for ancestor in (old,*old.parents):
        st=ancestor.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and not st.st_mode&0o022,'Unsafe controller ancestry')
    policy_path=old/'policy.json';st=policy_path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o600
            and st.st_size<=1024*1024,'Unsafe enrolled policy')
    policy=json.loads(policy_path.read_bytes())
    for name in enrolled_engine(policy):
        path=old/name if name=='controller.py' else old/'tools'/name
        require(path.resolve()==path and path.is_file() and path.stat().st_uid==0 and not path.stat().st_mode&0o022 and path.stat().st_nlink==1
                and hashlib.sha256(path.read_bytes()).hexdigest()==policy['engine_files'][name],'Enrolled engine drift')
    sys.path[:0]=[str(old),str(old/'tools')]
    from controller import Controller, control_inventory, parse_request, request_digest, sync_directory, HOST_REMOVAL, VPN_ENROLLMENT
    from lifecycle import _unit_state, _assert_no_application_processes
    lock=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        control_inventory(ROOT)
        policy=Controller(ROOT).policy()
        # Read-only reconciliation precedes expiration checks; never grants twice.
        previous=policy.get('engineering_authorization')
        reconciled=authorization_reconciliation(policy,pin,wire['authorization'])
        if reconciled is not None:
            if replacement.exists() or replacement.is_symlink():
                require(replacement.is_dir() and not replacement.is_symlink()
                        and authorization_tree_digest(replacement)==policy.get('authorization_predecessor_sha256'),
                        'Interrupted predecessor differs; preserve for reconciliation')
                shutil.rmtree(replacement);sync_directory(ROOT/'tmp')
            return reconciled
        doc=authorization_document(wire['authorization'],pin,int(time.time()))
        initial=globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256')
        continuation=initial is not None
        if continuation:
            require(previous is not None and initial==policy.get('engineering_initial_authorization_sha256')
                    and globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256')==previous['sha256'],
                    'Continuation differs from the authenticated initial or current receipt')
            require(doc['target']==policy.get('engineering_target') and len(doc['requests'])==1,
                    'Continuation must retain its exact target and grant one request')
            require(all(doc[key]==effective_engineering_selection(ROOT,policy).get(key) for key in
                        ('release_id','manifest_sha256','network_id','chain_id','node_name')),
                    'Continuation changes the approved master or network')
            require(globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256')==policy.get('validator_formation_sha256')
                    and isinstance(policy.get('validator_formation_sha256'),str),'Continuation changes the approved formation')
        else:
            require(previous is None,'An enrolled engineering authorization requires a bound continuation')
        if 'guest' in doc['target']:
            verify_guest_local_ssh(doc['target']['guest'])
        if doc['target']['kind']=='local':
            machine=Path('/etc/machine-id').read_bytes()
            require(0<len(machine)<=128 and hashlib.sha256(machine).hexdigest()==doc['target']['machine_id_sha256'],'Local machine identity differs')
        inputs=authorization_inputs(doc,wire['artifacts'])
        require(doc['sequence']==(previous['sequence']+1 if previous else 1),'Authorization sequence must advance exactly once')
        require(not replacement.exists() and not replacement.is_symlink(),'Interrupted authorization requires reconciliation')
        consumed=set()
        audit=old/'audit.jsonl'
        if audit.exists():
            Controller(ROOT).direct(audit,True)
            for line in audit.read_bytes().splitlines():
                item=json.loads(line);require(isinstance(item,dict) and isinstance(item.get('request_sha256'),str),'Invalid prior operation audit')
                consumed.add(item['request_sha256'])
        readiness_augmentation=readiness_refresh_allowed(ROOT,policy,doc,inputs,continuation,consumed)
        expired_grants=[]
        for grant_path in (old/'grants').iterdir():
            grant=Controller(ROOT).public_json(grant_path,True)
            require(previous is not None and grant.get('authorization_sha256')==previous['sha256']
                    and grant.get('authorization_sequence')==previous['sequence']
                    and grant.get('request_sha256')==grant_path.stem and type(grant.get('expires_at')) is int,
                    'Prior grant attribution differs; preserve it for reconciliation')
            require(grant['expires_at']<=int(time.time()) or readiness_augmentation
                    and grant_path.stem==doc['requests'][0]['request_sha256'] and grant.get('operation')=='commission',
                    'Prior live grants require reconciliation')
            expired_grants.append(grant_path.name)
        require(not (old/HOST_REMOVAL).exists() and not (old/VPN_ENROLLMENT).exists(),
                'Prior enrollment or retirement requires reconciliation')
        selected=policy.get('releases',{}).get(doc['release_id'])
        require(selected and selected.get('manifest_sha256')==doc['manifest_sha256'] and selected.get('inventory_authenticated') is True
                and selected.get('networks',{}).get(doc['network_id'])==doc['chain_id'],'Authorization differs from approved master/network')
        receipt_path=ROOT/'installation.json'
        if receipt_path.exists():
            from lifecycle import _sealed_receipt
            receipt,_=_sealed_receipt(ROOT)
            require(all(receipt[key]==doc[key] for key in ('network_id','chain_id','node_name'))
                    and receipt['package_sha256']==doc['manifest_sha256'],'Installed selection differs')
        status=_unit_state('synergy-node.service')
        active=status.get('MainPID','0') not in ('','0') or status.get('ActiveState') not in ('inactive','failed')
        pure_lifecycle=(continuation and not inputs and doc['genesis_pins'] in (None,policy.get('validator_identity_network'))
                        and (doc['requests'][0]['operation'] in ('stop','restart','treasury_send_prepare','treasury_send_submit')
                             or len(doc['requests'])==1 and doc['requests'][0]['operation']=='boot_policy'))
        guest_policy_only=active_guest_policy_only(continuation,inputs,doc,policy)
        gateway_policy_only=gateway_issuer_policy_only(ROOT,continuation,inputs,doc,policy)
        guest_lifecycle_only=(continuation and not inputs and len(doc['requests'])==1
            and doc['requests'][0]['operation'] in ('guest_stop','guest_resume','guest_remove')
            and doc['genesis_pins'] in (None,policy.get('validator_identity_network')))
        guest_manager=None
        if guest_lifecycle_only:
            from guest_lifecycle import GuestManager
            guest_manager=GuestManager(ROOT,policy);guest_manager.verify_guard();guest_manager.status({'guest_id':guest_manager.spec['guest_id']})
        require(not active or pure_lifecycle or guest_policy_only or guest_lifecycle_only or gateway_policy_only,'Stop validator before artifact, formation or configuration authorization change')
        vpn=_unit_state('synergy-vpn.service')
        if not active and not gateway_policy_only:
            if guest_lifecycle_only or transport_authorization(continuation,inputs,doc,policy):guest_management_quiescence(ROOT,policy,_assert_no_application_processes,vpn.get('MainPID'))
            else:_assert_no_application_processes(ROOT,vpn_pid=vpn.get('MainPID'))
        requests=[];seen=set()
        for request in doc['requests']:
            require(request['operation'] in __import__('controller').MUTATIONS,'Authorization may grant only exact supported mutations')
            key=request['request_sha256'];require(key not in seen,'Duplicate exact request');seen.add(key)
            require(key not in consumed or continuation and request['operation'] in ('start','stop','restart','vpn_stop','vpn_resume','boot_policy','guest_stop'),'Consumed non-lifecycle request cannot be granted again')
            requests.append((request,key))
            if request['operation']=='vpn_enroll':require('vpn-enrollment.json' in inputs,'Exact one-use VPN input required')
            if request['operation']=='vpn_bind':require('vpn-server-binding.json' in inputs,'Exact native provider binding required')
            if request['operation']=='vpn_retire':require('vpn-retirement.json' in inputs,'Exact verified provider retirement required')
            if request['operation']=='vpn_cancel_unused':require('vpn-unused-cancellation.json' in inputs,'Exact verified unused cancellation required')
        guest_input=inputs.get('managed-guest.json')
        if guest_input is not None:
            require(guest_policy_only,'Guest resource approval must be its exact existing-host continuation')
            from guest_lifecycle import resource_file_pins,validate_resource_policy,operator_public_key
            # The exact current installed release, not caller pins, supplies all
            # executable/image trust. Initial bootstrap cannot install guest policy.
            from lifecycle import _sealed_receipt
            receipt,manifest=_sealed_receipt(ROOT)
            require(receipt['package_sha256']==doc['manifest_sha256'] and receipt['role']=='validator'
                    and 'guest' not in doc['target'],'Managed guests require the physical installed host')
            require(not (ROOT/'hosted-machines/record.json').exists()
                    and not (ROOT/'hosted-machines/removed.json').exists(), 'Prior guest lifecycle must not be replaced')
            spec=validate_resource_policy(ROOT,json.loads(guest_input),resource_file_pins(manifest),operator_public_key(ROOT))
            prior=policy.get('managed_guest')
            require(prior is None or prior==spec,'An approved guest policy cannot be replaced')
            expected_request=__import__('controller').request_digest({'version':1,'operation':'guest_create',
                'parameters':{key:spec[key] for key in ('guest_id','image_sha256','cpu_count','memory_mib','disk_gib')}})
            require(len(doc['requests'])==1 and doc['requests'][0]=={'operation':'guest_create','request_sha256':expected_request},
                    'Guest policy requires its one exact native-approved creation request')
            policy['managed_guest']=spec
        formation=inputs.get('formation-context.json')
        if formation is not None:
            value=json.loads(formation)
            require(set(value)=={'network_id','chain_id_hex','formation_id'} and value['network_id']==doc['network_id']
                    and value['chain_id_hex']==format(doc['chain_id'],'064x') and isinstance(value['formation_id'],str)
                    and re.fullmatch('[a-f0-9]{64}',value['formation_id']) and value['formation_id']!='0'*64,'Formation context differs')
            prior=policy.get('validator_formation_sha256')
            require(prior is None or prior==doc['artifacts']['formation-context.json'],'Cannot replace prepared formation context')
            policy['validator_formation_sha256']=doc['artifacts']['formation-context.json']
        if doc['genesis_pins'] is not None:
            prior=policy.get('validator_identity_network')
            require(prior is None or prior==doc['genesis_pins'],'Cannot substitute authorized Genesis')
            policy['validator_identity_network']=doc['genesis_pins']
        commissioning={name[len('commissioning/'):]:pin for name,pin in doc['artifacts'].items() if name.startswith('commissioning/')}
        if commissioning:
            from apqe_layout import FORMATION_PUBLIC_INPUTS
            gateway_install=len(doc['requests'])==1 and doc['requests'][0]['operation']=='gateway_install'
            expected={'network/'+name for name in ('genesis.json','authority.json','authority-root.pub','network-manifest.json','transport-registry.json','transport-root.pub')} if gateway_install else FORMATION_PUBLIC_INPUTS
            require(set(commissioning)==expected,'Complete public commissioning inventory required')
            require(doc['genesis_pins'] is not None and all(commissioning['network/'+name]==pin for name,pin in doc['genesis_pins'].items()),'Commissioning Genesis differs from independent pins')
            field='gateway_origin_files' if gateway_install else 'validator_commissioning_files'
            require(field not in policy or policy[field]==commissioning,'Cannot replace approved commissioning origin')
            policy[field]=commissioning
        refresh_readiness=readiness_augmentation
        predecessor=authorization_tree_digest(old)
        exchanged=False
        try:
            shutil.copytree(old,replacement)
            for name in expired_grants:(replacement/'grants'/name).unlink()
            policy['authorization_predecessor_sha256']=predecessor
            # Retain previous authenticated inputs needed by already prepared custody.
            for name,data in inputs.items():
                path=replacement/(VPN_ENROLLMENT if name=='vpn-enrollment.json' else 'authorization/inputs/'+name)
                if path.exists():
                    if name=='commissioning-readiness.json' and refresh_readiness:
                        path.unlink();save(path,data)
                    else:require(path.read_bytes()==data,'Existing authorization input differs')
                else:save(path,data)
            policy['qualified_operations']=sorted({request['operation'] for request,_ in requests})
            if not continuation:policy['engineering_selection']={key:doc[key] for key in ('release_id','manifest_sha256','network_id','chain_id','node_name')}
            policy['engineering_initial_authorization_sha256']=initial if continuation else pin
            policy['engineering_target']=doc['target']
            policy['engineering_authorization']={'sha256':pin,'sequence':doc['sequence'],'expires_at':doc['expires_at']}
            policy['authorization_files']={**policy.get('authorization_files',{}),**{name:hashlib.sha256(data).hexdigest() for name,data in inputs.items() if name!='vpn-enrollment.json'}}
            for request,key in requests:
                grant={'root':str(ROOT),'operation':request['operation'],'request_sha256':key,'expires_at':doc['expires_at'],'authorization_sha256':pin,'authorization_sequence':doc['sequence']}
                if request['operation']=='vpn_enroll':grant['enrollment_sha256']=doc['artifacts']['vpn-enrollment.json']
                if request['operation']=='vpn_bind':grant['binding_sha256']=doc['artifacts']['vpn-server-binding.json']
                if request['operation']=='vpn_retire':grant['binding_sha256']=doc['artifacts']['vpn-retirement.json']
                if request['operation']=='vpn_cancel_unused':grant['binding_sha256']=doc['artifacts']['vpn-unused-cancellation.json']
                save(replacement/'grants'/(key+'.json'),json.dumps(grant,sort_keys=True).encode())
            (replacement/'policy.json').unlink();save(replacement/'policy.json',json.dumps(policy,sort_keys=True).encode())
            for path in replacement.rglob('*'):
                if path.is_file():
                    with path.open('rb') as stream:os.fsync(stream.fileno())
            for path in sorted([p for p in replacement.rglob('*') if p.is_dir()],key=lambda p:-len(p.parts)):sync_directory(path)
            sync_directory(replacement);sync_directory(ROOT/'tmp')
            exchange=ctypes.CDLL(None,use_errno=True).renameat2
            exchange.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint);exchange.restype=ctypes.c_int
            if exchange(-100,os.fsencode(old),-100,os.fsencode(replacement),2):raise OSError(ctypes.get_errno(),'Controller exchange failed')
            exchanged=True;sync_directory(ROOT/'tmp');control_inventory(ROOT)
            shutil.rmtree(replacement);sync_directory(ROOT/'tmp')
        except Exception:
            if not exchanged and replacement.exists():shutil.rmtree(replacement)
            raise
        return {'schema':'nodenetwork-engineering-authorization-v1',**policy['engineering_authorization'],
                'applied':True,'reconciled':False,'grants_recreated':False}
    finally:os.close(lock)


def retiring_update_members(root, selection):
    """Only hash-authenticated leftover PUBLIC staging; manifest is removed last."""
    pending=root/'tmp/update-master'
    if not pending.exists() and not pending.is_symlink():return set()
    metadata=pending.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and pending.resolve()==pending and metadata.st_uid==os.geteuid()
            and stat.S_IMODE(metadata.st_mode)==0o700,'Unsafe superseded staging root')
    package=pending/'package.json'
    if not package.exists() and not package.is_symlink():
        require(not any(pending.iterdir()),'Superseded staging lost its authenticated manifest')
        return {pending.relative_to(root).as_posix()}
    metadata=package.lstat()
    require(stat.S_ISREG(metadata.st_mode) and package.resolve()==package and metadata.st_nlink==1
            and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o600
            and 0<metadata.st_size<=1024*1024,'Unsafe superseded manifest')
    raw=package.read_bytes();require(hashlib.sha256(raw).hexdigest()==selection['manifest_sha256'],'Superseded manifest differs')
    manifest=json.loads(raw);files=manifest.get('files')
    require(manifest.get('format')=='synergy-universal-linux-v1' and manifest.get('architecture')=='x86_64'
            and manifest.get('release_id')==selection['release_id'] and isinstance(files,dict) and len(files)<=4096,
            'Invalid superseded manifest')
    for name,pin in files.items():
        path=PurePosixPath(name)
        require(name and name==path.as_posix() and not path.is_absolute() and '..' not in path.parts
                and name!='package.json' and isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),'Unsafe superseded member')
    limit=master_archive_limit(manifest)
    directories=set(DIRECTORIES)|{str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent)!='.'}
    roles=pending/'roles/roles.json'
    if roles.exists() and not roles.is_symlink():
        metadata=roles.lstat()
        require(roles.resolve()==roles and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1
                and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o600
                and metadata.st_size<=65536,'Unsafe superseded roles')
        require('roles/roles.json' in files and hashlib.sha256(roles.read_bytes()).hexdigest()==files['roles/roles.json'],'Superseded roles differ')
        values=json.loads(roles.read_bytes())['roles']
        require(isinstance(values,list) and len(values)<=20 and all(isinstance(v,str) and re.fullmatch('[a-z][a-z0-9_-]{0,63}',v) for v in values),'Invalid superseded roles')
        directories.update('roles/'+v for v in values)
    members={pending.relative_to(root).as_posix()};count=0;total=0
    for current,dirs,names in os.walk(pending,followlinks=False):
        for name in dirs+names:
            count+=1;require(count<=8192,'Superseded inventory exceeds bound')
            path=Path(current)/name;relative=path.relative_to(pending).as_posix();metadata=path.lstat()
            require(path.resolve()==path and metadata.st_uid==os.geteuid() and not metadata.st_mode&0o022,'Unsafe superseded member')
            if stat.S_ISDIR(metadata.st_mode):require(relative in directories and stat.S_IMODE(metadata.st_mode)==0o700,'Unknown superseded directory')
            else:
                require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1 and stat.S_IMODE(metadata.st_mode) in (0o600,0o700)
                        and relative in set(files)|{'package.json'},'Unknown superseded file')
                total+=metadata.st_size;require(total<=limit,'Superseded files exceed bound')
                digest=hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
                require(digest.hexdigest()==(selection['manifest_sha256'] if relative=='package.json' else files[relative]),'Superseded file differs')
            members.add(path.relative_to(root).as_posix())
    return members


def retire_superseded_update(root, selection):
    members=retiring_update_members(root,selection)
    pending=root/'tmp/update-master'
    if not members:return
    # Keep both directory authority (manifest) and empty-role inventory until
    # their children have gone. Every intermediate crash is a validated subset.
    def synced(directory):
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    held={pending/'package.json',pending/'roles/roles.json'}
    for name in sorted(members):
        path=root/name
        if path.is_file() and path not in held:path.unlink();synced(path.parent)
    for path in sorted((root/name for name in members),key=lambda p:-len(p.parts)):
        if path.is_dir() and path not in (pending,pending/'roles'):
            path.rmdir();synced(path.parent)
    roles=pending/'roles/roles.json'
    if roles.exists():roles.unlink();synced(roles.parent)
    role_dir=pending/'roles'
    if role_dir.exists():role_dir.rmdir();synced(pending)
    package=pending/'package.json'
    if package.exists():package.unlink();synced(pending)
    pending.rmdir();synced(root/'tmp')


UPGRADE_PROOF_PHASES="entry verifier engine scope receipt outcome audit package guest processes conformance".split()
_UPGRADE_PROOF_PHASE=None

def upgrade_not_applied_proof(wire, *, _already_locked=False, _retiring=False):
    """Read-only terminal proof: no rollback, grant creation or upgrade replay."""
    global _UPGRADE_PROOF_PHASE
    _UPGRADE_PROOF_PHASE='entry'
    import types,time
    require(isinstance(wire,dict) and set(wire) in ({'context','adoption','request','challenge','verifier_manifest_json','verifier_conformance'},{'context','adoption','request','challenge','verifier_manifest_json','verifier_conformance','unused'}) and type(wire.get('unused',False)) is bool,'Exact upgrade proof required')
    unused=wire.get('unused',False)
    context=wire['context'];request=wire['request']
    require(isinstance(context,dict) and set(context)=={'initial_sha256','parent_sha256','formation_sha256','target','selection','expires_at'}
            and type(context['expires_at']) is int and int(time.time())<=context['expires_at']<=int(time.time())+300,'Upgrade proof scope expired')
    require(isinstance(request,dict) and set(request)=={'version','operation','parameters'} and request['version']==1 and request['operation']=='upgrade'
            and set(request['parameters'])=={'release_id','manifest_sha256'},'Exact upgrade request required')
    for value in (wire['challenge'],context['initial_sha256'],context['parent_sha256'],context['formation_sha256'],request['parameters']['manifest_sha256']):
        require(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value),'Malformed upgrade proof pin')
    _UPGRADE_PROOF_PHASE='verifier'
    verifier=wire['verifier_manifest_json'];source=wire['verifier_conformance']
    require(isinstance(verifier,str) and len(verifier.encode())<=1024*1024 and isinstance(source,str) and 0<len(source.encode())<=256*1024,'Upgrade verifier exceeds bound')
    require(hashlib.sha256(verifier.encode()).hexdigest()==globals().get('NATIVE_AUTHENTICATED_MANIFEST_SHA256'),'Upgrade verifier lacks independent native approval')
    manifest=json.loads(verifier)
    require(hashlib.sha256(source.encode()).hexdigest()==manifest['files'].get('tools/conformance.py'),'Upgrade verifier source differs')
    _UPGRADE_PROOF_PHASE='engine'
    root=ROOT;control=root/'tmp/controller'
    policy_path=control/'policy.json'
    require(policy_path.resolve()==policy_path and stat.S_IMODE(policy_path.lstat().st_mode)==0o600 and policy_path.stat().st_uid==os.geteuid(),'Unsafe proof policy')
    policy=json.loads(policy_path.read_bytes())
    for name in enrolled_engine(policy):
        path=control/name if name=='controller.py' else control/'tools'/name
        metadata=path.lstat()
        require(path.resolve()==path and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink==1 and metadata.st_uid==os.geteuid()
                and not metadata.st_mode&0o022 and metadata.st_size<=1024*1024
                and hashlib.sha256(path.read_bytes()).hexdigest()==policy['engine_files'][name],'Enrolled proof engine drift')
    sys.path[:0]=[str(control),str(control/'tools')]
    from controller import Controller,request_digest,engineering_effective_selection
    import lifecycle as life
    from synergy_linux import verify_package,digest,read
    c=Controller(root)
    import contextlib
    with (contextlib.nullcontext() if _already_locked else life._lifecycle_lock(root)):
        _UPGRADE_PROOF_PHASE='scope'
        require(c.policy()==policy,'Proof policy changed')
        require(policy.get('engineering_initial_authorization_sha256')==context['initial_sha256']
                and policy.get('engineering_authorization',{}).get('sha256')==context['parent_sha256']
                and policy.get('validator_formation_sha256')==context['formation_sha256']
                and policy.get('engineering_target')==context['target']
                and engineering_effective_selection(root,policy)==context['selection']
                and policy.get('engineering_update')==wire['adoption'],'Proof changes original native scope')
        adoption=wire['adoption'];selection=adoption.get('selection',{})
        require(adoption.get('initial_sha256')==context['initial_sha256'] and adoption.get('formation_sha256')==context['formation_sha256']
                and adoption.get('previous_selection')==context['selection'] and request['parameters']=={k:selection.get(k) for k in ('release_id','manifest_sha256')},'Upgrade proof differs from exact adoption')
        _UPGRADE_PROOF_PHASE='receipt'
        receipt,old_manifest=life._sealed_receipt(root)
        require(receipt['package_sha256']==context['selection']['manifest_sha256'],'Old installation differs from native-reviewed scope')
        _UPGRADE_PROOF_PHASE='outcome'
        path=root/life.UPGRADE_INTENT
        require(not path.exists() and not path.is_symlink(),'Upgrade intent remains')
        path=root/life.UPGRADE_COMPLETED
        if path.exists() or path.is_symlink():
            prior=json.loads(c.direct(path,True,4096).read_bytes())
            require(isinstance(prior,dict) and set(prior)=={'format','root','old_package_sha256','new_package_sha256','resumed','consensus_started','automatic_restart'}
                and prior['format']=='synergy-software-upgrade-completed-v1' and prior['root']==str(root)
                and isinstance(prior['old_package_sha256'],str) and re.fullmatch('[a-f0-9]{64}',prior['old_package_sha256'])
                and prior['new_package_sha256']==receipt['package_sha256']!=request['parameters']['manifest_sha256']
                and prior['old_package_sha256']!=prior['new_package_sha256'] and type(prior['resumed']) is bool
                and prior['consensus_started'] is False and prior['automatic_restart'] is False,'Foreign or unfinished upgrade completion')
        count=0
        for current,dirs,files in os.walk(root,followlinks=False):
            for name in dirs+files:
                count+=1;require(count<=200000 and '.upgrade-' not in name,'Upgrade partial or inventory capacity requires reconciliation')
        _UPGRADE_PROOF_PHASE='audit'
        key=request_digest(request);grant=control/'grants'/(key+'.json')
        require(not grant.exists() and not grant.is_symlink(),'Upgrade grant is not consumed')
        audit=control/'audit.jsonl';rows=[]
        if not unused or audit.exists() or audit.is_symlink():
            audit=c.direct(audit,True);require(audit.stat().st_size<=1024*1024,'Upgrade audit exceeds bound');rows=audit.read_bytes().splitlines()
        require(len(rows)<=4096,'Upgrade audit exceeds bound')
        found=[]
        for row in rows:
            value=json.loads(row)
            require(isinstance(value,dict) and set(value)=={'operation','request_sha256','time'} and type(value['time']) is int
                    and 0<=value['time']<=int(time.time()),'Malformed upgrade audit')
            if value['request_sha256']==key or not unused and value['operation']=='upgrade':found.append(value)
        require(not found if unused else len(found)==1 and found[0]['operation']=='upgrade' and found[0]['request_sha256']==key,'Upgrade audit does not match exact unused or consumed proof')
        _UPGRADE_PROOF_PHASE='package'
        candidate=root/'tmp/update-master'
        retiring=retiring_update_members(root,selection) if _retiring else None
        if _retiring:candidate_manifest=old_manifest
        else:
            candidate_manifest=verify_package(candidate)
            require(digest(candidate/'package.json')==selection['manifest_sha256'] and candidate_manifest['release_id']==selection['release_id'],'Staged original upgrade differs')
        _UPGRADE_PROOF_PHASE='guest'
        from guest_lifecycle import require_upgrade_compatible
        require_upgrade_compatible(root,candidate_manifest)
        _UPGRADE_PROOF_PHASE='processes'
        plan=life._integration_plan(root)
        if plan:
            units=life._attributed_units(root,plan)
            node=units.get('synergy-node.service',{})
            require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),'Stop owned validator before upgrade proof')
        life._assert_no_application_processes(root,vpn_pid=units.get('synergy-vpn.service',{}).get('MainPID') if plan else None)
        _UPGRADE_PROOF_PHASE='conformance'
        module=types.ModuleType('nodenetwork_readonly_upgrade_conformance')
        exec(compile(source,'<authenticated-upgrade-conformance>','exec'),module.__dict__)
        if _retiring:
            original=module.approved_upgrade_members
            module.approved_upgrade_members=lambda root,pin,stage:original(root,None,stage)|retiring
        result=module.installed(root,old_manifest,host=plan is not None,stage=life._installation_stage(root),
            schema=read((root if _retiring else candidate)/'assets/node-config.schema.json'),allow_legacy_integrations=True,pending_upgrade_sha256=selection['manifest_sha256'])
        require(isinstance(result,dict) and c.policy()==policy,'Upgrade proof did not complete')
        return {'schema':'nodenetwork-upgrade-not-applied-v1','challenge':wire['challenge'],'request_sha256':key,
                'old_manifest_sha256':receipt['package_sha256'],'candidate_manifest_sha256':selection['manifest_sha256'],
                'not_applied':True,'mutation_performed':False}


def continuation_absence_facts(root,control,controller,policy,context,pending):
    """Pure reads; even expired grants and any consumed request forbid release."""
    import time
    require(controller.policy()==policy,'Continuation proof policy changed')
    current=policy.get('engineering_authorization',{})
    require(current==context['authorization'] and current.get('sequence')+1==pending['sequence']
            and current.get('sha256')!=context['pending_sha256'],'Pending continuation has no exact predecessor')
    require(policy.get('engineering_initial_authorization_sha256')==context['initial_sha256']
            and policy.get('engineering_target')==context['target']
            and policy.get('validator_formation_sha256')==context['formation_sha256']
            and policy.get('validator_identity_network')==context['genesis_pins'],'Continuation proof scope changed')
    require(all(pending[k]==context['selection'][k] for k in ('release_id','manifest_sha256','network_id','chain_id','node_name'))
            and pending['target']==context['target'] and pending['artifacts']=={}
            and len(pending['requests'])==1,'Only exact input-free continuation may be released')
    for name in ('controller-authorization','controller-authorization.pending'):
        path=root/'tmp'/name;require(not path.exists() and not path.is_symlink(),'Authorization exchange partial exists')
    key=pending['requests'][0]['request_sha256'];grant=control/'grants'/(key+'.json')
    require(not grant.exists() and not grant.is_symlink(),'Pending request has a grant')
    audit=control/'audit.jsonl'
    if audit.exists() or audit.is_symlink():
        path=controller.direct(audit,True);require(path.stat().st_size<=1024*1024,'Authorization audit exceeds bound')
        rows=path.read_bytes().splitlines();require(len(rows)<=4096,'Authorization audit exceeds bound')
        for row in rows:
            value=json.loads(row)
            require(isinstance(value,dict) and set(value)=={'operation','request_sha256','time'}
                    and isinstance(value['operation'],str) and isinstance(value['request_sha256'],str)
                    and re.fullmatch('[a-f0-9]{64}',value['request_sha256']) and type(value['time']) is int
                    and 0<=value['time']<=int(time.time()),'Malformed authorization audit')
            require(value['request_sha256']!=key,'Pending request was consumed')
    require(controller.policy()==policy,'Continuation proof policy changed')
    return key


def transport_absence_facts(root,control,controller,policy,context):
    pins=context['artifact_sha256'];names={n[14:] for n in AUTHORIZATION_FILES if n.startswith('commissioning/')}
    require(isinstance(pins,dict) and set(pins)==names and all(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v) for v in pins.values()),'Exact transport inventory required')
    genesis=context['genesis_pins']
    require(isinstance(genesis,dict) and set(genesis)=={'genesis.json','authority.json','authority-root.pub'}
        and all(pins['network/'+n]==v for n,v in genesis.items()),'Transport Genesis differs')
    require('validator_commissioning_files' not in policy,'Commissioning already approved')
    from controller import GENESIS_STAGE
    for name,pin in genesis.items():
        require(hashlib.sha256(controller.direct(root/GENESIS_STAGE/name,True,4*1024*1024).read_bytes()).hexdigest()==pin,'Prior signed Genesis changed')
    for name,pin in pins.items():
        label='commissioning/'+name;path=control/'authorization/inputs'/label
        prior=policy.get('authorization_files',{}).get(label)
        if path.exists() or path.is_symlink() or prior is not None:
            require(name in {'network/'+n for n in genesis} and prior==pin
                and hashlib.sha256(controller.direct(path,True,4*1024*1024).read_bytes()).hexdigest()==pin,'Transport input already present or changed')
    for name in ('data','tmp/commissioning','tmp/existing-network-identity-request.json','evidence/upgrade-intent.json','evidence/application-replacement-intent.json'):
        path=root/name;require(not path.exists() and not path.is_symlink(),'Published or partial application state')
    for name in ('config','network'):
        path=root/name;require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()),'Published application configuration')
    import lifecycle as life
    node=life._unit_state('synergy-node.service');vpn=life._unit_state('synergy-vpn.service')
    require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),'Stop validator before transport proof')
    guest_management_quiescence(root,policy,life._assert_no_application_processes,vpn.get('MainPID'))
    key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    pending={**context['selection'],'target':context['target'],'artifacts':{},'requests':[{'operation':'commission','request_sha256':key}],'sequence':context['authorization']['sequence']+1}
    continuation_absence_facts(root,control,controller,policy,context,pending)
    return context['dispatch_sha256']


def readiness_absence_facts(root,control,controller,policy,context,pending):
    name='commissioning-readiness.json';pin=context['artifact_sha256']
    require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),'Invalid readiness artifact commitment')
    key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    dispatch={'operation':'commission','request_sha256':key,'artifact_sha256':pin}
    require(context['dispatch_sha256']==hashlib.sha256(json.dumps(dispatch,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        and pending['artifacts']=={name:pin} and pending['requests']==[{'operation':'commission','request_sha256':key}]
        and pending['genesis_pins']==context['genesis_pins'],'Original readiness request differs')
    path=control/'authorization/inputs'/name
    require(not path.exists() and not path.is_symlink() and name not in policy.get('authorization_files',{}),
        'Readiness artifact or approval already present')
    from apqe_layout import FORMATION_PUBLIC_INPUTS
    pins=policy.get('validator_commissioning_files',{})
    require(set(pins)==FORMATION_PUBLIC_INPUTS and isinstance(context['genesis_pins'],dict)
        and all(pins.get('network/'+name)==value for name,value in context['genesis_pins'].items()),'Exact existing commissioning approval required')
    for name,expected in pins.items():
        raw=controller.direct(control/'authorization/inputs/commissioning'/name,True,4*1024*1024).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==expected,'Existing commissioning input changed')
    projected={**pending,'artifacts':{}}
    continuation_absence_facts(root,control,controller,policy,context,projected)
    for name in ('data','tmp/commissioning','tmp/existing-network-identity-request.json','evidence/upgrade-intent.json',
                 'evidence/application-replacement-intent.json','evidence/authority-recovery-intent.json','evidence/autonomous-epoch-intent.json'):
        path=root/name;require(not path.exists() and not path.is_symlink(),'Published or partial application state')
    require(not any((root/'tmp').glob('commission-prepare-*')) and not any((root/'tmp').glob('commission-observe-*')),
        'Partial commissioning observation exists')
    for name in ('config','network'):
        path=root/name;require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()),'Published application configuration')
    import lifecycle as life
    life._commission_fresh_keys(root)
    node=life._unit_state('synergy-node.service');vpn=life._unit_state('synergy-vpn.service')
    require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),'Stop validator before readiness proof')
    guest_management_quiescence(root,policy,life._assert_no_application_processes,vpn.get('MainPID'))
    continuation_absence_facts(root,control,controller,policy,context,projected)
    return context['dispatch_sha256']


def commission_absence_facts(root,control,controller,policy,context):
    """Unaudited grant and wholly unpublished application; no freshness renewal."""
    import time
    key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    current=policy.get('engineering_authorization',{})
    require(context['request_sha256']==key and current==context['authorization']
        and policy.get('engineering_initial_authorization_sha256')==context['initial_sha256']
        and policy.get('engineering_target')==context['target']
        and policy.get('validator_formation_sha256')==context['formation_sha256']
        and policy.get('validator_identity_network')==context['genesis_pins'],'Commission proof scope changed')
    require(isinstance(current,dict) and set(current)=={'sha256','sequence','expires_at'}
        and re.fullmatch('[a-f0-9]{64}',current['sha256']) and type(current['sequence']) is int and current['sequence']>0
        and type(current['expires_at']) is int and current['expires_at']>0,'Invalid commission authorization')
    grant=control/'grants'/(key+'.json')
    require(set(p.name for p in (control/'grants').iterdir())=={key+'.json'},'Other or absent commission grant')
    expected={'root':str(root),'operation':'commission','request_sha256':key,'expires_at':current['expires_at'],
        'authorization_sha256':current['sha256'],'authorization_sequence':current['sequence']}
    require(json.loads(controller.direct(grant,True,65536).read_bytes())==expected,'Exact unused commission grant required')
    audit=control/'audit.jsonl'
    if audit.exists() or audit.is_symlink():
        raw=controller.direct(audit,True,1024*1024).read_bytes();rows=raw.splitlines()
        require(len(rows)<=4096,'Authorization audit exceeds bound')
        for row in rows:
            value=json.loads(row)
            require(isinstance(value,dict) and set(value)=={'operation','request_sha256','time'}
                and isinstance(value['operation'],str) and isinstance(value['request_sha256'],str)
                and re.fullmatch('[a-f0-9]{64}',value['request_sha256']) and type(value['time']) is int
                and 0<=value['time']<=int(time.time()),'Malformed authorization audit')
            require(value['operation']!='commission' and value['request_sha256']!=key,'Commission was consumed')
    name='commissioning-readiness.json';pin=policy.get('authorization_files',{}).get(name)
    require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin),'Approved readiness required')
    require(hashlib.sha256(controller.direct(control/'authorization/inputs'/name,True,128*1024).read_bytes()).hexdigest()==pin,'Approved readiness changed')
    from apqe_layout import FORMATION_PUBLIC_INPUTS
    pins=policy.get('validator_commissioning_files',{})
    require(set(pins)==FORMATION_PUBLIC_INPUTS and isinstance(context['genesis_pins'],dict)
        and set(context['genesis_pins'])=={'genesis.json','authority.json','authority-root.pub'}
        and all(pins.get('network/'+n)==v for n,v in context['genesis_pins'].items()),'Exact commissioning approval required')
    from controller import GENESIS_STAGE
    for n,v in pins.items():
        require(isinstance(v,str) and re.fullmatch('[a-f0-9]{64}',v)
            and hashlib.sha256(controller.direct(control/'authorization/inputs/commissioning'/n,True,4*1024*1024).read_bytes()).hexdigest()==v,'Commissioning input changed')
    for n,v in context['genesis_pins'].items():
        require(hashlib.sha256(controller.direct(root/GENESIS_STAGE/n,True,4*1024*1024).read_bytes()).hexdigest()==v,'Bound Genesis changed')
    for n in ('data','tmp/commissioning','tmp/controller-authorization','tmp/controller-authorization.pending',
              'tmp/existing-network-identity-request.json','evidence/upgrade-intent.json','evidence/application-replacement-intent.json',
              'evidence/authority-recovery-intent.json','evidence/autonomous-epoch-intent.json'):
        path=root/n;require(not path.exists() and not path.is_symlink(),'Published or partial application state')
    require(not any((root/'tmp').glob('commission-prepare-*')) and not any((root/'tmp').glob('commission-observe-*')),'Partial commissioning exists')
    for n in ('config','network'):
        path=root/n;require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()),'Published application configuration')
    import lifecycle as life
    life._commission_fresh_keys(root)
    require(controller.genesis_binding(locked=True).get('bound') is True,'Retained Genesis custody was not verified')
    units=life._attributed_units(root)
    node=units.get('synergy-node.service',{});vpn=units.get('synergy-vpn.service',{})
    require(node.get('MainPID')=='0' and node.get('ActiveState') in ('inactive','failed'),'Stop validator before commission proof')
    guest_management_quiescence(root,policy,life._assert_no_application_processes,vpn.get('MainPID'))
    require(int(time.time())<=context['expires_at'] and controller.policy()==policy and json.loads(controller.direct(grant,True,65536).read_bytes())==expected,'Commission proof changed')
    return pin


def treasury_send_phase_facts(root,control,controller,policy,context,challenge):
    """Public hashes and phase facts only; never classify an outcome or retry."""
    import time
    require(type(context['nonce']) is int and 0<=context['nonce']<2**64-1,'Invalid original treasury nonce')
    require(policy.get('engineering_authorization')==context['authorization']
        and policy.get('engineering_initial_authorization_sha256')==context['initial_sha256']
        and policy.get('engineering_target')==context['target']
        and policy.get('validator_formation_sha256')==context['formation_sha256']
        and policy.get('validator_identity_network')==context['genesis_pins'],'Treasury phase scope changed')
    current=context['authorization']
    require(isinstance(current,dict) and set(current)=={'sha256','sequence','expires_at'}
        and isinstance(current['sha256'],str) and re.fullmatch('[a-f0-9]{64}',current['sha256'])
        and type(current['sequence']) is int and current['sequence']>0
        and type(current['expires_at']) is int and current['expires_at']>0,'Invalid treasury authorization')
    key=context['request_sha256'];grant=control/'grants'/(key+'.json');grant_state='absent'
    if grant.exists() or grant.is_symlink():
        value=json.loads(controller.direct(grant,True,65536).read_bytes())
        expected={'root':str(root),'operation':'treasury_send_prepare','request_sha256':key,
            'expires_at':current['expires_at'],'authorization_sha256':current['sha256'],'authorization_sequence':current['sequence']}
        require(isinstance(value,dict) and set(value)==set(expected),'Malformed treasury grant')
        grant_state='exact' if value==expected else 'different'
    audit=control/'audit.jsonl';consumed=False
    if audit.exists() or audit.is_symlink():
        rows=controller.direct(audit,True,1024*1024).read_bytes().splitlines()
        require(len(rows)<=4096,'Authorization audit exceeds bound')
        for row in rows:
            value=json.loads(row)
            require(isinstance(value,dict) and set(value)=={'operation','request_sha256','time'}
                and isinstance(value['operation'],str) and isinstance(value['request_sha256'],str)
                and re.fullmatch('[a-f0-9]{64}',value['request_sha256']) and type(value['time']) is int
                and 0<=value['time']<=int(time.time()),'Malformed authorization audit')
            if value['request_sha256']==key:
                require(value['operation']=='treasury_send_prepare','Treasury audit operation differs')
                consumed=True
    def directory(path):
        m=path.lstat();require(path.resolve()==path and stat.S_ISDIR(m.st_mode) and m.st_uid==os.geteuid()
            and stat.S_IMODE(m.st_mode)==0o700,'Unsafe treasury phase directory')
    directory(root/'keys');treasury=root/'keys/formation-treasury';directory(treasury)
    names={'request.json','treasury-public.json','treasury.enc.json','unlock'}
    require(set(p.name for p in treasury.iterdir()) in (names,names|{'sends'}),'Unexpected treasury custody inventory')
    for name in names:
        m=(treasury/name).lstat();require(stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid()
            and stat.S_IMODE(m.st_mode)==0o600,'Unsafe treasury custody member')
    files={name:None for name in ('request','prepared','admission','dispatch')};request_raw=None;empty=set()
    sends=treasury/'sends';path=sends/format(context['nonce'],'020d');reservation='absent'
    if sends.exists() or sends.is_symlink():
        directory(sends);children=list(sends.iterdir());require(len(children)<=128,'Treasury nonce inventory exceeds bound')
        for child in children:
            require(re.fullmatch('[0-9]{20}',child.name) and int(child.name)<2**64-1,'Unknown treasury nonce');directory(child)
        if path.exists() or path.is_symlink():
            directory(path)
            allowed={'request.json':('request',2*1024*1024),'prepared.json':('prepared',128*1024),
                'admission.json':('admission',1024*1024),'dispatch-intent.json':('dispatch',4096)}
            require(set(p.name for p in path.iterdir())<=set(allowed),'Unknown treasury reservation member')
            for name,(label,limit) in allowed.items():
                source=path/name
                if source.exists() or source.is_symlink():
                    raw=controller.direct(source,True,limit).read_bytes();require(len(raw)<=limit,'Oversized treasury reservation member')
                    files[label]=hashlib.sha256(raw).hexdigest()
                    if not raw:empty.add(label)
                    if label=='request':request_raw=raw
            reservation='complete_inventory_unverified' if all(files[n] is not None and n not in empty for n in ('request','prepared','admission')) else 'partial'
    if files['request']==key:
        original=json.loads(request_raw);parameters=original.get('parameters') if isinstance(original,dict) else None
        require(isinstance(original,dict) and set(original)=={'version','operation','parameters'}
            and type(original['version']) is int and original['version']==1 and original['operation']=='treasury_send_prepare'
            and isinstance(parameters,dict) and type(parameters.get('nonce')) is int and parameters['nonce']==context['nonce']
            and parameters.get('formation_sha256')==context['formation_sha256']
            and parameters.get('genesis_sha256')==context['genesis_pins'].get('genesis.json'),'Original treasury request scope differs')
    require(int(time.time())<=context['expires_at'] and controller.policy()==policy,'Treasury phase scope expired or changed')
    return {'schema':'nodenetwork-treasury-send-phase-v1','challenge':challenge,'request_sha256':key,'nonce':context['nonce'],
        'authorization_sha256':current['sha256'],'grant_state':grant_state,'audit_state':'consumed' if consumed else 'not_consumed',
        'reservation':reservation,'files':files,'request_matches':None if files['request'] is None else files['request']==key,
        'mutation_performed':False}


def treasury_send_not_applied_facts(root,control,controller,policy,context,challenge):
    """Only unaudited preparation with no nonce reservation can be released."""
    def absent():
        for name in ('tmp/controller-authorization','tmp/controller-authorization.pending','tmp/controller-update',
                     'evidence/upgrade-intent.json','evidence/application-replacement-intent.json'):
            path=root/name;require(not path.exists() and not path.is_symlink(),'Treasury proof refuses partial lifecycle state')
        require(not any((root/'tmp').glob('treasury-send-*')),'Treasury preparation temporary state exists')
        path=root/'keys/formation-treasury/sends'/format(context['nonce'],'020d')
        require(not path.exists() and not path.is_symlink(),'Treasury nonce reservation exists')
    first=treasury_send_phase_facts(root,control,controller,policy,context,challenge)
    require(first['grant_state']=='exact' and first['audit_state']=='not_consumed'
        and first['reservation']=='absent' and all(value is None for value in first['files'].values()),
        'Exact unaudited unused treasury grant and absent nonce required')
    sends=root/'keys/formation-treasury/sends'
    if sends.exists():
        for other in sends.iterdir():
            names={path.name for path in other.iterdir()}
            require(names in ({'request.json','prepared.json','admission.json'},
                {'request.json','prepared.json','admission.json','dispatch-intent.json'}),'Unknown or partial treasury nonce exists')
            raw=controller.direct(other/'request.json',True,2*1024*1024).read_bytes()
            require(hashlib.sha256(raw).hexdigest()!=context['request_sha256'],'Original treasury request has a reservation')
            previous=json.loads(raw);parameters=previous.get('parameters') if isinstance(previous,dict) else None
            require(isinstance(previous,dict) and set(previous)=={'version','operation','parameters'}
                and type(previous['version']) is int and previous['version']==1 and previous['operation']=='treasury_send_prepare'
                and isinstance(parameters,dict) and type(parameters.get('nonce')) is int and parameters['nonce']==int(other.name)
                and parameters.get('formation_sha256')==context['formation_sha256']
                and parameters.get('genesis_sha256')==context['genesis_pins'].get('genesis.json'),'Other treasury reservation is unattributed')
            for name,limit in (('prepared.json',128*1024),('admission.json',1024*1024),('dispatch-intent.json',4096)):
                if name in names:controller.direct(other/name,True,limit)
    pins=context['genesis_pins']
    require(isinstance(pins,dict) and set(pins)=={'genesis.json','authority.json','authority-root.pub'},'Exact signed Genesis pins required')
    for name,pin in pins.items():
        require(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin)
            and hashlib.sha256(controller.direct(root/'network'/name,True,4*1024*1024).read_bytes()).hexdigest()==pin,
            'Installed signed Genesis changed')
    absent()
    require(treasury_send_phase_facts(root,control,controller,policy,context,challenge)==first,'Treasury phase changed during proof')
    absent()
    return {'schema':'nodenetwork-treasury-send-not-applied-v1','challenge':challenge,
        'request_sha256':context['request_sha256'],'nonce':context['nonce'],
        'authorization_sha256':context['authorization']['sha256'],'not_applied':True,'mutation_performed':False}


def continuation_not_applied_proof(wire,transport=False,readiness=False,commission=False,treasury=False,treasury_not_applied=False):
    """Native-embedded proof only; never stages authorization or changes target state."""
    import time
    require(sum((transport,readiness,commission,treasury,treasury_not_applied))<=1,'Conflicting continuation proof modes')
    treasury=treasury or treasury_not_applied
    require(isinstance(wire,dict) and set(wire)==({'context','challenge'} if transport or commission or treasury else {'context','pending_json','challenge'}),'Exact continuation proof required')
    context=wire['context'];now=int(time.time())
    require(isinstance(context,dict) and set(context)==({'initial_sha256','authorization','formation_sha256','target','selection','genesis_pins',('request_sha256' if commission or treasury else 'pending_sha256'),'expires_at'}|({'artifact_sha256','dispatch_sha256'} if transport or readiness else {'nonce'} if treasury else set()))
            and type(context['expires_at']) is int and now<=context['expires_at']<=now+120,'Continuation proof expired')
    for value in (wire['challenge'],context['initial_sha256'],context['formation_sha256'],context['request_sha256' if commission or treasury else 'pending_sha256']):
        require(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value),'Invalid continuation proof pin')
    require(context['initial_sha256']==globals().get('NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256'),'No native initial approval')
    if not transport and not commission and not treasury:
        raw=wire['pending_json'];require(isinstance(raw,str) and len(raw.encode())<=65536,'Continuation exceeds bound')
        # Expiry is not extended: historical structure is validated solely for cancellation.
        value=json.loads(raw);expiry=value.get('expires_at')
        require(type(expiry) is int and expiry>0,'Invalid original continuation expiry')
        pending=authorization_document(raw,context['pending_sha256'],expiry-1)
    elif transport:require(isinstance(context['dispatch_sha256'],str) and re.fullmatch('[a-f0-9]{64}',context['dispatch_sha256']),'Invalid transport dispatch')
    root=ROOT;control=root/'tmp/controller';path=control/'policy.json'
    for ancestor in (control,*control.parents):
        m=ancestor.lstat();require(stat.S_ISDIR(m.st_mode) and not ancestor.is_symlink() and m.st_uid==os.geteuid() and not m.st_mode&0o022,'Unsafe proof ancestry')
    m=path.lstat();require(stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid() and stat.S_IMODE(m.st_mode)==0o600 and m.st_size<=1024*1024,'Unsafe proof policy')
    policy=json.loads(path.read_bytes())
    for name in enrolled_engine(policy):
        path=control/name if name=='controller.py' else control/'tools'/name;m=path.lstat()
        require(path.resolve()==path and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid() and not m.st_mode&0o022 and m.st_size<=1024*1024
                and hashlib.sha256(path.read_bytes()).hexdigest()==policy['engine_files'][name],'Enrolled proof engine drift')
    sys.path[:0]=[str(control),str(control/'tools')]
    from controller import Controller,control_inventory,engineering_effective_selection,MUTATIONS
    import lifecycle as life
    with life._lifecycle_lock(root):
        controller=Controller(root);control_inventory(root)
        require(engineering_effective_selection(root,policy)==context['selection'],'Continuation selection changed')
        if not transport and not commission and not treasury:require(pending['requests'][0]['operation'] in MUTATIONS,'Unknown pending operation')
        receipt,_=life._sealed_receipt(root)
        require(receipt['package_sha256']==context['selection']['manifest_sha256'],'Installed master changed')
        if treasury_not_applied:return treasury_send_not_applied_facts(root,control,controller,policy,context,wire['challenge'])
        if treasury:return treasury_send_phase_facts(root,control,controller,policy,context,wire['challenge'])
        if commission:
            pin=commission_absence_facts(root,control,controller,policy,context)
            return {'schema':'nodenetwork-commission-not-applied-v1','challenge':wire['challenge'],
                'request_sha256':context['request_sha256'],'authorization_sha256':context['authorization']['sha256'],
                'readiness_sha256':pin,'not_applied':True,'mutation_performed':False}
        key=(readiness_absence_facts(root,control,controller,policy,context,pending) if readiness else
             transport_absence_facts(root,control,controller,policy,context) if transport else continuation_absence_facts(root,control,controller,policy,context,pending))
        return {'schema':'nodenetwork-readiness-not-applied-v1' if readiness else 'nodenetwork-transport-not-applied-v1' if transport else 'nodenetwork-continuation-not-applied-v1','challenge':wire['challenge'],
                'pending_sha256':context['pending_sha256'],('dispatch_sha256' if transport or readiness else 'request_sha256'):key,'parent_sha256':context['authorization']['sha256'],
                'not_applied':True,'mutation_performed':False}


HANDOFF_UNITS=('synergy-chain1266-role@rpc-gateway.service','synergy-canary-rpc-relay.service','synergy-vpn.service')
HANDOFF_MANAGED_UNIT_LINKS={
    '/etc/systemd/system/synergy-canary-rpc-relay.service':'/opt/Synergy/systemd/synergy-canary-rpc-relay.service',
    '/etc/systemd/system/synergy-vpn.service':'/opt/Synergy/systemd/synergy-vpn.service',
    '/etc/systemd/system/synergy-node.service':'/opt/Synergy/systemd/synergy-node.service',
}
HANDOFF_FILES={
    'nginx_rpc':'/etc/nginx/sites-available/testnet-core-rpc.synergy-network.io',
    'nginx_origin_only':'/etc/nginx/snippets/synergy-cloudflare-origin-only.conf',
    'nginx_origin_aop':'/etc/nginx/snippets/synergy-cloudflare-aop.conf',
    'nginx_source_map':'/etc/nginx/conf.d/synergy-cloudflare-origin-source.conf',
    'tls_public_certificate':'/etc/nginx/ssl/synergy/cloudflare-origin-synergy-network.pem',
    'tunnel_unit':'/etc/systemd/system/synergy-chain1266-rpc-tunnel.service',
}


def _handoff_secure_parents(path):
    for parent in path.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,
                'Unsafe handoff parent')


def _handoff_file_stamp(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,
            info.st_gid,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _handoff_public(path,limit=131072):
    path=Path(path)
    require(path.is_absolute() and path.resolve()==path,'Noncanonical handoff public file')
    _handoff_secure_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and not info.st_mode&0o022 and 0<info.st_size<=limit,'Unsafe handoff public file')
        with os.fdopen(os.dup(fd),'rb') as stream:
            digest=hashlib.sha256();data=bytearray()
            for chunk in iter(lambda:stream.read(min(limit+1,1024*1024)),b''):
                digest.update(chunk)
                if limit<=131072:data.extend(chunk)
                require(stream.tell()<=limit,'Handoff public file exceeds bound')
        require(_handoff_file_stamp(os.fstat(fd))==_handoff_file_stamp(info)==_handoff_file_stamp(path.lstat()),
                'Handoff public file changed')
        return digest.hexdigest(),bytes(data)
    finally:os.close(fd)


def _handoff_unit_pin(fragment):
    managed=HANDOFF_MANAGED_UNIT_LINKS.get(fragment)
    if managed is None:
        return _handoff_public(fragment)[0]
    # These two legacy registrations link to files inside their managed root.
    # The target itself is still read as a canonical, fixed, root-owned file.
    path=Path(fragment)
    _handoff_secure_parents(path)
    before=path.lstat()
    require(stat.S_ISLNK(before.st_mode) and before.st_uid==0 and before.st_nlink==1
            and os.readlink(path)==managed and path.resolve()==Path(managed),'Unexpected legacy unit link')
    pin,_=_handoff_public(managed)
    require(_handoff_file_stamp(path.lstat())==_handoff_file_stamp(before)
            and os.readlink(path)==managed,'Legacy unit link changed')
    return pin


def _handoff_command(args,limit=65536,timeout=5):
    import selectors
    import time
    process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    deadline=time.monotonic()+timeout;output=bytearray()
    try:
        while True:
            remaining=deadline-time.monotonic()
            require(remaining>0 and selector.select(remaining),'Handoff command timed out')
            chunk=os.read(process.stdout.fileno(),min(65536,limit+1-len(output)))
            if not chunk:break
            output.extend(chunk);require(len(output)<=limit,'Handoff observation exceeds bound')
        require(process.wait(timeout=max(0.001,deadline-time.monotonic()))==0,'Handoff command refused')
        return bytes(output)
    finally:
        selector.close();process.stdout.close()
        if process.poll() is None:process.kill();process.wait()


def _handoff_unit(name,fragment,executable):
    raw=_handoff_command(['/usr/bin/systemctl','show',name,
        '--property=ActiveState,MainPID,FragmentPath,DropInPaths'],8192).decode('utf-8')
    values=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
    require(set(values)=={'ActiveState','MainPID','FragmentPath','DropInPaths'}
            and values['FragmentPath']==fragment and not values['DropInPaths']
            and values['ActiveState'] in ('active','inactive','failed')
            and re.fullmatch('[0-9]{1,10}',values['MainPID']),'Unattributed handoff service')
    pin=_handoff_unit_pin(fragment)
    pid=values['MainPID'];active=values['ActiveState']=='active'
    require(active==(pid!='0'),'Ambiguous handoff service state')
    if active:
        require(os.readlink('/proc/'+pid+'/exe')==executable,'Foreign handoff service process')
    return pin,active,pid


def _handoff_root_entries(root,allowed):
    # This is bounded depth-one metadata, never private contents or a claim of
    # recursive ownership. Retirement still requires separate attribution.
    root=Path(root);info=root.lstat()
    require(root.resolve()==root and stat.S_ISDIR(info.st_mode) and info.st_uid==0
            and not info.st_mode&0o022,'Unattributed legacy root')
    entries=[];blockers=set()
    with os.scandir(root) as stream:
        for entry in stream:
            if len(entries)==64:
                blockers.add('inventory_bound_exceeded');break
            item=entry.stat(follow_symlinks=False)
            kind='directory' if stat.S_ISDIR(item.st_mode) else 'file' if stat.S_ISREG(item.st_mode) else 'other'
            entries.append([entry.name,kind,stat.S_IMODE(item.st_mode),item.st_uid,item.st_gid])
            if entry.name not in allowed or kind=='other' or item.st_uid!=0 or item.st_mode&0o022 or (entry.name=='README.md' and (kind!='file' or stat.S_IMODE(item.st_mode)!=0o600 or item.st_nlink!=1)):
                blockers.add('foreign_resources')
    raw=json.dumps(sorted(entries),sort_keys=True,separators=(',',':')).encode()
    return hashlib.sha256(raw).hexdigest(),blockers


LEGACY_CANARY_RUNTIME_DIRECTORIES = {
    'cache', 'config', 'data', 'data/consensus', 'data/consensus/authority-transitions',
    'evidence', 'keys', 'keys/apqe', 'logs', 'network', 'recovery', 'run',
    'snapshots', 'systemd', 'tmp', 'vpn', 'vpn/netbird', 'vpn/root',
}
LEGACY_CANARY_RUNTIME_FILES = {
    'config/canary-rpc-relay.json', 'config/node.json', 'installation.json',
    'data/consensus/authority-transitions/.synergy-writer.lock',
    *(f'data/consensus/authority-transitions/epoch-{epoch:020d}.json' for epoch in range(2, 6)),
    *(f'evidence/{name}.json' for name in (
        'authority-recovery-completed', 'gateway-bootstrap-pin', 'host-integrations',
        'upgrade-completed', 'vpn-enrollment', 'vpn-gateway-route', 'vpn-server-binding')),
    *(f'keys/apqe/{name}' for name in (
        'gateway-enrollment.json', 'gateway-transport.encrypted.json', 'gateway-transport.unlock')),
    *(f'logs/{name}' for name in ('canary-rpc-relay.log', 'netbird-service.log', 'netbird.log')),
    *(f'network/{name}' for name in (
        'authority-recovery-certificate.json', 'authority-root.pub', 'authority.json',
        'genesis.json', 'network-manifest.json', 'rpc-gateway-admission.json',
        'transport-registry.json', 'transport-root.pub')),
    *(f'systemd/synergy-{name}.service' for name in ('canary-rpc-relay', 'node', 'vpn')),
    'tools/netbird-client', 'vpn/active_profile.json', 'vpn/default.json',
    'vpn/netbird/active_profile.txt', 'vpn/state.json',
}


def _legacy_upper_inventory(base=Path('/opt/Synergy'), *, attribute_runtime=False):
    """Old-only opaque commitment v1: recursive metadata + sealed SOFTWARE.

    The closed wire field stays upper_root_entries_sha256. Its old-only meaning
    is now domain-separated below; it is NOT a digest of private contents or a
    complete ownership/removal assertion. Unknown runtime is always unattributed.
    The generic gateway handoff retains its original depth-one interpretation.
    """
    import time
    base=Path(base)
    package_pin,raw=_handoff_public(base/'package.json')
    require(package_pin=='ef491eddd06e4145abc1f396b3c363cb2a7f2ec2d582d1d05cf5d28c6dfc679f','Exact old software manifest required')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'Duplicate legacy manifest field');value[key]=item
        return value
    package=json.loads(raw,object_pairs_hook=unique);files=package.get('files')
    require(isinstance(files,dict) and 0<len(files)<=128,'Bounded legacy software map required')
    runtime_dirs = LEGACY_CANARY_RUNTIME_DIRECTORIES
    if attribute_runtime:
        pin, roles_raw = _handoff_public(base/'roles/roles.json')
        require(pin == files.get('roles/roles.json'), 'Legacy role catalog differs')
        roles = json.loads(roles_raw, object_pairs_hook=unique)['roles']
        require(isinstance(roles, list) and len(roles) == 20
                and all(isinstance(role, str) and re.fullmatch('[a-z0-9_]{1,40}', role) for role in roles),
                'Legacy role directory catalog differs')
        runtime_dirs = runtime_dirs | {'roles/' + role for role in roles}
    software_dirs=set()
    for name,pin in files.items():
        require(isinstance(name,str) and len(name.encode())<=512 and isinstance(pin,str)
                and re.fullmatch('[a-f0-9]{64}',pin),'Invalid legacy software commitment')
        parts=PurePosixPath(name).parts
        require(parts and len(parts)<=12 and '/'.join(parts)==name and not name.startswith('/')
                and all(part not in ('.','..') and len(part.encode())<=128 for part in parts)
                and (name=='README.md' or len(parts)>1 and parts[0] in {'bin','lib','assets','systemd','tools','roles'}),
                'Manifest member is not attributable public software')
        software_dirs.update('/'.join(parts[:i]) for i in range(1,len(parts)))
    require(base.resolve()==base,'Noncanonical legacy inventory root')
    _handoff_secure_parents(base)
    bare_mounts(base) # also rejects same-device bind mounts; never unmounts.
    opened=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    deadline=time.monotonic()+15;records=[];verified={};blockers=set();total_bytes=0
    def metadata(info):
        return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    def walk(directory,prefix,depth):
        nonlocal total_bytes
        require(depth<=12 and time.monotonic()<deadline,'Legacy inventory bound exceeded')
        before=os.fstat(directory)
        with os.scandir(directory) as stream:
            for entry in stream:
                require(len(records)<512 and time.monotonic()<deadline,'Legacy inventory entry bound exceeded')
                name=entry.name;relative=prefix+name
                require(len(relative.encode())<=512 and len(name.encode())<=128,'Legacy inventory path bound exceeded')
                info=os.stat(name,dir_fd=directory,follow_symlinks=False)
                require(info.st_dev==root.st_dev,'Legacy inventory crosses a mount')
                kind='directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'socket' if stat.S_ISSOCK(info.st_mode) else 'other'
                classification='software' if relative in files else 'software_directory' if relative in software_dirs else 'manifest' if relative=='package.json' else 'runtime_unattributed'
                socket_attributed = attribute_runtime and relative == 'run/netbird.sock' and kind == 'socket' and stat.S_IMODE(info.st_mode) == 0o666
                if attribute_runtime:
                    if (kind == 'directory' and relative in runtime_dirs
                            or kind == 'file' and relative in LEGACY_CANARY_RUNTIME_FILES or socket_attributed):
                        classification = 'legacy_gateway_runtime'
                    if classification == 'runtime_unattributed' or info.st_gid != 0:
                        blockers.add('foreign_resources')
                records.append([relative,kind,classification,metadata(info)])
                if info.st_uid!=0 or info.st_mode&0o022 and not socket_attributed or kind=='file' and info.st_nlink!=1 or kind=='other':
                    blockers.add('foreign_resources')
                if not prefix and name not in DIRECTORIES|{'package.json','installation.json','README.md'}:
                    blockers.add('foreign_resources')
                if relative in files:
                    require(kind=='file' and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o022
                            and 0<info.st_size<=256*1024*1024,'Unsafe declared legacy software')
                    total_bytes+=info.st_size
                    require(total_bytes<=512*1024*1024,'Legacy software byte bound exceeded')
                    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
                    try:
                        require(metadata(os.fstat(fd))==metadata(info),'Legacy software inode changed')
                        digest=hashlib.sha256();size=0
                        while True:
                            require(time.monotonic()<deadline,'Legacy software read timed out')
                            chunk=os.read(fd,1024*1024)
                            if not chunk:break
                            size+=len(chunk);require(size<=info.st_size,'Legacy software grew')
                            digest.update(chunk)
                        require(size==info.st_size and digest.hexdigest()==files[relative]
                                and metadata(os.fstat(fd))==metadata(info)
                                and metadata(os.stat(name,dir_fd=directory,follow_symlinks=False))==metadata(info),
                                'Legacy software bytes or metadata differ')
                        verified[relative]=files[relative]
                    finally:os.close(fd)
                elif relative in software_dirs:
                    require(kind=='directory','Declared legacy software parent differs')
                if kind=='directory':
                    require(info.st_uid==0 and not info.st_mode&0o022,'Unsafe legacy subtree ownership or mode')
                    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
                    try:
                        require(metadata(os.fstat(fd))==metadata(info),'Legacy directory changed')
                        walk(fd,relative+'/',depth+1)
                    finally:os.close(fd)
                require(metadata(os.stat(name,dir_fd=directory,follow_symlinks=False))==metadata(info),
                        'Legacy entry changed during inventory')
        require(metadata(os.fstat(directory))==metadata(before),'Legacy directory inventory changed')
    try:
        root=os.fstat(opened)
        require(stat.S_ISDIR(root.st_mode) and root.st_uid==0 and not root.st_mode&0o022
                and metadata(base.lstat())==metadata(root),'Unsafe legacy root')
        walk(opened,'',0)
        require(verified==files and metadata(base.lstat())==metadata(root),'Incomplete legacy software inventory')
        bare_mounts(base)
        require(_handoff_public(base/'package.json')==(package_pin,raw) and time.monotonic()<deadline,'Legacy manifest changed')
        committed={'schema':'legacy-canary-upper-attributed-v1' if attribute_runtime else 'legacy-canary-upper-recursive-v1','package_sha256':package_pin,
                   'root_metadata':metadata(root),'entries':sorted(records),'software_sha256':verified}
        return hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':')).encode()).hexdigest(),blockers
    finally:os.close(opened)


def _gateway_handoff_snapshot(*, canary_only=False):
    files={key:_handoff_public(path)[0] for key,path in HANDOFF_FILES.items()}
    enabled=Path('/etc/nginx/sites-enabled/testnet-core-rpc.synergy-network.io')
    require(enabled.is_symlink() and enabled.lstat().st_uid==0
            and enabled.resolve()==Path(HANDOFF_FILES['nginx_rpc']),'Unattributed enabled RPC frontend')
    _,routes=_handoff_public(HANDOFF_FILES['nginx_rpc'])
    # Hash raw bytes, but never attribute an inactive commented directive.
    routes=b'\n'.join(line.split(b'#',1)[0] for line in routes.splitlines())
    require(set(re.findall(rb'proxy_pass\s+([^;\s]+)\s*;',routes))=={
        b'http://127.0.0.1:5640',b'http://127.0.0.1:5660',
        b'http://127.0.0.1:6030/metrics',b'http://127.0.0.1:9100/metrics'},'Unexpected RPC upstream scope')
    metrics_route=re.findall(rb'location\s*=\s*/metrics/node-rpc\s*\{([^{}]*)\}',routes)
    require(len(metrics_route)==1
            and re.findall(rb'(allow|deny)\s+([^;\s]+)\s*;',metrics_route[0])==[(b'allow',b'209.145.50.9'),(b'deny',b'all')]
            and re.findall(rb'proxy_pass\s+([^;\s]+)\s*;',metrics_route[0])==[b'http://127.0.0.1:6030/metrics'],
            'Unattributed metrics consumer route')
    tunnel,active,pid=_handoff_unit('synergy-chain1266-rpc-tunnel.service',HANDOFF_FILES['tunnel_unit'],'/usr/bin/ssh')
    require(tunnel==files['tunnel_unit'],'Tunnel registration changed')
    tunnel_owned=False
    if active:
        with Path('/proc/'+pid+'/cmdline').open('rb') as stream:args=stream.read(16385)
        require(len(args)<=16384,'Tunnel command exceeds bound')
        args=args.rstrip(b'\0').split(b'\0')
        forwards=[args[i+1] for i,arg in enumerate(args[:-1]) if arg==b'-L']
        tunnel_owned=(set(forwards)=={b'127.0.0.1:5640:127.0.0.1:5640',b'127.0.0.1:5660:127.0.0.1:5660'}
                      and len(forwards)==2 and args[-1]==b'root@62.146.182.207'
                      and not any(arg.startswith((b'-R',b'-D')) for arg in args))
    listeners=_handoff_command(['/usr/bin/ss','-H','-lntp']).decode('utf-8')
    owns=lambda port,owner:any(re.search(r'\b127\.0\.0\.1:'+str(port)+r'\s',line)
        and 'pid='+owner+',' in line for line in listeners.splitlines())
    preserved={'files':files,'tunnel_active':active and tunnel_owned,
               'rpc_listener_owned':active and owns(5640,pid),'ws_listener_owned':active and owns(5660,pid)}
    role='/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/bin/synergy-rpc-gateway-node'
    role_pin,role_active,role_pid=_handoff_unit(HANDOFF_UNITS[0],'/etc/systemd/system/synergy-chain1266-role@.service',role)
    canary_pin,canary_active,canary_pid=_handoff_unit(HANDOFF_UNITS[1],'/etc/systemd/system/'+HANDOFF_UNITS[1],'/opt/Synergy/bin/synergy-node')
    vpn_pin,vpn_active,vpn_pid=_handoff_unit(HANDOFF_UNITS[2],'/etc/systemd/system/'+HANDOFF_UNITS[2],'/opt/Synergy/bin/netbird')
    lower,lower_blockers=_handoff_root_entries('/opt/synergy',{'chain1266'})
    upper,upper_blockers=(_legacy_upper_inventory() if canary_only else
                          _handoff_root_entries('/opt/Synergy',DIRECTORIES|{'package.json','installation.json'}))
    # A verified software map never attributes residual runtime or authorizes
    # removal. Keep these blockers even for a complete recursive commitment.
    blockers={'metrics_resolution_required','explicit_retirement_approval_required','legacy_inventory_requires_attribution'}|(set() if canary_only else lower_blockers)|upper_blockers
    if not all(preserved[k] for k in ('tunnel_active','rpc_listener_owned','ws_listener_owned')):
        blockers.add('protected_attribution_failed')
    metrics={'unit_sha256':role_pin,'service_active':role_active,
        'listener_owned':role_active and owns(6030,role_pid),'consumer_ip':'209.145.50.9','resolution':'unresolved'}
    if not metrics['listener_owned']:blockers.add('legacy_attribution_failed')
    legacy={'canary_executable_sha256':_handoff_public('/opt/Synergy/bin/synergy-node',256*1024*1024)[0],
        'canary_unit_sha256':canary_pin,'vpn_unit_sha256':vpn_pin,
        'canary_active':canary_active,'vpn_active':vpn_active,
        'lower_root_entries_sha256':lower,'upper_root_entries_sha256':upper}
    if not canary_only:
        legacy['chain1266_executable_sha256']=_handoff_public(role,256*1024*1024)[0]
    else:
        # Observe protected 1266 registrations/processes only. Do not authenticate
        # or alter its independently owned binary tree as part of old Canary scope.
        legacy['old_network'],legacy['vpn_binding']=_legacy_canary_identity()
        legacy['canary_pid']=int(canary_pid);legacy['vpn_pid']=int(vpn_pid)
        preserved['rpc_tunnel_pid']=int(pid);preserved['metrics_pid']=int(role_pid)
        preserved['files']['canary_frontend']=_handoff_public('/etc/nginx/conf.d/synergy-canary-rpc.conf')[0]
        blockers.discard('metrics_resolution_required')
        blockers.add('legacy_peer_retirement_required')
    return {'preserved':preserved,'metrics':metrics,'legacy':legacy,
            'candidate_units':list(HANDOFF_UNITS[1:] if canary_only else HANDOFF_UNITS),'blockers':sorted(blockers)}


def _legacy_canary_identity():
    base=Path('/opt/Synergy')
    package_pin,package_raw=_handoff_public(base/'package.json')
    require(package_pin=='ef491eddd06e4145abc1f396b3c363cb2a7f2ec2d582d1d05cf5d28c6dfc679f','Independently attributed legacy package required')
    package=json.loads(package_raw);readme_pin,_=_handoff_public(base/'README.md')
    require(isinstance(package.get('files'),dict) and package['files'].get('README.md')==readme_pin,
            'Legacy README must match attributed package')
    node_pin,node_raw=_handoff_public(base/'config/node.json')
    relay_pin,relay_raw=_handoff_public(base/'config/canary-rpc-relay.json')
    node=json.loads(node_raw);relay=json.loads(relay_raw)
    require(node.get('network_id')=='posy-apqe-canary-process-49028' and node.get('chain_id')==99999
            and type(node['chain_id']) is int and node.get('role')=='rpc_gateway'
            and node.get('genesis_path')==str(base/'network/genesis.json')
            and relay.get('node_config_path')==str(base/'config/node.json')
            and relay.get('listen_address')=='127.0.0.1:8552','Exact obsolete Canary identity required')
    genesis_pin,_=_handoff_public(base/'network/genesis.json',1024*1024)
    require(genesis_pin=='d28ab09b6857f670482580a786edd939b090e88aa9378cdd0ad91379a724a9d7',
            'Obsolete Canary Genesis differs')
    enrollment_pin,enrollment_raw=_handoff_public(base/'evidence/vpn-enrollment.json',16384)
    binding_pin,binding_raw=_handoff_public(base/'evidence/vpn-server-binding.json',16384)
    local=json.loads(enrollment_raw);remote=json.loads(binding_raw)
    key='EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M='
    require(enrollment_pin=='f27a0e0031ba00f2a234e77e55449ca5f4b9a15dec7e2c8da3da5bde6ea37573'
            and binding_pin=='1629d857606c040ecbd7ed9d5dc692ac697dda3b129cc1f8b2bb9834e594d5f2'
            and local.get('native_enrollment_verified') is True
            and remote.get('server_binding_verified') is True
            and local.get('hostname')==remote.get('peer_name')=='synergy-canary-rpc-99999'
            and local.get('overlay_address')=='10.69.51.205/16' and remote.get('ip')=='10.69.51.205'
            and local.get('management_url')=='https://vpn-coordinator.synergy-network.io:443'
            and remote.get('peer_id')=='dboqb9if611ohpqo0e1g' and remote.get('hostname')=='vmi3381382'
            and local.get('wireguard_public_key')==remote.get('wireguard_public_key')==key,
            'Exact obsolete Canary VPN binding required')
    # This reader cannot authenticate provider-side absence or execute retirement.
    # A receipt appearing later must be independently reconciled, never adopted.
    receipt=base/'evidence/vpn-retirement.json'
    require(not receipt.exists() and not receipt.is_symlink(),'Legacy peer retirement requires separate reconciliation')
    return ({'network_id':node['network_id'],'chain_id':99999,'genesis_sha256':genesis_pin,
             'node_config_sha256':node_pin,'relay_config_sha256':relay_pin},
            {'enrollment_sha256':enrollment_pin,'binding_sha256':binding_pin,
             'peer_id':remote['peer_id'],'peer_name':remote['peer_name'],'hostname':remote['hostname'],
             'ip':remote['ip'],'wireguard_public_key':key,'management_origin':'https://vpn-coordinator.synergy-network.io',
             'retirement_verified':False})


def _handoff_machine():
    raw=_handoff_public('/etc/machine-id',4096)[1].strip()
    require(re.fullmatch(b'[a-f0-9]{32}',raw),'Canonical handoff machine identity required')
    # The retained independently verified pin hashes canonical 32-hex ASCII,
    # excluding the machine-id file's terminal newline.
    return hashlib.sha256(raw).hexdigest()


def gateway_handoff_plan(wire, *, canary_only=False):
    import time
    require(os.geteuid()==0 and isinstance(wire,dict) and set(wire)=={'context','challenge'},'Exact handoff read required')
    context=wire['context'];challenge=wire['challenge']
    require(isinstance(context,dict) and set(context)=={'target','machine_id_sha256','expires_at'}
            and context['target']=={'kind':'remote','host':'167.86.83.83','port':22,'root':'/opt/synergy'}
            and type(context['target']['port']) is int
            and isinstance(challenge,str) and re.fullmatch('[a-f0-9]{64}',challenge)
            and type(context['expires_at']) is int and int(time.time())<context['expires_at']<=int(time.time())+120,
            'Exact short-lived handoff context required')
    machine=_handoff_machine()
    require(machine==context['machine_id_sha256'],'Handoff machine differs')
    facts=_gateway_handoff_snapshot(canary_only=canary_only)
    require(_gateway_handoff_snapshot(canary_only=canary_only)==facts and _handoff_machine()==machine
            and int(time.time())<context['expires_at'],'Handoff scope changed')
    committed={'target':context['target'],'machine_id_sha256':machine,**facts}
    pin=hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'schema':'nodenetwork-legacy-canary-retirement-plan-v1' if canary_only else 'nodenetwork-legacy-gateway-handoff-plan-v1','challenge':challenge,
        **committed,'plan_sha256':pin,'mutation_performed':False,'removal_authorized':False,'automatic_retry':False}


LEGACY_CANARY_RETIREMENT_RECEIPT_SHA256 = 'e88b81a2ea6e12ef767eb65e14e0aedbe88be8bb6b6b26bfd362dba1e791b9ee'
LEGACY_CANARY_MACHINE_SHA256 = '8683ea9f4da9e9c05c26b6d8070cc13c0f5f75b0cd4a4de863492164f4c1e26d'


def _legacy_canary_stoppable(unit):
    """Require the exact linked legacy service and exclude stop propagation."""
    required = {
        'Id': unit, 'LoadState': 'loaded', 'UnitFileState': 'linked',
        'NeedDaemonReload': 'no', 'KillMode': 'control-group',
    }
    optional = {'CanStop', 'ExecStop', 'ExecStopPost', 'Job', 'RequiredBy', 'RequisiteOf',
                'WantedBy', 'BoundBy', 'ConsistsOf', 'PropagatesStopTo', 'TriggeredBy',
                'OnFailure', 'OnSuccess'}
    keys = sorted(required.keys() | optional)
    raw = _handoff_command(['/usr/bin/systemctl', 'show', '--all', unit,
                            '--property=' + ','.join(keys)], 8192).decode('utf-8')
    pairs = [line.split('=', 1) for line in raw.splitlines() if '=' in line]
    values = dict(pairs)
    require(len(values) == len(pairs) and values.keys() <= set(keys)
            and all(values.get(key) == value for key, value in required.items())
            and values.get('CanStop') == 'yes', 'Legacy unit is not safely stoppable')
    dependent = HANDOFF_UNITS[1] if unit == HANDOFF_UNITS[2] else ''
    for key in optional - {'CanStop'}:
        allowed = ('', dependent) if key in ('RequiredBy', 'WantedBy') else ('',)
        require(values.get(key, '') in allowed, 'Unexpected legacy unit stop dependency or hook')


def _legacy_canary_quiesce_scope():
    facts = _gateway_handoff_snapshot(canary_only=True)
    protected = facts['preserved']
    metrics = facts['metrics']
    legacy = dict(facts['legacy'])
    # Live log timestamps and the VPN control socket are not stable across a
    # service stop. They still require separate attribution before removal.
    legacy.pop('upper_root_entries_sha256')
    for unit in HANDOFF_UNITS[1:]:
        _legacy_canary_stoppable(unit)
    return {'preserved': protected, 'metrics': metrics, 'legacy': legacy}


def _legacy_canary_review(wire, apply):
    import time
    require(os.geteuid() == 0 and isinstance(wire, dict)
            and set(wire) == {'context', 'challenge', 'retirement_receipt_sha256', 'reviewed_sha256'},
            'Exact legacy service review required')
    context, challenge, reviewed = wire['context'], wire['challenge'], wire['reviewed_sha256']
    pin = lambda value: isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value)
    require(isinstance(context, dict) and set(context) == {'target', 'machine_id_sha256', 'expires_at'}
            and context['target'] == {'kind': 'remote', 'host': '167.86.83.83', 'port': 22, 'root': '/opt/synergy'}
            and type(context['target']['port']) is int and pin(challenge)
            and context['machine_id_sha256'] == LEGACY_CANARY_MACHINE_SHA256
            and type(context['expires_at']) is int and int(time.time()) < context['expires_at'] <= int(time.time()) + 120
            and wire['retirement_receipt_sha256'] == LEGACY_CANARY_RETIREMENT_RECEIPT_SHA256
            and (pin(reviewed) if apply else reviewed is None), 'Invalid legacy service review scope')
    machine = _handoff_machine()
    require(machine == context['machine_id_sha256'], 'Legacy service machine differs')
    return context, challenge, reviewed, machine


def legacy_canary_quiesce(wire, *, apply=False):
    """Review or stop exactly two obsolete services. Leave both roots intact."""
    import fcntl
    import time
    context, challenge, reviewed, machine = _legacy_canary_review(wire, apply)
    root = Path('/opt/Synergy')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        opened = os.fstat(directory)
        require(opened.st_uid == 0 and stat.S_IMODE(opened.st_mode) == 0o700
                and os.path.samestat(opened, root.lstat()), 'Legacy service root changed')
        before = _legacy_canary_quiesce_scope()
        scope = {'target': context['target'], 'machine_id_sha256': machine,
                 'retirement_receipt_sha256': LEGACY_CANARY_RETIREMENT_RECEIPT_SHA256, **before}
        digest = hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(int(time.time()) < context['expires_at'] and os.path.samestat(opened, root.lstat()),
                'Legacy service review expired or root changed')
        stopped = []
        if apply:
            require(reviewed == digest, 'Legacy service review changed before dispatch')
            state = before
            for unit, active, pid in zip(HANDOFF_UNITS[1:], ('canary_active', 'vpn_active'), ('canary_pid', 'vpn_pid')):
                if not state['legacy'][active]:
                    continue
                require(int(time.time()) < context['expires_at'] and os.path.samestat(opened, root.lstat()),
                        'Legacy service review expired before stop')
                _legacy_canary_stoppable(unit)
                _handoff_command(['/usr/bin/systemctl', '--job-mode=fail', 'stop', unit], 4096, timeout=40)
                expected = {**state, 'legacy': {**state['legacy'], active: False, pid: 0}}
                state = _legacy_canary_quiesce_scope()
                require(state == expected and _handoff_machine() == machine
                        and os.path.samestat(opened, root.lstat()), 'Legacy stop or protected service could not be reconciled')
                stopped.append(unit)
        return {'schema': 'nodenetwork-legacy-canary-quiescence-v1', 'challenge': challenge,
                **scope, 'reviewed_sha256': digest, 'stopped_units': stopped,
                'applied': apply, 'files_removed': False}
    finally:
        os.close(directory)


def _legacy_canary_root_scope(root):
    facts = _legacy_canary_quiesce_scope()
    require(not facts['legacy']['canary_active'] and not facts['legacy']['vpn_active'],
            'Stop both obsolete services before reviewing removal')
    inventory, blockers = _legacy_upper_inventory(root, attribute_runtime=True)
    require(not blockers, 'Legacy gateway contains an unattributed resource')
    package_pin, package_raw = _handoff_public(root/'package.json')
    installation = json.loads(_handoff_public(root/'installation.json')[1])
    require(installation['root'] == str(root) and installation['role'] == 'rpc_gateway'
            and installation['network_id'] == facts['legacy']['old_network']['network_id']
            and installation['chain_id'] == 99999 and installation['consensus_started'] is False
            and installation['package_sha256'] == package_pin
            and installation['package_files'] == json.loads(package_raw)['files'],
            'Legacy gateway installation differs')
    unit_directory = Path('/etc/systemd/system')
    plan = json.loads(_handoff_public(root/'evidence/host-integrations.json')[1])
    expected = [str(unit_directory/unit) for unit in ('synergy-node.service', HANDOFF_UNITS[2], HANDOFF_UNITS[1])]
    require(plan.get('root') == str(root) and plan.get('paths') == expected
            and set(plan.get('sha256', {})) == set(expected), 'Legacy unit record differs')
    registered = {}
    for name in expected:
        path = Path(name)
        unit = path.name
        pin, _ = _handoff_public(root/'systemd'/unit)
        require(pin == plan['sha256'][name], 'Legacy recorded unit bytes differ')
        if unit == 'synergy-node.service' and not path.exists() and not path.is_symlink():
            require(inert_missing_unit(unit), 'A loaded validator conflicts with gateway removal')
            continue
        observed, running, _ = _handoff_unit(unit, name, str(root/'bin/synergy-node'))
        require(observed == pin and not running, 'Legacy unit changed or restarted')
        _legacy_canary_stoppable(unit)
        registered[unit] = pin
    for process in Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            image=os.readlink(process/'exe').removesuffix(' (deleted)')
            with (process/'cmdline').open('rb') as stream:
                args = stream.read(131073).split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        require(not image.startswith(str(root) + '/')
                and not any(arg.startswith(os.fsencode(root) + b'/') for arg in args),
                'Legacy gateway process still owns the root')
    return {**facts, 'upper_inventory_sha256': inventory, 'registered_units': registered}


def legacy_canary_remove(wire, *, apply=False):
    """Unregister and remove only the attributed, stopped obsolete gateway."""
    import fcntl
    import time
    context, challenge, reviewed, machine = _legacy_canary_review(wire, apply)
    root = Path('/opt/Synergy')
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        opened = os.fstat(directory)
        require(opened.st_uid == 0 and stat.S_IMODE(opened.st_mode) == 0o700
                and os.path.samestat(opened, root.lstat()), 'Legacy removal root changed')
        scope = {'target': context['target'], 'machine_id_sha256': machine,
                 'retirement_receipt_sha256': LEGACY_CANARY_RETIREMENT_RECEIPT_SHA256,
                 **_legacy_canary_root_scope(root)}
        pin = hashlib.sha256(json.dumps(scope, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(os.path.samestat(opened, root.lstat()) and _handoff_machine() == machine
                and int(time.time()) < context['expires_at'], 'Legacy review expired or target changed')
        if apply:
            require(reviewed == pin and shutil.rmtree.avoids_symlink_attacks, 'Exact attributed legacy removal required')
            bare_mounts(root)
            for unit, digest in scope['registered_units'].items():
                _legacy_canary_stoppable(unit)
                fragment = Path('/etc/systemd/system')/unit
                observed, active, _ = _handoff_unit(unit, str(fragment), str(root/'bin/synergy-node'))
                require(observed == digest and not active, 'A legacy registration changed')
            inventory, blockers = _legacy_upper_inventory(root, attribute_runtime=True)
            require(not blockers and inventory == scope['upper_inventory_sha256']
                    and os.path.samestat(opened, root.lstat())
                    and int(time.time()) < context['expires_at'], 'Retirement inventory changed before removal')
            for unit in scope['registered_units']:
                (Path('/etc/systemd/system')/unit).unlink()
            _handoff_command(['/usr/bin/systemctl', 'daemon-reload'], 4096, timeout=30)
            require(all(inert_missing_unit(unit) for unit in (*HANDOFF_UNITS[1:], 'synergy-node.service')),
                    'Legacy service registrations could not be reconciled')
            bare_mounts(root)
            inventory, blockers = _legacy_upper_inventory(root, attribute_runtime=True)
            require(not blockers and inventory == scope['upper_inventory_sha256']
                    and os.path.samestat(opened, root.lstat())
                    and not os.path.samestat(opened, ROOT.lstat()),
                    'Legacy root changed or aliases the protected installation')
            shutil.rmtree(root)
            require(not root.exists() and not root.is_symlink()
                    and _handoff_root_entries('/opt/synergy', {'chain1266'})[0] == scope['legacy']['lower_root_entries_sha256'],
                    'Obsolete root removal or preserved root could not be verified')
        return {'schema':'nodenetwork-legacy-canary-root-retirement-v1', 'challenge':challenge,
                **scope, 'reviewed_sha256':pin, 'removed':apply}
    finally:
        os.close(directory)


LEGACY_PEER_KEY_BINARY = Path('/opt/synergy/netbird/bin/netbird-combined')
LEGACY_PEER_KEY_STORE = Path('/opt/synergy/netbird/lib/store.db')
LEGACY_PEER_KEY_BINARY_SHA256 = 'e01941ced937e0a5dff7b02b8ae2be38b6efa6b3be03ec9b89d0b7f52a16c292'
LEGACY_PEER_KEY_REVISION = '79a06720b684768b421f0a54f3bb14f22704994f'
LEGACY_PEER_KEY_ACCOUNT = 'da99e12f611ghl16dvjg'
LEGACY_PEER_KEY_ID = 'dboqb9if611ohpqo0e1g'
LEGACY_PEER_KEY_SHA256 = '5e781088b3b0a7cd2862ee1010b5f84ce4f91ebc1abbbce92a10a0dc8563159f'


def _legacy_peer_key_inode(info):
    return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink


def _legacy_peer_key_file(path,limit):
    require(path.is_absolute() and path.resolve()==path,'Noncanonical peer store member')
    _handoff_secure_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
                and not info.st_mode&0o022 and 0<=info.st_size<=limit
                and _legacy_peer_key_inode(info)==_legacy_peer_key_inode(path.lstat()),'Unsafe peer store member')
        return fd,info
    except BaseException:
        os.close(fd);raise


def _legacy_peer_key_process(binary,store,proc=Path('/proc')):
    # No caller-selected PID/command. Exactly one current root owner must open
    # this exact store inode using the exact pinned executable image.
    candidates=[]
    with os.scandir(proc) as stream:
        for count,entry in enumerate(stream):
            require(count<32768,'Process inventory exceeds bound')
            if not re.fullmatch('[1-9][0-9]{0,9}',entry.name):continue
            base=proc/entry.name
            try:exe=os.readlink(base/'exe')
            except (FileNotFoundError,PermissionError,ProcessLookupError):continue
            if exe!=str(LEGACY_PEER_KEY_BINARY):continue
            require(_legacy_peer_key_inode((base/'exe').stat())==_legacy_peer_key_inode(binary),'Peer process executable differs')
            raw=(base/'status').read_bytes();require(len(raw)<=16384,'Peer process status exceeds bound')
            uid=re.findall(rb'^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$',raw,re.M)
            require(uid==[(b'0',b'0',b'0',b'0')],'Peer process owner differs')
            raw=(base/'stat').read_bytes();require(len(raw)<=8192,'Peer process identity exceeds bound')
            suffix=raw.rsplit(b')',1)[-1].split()
            require(len(suffix)>=20 and suffix[0]!=b'Z' and suffix[19].isdigit(),'Peer process start identity unavailable')
            opened=[]
            with os.scandir(base/'fd') as descriptors:
                for n,entryfd in enumerate(descriptors):
                    require(n<4096,'Peer process descriptor inventory exceeds bound')
                    try:link=os.readlink(entryfd.path)
                    except FileNotFoundError:continue
                    if link==str(LEGACY_PEER_KEY_STORE):
                        require(_legacy_peer_key_inode(Path(entryfd.path).stat())==_legacy_peer_key_inode(store),'Peer process store inode differs')
                        opened.append(entryfd.name)
            require(opened,'Peer process does not own exact store')
            candidates.append((entry.name,suffix[19].decode(),tuple(sorted(opened))))
    require(len(candidates)==1,'Unique current peer store owner required')
    return candidates[0]


def legacy_peer_key_proof(wire):
    import base64
    import sqlite3
    import time
    require(os.geteuid()==0 and sys.platform=='linux','Linux root peer owner observation required')
    require(isinstance(wire,dict) and set(wire)=={'context','challenge'},'Exact peer proof request required')
    context=wire['context'];challenge=wire['challenge']
    require(isinstance(context,dict) and set(context)=={'account_id','peer_id','wireguard_public_key_sha256','expires_at'}
            and context['account_id']==LEGACY_PEER_KEY_ACCOUNT and context['peer_id']==LEGACY_PEER_KEY_ID
            and context['wireguard_public_key_sha256']==LEGACY_PEER_KEY_SHA256
            and isinstance(challenge,str) and re.fullmatch('[a-f0-9]{64}',challenge)
            and type(context['expires_at']) is int and int(time.time())<context['expires_at']<=int(time.time())+120,
            'Exact short-lived peer proof context required')
    deadline=time.monotonic()+8;fds=[];connection=None
    try:
        binary_fd,binary=_legacy_peer_key_file(LEGACY_PEER_KEY_BINARY,256*1024*1024);fds.append(binary_fd)
        require(_handoff_public(LEGACY_PEER_KEY_BINARY,256*1024*1024)[0]==LEGACY_PEER_KEY_BINARY_SHA256,'Peer owner binary differs')
        store_fd,store=_legacy_peer_key_file(LEGACY_PEER_KEY_STORE,2*1024*1024*1024);fds.append(store_fd)
        header=os.pread(store_fd,100,0)
        require(len(header)==100 and header[:16]==b'SQLite format 3\0' and header[18:20]==b'\1\1','Unsupported peer store journal mode')
        members=[(LEGACY_PEER_KEY_BINARY,binary_fd,binary),(LEGACY_PEER_KEY_STORE,store_fd,store)]
        # Deployed owner uses DELETE journal mode. Refuse every recovery/WAL
        # companion; WAL read marks would write SHM even with mode=ro. Never
        # immutable=1 on a live store, and never create/copy any database files.
        sidecars=[Path(str(LEGACY_PEER_KEY_STORE)+tail) for tail in ('-wal','-shm','-journal')]
        require(all(not p.exists() and not p.is_symlink() for p in sidecars),'Unsupported peer store companion')
        owner=_legacy_peer_key_process(binary,store)
        connection=sqlite3.connect(LEGACY_PEER_KEY_STORE.as_uri()+'?mode=ro',uri=True,timeout=0.25)
        require(connection.execute('PRAGMA journal_mode').fetchone()==('delete',),'Unsupported peer store journal profile')
        connection.execute('PRAGMA query_only=ON')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.set_progress_handler(lambda:1 if time.monotonic()>deadline else 0,1000)
        def authorize(action,table,column,database,trigger):
            if action==sqlite3.SQLITE_SELECT:return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_FUNCTION and column in ('length','typeof'):return sqlite3.SQLITE_OK
            if action==sqlite3.SQLITE_READ and table=='peers' and column in ('account_id','id','key','name','ip') and database=='main':return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        connection.set_authorizer(authorize)
        rows=connection.execute("SELECT account_id,id,CASE WHEN typeof(key)='text' AND length(CAST(key AS BLOB))=44 THEN key END,CASE WHEN typeof(name)='text' AND length(CAST(name AS BLOB))=24 THEN name END,CASE WHEN typeof(ip)='text' AND length(CAST(ip AS BLOB))=14 THEN ip END FROM peers WHERE account_id=? AND id=? LIMIT 2",
                                (LEGACY_PEER_KEY_ACCOUNT,LEGACY_PEER_KEY_ID)).fetchall()
        require(len(rows)==1,'Unique exact peer row required')
        account,peer,key,name,ip=rows[0]
        require(account==LEGACY_PEER_KEY_ACCOUNT and peer==LEGACY_PEER_KEY_ID
                and name=='synergy-canary-rpc-99999' and type(ip) is str
                and ip=='"10.69.51.205"','Peer row identity differs')
        require(type(key) is str and re.fullmatch('[A-Za-z0-9+/]{43}=',key),'Canonical peer public key required')
        decoded=base64.b64decode(key,validate=True)
        require(len(decoded)==32 and base64.b64encode(decoded).decode()==key
                and hashlib.sha256(decoded).hexdigest()==LEGACY_PEER_KEY_SHA256,'Peer public key differs')
        connection.close();connection=None
        require(_legacy_peer_key_process(binary,store)==owner,'Peer store owner changed')
        for path,fd,info in members:
            require(_legacy_peer_key_inode(os.fstat(fd))==_legacy_peer_key_inode(info)==_legacy_peer_key_inode(path.lstat()),'Peer owner path changed')
        require(_handoff_file_stamp(os.fstat(binary_fd))==_handoff_file_stamp(binary)
                and _handoff_public(LEGACY_PEER_KEY_BINARY,256*1024*1024)[0]==LEGACY_PEER_KEY_BINARY_SHA256
                and all(not p.exists() and not p.is_symlink() for p in sidecars)
                and os.pread(store_fd,20,0)[18:20]==b'\1\1'
                and int(time.time())<context['expires_at'] and time.monotonic()<deadline,'Peer proof scope changed')
        return {'schema':'nodenetwork-legacy-peer-key-proof-v1','challenge':challenge,
                'account_id':account,'peer_id':peer,'wireguard_public_key_sha256':LEGACY_PEER_KEY_SHA256,
                'ip':'10.69.51.205','peer_name':name,'provider_binary_sha256':LEGACY_PEER_KEY_BINARY_SHA256,
                'provider_revision':LEGACY_PEER_KEY_REVISION,'verified':True,'mutation_performed':False}
    finally:
        if connection is not None:connection.close()
        for fd in reversed(fds):os.close(fd)


def main():
    global _UPDATE_PHASE,_UPGRADE_PROOF_PHASE
    _UPDATE_PHASE=None;_UPGRADE_PROOF_PHASE=None
    try:
        if sys.argv[1:]==['--legacy-peer-key-proof']:
            raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'Peer proof input exceeds bound')
            def unique_peer_fields(pairs):
                value={}
                for name,item in pairs:
                    require(name not in value,'Duplicate peer proof field');value[name]=item
                return value
            operation=legacy_peer_key_proof(json.loads(raw,object_pairs_hook=unique_peer_fields))
        elif sys.argv[1:] in (['--gateway-handoff-plan'],['--legacy-canary-retirement-plan']):
            raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'Handoff context exceeds bound')
            operation=gateway_handoff_plan(json.loads(raw),canary_only=sys.argv[1:]==['--legacy-canary-retirement-plan'])
        elif sys.argv[1:] in (['--legacy-canary-quiesce-plan'], ['--legacy-canary-quiesce']):
            raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'Legacy service review exceeds bound')
            operation=legacy_canary_quiesce(json.loads(raw),apply=sys.argv[1:]==['--legacy-canary-quiesce'])
        elif sys.argv[1:] in (['--legacy-canary-root-plan'], ['--legacy-canary-root-retire']):
            raw=sys.stdin.buffer.read(4097);require(len(raw)<=4096,'Legacy root review exceeds bound')
            operation=legacy_canary_remove(json.loads(raw),apply=sys.argv[1:]==['--legacy-canary-root-retire'])
        elif len(sys.argv)==2 and sys.argv[1]=='--inspect-update-commission-grant':
            raw=sys.stdin.buffer.read(65537);require(len(raw)<=65536,'Preservation proof exceeds bound')
            operation=inspect_update_commission_grant(json.loads(raw))
        elif len(sys.argv)==2 and sys.argv[1] in ('--continuation-not-applied-proof','--prove-transport-not-applied','--prove-readiness-not-applied','--commission-outcome-proof','--treasury-send-phase-proof','--treasury-send-not-applied-proof'):
            raw=sys.stdin.buffer.read(131073);require(len(raw)<=131072,'Continuation proof exceeds bound')
            operation=continuation_not_applied_proof(json.loads(raw),sys.argv[1]=='--prove-transport-not-applied',sys.argv[1]=='--prove-readiness-not-applied',sys.argv[1]=='--commission-outcome-proof',sys.argv[1]=='--treasury-send-phase-proof',sys.argv[1]=='--treasury-send-not-applied-proof')
        elif len(sys.argv)==2 and sys.argv[1]=='--upgrade-not-applied-proof':
            raw=sys.stdin.buffer.read(2*1024*1024+1);require(len(raw)<=2*1024*1024,'Upgrade proof input exceeds bound')
            operation=upgrade_not_applied_proof(json.loads(raw))
        elif len(sys.argv)==4 and sys.argv[1]=='--bare-rollback-preflight':
            operation=bare_rollback(sys.argv[2],sys.argv[3])
        elif len(sys.argv)==5 and sys.argv[1]=='--bare-rollback-apply':
            operation=bare_rollback(sys.argv[2],sys.argv[3],sys.argv[4])
        elif len(sys.argv)==2 and sys.argv[1]=='--stage-engineering-authorization':
            operation=stage_engineering_authorization(sys.stdin.buffer)
        elif len(sys.argv)==4 and sys.argv[1]=='--reconcile-engineering-update':
            operation=stage_engineering_update(None,sys.argv[2],sys.argv[3],reconcile=True)
        elif len(sys.argv)==4 and sys.argv[1]=='--stage-engineering-update':
            operation=stage_engineering_update(sys.stdin.buffer,sys.argv[2],sys.argv[3])
        else:
            require(len(sys.argv)==1,'Unsupported bootstrap invocation')
            operation=bootstrap(sys.stdin.buffer)
        result={'version':1,'ok':True,'result':operation}
    except Exception:
        if sys.argv[1:]==['--legacy-peer-key-proof']:
            result={'version':1,'ok':False,'error':{'code':'legacy_peer_key_proof_refused','message':'Exact legacy peer key observation refused; no resources changed'}}
        elif sys.argv[1:] in (['--gateway-handoff-plan'],['--legacy-canary-retirement-plan']):
            result={'version':1,'ok':False,'error':{'code':'gateway_handoff_refused','message':'Legacy gateway handoff observation refused; no resources changed'}}
        elif sys.argv[1:] in (['--legacy-canary-quiesce-plan'], ['--legacy-canary-quiesce']):
            result={'version':1,'ok':False,'error':{'code':'legacy_canary_quiescence_unverified',
                'message':'The two obsolete services could not be verified. Review their current state before dispatching another stop.'}}
        elif sys.argv[1:] in (['--legacy-canary-root-plan'], ['--legacy-canary-root-retire']):
            result={'version':1,'ok':False,'error':{'code':'legacy_canary_root_retirement_unverified',
                'message':'Legacy remote removal was not verified. Inspect the original root and registrations before continuing.'}}
        elif sys.argv[1:]==['--upgrade-not-applied-proof'] and _UPGRADE_PROOF_PHASE in UPGRADE_PROOF_PHASES:
            result={'version':1,'ok':False,'error':{'code':'upgrade_proof_'+_UPGRADE_PROOF_PHASE+'_refused','message':'Read-only upgrade proof refused'}}
        elif _UPDATE_PHASE in UPDATE_PHASES:
            result={'version':1,'ok':False,'error':{'code':'engineering_update_'+_UPDATE_PHASE+'_refused',
                'message':'Engineering update refused at '+UPDATE_PHASES[_UPDATE_PHASE]+'. Inspect and reconcile the exact target; no validator was activated.'}}
        else:result={'version':1,'ok':False,'error':{'code':'bootstrap_refused','message':'Bootstrap validation or enrollment failed; no validator activated'}}
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
