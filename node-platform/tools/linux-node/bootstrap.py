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
def engine_names(files):
    return (*ENGINE,'guest_lifecycle.py') if 'tools/guest_lifecycle.py' in files else ENGINE

def initial_engine_pins(stage, manifest):
    # The extractor already authenticated this exact manifest. Include optional
    # qualified modules in policy only when the pinned package actually owns them.
    return {name:hashlib.sha256((stage/'tools'/name).read_bytes()).hexdigest()
            for name in engine_names(manifest['files'])}

def enrolled_engine(policy):
    names=set(policy.get('engine_files',{}))
    require(names in (set(ENGINE),set((*ENGINE,'guest_lifecycle.py'))),'Incomplete enrolled engine')
    return tuple(sorted(names))

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
            if operation=='list-units' and len(fields)>=4 and fields[1:4]==['not-found','inactive','dead']:continue
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
    """Only cancel an exact independently pinned, wholly unused first grant set.

    Policy/grant files do not authenticate their own completeness. The native
    app supplies the original public approval bytes after its compiled pin check.
    Expiry cannot grant new authority here: even expired grants must all remain.
    """
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
        require(operation in ('install','commission','register','start','stop','restart','upgrade','uninstall',
            'identity_generate','formation_prepare','treasury_prepare','genesis_stage','genesis_bind','network_formation_prepare',
            'network_formation_sign','network_transport_prepare','network_transport_sign','vpn_enroll','vpn_bind','vpn_retire',
            'guest_create','guest_stop','guest_remove') and key not in grants,'Invalid initial grant inventory')
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
    require(isinstance(context,dict) and set(context)=={'initial_sha256','parent_sha256','formation_sha256','target','selection','release_id','manifest_sha256','expires_at'},
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


def stage_engineering_update(stream, release_id, pin):
    """Adopt a sealed candidate and its controller on a quiescent engineering host.

    The root operator supplies the independently authenticated pin. This
    neither grants an upgrade request nor replaces installed validator files.
    """
    import ctypes
    import fcntl
    import time
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
        receipt,_=_sealed_receipt(root)
        network=receipt['network_id']
        previous=effective_engineering_selection(root,policy)
        context=engineering_update_context(policy,previous,release_id,pin,int(time.time()))
        require(receipt.get('role')=='validator'
                and all(receipt.get(key)==previous[key] for key in ('network_id','chain_id','node_name')),
                'Installed validator differs from the independently approved engineering selection')
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
        return {'schema':'nodenetwork-update-stage-v1','stagedRelease':release_id,'manifestSha256':pin,'controllerAdopted':True,'validatorUpgraded':False,'initial_sha256':context['initial_sha256'],'parent_sha256':context['parent_sha256']}
    finally:
        os.close(lock)



# Only an independently pinned isolated native build can authorize this path.
# The document is not a public policy issuer, membership proof or credential API.
AUTHORIZATION_PROFILE='nodenetwork-isolated-formation-authorization-v1'
AUTHORIZATION_LIMIT=12*1024*1024
AUTHORIZATION_FILES={'commissioning-readiness.json':128*1024,'managed-guest.json':16384,'formation-context.json':4096,'vpn-ca.pem':128*1024,'vpn-provider.json':16384,'vpn-enrollment.json':16384,'vpn-server-binding.json':16384,'vpn-retirement.json':16384,
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
    if 'commissioning-readiness.json' in result:
        # This public evidence cannot carry configuration or any other grant.
        expected=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},
            sort_keys=True,separators=(',',':')).encode()).hexdigest()
        require(set(result)=={'commissioning-readiness.json'} and doc['requests']==[
            {'operation':'commission','request_sha256':expected}],
            'Readiness requires its one exact commissioning grant only')
    return result



def readiness_refresh_allowed(root,policy,doc,inputs,continuation,consumed):
    """Only an unused prestart readiness review can be superseded atomically.

    Called under the existing controller exchange lock after native-pin,
    target/selection/sequence and stopped-process verification. Other public
    inputs, custody and carrier credentials remain immutable.
    """
    name='commissioning-readiness.json';root=Path(root)
    source=root/'tmp/controller/authorization/inputs'/name
    if name not in inputs:return False
    from controller import Controller,request_digest
    c=Controller(root)
    if source.exists() or source.is_symlink():
        raw=c.direct(source,True,128*1024).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==policy.get('authorization_files',{}).get(name),
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
    grant=c.public_json(c.control/'grants'/(key+'.json'),True)
    require(grant=={'root':str(root),'operation':'commission','request_sha256':key,
        'expires_at':previous['expires_at'],'authorization_sha256':previous['sha256'],
        'authorization_sequence':previous['sequence']},'Original commissioning grant is absent, consumed or changed')
    require(not any((root/path).exists() or (root/path).is_symlink() for path in (
        'data','tmp/commissioning','tmp/existing-network-identity-request.json',
        'evidence/upgrade-intent.json','evidence/application-replacement-intent.json',
        'evidence/authority-recovery-intent.json','evidence/autonomous-epoch-intent.json'))
        and not any((root/'tmp').glob('commission-prepare-*')) and not any((root/'tmp').glob('commission-observe-*'))
        and all((root/name).is_dir() and not any((root/name).iterdir()) for name in ('config','network','keys')),
        'Readiness refresh refuses published or uncertain application state')
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


def stage_engineering_authorization(stream):
    """Atomic exact engineering grants through the native application's admin transport.

    No renderer pin or package content can authorize itself. Repeating an applied
    document returns the durable receipt without recreating a consumed grant.
    """
    import ctypes
    import fcntl
    import time
    require(os.geteuid()==0 and sys.platform=='linux' and os.uname().machine=='x86_64','Linux x86_64 root required')
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
                        and doc['requests'][0]['operation'] in ('stop','restart'))
        guest_policy_only=active_guest_policy_only(continuation,inputs,doc,policy)
        require(not active or pure_lifecycle or guest_policy_only,'Stop validator before artifact, formation or configuration authorization change')
        vpn=_unit_state('synergy-vpn.service')
        if not active:_assert_no_application_processes(ROOT,vpn_pid=vpn.get('MainPID'))
        requests=[];seen=set()
        for request in doc['requests']:
            require(request['operation'] in __import__('controller').MUTATIONS,'Authorization may grant only exact supported mutations')
            key=request['request_sha256'];require(key not in seen,'Duplicate exact request');seen.add(key)
            require(key not in consumed or continuation and request['operation'] in ('start','stop','restart'),'Consumed non-lifecycle request cannot be granted again')
            requests.append((request,key))
            if request['operation']=='vpn_enroll':require('vpn-enrollment.json' in inputs,'Exact one-use VPN input required')
            if request['operation']=='vpn_bind':require('vpn-server-binding.json' in inputs,'Exact native provider binding required')
            if request['operation']=='vpn_retire':require('vpn-retirement.json' in inputs,'Exact verified provider retirement required')
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
            require(set(commissioning)==FORMATION_PUBLIC_INPUTS,'Complete public commissioning inventory required')
            require(doc['genesis_pins'] is not None and all(commissioning['network/'+name]==pin for name,pin in doc['genesis_pins'].items()),'Commissioning Genesis differs from independent pins')
            policy['validator_commissioning_files']=commissioning
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


def main():
    try:
        if len(sys.argv)==4 and sys.argv[1]=='--bare-rollback-preflight':
            operation=bare_rollback(sys.argv[2],sys.argv[3])
        elif len(sys.argv)==5 and sys.argv[1]=='--bare-rollback-apply':
            operation=bare_rollback(sys.argv[2],sys.argv[3],sys.argv[4])
        elif len(sys.argv)==2 and sys.argv[1]=='--stage-engineering-authorization':
            operation=stage_engineering_authorization(sys.stdin.buffer)
        elif len(sys.argv)==4 and sys.argv[1]=='--stage-engineering-update':
            operation=stage_engineering_update(sys.stdin.buffer,sys.argv[2],sys.argv[3])
        else:
            require(len(sys.argv)==1,'Unsupported bootstrap invocation')
            operation=bootstrap(sys.stdin.buffer)
        result={'version':1,'ok':True,'result':operation}
    except Exception:result={'version':1,'ok':False,'error':{'code':'bootstrap_refused','message':'Bootstrap validation or enrollment failed; no validator activated'}}
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
