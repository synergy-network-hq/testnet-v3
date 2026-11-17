"""Bounded NodeNetwork-owned Linux guests. Never installs validator software.

The host's independently enrolled policy pins the image, toolchain and exact
resource/loopback endpoint. Renderer parameters can only confirm that selection.
No image downloads, host package installation, arbitrary shell or public binds.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess

from synergy_linux import digest, require, write_new

TOOLS = ('qemu-system-x86_64', 'qemu-img', 'ssh-keygen', 'genisoimage')
CREATE = {'guest_id', 'image_sha256', 'cpu_count', 'memory_mib', 'disk_gib'}
FILES = {'guest.service', 'disk.qcow2', 'seed.iso', 'ssh-host',
         'ssh-host.pub', 'user-data', 'meta-data', 'qemu.log'}
SYSTEM = Path('/etc/systemd/system')


def valid_id(value):
    return isinstance(value, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,31}', value) is not None


def validate_parameters(operation, parameters):
    require(isinstance(parameters, dict) and set(parameters) ==
            (CREATE if operation == 'guest_create' else {'guest_id'}), 'Exact guest parameters required')
    require(valid_id(parameters['guest_id']), 'Invalid managed guest identifier')
    if operation == 'guest_create':
        require(isinstance(parameters['image_sha256'], str)
                and re.fullmatch('[a-f0-9]{64}', parameters['image_sha256']), 'Exact approved image pin required')
        for key, low, high in (('cpu_count', 1, 32), ('memory_mib', 1024, 65536), ('disk_gib', 8, 512)):
            require(type(parameters[key]) is int and low <= parameters[key] <= high,
                    'Invalid bounded guest resource: '+key)


def checked(path, directory=False, maximum=None):
    path = Path(path)
    st = path.lstat()
    require(not path.is_symlink() and st.st_uid == os.geteuid()
            and (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1)
            and stat.S_IMODE(st.st_mode) == (0o700 if directory or path.name in TOOLS else 0o600)
            and (maximum is None or st.st_size <= maximum), 'Unsafe managed guest member')
    return path


def atomic(path, value):
    temporary = path.with_name('.'+path.name+'.tmp')
    require(not temporary.exists() and not temporary.is_symlink(), 'Interrupted guest receipt needs reconciliation')
    if path.exists() or path.is_symlink(): checked(path, maximum=32768)
    write_new(temporary, value)
    os.replace(temporary, path)
    sync(path.parent)


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def public_ssh(raw):
    fields = raw.decode('ascii').strip().split()
    require(len(fields) in (2, 3) and fields[0] == 'ssh-ed25519', 'Managed guest requires an Ed25519 SSH host identity')
    blob = base64.b64decode(fields[1], validate=True)
    require(base64.b64encode(blob).decode() == fields[1] and len(blob) == 51
            and blob[:19] == b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 ', 'Invalid SSH public key encoding')
    return 'ssh-ed25519 '+fields[1], 'SHA256:'+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def host_capacity(root, spec):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86_64 KVM host required')
    require(stat.S_ISCHR(Path('/dev/kvm').stat().st_mode) and os.access('/dev/kvm', os.R_OK | os.W_OK),
            'Accessible host KVM is required; no TCG fallback')
    values = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    require(int(values['MemAvailable'].split()[0])*1024 >= (spec['memory_mib']+2048)*1024**2,
            'Guest allocation would consume reserved host memory')
    require((os.cpu_count() or 0) >= spec['cpu_count']+2, 'Guest allocation must preserve two host CPUs')
    fs = os.statvfs(root)
    require(fs.f_bavail*fs.f_frsize >= (spec['disk_gib']+2)*1024**3,
            'Guest allocation would consume reserved host storage')


class GuestManager:
    def __init__(self, root, policy):
        self.root = Path(root)
        self.policy = policy
        checked(self.root, directory=True)
        require(self.root.is_absolute() and self.root.resolve() == self.root
                and re.fullmatch(r'/[A-Za-z0-9_/.-]+', str(self.root)), 'Canonical guest host root required')
        self.base = self.root/'hosted-machines'
        self.spec = policy.get('managed_guest')
        s = self.spec
        require(isinstance(s, dict) and set(s) == CREATE | {'version', 'tools', 'bios_sha256', 'ssh_forward_port', 'operator_ssh_public_key'}
                and type(s['version']) is int and s['version'] == 1 and isinstance(s['tools'], dict) and set(s['tools']) == set(TOOLS), 'Independent managed guest policy is missing or malformed')
        validate_parameters('guest_create', {key:s[key] for key in CREATE})
        require(type(s['ssh_forward_port']) is int and 1024 <= s['ssh_forward_port'] <= 65535,
                'Approved loopback SSH port is invalid')
        public_ssh(s['operator_ssh_public_key'].encode('ascii'))
        require(all(isinstance(pin, str) and re.fullmatch('[a-f0-9]{64}', pin) for pin in [*s['tools'].values(), s['bios_sha256']]),
                'Exact approved guest toolchain pins required')
        self.directory = self.base/s['guest_id']
        self.unit_name = 'synergy-guest-'+s['guest_id']+'.service'
        self.registration = SYSTEM/self.unit_name
        self.target = self.directory/'guest.service'

    def selected(self, parameters):
        require(parameters['guest_id'] == self.spec['guest_id'], 'Guest is not independently approved on this host')
        if 'image_sha256' in parameters:
            require(all(parameters[key] == self.spec[key] for key in CREATE), 'Reviewed guest image or resources changed')

    def command(self, argv, timeout=120):
        env = {'PATH':str(self.root/'lib/guest-tools/bin')+':/usr/bin:/bin',
               'HOME':str(self.root), 'TMPDIR':str(self.directory if self.directory.exists() else self.root/'tmp'),
               'LANG':'C', 'LC_ALL':'C'}
        result = subprocess.run([str(v) for v in argv], input=None, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
        require(result.returncode == 0, 'Managed guest native operation failed: '+Path(argv[0]).name)
        require(len(result.stdout) <= 1024*1024, 'Managed guest native response exceeds bound')
        return result.stdout

    def dependencies(self):
        checked(self.root/'lib', directory=True)
        checked(self.base, directory=True)
        checked(self.base/'images', directory=True)
        image = checked(self.base/'images/os.qcow2')
        require(digest(image) == self.spec['image_sha256'], 'Approved guest image changed')
        tools = self.root/'lib/guest-tools/bin'
        checked(tools.parent, directory=True); checked(tools, directory=True)
        for name in TOOLS:
            require(digest(checked(tools/name)) == self.spec['tools'][name], 'Approved guest toolchain changed')
        # No external backing chain or external data file is accepted.
        require(digest(checked(tools.parent/'bios.bin')) == self.spec['bios_sha256'], 'Approved guest firmware changed')
        self.command([tools/'qemu-system-x86_64', '--version'], timeout=30)
        info = json.loads(self.command([tools/'qemu-img', 'info', '--output=json', '-f', 'qcow2', image], timeout=30))
        require(info.get('format') == 'qcow2' and type(info.get('virtual-size')) is int
                and 0 < info['virtual-size'] <= self.spec['disk_gib']*1024**3
                and not info.get('backing-filename') and not info.get('full-backing-filename')
                and not info.get('format-specific', {}).get('data', {}).get('data-file'),
                'Guest image has an unsupported format, size or external dependency')
        return image, tools

    def argv(self):
        s = self.spec
        return [str(self.root/'lib/guest-tools/bin/qemu-system-x86_64'), '-no-user-config', '-nodefaults',
                '-bios', str(self.root/'lib/guest-tools/bios.bin'), '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', str(s['cpu_count']), '-m', str(s['memory_mib']),
                '-drive', 'file='+str(self.directory/'disk.qcow2')+',if=virtio,format=qcow2',
                '-drive', 'file='+str(self.directory/'seed.iso')+',if=virtio,format=raw,readonly=on',
                '-netdev', 'user,id=n0,ipv6=off,hostfwd=tcp:127.0.0.1:'+str(s['ssh_forward_port'])+'-:22',
                '-device', 'virtio-net-pci,netdev=n0,romfile=', '-display', 'none', '-serial', 'none', '-monitor', 'none',
                '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']

    def unit(self):
        # All arguments are fixed vocabulary, validated integer or root-owned path.
        command = ' '.join('"'+arg+'"' for arg in self.argv())
        return f'''[Unit]
Description=Synergy NodeNetwork managed Linux guest {self.spec['guest_id']}
After=network-online.target synergy-installation-guard.service
BindsTo=synergy-installation-guard.service
ConditionPathExists={self.base}/record.json

[Service]
Type=exec
User=root
UMask=0077
WorkingDirectory={self.directory}
ExecStart={command}
KillMode=control-group
TimeoutStopSec=60s
Restart=no
MemoryMax={(self.spec['memory_mib']+1024)*1024**2}
TasksMax=256
NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=false
ReadWritePaths={self.directory}
DevicePolicy=closed
DeviceAllow=/dev/kvm rw
StandardOutput=append:{self.directory}/qemu.log
StandardError=append:{self.directory}/qemu.log
'''.encode()

    def attributed_state(self, allow_absent=False):
        from lifecycle import _unit_state
        require(not self.registration.with_name(self.unit_name+'.d').exists(), 'Guest service override is not approved')
        if self.registration.exists() or self.registration.is_symlink():
            st = self.registration.lstat()
            require(stat.S_ISLNK(st.st_mode) and st.st_uid == os.geteuid()
                    and os.readlink(self.registration) == str(self.target), 'Guest service is foreign')
            require(checked(self.target).read_bytes() == self.unit(), 'Managed guest service bytes changed')
        else: require(allow_absent, 'Managed guest service is absent')
        state = _unit_state(self.unit_name)
        require(not state.get('DropInPaths') and state.get('FragmentPath', '') in ('', str(self.registration), str(self.target)),
                'Guest effective service is foreign')
        if not (self.registration.exists() or self.registration.is_symlink()):
            require(state.get('LoadState') == 'not-found' and state.get('MainPID', '0') == '0',
                    'Unattributed guest process or loaded service')
        if state.get('MainPID', '0') != '0': self.verify_process(state['MainPID'])
        return state

    def verify_process(self, pid):
        require(isinstance(pid,str) and pid.isdecimal() and int(pid)>1, 'Invalid managed guest PID')
        process=Path('/proc')/pid
        require(process.stat().st_uid == 0
                and (process/'exe').resolve() == self.root/'lib/guest-tools/bin/qemu-system-x86_64',
                'Managed guest process executable differs')
        with (process/'cmdline').open('rb') as stream: raw=stream.read(16385)
        require(len(raw)<=16384 and raw == b'\x00'.join(arg.encode() for arg in self.argv())+b'\x00',
                'Managed guest process arguments differ')

    def inventory(self):
        if not self.directory.exists() and not self.directory.is_symlink(): return set()
        checked(self.directory, directory=True)
        found = set()
        for path in self.directory.iterdir():
            require(path.name in FILES, 'Unexpected guest member; preserve for reconciliation')
            checked(path)
            found.add(path.name)
        return found

    def receipt(self):
        path = checked(self.base/'record.json', maximum=32768)
        value = json.loads(path.read_bytes())
        require(value.get('schema') == 'nodenetwork-guest-intent-v1' and value.get('root') == str(self.root)
                and value.get('selection') == self.spec and value.get('phase') in ('creating', 'start-dispatched', 'created')
                and re.fullmatch('[a-f0-9]{64}', value.get('request_sha256', '')), 'Guest receipt differs from approved selection')
        return value

    def status(self, parameters):
        self.selected(parameters)
        if not self.directory.exists() and not self.directory.is_symlink() and not (self.base/'record.json').exists():
            self.attributed_state(allow_absent=True)
            return {'schema':'nodenetwork-guest-status-v1', 'guest_id':self.spec['guest_id'], 'exists':False,
                    'validator_installed':False, 'ssh_identity_verified':False}
        self.inventory()
        receipt = self.receipt()
        state = self.attributed_state(allow_absent=receipt['phase'] != 'created')
        ready = receipt['phase'] in ('created', 'start-dispatched')
        if ready:
            require(self.inventory() == FILES, 'Guest preparation is incomplete')
            public, fingerprint = public_ssh(checked(self.directory/'ssh-host.pub', maximum=1024).read_bytes())
            require(fingerprint == receipt.get('ssh_host_fingerprint') and public == receipt.get('ssh_host_public_key'),
                    'Independent guest SSH host identity changed')
        return {'schema':'nodenetwork-guest-status-v1', 'guest_id':self.spec['guest_id'], 'exists':True,
                'phase':receipt['phase'], 'request_sha256':receipt['request_sha256'],
                'service_state':state.get('ActiveState'), 'pid':int(state.get('MainPID', '0')),
                'ssh_endpoint':{'host':'127.0.0.1','port':self.spec['ssh_forward_port']} if ready else None,
                'ssh_host_public_key':receipt.get('ssh_host_public_key') if ready else None,
                'ssh_host_fingerprint':receipt.get('ssh_host_fingerprint') if ready else None,
                'ssh_identity_verified':ready, 'validator_installed':False,
                'guest_os_reachability_verified':False, 'vpn_enrolled':False}

    def verify_guard(self):
        import root_guard
        source=Path(root_guard.__file__).read_bytes()
        unit=root_guard.render(self.root,self.policy['host_account'],source)
        pin=hashlib.sha256(unit).hexdigest()
        require(self.policy.get('root_guard_sha256')==pin, 'Managed guests require the current attributed deletion guard')
        root_guard.check_registration(pin)
        root_guard.verify_runtime(root_guard.UNIT,unit)

    def preflight(self, parameters):
        self.selected(parameters)
        self.verify_guard()
        self.dependencies()
        from lifecycle import _reject_installation_mounts
        _reject_installation_mounts(self.root)
        host_capacity(self.root, self.spec)
        require(not self.directory.exists() and not self.directory.is_symlink(), 'Existing guest must be reconciled')
        self.attributed_state(allow_absent=True)
        return {'schema':'nodenetwork-guest-preflight-v1', 'selection':{key:self.spec[key] for key in CREATE},
                'ssh_forward_port':self.spec['ssh_forward_port'], 'image_verified':True,
                'toolchain_pins_verified':True, 'kvm_verified':True, 'validator_installed':False}

    def create(self, parameters, request_sha256, authorize):
        self.selected(parameters)
        require(isinstance(request_sha256,str) and re.fullmatch('[a-f0-9]{64}',request_sha256), 'Invalid creation request digest')
        if self.directory.exists() or self.directory.is_symlink() or (self.base/'record.json').exists():
            receipt = self.receipt()
            require(receipt['request_sha256'] == request_sha256, 'Guest belongs to another creation request')
            return self.status(parameters) # Never regenerate keys or restart after an uncertain dispatch.
        self.preflight(parameters)
        require(not (self.base/'removed.json').exists(), 'Removed guest must not be regenerated by replaying its creation request')
        authorize()
        image, tools = self.dependencies()
        receipt = {'schema':'nodenetwork-guest-intent-v1', 'root':str(self.root), 'selection':self.spec,
                   'request_sha256':request_sha256, 'phase':'creating'}
        write_new(self.base/'record.json', receipt)
        self.directory.mkdir(mode=0o700); sync(self.base)
        self.command([tools/'ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', self.directory/'ssh-host'])
        (self.directory/'ssh-host.pub').chmod(0o600)
        public, fingerprint = public_ssh(checked(self.directory/'ssh-host.pub', maximum=1024).read_bytes())
        # SSH provisioning keys are host-private management data, never APQE authority.
        private = checked(self.directory/'ssh-host', maximum=4096).read_text()
        user_data = '#cloud-config\n'+json.dumps({'ssh_pwauth':False,'disable_root':True,
            'users':[{'name':'synergy','lock_passwd':True,'sudo':'ALL=(ALL) NOPASSWD:ALL',
                      'shell':'/bin/bash','ssh_authorized_keys':[self.spec['operator_ssh_public_key']]}],
            'ssh_deletekeys':True,'ssh_keys':{'ed25519_private':private,'ed25519_public':public}})+'\n'
        for name, value in (('user-data', user_data), ('meta-data', 'instance-id: synergy-'+self.spec['guest_id']+'\nlocal-hostname: synergy-'+self.spec['guest_id']+'\n')):
            fd = os.open(self.directory/name, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream: stream.write(value); stream.flush(); os.fsync(stream.fileno())
        del private, user_data
        self.command([tools/'qemu-img','create','-f','qcow2','-F','qcow2','-b', image,
                self.directory/'disk.qcow2', str(self.spec['disk_gib'])+'G'], timeout=120)
        self.command([tools/'genisoimage','-output',self.directory/'seed.iso','-volid','cidata','-joliet','-rock',
                      self.directory/'user-data',self.directory/'meta-data'])
        for name in ('disk.qcow2','seed.iso'):
            (self.directory/name).chmod(0o600); checked(self.directory/name)
            with (self.directory/name).open('rb') as stream: os.fsync(stream.fileno())
        fd = os.open(self.directory/'qemu.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600); os.close(fd)
        fd = os.open(self.target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(self.unit()); stream.flush(); os.fsync(stream.fileno())
        receipt.update(phase='start-dispatched',ssh_host_public_key=public,ssh_host_fingerprint=fingerprint)
        atomic(self.base/'record.json', receipt)
        self.dependencies() # Refuse drift before registering or executing the image.
        self.attributed_state(allow_absent=True)
        self.registration.symlink_to(self.target)
        sync(SYSTEM)
        self.command(['/usr/bin/systemctl','daemon-reload'])
        self.attributed_state()
        self.command(['/usr/bin/systemctl','start',self.unit_name])
        receipt['phase'] = 'created'; atomic(self.base/'record.json', receipt)
        return self.status(parameters)

    def stop(self, parameters, authorize):
        self.selected(parameters); self.inventory(); self.receipt()
        state = self.attributed_state()
        if state.get('MainPID', '0') == '0' and state.get('ActiveState') in ('inactive','failed'): return self.status(parameters)
        authorize()
        self.command(['/usr/bin/systemctl','stop',self.unit_name])
        state = self.attributed_state()
        require(state.get('MainPID', '0') == '0' and state.get('ActiveState') in ('inactive','failed'), 'Guest did not stop')
        return self.status(parameters)

    def remove(self, parameters, request_sha256, authorize):
        self.selected(parameters)
        tombstone = self.base/'removed.json'
        if tombstone.exists() or tombstone.is_symlink():
            value = json.loads(checked(tombstone, maximum=32768).read_bytes())
            require(value == {'schema':'nodenetwork-guest-removal-v1','guest_id':self.spec['guest_id'],
                             'request_sha256':request_sha256}, 'Guest removal request differs')
            if not self.directory.exists() and not (self.base/'record.json').exists():
                self.attributed_state(allow_absent=True)
                return {'schema':'nodenetwork-guest-status-v1','guest_id':self.spec['guest_id'],'exists':False,'removed':True}
        self.inventory(); self.receipt()
        from lifecycle import _reject_installation_mounts
        _reject_installation_mounts(self.root)
        state = self.attributed_state(allow_absent=True)
        require(state.get('MainPID', '0') == '0' and state.get('ActiveState') in ('inactive','failed'),
                'Explicitly stop the managed guest before removal')
        if not tombstone.exists():
            authorize()
            write_new(tombstone, {'schema':'nodenetwork-guest-removal-v1','guest_id':self.spec['guest_id'],
                                 'request_sha256':request_sha256})
        if self.registration.is_symlink(): self.registration.unlink(); sync(SYSTEM)
        self.command(['/usr/bin/systemctl','daemon-reload'])
        self.attributed_state(allow_absent=True)
        if self.directory.exists(): shutil.rmtree(self.directory)
        (self.base/'record.json').unlink(); sync(self.base)
        return {'schema':'nodenetwork-guest-status-v1','guest_id':self.spec['guest_id'],'exists':False,'removed':True}


def approved_inventory(root, policy):
    """Conformance delegates only exact pinned files and attributed guest state."""
    root = Path(root)
    base = root/'hosted-machines'
    if not base.exists() and not base.is_symlink(): return set()
    manager = GuestManager(root, policy)
    manager.dependencies()
    allowed = {base, base/'images', base/'images/os.qcow2'}
    if manager.directory.exists() or manager.directory.is_symlink() or (base/'record.json').exists():
        manager.status({'guest_id':manager.spec['guest_id']})
        allowed.add(checked(base/'record.json', maximum=32768))
        if manager.directory.exists(): allowed |= {manager.directory, *(manager.directory/name for name in manager.inventory())}
    if (base/'removed.json').exists() or (base/'removed.json').is_symlink():
        tombstone=checked(base/'removed.json', maximum=32768)
        value=json.loads(tombstone.read_bytes())
        require(isinstance(value,dict) and set(value)=={'schema','guest_id','request_sha256'}
                and value['schema']=='nodenetwork-guest-removal-v1' and value['guest_id']==manager.spec['guest_id']
                and isinstance(value['request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['request_sha256']),
                'Malformed guest removal receipt')
        allowed.add(tombstone)
    require(set(base.iterdir()) <= {base/'images', manager.directory, base/'removed.json', base/'record.json'}, 'Unattributed hosted guest directory')
    require(set((base/'images').iterdir()) == {base/'images/os.qcow2'}, 'Unexpected guest image inventory')
    tools = root/'lib/guest-tools'
    allowed |= {tools, tools/'bios.bin', tools/'bin', *(tools/'bin'/name for name in TOOLS)}
    require(set(tools.iterdir()) == {tools/'bin', tools/'bios.bin'} and set((tools/'bin').iterdir()) == {tools/'bin'/name for name in TOOLS},
            'Unexpected guest toolchain inventory')
    return {path.relative_to(root).as_posix() for path in allowed}


def require_removed(root):
    base = Path(root)/'hosted-machines'
    if base.exists():
        require(not (base/'record.json').exists(), 'Managed guest creation/removal must be reconciled first')
        require(not any(path.is_dir() for path in base.iterdir() if path.name != 'images'),
                'Remove managed guests through NodeNetwork before removing the host installation')
    for path in SYSTEM.glob('synergy-guest-*.service'):
        if path.is_symlink():
            require(not os.readlink(path).startswith(str(base)+'/'), 'Managed guest OS registration remains')

# Dedicated controller channel, not an SSH forwarding policy or destination API.
GUEST_SSH_MAGIC = b'SYNERGY-GUEST-SSH/1 '
GUEST_SSH_HEADER_LIMIT = 1024
GUEST_SSH_LIFETIME = 600
GUEST_SSH_BYTE_LIMIT = 512*1024*1024
GUEST_SSH_BUFFER = 64*1024


def read_guest_prefix(fd):
    """No buffered read-ahead: raw SSH bytes must remain on the same channel."""
    import select
    import time
    deadline=time.monotonic()+5
    data=bytearray()
    while len(data)<len(GUEST_SSH_MAGIC):
        remaining=deadline-time.monotonic()
        require(remaining>0 and select.select([fd],[],[],remaining)[0], 'Controller input prefix timed out')
        chunk=os.read(fd,len(GUEST_SSH_MAGIC)-len(data))
        if not chunk:break
        data.extend(chunk)
    return bytes(data)


def read_guest_header(fd):
    import select
    import time
    deadline=time.monotonic()+5
    raw=bytearray()
    while len(raw)+len(GUEST_SSH_MAGIC)<GUEST_SSH_HEADER_LIMIT:
        remaining=deadline-time.monotonic()
        require(remaining>0 and select.select([fd],[],[],remaining)[0], 'Managed guest header timed out')
        byte=os.read(fd,1)
        require(bool(byte),'Managed guest header incomplete')
        if byte==b'\n':break
        raw.extend(byte)
    else:raise ValueError('Managed guest header exceeds bound')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'Duplicate managed guest field');value[key]=item
        return value
    value=json.loads(raw.decode('ascii'),object_pairs_hook=unique)
    require(isinstance(value,dict) and set(value)=={'guest_id','create_request_sha256','ssh_host_fingerprint'}
            and valid_id(value['guest_id'])
            and isinstance(value['create_request_sha256'],str) and re.fullmatch('[a-f0-9]{64}',value['create_request_sha256'])
            and isinstance(value['ssh_host_fingerprint'],str) and re.fullmatch('SHA256:[A-Za-z0-9+/]{43}',value['ssh_host_fingerprint'])
            and json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')==bytes(raw),
            'Exact canonical managed guest binding required')
    return value


def guest_channel_address(manager, header):
    """Resolve only an active, current, host-policy-owned guest, never a caller address."""
    current=manager.status({'guest_id':header['guest_id']})
    require(current.get('exists') is True and current.get('phase')=='created'
            and current.get('service_state')=='active' and type(current.get('pid')) is int and current['pid']>1
            and current.get('ssh_identity_verified') is True
            and current.get('request_sha256')==header['create_request_sha256']
            and current.get('ssh_host_fingerprint')==header['ssh_host_fingerprint'],
            'Managed guest is inactive, changed or not authenticated')
    endpoint=current.get('ssh_endpoint',{})
    require(endpoint=={'host':'127.0.0.1','port':manager.spec['ssh_forward_port']},
            'Managed guest endpoint differs from approved loopback binding')
    return ('127.0.0.1',manager.spec['ssh_forward_port'])


def pump_guest_ssh(connection, input_fd, output_fd, *, lifetime=GUEST_SSH_LIFETIME,
                   byte_limit=GUEST_SSH_BYTE_LIMIT):
    """Bounded single raw SSH channel; stdin half-close drains the peer reply.

    No retries, reconnects, SSH parsing, credentials, listener or destination
    selection. The peer's EOF terminates the channel after draining its output.
    The native inner SSH layer still verifies the exact preprovisioned host key.
    """
    import selectors
    import time
    deadline=time.monotonic()+lifetime
    to_peer=bytearray();to_client=bytearray();sent_in=0;received_out=0
    input_open=True;peer_open=True;write_shutdown=False
    original={fd:os.get_blocking(fd) for fd in (input_fd,output_fd)}
    require(input_fd!=output_fd,'Distinct SSH channel input/output required')
    connection.setblocking(False)
    try:
        for fd in original:os.set_blocking(fd,False)
        with selectors.DefaultSelector() as poll:
            while True:
                if not input_open and not to_peer and not write_shutdown:
                    import socket
                    connection.shutdown(socket.SHUT_WR);write_shutdown=True
                if not peer_open and not to_client:return
                remaining=deadline-time.monotonic()
                require(remaining>0,'Managed guest channel lifetime exceeded')
                for key in list(poll.get_map().values()):poll.unregister(key.fileobj)
                if input_open and len(to_peer)<GUEST_SSH_BUFFER and peer_open:
                    poll.register(input_fd,selectors.EVENT_READ,'input')
                if to_client:poll.register(output_fd,selectors.EVENT_WRITE,'output')
                events=(selectors.EVENT_READ if peer_open and len(to_client)<GUEST_SSH_BUFFER else 0)
                if to_peer and peer_open:events|=selectors.EVENT_WRITE
                if events:poll.register(connection,events,'peer')
                for key,ready in poll.select(min(remaining,1)):
                    try:
                        if key.data=='input':
                            chunk=os.read(input_fd,GUEST_SSH_BUFFER-len(to_peer))
                            if not chunk:input_open=False
                            else:
                                sent_in+=len(chunk);require(sent_in<=byte_limit,'Managed guest input exceeds bound')
                                to_peer.extend(chunk)
                        elif key.data=='output':
                            count=os.write(output_fd,to_client);del to_client[:count]
                        else:
                            if ready&selectors.EVENT_READ:
                                chunk=connection.recv(GUEST_SSH_BUFFER-len(to_client))
                                if not chunk:peer_open=False
                                else:
                                    received_out+=len(chunk);require(received_out<=byte_limit,'Managed guest output exceeds bound')
                                    to_client.extend(chunk)
                            if ready&selectors.EVENT_WRITE and peer_open and to_peer:
                                count=connection.send(to_peer);del to_peer[:count]
                    except BlockingIOError:pass
    finally:
        connection.close()
        for fd,blocking in original.items():
            try:os.set_blocking(fd,blocking)
            except OSError:pass


def serve_guest_ssh(root, policy, input_fd, output_fd):
    import socket
    header=read_guest_header(input_fd)
    address=guest_channel_address(GuestManager(root,policy),header)
    connection=socket.create_connection(address,timeout=5)
    pump_guest_ssh(connection,input_fd,output_fd)
