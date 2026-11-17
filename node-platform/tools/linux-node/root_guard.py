"""Linux OS registration for an installation removed outside NodeNetwork."""
import base64
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time

UNIT = 'synergy-installation-guard.service'
HANDOVER = 'synergy-installation-guard-handover.service'
PROC = Path('/proc')
GUARD_READY_V1 = True
SYSTEM = Path('/etc/systemd/system')
ACCOUNT = 'synergy-nodenetwork'
ROOT_TAG = 'user.synergy_installation'
CONTROLLER_LINKS = {
    Path('/etc/ssh/sshd_config.d/synergy-nodenetwork.conf'): 'sshd.conf',
    Path('/etc/sudoers.d/synergy-nodenetwork'): 'sudoers',
}
# Stop the application before the transport it uses.
RUNTIME_UNITS = ('synergy-canary-rpc-relay.service', 'synergy-node.service', 'synergy-vpn.service')


def require(value, error):
    if not value:
        raise ValueError(error)


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=90).stdout


def systemctl(*args):
    return run('/usr/bin/systemctl', *args)


def paths():
    return SYSTEM / UNIT, SYSTEM / 'multi-user.target.wants' / UNIT


def info(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def root_identity(root):
    st = info(root)
    if st and stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022:
        try:
            return os.getxattr(root, ROOT_TAG, follow_symlinks=False).decode('ascii')
        except (FileNotFoundError, UnicodeDecodeError):
            return None
        except OSError as error:
            import errno
            if error.errno == errno.ENODATA:
                return None
            raise
    return None


def owned_link(path, target):
    st = info(path)
    if st is None:
        return False
    require(stat.S_ISLNK(st.st_mode) and st.st_uid == 0 and os.readlink(path) == str(target),
            'unattributed OS registration: ' + str(path))
    return True


def unit_digest(path):
    st = info(path)
    require(st and stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
            and not st.st_mode & 0o022 and st.st_size <= 32768, 'unsafe guard registration')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def state(unit):
    fields = systemctl('show', unit,
                       '--property=LoadState,FragmentPath,DropInPaths,ActiveState,MainPID,ControlPID,KillMode')
    return dict(line.split('=', 1) for line in fields.splitlines() if '=' in line)


def quiescent(observed):
    return (observed.get('ActiveState') in ('inactive', 'failed')
            and observed.get('MainPID') == '0' and observed.get('ControlPID') == '0')


def check_registration(pin):
    unit, link = paths()
    require(isinstance(pin, str) and re.fullmatch(r'[a-f0-9]{64}', pin), 'guard is not attributed to this installation')
    require(unit_digest(unit) == pin and owned_link(link, unit), 'guard registration differs')
    observed = state(UNIT)
    require(observed.get('FragmentPath') == str(unit) and not observed.get('DropInPaths')
            and observed.get('ActiveState') == 'active', 'installation guard is not active')


def validate_inputs(root, account, source):
    require(str(root) == '/opt/synergy' and re.fullmatch(r'Synergy NodeNetwork [a-f0-9]{32}', account['label'])
            and type(account['uid']) is int and 0 < account['uid'] < 2**32 - 1 and account['gid'] == 65534,
            'invalid root guard attribution')
    require(isinstance(source, bytes) and 0 < len(source) <= 22000, 'invalid guard source')


def render(root, account, source, verify_identity=True):
    validate_inputs(root, account, source)
    encoded = base64.b64encode(source).decode('ascii')
    label = account['label'].rsplit(' ', 1)[1]
    require(not verify_identity or root_identity(root) == label, 'invalid installation identity')
    readiness='Type=notify\nNotifyAccess=main' if b'GUARD_READY_V1 = True' in source else 'Type=exec'
    return f"""[Unit]
Description=Synergy managed installation retirement
After=local-fs.target
RequiresMountsFor=/opt

[Service]
{readiness}
User=root
UMask=0077
ExecStart=/usr/bin/python3 -I -B -c "exec(__import__('base64').b64decode('{encoded}'))" {root} {account['uid']} {label}
Restart=on-failure
RestartSec=15s

[Install]
WantedBy=multi-user.target
""".encode()


def install(root, account, source):
    validate_inputs(root, account, source)
    unit, link = paths()
    require(not info(unit) and not info(link), 'guard registration already exists')
    label = account['label'].rsplit(' ', 1)[1]
    os.setxattr(root, ROOT_TAG, label.encode('ascii'), os.XATTR_CREATE, follow_symlinks=False)
    data = render(root, account, source)
    pin = hashlib.sha256(data).hexdigest()
    try:
        with unit.open('xb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        # Create only this enablement link, never mutate other services.
        link.parent.mkdir(mode=0o755, exist_ok=True)
        link.symlink_to(unit)
        systemctl('daemon-reload')
        systemctl('start', UNIT)
        check_registration(pin)
    except Exception:
        if info(unit) and unit_digest(unit) == pin:
            systemctl('stop', UNIT)
            if owned_link(link, unit):
                link.unlink()
            unit.unlink()
            systemctl('daemon-reload')
        raise
    return pin


def account_present(uid, suffix):
    try:
        grp.getgrnam(ACCOUNT)
    except KeyError:
        pass
    else:
        raise ValueError('unattributed dedicated group')
    try:
        entry = pwd.getpwnam(ACCOUNT)
    except KeyError:
        return False
    require((entry.pw_uid, entry.pw_gid, entry.pw_gecos, entry.pw_dir, entry.pw_shell)
            == (uid, 65534, 'Synergy NodeNetwork ' + suffix, '/nonexistent', '/bin/sh')
            and [p.pw_name for p in pwd.getpwall() if p.pw_uid == uid] == [ACCOUNT],
            'unattributed dedicated account')
    return True


def attributed_runtime(root, name, target=None):
    registration = SYSTEM / name
    target = root / 'systemd' / name if target is None else target
    linked = owned_link(registration, target)
    observed = state(name)
    require(not observed.get('DropInPaths'), 'unattributed service overrides: ' + name)
    fragment = observed.get('FragmentPath')
    if not linked:
        require(quiescent(observed)
                and ((not fragment and observed.get('LoadState') == 'not-found')
                     or fragment in (str(registration), str(target))),
                'unattributed effective service: ' + name)
    elif not fragment:
        require(observed.get('LoadState') == 'not-found' and quiescent(observed),
                'unattributed effective service: ' + name)
    else:
        require(fragment in (str(registration), str(target)) and observed.get('KillMode') == 'control-group',
                'unattributed effective service: ' + name)
    return linked, observed


def guest_registrations(root):
    result = {}
    base = root/'hosted-machines'
    for path in SYSTEM.glob('synergy-guest-*.service'):
        st = info(path)
        if not st or not stat.S_ISLNK(st.st_mode): continue
        target = Path(os.readlink(path))
        if not str(target).startswith(str(base)+'/'): continue
        match = re.fullmatch(r'synergy-guest-([a-z][a-z0-9-]{0,31})\.service', path.name)
        require(match is not None and target == base/match[1]/'guest.service'
                and st.st_uid == 0, 'unattributed guest OS registration')
        result[path.name] = target
    return result


def retire(root, uid, suffix, pin):
    unit, link = paths()
    require(unit_digest(unit) == pin and owned_link(link, unit), 'guard registration changed')
    managed, conflicts = {}, []
    targets = {name:root/'systemd'/name for name in RUNTIME_UNITS}
    targets.update(guest_registrations(root))
    for name, target in targets.items():
        try:
            linked, observed = attributed_runtime(root, name, target)
            if linked and observed.get('FragmentPath'):
                systemctl('stop', name)
                require(quiescent(state(name)), 'managed service still running: ' + name)
            managed[name] = linked
        except (ValueError, subprocess.SubprocessError) as error:
            conflicts.append(str(error))
    require(not conflicts, '; '.join(conflicts))
    enabled = [(SYSTEM / 'multi-user.target.wants' / name, SYSTEM / name) for name in targets]
    host = [(path, root / 'tmp/controller/host' / filename) for path, filename in CONTROLLER_LINKS.items()]
    for path, target in enabled + host:
        owned_link(path, target)
    has_account = account_present(uid, suffix)
    for path, target in enabled:
        if owned_link(path, target):
            path.unlink()
    for name, linked in managed.items():
        path = SYSTEM / name
        if linked and owned_link(path, targets[name]):
            path.unlink()
    for path, target in host:
        if owned_link(path, target):
            path.unlink()
    if state('ssh.service').get('ActiveState') in ('active', 'reloading'):
        run('/usr/sbin/sshd', '-t')
        systemctl('reload', 'ssh.service')
    if has_account:
        run('/usr/sbin/userdel', '--force', ACCOUNT)
    require(not account_present(uid, suffix), 'managed account remains')
    systemctl('daemon-reload')
    require(all(quiescent(state(name)) for name in targets), 'managed runtime remains')
    require(unit_digest(unit) == pin and owned_link(link, unit), 'guard registration changed')
    link.unlink()
    unit.unlink()
    systemctl('daemon-reload')


def wait_for_retirement():
    unit, link = paths()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not info(unit) and not info(link) and quiescent(state(UNIT)):
            return
        time.sleep(0.25)
    raise ValueError('Root removed; OS registration retirement did not finish. Inspect the installation guard service.')


def source_from_unit(data):
    require(isinstance(data, bytes) and len(data)<=32768, 'invalid guard unit bytes')
    matches=re.findall(rb"b64decode\('([A-Za-z0-9+/=]+)'\)",data)
    require(len(matches)==1, 'invalid embedded guard source')
    source=base64.b64decode(matches[0],validate=True)
    require(0<len(source)<=22000, 'invalid embedded guard source size')
    return source


def render_handover(root, account, source, old_pin, new_pin):
    validate_inputs(root,account,source)
    require(all(isinstance(pin,str) and re.fullmatch('[a-f0-9]{64}',pin) for pin in (old_pin,new_pin)),
            'invalid handover pins')
    suffix=account['label'].rsplit(' ',1)[1]
    encoded=base64.b64encode(source).decode('ascii')
    return f"""[Unit]
Description=Synergy installation guard authenticated handover
After=local-fs.target
RequiresMountsFor=/opt

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30s
User=root
UMask=0077
ExecStart=/usr/bin/python3 -I -B -c "exec(__import__('base64').b64decode('{encoded}'))" {root} {account['uid']} {suffix} handover {old_pin} {new_pin}
Restart=on-failure
RestartSec=1s
KillMode=control-group
""".encode()


def verify_runtime(name, unit):
    import shlex
    observed=state(name)
    pid=observed.get('MainPID','0')
    require(pid.isdecimal() and int(pid)>1 and observed.get('ActiveState')=='active', 'guard process is not active')
    process=PROC/pid
    require(info(process).st_uid==0 and (process/'exe').resolve()==Path('/usr/bin/python3').resolve(),
            'guard process executable differs')
    lines=[line[10:] for line in unit.decode('ascii').splitlines() if line.startswith('ExecStart=')]
    require(len(lines)==1,'guard execution binding absent')
    expected=b'\x00'.join(v.encode() for v in shlex.split(lines[0]))+b'\x00'
    with (process/'cmdline').open('rb') as stream:actual=stream.read(32769)
    require(actual==expected and len(actual)<=32768,'loaded guard source differs')


def migration_plan(root, account, source, old_source_pin, old_pin, recorded=None):
    """Pure plan binds exact prior package source and authenticated candidate."""
    new_unit=render(root,account,source)
    new_pin=hashlib.sha256(new_unit).hexdigest()
    if recorded is None:
        check_registration(old_pin)
        old_unit=paths()[0].read_bytes()
        verify_runtime(UNIT,old_unit)
    else:
        require(isinstance(recorded,dict) and set(recorded)=={'old_unit','new_unit','handover_unit'},
                'invalid guard migration intent')
        old_unit=base64.b64decode(recorded['old_unit'],validate=True)
    old_source=source_from_unit(old_unit)
    require(hashlib.sha256(old_source).hexdigest()==old_source_pin
            and render(root,account,old_source)==old_unit
            and hashlib.sha256(old_unit).hexdigest()==old_pin,
            'prior guard is not the exact installed package source')
    expected={'old_unit':base64.b64encode(old_unit).decode('ascii'),
              'new_unit':base64.b64encode(new_unit).decode('ascii'),
              'handover_unit':base64.b64encode(render_handover(root,account,source,old_pin,new_pin)).decode('ascii')}
    require(recorded is None or recorded==expected,'guard migration differs from authenticated candidate')
    return expected


def sync_system():
    fd=os.open(SYSTEM,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def replace_unit(path,data,allowed):
    if info(path): require(unit_digest(path) in allowed,'guard unit is neither recorded old nor new')
    temporary=path.with_name('.'+path.name+'.migration')
    if info(temporary):
        require(unit_digest(temporary)==hashlib.sha256(data).hexdigest(),'unattributed guard temporary file')
    else:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def migrate(root, account, plan, set_policy_pin):
    """Caller holds the lifecycle lock and has durably recorded this plan."""
    old,new,handover=(base64.b64decode(plan[k],validate=True) for k in ('old_unit','new_unit','handover_unit'))
    old_pin,new_pin=(hashlib.sha256(data).hexdigest() for data in (old,new))
    unit,link=paths(); temporary=SYSTEM/HANDOVER
    require(owned_link(link,unit),'guard enablement differs')
    require(unit_digest(unit) in (old_pin,new_pin),'guard is outside recorded migration')
    if unit_digest(unit)==new_pin:
        try:
            check_registration(new_pin)
            verify_runtime(UNIT,new)
        except ValueError:pass
        else:
            set_policy_pin(new_pin)
            if info(temporary):
                require(unit_digest(temporary)==hashlib.sha256(handover).hexdigest(),'foreign handover service')
                systemctl('stop',HANDOVER)
                require(quiescent(state(HANDOVER)),'handover did not stop')
                temporary.unlink();sync_system();systemctl('daemon-reload')
            elif state(HANDOVER).get('LoadState')!='not-found':
                require(quiescent(state(HANDOVER)) and state(HANDOVER).get('FragmentPath')==str(temporary), 'foreign cached handover')
                systemctl('daemon-reload')
            require(state(HANDOVER).get('LoadState')=='not-found' and quiescent(state(HANDOVER)), 'handover registration remains')
            return new_pin
    observed=state(UNIT)
    require(observed.get('FragmentPath')==str(unit) and not observed.get('DropInPaths')
            and observed.get('ActiveState') in ('active','inactive','failed'), 'foreign guard effective state')
    if observed.get('ActiveState')=='active':verify_runtime(UNIT,unit.read_bytes())
    if not info(temporary):
        require(state(HANDOVER).get('LoadState')=='not-found' and quiescent(state(HANDOVER)),
                'unattributed handover service')
        replace_unit(temporary,handover,set())
    require(unit_digest(temporary)==hashlib.sha256(handover).hexdigest(),'foreign handover service')
    systemctl('daemon-reload')
    h=state(HANDOVER)
    require(not h.get('DropInPaths') and h.get('FragmentPath')==str(temporary), 'foreign handover effective state')
    systemctl('start',HANDOVER)
    h=state(HANDOVER)
    require(h.get('ActiveState')=='active' and h.get('MainPID','0')!='0'
            and h.get('FragmentPath')==str(temporary) and not h.get('DropInPaths'), 'handover guard is not active')
    verify_runtime(HANDOVER,handover)
    systemctl('stop',UNIT)
    require(quiescent(state(UNIT)),'prior guard did not stop')
    require(root_identity(root)==account['label'].rsplit(' ',1)[1],'installation disappeared during guard handover')
    replace_unit(unit,new,{old_pin,new_pin})
    systemctl('daemon-reload');systemctl('start',UNIT)
    check_registration(new_pin)
    verify_runtime(UNIT,new)
    set_policy_pin(new_pin)
    systemctl('stop',HANDOVER)
    require(quiescent(state(HANDOVER)),'handover guard did not stop')
    temporary.unlink();sync_system();systemctl('daemon-reload')
    return new_pin


def handover_record(root, uid, suffix, new_pin, starting=False):
    path=SYSTEM/HANDOVER
    if not info(path):return False
    data=path.read_bytes();unit_digest(path)
    match=re.search(rb' handover ([a-f0-9]{64}) ([a-f0-9]{64})\n',data)
    require(match is not None and match[2].decode()==new_pin,'unattributed guard handover')
    account={'uid':uid,'gid':65534,'label':'Synergy NodeNetwork '+suffix}
    source=source_from_unit(data)
    require(render_handover(root,account,source,match[1].decode(),new_pin)==data
            and hashlib.sha256(render(root,account,source,verify_identity=False)).hexdigest()==new_pin,
            'handover source is outside current guard')
    h=state(HANDOVER)
    require(not h.get('DropInPaths') and h.get('FragmentPath')==str(path),'foreign handover effective state')
    return h.get('ActiveState') in (('active','activating') if starting else ('active',))


def handover_watch(root, uid, suffix, old_pin, new_pin):
    own=SYSTEM/HANDOVER
    pin=unit_digest(own)
    require(handover_record(root,uid,suffix,new_pin,starting=True),'handover is not active')
    if root_identity(root)==suffix:notify_ready()
    while root_identity(root)==suffix:time.sleep(.2)
    while info(paths()[0]) or info(paths()[1]):
        current=unit_digest(paths()[0])
        require(current in (old_pin,new_pin),'guard changed during handover retirement')
        if current==old_pin and state(UNIT).get('ActiveState')=='active':
            time.sleep(.2);continue
        retire(root,uid,suffix,current)
        break
    require(unit_digest(own)==pin,'handover registration changed')
    own.unlink();sync_system();systemctl('daemon-reload')


def notify_ready():
    import socket
    address=os.environ.get('NOTIFY_SOCKET')
    if not address:return
    require(address.startswith(('/', '@')),'invalid systemd readiness socket')
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:
        channel.connect('\x00'+address[1:] if address.startswith('@') else address)
        channel.sendall(b'READY=1')


def watch(root, uid, suffix):
    require(root == Path('/opt/synergy') and os.geteuid() == 0
            and 0 < uid < 2**32 - 1 and re.fullmatch(r'[a-f0-9]{32}', suffix),
            'invalid guard registration')
    pin = unit_digest(paths()[0])
    if root_identity(root)==suffix:notify_ready()
    while root_identity(root) == suffix:
        time.sleep(2)
    if info(SYSTEM/HANDOVER):
        handover_record(root,uid,suffix,pin)
        systemctl('start',HANDOVER)
        require(handover_record(root,uid,suffix,pin),'handover guard is not active')
    else:retire(root, uid, suffix, pin)


if __name__ == '__main__':
    if len(sys.argv)==7 and sys.argv[4]=='handover':
        handover_watch(Path(sys.argv[1]),int(sys.argv[2]),sys.argv[3],sys.argv[5],sys.argv[6])
    else:watch(Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
