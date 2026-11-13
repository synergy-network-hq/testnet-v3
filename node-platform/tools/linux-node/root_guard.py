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
    require(isinstance(source, bytes) and 0 < len(source) <= 18000, 'invalid guard source')


def render(root, account, source):
    validate_inputs(root, account, source)
    encoded = base64.b64encode(source).decode('ascii')
    label = account['label'].rsplit(' ', 1)[1]
    require(root_identity(root) == label, 'invalid installation identity')
    return f"""[Unit]
Description=Synergy managed installation retirement
After=local-fs.target
RequiresMountsFor=/opt

[Service]
Type=exec
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


def attributed_runtime(root, name):
    registration = SYSTEM / name
    target = root / 'systemd' / name
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


def retire(root, uid, suffix, pin):
    unit, link = paths()
    require(unit_digest(unit) == pin and owned_link(link, unit), 'guard registration changed')
    managed, conflicts = {}, []
    for name in RUNTIME_UNITS:
        try:
            linked, observed = attributed_runtime(root, name)
            if linked and observed.get('FragmentPath'):
                systemctl('stop', name)
                require(quiescent(state(name)), 'managed service still running: ' + name)
            managed[name] = linked
        except (ValueError, subprocess.SubprocessError) as error:
            conflicts.append(str(error))
    require(not conflicts, '; '.join(conflicts))
    enabled = [(SYSTEM / 'multi-user.target.wants' / name, SYSTEM / name) for name in RUNTIME_UNITS]
    host = [(path, root / 'tmp/controller/host' / filename) for path, filename in CONTROLLER_LINKS.items()]
    for path, target in enabled + host:
        owned_link(path, target)
    has_account = account_present(uid, suffix)
    for path, target in enabled:
        if owned_link(path, target):
            path.unlink()
    for name, linked in managed.items():
        path = SYSTEM / name
        if linked and owned_link(path, root / 'systemd' / name):
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
    require(all(quiescent(state(name)) for name in RUNTIME_UNITS), 'managed runtime remains')
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


def watch(root, uid, suffix):
    require(root == Path('/opt/synergy') and os.geteuid() == 0
            and 0 < uid < 2**32 - 1 and re.fullmatch(r'[a-f0-9]{32}', suffix),
            'invalid guard registration')
    pin = unit_digest(paths()[0])
    while root_identity(root) == suffix:
        time.sleep(2)
    retire(root, uid, suffix, pin)


if __name__ == '__main__':
    watch(Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3])
