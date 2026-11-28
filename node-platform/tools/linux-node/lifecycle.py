#!/usr/bin/env python3
"""One-root lifecycle; does not approve or perform legacy-fleet destruction."""
import argparse
import contextlib
import hashlib
import stat
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
from synergy_linux import LEGACY_EXISTING_ROOT, consensus_archive_version, digest, native, read, require, safe_root, verify_identity, verify_package, write_new

UNITS = ('synergy-node.service', 'synergy-vpn.service')
RELAY_UNIT = 'synergy-canary-rpc-relay.service'
UNIT_DIRECTORY = Path('/etc/systemd/system')
UPGRADE_INTENT = 'evidence/upgrade-intent.json'
UPGRADE_COMPLETED = 'evidence/upgrade-completed.json'
REPLACEMENT_INTENT = 'evidence/application-replacement-intent.json'
AUTHORITY_RECOVERY_INTENT = 'evidence/authority-recovery-intent.json'
AUTONOMOUS_EPOCH_INTENT = 'evidence/autonomous-epoch-intent.json'
AUTONOMOUS_EPOCH_ARTIFACT = 'network/autonomous-epoch-activation.json'


def guard_dependencies(root):
    # The approved existing-root path predates the Portal deletion guard. Do
    # not attach BindsTo to a nonexistent unit during its software upgrade.
    # A configured/registered guard always remains mandatory; fresh installs
    # retain the normal guard dependency regardless of installation stage.
    if Path(root) == LEGACY_EXISTING_ROOT:
        policy = Path(root)/'tmp/controller/policy.json'
        guard = UNIT_DIRECTORY/'synergy-installation-guard.service'
        if not any(p.exists() or p.is_symlink() for p in (policy,guard)):
            return '', ''
    return ' synergy-installation-guard.service', 'BindsTo=synergy-installation-guard.service\n'


def node_unit(root):
    after, binding = guard_dependencies(root)
    return f'''[Unit]
Description=Synergy universal validator
After=network-online.target synergy-vpn.service{after}
Requires=synergy-vpn.service
{binding}ConditionPathExists={root}/config/start-authorized.json

[Service]
Type=exec
User=root
UMask=0077
WorkingDirectory={root}
Environment=HOME={root}
Environment=TMPDIR={root}/tmp
Environment=XDG_CONFIG_HOME={root}/vpn
Environment=XDG_CACHE_HOME={root}/cache
Environment=NB_STATE_DIR={root}/vpn
Environment=NB_DNS_STATE_FILE={root}/vpn/state.json
Environment=SYNERGY_NETBIRD_BINARY={root}/tools/netbird-client
ExecStartPre=/usr/bin/python3 {root}/tools/lifecycle.py start-check --root {root}
ExecStart={root}/bin/synergy-node start --config {root}/config/node.json
Restart=on-failure
RestartSec=15s
MemoryMax=1073741824
MemorySwapMax=0
TasksMax=512
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={root}/data {root}/logs {root}/run {root}/tmp {root}/cache
StandardOutput=append:{root}/logs/node.log
StandardError=append:{root}/logs/node.log

[Install]
WantedBy=multi-user.target
'''


def vpn_unit(root):
    after, binding = guard_dependencies(root)
    return f'''[Unit]
Description=Synergy application-owned NetBird client
After=network-online.target{after}
Wants=network-online.target
{binding}
[Service]
Type=exec
User=root
UMask=0077
WorkingDirectory={root}/vpn
Environment=HOME={root}
Environment=TMPDIR={root}/tmp
Environment=XDG_CONFIG_HOME={root}/vpn
Environment=XDG_CACHE_HOME={root}/cache
Environment=NB_STATE_DIR={root}/vpn
Environment=NB_DNS_STATE_FILE={root}/vpn/state.json
ExecStart={root}/tools/netbird-client service run --config {root}/vpn/default.json --daemon-addr unix://{root}/run/netbird.sock --log-file {root}/logs/netbird.log
Restart=on-failure
RestartSec=5s
StandardOutput=append:{root}/logs/netbird-service.log
StandardError=append:{root}/logs/netbird-service.log

[Install]
WantedBy=multi-user.target
'''


def wrapper_text(root):
    import shlex
    code=("import sys;sys.path.insert(0,"+repr(str(root/'tools'))+");from vpn import client_exec;from pathlib import Path;"
          "\ntry:client_exec(Path("+repr(str(root))+"),sys.argv[1:])"
          "\nexcept Exception:sys.exit('Synergy VPN trust check refused')")
    return (f'#!/bin/sh\nexport HOME={root} TMPDIR={root}/tmp XDG_CONFIG_HOME={root}/vpn XDG_CACHE_HOME={root}/cache NB_STATE_DIR={root}/vpn NB_DNS_STATE_FILE={root}/vpn/state.json\n'
            +'exec /usr/bin/python3 -I -B -c '+shlex.quote(code)+' "$@"\n')


def rendered_units(root):
    result = dict(zip(UNITS, (node_unit(root), vpn_unit(root))))
    if (root/'config/canary-rpc-relay.json').exists():
        from canary_rpc_relay import unit_text
        result[RELAY_UNIT] = unit_text(root)
    return result


def _require_operator(linux=True):
    require(os.geteuid() == 0 and (not linux or sys.platform.startswith('linux')), 'Linux root operator required' if linux else 'root operator required')


def _hash_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


@contextlib.contextmanager
def _lifecycle_lock(root):
    # The stable directory inode survives receipt replacement; no lock file or
    # second installation footprint is introduced.
    import fcntl
    fd = os.open(root, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def _unit_state(unit):
    result = subprocess.run(['systemctl', 'show', unit,
        '--property=LoadState,FragmentPath,DropInPaths,ActiveState,MainPID'],
        capture_output=True, text=True, check=False)
    require(len(result.stdout) <= 65536, 'service state exceeds bound')
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(result.returncode == 0 or values.get('LoadState') == 'not-found',
            'cannot attribute effective service: '+unit)
    return values


def _integration_plan(root):
    path = root/'evidence/host-integrations.json'
    if not path.exists(): return None
    plan = read(path)
    expected = [str(UNIT_DIRECTORY/name) for name in UNITS]
    require(plan.get('paths') in (expected, expected + [str(UNIT_DIRECTORY/RELAY_UNIT)]), 'unsupported service inventory')
    expected = plan['paths']
    require(plan.get('root') == str(root) and plan.get('paths') == expected
            and set(plan.get('sha256', {})) == set(expected), 'host integration ownership plan differs')
    require(all(re.fullmatch(r'[0-9a-f]{64}', value) for value in plan['sha256'].values()),
            'host integration digest malformed')
    return plan


def _attributed_units(root, plan=None, alternate=None, allow_absent=False, allow_unloaded=False):
    plan = plan if plan is not None else _integration_plan(root)
    require(plan is not None, 'installation has no registered service ownership')
    paths=plan['paths']
    require(paths in ([str(UNIT_DIRECTORY/name) for name in UNITS],
                     [str(UNIT_DIRECTORY/name) for name in (*UNITS, RELAY_UNIT)]), 'unsupported service ownership')
    for candidate in (plan,alternate):
        if candidate is not None:
            require(candidate.get('root') == str(root) and candidate.get('paths') == paths
                    and set(candidate.get('sha256',{})) == set(paths), 'service ownership plan differs')
    owned = {}
    for service_path in paths:
        unit = Path(service_path).name
        path = UNIT_DIRECTORY/unit
        expected = {plan['sha256'][str(path)]}
        if alternate is not None: expected.add(alternate['sha256'][str(path)])
        state = _unit_state(unit)
        if not path.exists() and not path.is_symlink():
            require(allow_absent and state.get('LoadState') == 'not-found'
                    and not state.get('FragmentPath') and state.get('MainPID', '0') in ('','0'),
                    'missing owned unit has a loaded or foreign replacement: '+unit)
            continue
        target=root/'systemd'/unit if path.is_symlink() else path
        if path.is_symlink(): require(os.readlink(path)==str(target) and target.is_file() and not target.is_symlink(), 'service link escapes installation')
        metadata = target.lstat()
        require(stat.S_ISREG(metadata.st_mode)
                and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022
                and digest(path) in expected, 'host integration drift: '+unit)
        unloaded = allow_unloaded and state.get('LoadState') == 'not-found' and not state.get('FragmentPath') and state.get('MainPID','0') in ('','0')
        require(unloaded or state.get('FragmentPath') in (str(path),str(target)) and not state.get('DropInPaths'),
                'effective service is not owned by this installation: '+unit)
        owned[unit] = state
    return owned


def mutate_owned_service(root, action, unit, allow_absent=False):
    require(action in ('start','stop','restart','disable') and unit in (*UNITS, RELAY_UNIT), 'unsupported service mutation')
    owned = _attributed_units(Path(root),allow_absent=allow_absent)
    require(unit in owned, 'owned service is absent')
    native(['systemctl', action, unit])


def _boot_units(role):
    require(role in ('validator', 'rpc_gateway'), 'Unsupported installed boot role')
    return {'node': RELAY_UNIT if role == 'rpc_gateway' else UNITS[0], 'vpn': UNITS[1]}


def service_boot_state(root, *, role='validator'):
    """Observe the runtime for the sealed role and its VPN dependency."""
    root=Path(root);owned=_attributed_units(root)
    units = _boot_units(role)
    if role == 'rpc_gateway':
        units['validator'] = UNITS[0]
    result={}
    for service,unit in units.items():
        require(unit in owned,'Boot policy requires both registered owned services')
        expected=UNIT_DIRECTORY/'multi-user.target.wants'/unit
        if expected.parent.exists() or expected.parent.is_symlink():
            metadata=expected.parent.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.geteuid()
                    and not metadata.st_mode & 0o022 and not expected.parent.is_symlink(),
                    'Unsafe service boot registration directory')
        for directory in UNIT_DIRECTORY.iterdir():
            if directory.name.endswith(('.wants','.requires')):
                candidate=directory/unit
                if candidate.exists() or candidate.is_symlink():
                    require(candidate==expected,'Unexpected owned service boot registration')
        present=expected.exists() or expected.is_symlink()
        if present:
            require(expected.is_symlink() and expected.lstat().st_uid==os.geteuid()
                    and os.readlink(expected) in (str(root/'systemd'/unit),str(UNIT_DIRECTORY/unit)),
                    'Foreign service boot registration')
        state=subprocess.run(['systemctl','is-enabled',unit],stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL,check=False,timeout=8)
        raw=state.stdout
        require((state.returncode,raw) in ((0,b'enabled\n'),(1,b'disabled\n'),(1,b'linked\n')),
                'Unsupported service boot state')
        enabled=raw==b'enabled\n'
        require(enabled==present,'Service boot state and attributed registration disagree')
        if service == 'validator':
            require(not enabled and owned[unit].get('ActiveState') in ('inactive', 'failed')
                    and owned[unit].get('MainPID') == '0', 'Gateway validator service must stay stopped and disabled')
        else:
            result[service]=enabled
    return result


def set_service_boot_policy(root, service, enabled, *, role='validator'):
    require(service in ('node','vpn') and type(enabled) is bool,'Exact service boot policy required')
    before=service_boot_state(root, role=role)
    if before[service]!=enabled:
        unit=_boot_units(role)[service]
        link=UNIT_DIRECTORY/'multi-user.target.wants'/unit
        # systemctl disable also removes the manually registered main unit link.
        # Change only the fixed attributed boot link; retain that registration.
        if enabled:
            if not link.parent.exists():
                link.parent.mkdir(mode=0o755);_sync_directory(UNIT_DIRECTORY)
            link.symlink_to(UNIT_DIRECTORY/unit)
        else:link.unlink()
        _sync_directory(link.parent)
        native(['systemctl','daemon-reload'],timeout=8)
    after=service_boot_state(root, role=role)
    require(after[service]==enabled and after['vpn' if service=='node' else 'node']==before['vpn' if service=='node' else 'node'],
            'Service boot policy outcome uncertain; reconcile observed boot state')
    return after


def _sealed_receipt(root):
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'canonical installation root required')
    for path in [root, *root.parents]:
        require(not path.is_symlink(), 'installation ancestry symlink refused')
    metadata = root.stat()
    require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, 'unsafe installation root ownership/mode')
    receipt = read(root/'installation.json')
    mac_bootstrap_root = (receipt.get('format') == 'synergy-platform-release-v1'
                          and receipt.get('role') == 'bootstrap_root_custody'
                          and sys.platform == 'darwin' and os.uname().machine == 'arm64')
    require(receipt.get('root') == str(root)
            and (receipt.get('format') == 'synergy-universal-linux-v1' or mac_bootstrap_root),
            'installation receipt/root mismatch')
    require(digest(root/'package.json') == receipt['package_sha256'], 'installed manifest drift')
    manifest = read(root/'package.json')
    if mac_bootstrap_root:
        require(manifest.get('format') == 'synergy-platform-release-v1'
                and manifest.get('platform') == 'macos' and manifest.get('architecture') == 'aarch64',
                'initial macOS BootstrapRoot release platform differs')
    require(receipt['package_files'] == manifest['files'], 'installation inventory differs')
    if any(name.startswith(('hosted-machines/','lib/guest-tools/')) for name in manifest['files']):
        from guest_lifecycle import resource_file_pins
        resource_file_pins(manifest)
    for name, expected in manifest['files'].items():
        _software_path(root, name)
        require(digest(root/name) == expected, 'installed package drift: '+name)
    return receipt, manifest


def _software_path(root, name):
    relative = Path(name)
    require(name and not relative.is_absolute() and '..' not in relative.parts
            and (relative.parts[0] in ('bin','lib','assets','systemd','tools','roles') or name in ('README.md','hosted-machines/images/os.qcow2')),
            'upgrade must preserve runtime identity, state and configuration')
    path = root/relative
    for parent in [path, *path.parents]:
        require(not parent.is_symlink(), 'software symlink refused')
    if path.exists(): require(path.is_file(), 'software member is not regular')
    return path


def recover_consensus_archives(root):
    """Recover only existing canonical SQLite rollback journals, without boot/signing.

    Conformance remains read-only. Recovery uses SQLite's own atomic rollback;
    no journal is manually removed, no empty archive is created, and no legacy
    file is rewritten.
    """
    import sqlite3
    root = Path(root)
    _sealed_receipt(root)
    plan = _integration_plan(root)
    if plan is not None: _attributed_units(root, plan)
    marker = root/'data/metadata/schema-version'
    require(marker.is_file() and not marker.is_symlink()
            and marker.stat().st_uid == os.geteuid() and not marker.stat().st_mode & 0o022
            and marker.stat().st_size == len(b'synergy-node-storage:1') and marker.read_bytes() == b'synergy-node-storage:1', 'storage marker differs')
    directory = root/'data/consensus/posy'
    if not directory.exists(): return {'recovered_existing_archives':0}
    for path in [marker, directory, *directory.parents]:
        require(not path.is_symlink(), 'consensus storage ancestry symlink refused')
        if path == root or root in path.parents:
            metadata=path.stat()
            require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, 'unsafe consensus storage ancestry ownership/mode')
    # There is one archive at the canonical PoSy root. No recursive filesystem
    # search or database creation is needed for ordinary startup recovery.
    archive = directory/'consensus-evidence-v1.sqlite3'
    if not archive.exists():
        require(not archive.is_symlink(), 'archive symlink refused')
        require(not any(path.exists() or path.is_symlink() for path in (directory/(archive.name+'-journal'),directory/(archive.name+'-wal'),directory/(archive.name+'-shm'))), 'orphaned consensus journal requires inspection')
        return {'recovered_existing_archives':0}
    require(not any((directory/(archive.name+suffix)).exists() or (directory/(archive.name+suffix)).is_symlink() for suffix in ('-wal','-shm')), 'unexpected consensus WAL storage refused')
    require(archive.stat().st_size>0, 'empty existing consensus archive refused')
    for path in (archive, directory/(archive.name+'-journal')):
        if path.exists() or path.is_symlink():
            metadata = path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
                    and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1 and not metadata.st_mode & 0o022,
                    'unsafe consensus archive/journal')
    connection = sqlite3.connect(archive.as_uri()+'?mode=rw', uri=True, timeout=5)
    try:
        connection.execute('PRAGMA synchronous=EXTRA')
        connection.execute('PRAGMA fullfsync=ON')
        connection.execute('PRAGMA mmap_size=0')
        connection.execute('PRAGMA cache_size=-512')
        consensus_archive_version(connection)
    finally: connection.close()
    return {'recovered_existing_archives':1}


def register(root):
    _require_operator()
    require(re.fullmatch(r'/[A-Za-z0-9_/.-]+/synergy', str(root)), 'systemd root contains unsupported characters')
    _sealed_receipt(root)
    contents = rendered_units(root)
    paths = [UNIT_DIRECTORY/name for name in contents]
    plan = _integration_plan(root)
    with _lifecycle_lock(root):
        if plan is None:
            # Refuse foreign vendor/transient units even when /etc has no file.
            for path in paths:
                state = _unit_state(path.name)
                require(not path.exists() and not path.is_symlink()
                        and state.get('LoadState') == 'not-found' and not state.get('FragmentPath'),
                        'conflicting host service exists')
            plan = {'root':str(root),'paths':[str(p) for p in paths],
                    'sha256':{str(p):_hash_bytes(contents[p.name].encode()) for p in paths}}
            write_new(root/'evidence/host-integrations.json', plan)
        else:
            if str(UNIT_DIRECTORY/RELAY_UNIT) not in plan['paths'] and RELAY_UNIT in contents:
                _attributed_units(root, plan, allow_absent=True, allow_unloaded=True)
                relay = UNIT_DIRECTORY/RELAY_UNIT
                state = _unit_state(RELAY_UNIT)
                require(not relay.exists() and not relay.is_symlink() and state.get('LoadState') == 'not-found'
                        and not state.get('FragmentPath'), 'conflicting relay service exists')
                plan = dict(plan, paths=[str(p) for p in paths],
                    sha256={str(p):_hash_bytes(contents[p.name].encode()) for p in paths})
                _replace_bytes(root,root/'evidence/host-integrations.json',json.dumps(plan,sort_keys=True,indent=2).encode()+b'\n',0o600,_hash_bytes(contents[RELAY_UNIT].encode()))
            require(plan['sha256'] == {str(p):_hash_bytes(contents[p.name].encode()) for p in paths},
                    'partial registration belongs to a different unit policy')
            _attributed_units(root, plan, allow_absent=True,allow_unloaded=True)
        for path in paths:
            if path.exists(): continue
            # Only the host-managed registration link lives outside Synergy.
            # All application-owned unit text remains under the root.
            target=root/'systemd'/path.name
            target.parent.mkdir(mode=0o700,exist_ok=True)
            if target.exists(): require(not target.is_symlink() and target.read_text()==contents[path.name], 'rooted unit differs')
            else:
                with target.open('x') as stream:
                    os.fchmod(stream.fileno(),0o600);stream.write(contents[path.name]);stream.flush();os.fsync(stream.fileno())
                _sync_directory(target.parent)
            path.symlink_to(target)
            _sync_directory(path.parent)
        wrapper = root/'tools/netbird-client'
        if wrapper.exists(): require(wrapper.read_text() == wrapper_text(root), 'NetBird wrapper drift')
        else:
            with wrapper.open('x') as stream:
                os.fchmod(stream.fileno(),0o700);stream.write(wrapper_text(root));stream.flush();os.fsync(stream.fileno())
            _sync_directory(wrapper.parent)
        # Exact on-disk ownership is established before daemon reload. Missing
        # fragments are expected until this first reload, never a foreign one.
        for path in paths: require(digest(path) == plan['sha256'][str(path)], 'registration unit changed')
        native(['systemctl','daemon-reload'])
    return {'registered':[str(p) for p in paths],'services_started':False,'boot_enabled':False}


def start_check(root, *, authorize=None):
    _require_operator(linux=False)
    with _lifecycle_lock(root):
        result = _start_check_locked(root)
        if authorize is not None:
            authorize()
        return result


def _startup_pending_upgrade(root):
    """Only a reviewed successor may coexist with the still-installed runtime."""
    pending = root/'tmp/update-master'
    if not pending.exists() and not pending.is_symlink():
        return None
    # systemd repeats this check using sealed installed tools, rather than the
    # adopted controller engine. Its complete dependency closure must agree.
    from controller import Controller, ENGINE_MODULES, engineering_effective_selection
    controller = Controller(root)
    policy = controller.policy()
    engines = policy.get('engine_files')
    require(isinstance(engines, dict) and ENGINE_MODULES <= set(engines) <= ENGINE_MODULES | {'runtime_probe.py'}
            and engines.get('lifecycle.py') == digest(Path(__file__)),
            'startup engine closure lacks exact authenticated attribution')
    for name, expected in engines.items():
        installed = root/'tools'/name
        require(installed.is_file() and not installed.is_symlink() and digest(installed) == expected,
                'installed startup checker differs; finish the approved upgrade before startup')
    current = engineering_effective_selection(root, policy)
    update = policy.get('engineering_update')
    require(current is not None and isinstance(update, dict)
            and update.get('previous_selection') == current
            and update.get('selection') != current,
            'startup pending master lacks an exact unused native adoption')
    selected = update['selection']
    controller.approved_package({key:selected[key] for key in ('release_id','manifest_sha256')})
    return selected['manifest_sha256']


def _start_check_locked(root):
    require(not (root/UPGRADE_INTENT).exists(), 'finish the recorded upgrade before startup')
    require(not (root/REPLACEMENT_INTENT).exists(), 'finish application replacement before startup')
    require(not (root/AUTHORITY_RECOVERY_INTENT).exists() and not (root/AUTHORITY_RECOVERY_INTENT).is_symlink(),
            'finish authority recovery before startup')
    require(not (root/AUTONOMOUS_EPOCH_INTENT).exists() and not (root/AUTONOMOUS_EPOCH_INTENT).is_symlink(),
            'finish autonomous epoch activation before startup')
    receipt, installed_manifest = _sealed_receipt(root)
    pending_upgrade = _startup_pending_upgrade(root)
    _attributed_units(root)
    recover_consensus_archives(root)
    from conformance import installed
    installed(root, host=True, **({'pending_upgrade_sha256':pending_upgrade} if pending_upgrade is not None else {}))
    policy = read(root/'config/start-authorized.json')
    identity = verify_identity(root)
    require(policy['network_id'] == receipt['network_id'] and policy['chain_id'] == receipt['chain_id'], 'wrong startup incarnation')
    from apqe_layout import startup_readiness_authorized
    require(startup_readiness_authorized(root,policy,identity['address']), 'complete signed-authority quorum installation and online VPN readiness required')
    config = read(root/'config/node.json')
    verify_authority_recovery_pin(root,config,receipt,policy)
    verify_autonomous_epoch_pin(root,config,receipt,policy)
    from apqe_layout import selected, PUBLIC
    public_names=set(PUBLIC) if selected(config) else {'genesis.json','authority.json','authority-root.pub',
            'network-manifest.json','p2p-bindings.json','transport-registry.json'}
    require(set(policy['public_file_sha256']) == public_names, 'complete public-network pin set required')
    for name, expected in policy['public_file_sha256'].items():
        require(digest(root/'network'/name) == expected, 'network input changed after readiness gate')
    config = read(root/'config/node.json')
    require(config['network_id'] == receipt['network_id'] and config['chain_id'] == receipt['chain_id'], 'configuration incarnation mismatch')
    require(config.get('genesis_path') == str(root/'network/genesis.json')
            and config.get('manifest_path') == str(root/'network/network-manifest.json')
            and config.get('consensus',{}).get('authority_binding') == str(root/'network/authority.json')
            and config.get('consensus',{}).get('authority_trust_key_path') == str(root/'network/authority-root.pub'),
            'selected authenticated network path mismatch')
    result = json.loads(native([root/'bin/synergy-node','preflight','--config',root/'config/node.json']))
    require(result['signed_authority_verified'] and result['signed_genesis_verified'], 'signed native Genesis/authority preflight required')
    _verify_wallet_release_preflight(result, config, root, installed_manifest)
    authority = read(root/'network/authority.json')['payload']
    require(authority['network_id'] == receipt['network_id'] and authority['chain_id'] == receipt['chain_id'], 'authenticated authority incarnation differs')
    signed_ids = _authorized_validator_ids(policy,authority,identity['address'])
    vpn = native([root/'tools/netbird-client','status']).decode().lower()
    require('management: connected' in vpn and 'signal: connected' in vpn, 'native VPN not connected')
    return {'startup_check_passed':True,'network_id':receipt['network_id'],'signed_active_validator_count':len(signed_ids)}


def verify_authority_recovery_pin(root,config,receipt,policy=None):
    """The certificate is separately pinned; PUBLIC remains the exact original set."""
    path=config.get('consensus',{}).get('authority_recovery_certificate_path')
    expected=receipt.get('authority_recovery_certificate_sha256')
    startup=None if policy is None else policy.get('authority_recovery_certificate_sha256')
    if path is None:
        require(expected is None and startup is None, 'inactive recovery cannot retain activation pins')
        return
    canonical=root/'network/authority-recovery-certificate.json'
    require(path==str(canonical) and re.fullmatch('[0-9a-f]{64}',expected or '') is not None
            and (policy is None or startup==expected), 'exact separately pinned recovery certificate required')
    metadata=canonical.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not canonical.is_symlink()
            and metadata.st_uid==os.geteuid() and not metadata.st_mode & 0o022
            and 0 < metadata.st_size <= 8*1024*1024 and digest(canonical)==expected,
            'recovery certificate differs from activation pin')

def verify_autonomous_epoch_pin(root,config,receipt,policy):
    activation=config.get('consensus',{}).get('autonomous_epoch_activation')
    expected=receipt.get('autonomous_epoch_activation_sha256')
    startup=policy.get('autonomous_epoch_activation_sha256')
    artifact=root/AUTONOMOUS_EPOCH_ARTIFACT
    if activation is None:
        require(expected is None and startup is None and not artifact.exists() and not artifact.is_symlink(),
                'unconfigured autonomous epoch artifact or pin')
        return
    require(activation=={'path':str(artifact),'sha256':expected}
            and isinstance(expected,str) and re.fullmatch('[0-9a-f]{64}',expected)
            and startup==expected and receipt.get('chain_id')==99999 and receipt.get('role')=='validator',
            'autonomous activation pins or installation scope differ')
    metadata=artifact.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not artifact.is_symlink()
            and metadata.st_uid==os.geteuid() and not metadata.st_mode & 0o022
            and 0 < metadata.st_size <= 4*1024*1024 and digest(artifact)==expected,
            'autonomous epoch artifact differs from activation pin')


def relay_start_check(root):
    _require_operator(linux=False)
    with _lifecycle_lock(root):
        return _relay_start_check_locked(root)


def _relay_start_check_locked(root):
    for name in (UPGRADE_INTENT,REPLACEMENT_INTENT,AUTHORITY_RECOVERY_INTENT,AUTONOMOUS_EPOCH_INTENT):
        require(not (root/name).exists() and not (root/name).is_symlink(),
                'finish recorded lifecycle intent before relay startup')
    receipt,installed_manifest=_sealed_receipt(root)
    _attributed_units(root)
    config=read(root/'config/node.json')
    policy=read(root/'config/start-authorized.json') if receipt.get('role')=='validator' else None
    verify_authority_recovery_pin(root,config,receipt,policy)
    if receipt.get('role') == 'rpc_gateway':
        from canary_rpc_relay import verify_bootstrap_pin_record
        verify_bootstrap_pin_record(root)
        from apqe_layout import wallet_release_package, wallet_release_selection
        if wallet_release_package(root, installed_manifest) is not None or wallet_release_selection(config) is not None:
            result = json.loads(native([root/'bin/synergy-node','preflight-wallet-release',
                                        '--config',root/'config/node.json']))
            _verify_wallet_release_preflight(result, config, root, installed_manifest)
    native([root/'bin/synergy-node','canary-rpc-relay','check',root/'config/canary-rpc-relay.json'])
    return {'relay_startup_check_passed':True}


def _authorized_validator_ids(policy,authority,address):
    signed_ids=[entry['record']['validator_id'] for entry in authority['validators'] if entry['record']['status'] == 'active']
    ids=policy['validator_addresses']
    require(isinstance(ids,list) and ids and all(isinstance(value,str) and value for value in ids)
            and len(ids) == len(set(ids)) and len(signed_ids) == len(set(signed_ids))
            and set(ids) == set(signed_ids) and address in signed_ids,
            'startup validator set differs from authenticated active authority')
    return signed_ids


def _replace_bytes(root, path, data, mode, token):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Same-directory staging permits installation and /etc units on different
    # filesystems. The exact temporary filename is attributable to this intent.
    temporary = path.parent/('.'+path.name+'.upgrade-'+token[:16])
    if temporary.exists() or temporary.is_symlink():
        metadata = temporary.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not temporary.is_symlink()
                and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022,
                'unsafe interrupted upgrade staging member')
        temporary.unlink();_sync_directory(temporary.parent)
    try:
        with temporary.open('xb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path);_sync_directory(path.parent)
    finally:
        if temporary.exists(): temporary.unlink();_sync_directory(temporary.parent)


def _replace_guest_resource(root,path,source,expected,mode,token):
    """Large pinned resources use the same upgrade intent, without a RAM copy."""
    metadata=source.lstat()
    require(stat.S_ISREG(metadata.st_mode) and not source.is_symlink() and metadata.st_nlink==1
            and 0<metadata.st_size<=1024**3,'Unsafe guest upgrade source')
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    temporary=path.parent/('.'+path.name+'.upgrade-'+token[:16])
    if temporary.exists() or temporary.is_symlink():
        st=temporary.lstat()
        require(stat.S_ISREG(st.st_mode) and not temporary.is_symlink() and st.st_uid==os.geteuid()
                and not st.st_mode&0o022,'unsafe interrupted upgrade staging member')
        temporary.unlink();_sync_directory(temporary.parent)
    try:
        checksum=hashlib.sha256();total=0
        with source.open('rb') as incoming,temporary.open('xb') as outgoing:
            os.fchmod(outgoing.fileno(),mode)
            for chunk in iter(lambda:incoming.read(1024*1024),b''):
                total+=len(chunk);require(total<=metadata.st_size,'Guest source grew during upgrade')
                checksum.update(chunk);outgoing.write(chunk)
            require(total==metadata.st_size and checksum.hexdigest()==expected,'Guest resource changed during upgrade')
            outgoing.flush();os.fsync(outgoing.fileno())
        os.replace(temporary,path);_sync_directory(path.parent)
    finally:
        if temporary.exists():temporary.unlink();_sync_directory(temporary.parent)


def _assert_no_application_processes(root, vpn_pid=None, proc=Path('/proc'), invoking_lifecycle=None):
    # sudo and the invoking Python interpreter may retain this command in argv.
    # Permit only actual ancestors invoking this lifecycle operation, never a
    # native application image. A running VPN is permitted only through the
    # attributed systemd MainPID and its exact canonical executable path.
    ancestors=set(); pid=os.getppid()
    while pid > 1 and pid not in ancestors:
        ancestors.add(pid)
        try: pid=int((proc/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[1])
        except FileNotFoundError: break
    for process in proc.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid(): continue
        try:
            image = os.readlink(process/'exe')
            arguments = [value.decode(errors='replace') for value in (process/'cmdline').read_bytes().split(b'\0') if value]
        except FileNotFoundError: continue
        native_image=image.removesuffix(' (deleted)')
        if vpn_pid and process.name == str(vpn_pid) and native_image == str(root/'bin/netbird'): continue
        invokes_lifecycle=(str(invoking_lifecycle or root/'tools/lifecycle.py') in arguments
            and any(value in ('upgrade','uninstall','replace-application','finish-replacement','retire-delivery-stage') for value in arguments)
            and '--root' in arguments and str(root) in arguments)
        invokes_recovery=(str(root/'tools/activate_authority_recovery.py') in arguments
            and any(v in ('apply','apply-successor','apply-autonomous') for v in arguments)
            and '--root' in arguments and str(root) in arguments)
        invokes_controller=(arguments[-4:] == ['/usr/bin/python3','-I','-B',str(root/'tmp/controller/controller.py')])
        if int(process.name) in ancestors and (invokes_lifecycle or invokes_controller or invokes_recovery) and (
                Path(native_image).name == 'sudo' or Path(native_image).name.startswith('python')): continue
        require(not native_image.startswith(str(root)+'/') and not any(
            value.startswith(str(root)+'/') for value in arguments),
            'application process remains; mutation refused')


def retire_delivery_stage(root, package, package_sha256, stage_name, committed_sha256, stage_sha256, signer_sha256, witness, recovery_mode="finalized"):
    """Retire one authenticated, never-committed peer delivery supplement."""
    import fcntl
    _require_operator()
    from apqe_layout import require_frozen_tree
    package = Path(package)
    require(not package.is_relative_to(root) and not root.is_relative_to(package),
            'recovery package must be outside the installation')
    require_frozen_tree(package)
    for pin in (package_sha256, committed_sha256, stage_sha256, signer_sha256):
        require(re.fullmatch(r'[0-9a-f]{64}', pin or '') is not None, 'exact recovery SHA-256 pins required')
    require(digest(package/'package.json') == package_sha256, 'recovery package digest mismatch')
    manifest = verify_package(package)
    engine = package/'tools/lifecycle.py'
    require(Path(__file__).resolve() == engine and digest(engine) == manifest['files']['tools/lifecycle.py'],
            'invoke the exact sealed recovery lifecycle')
    match = re.fullmatch(r'delivery\.tmp-([1-9][0-9]{0,9})-(0|[1-9][0-9]{0,19})', stage_name or '')
    require(match is not None and int(match[1]) > 1, 'exact delivery staging basename required')
    require(recovery_mode in ('finalized','peer-supplement'), 'unsupported delivery recovery mode')
    require((recovery_mode == 'finalized' and 0 < len(witness) <= 4*1024*1024)
            or (recovery_mode == 'peer-supplement' and len(witness) == 0),
            'bounded finality witness or empty peer-supplement input required')
    with _lifecycle_lock(root):
        receipt, _ = _sealed_receipt(root)
        require(receipt.get('role') == 'validator', 'registered validator required')
        for intent in (UPGRADE_INTENT, REPLACEMENT_INTENT, AUTHORITY_RECOVERY_INTENT):
            require(not (root/intent).exists() and not (root/intent).is_symlink(),
                    'reconcile outstanding lifecycle intent before retiring stage')
        owned = _attributed_units(root)
        stopped = owned['synergy-node.service']
        require(stopped.get('MainPID') == '0' and stopped.get('ActiveState') in ('inactive','failed'),
                'stop the registered PoSy owner before retiring stage')
        _assert_no_application_processes(root, vpn_pid=owned['synergy-vpn.service'].get('MainPID'),
                                         invoking_lifecycle=engine)
        require(not (Path('/proc')/match[1]).exists(), 'delivery staging writer PID is still live')
        directory = root/'data/consensus/posy'
        for path in (directory, directory.parent, directory.parent.parent):
            st = path.lstat()
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o022,
                    'unsafe PoSy storage ancestry')
        def private_file(name, pin=None):
            path = directory/name
            st = path.lstat()
            require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1
                    and stat.S_IMODE(st.st_mode) == 0o600 and st.st_size <= 4*1024*1024,
                    'unsafe PoSy recovery member: '+name)
            if pin is not None:
                require(st.st_size > 0 and digest(path) == pin, 'PoSy recovery member digest mismatch: '+name)
            return st
        lock_name = '.synergy-writer.lock'
        metadata = private_file(lock_name)
        lock = os.open(directory/lock_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fd_metadata = os.fstat(lock)
            require((metadata.st_dev,metadata.st_ino)==(fd_metadata.st_dev,fd_metadata.st_ino),
                    'PoSy writer lock replaced')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            def pinned():
                require({p.name for p in directory.glob('delivery.tmp-*')} == {stage_name},
                        'exactly one delivery staging member required')
                return [private_file(name,pin) for name,pin in (
                    ('delivery.json',committed_sha256), (stage_name,stage_sha256), ('sign-once.json',signer_sha256))]
            before = pinned()
            arguments=[package/'bin/synergy-node','verify-delivery-stage',
                root/'config/node.json',stage_name,committed_sha256,stage_sha256,signer_sha256]
            if recovery_mode == 'peer-supplement': arguments.append(recovery_mode)
            verified = json.loads(native(arguments,data=witness))
            require(verified.get('verified') is True and verified.get('stage') == stage_name
                    and verified.get('committed_sha256') == committed_sha256
                    and verified.get('stage_sha256') == stage_sha256
                    and verified.get('signer_sha256') == signer_sha256
                    and verified.get('witness_sha256') == _hash_bytes(witness),
                    'native proof is not bound to the exact stage, journals and finality witness')
            if recovery_mode == 'peer-supplement':
                require(verified.get('recovery_mode') == recovery_mode
                        and verified.get('finalized') is None
                        and isinstance(verified.get('candidate'),dict)
                        and type(verified.get('epoch')) is int and verified['epoch'] > 0,
                        'native peer supplement proof lacks its exact authenticated mode/context')
            require(all((a.st_dev,a.st_ino,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_ctime_ns)
                        for a,b in zip(before,pinned())), 'PoSy recovery members changed during verification')
            (directory/stage_name).unlink()
            _sync_directory(directory)
            return {'retired_uncommitted_delivery_stage':stage_name,'finalized':verified['finalized'],
                    'committed_delivery_preserved':True,'signing_journal_preserved':True,
                    'consensus_started':False}
        finally:
            os.close(lock)


def _installation_stage(root):
    inputs=('genesis.json','authority.json','authority-root.pub','network-manifest.json','p2p-bindings.json','transport-registry.json')
    if read(root/'installation.json').get('role') == 'rpc_gateway':
        return 'commissioned' if read(root/'installation.json').get('gateway_commissioned') is True else 'fresh'
    if (root/'config/node.json').is_file():
        from apqe_layout import selected, PUBLIC
        if selected(read(root/'config/node.json')): inputs=PUBLIC
    present=[(root/'network'/name).exists() or (root/'network'/name).is_symlink() for name in inputs]
    require(not any(present) or all(present), 'partial selected network inputs require commissioning repair')
    if all(present): return 'commissioned'
    return 'uncommissioned' if (root/'data/metadata/schema-version').exists() else 'fresh'


def _fresh_conformance(root, manifest, registered, stage, pending_upgrade_sha256=None):
    # Re-import the NEW installed policy, not a stale module from the upgrader.
    code = "import sys,json;from pathlib import Path;sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(sys.argv[1])/'tools'));from conformance import installed;root=Path(sys.argv[1]);manifest=json.loads((root/'package.json').read_text());print(json.dumps(installed(root,manifest,host=sys.argv[2]=='1',stage=sys.argv[3],pending_upgrade_sha256=sys.argv[4] or None)))"
    result = json.loads(native([sys.executable,'-B','-c',code,root,str(int(registered)),stage,pending_upgrade_sha256 or '']))
    require(result.get('conformant') is True, 'replacement release conformance failed')
    return result


def _root_registered_unit(root, unit, text, token, allowed_digests):
    """Migrate only already-attributed exact old/new unit bytes, crash-resumably."""
    registered=UNIT_DIRECTORY/unit;target=root/'systemd'/unit
    for path in (registered,target):
        if path==registered and path.is_symlink():
            require(os.readlink(path)==str(target),'service registration escapes installation')
            continue
        if path.exists() or path.is_symlink():
            metadata=path.lstat()
            require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
                    and metadata.st_uid==os.geteuid() and not metadata.st_mode & 0o022
                    and digest(path) in allowed_digests,'unattributed unit bytes cannot be migrated')
    require(registered.exists(),'registered unit disappeared before migration')
    _replace_bytes(root,target,text.encode(),0o600,token)
    temporary=registered.parent/('.'+unit+'.synergy-registration-'+token[:16])
    if temporary.exists() or temporary.is_symlink():
        metadata=temporary.lstat()
        require(temporary.is_symlink() and metadata.st_uid==os.geteuid()
                and os.readlink(temporary)==str(target),'foreign interrupted unit registration')
        temporary.unlink();_sync_directory(temporary.parent)
    temporary.symlink_to(target);_sync_directory(temporary.parent)
    # Replacing the symlink itself never follows its target. An interruption
    # leaves either the recorded regular unit or the canonical new rooted link.
    os.replace(temporary,registered);_sync_directory(registered.parent)


def _verify_wallet_release_preflight(result, config, package, manifest):
    from apqe_layout import require_wallet_release_preflight, wallet_release_package, wallet_release_selection
    selection = wallet_release_selection(config)
    release = result.get('wallet_dispatch_release')
    if selection is None:
        require(release is None and (manifest is None or wallet_release_package(package, manifest) is None),
                'Sealed Wallet release requires its independently verified runtime selection')
        return
    if manifest is None:
        manifest = read(package/'package.json')
    bundled = wallet_release_package(package, manifest)
    if selection.get('from_sealed_package'):
        require(bundled is not None and bundled[0] == selection,
                'Installed Wallet release differs from its sealed package')
        base_pin = bundled[1]
    else:
        require(bundled is None, 'Loose Wallet release selection cannot alter the sealed package')
        base_pin = digest(package/'package.json')
    require_wallet_release_preflight(selection, release, base_pin, manifest['files']['bin/synergy-node'],
                                     manifest['files']['lib/apqe/build-report.json'])


def _prepare_wallet_release_update(root, package, manifest, receipt, stage, prior):
    """Authorize the one public configuration change under the upgrade lock."""
    import tempfile
    from apqe_layout import wallet_release_package, wallet_release_selection
    from canary_rpc_relay import _is_digest, _unique_fields
    bundled = wallet_release_package(package, manifest)
    role = receipt.get('role')
    if stage != 'commissioned' or role not in ('validator', 'rpc_gateway'):
        require(prior is None, 'Recorded Wallet release requires its original commissioned node')
        return None, None
    path = root/'config/node.json'
    metadata = path.lstat()
    require(path.resolve() == path and stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == os.geteuid() and metadata.st_nlink == 1
            and not metadata.st_mode & 0o022 and 0 < metadata.st_size <= 1024 * 1024,
            'Bounded canonical validator configuration required')
    before = path.read_bytes()
    config = json.loads(before, object_pairs_hook=_unique_fields)
    original_selection = wallet_release_selection(config)
    if bundled is None:
        require(original_selection is None and prior is None,
                'Upgrade cannot remove an independently approved Wallet release')
        return None, None
    selection, base_pin = bundled
    require(original_selection is None or original_selection == selection,
            'Upgrade cannot replace an independently approved Wallet release')
    require(config.get('role') == role
            and all(config.get(key) == receipt.get(key) for key in ('chain_id', 'network_id', 'node_name'))
            and config.get('genesis_path') == str(root/'network/genesis.json')
            and config.get('aegis_provider', {}).get('report_path') == str(root/'lib/apqe/build-report.json'),
            'Wallet release upgrade must preserve the original managed node selection')
    config['consensus']['managed_wallet_dispatch_release'] = selection
    config['aegis_provider']['authenticated_report_sha256'] = manifest['files']['lib/apqe/build-report.json']
    final_bytes = json.dumps(config, sort_keys=True, indent=2).encode() + b'\n'
    observed = _hash_bytes(before)
    wanted = _hash_bytes(final_bytes)
    require(prior is None or (prior.get('after_config_sha256') == wanted
                              and observed in (prior.get('before_config_sha256'), wanted)),
            'Interrupted Wallet release upgrade differs from the recorded configuration')
    # Preview the staged exact executable/provider using the original installed
    # public identity, signed origin and retained epoch proofs. Ordinary
    # preflight also authenticates that provider's transport enrollment.
    config['aegis_provider']['report_path'] = str(package/'lib/apqe/build-report.json')
    native_preflight = 'preflight' if role == 'validator' else 'preflight-wallet-release'
    with tempfile.TemporaryDirectory(prefix='wallet-release-preflight-', dir=root/'tmp') as directory:
        staged_config = Path(directory)/'node.json'
        write_new(staged_config, config)
        result = json.loads(native([package/'bin/synergy-node',native_preflight,'--config',staged_config],
                                   timeout=120, maximum_stdout=16384), object_pairs_hook=_unique_fields)
    require(path.read_bytes() == before and result.get('read_only') is True
            and _is_digest(result.get('genesis_hash'))
            and result['genesis_hash'] == read(root/'network/network-manifest.json')['genesis_hash']
            and all(result.get(key) == receipt.get(key) for key in ('chain_id', 'network_id')),
            'Managed Wallet release changed its authenticated origin or configuration')
    if role == 'validator':
        require(all(result.get(key) is True for key in
                    ('signed_genesis_verified', 'signed_authority_verified', 'validator_membership_verified')),
                'Wallet release preflight does not verify the original validator membership')
    else:
        require(result.get('schema') == 'nodenetwork-wallet-release-preflight-v1'
                and config.get('consensus', {}).get('mode') == 'observe',
                'Wallet release gateway must preserve its observer role')
    _verify_wallet_release_preflight(result, config, package, manifest)
    release = result['wallet_dispatch_release']
    if original_selection is None and prior is None and release['state'] == 'verified_pending':
        require(release['initial_adoption_before_close'] is True,
                'Selected Wallet release missed its previously reserved epoch-close slot')
    plan = {'base_package_manifest_sha256': base_pin,
            'before_config_sha256': prior['before_config_sha256'] if prior is not None else observed,
            'after_config_sha256': wanted, 'genesis_hash': result['genesis_hash']}
    require(prior is None or prior == plan, 'Interrupted Wallet release upgrade differs from the exact recorded plan')
    return plan, final_bytes


def upgrade(root, package):
    """Crash-resumable managed replacement. Never starts PoSy or VPN."""
    _require_operator()
    package = Path(package)
    contained = package == root/'tmp/update-master'
    if contained:
        from apqe_layout import require_frozen_tree
        require_frozen_tree(package)
    manifest = verify_package(package)
    token = digest(package/'package.json')
    staged = {'pending_upgrade_sha256': token} if contained else {}
    with _lifecycle_lock(root):
        from guest_lifecycle import require_upgrade_compatible
        require_upgrade_compatible(root, manifest)
        policy_path = root/'tmp/controller/policy.json'
        intent_path = root/UPGRADE_INTENT
        resumed = intent_path.exists()
        wallet_config = None
        if resumed:
            intent = read(intent_path)
            require(intent.get('format') == 'synergy-software-upgrade-v1' and intent.get('root') == str(root)
                    and intent.get('new_package_sha256') == token and intent.get('new_files') == manifest['files'],
                    'interrupted upgrade requires the exact recorded package')
            receipt = intent['old_receipt']
            require(receipt.get('root') == str(root) and type(intent.get('registered')) is bool and intent.get('stage') in ('fresh','uncommissioned','commissioned'), 'upgrade intent root/stage differs')
            old_manifest = json.loads(intent['old_manifest_json'])
            require(_hash_bytes(intent['old_manifest_json'].encode()) == receipt['package_sha256']
                    and old_manifest['files'] == receipt['package_files'], 'upgrade intent prior release binding differs')
            wallet_plan, wallet_config = _prepare_wallet_release_update(
                root, package, manifest, receipt, intent['stage'], intent.get('wallet_release'))
            require(wallet_plan == intent.get('wallet_release'), 'Interrupted upgrade lacks its exact Wallet release plan')
        else:
            receipt, old_manifest = _sealed_receipt(root)
            staging=intent_path.parent/('.'+intent_path.name+'.upgrade-'+token[:16])
            if staging.exists() or staging.is_symlink():
                metadata=staging.lstat()
                require(stat.S_ISREG(metadata.st_mode) and not staging.is_symlink() and metadata.st_uid==os.geteuid() and stat.S_IMODE(metadata.st_mode)==0o600, 'unsafe interrupted intent staging')
                staging.unlink();_sync_directory(staging.parent)
            plan = _integration_plan(root)
            stage = _installation_stage(root)
            if plan is not None:
                owned=_attributed_units(root,plan)
                require(owned['synergy-node.service'].get('MainPID') == '0' and owned['synergy-node.service'].get('ActiveState') in ('inactive','failed'), 'stop PoSy before upgrading')
            if stage != 'fresh' and receipt.get('role') != 'rpc_gateway': recover_consensus_archives(root)
            from conformance import installed
            installed(root,host=plan is not None,stage=stage,schema=read(package/'assets/node-config.schema.json'),allow_legacy_integrations=True,**staged)
            wallet_plan, wallet_config = _prepare_wallet_release_update(root, package, manifest, receipt, stage, None)
            if receipt['package_sha256'] == token:
                require(wallet_config is None or (root/'config/node.json').read_bytes() == wallet_config,
                        'Current package lacks its previously adopted Wallet release configuration')
                return {'package_sha256':token,'already_current':True,'consensus_started':False,'automatic_restart':False}
            candidate_plan = json.loads(native([sys.executable,'-B',package/'tools/lifecycle.py','render-units','--root',root])) if plan else {}
            candidate_units = candidate_plan.get('units',{})
            intent = {'format':'synergy-software-upgrade-v1','root':str(root),'old_receipt':receipt,
                'old_manifest_json':(root/'package.json').read_text(),'new_package_sha256':token,'new_files':manifest['files'],
                'registered':plan is not None,'stage':stage,'old_integration':plan,'new_units':candidate_units,'new_wrapper':candidate_plan.get('wrapper')}
            if wallet_plan is not None:
                intent['wallet_release'] = wallet_plan
            if plan:
                require(set(candidate_units) == {Path(p).name for p in plan['paths']}, 'candidate service inventory differs')
                intent['new_integration'] = {'root':str(root),'paths':plan['paths'],
                    'sha256':{str(UNIT_DIRECTORY/name):_hash_bytes(candidate_units[name].encode()) for name in candidate_units}}
            if policy_path.exists() or policy_path.is_symlink():
                from controller import Controller
                import root_guard
                policy=Controller(root).policy()
                pin=policy.get('root_guard_sha256')
                if pin is not None:
                    member='tools/root_guard.py'
                    require(member in manifest['files'] and member in receipt['package_files'], 'Complete guard provenance required')
                    plan=root_guard.migration_plan(root,policy['host_account'],(package/member).read_bytes(),
                                                  receipt['package_files'][member],pin)
                    if plan['old_unit']!=plan['new_unit']:intent['guard_migration']=plan
            for name in set(receipt['package_files'])|set(manifest['files']): _software_path(root,name)
            _assert_no_application_processes(root) if plan is None else None
            # Persist the package-bound recovery plan before service/file changes.
            _replace_bytes(root,intent_path,json.dumps(intent,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
        registered = intent['registered']
        if registered:
            owned = _attributed_units(root,intent['old_integration'],intent['new_integration'])
            state = owned['synergy-node.service']
            require(state.get('MainPID') == '0' and state.get('ActiveState') in ('inactive','failed'), 'stop PoSy before upgrading')
        vpn_pid=owned['synergy-vpn.service'].get('MainPID') if registered else None
        _assert_no_application_processes(root,vpn_pid=vpn_pid)
        if policy_path.exists() or policy_path.is_symlink():
            from controller import Controller
            import base64
            import root_guard
            policy=Controller(root).policy()
            pin=policy.get('root_guard_sha256')
            migration=intent.get('guard_migration')
            if migration is not None:
                old_pin=_hash_bytes(base64.b64decode(migration['old_unit'],validate=True))
                new_pin=_hash_bytes(base64.b64decode(migration['new_unit'],validate=True))
                require(pin in (old_pin,new_pin),'Guard policy is outside recorded upgrade')
                member='tools/root_guard.py'
                require(member in manifest['files'] and member in receipt['package_files'],'Complete guard provenance required')
                root_guard.migration_plan(root,policy['host_account'],(package/member).read_bytes(),
                                          receipt['package_files'][member],old_pin,migration)
                def set_guard_pin(value):
                    current=Controller(root).policy()
                    require(current.get('root_guard_sha256') in (old_pin,new_pin),'Guard policy changed during upgrade')
                    current['root_guard_sha256']=value
                    _replace_bytes(root,policy_path,json.dumps(current,sort_keys=True).encode(),0o600,token)
                root_guard.migrate(root,policy['host_account'],migration,set_guard_pin)
            elif pin is not None:
                root_guard.check_registration(pin)
                member='tools/root_guard.py'
                require(member in manifest['files'] and _hash_bytes(root_guard.render(root,policy['host_account'],(package/member).read_bytes()))==pin,
                        'Unrecorded guard migration refused')
        new_receipt = dict(receipt,package_sha256=token,package_files=manifest['files'])
        current_receipt = read(root/'installation.json')
        require(current_receipt in (receipt,new_receipt), 'installation receipt is outside recorded upgrade')
        require(digest(root/'package.json') in (receipt['package_sha256'],token), 'manifest is outside recorded upgrade')
        all_names = set(receipt['package_files'])|set(manifest['files'])
        # Validate all old/new bindings before replacing any additional file.
        for name in all_names:
            path = _software_path(root,name)
            if path.exists():
                allowed = {mapping[name] for mapping in (receipt['package_files'],manifest['files']) if name in mapping}
                require(digest(path) in allowed, 'upgrade member is neither recorded old nor new: '+name)
        for name,expected in manifest['files'].items():
            if name.startswith(('hosted-machines/','lib/guest-tools/')):
                target=root/name
                if not target.exists() or digest(target)!=expected:
                    _replace_guest_resource(root,target,package/name,expected,0o700 if target.parent.name=='bin' else 0o600,token)
                continue
            data = (package/name).read_bytes()
            require(_hash_bytes(data) == expected, 'candidate changed after package verification')
            target = root/name
            if not target.exists() or digest(target) != expected:
                _replace_bytes(root,target,data,0o700 if target.parent.name in ('bin','tools') else 0o600,token)
        for name in set(receipt['package_files'])-set(manifest['files']):
            path=root/name
            if path.exists(): path.unlink();_sync_directory(path.parent)
            parent=path.parent
            while parent != root and parent.name not in ('bin','lib','assets','systemd','tools','roles'):
                try: parent.rmdir();_sync_directory(parent.parent)
                except OSError: break
                parent=parent.parent
        if wallet_config is not None:
            path = root/'config/node.json'
            require(digest(path) in (wallet_plan['before_config_sha256'], wallet_plan['after_config_sha256'])
                    and _hash_bytes(wallet_config) == wallet_plan['after_config_sha256'],
                    'Wallet release configuration changed during upgrade')
            if path.read_bytes() != wallet_config:
                _replace_bytes(root,path,wallet_config,0o600,token)
        if registered:
            for unit,text in intent['new_units'].items():
                registered_path=UNIT_DIRECTORY/unit
                allowed={integration['sha256'][str(registered_path)]
                         for integration in (intent['old_integration'],intent['new_integration'])}
                _root_registered_unit(root,unit,text,token,allowed)
            _replace_bytes(root,root/'tools/netbird-client',intent['new_wrapper'].encode(),0o700,token)
            _replace_bytes(root,root/'evidence/host-integrations.json',json.dumps(intent['new_integration'],sort_keys=True,indent=2).encode()+b'\n',0o600,token)
            native(['systemctl','daemon-reload'])
        _replace_bytes(root,root/'package.json',(package/'package.json').read_bytes(),0o600,token)
        _replace_bytes(root,root/'installation.json',json.dumps(new_receipt,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
        _fresh_conformance(root,manifest,registered,intent['stage'],**staged)
        completed={'format':'synergy-software-upgrade-completed-v1','root':str(root),'old_package_sha256':receipt['package_sha256'],
            'new_package_sha256':token,'resumed':resumed,'consensus_started':False,'automatic_restart':False}
        _replace_bytes(root,root/UPGRADE_COMPLETED,json.dumps(completed,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
        intent_path.unlink();_sync_directory(intent_path.parent)
        if contained:
            shutil.rmtree(package);_sync_directory(package.parent)
    return dict(completed,package_sha256=token,vpn_stopped=False,vpn_restart_required=registered,custody_or_state_copied=False)


def require_vpn_retired_for_removal(root):
    """Fail closed if an interrupted enrollment may still own a remote peer."""
    from controller import Controller, VPN_ATTEMPT, require as require_vpn
    from vpn import RETIREMENT, RETIREMENT_LIMIT, validate_retirement_receipt
    enrollment_path = root/'evidence/vpn-enrollment.json'
    binding_path = root/'evidence/vpn-server-binding.json'
    present = lambda path: path.exists() or path.is_symlink()
    if not present(enrollment_path):
        vpn_state = root/'vpn'
        from vpn import attempt_state
        state=attempt_state(root)
        canceled=state['attempt_sha256'] is not None and state['retry_after_sha256'] is not None
        empty=not vpn_state.exists() or not vpn_state.is_symlink() and not any(vpn_state.iterdir())
        if canceled and not empty:
            Controller(root).unregistered_vpn_identity(allow_existing=True)
        require_vpn((not present(root/VPN_ATTEMPT) or canceled) and not present(binding_path)
                    and not vpn_state.is_symlink() and (empty or canceled),
                    'VPN enrollment may have succeeded; reconcile with the coordinator before removal',
                    'vpn_reconciliation_required')
        return
    retirement_path = root/'evidence'/RETIREMENT
    require_vpn(present(binding_path) and present(retirement_path),
                'Verify exact VPN registration retirement with the coordinator before removal',
                'vpn_retirement_required')
    controller = Controller(root)
    try:
        raw, local, binding = (controller.direct(path, True, maximum=RETIREMENT_LIMIT).read_bytes()
                               for path in (retirement_path, enrollment_path, binding_path))
        validate_retirement_receipt(raw, local, binding)
    except (ValueError, KeyError, TypeError, OSError, RecursionError):
        require_vpn(False, 'exact VPN registration retirement required', 'vpn_retirement_required')


def remove(root, confirmation):
    require(confirmation == str(root), 'exact --destroy-root confirmation required')
    _require_operator()
    _reject_installation_mounts(root)
    guard = None
    with _lifecycle_lock(root):
        from guest_lifecycle import require_removed
        require_removed(root)
        require(not (root/UPGRADE_INTENT).exists(), 'finish recorded upgrade before uninstall')
        require_vpn_retired_for_removal(root)
        if (root/'tmp/controller/policy.json').exists():
            from controller import Controller, host_removal_plan
            guard = Controller(root).policy().get('root_guard_sha256')
            if guard is not None:
                from root_guard import check_registration
                check_registration(guard)
            host_removal_plan(root)
        plan=_integration_plan(root)
        owned=_attributed_units(root,plan,allow_absent=True,allow_unloaded=True) if plan else {}
        for unit,state in owned.items():
            if state.get('LoadState') == 'not-found': continue
            mutate_owned_service(root,'stop',unit,allow_absent=True)
            mutate_owned_service(root,'disable',unit,allow_absent=True)
        _assert_no_application_processes(root)
        if plan:
            # systemctl disable may already remove its linked-unit registration.
            # Reattribute any remaining path before deleting it; absence is safe
            # only when systemd also reports that no replacement is loaded.
            remaining=_attributed_units(root,plan,allow_absent=True,allow_unloaded=True)
            for unit in remaining: (UNIT_DIRECTORY/unit).unlink()
            if owned: native(['systemctl','daemon-reload'])
        host_records=[]
        if (root/'tmp/controller/policy.json').exists():
            from controller import remove_host_registrations
            host_records=remove_host_registrations(root)
        shutil.rmtree(root)
        require(not root.exists(), 'logical installation removal failed')
    if guard is not None:
        from root_guard import wait_for_retirement
        wait_for_retirement()
    return {'removed_root':str(root),'logical_removal_verified':True,'forensic_erasure_proven':False,'backup_created':False,'remaining_host_managed_records':host_records}


def _validate_commissioning_native(root, staged, package, *, require_readiness=True):
    """Authenticate staged PUBLIC artifacts before replacing any application bytes."""
    import tempfile
    from apqe_layout import validate_stage
    manifest=validate_stage(staged,root,package)
    config=read(staged/'config/node.json')
    def mapped(value):
        if isinstance(value,dict): return {k:mapped(v) for k,v in value.items()}
        if isinstance(value,list): return [mapped(v) for v in value]
        if isinstance(value,str) and value.startswith(str(root)+'/'):
            return str(staged/value[len(str(root))+1:])
        return value
    temporary=mapped(config)
    # Reports retain their authenticated exact bytes and relative library paths.
    temporary['aegis_provider']['report_path']=str(package/'lib/apqe/build-report.json')
    with tempfile.TemporaryDirectory(prefix='synergy-public-preflight-',dir=root/'tmp') as directory:
        path=Path(directory)/'node.json'
        write_new(path,temporary)
        result=json.loads(native([package/'bin/synergy-node','preflight','--config',path]))
    require(result.get('signed_genesis_verified') is True
            and result.get('signed_authority_verified') is True
            and result.get('validator_membership_verified') is True
            and result.get('production_approved') is False,
            'staged native APQE public preflight did not authenticate validator authority')
    _verify_wallet_release_preflight(result, config, package, None)
    authority=read(staged/'network/authority.json')['payload']
    policy=read(staged/'config/start-authorized.json')
    from apqe_layout import startup_readiness_authorized
    ready=(startup_readiness_authorized(root,policy,read(staged/'keys/apqe/validator.pub.json')['node_address'],authority_source=staged)
           if require_readiness else policy.get('all_validators_ready') is False and policy.get('all_pairs_vpn_verified') is False)
    require(policy.get('network_id')==manifest['network_id'] and policy.get('chain_id')==manifest['chain_id'] and ready,
            'explicit provisioning/VPN readiness policy required')
    from apqe_layout import PUBLIC
    require(policy.get('public_file_sha256')=={name:digest(staged/'network'/name) for name in PUBLIC},
            'commissioning readiness pins differ')
    address=read(staged/'keys/apqe/validator.pub.json')['node_address']
    _authorized_validator_ids(policy,authority,address)
    return manifest


def _apply_commissioning(root, staged, manifest):
    from apqe_layout import INPUTS
    for relative in sorted(INPUTS):
        target=root/relative
        target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        require(not target.exists() and not target.is_symlink(),'commissioning refuses existing input: '+relative)
        data=(staged/relative).read_bytes()
        require(hashlib.sha256(data).hexdigest()==manifest['files'][relative],
                'commissioning stage changed after validation')
        with target.open('xb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
    native([root/'bin/synergy-node','init','--node-name',manifest['node_name'],
            '--role-name','validator','--config',root/'config/node.json','--data-directory',root/'data'])


def commission_check(root, package, staged):
    """Read-only gate used on every host before any fleet replacement begins."""
    _require_operator()
    from apqe_layout import require_frozen_tree
    root=Path(root); package=Path(package); staged=Path(staged)
    require(root not in package.parents and root not in staged.parents,
            'commissioning inputs must be outside installation')
    require_frozen_tree(package)
    verify_package(package)
    inputs=_validate_commissioning_native(root,staged,package)
    return {'commissioning_check_passed':True,'network_id':inputs['network_id'],
            'chain_id':inputs['chain_id'],'node_name':inputs['node_name'],
            'application_changed':False,'private_custody_possession_verified':False,
            'production_approved':False}


def commission(root, staged, *, formation_public_pins=None, formation_public_source=None, readiness_sha256=None, authorize=None):
    _require_operator()
    root=Path(root); staged=Path(staged)
    with _lifecycle_lock(root):
        return _commission_locked(root,staged,formation_public_pins,formation_public_source,readiness_sha256,authorize)


def _commission_fresh_keys(root):
    from conformance import approved_treasury_members, _require_fresh_keys
    _require_fresh_keys(root,approved_treasury_members(root))


def _commission_locked(root, staged, formation_public_pins, formation_public_source=None, readiness_sha256=None, authorize=None):
    require(staged==root/'tmp/commissioning','commissioning must be staged inside the installation root')
    receipt,manifest=_sealed_receipt(root)
    require(not (root/'data').exists()
            and not list((root/'config').iterdir()) and not list((root/'network').iterdir()),
            'commission requires fresh uninitialized application root')
    _commission_fresh_keys(root)
    formation=root/'tmp/pre-genesis-validator'
    formed=formation.exists() or formation.is_symlink()
    require(formed==(formation_public_pins is not None),
            'Formation commissioning requires exact public approval and original host-local custody')
    if formed:
        from apqe_layout import assemble_formation_stage
        from controller import Controller
        require(readiness_sha256 is not None and Controller(root).commissioning_readiness(locked=True)==readiness_sha256,
                'Exact current native-approved fleet readiness required under lifecycle lock')
        assemble_formation_stage(root,staged,formation_public_pins,public=formation_public_source,readiness_sha256=readiness_sha256)
    inputs=_validate_commissioning_native(root,staged,root)
    require(all(receipt.get(k)==inputs.get(k) for k in ('network_id','chain_id','node_name')),
            'fresh installation selection differs from commissioned inputs')
    pending=root/'tmp/pending-validator-custody'
    identity_network=root/'tmp/identity-network'
    existing_intent=root/'tmp/existing-network-identity-request.json'
    existing_join=existing_intent.exists() or existing_intent.is_symlink()
    require(not existing_join or (not formed and pending.exists()),
            'Existing-network custody preparation is incomplete or conflicts with formation')
    if pending.exists() or pending.is_symlink():
        from apqe_layout import require_frozen_tree
        require_frozen_tree(pending)
        require_frozen_tree(identity_network)
        staged_keys=staged/'keys/apqe'
        matches={
            'unlock':'unlock',
            'bundle/validator.enc.json':'custody.json',
            'bundle/enrollment-request.json':'enrollment.json',
            'node-identity.json':'validator.pub.json',
        }
        require({path.relative_to(pending).as_posix() for path in pending.rglob('*') if path.is_file()}
                ==set(matches)|{'bundle/validator.pub.json'},'Incomplete or unexpected pending custody')
        require(all(digest(pending/source)==digest(staged_keys/destination)
                    for source,destination in matches.items()),'Commissioning differs from prepared APQE custody')
        network_names={'genesis.json','authority.json','authority-root.pub'}
        actual_names={path.name for path in identity_network.iterdir()}
        approved_names=(network_names,network_names|{'stage-request.json'}) if formed else (network_names,)
        if existing_join:
            from controller import Controller, IDENTITY_INTENT
            controller=Controller(root)
            selection,_=controller.identity_network()
            require(selection.get('schema')=='nodenetwork-existing-identity-network-v1'
                    and 'stage_request_sha256' in selection, 'Certified existing-network staging receipt is required')
            controller.exact_request_receipt(IDENTITY_INTENT,'identity_generate','genesis_sha256',selection['genesis_sha256'])
            approved_names=(network_names|{'stage-request.json'},)
        require(actual_names in approved_names
                and all(digest(identity_network/name)==digest(staged/'network'/name) for name in network_names),
                'Commissioning network differs from prepared APQE identity')
    if authorize is not None:authorize()
    _apply_commissioning(root,staged,inputs)
    # The authenticated, exclusively copied inputs are now at their canonical
    # paths; temporary duplicate custody is no longer needed.
    shutil.rmtree(staged)
    if pending.exists():
        shutil.rmtree(pending)
        shutil.rmtree(identity_network)
    if existing_join:
        existing_intent.unlink()
    if formed:
        shutil.rmtree(formation)
        public=root/'tmp/commissioning-public'
        if public.exists():shutil.rmtree(public)
        for name in ('formation-context.json','formation-prepare-request.json','genesis-bind-request.json'):
            path=root/'tmp'/name
            if path.exists():path.unlink()
    _fresh_conformance(root,manifest,_integration_plan(root) is not None,'commissioned')
    return {'commissioned':True,'consensus_started':False,'production_approved':False}


def _mountinfo_text():
    return Path('/proc/self/mountinfo').read_text()


def _reject_installation_mounts(root):
    # A symlink-free tree may still contain bind mounts into unrelated storage.
    for line in _mountinfo_text().splitlines():
        mount=re.sub(r'\\([0-7]{3})', lambda m:chr(int(m[1],8)), line.split()[4])
        require(mount != str(root) and not mount.startswith(str(root)+'/'),
                'installation contains a mount; explicit unmount/ownership review required')


def replace_application(root, package, staged, authorization):
    _require_operator()
    require(authorization==str(root),'exact --replace-root authorization required')
    with _lifecycle_lock(root):
        from guest_lifecycle import require_removed
        require_removed(root)
        return _replace_application_locked(root, package, staged, authorization)


def _finish_replacement(root, manifest, receipt, token, genesis_sha256, vpn_hashes, vpn_pid):
    # These two empty roots are deleted during replacement but are not
    # recreated by native init. Never remove or overwrite existing contents.
    for name in ('snapshots', 'recovery'):
        path = root/name
        if not path.exists() and not path.is_symlink():
            path.mkdir(mode=0o700)
            _sync_directory(root)
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700, 'unsafe replacement directory: '+name)
    require(all(digest(root/name)==expected for name,expected in vpn_hashes.items()),'preserved VPN bytes changed')
    after=_attributed_units(root)
    require(after[UNITS[0]].get('ActiveState')=='inactive' and after[UNITS[0]].get('MainPID','0') in ('','0'),
            'validator state changed during application replacement')
    require(after[UNITS[1]].get('MainPID')==vpn_pid and after[UNITS[1]].get('ActiveState')=='active',
            'VPN process changed during application replacement')
    _fresh_conformance(root,manifest,True,'commissioned')
    completed=dict(receipt,application_replacement_completed={'token':token,'genesis_sha256':genesis_sha256})
    _replace_bytes(root,root/'installation.json',json.dumps(completed,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
    intent_path=root/REPLACEMENT_INTENT
    intent_path.unlink();_sync_directory(intent_path.parent)


def finish_replacement(root, package, staged):
    """Finish a fully initialized replacement without rerunning native init."""
    _require_operator()
    from apqe_layout import INPUTS, require_frozen_tree, validate_stage
    root,package,staged=map(Path,(root,package,staged))
    require(root not in package.parents and root not in staged.parents,
            'replacement inputs must be outside installation')
    with _lifecycle_lock(root):
        require_frozen_tree(package)
        manifest=verify_package(package)
        # The durable intent records the bytes already accepted by native
        # preflight before retirement. An expired registry must still block
        # startup, but cannot justify reinitializing accepted on-disk state.
        inputs=validate_stage(staged,root,package)
        package_sha=digest(package/'package.json')
        token=package_sha+':'+digest(staged/'commissioning.json')
        receipt,installed_manifest=_sealed_receipt(root)
        require(installed_manifest==manifest and receipt['package_sha256']==package_sha
                and all(receipt.get(k)==inputs.get(k) for k in ('network_id','chain_id','node_name')),
                'installed package or incarnation differs from replacement inputs')
        intent_path=root/REPLACEMENT_INTENT
        if not intent_path.exists() and not intent_path.is_symlink():
            require(receipt.get('application_replacement_completed',{}).get('token')==token,
                    'no matching interrupted replacement')
            return {'already_completed':True,'application_changed':False,'production_approved':False}
        metadata=intent_path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==os.geteuid()
                and stat.S_IMODE(metadata.st_mode)==0o600,'unsafe application replacement intent')
        intent=read(intent_path)
        require(intent.get('root')==str(root) and intent.get('token')==token,
                'interrupted replacement requires the identical validated package and stage')
        vpn_hashes=intent.get('vpn_sha256',{})
        require({'bin/netbird','tools/netbird-client','evidence/host-integrations.json'}<=set(vpn_hashes)
                and all(re.fullmatch(r'(?:bin/netbird|tools/netbird-client|tmp/controller/authorization/inputs/vpn-(?:ca\.pem|provider\.json)|evidence/(?:host-integrations|vpn-[\w-]+)\.json|systemd/[\w.-]*vpn[\w.-]*)',name)
                        and re.fullmatch(r'[a-f0-9]{64}',value) for name,value in vpn_hashes.items()),
                'interrupted replacement VPN preservation inventory differs')
        require(receipt.get('consensus_started') is False, 'replacement already started consensus')
        marker=root/'data/metadata/schema-version'
        require(marker.is_file() and not marker.is_symlink() and marker.read_bytes()==b'synergy-node-storage:1',
                'replacement native initialization did not complete')
        require(set(inputs['files'])==set(INPUTS), 'replacement commissioning inventory differs')
        for name,expected in inputs['files'].items():
            path=root/name
            require(path.is_file() and not path.is_symlink() and digest(path)==expected,
                    'installed commissioning input differs: '+name)
        owned=_attributed_units(root)
        node,vpn=(owned[name] for name in UNITS)
        vpn_pid=int(vpn.get('MainPID','0') or '0')
        require(node.get('ActiveState')=='inactive' and node.get('MainPID','0') in ('','0')
                and vpn.get('ActiveState')=='active' and vpn_pid>1,'replacement service state differs')
        _reject_installation_mounts(root)
        _assert_no_application_processes(root,vpn_pid=vpn_pid)
        _finish_replacement(root,manifest,receipt,token,digest(staged/'network/genesis.json'),
                            vpn_hashes,str(vpn_pid))
        return {'application_replacement_completed':True,'state_reinitialized':False,
                'consensus_started':False,'production_approved':False}


def _replace_application_locked(root, package, staged, authorization):
    """Explicitly retire old chain/application, preserving the attributed VPN.

    A surviving intent blocks startup and binds an interrupted replacement to
    the same complete package/stage. No old history or sign-once state is imported.
    """
    _require_operator()
    root=Path(root); package=Path(package); staged=Path(staged)
    require(authorization==str(root),'exact --replace-root authorization required')
    require(package.is_absolute() and package.resolve()==package and root not in package.parents
            and root not in staged.parents,'replacement inputs must be outside installation')
    from apqe_layout import require_frozen_tree
    require_frozen_tree(package)
    new=verify_package(package)
    inputs=_validate_commissioning_native(root,staged,package)
    intent_path=root/REPLACEMENT_INTENT
    token=digest(package/'package.json')+':'+digest(staged/'commissioning.json')
    genesis_sha256=digest(staged/'network/genesis.json')
    completed=read(root/'installation.json').get('application_replacement_completed')
    if completed:
        if completed.get('token')==token:
            # Even after the new node has signed and stopped, this command is
            # idempotent: never reset its fresh storage or sign-once journal.
            _sealed_receipt(root)
            if intent_path.exists():
                require(read(intent_path).get('token')==token, 'replacement completion/intent mismatch')
                intent_path.unlink();_sync_directory(intent_path.parent)
            return {'already_completed':True,'application_changed':False,'production_approved':False}
        require(completed.get('genesis_sha256')!=genesis_sha256,
                'replacement requires a fresh chain; refusing same-Genesis safety-state reset')
    if intent_path.exists():
        intent=read(intent_path)
        require(intent.get('token')==token and intent.get('root')==str(root),
                'interrupted replacement requires the identical validated package and stage')
        receipt=intent['receipt']; old_files=receipt['package_files']
        for name,old_hash in old_files.items():
            path=_software_path(root,name)
            if path.exists():
                require(digest(path) in (old_hash,new['files'].get(name)),
                        'interrupted replacement member differs from old/new sealed package')
    else:
        receipt,old=_sealed_receipt(root); old_files=old['files']
    owned=_attributed_units(root)
    node=owned['synergy-node.service']; vpn=owned['synergy-vpn.service']
    require(node.get('ActiveState')=='inactive' and node.get('MainPID','0') in ('','0'),
            'stop the attributed validator before replacing application')
    vpn_pid=int(vpn.get('MainPID','0') or '0')
    require(vpn.get('ActiveState')=='active' and vpn_pid>1,'owned VPN must remain active during application replacement')
    _assert_no_application_processes(root,vpn_pid=vpn_pid)
    preserved=['bin/netbird','tools/netbird-client','evidence/host-integrations.json']
    # The private-CA carrier trust remains exact through application replacement.
    # No credential contents or copies are needed to bind these public inputs.
    from vpn import client_environment
    client_environment(root)
    for name in ('vpn-ca.pem','vpn-provider.json'):
        relative='tmp/controller/authorization/inputs/'+name
        if (root/relative).exists() or (root/relative).is_symlink():preserved.append(relative)

    # The running VPN owns mutable state under vpn/. Never write, delete or
    # snapshot-copy that namespace; its daemon may legitimately update bytes.
    preserved += [str(path.relative_to(root)) for path in (root/'evidence').glob('vpn-*.json')]
    preserved += [str(path.relative_to(root)) for path in (root/'systemd').glob('*vpn*') if path.is_file()]
    vpn_hashes={name:digest(root/name) for name in preserved}
    require(new['files'].get('bin/netbird')==vpn_hashes['bin/netbird'],
            'replacement package must preserve the running VPN executable exactly')
    for name in preserved:
        if name in new['files']: require(new['files'][name]==vpn_hashes[name],'package changes protected VPN member')
    for name in ('keys','config','network','data','logs','snapshots','recovery'):
        path=root/name
        require(not path.is_symlink(),'replacement application directory is symlink')
        if path.exists():
            for child in path.rglob('*'): require(not child.is_symlink(),'replacement application symlink refused')
    if not intent_path.exists():
        write_new(intent_path,{'root':str(root),'token':token,'receipt':receipt,'vpn_sha256':vpn_hashes})
        _sync_directory(intent_path.parent)
    else:
        require(read(intent_path)['vpn_sha256']==vpn_hashes,'preserved VPN changed during interrupted replacement')
    _reject_installation_mounts(root)
    current=_attributed_units(root)['synergy-node.service']
    require(current.get('ActiveState')=='inactive' and current.get('MainPID','0') in ('','0'),
            'validator state changed before replacement deletion')
    _assert_no_application_processes(root,vpn_pid=vpn_pid)
    # Old validator role custody is retired; unrelated wallet custody stays in
    # its explicit existing namespace and cannot authorize this fresh validator.
    for child in (root/'keys').iterdir():
        if child.name=='wallets': continue
        require(child.name in ('root','p2p','consensus','ingress','authority','transport','apqe'),
                'unknown custody namespace; exact scope review required')
    require(not any(name.startswith('vpn/') or name=='tools/netbird-client' for name in old_files
                    if name not in preserved),'old software inventory overlaps preserved VPN state')
    for name in old_files:
        if name not in preserved:
            path=_software_path(root,name)
            if path.exists(): path.unlink()
    for name in ('config','network','data','snapshots','recovery'):
        path=root/name
        if path.exists(): shutil.rmtree(path)
    for child in list((root/'keys').iterdir()):
        if child.name!='wallets':
            if child.is_dir(): shutil.rmtree(child)
            else: child.unlink()
    for path in (root/'logs').glob('node.log*'): path.unlink()
    for path in (root/'evidence').iterdir():
        if path.name!='application-replacement-intent.json' and str(path.relative_to(root)) not in preserved:
            if path.is_dir(): shutil.rmtree(path)
            else: path.unlink()
    admin=root/'run/admin.sock'
    if admin.exists(): admin.unlink()
    for name,expected in new['files'].items():
        if name in preserved: continue
        target=_software_path(root,name);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if name.startswith(('hosted-machines/','lib/guest-tools/')):
            _replace_guest_resource(root,target,package/name,expected,0o700 if target.parent.name=='bin' else 0o600,token)
            continue
        data=(package/name).read_bytes()
        require(hashlib.sha256(data).hexdigest()==expected,'package changed during replacement')
        _replace_bytes(root,target,data,0o700 if target.parent.name in ('bin','tools') else 0o600,token)
    _replace_bytes(root,root/'package.json',(package/'package.json').read_bytes(),0o600,token)
    for name in ('config','network'): (root/name).mkdir(mode=0o700,exist_ok=True)
    new_receipt=dict(receipt,network_id=inputs['network_id'],chain_id=inputs['chain_id'],
        node_name=inputs['node_name'],package_sha256=digest(package/'package.json'),
        package_files=new['files'],consensus_started=False)
    _replace_bytes(root,root/'installation.json',json.dumps(new_receipt,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
    _apply_commissioning(root,staged,inputs)
    _finish_replacement(root,new,new_receipt,token,genesis_sha256,vpn_hashes,str(vpn_pid))
    return {'application_replaced':True,'old_chain_data_removed':True,'fresh_storage_initialized':True,
            'vpn_pid_preserved':vpn_pid,'consensus_started':False,'production_approved':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['register','render-units','storage-recover','start-check','relay-start-check','health','start','stop','restart','uninstall','upgrade','retire-delivery-stage','commission','commission-check','replace-application','finish-replacement'])
    parser.add_argument('--root',required=True);parser.add_argument('--destroy-root');parser.add_argument('--package');parser.add_argument('--staged');parser.add_argument('--replace-root')
    for option in ('package-sha256','stage-name','committed-sha256','stage-sha256','signer-sha256'):
        parser.add_argument('--'+option)
    parser.add_argument('--recovery-mode',choices=['finalized','peer-supplement'],default='finalized')
    args=parser.parse_args();root=safe_root(args.root)
    if args.command == 'render-units': result={'units':rendered_units(root),'wrapper':wrapper_text(root)}
    elif args.command == 'register': result=register(root)
    elif args.command == 'storage-recover': result=recover_consensus_archives(root)
    elif args.command == 'start-check': result=start_check(root)
    elif args.command == 'relay-start-check': result=relay_start_check(root)
    elif args.command == 'uninstall': result=remove(root,args.destroy_root)
    elif args.command == 'commission-check':
        require(args.package and args.staged,'sealed --package and --staged required')
        result=commission_check(root,Path(args.package),Path(args.staged))
    elif args.command == 'commission':
        require(args.staged,'verified --staged provisioning inputs required');result=commission(root,Path(args.staged))
    elif args.command == 'replace-application':
        require(args.package and args.staged,'sealed --package and --staged required')
        result=replace_application(root,Path(args.package),Path(args.staged),args.replace_root)
    elif args.command == 'finish-replacement':
        require(args.package and args.staged,'original sealed --package and --staged required')
        result=finish_replacement(root,Path(args.package),Path(args.staged))
    elif args.command == 'upgrade':
        require(args.package,'sealed --package required');result=upgrade(root,args.package)
    elif args.command == 'retire-delivery-stage':
        require(args.package,'sealed recovery --package required')
        result=retire_delivery_stage(root,args.package,args.package_sha256,args.stage_name,
            args.committed_sha256,args.stage_sha256,args.signer_sha256,sys.stdin.buffer.read(4*1024*1024+1),args.recovery_mode)
    elif args.command == 'health': result=json.loads(native([root/'bin/synergy-node','health','--admin-socket',root/'run/admin.sock']))
    else:
        if args.command in ('start','restart'): start_check(root)
        mutate_owned_service(root,args.command,'synergy-node.service')
        result={'requested':args.command,'unit':'synergy-node.service','health_not_inferred':True}
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (ValueError,OSError,subprocess.SubprocessError,KeyError) as error:
        print(f'Synergy lifecycle refused: {error}',file=sys.stderr);sys.exit(1)
