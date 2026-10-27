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
from synergy_linux import digest, native, read, require, safe_root, verify_identity, verify_package, write_new

UNITS = ('synergy-node.service', 'synergy-vpn.service')
UNIT_DIRECTORY = Path('/etc/systemd/system')
UPGRADE_INTENT = 'evidence/upgrade-intent.json'
UPGRADE_COMPLETED = 'evidence/upgrade-completed.json'


def node_unit(root):
    return f'''[Unit]
Description=Synergy universal validator
After=network-online.target synergy-vpn.service
Requires=synergy-vpn.service
ConditionPathExists={root}/config/start-authorized.json

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
    return f'''[Unit]
Description=Synergy application-owned NetBird client
After=network-online.target
Wants=network-online.target

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
ExecStart={root}/bin/netbird service run --config {root}/vpn/default.json --daemon-addr unix://{root}/run/netbird.sock --log-file {root}/logs/netbird.log
Restart=on-failure
RestartSec=5s
StandardOutput=append:{root}/logs/netbird-service.log
StandardError=append:{root}/logs/netbird-service.log

[Install]
WantedBy=multi-user.target
'''


def wrapper_text(root):
    return f'#!/bin/sh\nexport HOME={root} TMPDIR={root}/tmp XDG_CONFIG_HOME={root}/vpn XDG_CACHE_HOME={root}/cache NB_STATE_DIR={root}/vpn NB_DNS_STATE_FILE={root}/vpn/state.json\nexec {root}/bin/netbird --daemon-addr unix://{root}/run/netbird.sock "$@"\n'


def rendered_units(root):
    return dict(zip(UNITS, (node_unit(root), vpn_unit(root))))


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
    require(plan.get('root') == str(root) and plan.get('paths') == expected
            and set(plan.get('sha256', {})) == set(expected), 'host integration ownership plan differs')
    require(all(re.fullmatch(r'[0-9a-f]{64}', value) for value in plan['sha256'].values()),
            'host integration digest malformed')
    return plan


def _attributed_units(root, plan=None, alternate=None, allow_absent=False, allow_unloaded=False):
    plan = plan if plan is not None else _integration_plan(root)
    require(plan is not None, 'installation has no registered service ownership')
    paths=[str(UNIT_DIRECTORY/name) for name in UNITS]
    for candidate in (plan,alternate):
        if candidate is not None:
            require(candidate.get('root') == str(root) and candidate.get('paths') == paths
                    and set(candidate.get('sha256',{})) == set(paths), 'service ownership plan differs')
    owned = {}
    for unit in UNITS:
        path = UNIT_DIRECTORY/unit
        expected = {plan['sha256'][str(path)]}
        if alternate is not None: expected.add(alternate['sha256'][str(path)])
        state = _unit_state(unit)
        if not path.exists() and not path.is_symlink():
            require(allow_absent and state.get('LoadState') == 'not-found'
                    and not state.get('FragmentPath') and state.get('MainPID', '0') in ('','0'),
                    'missing owned unit has a loaded or foreign replacement: '+unit)
            continue
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
                and metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022
                and digest(path) in expected, 'host integration drift: '+unit)
        unloaded = allow_unloaded and state.get('LoadState') == 'not-found' and not state.get('FragmentPath') and state.get('MainPID','0') in ('','0')
        require(unloaded or state.get('FragmentPath') == str(path) and not state.get('DropInPaths'),
                'effective service is not owned by this installation: '+unit)
        owned[unit] = state
    return owned


def mutate_owned_service(root, action, unit, allow_absent=False):
    require(action in ('start','stop','restart','disable') and unit in UNITS, 'unsupported service mutation')
    owned = _attributed_units(Path(root),allow_absent=allow_absent)
    require(unit in owned, 'owned service is absent')
    native(['systemctl', action, unit])


def _sealed_receipt(root):
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'canonical installation root required')
    for path in [root, *root.parents]:
        require(not path.is_symlink(), 'installation ancestry symlink refused')
    metadata = root.stat()
    require(metadata.st_uid == os.geteuid() and not metadata.st_mode & 0o022, 'unsafe installation root ownership/mode')
    receipt = read(root/'installation.json')
    require(receipt.get('root') == str(root) and receipt.get('format') == 'synergy-universal-linux-v1', 'installation receipt/root mismatch')
    require(digest(root/'package.json') == receipt['package_sha256'], 'installed manifest drift')
    manifest = read(root/'package.json')
    require(receipt['package_files'] == manifest['files'], 'installation inventory differs')
    for name, expected in manifest['files'].items():
        _software_path(root, name)
        require(digest(root/name) == expected, 'installed package drift: '+name)
    return receipt, manifest


def _software_path(root, name):
    relative = Path(name)
    require(name and not relative.is_absolute() and '..' not in relative.parts
            and (relative.parts[0] in ('bin','lib','assets','systemd','tools','roles') or name == 'README.md'),
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
        require(connection.execute('PRAGMA user_version').fetchone() == (1,), 'unsupported consensus archive version')
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require(tables == {'evidence','revisions','legacy_timeout'}, 'unsupported consensus archive schema')
    finally: connection.close()
    return {'recovered_existing_archives':1}


def register(root):
    _require_operator()
    require(re.fullmatch(r'/[A-Za-z0-9_/.-]+/Synergy', str(root)), 'systemd root contains unsupported characters')
    _sealed_receipt(root)
    paths = [UNIT_DIRECTORY/name for name in UNITS]
    contents = rendered_units(root)
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
            require(plan['sha256'] == {str(p):_hash_bytes(contents[p.name].encode()) for p in paths},
                    'partial registration belongs to a different unit policy')
            _attributed_units(root, plan, allow_absent=True,allow_unloaded=True)
        for path in paths:
            if path.exists(): continue
            with path.open('x') as stream:
                os.fchmod(stream.fileno(),0o644);stream.write(contents[path.name]);stream.flush();os.fsync(stream.fileno())
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


def start_check(root):
    _require_operator(linux=False)
    require(not (root/UPGRADE_INTENT).exists(), 'finish the recorded upgrade before startup')
    receipt, _ = _sealed_receipt(root)
    _attributed_units(root)
    recover_consensus_archives(root)
    from conformance import installed
    installed(root, host=True)
    policy = read(root/'config/start-authorized.json')
    identity = verify_identity(root)
    require(policy['network_id'] == receipt['network_id'] and policy['chain_id'] == receipt['chain_id'], 'wrong startup incarnation')
    require(policy.get('all_validators_ready', policy.get('all_five_ready')) is True
            and policy.get('all_pairs_vpn_verified') is True, 'complete signed-authority installation and VPN readiness required')
    require(set(policy['public_file_sha256']) == {'genesis.json','authority.json','authority-root.pub',
            'network-manifest.json','p2p-bindings.json','transport-registry.json'}, 'complete public-network pin set required')
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
    authority = read(root/'network/authority.json')['payload']
    require(authority['network_id'] == receipt['network_id'] and authority['chain_id'] == receipt['chain_id'], 'authenticated authority incarnation differs')
    signed_ids = _authorized_validator_ids(policy,authority,identity['address'])
    vpn = native([root/'tools/netbird-client','status']).decode().lower()
    require('management: connected' in vpn and 'signal: connected' in vpn, 'native VPN not connected')
    return {'startup_check_passed':True,'network_id':receipt['network_id'],'signed_active_validator_count':len(signed_ids)}


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


def _assert_no_application_processes(root, vpn_pid=None, proc=Path('/proc')):
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
        invokes_lifecycle=(str(root/'tools/lifecycle.py') in arguments
            and any(value in ('upgrade','uninstall') for value in arguments)
            and '--root' in arguments and str(root) in arguments)
        if int(process.name) in ancestors and invokes_lifecycle and (
                Path(native_image).name == 'sudo' or Path(native_image).name.startswith('python')): continue
        require(not native_image.startswith(str(root)+'/') and not any(
            value.startswith(str(root)+'/') for value in arguments),
            'application process remains; mutation refused')


def _installation_stage(root):
    inputs=('genesis.json','authority.json','authority-root.pub','network-manifest.json','p2p-bindings.json','transport-registry.json')
    present=[(root/'network'/name).exists() or (root/'network'/name).is_symlink() for name in inputs]
    require(not any(present) or all(present), 'partial selected network inputs require commissioning repair')
    if all(present): return 'commissioned'
    return 'uncommissioned' if (root/'data/metadata/schema-version').exists() else 'fresh'


def _fresh_conformance(root, manifest, registered, stage):
    # Re-import the NEW installed policy, not a stale module from the upgrader.
    code = "import sys,json;from pathlib import Path;sys.dont_write_bytecode=True;sys.path.insert(0,str(Path(sys.argv[1])/'tools'));from conformance import installed;root=Path(sys.argv[1]);manifest=json.loads((root/'package.json').read_text());print(json.dumps(installed(root,manifest,host=sys.argv[2]=='1',stage=sys.argv[3])))"
    result = json.loads(native([sys.executable,'-B','-c',code,root,str(int(registered)),stage]))
    require(result.get('conformant') is True, 'replacement release conformance failed')
    return result


def upgrade(root, package):
    """Crash-resumable software-only replacement. Never starts PoSy or VPN."""
    _require_operator()
    package = Path(package)
    manifest = verify_package(package)
    token = digest(package/'package.json')
    with _lifecycle_lock(root):
        intent_path = root/UPGRADE_INTENT
        resumed = intent_path.exists()
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
            if stage != 'fresh': recover_consensus_archives(root)
            from conformance import installed
            installed(root,host=plan is not None,stage=stage,schema=read(package/'assets/node-config.schema.json'))
            if receipt['package_sha256'] == token:
                return {'package_sha256':token,'already_current':True,'consensus_started':False,'automatic_restart':False}
            candidate_plan = json.loads(native([sys.executable,'-B',package/'tools/lifecycle.py','render-units','--root',root])) if plan else {}
            candidate_units = candidate_plan.get('units',{})
            intent = {'format':'synergy-software-upgrade-v1','root':str(root),'old_receipt':receipt,
                'old_manifest_json':(root/'package.json').read_text(),'new_package_sha256':token,'new_files':manifest['files'],
                'registered':plan is not None,'stage':stage,'old_integration':plan,'new_units':candidate_units,'new_wrapper':candidate_plan.get('wrapper')}
            if plan:
                require(set(candidate_units) == set(UNITS), 'candidate service inventory differs')
                intent['new_integration'] = {'root':str(root),'paths':plan['paths'],
                    'sha256':{str(UNIT_DIRECTORY/name):_hash_bytes(candidate_units[name].encode()) for name in UNITS}}
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
        if registered:
            for unit,text in intent['new_units'].items():
                _replace_bytes(root,UNIT_DIRECTORY/unit,text.encode(),0o644,token)
            _replace_bytes(root,root/'tools/netbird-client',intent['new_wrapper'].encode(),0o700,token)
            _replace_bytes(root,root/'evidence/host-integrations.json',json.dumps(intent['new_integration'],sort_keys=True,indent=2).encode()+b'\n',0o600,token)
            native(['systemctl','daemon-reload'])
        _replace_bytes(root,root/'package.json',(package/'package.json').read_bytes(),0o600,token)
        _replace_bytes(root,root/'installation.json',json.dumps(new_receipt,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
        _fresh_conformance(root,manifest,registered,intent['stage'])
        completed={'format':'synergy-software-upgrade-completed-v1','root':str(root),'old_package_sha256':receipt['package_sha256'],
            'new_package_sha256':token,'resumed':resumed,'consensus_started':False,'automatic_restart':False}
        _replace_bytes(root,root/UPGRADE_COMPLETED,json.dumps(completed,sort_keys=True,indent=2).encode()+b'\n',0o600,token)
        intent_path.unlink();_sync_directory(intent_path.parent)
    return dict(completed,package_sha256=token,vpn_stopped=False,vpn_restart_required=registered,custody_or_state_copied=False)


def remove(root, confirmation):
    require(confirmation == str(root), 'exact --destroy-root confirmation required')
    _require_operator()
    require(not (root/UPGRADE_INTENT).exists(), 'finish recorded upgrade before uninstall')
    if (root/'evidence/vpn-enrollment.json').exists():
        enrollment=read(root/'evidence/vpn-server-binding.json');retirement=read(root/'evidence/vpn-retirement.json')
        require(enrollment['peer_id'] and retirement['peer_id'] == enrollment['peer_id']
                and retirement['retired'] is True and retirement['absence_verified'] is True, 'exact VPN registration retirement required')
    # mountinfo escapes whitespace/backslashes. Decode before containment checks.
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        mount=re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),line.split()[4])
        require(mount != str(root) and not mount.startswith(str(root)+'/'), 'installation contains a mount; explicit unmount/ownership review required')
    with _lifecycle_lock(root):
        plan=_integration_plan(root)
        owned=_attributed_units(root,plan,allow_absent=True,allow_unloaded=True) if plan else {}
        for unit,state in owned.items():
            if state.get('LoadState') == 'not-found': continue
            mutate_owned_service(root,'stop',unit,allow_absent=True)
            mutate_owned_service(root,'disable',unit,allow_absent=True)
        _assert_no_application_processes(root)
        if plan:
            for unit in owned: (UNIT_DIRECTORY/unit).unlink()
            if owned: native(['systemctl','daemon-reload'])
        shutil.rmtree(root)
        require(not root.exists(), 'logical installation removal failed')
    return {'removed_root':str(root),'logical_removal_verified':True,'forensic_erasure_proven':False,'backup_created':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['register','render-units','storage-recover','start-check','health','start','stop','restart','uninstall','upgrade'])
    parser.add_argument('--root',required=True);parser.add_argument('--destroy-root');parser.add_argument('--package')
    args=parser.parse_args();root=safe_root(args.root)
    if args.command == 'render-units': result={'units':rendered_units(root),'wrapper':wrapper_text(root)}
    elif args.command == 'register': result=register(root)
    elif args.command == 'storage-recover': result=recover_consensus_archives(root)
    elif args.command == 'start-check': result=start_check(root)
    elif args.command == 'uninstall': result=remove(root,args.destroy_root)
    elif args.command == 'upgrade':
        require(args.package,'sealed --package required');result=upgrade(root,args.package)
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
