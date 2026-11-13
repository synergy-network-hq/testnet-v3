#!/usr/bin/env python3
"""Native Linux installation boundary. Never imports old validator custody/state.

This tool manages one new, sealed Synergy root. Fleet destruction is deliberately
not implemented here: it requires the separate exact operator-approved manifest.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True

MARKER = 'synergy-universal-linux-v1'
VOLATILE = ('keys', 'data', 'run', 'logs', 'cache', 'tmp', 'vpn', 'snapshots', 'recovery', 'evidence')
BOOTSTRAP_MASTER = Path('tmp/bootstrap-master')
# Column order, SQLite affinity, NOT NULL and primary-key position are part of
# the native storage ABI. Table names alone cannot establish compatibility.
CONSENSUS_ARCHIVE_COLUMNS = {
    'evidence': (('key','TEXT',1,1),('bytes','BLOB',1,0),('digest','BLOB',1,0),('legacy_digest','BLOB',0,0),('height','TEXT',0,0)),
    'revisions': (('key','TEXT',1,1),('digest','BLOB',1,2),('bytes','BLOB',1,0)),
    'legacy_timeout': (('key','TEXT',1,1),('height','TEXT',1,0),('bytes','INTEGER',1,0)),
    'archive_objects': (('hash','BLOB',1,1),('kind','INTEGER',1,0),('segment','INTEGER',1,0),('offset','INTEGER',1,0),('length','INTEGER',1,0)),
    'archive_records': (('key','TEXT',1,1),('object_hash','BLOB',1,0),('digest','BLOB',1,0),('legacy_digest','BLOB',0,0),('height','TEXT',0,0),('bytes','INTEGER',1,0)),
    'archive_revisions': (('key','TEXT',1,1),('digest','BLOB',1,2),('object_hash','BLOB',1,0)),
    'archive_segments': (('segment','INTEGER',0,1),('committed_bytes','INTEGER',1,0),('sealed','INTEGER',1,0)),
    'archive_finality': (('height','TEXT',1,1),('finality_hash','BLOB',1,0),('qc1_hash','BLOB',1,0),('qc2_hash','BLOB',1,0),('qc3_hash','BLOB',1,0)),
    'hot_evidence': (('key','TEXT',1,1),('bytes','BLOB',1,0),('digest','BLOB',1,0),('legacy_digest','BLOB',0,0),('height','TEXT',1,0)),
    'archive_lifecycle': (('singleton','INTEGER',0,1),('floor','TEXT',1,0)),
}
CONSENSUS_ARCHIVE_TABLES = {
    1: frozenset(('evidence', 'revisions', 'legacy_timeout')),
    2: frozenset(CONSENSUS_ARCHIVE_COLUMNS),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def consensus_archive_version(connection):
    """Validate existing native storage only; never initialize or migrate it.

    Version2 is additive and forward-only after native activation. Recognizing
    it here does not promise that a version1 executable can read new writes.
    Native startup remains responsible for frame/index consistency and proofs.
    """
    version = connection.execute('PRAGMA user_version').fetchone()[0]
    require(version in CONSENSUS_ARCHIVE_TABLES, 'unsupported consensus archive version')
    tables = {row[0] for row in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    require(tables == CONSENSUS_ARCHIVE_TABLES[version], 'unsupported consensus archive schema')
    require(not connection.execute(
        "SELECT name FROM sqlite_master WHERE type IN ('view','trigger') LIMIT 1").fetchone(),
        'unexpected consensus archive executable schema')
    for table in sorted(tables):
        # `table` has already been checked against a closed, trusted name set.
        rows = connection.execute('PRAGMA table_xinfo(' + table + ')').fetchall()
        columns = tuple((row[1], row[2].upper(), row[3], row[5]) for row in rows)
        require(columns == CONSENSUS_ARCHIVE_COLUMNS[table]
                and all(row[4] is None and row[6] == 0 for row in rows),
                'unsupported consensus archive column schema: ' + table)
    return version


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path, maximum=16 * 1024 * 1024):
    path = Path(path)
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and not path.is_symlink() and st.st_size <= maximum,
            'bounded regular non-symlink file required')
    return json.loads(path.read_bytes())


def write_new(path, value, mode=0o600):
    path = Path(path)
    with path.open('xb') as stream:
        os.chmod(path, mode)
        stream.write(json.dumps(value, sort_keys=True, indent=2).encode() + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def safe_root(value, existing=True):
    root = Path(value)
    require(root.is_absolute() and root.name == 'synergy' and '..' not in root.parts,
            'explicit absolute installation root ending in lowercase synergy required')
    require(len(root.parts) >= 3, 'installation root is too broad')
    for parent in [root, *root.parents]:
        if parent.exists() or parent.is_symlink():
            require(not parent.is_symlink(), 'symlink installation ancestry refused')
            require(parent.is_dir(), 'installation ancestry must be directories')
            require(parent.stat().st_uid == os.geteuid(), 'installation ancestry ownership differs')
            require(not parent.stat().st_mode & 0o002 or parent.stat().st_mode & stat.S_ISVTX,
                    'world-writable installation ancestor refused')
    if existing:
        require(root.is_dir(), 'installation root absent')
        receipt = read(root / 'installation.json')
        require(receipt['format'] == MARKER and receipt['root'] == str(root),
                'installation receipt/root mismatch')
    else:
        require(not root.exists() and not root.is_symlink(), 'fresh installation root already exists')
    return root


def native(argv, timeout=120, data=None):
    # A tool may mention custody paths, but secret output/stderr is never relayed.
    result = subprocess.run([str(v) for v in argv], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode == 0, f'native {Path(argv[0]).name} operation failed (exit {result.returncode})')
    require(len(result.stdout) <= 1024 * 1024, 'native response exceeds bound')
    return result.stdout


def verify_package(package):
    package = Path(package)
    manifest = read(package / 'package.json')
    require(manifest['format'] == MARKER and manifest['architecture'] == 'x86_64', 'unsupported package')
    require(isinstance(manifest['files'], dict), 'package inventory required')
    members = list(package.rglob('*'))
    require(not any(p.is_symlink() for p in members), 'package symlink refused')
    require(all(p.is_dir() or p.is_file() for p in members), 'special package member refused')
    for name, expected in manifest['files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts, 'unsafe package member')
        path = package / relative
        require(path.is_file() and not path.is_symlink(), 'missing/nonregular package member')
        require(digest(path) == expected, 'package member digest mismatch')
    actual = {p.relative_to(package).as_posix() for p in package.rglob('*')
              if p.is_file() and not p.name.startswith('._') and p.name != 'package.json'}
    require(actual == set(manifest['files']), 'unexpected package file')
    require(not any((package / p).is_symlink() for p in manifest['files']), 'package symlink refused')
    roles = read(package / 'roles/roles.json')
    require(len(roles['roles']) == 20 and len(set(roles['roles'])) == 20
            and (roles['implemented'] == ['validator']
                 or roles['implemented'] == ['validator', 'rpc_gateway']
                 and 'tools/canary_rpc_relay.py' in manifest['files']
                 and 'rpc_gateway' in roles['roles']), 'canonical twenty-role inventory required')
    require({p.name for p in (package / 'roles').iterdir() if p.is_dir()} == set(roles['roles']),
            'role directory inventory differs')
    for name in VOLATILE:
        require((package / name).is_dir() and not list((package / name).iterdir()),
                'master contains runtime/private state')
    for name in ('synergy-node', 'synergy-keytool', 'synergy-genesis', 'netbird'):
        with (package / 'bin' / name).open('rb') as stream:
            header = stream.read(20)
        require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00', 'native Linux x86_64 executable required')
    return manifest


def _staged_master(root, package, expected_sha256):
    """Accept only a private, otherwise empty root prepared by the operator."""
    from apqe_layout import require_frozen_tree
    from lifecycle import _reject_installation_mounts
    require(root.is_absolute() and root.name == 'synergy' and root.resolve() == root,
            'canonical lowercase synergy root required')
    require(len(root.parts) >= 3, 'installation root is too broad')
    require(package == root/BOOTSTRAP_MASTER, 'master must be staged inside synergy/tmp/bootstrap-master')
    require_frozen_tree(package)
    _reject_installation_mounts(root)
    require(all(path.stat().st_nlink == 1 for path in package.rglob('*') if path.is_file()),
            'staged master contains a hard-linked file')
    require(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in (root, root/'tmp', package)),
            'bootstrap directories must be private')
    controller=root/'tmp/controller'
    if controller.exists():
        from controller import control_inventory
        control_inventory(root)
    require(set(root.iterdir()) == {root/'tmp'} and set((root/'tmp').iterdir()) == ({package,controller} if controller.exists() else {package}),
            'bootstrap refuses existing installation or additional staged files')
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha256) is not None
            and digest(package/'package.json') == expected_sha256,
            'master manifest does not match the independently supplied digest')


def _require_install_operator():
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86_64 host required')
    require(os.geteuid() == 0, 'installation requires root')


def install(package, root, role, network_id, chain_id, node_name, *, staged_master_sha256=None):
    _require_install_operator()
    require(re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,127}', network_id), 'explicit network incarnation required')
    require(0 < chain_id <= (1 << 64) - 1, 'explicit nonzero u64 chain ID required')
    package, root = Path(package), Path(root)
    if staged_master_sha256 is not None:
        _staged_master(root, package, staged_master_sha256)
    else:
        root = safe_root(root, existing=False)
    manifest = verify_package(package)
    roles = read(package / 'roles/roles.json')
    require(role in roles['roles'] and role in roles['implemented'], 'selected role is not implemented')
    require(role != 'rpc_gateway' or chain_id == 99999, 'RPC gateway setup is restricted to Canary 99999')
    require(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', node_name), 'invalid node name')
    # No merge, overwrite, source checkout or old state is copied.
    ignore = shutil.ignore_patterns('._*', '__pycache__')
    if staged_master_sha256 is None:
        shutil.copytree(package, root, ignore=ignore)
    else:
        # The package's empty tmp directory is already represented by root/tmp.
        # Copy siblings exclusively; never recurse into or overwrite staging.
        for source in package.iterdir():
            if source.name == 'tmp' or source.name in ignore(str(package), [source.name]):
                continue
            if source.is_dir():
                shutil.copytree(source, root/source.name, ignore=ignore)
            else:
                with source.open('rb') as src, (root/source.name).open('xb') as dst:
                    shutil.copyfileobj(src, dst)
        require(digest(root/'package.json') == staged_master_sha256, 'copied manifest differs from master pin')
        # Confirm all copied bytes before removing the operator's staged input.
        require(all(digest(root/name) == expected for name, expected in manifest['files'].items()),
                'copied software differs from master manifest')
        # Only the validated software stage is disposable; no node state exists.
        shutil.rmtree(package)
    os.chmod(root, 0o700)
    for relative in VOLATILE:
        path = root / relative
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        require(not list(path.iterdir()) or relative == 'tmp' and staged_master_sha256 is not None
                and set(path.iterdir()) == {root/'tmp/controller'}, 'master contains runtime/private state')
    (root / 'data').rmdir()  # Native initialization owns exclusive data-root creation.
    for path in root.rglob('*'):
        if path.is_dir():
            os.chmod(path, 0o700)
        elif path.is_file():
            os.chmod(path, 0o700 if path.parent.name in ('bin', 'tools') else 0o600)
    receipt = {'format': MARKER, 'root': str(root), 'role': role, 'network_id': network_id,
               'chain_id': chain_id, 'node_name': node_name,
               'package_sha256': digest(root / 'package.json'),
               'package_files': manifest['files'], 'host_integrations': [], 'consensus_started': False}
    write_new(root / 'installation.json', receipt)
    from conformance import installed
    installed(root, manifest, initialized=False)
    native([root / 'bin/synergy-node', 'version'])
    return receipt


def operational_key_id(role, address):
    require(role in ('p2p', 'consensus', 'ingress') and address.startswith('synv1'),
            'validator role/address required')
    # Global registry IDs must remain distinct across independently generated
    # validators. A shared basename such as "consensus" is not a fleet key ID.
    return role + '-' + hashlib.sha256(address.encode()).hexdigest()[:24]


def identity(root):
    raise ValueError('legacy raw validator identity generation is retired; commission explicit APQE custody')


def verify_identity(root):
    from apqe_layout import validate_layout
    return validate_layout(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('verify-package'); p.add_argument('package', type=Path)
    p = sub.add_parser('install')
    for name in ('package', 'root', 'role', 'network-id', 'node-name'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--chain-id', type=int, required=True)
    p.add_argument('--staged-master-sha256', help='independent package.json pin for in-root bootstrap')
    for command in ('identity-init', 'identity-verify'):
        p = sub.add_parser(command); p.add_argument('--root', required=True)
    args = parser.parse_args()
    if args.command == 'verify-package':
        m = verify_package(args.package); result = {'verified': True, 'files': len(m['files'])}
    elif args.command == 'install':
        result = install(args.package, args.root, args.role, args.network_id, args.chain_id, args.node_name,
                         staged_master_sha256=args.staged_master_sha256)
    else:
        root = safe_root(args.root)
        result = identity(root) if args.command == 'identity-init' else verify_identity(root)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print(f'Synergy installation refused: {error}', file=sys.stderr)
        sys.exit(1)
