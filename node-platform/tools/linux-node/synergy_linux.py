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

MARKER = 'synergy-universal-linux-v1'
VOLATILE = ('keys', 'data', 'run', 'logs', 'cache', 'tmp', 'vpn', 'snapshots', 'recovery', 'evidence')


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    require(root.is_absolute() and root.name == 'Synergy' and '..' not in root.parts,
            'explicit absolute installation root ending in Synergy required')
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
            and roles['implemented'] == ['validator'], 'canonical twenty-role inventory required')
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


def install(package, root, role, network_id, chain_id, node_name):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'Linux x86_64 host required')
    require(os.geteuid() == 0, 'installation requires root')
    require(re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,127}', network_id), 'explicit network incarnation required')
    require(0 < chain_id <= (1 << 64) - 1, 'explicit nonzero u64 chain ID required')
    manifest = verify_package(package)
    roles = read(Path(package) / 'roles/roles.json')
    require(role in roles['roles'] and role in roles['implemented'], 'selected role is not implemented')
    require(re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', node_name), 'invalid node name')
    root = safe_root(root, existing=False)
    # No merge, overwrite, source checkout or old state is copied.
    shutil.copytree(package, root, ignore=shutil.ignore_patterns('._*', '__pycache__'))
    os.chmod(root, 0o700)
    for relative in VOLATILE:
        path = root / relative
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
        require(not list(path.iterdir()), 'master contains runtime/private state')
    (root / 'data').rmdir()  # Native initialization owns exclusive data-root creation.
    for path in root.rglob('*'):
        if path.is_dir():
            os.chmod(path, 0o700)
        elif path.is_file():
            os.chmod(path, 0o700 if path.parent.name in ('bin', 'tools') else 0o600)
    receipt = {'format': MARKER, 'root': str(root), 'role': role, 'network_id': network_id,
               'chain_id': chain_id, 'node_name': node_name,
               'package_sha256': digest(Path(package) / 'package.json'),
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
    receipt = read(root / 'installation.json')
    keytool = root / 'bin/synergy-keytool'
    custody = root / 'keys'
    require(not list(custody.iterdir()), 'identity initialization requires empty new custody')
    for role in ('root', 'p2p', 'consensus', 'ingress'):
        (custody / role).mkdir(mode=0o700)
    native([keytool, 'generate-validator-root', 'root', receipt['network_id'], custody / 'root'])
    root_public = custody / 'root/root.identity-root.json'
    public = read(root_public)
    address = public['address']
    require(address.startswith('synv1'), 'native address is not a validator address')
    ids = {role: operational_key_id(role, address) for role in ('p2p', 'consensus', 'ingress')}
    native([keytool, 'generate-node', ids['p2p'], root_public, custody / 'p2p', '--validator'])
    native([keytool, 'generate-consensus', address, ids['consensus'], custody / 'consensus'])
    native([keytool, 'generate-etdag-1024', address, ids['ingress'], custody / 'ingress'])
    verify_identity(root)
    initialized = json.loads(native([root / 'bin/synergy-node', 'init', '--node-name', receipt['node_name'],
                                    '--role-name', 'validator', '--config', root / 'config/node.json',
                                    '--data-directory', root / 'data']))
    require(initialized['fresh_storage_initialized'] and not initialized['consensus_started'],
            'native storage initialization did not complete')
    # Public-only export: deliberately enumerated rather than copying custody.
    exported = {'network_id': receipt['network_id'], 'chain_id': receipt['chain_id'],
                'node_name': receipt['node_name'], 'address': address, 'identity_root': public,
                'identity': read(custody / 'p2p' / f"{ids['p2p']}.identity.json"), 'roles': {}}
    for role in ('p2p', 'consensus', 'ingress'):
        exported['roles'][role] = {'metadata': read(custody / role / f'{ids[role]}.metadata.json'),
                                   'public_key_hex': (custody / role / f'{ids[role]}.public.key').read_bytes().hex()}
    write_new(root / 'evidence/public-identity.json', exported, 0o644)
    write_new(root / 'evidence/initialization.json', initialized)
    return {'address': address, 'public_export': str(root / 'evidence/public-identity.json'),
            'private_keys_exported': False, 'consensus_started': False}


def verify_identity(root):
    receipt = read(root / 'installation.json')
    keytool = root / 'bin/synergy-keytool'
    custody = root / 'keys'
    native([keytool, 'verify-validator-root', custody / 'root/root.identity-root.json',
            custody / 'root/root.secret.key', receipt['network_id']])
    address = read(custody / 'root/root.identity-root.json')['address']
    for role in ('p2p', 'consensus', 'ingress'):
        key_id = operational_key_id(role, address)
        native([keytool, 'verify-key-pair', custody / role / f'{key_id}.metadata.json',
                custody / role / f'{key_id}.public.key', custody / role / f'{key_id}.secret.key', address, key_id])
    p2p_id = operational_key_id('p2p', address)
    require(read(custody / 'p2p' / f'{p2p_id}.identity.json')['node_address'] == address, 'P2P identity differs from root')
    return {'address': address, 'native_possession_verified': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('verify-package'); p.add_argument('package', type=Path)
    p = sub.add_parser('install')
    for name in ('package', 'root', 'role', 'network-id', 'node-name'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--chain-id', type=int, required=True)
    for command in ('identity-init', 'identity-verify'):
        p = sub.add_parser(command); p.add_argument('--root', required=True)
    args = parser.parse_args()
    if args.command == 'verify-package':
        m = verify_package(args.package); result = {'verified': True, 'files': len(m['files'])}
    elif args.command == 'install':
        result = install(args.package, args.root, args.role, args.network_id, args.chain_id, args.node_name)
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
