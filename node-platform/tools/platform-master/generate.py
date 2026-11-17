#!/usr/bin/env python3
"""Generate native platform layouts; never install, register services or authorize startup.

The existing Linux builder remains the Linux release owner. macOS and Windows
layout generation is separate from native release and controller qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import sys

SOURCE = Path(__file__).resolve().parents[2]
MASTER = SOURCE.parents[1] / 'Node-Architecture'
DIRECTORIES = ('bin', 'lib/apqe', 'assets', 'config', 'network', 'tools', 'data',
               'keys/apqe', 'logs', 'cache', 'tmp', 'run', 'vpn', 'snapshots',
               'recovery', 'evidence', 'roles')
PLATFORMS = {
    'macOS': {'root': '/Library/Application Support/Synergy', 'os': 'macos',
              'service': 'launchd', 'suffix': '', 'library': '.dylib'},
    'Windows': {'root': r'C:\ProgramData\Synergy', 'os': 'windows',
                'service': 'windows-service-control-manager', 'suffix': '.exe', 'library': '.dll'},
}
PROVIDERS = ('mldsa44', 'mldsa65', 'mldsa87', 'mlkem512', 'mlkem768',
             'mlkem1024', 'fndsa512', 'fndsa1024')


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def roles():
    # Same role owner as tools/linux-node/build_package.py; no NCP roster copy.
    text = (SOURCE/'crates/synergy-protocol-types/src/role.rs').read_text()
    body = re.search(r'pub enum NodeRole\s*\{([^}]+)\}', text).group(1)
    result = [re.sub(r'(?<!^)(?=[A-Z])', '_', item.strip()).lower()
              for item in body.split(',') if item.strip()]
    require(len(result) == 20 and len(set(result)) == 20, 'Role taxonomy changed')
    return result


def description(platform):
    spec = PLATFORMS[platform]
    payload = ['bin/'+name+spec['suffix'] for name in
               ('synergy-node', 'synergy-keytool', 'synergy-genesis', 'netbird', 'apqe')]
    payload += ['lib/apqe/build-report.json']
    payload += ['lib/apqe/libaegis'+name+spec['library'] for name in PROVIDERS]
    return {'schema': 'synergy-platform-master-v1', 'platform': spec['os'],
            'installation_root': spec['root'], 'service_manager': spec['service'],
            'directories': list(DIRECTORIES), 'roles': roles(),
            'required_native_payload': payload,
            'management_workflow': ['Synergy Portal', 'dApp Hub', 'NodeNetwork'],
            'runtime_qualified': False, 'activation_authorized': False,
            'missing_qualification': ['native target artifacts and provider report',
                                      'authenticated native NodeNetwork platform controller',
                                      'owned service registration and complete removal',
                                      'native lifecycle and restart qualification'],
            'source_owners': ['01-Core-Protocol/node-platform', 'Node-Architecture/'+platform]}


def contents(platform):
    spec = PLATFORMS[platform]
    files = {'architecture.json': canonical(description(platform)),
             'roles/roles.json': canonical({'roles': roles(), 'implemented': []})}
    if platform == 'macOS':
        root = spec['root']
        # Reuse NCP's launchd dictionary convention; no legacy paths/binaries.
        # This is a template only: never registered by generation or auto-loaded.
        job = {'Label': 'network.synergy.node',
               'ProgramArguments': [root+'/bin/synergy-node', 'start', '--config', root+'/config/node.json'],
               'WorkingDirectory': root, 'RunAtLoad': False, 'KeepAlive': False,
               'StandardOutPath': root+'/logs/node.out.log',
               'StandardErrorPath': root+'/logs/node.err.log', 'Umask': 0o077,
               'SoftResourceLimits': {'NumberOfFiles': 65536}}
        files['launchd/network.synergy.node.plist'] = plistlib.dumps(job, sort_keys=True)
    else:
        # synergy-node is not a Windows ServiceMain binary. Do not use sc.exe
        # to pretend an ordinary console process implements the SCM protocol.
        files['services/node-service.json'] = canonical({
            'schema': 'synergy-windows-service-template-v1', 'name': 'SynergyNode',
            'root': spec['root'], 'registration_supported': False,
            'reason': 'A qualified SCM host with native graceful shutdown is required',
            'owned_executable': spec['root']+r'\bin\synergy-node.exe',
            'owned_configuration': spec['root']+r'\config\node.json'})
    return files


def generate(master=MASTER, check=False):
    """Materialize only templates, with no runtime artifacts, identities or state."""
    for platform in PLATFORMS:
        root = master/platform/'synergy'
        require(not any(p.is_symlink() for p in (root, *root.parents)), 'Master symlink forbidden')
        expected = contents(platform)
        if check:
            for name, data in expected.items():
                require((root/name).is_file() and (root/name).read_bytes() == data,
                        'Generated platform template drift: '+platform+'/'+name)
            for name in DIRECTORIES:
                require((root/name).is_dir() and not (root/name).is_symlink(), 'Missing owned directory: '+name)
        else:
            for name in (*DIRECTORIES, *('roles/'+role for role in roles())):
                (root/name).mkdir(parents=True, exist_ok=True)
            for name, data in expected.items():
                path = root/name
                require(not path.is_symlink(), 'Generated file symlink forbidden')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
    return {'schema': 'synergy-platform-generation-result-v1',
            'platforms': list(PLATFORMS), 'templates_verified': True,
            'runtime_qualified': False, 'activation_authorized': False}


def native_target(data, os_name, arch):
    """Read native headers, refusing a filename/manifest-only target claim."""
    require(arch in ('x86_64', 'aarch64'), 'Unsupported architecture')
    if os_name == 'macos':
        require(len(data) >= 32 and data[:4] == b'\xcf\xfa\xed\xfe', 'Thin 64-bit Mach-O required')
        cpu = struct.unpack_from('<I', data, 4)[0]
        require(cpu == {'x86_64': 0x1000007, 'aarch64': 0x100000c}[arch], 'Mach-O architecture differs')
    elif os_name == 'windows':
        require(len(data) >= 64 and data[:2] == b'MZ', 'Windows PE required')
        offset = struct.unpack_from('<I', data, 60)[0]
        require(offset <= len(data)-26 and data[offset:offset+4] == b'PE\x00\x00', 'Invalid PE header')
        machine = struct.unpack_from('<H', data, offset+4)[0]
        require(machine == {'x86_64': 0x8664, 'aarch64': 0xaa64}[arch]
                and struct.unpack_from('<H', data, offset+24)[0] == 0x20b, 'PE architecture differs')
    else:
        raise ValueError('Unsupported native target')


def verify_release(root, expected_sha256, platform):
    """Integrity check only; independent pin does not grant startup or approval."""
    require(re.fullmatch('[a-f0-9]{64}', expected_sha256) is not None, 'Independent manifest SHA256 required')
    require(platform in PLATFORMS, 'Unsupported platform')
    root = Path(root)
    require(not any(p.is_symlink() for p in (root, *root.parents)), 'Release symlink forbidden')
    raw = (root/'package.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256, 'Package pin differs')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'Duplicate release field')
            value[key] = item
        return value
    manifest = json.loads(raw, object_pairs_hook=unique)
    require(manifest.get('format') == 'synergy-platform-release-v1'
            and manifest.get('platform') == PLATFORMS[platform]['os'], 'Release platform differs')
    inventory = manifest.get('files')
    require(isinstance(inventory, dict) and set(description(platform)['required_native_payload']) | set(contents(platform)) == set(inventory),
            'Native payload incomplete')
    actual = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'Release links forbidden')
        if path.is_file() and path.relative_to(root).as_posix() != 'package.json':
            actual.add(path.relative_to(root).as_posix())
    require(actual == set(inventory), 'Release has missing or undeclared files')
    for name, pin in inventory.items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts and relative.as_posix() == name
                and '\\' not in name and re.fullmatch('[a-f0-9]{64}', pin) is not None, 'Unsafe inventory member')
        data = (root/name).read_bytes()
        require(hashlib.sha256(data).hexdigest() == pin, 'Payload hash differs: '+name)
        if name.startswith('bin/') or name.endswith(PLATFORMS[platform]['library']):
            native_target(data, manifest['platform'], manifest.get('architecture'))
    return {'integrity_verified': True, 'runtime_qualified': False, 'activation_authorized': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(generate(check=args.check), sort_keys=True))
    except (ValueError, OSError) as error:
        parser.exit(1, str(error)+'\n')
