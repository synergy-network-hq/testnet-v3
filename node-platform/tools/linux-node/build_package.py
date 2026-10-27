#!/usr/bin/env python3
"""Build/seal the canonical Linux deployment master; never deploys or signs."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parents[2]
MASTER = SOURCE.parents[1] / 'Node-Architecture/Linux/Synergy'
TOOLS = ('synergy_linux.py', 'lifecycle.py', 'vpn.py', 'conformance.py',
         'test_cross_network.py')
DIRECTORIES = ('bin', 'lib', 'assets', 'config', 'network', 'systemd', 'tools',
               'data', 'keys', 'logs', 'cache', 'tmp', 'run', 'vpn',
               'snapshots', 'recovery', 'evidence', 'roles')


def desired_files(templates):
    """The source inventory defines the release; existing master bytes do not."""
    return ({p.relative_to(templates).as_posix() for p in templates.rglob('*')
             if p.is_file() and not p.name.startswith('._')}
            | {'bin/'+name for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird')}
            | {'tools/'+name for name in TOOLS}
            | {'assets/node-config.schema.json','roles/roles.json'})


def check_master_inventory(master, expected, roles):
    """Refuse stale files/directories before generation, without deleting them."""
    if not master.exists(): return
    directories=set(DIRECTORIES) | {'roles/'+role for role in roles}
    directories.update(str(p) for name in expected for p in Path(name).parents if str(p)!='.')
    for path in master.rglob('*'):
        if path.name.startswith('._'): continue  # ExFAT metadata is never packaged.
        relative=path.relative_to(master).as_posix()
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('unsafe master member: '+relative)
        allowed=directories if path.is_dir() else expected | {'package.json'}
        if relative not in allowed:
            raise ValueError('unexpected master member; explicit review required: '+relative)


def load_provenance():
    spec = importlib.util.spec_from_file_location('provenance', SOURCE / 'tools/release/provenance.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--netbird-binary', type=Path, required=True)
    p.add_argument('--netbird-sha256', required=True)
    args = p.parse_args()
    require = lambda c, m: None if c else (_ for _ in ()).throw(ValueError(m))
    require(not args.evidence.exists(), 'new evidence directory required')
    args.evidence.mkdir(parents=True, mode=0o700)
    provenance = load_provenance()
    subprocess.run([sys.executable, str(SOURCE / 'tools/linux-node/audit_chain_selection.py'),
                    '--output', str(args.evidence / 'chain-selection-audit.json')], check=True)
    core = SOURCE.parent
    subprocess.run([sys.executable, str(SOURCE / 'tools/release/provenance.py'), 'inventory',
                    '--root', str(core), '--output', str(args.evidence / 'source-before.json')], check=True)
    templates = Path(__file__).parent / 'templates'
    role_source = (SOURCE / 'crates/synergy-protocol-types/src/role.rs').read_text()
    enum_body = re.search(r'pub enum NodeRole\s*\{([^}]+)\}', role_source).group(1)
    roles = [re.sub(r'(?<!^)(?=[A-Z])', '_', v.strip()).lower()
             for v in enum_body.split(',') if v.strip()]
    require(len(roles) == 20 and len(set(roles)) == 20, 'canonical role taxonomy changed; review required')
    expected=desired_files(templates)
    check_master_inventory(MASTER, expected, roles)
    # The package is a generated deployment artifact. Its templates and role
    # inventory originate in this single version-controlled implementation.
    for relative in DIRECTORIES:
        (MASTER / relative).mkdir(parents=True, exist_ok=True)
    for path in templates.rglob('*'):
        if path.is_file() and not path.name.startswith('._'):
            target = MASTER / path.relative_to(templates)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    from configuration_schema import generate
    (MASTER/'assets/node-config.schema.json').write_text(json.dumps(generate(SOURCE),indent=2,sort_keys=True)+'\n')
    (MASTER / 'roles/roles.json').write_text(json.dumps({'roles': roles, 'implemented': ['validator']}, indent=2) + '\n')
    env = dict(os.environ)
    toolchain = SOURCE / 'target/posy-linux-tools/bin'
    env['PATH'] = str(toolchain) + os.pathsep + env['PATH']
    env['CARGO_ZIGBUILD_PYTHON_PATH'] = str(toolchain / 'python')
    env['CARGO_INCREMENTAL'] = '0'
    with (args.evidence / 'build.log').open('wb') as log:
        subprocess.run(['cargo', 'zigbuild', '--locked', '--release', '--no-default-features',
                            '-p', 'synergy-node', '-p', 'synergy-keytool', '-p', 'synergy-genesis',
                            '--target', 'x86_64-unknown-linux-gnu.2.28'], cwd=SOURCE, env=env,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    subprocess.run([sys.executable, str(SOURCE / 'tools/release/provenance.py'), 'inventory',
                    '--root', str(core), '--output', str(args.evidence / 'source-after.json')], check=True)
    before = json.loads((args.evidence / 'source-before.json').read_text())
    after = json.loads((args.evidence / 'source-after.json').read_text())
    # Exact inventory representation may contain timestamps; compare its content root.
    require(before == after, 'source changed during build')
    source_sha256 = hashlib.sha256(json.dumps(before,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    output = Path(env.get('CARGO_TARGET_DIR', SOURCE / 'target')) / 'x86_64-unknown-linux-gnu/release'
    artifacts = {}
    for name in ('synergy-node', 'synergy-keytool', 'synergy-genesis'):
        sealed=provenance.seal_artifact(output/name)
        shutil.copyfile(output / name, MASTER / 'bin' / name)
        require(provenance.seal_artifact(MASTER/'bin'/name)==sealed,
                'copied ELF differs from flushed build output: '+name)
        artifacts[name]=sealed
    sealed=provenance.seal_artifact(args.netbird_binary)
    require(provenance.digest(args.netbird_binary) == args.netbird_sha256, 'NetBird pin mismatch')
    shutil.copyfile(args.netbird_binary, MASTER / 'bin/netbird')
    require(provenance.seal_artifact(MASTER/'bin/netbird')==sealed,'copied NetBird differs from pinned artifact')
    artifacts['netbird']=sealed
    for name in TOOLS:
        shutil.copyfile(Path(__file__).parent/name, MASTER/'tools'/name)
    for role in json.loads((MASTER / 'roles/roles.json').read_text())['roles']:
        (MASTER / 'roles' / role).mkdir(exist_ok=True)
    check_master_inventory(MASTER, expected, roles)
    files = {name:provenance.digest(MASTER/name) for name in sorted(expected)}
    manifest = {'format': 'synergy-universal-linux-v1', 'architecture': 'x86_64',
                'source_sha256': source_sha256, 'files': files,
                'native_artifacts': artifacts,
                'release_id': 'synergy-linux-' + source_sha256[:16],
                'conformance_policy_version': 1,
                'configuration_schema_version': 1,
                'storage_formats': {'root': 'synergy-node-storage:1', 'consensus_evidence_sqlite': 1},
                'runtime_dependencies': ['Linux x86_64', 'glibc >= 2.28', 'systemd', 'Python >= 3.9 with sqlite3',
                                         'iproute2', 'iputils-ping', 'kernel TUN/WireGuard'],
                'features': [], 'acceptance_status': 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES'}
    (MASTER / 'package.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (args.evidence / 'package.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    subprocess.run([sys.executable, str(SOURCE/'tools/release/provenance.py'), 'inventory',
                    '--root',str(core),'--output',str(args.evidence/'source-after-package.json')],check=True)
    require(json.loads((args.evidence/'source-after-package.json').read_text())==before,
            'source changed while sealing package')
    print(json.dumps({'master': str(MASTER), 'files': len(files),
                      'package_sha256': provenance.digest(MASTER / 'package.json')}))


if __name__ == '__main__':
    main()
