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
MASTER = SOURCE.parents[1] / 'Node-Architecture/Linux/synergy'
TOOLS = ('synergy_linux.py', 'lifecycle.py', 'vpn.py', 'conformance.py',
         'test_cross_network.py', 'apqe_layout.py', 'canary_rpc_relay.py', 'controller.py', 'bootstrap.py', 'activate_authority_recovery.py', 'root_guard.py')
DIRECTORIES = ('bin', 'lib', 'assets', 'config', 'network', 'systemd', 'tools',
               'data', 'keys', 'logs', 'cache', 'tmp', 'run', 'vpn',
               'snapshots', 'recovery', 'evidence', 'roles')



def native_storage_formats(source=SOURCE):
    """Bind release metadata to the actual native formats being packaged."""
    persistence = source/'crates/synergy-posy/src/persistence'
    version = re.search(r'const FORMAT: i64 = (\d+);',
                        (persistence/'evidence_store.rs').read_text())
    header = re.search(r'const HEADER: &\[u8; 8\] = b"([A-Z0-9]{8})";',
                       (persistence/'archive_segments.rs').read_text())
    if version is None or header is None or int(version[1]) != 2 or header[1] != 'SNPARC02':
        raise ValueError('native archive format changed; explicit compatibility review required')
    return {'root': 'synergy-node-storage:1', 'consensus_evidence_sqlite': int(version[1]),
            'consensus_evidence_sqlite_readable': [1, 2],
            'consensus_archive_segment_header': header[1],
            'downgrade_after_schema2_activation': 'unsupported'}


def desired_files(templates):
    """The source inventory defines the release; existing master bytes do not."""
    return ({p.relative_to(templates).as_posix() for p in templates.rglob('*')
             if p.is_file() and not p.name.startswith('._')}
            | {'bin/'+name for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird','apqe')}
            | {'tools/'+name for name in TOOLS}
            | {'assets/node-config.schema.json','roles/roles.json'})


def check_master_inventory(master, expected, roles):
    """Refuse stale files/directories before generation, without deleting them."""
    if master.parent.is_dir():
        require(not any(p.name.casefold() == master.name.casefold() and p.name != master.name
                        for p in master.parent.iterdir()), 'mixed-case master exists; use a clean lowercase output')
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


def require(condition, message):
    if not condition:
        raise ValueError(message)


def content_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def dependency_sources(provenance):
    """Exact external Rust sources, separate from the native report's C pins."""
    apqe = SOURCE.parents[1] / '21-Aegis-Engine'
    inventory = provenance.inventory(apqe)
    require(provenance.clean(inventory), 'clean APQE dependency checkout required')
    manifest = apqe / 'synergy-address-engine/Cargo.toml'
    match = re.search(r'aegis-selected-backend\s*=\s*\{[^\n]*path\s*=\s*"([^"]+)"', manifest.read_text())
    require(match is not None, 'explicit selected-backend path required')
    rust = (manifest.parent / match[1]).resolve(strict=True)
    records = []
    total = 0
    def visit(directory):
        nonlocal total
        for path in sorted(directory.iterdir()):
            if path.name.startswith('.') or path.name == 'target':
                continue
            require(not path.is_symlink(), 'selected-backend source symlink forbidden')
            if path.is_dir():
                visit(path)
            else:
                require(path.is_file(), 'regular selected-backend source required')
                total += path.stat().st_size
                require(len(records) < 4096 and total <= 32 * 1024 * 1024,
                        'selected-backend source inventory exceeds bound')
                records.append({'path': path.relative_to(rust).as_posix(),
                                'length': path.stat().st_size, 'sha256': provenance.digest(path)})
    visit(rust)
    require(any(v['path'] == 'Cargo.toml' for v in records)
            and any(v['path'].startswith('src/') for v in records), 'Rust dependency source missing')
    return {'apqe': {'revision': inventory['source_revision'], 'inventory_sha256': content_sha256(inventory)},
            'selected_backend_rust': {'inventory_sha256': content_sha256(records), 'files': records}}


def verify_apqe_provider(provider, report_sha, provenance):
    report = provider / 'build-report.json'
    require(report.is_file() and not report.is_symlink() and provenance.digest(report) == report_sha,
            'independently pinned APQE native report required')
    value = json.loads(report.read_text())
    require(value.get('validation') is False
            and value.get('backend_policy', {}).get('selected_backend') == 'portable',
            'engineering portable provider required')
    files = {'build-report.json': report_sha}
    for artifact in value['artifacts']:
        name = artifact['path']
        require(isinstance(name, str) and Path(name).name == name
                and name.startswith('libaegis') and name.endswith('.so') and name not in files,
                'unsafe or duplicate APQE library')
        require(not (provider/name).is_symlink() and provenance.digest(provider/name) == artifact['sha256'],
                'APQE provider library differs from authenticated report')
        files[name] = artifact['sha256']
    require(value.get('required_variant_count') == 8 and len(files) == 9,
            'complete selected APQE provider inventory required')
    return files


def verify_copied_provider(destination, files, provenance):
    for name, expected in files.items():
        require(provenance.digest(destination/name) == expected,
                'copied APQE provider differs from authenticated report: ' + name)


def glibc_version(text):
    require(isinstance(text, str) and re.fullmatch(r'glibc >= [0-9]+\.[0-9]+(?:\.[0-9]+)?', text),
            'canonical glibc requirement required')
    return tuple(int(v) for v in text.removeprefix('glibc >= ').split('.'))


def required_glibc(paths):
    versions = set()
    for path in paths:
        with path.open('rb') as source:
            tail = b''
            while block := source.read(1024 * 1024):
                data = tail + block
                versions.update(tuple(int(n) for n in v.split(b'.'))
                                for v in re.findall(rb'GLIBC_([0-9]+(?:\.[0-9]+){1,2})\x00', data))
                tail = data[-64:]
    require(bool(versions), 'native ELF GLIBC requirements absent')
    maximum = max(versions, key=lambda v: (*v, *(0 for _ in range(3-len(v)))))
    return 'glibc >= ' + '.'.join(str(v) for v in maximum)


def verify_prebuilt_manifest(value, source_sha, dependencies, paths):
    require(value.get('format') == 'synergy-native-linux-build-v1'
            and value.get('source_sha256') == source_sha
            and value.get('target') == 'x86_64-unknown-linux-gnu'
            and value.get('profile') == 'release' and value.get('locked') is True
            and set(value.get('artifacts', {})) == {'synergy-node','synergy-keytool','synergy-genesis'}
            and value.get('dependency_sources') == dependencies,
            'prebuilt native source/profile/dependency binding mismatch')
    compiler = value.get('native_compiler', {})
    require(isinstance(compiler, dict) and compiler.get('host') == 'x86_64-unknown-linux-gnu'
            and all(isinstance(compiler.get(k), str) and compiler[k].strip() for k in ('rustc','cargo')),
            'native compiler identity required')
    claimed = glibc_version(value.get('glibc_requirement'))
    actual = glibc_version(required_glibc(paths))
    require(claimed + (0,)*(3-len(claimed)) >= actual + (0,)*(3-len(actual)),
            'glibc requirement understates native ELF symbols')
    return value


def build_replacement_recovery(output, expected_manifest_sha256):
    """Package the canonical non-destructive repair for one sealed master."""
    import io
    import tarfile
    old_bytes=(MASTER/'package.json').read_bytes()
    require(hashlib.sha256(old_bytes).hexdigest()==expected_manifest_sha256,
            'recovery requires the exact installed master manifest')
    old=json.loads(old_bytes)
    tool_root=Path(__file__).parent
    files={'lifecycle.py':(tool_root/'lifecycle.py').read_bytes()}
    for name in ('synergy_linux.py','apqe_layout.py'):
        contents=(MASTER/'tools'/name).read_bytes()
        require(hashlib.sha256(contents).hexdigest()==old['files']['tools/'+name],
                'sealed recovery dependency differs: '+name)
        files[name]=contents
    # The recovered installation still identifies the original release; this
    # tool-only package makes no claims about rebuilding any native artifact.
    files['recovery.json']=(json.dumps({
        'format':'synergy-finish-replacement-v1',
        'base_package_sha256':expected_manifest_sha256,
        'files':{name:hashlib.sha256(contents).hexdigest() for name,contents in files.items()},
    },sort_keys=True)+'\n').encode()
    with output.open('xb') as stream, tarfile.open(fileobj=stream,mode='w') as archive:
        for name,contents in sorted(files.items()):
            member=tarfile.TarInfo(name);member.size=len(contents);member.mode=0o600
            archive.addfile(member,io.BytesIO(contents))
    print(json.dumps({'recovery_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
                      'base_package_sha256':expected_manifest_sha256}))




R5_RELEASE = 'synergy-linux-389c509e47e55219'
R5_MANIFEST_SHA256 = '43eae3fdc42a2bff9e0ba2fa369d708fb60d14e90c6e18a6f344f5071c6cb23b'


def compose_existing_root_compatibility(original, output, expected_manifest):
    """Update only the canonical root validator around a pinned native release."""
    from synergy_linux import digest, verify_package
    original, output = Path(original), Path(output)
    require(re.fullmatch('[a-f0-9]{64}', expected_manifest) is not None,
            'exact base manifest SHA-256 required')
    require(original.is_absolute() and original.resolve() == original
            and digest(original/'package.json') == expected_manifest,
            'base package manifest pin mismatch')
    baseline = verify_package(original)
    require(output.is_absolute() and output.name == 'synergy'
            and not output.exists() and not output.is_symlink()
            and output.parent.is_dir() and output.parent.resolve() == output.parent
            and output.parent.stat().st_uid == os.geteuid()
            and output.parent.stat().st_mode & 0o777 == 0o700
            and not output.is_relative_to(original) and not original.is_relative_to(output),
            'fresh lowercase output under a private direct workspace required')
    member = 'tools/synergy_linux.py'
    require(member in baseline['files'], 'base lacks canonical root validator')
    tooling_path = Path(__file__).parent/'synergy_linux.py'
    tooling = tooling_path.read_bytes()
    tooling_pin = hashlib.sha256(tooling).hexdigest()
    manifest = dict(baseline)
    manifest['runtime_baseline'] = {
        'release_id': baseline['release_id'], 'manifest_sha256': expected_manifest,
        'source_sha256': baseline['source_sha256'],
        'immutable_files': {n:h for n,h in baseline['files'].items() if n != member},
    }
    manifest['files'] = dict(baseline['files'], **{member:tooling_pin})
    manifest['source_sha256'] = content_sha256({'baseline':expected_manifest, member:tooling_pin})
    manifest['release_id'] = 'synergy-linux-existing-root-' + manifest['source_sha256'][:16]
    manifest['acceptance_status'] = 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES'
    manifest['existing_root_compatibility'] = '/opt/Synergy'
    output.mkdir(mode=0o700)
    try:
        for directory in DIRECTORIES: (output/directory).mkdir(mode=0o700)
        for role in json.loads((original/'roles/roles.json').read_bytes())['roles']:
            require(re.fullmatch('[a-z_]+',role) is not None, 'invalid role name')
            (output/'roles'/role).mkdir(mode=0o700)
        for name, expected in manifest['files'].items():
            data = tooling if name == member else (original/name).read_bytes()
            require(hashlib.sha256(data).hexdigest() == expected, 'base changed during composition: '+name)
            path=output/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb') as stream: stream.write(data)
            path.chmod(0o700 if path.parent.name in ('bin','tools') else 0o600)
        (output/'package.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
        (output/'package.json').chmod(0o600)
        verify_package(output)
        require(digest(original/'package.json') == expected_manifest
                and tooling_path.read_bytes() == tooling, 'composition inputs changed')
    except BaseException:
        shutil.rmtree(output)
        raise
    return {'master':str(output),'release_id':manifest['release_id'],
            'package_sha256':digest(output/'package.json'),
            'runtime_release':baseline['release_id'],'qualified':False}


def compose_r5_controller(original, output):
    """New tooling release, preserving every authenticated R5 runtime byte."""
    from synergy_linux import digest, verify_package
    original, output = Path(original), Path(output)
    require(original.is_absolute() and original.resolve() == original,
            'direct original R5 directory required')
    require(digest(original/'package.json') == R5_MANIFEST_SHA256,
            'original R5 manifest pin mismatch')
    baseline = json.loads((original/'package.json').read_bytes())
    require(baseline.get('release_id') == R5_RELEASE, 'original R5 identity mismatch')
    # Read only inventoried software. Runtime/custody directories are never copied.
    baseline_bytes = {}
    for name, expected in baseline['files'].items():
        relative = Path(name)
        require(not relative.is_absolute() and '..' not in relative.parts,
                'unsafe R5 inventory path')
        target = original/relative
        require(target.resolve() == target and target.is_file(),
                'R5 member missing or linked')
        data = target.read_bytes()
        require(hashlib.sha256(data).hexdigest() == expected, 'R5 member digest mismatch: '+name)
        baseline_bytes[name] = data
    require(output.is_absolute() and output.name == 'synergy'
            and not output.exists() and not output.is_symlink()
            and output.parent.is_dir() and output.parent.resolve() == output.parent,
            'fresh direct candidate Synergy output required')
    require(not output.is_relative_to(original) and not original.is_relative_to(output),
            'candidate must not overlap original R5')
    tooling_names = TOOLS
    tooling = {'tools/'+name: (Path(__file__).parent/name).read_bytes() for name in tooling_names}
    # Freeze exact tooling bytes before creation. No rebuild of native binaries.
    files = dict(baseline_bytes)
    files.update(tooling)
    manifest = dict(baseline)
    manifest['runtime_baseline'] = {
        'release_id': R5_RELEASE, 'manifest_sha256': R5_MANIFEST_SHA256,
        'source_sha256': baseline['source_sha256'],
        'immutable_files': {name: expected for name, expected in baseline['files'].items()
                            if not name.startswith('tools/')},
    }
    manifest['files'] = {name: hashlib.sha256(data).hexdigest() for name,data in sorted(files.items())}
    manifest['source_sha256'] = content_sha256({'baseline':R5_MANIFEST_SHA256,
        'tooling':{name:hashlib.sha256(data).hexdigest() for name,data in sorted(tooling.items())}})
    manifest['release_id'] = 'synergy-linux-r5-controller-' + manifest['source_sha256'][:16]
    manifest['acceptance_status'] = 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES'
    manifest['controller_policy_version'] = 1
    output.mkdir(mode=0o700)
    try:
        for directory in DIRECTORIES:
            (output/directory).mkdir(mode=0o700)
        roles = json.loads(files['roles/roles.json'])['roles']
        for role in roles:
            require(re.fullmatch('[a-z_]+',role) is not None, 'invalid R5 role')
            (output/'roles'/role).mkdir(mode=0o700)
        for name,data in files.items():
            path = output/name
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o700 if name.startswith(('bin/','tools/')) else 0o600)
        (output/'package.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
        verify_package(output)
        require(all((Path(__file__).parent/name).read_bytes() == tooling['tools/'+name]
                    for name in tooling_names), 'tooling changed during composition')
        require(digest(original/'package.json') == R5_MANIFEST_SHA256,
                'R5 baseline changed during composition')
    except BaseException:
        shutil.rmtree(output)
        raise
    return {'master':str(output),'release_id':manifest['release_id'],
            'package_sha256':digest(output/'package.json'),'runtime_release':R5_RELEASE,
            'qualified':False}



def remove_generated_tree(path):
    # ExFAT unlinks the AppleDouble sidecar alongside its primary member.
    def onerror(function, member, error):
        if isinstance(error[1], FileNotFoundError) and Path(member).name.startswith('._'):
            return
        raise error[1]
    shutil.rmtree(path, onerror=onerror)


def recover_r5_promotion(candidate, candidate_pin, previous_pin, preserved):
    """Resume only a generated-package promotion with an authenticated archive."""
    from synergy_linux import digest, verify_package
    candidate, preserved = Path(candidate), Path(preserved)
    require(candidate.resolve() == candidate and preserved.resolve() == preserved
            and candidate.is_absolute() and preserved.is_absolute(), 'direct artifacts required')
    require(digest(candidate/'package.json') == candidate_pin
            and digest(preserved/'package.json') == previous_pin, 'promotion recovery pins differ')
    manifest = verify_package(candidate)
    previous = verify_package(preserved)
    require(manifest.get('runtime_baseline',{}).get('manifest_sha256') == R5_MANIFEST_SHA256
            and manifest.get('acceptance_status') == 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES',
            'R5 candidate required')
    roles = json.loads((preserved/'roles/roles.json').read_bytes())['roles']
    if MASTER.exists():
        require(MASTER.resolve() == MASTER, 'direct master required')
        check_master_inventory(MASTER, set(previous['files'])|set(manifest['files']), roles)
        from synergy_linux import VOLATILE
        for name in VOLATILE:
            path = MASTER/name
            require(not path.exists() or path.is_dir() and not list(path.iterdir()),
                    'runtime state in generated master; recovery refused')
        remove_generated_tree(MASTER)
    try:
        shutil.copytree(candidate,MASTER,ignore=shutil.ignore_patterns('._*','__pycache__'))
        verify_package(MASTER)
        require(digest(MASTER/'package.json') == candidate_pin, 'recovered master differs')
    except BaseException:
        if MASTER.exists(): remove_generated_tree(MASTER)
        shutil.copytree(preserved,MASTER)
        raise
    return {'master':str(MASTER),'release_id':manifest['release_id'],
            'package_sha256':candidate_pin,'preserved_previous':str(preserved),
            'production_qualified':False,'fleet_changed':False}


def promote_r5_controller(candidate, candidate_pin, current_pin, preserve):
    """Promote verified software only; preserve the later runtime, never host state."""
    from synergy_linux import digest, verify_package
    candidate, preserve = Path(candidate), Path(preserve)
    require(candidate.is_absolute() and candidate.resolve() == candidate,
            'direct qualified candidate required')
    require(digest(candidate/'package.json') == candidate_pin, 'candidate pin differs')
    require(MASTER.is_dir() and MASTER.resolve() == MASTER, 'direct canonical master required')
    manifest = verify_package(candidate)
    require(manifest.get('runtime_baseline', {}).get('manifest_sha256') == R5_MANIFEST_SHA256
            and manifest['runtime_baseline'].get('release_id') == R5_RELEASE
            and manifest.get('acceptance_status') == 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES',
            'R5 runtime candidate identity required')
    require(digest(MASTER/'package.json') == current_pin, 'current master pin differs')
    previous = verify_package(MASTER)
    roles = json.loads((MASTER/'roles/roles.json').read_bytes())['roles']
    check_master_inventory(MASTER, set(previous['files']), roles)
    require(preserve.is_absolute() and not preserve.exists() and not preserve.is_symlink()
            and preserve.parent.is_dir() and preserve.parent.resolve() == preserve.parent
            and not preserve.is_relative_to(MASTER) and not MASTER.is_relative_to(preserve),
            'fresh external previous-release artifact path required')
    require(not candidate.is_relative_to(MASTER) and not MASTER.is_relative_to(candidate),
            'candidate must not overlap master')
    # Authenticate the preserved artifact before replacing any generated bytes.
    shutil.copytree(MASTER, preserve, ignore=shutil.ignore_patterns('._*','__pycache__'))
    verify_package(preserve)
    require(digest(preserve/'package.json') == current_pin, 'preserved master differs')
    try:
        remove_generated_tree(MASTER)
        shutil.copytree(candidate, MASTER, ignore=shutil.ignore_patterns('._*','__pycache__'))
        verify_package(MASTER)
        require(digest(MASTER/'package.json') == candidate_pin, 'promoted master differs')
    except BaseException:
        if MASTER.exists():
            remove_generated_tree(MASTER)
        shutil.copytree(preserve, MASTER)
        raise
    return {'master':str(MASTER),'release_id':manifest['release_id'],
            'package_sha256':candidate_pin,'preserved_previous':str(preserve),
            'production_qualified':False,'fleet_changed':False}


def main():
    if sys.argv[1:2] == ['existing-root-compatibility']:
        p = argparse.ArgumentParser(description='Compose approved existing-root tooling without rebuilding native artifacts')
        p.add_argument('--base',type=Path,required=True)
        p.add_argument('--base-sha256',required=True)
        p.add_argument('--output',type=Path,required=True)
        args=p.parse_args(sys.argv[2:])
        print(json.dumps(compose_existing_root_compatibility(args.base,args.output,args.base_sha256),sort_keys=True))
        return
    global MASTER
    if sys.argv[1:2] == ['recover-master-promotion']:
        p = argparse.ArgumentParser(description='Recover interrupted generated master promotion from pinned artifacts')
        p.add_argument('command')
        p.add_argument('--candidate', type=Path, required=True)
        p.add_argument('--candidate-sha256', required=True)
        p.add_argument('--previous-sha256', required=True)
        p.add_argument('--preserved', type=Path, required=True)
        args = p.parse_args()
        print(json.dumps(recover_r5_promotion(args.candidate,args.candidate_sha256,args.previous_sha256,args.preserved)))
        return
    if sys.argv[1:2] == ['promote-r5-controller']:
        p = argparse.ArgumentParser(description='Promote pinned R5-runtime tooling candidate, preserving later runtime artifact')
        p.add_argument('command')
        p.add_argument('--candidate', type=Path, required=True)
        p.add_argument('--candidate-sha256', required=True)
        p.add_argument('--current-sha256', required=True)
        p.add_argument('--preserve-previous', type=Path, required=True)
        args = p.parse_args()
        print(json.dumps(promote_r5_controller(args.candidate,args.candidate_sha256,args.current_sha256,args.preserve_previous)))
        return
    if sys.argv[1:2] == ['r5-controller']:
        p = argparse.ArgumentParser(description='Compose new tooling around authenticated immutable R5 runtime')
        p.add_argument('command')
        p.add_argument('--original', type=Path, required=True)
        p.add_argument('--output', type=Path, required=True)
        args = p.parse_args()
        print(json.dumps(compose_r5_controller(args.original,args.output)))
        return
    if sys.argv[1:2]==['replacement-recovery']:
        p=argparse.ArgumentParser(description='Package the canonical non-destructive replacement repair')
        p.add_argument('command')
        p.add_argument('--output',type=Path,required=True)
        p.add_argument('--base-package-sha256',required=True)
        args=p.parse_args()
        build_replacement_recovery(args.output,args.base_package_sha256)
        return
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence', type=Path, required=True)
    p.add_argument('--netbird-binary', type=Path, required=True)
    p.add_argument('--netbird-sha256', required=True)
    p.add_argument('--apqe-binary', type=Path, required=True)
    p.add_argument('--apqe-binary-sha256', required=True)
    p.add_argument('--prebuilt-dir', type=Path)
    p.add_argument('--prebuilt-manifest', type=Path,
                   help='Exact source inventory and artifact pins from the native Linux build')
    p.add_argument('--apqe-provider-dir', type=Path, required=True)
    p.add_argument('--apqe-report-sha256', required=True)
    p.add_argument('--engineering-output', type=Path,
                   help='Build into a new lowercase synergy directory under an existing private engineering workspace')
    args = p.parse_args()
    if args.engineering_output is not None:
        output = args.engineering_output
        require(output.name == 'synergy' and output.is_absolute()
                and output.parent.resolve(strict=True) == output.parent
                and not output.exists() and not output.is_symlink()
                and output.parent.is_dir()
                and output.parent.stat().st_uid == os.geteuid()
                and output.parent.stat().st_mode & 0o777 == 0o700
                and SOURCE.parent not in output.parents and MASTER not in output.parents
                and output not in args.evidence.resolve().parents and output != args.evidence.resolve(),
                'fresh canonical Synergy output and separate evidence in a private workspace required')
        MASTER = output
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
    provider = args.apqe_provider_dir
    dependencies_before = dependency_sources(provenance)
    provider_files = verify_apqe_provider(provider, args.apqe_report_sha256, provenance)
    expected.update('lib/apqe/'+name for name in provider_files)
    check_master_inventory(MASTER, expected, roles)
    # The package is a generated deployment artifact. Its templates and role
    # inventory originate in this single version-controlled implementation.
    if args.engineering_output is not None:
        MASTER.mkdir(mode=0o700)
    for relative in DIRECTORIES:
        (MASTER / relative).mkdir(parents=True, exist_ok=True)
    (MASTER / 'lib/apqe').mkdir(parents=True, exist_ok=True)
    for name in provider_files:
        shutil.copyfile(provider/name, MASTER/'lib/apqe'/name)
    verify_copied_provider(MASTER/'lib/apqe', provider_files, provenance)
    for path in templates.rglob('*'):
        if path.is_file() and not path.name.startswith('._'):
            target = MASTER / path.relative_to(templates)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    from configuration_schema import generate
    (MASTER/'assets/node-config.schema.json').write_text(json.dumps(generate(SOURCE),indent=2,sort_keys=True)+'\n')
    (MASTER / 'roles/roles.json').write_text(json.dumps({'roles': roles, 'implemented': ['validator', 'rpc_gateway']}, indent=2) + '\n')
    env = dict(os.environ)
    toolchain = SOURCE / 'target/posy-linux-tools/bin'
    env['PATH'] = env['PATH'] + os.pathsep + str(toolchain)
    zig_python = Path(env.get('CARGO_ZIGBUILD_PYTHON_PATH', str(toolchain / 'python')))
    require(zig_python.is_file() and os.access(zig_python, os.X_OK),
            'explicit executable cargo-zigbuild Python required')
    env['CARGO_ZIGBUILD_PYTHON_PATH'] = str(zig_python)
    env['CARGO_INCREMENTAL'] = '0'
    require(bool(args.prebuilt_dir) == bool(args.prebuilt_manifest),
            'prebuilt directory and exact manifest must be supplied together')
    if not args.prebuilt_dir:
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
    output = args.prebuilt_dir or Path(env.get('CARGO_TARGET_DIR', SOURCE / 'target')) / 'x86_64-unknown-linux-gnu/release'
    prebuilt = None
    if args.prebuilt_manifest:
        prebuilt = json.loads(args.prebuilt_manifest.read_text())
        verify_prebuilt_manifest(prebuilt, source_sha256, dependencies_before,
                                 [output/name for name in ('synergy-node','synergy-keytool','synergy-genesis')])
    artifacts = {}
    for name in ('synergy-node', 'synergy-keytool', 'synergy-genesis'):
        sealed=provenance.seal_artifact(output/name)
        if prebuilt:
            require(sealed == prebuilt['artifacts'][name]['sealed']
                    and provenance.digest(output/name) == prebuilt['artifacts'][name]['sha256'],
                    'prebuilt artifact differs from independently recorded native build')
        shutil.copyfile(output / name, MASTER / 'bin' / name)
        require(provenance.seal_artifact(MASTER/'bin'/name)==sealed,
                'copied ELF differs from flushed build output: '+name)
        artifacts[name]=sealed
    sealed=provenance.seal_artifact(args.netbird_binary)
    require(provenance.digest(args.netbird_binary) == args.netbird_sha256, 'NetBird pin mismatch')
    shutil.copyfile(args.netbird_binary, MASTER / 'bin/netbird')
    require(provenance.seal_artifact(MASTER/'bin/netbird')==sealed,'copied NetBird differs from pinned artifact')
    artifacts['netbird']=sealed
    sealed=provenance.seal_artifact(args.apqe_binary)
    require(provenance.digest(args.apqe_binary) == args.apqe_binary_sha256,
            'independently built APQE CLI pin mismatch')
    shutil.copyfile(args.apqe_binary, MASTER/'bin/apqe')
    require(provenance.seal_artifact(MASTER/'bin/apqe')==sealed,
            'copied APQE CLI differs from pinned native artifact')
    artifacts['apqe']=sealed
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
                'conformance_policy_version': 2,
                'configuration_schema_version': 1,
                'storage_formats': native_storage_formats(),
                'runtime_dependencies': ['Linux x86_64', 'glibc >= 2.28', 'systemd', 'Python >= 3.9 with sqlite3',
                                         'iproute2', 'iputils-ping', 'kernel TUN/WireGuard'],
                'features': [], 'acceptance_status': 'CANDIDATE_REQUIRES_RECORDED_ACCEPTANCE_GATES'}
    manifest['apqe_provider'] = {'report_path':'lib/apqe/build-report.json',
                               'report_sha256':args.apqe_report_sha256,
                               'profile':'PQ-VSESSION-01-candidate-v1',
                               'production_qualified':False}
    manifest['dependency_sources'] = dependencies_before
    verify_copied_provider(MASTER/'lib/apqe', provider_files, provenance)
    require(dependency_sources(provenance) == dependencies_before, 'dependency sources changed while packaging')
    if prebuilt:
        manifest['native_build'] = prebuilt
        manifest['runtime_dependencies'][1] = prebuilt['glibc_requirement']
    (MASTER / 'package.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (args.evidence / 'package.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    subprocess.run([sys.executable, str(SOURCE/'tools/release/provenance.py'), 'inventory',
                    '--root',str(core),'--output',str(args.evidence/'source-after-package.json')],check=True)
    require(json.loads((args.evidence/'source-after-package.json').read_text())==before,
            'source changed while sealing package')
    require(dependency_sources(provenance) == dependencies_before, 'dependency sources changed after sealing package')
    verify_copied_provider(MASTER/'lib/apqe', provider_files, provenance)
    print(json.dumps({'master': str(MASTER), 'files': len(files),
                      'package_sha256': provenance.digest(MASTER / 'package.json')}))


if __name__ == '__main__':
    main()
