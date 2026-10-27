#!/usr/bin/env python3
"""Native, offline cross-network acceptance. Never invokes start, VPN, or systemd.

Generate public fixtures with disposable local signing custody, then replay the
same public suite against Linux binaries on the authorized machine. Historical
validator public keys are fixtures only; no validator private key is read.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def run(binaries, name, *args, succeeds=True):
    result = subprocess.run([str(binaries / name), *map(str, args)], capture_output=True, timeout=30)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(f'{name} {args[0]} unexpected exit {result.returncode}: {result.stderr.decode()[:600]}')
    return result.stdout.decode(), result.stderr.decode()


def generate(binaries, source, output):
    output.mkdir(mode=0o700)
    public_input = json.loads((source / 'fresh-genesis-input.json').read_text())
    template = json.loads((source / 'val2.json').read_text())
    # Temporary signing keys exist only in the local OS temporary directory.
    with tempfile.TemporaryDirectory(prefix='synergy-network-test-') as temporary:
        custody = Path(temporary).resolve()
        key_id = 'cross-network-fixture-authority'
        validator_address = public_input['validators'][0]['validator_id'] if 'validator_id' in public_input['validators'][0] else None
        if validator_address is None:
            validator_address = json.loads((source / 'genesis.unsigned.json').read_text())['validators'][0]['record']['validator_id']
        run(binaries, 'synergy-keytool', 'generate-consensus', validator_address, key_id, custody)
        public = custody / f'{key_id}.public.key'
        secret = custody / f'{key_id}.secret.key'
        (output / 'trust.pub').write_bytes(public.read_bytes())
        run(binaries, 'synergy-keytool', 'generate-consensus', validator_address, 'wrong-trust', custody)
        (output / 'wrong-trust.pub').write_bytes((custody / 'wrong-trust.public.key').read_bytes())
        cases = [(1266, 'testnet-incarnation-a'), (9001, 'mainnet-beta-fixture'),
                 (9002, 'mainnet-fixture'), (1266, 'testnet-incarnation-b')]
        for index, (chain_id, network_id) in enumerate(cases):
            case = output / f'network-{index}'
            case.mkdir()
            unsigned = copy.deepcopy(public_input)
            unsigned['authority_trust_key_id'] = key_id
            for part in [unsigned['authority'], unsigned['network']]:
                part['chain_id'] = chain_id
                part['network_id'] = network_id
            input_path = custody / f'input-{index}.json'
            save(input_path, unsigned)
            genesis_unsigned = custody / f'genesis-{index}.json'
            authority_unsigned = custody / f'authority-{index}.json'
            run(binaries, 'synergy-keytool', 'prepare-fresh-genesis', input_path, genesis_unsigned, authority_unsigned)
            run(binaries, 'synergy-genesis', 'sign', genesis_unsigned, key_id, secret, case / 'genesis.json')
            run(binaries, 'synergy-keytool', 'sign-authority', authority_unsigned, key_id, secret, public, case / 'authority.json')
            genesis = json.loads((case / 'genesis.json').read_text())
            save(case / 'manifest.json', {'chain_id': chain_id, 'network_id': network_id,
                'genesis_hash': genesis['genesis_hash'], 'protocol_version': genesis['unsigned']['network']['protocol_version'],
                'manifest_hash': hashlib.sha256((case / 'genesis.json').read_bytes()).hexdigest()})
        # Freeze an explicit historical V1 fixture for offline verification only.
        unsigned['genesis_format_version'] = 1
        input_path = custody / 'legacy-input.json'
        genesis_unsigned = custody / 'legacy-genesis-unsigned.json'
        authority_unsigned = custody / 'legacy-authority-unsigned.json'
        save(input_path, unsigned)
        run(binaries, 'synergy-keytool', 'prepare-fresh-genesis', input_path, genesis_unsigned, authority_unsigned)
        run(binaries, 'synergy-genesis', 'sign', genesis_unsigned, key_id, secret, output / 'legacy-genesis.json')
        run(binaries, 'synergy-keytool', 'sign-authority', authority_unsigned, key_id, secret, public, output / 'legacy-authority.json')
        # Contains public inputs and path conventions only. No private custody.
        save(output / 'configuration-template.json', template)


def test(binaries, fixtures, evidence):
    evidence.mkdir(mode=0o700)
    results = []
    template = json.loads((fixtures / 'configuration-template.json').read_text())
    def record(case, check, action):
        action()
        results.append({'network': case, 'check': check, 'passed': True})
    for case in sorted(fixtures.glob('network-*')):
        selected = json.loads((case / 'manifest.json').read_text())
        root = evidence / case.name
        root.mkdir()
        config = copy.deepcopy(template)
        config.update(chain_id=selected['chain_id'], network_id=selected['network_id'],
            genesis_path=str(case / 'genesis.json'), manifest_path=str(case / 'manifest.json'))
        config['consensus']['authority_binding'] = str(case / 'authority.json')
        config['consensus']['authority_trust_key_path'] = str(fixtures / 'trust.pub')
        config['storage']['data_directory'] = str(root / 'data')
        config['vpn']['transport_context'] = {'network': selected['network_id'], 'registry_id': 'fixture-registry',
            'release_id': 'fixture-release', 'protocol_version': selected['protocol_version']}
        path = root / 'node.json'
        save(path, config)
        record(case.name, 'signed-genesis-and-authority', lambda: run(binaries, 'synergy-genesis', 'verify-binding',
            case / 'genesis.json', fixtures / 'trust.pub', case / 'authority.json'))
        record(case.name, 'authenticated-native-preflight', lambda: run(binaries, 'synergy-node', 'preflight', '--config', path))
        record(case.name, 'fresh-native-storage-initialization', lambda: run(binaries, 'synergy-node', 'init',
            '--node-name', case.name, '--role-name', 'validator', '--config', path, '--data-directory', root / 'data'))
        record(case.name, 'existing-storage-refused', lambda: run(binaries, 'synergy-node', 'init',
            '--node-name', case.name, '--role-name', 'validator', '--config', path, '--data-directory', root / 'data', succeeds=False))
        bad_manifest = copy.deepcopy(selected)
        bad_manifest['genesis_hash'] = '00' * 32
        save(root / 'wrong-genesis-manifest.json', bad_manifest)
        bad_signature = json.loads((case / 'genesis.json').read_text())
        # Corrupt signed content without changing the embedded digest/signature.
        bad_signature['unsigned']['network']['network_id'] += '-tampered'
        save(root / 'tampered-genesis.json', bad_signature)
        # Every rejection is read-only and uses the same executable/config schema.
        for label, mutate in [
            ('wrong-genesis-hash', lambda value: value.update(manifest_path=str(root / 'wrong-genesis-manifest.json'))),
            ('tampered-genesis-signature', lambda value: value.update(genesis_path=str(root / 'tampered-genesis.json'))),
            ('historical-genesis-runtime-refused', lambda value: value.update(genesis_path=str(fixtures / 'legacy-genesis.json'))),
            ('wrong-chain', lambda value: value.update(chain_id=selected['chain_id'] + 1)),
            ('wrong-network', lambda value: value.update(network_id='other-network')),
            ('wrong-trust', lambda value: value['consensus'].update(authority_trust_key_path=str(fixtures / 'wrong-trust.pub'))),
            ('missing-genesis', lambda value: value.pop('genesis_path')),
            ('wrong-transport-protocol', lambda value: value['vpn']['transport_context'].update(protocol_version='other-protocol')),
            ('other-selected-genesis', lambda value: value.update(genesis_path=str(fixtures / ('network-3' if case.name != 'network-3' else 'network-0') / 'genesis.json'))),
            ('wrong-manifest', lambda value: value.update(manifest_path=str(fixtures / ('network-1' if case.name != 'network-1' else 'network-0') / 'manifest.json'))),
            ('wrong-authority', lambda value: value['consensus'].update(authority_binding=str(fixtures / ('network-1' if case.name != 'network-1' else 'network-0') / 'authority.json'))),
        ]:
            bad = copy.deepcopy(config)
            mutate(bad)
            bad_path = root / f'{label}.json'
            save(bad_path, bad)
            record(case.name, label, lambda: run(binaries, 'synergy-node', 'preflight', '--config', bad_path, succeeds=False))
    record('legacy', 'historical-v1-signature-and-authority-preserved', lambda: run(binaries, 'synergy-genesis', 'verify-binding',
        fixtures / 'legacy-genesis.json', fixtures / 'trust.pub', fixtures / 'legacy-authority.json'))
    report = {'format': 'synergy-cross-network-native-v1', 'checks': results,
        'passed': len(results), 'failed': 0, 'posy_started': False,
        'binary_sha256': {name: hashlib.sha256((binaries / name).read_bytes()).hexdigest()
            for name in ('synergy-node', 'synergy-keytool', 'synergy-genesis')},
        'scope': 'offline authentication and fresh disposable storage, not finality or fleet readiness'}
    save(evidence / 'results.json', report)
    print(json.dumps({'passed': len(results), 'posy_started': False, 'report': str(evidence / 'results.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--generate-from', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if args.generate_from:
        generate(args.bin_dir.resolve(), args.generate_from.resolve(), args.fixtures.resolve())
    test(args.bin_dir.resolve(), args.fixtures.resolve(), args.evidence.resolve())
