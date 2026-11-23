#!/usr/bin/env python3
"""Prepare the public artifact index and selection, or compose a managed Wallet package."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
from apqe_layout import (WALLET_RELEASE_PACKAGE_DIRECTORY, WALLET_RELEASE_PACKAGE_FILES,
                         WALLET_RELEASE_PUBLIC, _canonical_package_manifest,
                         require_frozen_tree, wallet_release_package)
from canary_rpc_relay import _unique_fields
from synergy_linux import digest, require, verify_package, write_new


def nonzero_digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) and value != '0'*64


def base_package(package, expected):
    require(nonzero_digest(expected), 'Independently supplied base package SHA-256 required')
    require_frozen_tree(package)
    path = package/'package.json'
    require(0 < path.stat().st_size <= 1024*1024 and digest(path) == expected,
            'Base package manifest differs from its independently supplied pin')
    manifest = verify_package(package)
    require(wallet_release_package(package, manifest) is None
            and path.read_bytes() == _canonical_package_manifest(manifest),
            'Exact canonical base package required')
    require('tools/runtime_probe.py' in manifest['files'], 'Base package lacks managed native preflight')
    binary = 'bin/synergy-node'
    report = 'lib/apqe/build-report.json'
    size = (package/binary).stat().st_size
    require(0 < size <= 512*1024*1024 and nonzero_digest(manifest['files'][binary])
            and nonzero_digest(manifest['files'][report])
            and manifest['apqe_provider']['report_sha256'] == manifest['files'][report],
            'Base package lacks its exact executable and provider report')
    entry = {'target': 'x86_64-unknown-linux-gnu', 'base_package_manifest_sha256': expected,
             'executable_size': size, 'executable_sha256': manifest['files'][binary],
             'apqe_report_sha256': manifest['files'][report]}
    return manifest, entry


def artifact_index(package, expected, chain_id, network_id, genesis_hash):
    require(0 < chain_id < 2**64 and re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,127}', network_id)
            and nonzero_digest(genesis_hash), 'Exact release chain, network and logical Genesis required')
    _, entry = base_package(package, expected)
    return json.dumps({'version': 1, 'chain_id': chain_id, 'network_id': network_id,
                       'genesis_hash': genesis_hash, 'platforms': [entry]}, separators=(',', ':')).encode()


def _public_inputs(package, release, inventory):
    require_frozen_tree(release)
    require(release != package and release not in package.parents and package not in release.parents,
            'Wallet release inputs must be separate from the exact base package')
    require({path.name for path in release.iterdir()} == set(inventory),
            'Exact public signed Wallet release inputs required')
    inputs = {}
    for name, maximum in inventory.items():
        path = release/name
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and 0 < metadata.st_size <= maximum, 'Unsafe signed Wallet release input')
        with path.open('rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == metadata.st_size, 'Wallet release input changed while reading')
        inputs[name] = raw
    return inputs


def _release_index(inputs, index_sha256, entry):
    index = inputs['wallet-dispatch-managed-artifacts.json']
    require(nonzero_digest(index_sha256) and hashlib.sha256(index).hexdigest() == index_sha256,
            'Managed Wallet release index differs from the approved digest')
    parsed = _document(index)
    platforms = parsed.get('platforms')
    require(type(parsed.get('version')) is int and parsed['version'] == 1
            and isinstance(platforms, list) and all(isinstance(platform, dict) for platform in platforms)
            and [platform for platform in platforms if platform.get('target') == entry['target']] == [entry],
            'Managed Wallet release index does not bind this base package')
    return parsed


def _document(raw):
    value = json.loads(raw, object_pairs_hook=_unique_fields)
    require(isinstance(value, dict), 'Wallet release input must be a JSON object')
    return value


def _signature(value):
    signature = value.get('signature')
    return (isinstance(signature, list) and len(signature) == 3309
            and all(type(byte) is int and 0 <= byte <= 255 for byte in signature)
            and any(signature))


def _matches_digest_array(value, expected):
    return (isinstance(value, list) and all(type(byte) is int for byte in value)
            and value == list(bytes.fromhex(expected)))


def prepare_selection(package, base_sha256, release, approved):
    """Prepare public package pins from reviewed attachments. Native preflight verifies signatures."""
    require(isinstance(approved, dict) and set(approved) == {
        'attachment_sha256', 'issuer_sha256', 'managed_release_manifest_sha256',
        'off_chain_approval_sha256', 'release_attestation_sha256',
    } and all(nonzero_digest(pin) for pin in approved.values()),
            'Complete independent Wallet release pins required')
    manifest, entry = base_package(package, base_sha256)
    inputs = _public_inputs(package, release, WALLET_RELEASE_PUBLIC)
    index = _release_index(inputs, approved['managed_release_manifest_sha256'], entry)
    attachment = inputs['wallet-dispatch-release.json']
    issuer = inputs['wallet-dispatch-release-issuer.pub']
    require(hashlib.sha256(attachment).hexdigest() == approved['attachment_sha256']
            and len(issuer) == 1952 and hashlib.sha256(issuer).hexdigest() == approved['issuer_sha256'],
            'Wallet dispatch attachment or issuer differs from its approved bytes')
    signed = _document(attachment)
    payload = signed.get('payload')
    require(isinstance(payload, dict) and isinstance(payload.get('policy'), dict),
            'Signed Wallet dispatch payload and policy required')
    policy = payload['policy']
    signer = payload.get('signer_key_id')
    network_id = index.get('network_id')
    require(signed.get('signature_algorithm') == 'ml_dsa65' and _signature(signed)
            and isinstance(signer, str) and re.fullmatch(r'[A-Za-z0-9_:/-]{1,128}', signer)
            and payload.get('version') == policy.get('version') == 1
            and type(index.get('chain_id')) is int and 0 < index['chain_id'] < 2**64
            and isinstance(network_id, str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{1,127}', network_id)
            and all(policy.get(key) == index.get(key) for key in ('chain_id', 'network_id', 'genesis_hash'))
            and nonzero_digest(index.get('genesis_hash'))
            and all(policy.get(key) == approved[key] for key in (
                'managed_release_manifest_sha256', 'off_chain_approval_sha256', 'release_attestation_sha256')),
            'Signed Wallet dispatch coordinates differ from the reviewed package and evidence')
    delegation = _document(inputs['wallet-dispatch-release-issuer-authorization.json'])
    require(delegation.get('version') == 1 and _signature(delegation)
            and delegation.get('issuer_key_id') == signer
            and delegation.get('genesis_hash') == index['genesis_hash']
            and all(delegation.get(key) == approved[key] for key in ('attachment_sha256', 'issuer_sha256')),
            'Wallet issuer delegation does not bind the reviewed attachment and issuer')
    qualification = _document(inputs['wallet-dispatch-ml-dsa-87-qualification.json'])
    artifact_pin = manifest['files'].get('lib/apqe/libaegismldsa87.so')
    verifier_pin = manifest['files'].get('lib/apqe/libaegismldsa65.so')
    proof_pins = policy.get('enrollment_proof_provider_artifacts')
    require(nonzero_digest(artifact_pin) and nonzero_digest(verifier_pin)
            and isinstance(proof_pins, list) and artifact_pin in proof_pins,
            'Signed Wallet dispatch does not select the packaged proof verifier')
    fields = qualification.get('qualification')
    require(_signature(qualification) and isinstance(fields, dict)
            and fields.get('version') == 1 and fields.get('target') == entry['target']
            and _matches_digest_array(fields.get('artifact_sha256'), artifact_pin)
            and _matches_digest_array(fields.get('report_sha256'), entry['apqe_report_sha256'])
            and _matches_digest_array(fields.get('release_attestation_sha256'), approved['release_attestation_sha256']),
            'Production verifier qualification differs from the reviewed release and packaged artifact')
    return {**approved, 'issuer_key_id': signer, 'release_verifier_artifact_sha256': verifier_pin}


def compose(package, expected, release, index_sha256, output):
    manifest, entry = base_package(package, expected)
    inputs = _public_inputs(package, release, WALLET_RELEASE_PACKAGE_FILES)
    _release_index(inputs, index_sha256, entry)
    require(output.is_absolute() and output.resolve() == output and output.parent.is_dir()
            and not output.exists() and output not in package.parents and package not in output.parents,
            'Use a new release output directory outside the base package')
    with tempfile.TemporaryDirectory(prefix='wallet-release-package-', dir=output.parent) as directory:
        candidate = Path(directory)/'candidate'
        shutil.copytree(package, candidate, ignore=shutil.ignore_patterns('._*'))
        target = candidate/WALLET_RELEASE_PACKAGE_DIRECTORY
        target.mkdir(mode=0o700)
        for name, raw in inputs.items():
            path = target/name
            with path.open('xb') as stream:
                path.chmod(0o600)
                stream.write(raw)
            manifest['files'][path.relative_to(candidate).as_posix()] = hashlib.sha256(raw).hexdigest()
        (candidate/'package.json').write_bytes(_canonical_package_manifest(manifest))
        require(verify_package(candidate) == manifest and wallet_release_package(candidate, manifest)[1] == expected,
                'Composed Wallet package changed its exact approved base')
        require(not output.exists() and not output.is_symlink(), 'Wallet release output already exists')
        candidate.rename(output)
    return {'release_id': manifest['release_id'], 'manifest_sha256': digest(output/'package.json'),
            'base_package_manifest_sha256': expected, 'managed_release_manifest_sha256': index_sha256,
            'managed_preflight_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    prepare = commands.add_parser('index')
    selection = commands.add_parser('selection')
    seal = commands.add_parser('compose')
    for command in (prepare, selection, seal):
        command.add_argument('--base', type=Path, required=True)
        command.add_argument('--base-sha256', required=True)
        command.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--chain-id', type=int, required=True)
    prepare.add_argument('--network-id', required=True)
    prepare.add_argument('--genesis-hash', required=True)
    for command in (selection, seal):
        command.add_argument('--release-inputs', type=Path, required=True)
        command.add_argument('--index-sha256', required=True)
    selection.add_argument('--attachment-sha256', required=True)
    selection.add_argument('--issuer-sha256', required=True)
    selection.add_argument('--off-chain-approval-sha256', required=True)
    selection.add_argument('--release-attestation-sha256', required=True)
    args = parser.parse_args()
    if args.operation == 'index':
        data = artifact_index(args.base, args.base_sha256, args.chain_id, args.network_id, args.genesis_hash)
        with args.output.open('xb') as output:
            output.write(data)
        print(json.dumps({'managed_release_manifest_sha256': hashlib.sha256(data).hexdigest()}))
    elif args.operation == 'selection':
        require(args.output == args.release_inputs/'selection.json',
                'Selection output must be the canonical selection.json in the public release inputs')
        approved = {'attachment_sha256': args.attachment_sha256, 'issuer_sha256': args.issuer_sha256,
                    'managed_release_manifest_sha256': args.index_sha256,
                    'off_chain_approval_sha256': args.off_chain_approval_sha256,
                    'release_attestation_sha256': args.release_attestation_sha256}
        value = prepare_selection(args.base, args.base_sha256, args.release_inputs, approved)
        write_new(args.output, value)
        print(json.dumps({'selection_sha256': digest(args.output), 'managed_preflight_verified': False}))
    else:
        print(json.dumps(compose(args.base, args.base_sha256, args.release_inputs, args.index_sha256, args.output)))


if __name__ == '__main__':
    main()
