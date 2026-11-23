#!/usr/bin/env python3
"""Prepare the public artifact index or compose a signed managed Wallet package."""
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
                         _canonical_package_manifest, require_frozen_tree, wallet_release_package)
from synergy_linux import digest, require, verify_package


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


def compose(package, expected, release, index_sha256, output):
    require(nonzero_digest(index_sha256), 'Independently supplied signed artifact index SHA-256 required')
    manifest, entry = base_package(package, expected)
    require_frozen_tree(release)
    require({path.name for path in release.iterdir()} == set(WALLET_RELEASE_PACKAGE_FILES),
            'Exact public signed Wallet release inputs required')
    inputs = {}
    for name, maximum in WALLET_RELEASE_PACKAGE_FILES.items():
        path = release/name
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and 0 < metadata.st_size <= maximum, 'Unsafe signed Wallet release input')
        with path.open('rb') as stream:
            raw = stream.read(maximum + 1)
        require(len(raw) == metadata.st_size, 'Wallet release input changed while reading')
        inputs[name] = raw
    index = inputs['wallet-dispatch-managed-artifacts.json']
    require(hashlib.sha256(index).hexdigest() == index_sha256,
            'Managed Wallet release index differs from the approved digest')
    parsed = json.loads(index)
    require(parsed.get('version') == 1 and len([platform for platform in parsed.get('platforms', [])
               if platform.get('target') == entry['target'] and platform == entry]) == 1,
            'Managed Wallet release index does not bind this base package')
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
    seal = commands.add_parser('compose')
    for command in (prepare, seal):
        command.add_argument('--base', type=Path, required=True)
        command.add_argument('--base-sha256', required=True)
        command.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--chain-id', type=int, required=True)
    prepare.add_argument('--network-id', required=True)
    prepare.add_argument('--genesis-hash', required=True)
    seal.add_argument('--release-inputs', type=Path, required=True)
    seal.add_argument('--index-sha256', required=True)
    args = parser.parse_args()
    if args.operation == 'index':
        data = artifact_index(args.base, args.base_sha256, args.chain_id, args.network_id, args.genesis_hash)
        with args.output.open('xb') as output:
            output.write(data)
        print(json.dumps({'managed_release_manifest_sha256': hashlib.sha256(data).hexdigest()}))
    else:
        print(json.dumps(compose(args.base, args.base_sha256, args.release_inputs, args.index_sha256, args.output)))


if __name__ == '__main__':
    main()
