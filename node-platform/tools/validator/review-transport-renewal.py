#!/usr/bin/env python3
"""Compare two exact public transport artifact pairs before native verification."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import time

REGISTRY = 'transport-registry.json'
ADMISSION = 'rpc-gateway-admission.json'
ROOT = 'transport-root.pub'
LIMIT = 256 * 1024
LEASE = {'generation', 'valid_from_unix', 'expires_at_unix'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    require(not any(item.is_symlink() for item in (path, *path.parents)),
            f'symlink input refused: {path.name}')
    require(stat.S_ISREG(path.stat().st_mode), f'regular input required: {path.name}')
    with path.open('rb') as stream:
        payload = stream.read(LIMIT + 1)
    require(0 < len(payload) <= LIMIT, f'input size invalid: {path.name}')
    return payload


def unique_object(items):
    result = dict(items)
    require(len(items) == len(result), 'duplicate JSON field')
    return result


def reject_constant(token):
    raise ValueError(f'nonstandard JSON constant: {token}')


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)


def load_pair(directory, pins, scope):
    require(set(pins) == {REGISTRY, ADMISSION}, 'exact registry and admission pins required')
    payloads = []
    for name in (REGISTRY, ADMISSION):
        raw = read(directory / name)
        require(sha(raw) == pins[name], f'{name} differs from its exact pin')
        artifact = decode(raw)
        require(isinstance(artifact, dict) and set(artifact) == {'payload', 'signature'}
                and isinstance(artifact['payload'], dict)
                and isinstance(artifact['signature'], list) and artifact['signature']
                and all(type(byte) is int and 0 <= byte <= 255 for byte in artifact['signature']),
                f'{name} signed envelope missing')
        payload = artifact['payload']
        require(all(key in payload and type(payload[key]) is type(value)
                    and payload[key] == value for key, value in scope.items()),
                f'{name} differs from selected network scope')
        require(all(type(payload.get(key)) is int for key in LEASE)
                and 0 < payload['generation'] < 2**64
                and 0 <= payload['valid_from_unix'] < payload['expires_at_unix'] < 2**64,
                f'{name} has an invalid lease window')
        payloads.append(payload)
    registry, admission = payloads
    require(admission.get('validator_registry_sha256') == pins[REGISTRY]
            and type(registry.get('epoch')) is type(admission.get('epoch')) is int
            and 0 < registry['epoch'] == admission['epoch']
            and admission['generation'] == registry['generation']
            and admission['expires_at_unix'] <= registry['expires_at_unix'],
            'gateway admission does not bind the exact registry and lease')
    return registry, admission


def preserved(payload, mutable):
    # JSON encoding preserves distinctions such as false versus 0.
    return json.dumps({k: v for k, v in payload.items() if k not in mutable}, sort_keys=True)


def review(base, candidate, expected, now):
    scope = {key: expected[key] for key in
             ('chain_id', 'network_id', 'genesis_artifact_sha256', 'authority_binding_sha256')}
    require(type(scope['chain_id']) is int and scope['chain_id'] > 0
            and isinstance(scope['network_id'], str) and bool(scope['network_id']),
            'a selected network is required')
    for key in ('genesis_artifact_sha256', 'authority_binding_sha256', 'issuer_root_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', expected[key]), f'exact {key} required')
    roots = [read(directory / ROOT) for directory in (base, candidate)]
    require(len(roots[0]) == 2592 and roots[0] == roots[1]
            and sha(roots[0]) == expected['issuer_root_sha256'],
            'renewal must preserve the selected issuer root')
    old = load_pair(base, expected['installed'], scope)
    new = load_pair(candidate, expected['candidate'], scope)
    for before, after, mutable in zip(old, new, (LEASE, LEASE | {'validator_registry_sha256'})):
        require(preserved(before, mutable) == preserved(after, mutable),
                'renewal changes protected payload fields')
        require(after['generation'] == before['generation'] + 1,
                'renewal must advance exactly one generation')
        require(before['valid_from_unix'] <= now < before['expires_at_unix']
                and before['valid_from_unix'] <= after['valid_from_unix'] <= now
                and before['expires_at_unix'] < after['expires_at_unix'],
                'renewal must extend the current active lease with overlap')
    return {'chain_id': scope['chain_id'], 'network_id': scope['network_id'],
            'from_generation': old[0]['generation'], 'to_generation': new[0]['generation'],
            'candidate_pins': expected['candidate'],
            'registry_expires_at_unix': new[0]['expires_at_unix'],
            'admission_expires_at_unix': new[1]['expires_at_unix'],
            'native_signatures_verified': False, 'activation_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('installed', 'candidate', 'expectations'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        expected = decode(read(args.expectations.absolute()))
        print(json.dumps(review(args.installed.absolute(), args.candidate.absolute(),
                                expected, int(time.time())), sort_keys=True))
    except (TypeError, KeyError, OSError, ValueError) as error:
        parser.exit(1, f'Transport renewal review refused: {error}\n')


if __name__ == '__main__':
    main()
