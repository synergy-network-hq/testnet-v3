#!/usr/bin/env python3
"""Read original custody workbook and reuse existing consensus via memory only.

Library entrypoint recover_and_supply invokes an explicitly supplied owner
callback only AFTER canonical public binding and PQVM possession verification.
It creates no SSH process, key file, workbook copy, or workbook mutation. Never
send the callback's stdin to a terminal/log; the owner supplies the final host
keytool import-consensus-public-bound process via its existing SSH connection.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import resource
import subprocess

from openpyxl import load_workbook

WORKBOOK = Path('/Users/jhutzler/Desktop/node-machine-credentials.xlsx')
IDENTITIES = Path('/Volumes/PortableSSD/Synergy-Network/01-Core-Protocol/testnet-v3/testnet-v3-identity-files')
MAX_PUBLIC = 64 * 1024
MAX_DECRYPTED = 128 * 1024


class ProvisionError(Exception):
    """Fixed nonsecret error messages only; never attach original exceptions."""


def _rows(workbook, sheet):
    if sheet not in workbook.sheetnames:
        raise ProvisionError('required custody worksheet missing')
    rows = workbook[sheet].iter_rows(values_only=True)
    headers = next(rows)
    mapping = {}
    for index, value in enumerate(headers):
        if value:
            if value in mapping:
                raise ProvisionError('duplicate custody column header')
            mapping[value] = index
    return mapping, rows


def _cell(row, mapping, name):
    if name not in mapping:
        raise ProvisionError('required exact custody column missing')
    value = row[mapping[name]]
    if value is None:
        return ''
    if not isinstance(value, str):
        raise ProvisionError('custody field is not text')
    return value


def custody_for_validator(number):
    if number not in range(2, 7):
        raise ProvisionError('only initial validators 2 through 6 supported')
    validator = f'validator-{number:02}'
    allocation = f'VNS-A{number + 1:02}'
    directory = IDENTITIES / f'{allocation}_{validator}'
    public = directory / 'identity.pub.json'
    encrypted = directory / 'identity.enc.json'
    workbook = load_workbook(WORKBOOK, read_only=True, data_only=True)
    try:
        mapping, rows = _rows(workbook, 'Testnet-v3 Identities')
        matches = [row for row in rows if _cell(row, mapping, 'Identity ID').strip() == allocation
                   and _cell(row, mapping, 'Alias').strip() == validator]
        if len(matches) != 1:
            raise ProvisionError('canonical validator custody row missing or ambiguous')
        row = matches[0]
        for name, expected in [('Public Identity File', public), ('Encrypted Key / Policy File', encrypted)]:
            if Path(_cell(row, mapping, name)) != expected:
                raise ProvisionError('workbook custody path differs from canonical validator')
        passphrase = _cell(row, mapping, 'Encryption Passphrase')
        mapping, rows = _rows(workbook, 'Validator Passphrases')
        matches = [row for row in rows if _cell(row, mapping, 'Validator ID').strip() == validator
                   and _cell(row, mapping, 'Allocation ID').strip() == allocation]
        if len(matches) > 1:
            raise ProvisionError('validator passphrase row ambiguous')
        other = _cell(matches[0], mapping, 'Custody Passphrase') if matches else ''
        candidates = []
        for source, value in [('Testnet-v3 Identities!Encryption Passphrase', passphrase),
                              ('Validator Passphrases!Custody Passphrase', other)]:
            if value and not any(hmac.compare_digest(value.encode(), existing.encode()) for _, existing in candidates):
                candidates.append((source, value))
        if not candidates:
            raise ProvisionError('canonical encrypted identity passphrase missing')
        return public, encrypted, candidates
    finally:
        workbook.close()


def _pinned_binary(path, expected_sha256):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise ProvisionError('explicit pinned regular binary required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        raise ProvisionError('approved binary digest mismatch')
    return str(path)


def _lower_hex(value, length):
    if not isinstance(value, str) or not re.fullmatch(f'[0-9a-f]{{{length * 2}}}', value):
        raise ProvisionError('custody key encoding or size is invalid')
    return bytearray.fromhex(value)


def recover_and_supply(number, engine, engine_sha256, keytool, keytool_sha256, supply):
    """Owner callback receives (public_path, address, key_id, raw_secret).

    raw_secret is valid only during callback. No secret is returned or logged.
    Return value is only the successful exact workbook column label.
    Verification command is local native keytool; import is final-host keytool.
    Python immutable copies cannot guarantee zeroization; run this in a short
    lived owner process, disable core dumps, and avoid process tracing.
    """
    # Core dumps must not persist decrypted process memory.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    engine = _pinned_binary(engine, engine_sha256)
    keytool = _pinned_binary(keytool, keytool_sha256)
    public_path, encrypted_path, candidates = custody_for_validator(number)
    secret = bytearray()
    recovered = bytearray()
    try:
        if public_path.is_symlink() or public_path.stat().st_size > MAX_PUBLIC:
            raise ProvisionError('public identity source must be bounded and canonical')
        if encrypted_path.is_symlink() or not encrypted_path.is_file() or encrypted_path.stat().st_size > 1024 * 1024:
            raise ProvisionError('encrypted custody must be bounded canonical regular file')
        public = json.loads(public_path.read_bytes())
        address = public['address']
        key_id = f'val{number}-posy-consensus-v1'
        for source, passphrase in candidates:
            environment = os.environ.copy()
            environment['SYNERGY_DECRYPT_PASSPHRASE'] = passphrase
            result = subprocess.run([engine, 'decrypt', str(encrypted_path), '--stdout'],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=environment, timeout=60, check=False)
            environment.pop('SYNERGY_DECRYPT_PASSPHRASE', None)
            if result.returncode:
                continue
            if len(result.stdout) > MAX_DECRYPTED:
                raise ProvisionError('decrypted identity exceeds custody bound')
            recovered.extend(result.stdout)
            document = json.loads(recovered)
            if (document.get('schema_version') != 'synergy-validator-private-identity-v3'
                or document.get('binary_encoding') != 'lowercase-hex'
                or document.get('address') != address):
                raise ProvisionError('decrypted identity schema or canonical address mismatch')
            entries = [entry for entry in document.get('keys', []) if entry.get('role') == 'consensus']
            if len(entries) != 1 or entries[0].get('algorithm') != 'ML-DSA-65':
                raise ProvisionError('exact existing consensus role missing')
            secret.extend(_lower_hex(entries[0].get('private_key'), 4032))
            verified = subprocess.run([keytool, 'verify-consensus-public-bound', address, key_id, str(public_path)],
                                      input=secret, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      timeout=60, check=False)
            if verified.returncode:
                raise ProvisionError('existing consensus possession verification failed')
            supply(public_path, address, key_id, secret)
            return source
        raise ProvisionError('no workbook custody passphrase decrypts canonical identity')
    except ProvisionError:
        raise
    except Exception:
        raise ProvisionError('existing consensus provisioning failed') from None
    finally:
        secret[:] = b'\x00' * len(secret)
        recovered[:] = b'\x00' * len(recovered)
        candidates.clear()
        passphrase = None
