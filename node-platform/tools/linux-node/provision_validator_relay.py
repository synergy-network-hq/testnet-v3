#!/usr/bin/env python3
"""Provision the approved Val2 Canary relay without registering or starting it."""
import argparse
import contextlib
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
from canary_rpc_relay import CONFIG, configuration
from lifecycle import (RELAY_UNIT, REPLACEMENT_INTENT, UPGRADE_INTENT, _attributed_units,
                       _lifecycle_lock, _reject_installation_mounts, _replace_bytes,
                       _require_operator, _sealed_receipt, _sync_directory)
from rotate_transport import NETWORK, checked_read, json_bytes, sha
from synergy_linux import native, require, safe_root
from vpn import status

ADMISSION = 'network/rpc-gateway-admission.json'
REGISTRY = 'network/transport-registry.json'
LIMIT = 128 * 1024


def pinned(path, limit, digest):
    raw = checked_read(path, limit)
    require(re.fullmatch(r'[0-9a-f]{64}', digest) and sha(raw) == digest, 'independent input pin mismatch')
    return raw


@contextlib.contextmanager
def operator_lock(root):
    fd = os.open(root/'evidence', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def live_rpc(config, registry):
    address, separator, port = config['rpc']['listen_address'].rpartition(':')
    require(separator and ipaddress.ip_address(address.strip('[]')).is_loopback
            and config['rpc']['enabled'] is True, 'canonical validator RPC must be loopback')
    client = http.client.HTTPConnection(address.strip('[]'), int(port), timeout=3)
    try:
        client.request('POST','/',b'{"jsonrpc":"2.0","method":"synergy_chainTelemetry","params":{},"id":1}',
                       {'Content-Type':'application/json'})
        response = client.getresponse()
        raw = response.read(LIMIT+1)
        require(response.status == 200 and len(raw) <= LIMIT, 'bounded live validator telemetry required')
        reply = json.loads(raw)
        value = reply['result']
        require(reply.get('jsonrpc') == '2.0' and reply.get('id') == 1
                and value.get('chain_id') == 99999 and value.get('network_identity') == NETWORK
                and value.get('epoch') == registry['epoch']
                and type(value.get('finalized_height')) is int and value['finalized_height'] > 0,
                'live validator is not the selected finalized Canary')
    finally:
        client.close()


def validate(root, receipt, spec, admission):
    require(receipt.get('role') == 'validator' and receipt.get('node_name') == 'validator-02'
            and receipt.get('chain_id') == 99999 and receipt.get('network_id') == NETWORK,
            'exact commissioned Canary Val2 required')
    require(not any((root/name).exists() or (root/name).is_symlink() for name in (UPGRADE_INTENT,REPLACEMENT_INTENT)),
            'finish installed lifecycle intent first')
    _reject_installation_mounts(root)
    result = configuration(root,spec)
    role = result['role']
    require(role['kind'] == 'validator' and result['listen_address'].endswith(':8551'),
            'Val2 relay must use the canonical validator TCP 8551 listener')
    listen_ip = ipaddress.ip_address(result['listen_address'].rpartition(':')[0].strip('[]'))
    identity = json.loads(checked_read(root/'keys/apqe/validator.pub.json',LIMIT,True))
    require(identity['node_address'] == role['validator_address'], 'spec does not name installed validator')
    config = json.loads(checked_read(root/'config/node.json',LIMIT,True))
    startup = json.loads(checked_read(root/'config/start-authorized.json',LIMIT,True))
    require(config.get('node_name') == receipt['node_name'] and config.get('chain_id') == 99999
            and config.get('network_id') == NETWORK and config.get('role') == 'validator'
            and config['apqe_transport']['registry_path'] == str(root/REGISTRY),
            'canonical live validator config differs')
    raw_registry = checked_read(root/REGISTRY,LIMIT,True)
    registry_sha = sha(raw_registry)
    registry = json.loads(raw_registry)['payload']
    payload = json.loads(admission)['payload']
    require(startup['public_file_sha256']['transport-registry.json'] == registry_sha
            and payload['validator_registry_sha256'] == registry_sha
            and payload['generation'] == registry['generation']
            and payload['epoch'] == registry['epoch']
            and payload['chain_id'] == registry['chain_id'] == 99999
            and payload['network_id'] == registry['network_id'] == NETWORK,
            'admission must bind exact currently installed authorized registry')
    entries = [v for v in registry['validators'] if v['node_address'] == role['validator_address'] and v['revoked'] is False]
    require(len(entries) == 1 and ipaddress.ip_address(entries[0]['dial_address'].rpartition(':')[0].strip('[]')) == listen_ip,
            'listener differs from signed Val2 overlay endpoint')
    units = _attributed_units(root)
    for unit in ('synergy-node.service','synergy-vpn.service'):
        state = units.get(unit,{})
        require(state.get('ActiveState') == 'active' and int(state.get('MainPID') or 0) > 1,
                'live attributed validator and VPN required')
    require(ipaddress.ip_interface(status(root)['netbirdIp']).ip == listen_ip,
            'live Val2 VPN address differs from signed listener')
    live_rpc(config,registry)
    return result


def install(root, spec_path, spec_sha, admission_path, admission_sha, package_sha):
    _require_operator()
    for path in (spec_path,admission_path):
        require(root not in (path,*path.parents), 'external provisioning input required')
    spec_raw = pinned(spec_path,8192,spec_sha)
    admission = pinned(admission_path,LIMIT,admission_sha)
    spec = json.loads(spec_raw)
    with operator_lock(root), tempfile.TemporaryDirectory(prefix='synergy-validator-relay-') as folder:
        stage = Path(folder)
        local_spec = stage/'spec.json';local_spec.write_bytes(spec_raw)
        with _lifecycle_lock(root):
            receipt,_ = _sealed_receipt(root)
            require(re.fullmatch(r'[0-9a-f]{64}',package_sha) and receipt.get('package_sha256') == package_sha,
                    'installed release differs from independent package pin')
            result = validate(root,receipt,spec,admission)
            admission_file, config_file = root/ADMISSION, root/CONFIG
            already = config_file.exists() or config_file.is_symlink()
            admitted = admission_file.exists() or admission_file.is_symlink()
            require(not admitted or checked_read(admission_file,LIMIT,True) == admission,
                    'existing admission differs; use explicit rotation')
            if already:
                require(admitted and json.loads(checked_read(config_file,8192,True)) == result,
                        'existing relay differs; refusing overwrite')
            else:
                require(RELAY_UNIT not in _attributed_units(root), 'relay already registered without config')
                staged_admission = stage/'admission.json';staged_admission.write_bytes(admission)
                staged_config = stage/'relay.json'
                staged_config.write_bytes(json_bytes(dict(result,admission_path=str(staged_admission))))
                native([root/'bin/synergy-node','canary-rpc-relay','check',staged_config])
                pending = config_file.with_name('.canary-rpc-relay.pending')
                if pending.exists() or pending.is_symlink():
                    require(json.loads(checked_read(pending,8192,True)) == result,
                            'foreign pending relay configuration')
                    pending.unlink();_sync_directory(pending.parent)
                if not admitted:
                    _replace_bytes(root,admission_file,admission,0o600,admission_sha)
        if not already:
            # The sealed configure command acquires its own lifecycle lock.
            native([sys.executable,'-B',root/'tools/canary_rpc_relay.py','configure',
                    '--root',root,'--spec',local_spec])
        with _lifecycle_lock(root):
            require(checked_read(admission_file,LIMIT,True) == admission
                    and json.loads(checked_read(config_file,8192,True)) == result,
                    'installed relay provisioning differs')
            native([root/'bin/synergy-node','canary-rpc-relay','check',config_file])
    return {'configured':True,'already_configured':already,'native_preflight_verified':True,
            'relay_registered':False,'relay_started':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('root','spec','spec-sha256','admission','admission-sha256','package-sha256'):
        p.add_argument('--'+key,required=True)
    a=p.parse_args()
    print(json.dumps(install(safe_root(a.root),Path(a.spec).absolute(),a.spec_sha256,
                      Path(a.admission).absolute(),a.admission_sha256,a.package_sha256),sort_keys=True))

if __name__=='__main__':
    try:
        main()
    except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException) as error:
        raise SystemExit(f'Validator relay provisioning refused: {error}') from None
