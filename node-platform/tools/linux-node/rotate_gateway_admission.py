#!/usr/bin/env python3
"""Rotate one stopped canonical Canary gateway using an independently pinned plan."""
import argparse
import json
from pathlib import Path
import re
import sys
import tempfile

sys.dont_write_bytecode = True
from lifecycle import (RELAY_UNIT, UPGRADE_INTENT, _attributed_units, _lifecycle_lock,
                       _reject_installation_mounts, _replace_bytes, _require_operator,
                       _sealed_receipt, _sync_directory)
from rotate_transport import checked_read, json_bytes, sha
from synergy_linux import native, require, safe_root

REGISTRY = 'network/transport-registry.json'
ADMISSION = 'network/rpc-gateway-admission.json'
RELAY = 'config/canary-rpc-relay.json'
FORMAT = 'synergy-canary-gateway-rotation-v1'
FILES = (REGISTRY, ADMISSION)
LIMIT = 128 * 1024


def digest(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def load_plan(stage, pin):
    raw = checked_read(stage/'gateway-rotation.json', 8192)
    require(digest(pin) and sha(raw) == pin, 'gateway rotation plan pin mismatch')
    p = json.loads(raw)
    require(set(p) == {'format','package_sha256','network_id','from_generation','to_generation',
                       'root_sha256','before','after'} and p['format'] == FORMAT
            and all(digest(p[k]) for k in ('package_sha256','root_sha256'))
            and type(p['from_generation']) is int and p['from_generation'] > 0
            and type(p['to_generation']) is int and p['to_generation'] == p['from_generation'] + 1,
            'strict forward gateway rotation required')
    for side in ('before','after'):
        require(set(p[side]) == set(FILES) and all(map(digest,p[side].values())),
                'exact registry and admission pins required')
    require(all(p['before'][name] != p['after'][name] for name in FILES), 'both artifacts must advance')
    proposed = {name: checked_read(stage/Path(name).name, LIMIT) for name in FILES}
    require({name:sha(raw) for name,raw in proposed.items()} == p['after'], 'staged gateway artifacts differ')
    registry, admission = (json.loads(proposed[name])['payload'] for name in FILES)
    require(registry['generation'] == admission['generation'] == p['to_generation']
            and registry['chain_id'] == admission['chain_id'] == 99999
            and registry['network_id'] == admission['network_id'] == p['network_id']
            and admission['validator_registry_sha256'] == p['after'][REGISTRY],
            'admission must select exact next registry')
    return p, proposed


def preflight(root, proposed):
    with tempfile.TemporaryDirectory(prefix='synergy-gateway-rotation-') as folder:
        stage = Path(folder)
        config = json.loads(checked_read(root/'config/node.json', LIMIT, True))
        relay = json.loads(checked_read(root/RELAY, LIMIT, True))
        require(relay['node_config_path'] == str(root/'config/node.json')
                and relay['admission_path'] == str(root/ADMISSION)
                and config['apqe_transport']['registry_path'] == str(root/REGISTRY)
                and relay['role']['kind'] == 'gateway', 'noncanonical gateway input paths')
        for name, raw in proposed.items():
            (stage/Path(name).name).write_bytes(raw)
        config['apqe_transport']['registry_path'] = str(stage/Path(REGISTRY).name)
        relay['admission_path'] = str(stage/Path(ADMISSION).name)
        relay['node_config_path'] = str(stage/'node.json')
        (stage/'node.json').write_bytes(json_bytes(config))
        (stage/'relay.json').write_bytes(json_bytes(relay))
        native([root/'bin/synergy-node','canary-rpc-relay','check',stage/'relay.json'])


def stopped(root):
    units = _attributed_units(root)
    relay = units.get(RELAY_UNIT, {})
    require(relay.get('ActiveState') in ('inactive','failed') and relay.get('MainPID') == '0',
            'stop the attributed gateway relay before rotation')
    vpn = units.get('synergy-vpn.service', {})
    require(vpn.get('ActiveState') == 'active' and int(vpn.get('MainPID') or '0') > 1,
            'keep the attributed gateway VPN running')


def rotate(root, stage, pin, apply):
    _require_operator()
    require(root not in (stage,*stage.parents), 'staged input must be outside installation')
    p, proposed = load_plan(stage, pin)
    with _lifecycle_lock(root):
        receipt, _ = _sealed_receipt(root)
        require(receipt.get('role') == 'rpc_gateway' and receipt.get('gateway_commissioned') is True
                and receipt.get('chain_id') == 99999 and receipt.get('network_id') == p['network_id']
                and receipt.get('package_sha256') == p['package_sha256'], 'wrong commissioned gateway release')
        _reject_installation_mounts(root)
        config = json.loads(checked_read(root/'config/node.json', LIMIT, True))
        root_key = root/'network/transport-root.pub'
        require(config['apqe_transport']['registry_trust_key_path'] == str(root_key)
                and config['apqe_transport']['registry_trust_key_sha256'] == p['root_sha256']
                and sha(checked_read(root_key, 8192, True)) == p['root_sha256'],
                'same pinned gateway trust root required')
        marker = root/UPGRADE_INTENT
        intent = {'format':FORMAT,'root':str(root),'plan_sha256':pin}
        resumed = marker.exists() or marker.is_symlink()
        if resumed:
            require(json.loads(checked_read(marker,4096,True)) == intent,
                    'interrupted mutation requires original exact gateway rotation plan')
        current = {name:checked_read(root/name,LIMIT,True) for name in FILES}
        current_pins = {name:sha(raw) for name,raw in current.items()}
        already = current_pins == p['after']
        require(already or all(current_pins[name] == p['before'][name]
                   or resumed and current_pins[name] == p['after'][name] for name in FILES),
                'installed artifacts outside pinned rotation')
        if current_pins[REGISTRY] == p['before'][REGISTRY]:
            before, after = (json.loads(data)['payload'] for data in (current[REGISTRY],proposed[REGISTRY]))
            mutable = {'generation','valid_from_unix','expires_at_unix'}
            require(before['generation'] == p['from_generation']
                    and {k:v for k,v in before.items() if k not in mutable}
                    == {k:v for k,v in after.items() if k not in mutable},
                    'rotation cannot change validator membership, endpoints or keys')
        if current_pins[ADMISSION] == p['before'][ADMISSION]:
            before, after = (json.loads(data)['payload'] for data in (current[ADMISSION],proposed[ADMISSION]))
            mutable = {'generation','valid_from_unix','expires_at_unix','validator_registry_sha256'}
            require(before['generation'] == p['from_generation']
                    and before['validator_registry_sha256'] == p['before'][REGISTRY]
                    and {k:v for k,v in before.items() if k not in mutable}
                    == {k:v for k,v in after.items() if k not in mutable},
                    'rotation cannot change gateway identities, transport keys or authority')
        preflight(root, proposed)
        if apply and (not already or resumed):
            stopped(root)
            if not resumed:
                _replace_bytes(root,marker,json_bytes(intent),0o600,pin)
            for name in FILES:
                if current[name] != proposed[name]:
                    _replace_bytes(root,root/name,proposed[name],0o600,pin)
            require(all(checked_read(root/name,LIMIT,True) == proposed[name] for name in FILES),
                    'post-install gateway artifact pin differs')
            native([root/'bin/synergy-node','canary-rpc-relay','check',root/RELAY])
            marker.unlink()
            _sync_directory(marker.parent)
        return {'generation':p['to_generation'],'native_preflight_passed':True,
                'rotation_installed':already or apply,'relay_started':False,'vpn_reset':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('check','apply'))
    parser.add_argument('--root',required=True)
    parser.add_argument('--staged',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    a = parser.parse_args()
    print(json.dumps(rotate(safe_root(a.root),a.staged.absolute(),a.plan_sha256,a.command=='apply'),
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError,ValueError,KeyError,TypeError) as error:
        raise SystemExit(f'Gateway rotation refused: {error}') from None
