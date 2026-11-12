#!/usr/bin/env python3
"""Apply one independently pinned Canary processing resource profile, stopped only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
from lifecycle import (_attributed_units, _lifecycle_lock, _replace_bytes,
                       _require_operator, _sealed_receipt)
from synergy_linux import native, read, require, safe_root

NETWORK = 'posy-apqe-canary-process-49028'
BUDGET = 512 * 1024 * 1024


def proposed(config):
    require(config.get('chain_id') == 99999 and config.get('network_id') == NETWORK
            and config.get('role') == 'validator' and config.get('etdag', {}).get('enabled') is True,
            'selected Canary processing validator required')
    require(config.get('storage', {}).get('world_memory_budget_bytes') in (128*1024*1024, BUDGET),
            'unreviewed resource profile refused')
    result = copy.deepcopy(config)
    result['storage']['world_memory_budget_bytes'] = BUDGET
    return result


def configure(root, package_pin, config_pin, result_pin, apply):
    _require_operator()
    require(len(package_pin) == len(config_pin) == len(result_pin) == 64
            and all(c in '0123456789abcdef' for c in package_pin+config_pin+result_pin), 'independent pins required')
    with _lifecycle_lock(root):
        receipt, _ = _sealed_receipt(root)
        require(receipt.get('package_sha256') == package_pin and receipt.get('role') == 'validator',
                'installed software differs from reviewed package')
        path = root/'config/node.json'
        require(path.is_file() and not path.is_symlink(), 'regular installed config required')
        before = path.read_bytes()
        current = read(path)
        selected = proposed(current)
        encoded = (json.dumps(selected, sort_keys=True, indent=2)+'\n').encode()
        require(hashlib.sha256(encoded).hexdigest() == result_pin, 'result differs from approved profile')
        # Retry after atomic publication is valid only for the exact intended profile.
        require(hashlib.sha256(before).hexdigest() == config_pin or before == encoded,
                'config differs from independently reviewed original')
        units = _attributed_units(root)
        require(units['synergy-vpn.service'].get('ActiveState') == 'active',
                'keep attributed validator VPN running')
        if apply:
            node = units['synergy-node.service']
            require(node.get('MainPID') == '0' and node.get('ActiveState') in ('inactive','failed'),
                    'stop attributed PoSy before resource configuration')
        with tempfile.TemporaryDirectory(prefix='canary-processing-resources-') as directory:
            stage = Path(directory)/'node.json'
            stage.write_bytes(encoded)
            response = json.loads(native([root/'bin/synergy-node', 'preflight', '--config', stage]))
            require(response.get('chain_id') == 99999 and response.get('network_id') == NETWORK
                    and response.get('active_validator_count') == 5
                    and response.get('signed_genesis_verified') is True
                    and response.get('signed_authority_verified') is True
                    and response.get('read_only') is True, 'native profile preflight failed')
        if apply and before != encoded:
            _replace_bytes(root, path, encoded, 0o600, config_pin)
        return {'world_memory_budget_bytes': BUDGET, 'native_preflight_passed': True,
                'installed': apply or before == encoded, 'consensus_started': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('check','apply'))
    p.add_argument('--root', required=True)
    p.add_argument('--package-sha256', required=True)
    p.add_argument('--config-sha256', required=True)
    p.add_argument('--result-sha256', required=True)
    a = p.parse_args()
    print(json.dumps(configure(safe_root(a.root), a.package_sha256, a.config_sha256, a.result_sha256,
                               a.command == 'apply'), sort_keys=True))
