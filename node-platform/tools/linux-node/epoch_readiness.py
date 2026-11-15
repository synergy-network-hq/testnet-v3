#!/usr/bin/env python3
"""Read-only Canary successor warning and native unsigned-payload preparation.

No custody access, signing, service control or activation. A complete successor
still needs the predecessor's terminal QC, so early readiness is a forecast,
never a substitute for that authenticated boundary or operator authorization.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import tempfile
import time
import urllib.request

from activate_authority_recovery import _canary_successor_range, checked, sha
from synergy_linux import native, require, safe_root


def forecast(authority, registry, telemetry, now, warning_blocks=100):
    payload = authority['payload']
    epoch, first, last = _canary_successor_range(payload)
    require(type(warning_blocks) is int and 1 <= warning_blocks <= 1000,
            'warning window must be 1..1000 blocks')
    require(registry['payload']['authority_binding_sha256'] == authority['sha256']
            and registry['payload']['epoch'] == payload['epoch']
            and registry['payload']['chain_id'] == payload['chain_id']
            and registry['payload']['network_id'] == payload['network_id'],
            'registry and authority disagree')
    require(telemetry['chain_id'] == payload['chain_id']
            and telemetry['network_identity'] == payload['network_id']
            and telemetry['epoch'] == payload['epoch']
            and telemetry['genesis_hash'] == registry['payload']['genesis_hash'],
            'live process and authenticated network disagree')
    height = telemetry['finalized_height']
    require(type(height) is int and 0 <= height <= payload['epoch_end_height'] - 2,
            'finalized height outside authenticated epoch range')
    remaining = payload['epoch_end_height'] - 2 - height
    valid = registry['payload']['valid_from_unix'] <= now < registry['payload']['expires_at_unix']
    status = ('registry-expired-or-not-current' if not valid else
              'awaiting-authorized-successor' if remaining == 0 else
              'successor-preparation-due' if remaining <= warning_blocks else 'within-epoch')
    return {'schema': 'nodenetwork-epoch-readiness-v1', 'status': status,
            'epoch': payload['epoch'], 'finalized_height': height,
            'finalizable_blocks_remaining': remaining,
            'authority_sha256': authority['sha256'],
            'registry_generation': registry['payload']['generation'],
            'registry_seconds_remaining': registry['payload']['expires_at_unix'] - now,
            'expected_successor': {'epoch': epoch, 'first_height': first, 'last_height': last},
            'following_epoch': {'epoch': epoch + 1, 'first_height': last + 1, 'last_height': last + 1000},
            'terminal_qc_required': True, 'signing_authorization_required': True,
            'activation_authorization_required': True, 'automatic_signing': False,
            'installed_files_changed': False}


def observe(root, warning_blocks=100):
    root = safe_root(root)
    config_path = root/'config/node.json'
    paths = [config_path, root/'network/authority.json', root/'network/transport-registry.json']
    before = [checked(p) for p in paths]
    config, authority, registry = [json.loads(raw) for raw in before]
    require(config['consensus']['authority_binding'] == str(paths[1])
            and config['apqe_transport']['registry_path'] == str(paths[2]),
            'configured public inputs must use canonical installation paths')
    # JSON or matching hashes alone cannot admit a purported authority.
    report = json.loads(native([root/'bin/synergy-node', 'preflight', '--config', config_path]))
    require(report.get('signed_authority_verified') is True
            and report.get('signed_genesis_verified') is True, 'native authority preflight required')
    host, port = config['rpc']['listen_address'].rsplit(':', 1)
    host = host.strip('[]')
    require(ipaddress.ip_address(host).is_loopback and 1 <= int(port) <= 65535,
            'only the configured loopback RPC may supply observations')
    address = f'[{host}]' if ':' in host else host
    request = urllib.request.Request(f'http://{address}:{int(port)}/',
        data=b'{"jsonrpc":"2.0","id":1,"method":"synergy_chainTelemetry","params":{}}',
        headers={'Content-Type': 'application/json'})
    # No proxy or redirect may silently substitute another observation source.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs): return None
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect).open(request, timeout=5) as reply:
        body = reply.read(1024 * 1024 + 1)
    require(len(body) <= 1024 * 1024, 'bounded live telemetry required')
    require([checked(p) for p in paths] == before, 'network inputs changed during readiness check')
    authority['sha256'] = sha(before[1])
    result = forecast(authority, registry, json.loads(body)['result'], int(time.time()), warning_blocks)
    result['registry_sha256'] = sha(before[2])
    return result


def prepare(root, witness, output):
    root, witness, output = safe_root(root), Path(witness), Path(output)
    require(output.is_absolute() and '..' not in output.parts and not output.is_relative_to(root),
            'prepare outside the active installation; staging inside it prevents startup')
    checked(output, optional=True)  # Reject linked output ancestry before native work.
    proof = checked(witness)
    # Native verification owns all QC/signature/successor rules. Repeated
    # preparation reconciles exact bytes rather than overwriting an artifact.
    with tempfile.TemporaryDirectory(prefix='epoch-readiness-', dir=output.parent) as temp:
        staged = Path(temp)/'unsigned.json'
        native([root/'bin/synergy-node', 'authority-successor', 'prepare-payload',
                root/'config/node.json', witness, staged])
        raw = checked(staged)
        require(checked(witness) == proof, 'boundary witness changed during preparation')
        repeated = output.exists() or output.is_symlink()
        if repeated:
            require(checked(output) == raw, 'existing output differs; reconcile before preparing again')
        else:
            from activate_authority_recovery import _write_new
            _write_new(output, raw)
    return {'status': 'unsigned-successor-prepared', 'sha256': sha(raw), 'repeated': repeated,
            'signed': False, 'activated': False, 'installed_files_changed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--warning-blocks', type=int, default=100)
    parser.add_argument('--witness', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    require(bool(args.witness) == bool(args.output), 'witness and output must be provided together')
    result = observe(args.root, args.warning_blocks)
    if args.witness:
        result['preparation'] = prepare(args.root, args.witness, args.output)
    print(json.dumps(result, sort_keys=True))
