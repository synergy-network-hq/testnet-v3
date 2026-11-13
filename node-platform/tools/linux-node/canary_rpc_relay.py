#!/usr/bin/env python3
"""Opt-in Canary relay configuration within the sealed universal node package.

This never provisions keys, edits admission, starts services or grants production
qualification. The native check authenticates all actual selected artifacts.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from synergy_linux import read, require, native

CONFIG = 'config/canary-rpc-relay.json'
GATEWAY_INPUTS = frozenset((CONFIG, 'config/node.json',
    'network/genesis.json', 'network/authority.json', 'network/authority-root.pub',
    'network/network-manifest.json', 'network/transport-registry.json',
    'network/transport-root.pub', 'network/rpc-gateway-admission.json',
    'keys/apqe/gateway-enrollment.json', 'keys/apqe/gateway-transport.encrypted.json',
    'keys/apqe/gateway-transport.unlock'))


def seal_gateway_inputs(staged, root):
    """Shared provisioning manifest; caller authenticates its returned digest."""
    unit_text(root)
    config = read(staged/'config/node.json')
    require(config.get('role') == 'rpc_gateway' and config.get('chain_id') == 99999,
            'Canary gateway configuration required')
    files = {}
    for name in sorted(GATEWAY_INPUTS):
        path = staged/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16*1024*1024,
                'bounded regular gateway input required: '+name)
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    value = {'format': 'synergy-canary-rpc-gateway-commissioning-v1',
        'root': str(root), 'chain_id': 99999, 'network_id': config['network_id'], 'files': files}
    from synergy_linux import write_new
    path = staged/'gateway-commissioning.json'
    write_new(path, value)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_gateway_layout(root):
    receipt = read(root/'installation.json')
    config = read(root/'config/node.json')
    require(receipt.get('role') == config.get('role') == 'rpc_gateway'
            and receipt.get('chain_id') == config.get('chain_id') == 99999
            and receipt.get('network_id') == config.get('network_id'), 'gateway selected incarnation differs')
    require(config.get('consensus', {}).get('mode') == 'observe'
            and config.get('consensus', {}).get('signing_key_path') is None
            and config.get('aegis_signing_key_path') is None
            and not config.get('rpc', {}).get('enabled')
            and config.get('etdag', {}).get('ingress_kem_secret_key_path') is None,
            'gateway cannot enable validator signing, ingress custody or ordinary RPC')
    for key, relative in {'manifest_path': 'network/network-manifest.json',
                          'genesis_path': 'network/genesis.json'}.items():
        require(config.get(key) == str(root/relative), 'gateway public context path differs')
    consensus = config['consensus']
    require(consensus.get('authority_binding') == str(root/'network/authority.json')
            and consensus.get('authority_trust_key_path') == str(root/'network/authority-root.pub'),
            'gateway authority paths differ')
    selected = config.get('apqe_transport', {})
    require(selected.get('registry_path') == str(root/'network/transport-registry.json')
            and selected.get('registry_trust_key_path') == str(root/'network/transport-root.pub'),
            'gateway transport trust paths differ')
    packaged = read(root/'package.json').get('apqe_provider', {})
    provider = config.get('aegis_provider', {})
    require(provider.get('report_path') == str(root/'lib/apqe/build-report.json')
            and provider.get('authenticated_report_sha256') == packaged.get('report_sha256')
            and re.fullmatch(r'[0-9a-f]{64}', packaged.get('report_sha256', '')),
            'gateway provider must match sealed package')
    require(not (root/'config/start-authorized.json').exists(), 'gateway cannot authorize PoSy startup')
    validate_observer_transition_layout(root,config,receipt)
    allowed_keys = {root/name for name in GATEWAY_INPUTS if name.startswith('keys/')}
    require({p for p in (root/'keys').rglob('*') if p.is_file()} == allowed_keys,
            'gateway keys must contain only own transport custody and public enrollment')
    for name in GATEWAY_INPUTS:
        path = root/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_uid == os.geteuid()
                and path.stat().st_mode & 0o777 == 0o600, 'unsafe gateway input: '+name)
    actual = read(root/CONFIG)
    role = dict(actual['role'])
    for key in ('enrollment_path', 'custody_path', 'custody_unlock_path'):
        role.pop(key, None)
    require(actual == configuration(root, {'role': role, 'listen_address': actual['listen_address']})
            and role['kind'] == 'gateway', 'noncanonical gateway relay configuration')
    native([root/'bin/synergy-node', 'canary-rpc-relay', 'check', root/CONFIG])
    return {'native_admission_custody_verified': True, 'validator_keys_present': False,
            'production_qualified': False}


def validate_observer_transition_layout(root,config,receipt):
    """Allow only public epoch-transition proofs; gateways never own chain state."""
    data=root/'data'
    if not data.exists() or not any(data.rglob('*')): return
    from lifecycle import verify_authority_recovery_pin
    verify_authority_recovery_pin(root,config,receipt)
    require(config.get('consensus',{}).get('authority_recovery_certificate_path') is not None,
            'gateway public transition storage requires activated quorum recovery')
    epoch=read(root/'network/authority.json')['payload']['epoch']
    require(type(epoch) is int and 2 <= epoch <= 2**64-1, 'recovered observer epoch required')
    directories={'consensus','consensus/authority-transitions','consensus/authority-transitions/.transactions'}
    prefix='consensus/authority-transitions/'
    for path in data.rglob('*'):
        name=path.relative_to(data).as_posix()
        require(not path.is_symlink() and path.stat().st_uid==os.geteuid()
                and not path.stat().st_mode & 0o022, 'unsafe observer public transition member')
        if path.is_dir(): require(name in directories, 'gateway cannot own chain storage')
        else:
            match=re.fullmatch(re.escape(prefix)+r'epoch-([0-9]{20})\.json',name)
            require(path.is_file() and (name==prefix+'.synergy-writer.lock'
                    or match is not None and 2 <= int(match[1]) <= epoch),
                    'gateway cannot own chain storage')


def _safe_staging(staged):
    for path in (staged, *staged.parents):
        require(not path.is_symlink() and path.stat().st_uid == os.geteuid()
                and not path.stat().st_mode & 0o022, 'unsafe staging ancestry')


def commission_gateway(root, staged, expected_sha256):
    """Install one exact staged input set, authenticate, then mark commissioned.

    The input manifest pin is supplied independently by the shared provisioner.
    Actual trust/key correspondence is verified by the native APQE owner.
    """
    import lifecycle
    lifecycle._require_operator()
    require(re.fullmatch(r'[0-9a-f]{64}', expected_sha256 or ''), 'independent commissioning manifest pin required')
    require(staged.is_absolute() and root not in staged.parents and staged != root
            and staged.resolve() == staged, 'separate canonical staging directory required')
    _safe_staging(staged)
    manifest_path = staged/'gateway-commissioning.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink()
            and manifest_path.stat().st_size <= 16384, 'bounded gateway manifest required')
    require(hashlib.sha256(manifest_path.read_bytes()).hexdigest() == expected_sha256,
            'gateway commissioning manifest pin mismatch')
    manifest = read(manifest_path)
    require(set(manifest) == {'format', 'root', 'chain_id', 'network_id', 'files'}
            and manifest['format'] == 'synergy-canary-rpc-gateway-commissioning-v1'
            and manifest['root'] == str(root) and manifest['chain_id'] == 99999
            and set(manifest['files']) == GATEWAY_INPUTS, 'exact gateway input manifest required')
    from synergy_linux import write_new
    with lifecycle._lifecycle_lock(root):
        receipt, _ = lifecycle._sealed_receipt(root)
        require(receipt.get('role') == 'rpc_gateway' and receipt.get('chain_id') == 99999
                and receipt.get('network_id') == manifest['network_id']
                and not receipt.get('gateway_commissioned'), 'fresh selected gateway installation required')
        require(not (root/'config/start-authorized.json').exists()
                and not any((root/'keys').rglob('*')), 'gateway already contains keys or startup authority')
        for name, expected in manifest['files'].items():
            source = staged/name
            for path in (source, *source.parents):
                if path == staged: break
                require(not path.is_symlink(), 'staging symlink forbidden')
            require(source.is_file() and source.stat().st_uid == os.geteuid()
                    and source.stat().st_mode & 0o777 == 0o600
                    and source.stat().st_size <= 16*1024*1024
                    and re.fullmatch(r'[0-9a-f]{64}', expected)
                    and hashlib.sha256(source.read_bytes()).hexdigest() == expected,
                    'gateway staged input differs: '+name)
            require(not (root/name).exists() and not (root/name).is_symlink(), 'gateway input already exists')
        created = []
        try:
            for name, expected in sorted(manifest['files'].items()):
                path = root/name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                # Stream custody/unlock bytes, never decode a plaintext secret.
                with (staged/name).open('rb') as source, path.open('xb') as target:
                    created.append(path)
                    os.fchmod(target.fileno(), 0o600)
                    digest = hashlib.sha256()
                    while block := source.read(65536):
                        digest.update(block); target.write(block)
                    target.flush(); os.fsync(target.fileno())
                require(digest.hexdigest() == expected, 'staging changed while copying')
                lifecycle._sync_directory(path.parent)
            validate_gateway_layout(root)
            receipt = dict(receipt, gateway_commissioned=True,
                           gateway_commissioning_sha256=expected_sha256)
            lifecycle._replace_bytes(root, root/'installation.json',
                json.dumps(receipt, sort_keys=True, indent=2).encode()+b'\n', 0o600, expected_sha256)
        except BaseException:
            for path in reversed(created): path.unlink()
            apqe = root/'keys/apqe'
            if apqe.exists() and not any(apqe.iterdir()): apqe.rmdir()
            raise
    return {'gateway_commissioned': True, 'services_started': False, 'production_qualified': False}


def unit_text(root):
    import synergy_linux as boundary
    from lifecycle import guard_dependencies
    legacy = Path(root) == boundary.LEGACY_EXISTING_ROOT
    require(re.fullmatch(r'/[A-Za-z0-9_/.-]+/synergy', str(root)) or legacy, 'unsafe service root')
    if legacy: boundary.safe_root(root)
    after, binding = guard_dependencies(root)
    return f'''[Unit]
{binding}Description=Synergy authenticated Canary RPC relay
After=network-online.target synergy-vpn.service{after}
Requires=synergy-vpn.service
ConditionPathExists={root}/{CONFIG}

[Service]
Type=exec
User=root
UMask=0077
WorkingDirectory={root}
Environment=HOME={root}
Environment=TMPDIR={root}/tmp
ExecStartPre=/usr/bin/python3 {root}/tools/lifecycle.py relay-start-check --root {root}
ExecStartPre={root}/bin/synergy-node canary-rpc-relay check {root}/{CONFIG}
ExecStart={root}/bin/synergy-node canary-rpc-relay serve {root}/{CONFIG}
Restart=on-failure
RestartSec=5s
MemoryMax=268435456
MemorySwapMax=0
TasksMax=32
LimitNOFILE=256
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={root}/logs {root}/tmp
StandardOutput=append:{root}/logs/canary-rpc-relay.log
StandardError=append:{root}/logs/canary-rpc-relay.log

[Install]
WantedBy=multi-user.target
'''


def configuration(root, value):
    unit_text(root)  # No systemd, path or argument injection.
    require(isinstance(value, dict) and set(value) == {'listen_address', 'role'}, 'exact relay specification required')
    role = value['role']
    require(isinstance(role, dict), 'relay role required')
    kind = role.get('kind')
    common = {'kind', 'validator_address'}
    fields = common | ({'gateway_vpn_ip'} if kind == 'validator' else
        {'gateway_address', 'validator_relay_port', 'allowed_origins'} if kind == 'gateway' else set())
    require(kind in ('validator', 'gateway') and set(role) == fields, 'unsupported relay role fields')
    require(isinstance(role['validator_address'], str) and re.fullmatch(r'synv1[0-9a-z]+', role['validator_address']), 'validator address required')
    listen = value['listen_address']
    require(isinstance(listen, str) and len(listen) <= 128, 'literal relay endpoint required')
    match = re.fullmatch(r'(\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)', listen)
    require(match is not None, 'literal relay endpoint required')
    ip = ipaddress.ip_address(match[1].strip('[]'))
    port = int(match[2])
    require(0 < port <= 65535 and not ip.is_unspecified and not ip.is_multicast, 'invalid relay endpoint')
    role = dict(role)
    if kind == 'validator':
        gateway = ipaddress.ip_address(role['gateway_vpn_ip'])
        require(not ip.is_loopback and not gateway.is_loopback and not gateway.is_unspecified
                and not gateway.is_multicast and gateway != ip and gateway.version == ip.version, 'distinct overlay endpoints required')
    else:
        require(ip.is_loopback and type(role['validator_relay_port']) is int and 0 < role['validator_relay_port'] <= 65535, 'gateway loopback and validator port required')
        require(isinstance(role['gateway_address'], str) and re.fullmatch(r'synv5[0-9a-z]+', role['gateway_address']), 'service gateway address required')
        origins = role['allowed_origins']
        require(isinstance(origins, list) and len(origins) <= 16 and len(set(origins)) == len(origins), 'bounded distinct origins required')
        for origin in origins:
            require(isinstance(origin, str) and len(origin) <= 261, 'bounded HTTPS origin required')
            parsed = urlsplit(origin)
            require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
                    and not parsed.path and not parsed.query and not parsed.fragment
                    and re.fullmatch(r'https://[A-Za-z0-9.:-]+', origin), 'exact HTTPS origin required')
            require(parsed.port is None or 0 < parsed.port <= 65535, 'valid origin port required')
        role.update(enrollment_path=str(root/'keys/apqe/gateway-enrollment.json'),
                    custody_path=str(root/'keys/apqe/gateway-transport.encrypted.json'),
                    custody_unlock_path=str(root/'keys/apqe/gateway-transport.unlock'))
    return {'schema_version': 1, 'node_config_path': str(root/'config/node.json'),
            'admission_path': str(root/'network/rpc-gateway-admission.json'),
            'listen_address': listen, 'role': role}


def configure(root, spec):
    import lifecycle
    lifecycle._require_operator()
    with lifecycle._lifecycle_lock(root):
        lifecycle._sealed_receipt(root)
        require(read(root/'config/node.json').get('chain_id') == 99999, 'Canary 99999 only')
        result = configuration(root, spec)
        path = root/CONFIG
        require(not path.exists() and not path.is_symlink(), 'relay configuration already exists')
        candidate = path.with_name('.canary-rpc-relay.pending')
        created = False
        try:
            # Exclusive 0600 creation also prevents a stale/foreign staging file
            # from being overwritten. Cleanup only a file this call created.
            with candidate.open('x') as stream:
                created = True
                os.fchmod(stream.fileno(), 0o600)
                json.dump(result, stream, sort_keys=True)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            native([root/'bin/synergy-node', 'canary-rpc-relay', 'check', candidate])
            os.link(candidate, path)  # atomic no-replace publication
            lifecycle._sync_directory(path.parent)
        finally:
            if created:
                candidate.unlink()
                lifecycle._sync_directory(path.parent)
    return {'configuration': str(path), 'native_preflight_verified': True, 'services_started': False,
            'production_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('render', 'configure', 'register', 'start', 'stop', 'commission-gateway'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--staged', type=Path)
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    import lifecycle
    from synergy_linux import safe_root
    root = safe_root(str(args.root))
    if args.command == 'commission-gateway':
        require(args.staged is not None, 'staged inputs required')
        result = commission_gateway(root, args.staged, args.manifest_sha256)
    elif args.command in ('render', 'configure'):
        require(args.spec is not None and args.spec.stat().st_size <= 8192 and not args.spec.is_symlink(), 'bounded regular specification required')
        spec = read(args.spec)
        result = configuration(root, spec) if args.command == 'render' else configure(root, spec)
    else:
        lifecycle._require_operator()
        lifecycle._sealed_receipt(root)
        if args.command == 'start': lifecycle.relay_start_check(root)
        require((root/CONFIG).is_file(), 'configure relay before registration/control')
        native([root/'bin/synergy-node', 'canary-rpc-relay', 'check', root/CONFIG]) if args.command != 'stop' else None
        if args.command == 'start' and read(root/CONFIG)['role']['kind'] == 'gateway':
            from vpn import verify_gateway_route
            verify_gateway_route(root)
        result = lifecycle.register(root) if args.command == 'register' else lifecycle.mutate_owned_service(root, args.command, lifecycle.RELAY_UNIT)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('Canary relay refused: '+str(error), file=sys.stderr)
        sys.exit(1)
