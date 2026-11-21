#!/usr/bin/env python3
"""Opt-in authenticated RPC relay configuration within the universal node package.

Explicit managed gateway operations use native custody and exact one-use host
authorization. Native checks authenticate the selected artifacts; no operation
grants production qualification.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from synergy_linux import read, require, native

CONFIG = 'config/canary-rpc-relay.json'
NETWORK_PROFILE = 'network-provisioning.json'
BOOTSTRAP_PIN = 'autonomous_bootstrap_sha256'
BOOTSTRAP_RECORD = 'evidence/gateway-bootstrap-pin.json'
BOOTSTRAP_STAGED = 'config/.gateway-bootstrap-pin.pending.json'
BOOTSTRAP_FORMAT = 'synergy-canary-gateway-bootstrap-pin-v1'
SHA256 = re.compile(r'[0-9a-f]{64}')
GATEWAY_INPUTS = frozenset((CONFIG, 'config/node.json',
    'network/genesis.json', 'network/authority.json', 'network/authority-root.pub',
    'network/network-manifest.json', 'network/transport-registry.json',
    'network/transport-root.pub', 'network/rpc-gateway-admission.json',
    'keys/apqe/gateway-enrollment.json', 'keys/apqe/gateway-transport.encrypted.json',
    'keys/apqe/gateway-transport.unlock'))


def _chain_id(scope):
    value = scope.get('chain_id')
    require(type(value) is int and 0 < value < 2**64, 'Explicit nonzero u64 chain ID required')
    return value


def seal_gateway_inputs(staged, root):
    """Shared provisioning manifest; caller authenticates its returned digest."""
    unit_text(root)
    config = read(staged/'config/node.json')
    require(config.get('role') == 'rpc_gateway', 'RPC gateway configuration required')
    files = {}
    for name in sorted(GATEWAY_INPUTS):
        path = staged/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 16*1024*1024,
                'bounded regular gateway input required: '+name)
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    value = {'format': 'synergy-canary-rpc-gateway-commissioning-v1',
        'root': str(root), 'chain_id': _chain_id(config), 'network_id': config['network_id'], 'files': files}
    from synergy_linux import write_new
    path = staged/'gateway-commissioning.json'
    write_new(path, value)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_gateway_layout(root):
    receipt = read(root/'installation.json')
    config = read(root/'config/node.json')
    require(receipt.get('role') == config.get('role') == 'rpc_gateway'
            and _chain_id(receipt) == _chain_id(config)
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
    if (root/'tmp/gateway-target/generated.json').exists():
        approved_gateway_target_members(root)
        allowed_keys|={root/'keys/apqe/gateway-identity.encrypted.json',root/'keys/apqe/gateway-identity.unlock'}
    require({p for p in (root/'keys').rglob('*') if p.is_file()} == allowed_keys,
            'gateway keys must contain only own transport custody and public enrollment')
    for name in GATEWAY_INPUTS:
        path = root/name
        require(path.is_file() and not path.is_symlink() and path.stat().st_uid == os.geteuid()
                and path.stat().st_mode & 0o777 == 0o600, 'unsafe gateway input: '+name)
    _canonical_gateway_configuration(root, read(root/CONFIG))
    verify_bootstrap_pin_record(root)
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
            and manifest['root'] == str(root)
            and set(manifest['files']) == GATEWAY_INPUTS, 'exact gateway input manifest required')
    from synergy_linux import write_new
    with lifecycle._lifecycle_lock(root):
        receipt, _ = lifecycle._sealed_receipt(root)
        require(receipt.get('role') == 'rpc_gateway' and _chain_id(receipt) == _chain_id(manifest)
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
    if kind == 'gateway' and BOOTSTRAP_PIN in role:
        fields.add(BOOTSTRAP_PIN)
        require(_is_digest(role[BOOTSTRAP_PIN]), 'exact lowercase gateway bootstrap SHA-256 required')
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


def _is_digest(value):
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def _canonical_gateway_configuration(root, actual):
    role = dict(actual['role'])
    for key in ('enrollment_path', 'custody_path', 'custody_unlock_path'):
        role.pop(key, None)
    require(role.get('kind') == 'gateway'
            and actual == configuration(root, {'role': role, 'listen_address': actual['listen_address']}),
            'noncanonical gateway relay configuration')
    return actual


def _private_bytes(path, limit):
    require(path.parent.resolve(strict=True) == path.parent, 'noncanonical gateway pin path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid()
                and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1
                and 0 < meta.st_size <= limit, 'unsafe private gateway pin input')
        raw = stream.read(limit + 1)
        require(len(raw) == meta.st_size, 'gateway pin input changed while reading')
        return raw


def _unique_fields(fields):
    value = dict(fields)
    require(len(value) == len(fields), 'duplicate gateway pin input field')
    return value


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _exists(path):
    return path.exists() or path.is_symlink()


def _bootstrap_record(root):
    path = root/BOOTSTRAP_RECORD
    if not _exists(path):
        return None
    value = json.loads(_private_bytes(path, 4096), object_pairs_hook=_unique_fields)
    require(isinstance(value, dict) and set(value) == {
                'format', 'phase', 'bootstrap_sha256', 'before_sha256', 'after_sha256'}
            and value['format'] == BOOTSTRAP_FORMAT and value['phase'] in ('pending', 'complete')
            and all(_is_digest(value[field]) for field in ('bootstrap_sha256', 'before_sha256', 'after_sha256'))
            and value['before_sha256'] != value['after_sha256'], 'invalid gateway bootstrap pin record')
    return value


def verify_bootstrap_pin_record(root):
    record = _bootstrap_record(root)
    require(not _exists(root/BOOTSTRAP_STAGED) and (record is None or record['phase'] == 'complete'),
            'finish recorded gateway bootstrap pin update before startup')
    if record is not None:
        installed = _private_bytes(root/CONFIG, 64*1024)
        actual = json.loads(installed, object_pairs_hook=_unique_fields)
        require(_sha(installed) == record['after_sha256']
                and actual['role'].get(BOOTSTRAP_PIN) == record['bootstrap_sha256'],
                'installed gateway configuration differs from completed bootstrap pin record')


def apply_bootstrap_pin(root, expected_config_sha256, bootstrap_sha256):
    """One-time, stopped gateway update. Resume only the exact pinned transaction."""
    import lifecycle
    lifecycle._require_operator()
    require(_is_digest(expected_config_sha256) and _is_digest(bootstrap_sha256),
            'independent prior configuration and bootstrap SHA-256 pins required')
    token = _sha(f'{expected_config_sha256}:{bootstrap_sha256}'.encode('ascii'))
    path, staged, record_path = (root/name for name in (CONFIG, BOOTSTRAP_STAGED, BOOTSTRAP_RECORD))
    check = [root/'bin/synergy-node', 'canary-rpc-relay', 'check']
    with lifecycle._lifecycle_lock(root):
        receipt, _ = lifecycle._sealed_receipt(root)
        require(receipt.get('role') == 'rpc_gateway', 'commissioned RPC gateway required')
        _chain_id(receipt)
        for name in (lifecycle.UPGRADE_INTENT, lifecycle.REPLACEMENT_INTENT,
                     lifecycle.AUTHORITY_RECOVERY_INTENT, lifecycle.AUTONOMOUS_EPOCH_INTENT):
            require(not _exists(root/name), 'reconcile other lifecycle intent before gateway pin update')
        lifecycle._reject_installation_mounts(root)
        unit = lifecycle._attributed_units(root).get(lifecycle.RELAY_UNIT, {})
        require(unit.get('MainPID') == '0' and unit.get('ActiveState') in ('inactive', 'failed'),
                'stop the attributed gateway relay before bootstrap pin update')
        installed = _private_bytes(path, 64*1024)
        old_sha = _sha(installed)
        config = _canonical_gateway_configuration(root, json.loads(installed, object_pairs_hook=_unique_fields))
        record = _bootstrap_record(root)
        if record is not None:
            require(record['before_sha256'] == expected_config_sha256
                    and record['bootstrap_sha256'] == bootstrap_sha256,
                    'gateway bootstrap pin update already bound to another request')
        if record is not None and old_sha == record['after_sha256']:
            require(config['role'].get(BOOTSTRAP_PIN) == bootstrap_sha256 and not _exists(staged),
                    'published gateway pin update differs from its recorded intent')
            native([*check, path])
            already_current = record['phase'] == 'complete'
        else:
            require(old_sha == expected_config_sha256 and BOOTSTRAP_PIN not in config['role']
                    and (record is None or record['phase'] == 'pending'),
                    'exact unpinned prior gateway configuration required')
            config['role'][BOOTSTRAP_PIN] = bootstrap_sha256
            candidate = _json_bytes(config)
            if record is None:
                record = {'format': BOOTSTRAP_FORMAT, 'phase': 'pending',
                          'bootstrap_sha256': bootstrap_sha256, 'before_sha256': old_sha,
                          'after_sha256': _sha(candidate)}
            require(_sha(candidate) == record['after_sha256'], 'gateway pin candidate differs from recorded intent')
            if _exists(staged):
                require(_private_bytes(staged, 64*1024) == candidate, 'foreign gateway pin staging member')
            else:
                lifecycle._replace_bytes(root, staged, candidate, 0o600, token)
            try:
                native([*check, staged])
                if not _exists(record_path):
                    lifecycle._replace_bytes(root, record_path, _json_bytes(record), 0o600, token)
                require(_sha(_private_bytes(path, 64*1024)) == old_sha
                        and _private_bytes(staged, 64*1024) == candidate, 'gateway pin inputs changed before publication')
                os.replace(staged, path)
                lifecycle._sync_directory(path.parent)
            finally:
                if _exists(staged):
                    staged.unlink()
                    lifecycle._sync_directory(staged.parent)
            already_current = False
        require(_sha(_private_bytes(path, 64*1024)) == record['after_sha256'],
                'published gateway configuration changed')
        if not already_current:
            lifecycle._replace_bytes(root, record_path, _json_bytes(dict(record, phase='complete')), 0o600, token)
        verify_bootstrap_pin_record(root)
    return {'bootstrap_sha256': bootstrap_sha256, 'configuration_sha256': record['after_sha256'],
            'native_preflight_verified': True, 'already_current': already_current, 'services_started': False}


def configure(root, spec):
    import lifecycle
    lifecycle._require_operator()
    with lifecycle._lifecycle_lock(root):
        receipt, _ = lifecycle._sealed_receipt(root)
        config = read(root/'config/node.json')
        require(_chain_id(config) == _chain_id(receipt)
                and config.get('network_id') == receipt.get('network_id'),
                'Relay configuration must match the installed network')
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
    parser.add_argument('command', choices=('render', 'configure', 'register', 'start', 'stop', 'commission-gateway', 'apply-bootstrap-pin'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--spec', type=Path)
    parser.add_argument('--staged', type=Path)
    parser.add_argument('--manifest-sha256')
    parser.add_argument('--expected-config-sha256')
    parser.add_argument('--bootstrap-sha256')
    args = parser.parse_args()
    import lifecycle
    from synergy_linux import safe_root
    root = safe_root(str(args.root))
    if args.command == 'apply-bootstrap-pin':
        result = apply_bootstrap_pin(root, args.expected_config_sha256, args.bootstrap_sha256)
    elif args.command == 'commission-gateway':
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

# Prospective engineering-only formation-issuer management. This is admission
# issuance, never gateway OS commissioning or validator/public RPC exposure.
GATEWAY_PURPOSE = 'engineering-rpc-gateway-admission-v1'
GATEWAY_PREPARE = {'formation_sha256','transport_review_sha256','gateway_enrollment_json',
                   'purpose_approval_sha256','purpose_approval_json','valid_from_unix','expires_at_unix'}
GATEWAY_RESULT = {'schema','pending','signed','request_sha256','review_sha256','purpose_approval_sha256',
    'formation_sha256','network_id','chain_id','genesis_sha256','authority_sha256','registry_sha256',
    'gateway_address','gateway_enrollment_sha256','valid_from_unix','expires_at_unix','admission_sha256',
    'sign_request_sha256','gateway_commissioned','services_started','public_listener','production_qualified','automatic_retry'}
GATEWAY_DIRECTORY = 'tmp/gateway-admission'
GATEWAY_PREPARE_INTENT = 'tmp/gateway-admission-prepare-request.json'
GATEWAY_SIGN_INTENT = 'tmp/gateway-admission-sign-request.json'
GATEWAY_APPROVAL = 'gateway-purpose.json'


def gateway_parameters(operation, parameters):
    expected = GATEWAY_PREPARE if operation in ('gateway_admission_prepare','gateway_admission_preflight') else {'review_sha256','purpose_approval_sha256'} if operation=='gateway_admission_sign' else {'request_sha256'} if operation=='gateway_admission_reconcile' else set()
    require(operation in {'gateway_admission_preflight','gateway_admission_prepare','gateway_admission_sign','gateway_admission_status','gateway_admission_export','gateway_admission_reconcile'}
            and isinstance(parameters,dict) and set(parameters)==expected,'Exact gateway admission parameters required')
    for key in expected-{'gateway_enrollment_json','purpose_approval_json','valid_from_unix','expires_at_unix'}:
        require(_is_digest(parameters[key]),'Exact gateway admission pin required')
    if operation in ('gateway_admission_prepare','gateway_admission_preflight'):
        require(all(type(parameters[k]) is int and 0<parameters[k]<2**53 for k in ('valid_from_unix','expires_at_unix'))
                and 0<parameters['expires_at_unix']-parameters['valid_from_unix']<=7*86400,'Bounded engineering gateway validity required')
        for key,limit in (('gateway_enrollment_json',128*1024),('purpose_approval_json',16384)):
            require(isinstance(parameters[key],str) and 0<len(parameters[key].encode('utf-8'))<=limit,'Bounded public gateway artifact required')
        require(_sha(parameters['purpose_approval_json'].encode())==parameters['purpose_approval_sha256'],'Exact gateway purpose bytes required')


def _gateway_request_bytes(request):
    return json.dumps(request,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')


def _gateway_empty(blocker,scope=None):
    result={k:None for k in GATEWAY_RESULT}
    result.update(schema='nodenetwork-gateway-admission-v1',pending=False,signed=False,available=blocker is None,blocker=blocker,
                  gateway_commissioned=False,services_started=False,public_listener=False,production_qualified=False,automatic_retry=False)
    return result


def _gateway_authority_root(c,policy):
    pins=policy.get('validator_identity_network',{})
    pin=pins.get('authority-root.pub')
    require(_is_digest(pin),'Exact approved gateway authority root required')
    installed=c.direct(c.root/'network/authority-root.pub',True,8192).read_bytes()
    source=c.direct(c.root/'tmp/network-formation/authority-root.pub',True,8192).read_bytes()
    require(_sha(installed)==pin and installed==source,'Gateway authority root differs from approved signed formation')


def _gateway_scope(c,historical=False):
    import lifecycle as life
    receipt,manifest=life._sealed_receipt(c.root)
    policy=c.policy()
    require(_is_digest(policy.get('engineering_initial_authorization_sha256')) and receipt['role']=='validator'
            and policy.get('engineering_target',{}).get('guest') is None,
            'Engineering formation issuer on the exact physical network required')
    from controller import engineering_effective_selection
    selected=engineering_effective_selection(c.root,policy)
    require(selected is not None and all(selected[k]==receipt[k] for k in ('network_id','chain_id','node_name')),
            'Gateway issuer installed selection differs')
    for name in ('bin/synergy-node','bin/synergy-keytool','bin/synergy-genesis','lib/apqe/build-report.json'):
        require(_is_digest(manifest['files'].get(name)),'Qualified native gateway owner is absent')
    capability=json.loads(native([c.root/'bin/synergy-keytool','gateway-admission-capability'],maximum_stdout=4096))
    require(capability=={'capability':GATEWAY_PURPOSE,'custody_role':'formation-transport-issuer-ml-dsa-87-v1',
                         'additional_purpose_required':True,'production_qualified':False},'Qualified gateway issuer capability unavailable')
    selection,flags=c.formation_context()
    require(selection['network_id']==receipt['network_id'] and selection['chain_id']==str(_chain_id(receipt)),
            'Gateway formation differs from installed scope')
    args=[c.formation_context_path(),selection['formation_sha256'],c.root/'tmp/network-formation',c.root/'tmp/network-transport']
    review=json.loads(native([c.root/'bin/synergy-keytool','review-gateway-issuer' if historical else 'review-network-transport',*args,*flags],maximum_stdout=128*1024))
    require(review.get('signed') is True and review.get('formation_sha256')==selection['formation_sha256'],
            'Exact signed transport owner required')
    public={'genesis_sha256':'network/genesis.json','authority_sha256':'network/authority.json',
            'registry_sha256':'network/transport-registry.json','issuer_root_sha256':'network/transport-root.pub'}
    pins=policy.get('validator_commissioning_files',{})
    for key,name in public.items():
        require(_is_digest(review.get(key)) and pins.get(name)==review[key]
                and _sha(c.direct(c.root/name,True,4*1024*1024).read_bytes())==review[key],
                'Gateway origin differs from exact approved installed public files')
    _gateway_authority_root(c,policy)
    scope={k:selection[k] for k in ('formation_sha256','network_id','chain_id')}
    scope.update({k:review[k] for k in ('genesis_sha256','authority_sha256','registry_sha256')})
    return policy,scope,review,args,flags


def _gateway_approval(c,policy,scope,review,historical=False):
    pin=policy.get('authorization_files',{}).get(GATEWAY_APPROVAL)
    require(_is_digest(pin),'Exact additional gateway purpose approval is required')
    path=c.control/'authorization/inputs'/GATEWAY_APPROVAL
    raw=c.direct(path,True,16384).read_bytes()
    require(_sha(raw)==pin,'Gateway purpose artifact changed')
    a=json.loads(raw,object_pairs_hook=_unique_fields)
    expected={'format','purpose','formation_sha256','transport_review_sha256','issuer_root_sha256','gateway_enrollment_sha256',
              'genesis_sha256','authority_sha256','registry_sha256','valid_from_unix','expires_at_unix'}
    import time
    require(isinstance(a,dict) and set(a)==expected and a['format']=='synergy-engineering-gateway-purpose-v1'
            and a['purpose']==GATEWAY_PURPOSE and all(_is_digest(a[k]) for k in expected-{'format','purpose','valid_from_unix','expires_at_unix'})
            and all(a[k]==scope[k] for k in ('formation_sha256','genesis_sha256','authority_sha256','registry_sha256'))
            and a['transport_review_sha256']==review['review_sha256'] and a['issuer_root_sha256']==review['issuer_root_sha256']
            and type(a['valid_from_unix']) is int and type(a['expires_at_unix']) is int
            and 0<a['valid_from_unix']<a['expires_at_unix']<2**53
            and (historical or a['valid_from_unix']<=int(time.time())<a['expires_at_unix'])
            and a['expires_at_unix']-a['valid_from_unix']<=7*86400
            and review['valid_from_unix']<=a['valid_from_unix'] and a['expires_at_unix']<=review['expires_at_unix'],
            'Gateway purpose differs from the exact current formation owner')
    return path,pin,raw,a


def gateway_owner_available(c):
    try:_gateway_scope(c);return True
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):return False


def _gateway_attributed(c):
    import lifecycle as life
    life._attributed_units(c.root)
    # The isolated issuer is read-only; no validator/VPN service is changed.


def _gateway_preflight(c,p,args,flags,scope,review,policy):
    from controller import canonical,request_digest
    _gateway_attributed(c)
    require(not any((c.root/name).exists() or (c.root/name).is_symlink() for name in
                    (GATEWAY_DIRECTORY,GATEWAY_PREPARE_INTENT,GATEWAY_SIGN_INTENT)),
            'Gateway prepare exists or is uncertain; reconcile original request')
    path=c.control/'authorization/inputs'/GATEWAY_APPROVAL
    existing=policy.get('authorization_files',{}).get(GATEWAY_APPROVAL)
    if existing is None:
        require(not path.exists() and not path.is_symlink(),'Unapproved gateway purpose file requires reconciliation')
    else:
        require(existing==p['purpose_approval_sha256'] and c.direct(path,True,16384).read_bytes()==p['purpose_approval_json'].encode(),
                'Existing gateway purpose differs; no new authorization may replace it')
    prepared={'version':1,'operation':'gateway_admission_prepare','parameters':p}
    value=json.loads(native([c.root/'bin/synergy-keytool','check-gateway-admission',*args,*flags],data=_gateway_request_bytes(prepared),maximum_stdout=16384))
    expected={'schema','ready','request_sha256','formation_sha256','transport_review_sha256','issuer_root_sha256','purpose_approval_sha256',
              'genesis_sha256','authority_sha256','registry_sha256','gateway_enrollment_sha256','gateway_address','network_id','chain_id',
              'valid_from_unix','expires_at_unix','mutation_performed','services_started','public_listener','production_qualified'}
    require(isinstance(value,dict) and set(value)==expected and value['schema']=='nodenetwork-gateway-admission-preflight-v1'
            and value['ready'] is True and value['request_sha256']==request_digest(prepared)
            and all(value[k]==v for k,v in scope.items()) and value['transport_review_sha256']==review['review_sha256']
            and value['issuer_root_sha256']==review['issuer_root_sha256'] and value['purpose_approval_sha256']==p['purpose_approval_sha256']
            and value['gateway_enrollment_sha256']==_sha(p['gateway_enrollment_json'].encode())
            and all(value[k]==p[k] for k in ('valid_from_unix','expires_at_unix'))
            and all(value[k] is False for k in ('mutation_performed','services_started','public_listener','production_qualified')),
            'Gateway owner preflight differs')
    return value


def gateway_admission(c,request):
    """Fixed owner CLI only. No generic paths, secret export, grants or network I/O."""
    import lifecycle as life
    from controller import canonical,request_digest
    op=request['operation'];p=request['parameters'];gateway_parameters(op,p)
    with life._lifecycle_lock(c.root):
        try:policy,scope,review,args,flags=_gateway_scope(c,historical=op not in ('gateway_admission_prepare','gateway_admission_preflight','gateway_admission_sign'))
        except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
            if op=='gateway_admission_status':return _gateway_empty('gateway_runtime_or_origin_unavailable')
            raise ValueError('Qualified gateway owner and exact installed origin required') from None
        if op=='gateway_admission_preflight':return _gateway_preflight(c,p,args,flags,scope,review,policy)
        try:approval,pin,approval_raw,approved=_gateway_approval(c,policy,scope,review,historical=op not in ('gateway_admission_prepare','gateway_admission_sign'))
        except (ValueError,OSError,KeyError,TypeError):
            if op=='gateway_admission_status':return _gateway_empty('gateway_purpose_approval_required',scope)
            raise ValueError('Exact independently staged gateway purpose approval required') from None
        directory=c.root/GATEWAY_DIRECTORY;prepare=c.root/GATEWAY_PREPARE_INTENT;sign=c.root/GATEWAY_SIGN_INTENT
        prefix=[c.root/'bin/synergy-keytool'];owner=[*args,approval,pin]
        if op in ('gateway_admission_prepare','gateway_admission_sign'):
            _gateway_attributed(c)
            if op=='gateway_admission_prepare':
                require(not any(path.exists() or path.is_symlink() for path in (directory,prepare,sign)),
                        'Gateway prepare exists or is uncertain; reconcile original request')
                require(p['formation_sha256']==scope['formation_sha256'] and p['transport_review_sha256']==review['review_sha256']
                        and p['purpose_approval_sha256']==pin and p['purpose_approval_json'].encode()==approval_raw
                        and _sha(p['gateway_enrollment_json'].encode())==approved['gateway_enrollment_sha256']
                        and all(p[k]==approved[k] for k in ('valid_from_unix','expires_at_unix')),
                        'Gateway prepare differs from reviewed additional purpose')
                _gateway_preflight(c,p,args,flags,scope,review,policy)
                path=prepare;command='prepare-gateway-admission'
            else:
                current=_gateway_read(c,prefix,owner,flags,directory,prepare,sign,scope,pin)
                require(current['signed'] is False and current['review_sha256']==p['review_sha256'] and p['purpose_approval_sha256']==pin
                        and not sign.exists() and not sign.is_symlink(),'Gateway sign exists or exact review changed')
                path=sign;command='sign-gateway-admission'
            # The existing independently scoped one-use grant remains the only
            # mutation authorization. Intent is fsynced before invoking owner.
            c.authorize(request);raw=_gateway_request_bytes(request)
            with path.open('xb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
            life._sync_directory(path.parent)
            tail=[path,request_digest(request),directory] if op=='gateway_admission_prepare' else [directory,path,request_digest(request)]
            native([*prefix,command,*owner,*tail,*flags],maximum_stdout=128*1024)
        if op=='gateway_admission_status' and not any(path.exists() or path.is_symlink() for path in (directory,prepare,sign)):
            return _gateway_empty(None,scope)
        result=_gateway_read(c,prefix,owner,flags,directory,prepare,sign,scope,pin,export=op=='gateway_admission_export')
        if op=='gateway_admission_reconcile':require(p['request_sha256'] in (result['request_sha256'],result['sign_request_sha256']),
            'Gateway reconciliation does not match the retained original request')
        return result


def _gateway_consumed(c,request):
    from controller import MUTATIONS,request_digest
    import time
    key=request_digest(request);grant=c.control/'grants'/(key+'.json')
    require(not grant.exists() and not grant.is_symlink(),'Gateway original grant is not consumed')
    raw=c.direct(c.control/'audit.jsonl',True,1024*1024).read_bytes();rows=raw.splitlines()
    require(0<len(rows)<=4096,'Gateway audit exceeds bound');matched=0
    for line in rows:
        row=json.loads(line,object_pairs_hook=_unique_fields)
        require(isinstance(row,dict) and set(row)=={'request_sha256','operation','time'}
                and _is_digest(row['request_sha256']) and row['operation'] in MUTATIONS
                and type(row['time']) is int and 0<=row['time']<=int(time.time()),'Malformed gateway audit')
        if row['request_sha256']==key:
            require(row['operation']==request['operation'],'Gateway original audit differs');matched+=1
    require(matched==1,'Exact consumed gateway request audit required')


def _gateway_tree(c,directory,prepare,sign):
    from apqe_layout import require_frozen_tree
    require_frozen_tree(directory)
    signed=directory/'signed';has_signed=signed.exists() or signed.is_symlink()
    names={'request.json','review.json'}|({'signed/sign-request.json','signed/rpc-gateway-admission.json'} if has_signed else set())
    children=list(directory.rglob('*'))
    require({p.relative_to(directory).as_posix() for p in children if p.is_file()}==names
            and {p.relative_to(directory).as_posix() for p in children if p.is_dir()}==({'signed'} if has_signed else set()),
            'Gateway admission inventory is incomplete or unexpected')
    for path in (directory,*children):
        st=path.lstat()
        require(st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==(0o700 if path.is_dir() else 0o600)
                and (path.is_dir() or st.st_nlink==1),'Gateway admission private ownership or links differ')
    require((directory/'request.json').read_bytes()==c.direct(prepare,True,2*1024*1024).read_bytes(),
            'Gateway original prepare bytes changed')
    if has_signed:
        require((signed/'sign-request.json').read_bytes()==c.direct(sign,True).read_bytes(),
                'Gateway original sign bytes changed')
    else:require(not sign.exists() and not sign.is_symlink(),'Gateway signature outcome is uncertain')
    return {p.relative_to(c.root).as_posix() for p in (directory,*children,prepare,*([sign] if has_signed else []))}


def _gateway_read(c,prefix,owner,flags,directory,prepare,sign,scope,pin,export=False):
    _gateway_tree(c,directory,prepare,sign)
    from controller import parse_request,request_digest
    original=parse_request(c.direct(prepare,True,2*1024*1024).read_bytes())
    require(original['operation']=='gateway_admission_prepare','Gateway prepare intent differs')
    _gateway_consumed(c,original)
    result=json.loads(native([*prefix,'export-gateway-admission' if export else 'review-gateway-admission',*owner,directory,*flags],maximum_stdout=256*1024))
    require(isinstance(result,dict) and set(result)==GATEWAY_RESULT|({'admission_json'} if export else set())
            and result['schema']=='nodenetwork-gateway-admission-v1' and result['pending'] is True and type(result['signed']) is bool
            and all(result[k]==v for k,v in scope.items()) and result['request_sha256']==request_digest(original)
            and result['purpose_approval_sha256']==pin
            and all(_is_digest(result[k]) for k in ('review_sha256','gateway_enrollment_sha256'))
            and result['gateway_enrollment_sha256']==_sha(original['parameters']['gateway_enrollment_json'].encode())
            and all(result[k]==original['parameters'][k] for k in ('valid_from_unix','expires_at_unix'))
            and isinstance(result['gateway_address'],str) and len(result['gateway_address'])<=128 and re.fullmatch('synv5[0-9a-z]+',result['gateway_address'])
            and all(result[k] is False for k in
                ('gateway_commissioned','services_started','public_listener','production_qualified','automatic_retry')),
            'Gateway owner public review differs')
    if result['signed']:
        require(_is_digest(result['admission_sha256']) and _is_digest(result['sign_request_sha256']),'Gateway signed public pin differs')
        signed=parse_request(c.direct(sign,True).read_bytes())
        _gateway_consumed(c,signed)
        require(signed['operation']=='gateway_admission_sign' and request_digest(signed)==result['sign_request_sha256']
                and signed['parameters']=={'review_sha256':result['review_sha256'],'purpose_approval_sha256':pin},'Gateway sign intent differs')
    else:require(not sign.exists() and not sign.is_symlink() and result['sign_request_sha256'] is None and result['admission_sha256'] is None,
                 'Gateway signature outcome is uncertain')
    if export:require(result['signed'] and isinstance(result['admission_json'],str) and 0<len(result['admission_json'].encode())<=128*1024
                      and _sha(result['admission_json'].encode())==result['admission_sha256'],'Gateway public export differs')
    return {**result,'available':True,'blocker':None}

# Prospective target owner. No private artifacts enter or leave the controller wire.
GATEWAY_TARGET = 'tmp/gateway-target'
GATEWAY_TARGET_CAPABILITY = {'capability':'engineering-rpc-gateway-target-v1','local_custody_only':True,'production_qualified':False}
GATEWAY_TARGET_PUBLIC = {'genesis.json':4*1024*1024,'authority.json':1024*1024,'authority-root.pub':8192,
                        'network-manifest.json':1024*1024,'transport-registry.json':1024*1024,'transport-root.pub':8192}
GATEWAY_TARGET_KEYS = {'gateway-enrollment.json','gateway-transport.encrypted.json','gateway-identity.encrypted.json',
                       'gateway-transport.unlock','gateway-identity.unlock'}
GATEWAY_TARGET_COMMISSION = {'admission_json','admission_sha256','configuration_json','configuration_sha256'}


def gateway_target_parameters(operation,p):
    expected = {'genesis_sha256'} if operation=='gateway_target_generate' else GATEWAY_TARGET_COMMISSION if operation in ('gateway_target_commission','gateway_target_commission_preflight') else {'request_sha256'} if operation=='gateway_target_reconcile' else set()
    require(operation in {'gateway_target_preflight','gateway_target_status','gateway_target_export','gateway_target_configuration','gateway_target_generate','gateway_target_commission','gateway_target_commission_preflight','gateway_target_reconcile'} and isinstance(p,dict) and set(p)==expected,'Exact gateway target parameters required')
    for key in expected-{'admission_json','configuration_json'}:require(_is_digest(p[key]),'Exact gateway target digest required')
    for key,limit in (('admission_json',128*1024),('configuration_json',64*1024)):
        if key in p:
            require(isinstance(p[key],str) and 0<len(p[key].encode())<=limit and _sha(p[key].encode())==p[key.replace('_json','_sha256')],'Exact bounded public gateway bytes required')


def _gateway_target_result(state,scope=None,blocker=None,generated=None,commission=None):
    out={'schema':'nodenetwork-gateway-target-v1','available':blocker is None,'blocker':blocker,'state':state,
         **dict.fromkeys(('generation_request_sha256','commission_request_sha256','network_id','chain_id','genesis_sha256',
                        'gateway_address','enrollment_sha256','admission_sha256','configuration_sha256')),
         'transport_custody_verified':False,'services_started':False,'public_listener':False,'production_qualified':False,'automatic_retry':False}
    if scope:out.update({k:scope[k] for k in ('network_id','chain_id','genesis_sha256')})
    if generated:out.update(generation_request_sha256=generated['request_sha256'],gateway_address=generated['gateway_address'],enrollment_sha256=generated['enrollment_sha256'])
    if commission:out.update(commission_request_sha256=commission['request_sha256'],admission_sha256=commission['admission_sha256'],configuration_sha256=commission['configuration_sha256'],transport_custody_verified=True)
    return out


def _gateway_target_config(c,receipt,pins,source):
    root=c.root
    return {'schema_version':1,'node_name':receipt['node_name'],'role':'rpc_gateway','chain_id':_chain_id(receipt),'network_id':receipt['network_id'],
        'manifest_path':str(source/'network-manifest.json'),'genesis_path':str(source/'genesis.json'),
        'public_identity_path':str(root/'keys/apqe/gateway-enrollment.json'),'admin_socket_path':str(root/'run/admin.sock'),
        'aegis_provider':{'report_path':str(root/'lib/apqe/build-report.json'),'authenticated_report_sha256':pins['provider']},
        'apqe_transport':{'profile':'engineering_canary_pq_vsession_v1','registry_path':str(source/'transport-registry.json'),
            'registry_trust_key_path':str(source/'transport-root.pub'),'registry_trust_key_sha256':pins['transport-root.pub'],
            'genesis_trust_key_sha256':pins['authority-root.pub'],'enrollment_path':str(root/'keys/apqe/gateway-enrollment.json'),
            'custody_path':str(root/'keys/apqe/gateway-transport.encrypted.json'),'custody_unlock_path':str(root/'keys/apqe/gateway-transport.unlock')},
        'consensus':{'mode':'observe','authority_binding':str(source/'authority.json'),'authority_trust_key_path':str(source/'authority-root.pub'),
            'proposal_timeout_ms':2000,'round_timeout_ms':5000,'max_rounds_behind':64},
        'etdag':{'enabled':False,'protected_lookahead':5,'admission_queue_capacity':4096,'max_vertex_bytes':2097152,'proposal_material_wait_ms':1500},
        'rpc':{'enabled':False,'listen_address':None,'max_request_bytes':1048576,'max_concurrent_requests':256},
        'storage':{'data_directory':str(root/'data'),'wal_sync':'every_commit','max_open_files':128,'prune_finalized_history_after_blocks':64}}


def _gateway_profile(c, policy, receipt):
    approved = policy.get('authorization_files', {}).get(NETWORK_PROFILE)
    if approved is None:
        return None, None
    source = c.control/'authorization/inputs'/NETWORK_PROFILE
    raw = c.direct(source, True, 16384).read_bytes()
    require(_sha(raw) == approved, 'Network profile differs from its approved bytes')
    from synergy_linux import network_provisioning_profile
    profile = network_provisioning_profile(json.loads(raw, object_pairs_hook=_unique_fields), receipt)
    require(policy.get('gateway_origin_files') == {
        'network/'+name: pin for name, pin in profile['origin'].items()
    }, 'Network profile must use the exact signed gateway origin')
    return profile, raw


def _gateway_target_origin(c,policy,receipt,manifest,software):
    source=c.control/'authorization/inputs/commissioning/network';approved=policy.get('authorization_files',{})
    formation=c.direct(c.control/'authorization/inputs/formation-context.json',True,4096).read_bytes()
    context=json.loads(formation,object_pairs_hook=_unique_fields)
    require(_is_digest(policy.get('validator_formation_sha256')) and _sha(formation)==policy['validator_formation_sha256']==approved.get('formation-context.json')
            and isinstance(context,dict) and set(context)=={'network_id','chain_id_hex','formation_id'}
            and context['network_id']==receipt['network_id'] and context['chain_id_hex']==format(_chain_id(receipt),'064x')
            and _is_digest(context['formation_id']) and context['formation_id']!='0'*64,'Exact original formation context required')
    pins={name:approved.get('commissioning/network/'+name) for name in GATEWAY_TARGET_PUBLIC}
    require(policy.get('gateway_origin_files')=={'network/'+name:pin for name,pin in pins.items()},'Exact gateway public origin inventory required')
    raw={name:c.direct(source/name,True,limit).read_bytes() for name,limit in GATEWAY_TARGET_PUBLIC.items()}
    require(all(_is_digest(pins.get(name)) and _sha(value)==pins[name] for name,value in raw.items()),'Exact approved gateway public origin required')
    independent=policy.get('validator_identity_network',{})
    require(all(independent.get(name)==pins[name] for name in ('genesis.json','authority.json','authority-root.pub')),'Independent signed gateway Genesis pins required')
    pins={name:pins[name] for name in GATEWAY_TARGET_PUBLIC};pins['provider']=manifest['files'].get('lib/apqe/build-report.json')
    require(_is_digest(pins['provider']),'Qualified gateway provider required')
    config=_gateway_target_config(c,receipt,pins,source)
    config['aegis_provider']['report_path']=str(software/'lib/apqe/build-report.json')
    scope=json.loads(native([software/'bin/synergy-node','canary-rpc-relay','inspect-origin'],data=_gateway_request_bytes(config),maximum_stdout=8192))
    fields={'schema','network_id','chain_id','mutation_performed','genesis_sha256','authority_sha256','authority_root_sha256','registry_sha256','issuer_root_sha256','manifest_sha256'}
    require(isinstance(scope,dict) and set(scope)==fields and scope['schema']=='nodenetwork-gateway-origin-v1'
            and scope['network_id']==receipt['network_id'] and scope['chain_id']==str(_chain_id(receipt)) and scope['mutation_performed'] is False
            and all(scope[key]==pins[name] for key,name in (('genesis_sha256','genesis.json'),('authority_sha256','authority.json'),('authority_root_sha256','authority-root.pub'),('registry_sha256','transport-registry.json'),('issuer_root_sha256','transport-root.pub'),('manifest_sha256','network-manifest.json'))),'Native gateway origin differs')
    profile, _ = _gateway_profile(c, policy, receipt)
    if profile is not None:
        authorized_manifest = json.loads(raw['network-manifest.json'], object_pairs_hook=_unique_fields)
        require(authorized_manifest['genesis_hash'] == profile['genesis_hash'],
                'Network profile logical Genesis differs from authenticated origin')
        entries = json.loads(raw['transport-registry.json'], object_pairs_hook=_unique_fields)['payload']['validators']
        upstream = profile['gateway']['validator_address']
        require(sum(entry.get('node_address') == upstream and entry.get('revoked') is False
                    for entry in entries) == 1, 'Network profile upstream is not in the signed transport registry')
    return pins,raw,config,scope


def _gateway_target_scope(c):
    import lifecycle as life
    receipt,manifest=life._sealed_receipt(c.root)
    policy=c.policy()
    require(receipt['role']=='rpc_gateway' and _is_digest(policy.get('engineering_initial_authorization_sha256')),'Exact engineering gateway installation required')
    from controller import engineering_effective_selection
    selection=engineering_effective_selection(c.root,policy)
    require(selection is not None and all(selection[k]==receipt[k] for k in ('network_id','chain_id','node_name')),'Gateway installed selection differs')
    require(json.loads(native([c.root/'bin/synergy-node','canary-rpc-relay','target-capability'],maximum_stdout=4096))==GATEWAY_TARGET_CAPABILITY,'Qualified gateway target owner unavailable')
    pins,raw,config,scope=_gateway_target_origin(c,policy,receipt,manifest,c.root)
    _gateway_target_services(c)
    return policy,receipt,pins,raw,config,scope



def _gateway_target_services(c):
    import lifecycle as life
    if life._integration_plan(c.root) is None:
        for unit in (*life.UNITS,life.RELAY_UNIT):
            state=life._unit_state(unit)
            require(state.get('LoadState')=='not-found' and not state.get('FragmentPath') and state.get('MainPID','0') in ('','0'),
                    'Unattributed gateway service already exists')
    else:life._attributed_units(c.root)


def _gateway_target_quiescent(c):
    import lifecycle as life
    _gateway_target_services(c)
    if life._integration_plan(c.root) is not None:
        for state in life._attributed_units(c.root).values():
            require(state.get('ActiveState') in ('inactive','failed') and state.get('MainPID')=='0','Gateway target services must remain stopped')
    life._assert_no_application_processes(c.root)
    require(not any(_exists(c.root/name) for name in ('data','tmp/commissioning','evidence/upgrade-intent.json','evidence/application-replacement-intent.json',
            'evidence/authority-recovery-intent.json','evidence/autonomous-epoch-intent.json')),'Gateway target application lifecycle is not quiescent')


def _gateway_target_unpublished(c):
    for name in ('config','network'):
        folder=c.root/name;meta=folder.lstat()
        require(stat.S_ISDIR(meta.st_mode) and not folder.is_symlink() and meta.st_uid==os.geteuid()
                and stat.S_IMODE(meta.st_mode)==0o700 and not any(folder.iterdir()),'Gateway target public outputs already exist')


def _gateway_target_write(c,path,raw):
    require(not path.exists() and not path.is_symlink(),'Gateway target output already exists')
    require(c.root in path.parents and '..' not in path.parts,'Gateway output escapes root')
    parent=c.root
    for component in (None,*path.parent.relative_to(c.root).parts):
        if component is not None:
            parent=parent/component
            if not _exists(parent):parent.mkdir(mode=0o700)
        meta=parent.lstat()
        require(stat.S_ISDIR(meta.st_mode) and not parent.is_symlink() and meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700,'Unsafe gateway output ancestry')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:
        import lifecycle
        lifecycle._sync_directory(path.parent)


def _gateway_target_read(c,path,maximum=256*1024):
    return json.loads(c.direct(path,True,maximum).read_bytes(),object_pairs_hook=_unique_fields)


def _gateway_target_consumed(c,operation,digest):
    require(_is_digest(digest),'Exact retained gateway request required')
    require(not _exists(c.control/'grants'/(digest+'.json')),'Gateway target grant remains unused')
    path=c.control/'audit.jsonl';raw=c.direct(path,True,4*1024*1024).read_bytes()
    found=[]
    for line in raw.splitlines():
        row=json.loads(line,object_pairs_hook=_unique_fields)
        require(isinstance(row,dict) and set(row)=={'operation','request_sha256','time'} and type(row['time']) is int and row['time']>0 and isinstance(row['operation'],str) and _is_digest(row['request_sha256']),'Malformed gateway audit')
        if row['request_sha256']==digest:found.append(row)
    require(len(found)==1 and found[0]['operation']==operation,'Exact consumed gateway target request required')


def _gateway_target_generated(c,config,scope):
    directory=c.root/GATEWAY_TARGET
    keys=c.root/'keys';meta=keys.lstat()
    require(stat.S_ISDIR(meta.st_mode) and not keys.is_symlink() and meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700,'Private direct gateway keys root required')
    if not _exists(directory/'generate-request.json'):
        require(not _exists(directory) and not any((c.root/'keys').rglob('*')),'Unknown gateway target custody or staging')
        return None
    allowed={'generate-request.json','origin-config.json','generated.json','commission-request.json','commissioned.json'}
    require(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()}<=allowed,'Unknown gateway target staging member')
    require(c.direct(directory/'origin-config.json',True,65536).read_bytes()==_gateway_request_bytes(config),'Gateway origin configuration changed')
    request=_gateway_target_read(c,directory/'generate-request.json');gateway_target_parameters(request['operation'],request['parameters'])
    require(set(request)=={'version','operation','parameters'} and request['version']==1 and request['operation']=='gateway_target_generate'
            and request['parameters']['genesis_sha256']==scope['genesis_sha256'],'Retained gateway generation request differs')
    from controller import request_digest
    key=request_digest(request);_gateway_target_consumed(c,'gateway_target_generate',key)
    receipt=_gateway_target_read(c,directory/'generated.json')
    require(set(receipt)=={'request_sha256','gateway_address','enrollment_sha256','files'} and receipt['request_sha256']==key
            and set(receipt['files'])==GATEWAY_TARGET_KEYS,'Incomplete gateway generation receipt')
    base=c.root/'keys/apqe'
    for folder in (directory,c.root/'keys',base):
        meta=folder.lstat()
        require(stat.S_ISDIR(meta.st_mode) and not folder.is_symlink() and meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700,'Private direct gateway directories required')
    require({p.name for p in (c.root/'keys').iterdir()}=={'apqe'},'Unknown target key directory')
    require(base.is_dir() and not base.is_symlink() and {p.name for p in base.iterdir()}==GATEWAY_TARGET_KEYS,'Exact target custody inventory required')
    for name,pin in receipt['files'].items():require(_is_digest(pin) and _sha(c.direct(base/name,True,256*1024).read_bytes())==pin,'Gateway custody changed')
    enrollment=c.direct(base/'gateway-enrollment.json',True,128*1024).read_bytes()
    checked=json.loads(native([c.root/'bin/synergy-node','canary-rpc-relay','inspect-target-enrollment'],data=_gateway_request_bytes({'node_configuration':config,'enrollment_json':enrollment.decode()}),maximum_stdout=4096))
    require(isinstance(checked,dict) and checked.get('mutation_performed') is False and checked=={'gateway_address':receipt['gateway_address'],'enrollment_sha256':_sha(enrollment),'mutation_performed':False}
            and receipt['enrollment_sha256']==_sha(enrollment) and re.fullmatch('synv5[0-9a-z]+',receipt['gateway_address']),'Native target enrollment differs')
    return receipt


def _gateway_target_candidate(c,p,receipt,pins,config,generated):
    require(generated is not None,'Generate the target gateway identity first')
    wrapper=json.loads(p['configuration_json'],object_pairs_hook=_unique_fields)
    require(isinstance(wrapper,dict) and set(wrapper)=={'node_configuration','relay_specification'},'Exact gateway configuration wrapper required')
    final=_gateway_target_config(c,receipt,pins,c.root/'network')
    # Comparing complete canonical defaults prevents arbitrary service/path/provider controls.
    require(wrapper['node_configuration']==final,'Exact contained observer configuration required')
    spec=wrapper['relay_specification'];relay=configuration(c.root,spec)
    profile, _ = _gateway_profile(c, c.policy(), receipt)
    if profile is not None:
        from synergy_linux import gateway_profile_relay
        require(spec == gateway_profile_relay(profile['gateway'], generated['gateway_address']),
                'Relay settings differ from the approved network profile')
    require(relay['role']['kind']=='gateway' and relay['role']['gateway_address']==generated['gateway_address']
            and BOOTSTRAP_PIN not in relay['role'],'Exact fresh signed-origin gateway relay required')
    candidate=json.loads(json.dumps(relay))
    checked=json.loads(native([c.root/'bin/synergy-node','canary-rpc-relay','inspect-target-candidate'],data=_gateway_request_bytes({'node_configuration':config,'relay_configuration':candidate,'admission_json':p['admission_json']}),maximum_stdout=4096))
    require(isinstance(checked,dict) and checked.get('transport_custody_verified') is True and checked.get('mutation_performed') is False and checked=={'transport_custody_verified':True,'mutation_performed':False},'Native gateway admission/custody not proven')
    return final,relay


def _gateway_target_status(c,parts,export=False):
    policy,receipt,pins,raw,config,scope=parts
    generated=_gateway_target_generated(c,config,scope)
    if generated is None:
        _gateway_target_unpublished(c)
        require(c.policy()==policy,'Gateway target authorization changed during review')
        result=_gateway_target_result('ready',scope)
        if export:result['enrollment_json']=None
        return result
    directory=c.root/GATEWAY_TARGET;record=None
    if _exists(directory/'commission-request.json'):
        q=_gateway_target_read(c,directory/'commission-request.json',256*1024);gateway_target_parameters(q['operation'],q['parameters'])
        from controller import request_digest
        key=request_digest(q);_gateway_target_consumed(c,'gateway_target_commission',key)
        require(q['operation']=='gateway_target_commission' and q['version']==1 and set(q)=={'version','operation','parameters'},'Retained gateway commission request differs')
        require(_exists(directory/'commissioned.json') and receipt.get('gateway_commissioned') is True,'Gateway commission requires reconciliation')
        record=_gateway_target_read(c,directory/'commissioned.json')
        require(record=={'request_sha256':key,'admission_sha256':q['parameters']['admission_sha256'],'configuration_sha256':q['parameters']['configuration_sha256']},'Gateway commission receipt differs')
        final,relay=_gateway_target_candidate(c,q['parameters'],receipt,pins,config,generated)
        expected={'config/node.json':_gateway_request_bytes(final),'config/canary-rpc-relay.json':_gateway_request_bytes(relay),
                  'network/rpc-gateway-admission.json':q['parameters']['admission_json'].encode(),**{'network/'+k:v for k,v in raw.items()}}
        _, profile_raw = _gateway_profile(c, policy, receipt)
        if profile_raw is not None:
            expected['config/'+NETWORK_PROFILE] = profile_raw
        require(all(c.direct(c.root/name,True,4*1024*1024).read_bytes()==value for name,value in expected.items()),'Installed gateway public files differ')
    if record is None:
        require(receipt.get('gateway_commissioned') is not True,'Gateway installation has an unmatched commission marker')
        _gateway_target_unpublished(c)
    require(c.policy()==policy,'Gateway target authorization changed during review')
    result=_gateway_target_result('commissioned' if record else 'identity_ready',scope,generated=generated,commission=record)
    if export:result['enrollment_json']=c.direct(c.root/'keys/apqe/gateway-enrollment.json',True,128*1024).read_bytes().decode()
    return result


def gateway_target(c,request):
    import lifecycle as life
    from controller import request_digest
    op=request['operation'];p=request['parameters'];gateway_target_parameters(op,p)
    with life._lifecycle_lock(c.root):
        try:parts=_gateway_target_scope(c)
        except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
            if op in ('gateway_target_preflight','gateway_target_status','gateway_target_export'):
                result=_gateway_target_result('absent',blocker='owner_unavailable' if not _exists(c.root/'installation.json') else 'origin_required')
                if op=='gateway_target_export':result['enrollment_json']=None
                return result
            raise
        policy,receipt,pins,raw,config,scope=parts
        try:
            if op=='gateway_target_preflight':_gateway_target_quiescent(c)
            state=_gateway_target_status(c,parts,op=='gateway_target_export')
        except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
            if op in ('gateway_target_preflight','gateway_target_status','gateway_target_export'):
                result=_gateway_target_result('uncertain',blocker='reconciliation_required')
                if op=='gateway_target_export':result['enrollment_json']=None
                return result
            raise
        if op in ('gateway_target_preflight','gateway_target_status','gateway_target_export'):return state
        if op == 'gateway_target_configuration':
            profile, profile_raw = _gateway_profile(c, policy, receipt)
            require(profile is not None and state['state'] in ('identity_ready', 'commissioned'),
                    'An approved profile and verified gateway identity are required')
            from synergy_linux import gateway_profile_relay
            wrapper = {
                'node_configuration': _gateway_target_config(c, receipt, pins, c.root/'network'),
                'relay_specification': gateway_profile_relay(profile['gateway'], state['gateway_address']),
            }
            return {
                'schema': 'nodenetwork-gateway-profile-configuration-v1',
                'profile': profile,
                'profile_json': profile_raw.decode('utf-8'),
                'profile_sha256': _sha(profile_raw),
                'configuration_json': _gateway_request_bytes(wrapper).decode(),
                'installed': state['state'] == 'commissioned',
            }
        if op=='gateway_target_reconcile':
            require(state['state'] in ('identity_ready','commissioned') and p['request_sha256'] in (state['generation_request_sha256'],state['commission_request_sha256']),'Exact verified target outcome required')
            return state
        _gateway_target_quiescent(c)
        if op=='gateway_target_generate':
            require(state['state']=='ready' and p['genesis_sha256']==scope['genesis_sha256'],'Exact fresh gateway generation scope required')
            c.authorize(request);directory=c.root/GATEWAY_TARGET
            _gateway_target_write(c,directory/'generate-request.json',_gateway_request_bytes(request))
            # Both unlocks stay contained; APQE owns all key generation/envelope handling.
            for name in ('gateway-transport.unlock','gateway-identity.unlock'):_gateway_target_write(c,directory/name,os.urandom(48).hex().encode())
            cfg=directory/'origin-config.json';_gateway_target_write(c,cfg,_gateway_request_bytes(config))
            base=c.root/'keys/apqe'
            native([c.root/'bin/synergy-node','canary-rpc-relay','provision',cfg,base,directory/'gateway-transport.unlock',directory/'gateway-identity.unlock'])
            for name in ('gateway-transport.unlock','gateway-identity.unlock'):os.rename(directory/name,base/name)
            life._sync_directory(directory);life._sync_directory(base)
            enrollment=c.direct(base/'gateway-enrollment.json',True,128*1024).read_bytes();value=json.loads(enrollment)
            result={'request_sha256':request_digest(request),'gateway_address':value['payload']['node_address'],'enrollment_sha256':_sha(enrollment),
                    'files':{name:_sha(c.direct(base/name,True,256*1024).read_bytes()) for name in GATEWAY_TARGET_KEYS}}
            _gateway_target_write(c,directory/'generated.json',_gateway_request_bytes(result))
            return _gateway_target_status(c,parts)
        generated=_gateway_target_generated(c,config,scope)
        require(state['state']=='identity_ready','Gateway target is already commissioned or uncertain')
        _gateway_target_unpublished(c)
        final,relay=_gateway_target_candidate(c,p,receipt,pins,config,generated)
        if op=='gateway_target_commission_preflight':
            future={'version':1,'operation':'gateway_target_commission','parameters':p}
            return {'schema':'nodenetwork-gateway-target-commission-preflight-v1','ready':True,'request_sha256':request_digest(future),
                    **{k:scope[k] for k in ('network_id','chain_id','genesis_sha256')},'gateway_address':generated['gateway_address'],
                    'enrollment_sha256':generated['enrollment_sha256'],'admission_sha256':p['admission_sha256'],'configuration_sha256':p['configuration_sha256'],
                    'transport_custody_verified':True,'mutation_performed':False,'services_started':False,'public_listener':False,'production_qualified':False}
        c.authorize(request);directory=c.root/GATEWAY_TARGET
        _gateway_target_write(c,directory/'commission-request.json',_gateway_request_bytes(request))
        files = {**{'network/'+k:v for k,v in raw.items()},'config/node.json':_gateway_request_bytes(final),
                 CONFIG:_gateway_request_bytes(relay),'network/rpc-gateway-admission.json':p['admission_json'].encode()}
        _, profile_raw = _gateway_profile(c, policy, receipt)
        if profile_raw is not None:
            files['config/'+NETWORK_PROFILE] = profile_raw
        for name,value in files.items():
            _gateway_target_write(c,c.root/name,value)
        native([c.root/'bin/synergy-node','canary-rpc-relay','check',c.root/CONFIG])
        life._replace_bytes(c.root,c.root/'installation.json',_gateway_request_bytes(dict(receipt,gateway_commissioned=True)),0o600,request_digest(request))
        record={'request_sha256':request_digest(request),'admission_sha256':p['admission_sha256'],'configuration_sha256':p['configuration_sha256']}
        _gateway_target_write(c,directory/'commissioned.json',_gateway_request_bytes(record))
        return _gateway_target_status(c,_gateway_target_scope(c))


def gateway_install(c,request):
    import lifecycle as life
    from synergy_linux import install
    from controller import request_digest
    op=request['operation'];p=request['parameters']
    with life._lifecycle_lock(c.root):
        if op=='gateway_install_status':
            original=_gateway_target_read(c,c.control/'gateway-install-request.json',16384)
            require(original['operation']=='gateway_install' and request_digest(original)==p['request_sha256'],'Original gateway install differs')
            from controller import parse_request
            require(parse_request(_gateway_request_bytes(original))==original,'Exact original gateway install required')
            _gateway_target_consumed(c,'gateway_install',p['request_sha256'])
            parts=_gateway_target_scope(c);receipt=parts[1];manifest=life._sealed_receipt(c.root)[1]
            expected=original['parameters']
            require(receipt['package_sha256']==expected['manifest_sha256'] and manifest['release_id']==expected['release_id']
                    and all(receipt[k]==expected[k] for k in ('network_id','chain_id','node_name')),'Installed gateway differs from original request')
            fields={'format','root','role','network_id','chain_id','node_name','package_sha256','package_files','host_integrations','consensus_started'}
            require(set(receipt) in (fields,fields|{'gateway_commissioned'}),'Gateway installation receipt fields differ')
            if 'gateway_commissioned' in receipt:
                require(receipt['gateway_commissioned'] is True and _gateway_target_status(c,parts)['state']=='commissioned','Gateway installation commission marker differs')
                receipt={k:v for k,v in receipt.items() if k!='gateway_commissioned'}
            return {'schema':'nodenetwork-gateway-install-status-v1','request_sha256':p['request_sha256'],'request':original,
                    'installation':receipt,'origin_verified':True,'install_audit_verified':True,'grant_absent':True,'services_started':False}
        package,manifest,approval=c.approved_package(p,bootstrap=True)
        require(approval.get('networks',{}).get(p['network_id'])==_chain_id(p),'Network not approved for selected release')
        require('rpc_gateway' in read(package/'roles/roles.json')['implemented'],'Qualified gateway role missing')
        require(json.loads(native([package/'bin/synergy-node','canary-rpc-relay','target-capability'],maximum_stdout=4096))==GATEWAY_TARGET_CAPABILITY,'Qualified gateway target owner unavailable')
        receipt={k:p[k] for k in ('network_id','chain_id','node_name')};receipt['role']='rpc_gateway'
        _gateway_target_origin(c,c.policy(),receipt,manifest,package)
        # No service registration may be borrowed from another installation.
        _gateway_target_services(c)
        # Match install's exact fresh-root closure before readiness or grant use;
        # co-resident state must never be merged. Install rechecks before copy.
        from synergy_linux import _staged_master
        _staged_master(c.root,package,p['manifest_sha256'])
        if op=='gateway_install_preflight':return {'packageVerified':True,'release':manifest['release_id'],'root':str(c.root),'networkSelectionApproved':True,'genesisAuthorityVerified':False,'activationAuthorized':False}
        require(not _exists(c.control/'gateway-install-request.json'),'Reconcile original gateway installation before another request')
        c.authorize(request)
        _gateway_target_write(c,c.control/'gateway-install-request.json',_gateway_request_bytes(request))
        return install(package,c.root,'rpc_gateway',p['network_id'],p['chain_id'],p['node_name'],staged_master_sha256=p['manifest_sha256'])


def gateway_target_available(c):
    try:
        import lifecycle as life
        if _exists(c.root/'installation.json'):
            receipt,_=life._sealed_receipt(c.root)
            if receipt['role']!='rpc_gateway':return False
            package=c.root
        else:
            selection=c.policy().get('engineering_selection')
            require(isinstance(selection,dict),'Exact staged selection required')
            package,_,_=c.approved_package(selection,bootstrap=True)
        return json.loads(native([package/'bin/synergy-node','canary-rpc-relay','target-capability'],maximum_stdout=4096))==GATEWAY_TARGET_CAPABILITY
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):return False


def approved_gateway_target_members(root):
    from controller import Controller
    c=Controller(root);directory=root/GATEWAY_TARGET;approved=set()
    if not _exists(directory):return approved
    parts=_gateway_target_scope(c)
    state=_gateway_target_status(c,parts)
    require(state['state'] in ('identity_ready','commissioned'),'Unverified gateway target state')
    expected={'generate-request.json','origin-config.json','generated.json'}
    if state['state']=='commissioned':expected|={'commission-request.json','commissioned.json'}
    require({p.name for p in directory.iterdir()}==expected,'Unknown gateway target member')
    for name in expected:c.direct(directory/name,True,256*1024);approved.add(str(Path(GATEWAY_TARGET)/name))
    approved.update(str(Path('keys/apqe')/name) for name in GATEWAY_TARGET_KEYS)
    approved.update({GATEWAY_TARGET,'keys/apqe'})
    if state['state'] == 'commissioned' and _gateway_profile(c, parts[0], parts[1])[0] is not None:
        approved.add('config/'+NETWORK_PROFILE)
    return approved


def gateway_upstream_tcp(role, validators):
    """Combine the signed transport peer IP with the reviewed RPC relay port."""
    from vpn_authorization import gateway_tcp

    require(role['kind'] == 'gateway', 'Exact gateway relay required')
    require(isinstance(validators, list) and 0 < len(validators) <= 128, 'Bounded signed transport roster required')
    matches = [entry for entry in validators if entry.get('node_address') == role['validator_address']]
    require(len(matches) == 1 and matches[0].get('revoked') is False, 'Selected signed validator is not uniquely active')
    address, transport_port = matches[0]['dial_address'].rsplit(':', 1)
    require(transport_port.isdecimal() and 0 < int(transport_port) <= 65535,
            'Signed validator endpoint differs')
    tcp = gateway_tcp({'ip': str(ipaddress.ip_address(address.strip('[]'))), 'port': role['validator_relay_port']})
    require(tcp['port'] != int(transport_port), 'Gateway RPC relay must use a different port from validator P2P')
    return tcp


def _gateway_selected_tcp(c):
    role = c.public_json(c.root/CONFIG, True)['role']
    validators = c.public_json(c.root/'network/transport-registry.json', True)['payload']['validators']
    return gateway_upstream_tcp(role, validators)


def gateway_relay_ready_locked(c, owned):
    """Check online relay prerequisites under the controller lifecycle lock."""
    import lifecycle as life
    from vpn import verify_gateway_route

    node=owned.get(life.UNITS[0],{})
    require(node.get('ActiveState') in ('inactive','failed') and node.get('MainPID')=='0','Gateway must never run the validator service')
    require(life.RELAY_UNIT in owned,'Register the exact gateway relay before starting')
    current=c.vpn_status()
    require(current['service_registered'] and current['enrollment_recorded'] and current['server_bound'] and current['connected']
            and not current['reconciliation_required'] and not current['retired'],'Existing bound gateway VPN must be connected')
    local=c.public_json(c.root/'evidence/vpn-enrollment.json',True)
    require(local.get('required_gateway_tcp')==_gateway_selected_tcp(c),'VPN target differs from selected signed validator')
    verify_gateway_route(c.root,persist=False,locked=True)
    life._relay_start_check_locked(c.root)


def gateway_lifecycle(c,request):
    """Existing host operations with an explicit relay-only gateway role branch."""
    import lifecycle as life
    life._require_operator(linux=False)
    op=request['operation'];require(op in ('register','start','stop','restart','health') and not request['parameters'],'Exact gateway lifecycle operation required')
    with life._lifecycle_lock(c.root):
        receipt,_=life._sealed_receipt(c.root)
        require(receipt.get('role')=='rpc_gateway','Engineering gateway role required')
        _chain_id(receipt)
        _gateway_target_services(c)
        if op=='stop':
            owned=life._attributed_units(c.root)
            require(life.RELAY_UNIT in owned,'Attributed gateway relay registration required')
        else:
            require(receipt.get('gateway_commissioned') is True and _exists(c.root/GATEWAY_TARGET/'commissioned.json'),'Commission fresh gateway custody before service operations')
            validate_gateway_layout(c.root)
            owned=life._attributed_units(c.root) if life._integration_plan(c.root) is not None else {}
            if op=='health':
                relay=owned.get(life.RELAY_UNIT);current=c.vpn_status()
                states={'active','inactive','failed','activating','deactivating','reloading','maintenance','refreshing'}
                state='unregistered' if relay is None else relay.get('ActiveState')
                require(state=='unregistered' or state in states,'Gateway relay state unavailable')
                pid=None if relay is None else relay.get('MainPID')
                require(pid is None or isinstance(pid,str) and pid.isdecimal() and int(pid)<=2**53-1,'Gateway relay PID unavailable')
                return {'schema':'nodenetwork-gateway-health-v1','observed_at_ms':int(time.time()*1000),'role':'rpc_gateway',
                        'relay':{'unit':life.RELAY_UNIT,'state':state,'pid':None if pid is None else int(pid)},
                        'vpn':{'registered':current['service_registered'],'enrollment_recorded':current['enrollment_recorded'],
                               'server_bound':current['server_bound'],'connected':current['connected']},
                        'admission_custody_verified':True,'consensus_participant':False,'configured_loopback':True,'production_qualified':False}
            if op in ('start','restart'):
                gateway_relay_ready_locked(c, owned)
        c.authorize(request)
    # ExecStartPre acquires the same lifecycle lock in its own process. Never
    # hold that lock across systemctl or registration's own locked transaction.
    if op=='register':return life.register(c.root)
    life.mutate_owned_service(c.root,op,life.RELAY_UNIT)
    return {'requested':op,'healthNotInferred':True}


def gateway_vpn_enrollment_scope(c,receipt,secret_input):
    """Pure gateway-specific provider scope before a one-use enrollment grant."""
    from vpn_authorization import provider_policy,GATEWAY_PROFILE,decode,network_scope
    require(receipt.get('role')=='rpc_gateway' and receipt.get('gateway_commissioned') is True
            and _exists(c.root/GATEWAY_TARGET/'commissioned.json'),'Commission gateway custody before VPN enrollment')
    validate_gateway_layout(c.root)
    path=c.control/'authorization/inputs/vpn-provider.json'
    raw=c.direct(path,True,16384).read_bytes();ca=c.direct(c.control/'authorization/inputs/vpn-ca.pem',True,128*1024).read_bytes()
    installed_policy = c.policy()
    provider_pin = installed_policy.get('authorization_files', {}).get('vpn-provider.json')
    profile, _ = _gateway_profile(c, installed_policy, receipt)
    require(profile is None or profile['gateway']['vpn_provider_sha256'] == provider_pin,
            'VPN provider differs from the installed network profile')
    policy=provider_policy(raw,provider_pin,ca,int(time.time()))
    require(policy['profile']==GATEWAY_PROFILE,'Gateway requires independently approved restricted VPN profile')
    network_scope(policy,c.vpn_provider_binding())
    target=_gateway_selected_tcp(c)
    request=decode(secret_input)
    require(policy['required_gateway_tcp']==target and isinstance(request,dict)
            and set(request)=={'setup_key','management_url','hostname','required_gateway_tcp'}
            and request['required_gateway_tcp']==target and request['management_url']==policy['management_origin'],
            'Enrollment differs from exact signed gateway TCP/provider scope')
    return target


def gateway_vpn_parameters(parameters):
    from vpn_authorization import gateway_tcp
    require(isinstance(parameters, dict) and set(parameters) == {'required_gateway_tcp'},
            'Exact gateway TCP parameter required')
    return gateway_tcp(parameters['required_gateway_tcp'])


def gateway_vpn_preflight(c,parameters):
    import lifecycle as life
    target=gateway_vpn_parameters(parameters)
    with life._lifecycle_lock(c.root):
        receipt,_=life._sealed_receipt(c.root)
        require(receipt.get('role')=='rpc_gateway' and receipt.get('gateway_commissioned') is True
                and _exists(c.root/GATEWAY_TARGET/'commissioned.json'),'Commission gateway custody before VPN provider use')
        validate_gateway_layout(c.root)
        require(target==_gateway_selected_tcp(c),'Provider target differs from selected signed validator')
        genesis=_sha(c.direct(c.root/'network/genesis.json',True,4*1024*1024).read_bytes())
        require(c.policy().get('validator_identity_network',{}).get('genesis.json')==genesis,'Independent gateway Genesis differs')
        return {'schema':'nodenetwork-gateway-vpn-preflight-v1','required_gateway_tcp':target,
                'network_id':receipt['network_id'],'chain_id':str(_chain_id(receipt)),'genesis_sha256':genesis,
                'mutation_performed':False,'production_qualified':False}


def gateway_vpn_recovery_scope(c,receipt,provider):
    from vpn_authorization import GATEWAY_PROFILE,network_scope
    require(receipt.get('role')=='rpc_gateway' and receipt.get('gateway_commissioned') is True
            and _exists(c.root/GATEWAY_TARGET/'commissioned.json'),'Existing gateway custody required for VPN recovery')
    validate_gateway_layout(c.root)
    require(provider.get('profile')==GATEWAY_PROFILE,'Original restricted gateway VPN provider required')
    network_scope(provider,c.vpn_provider_binding())
    require(provider.get('required_gateway_tcp')==_gateway_selected_tcp(c),'Original gateway VPN target differs')
