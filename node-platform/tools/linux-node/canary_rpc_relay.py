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
import stat
import subprocess
import sys
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
from synergy_linux import read, require, native

CONFIG = 'config/canary-rpc-relay.json'
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
        require(receipt.get('role') == 'rpc_gateway' and receipt.get('chain_id') == 99999
                and receipt.get('gateway_commissioned') is True, 'commissioned Canary gateway required')
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
            and receipt['chain_id']==99999 and policy.get('engineering_target',{}).get('guest') is None,
            'Engineering formation issuer on the exact physical Canary required')
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
    require(selection['network_id']==receipt['network_id'] and selection['chain_id']=='99999','Gateway formation differs from installed scope')
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
