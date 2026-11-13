#!/usr/bin/env python3
"""Unattended application-owned NetBird enrollment. One-use input arrives on stdin.

No browser flow, reusable enrollment key or management API token is installed.
The coordinator retains the management credential and binds the returned public
WireGuard key to the newly registered server peer before accepting completion.
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from urllib.parse import urlparse
sys.dont_write_bytecode = True
from synergy_linux import native, read, require, safe_root, write_new


def status(root, timeout=8):
    j = json.loads(native([root / 'tools/netbird-client', 'status', '--json'], timeout=timeout))
    require(j['management']['connected'] and j['signal']['connected'], 'management or signal disconnected')
    require(j['publicKey'] and j['netbirdIp'], 'native VPN identity/address absent')
    return j


GATEWAY_PORT = 8551
GATEWAY_RECEIPT = 'evidence/vpn-gateway-route.json'


def gateway_target(root, value):
    receipt = read(root/'installation.json')
    require(receipt.get('role') == 'rpc_gateway' and receipt.get('chain_id') == 99999,
            'restricted TCP enrollment requires the Canary RPC gateway role')
    require(isinstance(value, dict) and set(value) == {'ip', 'port'}
            and isinstance(value['ip'], str) and type(value['port']) is int
            and value['port'] == GATEWAY_PORT, 'exact validator TCP 8551 target required')
    peer = ipaddress.ip_address(value['ip'])
    require(str(peer) == value['ip'] and not (peer.is_loopback or peer.is_unspecified
            or peer.is_multicast or peer.is_link_local), 'literal unicast overlay address required')
    return {'ip': str(peer), 'port': GATEWAY_PORT}


def verify_gateway_route(root):
    from lifecycle import _lifecycle_lock, _require_operator, _sealed_receipt
    _require_operator()
    with _lifecycle_lock(root):
        _sealed_receipt(root)
        local = read(root/'evidence/vpn-enrollment.json')
        server = read(root/'evidence/vpn-server-binding.json')
        target = gateway_target(root, local['required_gateway_tcp'])
        require(local.get('native_enrollment_verified') is True
                and server.get('server_binding_verified') is True
                and server.get('peer_id')
                and server.get('wireguard_public_key') == local['wireguard_public_key'],
                'fresh bound VPN identity required')
        live = status(root)
        source = ipaddress.ip_interface(local['overlay_address']).ip
        peer = ipaddress.ip_address(target['ip'])
        require(live['publicKey'] == local['wireguard_public_key']
                and ipaddress.ip_interface(live['netbirdIp']).ip == source
                and ipaddress.ip_address(server['ip']) == source
                and source != peer and source.version == peer.version,
                'live VPN identity/target differs from bound enrollment')
        family = socket.AF_INET if source.version == 4 else socket.AF_INET6
        routes = json.loads(native(['ip', '-j', 'route', 'get', str(peer), 'from', str(source)], timeout=4))
        require(isinstance(routes, list) and len(routes) == 1 and routes[0].get('dev') == 'wt0',
                'validator route must use wt0')
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'wt0\0')
            connection.bind((str(source), 0))
            connection.connect((str(peer), GATEWAY_PORT))
        result = {'peer_id': server['peer_id'], 'source_ip': str(source), 'target': target,
                  'interface': 'wt0', 'tcp_verified': True, 'apqe_verified': False}
        path = root/GATEWAY_RECEIPT
        if path.exists() or path.is_symlink():
            require(not path.is_symlink() and read(path) == result, 'gateway VPN route receipt differs')
        else:
            write_new(path, result)
        return result


def enroll(root, secret_input):
    require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Linux root required')
    require(not (root / 'evidence/vpn-enrollment.json').exists(), 'VPN enrollment already recorded')
    require(not list((root / 'vpn').iterdir()), 'fresh machine-specific VPN identity required')
    request = json.loads(secret_input)
    common = {'setup_key', 'management_url', 'hostname'}
    require(isinstance(request, dict) and set(request) in
            (common | {'required_peer_ips'}, common | {'required_gateway_tcp'}), 'invalid enrollment input')
    gateway = gateway_target(root, request['required_gateway_tcp']) if 'required_gateway_tcp' in request else None
    require(gateway is not None or read(root/'installation.json').get('role') != 'rpc_gateway',
            'RPC gateway requires restricted TCP enrollment')
    url = urlparse(request['management_url'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment, 'HTTPS management URL required')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,63}', request['hostname']), 'invalid VPN hostname')
    peers = request.get('required_peer_ips', [])
    if gateway is None:
        require(isinstance(peers, list) and peers and len(peers) <= 5
                and all(isinstance(peer, str) for peer in peers) and len(set(peers)) == len(peers),
                'explicit independent authorized peer connectivity targets required')
        for peer in peers: ipaddress.ip_address(peer)
    key = request.pop('setup_key')
    require(isinstance(key, str) and 1 <= len(key) <= 4096 and '\n' not in key, 'invalid one-use setup key')
    secret = root / 'run/enrollment.key'
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as out: out.write(key); out.flush(); os.fsync(out.fileno())
        from lifecycle import mutate_owned_service
        mutate_owned_service(root, 'start', 'synergy-vpn.service')
        native([root / 'tools/netbird-client', 'up', '--management-url', request['management_url'],
                '--setup-key-file', secret, '--hostname', request['hostname'], '--interface-name', 'wt0',
                '--mtu', '1280', '--disable-auto-connect=false', '--disable-dns', '--no-browser'], timeout=90)
    finally:
        secret.unlink(missing_ok=True)
        key = None
    native(['ip', 'link', 'show', 'wt0'])
    deadline = time.monotonic() + 60
    j = None
    while time.monotonic() < deadline:
        try:
            j = status(root)
            for peer in peers:
                native(['ping', '-n', '-I', 'wt0', '-c', '1', '-W', '2', peer], timeout=4)
            break
        except (ValueError, OSError, subprocess.SubprocessError):
            time.sleep(1)
    else: raise ValueError('bounded native VPN/peer connectivity gate failed')
    result = {'wireguard_public_key': j['publicKey'], 'overlay_address': j['netbirdIp'],
              'hostname': request['hostname'], 'management_url': request['management_url'],
              'verified_peer_ips': peers, 'peer_id': None, 'server_binding_verified': False,
              'native_enrollment_verified': True, 'consensus_started': False}
    if gateway is not None:
        result['required_gateway_tcp'] = gateway
        result['gateway_tcp_verified'] = False
    write_new(root / 'evidence/vpn-enrollment.json', result)
    return result


def bind_server(root, server_peer):
    # Public result from authenticated management API, no enrollment credential.
    local = read(root / 'evidence/vpn-enrollment.json')
    # NetBird's public peer API does not expose the WireGuard public key.
    # Attribution uses a fresh API peer ID, issued one-off key usage, unique
    # enrollment hostname and matching native IP; never invent a server key.
    # --hostname selects NetBird's peer name. The API hostname remains the
    # operating-system hostname, which can legitimately be different.
    require(server_peer.get('name') == local['hostname'], 'management peer name differs')
    require(server_peer['new_peer_verified'] is True and server_peer['one_off_usage_verified'] is True,
            'fresh one-off server attribution required')
    require(ipaddress.ip_interface(local['overlay_address']).ip == ipaddress.ip_address(server_peer['ip']),
            'management peer address differs')
    require(server_peer['id'] and server_peer['connected'] is True, 'server peer not connected')
    write_new(root / 'evidence/vpn-server-binding.json', {'peer_id': server_peer['id'],
              'wireguard_public_key': local['wireguard_public_key'], 'ip': server_peer['ip'],
              'hostname': server_peer['hostname'], 'peer_name': server_peer['name'],
              'server_binding_verified': True,
              'binding_method': 'fresh peer ID + one-off enrollment evidence + unique peer name + native IP',
              'one_off_usage_evidence': server_peer.get('one_off_usage_evidence', 'management key counter'),
              'management_public_key_exposed': False})
    return {'peer_id': server_peer['id'], 'server_binding_verified': True}


RETIREMENT = 'vpn-retirement.json'
RETIREMENT_INTENT = 'vpn-retirement-intent.json'
RETIREMENT_LIMIT = 16384


def retirement_hash(raw):
    return hashlib.sha256(raw).hexdigest()


def retirement_input(path, limit=RETIREMENT_LIMIT):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                and not meta.st_mode & 0o077 and 0 < meta.st_size <= limit,
                'bounded private root-owned retirement input required')
        raw = source.read(limit + 1)
        require(len(raw) == meta.st_size, 'retirement input changed while reading')
        return raw


def retirement_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate retirement field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def management_origin(value):
    require(isinstance(value, str) and re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/?', value),
            'explicit HTTPS management origin required')
    parsed = urlparse(value)
    require(parsed.hostname and (parsed.port is None or parsed.port > 0), 'invalid HTTPS management origin')
    return 'https://' + parsed.hostname + (f':{parsed.port}' if parsed.port not in (None, 443) else '')


def retirement_binding(enrollment, binding):
    local, remote = retirement_json(enrollment), retirement_json(binding)
    require(isinstance(local, dict) and isinstance(remote, dict)
            and local.get('native_enrollment_verified') is True and remote.get('server_binding_verified') is True,
            'verified enrollment and server binding required')
    peer, key = remote.get('peer_id'), local.get('wireguard_public_key')
    require(isinstance(peer, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', peer)
            and isinstance(key, str) and re.fullmatch(r'[A-Za-z0-9+/]{43}=', key)
            and base64.b64encode(base64.b64decode(key, validate=True)).decode() == key
            and key == remote.get('wireguard_public_key'), 'invalid or different VPN identity')
    name, hostname = local.get('hostname'), remote.get('hostname')
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,63}', name)
            and name == remote.get('peer_name') and isinstance(hostname, str)
            and re.fullmatch(r'[A-Za-z0-9_.-]{1,253}', hostname), 'different VPN peer name or hostname')
    ip = ipaddress.ip_interface(local['overlay_address']).ip
    require(str(ip) == remote.get('ip') and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback),
            'invalid or different overlay address')
    return {'peer_id': peer, 'peer_name': name, 'hostname': hostname, 'ip': str(ip),
            'management_origin': management_origin(local['management_url']),
            'enrollment_sha256': retirement_hash(enrollment), 'binding_sha256': retirement_hash(binding)}


def _management_request(origin, token, method, path):
    """No redirects/proxies; only the independently pinned HTTPS origin gets the token."""
    parsed = urlparse(origin)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                            timeout=8, context=ssl.create_default_context())
    try:
        connection.request(method, path, headers={'Authorization': 'Token ' + token,
                           'Accept': 'application/json', 'Connection': 'close', 'Cache-Control': 'no-cache'})
        with connection.getresponse() as response:
            code = response.status
            if code != 200 or method == 'DELETE':
                return code, None
            require(response.headers.get_content_type() == 'application/json', 'management JSON response required')
            body, limit, deadline = bytearray(), 2 * 1024 * 1024, time.monotonic() + 8
            while True:
                require(time.monotonic() < deadline, 'management response deadline exceeded')
                chunk = response.read1(min(65536, limit + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                require(len(body) <= limit, 'management response exceeds limit')
            return code, retirement_json(body)
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        raise ValueError('VPN management request failed; any pending retirement must be reconciled') from None
    finally:
        connection.close()


def _retirement_write(path, record):
    # Both callers hold the private directory's lifecycle lock. The canonical
    # writer safely resumes stale staging from a crash and syncs the directory.
    from lifecycle import _replace_bytes
    require(not path.exists() and not path.is_symlink(), 'retirement record already exists')
    data = json.dumps(record, sort_keys=True, indent=2).encode() + b'\n'
    _replace_bytes(path.parent, path, data, 0o600, retirement_hash(data))


def _retire_bound_peer(work, identity, account, request):
    peer_id = identity['peer_id']
    path = '/api/peers/' + peer_id
    intent = {'format': 'synergy-vpn-retirement-intent-v1', 'account_id': account, **identity}
    intent_path, receipt_path = work / RETIREMENT_INTENT, work / RETIREMENT
    resumed = intent_path.exists() or intent_path.is_symlink()
    if resumed:
        require(retirement_json(retirement_input(intent_path)) == intent, 'VPN retirement intent differs')
    receipt = {'format': 'synergy-vpn-retirement-v1', 'account_id': account,
               **identity, 'retired': True, 'absence_verified': True}
    if receipt_path.exists() or receipt_path.is_symlink():
        require(resumed and retirement_json(retirement_input(receipt_path)) == receipt,
                'VPN retirement receipt differs')

    code, accounts = request('GET', '/api/accounts')
    require(code == 200 and isinstance(accounts, list) and len(accounts) == 1
            and isinstance(accounts[0], dict) and accounts[0].get('id') == account,
            'VPN management account differs')
    code, current = request('GET', path)
    if code == 200:
        require(not receipt_path.exists() and isinstance(current, dict)
                and all(current.get(remote) == identity[local] for remote, local in
                        (('id', 'peer_id'), ('name', 'peer_name'), ('ip', 'ip'), ('hostname', 'hostname'))),
                'VPN management peer differs')
        if not resumed:
            _retirement_write(intent_path, intent)
        code, _ = request('DELETE', path)
        require(code in (200, 204), 'VPN delete outcome uncertain; reconcile exact intent')
        code, _ = request('GET', path)
    else:
        require(resumed, 'VPN peer must be attributed before initial retirement')
    require(code == 404, 'VPN peer absence was not verified')
    code, inventory = request('GET', '/api/peers')
    require(code == 200 and isinstance(inventory, list) and all(isinstance(p, dict)
            and isinstance(p.get('id'), str) and isinstance(p.get('name'), str)
            and isinstance(p.get('ip'), str) and p['id'] != peer_id
            and p['name'] != identity['peer_name'] and p['ip'] != identity['ip'] for p in inventory),
            'VPN account inventory does not confirm absence')
    if not receipt_path.exists():
        _retirement_write(receipt_path, receipt)
    return receipt_path


def retire_peer(work, management, account, enrollment_pin, binding_pin):
    """Coordinator only. The fixed credential file must never travel to the validator."""
    from lifecycle import _lifecycle_lock, _require_operator
    _require_operator()
    require(work.is_absolute() and Path('/opt') not in (work, *work.parents),
            'use a separate coordinator workspace, not an installation root')
    for parent in (work, *work.parents):
        meta = parent.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o022,
                'root-owned coordinator workspace ancestry required')
    require(not work.stat().st_mode & 0o077 and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', account),
            'private coordinator workspace and exact management account required')
    origin = management_origin(management)
    with _lifecycle_lock(work):
        enrollment = retirement_input(work/'vpn-enrollment.json')
        binding = retirement_input(work/'vpn-server-binding.json')
        identity = retirement_binding(enrollment, binding)
        require((identity['management_origin'], identity['enrollment_sha256'], identity['binding_sha256'])
                == (origin, enrollment_pin, binding_pin), 'VPN endpoint or reviewed binding digest differs')
        token = retirement_input(work/'management.token', 4096).decode('ascii').removesuffix('\n')
        require(re.fullmatch(r'[A-Za-z0-9._~-]{20,4095}', token), 'invalid coordinator token format')
        return _retire_bound_peer(work, identity, account,
                                  lambda method, path: _management_request(origin, token, method, path))


def validate_retirement_receipt(raw, enrollment, binding):
    identity = retirement_binding(enrollment, binding)
    receipt = retirement_json(raw)
    require(isinstance(receipt, dict) and isinstance(receipt.get('account_id'), str)
            and re.fullmatch(r'[A-Za-z0-9_-]{1,100}', receipt['account_id'])
            and receipt == {'format': 'synergy-vpn-retirement-v1', 'account_id': receipt['account_id'],
                            **identity, 'retired': True, 'absence_verified': True}
            and receipt['retired'] is True and receipt['absence_verified'] is True,
            'retirement receipt differs from current verified VPN binding')
    return receipt


def record_retirement(root, raw, pin):
    from lifecycle import _lifecycle_lock, _require_operator, _sealed_receipt
    _require_operator()
    require(len(raw) <= RETIREMENT_LIMIT and retirement_hash(raw) == pin,
            'independently reviewed retirement receipt digest required')
    with _lifecycle_lock(root):
        _sealed_receipt(root)
        evidence = root/'evidence'
        meta = evidence.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == 0 and not meta.st_mode & 0o077,
                'private installation evidence directory required')
        receipt = validate_retirement_receipt(raw, retirement_input(evidence/'vpn-enrollment.json'),
                                              retirement_input(evidence/'vpn-server-binding.json'))
        path = evidence/RETIREMENT
        if path.exists() or path.is_symlink():
            require(retirement_json(retirement_input(path)) == receipt, 'recorded retirement differs')
        else:
            _retirement_write(path, receipt)
        return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['enroll', 'status', 'bind-server', 'verify-gateway-route', 'retire-peer', 'record-retirement'])
    p.add_argument('--root'); p.add_argument('--coordinator-work', type=Path)
    p.add_argument('--management-origin'); p.add_argument('--account-id'); p.add_argument('--enrollment-sha256')
    p.add_argument('--binding-sha256'); p.add_argument('--retirement-sha256')
    a = p.parse_args()
    if a.command == 'retire-peer':
        require(a.root is None and a.coordinator_work is not None and a.management_origin and a.account_id
                and a.enrollment_sha256 and a.binding_sha256 and a.retirement_sha256 is None,
                'coordinator workspace, endpoint, account and reviewed binding digests required')
        path = retire_peer(a.coordinator_work, a.management_origin, a.account_id, a.enrollment_sha256, a.binding_sha256)
        print(json.dumps({'receipt': str(path), 'sha256': retirement_hash(retirement_input(path))}, sort_keys=True))
        return
    require(a.root and all(v is None for v in (a.coordinator_work, a.management_origin, a.account_id,
                                               a.enrollment_sha256, a.binding_sha256))
            and bool(a.retirement_sha256) == (a.command == 'record-retirement'), 'invalid VPN operation inputs')
    root = safe_root(a.root)
    if a.command == 'enroll':
        b = sys.stdin.buffer.read(16385); require(len(b) <= 16384, 'bounded enrollment input required')
        result = enroll(root, b)
    elif a.command == 'verify-gateway-route':
        result = verify_gateway_route(root)
    elif a.command == 'bind-server':
        b = sys.stdin.buffer.read(16385); require(len(b) <= 16384, 'bounded public server result required')
        result = bind_server(root, json.loads(b))
    elif a.command == 'record-retirement':
        result = record_retirement(root, sys.stdin.buffer.read(RETIREMENT_LIMIT + 1), a.retirement_sha256)
    else:
        j = status(root); result = {'management_connected': j['management']['connected'],
                  'signal_connected': j['signal']['connected'], 'overlay_address': j['netbirdIp'],
                  'public_key': j['publicKey'], 'connected_peers': j['peers']['connected']}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        # Native stderr may contain setup credentials; it is deliberately suppressed.
        print(f'Synergy VPN operation refused: {type(error).__name__}', file=sys.stderr); sys.exit(1)
