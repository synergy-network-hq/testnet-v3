#!/usr/bin/env python3
"""Unattended application-owned NetBird enrollment. One-use input arrives on stdin.

No browser flow, reusable enrollment key or management API token is installed.
The coordinator retains the management credential and binds the returned public
WireGuard key to the newly registered server peer before accepting completion.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlparse
from synergy_linux import native, read, require, safe_root, write_new


def status(root):
    j = json.loads(native([root / 'tools/netbird-client', 'status', '--json']))
    require(j['management']['connected'] and j['signal']['connected'], 'management or signal disconnected')
    require(j['publicKey'] and j['netbirdIp'], 'native VPN identity/address absent')
    return j


def enroll(root, secret_input):
    require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Linux root required')
    require(not (root / 'evidence/vpn-enrollment.json').exists(), 'VPN enrollment already recorded')
    require(not list((root / 'vpn').iterdir()), 'fresh machine-specific VPN identity required')
    request = json.loads(secret_input)
    require(set(request) == {'setup_key', 'management_url', 'hostname', 'required_peer_ips'}, 'invalid enrollment input')
    url = urlparse(request['management_url'])
    require(url.scheme == 'https' and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment, 'HTTPS management URL required')
    require(re.fullmatch(r'[A-Za-z0-9_-]{1,63}', request['hostname']), 'invalid VPN hostname')
    peers = request['required_peer_ips']
    require(isinstance(peers, list) and peers and len(peers) <= 5 and len(set(peers)) == len(peers),
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
                '--mtu', '1280', '--disable-auto-connect=false', '--no-browser'], timeout=90)
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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['enroll', 'status', 'bind-server']); p.add_argument('--root', required=True)
    a = p.parse_args(); root = safe_root(a.root)
    if a.command == 'enroll':
        b = sys.stdin.buffer.read(16385); require(len(b) <= 16384, 'bounded enrollment input required')
        result = enroll(root, b)
    elif a.command == 'bind-server':
        b = sys.stdin.buffer.read(16385); require(len(b) <= 16384, 'bounded public server result required')
        result = bind_server(root, json.loads(b))
    else:
        j = status(root); result = {'management_connected': j['management']['connected'],
                  'signal_connected': j['signal']['connected'], 'overlay_address': j['netbirdIp'],
                  'public_key': j['publicKey'], 'connected_peers': j['peers']['connected']}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        # Native stderr may contain setup credentials; it is deliberately suppressed.
        print(f'Synergy VPN enrollment refused: {type(error).__name__}', file=sys.stderr); sys.exit(1)
