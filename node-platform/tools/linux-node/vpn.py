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


def client_environment(root):
    """Per-process TLS trust; never modifies the host certificate store."""
    from controller import Controller
    root=Path(root);c=Controller(root)
    env=os.environ.copy()
    inputs=root/'tmp/controller/authorization/inputs'
    paths={name:inputs/name for name in ('vpn-ca.pem','vpn-provider.json')}
    policy_path=c.control/'policy.json'
    policy=c.policy() if policy_path.exists() or policy_path.is_symlink() else {}
    pins=policy.get('authorization_files',{})
    require(isinstance(pins,dict),'Malformed VPN trust inventory')
    selected=any(name in pins or path.exists() or path.is_symlink() for name,path in paths.items())
    if not selected:return env
    auth=policy.get('engineering_authorization',{})
    pin=lambda value:isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None
    require(pin(policy.get('engineering_initial_authorization_sha256')) and isinstance(auth,dict)
            and pin(auth.get('sha256')) and type(auth.get('sequence')) is int and 0<auth['sequence']<2**53,
            'VPN private CA requires independently approved engineering scope')
    raw={}
    for name,path in paths.items():
        require(pin(pins.get(name)),'Both approved VPN provider and CA required')
        raw[name]=c.direct(path,True,128*1024 if name.endswith('.pem') else 16384).read_bytes()
        require(hashlib.sha256(raw[name]).hexdigest()==pins[name],'Approved VPN trust artifact changed')
    provider=json.loads(raw['vpn-provider.json'])
    require(isinstance(provider,dict) and type(provider.get('version')) is int and provider['version']==1
            and provider.get('profile') in ('nodenetwork-debug-vpn-provider-v1','nodenetwork-controlled-canary-v1')
            and provider.get('ca_sha256')==pins['vpn-ca.pem'],'Only exact isolated engineering CA scope is supported')
    from vpn_authorization import network_scope
    selection=policy.get('engineering_selection',{})
    network_scope(provider,{'network_id':selection.get('network_id'),'chain_id':selection.get('chain_id'),
                            'formation_sha256':policy.get('validator_formation_sha256')})
    ca=raw['vpn-ca.pem']
    require(b'PRIVATE KEY' not in ca and ca.count(b'-----BEGIN CERTIFICATE-----')>=1,'Public CA certificate required')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca.decode('ascii'))
    require(context.get_ca_certs(),'VPN trust input contains no CA certificate')
    env.pop('SSL_CERT_DIR',None)
    env['SSL_CERT_FILE']=str(paths['vpn-ca.pem'])
    return env


def client_exec(root,args):
    """Fixed wrapper entrypoint; credentials remain file-backed native inputs."""
    root=Path(root)
    require(isinstance(args,list) and 0<len(args)<=64 and all(isinstance(a,str) and len(a)<=4096 for a in args)
            and sum(map(len,args))<=16384,'Bounded VPN arguments required')
    env=client_environment(root)
    if args[:2]==['service','run']:
        expected=['service','run','--config',str(root/'vpn/default.json'),'--daemon-addr',
                  'unix://'+str(root/'run/netbird.sock'),'--log-file',str(root/'logs/netbird.log')]
        require(args==expected,'Exact attributed daemon invocation required')
        argv=[str(root/'bin/netbird'),*args]
    else:argv=[str(root/'bin/netbird'),'--daemon-addr','unix://'+str(root/'run/netbird.sock'),*args]
    os.execve(str(root/'bin/netbird'),argv,env)


def _profile_json(path):
    """Read private daemon state internally; never return it through IPC/logs."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        meta=os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and meta.st_uid==os.geteuid()
                and stat.S_IMODE(meta.st_mode)==0o600 and 0<meta.st_size<=16384,'Unsafe local VPN profile')
        raw=os.read(fd,16385)
        require(len(raw)==meta.st_size,'Local VPN profile changed during read')
    finally:os.close(fd)
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'Duplicate local VPN profile field')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=unique)


def profile_identity(config):
    """Exact approved provider encodings; opaque private values never leave memory."""
    private=config['PrivateKey'];ssh=config['SSHKey']
    require(isinstance(private,str) and len(private)==44,'Invalid local VPN identity format')
    try:key=base64.b64decode(private,validate=True)
    except ValueError:raise ValueError('Invalid local VPN identity format') from None
    require(len(key)==32 and any(key) and base64.b64encode(key).decode()==private
            and isinstance(ssh,str) and len(ssh)==119
            and ssh.startswith('-----BEGIN PRIVATE KEY-----\n')
            and ssh.endswith('-----END PRIVATE KEY-----\n'),'Invalid local VPN identity format')
    try:ssh_blob=base64.b64decode(''.join(ssh.splitlines()[1:-1]),validate=True)
    except ValueError:raise ValueError('Invalid local VPN identity format') from None
    # Approved NetBird v0.77.1 profilemanager generates ED25519 and calls
    # client/ssh.EncodePrivateKeyToPEM: x509.MarshalPKCS8PrivateKey, PEM PRIVATE KEY.
    # RFC 8410's Ed25519 PrivateKeyInfo is a fixed 16-byte DER envelope + seed.
    # This checks only that exact provider encoding, not private-key cryptography
    # or peer membership. NetBird remains the key parser/user; identity is retained
    # only in memory for the existing same-profile comparison after explicit up.
    require(len(ssh_blob)==48 and ssh_blob[:16]==bytes.fromhex('302e020100300506032b657004220420')
            and any(ssh_blob[16:])
            and ssh=='-----BEGIN PRIVATE KEY-----\n'+base64.b64encode(ssh_blob).decode()+'\n-----END PRIVATE KEY-----\n',
            'Invalid local VPN identity format')
    return private,ssh


def unregistered_default_profile(root):
    """Only the daemon-created, never-coordinator default profile is reusable.

    This is structural/provenance validation, NOT a peer-membership proof. Private
    identity strings remain in process memory solely to detect a client key change.
    NetBird itself validates/uses the keys; no alternative crypto implementation.
    """
    directory=Path(root)/'vpn';meta=directory.lstat()
    require(stat.S_ISDIR(meta.st_mode),'Unsafe local VPN directory')
    names={p.name for p in directory.iterdir()}
    if not names:return None
    require(meta.st_uid==os.geteuid() and stat.S_IMODE(meta.st_mode)==0o700,'Unsafe local VPN directory')
    require(names=={'default.json','active_profile.json'},'Unknown local VPN state requires reconciliation')
    require(_profile_json(directory/'active_profile.json')=={'name':'default','username':''},'Foreign VPN profile selector')
    config=_profile_json(directory/'default.json')
    false_fields=('BlockInbound','BlockLANAccess','DisableAutoConnect','DisableClientRoutes','DisableDNS',
                  'DisableFirewall','DisableIPv6','DisableIPv6Discovery','DisableServerRoutes',
                  'RosenpassEnabled','RosenpassPermissive','ServerSSHAllowed')
    null_fields=('DNSLabels','DisableSSHAuth','EnableSSHLocalPortForwarding','EnableSSHRemotePortForwarding',
                 'EnableSSHRoot','EnableSSHSFTP','NATExternalIPs','NetworkMonitor','SSHJWTCacheTTL','SyncMessageVersion')
    blank_fields=('ClientCertKeyPath','ClientCertPath','CustomDNSAddress','Name','PreSharedKey')
    exact={'ManagementURL','AdminURL','PrivateKey','SSHKey','WgIface','WgPort','MTU','IFaceBlackList',
           'DNSRouteInterval','DisableNotifications',*false_fields,*null_fields,*blank_fields}
    require(isinstance(config,dict) and set(config)==exact,'Unsupported unregistered VPN profile schema')
    require(all(config[k] is False for k in false_fields) and all(config[k] is None for k in null_fields)
            and all(config[k]=='' for k in blank_fields) and config['DisableNotifications'] is True,
            'Local VPN profile is not an untouched unregistered default')
    require(config['WgIface']=='wt0' and type(config['WgPort']) is int and config['WgPort']==51820
            and type(config['MTU']) is int and config['MTU']==1280
            and type(config['DNSRouteInterval']) is int and config['DNSRouteInterval']==60000000000
            and config['IFaceBlackList']==['wt0','wt','utun','tun0','zt','ZeroTier','wg','ts','Tailscale','tailscale','docker','veth','br-','lo'],
            'Local VPN default networking differs')
    for field,host in [('ManagementURL','api.netbird.io:443'),('AdminURL','app.netbird.io:443')]:
        url=config[field]
        expected={'Scheme':'https','Opaque':'','User':None,'Host':host,'Path':'','RawPath':'','OmitHost':False,
                  'ForceQuery':False,'RawQuery':'','Fragment':''}
        require(url==expected or url==dict(expected,RawFragment=''),'Foreign VPN management or admin origin')
    return profile_identity(config)



def _same_profile_identity(root,identity):
    config=_profile_json(Path(root)/'vpn/default.json')
    require(isinstance(config,dict) and (config.get('PrivateKey'),config.get('SSHKey'))==identity,
            'Native VPN identity changed; preserve attempt for reconciliation')


def status(root, timeout=8):
    j = json.loads(native([root / 'tools/netbird-client', 'status', '--json'], timeout=timeout))
    require(j['management']['connected'] and j['signal']['connected'], 'management or signal disconnected')
    require(j['publicKey'] and j['netbirdIp'], 'native VPN identity/address absent')
    return j


GATEWAY_RECEIPT = 'evidence/vpn-gateway-route.json'


def gateway_target(root, value):
    receipt = read(root/'installation.json')
    require(receipt.get('role') == 'rpc_gateway' and type(receipt.get('chain_id')) is int
            and 0 < receipt['chain_id'] < 2**64, 'restricted TCP enrollment requires a scoped RPC gateway')
    from canary_rpc_relay import CONFIG, gateway_upstream_tcp
    from vpn_authorization import gateway_tcp
    role = read(root/CONFIG)['role']
    validators = read(root/'network/transport-registry.json')['payload']['validators']
    target = gateway_tcp(value)
    require(target == gateway_upstream_tcp(role, validators),
            'VPN target differs from the exact approved gateway TCP endpoint')
    return target


def verify_gateway_route(root, *, persist=True, locked=False):
    from lifecycle import _lifecycle_lock, _require_operator, _sealed_receipt
    _require_operator()
    import contextlib
    with contextlib.nullcontext() if locked else _lifecycle_lock(root):
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
            connection.connect((str(peer), target['port']))
        result = {'peer_id': server['peer_id'], 'source_ip': str(source), 'target': target,
                  'interface': 'wt0', 'tcp_verified': True, 'apqe_verified': False}
        path = root/GATEWAY_RECEIPT
        if path.exists() or path.is_symlink():
            require(not path.is_symlink() and read(path) == result, 'gateway VPN route receipt differs')
        elif persist:
            write_new(path, result)
        return result


def enroll(root, secret_input, preserved_identity=None):
    require(os.geteuid() == 0 and sys.platform.startswith('linux'), 'Linux root required')
    require(not (root / 'evidence/vpn-enrollment.json').exists(), 'VPN enrollment already recorded')
    require(unregistered_default_profile(root)==preserved_identity,
            'Fresh or exactly preserved machine-specific VPN identity required')
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
    if preserved_identity is not None:_same_profile_identity(root,preserved_identity)
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
    if preserved_identity is not None:_same_profile_identity(root,preserved_identity)
    result = {'wireguard_public_key': j['publicKey'], 'overlay_address': j['netbirdIp'],
              'hostname': request['hostname'], 'management_url': request['management_url'],
              'verified_peer_ips': peers, 'peer_id': None, 'server_binding_verified': False,
              'native_enrollment_verified': True, 'consensus_started': False}
    if gateway is not None:
        result['required_gateway_tcp'] = gateway
        result['gateway_tcp_verified'] = False
    write_new(root / 'evidence/vpn-enrollment.json', result)
    return result


ATTEMPTS = 'evidence/vpn-attempts.json'
CANCELLATION = 'vpn-unused-cancellation.json'


def public_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',', ':')).encode()).hexdigest()


def attempt_state(root, proposed_events=None):
    """Bounded alternating cancellations/retries; original fence never changes."""
    original=root/'evidence/vpn-enrollment-attempt.json'
    if not original.exists() and not original.is_symlink():
        require(not (root/ATTEMPTS).exists() and not (root/ATTEMPTS).is_symlink(),'Orphan VPN attempt history')
        return {'attempt_sha256':None,'scope_sha256':None,'retry_after_sha256':None,'events':[]}
    require(read(original)=={'format':'nodenetwork-vpn-attempt-v1'},'Original VPN attempt differs')
    current=hashlib.sha256(original.read_bytes()).hexdigest();scope=None;retry=None
    path=root/ATTEMPTS;events=[]
    if proposed_events is not None or path.exists() or path.is_symlink():
        record=({'format':'nodenetwork-vpn-attempts-v1','events':proposed_events}
                if proposed_events is not None else read(path,256*1024))
        require(set(record)=={'format','events'} and record['format']=='nodenetwork-vpn-attempts-v1'
                and isinstance(record['events'],list) and len(record['events'])<=128,'Invalid VPN attempt history')
        events=record['events']
        for event in events:
            require(isinstance(event,dict),'Invalid VPN attempt event')
            if event.get('kind')=='cancel':
                require(set(event)=={'kind','receipt'} and retry is None and isinstance(event['receipt'],dict)
                        and event['receipt'].get('attempt_sha256')==current,'Stale VPN cancellation history')
                validate_unused_cancellation(event['receipt'])
                retry=public_hash(event)
            else:
                require(set(event)=={'kind','cancellation_sha256','enrollment_sha256'} and event.get('kind')=='attempt'
                        and retry is not None and event['cancellation_sha256']==retry
                        and re.fullmatch('[a-f0-9]{64}',event.get('enrollment_sha256','')),'Invalid VPN retry history')
                scope=retry;current=public_hash(event);retry=None
    return {'attempt_sha256':current,'scope_sha256':scope,'retry_after_sha256':retry,'events':events}


def append_attempt_event(root,event):
    state=attempt_state(root);events=[*state['events'],event]
    require(len(events)<=128,'VPN attempt history exhausted')
    attempt_state(root,events)  # Validate the entire proposed transition before writing.
    record={'format':'nodenetwork-vpn-attempts-v1','events':events}
    raw=json.dumps(record,sort_keys=True,indent=2).encode()+b'\n'
    require(len(raw)<=256*1024,'VPN attempt history exceeds bound')
    from lifecycle import _replace_bytes
    _replace_bytes(root,root/ATTEMPTS,raw,0o600,hashlib.sha256(raw).hexdigest())
    return attempt_state(root)


def validate_unused_cancellation(value):
    fields={'format','binding','provider_sha256','account_id','setup_key_id','name','intent_sha256',
            'attempt_sha256','unused_verified','setup_key_absent','peer_absence_verified'}
    require(isinstance(value,dict) and set(value)==fields and value['format']=='nodenetwork-vpn-unused-cancellation-v1'
            and all(value[k] is True for k in ('unused_verified','setup_key_absent','peer_absence_verified')),
            'Exact unused VPN cancellation proof required')
    require(all(isinstance(value[k],str) and re.fullmatch('[a-f0-9]{64}',value[k])
                for k in ('provider_sha256','intent_sha256','attempt_sha256'))
            and all(isinstance(value[k],str) and re.fullmatch('[A-Za-z0-9_-]{1,100}',value[k])
                    for k in ('account_id','setup_key_id','name')),'Invalid unused VPN cancellation attribution')


def recover_enrollment(root, server_peer, provider):
    """Recover identity evidence, never replay enrollment or claim peer probes.

    The controller has authenticated the original attempt, native grant, origin
    and provider artifact. Re-observe the daemon before publishing any receipt.
    """
    current = status(root)
    require(current.get('management', {}).get('connected') is True
            and current.get('signal', {}).get('connected') is True,
            'Native VPN recovery daemon is not connected')
    public = current.get('publicKey')
    try:
        decoded = base64.b64decode(public, validate=True)
        address = ipaddress.ip_interface(current['netbirdIp'])
    except (ValueError, TypeError, KeyError):
        raise ValueError('Native VPN recovery identity unavailable') from None
    require(len(decoded) == 32 and base64.b64encode(decoded).decode() == public
            and public == server_peer['wireguard_public_key']
            and address.ip == ipaddress.ip_address(server_peer['ip']),
            'Native VPN recovery identity differs from verified provider observation')
    require(server_peer['connected'] is True and server_peer['new_peer_verified'] is True
            and server_peer['one_off_usage_verified'] is True
            and server_peer['provider_account_id'] == provider['account_id'],
            'Independent exact provider recovery evidence required')
    result = {'wireguard_public_key': public, 'overlay_address': str(address),
              'hostname': server_peer['name'], 'management_url': provider['management_origin'],
              'verified_peer_ips': [], 'peer_id': None, 'server_binding_verified': False,
              'native_enrollment_verified': True, 'consensus_started': False}
    if provider.get('profile')=='nodenetwork-controlled-gateway-v1':
        result.update(required_gateway_tcp=gateway_target(root,provider['required_gateway_tcp']),gateway_tcp_verified=False)
    path = root / 'evidence/vpn-enrollment.json'
    if path.exists() or path.is_symlink():
        require(read(path) == result, 'Recovered native enrollment differs')
    else:
        _retirement_write(path, result)
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
    result = {'peer_id': server_peer['id'],
              'wireguard_public_key': local['wireguard_public_key'], 'ip': server_peer['ip'],
              'hostname': server_peer['hostname'], 'peer_name': server_peer['name'],
              'server_binding_verified': True,
              'binding_method': 'fresh peer ID + one-off enrollment evidence + unique peer name + native IP',
              'one_off_usage_evidence': server_peer.get('one_off_usage_evidence', 'management key counter'),
              'management_public_key_exposed': False}
    path = root / 'evidence/vpn-server-binding.json'
    if path.exists() or path.is_symlink():
        require(read(path) == result, 'Existing VPN server binding differs')
    else:
        _retirement_write(path, result)
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


def legacy_canary_retirement_scope(enrollment, binding, provider_raw, expected, ca, now):
    """Coordinator library only; expected pins/account come from native review.

    This does not grant provider access. The caller must independently admit the
    ORIGINAL old-network provider and credential, never a fresh-network policy.
    No credential, setup key, or renderer-supplied authority is accepted here.
    """
    from vpn_authorization import provider_policy, CONTROLLED_PROFILE
    require(isinstance(expected, dict) and set(expected) == {
        'provider_sha256', 'account_id', 'enrollment_sha256', 'binding_sha256'},
        'Exact native-reviewed legacy peer commitments required')
    for key in ('provider_sha256', 'enrollment_sha256', 'binding_sha256'):
        require(isinstance(expected[key], str) and re.fullmatch('[a-f0-9]{64}', expected[key]),
                'Independent legacy retirement pin required')
    policy = provider_policy(provider_raw, expected['provider_sha256'], ca, now, cleanup_action='retire')
    require(policy['profile'] == CONTROLLED_PROFILE
            and policy['network_binding']['network_id'] == 'posy-apqe-canary-process-49028'
            and policy['network_binding']['chain_id'] == 99999
            and policy['account_id'] == expected['account_id'],
            'Original obsolete Canary provider account approval required')
    identity = retirement_binding(enrollment, binding)
    require(identity['enrollment_sha256'] == expected['enrollment_sha256']
            and identity['binding_sha256'] == expected['binding_sha256']
            and identity['management_origin'] == management_origin(policy['management_origin'])
            and identity['management_origin'] == 'https://vpn-coordinator.synergy-network.io'
            and retirement_json(enrollment).get('wireguard_public_key') == 'EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M='
            and identity['peer_id'] == 'dboqb9if611ohpqo0e1g'
            and identity['peer_name'] == 'synergy-canary-rpc-99999'
            and identity['hostname'] == 'vmi3381382' and identity['ip'] == '10.69.51.205',
            'Exact obsolete Canary peer binding required')
    return policy, identity


def legacy_canary_peer_preflight(enrollment, binding, provider_raw, expected_provider_sha256,
                                ca, review, expected_plan_sha256, now, request):
    """NEW retirement-only native purpose, never expired issuance authority.

    Transport policy/pin and CA are existing independently approved coordinator
    trust. `review` must be created by native explicit consent for this purpose,
    with expected_plan_sha256 from its fresh authenticated legacy-plan read.
    No CLI/native route admits renderer-created reviews or loads credentials here.
    Standard NetBird REST omits the WG key, so this preflight cannot authorize
    deletion. It provides useful account/peer checks without inventing key proof.
    """
    from vpn_authorization import provider_policy
    fields = {'purpose','plan_sha256','provider_sha256','account_id','enrollment_sha256',
              'binding_sha256','expires_at','network_id','genesis_sha256','machine_id_sha256','target'}
    require(isinstance(review,dict) and set(review)==fields
            and review['purpose']=='nodenetwork-legacy-peer-retirement-v1'
            and review['network_id']=='posy-apqe-canary-process-49028'
            and review['genesis_sha256']=='d28ab09b6857f670482580a786edd939b090e88aa9378cdd0ad91379a724a9d7'
            and review['machine_id_sha256']=='8683ea9f4da9e9c05c26b6d8070cc13c0f5f75b0cd4a4de863492164f4c1e26d'
            and review['target']=={'kind':'remote','host':'167.86.83.83','port':22,'root':'/opt/Synergy'}
            and type(review['target']['port']) is int,'Exact legacy retirement native purpose required')
    for value in (expected_plan_sha256,expected_provider_sha256,review['enrollment_sha256'],review['binding_sha256']):
        require(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value),'Independent retirement commitment required')
    require(review['plan_sha256']==expected_plan_sha256 and review['provider_sha256']==expected_provider_sha256,
            'Retirement review differs from authenticated plan or provider')
    require(type(now) is int and type(review['expires_at']) is int
            and 0<now<review['expires_at']<=now+120,'Fresh native retirement-purpose review required')
    # cleanup_action permits parsing the pinned transport identity after its old
    # issuance deadline. ONLY the separate fresh purpose authorizes these GETs.
    transport=provider_policy(provider_raw,expected_provider_sha256,ca,now,cleanup_action='retire')
    require(transport['account_id']==review['account_id'],'Reviewed coordinator account differs')
    identity=retirement_binding(enrollment,binding)
    require(identity['enrollment_sha256']==review['enrollment_sha256']
            and identity['binding_sha256']==review['binding_sha256']
            and identity['management_origin']==management_origin(transport['management_origin'])
            and identity['management_origin']=='https://vpn-coordinator.synergy-network.io'
            and identity['peer_id']=='dboqb9if611ohpqo0e1g' and identity['peer_name']=='synergy-canary-rpc-99999'
            and identity['hostname']=='vmi3381382' and identity['ip']=='10.69.51.205'
            and retirement_json(enrollment).get('wireguard_public_key')=='EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M=',
            'Reviewed obsolete peer differs')
    def get(path):
        require(now<=int(time.time())<review['expires_at'],'Native retirement-purpose review expired')
        code,value=request('GET',path)
        require(code==200,'Authenticated legacy peer read refused')
        return value
    accounts=get('/api/accounts')
    require(isinstance(accounts,list) and len(accounts)==1 and isinstance(accounts[0],dict)
            and accounts[0].get('id')==review['account_id'],'Authenticated account differs')
    peer=get('/api/peers/'+identity['peer_id'])
    matches=lambda p:isinstance(p,dict) and all(p.get(remote)==identity[local] for remote,local in
        (('id','peer_id'),('name','peer_name'),('hostname','hostname'),('ip','ip')))
    require(matches(peer),'Authenticated peer differs')
    peers=get('/api/peers')
    require(isinstance(peers,list) and len(peers)<=8192 and all(isinstance(p,dict)
            and isinstance(p.get('id'),str) for p in peers) and len({p['id'] for p in peers})==len(peers),
            'Bounded unique peer inventory required')
    selected=[p for p in peers if p.get('id')==identity['peer_id'] or p.get('name')==identity['peer_name'] or p.get('ip')==identity['ip']]
    require(len(selected)==1 and matches(selected[0]),'Legacy peer inventory ambiguous')
    return {'schema':'nodenetwork-legacy-peer-retirement-preflight-v1','ready':False,
            'plan_sha256':expected_plan_sha256,'provider_sha256':expected_provider_sha256,
            'account_id':review['account_id'],'peer_id':identity['peer_id'],
            'account_verified':True,'peer_verified':True,'public_key_verified':False,
            'blocker':'independent_peer_key_binding_unavailable','mutation_performed':False,
            'retirement_authorized':False}


def retire_legacy_canary_peer(work, enrollment, binding, provider_raw, expected, ca, now, request, *, review_expires_at):
    """Exact-peer adapter to the existing durable retirement, not enrollment.

    No CLI or current native route exposes this function. A native-approved
    original provider/credential and explicit per-peer consent remain required.
    The supplied request is the existing authenticated provider transport.
    """
    from lifecycle import _require_operator
    _require_operator()
    require(type(now) is int and type(review_expires_at) is int and 0 < now < review_expires_at <= now + 120,
            'Fresh exact-peer native review required')
    require(now <= int(time.time()) < review_expires_at, 'Exact-peer native review expired')
    policy, identity = legacy_canary_retirement_scope(
        enrollment, binding, provider_raw, expected, ca, now)
    work = Path(work)
    require(work.is_absolute() and Path('/opt') not in (work, *work.parents),
            'Native coordinator workspace required, never an installation root')
    for parent in (work, *work.parents):
        meta = parent.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid()
                and not meta.st_mode & 0o022, 'Unsafe coordinator workspace ancestry')
    require(not work.stat().st_mode & 0o077, 'Private coordinator workspace required')
    from lifecycle import _lifecycle_lock
    with _lifecycle_lock(work):
        # Existing helper persists the exact intent before DELETE and only
        # receipts GET404 plus account inventory absence. Lost replies reconcile.
        def bounded_request(method, path):
            if method == 'DELETE':
                require(int(time.time()) < review_expires_at, 'Exact-peer native review expired before deletion')
            return request(method, path)
        return _retire_bound_peer(work, identity, policy['account_id'], bounded_request)


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



_DIAGNOSTIC_MARKERS = {
    'launcher_import_failure': (b'modulenotfounderror:', b'importerror:'),
    'tls_untrusted': (b'certificate signed by unknown authority', b'certificate verify failed', b'unable to get local issuer'),
    'tls_expired': (b'certificate has expired', b'certificate is not yet valid'),
    'tls_name_mismatch': (b'certificate is valid for', b'cannot validate certificate for'),
    'setup_key_rejected': (b'invalid setup key', b'setup key is invalid', b'setup key expired'),
    'transport_timeout': (b'context deadline exceeded', b'i/o timeout', b'connection timed out'),
    'connection_refused': (b'connection refused',),
    'interface_permission': (b'operation not permitted', b'failed to create interface'),
}


def diagnostic_codes(raw):
    """Fixed categories only: never emit raw daemon/client text or credentials."""
    text = raw.lower()
    return sorted(code for code, markers in _DIAGNOSTIC_MARKERS.items()
                  if any(marker in text for marker in markers))


def diagnostic_log(root):
    result = {'available': False, 'modified_at_ms': None, 'sampled_bytes': 0, 'codes': []}
    try:
        directory = os.open(root/'logs', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return result
    try:
        # Fixed names only: launcher failures precede the daemon's own log.
        for name in ('netbird.log','netbird-service.log'):
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                try:
                    metadata = os.fstat(fd)
                    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                            and metadata.st_uid == 0, 'Unsafe VPN diagnostic log')
                    os.lseek(fd, max(0, metadata.st_size-32768), os.SEEK_SET)
                    raw = os.read(fd, 32768)
                    result['available'] = True
                    result['modified_at_ms'] = max(result['modified_at_ms'] or 0, metadata.st_mtime_ns//1000000)
                    result['sampled_bytes'] += len(raw)
                    result['codes'] = sorted(set(result['codes']) | set(diagnostic_codes(raw)))
                finally:
                    os.close(fd)
            except (ValueError, OSError):
                pass
    finally:
        os.close(directory)
    return result


def diagnostics(root, enrollment, *, observe_live=None):
    """Read-only observation, independent of a completed enrollment receipt.

    An absent receipt does not imply the client is disconnected. Reachability
    is tested only against exact authenticated provider-policy peers; no input
    supplies commands, destinations, paths, setup keys or management credentials.
    """
    from controller import Controller
    root = Path(root)
    result = {'schema': 'nodenetwork-vpn-diagnostics-v1', 'observed_at_ms': int(time.time()*1000),
              'enrollment': {key: enrollment[key] for key in
                             ('service_registered', 'enrollment_staged', 'enrollment_recorded',
                              'reconciliation_required', 'server_bound')},
              'trust': {'mode': None, 'error_code': None},
              'client': {'available': False, 'management_connected': None, 'signal_connected': None,
                         'wireguard_public_key': None, 'overlay_address': None, 'error_code': None},
              'peers': [], 'log': diagnostic_log(root), 'mutation_performed': False}
    try:
        environment = client_environment(root)
        controller = Controller(root)
        policy = controller.policy()
        pins = policy.get('authorization_files', {})
        peers = []
        if 'vpn-provider.json' in pins:
            raw = controller.direct(root/'tmp/controller/authorization/inputs/vpn-provider.json', True, 16384).read_bytes()
            require(hashlib.sha256(raw).hexdigest() == pins['vpn-provider.json'], 'VPN provider changed')
            provider = json.loads(raw)
            peers = provider['required_peer_ips']
            require(isinstance(peers, list) and 0 < len(peers) <= 5
                    and len(set(peers)) == len(peers), 'Invalid approved VPN peer set')
            for peer in peers:
                address = ipaddress.ip_address(peer)
                require(str(address) == peer and not (address.is_loopback or address.is_unspecified
                        or address.is_multicast or address.is_link_local), 'Invalid approved peer')
        result['trust']['mode'] = 'approved_private_ca' if 'SSL_CERT_FILE' in environment else 'system'
    except (ValueError, OSError, KeyError, TypeError):
        result['trust']['error_code'] = 'approved_trust_scope_refused'
        return result
    try:
        raw = native([root/'tools/netbird-client', 'status', '--json'], timeout=8)
        current = json.loads(raw)
        management = current['management']['connected']
        signal = current['signal']['connected']
        require(type(management) is bool and type(signal) is bool, 'Invalid VPN connected state')
        key = current.get('publicKey') or None
        if key is not None:
            decoded = base64.b64decode(key, validate=True)
            require(len(decoded) == 32 and base64.b64encode(decoded).decode() == key, 'Invalid public VPN key')
        overlay = current.get('netbirdIp') or None
        if overlay is not None:
            overlay = str(ipaddress.ip_interface(overlay))
        result['client'].update(available=True, management_connected=management,
                                signal_connected=signal, wireguard_public_key=key, overlay_address=overlay)
    except subprocess.TimeoutExpired:
        result['client']['error_code'] = 'client_status_timeout'
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        result['client']['error_code'] = 'client_status_unavailable'
    if observe_live is not None:
        observe_live(current if result['client']['available'] else None)
    for peer in peers:
        observation = {'ip': peer, 'route_via_wt0': False, 'reachable': False, 'error_code': None}
        try:
            route = json.loads(native(['ip', '-j', 'route', 'get', peer], timeout=3))
            require(isinstance(route, list) and len(route) == 1 and route[0].get('dev') == 'wt0',
                    'Peer route is not the contained VPN interface')
            observation['route_via_wt0'] = True
            native(['ping', '-n', '-I', 'wt0', '-c', '1', '-W', '1', peer], timeout=3)
            observation['reachable'] = True
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
            observation['error_code'] = 'peer_unreachable' if observation['route_via_wt0'] else 'peer_route_unavailable'
        result['peers'].append(observation)
    return result


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
