"""Native coordinator's isolated engineering VPN authorization state machine.

Library only: no CLI, token storage, target mutation, or renderer authority.
The caller must authenticate this exact provider policy in the native build and
keep the credential and returned one-use key outside renderer messages. NetBird
is an outer carrier; neither its TLS nor WireGuard grants native chain authority.
"""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
from urllib.parse import urlsplit

LIMIT = 2 * 1024 * 1024
PROFILE = 'nodenetwork-debug-vpn-provider-v1'
CONTROLLED_PROFILE = 'nodenetwork-controlled-canary-v1'
GATEWAY_PROFILE = 'nodenetwork-controlled-gateway-v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate VPN authorization field')
            result[key] = value
        return result
    require(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT, 'Bounded VPN JSON required')
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'Finite JSON required'))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def pin(value):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value) is not None


def identifier(value):
    return isinstance(value, str) and re.fullmatch('[A-Za-z0-9_-]{1,100}', value) is not None


def network_scope(policy, binding=None):
    require(type(policy.get('version')) is int and policy.get('version') == 1 and policy.get('profile') in (PROFILE, CONTROLLED_PROFILE, GATEWAY_PROFILE),
            'Unknown engineering provider profile')
    if policy['profile'] == PROFILE:
        require('network_binding' not in policy, 'Isolated profile cannot adopt controlled network scope')
        return
    scope = policy.get('network_binding')
    require(isinstance(scope, dict) and set(scope) == {'network_id', 'chain_id', 'formation_sha256'}
            and isinstance(scope['network_id'], str)
            and re.fullmatch('[a-z0-9][a-z0-9_-]{1,127}', scope['network_id'])
            and type(scope['chain_id']) is int and 0 < scope['chain_id'] < 2**64
            and pin(scope['formation_sha256']), 'Exact controlled network scope required')
    if binding is not None:
        require(isinstance(binding, dict) and all(type(binding.get(k)) is type(value) and binding.get(k) == value for k, value in scope.items()),
                'Controlled network differs from approved scope')


def provider_policy(raw, expected_sha256, ca, now, *, cleanup_action=None):
    require(cleanup_action in (None, 'revoke', 'retire'), 'Unknown cleanup action')
    require(pin(expected_sha256) and hashlib.sha256(raw).hexdigest() == expected_sha256,
            'Provider policy differs from independent native pin')
    policy = decode(raw)
    require(isinstance(policy, dict), 'Exact provider policy required')
    network_scope(policy)
    extra = {'network_binding'} if policy['profile'] in (CONTROLLED_PROFILE,GATEWAY_PROFILE) else set()
    connectivity = 'required_gateway_tcp' if policy['profile']==GATEWAY_PROFILE else 'required_peer_ips'
    require(set(policy) == extra | {'version', 'profile', 'management_origin',
            'api_origin', 'account_id', 'ca_sha256', 'auto_groups', connectivity, 'expires_at'}, 'Exact provider policy required')
    require(type(policy['version']) is int, 'Exact engineering provider version required')
    for field in ('api_origin', 'management_origin'):
        origin = policy[field]
        require(isinstance(origin, str) and len(origin) <= 512, 'Bounded provider origin required')
        parsed = urlsplit(origin)
        require(parsed.scheme == 'https' and parsed.hostname and parsed.username is None
                and parsed.password is None and parsed.path == '' and not parsed.query and not parsed.fragment
                and origin == 'https://' + parsed.netloc and chr(92) not in origin
                and not any(ord(c) < 33 or ord(c) > 126 for c in origin), 'Exact HTTPS origin required')
        require(parsed.port is None or 0 < parsed.port <= 65535, 'Invalid provider port')
    require(identifier(policy['account_id']) and isinstance(policy['auto_groups'], list)
            and len(policy['auto_groups']) <= 16 and len(set(policy['auto_groups'])) == len(policy['auto_groups'])
            and all(identifier(group) for group in policy['auto_groups']), 'Exact account and groups required')
    if policy['profile']==GATEWAY_PROFILE:
        target=policy['required_gateway_tcp']
        require(isinstance(target,dict) and set(target)=={'ip','port'} and isinstance(target['ip'],str) and type(target['port']) is int and target['port']==8551,'Exact restricted gateway TCP target required')
        address=ipaddress.ip_address(target['ip'])
        require(str(address)==target['ip'] and not(address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local),'Literal signed gateway overlay target required')
    else:
        require(isinstance(policy['required_peer_ips'], list) and 0 < len(policy['required_peer_ips']) <= 5
                and len(set(policy['required_peer_ips'])) == len(policy['required_peer_ips']), 'Independent VPN peer targets required')
        for value in policy['required_peer_ips']:
            address = ipaddress.ip_address(value)
            require(str(address) == value and not (address.is_unspecified or address.is_loopback or address.is_multicast),
                    'Literal independent overlay peer required')
    require(pin(policy['ca_sha256']) and isinstance(ca, bytes) and 0 < len(ca) <= 128 * 1024
            and hashlib.sha256(ca).hexdigest() == policy['ca_sha256'], 'Independent CA bytes differ')
    require(type(policy['expires_at']) is int and (now < policy['expires_at'] or cleanup_action is not None), 'Provider approval expired')
    return policy


class HttpsProvider:
    """Only exact API resources, no redirects/proxies/system-CA fallback."""
    def __init__(self, policy, ca, token):
        require(isinstance(token, str) and 1 <= len(token) <= 4096
                and all(33 <= ord(c) <= 126 for c in token), 'Private native provider credential required')
        require(hashlib.sha256(ca).hexdigest() == policy['ca_sha256'], 'Independent CA bytes differ')
        self.origin = urlsplit(policy['api_origin'])
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=ca.decode('ascii'))
        self.token = token

    def __repr__(self):
        return '<HttpsProvider credential=redacted>'

    def request(self, method, path, body=None):
        require((method, path) in {('GET', '/api/accounts'), ('GET', '/api/peers'),
                ('GET', '/api/setup-keys'), ('POST', '/api/setup-keys')}
                or re.fullmatch('/api/(?:peers|setup-keys)/[A-Za-z0-9_-]{1,100}', path)
                and method in ('GET', 'DELETE'), 'Unsupported provider resource')
        require((method == 'POST') == (body is not None), 'Unexpected provider body')
        data = None if body is None else encode(body)
        require(data is None or len(data) <= 16384, 'Provider request exceeds bound')
        connection = http.client.HTTPSConnection(self.origin.hostname, self.origin.port or 443,
                                                timeout=8, context=self.context)
        try:
            connection.request(method, path, body=data, headers={'Authorization': 'Token ' + self.token,
                'Accept': 'application/json', 'Content-Type': 'application/json', 'Connection': 'close'})
            response = connection.getresponse()
            require(response.status not in range(300, 400), 'Provider redirects are forbidden')
            if response.status in (204, 404):
                return response.status, None
            require(response.headers.get_content_type() == 'application/json', 'Provider JSON required')
            raw, deadline = bytearray(), time.monotonic() + 8
            while True:
                require(time.monotonic() < deadline, 'Provider response deadline exceeded')
                chunk = response.read1(min(65536, LIMIT + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= LIMIT, 'Provider response exceeds bound')
            return response.status, decode(bytes(raw))
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            raise ValueError('Provider exchange failed; reconcile the durable intent before retry') from None
        finally:
            connection.close()


def _read_state(directory, name):
    fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        meta = os.fstat(source.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and meta.st_nlink == 1
                and not meta.st_mode & 0o077 and 0 < meta.st_size <= LIMIT, 'Unsafe VPN receipt')
        raw = source.read(LIMIT + 1)
        require(len(raw) == meta.st_size, 'VPN receipt changed while reading')
        return decode(raw)


def _write_state(directory, name, value):
    raw = encode(value)
    require(len(raw) <= LIMIT, 'VPN receipt exceeds bound')
    fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def retire_verified_legacy_peer(directory, policy, request, scope, *, reconcile_only):
    """Execute the exact peer removal admitted by fresh native review.

    The native caller must authenticate the public-key proof and locator before
    sending this private wire. The issuance policy only authenticates the TLS
    transport and account. It contributes no retirement or enrollment authority.
    """
    origin = 'https://vpn-coordinator.synergy-network.io'
    identity = {
        'account_id': 'da99e12f611ghl16dvjg',
        'peer_id': 'dboqb9if611ohpqo0e1g',
        'peer_name': 'synergy-canary-rpc-99999',
        'hostname': 'vmi3381382',
        'ip': '10.69.51.205',
        'management_origin': origin,
        'enrollment_sha256': 'f27a0e0031ba00f2a234e77e55449ca5f4b9a15dec7e2c8da3da5bde6ea37573',
        'binding_sha256': '1629d857606c040ecbd7ed9d5dc692ac697dda3b129cc1f8b2bb9834e594d5f2',
    }
    pin_fields = ('plan_sha256', 'provider_sha256', 'credential_locator_sha256', 'ca_sha256')
    require(type(reconcile_only) is bool and isinstance(scope, dict)
            and set(scope) == set(identity) | set(pin_fields) | {'purpose', 'wireguard_public_key_sha256', 'expires_at'}
            and scope['purpose'] == 'nodenetwork-legacy-vpn-peer-retirement-v1'
            and scope['wireguard_public_key_sha256'] == '5e781088b3b0a7cd2862ee1010b5f84ce4f91ebc1abbbce92a10a0dc8563159f'
            and all(scope[key] == value for key, value in identity.items())
            and all(pin(scope[key]) for key in pin_fields)
            and policy['profile'] == CONTROLLED_PROFILE
            and policy['api_origin'] == policy['management_origin'] == origin
            and policy['account_id'] == identity['account_id'] and scope['ca_sha256'] == policy['ca_sha256'],
            'Exact legacy peer retirement scope required')
    def call(method, path):
        now = int(time.time())
        require(type(scope['expires_at']) is int and now < scope['expires_at'] <= now + 120,
                'Native retirement review expired')
        return request(method, path)

    directory = Path(directory)
    require(directory.is_absolute() and all(p.is_dir() and not p.is_symlink() for p in directory.parents),
            'Unsafe native retirement ancestry')
    if not reconcile_only:
        directory.mkdir(mode=0o700, exist_ok=True)
    meta = directory.lstat()
    require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid()
            and stat.S_IMODE(meta.st_mode) == 0o700, 'Private native retirement directory required')

    stable = {**identity, **{key: scope[key] for key in pin_fields if key != 'plan_sha256'},
              'wireguard_public_key_sha256': scope['wireguard_public_key_sha256']}
    intent_name = 'retire-intent.json'
    if reconcile_only:
        intent = _read_state(directory, intent_name)
        require(set(intent) == {'scope', 'reviewed_plan_sha256'} and intent['scope'] == stable
                and pin(intent['reviewed_plan_sha256']), 'Original retirement intent differs')
    else:
        require(not os.path.lexists(directory / intent_name) and not os.path.lexists(directory / 'retired.json'),
                'Retirement already dispatched. Check provider absence without sending DELETE again.')

    def peer_inventory():
        code, peers = call('GET', '/api/peers')
        require(code == 200 and isinstance(peers, list) and len(peers) <= 8192
                and all(isinstance(peer, dict) and identifier(peer.get('id'))
                        and isinstance(peer.get('name'), str) and isinstance(peer.get('ip'), str) for peer in peers)
                and len({peer['id'] for peer in peers}) == len(peers), 'Invalid peer inventory')
        return [peer for peer in peers if peer['id'] == identity['peer_id']
                or peer.get('name') == identity['peer_name'] or peer.get('ip') == identity['ip']]

    code, accounts = call('GET', '/api/accounts')
    require(code == 200 and isinstance(accounts, list) and len(accounts) == 1
            and isinstance(accounts[0], dict) and accounts[0].get('id') == identity['account_id'],
            'VPN management account differs')
    path = '/api/peers/' + identity['peer_id']
    code, peer = call('GET', path)
    if not reconcile_only:
        def matches(value):
            return isinstance(value, dict) and all(value.get(key) == identity[owner] for key, owner in
                (('id', 'peer_id'), ('name', 'peer_name'), ('ip', 'ip'), ('hostname', 'hostname')))
        aliases = peer_inventory()
        require(code == 200 and matches(peer) and len(aliases) == 1 and matches(aliases[0]),
                'Exact provider peer identity differs')
        _write_state(directory, intent_name, {'scope': stable, 'reviewed_plan_sha256': scope['plan_sha256']})
        code, _ = call('DELETE', path)
        require(code in (200, 204, 404), 'Retirement outcome requires reconciliation')
        code, _ = call('GET', path)
    require(code == 404 and not peer_inventory(), 'Provider absence has not been verified')
    receipt = {'format': 'synergy-vpn-retirement-v1', **identity, 'retired': True, 'absence_verified': True}
    if os.path.lexists(directory / 'retired.json'):
        require(_read_state(directory, 'retired.json') == receipt, 'Retirement receipt differs')
    else:
        _write_state(directory, 'retired.json', receipt)
    return receipt


class Authorization:
    """One exact intent per private app-owned directory, never retries POST.

    Returned setup_key is exclusively for the native private controller exchange.
    It must never enter an IPC response, log or this class's durable public state.
    A lost POST response is discovered/revoked by exact name; it is not regenerated.
    """
    def __init__(self, directory, policy, request, now=None, *, cleanup_action=None):
        require(cleanup_action in (None, 'revoke', 'retire'), 'Unknown cleanup action')
        network_scope(policy)
        self.cleanup_action = cleanup_action
        self.directory, self.policy, self.request = Path(directory), policy, request
        self.now = time.time if now is None else now
        for ancestor in self.directory.parents:
            require(not ancestor.is_symlink(), 'VPN state ancestry contains a link')
        if not self.directory.exists():
            require(cleanup_action is None, 'Cleanup requires an existing attributed intent')
            self.directory.mkdir(mode=0o700)
        meta = self.directory.lstat()
        require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid()
                and not meta.st_mode & 0o077, 'Private native-owned VPN state required')
        if policy['profile'] in (CONTROLLED_PROFILE,GATEWAY_PROFILE) and (self.directory / 'intent.json').exists():
            intent = self._read('intent.json')
            network_scope(policy, intent.get('binding'))
            require(intent.get('provider_sha256') == hashlib.sha256(encode(policy)).hexdigest()
                    and intent.get('account_id') == policy['account_id'], 'Controlled provider differs from original intent')
        if cleanup_action is not None:
            intent = self._read('intent.json')
            require(intent.get('provider_sha256') == hashlib.sha256(encode(policy)).hexdigest()
                    and intent.get('account_id') == policy['account_id'], 'Cleanup provider differs from original intent')
            if cleanup_action == 'retire':
                require(self._read('bound.json')['binding'] == intent['binding'], 'Cleanup bound scope differs')

    def _read(self, name):
        return _read_state(self.directory, name)

    def _write(self, name, value):
        _write_state(self.directory, name, value)

    def _account(self, action=None):
        if self.policy['profile'] in (CONTROLLED_PROFILE,GATEWAY_PROFILE) and (self.directory / 'intent.json').exists():
            network_scope(self.policy, self._read('intent.json').get('binding'))
        require(self.cleanup_action is None or action == self.cleanup_action, 'Cleanup capability cannot issue, bind or change action')
        require(self.now() < self.policy['expires_at'] or self.cleanup_action == action and action in ('revoke','retire'), 'Provider approval expired')
        code, accounts = self.request('GET', '/api/accounts')
        require(code == 200 and isinstance(accounts, list) and len(accounts) == 1
                and accounts[0].get('id') == self.policy['account_id'], 'Provider account differs')

    def _list(self, resource):
        code, result = self.request('GET', '/api/' + resource)
        require(code == 200 and isinstance(result, list) and len(result) <= 8192
                and all(isinstance(item, dict) and identifier(str(item.get('id', ''))) for item in result)
                and len({str(item['id']) for item in result}) == len(result), 'Invalid provider inventory')
        return result

    def _key(self, key, intent, consumed=False):
        require(isinstance(key, dict) and identifier(str(key.get('id', '')))
                and key.get('name') == intent['name'] and key.get('type') == 'one-off'
                and type(key.get('usage_limit')) is int and key['usage_limit'] == 1
                and key.get('ephemeral') is True and key.get('auto_groups') == self.policy['auto_groups']
                and type(key.get('used_times')) is int and key['used_times'] == (1 if consumed else 0)
                and key.get('revoked') is False, 'One-use provider key policy differs')

    def prepare(self, binding):
        network_scope(self.policy, binding)
        fields = {'target_sha256', 'manifest_sha256', 'formation_sha256', 'network_id', 'chain_id'}
        require(isinstance(binding, dict) and set(binding) in (fields,fields|{'attempt_sha256'})
                and ('attempt_sha256' not in binding or pin(binding['attempt_sha256']))
                and all(pin(binding[f]) for f in fields if f.endswith('sha256'))
                and isinstance(binding['network_id'], str)
                and re.fullmatch('[a-z0-9][a-z0-9_-]{1,127}', binding['network_id'])
                and type(binding['chain_id']) is int and 0 < binding['chain_id'] < 2**64,
                'Exact native-approved target, release and formation required')
        require(not (self.directory / 'intent.json').exists(), 'VPN intent already exists; reconcile, never reissue')
        self._account()
        peers, keys = self._list('peers'), self._list('setup-keys')
        name = 'nn-' + hashlib.sha256(encode(binding)).hexdigest()[:60]
        require(not any(p.get('name') == name for p in peers + keys), 'VPN intent name already exists')
        intent = {'version': 1, 'binding': binding, 'name': name, 'account_id': self.policy['account_id'],
                  'peer_ids_before': [str(p['id']) for p in peers],
                  'created_at': int(self.now()), 'provider_sha256': hashlib.sha256(encode(self.policy)).hexdigest()}
        self._write('intent.json', intent)  # Durable BEFORE the only POST.
        code, key = self.request('POST', '/api/setup-keys', {'name': name, 'type': 'one-off',
            'expires_in': 86400, 'usage_limit': 1, 'auto_groups': self.policy['auto_groups'],
            'ephemeral': True, 'allow_extra_dns_labels': False})
        require(code in (200, 201), 'Provider setup-key creation uncertain; reconcile')
        self._key(key, intent)
        secret = key.get('key')
        require(isinstance(secret, str) and 1 <= len(secret) <= 4096
                and all(33 <= ord(c) <= 126 for c in secret), 'Provider omitted one-use credential')
        public = {'setup_key_id': str(key['id']), 'name': name, 'binding': binding}
        self._write('issued.json', public)
        return public, secret

    def reconcile(self, local):
        self._account()
        intent = self._read('intent.json')
        require(intent.get('provider_sha256') == hashlib.sha256(encode(self.policy)).hexdigest()
                and intent.get('account_id') == self.policy['account_id'], 'Provider differs from original intent')
        keys = [key for key in self._list('setup-keys') if key.get('name') == intent['name']]
        prior = self._read('bound.json') if (self.directory / 'bound.json').exists() else None
        require(len(keys) == 1 or not keys and prior is not None,
                'Uncertain setup-key creation requires exact provider reconciliation')
        if keys:
            self._key(keys[0], intent, consumed=True)
            key_id = str(keys[0]['id'])
        else:
            key_id = prior['setup_key_id']
        issued = self.directory / 'issued.json'
        if issued.exists():
            require(self._read('issued.json')['setup_key_id'] == key_id, 'Provider key identity differs')
        require(isinstance(local, dict) and local.get('native_enrollment_verified') is True
                and local.get('hostname') == intent['name']
                and local.get('management_url') == self.policy['management_origin'], 'Native enrollment context differs')
        import base64
        public = local.get('wireguard_public_key')
        try:
            key_bytes = base64.b64decode(public, validate=True)
            address = str(ipaddress.ip_interface(local['overlay_address']).ip)
        except (ValueError, TypeError, KeyError):
            raise ValueError('Invalid native VPN identity') from None
        require(len(key_bytes) == 32 and base64.b64encode(key_bytes).decode() == public,
                'Invalid native VPN public key')
        matches = [peer for peer in self._list('peers') if peer.get('name') == intent['name']]
        require(len(matches) == 1, 'Unique fresh provider peer required')
        peer = matches[0]
        require(str(peer['id']) not in intent['peer_ids_before'] and peer.get('ip') == address
                and peer.get('connected') is True and isinstance(peer.get('hostname'), str)
                and re.fullmatch('[A-Za-z0-9_.-]{1,253}', peer['hostname']), 'Provider peer does not match native enrollment')
        result = {'peer_id': str(peer['id']), 'ip': address, 'name': intent['name'],
                  'hostname': peer['hostname'], 'connected': True, 'new_peer_verified': True,
                  'one_off_usage_verified': True, 'wireguard_public_key': public,
                  'binding': intent['binding'], 'setup_key_id': key_id,
                  'provider_account_id': self.policy['account_id'],
                  'one_off_usage_evidence': 'independent provider one-off used_times=1 + precreation inventory'}
        path = self.directory / 'bound.json'
        if path.exists():
            require(self._read('bound.json') == result, 'Prior verified VPN binding differs')
        else:
            self._write('bound.json', result)
        return result

    def _cancel_write(self, name, value):
        # Cancellation only: a process can die while writing without leaving a
        # malformed durable proof or permitting a second DELETE on restart.
        require(name in ('cancel-unused-intent.json','cancelled-unused.json'),'Unknown cancellation receipt')
        path=self.directory/name;stage=self.directory/('.'+name+'.stage')
        if path.exists():
            require(self._read(name)==value,'Cancellation receipt differs')
            return
        if stage.exists() or stage.is_symlink():
            meta=stage.lstat()
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid==os.geteuid() and meta.st_nlink==1
                    and not meta.st_mode&0o077,'Unsafe interrupted cancellation staging')
            stage.unlink()
        raw=encode(value)
        require(len(raw)<=LIMIT,'Cancellation receipt exceeds bound')
        fd=os.open(stage,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as output:output.write(raw);output.flush();os.fsync(output.fileno())
            os.replace(stage,path)
            fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if stage.exists():stage.unlink()

    def cancel_unused(self, local):
        """One fenced DELETE only after authoritative zero-use and peer absence."""
        import fcntl
        fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return self._cancel_unused(local)
        finally:os.close(fd)

    def _cancel_unused(self, local):
        self._account('revoke')
        intent=self._read('intent.json');issued=self._read('issued.json')
        require(intent.get('provider_sha256')==hashlib.sha256(encode(self.policy)).hexdigest()
                and intent.get('account_id')==self.policy['account_id']
                and issued.get('binding')==intent['binding'] and issued.get('name')==intent['name']
                and identifier(issued.get('setup_key_id')),'Original issued VPN intent differs')
        require(isinstance(local,dict) and local.get('schema')=='nodenetwork-vpn-unused-preflight-v1'
                and local.get('quiescent') is True and pin(local.get('attempt_sha256'))
                and local.get('binding')==intent['binding'],'Exact quiescent original target required')
        proof={'format':'nodenetwork-vpn-unused-cancellation-v1','binding':intent['binding'],
               'provider_sha256':intent['provider_sha256'],'account_id':intent['account_id'],
               'setup_key_id':issued['setup_key_id'],'name':intent['name'],
               'intent_sha256':hashlib.sha256(encode(intent)).hexdigest(),
               'attempt_sha256':local['attempt_sha256'],'unused_verified':True,
               'setup_key_absent':True,'peer_absence_verified':True}
        def no_peer():
            require(not any(peer.get('name')==intent['name'] for peer in self._list('peers')),
                    'Matching peer prevents unused-attempt cancellation')
        no_peer()
        pending=self.directory/'cancel-unused-intent.json';terminal=self.directory/'cancelled-unused.json'
        if terminal.exists():
            require(self._read('cancelled-unused.json')==proof and pending.exists()
                    and self._read('cancel-unused-intent.json')==proof,'Prior unused cancellation differs')
        if pending.exists():
            require(self._read('cancel-unused-intent.json')==proof,'Uncertain unused cancellation scope differs')
        else:
            require(not (self.directory/'revoke-intent.json').exists(),'Prior unqualified revocation cannot prove unused state')
            keys=[key for key in self._list('setup-keys') if key.get('name')==intent['name'] or str(key.get('id'))==issued['setup_key_id']]
            require(len(keys)==1 and str(keys[0]['id'])==issued['setup_key_id'],'Exact original unused key required')
            self._key(keys[0],intent,consumed=False)
            self._cancel_write('cancel-unused-intent.json',proof)
            code,_=self.request('DELETE','/api/setup-keys/'+issued['setup_key_id'])
            require(code in (200,204,404),'Unused key deletion uncertain; reconcile absence without repeating DELETE')
        code,_=self.request('GET','/api/setup-keys/'+issued['setup_key_id'])
        require(code==404,'Original unused key absence not verified')
        require(not any(key.get('name')==intent['name'] or str(key['id'])==issued['setup_key_id']
                        for key in self._list('setup-keys')),'Original unused key remains')
        no_peer()
        if not terminal.exists():self._cancel_write('cancelled-unused.json',proof)
        return proof

    def revoke_setup_key(self):
        """Even a lost create response can be revoked by its exact durable name."""
        self._account('revoke')
        intent = self._read('intent.json')
        require(intent.get('provider_sha256') == hashlib.sha256(encode(self.policy)).hexdigest()
                and intent.get('account_id') == self.policy['account_id'], 'Provider differs from original intent')
        keys = [key for key in self._list('setup-keys') if key.get('name') == intent['name']]
        require(len(keys) <= 1, 'Ambiguous provider key cannot be revoked')
        known_id = None
        if keys:
            key = keys[0]
            require(key.get('type') == 'one-off' and key.get('usage_limit') == 1
                    and key.get('auto_groups') == self.policy['auto_groups'], 'Provider key attribution differs')
            known_id = str(key['id'])
            intent_path = self.directory / 'revoke-intent.json'
            require(not intent_path.exists() and not intent_path.is_symlink(),
                    'Uncertain key revocation must reconcile absence, never repeat DELETE')
            self._write('revoke-intent.json', {'setup_key_id': known_id, 'name': intent['name']})
            code, _ = self.request('DELETE', '/api/setup-keys/' + known_id)
            require(code in (200, 204, 404), 'Provider key revocation uncertain')
        elif (self.directory / 'revoke-intent.json').exists():
            known_id = self._read('revoke-intent.json')['setup_key_id']
        elif (self.directory / 'issued.json').exists():
            known_id = self._read('issued.json')['setup_key_id']
        if known_id is not None:
            require(identifier(known_id), 'Invalid attributed setup key ID')
            code, _ = self.request('GET', '/api/setup-keys/' + known_id)
            require(code == 404, 'Exact provider key absence not verified')
        require(not any(key.get('name') == intent['name'] or str(key['id']) == known_id
                        for key in self._list('setup-keys')), 'Provider key absence not verified')
        return {'setup_key_absent': True, 'binding': intent['binding']}

    def retire_bound_peer(self, evidence):
        """One attributed DELETE; a lost reply is reconciled by absence only."""
        self._account('retire')
        intent, bound = self._read('intent.json'), self._read('bound.json')
        require(intent.get('provider_sha256') == hashlib.sha256(encode(self.policy)).hexdigest()
                and bound['binding'] == intent['binding'], 'Provider/formation binding differs')
        local, remote = evidence['enrollment'], evidence['server_binding']
        require(local['hostname'] == bound['name'] and local['wireguard_public_key'] == bound['wireguard_public_key']
                and local['management_url'] == self.policy['management_origin']
                and remote['peer_id'] == bound['peer_id'] and remote['peer_name'] == bound['name']
                and remote['hostname'] == bound['hostname'] and remote['ip'] == bound['ip']
                and remote['wireguard_public_key'] == bound['wireguard_public_key']
                and remote['server_binding_verified'] is True
                and all(pin(evidence[name]) for name in ('enrollment_sha256','server_binding_sha256')),
                'Retirement differs from exact native+provider binding')
        peer_id = bound['peer_id']
        require(identifier(peer_id), 'Invalid attributed peer ID')
        code, peer = self.request('GET', '/api/peers/' + peer_id)
        deletion = {'peer_id': peer_id, 'binding': bound['binding'],
                    'enrollment_sha256': evidence['enrollment_sha256'],
                    'binding_sha256': evidence['server_binding_sha256']}
        path = self.directory / 'retire-intent.json'
        if path.exists() or path.is_symlink():
            require(self._read('retire-intent.json') == deletion, 'Retirement intent differs')
            require(code == 404, 'Uncertain peer deletion must reconcile absence, never repeat DELETE')
        else:
            require(code == 200 and isinstance(peer, dict) and str(peer.get('id')) == peer_id
                    and all(peer.get(field) == bound[field] for field in ('name','ip','hostname')),
                    'Independent provider peer attribution differs')
            self._write('retire-intent.json', deletion)
            code, _ = self.request('DELETE', '/api/peers/' + peer_id)
            require(code in (200, 204, 404), 'Provider peer deletion uncertain')
            code, _ = self.request('GET', '/api/peers/' + peer_id)
        require(code == 404 and not any(str(peer['id']) == peer_id or peer.get('name') == bound['name']
                or peer.get('ip') == bound['ip'] for peer in self._list('peers')),
                'Provider peer absence not verified')
        origin = urlsplit(self.policy['management_origin'])
        receipt = {'format':'synergy-vpn-retirement-v1','account_id':self.policy['account_id'],
            'peer_id':peer_id,'peer_name':bound['name'],'hostname':bound['hostname'],'ip':bound['ip'],
            'management_origin':'https://' + origin.hostname + (':' + str(origin.port) if origin.port not in (None,443) else ''),
            'enrollment_sha256':evidence['enrollment_sha256'],'binding_sha256':evidence['server_binding_sha256'],
            'retired':True,'absence_verified':True}
        path = self.directory / 'retired.json'
        if path.exists():
            require(self._read('retired.json') == receipt, 'Retired receipt differs')
        else:
            self._write('retired.json', receipt)
        return receipt
