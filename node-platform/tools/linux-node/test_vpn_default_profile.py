"""Private disposable daemon-profile fixtures; no client, keys, peers or network."""
import base64
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import vpn
import lifecycle


def write_default_profile(root):
    directory=root/'vpn';directory.mkdir(mode=0o700,exist_ok=True);directory.chmod(0o700)
    url={'Scheme':'https','Opaque':'','User':None,'Host':'api.netbird.io:443','Path':'','RawPath':'',
         'OmitHost':False,'ForceQuery':False,'RawQuery':'','Fragment':'','RawFragment':''}
    value={'ManagementURL':url,'AdminURL':dict(url,Host='app.netbird.io:443'),
           'PrivateKey':base64.b64encode(b'p'*32).decode(),
           # Public deterministic format fixture, not a generated/usable node key.
           # Matches approved NetBird ED25519 x509.MarshalPKCS8PrivateKey + pem.Encode.
           'SSHKey':'-----BEGIN PRIVATE KEY-----\n'+base64.b64encode(bytes.fromhex('302e020100300506032b657004220420')+b'q'*32).decode()+'\n-----END PRIVATE KEY-----\n',
           'WgIface':'wt0','WgPort':51820,'MTU':1280,'DNSRouteInterval':60000000000,'DisableNotifications':True,
           'IFaceBlackList':['wt0','wt','utun','tun0','zt','ZeroTier','wg','ts','Tailscale','tailscale','docker','veth','br-','lo']}
    for name in ('BlockInbound','BlockLANAccess','DisableAutoConnect','DisableClientRoutes','DisableDNS','DisableFirewall','DisableIPv6','DisableIPv6Discovery','DisableServerRoutes','RosenpassEnabled','RosenpassPermissive','ServerSSHAllowed'):value[name]=False
    for name in ('DNSLabels','DisableSSHAuth','EnableSSHLocalPortForwarding','EnableSSHRemotePortForwarding','EnableSSHRoot','EnableSSHSFTP','NATExternalIPs','NetworkMonitor','SSHJWTCacheTTL','SyncMessageVersion'):value[name]=None
    for name in ('ClientCertKeyPath','ClientCertPath','CustomDNSAddress','Name','PreSharedKey'):value[name]=''
    for name,payload in [('default.json',value),('active_profile.json',{'name':'default','username':''})]:
        path=directory/name;path.write_text(json.dumps(payload));path.chmod(0o600)
    return value


class DefaultProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.config=write_default_profile(self.root)

    def write(self,value):
        (self.root/'vpn/default.json').write_text(json.dumps(value))

    def test_only_exact_unregistered_defaults_are_admitted_without_writes(self):
        before={p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()}
        identity=vpn.unregistered_default_profile(self.root)
        self.assertEqual(identity,(self.config['PrivateKey'],self.config['SSHKey']))
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()})

    def test_foreign_origin_psk_external_paths_unknown_fields_and_selector_fail_closed(self):
        changes=[('PreSharedKey','foreign'),('ClientCertPath','/outside/cert'),('ClientCertKeyPath','/outside/key'),
                 ('CustomDNSAddress','127.0.0.1'),('Name','foreign'),('ServerSSHAllowed',True),('unknown',False)]
        for field,value in changes:
            altered=copy.deepcopy(self.config);altered[field]=value;self.write(altered)
            with self.subTest(field=field),self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        for field in ('ManagementURL','AdminURL'):
            altered=copy.deepcopy(self.config);altered[field]['Host']='approved-but-not-unregistered.example';self.write(altered)
            with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        self.write(self.config)
        (self.root/'vpn/active_profile.json').write_text('{"name":"foreign","username":""}')
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)

    def test_extra_state_symlink_hardlink_and_modes_are_rejected(self):
        profile=self.root/'vpn/default.json';extra=self.root/'vpn/state.json';extra.write_text('{}')
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        extra.unlink();profile.chmod(0o644)
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        profile.chmod(0o600);os.link(profile,self.root/'other')
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        (self.root/'other').unlink();profile.rename(self.root/'outside');profile.symlink_to(self.root/'outside')
        with self.assertRaises((ValueError,OSError)):vpn.unregistered_default_profile(self.root)

    def test_only_provider_pkcs8_ed25519_encoding_is_accepted(self):
        valid=self.config['SSHKey']
        der=bytes.fromhex('302e020100300506032b657004220420')+b'q'*32
        def pem(body):return '-----BEGIN PRIVATE KEY-----\n'+base64.b64encode(body).decode()+'\n-----END PRIVATE KEY-----\n'
        variants=[valid.rstrip('\n'),valid+'\n',valid+'foreign',valid.replace('PRIVATE KEY','RSA PRIVATE KEY'),
                  valid.replace('PRIVATE KEY','OPENSSH PRIVATE KEY'),valid.replace('PRIVATE KEY','EC PRIVATE KEY'),
                  valid.replace('\n', '\r\n'),valid.replace(base64.b64encode(der).decode(), '!'*64),
                  pem(der+b'x'),pem(der[:-1]),pem(der[:8]+b'\x71'+der[9:]),
                  pem(der[:16]+bytes(32)),pem(b'openssh-key-v1\0'+b'q'*32),
                  valid[:50]+'\n'+valid[50:]]
        for value in variants:
            altered=copy.deepcopy(self.config);altered['SSHKey']=value;self.write(altered)
            with self.subTest(length=len(value)),self.assertRaisesRegex(ValueError,'identity format'):
                vpn.unregistered_default_profile(self.root)
        self.write(self.config)
        self.assertEqual(vpn.unregistered_default_profile(self.root),(self.config['PrivateKey'],valid))

    def test_separate_client_attempt_preserves_identity_and_failure_never_records_enrollment(self):
        identity=vpn.unregistered_default_profile(self.root)
        for name in ('run','evidence'):(self.root/name).mkdir()
        (self.root/'installation.json').write_text('{"role":"validator"}')
        request=json.dumps({'setup_key':'fixture-only','management_url':'https://approved.example','hostname':'node',
                            'required_peer_ips':['100.64.0.1']})
        before={p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()}
        real=os.fstat
        def root_owned(fd):
            m=real(fd);return SimpleNamespace(st_mode=m.st_mode,st_nlink=m.st_nlink,st_uid=0,st_size=m.st_size)
        with patch.object(vpn.os,'geteuid',return_value=0),patch.object(vpn.sys,'platform','linux'),patch.object(vpn,'unregistered_default_profile',return_value=identity),patch.object(vpn.os,'fstat',side_effect=root_owned),patch.object(lifecycle,'mutate_owned_service'),patch.object(vpn,'native',side_effect=ValueError('uncertain client')):
            with self.assertRaises(ValueError):vpn.enroll(self.root,request,preserved_identity=identity)
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()})
        self.assertFalse((self.root/'run/enrollment.key').exists());self.assertFalse((self.root/'evidence/vpn-enrollment.json').exists())
        def native(args,**kwargs):
            if 'up' in args:
                changed=copy.deepcopy(self.config);changed['PrivateKey']=base64.b64encode(b'z'*32).decode();self.write(changed)
            return ''
        with patch.object(vpn.os,'geteuid',return_value=0),patch.object(vpn.sys,'platform','linux'),patch.object(vpn,'unregistered_default_profile',return_value=identity),patch.object(vpn.os,'fstat',side_effect=root_owned),patch.object(lifecycle,'mutate_owned_service'),patch.object(vpn,'native',side_effect=native):
            with self.assertRaisesRegex(ValueError,'identity changed'):vpn.enroll(self.root,request,preserved_identity=identity)
        self.assertFalse((self.root/'evidence/vpn-enrollment.json').exists())

    def test_duplicate_fields_and_noncanonical_identity_are_rejected(self):
        path=self.root/'vpn/default.json'
        path.write_text(json.dumps(self.config)[:-1]+',"Name":""}')
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        altered=copy.deepcopy(self.config);altered['PrivateKey']='!'*44;self.write(altered)
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)
        self.write(self.config);(self.root/'vpn').chmod(0o755)
        with self.assertRaises(ValueError):vpn.unregistered_default_profile(self.root)

    def test_successful_explicit_retry_retains_identity_and_records_only_actual_probes(self):
        identity=vpn.unregistered_default_profile(self.root)
        for name in ('run','evidence'):(self.root/name).mkdir()
        (self.root/'installation.json').write_text('{"role":"validator"}')
        request=json.dumps({'setup_key':'fixture-only','management_url':'https://approved.example','hostname':'node',
                            'required_peer_ips':['100.64.0.1']})
        before={p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()}
        real=os.fstat
        def root_owned(fd):
            m=real(fd);return SimpleNamespace(st_mode=m.st_mode,st_nlink=m.st_nlink,st_uid=0,st_size=m.st_size)
        live={'publicKey':'fixture-public','netbirdIp':'100.64.0.2/16'}
        with patch.object(vpn.os,'geteuid',return_value=0),patch.object(vpn.sys,'platform','linux'),patch.object(vpn,'unregistered_default_profile',return_value=identity),patch.object(vpn.os,'fstat',side_effect=root_owned),patch.object(lifecycle,'mutate_owned_service'),patch.object(vpn,'native',return_value='') as client,patch.object(vpn,'status',return_value=live):
            result=vpn.enroll(self.root,request,preserved_identity=identity)
        self.assertEqual(result['verified_peer_ips'],['100.64.0.1'])
        self.assertFalse(result['server_binding_verified'])
        self.assertIn(['ping','-n','-I','wt0','-c','1','-W','2','100.64.0.1'],[call.args[0] for call in client.call_args_list])
        self.assertEqual(before,{p.name:p.read_bytes() for p in (self.root/'vpn').iterdir()})
        self.assertFalse((self.root/'run/enrollment.key').exists())
        self.assertTrue((self.root/'evidence/vpn-enrollment.json').exists())

    def test_fresh_registration_never_starts_daemon_or_creates_default_profile(self):
        root=self.root/'synergy';root.mkdir(mode=0o700)
        for name in ('tools','evidence','vpn'):(root/name).mkdir(mode=0o700)
        units=self.root/'units';units.mkdir()
        state={'LoadState':'not-found','FragmentPath':'','MainPID':'0'}
        with patch.object(lifecycle,'_require_operator'),patch.object(lifecycle,'_sealed_receipt'),patch.object(lifecycle,'UNIT_DIRECTORY',units),patch.object(lifecycle,'_unit_state',return_value=state),patch.object(lifecycle,'rendered_units',return_value={'synergy-node.service':'node','synergy-vpn.service':'vpn'}),patch.object(lifecycle,'native',return_value='') as calls:
            result=lifecycle.register(root)
        self.assertFalse(result['services_started']);self.assertFalse(result['boot_enabled'])
        self.assertEqual([c.args[0] for c in calls.call_args_list],[['systemctl','daemon-reload']])
        self.assertIsNone(vpn.unregistered_default_profile(root))
