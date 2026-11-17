"""Per-process isolated CA scope; no host trust installation or NetBird process."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
import unittest
import lifecycle
import conformance
import vpn

class CaTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()/'synergy';self.inputs=self.root/'tmp/controller/authorization/inputs'
  self.inputs.mkdir(parents=True,mode=0o700)
  for p in (self.root,self.root/'tmp',self.root/'tmp/controller',self.inputs.parent):p.chmod(0o700)
  self.ca=b'-----BEGIN CERTIFICATE-----\nPUBLIC-CA-FIXTURE\n-----END CERTIFICATE-----\n'
  self.provider={'version':1,'profile':'nodenetwork-debug-vpn-provider-v1','ca_sha256':hashlib.sha256(self.ca).hexdigest(),'expires_at':1}
  self.policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(self.root),'community_enrollment':False,'qualified_operations':[],'releases':{},
               'engineering_initial_authorization_sha256':'a'*64,'engineering_authorization':{'sha256':'b'*64,'sequence':1,'expires_at':1},'authorization_files':{}}
  self.save(self.root/'tmp/controller/policy.json',self.policy)
 def save(self,p,v):
  raw=v if isinstance(v,bytes) else json.dumps(v).encode();p.write_bytes(raw);p.chmod(0o600);return hashlib.sha256(raw).hexdigest()
 def approve(self):
  for name,raw in (('vpn-ca.pem',self.ca),('vpn-provider.json',self.provider)):self.policy['authorization_files'][name]=self.save(self.inputs/name,raw)
  self.save(self.root/'tmp/controller/policy.json',self.policy)
 def context(self):
  # These are boundary tests, not a fabricated TLS handshake/certificate test.
  mock=Mock();mock.get_ca_certs.return_value=[{'CA':'approved-public-fixture'}]
  return patch.object(vpn.ssl,'SSLContext',return_value=mock)
 def test_upgrade_preflight_accepts_only_exact_authenticated_old_wrapper(self):
  (self.root/'tools').mkdir(mode=0o700)
  old="def wrapper_text(root):\n    return f'#!/bin/sh\\nexport HOME={root}\\nexec {root}/bin/netbird \"$@\"\\n'\n"
  source=self.root/'tools/lifecycle.py';self.save(source,old.encode())
  wrapper=self.root/'tools/netbird-client';self.save(wrapper,('#!/bin/sh\nexport HOME='+str(self.root)+'\nexec '+str(self.root)+'/bin/netbird "$@"\n').encode())
  manifest={'files':{'tools/lifecycle.py':hashlib.sha256(old.encode()).hexdigest()}}
  conformance.verify_vpn_wrapper(self.root,manifest,allow_legacy=True)
  with self.assertRaisesRegex(ValueError,'drift'):conformance.verify_vpn_wrapper(self.root,manifest)
  wrapper.write_text('tampered')
  with self.assertRaisesRegex(ValueError,'differs'):conformance.verify_vpn_wrapper(self.root,manifest,allow_legacy=True)
  source.write_text(old+'# altered source')
  with self.assertRaisesRegex(ValueError,'not authenticated'):conformance.verify_vpn_wrapper(self.root,manifest,allow_legacy=True)

 def test_controlled_ca_requires_exact_host_network_formation(self):
  self.provider.update(profile='nodenetwork-controlled-canary-v1',network_binding={'network_id':'canary-testing','chain_id':99999,'formation_sha256':'c'*64})
  self.policy.update(engineering_selection={'network_id':'canary-testing','chain_id':99999},validator_formation_sha256='c'*64)
  self.approve()
  with self.context():self.assertIn('SSL_CERT_FILE',vpn.client_environment(self.root))
  for key,value in [('network_id','wrong-network'),('chain_id',1)]:
   self.policy['engineering_selection'][key]=value;self.save(self.root/'tmp/controller/policy.json',self.policy)
   with self.context(),self.assertRaises(ValueError):vpn.client_environment(self.root)
   self.policy['engineering_selection'][key]=self.provider['network_binding'][key]
  self.policy['validator_formation_sha256']='d'*64;self.save(self.root/'tmp/controller/policy.json',self.policy)
  with self.context(),self.assertRaises(ValueError):vpn.client_environment(self.root)

 def test_ordinary_profile_keeps_system_trust_and_creates_no_ca(self):
  with patch.dict(os.environ,{'EXISTING_ENV':'kept'},clear=True):
   env=vpn.client_environment(self.root)
  self.assertEqual(env,{'EXISTING_ENV':'kept'});self.assertFalse((self.inputs/'vpn-ca.pem').exists())
 def test_approved_ca_applies_to_daemon_up_status_without_expiring_existing_membership(self):
  self.approve()
  daemon=['service','run','--config',str(self.root/'vpn/default.json'),'--daemon-addr','unix://'+str(self.root/'run/netbird.sock'),'--log-file',str(self.root/'logs/netbird.log')]
  for args in (daemon,['status','--json'],['up','--management-url','https://127.0.0.1:8443','--setup-key-file',str(self.root/'run/enrollment.key')]):
   with self.subTest(args=args),self.context(),patch.object(vpn.os,'execve') as run:
    vpn.client_exec(self.root,args)
    executable,argv,env=run.call_args.args
    self.assertEqual(executable,str(self.root/'bin/netbird'));self.assertEqual(env['SSL_CERT_FILE'],str(self.inputs/'vpn-ca.pem'))
    self.assertNotIn('/etc/ssl',env['SSL_CERT_FILE']);self.assertEqual(argv[0],executable)
  self.assertIn('ExecStart='+str(self.root)+'/tools/netbird-client service run',lifecycle.vpn_unit(self.root))
  self.assertIn('exec /usr/bin/python3 -I -B',lifecycle.wrapper_text(self.root))
 def test_missing_declared_unapproved_tampered_symlink_or_hardlink_ca_refuses_before_exec(self):
  self.approve();ca=self.inputs/'vpn-ca.pem'
  for mode in ('missing','tampered','symlink','hardlink','unapproved'):
   with self.subTest(mode=mode):
    if ca.exists() or ca.is_symlink():ca.unlink()
    self.save(ca,self.ca)
    if mode=='missing':ca.unlink()
    if mode=='tampered':ca.write_bytes(b'changed')
    if mode=='symlink':ca.unlink();ca.symlink_to('/etc/passwd')
    if mode=='hardlink':os.link(ca,self.inputs/'duplicate')
    if mode=='unapproved':self.policy['authorization_files'].pop('vpn-ca.pem');self.save(self.root/'tmp/controller/policy.json',self.policy)
    with self.context(),patch.object(vpn.os,'execve') as run:
     with self.assertRaises((ValueError,OSError)):vpn.client_exec(self.root,['status'])
     run.assert_not_called()
    if mode=='hardlink':(self.inputs/'duplicate').unlink()
 def test_wrong_profile_scope_or_malformed_non_ca_certificate_is_refused(self):
  self.approve()
  for change in ({'profile':'production'},{'version':True},{'ca_sha256':'c'*64}):
   self.save(self.inputs/'vpn-provider.json',{**self.provider,**change});self.policy['authorization_files']['vpn-provider.json']=hashlib.sha256((self.inputs/'vpn-provider.json').read_bytes()).hexdigest();self.save(self.root/'tmp/controller/policy.json',self.policy)
   with self.context(),self.assertRaises(ValueError):vpn.client_environment(self.root)
  self.approve();self.policy.pop('engineering_initial_authorization_sha256');self.save(self.root/'tmp/controller/policy.json',self.policy)
  with self.context(),self.assertRaises(ValueError):vpn.client_environment(self.root)
  self.policy['engineering_initial_authorization_sha256']='a'*64;self.save(self.root/'tmp/controller/policy.json',self.policy)
  with self.assertRaises((ValueError,vpn.ssl.SSLError)):vpn.client_environment(self.root)
  with self.context() as context:
   context.return_value.get_ca_certs.return_value=[]
   with self.assertRaisesRegex(ValueError,'no CA'):vpn.client_environment(self.root)

if __name__=='__main__':unittest.main()
