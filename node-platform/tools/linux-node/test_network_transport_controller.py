"""Controller/journal boundaries; native APQE crypto is qualified by keytool tests."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import controller as c
import conformance
import synergy_linux as linux

def request(op,p=None):return {'version':1,'operation':op,'parameters':p or {}}
def sha(raw):return hashlib.sha256(raw).hexdigest()

class TransportTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name).resolve()/'synergy';(self.root/'tmp/network-formation').mkdir(parents=True,mode=0o700)
  self.root.chmod(0o700);(self.root/'tmp').chmod(0o700)
  self.controller=c.Controller(self.root);self.directory=self.root/'tmp/network-transport'
  self.selection={'formation_sha256':'a'*64,'network_id':'fresh','chain_id':'99999'};self.flags=['--apqe-report',self.root/'lib/apqe/build-report.json','--apqe-report-sha256','b'*64]
  self.source={'schema':'nodenetwork-network-formation-v1','pending':True,'signed':True,**self.selection,'review_sha256':'c'*64,
               'genesis_sha256':sha(b'{}'),'authority_sha256':sha(b'{}'),'authority_root_sha256':sha(b'a'*1952),'validator_addresses':['synv'+str(i) for i in range(5)]}
  self.p={'formation_sha256':'a'*64,'genesis_review_sha256':'c'*64,'target_provider_report_sha256':'b'*64,'valid_from_unix':100,'expires_at_unix':200,
          'members':[{'enrollment_json':'{}','configuration_json':'{"name":"é"}','dial_address':'127.0.0.1:'+str(10000+i),'transport_key_id':'key-'+str(i)} for i in range(5)]}
  self.receipt=None;self.calls=[];self.authorized=[]
  self.patch(patch.object(c.Controller,'formation_context',return_value=(self.selection,self.flags)))
  self.patch(patch.object(c.Controller,'formation_context_path',return_value=self.root/'tmp/context.json'))
  self.patch(patch.object(self.controller,'authorize',side_effect=lambda req:self.authorized.append(copy.deepcopy(req))))
  self.patch(patch('lifecycle._unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}));self.patch(patch('lifecycle._assert_no_application_processes'))
  self.patch(patch.object(linux,'native',side_effect=self.native))
 def patch(self,p):p.start();self.addCleanup(p.stop)
 def save(self,p,raw):
  p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
 def native(self,args,**kwargs):
  command=args[1];self.calls.append(command)
  if command=='review-network-formation':return json.dumps(self.source).encode()
  if command=='prepare-network-transport':
   self.assertEqual(args[2:5],[self.root/'tmp/context.json','a'*64,self.root/'tmp/network-formation'])
   raw=Path(args[5]).read_bytes();req=c.parse_request(raw);self.assertEqual(sha(raw),args[6]);self.assertEqual(self.authorized[-1],req)
   self.directory.mkdir(mode=0o700)
   for name in ('request.json','unlock','issuer.enc.json','issuer-root.pub','registry-payload.json','review.json'):self.save(self.directory/name,raw if name=='request.json' else b'fixture')
   self.receipt={'schema':'nodenetwork-network-transport-v1','pending':True,'signed':False,'formation_sha256':'a'*64,'genesis_review_sha256':'c'*64,
                 'request_sha256':sha(raw),'review_sha256':'d'*64,'genesis_sha256':self.source['genesis_sha256'],'authority_sha256':self.source['authority_sha256'],
                 'issuer_root_sha256':sha(b't'*2592),'valid_from_unix':100,'expires_at_unix':200,'validator_addresses':self.source['validator_addresses'],
                 'runtime_admission':False,'fleet_readiness_verified':False}
  if command=='sign-network-transport':
   raw=Path(args[6]).read_bytes();self.assertEqual(sha(raw),args[7]);self.assertEqual(self.authorized[-1],c.parse_request(raw))
   self.save(self.directory/'signed/sign-request.json',raw);self.save(self.directory/'signed/transport-registry.json',b'{}')
   self.receipt.update(signed=True,registry_sha256=sha(b'{}'),sign_request_sha256=sha(raw))
  if command=='export-network-transport':return json.dumps(self.export()).encode()
  return json.dumps(self.receipt).encode()
 def prepare(self):return self.controller.network_transport(request('network_transport_prepare',self.p))
 def sign(self):return self.controller.network_transport(request('network_transport_sign',{'review_sha256':'d'*64}))
 def export(self):
  artifacts={'network/genesis.json':'{}','network/authority.json':'{}','network/authority-root.pub':base64.b64encode(b'a'*1952).decode(),
             'network/network-manifest.json':'{}','network/transport-registry.json':'{}','network/transport-root.pub':base64.b64encode(b't'*2592).decode(),
             'config/node.json':'{}','config/start-authorized.json':json.dumps({'production_approved':False,'all_validators_ready':False,'all_pairs_vpn_verified':False,'validator_addresses':self.source['validator_addresses']})}
  return {'schema':'nodenetwork-network-transport-export-v1','review_sha256':'d'*64,'registry_sha256':sha(b'{}'),'issuer_root_sha256':sha(b't'*2592),'fleet_readiness_verified':False,
          'nodes':[{'address':v,'artifacts':dict(artifacts)} for v in self.source['validator_addresses']]}
 def test_prepare_review_separate_sign_export_and_exact_utf8_journals(self):
  status=self.controller.network_transport(request('network_transport_status'));self.assertFalse(status['pending']);self.assertEqual(status['target_provider_report_sha256'],'b'*64)
  self.assertFalse(self.prepare()['signed']);raw=(self.root/'tmp/network-transport-prepare-request.json').read_bytes();self.assertIn('é'.encode(),raw)
  self.assertEqual(sha(raw),c.request_digest(request('network_transport_prepare',self.p)))
  self.assertTrue(self.sign()['signed']);result=self.controller.network_transport(request('network_transport_export'))
  self.assertFalse(result['fleet_readiness_verified']);self.assertEqual(len(result['nodes']),5)
  self.assertEqual(len(self.authorized),2)
  with self.assertRaisesRegex(c.Refused,'reconciled'):self.prepare()
  with self.assertRaisesRegex(c.Refused,'already dispatched'):self.sign()
  self.assertEqual(len(self.authorized),2)
 def test_wrong_provider_genesis_or_review_rejects_before_authorization(self):
  for field in ('formation_sha256','genesis_review_sha256','target_provider_report_sha256'):
   p={**self.p,field:'e'*64}
   with self.assertRaisesRegex(c.Refused,'Exact signed Genesis'):self.controller.network_transport(request('network_transport_prepare',p))
  self.assertEqual(self.authorized,[]);self.prepare()
  with self.assertRaisesRegex(c.Refused,'review changed'):self.controller.network_transport(request('network_transport_sign',{'review_sha256':'e'*64}))
  self.assertEqual(len(self.authorized),1)
 def test_failure_retains_intent_and_never_generates_or_signs_again(self):
  with patch.object(linux,'native',side_effect=lambda args,**kw:json.dumps(self.source).encode() if args[1]=='review-network-formation' else (_ for _ in ()).throw(ValueError('provider failed'))):
   with self.assertRaisesRegex(ValueError,'provider failed'):self.prepare()
  self.assertTrue((self.root/'tmp/network-transport-prepare-request.json').exists())
  with self.assertRaisesRegex(c.Refused,'reconciled'):self.prepare()
  self.assertEqual(len(self.authorized),1)
 def test_parser_rejects_bounds_shell_public_endpoints_and_unknown_fields(self):
  for field,value in [('members',self.p['members'][:4]),('valid_from_unix',True),('expires_at_unix',100+7*86400+1),('target_provider_report_sha256','x'*64)]:
   with self.assertRaises(c.Refused):c.parse_request(c.canonical(request('network_transport_prepare',{**self.p,field:value})))
  for endpoint in ('example.com:123','8.8.8.8:123','127.0.0.1:0','[fe80::1%en0]:123','127.0.0.1:22;sh'):
   p=copy.deepcopy(self.p);p['members'][0]['dial_address']=endpoint
   with self.assertRaises(c.Refused):c.parse_request(c.canonical(request('network_transport_prepare',p)))
  for endpoint in ('127.0.0.1:123','10.1.2.3:123','100.64.0.1:123','[::1]:123','[fd00::1]:123'):
   p=copy.deepcopy(self.p);p['members'][0]['dial_address']=endpoint;c.parse_request(c.canonical(request('network_transport_prepare',p)))
 def test_conformance_inventory_native_scope_and_private_tamper(self):
  self.prepare();self.sign()
  found=conformance.approved_network_transport_members(self.root);self.assertIn('tmp/network-transport/unlock',found)
  self.save(self.directory/'unexpected',b'keep')
  with self.assertRaisesRegex(ValueError,'incomplete or unexpected'):conformance.approved_network_transport_members(self.root)
  (self.directory/'unexpected').unlink();(self.directory/'unlock').chmod(0o644)
  with self.assertRaisesRegex(ValueError,'permissions'):conformance.approved_network_transport_members(self.root)
 def test_export_refuses_extra_private_file_wrong_hash_roster_or_readiness(self):
  self.prepare();self.sign()
  for kind in ('extra','hash','roster','readiness'):
   value=self.export()
   if kind=='extra':value['nodes'][0]['artifacts']['keys/unlock']='forbidden'
   if kind=='hash':value['nodes'][0]['artifacts']['network/genesis.json']='tampered'
   if kind=='roster':value['nodes'][1]['address']=value['nodes'][0]['address']
   if kind=='readiness':value['nodes'][0]['artifacts']['config/start-authorized.json']='{"production_approved":true}'
   with self.assertRaises(c.Refused):c.validate_transport_export(value,self.receipt,self.source)

if __name__=='__main__':unittest.main()
