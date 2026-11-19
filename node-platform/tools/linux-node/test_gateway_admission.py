"""Real controller boundaries; native fixture separately owns APQE qualification."""
import contextlib,copy,hashlib,json,os,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
import canary_rpc_relay as g
import conformance
import controller as c

def req(op,p=None):return {'version':1,'operation':op,'parameters':p or {}}
def sha(raw):return hashlib.sha256(raw).hexdigest()

class GatewayTests(unittest.TestCase):
 def setUp(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name).resolve()/'synergy';self.root.mkdir(mode=0o700);(self.root/'tmp').mkdir(mode=0o700)
  self.c=c.Controller(self.root);self.authorized=[];self.calls=[];self.result=None
  self.scope={'formation_sha256':'a'*64,'network_id':'synergy-posy-canary-20261117','chain_id':'99999','genesis_sha256':'b'*64,'authority_sha256':'c'*64,'registry_sha256':'d'*64}
  now=int(time.time());self.review={'review_sha256':'e'*64,'issuer_root_sha256':'f'*64,'valid_from_unix':now-5,'expires_at_unix':now+600}
  self.approval={'format':'synergy-engineering-gateway-purpose-v1','purpose':g.GATEWAY_PURPOSE,**{k:v for k,v in self.scope.items() if k not in ('network_id','chain_id')},'transport_review_sha256':'e'*64,'issuer_root_sha256':'f'*64,'gateway_enrollment_sha256':sha(b'{"public":"enrollment"}'),'valid_from_unix':now-1,'expires_at_unix':now+300}
  raw=json.dumps(self.approval,sort_keys=True).encode();self.pin=sha(raw);self.policy={'authorization_files':{g.GATEWAY_APPROVAL:self.pin}}
  self.save(self.c.control/'authorization/inputs'/g.GATEWAY_APPROVAL,raw)
  self.p={'formation_sha256':'a'*64,'transport_review_sha256':'e'*64,'gateway_enrollment_json':'{"public":"enrollment"}','purpose_approval_json':raw.decode(),'purpose_approval_sha256':self.pin,'valid_from_unix':now-1,'expires_at_unix':now+300}
  self.directory=self.root/g.GATEWAY_DIRECTORY;self.args=[self.root/'tmp/context.json','a'*64,self.root/'tmp/network-formation',self.root/'tmp/network-transport']
  for p in (patch.object(g,'_gateway_scope',return_value=(self.policy,self.scope,self.review,self.args,[])),patch('lifecycle._lifecycle_lock',side_effect=lambda _:contextlib.nullcontext()),patch('lifecycle._attributed_units',return_value={}),patch('lifecycle._unit_state',return_value={'ActiveState':'inactive','MainPID':'0'}),patch('lifecycle._assert_no_application_processes'),patch.object(self.c,'authorize',side_effect=self.authorize),patch.object(g,'native',side_effect=self.native)):
   p.start();self.addCleanup(p.stop)
 def save(self,p,raw):
  p.parent.mkdir(mode=0o700,parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
 def authorize(self,r):
  self.authorized.append(copy.deepcopy(r));self.c.audit(r)
 def native(self,args,**kw):
  op=args[1];self.calls.append(op)
  if op=='check-gateway-admission':
   original=c.parse_request(kw['data']);self.assertEqual(original,req('gateway_admission_prepare',self.p))
   return json.dumps({'schema':'nodenetwork-gateway-admission-preflight-v1','ready':True,'request_sha256':c.request_digest(original),**self.scope,'transport_review_sha256':'e'*64,'issuer_root_sha256':'f'*64,'purpose_approval_sha256':self.pin,'gateway_enrollment_sha256':sha(self.p['gateway_enrollment_json'].encode()),'gateway_address':'synv5fixture','valid_from_unix':self.p['valid_from_unix'],'expires_at_unix':self.p['expires_at_unix'],'mutation_performed':False,'services_started':False,'public_listener':False,'production_qualified':False}).encode()
  if op=='prepare-gateway-admission':
   raw=Path(args[8]).read_bytes();self.assertEqual(args[9],sha(raw));self.assertEqual(self.authorized[-1],c.parse_request(raw));self.directory.mkdir(mode=0o700)
   self.save(self.directory/'request.json',raw);self.save(self.directory/'review.json',b'public review')
   self.result={'schema':'nodenetwork-gateway-admission-v1','pending':True,'signed':False,**self.scope,'request_sha256':sha(raw),'review_sha256':'1'*64,'purpose_approval_sha256':self.pin,'gateway_address':'synv5fixture','gateway_enrollment_sha256':sha(self.p['gateway_enrollment_json'].encode()),'valid_from_unix':self.p['valid_from_unix'],'expires_at_unix':self.p['expires_at_unix'],'admission_sha256':None,'sign_request_sha256':None,'gateway_commissioned':False,'services_started':False,'public_listener':False,'production_qualified':False,'automatic_retry':False}
  if op=='sign-gateway-admission':
   raw=Path(args[9]).read_bytes();self.assertEqual(args[10],sha(raw));self.assertEqual(self.authorized[-1],c.parse_request(raw))
   self.save(self.directory/'signed/sign-request.json',raw);self.save(self.directory/'signed/rpc-gateway-admission.json',b'{"public":"signed"}');self.result.update(signed=True,sign_request_sha256=sha(raw),admission_sha256=sha(b'{"public":"signed"}'))
  result=copy.deepcopy(self.result)
  if op=='export-gateway-admission':result['admission_json']='{"public":"signed"}'
  return json.dumps(result).encode()
 def call(self,op,p=None):return g.gateway_admission(self.c,req(op,p))
 def prepare(self):return self.call('gateway_admission_prepare',self.p)
 def sign(self):return self.call('gateway_admission_sign',{'review_sha256':'1'*64,'purpose_approval_sha256':self.pin})
 def test_prepare_separate_sign_export_reconcile_preserves_exact_public_bytes(self):
  empty=self.call('gateway_admission_status');self.assertFalse(empty['pending']);self.assertTrue(empty['available']);self.assertEqual(len(empty),25);self.assertTrue(all(empty[k] is None for k in self.scope))
  self.assertEqual(len(self.call('gateway_admission_preflight',self.p)),20);self.assertEqual(self.authorized,[])
  self.assertFalse(self.prepare()['signed']);self.assertTrue(self.sign()['signed']);out=self.call('gateway_admission_export');self.assertEqual(len(out),26);self.assertFalse(out['gateway_commissioned'])
  for digest in (out['request_sha256'],out['sign_request_sha256']):self.assertEqual(self.call('gateway_admission_reconcile',{'request_sha256':digest})['admission_sha256'],out['admission_sha256'])
  with self.assertRaisesRegex(ValueError,'retained original'):self.call('gateway_admission_reconcile',{'request_sha256':'9'*64})
  with self.assertRaisesRegex(ValueError,'uncertain'):self.prepare()
  with self.assertRaisesRegex(ValueError,'sign exists'):self.sign()
  self.assertEqual(len(self.authorized),2);self.assertNotIn('envelope',json.dumps(out))
 def test_missing_expired_foreign_or_widened_purpose_never_authorizes(self):
  for field,value in [('purpose','any-signature'),('formation_sha256','0'*64),('issuer_root_sha256','0'*64),('registry_sha256','0'*64),('expires_at_unix',int(time.time())-1),('extra',True)]:
   raw=json.dumps({**self.approval,field:value}).encode();self.policy['authorization_files'][g.GATEWAY_APPROVAL]=sha(raw);self.save(self.c.control/'authorization/inputs'/g.GATEWAY_APPROVAL,raw)
   with self.assertRaises(ValueError):self.prepare()
  self.policy['authorization_files']={};self.assertEqual(self.call('gateway_admission_status')['blocker'],'gateway_purpose_approval_required')
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.authorized,[])
 def test_failed_owner_retains_intent_and_never_reexecutes(self):
  original=self.native
  def fail(args,**kw):
   if args[1]=='prepare-gateway-admission':raise ValueError('provider unavailable')
   return original(args,**kw)
  with patch.object(g,'native',side_effect=fail),self.assertRaisesRegex(ValueError,'provider unavailable'):self.prepare()
  self.assertEqual((self.root/g.GATEWAY_PREPARE_INTENT).read_bytes(),c.canonical(req('gateway_admission_prepare',self.p)))
  with self.assertRaisesRegex(ValueError,'uncertain'):self.prepare()
  self.assertEqual(len(self.authorized),1)
  with self.assertRaises((ValueError,OSError)):self.call('gateway_admission_status')
 def test_private_inventory_rejects_extra_partial_symlink_modes_and_changed_request(self):
  self.prepare();self.sign();members=conformance.approved_gateway_admission_members(self.root);self.assertEqual(len(members),8)
  for defect in ('extra','directory','symlink','hardlink','mode','partial','request'):
   with self.subTest(defect=defect):
    path=self.directory/'review.json';raw=path.read_bytes()
    if defect=='extra':self.save(self.directory/'secret',b'no')
    if defect=='directory':(self.directory/'extra').mkdir(mode=0o700)
    if defect=='symlink':path.unlink();path.symlink_to(self.directory/'request.json')
    if defect=='hardlink':path.unlink();os.link(self.directory/'request.json',path)
    if defect=='mode':path.chmod(0o644)
    if defect=='partial':(self.directory/'signed-pending').mkdir(mode=0o700)
    if defect=='request':self.save(self.directory/'request.json',b'{}')
    with self.assertRaises(ValueError):conformance.approved_gateway_admission_members(self.root)
    for name in ('secret','extra','signed-pending'):
     p=self.directory/name
     if p.is_dir():p.rmdir()
     elif p.exists():p.unlink()
    if path.is_symlink() or path.stat().st_nlink>1:path.unlink()
    self.save(path,raw);self.save(self.directory/'request.json',(self.root/g.GATEWAY_PREPARE_INTENT).read_bytes())
 def test_closed_parser_and_response_deny_paths_private_or_foreign_claims(self):
  for bad in ({'path':'/etc/shadow'},{'expires_at_unix':True},{'purpose_approval_sha256':'F'*64},{'gateway_enrollment_json':'x'*(128*1024+1)}):
   with self.assertRaises(c.Refused):c.parse_request(c.canonical(req('gateway_admission_prepare',{**self.p,**bad})))
  self.prepare()
  for key,value in [('request_sha256','0'*64),('gateway_enrollment_sha256','0'*64),('gateway_address','syna1wallet'),('gateway_commissioned',True),('signed',1),('extra','private')]:
   original=copy.deepcopy(self.result);self.result[key]=value
   with self.assertRaises(ValueError):self.call('gateway_admission_status')
   self.result=original
  with patch.object(g,'_gateway_scope',side_effect=ValueError('private detail')):
   out=self.call('gateway_admission_status');self.assertEqual(out['blocker'],'gateway_runtime_or_origin_unavailable');self.assertNotIn('private',json.dumps(out))
 def test_non_ascii_exact_request_bytes_match_native_digest(self):
  self.p['gateway_enrollment_json']='{"public":"é"}'
  self.approval['gateway_enrollment_sha256']=sha(self.p['gateway_enrollment_json'].encode())
  raw=json.dumps(self.approval,sort_keys=True).encode();self.pin=sha(raw)
  self.policy['authorization_files'][g.GATEWAY_APPROVAL]=self.pin
  self.save(self.c.control/'authorization/inputs'/g.GATEWAY_APPROVAL,raw)
  self.p.update(purpose_approval_json=raw.decode(),purpose_approval_sha256=self.pin)
  self.prepare();raw=(self.root/g.GATEWAY_PREPARE_INTENT).read_bytes()
  self.assertIn('é'.encode(),raw);self.assertEqual(sha(raw),c.request_digest(req('gateway_admission_prepare',self.p)))
 def test_foreign_service_denies_but_live_validator_is_unchanged(self):
  with patch('lifecycle._attributed_units',side_effect=ValueError('foreign unit')),self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.authorized,[])
  sentinels={'keys/validator.secret':b'private fixture','network/transport-registry.json':b'signed registry','systemd/synergy-node.service':b'unit'}
  for name,raw in sentinels.items():self.save(self.root/name,raw)
  with patch('lifecycle._unit_state',return_value={'ActiveState':'active','MainPID':'42'}),patch('lifecycle.mutate_owned_service') as mutate:
   self.prepare();self.sign();mutate.assert_not_called()
  for name,raw in sentinels.items():self.assertEqual((self.root/name).read_bytes(),raw)
 def test_retained_review_is_not_new_authority_when_purpose_expired(self):
  self.prepare();self.sign()
  with patch('time.time',return_value=self.approval['expires_at_unix']+1):
   self.assertTrue(self.call('gateway_admission_status')['signed'])
   self.assertEqual(len(conformance.approved_gateway_admission_members(self.root)),8)
   with self.assertRaises(ValueError):g._gateway_approval(self.c,self.policy,self.scope,self.review)
 def test_positive_reconcile_requires_consumed_exact_audit_and_no_grant(self):
  self.prepare();audit=self.c.control/'audit.jsonl';saved=audit.read_bytes();key=c.request_digest(req('gateway_admission_prepare',self.p))
  for bad in (b'',saved+saved,json.dumps({'request_sha256':key,'operation':'gateway_admission_sign','time':int(time.time())}).encode()):
   self.save(audit,bad)
   with self.assertRaises(ValueError):self.call('gateway_admission_reconcile',{'request_sha256':key})
  self.save(audit,saved);grant=self.c.control/'grants'/(key+'.json');self.save(grant,b'{}')
  with self.assertRaisesRegex(ValueError,'not consumed'):self.call('gateway_admission_status')
  grant.unlink();self.assertTrue(self.call('gateway_admission_status')['pending'])

 def test_pregrant_preflight_refuses_existing_intent_or_different_staged_purpose(self):
  self.prepare();count=len(self.authorized)
  with self.assertRaisesRegex(ValueError,'uncertain'):self.call('gateway_admission_preflight',self.p)
  self.assertEqual(len(self.authorized),count)
  (self.root/g.GATEWAY_PREPARE_INTENT).unlink()
  for path in self.directory.iterdir():path.unlink()
  self.directory.rmdir();self.policy['authorization_files'][g.GATEWAY_APPROVAL]='0'*64
  with self.assertRaisesRegex(ValueError,'Existing gateway purpose differs'):self.call('gateway_admission_preflight',self.p)
 def test_gateway_authority_root_is_exact_approved_installed_and_source_bytes(self):
  installed=self.root/'network/authority-root.pub';source=self.root/'tmp/network-formation/authority-root.pub'
  raw=b'fixture public authority root';self.save(installed,raw);self.save(source,raw)
  policy={'validator_identity_network':{'authority-root.pub':sha(raw)}}
  before=(installed.read_bytes(),source.read_bytes())
  g._gateway_authority_root(self.c,policy)
  for path in (installed,source):
   self.save(path,b'foreign public root')
   with self.assertRaises(ValueError):g._gateway_authority_root(self.c,policy)
   self.save(path,raw)
  for bad in ({},{'validator_identity_network':{'authority-root.pub':'0'*64}}):
   with self.assertRaises(ValueError):g._gateway_authority_root(self.c,bad)
  source.unlink();source.symlink_to(installed)
  with self.assertRaises(ValueError):g._gateway_authority_root(self.c,policy)
  source.unlink();self.save(source,raw)
  self.assertEqual(before,(installed.read_bytes(),source.read_bytes()))
 def test_active_policy_exception_is_only_fixed_purpose_or_input_free_sign(self):
  import bootstrap as b
  policy={'validator_identity_network':{'genesis.json':'b'*64,'authority.json':'c'*64,'authority-root.pub':'d'*64}}
  doc={'requests':[{'operation':'gateway_admission_prepare','request_sha256':'1'*64}],'genesis_pins':policy['validator_identity_network']}
  inputs={g.GATEWAY_APPROVAL:json.dumps(self.approval).encode()}
  self.assertTrue(b.gateway_issuer_policy_only(self.root,True,inputs,doc,policy))
  for bad in (dict(doc,genesis_pins=None),dict(doc,requests=[{'operation':'upgrade','request_sha256':'1'*64}])):
   self.assertFalse(b.gateway_issuer_policy_only(self.root,True,inputs,bad,policy))
  self.assertFalse(b.gateway_issuer_policy_only(self.root,False,inputs,doc,policy))
  self.assertFalse(b.gateway_issuer_policy_only(self.root,True,{**inputs,'config/node.json':b'{}'},doc,policy))
  changed={**self.approval,'genesis_sha256':'0'*64}
  with self.assertRaises(ValueError):b.gateway_issuer_policy_only(self.root,True,{g.GATEWAY_APPROVAL:json.dumps(changed).encode()},doc,policy)
  sign=dict(doc,requests=[{'operation':'gateway_admission_sign','request_sha256':'2'*64}])
  with patch.object(g,'_gateway_approval',return_value=None) as approval:
   self.assertTrue(b.gateway_issuer_policy_only(self.root,True,{},sign,policy));approval.assert_called_once()
  self.assertFalse(b.gateway_issuer_policy_only(self.root,True,inputs,sign,policy))

class GatewayLegacyEngineTests(unittest.TestCase):
 from test_controller import ControllerTests as _Fixture
 setUp=_Fixture.setUp
 tearDown=_Fixture.tearDown
 save=_Fixture.save
 def test_old_enrolled_engine_needs_no_new_module_or_owner_for_existing_reads(self):
  import bootstrap as b
  old={'controller.py','synergy_linux.py','lifecycle.py','conformance.py','apqe_layout.py','vpn.py','canary_rpc_relay.py','root_guard.py','guest_lifecycle.py','vpn_authorization.py','treasury_send.py'}
  self.assertEqual(c.ENGINE_MODULES,old);self.assertEqual(set(b.enrolled_engine(self.policy)),old)
  before=(self.control/'policy.json').read_bytes();files,_=c.control_inventory(self.root)
  with patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'):
   result=c.serve(c.canonical(req('authorization_status')),self.controller);self.assertTrue(result['ok'])
   status=g.gateway_admission(self.controller,req('gateway_admission_status'));self.assertEqual(status['blocker'],'gateway_runtime_or_origin_unavailable')
   target=self.controller.target();operations={row['operation']:row for row in target['operations']}
   self.assertTrue(operations['authorization_status']['available']);self.assertTrue(operations['stop']['available'])
   self.assertFalse(operations['gateway_admission_prepare']['available']);self.assertNotEqual(operations['gateway_admission_prepare']['blocker'],'Operation has not passed host qualification')
  with patch.object(g,'_gateway_scope',side_effect=g.subprocess.TimeoutExpired('private command',120)),patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'):
   self.assertFalse(g.gateway_owner_available(self.controller));self.assertEqual(g.gateway_admission(self.controller,req('gateway_admission_status'))['blocker'],'gateway_runtime_or_origin_unavailable')
   self.assertTrue(next(row for row in self.controller.target()['operations'] if row['operation']=='authorization_status')['available'])
  self.assertEqual(before,(self.control/'policy.json').read_bytes());self.assertEqual(files,c.control_inventory(self.root)[0])

if __name__=='__main__':unittest.main()
